# TokenFlare

**Serverless AITM Phishing Simulation Framework for Entra ID / M365**


## Features

- Lean: Core logic (in `src/worker.js` only ~530 lines of JavaScript).
- Modular: Supports a number of OAuth flows, with [Intune Conditional Access bypass](https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/) support out of the box
- Easily tweaked: Set up client branding, URL structure (custom lure path and parameter), final redirect after completing auth, and more, with the semi-interactive `tokenflare configure campaign` subcommand.
- Local or remote deployment: Supports getting SSL certs with Certbot for you, or deployment to CF directly.
- Built in OpSec: bot and scraper blocking, your campaign wouldn't be burnt in 10 minutes.
- Fast: get working, production ready infra within minutes.

## Prerequisites

- Python 3.7+
- Node.js 20+ with Wrangler CLI. On Linux, we recommend [NodeSource](https://github.com/nodesource/distributions):
  ```bash
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
  npm install -g wrangler
  ```
- CloudFlare account (for remote deployment)
- [Optional] Certbot for local SSL: `sudo apt install certbot`

>Note: Developed and tested on an Ubuntu VPS hosted on a public cloud. Running on localhost is possible but not recommended (for reasons such as port forwarding, DNS record pointing to you, etc)

## Quick Start

```bash
# 1. Initialise
python3 tokenflare.py init yourdomain.com

# 2. Configure campaign (interactive wizard)
python3 tokenflare.py configure campaign

# 2.5. Get valid SSL certificate for the domain pointing to your VPS
sudo python3 tokenflare.py configure ssl

# 3. Deploy locally for testing
sudo python3 tokenflare.py deploy local


# 4. Deploy to CloudFlare
python3 tokenflare.py configure cf
python3 tokenflare.py deploy remote

# 5. Troubleshooting
# change some settings in wrangler.toml, src/worker.js, or with tokenflare configure, then
python3 tokenflare.py deploy local #or
python3 tokenflare.py deploy remote
```

## Commands

| Command | Description |
|---------|-------------|
| `init <domain>` | Initialise project for domain |
| `configure campaign` | Interactive campaign setup |
| `configure cf` | CloudFlare credentials |
| `configure ssl` | SSL certificate setup |
| `deploy local` | Local HTTPS proxy |
| `deploy remote` | Deploy to CloudFlare |
| `status` | Configuration overview |
| `status --get-lure-url` | Show lure URLs |

## Captured Credentials

Credentials, auth codes, and session cookies are sent to your configured webhook. Supports Slack, Discord, Teams, and generic webhooks (auto-detected from URL).

Configure during `configure campaign` or set `WEBHOOK_URL` in wrangler.toml.

Local credential saving in files is not implemented due to serverless nature of Workers. If you'd like to add `log(creds);` in src/worker.js, beware that CF might redact JWTs, cookies or creds captured. Having a working webhook is the most reliable method in our experience.

## Easy IoCs for blue teams

```
Header:     X-TokenFlare: Authorised-Security-Testing
User-Agent: TokenFlare/1.0 For_Authorised_Testing_Only
```

## Acknowledgements

Many Thanks to:
- [TE](https://github.com/tdejmp) - for helping, debugging, teaching me a ton and otherwise being an awesome human being.
- [Dave @Cyb3rC3lt](https://github.com/Cyb3rC3lt/) - for creating our v1 internal prod Worker.
- [Zolderio](https://github.com/zolderio/) - for creating the prototype PoC Worker that started it all.

## Disclaimer

**FOR AUTHORISED SECURITY TESTING ONLY**

Unauthorised use against systems you do not own or have permission to test is illegal.

Using Cloudflare's services to penetration test a third party might go against some of their T&C's. Don't write to us if your prod CF account was banned - consider yourself warned. 

## License

See LICENSE file.
