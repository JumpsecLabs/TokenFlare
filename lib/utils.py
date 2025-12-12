"""
TokenFlare Utility Functions

Helper functions for certificate generation, UUID generation,
command execution, and URL defanging.
"""

import os
import sys
import subprocess
import shutil
import uuid
import logging
from typing import Optional, List, Union
from pathlib import Path


def run_command(cmd: Union[str, List[str]], timeout: int = 5, **kwargs) -> Optional[subprocess.CompletedProcess]:
    """Run a command and return result"""
    try:
        return subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True,
            timeout=timeout,
            **kwargs
        )
    except Exception as e:
        logging.debug(f"Command failed: {e}")
        return None


def generate_uuids(count: int = 20) -> List[str]:
    """Generate random UUIDs"""
    return [str(uuid.uuid4()) for _ in range(count)]


def generate_self_signed_cert(domain: str, cert_path: Path, key_path: Path, days: int = 365) -> bool:
    """
    Generate self-signed certificate using openssl

    Args:
        domain: Domain name for certificate CN and SAN
        cert_path: Path to save certificate
        key_path: Path to save private key
        days: Certificate validity period (default 365)

    Returns:
        True if successful, False otherwise
    """
    logging.info(f"Generating self-signed certificate for {domain}...")

    # Modern browsers require Subject Alternative Name (SAN) - CN alone is not enough
    # The -addext flag requires OpenSSL 1.1.1+
    cmd = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', str(key_path),
        '-out', str(cert_path),
        '-days', str(days),
        '-subj', f'/CN={domain}',
        '-addext', f'subjectAltName=DNS:{domain}'
    ]

    result = run_command(cmd, timeout=30)

    if result and result.returncode == 0:
        # Set secure permissions (600)
        os.chmod(cert_path, 0o600)
        os.chmod(key_path, 0o600)
        logging.info("✓ Certificate generated successfully")
        return True

    logging.error(f"Failed to generate certificate: {result.stderr if result else 'timeout'}")
    return False


def defang_url(url: Optional[str]) -> Optional[str]:
    """Convert URLs to defanged format for safe display"""
    if not url:
        return url
    return url.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]', 1)


def get_wrangler_command() -> Optional[List[str]]:
    """Get the appropriate wrangler command (wrangler or npx wrangler)"""
    if shutil.which('wrangler'):
        return ['wrangler']
    elif shutil.which('npx'):
        return ['npx', 'wrangler']
    else:
        return None


# ============================================================
# Permission Utilities
# ============================================================

def is_root() -> bool:
    """Check if running as root"""
    return os.geteuid() == 0


def require_root(command_description: str) -> bool:
    """
    Check if running as root, exit with helpful message if not

    Args:
        command_description: Description of what needs root (e.g., "deploy local")

    Returns:
        True if root, exits otherwise
    """
    if not is_root():
        print(f"\n[!] The '{command_description}' command requires root privileges")
        print(f"    Reason: Binding to port 443 and/or installing system packages")
        print(f"\n    Run: sudo python3 tokenflare.py {command_description}")
        # print(f"\n    Note: TokenFlare must be installed globally to work with sudo")
        sys.exit(1)
    return True
