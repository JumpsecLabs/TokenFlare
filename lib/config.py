"""
TokenFlare Configuration Management

Functions for loading, saving, and updating TOML configuration files
with comment preservation, and CloudFlare API integration.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, Union, List
from pathlib import Path


def load_toml(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Minimal TOML parser for wrangler.toml

    Handles: sections, nested sections, strings (single/double quoted), booleans
    Does NOT handle: arrays, inline tables, multiline strings, dates
    """
    result = {}
    current_section = None

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Section header [section] or [section.subsection]
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                # Create nested dict for section
                parts = current_section.split('.')
                d = result
                for part in parts:
                    d = d.setdefault(part, {})
                continue

            # Key = value
            if '=' in line:
                key, _, value = line.partition('=')
                key = key.strip()

                # Handle inline comments (but not # inside quotes)
                value = value.strip()
                if value.startswith('"'):
                    # Find closing quote
                    end = value.find('"', 1)
                    if end != -1:
                        value = value[1:end]
                elif value.startswith("'"):
                    # Find closing quote
                    end = value.find("'", 1)
                    if end != -1:
                        value = value[1:end]
                else:
                    # Unquoted - strip inline comment
                    value = value.split('#')[0].strip()
                    if value == 'true':
                        value = True
                    elif value == 'false':
                        value = False

                # Place in correct section
                if current_section:
                    parts = current_section.split('.')
                    d = result
                    for part in parts:
                        d = d.setdefault(part, {})
                    d[key] = value
                else:
                    result[key] = value

    return result


def update_wrangler_var(file_path: Union[str, Path], var_name: str, value: Union[str, List, Tuple]) -> None:
    """
    Update or add a variable in wrangler.toml while preserving comments

    This does a surgical text replacement instead of parsing/dumping TOML
    to preserve all comments and formatting.
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Format the value appropriately
    if isinstance(value, str):
        formatted_value = f'{var_name} = "{value}"'
    elif isinstance(value, (list, tuple)):
        # For lists, create comma-separated string
        formatted_value = f'{var_name} = "{", ".join(str(v) for v in value)}"'
    else:
        formatted_value = f'{var_name} = {value}'

    # Find if variable exists
    var_found = False
    for i, line in enumerate(lines):
        # Match variable assignment (with or without comments)
        if line.strip().startswith(f'{var_name}=') or line.strip().startswith(f'{var_name} ='):
            lines[i] = formatted_value + '\n'
            var_found = True
            break
        # Also check for commented-out version
        if line.strip().startswith(f'#{var_name}=') or line.strip().startswith(f'# {var_name} ='):
            lines[i] = formatted_value + '\n'
            var_found = True
            break

    # If not found, add after [vars] section
    if not var_found:
        for i, line in enumerate(lines):
            if line.strip() == '[vars]':
                # Insert after the [vars] line
                lines.insert(i + 1, formatted_value + '\n')
                break

    # Write back
    with open(file_path, 'w') as f:
        f.writelines(lines)


def update_wrangler_field(file_path: Union[str, Path], field_name: str, value: str) -> None:
    """
    Update a top-level field in wrangler.toml (e.g., name, account_id)

    Unlike update_wrangler_var() which handles [vars] section,
    this handles top-level key = "value" fields before any section.
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()

    formatted_value = f'{field_name} = "{value}"'

    field_found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Match field assignment (before any section like [vars])
        if stripped.startswith(f'{field_name} =') or stripped.startswith(f'{field_name}='):
            lines[i] = formatted_value + '\n'
            field_found = True
            break

    if not field_found:
        # Insert after first comment block
        for i, line in enumerate(lines):
            if not line.startswith('#') and line.strip():
                lines.insert(i, formatted_value + '\n')
                break

    with open(file_path, 'w') as f:
        f.writelines(lines)


def test_cloudflare_api(api_key: str, account_id: str) -> Tuple[bool, str]:
    """
    Test CloudFlare API credentials and get account subdomain

    Returns: (success: bool, subdomain: str or error_message: str)
    """
    try:
        # Call CloudFlare API to get account details
        url = f'https://api.cloudflare.com/client/v4/accounts/{account_id}'
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

            if data.get('success'):
                # Get account subdomain for workers
                account_name = data['result'].get('name', '')
                # The subdomain is typically derived from account, but we need to check workers subdomain
                # Let's get the workers subdomain from the account settings
                workers_url = f'https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/subdomain'
                req2 = urllib.request.Request(workers_url, headers=headers)

                try:
                    with urllib.request.urlopen(req2, timeout=10) as response2:
                        subdomain_data = json.loads(response2.read().decode())
                        if subdomain_data.get('success'):
                            subdomain = subdomain_data['result'].get('subdomain', '')
                            return True, subdomain
                except:
                    # If subdomain endpoint fails, return success but no subdomain
                    return True, None

                return True, None
            else:
                errors = data.get('errors', [])
                if errors:
                    return False, errors[0].get('message', 'Unknown error')
                return False, 'API call failed'

    except urllib.error.HTTPError as e:
        if e.code == 403:
            return False, 'Invalid API key or insufficient permissions'
        elif e.code == 401:
            return False, 'Authentication failed - check your API key'
        else:
            return False, f'HTTP error {e.code}: {e.reason}'
    except Exception as e:
        return False, f'Connection error: {str(e)}'
