#!/usr/bin/env python3
"""
TokenFlare - Modular, Serverless AITM Framework for Entra ID

AUTHORIZATION DISCLAIMER:
This tool is designed for authorized security testing and ethical penetration
testing engagements only. Use of this tool against systems without explicit
written permission is illegal and unethical.

Author: Gladstomych @ JUMPSEC Labs
License: GPL-3.0
Version: 1.0
"""

import sys

if __name__ == '__main__':
    from lib.cli import main
    sys.exit(main())
