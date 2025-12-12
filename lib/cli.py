"""
TokenFlare CLI Application

Main CLI class, argument parsing, and command dispatch.
"""

import sys
import os
import logging
import argparse
from pathlib import Path
from typing import Optional, Tuple, Dict, Union, Callable

from lib import VERSION, BANNER
from lib.commands import Commands


class TokenFlare:
    """Main TokenFlare CLI application"""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.setup_logging()
        # Project root is where tokenflare.py is located
        self.project_root = Path(__file__).parent.parent.resolve()
        self.src_dir = self.project_root / "src"
        self.certs_dir = self.project_root / "certs"
        self.config_file = self.project_root / "tokenflare.cfg"
        self.wrangler_toml = self.project_root / "wrangler.toml"

        # Initialise commands with self
        self.commands = Commands(self)

    def setup_logging(self) -> None:
        """Configure logging based on verbosity"""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            format='[%(levelname)s] %(message)s',
            level=level,
            stream=sys.stdout
        )
        self.logger = logging.getLogger('tokenflare')


def dispatch_command(app: TokenFlare, args: argparse.Namespace, parser: argparse.ArgumentParser) -> Optional[Union[int, Tuple[str, str]]]:
    """Route commands to appropriate handlers using dispatch dictionary"""

    # Command dispatch map
    dispatch = {
        'init': lambda: app.commands.cmd_init(args.domain),
        'configure': {
            'campaign': app.commands.cmd_configure_campaign,
            'cf': app.commands.cmd_configure_cf,
            'ssl': app.commands.cmd_configure_ssl,
        },
        'deploy': {
            'local': app.commands.cmd_deploy_local,
            'remote': app.commands.cmd_deploy_remote,
        },
        'status': lambda: app.commands.cmd_status(get_lure_url=getattr(args, 'get_lure_url', False)),
        'version': app.commands.cmd_version,
    }

    handler = dispatch.get(args.command)

    if handler is None:
        return None

    # Handle nested commands (configure, deploy)
    if isinstance(handler, dict):
        subcommand_attr = f"{args.command}_type"
        subcommand = getattr(args, subcommand_attr, None)

        # If no subcommand provided, return special value to trigger subparser help
        if subcommand is None:
            return ('show_subparser_help', args.command)

        handler = handler.get(subcommand)

    if handler is None:
        return None

    # Execute handler
    return handler() if callable(handler) else handler


def create_parser() -> Tuple[argparse.ArgumentParser, Dict[str, argparse.ArgumentParser]]:
    """Create argument parser with all commands"""
    parser = argparse.ArgumentParser(
        description='TokenFlare - Serverless AITM Framework for Entra ID',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--no-banner', action='store_true',
                        help='Suppress banner output')
    parser.add_argument('--version', action='store_true',
                        help='Show version information')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Init command
    parser_init = subparsers.add_parser('init', help='Initialise TokenFlare project')
    parser_init.add_argument('domain', help='Domain for deployment (e.g., example.com)')

    # Configure command
    parser_configure = subparsers.add_parser('configure', help='Configure TokenFlare settings')
    cfg_sub = parser_configure.add_subparsers(dest='configure_type', help='Configuration type')
    cfg_sub.add_parser('campaign', help='Configure campaign settings')
    cfg_sub.add_parser('cf', help='Configure CloudFlare credentials')
    cfg_sub.add_parser('ssl', help='Configure SSL certificates')

    # Deploy command
    parser_deploy = subparsers.add_parser('deploy', help='Deploy TokenFlare worker')
    deploy_sub = parser_deploy.add_subparsers(dest='deploy_type', help='Deployment type')
    deploy_sub.add_parser('local', help='Deploy locally with wrangler dev')
    deploy_sub.add_parser('remote', help='Deploy to CloudFlare')

    # Status command
    parser_status = subparsers.add_parser('status', help='Show configuration and deployment status')
    parser_status.add_argument('--get-lure-url', action='store_true',
                               help='Display lure URLs')

    # Version command
    subparsers.add_parser('version', help='Show version information')

    # Return parser and subparsers for help messages
    subparser_map = {
        'configure': parser_configure,
        'deploy': parser_deploy
    }

    return parser, subparser_map


def main() -> int:
    """Main entry point"""
    parser, subparser_map = create_parser()
    args = parser.parse_args()

    # Handle --version flag
    if args.version:
        print(BANNER)
        print(f"Version: {VERSION}")
        return 0

    # Show help if no command
    if not args.command:
        parser.print_help()
        return 0

    # Show banner (unless suppressed)
    if not args.no_banner:
        print(BANNER)

    # Initialise app
    app = TokenFlare(verbose=args.verbose)

    try:
        # Dispatch to appropriate command handler
        result = dispatch_command(app, args, parser)

        # Handle special return values
        if isinstance(result, tuple) and result[0] == 'show_subparser_help':
            command_name = result[1]
            if command_name in subparser_map:
                subparser_map[command_name].print_help()
            else:
                parser.print_help()
            return 1

        if result is None:
            # Invalid subcommand
            parser.print_help()
            return 1

        return result

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if app.verbose:
            logging.exception("Full traceback:")
        else:
            logging.info("Use -v flag for detailed error information")
        return 2
