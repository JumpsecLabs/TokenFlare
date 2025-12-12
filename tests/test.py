#!/usr/bin/env python3
"""
TokenFlare Automated Tests

Tests CLI error handling and validation logic.
Does NOT test actual worker functionality (manual testing required).

Usage:
    python3 tests/test.py
    python3 tests/test.py -v  # verbose
"""

import os
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test configuration
PROJECT_ROOT = Path(__file__).parent.parent
TOKENFLARE_PY = PROJECT_ROOT / "tokenflare.py"
VERBOSE = '-v' in sys.argv

# === Test Utilities ===

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def run_cli(*args, expect_fail=False, needs_root=False):
    """Run tokenflare.py with args and return (returncode, stdout, stderr)"""
    cmd = ['python3', str(TOKENFLARE_PY)] + list(args)

    if needs_root and os.geteuid() != 0:
        # Skip root-required tests if not root
        return None, None, None

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)

    if VERBOSE:
        print(f"  CMD: {' '.join(args)}")
        print(f"  RC:  {result.returncode}")
        if result.stdout.strip():
            print(f"  OUT: {result.stdout[:200]}...")
        if result.stderr.strip():
            print(f"  ERR: {result.stderr[:200]}...")

    return result.returncode, result.stdout, result.stderr

def test(name, condition, msg_pass="", msg_fail=""):
    """Report test result"""
    if condition:
        print(f"  {Colors.GREEN}[PASS]{Colors.RESET} {name}")
        return True
    else:
        print(f"  {Colors.RED}[FAIL]{Colors.RESET} {name}")
        if msg_fail:
            print(f"        {msg_fail}")
        return False

def skip(name, reason):
    """Report skipped test"""
    print(f"  {Colors.YELLOW}[SKIP]{Colors.RESET} {name} - {reason}")

# === Backup/Restore Utilities ===

class ConfigBackup:
    """Context manager to backup and restore config files"""
    def __init__(self):
        self.backup_dir = None
        self.files = ['wrangler.toml', 'tokenflare.cfg']
        self.dirs = ['certs']

    def __enter__(self):
        self.backup_dir = tempfile.mkdtemp(prefix='tokenflare_test_')
        for f in self.files:
            src = PROJECT_ROOT / f
            if src.exists():
                try:
                    shutil.copy2(src, self.backup_dir)
                except PermissionError:
                    # File owned by root - mark as existing but can't backup
                    (Path(self.backup_dir) / f'{f}.exists').touch()
        for d in self.dirs:
            src = PROJECT_ROOT / d
            if src.exists():
                try:
                    shutil.copytree(src, Path(self.backup_dir) / d)
                except (PermissionError, shutil.Error):
                    # Certs have 600 permissions - just note the dir exists
                    (Path(self.backup_dir) / d).mkdir(exist_ok=True)
                    (Path(self.backup_dir) / d / '.exists').touch()
        return self

    def __exit__(self, *args):
        # Restore files
        for f in self.files:
            backup = Path(self.backup_dir) / f
            marker = Path(self.backup_dir) / f'{f}.exists'
            dest = PROJECT_ROOT / f

            if marker.exists():
                # File existed but couldn't backup (permissions) - leave alone
                pass
            elif backup.exists():
                shutil.copy2(backup, dest)
            elif dest.exists():
                try:
                    dest.unlink()
                except PermissionError:
                    pass  # Can't delete root-owned file

        # Restore dirs
        for d in self.dirs:
            backup = Path(self.backup_dir) / d
            dest = PROJECT_ROOT / d
            marker = backup / '.exists'

            if marker.exists():
                # Dir existed but we couldn't copy (permissions) - leave it alone
                pass
            elif backup.exists():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(backup, dest)
            elif dest.exists():
                # Backup didn't exist, so remove any created dir
                shutil.rmtree(dest)

        shutil.rmtree(self.backup_dir)

    def remove_file(self, name):
        """Remove a config file for testing"""
        path = PROJECT_ROOT / name
        if path.exists():
            path.unlink()

    def remove_dir(self, name):
        """Remove a directory for testing. Returns True if removed, False otherwise."""
        path = PROJECT_ROOT / name
        if path.exists():
            try:
                shutil.rmtree(path)
                return True
            except (PermissionError, shutil.Error):
                return False
        return True  # Didn't exist, so "removal" succeeded

    def create_minimal_wrangler(self):
        """Create wrangler.toml with unconfigured UUIDs"""
        content = '''name = "test"
main = "src/worker.js"
compatibility_date = "2024-01-01"

[vars]
LURE_UUID = "CHANGEME"
'''
        (PROJECT_ROOT / 'wrangler.toml').write_text(content)


# === Test Suites ===

def test_status_command():
    """Test status command error handling"""
    print(f"\n{Colors.BOLD}=== Status Command Tests ==={Colors.RESET}")
    passed = 0
    total = 0

    # Test 1: Status runs without error
    total += 1
    rc, out, err = run_cli('status')
    if test("status command runs", rc == 0):
        passed += 1

    # Test 2: Status shows banner
    total += 1
    if test("status shows banner", "TokenFlare" in out):
        passed += 1

    # Test 3: Status shows sections
    total += 1
    has_sections = all(s in out for s in ['Initialisation', 'SSL Certificates', 'CloudFlare', 'Campaign'])
    if test("status shows all sections", has_sections):
        passed += 1

    # Test 4: Status with missing wrangler.toml
    with ConfigBackup() as backup:
        backup.remove_file('wrangler.toml')
        total += 1
        rc, out, err = run_cli('status')
        if test("status handles missing wrangler.toml", rc == 0 and '[-]' in out):
            passed += 1

    # Test 5: Status with missing certs
    # Skip if certs are owned by root (can't remove as non-root)
    certs_dir = PROJECT_ROOT / 'certs'
    can_test_missing_certs = True
    if certs_dir.exists() and os.geteuid() != 0:
        # Check if files inside are owned by root
        for f in certs_dir.iterdir():
            try:
                if f.stat().st_uid == 0:
                    can_test_missing_certs = False
                    break
            except PermissionError:
                can_test_missing_certs = False
                break

    if can_test_missing_certs:
        with ConfigBackup() as backup:
            if backup.remove_dir('certs'):
                total += 1
                rc, out, err = run_cli('status')
                if test("status handles missing certs", rc == 0 and 'not found' in out.lower()):
                    passed += 1
            else:
                skip("status handles missing certs", "cannot remove certs dir")
    else:
        skip("status handles missing certs", "cannot remove certs dir (permission)")

    return passed, total


def test_deploy_local_validation():
    """Test deploy local validation (without actually running wrangler)"""
    print(f"\n{Colors.BOLD}=== Deploy Local Validation Tests ==={Colors.RESET}")
    passed = 0
    total = 0

    # Test 1: Requires root
    if os.geteuid() == 0:
        skip("deploy local requires root", "already running as root")
    else:
        total += 1
        rc, out, err = run_cli('deploy', 'local')
        if test("deploy local requires root", rc != 0 and 'root' in out.lower()):
            passed += 1

    # Test 2: Missing certs (need to run as root for this)
    if os.geteuid() != 0:
        skip("deploy local missing certs check", "requires root")
    else:
        with ConfigBackup() as backup:
            backup.remove_dir('certs')
            total += 1
            rc, out, err = run_cli('deploy', 'local')
            if test("deploy local checks for certs", rc != 0 and 'certificate' in out.lower()):
                passed += 1

    # Test 3: Unconfigured UUIDs (need root)
    if os.geteuid() != 0:
        skip("deploy local UUID check", "requires root")
    else:
        with ConfigBackup() as backup:
            backup.create_minimal_wrangler()
            total += 1
            rc, out, err = run_cli('deploy', 'local')
            if test("deploy local checks UUID config", rc != 0 and 'UUID' in out):
                passed += 1

    return passed, total


def test_deploy_remote_validation():
    """Test deploy remote validation"""
    print(f"\n{Colors.BOLD}=== Deploy Remote Validation Tests ==={Colors.RESET}")
    passed = 0
    total = 0

    # Test 1: Missing CloudFlare config
    with ConfigBackup() as backup:
        backup.remove_file('tokenflare.cfg')
        total += 1
        rc, out, err = run_cli('deploy', 'remote')
        if test("deploy remote requires CF config", rc != 0 and 'configure cf' in out.lower()):
            passed += 1

    # Test 2: Missing wrangler
    # Skip this - hard to test without messing with PATH

    return passed, total


def test_cli_help():
    """Test CLI help messages"""
    print(f"\n{Colors.BOLD}=== CLI Help Tests ==={Colors.RESET}")
    passed = 0
    total = 0

    # Test 1: Main help
    total += 1
    rc, out, err = run_cli('--help')
    if test("main help shows commands", 'init' in out and 'configure' in out and 'deploy' in out):
        passed += 1

    # Test 2: Configure without subcommand shows subcommand help
    total += 1
    rc, out, err = run_cli('configure')
    if test("configure shows subcommands", 'campaign' in out and 'cf' in out and 'ssl' in out):
        passed += 1

    # Test 3: Deploy without subcommand shows subcommand help
    total += 1
    rc, out, err = run_cli('deploy')
    if test("deploy shows subcommands", 'local' in out and 'remote' in out):
        passed += 1

    # Test 4: Version flag
    total += 1
    rc, out, err = run_cli('--version')
    if test("--version shows version", 'Version:' in out):
        passed += 1

    return passed, total


def test_init_command():
    """Test init command"""
    print(f"\n{Colors.BOLD}=== Init Command Tests ==={Colors.RESET}")
    passed = 0
    total = 0

    # Test 1: Init without domain
    total += 1
    rc, out, err = run_cli('init')
    if test("init requires domain argument", rc != 0):
        passed += 1

    # Test 2: Init requires root - just test that it runs successfully
    # (File creation is verified in manual testing)
    if os.geteuid() != 0:
        skip("init runs successfully", "requires root")
    else:
        total += 1
        rc, out, err = run_cli('init', 'test.example.com')
        if test("init runs successfully", rc == 0 and 'complete' in out.lower()):
            passed += 1

    return passed, total


# === Main ===

def main():
    print(f"{Colors.BOLD}")
    print("=" * 60)
    print("TokenFlare - Automated Tests")
    print("=" * 60)
    print(f"{Colors.RESET}")

    if os.geteuid() == 0:
        print(f"{Colors.YELLOW}Running as root - all tests will execute{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}Not root - some tests will be skipped{Colors.RESET}")
        print(f"Run with sudo for full test coverage\n")

    total_passed = 0
    total_tests = 0

    # Run test suites
    suites = [
        test_cli_help,
        test_status_command,
        test_init_command,
        test_deploy_local_validation,
        test_deploy_remote_validation,
    ]

    for suite in suites:
        passed, total = suite()
        total_passed += passed
        total_tests += total

    # Summary
    print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    if total_passed == total_tests:
        print(f"{Colors.GREEN}All {total_tests} tests passed!{Colors.RESET}")
    else:
        print(f"{Colors.RED}Passed: {total_passed}/{total_tests}{Colors.RESET}")
    print()

    return 0 if total_passed == total_tests else 1


if __name__ == '__main__':
    sys.exit(main())
