"""VaultCat — entry point.

Delegates to the Typer CLI in ``cli.py``.  Backward-compatible shim:
``python main.py --target URL`` is automatically rewritten to
``python main.py scan --target URL``.
"""

from __future__ import annotations

import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Backward-compatible shim: old-style default-command invocations
# ---------------------------------------------------------------------------
# Before:  python main.py --target URL --token TOKEN --capability-audit
# After:   python main.py scan --target URL --token TOKEN --capability-audit
#
# We insert "scan" when the first argument is missing or starts with "-"
# (i.e. it looks like a flag, not a subcommand).

_KNOWN_COMMANDS = frozenset({"scan", "hijack", "chat", "cleanup", "mcp"})


def _apply_shim() -> None:
    """Insert the default ``scan`` command when no subcommand is given."""
    first = sys.argv[1] if len(sys.argv) > 1 else ""
    if not first or first.startswith("-") or first not in _KNOWN_COMMANDS:
        sys.argv.insert(1, "scan")


def main() -> None:
    """Entry point for ``vaultcat`` console script (pip install)."""
    _apply_shim()
    from vault_cli import app
    app()


if __name__ == "__main__":
    main()
