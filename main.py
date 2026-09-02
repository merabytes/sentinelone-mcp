#!/usr/bin/env python3
"""
main.py — SentinelOne MCP entry point.

Usage:
    python main.py              # Start FastMCP server (stdio)
    python -m sentinelone_mcp   # Same
    python main.py --mode login # Legacy CLI: refresh session cookies
"""

import argparse
import logging
import os
import sys

# SOC L2 desktop — headed Playwright Chromium must stay on :6 across MCP restarts.
os.environ["DISPLAY"] = ":6"
_xauth = "/tmp/s1_xauth_display6"
if os.path.exists(_xauth):
    os.environ["XAUTHORITY"] = _xauth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)

MODES = ["login", "create_alert", "mcp"]


def _apply_purple_display() -> None:
    """Hard-lock headed Chromium to SOC L2 desktop DISPLAY=:6."""
    from pathlib import Path
    Path("/workspace/sentinelone-mcp/purple_display.env").write_text(":6\n")
    os.environ["DISPLAY"] = ":6"
    os.environ["PURPLE_DISPLAY"] = ":6"
    xauth = "/tmp/s1_xauth_display6"
    if Path(xauth).is_file():
        os.environ["XAUTHORITY"] = xauth


def main():
    _apply_purple_display()
    parser = argparse.ArgumentParser(description="SentinelOne MCP")
    parser.add_argument(
        "--mode",
        choices=MODES,
        default="mcp",
        help=f"Mode: {', '.join(MODES)} (default: mcp)",
    )
    args = parser.parse_args()

    if args.mode == "mcp":
        from sentinelone_mcp.server import main as mcp_main
        mcp_main()
        return

    logger.info("=" * 60)
    logger.info("SentinelOne — mode: %s", args.mode)
    logger.info("=" * 60)

    if args.mode == "login":
        from login import run_login_all_tenants
        run_login_all_tenants()
    elif args.mode == "create_alert":
        from create_alert import run_create_alert_mode
        run_create_alert_mode(once=True)
    else:
        logger.error("Unknown mode: %s", args.mode)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
        sys.exit(1)
