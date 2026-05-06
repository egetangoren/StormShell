#!/usr/bin/env python3
"""
StormShell — Lightweight Reverse Shell Handler

Entry point for the StormShell server.  Parses command-line arguments for
the listener host and port, then starts the TCP listener.
"""

import argparse
import logging
import sys

from server.listener import Listener

# ---------------------------------------------------------------------------
# Logging setup — default to INFO; override with -v / --verbose for DEBUG.
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def _parse_args() -> argparse.Namespace:
    """
    Build and return the argument parser for StormShell.

    Returns:
        argparse.Namespace with `host`, `port`, and `verbose` attributes.
    """
    parser = argparse.ArgumentParser(
        description="StormShell — Lightweight Reverse Shell Handler",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="IP address to listen on (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="TCP port to listen on (default: 4444)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose (DEBUG) logging output",
    )
    return parser.parse_args()


def main() -> None:
    """Parse arguments, configure logging, and start the listener."""
    args = _parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format=LOG_FORMAT)

    banner = r"""
   _____ __                        _____ __         ____
  / ___// /_____  _________ ___   / ___// /_  ___  / / /
  \__ \/ __/ __ \/ ___/ __ `__ \  \__ \/ __ \/ _ \/ / / 
 ___/ / /_/ /_/ / /  / / / / / / ___/ / / / /  __/ / /  
/____/\__/\____/_/  /_/ /_/ /_/ /____/_/ /_/\___/_/_/   
    """
    print(banner)
    print("  [ StormShell — Reverse Shell Handler ]\n")

    listener = Listener(host=args.host, port=args.port)
    listener.start()


if __name__ == "__main__":
    main()
