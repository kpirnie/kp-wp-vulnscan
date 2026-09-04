#!/usr/bin/env python3
"""
Command Line Entry Point

The single entry point for every mode the application runs in, the
weekly scan, the individual pipeline stages, and the web interface.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import argparse
import logging
import sys

from kpwpvs import __version__
from kpwpvs.core.config import load_config
from kpwpvs.core.logging import setup_logging

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command line argument parser

    Sets up the global arguments and every subcommand the application
    responds to.

    @return argparse.ArgumentParser: The configured argument parser
    """

    # the top level parser
    parser = argparse.ArgumentParser(
        prog="kpwpvs",
        description="WordPress plugin vulnerability scanner and reporter",
    )
    parser.add_argument("-c", "--config", help="path to the yaml config file")
    parser.add_argument("-d", "--debug", action="store_true", help="enable verbose debug logging")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    # every mode lives under a subcommand
    sub = parser.add_subparsers(dest="command", required=True)

    # the whole pipeline, this is what cron calls
    sub.add_parser("scan", help="run the full pipeline, crawl then feeds then match then report")

    # pull the wordpress.org plugin catalog
    crawl = sub.add_parser("crawl", help="crawl the wordpress.org plugin repository")
    crawl.add_argument("--full", action="store_true", help="force a full seed crawl instead of incremental")

    # refresh the vulnerability feeds
    sub.add_parser("feeds", help="refresh the vulnerability feeds")

    # match the feeds against the catalog
    sub.add_parser("match", help="match known vulnerabilities against the plugin catalog")

    # generate the reports for the latest run
    sub.add_parser("report", help="generate reports for the most recent run")

    # database schema management
    db = sub.add_parser("db", help="database schema management")
    db.add_argument("action", choices=["init", "upgrade", "status"], help="what to do to the schema")

    # the web interface
    web = sub.add_parser("web", help="run the web interface")
    web.add_argument("--host", help="override the configured bind address")
    web.add_argument("--port", type=int, help="override the configured bind port")

    # hand back the parser
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Application entry point

    Parses the command line, loads configuration, sets up logging, and
    dispatches to the requested subcommand.

    @param argv: list[str]|None Arguments to parse, defaults to sys.argv
    @return int: The process exit code, zero on success
    """

    # parse what we were given
    parser = build_parser()
    args = parser.parse_args(argv)

    # load the config before anything else needs it
    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"failed to load configuration: {exc}", file=sys.stderr)
        return 1

    # the command line debug flag forces debug on regardless of config
    setup_logging(config.debug or args.debug)
    logger.debug("configuration loaded, running command %s", args.command)

    # dispatch, the handlers land as each pipeline stage is built
    logger.error("command '%s' is not implemented yet", args.command)
    return 1


# run it when called directly
if __name__ == "__main__":
    sys.exit(main())
