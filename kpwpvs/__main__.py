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
import time

from kpwpvs import __version__
from kpwpvs.core.config import BootstrapConfig, load_config
from kpwpvs.core.db import ping
from kpwpvs.core.logging import setup_logging
from kpwpvs.core.migrate import current_revision, downgrade, head_revision, upgrade

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
    db.add_argument(
        "action",
        choices=["upgrade", "downgrade", "status", "wait"],
        help="what to do to the schema",
    )
    db.add_argument("--revision", default="head", help="target revision, defaults to head")
    db.add_argument("--timeout", type=int, default=60, help="seconds to wait, for the wait action")

    # the web interface
    web = sub.add_parser("web", help="run the web interface")
    web.add_argument("--host", help="override the configured bind address")
    web.add_argument("--port", type=int, help="override the configured bind port")

    # hand back the parser
    return parser


def handle_db(config: BootstrapConfig, args: argparse.Namespace) -> int:
    """
    Handle the database schema subcommand

    Covers bringing the schema up, rolling it back, reporting where it
    stands, and waiting for the server to accept connections.

    @param config: BootstrapConfig The bootstrap configuration
    @param args: argparse.Namespace The parsed command line arguments
    @return int: The process exit code, zero on success
    """

    # the entrypoint calls this before anything else, the server takes a
    # moment to come up and there is no point failing over that
    if args.action == "wait":
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            if ping(config):
                logger.info("database is accepting connections")
                return 0
            time.sleep(1)
        logger.error("database did not come up within %s seconds", args.timeout)
        return 1

    # everything else needs the database reachable right now
    if not ping(config):
        logger.error("cannot reach the database at %s:%s", config.database.host, config.database.port)
        return 1

    # where the schema stands
    if args.action == "status":
        current = current_revision(config)
        head = head_revision(config)
        logger.info("schema revision %s, head is %s", current or "empty", head or "none")
        if current == head:
            logger.info("schema is up to date")
            return 0
        logger.warning("schema is behind, run 'kpwpvs db upgrade'")
        return 1

    # bring it up
    if args.action == "upgrade":
        upgrade(config, args.revision)
        return 0

    # or roll it back, which needs an explicit target
    if args.action == "downgrade":
        if args.revision == "head":
            logger.error("downgrade needs an explicit --revision, refusing to guess")
            return 1
        downgrade(config, args.revision)
        return 0

    # argparse should have caught anything else
    logger.error("unknown db action '%s'", args.action)
    return 1


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

    # the environment gives us the database connection, everything else
    # gets read out of the settings table once we are connected
    try:
        config = load_config()
    except Exception as exc:
        print(f"failed to load configuration: {exc}", file=sys.stderr)
        return 1

    # the command line debug flag forces debug on regardless of config
    setup_logging(config.debug or args.debug)
    logger.debug("configuration loaded, running command %s", args.command)

    # dispatch to the handler
    if args.command == "db":
        return handle_db(config, args)

    # the pipeline stages land here as each one is built
    logger.error("command '%s' is not implemented yet", args.command)
    return 1


# run it when called directly
if __name__ == "__main__":
    sys.exit(main())
