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
import asyncio
import logging
import sys
import time

from kpwpvs import __version__
from sqlalchemy import select

from kpwpvs.core.config import BootstrapConfig, load_config
from kpwpvs.core.crypto import SecretBox
from kpwpvs.core.db import init_engine, ping, session_scope
from kpwpvs.core.logging import setup_logging
from kpwpvs.core.migrate import current_revision, downgrade, head_revision, is_current, upgrade
from kpwpvs.models import Feed, RunStatus, RunTrigger
from kpwpvs.services.crawler import Crawler
from kpwpvs.services.feeds import FeedService
from kpwpvs.services.matcher import Matcher
from kpwpvs.services.pipeline import Pipeline
from kpwpvs.services.reporter import Reporter
from kpwpvs.services.settings_service import SettingsService

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
    scan = sub.add_parser("scan", help="run the full pipeline, crawl then feeds then match then report")
    scan.add_argument("--full", action="store_true", help="force a full seed crawl rather than incremental")

    # pull the wordpress.org plugin catalog
    crawl = sub.add_parser("crawl", help="crawl the wordpress.org plugin repository")
    crawl.add_argument("--full", action="store_true", help="force a full seed crawl instead of incremental")
    crawl.add_argument("--max-pages", type=int, help="stop after this many pages, for a quick look")
    crawl.add_argument("--core-only", action="store_true", help="only refresh the core release history")
    crawl.add_argument("--skip-core", action="store_true", help="skip the core release history")

    # refresh the vulnerability feeds
    feeds = sub.add_parser("feeds", help="refresh the vulnerability feeds")
    feeds.add_argument("--source", help="sync only this one feed, by source name")
    feeds.add_argument("--list", action="store_true", help="list the configured feeds and exit")
    feeds.add_argument("--set-key", metavar="SOURCE", help="store an api key for a feed, read from stdin")

    # match the feeds against the catalog
    sub.add_parser("match", help="match known vulnerabilities against the plugin catalog")

    # generate the reports for the latest run
    report = sub.add_parser("report", help="generate reports without running the pipeline")
    report.add_argument("--stdout", action="store_true", help="write the html to stdout instead of to disk")

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


def handle_crawl(config: BootstrapConfig, args: argparse.Namespace) -> int:
    """
    Handle the catalog crawl subcommand

    Walks the wordpress.org plugin repository into the database, seeding
    it on the first run and only catching up on every run after.

    @param config: BootstrapConfig The bootstrap configuration
    @param args: argparse.Namespace The parsed command line arguments
    @return int: The process exit code, zero on success
    """

    # the schema has to be current before we write anything to it
    if not ping(config):
        logger.error("cannot reach the database at %s:%s", config.database.host, config.database.port)
        return 1
    if not is_current(config):
        logger.error("database schema is out of date, run 'kpwpvs db upgrade' first")
        return 1

    init_engine(config)

    # run it, the http side is async and the database side is not
    try:
        with session_scope() as session:
            crawler = Crawler(session, SettingsService(session))

            # core first, it is the one that matters most and it is cheap
            if not args.skip_core:
                crawler.crawl_core()

            if args.core_only:
                return 0

            stats = asyncio.run(crawler.crawl(full=args.full, max_pages=args.max_pages))
    except Exception as exc:
        logger.error("crawl failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
        return 1

    # say what happened, in something a human can read
    logger.info(
        "%s plugins seen, %s new, %s updated, %s unchanged, %s new versions",
        stats.seen,
        stats.added,
        stats.updated,
        stats.unchanged,
        stats.versions_added,
    )

    return 0


def handle_feeds(config: BootstrapConfig, args: argparse.Namespace) -> int:
    """
    Handle the vulnerability feed subcommand

    Lists the configured feeds, stores an api key for one, or syncs them.

    @param config: BootstrapConfig The bootstrap configuration
    @param args: argparse.Namespace The parsed command line arguments
    @return int: The process exit code, zero on success
    """

    # the schema has to be current before we touch anything
    if not ping(config):
        logger.error("cannot reach the database at %s:%s", config.database.host, config.database.port)
        return 1
    if not is_current(config):
        logger.error("database schema is out of date, run 'kpwpvs db upgrade' first")
        return 1

    init_engine(config)

    # the secret box is only buildable once a secret key is configured
    secret_box = None
    try:
        secret_box = SecretBox(config.secret_key)
    except ValueError:
        logger.warning("no secret key configured, stored api keys cannot be read")

    with session_scope() as session:
        service = FeedService(session, secret_box)

        # just show what is configured
        if args.list:
            for feed in session.execute(select(Feed).order_by(Feed.priority)).scalars():
                logger.info(
                    "%-10s priority %-4s %-9s key %-3s  %s",
                    feed.source.value,
                    feed.priority,
                    "enabled" if feed.enabled else "disabled",
                    "yes" if feed.has_api_key else "no",
                    feed.url,
                )
            return 0

        # store a key, read from stdin so it never lands in the shell history
        if args.set_key:
            if secret_box is None:
                logger.error("set KPWPVS_SECRET_KEY before storing an api key")
                return 1

            feed = session.execute(select(Feed).where(Feed.source == args.set_key)).scalar_one_or_none()
            if feed is None:
                logger.error("no feed named '%s'", args.set_key)
                return 1

            key = sys.stdin.readline().strip()
            if not key:
                logger.error("nothing on stdin, no key stored")
                return 1

            feed.api_key_encrypted = secret_box.encrypt(key)
            session.commit()
            logger.info("stored an api key for %s", feed.source.value)
            return 0

        # otherwise sync, either one feed or all of them
        if args.source:
            feed = session.execute(select(Feed).where(Feed.source == args.source)).scalar_one_or_none()
            if feed is None:
                logger.error("no feed named '%s'", args.source)
                return 1
            results = {feed.source.value: service.sync_feed(feed)}
        else:
            results = service.sync_all()

    # report what happened, and fail the command if nothing worked at all
    if not results:
        return 1

    for source, stats in results.items():
        logger.info("%s: %s", source, stats.as_dict())

    return 0


def handle_match(config: BootstrapConfig, args: argparse.Namespace) -> int:
    """
    Handle the matching subcommand

    Joins the vulnerability feeds onto the catalog, opens and resolves
    findings, and reranks everything.

    @param config: BootstrapConfig The bootstrap configuration
    @param args: argparse.Namespace The parsed command line arguments
    @return int: The process exit code, zero on success
    """

    # the schema has to be current before we touch anything
    if not ping(config):
        logger.error("cannot reach the database at %s:%s", config.database.host, config.database.port)
        return 1
    if not is_current(config):
        logger.error("database schema is out of date, run 'kpwpvs db upgrade' first")
        return 1

    init_engine(config)

    # run the pass
    try:
        with session_scope() as session:
            matcher = Matcher(session, SettingsService(session))
            stats = matcher.match()
    except Exception as exc:
        logger.error("matching failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
        return 1

    logger.info("%s", stats.as_dict())

    return 0


def _ready(config: BootstrapConfig) -> bool:
    """
    Check the database is reachable and the schema is current

    @param config: BootstrapConfig The bootstrap configuration
    @return bool: True when it is safe to proceed
    """

    # nothing works without these two
    if not ping(config):
        logger.error("cannot reach the database at %s:%s", config.database.host, config.database.port)
        return False
    if not is_current(config):
        logger.error("database schema is out of date, run 'kpwpvs db upgrade' first")
        return False

    return True


def _secret_box(config: BootstrapConfig) -> SecretBox | None:
    """
    Build a secret box, or explain why we cannot

    @param config: BootstrapConfig The bootstrap configuration
    @return SecretBox|None: The secret box, when a key is configured
    """

    # without a key the stored api keys are unreadable, which is worth
    # saying out loud rather than failing mysteriously later
    try:
        return SecretBox(config.secret_key)
    except ValueError:
        logger.warning("no secret key configured, stored api keys cannot be read")
        return None


def handle_report(config: BootstrapConfig, args: argparse.Namespace) -> int:
    """
    Handle the reporting subcommand

    Builds a report from what is already in the database, without
    running any of the pipeline stages first.

    @param config: BootstrapConfig The bootstrap configuration
    @param args: argparse.Namespace The parsed command line arguments
    @return int: The process exit code, zero on success
    """

    if not _ready(config):
        return 1

    init_engine(config)

    try:
        with session_scope() as session:
            reporter = Reporter(session, SettingsService(session, _secret_box(config)))

            # straight to stdout, handy for piping somewhere else
            if args.stdout:
                print(reporter.render_html(reporter.build_payload()))
                return 0

            payload = reporter.generate()

    except Exception as exc:
        logger.error("reporting failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
        return 1

    core = payload["core"]
    logger.info(
        "core %s with %s issue(s) in the current release, %s open plugin finding(s)",
        core.get("current_version", "unknown"),
        core.get("current_issue_count", 0),
        payload["findings"]["plugin_total"],
    )

    return 0


def handle_scan(config: BootstrapConfig, args: argparse.Namespace) -> int:
    """
    Handle the full pipeline subcommand

    This is what cron calls. Every stage runs, a failing one is recorded
    rather than abandoning the rest.

    @param config: BootstrapConfig The bootstrap configuration
    @param args: argparse.Namespace The parsed command line arguments
    @return int: Zero when everything worked, one when anything did not
    """

    if not _ready(config):
        return 1

    init_engine(config)

    try:
        with session_scope() as session:
            secret_box = _secret_box(config)
            pipeline = Pipeline(session, SettingsService(session, secret_box), secret_box)
            run = pipeline.run(trigger=RunTrigger.CRON, full_crawl=args.full)
            status = run.status

    except Exception as exc:
        logger.error("the run failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
        return 1

    # a partial run is a non zero exit, cron should notice
    return 0 if status is RunStatus.SUCCESS else 1


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
    if args.command == "crawl":
        return handle_crawl(config, args)
    if args.command == "feeds":
        return handle_feeds(config, args)
    if args.command == "match":
        return handle_match(config, args)
    if args.command == "report":
        return handle_report(config, args)
    if args.command == "scan":
        return handle_scan(config, args)

    # the pipeline stages land here as each one is built
    logger.error("command '%s' is not implemented yet", args.command)
    return 1


# run it when called directly
if __name__ == "__main__":
    sys.exit(main())
