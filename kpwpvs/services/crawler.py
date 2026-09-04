#!/usr/bin/env python3
"""
Crawler Service Module

Walks the wordpress.org plugin catalog into our database. The first run
seeds the whole thing, checkpointing as it goes so an interruption does
not cost the whole crawl. After that it only walks far enough back to
catch what has changed.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from kpwpvs.models import CrawlCheckpoint, Plugin, PluginStatus, PluginTag, PluginVersion
from kpwpvs.services.settings_service import SettingsService
from kpwpvs.sources.wporg import PluginRecord, WporgClient
from kpwpvs.utils.version import sort_key

logger = logging.getLogger(__name__)

# the two kinds of walk, kept as checkpoint keys
SEED = "seed"
INCREMENTAL = "incremental"


class CrawlStats:
    """
    Running counts for one crawl

    Handed back to the caller and folded into the run record.
    """

    def __init__(self) -> None:
        """
        Start every counter at zero

        @return None
        """

        self.pages = 0
        self.seen = 0
        self.added = 0
        self.updated = 0
        self.unchanged = 0
        self.versions_added = 0
        self.marked_abandoned = 0

    def as_dict(self) -> dict[str, int]:
        """
        The counters as a plain dictionary

        @return dict: Every counter, keyed by name
        """

        return {
            "pages": self.pages,
            "seen": self.seen,
            "added": self.added,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "versions_added": self.versions_added,
            "marked_abandoned": self.marked_abandoned,
        }


class Crawler:
    """
    Pulls the wordpress.org catalog into the database

    Deliberately synchronous at the database layer and async only at the
    http layer, which keeps the session handling simple.
    """

    def __init__(self, session: Session, settings: SettingsService) -> None:
        """
        Build a crawler

        @param session: Session The database session to write through
        @param settings: SettingsService Where the crawler settings come from
        """

        self._session = session
        self._settings = settings
        self._config = settings.get_many("crawler")

    def _checkpoint(self, kind: str) -> CrawlCheckpoint:
        """
        Get or create the checkpoint for a crawl kind

        @param kind: str Either seed or incremental
        @return CrawlCheckpoint: The checkpoint row
        """

        # find it, or start one
        checkpoint = self._session.execute(
            select(CrawlCheckpoint).where(CrawlCheckpoint.kind == kind)
        ).scalar_one_or_none()

        if checkpoint is None:
            checkpoint = CrawlCheckpoint(kind=kind)
            self._session.add(checkpoint)
            self._session.flush()

        return checkpoint

    def _upsert(self, record: PluginRecord, stats: CrawlStats, now: datetime) -> None:
        """
        Insert or update one plugin from a catalog record

        Only writes when something actually changed, so a weekly crawl
        over a mostly static catalog does not churn every row.

        @param record: PluginRecord The cleaned record from the api
        @param stats: CrawlStats The running counters to update
        @param now: datetime The timestamp to stamp this crawl with
        @return None
        """

        # find it by slug, that is the identity
        plugin = self._session.execute(select(Plugin).where(Plugin.slug == record.slug)).scalar_one_or_none()

        # brand new to us
        if plugin is None:
            plugin = Plugin(slug=record.slug, first_seen=now, status=PluginStatus.ACTIVE)
            self._session.add(plugin)
            stats.added += 1
            is_new = True
        else:
            is_new = False

        # has anything we care about actually moved
        changed = (
            plugin.version != record.version
            or plugin.last_updated != record.last_updated
            or plugin.active_installs != record.active_installs
            or plugin.name != record.name
        )

        # the catalog fields, always refreshed, they are cheap
        plugin.name = record.name
        plugin.version = record.version
        plugin.version_key = sort_key(record.version) if record.version else None
        plugin.author = record.author
        plugin.author_profile = record.author_profile
        plugin.homepage = record.homepage
        plugin.download_link = record.download_link
        plugin.short_description = record.short_description
        plugin.requires_wp = record.requires_wp
        plugin.tested_wp = record.tested_wp
        plugin.requires_php = record.requires_php
        plugin.rating = record.rating
        plugin.num_ratings = record.num_ratings
        plugin.active_installs = record.active_installs
        plugin.downloaded = record.downloaded
        plugin.support_threads = record.support_threads
        plugin.support_threads_resolved = record.support_threads_resolved
        plugin.added_on = record.added_on
        plugin.last_updated = record.last_updated
        plugin.last_seen = now
        plugin.last_crawled = now

        # something that is back in the catalog is no longer missing
        if plugin.status in (PluginStatus.MISSING, PluginStatus.CLOSED):
            plugin.status = PluginStatus.ACTIVE
            plugin.closed_reason = None
            plugin.closed_at = None

        # a plugin nobody has touched in a long while is worth flagging on
        # its own, it will never be patched no matter what turns up in it
        abandoned_days = self._config.get("abandoned_after_days", 730)
        if record.last_updated and record.last_updated < now - timedelta(days=abandoned_days):
            if plugin.status is PluginStatus.ACTIVE:
                plugin.status = PluginStatus.ABANDONED
                stats.marked_abandoned += 1
        elif plugin.status is PluginStatus.ABANDONED:
            plugin.status = PluginStatus.ACTIVE

        # we need the id before anything can hang off it
        self._session.flush()

        # record the version if this one is new to us
        if record.version:
            self._record_version(plugin, record, stats, now)

        # and keep the tags in step
        self._sync_tags(plugin, record)

        # count it
        if is_new:
            pass
        elif changed:
            stats.updated += 1
        else:
            stats.unchanged += 1

    def _record_version(self, plugin: Plugin, record: PluginRecord, stats: CrawlStats, now: datetime) -> None:
        """
        Note the currently published version of a plugin

        We only ever see the current version through the api, so the
        version history builds up over time as the catalog moves.

        @param plugin: Plugin The plugin row
        @param record: PluginRecord The record from the api
        @param stats: CrawlStats The running counters to update
        @param now: datetime The timestamp to stamp this crawl with
        @return None
        """

        # look for this exact version
        existing = self._session.execute(
            select(PluginVersion).where(
                PluginVersion.plugin_id == plugin.id,
                PluginVersion.version == record.version,
            )
        ).scalar_one_or_none()

        # new to us, so record it and demote whatever was current
        if existing is None:
            self._session.execute(
                PluginVersion.__table__.update()
                .where(PluginVersion.plugin_id == plugin.id)
                .values(is_current=False)
            )
            self._session.add(
                PluginVersion(
                    plugin_id=plugin.id,
                    version=record.version,
                    version_key=sort_key(record.version),
                    download_link=record.download_link,
                    is_current=True,
                    released_at=record.last_updated,
                    first_seen=now,
                )
            )
            stats.versions_added += 1
            return

        # already known, just make sure it is flagged as the current one
        if not existing.is_current:
            self._session.execute(
                PluginVersion.__table__.update()
                .where(PluginVersion.plugin_id == plugin.id)
                .values(is_current=False)
            )
            existing.is_current = True

    def _sync_tags(self, plugin: Plugin, record: PluginRecord) -> None:
        """
        Bring a plugin's tags in line with the catalog

        @param plugin: Plugin The plugin row
        @param record: PluginRecord The record from the api
        @return None
        """

        # what we have against what the api says
        existing = {row.tag for row in plugin.tags}
        incoming = set(record.tags)

        # add the new ones
        for tag in incoming - existing:
            self._session.add(PluginTag(plugin_id=plugin.id, tag=tag))

        # and drop the ones that went away
        for row in list(plugin.tags):
            if row.tag not in incoming:
                self._session.delete(row)

    def _build_client(self) -> WporgClient:
        """
        Build an api client from the current settings

        @return WporgClient: A configured client
        """

        return WporgClient(
            user_agent=self._config.get("user_agent", "kp-wp-vulnscan"),
            timeout=self._config.get("request_timeout", 30),
            max_retries=self._config.get("max_retries", 3),
            retry_backoff=self._config.get("retry_backoff", 2.0),
            rate_limit_delay=self._config.get("rate_limit_delay", 0.25),
        )

    async def crawl(self, full: bool = False, max_pages: int | None = None) -> CrawlStats:
        """
        Walk the catalog and bring the database in line with it

        A full crawl walks every page. An incremental one walks the
        updated ordering only until it reaches plugins we have already
        seen, which on a weekly cadence is a handful of pages.

        @param full: bool Force a full seed crawl
        @param max_pages: int|None Stop after this many pages, for testing
        @return CrawlStats: What the crawl did
        """

        stats = CrawlStats()
        now = datetime.now()

        # a seed that never finished resumes rather than starting over
        seed = self._checkpoint(SEED)
        resuming = not seed.completed and seed.page > 0
        is_seed = full or not seed.completed

        # work out where to start and when to stop
        if is_seed:
            checkpoint = seed
            start_page = seed.page + 1 if resuming and not full else 1
            stop_at = None
            if full and not resuming:
                checkpoint.high_water_mark = None
            logger.info("running a %s seed crawl from page %s", "resumed" if resuming else "full", start_page)
        else:
            checkpoint = self._checkpoint(INCREMENTAL)
            start_page = 1
            stop_at = checkpoint.high_water_mark or seed.high_water_mark
            logger.info("running an incremental crawl back to %s", stop_at or "the beginning")

        # reset the checkpoint for a fresh start
        if start_page == 1:
            checkpoint.started_at = now
            checkpoint.completed = False
            checkpoint.processed = 0
            checkpoint.last_error = None

        per_page = self._config.get("per_page", 250)
        concurrency = self._config.get("concurrency", 4)
        checkpoint_every = self._config.get("checkpoint_every", 5)

        # the newest timestamp this crawl saw, which becomes the next
        # incremental crawl's stopping point
        newest: datetime | None = None
        reached_known = False

        async with self._build_client() as client:
            total_pages, _ = await client.page_count(per_page=per_page)
            checkpoint.total_pages = total_pages

            async for page, records in client.iter_pages(
                start_page=start_page,
                per_page=per_page,
                concurrency=concurrency,
            ):
                stats.pages += 1

                # walk the page, oldest api ordering is newest first
                for record in records:
                    stats.seen += 1

                    # track the newest timestamp we have seen this run
                    if record.last_updated and (newest is None or record.last_updated > newest):
                        newest = record.last_updated

                    # on an incremental crawl, once we reach something older
                    # than our high water mark there is nothing new behind it
                    if stop_at and record.last_updated and record.last_updated <= stop_at:
                        reached_known = True
                        continue

                    self._upsert(record, stats, now)

                checkpoint.page = page
                checkpoint.processed = stats.seen

                # write the checkpoint out periodically so an interruption
                # costs a few pages rather than the whole crawl
                if stats.pages % checkpoint_every == 0:
                    self._session.commit()
                    logger.info(
                        "page %s/%s, %s seen, %s added, %s updated",
                        page,
                        total_pages,
                        stats.seen,
                        stats.added,
                        stats.updated,
                    )

                # an incremental crawl stops as soon as it catches up
                if reached_known and not is_seed:
                    logger.info("caught up with the catalog at page %s", page)
                    break

                # and a bounded run stops where it was told to
                if max_pages and stats.pages >= max_pages:
                    logger.info("stopping after %s pages as instructed", max_pages)
                    break

        # a crawl that walked the whole thing has completed the seed
        walked_everything = checkpoint.page >= total_pages and not max_pages
        if walked_everything or (reached_known and not is_seed):
            checkpoint.completed = True
            checkpoint.finished_at = datetime.now()

        # move the high water mark up, but only on a crawl that finished,
        # otherwise a partial run would skip whatever it never reached
        if newest and checkpoint.completed:
            checkpoint.high_water_mark = newest
            if is_seed:
                seed.high_water_mark = newest

        self._session.commit()
        logger.info(
            "crawl finished: %s pages, %s seen, %s added, %s updated, %s unchanged",
            stats.pages,
            stats.seen,
            stats.added,
            stats.updated,
            stats.unchanged,
        )

        return stats
