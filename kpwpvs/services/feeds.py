#!/usr/bin/env python3
"""
Feed Service Module

Pulls every enabled vulnerability feed and folds what comes back into
the database. Feeds are rows, so which ones run, in what order, and
against what endpoint is all configuration rather than code.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from collections.abc import Iterator
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from kpwpvs.core.crypto import SecretBox
from kpwpvs.models import (
    Feed,
    FeedSource,
    Vulnerability,
    VulnerabilityAffect,
)
from kpwpvs.sources.base import VulnRecord
from kpwpvs.sources.cve import CveClient
from kpwpvs.sources.nvd import NvdClient
from kpwpvs.sources.wordfence import FeedThrottled, FeedUnauthorized, WordfenceClient

logger = logging.getLogger(__name__)

# how many records to write before committing, keeps the transaction from
# growing unbounded across a forty thousand record feed
COMMIT_EVERY = 500


class FeedStats:
    """
    Running counts for one feed's sync

    Folded into the feed row and the run record when the sync finishes.
    """

    def __init__(self) -> None:
        """
        Start every counter at zero

        @return None
        """

        self.seen = 0
        self.added = 0
        self.updated = 0
        self.unchanged = 0
        self.affects = 0
        self.skipped = 0

    def as_dict(self) -> dict[str, int]:
        """
        The counters as a plain dictionary

        @return dict: Every counter, keyed by name
        """

        return {
            "seen": self.seen,
            "added": self.added,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "affects": self.affects,
            "skipped": self.skipped,
        }


class FeedService:
    """
    Syncs the vulnerability feeds into the database

    Each feed is pulled independently, so one being down or unkeyed does
    not stop the others.
    """

    def __init__(self, session: Session, secret_box: SecretBox | None = None) -> None:
        """
        Build a feed service

        @param session: Session The database session to write through
        @param secret_box: SecretBox|None Needed to read the stored api keys
        """

        self._session = session
        self._secret_box = secret_box

    def enabled_feeds(self) -> list[Feed]:
        """
        Every enabled feed, in priority order

        @return list[Feed]: The feeds to sync, most trusted first
        """

        return list(self._session.execute(select(Feed).where(Feed.enabled.is_(True)).order_by(Feed.priority)).scalars())

    def _api_key(self, feed: Feed) -> str:
        """
        Decrypt a feed's stored api key

        @param feed: Feed The feed row
        @return str: The plaintext key, empty when none is stored
        """

        # nothing stored, nothing to decrypt
        if not feed.api_key_encrypted:
            return ""

        # a key is stored but we have no way to read it
        if self._secret_box is None:
            logger.warning("feed %s has a stored key but no secret key is configured", feed.source.value)
            return ""

        return self._secret_box.decrypt(feed.api_key_encrypted)

    def _records_for(self, feed: Feed) -> Iterator[VulnRecord]:
        """
        Build the right client for a feed and hand back its records

        @param feed: Feed The feed row
        @return Iterator[VulnRecord]: Whatever that feed produces
        @throws ValueError: When the feed names a source we cannot handle
        """

        options = feed.options or {}
        api_key = self._api_key(feed)

        # the primary, the only one that carries slugs outright
        if feed.source is FeedSource.WORDFENCE:
            if not api_key:
                logger.error("wordfence needs an api key, set one on the feeds page")
                return iter(())
            return WordfenceClient(feed.url, api_key, feed.timeout).fetch()

        # the secondary, walked by modification window
        if feed.source is FeedSource.NVD:
            return NvdClient(feed.url, api_key, feed.timeout).fetch(
                since=feed.last_success_at,
                lookback_days=options.get("lookback_days", 14),
            )

        # the tertiary, which enriches cve ids the others already found
        if feed.source is FeedSource.CVE:
            return CveClient(feed.url, feed.timeout).fetch_many(self._cve_ids_needing_enrichment())

        raise ValueError(f"no client for feed source {feed.source}")

    def _known_cve_ids(self) -> set[str]:
        """
        Every cve id we already hold from a higher priority source

        Used to decide whether a record from a secondary feed is worth
        keeping. NVD carries every cve there is, the overwhelming
        majority of which have nothing to do with WordPress.

        @return set[str]: The cve ids we already know about
        """

        rows = self._session.execute(
            select(Vulnerability.cve).where(Vulnerability.cve.is_not(None)).distinct()
        ).scalars()

        return {cve for cve in rows if cve}

    def _is_relevant(self, source: FeedSource, record: VulnRecord, known_cves: set[str]) -> bool:
        """
        Decide whether a record from a secondary feed is worth storing

        The primary feed is WordPress only by definition, so everything
        it hands us is relevant. The secondary feeds are not, so a record
        earns its place by naming a plugin we can identify, or by adding
        to a cve some other feed already tied to one.

        @param source: FeedSource Which feed this came from
        @param record: VulnRecord The normalized record
        @param known_cves: set[str] Cve ids we already hold
        @return bool: True when the record should be stored
        """

        # everything wordfence sends is WordPress by definition
        if source is FeedSource.WORDFENCE:
            return True

        # it named a plugin we could identify, that is relevant on its own
        if record.affects:
            return True

        # or it adds detail to something another feed already found
        return bool(record.cve and record.cve in known_cves)

    def _cve_ids_needing_enrichment(self, limit: int = 500) -> list[str]:
        """
        CVE ids worth pulling from CVE Services

        Records we already hold that are missing scoring or a weakness
        classification. In practice wordfence leaves very few gaps, so
        this feed earns its place mainly as the keyless fallback for when
        the primary is unavailable rather than as an enrichment pass.

        @param limit: int How many to fetch in one run
        @return list[str]: The cve ids to look up
        """

        # anything we know the id of but never got a score for
        rows = self._session.execute(
            select(Vulnerability.cve)
            .where(
                Vulnerability.cve.is_not(None),
                or_(Vulnerability.cvss_score.is_(None), Vulnerability.cwe_id.is_(None)),
                Vulnerability.source != FeedSource.CVE,
            )
            .distinct()
            .limit(limit)
        ).scalars()

        return [cve for cve in rows if cve]

    def _upsert(self, source: FeedSource, record: VulnRecord, stats: FeedStats, now: datetime) -> None:
        """
        Insert or update one vulnerability and its affected ranges

        @param source: FeedSource Which feed this came from
        @param record: VulnRecord The normalized record
        @param stats: FeedStats The running counters to update
        @param now: datetime The timestamp to stamp this sync with
        @return None
        """

        # find it by source and the source's own id
        vulnerability = self._session.execute(
            select(Vulnerability).where(
                Vulnerability.source == source,
                Vulnerability.source_id == record.source_id,
            )
        ).scalar_one_or_none()

        # new to us
        if vulnerability is None:
            vulnerability = Vulnerability(
                source=source,
                source_id=record.source_id,
                first_seen=now,
            )
            self._session.add(vulnerability)
            stats.added += 1
            is_new = True
        else:
            is_new = False

        # has the source changed it since we last looked
        changed = (
            vulnerability.source_updated_at != record.source_updated_at
            or vulnerability.cvss_score != record.cvss_score
            or vulnerability.title != record.title
        )

        # refresh the record itself
        vulnerability.cve = record.cve
        vulnerability.cve_link = record.cve_link
        vulnerability.title = record.title[:512]
        vulnerability.description = record.description
        vulnerability.cwe_id = record.cwe_id
        vulnerability.cwe_name = record.cwe_name
        vulnerability.cvss_score = record.cvss_score
        vulnerability.cvss_vector = record.cvss_vector
        vulnerability.severity = record.severity
        vulnerability.informational = record.informational
        vulnerability.references = record.references or None
        vulnerability.researchers = record.researchers or None
        vulnerability.copyright_notice = record.copyright_notice
        vulnerability.copyright_license = record.copyright_license
        vulnerability.published_at = record.published_at
        vulnerability.source_updated_at = record.source_updated_at
        vulnerability.last_seen = now

        # we need the id before the ranges can hang off it
        self._session.flush()

        # replace the ranges wholesale rather than diffing them, a record's
        # ranges are small and the source is the authority on them
        if is_new or changed:
            self._replace_affects(vulnerability, record, stats)

        # count it
        if is_new:
            pass
        elif changed:
            stats.updated += 1
        else:
            stats.unchanged += 1

    def _replace_affects(self, vulnerability: Vulnerability, record: VulnRecord, stats: FeedStats) -> None:
        """
        Replace a vulnerability's affected ranges

        Deduplicates as it goes, a cve that names the free, pro, and
        multisite editions of one plugin resolves to the same slug and
        the same range three times over.

        @param vulnerability: Vulnerability The row to attach ranges to
        @param record: VulnRecord The normalized record
        @param stats: FeedStats The running counters to update
        @return None
        """

        # clear what was there
        self._session.execute(
            VulnerabilityAffect.__table__.delete().where(VulnerabilityAffect.vulnerability_id == vulnerability.id)
        )

        # then write the current set, skipping exact duplicates
        seen: set[tuple] = set()
        for affect in record.affects:
            fingerprint = (
                affect.slug,
                affect.software_type,
                affect.from_version,
                affect.from_inclusive,
                affect.to_version,
                affect.to_inclusive,
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            self._session.add(
                VulnerabilityAffect(
                    vulnerability_id=vulnerability.id,
                    software_type=affect.software_type,
                    slug=affect.slug[:255],
                    software_name=affect.software_name,
                    from_version=affect.from_version,
                    from_inclusive=affect.from_inclusive,
                    to_version=affect.to_version,
                    to_inclusive=affect.to_inclusive,
                    from_key=affect.from_key,
                    to_key=affect.to_key,
                    patched=affect.patched,
                    patched_versions=affect.patched_versions or None,
                    remediation=affect.remediation,
                )
            )
            stats.affects += 1

    def sync_feed(self, feed: Feed) -> FeedStats:
        """
        Sync one feed into the database

        @param feed: Feed The feed row to sync
        @return FeedStats: What the sync did
        """

        stats = FeedStats()
        now = datetime.now()
        feed.last_sync_at = now

        logger.info("syncing the %s feed", feed.name)

        # what the higher priority feeds already gave us, so a secondary
        # feed's irrelevant records can be dropped rather than stored
        known_cves = set() if feed.source is FeedSource.WORDFENCE else self._known_cve_ids()

        # pull it, and record why if we cannot
        try:
            for record in self._records_for(feed):
                stats.seen += 1

                # a secondary feed's record has to earn its place
                if not self._is_relevant(feed.source, record, known_cves):
                    stats.skipped += 1
                    continue

                self._upsert(feed.source, record, stats, now)

                # commit periodically, these feeds are large
                if stats.seen % COMMIT_EVERY == 0:
                    self._session.commit()
                    logger.debug("%s: %s records processed", feed.source.value, stats.seen)

        except (FeedThrottled, FeedUnauthorized) as exc:
            # these are expected conditions with a clear cause, so they get
            # recorded plainly rather than as an unexplained failure
            self._session.rollback()
            feed = self._session.get(Feed, feed.id)
            feed.last_sync_at = now
            feed.last_error = str(exc)[:2000]
            self._session.commit()
            logger.warning("%s: %s", feed.name, exc)
            return stats

        except Exception as exc:
            self._session.rollback()

            # the feed row itself has to survive the rollback
            feed = self._session.get(Feed, feed.id)
            feed.last_sync_at = now
            feed.last_error = str(exc)[:2000]
            self._session.commit()

            logger.error("the %s feed failed: %s", feed.name, exc)
            return stats

        # it worked, so record that
        feed.last_success_at = now
        feed.last_error = None
        feed.record_count = stats.seen
        feed.added_count = stats.added
        feed.updated_count = stats.updated
        self._session.commit()

        logger.info(
            "%s: %s records, %s new, %s updated, %s unchanged, %s ranges",
            feed.source.value,
            stats.seen,
            stats.added,
            stats.updated,
            stats.unchanged,
            stats.affects,
        )

        return stats

    def sync_all(self) -> dict[str, FeedStats]:
        """
        Sync every enabled feed, in priority order

        One feed failing does not stop the rest, which matters when the
        primary needs a key somebody has not set yet.

        @return dict: Each feed's stats, keyed by source
        """

        results: dict[str, FeedStats] = {}

        # most trusted first
        feeds = self.enabled_feeds()
        if not feeds:
            logger.warning("no feeds are enabled, there is nothing to sync")
            return results

        for feed in feeds:
            results[feed.source.value] = self.sync_feed(feed)

        return results
