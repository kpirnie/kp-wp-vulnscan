#!/usr/bin/env python3
"""
Matcher Service Module

Joins the vulnerability feeds onto the catalog. Three jobs: bring in the
software the feeds know about but the free repository does not, work out
which catalogued versions are actually affected, and rank everything so
the expensive source scanning in phase two knows where to start.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
import math
from datetime import datetime

from sqlalchemy import bindparam, func, select, text
from sqlalchemy.orm import Session

from kpwpvs.models import (
    Finding,
    FindingEvent,
    FindingEventType,
    FindingStatus,
    Severity,
    Software,
    SoftwareStatus,
    SoftwareType,
    SoftwareVersion,
    Vulnerability,
    VulnerabilityAffect,
)
from kpwpvs.services.settings_service import SettingsService
from kpwpvs.utils.version import in_range

logger = logging.getLogger(__name__)

# what each severity contributes to a priority score. deliberately steep,
# one critical should outrank a pile of mediums
SEVERITY_POINTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
    Severity.NONE: 0.0,
}

# statuses that mean nobody is going to patch this, whatever turns up
UNMAINTAINED = (SoftwareStatus.ABANDONED, SoftwareStatus.CLOSED, SoftwareStatus.PREMIUM)

# how many rows to write between commits
COMMIT_EVERY = 1000


class MatchStats:
    """
    Running counts for one matching pass

    Folded into the run record when the pass finishes.
    """

    def __init__(self) -> None:
        """
        Start every counter at zero

        @return None
        """

        self.premium_added = 0
        self.candidates = 0
        self.matched = 0
        self.findings_opened = 0
        self.findings_updated = 0
        self.findings_resolved = 0
        self.scored = 0
        self.core_matched = 0

    def as_dict(self) -> dict[str, int]:
        """
        The counters as a plain dictionary

        @return dict: Every counter, keyed by name
        """

        return {
            "premium_added": self.premium_added,
            "candidates": self.candidates,
            "matched": self.matched,
            "findings_opened": self.findings_opened,
            "findings_updated": self.findings_updated,
            "findings_resolved": self.findings_resolved,
            "scored": self.scored,
            "core_matched": self.core_matched,
        }


class Matcher:
    """
    Ties vulnerabilities to catalogued software and ranks the result

    The heavy lifting is done in sql, python only sees the candidate
    pairs that survived a coarse version range filter.
    """

    def __init__(self, session: Session, settings: SettingsService) -> None:
        """
        Build a matcher

        @param session: Session The database session to write through
        @param settings: SettingsService Where the scoring weights come from
        """

        self._session = session
        self._settings = settings
        self._weights = settings.get_many("scoring")

    def backfill_premium(self, now: datetime) -> int:
        """
        Create catalog entries for software only the feeds know about

        Roughly half the vulnerable slugs in the wordfence feed are not
        in the free repository, they are commercial plugins or ones that
        were withdrawn. They still belong in the catalog, they are just
        never going to be crawled.

        @param now: datetime The timestamp to stamp these with
        @return int: How many entries were created
        """

        # every slug the feeds named that we have no catalog row for
        missing = self._session.execute(
            select(
                VulnerabilityAffect.slug,
                VulnerabilityAffect.software_type,
                func.max(VulnerabilityAffect.software_name).label("name"),
            )
            .outerjoin(
                Software,
                (Software.slug == VulnerabilityAffect.slug)
                & (Software.software_type == VulnerabilityAffect.software_type),
            )
            .where(Software.id.is_(None))
            .group_by(VulnerabilityAffect.slug, VulnerabilityAffect.software_type)
        ).all()

        # nothing to do, which is what a second run should look like
        if not missing:
            return 0

        # add them, flagged so nothing tries to crawl them later
        for slug, software_type, name in missing:
            self._session.add(
                Software(
                    slug=slug,
                    software_type=software_type,
                    name=name or slug,
                    status=SoftwareStatus.PREMIUM,
                    first_seen=now,
                    last_seen=now,
                )
            )

        self._session.commit()
        logger.info("added %s entries the free repository does not carry", len(missing))

        return len(missing)

    def _candidates(self) -> list[tuple]:
        """
        Every software and affected range pair that might match

        The padded sort keys let sql throw out the ranges that obviously
        cannot apply, which is the overwhelming majority of them. What
        survives gets an exact comparison in python, where the
        inclusivity of each bound is actually honored.

        @return list[tuple]: The candidate pairs to check properly
        """

        # the coarse filter. note this deliberately uses >= and <= on both
        # bounds regardless of inclusivity, so it is a superset of the real
        # matches rather than a subset, and nothing gets missed
        statement = (
            select(
                Software.id,
                Software.version,
                VulnerabilityAffect.id,
                VulnerabilityAffect.vulnerability_id,
                VulnerabilityAffect.from_version,
                VulnerabilityAffect.from_inclusive,
                VulnerabilityAffect.to_version,
                VulnerabilityAffect.to_inclusive,
                VulnerabilityAffect.patched,
                VulnerabilityAffect.patched_versions,
                Vulnerability.severity,
            )
            .join(
                VulnerabilityAffect,
                (VulnerabilityAffect.slug == Software.slug)
                & (VulnerabilityAffect.software_type == Software.software_type),
            )
            .join(Vulnerability, Vulnerability.id == VulnerabilityAffect.vulnerability_id)
            .where(
                Software.software_type != SoftwareType.CORE,
                Software.version_key.is_not(None),
                (VulnerabilityAffect.from_key.is_(None)) | (Software.version_key >= VulnerabilityAffect.from_key),
                (VulnerabilityAffect.to_key.is_(None)) | (Software.version_key <= VulnerabilityAffect.to_key),
            )
        )

        return list(self._session.execute(statement))

    def _core_candidates(self) -> list[tuple]:
        """
        Every core release and affected range pair that might match

        Core is matched per release rather than against whatever is
        current, because unlike a plugin everybody is running some older
        version of it and the useful question is what is wrong with the
        one you are actually on.

        @return list[tuple]: The candidate pairs to check properly
        """

        # same coarse key filter as plugins, but against every release
        statement = (
            select(
                Software.id,
                SoftwareVersion.id,
                SoftwareVersion.version,
                VulnerabilityAffect.id,
                VulnerabilityAffect.vulnerability_id,
                VulnerabilityAffect.from_version,
                VulnerabilityAffect.from_inclusive,
                VulnerabilityAffect.to_version,
                VulnerabilityAffect.to_inclusive,
                VulnerabilityAffect.patched,
                VulnerabilityAffect.patched_versions,
                Vulnerability.severity,
            )
            .select_from(SoftwareVersion)
            .join(Software, Software.id == SoftwareVersion.software_id)
            .join(
                VulnerabilityAffect,
                (VulnerabilityAffect.slug == Software.slug)
                & (VulnerabilityAffect.software_type == Software.software_type),
            )
            .join(Vulnerability, Vulnerability.id == VulnerabilityAffect.vulnerability_id)
            .where(
                Software.software_type == SoftwareType.CORE,
                (VulnerabilityAffect.from_key.is_(None))
                | (SoftwareVersion.version_key >= VulnerabilityAffect.from_key),
                (VulnerabilityAffect.to_key.is_(None)) | (SoftwareVersion.version_key <= VulnerabilityAffect.to_key),
            )
        )

        return list(self._session.execute(statement))

    def match_core(self, run_id: int | None = None) -> int:
        """
        Match vulnerabilities against every core release

        Produces a finding per release rather than per piece of software,
        so somebody on an older core can be told exactly what is wrong
        with the version they are on. Core is the one thing where that
        matters, because a vulnerable core makes every other result moot.

        @param run_id: int|None The run this pass belongs to
        @return int: How many core findings matched
        """

        now = datetime.now()
        candidates = self._core_candidates()
        logger.info("checking %s core release candidate pairs", len(candidates))

        # what is already on the books for core
        existing = {
            (f.software_id, f.vulnerability_id, f.software_version_id): f
            for f in self._session.execute(select(Finding).where(Finding.software_version_id.is_not(None))).scalars()
        }

        matched = 0

        # distinct vulnerability and release pairings seen this pass. a set
        # rather than a counter because a vulnerability with several ranges
        # can match one release more than once, and because the counts have
        # to come out the same whether the findings already existed or not
        seen: set[tuple[int, int]] = set()

        for row in candidates:
            (
                software_id,
                version_id,
                version,
                affect_id,
                vulnerability_id,
                from_version,
                from_inclusive,
                to_version,
                to_inclusive,
                patched,
                patched_versions,
                severity,
            ) = row

            if not in_range(version, from_version, from_inclusive, to_version, to_inclusive):
                continue

            key = (software_id, vulnerability_id, version_id)
            finding = existing.get(key)

            # count distinct vulnerabilities per release, not range hits,
            # otherwise a vulnerability with three ranges counts as three
            if (version_id, vulnerability_id) not in seen:
                seen.add((version_id, vulnerability_id))
                matched += 1

            # new to us. note it has to go straight into the lookup as
            # well, a vulnerability can carry several affected ranges and
            # one release can legitimately fall inside more than one of
            # them, which would otherwise insert the same finding twice
            if finding is None:
                finding = Finding(
                    software_id=software_id,
                    software_version_id=version_id,
                    vulnerability_id=vulnerability_id,
                    affect_id=affect_id,
                    matched_version=version,
                    severity=severity,
                    status=FindingStatus.OPEN,
                    fix_available=bool(patched),
                    fixed_in_version=self._fix_target(patched_versions),
                    first_seen=now,
                    last_seen=now,
                    first_run_id=run_id,
                    last_run_id=run_id,
                )
                self._session.add(finding)
                existing[key] = finding
            else:
                finding.last_seen = now
                finding.last_run_id = run_id

            if (matched % COMMIT_EVERY) == 0:
                self._session.commit()

        self._session.commit()

        # fold the pairings down into a count per release
        per_version: dict[int, int] = {}
        for version_id, _ in seen:
            per_version[version_id] = per_version.get(version_id, 0) + 1

        # stamp each release with how many issues it carries, which is the
        # number that actually goes in front of somebody
        self._session.execute(text("UPDATE software_versions SET issue_count = 0 WHERE issue_count <> 0"))
        if per_version:
            statement = (
                SoftwareVersion.__table__.update()
                .where(SoftwareVersion.__table__.c.id == bindparam("b_id"))
                .values(issue_count=bindparam("b_count"))
            )
            payload = [{"b_id": vid, "b_count": count} for vid, count in per_version.items()]
            for start in range(0, len(payload), COMMIT_EVERY):
                self._session.execute(statement, payload[start : start + COMMIT_EVERY])
            self._session.commit()

        logger.info("core: %s findings across %s releases", matched, len(per_version))

        return matched

    def match(self, run_id: int | None = None) -> MatchStats:
        """
        Match vulnerabilities against the catalog

        A finding means the version currently published is inside an
        affected range. Anything already fixed upstream stops being a
        finding, but still counts toward the software's issue history,
        which is what drives its priority.

        @param run_id: int|None The run this pass belongs to
        @return MatchStats: What the pass did
        """

        stats = MatchStats()
        now = datetime.now()

        # bring in whatever the feeds know about and the repository does not
        stats.premium_added = self.backfill_premium(now)

        # what could possibly match
        candidates = self._candidates()
        stats.candidates = len(candidates)
        logger.info("checking %s candidate pairs", stats.candidates)

        # everything currently on the books, so we can tell what went away
        existing = {
            (finding.software_id, finding.vulnerability_id): finding
            for finding in self._session.execute(select(Finding).where(Finding.software_version_id.is_(None))).scalars()
        }
        still_matching: set[tuple[int, int]] = set()

        # now the exact comparison, honoring each bound's inclusivity
        for row in candidates:
            (
                software_id,
                version,
                affect_id,
                vulnerability_id,
                from_version,
                from_inclusive,
                to_version,
                to_inclusive,
                patched,
                patched_versions,
                severity,
            ) = row

            if not in_range(version, from_version, from_inclusive, to_version, to_inclusive):
                continue

            stats.matched += 1
            key = (software_id, vulnerability_id)
            still_matching.add(key)

            # the lowest patched version above where we are, which is what
            # somebody actually needs to update to
            fixed_in = self._fix_target(patched_versions)

            finding = existing.get(key)

            # new finding, somebody needs to look at this
            if finding is None:
                finding = Finding(
                    software_id=software_id,
                    vulnerability_id=vulnerability_id,
                    affect_id=affect_id,
                    matched_version=version,
                    severity=severity,
                    status=FindingStatus.OPEN,
                    fix_available=bool(patched),
                    fixed_in_version=fixed_in,
                    first_seen=now,
                    last_seen=now,
                    first_run_id=run_id,
                    last_run_id=run_id,
                )
                self._session.add(finding)
                self._session.flush()
                self._session.add(
                    FindingEvent(
                        finding_id=finding.id,
                        event_type=FindingEventType.CREATED,
                        new_value=FindingStatus.OPEN.value,
                    )
                )

                # into the lookup straight away, for the same reason as
                # core: several ranges on one vulnerability can all match
                existing[key] = finding
                stats.findings_opened += 1

            # already known, just confirm it still applies
            else:
                finding.affect_id = affect_id
                finding.matched_version = version
                finding.severity = severity
                finding.fix_available = bool(patched)
                finding.fixed_in_version = fixed_in
                finding.last_seen = now
                finding.last_run_id = run_id

                # something a person had closed has come back, which
                # usually means the plugin regressed or the feed widened
                # the affected range
                if finding.status in (FindingStatus.RESOLVED, FindingStatus.IGNORED):
                    finding.status = FindingStatus.OPEN
                    finding.resolved_at = None
                    self._session.add(
                        FindingEvent(
                            finding_id=finding.id,
                            event_type=FindingEventType.REOPENED,
                            comment="the current version is affected again",
                        )
                    )

                stats.findings_updated += 1

            if (stats.matched % COMMIT_EVERY) == 0:
                self._session.commit()

        self._session.commit()

        # anything open that no longer matches has been fixed upstream
        stats.findings_resolved = self._auto_resolve(existing, still_matching, now, run_id)

        # core gets its own pass, matched per release
        stats.core_matched = self.match_core(run_id)

        # and rank the lot
        stats.scored = self.rescore()

        logger.info(
            "matching finished: %s matched, %s opened, %s resolved, %s ranked",
            stats.matched,
            stats.findings_opened,
            stats.findings_resolved,
            stats.scored,
        )

        return stats

    def _fix_target(self, patched_versions: list | None) -> str | None:
        """
        Pick the version somebody should update to

        The feed can list several patched versions across release lines,
        the lowest is the smallest step that gets you out of trouble.

        @param patched_versions: list|None What the feed said was patched
        @return str|None: The version to update to, when there is one
        """

        # nothing published, nothing to point at
        if not patched_versions:
            return None

        from kpwpvs.utils.version import sort_key

        return min((str(v) for v in patched_versions), key=sort_key)

    def _auto_resolve(
        self,
        existing: dict[tuple[int, int], Finding],
        still_matching: set[tuple[int, int]],
        now: datetime,
        run_id: int | None,
    ) -> int:
        """
        Close findings whose software has moved out of the affected range

        Only touches findings nobody has already made a decision about,
        an ignored or false positive finding stays where somebody put it.

        @param existing: dict The findings that were on the books
        @param still_matching: set The pairs that matched this pass
        @param now: datetime The timestamp to stamp the resolution with
        @param run_id: int|None The run this pass belongs to
        @return int: How many findings were resolved
        """

        resolved = 0

        # anything that was open and is no longer matched has been fixed
        for key, finding in existing.items():
            if key in still_matching:
                continue
            if finding.status not in (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED, FindingStatus.IN_PROGRESS):
                continue

            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            finding.last_run_id = run_id
            self._session.add(
                FindingEvent(
                    finding_id=finding.id,
                    event_type=FindingEventType.AUTO_RESOLVED,
                    old_value=FindingStatus.OPEN.value,
                    new_value=FindingStatus.RESOLVED.value,
                    comment="the published version is no longer in an affected range",
                )
            )
            resolved += 1

        self._session.commit()

        return resolved

    def rescore(self) -> int:
        """
        Recompute issue counts and priority scores across the catalog

        The issue count is every vulnerability ever tied to a slug, not
        just the ones affecting the current version, because a plugin
        with a long history of holes is worth looking at whether or not
        today's release happens to be clean. That is what makes this
        useful for ranking the phase two source scanning.

        @return int: How many entries were scored
        """

        # counts of everything ever reported against each entry, done in
        # sql because doing it per row would be tens of thousands of queries.
        # these are inner joins with a changed check rather than a blanket
        # update over the whole catalog, writing all eighty thousand rows
        # every pass costs two minutes in index maintenance alone
        self._session.execute(
            text("""
            UPDATE software s
            JOIN (
                SELECT va.slug, va.software_type,
                       COUNT(DISTINCT va.vulnerability_id) AS total,
                       COUNT(DISTINCT CASE WHEN v.severity = 'critical'
                                           THEN va.vulnerability_id END) AS critical
                  FROM vulnerability_affects va
                  JOIN vulnerabilities v ON v.id = va.vulnerability_id
                 GROUP BY va.slug, va.software_type
            ) counts ON counts.slug = s.slug AND counts.software_type = s.software_type
            SET s.issue_count = counts.total,
                s.critical_issue_count = counts.critical
            WHERE s.issue_count <> counts.total
               OR s.critical_issue_count <> counts.critical
        """)
        )

        # and zero anything that used to have counts and no longer does
        self._session.execute(
            text("""
            UPDATE software s
            LEFT JOIN (
                SELECT DISTINCT slug, software_type FROM vulnerability_affects
            ) known ON known.slug = s.slug AND known.software_type = s.software_type
            SET s.issue_count = 0, s.critical_issue_count = 0
            WHERE known.slug IS NULL
              AND (s.issue_count <> 0 OR s.critical_issue_count <> 0)
        """)
        )

        # how many are actually open right now, same treatment
        self._session.execute(
            text("""
            UPDATE software s
            JOIN (
                SELECT software_id, COUNT(*) AS open_count
                  FROM findings
                 WHERE status IN ('open', 'acknowledged', 'in_progress')
                 GROUP BY software_id
            ) f ON f.software_id = s.id
            SET s.open_issue_count = f.open_count
            WHERE s.open_issue_count <> f.open_count
        """)
        )

        # and zero the ones with nothing open any more
        self._session.execute(
            text("""
            UPDATE software s
            LEFT JOIN (
                SELECT DISTINCT software_id FROM findings
                 WHERE status IN ('open', 'acknowledged', 'in_progress')
            ) f ON f.software_id = s.id
            SET s.open_issue_count = 0
            WHERE f.software_id IS NULL AND s.open_issue_count <> 0
        """)
        )

        self._session.commit()

        # then the score itself, which needs the severity mix so it comes
        # back to python. only entries with a history are worth scoring
        weight_issue = self._weights.get("weight_issue_count", 1.0)
        weight_severity = self._weights.get("weight_severity", 2.0)
        weight_installs = self._weights.get("weight_installs", 1.5)
        weight_abandoned = self._weights.get("weight_abandoned", 1.25)

        severity_mix = self._session.execute(
            text("""
            SELECT s.id, s.active_installs, s.status, s.issue_count, v.severity, COUNT(*) AS n
              FROM software s
              JOIN vulnerability_affects va
                ON va.slug = s.slug AND va.software_type = s.software_type
              JOIN vulnerabilities v ON v.id = va.vulnerability_id
             WHERE s.issue_count > 0
             GROUP BY s.id, s.active_installs, s.status, s.issue_count, v.severity
        """)
        ).all()

        # fold the severity rows back together per entry
        scores: dict[int, float] = {}
        context: dict[int, tuple[int, str, int]] = {}
        for software_id, installs, status, issue_count, severity, count in severity_mix:
            scores[software_id] = scores.get(software_id, 0.0) + (SEVERITY_POINTS.get(Severity(severity), 0.0) * count)
            context[software_id] = (installs or 0, status, issue_count or 0)

        # what the scores are now, so we only write the ones that moved.
        # on a steady week almost nothing does, and each write is its own
        # statement
        current = dict(
            self._session.execute(select(Software.id, Software.priority_score).where(Software.issue_count > 0)).all()
        )

        # then the actual formula
        updates = []
        for software_id, severity_points in scores.items():
            installs, status, issue_count = context[software_id]

            # installs are log scaled, the difference between ten and a
            # hundred installs matters far more than a million and two
            reach = math.log10(installs + 1)

            score = (issue_count * weight_issue) + (severity_points * weight_severity) + (reach * weight_installs)

            # nothing is coming to save an unmaintained plugin
            if status in [s.value for s in UNMAINTAINED]:
                score *= weight_abandoned

            score = round(score, 4)

            # unchanged, leave it alone
            if abs(current.get(software_id, -1.0) - score) < 0.0001:
                continue

            updates.append({"b_id": software_id, "b_score": score})

        # write them back with a single prepared statement run over every
        # set of parameters, rather than one statement per row
        if updates:
            # against the table rather than the mapped class, so the orm
            # does not try to synchronize sessions for every row
            statement = (
                Software.__table__.update()
                .where(Software.__table__.c.id == bindparam("b_id"))
                .values(priority_score=bindparam("b_score"))
            )
            for start in range(0, len(updates), COMMIT_EVERY):
                self._session.execute(statement, updates[start : start + COMMIT_EVERY])
                self._session.commit()

        return len(updates)
