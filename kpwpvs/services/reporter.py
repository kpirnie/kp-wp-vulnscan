    #!/usr/bin/env python3
"""
Reporter Service Module

Turns a run into something somebody actually reads. The database always
gets a summary. Json and html only get written when the output directory
is really mounted, and the webhook only fires when one is configured, so
an install with neither still works and simply produces less.

Core leads every report. A vulnerable core makes everything below it
moot, so it is never buried under a plugin table.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kpwpvs import __version__
from kpwpvs.models import (
    DeliveryStatus,
    Feed,
    Finding,
    FindingStatus,
    Report,
    ReportFormat,
    Severity,
    Software,
    SoftwareType,
    SoftwareVersion,
    Vulnerability,
    WebhookDelivery,
)
from kpwpvs.services.settings_service import SettingsService

logger = logging.getLogger(__name__)

# where the html template lives
TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# severity ordering, worst first, used everywhere we sort
SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE)

# how much detail goes in a report before it stops being readable
TOP_FINDINGS = 50
TOP_PRIORITY = 25
CORE_RELEASES = 15

# statuses that count as needing attention
OPEN_STATUSES = (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED, FindingStatus.IN_PROGRESS)

# minimum severity a webhook will fire on, mapped to a rank
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITY_ORDER))}


class Reporter:
    """
    Builds and delivers the report for a run

    The payload is assembled once and every output format renders from
    it, so the json, the html, and the webhook can never disagree about
    what the run found.
    """

    def __init__(self, session: Session, settings: SettingsService) -> None:
        """
        Build a reporter

        @param session: Session The database session to read through
        @param settings: SettingsService Where the reporting settings come from
        """

        self._session = session
        self._settings = settings
        self._config = settings.get_many("reporting")

    def build_payload(self, run_id: int | None = None) -> dict[str, Any]:
        """
        Assemble everything the report needs

        One pass over the database producing a plain dictionary, which is
        what gets written as json and handed to the html template.

        @param run_id: int|None The run this report covers
        @return dict: The full report payload
        """

        now = datetime.now()

        payload: dict[str, Any] = {
            "generated_at": now.isoformat(timespec="seconds"),
            "generator": f"kp-wp-vulnscan {__version__}",
            "run_id": run_id,
            "site_name": self._settings.get("general.site_name"),
            "core": self._core_section(),
            "catalog": self._catalog_section(),
            "findings": self._findings_section(),
            "top_findings": self._top_findings(),
            "priorities": self._priorities(),
            "feeds": self._feeds_section(),
            "attribution": self._attribution(),
        }

        return payload

    def _core_section(self) -> dict[str, Any]:
        """
        Everything about WordPress core

        This leads the report. Core is the one thing where the version
        somebody is running matters more than the version being shipped,
        so it reports per release rather than per package.

        @return dict: The core section of the payload
        """

        # the core entry itself
        core = self._session.execute(
            select(Software).where(
                Software.software_type == SoftwareType.CORE,
                Software.slug == "wordpress",
            )
        ).scalar_one_or_none()

        # no core crawled yet, say so rather than pretending
        if core is None:
            return {"tracked": False}

        # the releases, newest first, with what is wrong with each
        releases = (
            self._session.execute(
                select(SoftwareVersion)
                .where(SoftwareVersion.software_id == core.id)
                .order_by(SoftwareVersion.version_key.desc())
                .limit(CORE_RELEASES)
            )
            .scalars()
            .all()
        )

        # what is wrong with the release currently shipping, which is the
        # number people least expect to be above zero
        current_issues = []
        current = next((r for r in releases if r.is_current), None)
        if current is not None:
            rows = self._session.execute(
                select(Finding, Vulnerability)
                .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
                .where(Finding.software_version_id == current.id)
                .order_by(Vulnerability.cvss_score.desc())
            ).all()
            current_issues = [
                {
                    "cve": vulnerability.cve,
                    "title": vulnerability.title,
                    "severity": finding.severity.value,
                    "cvss_score": vulnerability.cvss_score,
                    "references": vulnerability.references or [],
                }
                for finding, vulnerability in rows
            ]

        # how many releases wordpress.org itself calls insecure
        insecure = self._session.execute(
            select(func.count())
            .select_from(SoftwareVersion)
            .where(
                SoftwareVersion.software_id == core.id,
                SoftwareVersion.release_status == "insecure",
            )
        ).scalar_one()

        total = self._session.execute(
            select(func.count()).select_from(SoftwareVersion).where(SoftwareVersion.software_id == core.id)
        ).scalar_one()

        return {
            "tracked": True,
            "current_version": core.version,
            "current_issue_count": len(current_issues),
            "current_issues": current_issues,
            "releases_tracked": total,
            "releases_insecure": insecure,
            "releases": [
                {
                    "version": release.version,
                    "status": release.release_status.value,
                    "issue_count": release.issue_count,
                    "is_current": release.is_current,
                }
                for release in releases
            ],
        }

    def _catalog_section(self) -> dict[str, Any]:
        """
        What the catalog holds

        @return dict: Counts by type and status
        """

        rows = self._session.execute(
            select(Software.software_type, Software.status, func.count()).group_by(
                Software.software_type, Software.status
            )
        ).all()

        by_type: dict[str, dict[str, int]] = {}
        total = 0
        for software_type, status, count in rows:
            by_type.setdefault(software_type.value, {})[status.value] = count
            total += count

        return {"total": total, "by_type": by_type}
    def _findings_section(self) -> dict[str, Any]:
        """
        The headline finding counts

        Split by whether they are about core, a plugin, or a theme,
        because the three mean quite different things.

        @return dict: Finding counts by severity and kind
        """

        rows = self._session.execute(
            select(Finding.severity, Software.software_type, func.count())
            .join(Software, Software.id == Finding.software_id)
            .where(Finding.status.in_(OPEN_STATUSES))
            .group_by(Finding.severity, Software.software_type)
        ).all()

        buckets: dict[str, dict[str, int]] = {t.value: {s.value: 0 for s in SEVERITY_ORDER} for t in SoftwareType}

        for severity, software_type, count in rows:
            buckets[software_type.value][severity.value] = count

        return {
            "plugin": buckets[SoftwareType.PLUGIN.value],
            "plugin_total": sum(buckets[SoftwareType.PLUGIN.value].values()),
            "theme": buckets[SoftwareType.THEME.value],
            "theme_total": sum(buckets[SoftwareType.THEME.value].values()),
            "core": buckets[SoftwareType.CORE.value],
            "core_total": sum(buckets[SoftwareType.CORE.value].values()),
        }

    def _top_findings(self) -> list[dict[str, Any]]:
        """
        The open plugin and theme findings most worth looking at

        Ordered by severity then by how many installs are exposed, which
        is the order somebody would triage them in.

        @return list[dict]: The findings, worst first
        """

        rows = self._session.execute(
            select(Finding, Software, Vulnerability)
            .join(Software, Software.id == Finding.software_id)
            .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
            .where(
                Finding.status.in_(OPEN_STATUSES),
                Finding.software_version_id.is_(None),
            )
            .order_by(
                func.field(Finding.severity, *[s.value for s in SEVERITY_ORDER]),
                Software.active_installs.desc(),
            )
            .limit(TOP_FINDINGS)
        ).all()

        return [
            {
                "slug": software.slug,
                "name": software.name,
                "type": software.software_type.value,
                "software_status": software.status.value,
                "version": finding.matched_version,
                "active_installs": software.active_installs,
                "severity": finding.severity.value,
                "cve": vulnerability.cve,
                "title": vulnerability.title,
                "cvss_score": vulnerability.cvss_score,
                "cwe": vulnerability.cwe_name,
                "fix_available": finding.fix_available,
                "fixed_in_version": finding.fixed_in_version,
                "references": vulnerability.references or [],
            }
            for finding, software, vulnerability in rows
        ]

    def _new_findings(self, run_id: int | None, minimum: Severity) -> list[dict[str, Any]]:
        """
        The findings this run opened, at or above a severity

        Plugin and theme findings, plus whatever is newly wrong with the
        core release currently shipping. Older core releases are left out,
        nobody is running them.

        @param run_id: int|None The run to look at
        @param minimum: Severity The lowest severity to include
        @return list[dict]: The new findings, worst first
        """

        # a report built outside of a run has nothing new by definition
        if run_id is None:
            return []

        rows = self._session.execute(
            select(Finding, Software, Vulnerability)
            .join(Software, Software.id == Finding.software_id)
            .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
            .outerjoin(SoftwareVersion, SoftwareVersion.id == Finding.software_version_id)
            .where(
                Finding.first_run_id == run_id,
                Finding.status.in_(OPEN_STATUSES),
                (Finding.software_version_id.is_(None)) | (SoftwareVersion.is_current.is_(True)),
            )
            .order_by(
                func.field(Finding.severity, *[s.value for s in SEVERITY_ORDER]),
                Software.active_installs.desc(),
            )
        ).all()

        return [
            {
                "slug": software.slug,
                "name": software.name,
                "type": software.software_type.value,
                "version": finding.matched_version,
                "severity": finding.severity.value,
                "cve": vulnerability.cve,
                "title": vulnerability.title,
                "cvss_score": vulnerability.cvss_score,
                "fixed_in_version": finding.fixed_in_version,
            }
            for finding, software, vulnerability in rows
            if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[minimum]
        ]

    def _priorities(self) -> list[dict[str, Any]]:
        """
        The highest ranked entries in the catalog

        This is the queue phase two source scanning works through, so it
        is worth showing even when nothing is currently vulnerable.

        @return list[dict]: The highest priority entries
        """

        rows = (
            self._session.execute(
                select(Software)
                .where(Software.issue_count > 0)
                .order_by(Software.priority_score.desc())
                .limit(TOP_PRIORITY)
            )
            .scalars()
            .all()
        )

        return [
            {
                "slug": software.slug,
                "name": software.name,
                "type": software.software_type.value,
                "status": software.status.value,
                "version": software.version,
                "active_installs": software.active_installs,
                "issue_count": software.issue_count,
                "open_issue_count": software.open_issue_count,
                "critical_issue_count": software.critical_issue_count,
                "priority_score": round(software.priority_score, 1),
            }
            for software in rows
        ]

    def _feeds_section(self) -> list[dict[str, Any]]:
        """
        How each feed is doing

        A silently stale feed is the failure mode that matters most here,
        so every report says when each one last worked.

        @return list[dict]: The feed states
        """

        feeds = self._session.execute(select(Feed).order_by(Feed.priority)).scalars().all()

        return [
            {
                "source": feed.source.value,
                "name": feed.name,
                "enabled": feed.enabled,
                "last_success_at": feed.last_success_at.isoformat(timespec="seconds") if feed.last_success_at else None,
                "record_count": feed.record_count,
                "error": feed.last_error,
            }
            for feed in feeds
        ]

    def _attribution(self) -> list[dict[str, str]]:
        """
        The attribution every source requires

        Defiant's license asks that the copyright notice travel with any
        reproduction of their vulnerability data, and this report is a
        reproduction of it.

        @return list[dict]: One entry per source we actually used
        """

        rows = self._session.execute(
            select(Vulnerability.source, Vulnerability.copyright_notice)
            .where(Vulnerability.copyright_notice.is_not(None))
            .distinct()
        ).all()

        seen: set[str] = set()
        notices = []
        for source, notice in rows:
            if notice in seen:
                continue
            seen.add(notice)
            notices.append({"source": source.value, "notice": notice})

        return notices

    def output_dir(self) -> Path | None:
        """
        The report directory, when it is really there

        Deliberately does not create it. A missing directory means the
        volume was not mounted, and quietly writing into the container
        layer would lose the reports on the next pull without anybody
        noticing.

        @return Path|None: The directory, or None when it is not mounted
        """

        configured = self._config.get("output_dir") or ""
        if not configured:
            return None

        path = Path(configured)
        if not path.is_dir():
            logger.info("%s is not mounted, skipping the file reports", path)
            return None

        return path

    def write_json(self, payload: dict[str, Any], run_id: int | None) -> Report | None:
        """
        Write the json report

        @param payload: dict The assembled report payload
        @param run_id: int|None The run this report covers
        @return Report|None: The recorded report, or None when not written
        """

        # nothing to do without somewhere to put it
        if not self._config.get("json_enabled", True):
            return None

        directory = self.output_dir()
        if directory is None:
            return None

        # named for when it was generated, so they sort chronologically
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = directory / f"kpwpvs-{stamp}.json"

        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        logger.info("wrote %s", path)

        return self._record(run_id, ReportFormat.JSON, path, payload)

    def write_html(self, payload: dict[str, Any], run_id: int | None) -> Report | None:
        """
        Render and write the html report

        @param payload: dict The assembled report payload
        @param run_id: int|None The run this report covers
        @return Report|None: The recorded report, or None when not written
        """

        # nothing to do without somewhere to put it
        if not self._config.get("html_enabled", True):
            return None

        directory = self.output_dir()
        if directory is None:
            return None

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = directory / f"kpwpvs-{stamp}.html"

        path.write_text(self.render_html(payload), encoding="utf-8")
        logger.info("wrote %s", path)

        return self._record(run_id, ReportFormat.HTML, path, payload)

    def render_html(self, payload: dict[str, Any]) -> str:
        """
        Render the html report

        Self contained, no external assets beyond a webfont, so it can be
        opened from a file or emailed on without breaking.

        @param payload: dict The assembled report payload
        @return str: The rendered html
        """

        environment = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # a couple of filters the template leans on
        environment.filters["installs"] = _format_installs

        return environment.get_template("report.html.j2").render(**payload)

    def _record(
        self,
        run_id: int | None,
        report_format: ReportFormat,
        path: Path,
        payload: dict[str, Any],
    ) -> Report:
        """
        Record a written report in the database

        The summary is kept on the row so the interface can render the
        history without reading files back off disk.

        @param run_id: int|None The run this report covers
        @param report_format: ReportFormat Which format was written
        @param path: Path Where it went
        @param payload: dict The assembled report payload
        @return Report: The recorded report
        """

        report = Report(
            run_id=run_id,
            format=report_format,
            path=str(path),
            size_bytes=path.stat().st_size,
            summary={
                "core": {
                    "current_version": payload["core"].get("current_version"),
                    "current_issue_count": payload["core"].get("current_issue_count", 0),
                },
                "findings": payload["findings"],
                "catalog_total": payload["catalog"]["total"],
            },
            generated_at=datetime.now(),
        )
        self._session.add(report)
        self._session.commit()

        return report

    def prune(self) -> int:
        """
        Delete report files beyond the configured retention

        @return int: How many files were removed
        """

        retention = self._config.get("retention", 52)

        # zero means keep everything
        directory = self.output_dir()
        if directory is None or retention <= 0:
            return 0

        removed = 0

        # each format is pruned on its own so one does not starve the other
        for suffix in ("json", "html"):
            files = sorted(directory.glob(f"kpwpvs-*.{suffix}"), reverse=True)
            for stale in files[retention:]:
                stale.unlink(missing_ok=True)
                removed += 1

        if removed:
            logger.info("pruned %s report files beyond the retention of %s", removed, retention)

        return removed

    def send_webhook(self, payload: dict[str, Any], run_id: int | None) -> WebhookDelivery | None:
        """
        Post the run summary to the configured webhook

        Fires only when one is configured and this run opened something at
        or above the minimum severity, so a quiet run stays quiet.

        @param payload: dict The assembled report payload
        @param run_id: int|None The run this report covers
        @return WebhookDelivery|None: The delivery record, or None when not sent
        """

        # nothing configured, nothing to do
        if not self._settings.get("webhook.enabled"):
            return None

        url = self._settings.get("webhook.url")
        if not url:
            logger.warning("the webhook is enabled but no url is set")
            return None

        # only what this run opened, never the standing list
        minimum = Severity(self._settings.get("webhook.min_severity"))
        new_findings = self._new_findings(run_id, minimum)

        delivery = WebhookDelivery(
            run_id=run_id,
            url=url.split("?")[0],
            format=self._settings.get("webhook.format"),
        )

        # a quiet run is not worth a notification
        if not new_findings:
            delivery.status = DeliveryStatus.SKIPPED
            self._session.add(delivery)
            self._session.commit()
            logger.info("nothing new met the %s threshold, no notification sent", minimum.value)
            return delivery

        body = _build_webhook_body(self._settings.get("webhook.format"), payload, new_findings, minimum)

        # send it, recording whatever happens
        try:
            response = httpx.post(
                url,
                json=body,
                timeout=self._settings.get("webhook.timeout"),
            )
            delivery.attempts = 1
            delivery.response_code = response.status_code
            delivery.response_body = response.text[:2000]

            if response.is_success:
                delivery.status = DeliveryStatus.DELIVERED
                delivery.delivered_at = datetime.now()
                logger.info("notification delivered")
            else:
                delivery.status = DeliveryStatus.FAILED
                logger.error("the webhook answered %s", response.status_code)

        except httpx.HTTPError as exc:
            delivery.attempts = 1
            delivery.status = DeliveryStatus.FAILED
            delivery.error = str(exc)[:2000]
            logger.error("could not reach the webhook: %s", exc)

        self._session.add(delivery)
        self._session.commit()

        return delivery

    def generate(self, run_id: int | None = None) -> dict[str, Any]:
        """
        Build and deliver every configured output

        The database summary always happens. The rest are best effort and
        each is skipped rather than failed when it is not configured.

        @param run_id: int|None The run this report covers
        @return dict: The assembled report payload
        """

        payload = self.build_payload(run_id)

        self.write_json(payload, run_id)
        self.write_html(payload, run_id)
        self.prune()
        self.send_webhook(payload, run_id)

        return payload


def _format_installs(value: object) -> str:
    """
    Render an install count the way wordpress.org does

    @param value: object The raw install count
    @return str: A short readable count
    """

    # anything unusable reads as unknown rather than zero
    if not isinstance(value, int) or value <= 0:
        return "-"

    if value >= 1_000_000:
        return f"{value // 1_000_000}M+"
    if value >= 1_000:
        return f"{value // 1_000}k+"

    return str(value)

def _build_webhook_body(
    style: str,
    payload: dict[str, Any],
    new_findings: list[dict[str, Any]],
    minimum: Severity,
) -> dict[str, Any]:
    """
    Shape the notification for whatever is receiving it

    @param style: str Which service shape to build
    @param payload: dict The assembled report payload
    @param new_findings: list[dict] What this run opened at or above the threshold
    @param minimum: Severity The threshold that was applied
    @return dict: The payload to post
    """

    headline = f"{payload['site_name']}: {len(new_findings)} new finding(s) at {minimum.value} or above"

    # one line per finding, already ordered worst first
    lines = []
    for finding in new_findings:
        line = (
            f"[{finding['severity']}] {finding['type']} {finding['name']} {finding['version']}: "
            f"{finding['cve'] or 'no cve'} {finding['title']}"
        )
        if finding["fixed_in_version"]:
            line += f" (fixed in {finding['fixed_in_version']})"
        lines.append(line)

    text_body = headline + "\n" + "\n".join(lines)

    # slack and discord both take a plain text field, everything else gets
    # the structured list so it can be parsed rather than read
    if style == "slack":
        return {"text": text_body}
    if style == "discord":
        return {"content": text_body}

    return {
        "generated_at": payload["generated_at"],
        "run_id": payload["run_id"],
        "summary": headline,
        "new_findings": new_findings,
    }
    