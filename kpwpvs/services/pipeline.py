#!/usr/bin/env python3
"""
Pipeline Service Module

Runs the stages in order and records what each one did. This is what
cron calls once a week, and what the button in the interface triggers.

A stage failing does not abandon the run. A feed being down should still
leave you with a report built from what you already had, and a record
saying which part was stale.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import asyncio
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from kpwpvs.core.crypto import SecretBox
from kpwpvs.models import Run, RunKind, RunStage, RunStatus, RunTrigger
from kpwpvs.services.crawler import Crawler
from kpwpvs.services.feeds import FeedService
from kpwpvs.services.matcher import Matcher
from kpwpvs.services.reporter import Reporter
from kpwpvs.services.settings_service import SettingsService

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Runs the whole scan, stage by stage

    Each stage records its own timing and counts, so a partial run is
    legible afterwards rather than being a single failed flag.
    """

    def __init__(
        self,
        session: Session,
        settings: SettingsService,
        secret_box: SecretBox | None = None,
    ) -> None:
        """
        Build a pipeline

        @param session: Session The database session to write through
        @param settings: SettingsService Where the stage settings come from
        @param secret_box: SecretBox|None Needed to read the stored feed keys
        """

        self._session = session
        self._settings = settings
        self._secret_box = secret_box

    def _start_stage(self, run: Run, name: str) -> RunStage:
        """
        Open a stage record

        @param run: Run The run this stage belongs to
        @param name: str The stage name
        @return RunStage: The open stage record
        """

        stage = RunStage(
            run_id=run.id,
            stage=name,
            status=RunStatus.RUNNING,
            started_at=datetime.now(),
        )
        self._session.add(stage)
        self._session.commit()

        return stage

    def _finish_stage(
        self,
        stage: RunStage,
        status: RunStatus,
        stats: dict | None = None,
        error: str | None = None,
    ) -> None:
        """
        Close a stage record

        @param stage: RunStage The stage to close
        @param status: RunStatus How it went
        @param stats: dict|None Whatever counts the stage produced
        @param error: str|None What went wrong, when something did
        @return None
        """

        stage.status = status
        stage.finished_at = datetime.now()
        stage.stats = stats
        stage.error = error[:2000] if error else None
        self._session.commit()

    def run(
        self,
        trigger: RunTrigger = RunTrigger.CRON,
        started_by_id: int | None = None,
        full_crawl: bool = False,
    ) -> Run:
        """
        Run every stage in order

        Crawl, then feeds, then match, then report. Each stage is caught
        on its own so one failure does not cost the rest of the run.

        @param trigger: RunTrigger What kicked this off
        @param started_by_id: int|None Who pressed the button, when somebody did
        @param full_crawl: bool Force a full seed crawl
        @return Run: The completed run record
        """

        # open the run
        run = Run(
            kind=RunKind.SCAN,
            trigger_source=trigger,
            status=RunStatus.RUNNING,
            started_by_id=started_by_id,
            started_at=datetime.now(),
        )
        self._session.add(run)
        self._session.commit()
        logger.info("run %s started", run.id)

        failures = 0
        stages = 0

        # --- the catalog -------------------------------------------------
        stages += 1
        stage = self._start_stage(run, "crawl")
        try:
            crawler = Crawler(self._session, self._settings)

            # core first, it matters most and costs almost nothing
            core_releases = crawler.crawl_core()
            crawl_stats = asyncio.run(crawler.crawl(full=full_crawl))

            run.plugins_seen = crawl_stats.seen
            run.plugins_added = crawl_stats.added
            run.plugins_updated = crawl_stats.updated

            payload = crawl_stats.as_dict()
            payload["core_releases"] = core_releases
            self._finish_stage(stage, RunStatus.SUCCESS, payload)

        except Exception as exc:
            failures += 1
            logger.error("the crawl stage failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
            self._finish_stage(stage, RunStatus.FAILED, error=str(exc))

        # --- the feeds ---------------------------------------------------
        stages += 1
        stage = self._start_stage(run, "feeds")
        try:
            results = FeedService(self._session, self._secret_box).sync_all()

            run.vulnerabilities_seen = sum(s.seen for s in results.values())
            self._finish_stage(
                stage,
                RunStatus.SUCCESS,
                {source: stats.as_dict() for source, stats in results.items()},
            )

        except Exception as exc:
            failures += 1
            logger.error("the feed stage failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
            self._finish_stage(stage, RunStatus.FAILED, error=str(exc))

        # --- the match ---------------------------------------------------
        stages += 1
        stage = self._start_stage(run, "match")
        try:
            match_stats = Matcher(self._session, self._settings).match(run_id=run.id)

            run.findings_opened = match_stats.findings_opened
            run.findings_resolved = match_stats.findings_resolved
            self._finish_stage(stage, RunStatus.SUCCESS, match_stats.as_dict())

        except Exception as exc:
            failures += 1
            logger.error("the match stage failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
            self._finish_stage(stage, RunStatus.FAILED, error=str(exc))

        # --- the report --------------------------------------------------
        stages += 1
        stage = self._start_stage(run, "report")
        try:
            payload = Reporter(self._session, self._settings).generate(run_id=run.id)

            self._finish_stage(
                stage,
                RunStatus.SUCCESS,
                {
                    "core_current_issues": payload["core"].get("current_issue_count", 0),
                    "plugin_findings": payload["findings"]["plugin_total"],
                    "core_findings": payload["findings"]["core_total"],
                },
            )

        except Exception as exc:
            failures += 1
            logger.error("the report stage failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
            self._finish_stage(stage, RunStatus.FAILED, error=str(exc))

        # close the run out, partial is the honest answer when some of it
        # worked and some of it did not
        if failures == 0:
            run.status = RunStatus.SUCCESS
        elif failures < stages:
            run.status = RunStatus.PARTIAL
        else:
            run.status = RunStatus.FAILED

        run.finished_at = datetime.now()
        self._session.commit()

        elapsed = (run.finished_at - run.started_at).total_seconds()
        logger.info("run %s finished %s in %.0fs", run.id, run.status.value, elapsed)

        return run
