#!/usr/bin/env python3
"""
Run Models Module

Pipeline run bookkeeping, the individual stages within a run, and the
crawl checkpoints that let a seed crawl pick up where it left off.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kpwpvs.models.base import TABLE_ARGS, Base, TimestampMixin


class RunKind(enum.StrEnum):
    """
    What a run was asked to do

    A full scan runs every stage, the rest are the stages on their own
    for when you only want to refresh one thing.
    """

    SCAN = "scan"
    CRAWL = "crawl"
    FEEDS = "feeds"
    MATCH = "match"
    REPORT = "report"
    # phase two source scanning
    SOURCE_SCAN = "source_scan"


class RunTrigger(enum.StrEnum):
    """
    What kicked a run off

    Cron is the weekly schedule, manual is somebody on the command line,
    ui is the button in the web interface.
    """

    CRON = "cron"
    MANUAL = "manual"
    UI = "ui"


class RunStatus(enum.StrEnum):
    """
    How a run is going, or how it went

    Partial means some stages worked and some did not, which is the
    normal outcome when one feed is down and the rest are fine.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Run(TimestampMixin, Base):
    """
    One execution of the pipeline

    Everything the pipeline produces hangs off a run, which is what makes
    the week over week diff possible.
    """

    __tablename__ = "runs"
    __table_args__ = (
        Index("ix_runs_kind_started", "kind", "started_at"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    kind: Mapped[RunKind] = mapped_column(
        Enum(RunKind, native_enum=False, length=32),
        nullable=False,
    )
    trigger: Mapped[RunTrigger] = mapped_column(
        Enum(RunTrigger, native_enum=False, length=16),
        nullable=False,
        default=RunTrigger.CRON,
    )
    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus, native_enum=False, length=16),
        nullable=False,
        default=RunStatus.PENDING,
        index=True,
    )

    # who pressed the button, null for cron and the command line
    started_by_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # the headline numbers, the details live on the stages
    plugins_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    plugins_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    plugins_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerabilities_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_opened: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # what hangs off it
    stages: Mapped[list["RunStage"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="RunStage.id",
    )

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The run id, kind, and status
        """

        return f"<Run {self.id} {self.kind} {self.status}>"


class RunStage(Base):
    """
    One stage within a run

    Each pipeline stage records its own timing, counts, and error so a
    partial failure is legible after the fact.
    """

    __tablename__ = "run_stages"
    __table_args__ = (
        Index("ix_run_stages_run_stage", "run_id", "stage"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("runs.id", ondelete="CASCADE"),
        nullable=False,
    )

    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus, native_enum=False, length=16),
        nullable=False,
        default=RunStatus.PENDING,
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # whatever counts make sense for this particular stage
    stats: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    run: Mapped["Run"] = relationship(back_populates="stages")

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The run, stage name, and status
        """

        return f"<RunStage {self.run_id} {self.stage} {self.status}>"


class CrawlCheckpoint(TimestampMixin, Base):
    """
    Resume state for a catalog crawl

    The first seed walks the better part of three hundred pages, so it
    checkpoints as it goes and picks back up on the next attempt rather
    than starting over.
    """

    __tablename__ = "crawl_checkpoints"
    __table_args__ = (TABLE_ARGS,)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # what kind of crawl this checkpoint belongs to, seed or incremental
    kind: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)

    # where we got to
    page: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_pages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # the newest last_updated we have already ingested, an incremental
    # crawl walks the updated ordering until it reaches this and stops
    high_water_mark: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # whether the walk finished cleanly, a false here means resume
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The kind and how far it got
        """

        return f"<CrawlCheckpoint {self.kind} {self.page}/{self.total_pages}>"
