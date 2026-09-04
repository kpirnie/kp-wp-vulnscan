#!/usr/bin/env python3
"""
Report Models Module

Generated report artifacts and the outbound webhook delivery log.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from kpwpvs.models.base import Base, TABLE_ARGS, TimestampMixin, enum_column


class ReportFormat(enum.StrEnum):
    """
    What shape a generated report took

    The database summary is always written, the file formats only when
    the output directory is actually mounted.
    """

    JSON = "json"
    HTML = "html"


class DeliveryStatus(enum.StrEnum):
    """
    How an outbound notification went

    Retrying means we will have another go, failed means we gave up.
    """

    PENDING = "pending"
    DELIVERED = "delivered"
    RETRYING = "retrying"
    FAILED = "failed"
    # nothing met the minimum severity, so nothing was sent
    SKIPPED = "skipped"


class Report(TimestampMixin, Base):
    """
    A report generated for a run

    The summary is kept on the row so the interface can render the
    history without reading any files back off disk.
    """

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_run_format", "run_id", "format"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # null when a report was generated on its own rather than as part of
    # a run, which is what the report subcommand does
    run_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("runs.id", ondelete="CASCADE"),
        nullable=True,
    )

    format: Mapped[ReportFormat] = mapped_column(
        enum_column(ReportFormat, 16),
        nullable=False,
    )

    # null when the output directory was not mounted and we only kept the
    # summary in the database
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # the counts the report was built from, enough to render a history row
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    generated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The run and format
        """

        return f"<Report {self.run_id} {self.format}>"


class WebhookDelivery(TimestampMixin, Base):
    """
    One attempt at delivering a notification

    Kept so a silent webhook is diagnosable without turning on debug
    logging and waiting a week for the next run.
    """

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        Index("ix_webhook_deliveries_run_status", "run_id", "status"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("runs.id", ondelete="CASCADE"),
        nullable=True,
    )

    # the target, stored without any query string in case it carries a token
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False, default="generic")

    status: Mapped[DeliveryStatus] = mapped_column(
        enum_column(DeliveryStatus, 16),
        nullable=False,
        default=DeliveryStatus.PENDING,
    )

    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The run and delivery status
        """

        return f"<WebhookDelivery {self.run_id} {self.status}>"
