#!/usr/bin/env python3
"""
Finding Models Module

A finding is a vulnerability matched against a plugin in our catalog.
This is the thing managers actually work, so it carries a status, an
assignee, and an audit trail.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kpwpvs.models.base import Base, TABLE_ARGS, TimestampMixin, enum_column
from kpwpvs.models.vulnerability import Severity


class FindingStatus(enum.StrEnum):
    """
    Where a finding stands in the workflow

    Open is the default, everything else is somebody having looked at it
    and made a call.
    """

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


class FindingEventType(enum.StrEnum):
    """
    What happened to a finding

    Everything that changes a finding leaves one of these behind so we
    can show a history in the interface.
    """

    CREATED = "created"
    STATUS_CHANGED = "status_changed"
    ASSIGNED = "assigned"
    COMMENTED = "commented"
    REOPENED = "reopened"
    # the catalog moved and the plugin is no longer in the affected range
    AUTO_RESOLVED = "auto_resolved"


class Finding(TimestampMixin, Base):
    """
    A vulnerability matched against a catalogued entry

    One row per software and vulnerability pairing. Re-running the matcher
    updates the existing row rather than piling up duplicates, so the
    workflow state people set is never lost.
    """

    __tablename__ = "findings"
    __table_args__ = (
        # note mysql treats nulls as distinct in a unique index, so this
        # does not constrain plugin findings, where the version is null.
        # the matcher keys its own lookup on the same triple and is what
        # actually prevents duplicates there
        UniqueConstraint(
            "software_id",
            "vulnerability_id",
            "software_version_id",
            name="uq_findings_software_id_vulnerability_id_software_version_id",
        ),
        Index("ix_findings_status_severity", "status", "severity"),
        Index("ix_findings_software_status", "software_id", "status"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    software_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("software.id", ondelete="CASCADE"),
        nullable=False,
    )
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )

    # which version this is about. null means the currently published
    # one, which is how plugins work, there is only ever one version of a
    # plugin worth caring about. core is different, everybody is on some
    # older release, so core findings name the version explicitly
    software_version_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("software_versions.id", ondelete="CASCADE"),
        nullable=True,
    )

    # which range actually matched, kept so the interface can show why
    affect_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("vulnerability_affects.id", ondelete="SET NULL"),
        nullable=True,
    )

    # the catalog version that was affected when we matched it
    matched_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # copied off the vulnerability so we can sort and filter without a join
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity, 16),
        nullable=False,
        default=Severity.NONE,
    )

    # the workflow bits
    status: Mapped[FindingStatus] = mapped_column(
        enum_column(FindingStatus, 32),
        nullable=False,
        default=FindingStatus.OPEN,
        index=True,
    )
    assigned_to_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # whether a fixed version is available upstream right now
    fix_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    fixed_in_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # when we first matched it and when we last confirmed it still matches
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # which runs bracketed it, useful for the week over week diff
    first_run_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("runs.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_run_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("runs.id", ondelete="SET NULL"),
        nullable=True,
    )

    # what hangs off it
    events: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="FindingEvent.id",
    )

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The software, vulnerability, and current status
        """

        return f"<Finding s{self.software_id} v{self.vulnerability_id} {self.status}>"


class FindingEvent(Base):
    """
    One entry in a finding's history

    Records who did what and when, including the automated transitions
    the matcher makes on its own.
    """

    __tablename__ = "finding_events"
    __table_args__ = (
        Index("ix_finding_events_finding_created", "finding_id", "created_at"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )

    event_type: Mapped[FindingEventType] = mapped_column(
        enum_column(FindingEventType, 32),
        nullable=False,
    )

    # null when the pipeline did it rather than a person
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # what changed, both null for a plain comment
    old_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    new_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=func.now(),
    )

    finding: Mapped["Finding"] = relationship(back_populates="events")

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The finding and what happened to it
        """

        return f"<FindingEvent {self.finding_id} {self.event_type}>"
