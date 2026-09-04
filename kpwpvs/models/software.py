#!/usr/bin/env python3
"""
Software Models Module

The wordpress.org catalog, the versions we have seen for each entry, and
the tags they carry. Plugins today, themes when phase two lands, which
is why this is software rather than plugins, the two differ in almost
nothing that matters here.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import enum
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Double,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kpwpvs.models.base import TABLE_ARGS, Base, TimestampMixin, enum_column
from kpwpvs.models.vulnerability import SoftwareType


class ReleaseStatus(enum.StrEnum):
    """
    What wordpress.org says about a particular release

    Only core carries this today, because core is the only thing
    wordpress.org publishes a per release security verdict for. It is
    their assessment, kept alongside our own matching rather than
    instead of it.
    """

    LATEST = "latest"
    OUTDATED = "outdated"
    INSECURE = "insecure"
    UNKNOWN = "unknown"


class SoftwareStatus(enum.StrEnum):
    """
    Where an entry stands in the wordpress.org repository

    Closed and abandoned entries are worth flagging on their own, they
    never get patched no matter what turns up in them. Premium ones are
    not in the free repository at all, we only know they exist because a
    vulnerability feed named them.
    """

    ACTIVE = "active"
    CLOSED = "closed"
    # still listed but has not been touched in a very long time
    ABANDONED = "abandoned"
    # we knew about it and it stopped coming back in the catalog
    MISSING = "missing"
    # commercial, never in the free repository, known only from the feeds
    PREMIUM = "premium"


class Software(TimestampMixin, Base):
    """
    An entry in the wordpress.org catalog

    One row per slug. Carries the catalog metadata we pull from the
    plugins api plus the denormalized issue counts that drive scan
    priority.
    """

    __tablename__ = "software"
    __table_args__ = (
        UniqueConstraint("slug", "software_type", name="uq_software_slug_software_type"),
        Index("ix_software_priority", "priority_score", "issue_count"),
        Index("ix_software_status_installs", "status", "active_installs"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # slug and type together are the identity. a plugin and a theme can
    # legitimately share a slug, so the type has to be part of the key
    slug: Mapped[str] = mapped_column(String(255), nullable=False)
    software_type: Mapped[SoftwareType] = mapped_column(
        enum_column(SoftwareType, 16),
        nullable=False,
        default=SoftwareType.PLUGIN,
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    # the version currently published in the repository
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version_key: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)

    # who publishes it, the author field comes back as an html anchor so we
    # keep the cleaned name and the profile url separately
    author: Mapped[str | None] = mapped_column(String(512), nullable=True)
    author_profile: Mapped[str | None] = mapped_column(String(512), nullable=True)
    homepage: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    download_link: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    short_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # compatibility, all strings because "trunk" and "" both show up
    requires_wp: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tested_wp: Mapped[str | None] = mapped_column(String(32), nullable=True)
    requires_php: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # popularity signals, these weight the priority score
    rating: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    num_ratings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active_installs: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    downloaded: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    support_threads: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    support_threads_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # repository dates, added is a plain date, last_updated a timestamp
    added_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_updated: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    # where it stands, and why if it is closed
    status: Mapped[SoftwareStatus] = mapped_column(
        enum_column(SoftwareStatus, 32),
        nullable=False,
        default=SoftwareStatus.ACTIVE,
    )
    closed_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # the ranking inputs, recomputed by the matcher after every run
    issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    open_issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority_score: Mapped[float] = mapped_column(Double, nullable=False, default=0.0)

    # crawl bookkeeping, last_seen tells us when it fell out of the catalog
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_crawled: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    # phase two source scanning bookkeeping
    last_scanned_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # what hangs off it
    versions: Mapped[list[SoftwareVersion]] = relationship(
        back_populates="software",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    tags: Mapped[list[SoftwareTag]] = relationship(
        back_populates="software",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The slug and current version
        """

        return f"<Software {self.slug} {self.version}>"


class SoftwareVersion(TimestampMixin, Base):
    """
    A version of a plugin we have seen published

    We only ever see the current version through the api, so this builds
    up over time as the catalog moves.
    """

    __tablename__ = "software_versions"
    __table_args__ = (
        UniqueConstraint("software_id", "version", name="uq_software_versions_software_id_version"),
        Index("ix_software_versions_software_key", "software_id", "version_key"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    software_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("software.id", ondelete="CASCADE"),
        nullable=False,
    )

    version: Mapped[str] = mapped_column(String(64), nullable=False)

    # the padded sort key, lets us range scan versions directly in sql
    version_key: Mapped[str] = mapped_column(String(80), nullable=False)

    download_link: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # whether this is the version currently published
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # wordpress.org's own verdict on this release, core only for now
    release_status: Mapped[ReleaseStatus] = mapped_column(
        enum_column(ReleaseStatus, 16),
        nullable=False,
        default=ReleaseStatus.UNKNOWN,
        index=True,
    )

    # how many known vulnerabilities affect this specific version, which
    # for core is the number somebody actually wants to see
    issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # when we first saw it, and when the repository said it landed
    released_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    software: Mapped[Software] = relationship(back_populates="versions")

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The software id and version
        """

        return f"<SoftwareVersion {self.software_id} {self.version}>"


class SoftwareTag(Base):
    """
    A repository tag attached to a plugin

    Kept relational rather than as a json blob so the interface can
    filter and facet on them cheaply.
    """

    __tablename__ = "software_tags"
    __table_args__ = (
        UniqueConstraint("software_id", "tag", name="uq_software_tags_software_id_tag"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    software_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("software.id", ondelete="CASCADE"),
        nullable=False,
    )
    tag: Mapped[str] = mapped_column(String(191), nullable=False, index=True)

    software: Mapped[Software] = relationship(back_populates="tags")

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The software id and tag
        """

        return f"<SoftwareTag {self.software_id} {self.tag}>"
