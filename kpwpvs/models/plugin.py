#!/usr/bin/env python3
"""
Plugin Models Module

The wordpress.org plugin catalog, the versions we have seen for each
plugin, and the tags they carry.

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
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kpwpvs.models.base import TABLE_ARGS, Base, TimestampMixin


class PluginStatus(enum.StrEnum):
    """
    Where a plugin stands in the wordpress.org repository

    Closed and abandoned plugins are worth flagging on their own, they
    never get patched no matter what turns up in them.
    """

    ACTIVE = "active"
    CLOSED = "closed"
    # still listed but has not been touched in a very long time
    ABANDONED = "abandoned"
    # we knew about it and it stopped coming back in the catalog
    MISSING = "missing"


class Plugin(TimestampMixin, Base):
    """
    A plugin in the wordpress.org repository

    One row per slug. Carries the catalog metadata we pull from the
    plugins api plus the denormalized issue counts that drive scan
    priority.
    """

    __tablename__ = "plugins"
    __table_args__ = (
        Index("ix_plugins_priority", "priority_score", "issue_count"),
        Index("ix_plugins_status_installs", "status", "active_installs"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # the slug is the real identity, everything else can change
    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
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
    status: Mapped[PluginStatus] = mapped_column(
        Enum(PluginStatus, native_enum=False, length=32),
        nullable=False,
        default=PluginStatus.ACTIVE,
    )
    closed_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # the ranking inputs, recomputed by the matcher after every run
    issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    open_issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # crawl bookkeeping, last_seen tells us when it fell out of the catalog
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_crawled: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    # phase two source scanning bookkeeping
    last_scanned_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # what hangs off it
    versions: Mapped[list["PluginVersion"]] = relationship(
        back_populates="plugin",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    tags: Mapped[list["PluginTag"]] = relationship(
        back_populates="plugin",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The slug and current version
        """

        return f"<Plugin {self.slug} {self.version}>"


class PluginVersion(TimestampMixin, Base):
    """
    A version of a plugin we have seen published

    We only ever see the current version through the api, so this builds
    up over time as the catalog moves.
    """

    __tablename__ = "plugin_versions"
    __table_args__ = (
        UniqueConstraint("plugin_id", "version", name="uq_plugin_versions_plugin_id_version"),
        Index("ix_plugin_versions_plugin_key", "plugin_id", "version_key"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plugin_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("plugins.id", ondelete="CASCADE"),
        nullable=False,
    )

    version: Mapped[str] = mapped_column(String(64), nullable=False)

    # the padded sort key, lets us range scan versions directly in sql
    version_key: Mapped[str] = mapped_column(String(80), nullable=False)

    download_link: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # whether this is the version currently published
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # when we first saw it, and when the repository said it landed
    released_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    plugin: Mapped["Plugin"] = relationship(back_populates="versions")

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The plugin id and version
        """

        return f"<PluginVersion {self.plugin_id} {self.version}>"


class PluginTag(Base):
    """
    A repository tag attached to a plugin

    Kept relational rather than as a json blob so the interface can
    filter and facet on them cheaply.
    """

    __tablename__ = "plugin_tags"
    __table_args__ = (
        UniqueConstraint("plugin_id", "tag", name="uq_plugin_tags_plugin_id_tag"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plugin_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("plugins.id", ondelete="CASCADE"),
        nullable=False,
    )
    tag: Mapped[str] = mapped_column(String(191), nullable=False, index=True)

    plugin: Mapped["Plugin"] = relationship(back_populates="tags")

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The plugin id and tag
        """

        return f"<PluginTag {self.plugin_id} {self.tag}>"
