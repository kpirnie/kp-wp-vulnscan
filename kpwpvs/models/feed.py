#!/usr/bin/env python3
"""
Feed Model Module

The vulnerability data sources. These are rows rather than config so
they can be managed from the interface, because api endpoints move,
change their authentication, and occasionally get retired outright.

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
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from kpwpvs.models.base import TABLE_ARGS, Base, TimestampMixin
from kpwpvs.models.vulnerability import FeedSource


class FeedAuth(enum.StrEnum):
    """
    How a feed wants to be authenticated

    Wordfence takes a bearer token, nvd wants its key in a header, cve
    services needs nothing at all.
    """

    NONE = "none"
    BEARER = "bearer"
    HEADER = "header"
    QUERY = "query"


class Feed(TimestampMixin, Base):
    """
    A vulnerability data source

    Carries both the connection settings and the sync state, because in
    practice you always want to see them together.
    """

    __tablename__ = "feeds"
    __table_args__ = (TABLE_ARGS,)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # which source this is, ties rows here to the vulnerabilities they produce
    source: Mapped[FeedSource] = mapped_column(
        Enum(FeedSource, native_enum=False, length=32),
        nullable=False,
        unique=True,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # lower numbers win when two feeds disagree about the same issue
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    # the endpoint, editable because these do move
    url: Mapped[str] = mapped_column(String(1024), nullable=False)

    # how to authenticate, and the name of the header or query parameter
    # when the scheme needs one
    auth_type: Mapped[FeedAuth] = mapped_column(
        Enum(FeedAuth, native_enum=False, length=16),
        nullable=False,
        default=FeedAuth.NONE,
    )
    auth_param: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # the api key, encrypted at rest, never rendered back to the interface
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)

    timeout: Mapped[int] = mapped_column(Integer, nullable=False, default=120)

    # anything feed specific that does not deserve its own column
    options: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # seeded by the migration, so the interface can warn before deleting one
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # sync state, kept here rather than in a separate table because you
    # never want one without the other
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # conditional request hints, saves pulling an unchanged feed in full
    etag: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cursor: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # what the last successful pull produced
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    added_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    @property
    def has_api_key(self) -> bool:
        """
        Whether an api key has been stored for this feed

        The interface shows this instead of the key itself.

        @return bool: True when a key is stored
        """

        return bool(self.api_key_encrypted)

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The source and whether it is enabled
        """

        return f"<Feed {self.source} {'enabled' if self.enabled else 'disabled'}>"
