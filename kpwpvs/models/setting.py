#!/usr/bin/env python3
"""
Settings Model Module

Database backed settings, so an admin can change things from the web
interface without editing the yaml and restarting. Secrets are stored
encrypted rather than in the clear.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from kpwpvs.models.base import TABLE_ARGS, Base, TimestampMixin


class Setting(TimestampMixin, Base):
    """
    One configuration value an admin can change from the interface

    The key is the dotted config path, so "feeds.wordfence.api_key" here
    overlays exactly that field in the loaded configuration. Anything
    marked secret is stored encrypted and never rendered back out.
    """

    __tablename__ = "settings"
    __table_args__ = (TABLE_ARGS,)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # the dotted path into the config tree, eg. feeds.wordfence.api_key
    key: Mapped[str] = mapped_column(String(191), nullable=False, unique=True)

    # the value as a json encoded scalar, so types survive the round trip.
    # for a secret this holds the ciphertext instead
    value: Mapped[str | None] = mapped_column(Text, nullable=True)

    # secrets are encrypted with a key derived from web.secret_key, and the
    # interface only ever shows whether one is set, never the value
    is_secret: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # who changed it last, for the settings page and the audit trail
    updated_by_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_by_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The key, never the value
        """

        return f"<Setting {self.key}{' (secret)' if self.is_secret else ''}>"
