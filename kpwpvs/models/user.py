#!/usr/bin/env python3
"""
User Models Module

Accounts, roles, server side sessions, and the audit log. Three roles,
admin does everything including user management, manager reads and works
findings, user reads.

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
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kpwpvs.models.base import Base, TABLE_ARGS, TimestampMixin, enum_column


class UserRole(enum.StrEnum):
    """
    What a user is allowed to do

    Deliberately a flat ladder rather than a permission matrix, three
    levels is enough and stays obvious.
    """

    # everything, including adding users and changing their level
    ADMIN = "admin"
    # read everything and work findings, no user or settings management
    MANAGER = "manager"
    # read only
    USER = "user"

    @property
    def rank(self) -> int:
        """
        Numeric rank for comparisons

        Higher outranks lower, which is all the authorization checks
        actually need.

        @return int: The rank of this role
        """

        # the ladder, in order
        return {UserRole.USER: 1, UserRole.MANAGER: 2, UserRole.ADMIN: 3}[self]


class User(TimestampMixin, Base):
    """
    An account that can sign in to the web interface

    Passwords are argon2 hashes, never anything reversible. The lockout
    counters are here rather than in memory so they survive a restart.
    """

    __tablename__ = "users"
    __table_args__ = (TABLE_ARGS,)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # argon2id, sized for the longest encoded hash we could ever produce
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    role: Mapped[UserRole] = mapped_column(
        enum_column(UserRole, 16),
        nullable=False,
        default=UserRole.USER,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # forces a password change on next sign in, set on seeded accounts
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # brute force throttling, cleared on a successful sign in
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # what hangs off it
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The username and role
        """

        return f"<User {self.username} {self.role}>"


class UserSession(Base):
    """
    A server side session

    Kept in the database rather than purely in a signed cookie so an
    admin can actually revoke somebody, and so sessions survive a
    container restart.
    """

    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_user_expires", "user_id", "expires_at"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # the sha256 of the cookie token, never the token itself, so a dump of
    # this table does not hand somebody a set of live sessions
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # set when somebody signs out or an admin kills the session
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="sessions")

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: The user and when the session expires
        """

        return f"<UserSession {self.user_id} {self.expires_at}>"


class AuditLog(Base):
    """
    A record of something somebody did

    Covers the administrative actions, sign ins, user management, and
    settings changes. Finding workflow history lives on the finding
    itself where it is more useful.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_created_action", "created_at", "action"),
        TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # null when the action was not somebody signed in, a failed login say
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # kept alongside the id so the log still reads correctly after a
    # user has been deleted
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)

    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(191), nullable=True)

    # whatever else is worth keeping about the action
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    def __repr__(self) -> str:
        """
        Readable representation for logs and the shell

        @return str: Who did what
        """

        return f"<AuditLog {self.username} {self.action}>"
