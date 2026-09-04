#!/usr/bin/env python3
"""
Web Security Module

Password hashing, session handling, and the role checks every route
leans on. Deliberately conservative: argon2id for passwords, only a hash
of the session token ever reaches the database, and a failed sign in
costs the same amount of time whether or not the account exists.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from kpwpvs.models import AuditLog, User, UserRole, UserSession

logger = logging.getLogger(__name__)

# the cookie the session token rides in
SESSION_COOKIE = "kpwpvs_session"

# and the one carrying the csrf token
CSRF_COOKIE = "kpwpvs_csrf"
CSRF_FIELD = "csrf_token"

# argon2id at sensible defaults. these are the library's own recommended
# parameters rather than something invented here
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# a real argon2 hash of a throwaway value. verifying against this when the
# account does not exist keeps a failed sign in the same cost either way,
# so the response time does not say whether a username is real
_DUMMY_HASH = _hasher.hash("kpwpvs-timing-equalizer")


def hash_password(password: str) -> str:
    """
    Hash a password for storage

    @param password: str The plaintext password
    @return str: The encoded argon2id hash
    @throws ValueError: When the password is empty
    """

    # refuse to hash nothing, that is a bug not a password
    if not password:
        raise ValueError("a password is required")

    return _hasher.hash(password)


def verify_password(encoded: str | None, password: str) -> bool:
    """
    Check a password against a stored hash

    Always does the work, even with nothing to check against, so the
    caller cannot leak account existence through timing.

    @param encoded: str|None The stored hash, or None when there is none
    @param password: str The plaintext password offered
    @return bool: True when the password matches
    """

    # no stored hash still costs a verification, against the dummy
    target = encoded or _DUMMY_HASH

    try:
        _hasher.verify(target, password)
    except VerifyMismatchError, InvalidHashError:
        return False
    except Exception as exc:
        logger.warning("password verification failed unexpectedly: %s", exc)
        return False

    # a match against the dummy is never a real match
    return encoded is not None


def needs_rehash(encoded: str) -> bool:
    """
    Whether a stored hash was made with outdated parameters

    @param encoded: str The stored hash
    @return bool: True when it should be rehashed on next sign in
    """

    try:
        return _hasher.check_needs_rehash(encoded)
    except InvalidHashError:
        return True


def hash_token(token: str) -> str:
    """
    Hash a session token for storage

    Session tokens are high entropy random values rather than passwords,
    so a fast hash is right here. What matters is that a dump of the
    sessions table does not hand somebody a set of live sessions.

    @param token: str The raw session token
    @return str: The hex sha256 of the token
    """

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    session: Session,
    user: User,
    ttl_seconds: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> str:
    """
    Open a server side session for a user

    @param session: Session The database session
    @param user: User Who is signing in
    @param ttl_seconds: int How long the session lasts
    @param ip_address: str|None Where they signed in from
    @param user_agent: str|None What they signed in with
    @return str: The raw token to set as a cookie, never stored
    """

    # generate it, store only the hash
    token = secrets.token_urlsafe(48)

    session.add(
        UserSession(
            token_hash=hash_token(token),
            user_id=user.id,
            expires_at=datetime.now() + timedelta(seconds=ttl_seconds),
            last_seen_at=datetime.now(),
            ip_address=ip_address,
            user_agent=(user_agent or "")[:512] or None,
        )
    )

    # note the sign in on the account itself
    user.last_login_at = datetime.now()
    user.last_login_ip = ip_address
    user.failed_attempts = 0
    user.locked_until = None

    session.commit()

    return token


def resolve_session(session: Session, token: str | None) -> User | None:
    """
    Find the user behind a session token

    Rejects anything expired or revoked, and refreshes the last seen
    timestamp so an idle session is visible as idle.

    @param session: Session The database session
    @param token: str|None The raw token from the cookie
    @return User|None: The signed in user, or None
    """

    # nothing offered, nobody signed in
    if not token:
        return None

    row = session.execute(select(UserSession).where(UserSession.token_hash == hash_token(token))).scalar_one_or_none()

    # unknown, revoked, or expired all mean the same thing to the caller
    if row is None or row.revoked_at is not None or row.expires_at < datetime.now():
        return None

    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        return None

    # keep the session's own record current
    row.last_seen_at = datetime.now()
    session.commit()

    return user


def revoke_session(session: Session, token: str | None) -> None:
    """
    Revoke a session

    @param session: Session The database session
    @param token: str|None The raw token from the cookie
    @return None
    """

    # nothing to revoke
    if not token:
        return

    row = session.execute(select(UserSession).where(UserSession.token_hash == hash_token(token))).scalar_one_or_none()

    if row is not None:
        row.revoked_at = datetime.now()
        session.commit()


def purge_expired_sessions(session: Session) -> int:
    """
    Delete sessions that have expired

    Called on sign in, which is often enough to keep the table honest
    without needing its own schedule.

    @param session: Session The database session
    @return int: How many rows were removed
    """

    result = session.execute(UserSession.__table__.delete().where(UserSession.expires_at < datetime.now()))
    session.commit()

    return result.rowcount or 0


def is_locked(user: User) -> bool:
    """
    Whether an account is currently locked out

    @param user: User The account to check
    @return bool: True while the lockout is in force
    """

    return user.locked_until is not None and user.locked_until > datetime.now()


def note_failed_login(
    session: Session,
    user: User | None,
    username: str,
    max_attempts: int,
    lockout_minutes: int,
    ip_address: str | None,
) -> None:
    """
    Record a failed sign in, locking the account when it repeats

    @param session: Session The database session
    @param user: User|None The account, when the username matched one
    @param username: str What was typed, for the audit log
    @param max_attempts: int Failures allowed before a lockout
    @param lockout_minutes: int How long the lockout lasts
    @param ip_address: str|None Where the attempt came from
    @return None
    """

    # count it against the account when there is one
    if user is not None:
        user.failed_attempts += 1
        if user.failed_attempts >= max_attempts:
            user.locked_until = datetime.now() + timedelta(minutes=lockout_minutes)
            logger.warning("locked %s after %s failed attempts", user.username, user.failed_attempts)

    # and log it either way, a run of failures against a username that does
    # not exist is worth being able to see
    session.add(
        AuditLog(
            user_id=user.id if user else None,
            username=username[:64],
            action="login_failed",
            ip_address=ip_address,
        )
    )
    session.commit()


def audit(
    session: Session,
    user: User | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """
    Write an entry to the audit log

    @param session: Session The database session
    @param user: User|None Who did it
    @param action: str What they did
    @param target_type: str|None What kind of thing they did it to
    @param target_id: str|None Which one
    @param detail: dict|None Anything else worth keeping
    @param ip_address: str|None Where from
    @return None
    """

    session.add(
        AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else None,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            detail=detail,
            ip_address=ip_address,
        )
    )
    session.commit()


def issue_csrf_token() -> str:
    """
    Generate a csrf token

    @return str: A fresh random token
    """

    return secrets.token_urlsafe(32)


def csrf_ok(cookie_token: str | None, form_token: str | None) -> bool:
    """
    Check a submitted csrf token against the cookie

    Double submit: the token is in a cookie and in the form, and they
    have to match. Compared in constant time.

    @param cookie_token: str|None The token from the cookie
    @param form_token: str|None The token from the submitted form
    @return bool: True when they match
    """

    # both have to be there
    if not cookie_token or not form_token:
        return False

    return hmac.compare_digest(cookie_token, form_token)


def can(user: User | None, minimum: UserRole) -> bool:
    """
    Whether a user meets a minimum role

    @param user: User|None The signed in user, when there is one
    @param minimum: UserRole The role required
    @return bool: True when the user outranks or matches it
    """

    # nobody signed in never passes
    if user is None or not user.is_active:
        return False

    return user.role.rank >= minimum.rank
