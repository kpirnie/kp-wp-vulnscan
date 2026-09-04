#!/usr/bin/env python3
"""
Web Dependencies Module

The shared request dependencies: a database session, whoever is signed
in, and the role gates routes use to say who may do what.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from collections.abc import Callable, Iterator

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from kpwpvs.core.crypto import SecretBox
from kpwpvs.core.db import session_scope
from kpwpvs.models import User, UserRole
from kpwpvs.services.settings_service import SettingsService
from kpwpvs.web.security import SESSION_COOKIE, can, resolve_session

logger = logging.getLogger(__name__)


class RedirectToLogin(Exception):
    """
    Raised when an anonymous request hits a page that needs a sign in

    Handled by an exception handler so it becomes a redirect rather than
    an error page.
    """

    def __init__(self, next_url: str = "/") -> None:
        """
        Note where they were trying to go

        @param next_url: str The path to return to after signing in
        """

        self.next_url = next_url


def get_session() -> Iterator[Session]:
    """
    Hand out a database session for the request

    @return Iterator[Session]: The session, for the life of the request
    """

    with session_scope() as session:
        yield session


def get_settings(request: Request, session: Session = Depends(get_session)) -> SettingsService:
    """
    Build a settings service for the request

    @param request: Request The incoming request
    @param session: Session The request's database session
    @return SettingsService: Settings, with secrets readable when possible
    """

    # the box is built once at startup and kept on the app
    secret_box: SecretBox | None = getattr(request.app.state, "secret_box", None)

    return SettingsService(session, secret_box)


def current_user(request: Request, session: Session = Depends(get_session)) -> User | None:
    """
    Whoever is signed in, if anybody

    @param request: Request The incoming request
    @param session: Session The request's database session
    @return User|None: The signed in user, or None
    """

    # when auth is switched off everything runs as a synthetic admin, which
    # is only sane behind something else doing the authenticating
    if not request.app.state.auth_enabled:
        return request.app.state.anonymous_admin

    return resolve_session(session, request.cookies.get(SESSION_COOKIE))


def require(minimum: UserRole) -> Callable:
    """
    Build a dependency that enforces a minimum role

    Anonymous requests are redirected to the sign in page. A signed in
    user who simply lacks the role gets a plain refusal, because sending
    them to sign in again would only loop.

    @param minimum: UserRole The role the route requires
    @return Callable: A FastAPI dependency
    """

    def guard(request: Request, user: User | None = Depends(current_user)) -> User:
        """
        Enforce the role

        @param request: Request The incoming request
        @param user: User|None Whoever is signed in
        @return User: The signed in user, when they are allowed through
        @throws RedirectToLogin: When nobody is signed in
        @throws HTTPException: When they are signed in but outranked
        """

        # not signed in at all, send them to do that
        if user is None:
            raise RedirectToLogin(request.url.path)

        # signed in but not allowed, say so plainly
        if not can(user, minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"this needs the {minimum.value} role or higher",
            )

        return user

    return guard


# the three gates, named for what they let through
require_user = require(UserRole.USER)
require_manager = require(UserRole.MANAGER)
require_admin = require(UserRole.ADMIN)


def login_redirect(next_url: str = "/") -> RedirectResponse:
    """
    Build the redirect to the sign in page

    @param next_url: str Where to return to afterwards
    @return RedirectResponse: The redirect
    """

    from urllib.parse import quote

    return RedirectResponse(f"/login?next={quote(next_url, safe='')}", status_code=status.HTTP_303_SEE_OTHER)
