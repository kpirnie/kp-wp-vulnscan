#!/usr/bin/env python3
"""
Authentication Routes Module

Signing in and out, and the password change somebody is forced through
when their account was seeded with a temporary one.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from kpwpvs.models import User
from kpwpvs.services.settings_service import SettingsService
from kpwpvs.web.deps import current_user, get_session, get_settings, require_user
from kpwpvs.web.security import (
    CSRF_COOKIE,
    CSRF_FIELD,
    SESSION_COOKIE,
    audit,
    create_session,
    csrf_ok,
    hash_password,
    is_locked,
    issue_csrf_token,
    needs_rehash,
    note_failed_login,
    purge_expired_sessions,
    revoke_session,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# deliberately identical whatever went wrong, so the page never says
# whether a username exists
LOGIN_FAILED = "That username and password combination was not recognised."


def _client_ip(request: Request) -> str | None:
    """
    Best effort at the client address

    Honors the usual proxy header, since this is expected to sit behind
    one, and falls back to the socket address.

    @param request: Request The incoming request
    @return str|None: The client address
    """

    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]

    return request.client.host if request.client else None


def _render_login(request: Request, error: str | None = None, next_url: str = "/") -> HTMLResponse:
    """
    Render the sign in page with a fresh csrf token

    @param request: Request The incoming request
    @param error: str|None A message to show
    @param next_url: str Where to go after signing in
    @return HTMLResponse: The rendered page
    """

    token = issue_csrf_token()

    response = request.app.state.templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": error,
            "next_url": next_url,
            "csrf_token": token,
            "site_name": request.app.state.site_name,
            "user": None,
        },
        status_code=status.HTTP_401_UNAUTHORIZED if error else status.HTTP_200_OK,
    )
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=1800,
    )

    return response


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str = "/") -> HTMLResponse:
    """
    Show the sign in page

    @param request: Request The incoming request
    @param next: str Where to go after signing in
    @return HTMLResponse: The rendered page
    """

    # already signed in, no reason to be here
    if not request.app.state.auth_enabled:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)

    return _render_login(request, next_url=next)


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next_url: str = Form("/"),
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    session: Session = Depends(get_session),
    settings: SettingsService = Depends(get_settings),
) -> HTMLResponse:
    """
    Handle a sign in attempt

    @param request: Request The incoming request
    @param username: str The username offered
    @param password: str The password offered
    @param next_url: str Where to go on success
    @param csrf_token: str The submitted csrf token
    @param session: Session The request's database session
    @param settings: SettingsService The interface settings
    @return HTMLResponse: A redirect on success, the form again on failure
    """

    # the form has to carry a token matching the cookie
    if not csrf_ok(request.cookies.get(CSRF_COOKIE), csrf_token):
        return _render_login(request, "Your session expired, please try again.", next_url)

    ip_address = _client_ip(request)

    # look them up. note every path below costs a password verification,
    # so a missing account and a wrong password take the same time
    user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()

    # a locked account is told it is locked, there is no point hiding that
    # from somebody who already knows the username
    if user is not None and is_locked(user):
        note_failed_login(session, user, username, 10**9, 0, ip_address)
        return _render_login(request, "That account is temporarily locked. Try again shortly.", next_url)

    matched = verify_password(user.password_hash if user else None, password)

    # anything wrong gives the same answer
    if user is None or not matched or not user.is_active:
        note_failed_login(
            session,
            user,
            username,
            settings.get("web.max_failed_logins"),
            settings.get("web.lockout_minutes"),
            ip_address,
        )
        return _render_login(request, LOGIN_FAILED, next_url)

    # take the opportunity to upgrade an old hash
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    # and to clear out sessions nobody is using
    purge_expired_sessions(session)

    token = create_session(
        session,
        user,
        settings.get("web.session_ttl"),
        ip_address,
        request.headers.get("User-Agent"),
    )
    audit(session, user, "login", ip_address=ip_address)

    # somewhere sensible to land, refusing anything that is not a local path
    destination = next_url if next_url.startswith("/") and not next_url.startswith("//") else "/"
    if user.must_change_password:
        destination = "/password"

    response = RedirectResponse(destination, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=settings.get("web.session_ttl"),
    )
    response.delete_cookie(CSRF_COOKIE)

    return response


@router.post("/logout")
async def logout(
    request: Request,
    session: Session = Depends(get_session),
    user: User | None = Depends(current_user),
) -> RedirectResponse:
    """
    Sign out

    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User|None Whoever is signed in
    @return RedirectResponse: Back to the sign in page
    """

    revoke_session(session, request.cookies.get(SESSION_COOKIE))

    if user is not None and user.id:
        audit(session, user, "logout", ip_address=_client_ip(request))

    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)

    return response


@router.get("/password", response_class=HTMLResponse)
async def password_form(request: Request, user: User = Depends(require_user)) -> HTMLResponse:
    """
    Show the change password page

    @param request: Request The incoming request
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    """

    token = issue_csrf_token()

    response = request.app.state.templates.TemplateResponse(
        request,
        "password.html",
        {"user": user, "csrf_token": token, "site_name": request.app.state.site_name, "error": None},
    )
    response.set_cookie(
        CSRF_COOKIE, token, httponly=True, samesite="lax", secure=request.url.scheme == "https", max_age=1800
    )

    return response


@router.post("/password", response_class=HTMLResponse)
async def password_submit(
    request: Request,
    current: str = Form(...),
    replacement: str = Form(...),
    confirm: str = Form(...),
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
) -> HTMLResponse:
    """
    Change the signed in user's password

    @param request: Request The incoming request
    @param current: str Their current password
    @param replacement: str The new password
    @param confirm: str The new password again
    @param csrf_token: str The submitted csrf token
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: A redirect on success, the form again on failure
    """

    def fail(message: str) -> HTMLResponse:
        """
        Render the form again with a message

        @param message: str What went wrong
        @return HTMLResponse: The rendered page
        """

        token = issue_csrf_token()
        response = request.app.state.templates.TemplateResponse(
            request,
            "password.html",
            {"user": user, "csrf_token": token, "site_name": request.app.state.site_name, "error": message},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
        response.set_cookie(
            CSRF_COOKIE, token, httponly=True, samesite="lax", secure=request.url.scheme == "https", max_age=1800
        )
        return response

    if not csrf_ok(request.cookies.get(CSRF_COOKIE), csrf_token):
        return fail("Your session expired, please try again.")

    # the current one has to be right, even though they are already signed in
    if not verify_password(user.password_hash, current):
        return fail("Your current password was not correct.")

    if replacement != confirm:
        return fail("The new passwords did not match.")

    if len(replacement) < 12:
        return fail("Use at least 12 characters.")

    if replacement == current:
        return fail("The new password has to be different from the old one.")

    user.password_hash = hash_password(replacement)
    user.must_change_password = False
    session.commit()

    audit(session, user, "password_changed", ip_address=_client_ip(request))

    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
