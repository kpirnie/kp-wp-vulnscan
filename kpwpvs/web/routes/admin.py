#!/usr/bin/env python3
"""
Admin Routes Module

Feeds, settings, users, and run history. Everything here is admin only
except the run history, which managers can see because it tells them
whether the data they are working is current.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from kpwpvs.models import (
    AuditLog,
    Feed,
    Run,
    RunStage,
    User,
    UserRole,
)
from kpwpvs.core.settings import SETTING_GROUPS, group_of
from kpwpvs.services.settings_service import SettingsService
from kpwpvs.web.deps import get_session, get_settings, require_admin, require_manager
from kpwpvs.web.security import (
    CSRF_COOKIE,
    CSRF_FIELD,
    audit,
    csrf_ok,
    hash_password,
    issue_csrf_token,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _with_csrf(request: Request, template: str, context: dict) -> HTMLResponse:
    """
    Render a template with a fresh csrf token attached

    @param request: Request The incoming request
    @param template: str Which template to render
    @param context: dict The template context
    @return HTMLResponse: The rendered page, with the token cookie set
    """

    token = issue_csrf_token()
    context["csrf_token"] = token
    context.setdefault("site_name", request.app.state.site_name)

    response = request.app.state.templates.TemplateResponse(request, template, context)
    response.set_cookie(
        CSRF_COOKIE, token, httponly=True, samesite="lax", secure=request.url.scheme == "https", max_age=1800
    )

    return response


def _check_csrf(request: Request, token: str) -> None:
    """
    Reject a post whose csrf token does not match

    @param request: Request The incoming request
    @param token: str The submitted token
    @return None
    @throws HTTPException: When the token does not match
    """

    if not csrf_ok(request.cookies.get(CSRF_COOKIE), token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="your session expired, try again")


@router.get("/runs", response_class=HTMLResponse)
async def run_history(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_manager),
) -> HTMLResponse:
    """
    Recent runs and how each stage went

    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    """

    runs = session.execute(select(Run).order_by(Run.id.desc()).limit(30)).scalars().all()

    # the stages for those runs, grouped so the template can nest them
    stages: dict[int, list[RunStage]] = {}
    if runs:
        rows = session.execute(
            select(RunStage).where(RunStage.run_id.in_([r.id for r in runs])).order_by(RunStage.id)
        ).scalars().all()
        for stage in rows:
            stages.setdefault(stage.run_id, []).append(stage)

    return request.app.state.templates.TemplateResponse(
        request,
        "runs.html",
        {
            "user": user,
            "site_name": request.app.state.site_name,
            "runs": runs,
            "stages": stages,
        },
    )


@router.get("/feeds", response_class=HTMLResponse)
async def feeds_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
) -> HTMLResponse:
    """
    The vulnerability feeds, and their sync state

    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    """

    feeds = session.execute(select(Feed).order_by(Feed.priority)).scalars().all()

    return _with_csrf(
        request,
        "feeds.html",
        {
            "user": user,
            "feeds": feeds,
            "can_store_keys": request.app.state.secret_box is not None,
        },
    )


@router.post("/feeds/{feed_id}")
async def update_feed(
    feed_id: int,
    request: Request,
    url: str = Form(...),
    timeout: int = Form(...),
    priority: int = Form(...),
    enabled: str = Form(""),
    api_key: str = Form(""),
    clear_key: str = Form(""),
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
) -> RedirectResponse:
    """
    Update a feed

    The endpoint is editable on purpose. The wordfence v2 feed was
    retired mid-project and started answering 410, and being able to
    point at the replacement without a redeploy is the whole reason
    these are rows rather than configuration.

    @param feed_id: int Which feed
    @param request: Request The incoming request
    @param url: str The endpoint
    @param timeout: int Seconds to wait on it
    @param priority: int Lower wins when feeds disagree
    @param enabled: str Present when the checkbox was ticked
    @param api_key: str A new key, when one was typed
    @param clear_key: str Present when the stored key should be removed
    @param csrf_token: str The submitted csrf token
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return RedirectResponse: Back to the feeds page
    @throws HTTPException: When the feed does not exist
    """

    _check_csrf(request, csrf_token)

    feed = session.get(Feed, feed_id)
    if feed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such feed")

    feed.url = url.strip()
    feed.timeout = max(1, timeout)
    feed.priority = priority
    feed.enabled = bool(enabled)

    # the key is only touched when somebody actually typed one, so saving
    # the form without retyping it does not wipe it
    secret_box = request.app.state.secret_box
    if clear_key:
        feed.api_key_encrypted = None
    elif api_key.strip():
        if secret_box is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="no secret key is configured, so api keys cannot be stored",
            )
        feed.api_key_encrypted = secret_box.encrypt(api_key.strip())

    session.commit()
    audit(session, user, "feed_updated", target_type="feed", target_id=feed.source.value)

    return RedirectResponse("/feeds", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    settings: SettingsService = Depends(get_settings),
    user: User = Depends(require_admin),
) -> HTMLResponse:
    """
    Every setting, grouped the way the registry declares them

    @param request: Request The incoming request
    @param settings: SettingsService The interface settings
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    """

    # build the groups, never rendering a secret's value back out
    groups = []
    for group in SETTING_GROUPS:
        entries = []
        for definition in group_of(group):
            entries.append(
                {
                    "definition": definition,
                    "value": "" if definition.is_secret else settings.get(definition.key),
                    "is_set": bool(settings.get(definition.key)) if definition.is_secret else None,
                }
            )
        groups.append({"name": group, "entries": entries})

    return _with_csrf(request, "settings.html", {"user": user, "groups": groups})


@router.post("/settings")
async def update_settings(
    request: Request,
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    settings: SettingsService = Depends(get_settings),
    user: User = Depends(require_admin),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """
    Save the settings form

    @param request: Request The incoming request
    @param csrf_token: str The submitted csrf token
    @param settings: SettingsService The interface settings
    @param user: User Whoever is signed in
    @param session: Session The request's database session
    @return RedirectResponse: Back to the settings page
    """

    _check_csrf(request, csrf_token)

    form = await request.form()
    changed = []

    # walk the registry rather than the form, so nothing unexpected is
    # accepted just because somebody posted it
    for group in SETTING_GROUPS:
        for definition in group_of(group):
            field = f"setting__{definition.key}"

            # a checkbox that is off simply is not submitted
            if definition.type.value == "boolean":
                new_value = field in form
            elif field not in form:
                continue
            else:
                new_value = str(form[field])

            # an untouched secret stays as it is
            if definition.is_secret and not new_value:
                continue

            try:
                settings.set(definition.key, new_value, user.id or None)
                changed.append(definition.key)
            except ValueError as exc:
                logger.warning("rejected %s: %s", definition.key, exc)

    session.commit()
    audit(session, user, "settings_updated", detail={"changed": changed})

    return RedirectResponse("/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
) -> HTMLResponse:
    """
    The accounts, and the recent audit trail

    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    """

    users = session.execute(select(User).order_by(User.username)).scalars().all()
    events = session.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(40)).scalars().all()

    return _with_csrf(
        request,
        "users.html",
        {"user": user, "users": users, "events": events, "roles": [r.value for r in UserRole]},
    )


@router.post("/users")
async def create_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(""),
    display_name: str = Form(""),
    role: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
) -> RedirectResponse:
    """
    Add an account

    @param request: Request The incoming request
    @param username: str The new username
    @param email: str Their email, optional
    @param display_name: str Their display name, optional
    @param role: str Which role to give them
    @param password: str Their initial password
    @param csrf_token: str The submitted csrf token
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return RedirectResponse: Back to the users page
    @throws HTTPException: When the input is not acceptable
    """

    _check_csrf(request, csrf_token)

    username = username.strip()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="a username is required")

    if len(password) < 12:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="use at least 12 characters")

    try:
        target_role = UserRole(role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown role") from exc

    existing = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="that username is taken")

    session.add(
        User(
            username=username,
            email=email.strip() or None,
            display_name=display_name.strip() or None,
            role=target_role,
            password_hash=hash_password(password),
            must_change_password=True,
        )
    )
    session.commit()
    audit(session, user, "user_created", target_type="user", target_id=username, detail={"role": role})

    return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}")
async def update_user(
    user_id: int,
    request: Request,
    role: str = Form(...),
    is_active: str = Form(""),
    unlock: str = Form(""),
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
) -> RedirectResponse:
    """
    Change an account's role or state

    An admin cannot demote or deactivate themselves, which is the usual
    way somebody locks everybody out of their own install.

    @param user_id: int Which account
    @param request: Request The incoming request
    @param role: str The role to set
    @param is_active: str Present when the account should stay active
    @param unlock: str Present when a lockout should be cleared
    @param csrf_token: str The submitted csrf token
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return RedirectResponse: Back to the users page
    @throws HTTPException: When the change is not allowed
    """

    _check_csrf(request, csrf_token)

    target = session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such user")

    try:
        new_role = UserRole(role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown role") from exc

    # do not let somebody lock themselves out
    if target.id == user.id and (new_role is not UserRole.ADMIN or not is_active):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="you cannot remove your own admin access",
        )

    # nor the last admin standing
    remaining_admins = session.execute(
        select(User).where(User.role == UserRole.ADMIN, User.is_active.is_(True), User.id != target.id)
    ).scalars().all()

    if target.role is UserRole.ADMIN and not remaining_admins and (new_role is not UserRole.ADMIN or not is_active):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="this is the only active admin, promote somebody else first",
        )

    target.role = new_role
    target.is_active = bool(is_active)

    if unlock:
        target.locked_until = None
        target.failed_attempts = 0

    session.commit()
    audit(
        session,
        user,
        "user_updated",
        target_type="user",
        target_id=target.username,
        detail={"role": new_role.value, "active": bool(is_active)},
    )

    return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/reset")
async def reset_password(
    user_id: int,
    request: Request,
    password: str = Form(...),
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
) -> RedirectResponse:
    """
    Set a new password on an account

    The account is forced to change it on next sign in, so an admin never
    ends up knowing somebody's working password.

    @param user_id: int Which account
    @param request: Request The incoming request
    @param password: str The temporary password
    @param csrf_token: str The submitted csrf token
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return RedirectResponse: Back to the users page
    @throws HTTPException: When the account or password is not acceptable
    """

    _check_csrf(request, csrf_token)

    target = session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such user")

    if len(password) < 12:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="use at least 12 characters")

    target.password_hash = hash_password(password)
    target.must_change_password = True
    target.failed_attempts = 0
    target.locked_until = None

    # every session that account had is now void
    from kpwpvs.models import UserSession

    session.execute(
        UserSession.__table__.update()
        .where(UserSession.user_id == target.id)
        .values(revoked_at=datetime.now())
    )
    session.commit()

    audit(session, user, "password_reset", target_type="user", target_id=target.username)

    return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)
