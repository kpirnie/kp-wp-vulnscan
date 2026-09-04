#!/usr/bin/env python3
"""
Findings Routes Module

Browsing findings, and working them. Reading is open to anybody signed
in; changing a status or leaving a note needs the manager role.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kpwpvs.models import (
    Finding,
    FindingEvent,
    FindingEventType,
    FindingStatus,
    Severity,
    Software,
    User,
    Vulnerability,
)
from kpwpvs.web.deps import get_session, require_manager, require_user
from kpwpvs.web.security import CSRF_COOKIE, CSRF_FIELD, audit, csrf_ok, issue_csrf_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings")

# how many rows a page holds
PAGE_SIZE = 50

# severity worst first, which is the order anybody triages in
SEVERITY_ORDER = [s.value for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE)]


@router.get("", response_class=HTMLResponse)
async def list_findings(
    request: Request,
    severity: str = "",
    state: str = "open",
    kind: str = "plugin",
    q: str = "",
    page: int = 1,
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
) -> HTMLResponse:
    """
    List findings, filtered

    Returns just the table when htmx asked for it, so filtering does not
    reload the whole page.

    @param request: Request The incoming request
    @param severity: str Filter to one severity
    @param state: str Filter to one status, or open for the working set
    @param kind: str Either plugin or core
    @param q: str Search the slug and the vulnerability title
    @param page: int Which page of results
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The page, or just the table for htmx
    """

    page = max(1, page)

    statement = (
        select(Finding, Software, Vulnerability)
        .join(Software, Software.id == Finding.software_id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
    )

    # core findings name a release, plugin findings do not
    if kind == "core":
        statement = statement.where(Finding.software_version_id.is_not(None))
    else:
        statement = statement.where(Finding.software_version_id.is_(None))

    # the working set is anything nobody has closed out
    if state == "open":
        statement = statement.where(
            Finding.status.in_((FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED, FindingStatus.IN_PROGRESS))
        )
    elif state and state != "all":
        statement = statement.where(Finding.status == state)

    if severity:
        statement = statement.where(Finding.severity == severity)

    if q:
        term = f"%{q.strip()}%"
        statement = statement.where(Software.slug.like(term) | Vulnerability.title.like(term))

    # count before paging, so the pager knows how far it goes
    total = session.execute(select(func.count()).select_from(statement.subquery())).scalar_one()

    rows = session.execute(
        statement.order_by(
            func.field(Finding.severity, *SEVERITY_ORDER),
            Software.active_installs.desc(),
        )
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()

    context = {
        "user": user,
        "site_name": request.app.state.site_name,
        "rows": rows,
        "total": total,
        "page": page,
        "pages": max(1, -(-total // PAGE_SIZE)),
        "severity": severity,
        "state": state,
        "kind": kind,
        "q": q,
        "statuses": [s.value for s in FindingStatus],
        "severities": SEVERITY_ORDER,
    }

    # htmx swaps just the results, everything else stays put
    template = "partials/findings_table.html" if request.headers.get("HX-Request") else "findings.html"

    return request.app.state.templates.TemplateResponse(request, template, context)


@router.get("/{finding_id}", response_class=HTMLResponse)
async def finding_detail(
    finding_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
) -> HTMLResponse:
    """
    Show one finding in full

    @param finding_id: int Which finding
    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    @throws HTTPException: When there is no such finding
    """

    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such finding")

    software = session.get(Software, finding.software_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)

    events = session.execute(
        select(FindingEvent, User)
        .outerjoin(User, User.id == FindingEvent.user_id)
        .where(FindingEvent.finding_id == finding.id)
        .order_by(FindingEvent.id.desc())
    ).all()

    token = issue_csrf_token()

    response = request.app.state.templates.TemplateResponse(
        request,
        "finding_detail.html",
        {
            "user": user,
            "site_name": request.app.state.site_name,
            "finding": finding,
            "software": software,
            "vulnerability": vulnerability,
            "events": events,
            "statuses": [s.value for s in FindingStatus],
            "csrf_token": token,
        },
    )
    response.set_cookie(
        CSRF_COOKIE, token, httponly=True, samesite="lax", secure=request.url.scheme == "https", max_age=1800
    )

    return response


@router.post("/{finding_id}")
async def update_finding(
    finding_id: int,
    request: Request,
    new_status: str = Form(...),
    comment: str = Form(""),
    csrf_token: str = Form(..., alias=CSRF_FIELD),
    session: Session = Depends(get_session),
    user: User = Depends(require_manager),
) -> RedirectResponse:
    """
    Change a finding's status, or leave a note on it

    Managers and admins only. Every change leaves an entry in the
    finding's own history.

    @param finding_id: int Which finding
    @param request: Request The incoming request
    @param new_status: str The status to move it to
    @param comment: str An optional note
    @param csrf_token: str The submitted csrf token
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return RedirectResponse: Back to the finding
    @throws HTTPException: When the finding or status is not valid
    """

    if not csrf_ok(request.cookies.get(CSRF_COOKIE), csrf_token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="your session expired, try again")

    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such finding")

    # only a real status, never whatever was posted
    try:
        target = FindingStatus(new_status)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown status") from exc

    previous = finding.status

    # the status move, when it actually moved
    if target is not previous:
        finding.status = target
        finding.resolved_at = datetime.now() if target is FindingStatus.RESOLVED else None
        session.add(
            FindingEvent(
                finding_id=finding.id,
                event_type=FindingEventType.STATUS_CHANGED,
                user_id=user.id or None,
                old_value=previous.value,
                new_value=target.value,
                comment=comment.strip() or None,
            )
        )

    # a note on its own is still worth recording
    elif comment.strip():
        session.add(
            FindingEvent(
                finding_id=finding.id,
                event_type=FindingEventType.COMMENTED,
                user_id=user.id or None,
                comment=comment.strip(),
            )
        )

    session.commit()
    audit(
        session,
        user,
        "finding_updated",
        target_type="finding",
        target_id=finding.id,
        detail={"from": previous.value, "to": target.value},
    )

    return RedirectResponse(f"/findings/{finding.id}", status_code=status.HTTP_303_SEE_OTHER)
