#!/usr/bin/env python3
"""
Catalog Routes Module

Browsing the software catalog and the core release history.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kpwpvs.models import (
    Finding,
    Software,
    SoftwareStatus,
    SoftwareTag,
    SoftwareType,
    SoftwareVersion,
    User,
    Vulnerability,
)
from kpwpvs.web.deps import get_session, require_user

logger = logging.getLogger(__name__)

router = APIRouter()

# how many rows a page holds
PAGE_SIZE = 50


@router.get("/software", response_class=HTMLResponse)
async def list_software(
    request: Request,
    q: str = "",
    software_type: str = "",
    software_status: str = "",
    sort: str = "priority",
    page: int = 1,
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
) -> HTMLResponse:
    """
    Browse the catalog

    @param request: Request The incoming request
    @param q: str Search the slug and name
    @param software_type: str Filter by plugin, theme, or core
    @param software_status: str Filter by catalog status
    @param sort: str Either priority, issues, or installs
    @param page: int Which page of results
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The page, or just the table for htmx
    """

    page = max(1, page)
    statement = select(Software)

    if q:
        term = f"%{q.strip()}%"
        statement = statement.where(Software.slug.like(term) | Software.name.like(term))
    if software_type:
        statement = statement.where(Software.software_type == software_type)
    if software_status:
        statement = statement.where(Software.status == software_status)

    total = session.execute(select(func.count()).select_from(statement.subquery())).scalar_one()

    # the sort somebody picked, defaulting to what we would scan first
    ordering = {
        "priority": Software.priority_score.desc(),
        "issues": Software.issue_count.desc(),
        "installs": Software.active_installs.desc(),
        "updated": Software.last_updated.desc(),
    }.get(sort, Software.priority_score.desc())

    rows = session.execute(statement.order_by(ordering).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)).scalars().all()

    context = {
        "user": user,
        "site_name": request.app.state.site_name,
        "rows": rows,
        "total": total,
        "page": page,
        "pages": max(1, -(-total // PAGE_SIZE)),
        "q": q,
        "software_type": software_type,
        "software_status": software_status,
        "sort": sort,
        "types": [t.value for t in SoftwareType],
        "statuses": [s.value for s in SoftwareStatus],
    }

    template = "partials/software_table.html" if request.headers.get("HX-Request") else "software.html"

    return request.app.state.templates.TemplateResponse(request, template, context)


@router.get("/software/{software_id}", response_class=HTMLResponse)
async def software_detail(
    software_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
) -> HTMLResponse:
    """
    Show one catalog entry in full

    @param software_id: int Which entry
    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    @throws HTTPException: When there is no such entry
    """

    software = session.get(Software, software_id)
    if software is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such catalog entry")

    findings = session.execute(
        select(Finding, Vulnerability)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(Finding.software_id == software.id)
        .order_by(Vulnerability.cvss_score.desc())
        .limit(100)
    ).all()

    versions = (
        session.execute(
            select(SoftwareVersion)
            .where(SoftwareVersion.software_id == software.id)
            .order_by(SoftwareVersion.version_key.desc())
            .limit(25)
        )
        .scalars()
        .all()
    )

    tags = (
        session.execute(select(SoftwareTag.tag).where(SoftwareTag.software_id == software.id).order_by(SoftwareTag.tag))
        .scalars()
        .all()
    )

    return request.app.state.templates.TemplateResponse(
        request,
        "software_detail.html",
        {
            "user": user,
            "site_name": request.app.state.site_name,
            "software": software,
            "findings": findings,
            "versions": versions,
            "tags": tags,
        },
    )


@router.get("/core", response_class=HTMLResponse)
async def core_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
) -> HTMLResponse:
    """
    The core release history in full

    Every release wordpress.org has ever shipped, what it says about
    each, and how many known issues we matched against it.

    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    """

    core = session.execute(
        select(Software).where(
            Software.software_type == SoftwareType.CORE,
            Software.slug == "wordpress",
        )
    ).scalar_one_or_none()

    releases: list = []
    current_issues: list = []

    if core is not None:
        releases = (
            session.execute(
                select(SoftwareVersion)
                .where(SoftwareVersion.software_id == core.id)
                .order_by(SoftwareVersion.version_key.desc())
            )
            .scalars()
            .all()
        )

        current = next((r for r in releases if r.is_current), None)
        if current is not None:
            current_issues = session.execute(
                select(Finding, Vulnerability)
                .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
                .where(Finding.software_version_id == current.id)
                .order_by(Vulnerability.cvss_score.desc())
            ).all()

    return request.app.state.templates.TemplateResponse(
        request,
        "core.html",
        {
            "user": user,
            "site_name": request.app.state.site_name,
            "core": core,
            "releases": releases,
            "current_issues": current_issues,
        },
    )
