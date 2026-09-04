#!/usr/bin/env python3
"""
Dashboard Routes Module

The landing page. Core first, then the headline counts, then what the
last few runs did.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kpwpvs.models import (
    Feed,
    Finding,
    FindingStatus,
    Run,
    Software,
    SoftwareType,
    SoftwareVersion,
    User,
    Vulnerability,
)
from kpwpvs.web.deps import get_session, require_user

logger = logging.getLogger(__name__)

router = APIRouter()

# the finding states that still want somebody's attention
OPEN_STATUSES = (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED, FindingStatus.IN_PROGRESS)


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
) -> HTMLResponse:
    """
    Render the dashboard

    @param request: Request The incoming request
    @param session: Session The request's database session
    @param user: User Whoever is signed in
    @return HTMLResponse: The rendered page
    """

    # core leads, for the same reason it leads the reports
    core = session.execute(
        select(Software).where(
            Software.software_type == SoftwareType.CORE,
            Software.slug == "wordpress",
        )
    ).scalar_one_or_none()

    core_current = None
    core_issues: list = []
    core_releases: list = []

    if core is not None:
        core_current = session.execute(
            select(SoftwareVersion).where(
                SoftwareVersion.software_id == core.id,
                SoftwareVersion.is_current.is_(True),
            )
        ).scalar_one_or_none()

        if core_current is not None:
            core_issues = session.execute(
                select(Finding, Vulnerability)
                .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
                .where(Finding.software_version_id == core_current.id)
                .order_by(Vulnerability.cvss_score.desc())
            ).all()

        core_releases = session.execute(
            select(SoftwareVersion)
            .where(SoftwareVersion.software_id == core.id)
            .order_by(SoftwareVersion.version_key.desc())
            .limit(8)
        ).scalars().all()

    # open plugin findings by severity
    severity_rows = session.execute(
        select(Finding.severity, func.count())
        .where(Finding.status.in_(OPEN_STATUSES), Finding.software_version_id.is_(None))
        .group_by(Finding.severity)
    ).all()
    severities = {severity.value: count for severity, count in severity_rows}

    # what the catalog holds
    catalog_rows = session.execute(
        select(Software.software_type, Software.status, func.count())
        .group_by(Software.software_type, Software.status)
    ).all()

    catalog_total = sum(count for _, _, count in catalog_rows)

    # the highest priority scan targets
    priorities = session.execute(
        select(Software)
        .where(Software.issue_count > 0)
        .order_by(Software.priority_score.desc())
        .limit(10)
    ).scalars().all()

    # and how things have been going
    runs = session.execute(select(Run).order_by(Run.id.desc()).limit(5)).scalars().all()
    feeds = session.execute(select(Feed).order_by(Feed.priority)).scalars().all()

    return request.app.state.templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "site_name": request.app.state.site_name,
            "core": core,
            "core_current": core_current,
            "core_issues": core_issues,
            "core_releases": core_releases,
            "severities": severities,
            "open_total": sum(severities.values()),
            "catalog_rows": catalog_rows,
            "catalog_total": catalog_total,
            "priorities": priorities,
            "runs": runs,
            "feeds": feeds,
        },
    )
