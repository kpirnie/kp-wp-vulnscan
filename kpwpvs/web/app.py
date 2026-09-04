#!/usr/bin/env python3
"""
Web Application Module

The FastAPI application factory. Server rendered with jinja, htmx for
the parts that would otherwise need a full page load, and no javascript
build step of its own.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from kpwpvs import __version__
from kpwpvs.core.config import BootstrapConfig
from kpwpvs.core.crypto import SecretBox
from kpwpvs.core.db import init_engine, session_scope
from kpwpvs.models import User, UserRole
from kpwpvs.services.settings_service import SettingsService
from kpwpvs.web.deps import RedirectToLogin, login_redirect
from kpwpvs.web.routes import admin, auth, catalog, dashboard, findings

logger = logging.getLogger(__name__)

# where the templates and the compiled stylesheet live
WEB_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

# how numbers render throughout the interface
SEVERITY_ORDER = ("critical", "high", "medium", "low", "none")


def format_installs(value: object) -> str:
    """
    Render an install count the way wordpress.org does

    @param value: object The raw install count
    @return str: A short readable count
    """

    # anything unusable reads as unknown rather than zero
    if not isinstance(value, int) or value <= 0:
        return "-"

    if value >= 1_000_000:
        return f"{value // 1_000_000}M+"
    if value >= 1_000:
        return f"{value // 1_000}k+"

    return str(value)


def format_number(value: object) -> str:
    """
    Render a plain integer with thousands separators

    @param value: object The number
    @return str: The formatted number
    """

    if not isinstance(value, int | float):
        return "-"

    return f"{int(value):,}"


def format_when(value: object) -> str:
    """
    Render a timestamp compactly

    @param value: object The datetime, or None
    @return str: A readable timestamp, or a dash
    """

    from datetime import datetime

    if not isinstance(value, datetime):
        return "-"

    return value.strftime("%Y-%m-%d %H:%M")


def build_templates() -> Jinja2Templates:
    """
    Build the template environment

    @return Jinja2Templates: The configured environment
    """

    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    templates.env.filters["installs"] = format_installs
    templates.env.filters["number"] = format_number
    templates.env.filters["when"] = format_when
    templates.env.globals["version"] = __version__
    templates.env.globals["severity_order"] = SEVERITY_ORDER

    return templates


def create_app(config: BootstrapConfig) -> FastAPI:
    """
    Build the application

    @param config: BootstrapConfig The bootstrap configuration
    @return FastAPI: The configured application
    """

    app = FastAPI(
        title="KP WP VulnScan",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # the engine has to exist before any request can be served
    init_engine(config)

    # everything the routes need off the app itself
    app.state.config = config
    app.state.templates = build_templates()

    # secrets are only readable when a key was configured
    try:
        app.state.secret_box = SecretBox(config.secret_key)
    except ValueError:
        app.state.secret_box = None
        logger.warning("no secret key configured, api keys cannot be read or stored from the interface")

    # read the interface settings once at startup
    with session_scope() as session:
        settings = SettingsService(session, app.state.secret_box)
        app.state.auth_enabled = bool(settings.get("web.auth_enabled"))
        app.state.site_name = settings.get("general.site_name")

    # when auth is off every request runs as this, which only makes sense
    # behind something else doing the authenticating
    app.state.anonymous_admin = User(
        id=0,
        username="anonymous",
        display_name="Anonymous",
        role=UserRole.ADMIN,
        is_active=True,
        password_hash="",
    )

    if not app.state.auth_enabled:
        logger.warning("authentication is disabled, every visitor has full access")

    # the compiled stylesheet, built at image build time
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # the routes
    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(findings.router)
    app.include_router(catalog.router)
    app.include_router(admin.router)

    @app.exception_handler(RedirectToLogin)
    async def _redirect_to_login(request: Request, exc: RedirectToLogin) -> RedirectResponse:
        """
        Turn an anonymous request into a redirect rather than an error

        @param request: Request The incoming request
        @param exc: RedirectToLogin Carries where they were going
        @return RedirectResponse: The redirect to the sign in page
        """

        return login_redirect(exc.next_url)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> HTMLResponse:
        """
        Render http errors in the interface's own styling

        @param request: Request The incoming request
        @param exc: StarletteHTTPException The error raised
        @return HTMLResponse: The rendered error page
        """

        from kpwpvs.web.deps import current_user

        # the error page still shows the nav when somebody is signed in
        user = None
        try:
            with session_scope() as session:
                user = current_user(request, session)
        except Exception:
            user = None

        return app.state.templates.TemplateResponse(
            request,
            "error.html",
            {
                "status_code": exc.status_code,
                "detail": exc.detail,
                "user": user,
                "site_name": app.state.site_name,
            },
            status_code=exc.status_code,
        )

    return app
