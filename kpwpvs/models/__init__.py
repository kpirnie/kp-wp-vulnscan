#!/usr/bin/env python3
"""
Models Package

Every table in the schema, exported in one place so alembic and the
application both see the full metadata.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from kpwpvs.models.base import Base, TimestampMixin
from kpwpvs.models.feed import Feed, FeedAuth
from kpwpvs.models.finding import (
    Finding,
    FindingEvent,
    FindingEventType,
    FindingStatus,
)
from kpwpvs.models.software import Software, SoftwareStatus, SoftwareTag, SoftwareVersion
from kpwpvs.models.report import (
    DeliveryStatus,
    Report,
    ReportFormat,
    WebhookDelivery,
)
from kpwpvs.models.run import (
    CrawlCheckpoint,
    Run,
    RunKind,
    RunStage,
    RunStatus,
    RunTrigger,
)
from kpwpvs.models.setting import Setting
from kpwpvs.models.user import AuditLog, User, UserRole, UserSession
from kpwpvs.models.vulnerability import (
    FeedSource,
    Severity,
    SoftwareType,
    Vulnerability,
    VulnerabilityAffect,
)

# what this package hands out
__all__ = [
    "AuditLog",
    "Base",
    "CrawlCheckpoint",
    "DeliveryStatus",
    "Feed",
    "FeedAuth",
    "FeedSource",
    "Finding",
    "FindingEvent",
    "FindingEventType",
    "FindingStatus",
    "Report",
    "ReportFormat",
    "Run",
    "RunKind",
    "RunStage",
    "RunStatus",
    "RunTrigger",
    "Setting",
    "Severity",
    "Software",
    "SoftwareStatus",
    "SoftwareTag",
    "SoftwareType",
    "SoftwareVersion",
    "TimestampMixin",
    "User",
    "UserRole",
    "UserSession",
    "Vulnerability",
    "VulnerabilityAffect",
    "WebhookDelivery",
]
