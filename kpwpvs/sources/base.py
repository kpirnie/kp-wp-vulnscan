#!/usr/bin/env python3
"""
Feed Source Base Module

The normalized shape every vulnerability feed gets turned into, plus the
helpers they share. Feeds differ wildly in what they give us, this is
where those differences stop.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import re
from dataclasses import dataclass, field
from datetime import datetime

from kpwpvs.models import Severity, SoftwareType
from kpwpvs.utils.version import sort_key

# the feeds spell an open ended range as a star, we store it as null
OPEN_RANGE = "*"

# how the sources label severity, mapped onto our own scale
SEVERITY_MAP = {
    "none": Severity.NONE,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# urls a wordpress.org slug can be recovered from. only wordfence carries
# the slug outright, for the other feeds this is the best we can do
SLUG_PATTERNS = (
    re.compile(r"wordpress\.org/plugins/([a-z0-9][a-z0-9\-_]*)", re.IGNORECASE),
    re.compile(r"wordpress\.org/support/plugin/([a-z0-9][a-z0-9\-_]*)", re.IGNORECASE),
    re.compile(r"plugins\.trac\.wordpress\.org/browser/([a-z0-9][a-z0-9\-_]*)", re.IGNORECASE),
    re.compile(r"plugins\.trac\.wordpress\.org/changeset/\d+/([a-z0-9][a-z0-9\-_]*)", re.IGNORECASE),
    re.compile(r"wordfence\.com/threat-intel/vulnerabilities/wordpress-plugins/([a-z0-9][a-z0-9\-_]*)", re.IGNORECASE),
)


@dataclass
class AffectRecord:
    """
    One affected version range for one piece of software

    Bounds are None when open on that end, which is how the star in the
    source feeds gets normalized.
    """

    slug: str
    software_type: SoftwareType = SoftwareType.PLUGIN
    software_name: str | None = None
    from_version: str | None = None
    from_inclusive: bool = True
    to_version: str | None = None
    to_inclusive: bool = True
    patched: bool = False
    patched_versions: list[str] = field(default_factory=list)
    remediation: str | None = None

    @property
    def from_key(self) -> str | None:
        """
        Padded sort key for the lower bound

        @return str|None: The sort key, or None when the bound is open
        """

        return sort_key(self.from_version) if self.from_version else None

    @property
    def to_key(self) -> str | None:
        """
        Padded sort key for the upper bound

        @return str|None: The sort key, or None when the bound is open
        """

        return sort_key(self.to_version) if self.to_version else None


@dataclass
class VulnRecord:
    """
    One vulnerability, normalized

    Whatever the source called things, by the time it gets here it looks
    like this.
    """

    source_id: str
    title: str = ""
    description: str | None = None
    cve: str | None = None
    cve_link: str | None = None
    cwe_id: int | None = None
    cwe_name: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: Severity = Severity.NONE
    informational: bool = False
    references: list[str] = field(default_factory=list)
    researchers: list[str] = field(default_factory=list)
    copyright_notice: str | None = None
    copyright_license: str | None = None
    published_at: datetime | None = None
    source_updated_at: datetime | None = None
    affects: list[AffectRecord] = field(default_factory=list)


def normalize_version(value: object) -> str | None:
    """
    Turn a feed's version bound into something storable

    The feeds use a star for an open bound, we use null, which lets the
    range checks treat "no bound" and "any version" as the same thing.

    @param value: object The raw bound from the feed
    @return str|None: The version string, or None when the bound is open
    """

    # anything that is not a useful string is an open bound
    if not isinstance(value, str):
        return None

    cleaned = value.strip()
    if not cleaned or cleaned == OPEN_RANGE:
        return None

    return cleaned


def map_severity(rating: object, score: float | None = None) -> Severity:
    """
    Map a source's severity onto our own scale

    Prefers the label the source gave us, falling back to the cvss score
    when there is not one.

    @param rating: object The severity label from the source
    @param score: float|None The cvss base score, as a fallback
    @return Severity: The normalized severity
    """

    # the label, when we recognize it
    if isinstance(rating, str):
        mapped = SEVERITY_MAP.get(rating.strip().lower())
        if mapped is not None:
            return mapped

    # otherwise derive it from the score, using the cvss v3 bands
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW

    return Severity.NONE


def extract_slug(urls: list[str]) -> str | None:
    """
    Try to recover a wordpress.org slug from a set of reference urls

    Only wordfence gives us the slug outright. For the other feeds this
    is how a record gets tied to a plugin at all, and it does not always
    work, which is why they are secondary sources.

    @param urls: list[str] The reference urls to search
    @return str|None: The recovered slug, or None when there is not one
    """

    # first pattern that matches anything wins
    for url in urls:
        if not isinstance(url, str):
            continue
        for pattern in SLUG_PATTERNS:
            match = pattern.search(url)
            if match:
                return match.group(1).lower()

    return None
