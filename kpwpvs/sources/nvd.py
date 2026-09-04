#!/usr/bin/env python3
"""
NVD Source Module

Secondary feed. Authoritative on scoring but poorly structured for
WordPress specifically, its CPE product names do not map to
wordpress.org slugs, so records here are tied to plugins by cve id
against what wordfence already gave us, or by recovering a slug from the
reference urls when one happens to be there.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any

import httpx

from kpwpvs.sources.base import (
    AffectRecord,
    VulnRecord,
    extract_slug,
    map_severity,
)

logger = logging.getLogger(__name__)

# nvd's own timestamp format, with milliseconds
TIMESTAMP_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S")

# the api caps a page at this many
MAX_RESULTS_PER_PAGE = 2000

# and it will not accept a date window wider than this
MAX_WINDOW_DAYS = 120

# how long to wait between requests. without a key nvd allows five requests
# per thirty seconds, with one it allows fifty, so pace accordingly
DELAY_WITHOUT_KEY = 6.5
DELAY_WITH_KEY = 0.7

# the metric blocks nvd publishes, newest scoring first
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _parse_timestamp(value: Any) -> datetime | None:
    """
    Parse one of nvd's timestamps

    @param value: Any The raw value from the api
    @return datetime|None: The parsed timestamp, or None when unparseable
    """

    # nothing to do without a string
    if not isinstance(value, str) or not value.strip():
        return None

    # try each format it uses
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value.strip().rstrip("Z"), fmt)
        except ValueError:
            continue

    logger.debug("could not parse nvd timestamp %r", value)
    return None


def _best_metric(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """
    Pick the best available cvss metric off a cve

    Prefers the newest scoring version present, since a cve often carries
    several at once.

    @param metrics: dict The metrics block from the api
    @return tuple: The score, the vector, and the severity label
    """

    # newest first, take the first one that is actually there
    for key in METRIC_KEYS:
        entries = metrics.get(key)
        if not entries:
            continue

        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")

        # v2 puts the severity on the entry rather than in cvssData
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")

        return (
            float(score) if isinstance(score, int | float) else None,
            data.get("vectorString"),
            severity,
        )

    return (None, None, None)


def parse_cve(raw: dict[str, Any]) -> VulnRecord | None:
    """
    Turn one nvd cve into a normalized vulnerability

    @param raw: dict The cve object from the api
    @return VulnRecord|None: The normalized record, or None without an id
    """

    # the cve id is the identity here
    cve_id = raw.get("id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None

    # the english description, there is usually exactly one
    description = None
    for entry in raw.get("descriptions") or []:
        if entry.get("lang") == "en":
            description = (entry.get("value") or "").strip() or None
            break

    # scoring
    score, vector, severity_label = _best_metric(raw.get("metrics") or {})

    # the first real weakness, nvd pads these with NVD-CWE-noinfo entries
    cwe_id = None
    cwe_name = None
    for weakness in raw.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            value = entry.get("value") or ""
            if value.startswith("CWE-") and value[4:].isdigit():
                cwe_id = int(value[4:])
                cwe_name = value
                break
        if cwe_id:
            break

    references = [ref.get("url") for ref in (raw.get("references") or []) if isinstance(ref.get("url"), str)]

    record = VulnRecord(
        source_id=cve_id.strip(),
        title=cve_id.strip(),
        description=description,
        cve=cve_id.strip(),
        cve_link=f"https://nvd.nist.gov/vuln/detail/{cve_id.strip()}",
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cvss_score=score,
        cvss_vector=vector,
        severity=map_severity(severity_label, score),
        references=references,
        published_at=_parse_timestamp(raw.get("published")),
        source_updated_at=_parse_timestamp(raw.get("lastModified")),
    )

    # a slug is the only way to tie this to a plugin, and it is only ever
    # in the references if it is anywhere. no slug is not an error, it
    # just means this record enriches by cve id rather than matching
    slug = extract_slug(references)
    if slug:
        record.affects.append(_build_affect(slug, raw))

    return record


def _build_affect(slug: str, raw: dict[str, Any]) -> AffectRecord:
    """
    Build an affected range from a cve's cpe configuration

    NVD expresses ranges on the cpe match rather than as a version list,
    so pull the bounds off the first vulnerable match we find.

    @param slug: str The slug recovered from the references
    @param raw: dict The cve object from the api
    @return AffectRecord: The affected range
    """

    affect = AffectRecord(slug=slug)

    # walk down to the first vulnerable cpe match and take its bounds
    for configuration in raw.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue

                # nvd spells inclusivity into the key name itself
                if match.get("versionStartIncluding"):
                    affect.from_version = match["versionStartIncluding"]
                    affect.from_inclusive = True
                elif match.get("versionStartExcluding"):
                    affect.from_version = match["versionStartExcluding"]
                    affect.from_inclusive = False

                if match.get("versionEndIncluding"):
                    affect.to_version = match["versionEndIncluding"]
                    affect.to_inclusive = True
                elif match.get("versionEndExcluding"):
                    affect.to_version = match["versionEndExcluding"]
                    affect.to_inclusive = False

                return affect

    return affect


class NvdClient:
    """
    Pulls CVEs from the NVD api

    Walks a date window rather than the whole database, because the whole
    database is not something anybody should be pulling weekly.
    """

    def __init__(self, url: str, api_key: str = "", timeout: int = 60) -> None:
        """
        Build a client

        @param url: str The api endpoint, from the feeds table
        @param api_key: str The api key, optional but raises the rate limit
        @param timeout: int Seconds to wait on any single request
        """

        self._url = url
        self._api_key = api_key
        self._timeout = timeout
        self._delay = DELAY_WITH_KEY if api_key else DELAY_WITHOUT_KEY

    def _headers(self) -> dict[str, str]:
        """
        Build the request headers

        @return dict: The headers, including the api key when we have one
        """

        headers = {"Accept": "application/json"}

        # nvd wants this as its own header rather than an authorization one
        if self._api_key:
            headers["apiKey"] = self._api_key

        return headers

    def fetch(self, since: datetime | None = None, lookback_days: int = 14) -> Iterator[VulnRecord]:
        """
        Fetch CVEs modified within a window

        Walks backwards in windows no wider than the api allows, paging
        through each one.

        @param since: datetime|None Fetch changes since this point
        @param lookback_days: int How far back to go when since is unset
        @return Iterator[VulnRecord]: Every normalized cve in the window
        """

        # work out the window, capped at what the api will accept
        end = datetime.now()
        start = since or (end - timedelta(days=lookback_days))
        if (end - start).days > MAX_WINDOW_DAYS:
            logger.info("clamping the nvd window to %s days", MAX_WINDOW_DAYS)
            start = end - timedelta(days=MAX_WINDOW_DAYS)

        logger.info("fetching nvd changes from %s to %s", start.date(), end.date())

        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            start_index = 0

            # page until we have seen everything the api says there is
            while True:
                params = {
                    "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": MAX_RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }

                # pace ourselves, nvd is strict about this and answers a
                # burst with a 403 rather than a 429
                time.sleep(self._delay)

                response = client.get(self._url, params=params, headers=self._headers())
                response.raise_for_status()
                payload = response.json()

                total = payload.get("totalResults", 0)
                vulnerabilities = payload.get("vulnerabilities") or []

                if start_index == 0:
                    logger.info("nvd has %s cves in this window", total)

                # nothing came back, we are done
                if not vulnerabilities:
                    break

                for entry in vulnerabilities:
                    record = parse_cve(entry.get("cve") or {})
                    if record is not None:
                        yield record

                start_index += len(vulnerabilities)
                if start_index >= total:
                    break
