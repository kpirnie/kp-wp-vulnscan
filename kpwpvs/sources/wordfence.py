#!/usr/bin/env python3
"""
Wordfence Intelligence Source Module

The primary vulnerability feed, and the only one that carries the
wordpress.org slug outright, which is what lets a record join straight
onto our catalog rather than being matched by inference.

Needs an api key as a bearer token. The v2 feed was retired and answers
with a 410, so the endpoint is stored as a setting rather than a
constant, and this module works against whatever it is pointed at.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import json
import logging
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from kpwpvs.models import SoftwareType
from kpwpvs.sources.base import (
    AffectRecord,
    VulnRecord,
    map_severity,
    normalize_version,
)

logger = logging.getLogger(__name__)

# the feed's timestamps, "2024-01-22 19:56:02"
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# how the feed labels software, mapped onto ours
SOFTWARE_TYPES = {
    "plugin": SoftwareType.PLUGIN,
    "theme": SoftwareType.THEME,
    "core": SoftwareType.CORE,
}

# the whole feed is a single json object of roughly 150mb, so it gets
# streamed to disk rather than held in memory twice over
DOWNLOAD_CHUNK = 1 << 20


class FeedThrottled(Exception):
    """
    Raised when the feed turns us away for asking too often

    The feed updates on the order of hours and we are meant to pull it
    on the order of days, so this is a scheduling problem rather than
    something to retry around.
    """


class FeedUnauthorized(Exception):
    """
    Raised when the feed will not accept our api key

    Either no key is stored, or the one that is has been revoked.
    """


def _parse_timestamp(value: Any) -> datetime | None:
    """
    Parse one of the feed's timestamps

    @param value: Any The raw value from the feed
    @return datetime|None: The parsed timestamp, or None when unparseable
    """

    # nothing to do without a string
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return datetime.strptime(value.strip(), TIMESTAMP_FORMAT)
    except ValueError:
        logger.debug("could not parse wordfence timestamp %r", value)
        return None


def parse_record(raw: dict[str, Any]) -> VulnRecord | None:
    """
    Turn one raw feed record into a normalized vulnerability

    @param raw: dict One record straight off the feed
    @return VulnRecord|None: The normalized record, or None without an id
    """

    # no identifier means we cannot key it, and nothing we can do with it
    source_id = raw.get("id")
    if not isinstance(source_id, str) or not source_id.strip():
        return None

    # scoring, the feed gives us both a vector and a rating
    cvss = raw.get("cvss") or {}
    score = cvss.get("score")
    score = float(score) if isinstance(score, int | float) else None

    # the weakness classification
    cwe = raw.get("cwe") or {}
    cwe_id = cwe.get("id")

    # the defiant license asks that the notice and a link back to the
    # record travel with the data, so carry them on the record itself
    copyrights = raw.get("copyrights") or {}
    defiant = copyrights.get("defiant") or {}

    record = VulnRecord(
        source_id=source_id.strip(),
        title=(raw.get("title") or "").strip(),
        description=(raw.get("description") or "").strip() or None,
        cve=(raw.get("cve") or "").strip() or None,
        cve_link=(raw.get("cve_link") or "").strip() or None,
        cwe_id=int(cwe_id) if isinstance(cwe_id, int) else None,
        cwe_name=(cwe.get("name") or "").strip() or None,
        cvss_score=score,
        cvss_vector=(cvss.get("vector") or "").strip() or None,
        severity=map_severity(cvss.get("rating"), score),
        informational=bool(raw.get("informational")),
        references=[url for url in (raw.get("references") or []) if isinstance(url, str)],
        researchers=[name for name in (raw.get("researchers") or []) if isinstance(name, str)],
        copyright_notice=(defiant.get("notice") or "").strip() or None,
        copyright_license=(defiant.get("license") or "").strip() or None,
        published_at=_parse_timestamp(raw.get("published")),
        source_updated_at=_parse_timestamp(raw.get("updated")),
    )

    # then every piece of software it affects, and every range within that
    for software in raw.get("software") or []:
        if not isinstance(software, dict):
            continue

        slug = software.get("slug")
        if not isinstance(slug, str) or not slug.strip():
            continue

        patched_versions = [v for v in (software.get("patched_versions") or []) if isinstance(v, str)]

        # affected_versions is keyed by a human readable label like "*-1.37",
        # the label carries no information the bounds do not, so ignore it
        for bounds in (software.get("affected_versions") or {}).values():
            if not isinstance(bounds, dict):
                continue

            record.affects.append(
                AffectRecord(
                    slug=slug.strip(),
                    software_type=SOFTWARE_TYPES.get(software.get("type"), SoftwareType.PLUGIN),
                    software_name=(software.get("name") or "").strip() or None,
                    from_version=normalize_version(bounds.get("from_version")),
                    from_inclusive=bool(bounds.get("from_inclusive", True)),
                    to_version=normalize_version(bounds.get("to_version")),
                    to_inclusive=bool(bounds.get("to_inclusive", True)),
                    patched=bool(software.get("patched")),
                    patched_versions=patched_versions,
                    remediation=(software.get("remediation") or "").strip() or None,
                )
            )

    return record


class WordfenceClient:
    """
    Pulls the Wordfence Intelligence vulnerability feed

    The feed is one large json object keyed by record id, delivered in a
    single response, so this downloads it to a temporary file first and
    parses from there.
    """

    def __init__(self, url: str, api_key: str, timeout: int = 180) -> None:
        """
        Build a client

        @param url: str The feed endpoint, from the feeds table
        @param api_key: str The api key, sent as a bearer token
        @param timeout: int Seconds to wait on the feed
        """

        self._url = url
        self._api_key = api_key
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        """
        Build the request headers

        @return dict: The headers, including authorization when we have a key
        """

        headers = {"Accept": "application/json", "Accept-Encoding": "gzip"}

        # the v3 feed will not answer at all without this
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        return headers

    def fetch(self) -> Iterator[VulnRecord]:
        """
        Download the feed and yield every record in it

        Streams to a temporary file so we are not holding the raw json
        and the parsed structure in memory at the same time, and cleans
        the file up regardless of how this exits.

        @return Iterator[VulnRecord]: Every normalized record in the feed
        @throws httpx.HTTPStatusError: When the feed rejects the request
        """

        # somewhere to put it while we work
        handle = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        path = Path(handle.name)

        try:
            # stream it down rather than buffering the whole body
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                with client.stream("GET", self._url, headers=self._headers()) as response:
                    # tell the common failures apart, they need very
                    # different things from whoever is reading the log
                    if response.status_code == 429:
                        retry_after = response.headers.get("Retry-After", "unknown")
                        raise FeedThrottled(
                            f"the feed is rate limiting us, retry after {retry_after}. "
                            "it only changes every few hours, so pulling it weekly is the intent"
                        )

                    if response.status_code in (401, 403):
                        raise FeedUnauthorized("the feed rejected our api key, check it on the feeds page")

                    if response.status_code == 410:
                        raise httpx.HTTPStatusError(
                            f"the feed endpoint {self._url} has been retired, update it on the feeds page",
                            request=response.request,
                            response=response,
                        )

                    response.raise_for_status()

                    for chunk in response.iter_bytes(DOWNLOAD_CHUNK):
                        handle.write(chunk)

            handle.close()
            logger.info("downloaded the wordfence feed, %.1f MB", path.stat().st_size / 1024 / 1024)

            # parse it, the top level is keyed by record id
            with path.open(encoding="utf-8") as parsed:
                payload = json.load(parsed)

            if not isinstance(payload, dict):
                logger.error("the wordfence feed was not the object we expected")
                return

            logger.info("wordfence feed carries %s records", len(payload))

            # hand them out one at a time so the caller can write as it goes
            for raw in payload.values():
                if not isinstance(raw, dict):
                    continue
                record = parse_record(raw)
                if record is not None:
                    yield record

        finally:
            # always clean up, this is a large file
            handle.close()
            path.unlink(missing_ok=True)
