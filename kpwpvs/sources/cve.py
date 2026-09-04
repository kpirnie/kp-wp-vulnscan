#!/usr/bin/env python3
"""
CVE Services Source Module

Tertiary feed, and the keyless fallback. Wordfence and Patchstack are
both CNAs, so their WordPress records are published here too, with
structured version ranges and references a slug can be recovered from.
One step removed from the vendor feeds, but it needs no api key at all,
which is the point.

Records are fetched by cve id rather than in bulk, so this enriches what
the other feeds already found rather than discovering anything on its
own.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
import time
from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Any

import httpx

from kpwpvs.sources.base import (
    AffectRecord,
    VulnRecord,
    extract_slug,
    map_severity,
)

logger = logging.getLogger(__name__)

# the record format's timestamps
TIMESTAMP_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S")

# be polite, this is a free service with no key to throttle us by
REQUEST_DELAY = 0.35

# the scoring blocks a cna might publish, newest first
METRIC_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


def _parse_timestamp(value: Any) -> datetime | None:
    """
    Parse one of the record format's timestamps

    @param value: Any The raw value from the api
    @return datetime|None: The parsed timestamp, or None when unparseable
    """

    # nothing to do without a string
    if not isinstance(value, str) or not value.strip():
        return None

    # strip the zone marker, these are all utc
    cleaned = value.strip().rstrip("Z").split("+")[0]

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue

    logger.debug("could not parse cve timestamp %r", value)
    return None


def _best_metric(metrics: list[Any]) -> tuple[float | None, str | None, str | None]:
    """
    Pick the best available score off a cve record

    @param metrics: list The metrics block from the cna container
    @return tuple: The score, the vector, and the severity label
    """

    # newest scoring version wins
    for key in METRIC_KEYS:
        for entry in metrics or []:
            data = entry.get(key)
            if not data:
                continue

            score = data.get("baseScore")
            return (
                float(score) if isinstance(score, int | float) else None,
                data.get("vectorString"),
                data.get("baseSeverity"),
            )

    return (None, None, None)


def parse_record(payload: dict[str, Any]) -> VulnRecord | None:
    """
    Turn one cve record into a normalized vulnerability

    @param payload: dict The full record as the api returns it
    @return VulnRecord|None: The normalized record, or None without an id
    """

    # the id lives in the metadata block
    metadata = payload.get("cveMetadata") or {}
    cve_id = metadata.get("cveId")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None

    # everything else is in the cna's container
    cna = (payload.get("containers") or {}).get("cna") or {}

    # the english description
    description = None
    for entry in cna.get("descriptions") or []:
        if entry.get("lang", "").startswith("en"):
            description = (entry.get("value") or "").strip() or None
            break

    # the title, falling back to the id when the cna did not set one
    title = (cna.get("title") or "").strip() or cve_id.strip()

    # scoring
    score, vector, severity_label = _best_metric(cna.get("metrics") or [])

    # the first real weakness
    cwe_id = None
    cwe_name = None
    for problem in cna.get("problemTypes") or []:
        for entry in problem.get("descriptions") or []:
            raw_id = entry.get("cweId") or ""
            if raw_id.startswith("CWE-") and raw_id[4:].isdigit():
                cwe_id = int(raw_id[4:])
                cwe_name = (entry.get("description") or raw_id).strip()
                break
        if cwe_id:
            break

    references = [
        ref.get("url") for ref in (cna.get("references") or []) if isinstance(ref.get("url"), str)
    ]

    record = VulnRecord(
        source_id=cve_id.strip(),
        title=title,
        description=description,
        cve=cve_id.strip(),
        cve_link=f"https://www.cve.org/CVERecord?id={cve_id.strip()}",
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cvss_score=score,
        cvss_vector=vector,
        severity=map_severity(severity_label, score),
        references=references,
        published_at=_parse_timestamp(metadata.get("datePublished")),
        source_updated_at=_parse_timestamp(metadata.get("dateUpdated")),
    )

    # the slug has to come out of the references, the affected block names
    # products in prose rather than by slug
    slug = extract_slug(references)
    if slug:
        record.affects.extend(_build_affects(slug, cna))

    return record


def _build_affects(slug: str, cna: dict[str, Any]) -> list[AffectRecord]:
    """
    Build the affected ranges off a cna container

    The record format expresses a range as a starting version plus a
    lessThan or lessThanOrEqual bound, which maps onto ours directly.

    @param slug: str The slug recovered from the references
    @param cna: dict The cna container
    @return list[AffectRecord]: One record per affected version range
    """

    affects: list[AffectRecord] = []

    # each affected product can carry several ranges
    for product in cna.get("affected") or []:
        name = (product.get("product") or "").strip() or None

        for version in product.get("versions") or []:
            if version.get("status") != "affected":
                continue

            # the lower bound is the version itself, unless it is the
            # catch all the format uses for "everything"
            start = version.get("version")
            start = None if start in (None, "", "0", "*") else str(start)

            # and the upper bound comes in one of two flavours
            if version.get("lessThanOrEqual"):
                to_version = str(version["lessThanOrEqual"])
                to_inclusive = True
            elif version.get("lessThan"):
                to_version = str(version["lessThan"])
                to_inclusive = False
            else:
                to_version = start
                to_inclusive = True

            affects.append(
                AffectRecord(
                    slug=slug,
                    software_name=name,
                    from_version=start,
                    from_inclusive=True,
                    to_version=to_version,
                    to_inclusive=to_inclusive,
                )
            )

    return affects


class CveClient:
    """
    Fetches individual records from the CVE Services api

    No key, no bulk endpoint, so this is used to enrich cve ids the other
    feeds already turned up rather than to discover new ones.
    """

    def __init__(self, url: str, timeout: int = 60) -> None:
        """
        Build a client

        @param url: str The api base, from the feeds table
        @param timeout: int Seconds to wait on any single request
        """

        self._url = url.rstrip("/")
        self._timeout = timeout

    def fetch_many(self, cve_ids: Iterable[str]) -> Iterator[VulnRecord]:
        """
        Fetch a set of cve records by id

        A record that is not there is skipped rather than failing the
        whole batch, plenty of ids simply are not published here.

        @param cve_ids: Iterable[str] The cve ids to fetch
        @return Iterator[VulnRecord]: The records that came back
        """

        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            for cve_id in cve_ids:

                # be a good guest, there is no key throttling us here
                time.sleep(REQUEST_DELAY)

                try:
                    response = client.get(f"{self._url}/{cve_id}")

                    # not every id is published here, that is expected
                    if response.status_code == 404:
                        logger.debug("%s is not published on cve services", cve_id)
                        continue

                    response.raise_for_status()
                    record = parse_record(response.json())

                    if record is not None:
                        yield record

                except (httpx.HTTPError, ValueError) as exc:
                    logger.warning("could not fetch %s from cve services: %s", cve_id, exc)
                    continue
