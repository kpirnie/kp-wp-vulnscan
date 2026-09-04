#!/usr/bin/env python3
"""
WordPress.org Source Module

Client for the wordpress.org plugins api. Handles paging, retries, and
turning the api's slightly awkward payload into something clean.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import asyncio
import html
import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from urllib.parse import unquote

import httpx

logger = logging.getLogger(__name__)

# the api endpoint, version 1.2 is the current json one
API_URL = "https://api.wordpress.org/plugins/info/1.2/"

# the api caps this no matter what we ask for
MAX_PER_PAGE = 250

# fields we explicitly turn off, they are enormous and we do not store them.
# dropping these takes a page from roughly a megabyte down to a quarter of one
UNWANTED_FIELDS = (
    "description",
    "sections",
    "screenshots",
    "icons",
    "banners",
    "ratings",
    "contributors",
    "compatibility",
    "versions",
    "reviews",
)

# the author comes back as an html anchor, we want the text inside it
TAG_RE = re.compile(r"<[^>]+>")

# how long a tag we will store, matching the column. non latin tags arrive
# percent encoded and blow well past this until they are decoded, a cyrillic
# tag of thirty odd characters encodes to over two hundred
MAX_TAG_LENGTH = 191

# "2026-09-04 11:06am GMT", the only timestamp format the api uses
LAST_UPDATED_FORMAT = "%Y-%m-%d %I:%M%p %Z"


@dataclass
class PluginRecord:
    """
    One plugin as the api describes it, cleaned up

    Everything is already the right python type here, so the crawler
    does not have to think about the api's quirks.
    """

    slug: str
    name: str = ""
    version: str | None = None
    author: str | None = None
    author_profile: str | None = None
    homepage: str | None = None
    download_link: str | None = None
    short_description: str | None = None
    requires_wp: str | None = None
    tested_wp: str | None = None
    requires_php: str | None = None
    rating: int = 0
    num_ratings: int = 0
    active_installs: int = 0
    downloaded: int = 0
    support_threads: int = 0
    support_threads_resolved: int = 0
    added_on: date | None = None
    last_updated: datetime | None = None
    tags: list[str] = field(default_factory=list)


class PluginNotFound(Exception):
    """
    Raised when the api has no record of a slug

    A plugin that was closed comes back exactly the same way as one that
    never existed, so the caller decides which it is from what we already
    had stored.
    """


def _clean_text(value: Any) -> str:
    """
    Strip html and decode entities out of an api string

    Plugin names and authors come back with markup and entities in them,
    "Elementor &#8211; more than just a page builder" and so on.

    @param value: Any The raw api value
    @return str: Clean plain text
    """

    # not a string, nothing to clean
    if not isinstance(value, str):
        return ""

    # tags out first, then entities, then tidy the whitespace
    return re.sub(r"\s+", " ", html.unescape(TAG_RE.sub("", value))).strip()


def _parse_last_updated(value: Any) -> datetime | None:
    """
    Parse the api's last_updated timestamp

    Comes through as "2026-09-04 11:06am GMT", which is always UTC
    regardless of the trailing label.

    @param value: Any The raw api value
    @return datetime|None: The parsed timestamp, or None when unparseable
    """

    # nothing to do without a string
    if not isinstance(value, str) or not value.strip():
        return None

    # try the documented format, and do not guess if it does not fit
    try:
        return datetime.strptime(value.strip(), LAST_UPDATED_FORMAT)
    except ValueError:
        logger.debug("could not parse last_updated %r", value)
        return None


def _parse_added(value: Any) -> date | None:
    """
    Parse the api's added date

    A plain "2016-05-30", no time component.

    @param value: Any The raw api value
    @return date|None: The parsed date, or None when unparseable
    """

    # nothing to do without a string
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        logger.debug("could not parse added %r", value)
        return None


def _as_int(value: Any) -> int:
    """
    Coerce an api value to an integer

    Several of these come back as empty strings or false rather than
    zero when the api has nothing for them.

    @param value: Any The raw api value
    @return int: The value as an integer, zero when it will not convert
    """

    # bools are ints in python and we do not want True becoming 1 here
    if isinstance(value, bool):
        return 0

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_tags(raw_tags: dict[str, Any]) -> list[str]:
    """
    Clean up the tag slugs on a plugin

    Non latin tags come back percent encoded, so a short cyrillic or
    persian tag arrives as a couple of hundred characters. Decoding puts
    them back to a sane length and, more to the point, makes them
    readable and comparable.

    @param raw_tags: dict The tags object straight off the api
    @return list[str]: Clean, deduplicated, sorted tag slugs
    """

    tags: set[str] = set()

    # decode each one, dropping anything still unreasonable afterwards
    for key in raw_tags:
        if not isinstance(key, str) or not key.strip():
            continue

        tag = unquote(key.strip())
        if len(tag) > MAX_TAG_LENGTH:
            logger.debug("dropping an over-long tag %r", tag[:60])
            continue

        tags.add(tag)

    # sorted so the order is stable between runs
    return sorted(tags)


def parse_plugin(raw: dict[str, Any]) -> PluginRecord | None:
    """
    Turn one raw api plugin into a clean record

    @param raw: dict The plugin object straight off the api
    @return PluginRecord|None: The cleaned record, or None without a slug
    """

    # no slug means no identity, and nothing we can do with it
    slug = raw.get("slug")
    if not isinstance(slug, str) or not slug.strip():
        return None

    # tags come back as a slug keyed dict, we only want the slugs
    raw_tags = raw.get("tags")
    tags = _parse_tags(raw_tags) if isinstance(raw_tags, dict) else []

    # build it out, cleaning as we go
    return PluginRecord(
        slug=slug.strip(),
        name=_clean_text(raw.get("name")),
        version=(raw.get("version") or "").strip() or None,
        author=_clean_text(raw.get("author")) or None,
        author_profile=(raw.get("author_profile") or "").strip() or None,
        homepage=(raw.get("homepage") or "").strip() or None,
        download_link=(raw.get("download_link") or "").strip() or None,
        short_description=_clean_text(raw.get("short_description")) or None,
        requires_wp=(str(raw.get("requires") or "")).strip() or None,
        tested_wp=(str(raw.get("tested") or "")).strip() or None,
        requires_php=(str(raw.get("requires_php") or "")).strip() or None,
        rating=_as_int(raw.get("rating")),
        num_ratings=_as_int(raw.get("num_ratings")),
        active_installs=_as_int(raw.get("active_installs")),
        downloaded=_as_int(raw.get("downloaded")),
        support_threads=_as_int(raw.get("support_threads")),
        support_threads_resolved=_as_int(raw.get("support_threads_resolved")),
        added_on=_parse_added(raw.get("added")),
        last_updated=_parse_last_updated(raw.get("last_updated")),
        tags=tags,
    )


class WporgClient:
    """
    Talks to the wordpress.org plugins api

    Retries with backoff, rate limits itself, and never asks for the
    fields we are only going to throw away.
    """

    def __init__(
        self,
        user_agent: str,
        timeout: int = 30,
        max_retries: int = 3,
        retry_backoff: float = 2.0,
        rate_limit_delay: float = 0.25,
    ) -> None:
        """
        Build a client

        @param user_agent: str How we identify ourselves to wordpress.org
        @param timeout: int Seconds to wait on any single request
        @param max_retries: int Attempts before giving up on a page
        @param retry_backoff: float Multiplier between retry attempts
        @param rate_limit_delay: float Seconds to pause between requests
        """

        self._max_retries = max_retries
        self._retry_backoff = retry_backoff
        self._rate_limit_delay = rate_limit_delay
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            follow_redirects=True,
        )

    async def __aenter__(self) -> "WporgClient":
        """
        Enter the async context

        @return WporgClient: This client
        """

        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """
        Leave the async context, closing the connection pool

        @return None
        """

        await self.close()

    async def close(self) -> None:
        """
        Close the underlying http client

        @return None
        """

        await self._client.aclose()

    def _build_params(self, **request: Any) -> dict[str, str]:
        """
        Build the api's bracketed query parameters

        The api wants request[per_page] rather than per_page, and the
        field toggles nest a level deeper again.

        @param request: Any The request keys to send
        @return dict: Flat query parameters ready for httpx
        """

        # the plain request keys
        params = {f"request[{key}]": str(value) for key, value in request.items()}

        # then turn off everything we do not want back
        for unwanted in UNWANTED_FIELDS:
            params[f"request[fields][{unwanted}]"] = "0"

        return params

    async def _get(self, action: str, **request: Any) -> dict[str, Any]:
        """
        Make one api request, with retries

        @param action: str The api action to call
        @param request: Any The request keys to send
        @return dict: The decoded json response
        @throws PluginNotFound: When the api has no record of the slug
        @throws httpx.HTTPError: When every attempt failed
        """

        params = self._build_params(**request)
        params["action"] = action
        last_error: Exception | None = None

        # try, back off, try again
        for attempt in range(self._max_retries + 1):

            # pace ourselves, this is somebody else's free api
            if self._rate_limit_delay > 0:
                await asyncio.sleep(self._rate_limit_delay)

            try:
                response = await self._client.get(API_URL, params=params)

                # a 404 here is a real answer, not a failure to retry
                if response.status_code == 404:
                    raise PluginNotFound(request.get("slug", "unknown"))

                response.raise_for_status()
                return response.json()

            except PluginNotFound:
                raise
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                if attempt < self._max_retries:
                    delay = self._retry_backoff**attempt
                    logger.warning("wordpress.org request failed (%s), retrying in %.1fs", exc, delay)
                    await asyncio.sleep(delay)

        # every attempt failed, let the caller decide what that means
        raise last_error if last_error else httpx.HTTPError("request failed")

    async def page_count(self, per_page: int = MAX_PER_PAGE, browse: str = "updated") -> tuple[int, int]:
        """
        Find out how big the catalog is right now

        @param per_page: int Plugins per page
        @param browse: str Which ordering to count against
        @return tuple: The page count and the total plugin count
        """

        # one page is enough to read the totals off
        payload = await self._get("query_plugins", per_page=min(per_page, MAX_PER_PAGE), page=1, browse=browse)
        info = payload.get("info", {})

        return (_as_int(info.get("pages")), _as_int(info.get("results")))

    async def fetch_page(
        self,
        page: int,
        per_page: int = MAX_PER_PAGE,
        browse: str = "updated",
    ) -> list[PluginRecord]:
        """
        Fetch one page of the catalog

        @param page: int The page number, one based
        @param per_page: int Plugins per page, capped at 250 by the api
        @param browse: str The ordering, updated walks newest first
        @return list[PluginRecord]: The cleaned records from that page
        """

        # ask for it
        payload = await self._get(
            "query_plugins",
            per_page=min(per_page, MAX_PER_PAGE),
            page=page,
            browse=browse,
        )

        # clean each one, dropping anything without a slug
        records = []
        for raw in payload.get("plugins", []):
            record = parse_plugin(raw)
            if record is not None:
                records.append(record)

        return records

    async def fetch_plugin(self, slug: str) -> PluginRecord:
        """
        Fetch a single plugin by slug

        Used to confirm whether a plugin that fell out of the catalog was
        actually closed, rather than just missed.

        @param slug: str The plugin slug
        @return PluginRecord: The cleaned record
        @throws PluginNotFound: When the api has no record of the slug
        """

        # ask for just this one
        payload = await self._get("plugin_information", slug=slug)

        # the api answers a missing plugin with an error body as well as a 404
        if payload.get("error"):
            raise PluginNotFound(slug)

        record = parse_plugin(payload)
        if record is None:
            raise PluginNotFound(slug)

        return record

    async def iter_pages(
        self,
        start_page: int = 1,
        per_page: int = MAX_PER_PAGE,
        browse: str = "updated",
        concurrency: int = 4,
    ) -> AsyncIterator[tuple[int, list[PluginRecord]]]:
        """
        Walk the catalog, several pages at a time

        Yields pages as they complete, in batches, so the caller can
        checkpoint as it goes rather than holding the whole catalog in
        memory.

        @param start_page: int Page to resume from, one based
        @param per_page: int Plugins per page
        @param browse: str The ordering to walk
        @param concurrency: int How many pages to fetch at once
        @return AsyncIterator: Page numbers paired with their records
        """

        # find out how far we have to go
        total_pages, total_results = await self.page_count(per_page=per_page, browse=browse)
        logger.info("wordpress.org catalog has %s plugins across %s pages", total_results, total_pages)

        # walk it in batches so we can yield and checkpoint between them
        page = start_page
        while page <= total_pages:
            batch = list(range(page, min(page + concurrency, total_pages + 1)))
            results = await asyncio.gather(
                *(self.fetch_page(number, per_page=per_page, browse=browse) for number in batch),
                return_exceptions=True,
            )

            # hand back whatever came through, logging what did not
            for number, result in zip(batch, results, strict=True):
                if isinstance(result, BaseException):
                    logger.error("page %s failed after retries: %s", number, result)
                    continue
                yield (number, result)

            page += len(batch)
