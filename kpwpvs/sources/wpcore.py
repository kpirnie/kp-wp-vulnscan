#!/usr/bin/env python3
"""
WordPress Core Source Module

Core is not like a plugin. There is one of it, everybody runs some
version of it, and wordpress.org publishes the security status of every
release it has ever made. So rather than tracking only what is current,
we track every version and what is wrong with each.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from dataclasses import dataclass, field
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

# every release ever, mapped to insecure, outdated, or latest
STABLE_CHECK_URL = "https://api.wordpress.org/core/stable-check/1.0/"

# the current release and its download, used for the release date
VERSION_CHECK_URL = "https://api.wordpress.org/core/version-check/1.7/"

# core is one piece of software with one slug, and wordpress mu is the
# other one the feeds still carry records for
CORE_SLUG = "wordpress"
CORE_NAME = "WordPress"
MU_SLUG = "wpmu"
MU_NAME = "WordPress MU"

# what wordpress.org says about a release
STATUS_LATEST = "latest"
STATUS_OUTDATED = "outdated"
STATUS_INSECURE = "insecure"


@dataclass
class CoreRelease:
    """
    One WordPress core release

    The status is wordpress.org's own assessment, which is worth keeping
    alongside our vulnerability matching rather than instead of it.
    """

    version: str
    status: str = STATUS_INSECURE
    released_at: datetime | None = None


@dataclass
class CoreCatalog:
    """
    Every core release, and which one is current

    @param releases: The full release history
    @param current: The version wordpress.org currently ships
    """

    releases: list[CoreRelease] = field(default_factory=list)
    current: str | None = None


class WpCoreClient:
    """
    Pulls the WordPress core release history

    Two endpoints, neither of which needs a key. The stable check is the
    interesting one, it is wordpress.org telling us which of its own
    releases are insecure.
    """

    def __init__(self, user_agent: str, timeout: int = 30) -> None:
        """
        Build a client

        @param user_agent: str How we identify ourselves to wordpress.org
        @param timeout: int Seconds to wait on any single request
        """

        self._timeout = timeout
        self._headers = {"User-Agent": user_agent, "Accept": "application/json"}

    def fetch(self) -> CoreCatalog:
        """
        Fetch every core release and its security status

        @return CoreCatalog: The release history and the current version
        @throws httpx.HTTPError: When wordpress.org cannot be reached
        """

        catalog = CoreCatalog()

        with httpx.Client(timeout=self._timeout, headers=self._headers, follow_redirects=True) as client:

            # every release ever made, with wordpress.org's own verdict
            response = client.get(STABLE_CHECK_URL)
            response.raise_for_status()
            statuses = response.json()

            if not isinstance(statuses, dict):
                logger.error("the stable check did not return the object we expected")
                return catalog

            for version, status in statuses.items():
                if not isinstance(version, str) or not version.strip():
                    continue

                catalog.releases.append(
                    CoreRelease(
                        version=version.strip(),
                        status=status if isinstance(status, str) else STATUS_INSECURE,
                    )
                )

                # the one release flagged latest is what core currently is
                if status == STATUS_LATEST:
                    catalog.current = version.strip()

            logger.info(
                "wordpress.org lists %s core releases, %s of them insecure",
                len(catalog.releases),
                sum(1 for r in catalog.releases if r.status == STATUS_INSECURE),
            )

            # fall back to the version check when nothing was flagged latest
            if catalog.current is None:
                catalog.current = self._current_version(client)

        return catalog

    def _current_version(self, client: httpx.Client) -> str | None:
        """
        Ask the version check what core currently is

        Only used when the stable check did not flag anything as latest,
        which should not happen but is cheap to guard against.

        @param client: httpx.Client The client to reuse
        @return str|None: The current version, when it could be read
        """

        # the first upgrade offer names the current release
        try:
            response = client.get(VERSION_CHECK_URL)
            response.raise_for_status()
            offers = response.json().get("offers") or []

            for offer in offers:
                version = offer.get("current") or offer.get("version")
                if isinstance(version, str) and version.strip():
                    return version.strip()

        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("could not read the core version check: %s", exc)

        return None
