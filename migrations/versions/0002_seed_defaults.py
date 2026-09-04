#!/usr/bin/env python3
"""
Seed Defaults Migration

Inserts the three vulnerability feeds and every setting at its default
value. Feeds are rows rather than config precisely so this can be a
starting point somebody edits later, endpoint included, because api
endpoints move and occasionally get retired outright.

Revision ID: 0002
Revises: 0001

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from kpwpvs.core.settings import SETTINGS

# revision identifiers, used by alembic
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# the feeds we ship with. priority orders them when two disagree about
# the same underlying issue, lower wins
SEED_FEEDS = (
    {
        "source": "wordfence",
        "name": "Wordfence Intelligence",
        "description": (
            "Primary source. Best WordPress coverage by a wide margin and the only feed that carries the "
            "wordpress.org slug directly, so it joins straight onto the catalog. Needs an api key, sent as a "
            "bearer token. The v2 feed was retired and now returns a 410."
        ),
        "enabled": True,
        "priority": 10,
        "url": "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
        "auth_type": "bearer",
        "auth_param": None,
        "timeout": 180,
        "options": {"format": "wordfence_v3"},
        "is_builtin": True,
    },
    {
        "source": "nvd",
        "name": "NVD",
        "description": (
            "Secondary source. Authoritative but poorly structured for WordPress, its CPE product names do not "
            "map to wordpress.org slugs, so matches come through the cve id rather than directly. Works without "
            "a key at a much lower rate limit."
        ),
        "enabled": True,
        "priority": 20,
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "auth_type": "header",
        "auth_param": "apiKey",
        "timeout": 60,
        "options": {"lookback_days": 14, "results_per_page": 2000},
        "is_builtin": True,
    },
    {
        "source": "cve",
        "name": "CVE Services",
        "description": (
            "Tertiary source, and the keyless fallback. Wordfence and Patchstack are both CNAs, so their "
            "WordPress records land here too with structured version ranges and a plugins.trac.wordpress.org "
            "reference the slug can be recovered from."
        ),
        "enabled": True,
        "priority": 30,
        "url": "https://cveawg.mitre.org/api/cve",
        "auth_type": "none",
        "auth_param": None,
        "timeout": 60,
        "options": {"lookback_days": 14},
        "is_builtin": True,
    },
)


def upgrade() -> None:
    """
    Insert the seed feeds and the default settings

    @return None
    """

    # a lightweight table definition is enough for a bulk insert, we do not
    # want the migration importing the live models and drifting with them.
    # note the options below are passed as plain dicts, sa.JSON encodes them
    # for us and handing it a pre-encoded string stores a json string
    feeds = sa.table(
        "feeds",
        sa.column("source", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("enabled", sa.Boolean),
        sa.column("priority", sa.Integer),
        sa.column("url", sa.String),
        sa.column("auth_type", sa.String),
        sa.column("auth_param", sa.String),
        sa.column("timeout", sa.Integer),
        sa.column("options", sa.JSON),
        sa.column("is_builtin", sa.Boolean),
        sa.column("record_count", sa.Integer),
        sa.column("added_count", sa.Integer),
        sa.column("updated_count", sa.Integer),
    )

    # zero out the counters rather than leaning on the column defaults,
    # a bulk insert does not run the python side ones
    op.bulk_insert(
        feeds,
        [dict(feed, record_count=0, added_count=0, updated_count=0) for feed in SEED_FEEDS],
    )

    # now every setting at its declared default, json encoded so the type
    # survives the round trip back out
    settings = sa.table(
        "settings",
        sa.column("key", sa.String),
        sa.column("value", sa.Text),
        sa.column("is_secret", sa.Boolean),
    )

    # secrets seed empty, there is nothing to encrypt yet and the migration
    # has no business holding the encryption key anyway
    op.bulk_insert(
        settings,
        [
            {
                "key": definition.key,
                "value": "" if definition.is_secret else json.dumps(definition.default),
                "is_secret": definition.is_secret,
            }
            for definition in SETTINGS
        ],
    )


def downgrade() -> None:
    """
    Remove the seed feeds and settings

    Only touches the builtin feeds, anything somebody added themselves
    is left alone.

    @return None
    """

    # drop the settings we seeded, by key
    keys = ", ".join(f"'{definition.key}'" for definition in SETTINGS)
    op.execute(f"DELETE FROM settings WHERE `key` IN ({keys})")

    # and the builtin feeds, leaving any custom ones in place
    op.execute("DELETE FROM feeds WHERE is_builtin = 1")
