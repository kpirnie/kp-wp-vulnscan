#!/usr/bin/env python3
"""
Settings Registry Module

Declares every setting the application knows about, its type, default,
and how the interface should present it. The settings table only ever
holds the values that differ from these defaults, and the settings page
renders itself off this registry rather than a hand written form.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import enum
from dataclasses import dataclass
from typing import Any


class SettingType(enum.StrEnum):
    """
    What kind of value a setting holds

    Drives both the coercion on the way in and the widget the interface
    renders on the way out.
    """

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    CHOICE = "choice"
    # a string rendered as a password field and stored encrypted
    SECRET = "secret"


@dataclass(frozen=True)
class SettingDef:
    """
    The definition of one setting

    Everything needed to store it, validate it, and render it, in one
    place so the three never drift apart.
    """

    key: str
    type: SettingType
    default: Any
    label: str
    description: str = ""
    group: str = "general"

    # only meaningful for a choice, the allowed values
    choices: tuple[str, ...] = ()

    # bounds for the numeric types, ignored otherwise
    minimum: float | None = None
    maximum: float | None = None

    # admin only settings are hidden from managers entirely
    admin_only: bool = True

    @property
    def is_secret(self) -> bool:
        """
        Whether this setting holds a secret

        @return bool: True when the value must be stored encrypted
        """

        return self.type is SettingType.SECRET


# every setting, grouped the way the interface presents them
SETTINGS: tuple[SettingDef, ...] = (
    # --- general ---------------------------------------------------------
    SettingDef(
        key="general.debug",
        type=SettingType.BOOLEAN,
        default=False,
        label="Debug logging",
        description="Verbose logging with function and line numbers. Noisy, leave off unless chasing something.",
        group="general",
    ),
    SettingDef(
        key="general.site_name",
        type=SettingType.STRING,
        default="KP WP VulnScan",
        label="Site name",
        description="Shown in the interface header and in report titles.",
        group="general",
    ),
    # --- crawler ---------------------------------------------------------
    SettingDef(
        key="crawler.user_agent",
        type=SettingType.STRING,
        default="kp-wp-vulnscan/0.1 (+https://github.com/kpirnie/kp-wp-vulnscan)",
        label="User agent",
        description="Sent on every request to wordpress.org. Identify yourself honestly, they are doing us a favour.",
        group="crawler",
    ),
    SettingDef(
        key="crawler.concurrency",
        type=SettingType.INTEGER,
        default=4,
        label="Concurrent requests",
        description="How many catalog pages to pull at once. Be conservative, this is a free API.",
        group="crawler",
        minimum=1,
        maximum=16,
    ),
    SettingDef(
        key="crawler.request_timeout",
        type=SettingType.INTEGER,
        default=30,
        label="Request timeout",
        description="Seconds to wait on any single request to wordpress.org.",
        group="crawler",
        minimum=5,
        maximum=300,
    ),
    SettingDef(
        key="crawler.max_retries",
        type=SettingType.INTEGER,
        default=3,
        label="Max retries",
        description="How many times to retry a failed request before giving up on that page.",
        group="crawler",
        minimum=0,
        maximum=10,
    ),
    SettingDef(
        key="crawler.retry_backoff",
        type=SettingType.FLOAT,
        default=2.0,
        label="Retry backoff",
        description="Multiplier between retry attempts, so 2.0 waits 2s, 4s, 8s.",
        group="crawler",
        minimum=1.0,
        maximum=10.0,
    ),
    SettingDef(
        key="crawler.rate_limit_delay",
        type=SettingType.FLOAT,
        default=0.25,
        label="Rate limit delay",
        description="Seconds each worker pauses between requests. Keeps us a polite guest.",
        group="crawler",
        minimum=0.0,
        maximum=10.0,
    ),
    SettingDef(
        key="crawler.per_page",
        type=SettingType.INTEGER,
        default=250,
        label="Results per page",
        description="Plugins per catalog page. The API caps this at 250, which is about 287 pages in total.",
        group="crawler",
        minimum=1,
        maximum=250,
    ),
    SettingDef(
        key="crawler.checkpoint_every",
        type=SettingType.INTEGER,
        default=5,
        label="Checkpoint interval",
        description="Pages between checkpoint writes, so an interrupted seed crawl resumes near where it stopped.",
        group="crawler",
        minimum=1,
        maximum=100,
    ),
    SettingDef(
        key="crawler.abandoned_after_days",
        type=SettingType.INTEGER,
        default=730,
        label="Abandoned after",
        description="Days without an update before a plugin is flagged abandoned. Two years by default.",
        group="crawler",
        minimum=90,
        maximum=3650,
    ),
    # --- scoring ---------------------------------------------------------
    SettingDef(
        key="scoring.weight_issue_count",
        type=SettingType.FLOAT,
        default=1.0,
        label="Issue count weight",
        description="How much a plugin's total issue count contributes to its scan priority.",
        group="scoring",
        minimum=0.0,
        maximum=10.0,
    ),
    SettingDef(
        key="scoring.weight_severity",
        type=SettingType.FLOAT,
        default=2.0,
        label="Severity weight",
        description="How much the severity of those issues contributes, above the raw count.",
        group="scoring",
        minimum=0.0,
        maximum=10.0,
    ),
    SettingDef(
        key="scoring.weight_installs",
        type=SettingType.FLOAT,
        default=1.5,
        label="Install base weight",
        description="How much active installs contribute. Blast radius matters as much as bug count.",
        group="scoring",
        minimum=0.0,
        maximum=10.0,
    ),
    SettingDef(
        key="scoring.weight_abandoned",
        type=SettingType.FLOAT,
        default=1.25,
        label="Abandoned weight",
        description="Multiplier applied to plugins that are closed or abandoned. They never get patched.",
        group="scoring",
        minimum=0.0,
        maximum=10.0,
    ),
    # --- reporting -------------------------------------------------------
    SettingDef(
        key="reporting.output_dir",
        type=SettingType.STRING,
        default="/reports",
        label="Report directory",
        description="Where json and html reports are written. Skipped entirely when this is not a mounted volume.",
        group="reporting",
    ),
    SettingDef(
        key="reporting.json_enabled",
        type=SettingType.BOOLEAN,
        default=True,
        label="Write JSON reports",
        description="Only takes effect when the report directory exists.",
        group="reporting",
    ),
    SettingDef(
        key="reporting.html_enabled",
        type=SettingType.BOOLEAN,
        default=True,
        label="Write HTML reports",
        description="Only takes effect when the report directory exists.",
        group="reporting",
    ),
    SettingDef(
        key="reporting.retention",
        type=SettingType.INTEGER,
        default=52,
        label="Reports to keep",
        description="How many report files to keep on disk. Zero keeps everything.",
        group="reporting",
        minimum=0,
        maximum=1000,
    ),
    # --- notifications ---------------------------------------------------
    SettingDef(
        key="webhook.enabled",
        type=SettingType.BOOLEAN,
        default=False,
        label="Enable webhook",
        description="Post a summary after each run. Nothing is sent unless this is on and a url is set.",
        group="webhook",
    ),
    SettingDef(
        key="webhook.url",
        type=SettingType.SECRET,
        default="",
        label="Webhook URL",
        description="Stored encrypted, because these usually carry a token in the path.",
        group="webhook",
    ),
    SettingDef(
        key="webhook.format",
        type=SettingType.CHOICE,
        default="generic",
        label="Payload format",
        description="Shape of the posted payload.",
        group="webhook",
        choices=("generic", "slack", "discord"),
    ),
    SettingDef(
        key="webhook.timeout",
        type=SettingType.INTEGER,
        default=30,
        label="Timeout",
        description="Seconds to wait on the webhook endpoint.",
        group="webhook",
        minimum=1,
        maximum=300,
    ),
    SettingDef(
        key="webhook.min_severity",
        type=SettingType.CHOICE,
        default="medium",
        label="Minimum severity",
        description="Nothing below this severity triggers a notification.",
        group="webhook",
        choices=("low", "medium", "high", "critical"),
    ),
    # --- web -------------------------------------------------------------
    SettingDef(
        key="web.host",
        type=SettingType.STRING,
        default="0.0.0.0",
        label="Bind address",
        description="What the interface listens on. Takes effect when the interface restarts.",
        group="web",
    ),
    SettingDef(
        key="web.port",
        type=SettingType.INTEGER,
        default=8080,
        label="Bind port",
        description="What port the interface listens on. Takes effect when the interface restarts.",
        group="web",
        minimum=1,
        maximum=65535,
    ),
    SettingDef(
        key="web.auth_enabled",
        type=SettingType.BOOLEAN,
        default=True,
        label="Require sign in",
        description=(
            "Leave on unless something in front of this is doing the authenticating. "
            "Off means every visitor has full access."
        ),
        group="web",
    ),
    SettingDef(
        key="web.base_url",
        type=SettingType.STRING,
        default="",
        label="Base URL",
        description="Public url of this install, used for links in reports and notifications.",
        group="web",
    ),
    SettingDef(
        key="web.session_ttl",
        type=SettingType.INTEGER,
        default=86400,
        label="Session lifetime",
        description="Seconds a sign in lasts before it has to be renewed.",
        group="web",
        minimum=300,
        maximum=2592000,
    ),
    SettingDef(
        key="web.max_failed_logins",
        type=SettingType.INTEGER,
        default=5,
        label="Max failed logins",
        description="Failed attempts before an account is temporarily locked.",
        group="web",
        minimum=3,
        maximum=50,
    ),
    SettingDef(
        key="web.lockout_minutes",
        type=SettingType.INTEGER,
        default=15,
        label="Lockout duration",
        description="Minutes an account stays locked after too many failed attempts.",
        group="web",
        minimum=1,
        maximum=1440,
    ),
    # --- ai --------------------------------------------------------------
    SettingDef(
        key="ai.enabled",
        type=SettingType.BOOLEAN,
        default=False,
        label="Enable AI analysis",
        description="Used by the local source scanning phase. Off until you have set a provider and key.",
        group="ai",
    ),
    SettingDef(
        key="ai.provider",
        type=SettingType.CHOICE,
        default="anthropic",
        label="Provider",
        description="Which service to use. Custom points the anthropic-compatible client at your own endpoint.",
        group="ai",
        choices=("anthropic", "openai", "google", "ollama", "custom"),
    ),
    SettingDef(
        key="ai.api_key",
        type=SettingType.SECRET,
        default="",
        label="API key",
        description="Stored encrypted. Not needed for a local ollama endpoint.",
        group="ai",
    ),
    SettingDef(
        key="ai.model",
        type=SettingType.STRING,
        default="claude-sonnet-5",
        label="Model",
        description="Model identifier, as the chosen provider names it.",
        group="ai",
    ),
    SettingDef(
        key="ai.base_url",
        type=SettingType.STRING,
        default="",
        label="Base URL",
        description="Override for self hosted or non standard endpoints. Leave empty for the provider default.",
        group="ai",
    ),
    SettingDef(
        key="ai.max_tokens",
        type=SettingType.INTEGER,
        default=4096,
        label="Max tokens",
        description="Ceiling on the response length per analysis.",
        group="ai",
        minimum=256,
        maximum=200000,
    ),
    SettingDef(
        key="ai.temperature",
        type=SettingType.FLOAT,
        default=0.0,
        label="Temperature",
        description="Leave at zero. Security analysis wants reproducible answers, not creative ones.",
        group="ai",
        minimum=0.0,
        maximum=2.0,
    ),
    SettingDef(
        key="ai.request_timeout",
        type=SettingType.INTEGER,
        default=120,
        label="Request timeout",
        description="Seconds to wait on the provider before giving up on one analysis.",
        group="ai",
        minimum=10,
        maximum=900,
    ),
    SettingDef(
        key="ai.max_plugins_per_run",
        type=SettingType.INTEGER,
        default=25,
        label="Plugins per run",
        description="Caps the spend. Only the highest priority plugins are analysed, in priority order.",
        group="ai",
        minimum=1,
        maximum=10000,
    ),
)

# indexed by key for lookups, built once at import
SETTINGS_BY_KEY: dict[str, SettingDef] = {definition.key: definition for definition in SETTINGS}

# the groups in the order the interface should present them
SETTING_GROUPS: tuple[str, ...] = (
    "general",
    "crawler",
    "scoring",
    "reporting",
    "webhook",
    "web",
    "ai",
)


def defaults() -> dict[str, Any]:
    """
    Every setting key mapped to its default value

    Used to seed a fresh install and to fall back on for anything the
    settings table does not carry.

    @return dict: Setting keys mapped to their default values
    """

    # straight off the registry
    return {definition.key: definition.default for definition in SETTINGS}


def group_of(group: str) -> tuple[SettingDef, ...]:
    """
    Every setting in one group

    @param group: str The group name to filter on
    @return tuple: The settings belonging to that group, in declared order
    """

    # keep the declared order, it is the order they should render in
    return tuple(definition for definition in SETTINGS if definition.group == group)
