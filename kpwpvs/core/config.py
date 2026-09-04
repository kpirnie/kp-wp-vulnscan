#!/usr/bin/env python3
"""
Configuration Module

Loads the application configuration from a YAML file, applies any
environment variable overrides, and hands back a typed config object.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

# environment variables are prefixed with this, then the dotted config path
# uppercased with underscores: KPWPVS_DATABASE_PASSWORD, KPWPVS_WEB_PORT, etc
ENV_PREFIX = "KPWPVS_"

# where we look for the config file when nothing is passed in
DEFAULT_CONFIG_PATHS = (
    "/config/config.yaml",
    "config/config.yaml",
)


class DatabaseConfig(BaseModel):
    """
    Database connection settings

    Everything needed to build the MariaDB/MySQL connection URL along
    with the connection pool tuning.
    """

    host: str = "localhost"
    port: int = 3306
    name: str = "kpwpvs"
    user: str = "kpwpvs"
    password: str = ""
    charset: str = "utf8mb4"
    pool_size: int = 5
    pool_recycle: int = 3600
    echo: bool = False

    @property
    def url(self) -> str:
        """
        Build the SQLAlchemy connection URL

        Assembles a PyMySQL driver URL from the individual connection
        settings, url-quoting the password so specials do not break it.

        @return str: A SQLAlchemy compatible connection URL
        """

        # quote the credentials, they can legitimately contain url specials
        from urllib.parse import quote_plus

        user = quote_plus(self.user)
        password = quote_plus(self.password)

        # hand back the assembled url
        return f"mysql+pymysql://{user}:{password}@{self.host}:{self.port}/{self.name}?charset={self.charset}"


class CrawlerConfig(BaseModel):
    """
    wordpress.org repository crawler settings

    Controls how hard we hit the wp.org plugins API, and how the full
    seed crawl is chunked and checkpointed.
    """

    user_agent: str = "kp-wp-vulnscan/0.1 (+https://github.com/kpirnie/kp-wp-vulnscan)"
    concurrency: int = 4
    request_timeout: int = 30
    max_retries: int = 3
    retry_backoff: float = 2.0
    # seconds to wait between requests per worker, keeps us polite
    rate_limit_delay: float = 0.25
    # plugins per api page, wp.org caps this at 250
    per_page: int = 100
    # how many pages to pull before writing a checkpoint
    checkpoint_every: int = 5


class WordfenceFeedConfig(BaseModel):
    """
    Wordfence Intelligence feed settings

    The primary vulnerability source, free and keyless under CC BY-SA.
    """

    enabled: bool = True
    url: str = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
    timeout: int = 120


class NvdFeedConfig(BaseModel):
    """
    NVD / CVE feed settings

    Supplemental source, an api key is optional but raises the rate limit
    considerably so it is worth setting.
    """

    enabled: bool = True
    url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: str = ""
    timeout: int = 60
    # only pull cves modified within this many days on incremental runs
    lookback_days: int = 14


class FeedsConfig(BaseModel):
    """
    Vulnerability feed sources

    Wraps each individual feed's settings.
    """

    wordfence: WordfenceFeedConfig = Field(default_factory=WordfenceFeedConfig)
    nvd: NvdFeedConfig = Field(default_factory=NvdFeedConfig)


class WebhookConfig(BaseModel):
    """
    Outbound webhook settings

    Only fires when enabled and a url is actually configured, the format
    picks the payload shape for the target service.
    """

    enabled: bool = False
    url: str = ""
    format: Literal["slack", "discord", "generic"] = "generic"
    timeout: int = 30
    # do not notify on anything below this severity
    min_severity: Literal["low", "medium", "high", "critical"] = "medium"


class ReportingConfig(BaseModel):
    """
    Report output settings

    The database is always written, these are the optional extras. The
    file writers no-op when their output directory is not mounted.
    """

    output_dir: str = "/reports"
    json_enabled: bool = True
    html_enabled: bool = True
    # how many past report files to keep on disk, 0 keeps everything
    retention: int = 52
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)


class WebConfig(BaseModel):
    """
    Web interface settings

    Bind address, session handling, and whether the built in login is
    enforced. Auth stays on unless something in front handles it.
    """

    host: str = "0.0.0.0"
    port: int = 8080
    # required in production, sessions are signed with it
    secret_key: str = ""
    session_ttl: int = 86400
    auth_enabled: bool = True
    # public base url, used for links in reports and notifications
    base_url: str = ""


class AiConfig(BaseModel):
    """
    AI provider settings

    Used by the local source scanning phase. Provider is pluggable so
    anyone can point this at whatever service they prefer.
    """

    enabled: bool = False
    provider: Literal["anthropic", "openai", "google", "ollama", "custom"] = "anthropic"
    api_key: str = ""
    model: str = "claude-sonnet-5"
    # override for self hosted or non standard endpoints
    base_url: str = ""
    max_tokens: int = 4096
    temperature: float = 0.0
    request_timeout: int = 120
    # cap the spend, only scan this many plugins per run
    max_plugins_per_run: int = 25


class AppConfig(BaseModel):
    """
    Root application configuration

    Everything the scanner, reporters, and web interface need, in one
    typed object.
    """

    debug: bool = False
    # where checkpoints, caches, and scratch work land
    data_dir: str = "/data"
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    feeds: FeedsConfig = Field(default_factory=FeedsConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    ai: AiConfig = Field(default_factory=AiConfig)


def _coerce(value: str) -> Any:
    """
    Turn an environment string into a sensible python value

    Environment variables are always strings, so make a reasonable
    attempt at booleans, numbers, and lists before giving up.

    @param value: str The raw environment variable value
    @return Any: The coerced value, or the original string
    """

    # normalize it for the boolean checks
    lowered = value.strip().lower()

    # the obvious booleans
    if lowered in ("true", "yes", "on", "1"):
        return True
    if lowered in ("false", "no", "off", "0"):
        return False

    # try it as a number, integers first so we do not float everything
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass

    # comma separated becomes a list
    if "," in value:
        return [part.strip() for part in value.split(",")]

    # nothing special, hand back the string
    return value


def _apply_env_overrides(data: dict[str, Any], model: type[BaseModel], prefix: str = ENV_PREFIX) -> dict[str, Any]:
    """
    Overlay environment variables onto the parsed config data

    Walks the config model recursively, building the environment key for
    each field from its dotted path, and overriding anything that is set.

    @param data: dict The config data parsed from yaml
    @param model: type[BaseModel] The pydantic model describing this level
    @param prefix: str The environment key prefix for this level
    @return dict: The config data with environment overrides applied
    """

    # walk every field the model declares at this level
    for name, field in model.model_fields.items():
        env_key = f"{prefix}{name.upper()}"
        annotation = field.annotation

        # nested config section, recurse into it with the extended prefix
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            nested = data.get(name)
            data[name] = _apply_env_overrides(
                nested if isinstance(nested, dict) else {},
                annotation,
                f"{env_key}_",
            )
            continue

        # plain scalar, override it when the environment has something for us
        if env_key in os.environ:
            data[name] = _coerce(os.environ[env_key])

    # hand back what we built
    return data


def find_config_file(explicit: str | None = None) -> Path | None:
    """
    Locate the configuration file

    Honors an explicit path first, then KPWPVS_CONFIG, then falls back
    to the known default locations.

    @param explicit: str|None A path passed in on the command line
    @return Path|None: The first config file that exists, or None
    """

    # build the candidate list in priority order
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("KPWPVS_CONFIG"):
        candidates.append(os.environ["KPWPVS_CONFIG"])
    candidates.extend(DEFAULT_CONFIG_PATHS)

    # first one that actually exists wins
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file():
            return path

    # nothing found, the caller can still run on defaults plus environment
    return None


def load_config(config_path: str | None = None) -> AppConfig:
    """
    Load and parse the application configuration

    Reads the yaml config file when one exists, layers environment
    variable overrides on top, and validates the result into a typed
    configuration object.

    @param config_path: str|None Explicit path to the yaml config file
    @return AppConfig: Fully populated application configuration object
    @throws ValueError: When the yaml does not parse into a mapping
    """

    # start empty, a missing config file is fine when the environment is set
    data: dict[str, Any] = {}

    # find it and read it if we have one
    path = find_config_file(config_path)
    if path is not None:
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)

        # an empty file parses to None, that is still valid
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise ValueError(f"config file {path} must contain a mapping at the top level")
            data = loaded

    # environment always wins over the file
    data = _apply_env_overrides(data, AppConfig)

    # validate and hand it back
    return AppConfig(**data)
