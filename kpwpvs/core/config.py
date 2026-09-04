#!/usr/bin/env python3
"""
Bootstrap Configuration Module

Only what we need before the database is reachable, which is how to
reach the database and how to decrypt what is stored in it. Everything
else lives in the settings table and is managed from the web interface.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import os
from typing import Any
from urllib.parse import quote_plus

from pydantic import BaseModel, Field

# environment variables are prefixed with this, then the dotted path
# uppercased with underscores: KPWPVS_DATABASE_PASSWORD, KPWPVS_SECRET_KEY
ENV_PREFIX = "KPWPVS_"

# a secret can also be handed to us as a file path, which is how you feed
# a podman secret in without it landing in the process environment
FILE_SUFFIX = "_FILE"


class DatabaseConfig(BaseModel):
    """
    Database connection settings

    Bootstrap only, because we obviously cannot read these out of the
    database we are trying to reach.
    """

    host: str = "127.0.0.1"
    port: int = 3306
    name: str = "kpwpvs"
    user: str = "kpwpvs"
    password: str = ""
    charset: str = "utf8mb4"
    pool_size: int = 5
    pool_recycle: int = 3600
    echo: bool = False

    # run the mariadb server inside this container, turn it off to point
    # at an existing server somewhere else
    embedded: bool = True

    @property
    def url(self) -> str:
        """
        Build the SQLAlchemy connection URL

        Assembles a PyMySQL driver URL from the individual connection
        settings, url-quoting the credentials so specials do not break it.

        @return str: A SQLAlchemy compatible connection URL
        """

        # quote them, both can legitimately contain url specials
        user = quote_plus(self.user)
        password = quote_plus(self.password)

        # hand back the assembled url
        return f"mysql+pymysql://{user}:{password}@{self.host}:{self.port}/{self.name}?charset={self.charset}"


class BootstrapConfig(BaseModel):
    """
    Everything that has to come from the environment

    Deliberately small. If you find yourself wanting to add something
    here, ask first whether it could be a setting instead.
    """

    # verbose logging, on before we have a database to read it from
    debug: bool = False

    # where checkpoints, caches, and scratch work land
    data_dir: str = "/data"

    # signs sessions and derives the key that encrypts stored secrets.
    # changing it invalidates every session and every stored secret
    secret_key: str = ""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)


def _coerce(value: str) -> Any:
    """
    Turn an environment string into a sensible python value

    Environment variables are always strings, so make a reasonable
    attempt at booleans and numbers before giving up.

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

    # nothing special, hand back the string
    return value


def _read_env(key: str) -> str | None:
    """
    Read one environment variable, honoring the _FILE convention

    Container secrets are usually mounted as files rather than passed in
    the environment, so KPWPVS_DATABASE_PASSWORD_FILE pointing at a file
    works the same as setting the value directly.

    @param key: str The environment key to look for
    @return str|None: The value, or None when neither form is set
    """

    # the file form wins, it is the more deliberate of the two
    path = os.environ.get(f"{key}{FILE_SUFFIX}")
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()

    # otherwise the plain variable
    return os.environ.get(key)


def _collect(model: type[BaseModel], prefix: str = ENV_PREFIX) -> dict[str, Any]:
    """
    Gather environment values for a config model

    Walks the model recursively, building the environment key for each
    field from its dotted path.

    @param model: type[BaseModel] The pydantic model to gather values for
    @param prefix: str The environment key prefix for this level
    @return dict: Whatever the environment had for this model
    """

    data: dict[str, Any] = {}

    # walk every field the model declares at this level
    for name, field in model.model_fields.items():
        env_key = f"{prefix}{name.upper()}"
        annotation = field.annotation

        # nested section, recurse into it with the extended prefix
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            nested = _collect(annotation, f"{env_key}_")
            if nested:
                data[name] = nested
            continue

        # plain scalar, take it when the environment has something for us
        raw = _read_env(env_key)
        if raw is not None:
            data[name] = _coerce(raw)

    # hand back what we found
    return data


def load_config() -> BootstrapConfig:
    """
    Load the bootstrap configuration from the environment

    There is no config file. Anything not set here falls back to the
    model default, and everything else the application needs is read
    out of the settings table once the database is up.

    @return BootstrapConfig: The bootstrap configuration
    """

    # gather and validate
    return BootstrapConfig(**_collect(BootstrapConfig))
