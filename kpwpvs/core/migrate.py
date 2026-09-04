#!/usr/bin/env python3
"""
Migration Module

Wraps alembic so the application drives its own schema, which matters
for the container entrypoint, it brings the schema up on start rather
than leaving somebody to remember.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from kpwpvs.core.config import BootstrapConfig
from kpwpvs.core.db import init_engine

logger = logging.getLogger(__name__)

# the migrations live alongside the package rather than inside it, so walk
# up out of kpwpvs/core to find them
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def escape_url(url: str) -> str:
    """
    Make a connection url safe to store in alembic's config

    Alembic's Config is a ConfigParser with interpolation switched on, so
    a percent sign in a value is a format character rather than a literal
    one. Any password containing a character that url-quotes, which is
    most punctuation, produces percent escapes and blows up with an
    invalid interpolation syntax error. Doubling them is what
    ConfigParser expects, and it reads back as the original.

    @param url: str The connection url
    @return str: The url with its percent signs escaped
    """

    return url.replace("%", "%%")


def build_alembic_config(config: BootstrapConfig) -> Config:
    """
    Build an alembic configuration pointed at our migrations

    @param config: BootstrapConfig The bootstrap configuration
    @return Config: An alembic config ready to hand to a command
    @throws FileNotFoundError: When the migrations directory is missing
    """

    # make sure we can actually find them before alembic complains obscurely
    script_location = PROJECT_ROOT / "migrations"
    if not script_location.is_dir():
        raise FileNotFoundError(f"migrations directory not found at {script_location}")

    # wire it up, the url comes from us rather than the ini
    alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    alembic_config.set_main_option("script_location", str(script_location))
    alembic_config.set_main_option("sqlalchemy.url", escape_url(config.database.url))

    return alembic_config


def current_revision(config: BootstrapConfig) -> str | None:
    """
    Get the revision the database is currently at

    @param config: BootstrapConfig The bootstrap configuration
    @return str|None: The current revision, or None on an empty database
    """

    # ask the database itself rather than guessing
    engine = init_engine(config)
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def head_revision(config: BootstrapConfig) -> str | None:
    """
    Get the newest revision available in the migrations directory

    @param config: BootstrapConfig The bootstrap configuration
    @return str|None: The head revision, or None when there are none
    """

    # straight off the script directory
    return ScriptDirectory.from_config(build_alembic_config(config)).get_current_head()


def is_current(config: BootstrapConfig) -> bool:
    """
    Whether the database schema is up to date

    @param config: BootstrapConfig The bootstrap configuration
    @return bool: True when the database is at the head revision
    """

    # both sides have to agree
    return current_revision(config) == head_revision(config)


def upgrade(config: BootstrapConfig, revision: str = "head") -> None:
    """
    Bring the schema up to a revision

    Safe to run against a database that is already current, alembic
    works out that there is nothing to do.

    @param config: BootstrapConfig The bootstrap configuration
    @param revision: str The target revision, head by default
    @return None
    """

    # log where we are going so the container output says something useful
    logger.info("upgrading schema from %s to %s", current_revision(config) or "empty", revision)
    command.upgrade(build_alembic_config(config), revision)
    logger.info("schema is now at %s", current_revision(config))


def downgrade(config: BootstrapConfig, revision: str) -> None:
    """
    Roll the schema back to a revision

    @param config: BootstrapConfig The bootstrap configuration
    @param revision: str The target revision
    @return None
    """

    # this one is destructive, so say so plainly
    logger.warning("downgrading schema from %s to %s", current_revision(config) or "empty", revision)
    command.downgrade(build_alembic_config(config), revision)
