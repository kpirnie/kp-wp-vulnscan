#!/usr/bin/env python3
"""
Alembic Environment Module

Wires alembic up to our own configuration and model metadata, so the
connection url comes from the environment rather than alembic.ini.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from alembic import context
from sqlalchemy import engine_from_config, pool

from kpwpvs.core.config import load_config
from kpwpvs.models import Base

# the alembic config object, gives us access to the ini values
config = context.config

# what autogenerate compares against
target_metadata = Base.metadata

# the url always comes from the environment, never the ini file
config.set_main_option("sqlalchemy.url", load_config().database.url)


def run_migrations_offline() -> None:
    """
    Run migrations without a live connection

    Emits the sql to stdout instead of executing it, which is handy for
    reviewing what an upgrade is about to do.

    @return None
    """

    # configure against the url alone
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    # and run it
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations against a live connection

    The normal path, used by every db command.

    @return None
    """

    # build an engine from the ini section we just overrode
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    # connect and run
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


# pick the mode we were invoked in
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
