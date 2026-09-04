#!/usr/bin/env python3
"""
Database Module

Engine and session handling. One engine per process, handed out through
a context manager so nothing leaks a connection back into the pool in a
dirty state.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from kpwpvs.core.config import BootstrapConfig

logger = logging.getLogger(__name__)

# the process wide engine and session factory, built on first use
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def build_engine(config: BootstrapConfig) -> Engine:
    """
    Build a database engine from the configuration

    Pools connections with a pre-ping so a connection the server has
    already dropped gets replaced instead of blowing up mid query.

    @param config: BootstrapConfig The loaded application configuration
    @return Engine: A configured SQLAlchemy engine
    """

    # build it, pre_ping matters because the weekly cadence means most
    # connections sit idle far longer than the server's wait_timeout
    return create_engine(
        config.database.url,
        echo=config.database.echo,
        pool_size=config.database.pool_size,
        pool_recycle=config.database.pool_recycle,
        pool_pre_ping=True,
        future=True,
    )


def init_engine(config: BootstrapConfig) -> Engine:
    """
    Initialize the process wide engine and session factory

    Safe to call more than once, the second call hands back what the
    first one built.

    @param config: BootstrapConfig The loaded application configuration
    @return Engine: The process wide engine
    """

    global _engine, _session_factory

    # only build it the once
    if _engine is None:
        _engine = build_engine(config)
        _session_factory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
        logger.debug("database engine initialized for %s:%s", config.database.host, config.database.port)

    # hand it back
    return _engine


def get_engine() -> Engine:
    """
    Get the process wide engine

    @return Engine: The engine built by init_engine
    @throws RuntimeError: When init_engine has not been called yet
    """

    # make sure somebody set it up first
    if _engine is None:
        raise RuntimeError("database engine has not been initialized, call init_engine first")

    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    """
    Hand out a session wrapped in a transaction

    Commits when the block finishes cleanly, rolls back when it does
    not, and always closes.

    @return Iterator[Session]: The session, for the duration of the block
    @throws RuntimeError: When init_engine has not been called yet
    """

    # make sure somebody set it up first
    if _session_factory is None:
        raise RuntimeError("database engine has not been initialized, call init_engine first")

    # hand out the session and clean up after whatever happens
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def ping(config: BootstrapConfig) -> bool:
    """
    Check whether the database is reachable

    Used by the container entrypoint to wait for the server to come up
    before running migrations against it.

    @param config: BootstrapConfig The loaded application configuration
    @return bool: True when a trivial query succeeded
    """

    # try the simplest possible query
    try:
        engine = init_engine(config)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.debug("database ping failed: %s", exc)
        return False


def dispose() -> None:
    """
    Tear the engine down

    Closes every pooled connection, mostly so short lived commands exit
    without waiting on the pool.

    @return None
    """

    global _engine, _session_factory

    # nothing to do if it was never built
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _session_factory = None
