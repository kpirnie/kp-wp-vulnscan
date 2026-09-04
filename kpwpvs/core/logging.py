#!/usr/bin/env python3
"""
Logging Module

Central logging setup for the whole application, keyed on the debug
flag so we get verbose output when we want it and clean output when
we do not.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import logging
import sys

# third party loggers that get chatty at debug level
NOISY_LOGGERS = (
    "httpx",
    "httpcore",
    "urllib3",
    "asyncio",
    "sqlalchemy.engine",
    "alembic.runtime.migration",
    "uvicorn.access",
    "multipart",
)

# the two formats we switch between
DEBUG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s %(funcName)s:%(lineno)d - %(message)s"
CLEAN_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


def setup_logging(debug: bool = False) -> None:
    """
    Configure application wide logging

    Sets the root logger level and format based on the debug flag, and
    quiets the noisy third party loggers when we are not debugging.

    @param debug: bool True for verbose debug output, False for clean info
    @return None
    """

    # pick the level and format
    level = logging.DEBUG if debug else logging.INFO
    fmt = DEBUG_FORMAT if debug else CLEAN_FORMAT

    # everything goes to stdout, the container runtime collects it
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S"))

    # wire up the root logger, replacing anything already attached
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # keep the third party chatter down unless we actually want it
    if not debug:
        for name in NOISY_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)
