#!/usr/bin/env python3
"""
Core Package

Shared plumbing used across the application, configuration and logging
for now, database access and models to follow.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from kpwpvs.core.config import AppConfig, find_config_file, load_config
from kpwpvs.core.logging import setup_logging

# what this package hands out
__all__ = [
    "AppConfig",
    "find_config_file",
    "load_config",
    "setup_logging",
]
