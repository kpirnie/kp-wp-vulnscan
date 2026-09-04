#!/usr/bin/env python3
"""
Sources Package

Clients for the external services we pull data from.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from kpwpvs.sources.wporg import PluginNotFound, PluginRecord, WporgClient

# what this package hands out
__all__ = ["PluginNotFound", "PluginRecord", "WporgClient"]
