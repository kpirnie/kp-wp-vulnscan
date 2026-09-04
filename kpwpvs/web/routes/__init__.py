#!/usr/bin/env python3
"""
Web Routes Package

The interface's routes, grouped by what they are about.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from kpwpvs.web.routes import admin, auth, catalog, dashboard, findings

# what this package hands out
__all__ = ["admin", "auth", "catalog", "dashboard", "findings"]
