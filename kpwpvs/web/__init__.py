#!/usr/bin/env python3
"""
Web Package

The server rendered interface: FastAPI, jinja templates, htmx for the
parts that would otherwise reload the page, and tailwind compiled ahead
of time so nothing needs node at runtime.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from kpwpvs.web.app import create_app

# what this package hands out
__all__ = ["create_app"]
