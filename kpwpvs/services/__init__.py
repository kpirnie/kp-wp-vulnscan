#!/usr/bin/env python3
"""
Services Package

The pipeline stages and the shared services they lean on.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
from kpwpvs.services.crawler import Crawler, CrawlStats
from kpwpvs.services.feeds import FeedService, FeedStats
from kpwpvs.services.matcher import Matcher, MatchStats
from kpwpvs.services.pipeline import Pipeline
from kpwpvs.services.reporter import Reporter
from kpwpvs.services.settings_service import SettingsService

# what this package hands out
__all__ = [
    "Crawler",
    "CrawlStats",
    "FeedService",
    "FeedStats",
    "MatchStats",
    "Matcher",
    "Pipeline",
    "Reporter",
    "SettingsService",
]
