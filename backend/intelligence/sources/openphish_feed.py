"""
OpenPhish threat feed integration.

Feed URL: https://openphish.com/feed.txt
License: OpenPhish Community Feed is free for research and defensive operations with attribution.
Attribution: OpenPhish (https://openphish.com)
"""

from ..loaders.threat_feed_loader import refresh_feeds_async

__all__ = ["refresh_feeds_async"]

