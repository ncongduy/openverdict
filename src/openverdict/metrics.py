"""All Prometheus metrics, registered once in the default registry."""

from prometheus_client import Counter, Gauge

FEED_LAST_SUCCESS = Gauge(
    "openverdict_feed_last_success_timestamp_seconds",
    "Unix time of the last successful feed sync.",
    ["feed"],
)
FEED_ENTRIES = Gauge(
    "openverdict_feed_entries",
    "Entries in the active feed version.",
    ["feed", "kind"],
)
FEED_SYNC_FAILURES = Counter(
    "openverdict_feed_sync_failures_total",
    "Feed syncs that failed and kept the previous version.",
    ["feed"],
)
