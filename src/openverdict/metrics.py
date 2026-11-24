"""All Prometheus metrics, registered once in the default registry."""

from prometheus_client import Counter, Gauge, Histogram

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
URL_VERDICTS = Counter(
    "openverdict_url_verdicts_total",
    "URL verdicts returned, by verdict (invalid = per-item error).",
    ["verdict"],
)
CACHE_REQUESTS = Counter(
    "openverdict_cache_requests_total",
    "Verdict cache lookups by result.",
    ["result"],
)
DETECTOR_DURATION = Histogram(
    "openverdict_detector_duration_seconds",
    "Time one detector took for one batch.",
    ["detector"],
)
DETECTOR_FAILURES = Counter(
    "openverdict_detector_failures_total",
    "Detector batches that timed out or raised.",
    ["detector", "reason"],
)
HTTP_DURATION = Histogram(
    "openverdict_http_request_duration_seconds",
    "HTTP request latency by method, route template and status.",
    ["method", "route", "status"],
)
