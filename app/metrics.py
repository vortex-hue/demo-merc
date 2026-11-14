from prometheus_client import Counter, Histogram

REQUESTS = Counter("http_requests_total", "Requests", ["method", "endpoint", "status"])
ERRORS = Counter("http_errors_total", "Error responses", ["method", "endpoint"])
LATENCY = Histogram("http_request_seconds", "Latency", ["method", "endpoint"])
EVENTS_PROCESSED = Counter("events_processed_total", "Events persisted", ["type"])

