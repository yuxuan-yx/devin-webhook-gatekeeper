"""Structured logging shared by the service and the reporting entrypoint.

WHY a shared module: every process that touches a delivery must emit the *same*
event vocabulary — `event_accepted`, `event_dropped`,
`devin_dispatch_succeeded`. If each wrote its own logging, a dashboard built on
one of them would silently miss the rest. One formatter, one `log()` helper,
one set of field names.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any


class JsonLogFormatter(logging.Formatter):
    """Render log records as single-line JSON.

    WHY JSON rather than human-readable lines: these logs are shipped to a log
    aggregator, and the questions we need to answer ("how many deliveries were
    dropped for repository_not_allowlisted last hour?", "show me everything for
    delivery X") are field queries, not text searches. Structured output makes
    them cheap and unambiguous.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Anything passed via logger.info(..., extra={"context": {...}}) is
        # merged in at the top level so it is directly queryable.
        context = getattr(record, "context", None)
        if isinstance(context, dict):
            payload.update(context)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str, logger_name: str = "gatekeeper") -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers = [handler]  # replace uvicorn's / the runner's default handlers
    root.setLevel(level.upper())
    return logging.getLogger(logger_name)


logger = logging.getLogger("gatekeeper")


def log(level: int, message: str, **fields: Any) -> None:
    """Emit a structured line.

    Every call site passes `delivery_id`; it is the correlation key that ties an
    inbound trigger — a webhook delivery or a scanner finding — to the eventual
    Devin session id, across process boundaries.
    """
    logger.log(level, message, extra={"context": fields})
