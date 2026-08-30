"""Structured logging and run-summary helpers shared by both entrypoints.

WHY a shared module: the service (main.py) and the GitHub Actions entrypoint
(dispatch.py) must emit the *same* event vocabulary — `event_accepted`,
`event_dropped`, `devin_dispatch_succeeded`. If each wrote its own logging, a
dashboard built on one trigger path would silently miss the other. One
formatter, one `log()` helper, one set of field names.
"""

from __future__ import annotations

import json
import logging
import os
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
    inbound trigger (a GitHub webhook delivery, or an Actions run) to the
    eventual Devin session id, across process and job boundaries.
    """
    logger.log(level, message, extra={"context": fields})


def write_step_summary(markdown: str) -> None:
    """Append Markdown to the GitHub Actions job summary, if we are in a job.

    WHY: JSON logs answer an operator's questions, but an engineering leader
    will not open a log aggregator. `$GITHUB_STEP_SUMMARY` renders directly on
    the run page, so the same dispatch produces both a machine-queryable record
    and a human-readable one at zero extra infrastructure cost. Outside Actions
    the variable is unset and this is a no-op, which keeps the service and the
    job on one code path.
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(markdown.rstrip() + "\n")


def write_job_output(name: str, value: str) -> None:
    """Expose a value to later steps via `$GITHUB_OUTPUT` (no-op locally)."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")
