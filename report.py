"""Fleet report: "if I were an engineering leader, how would I know this works?"

Reads every session this gatekeeper has ever created (they are identifiable by
the `category:` tag the translation layer stamps on) and renders throughput,
in-flight count, and outcome rate.

WHY tags are the join key: the tag is written at dispatch time in
`build_devin_payload`, so a session is attributable to a trigger category
without any local bookkeeping. That keeps the reporting path stateless — it can
run in a scheduled job, on a laptop, or nowhere at all, and the numbers are
identical.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections import Counter
from typing import Any

import httpx

from config import CoreSettings, get_core_settings
from observability import configure_logging, log
from services import DevinClient, TriageCategory

# Statuses the API reports. Grouped rather than listed individually because the
# leader-facing question is only ever "working, done, or stuck?".
_TERMINAL_OK = {"finished", "blocked", "completed"}
_TERMINAL_BAD = {"expired", "stopped", "failed"}

_CATEGORY_TAG_PREFIX = "category:"


def _category_of(session: dict[str, Any]) -> str | None:
    for tag in session.get("tags") or []:
        if isinstance(tag, str) and tag.startswith(_CATEGORY_TAG_PREFIX):
            return tag[len(_CATEGORY_TAG_PREFIX) :]
    return None


def _pull_request_url(session: dict[str, Any]) -> str | None:
    """Extract a PR link if the session produced one.

    The PR is the only outcome signal that matters to the audience: a session
    that ran and changed nothing is not a success, however green its status.
    """
    candidates = session.get("pull_requests") or []
    pull_request = session.get("pull_request")
    if isinstance(pull_request, dict):
        candidates = [pull_request, *candidates]
    for candidate in candidates:
        if isinstance(candidate, str):
            return candidate
        if isinstance(candidate, dict):
            url = candidate.get("url") or candidate.get("html_url")
            if isinstance(url, str):
                return url
    structured = session.get("structured_output")
    if isinstance(structured, dict):
        url = structured.get("pull_request_url")
        if isinstance(url, str):
            return url
    return None


async def _collect(devin: DevinClient, max_sessions: int) -> list[dict[str, Any]]:
    """Page until we run out of sessions or hit the cap (bounded work)."""
    collected: list[dict[str, Any]] = []
    offset = 0
    page_size = 100
    while len(collected) < max_sessions:
        page = await devin.list_sessions(limit=page_size, offset=offset)
        if not page:
            break
        collected.extend(page)
        if len(page) < page_size:
            break
        offset += page_size
    return collected[:max_sessions]


def _render(sessions: list[dict[str, Any]]) -> tuple[dict[str, Any], str]:
    """Return (metrics, markdown). Pure, so it is trivially testable."""
    gatekeeper_sessions = [s for s in sessions if _category_of(s) is not None]

    by_category: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    in_flight = 0
    with_pr = 0
    recent_rows: list[str] = []

    for session in gatekeeper_sessions:
        category = _category_of(session) or "unknown"
        status = str(session.get("status_enum") or session.get("status") or "unknown").lower()
        by_category[category] += 1
        by_status[status] += 1
        if status not in _TERMINAL_OK and status not in _TERMINAL_BAD:
            in_flight += 1
        pr_url = _pull_request_url(session)
        if pr_url:
            with_pr += 1
        if len(recent_rows) < 10:
            recent_rows.append(
                f"| `{session.get('session_id', '')[:16]}` | `{category}` | {status} | "
                f"{('[PR](' + pr_url + ')') if pr_url else '—'} |"
            )

    total = len(gatekeeper_sessions)
    completed = sum(by_status[s] for s in by_status if s in _TERMINAL_OK | _TERMINAL_BAD)
    pr_rate = round(100 * with_pr / total, 1) if total else 0.0

    metrics: dict[str, Any] = {
        "sessions_total": total,
        "sessions_in_flight": in_flight,
        "sessions_completed": completed,
        "sessions_with_pull_request": with_pr,
        "pull_request_rate_pct": pr_rate,
        "by_category": dict(by_category),
        "by_status": dict(by_status),
    }

    category_rows = "".join(
        f"| `{category.value}` | {by_category.get(category.value, 0)} |\n"
        for category in TriageCategory
    )

    markdown = (
        "## Devin Gatekeeper — fleet report\n\n"
        f"**{total}** sessions dispatched · **{in_flight}** in flight · "
        f"**{with_pr}** produced a pull request (**{pr_rate}%**)\n\n"
        "### By trigger category\n\n"
        "| category | sessions |\n| --- | --- |\n" + category_rows + "\n"
        "### Most recent\n\n"
        "| session | category | status | output |\n| --- | --- | --- | --- |\n"
        + "\n".join(recent_rows)
        + "\n"
    )
    return metrics, markdown


async def _run() -> int:
    settings: CoreSettings = get_core_settings()
    configure_logging(settings.log_level)

    timeout = httpx.Timeout(settings.devin_request_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout) as http:
        devin = DevinClient(
            http_client=http,
            api_key=settings.devin_api_key,
            base_url=settings.devin_api_base_url,
            org_id=settings.devin_org_id,
        )
        try:
            sessions = await _collect(devin, max_sessions=500)
        except httpx.HTTPError as exc:
            log(
                logging.ERROR,
                "report_fetch_failed",
                delivery_id=None,
                error=type(exc).__name__,
                detail=str(exc),
            )
            return 1

    metrics, markdown = _render(sessions)
    # Two consumers, one computation: the JSON line feeds a dashboard, the
    # Markdown is what a human reads.
    log(logging.INFO, "fleet_report", delivery_id=None, **metrics)
    print(markdown)
    print(json.dumps(metrics, indent=2))
    return 0


def main() -> None:
    sys.exit(asyncio.run(_run()))


if __name__ == "__main__":
    main()
