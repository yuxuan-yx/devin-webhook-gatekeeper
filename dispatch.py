"""GitHub Actions entrypoint: the same gatekeeper, triggered from inside CI.

WHY this exists alongside the webhook service:
The webhook service (main.py) is the production topology — one always-on
gatekeeper in front of many repositories. But it requires a publicly reachable
HTTPS endpoint, which is a deployment prerequisite, not a design property. A
GitHub Actions job runs *inside* GitHub's network, receives the identical event
payload on disk, and is authenticated by the runner itself. So the same
governance and translation code can be triggered with no ingress at all.

The load-bearing point for a reviewer: everything below the trigger is shared.
`evaluate_payload` and `build_devin_payload` are imported, not reimplemented, so
the two trigger paths can never disagree about what is actionable or about what
Devin is asked to do. Only the three things that genuinely differ are handled
here: how the event arrives (a file, not a request body), how the caller is
authenticated (the runner, not an HMAC), and where the result is reported (the
run summary and the issue thread, not a log aggregator alone).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

import httpx

from config import CoreSettings, get_core_settings
from observability import configure_logging, log, write_job_output, write_step_summary
from services import (
    DevinClient,
    TriageCategory,
    TriageDecision,
    build_devin_payload,
    evaluate_payload,
)

GITHUB_API_BASE = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def _load_event() -> tuple[str | None, dict[str, Any]]:
    """Read the triggering event from the runner.

    GitHub writes the exact webhook payload to `$GITHUB_EVENT_PATH` and names it
    in `$GITHUB_EVENT_NAME`. It is byte-identical to what the webhook endpoint
    would have received, which is precisely why the governance filter can be
    reused unchanged.
    """
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        raise RuntimeError("GITHUB_EVENT_PATH is not set; this must run inside GitHub Actions")
    with open(event_path, encoding="utf-8") as handle:
        return event_name, json.load(handle)


def _correlation_id() -> str:
    """Stable per-run id, playing the role X-GitHub-Delivery plays for webhooks.

    Includes the attempt number so a re-run is a distinct dispatch, while an
    unchanged run that is retried internally is not.
    """
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    return f"actions-{run_id}-{attempt}"


async def _comment_on_issue(
    http: httpx.AsyncClient,
    repository: str,
    issue_number: int,
    body: str,
) -> None:
    """Post the session link back onto the issue thread.

    WHY: the run summary proves it to whoever opens the Actions tab; the comment
    proves it to the maintainer who filed the issue and never leaves it. Best
    effort by design — a failure to comment must not mark a successful dispatch
    as failed.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return
    try:
        response = await http.post(
            f"{GITHUB_API_BASE}/repos/{repository}/issues/{issue_number}/comments",
            json={"body": body},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        log(
            logging.WARNING,
            "issue_comment_failed",
            delivery_id=_correlation_id(),
            repository=repository,
            issue_number=issue_number,
            error=type(exc).__name__,
        )


def _summary_row(label: str, value: Any) -> str:
    return f"| {label} | {value} |\n"


async def _run() -> int:
    settings: CoreSettings = get_core_settings()
    configure_logging(settings.log_level)

    delivery_id = _correlation_id()
    event_name, payload = _load_event()

    # GOVERNANCE — identical rules to the webhook path, imported not copied.
    decision: TriageDecision = evaluate_payload(
        event=event_name,
        payload=payload,
        allowed_repositories=settings.allowed_repositories,
        allowed_issue_labels=settings.allowed_issue_labels,
    )

    if not decision.accepted:
        log(
            logging.INFO,
            "event_dropped",
            delivery_id=delivery_id,
            event=event_name,
            action=payload.get("action"),
            repository=decision.repository,
            reason=decision.reason,
        )
        write_step_summary(
            "### Devin Gatekeeper — dropped\n\n"
            "| field | value |\n| --- | --- |\n"
            + _summary_row("event", event_name)
            + _summary_row("repository", decision.repository)
            + _summary_row("reason", f"`{decision.reason}`")
            + "\nNo Devin session was created, so no spend was incurred.\n"
        )
        write_job_output("decision", "dropped")
        write_job_output("reason", decision.reason)
        # Exit 0: a dropped event is a correct outcome, not a build failure.
        return 0

    # TRANSLATION — same anti-corruption layer as the service.
    assert decision.category is not None  # guaranteed by evaluate_payload
    playbook_ids = {
        TriageCategory.CI_FAILURE: settings.playbook_id_ci_failure,
        TriageCategory.ISSUE_TRIAGE: settings.playbook_id_issue_triage,
        TriageCategory.SECURITY: settings.playbook_id_security,
    }
    knowledge_ids = (
        [settings.knowledge_id_repo_context] if settings.knowledge_id_repo_context else []
    )
    devin_payload = build_devin_payload(
        decision=decision,
        playbook_ids=playbook_ids,
        knowledge_ids=knowledge_ids,
        delivery_id=delivery_id,
    )

    log(
        logging.INFO,
        "event_accepted",
        delivery_id=delivery_id,
        event=event_name,
        action=payload.get("action"),
        repository=decision.repository,
        category=decision.category.value,
        reason=decision.reason,
        playbook_id=devin_payload.get("playbook_id"),
        knowledge_ids=devin_payload.get("knowledge_ids"),
    )

    # DISPATCH — synchronous here, unlike the webhook path. WHY the difference:
    # the webhook must answer GitHub within ~10s or be retried, so it defers the
    # call to a background task. A job has no such deadline, and waiting lets us
    # report the real session id on the run page instead of "queued".
    timeout = httpx.Timeout(settings.devin_request_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout) as http:
        devin = DevinClient(
            http_client=http,
            api_key=settings.devin_api_key,
            base_url=settings.devin_api_base_url,
            org_id=settings.devin_org_id,
        )
        try:
            result = await devin.create_session(devin_payload)
        except httpx.HTTPStatusError as exc:
            log(
                logging.ERROR,
                "devin_dispatch_failed",
                delivery_id=delivery_id,
                category=decision.category.value,
                status_code=exc.response.status_code,
                response_body=exc.response.text[:500],
            )
            write_step_summary(
                f"### Devin Gatekeeper — dispatch failed\n\n"
                f"HTTP {exc.response.status_code} from the Devin API "
                f"(correlation `{delivery_id}`).\n"
            )
            # Exit non-zero: unlike a drop, this is a real failure and should
            # turn the job red so it is noticed.
            return 1
        except httpx.HTTPError as exc:
            log(
                logging.ERROR,
                "devin_dispatch_failed",
                delivery_id=delivery_id,
                category=decision.category.value,
                error=type(exc).__name__,
                detail=str(exc),
            )
            write_step_summary(
                f"### Devin Gatekeeper — dispatch failed\n\n"
                f"`{type(exc).__name__}` calling the Devin API "
                f"(correlation `{delivery_id}`).\n"
            )
            return 1

        session_id = result.get("session_id", "")
        session_url = result.get("url", "")
        log(
            logging.INFO,
            "devin_dispatch_succeeded",
            delivery_id=delivery_id,
            category=decision.category.value,
            session_id=session_id,
            session_url=session_url,
        )

        write_step_summary(
            "### Devin Gatekeeper — session dispatched\n\n"
            "| field | value |\n| --- | --- |\n"
            + _summary_row("event", event_name)
            + _summary_row("repository", decision.repository)
            + _summary_row("category", f"`{decision.category.value}`")
            + _summary_row("playbook", f"`{devin_payload.get('playbook_id') or 'none'}`")
            + _summary_row("session", f"[{session_id}]({session_url})" if session_url else session_id)
            + _summary_row("correlation", f"`{delivery_id}`")
        )
        write_job_output("decision", "accepted")
        write_job_output("category", decision.category.value)
        write_job_output("session_id", session_id)
        write_job_output("session_url", session_url)

        issue_number = decision.context.get("issue_number")
        if isinstance(issue_number, int) and decision.repository:
            await _comment_on_issue(
                http,
                repository=decision.repository,
                issue_number=issue_number,
                body=(
                    f"Devin session dispatched by the gatekeeper "
                    f"(`{decision.category.value}`, correlation `{delivery_id}`).\n\n"
                    f"Session: {session_url or session_id}"
                ),
            )

    return 0


def main() -> None:
    sys.exit(asyncio.run(_run()))


if __name__ == "__main__":
    main()
