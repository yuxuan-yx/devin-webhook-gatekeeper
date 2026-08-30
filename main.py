"""FastAPI application wiring for the GitHub -> Devin gatekeeper.

Responsibility split: this module only wires. It owns the HTTP surface, the
application lifespan (and therefore the shared httpx client), logging, and the
ordering of the security/governance/translation steps. All of the actual logic
lives in services.py.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from config import Settings, get_settings
from ledger import DeliveryRecord, Ledger
from observability import configure_logging
from observability import log as _log
from services import (
    DevinClient,
    TriageCategory,
    TriageDecision,
    build_devin_payload,
    evaluate_payload,
    evaluate_scan_payload,
    verify_signature,
)

# One ledger per process, holding the delivery lifecycle and the spend counters
# that /stats, /deliveries/{id} and the daily cap all read. Module-level rather
# than app.state so background tasks can record an outcome without carrying a
# reference to the app through every call.
ledger = Ledger()


# ---------------------------------------------------------------------------
# LIFESPAN
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create one httpx.AsyncClient for the whole application.

    WHY app-scoped: an AsyncClient owns a connection pool. Constructing one per
    request throws away keep-alive connections, pays a fresh TLS handshake on
    every dispatch, and — because the client would be garbage collected while a
    background task still holds it — risks 'client has been closed' errors. One
    client, created at startup and closed at shutdown, is both faster and
    correct.
    """
    settings = get_settings()
    configure_logging(settings.log_level)

    timeout = httpx.Timeout(settings.devin_request_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout) as client:
        app.state.http_client = client
        app.state.devin_client = DevinClient(
            http_client=client,
            api_key=settings.devin_api_key,
            base_url=settings.devin_api_base_url,
            org_id=settings.devin_org_id,
        )
        _log(logging.INFO, "gatekeeper_started", delivery_id=None, log_level=settings.log_level)
        yield
    _log(logging.INFO, "gatekeeper_stopped", delivery_id=None)


app = FastAPI(
    title="FastAPI Gatekeeper",
    description="Verifies GitHub webhooks and dispatches Devin sessions for autonomous triage.",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# BACKGROUND DISPATCH
# ---------------------------------------------------------------------------
async def dispatch_to_devin(
    devin_client: DevinClient,
    devin_payload: dict[str, Any],
    delivery_id: str,
    category: TriageCategory,
) -> None:
    """Call the Devin API outside the request/response cycle.

    WHY a background task: GitHub gives a webhook roughly 10 seconds before it
    considers the delivery failed and retries. Session creation is a network
    call to a third party with no such guarantee. Acknowledging first and
    dispatching after decouples our latency SLA from theirs, and prevents
    duplicate deliveries (and therefore duplicate sessions) caused by our own
    slowness.

    The trade-off, stated explicitly: a crash between the 202 and the API call
    loses the event. That is acceptable here because every trigger is
    reconstructible from GitHub state, and the alternative (durable queue) is
    not justified at this volume.
    """
    try:
        result = await devin_client.create_session(devin_payload)
        ledger.dispatch_succeeded(delivery_id, result.get("session_id"), result.get("url"))
        _log(
            logging.INFO,
            "devin_dispatch_succeeded",
            delivery_id=delivery_id,
            category=category.value,
            session_id=result.get("session_id"),
            session_url=result.get("url"),
        )
    except httpx.HTTPStatusError as exc:
        ledger.dispatch_failed(delivery_id, f"http_{exc.response.status_code}")
        # Log the status and a truncated body: enough to distinguish auth
        # failures from validation errors without dumping a large response.
        _log(
            logging.ERROR,
            "devin_dispatch_failed",
            delivery_id=delivery_id,
            category=category.value,
            status_code=exc.response.status_code,
            response_body=exc.response.text[:500],
        )
    except httpx.HTTPError as exc:
        ledger.dispatch_failed(delivery_id, type(exc).__name__)
        _log(
            logging.ERROR,
            "devin_dispatch_failed",
            delivery_id=delivery_id,
            category=category.value,
            error=type(exc).__name__,
            detail=str(exc),
        )


def _apply_budget(decision: TriageDecision, settings: Settings) -> TriageDecision:
    """Convert an acceptance into a drop once the daily session cap is reached.

    Expressed as a decision rewrite rather than an exception so the cap shows up
    in exactly the same place as every other policy outcome: one reason code, on
    the same log line and the same counter an operator is already watching.
    """
    if not decision.accepted:
        return decision
    if ledger.sessions_today() < settings.max_daily_sessions:
        ledger.reserve_session()
        return decision
    return TriageDecision(
        accepted=False,
        reason="daily_cap_exceeded",
        repository=decision.repository,
    )


def _extract_source_url(decision: TriageDecision) -> str | None:
    """Return the human-facing GitHub URL for an accepted event.

    The ledger stores this so the dashboard can link a delivery directly back
    to the issue or failed run that triggered it, without needing to keep the
    raw webhook payload.
    """
    context = decision.context or {}
    return context.get("issue_url") or context.get("run_url") or None


def _handle_decision(
    decision: TriageDecision,
    delivery_id: str,
    settings: Settings,
    request: Request,
    background_tasks: BackgroundTasks,
    event: str | None,
) -> Response:
    """Shared tail of every ingress: record, translate, dispatch, answer.

    WHY shared: the value of a control plane is that a GitHub event and a
    scanner finding are governed, budgeted, logged and audited identically. If
    each ingress owned its own copy of this, they would diverge, and the
    guarantee the whole design sells would quietly stop being true.
    """
    decision = _apply_budget(decision, settings)
    ledger.decided(
        delivery_id,
        accepted=decision.accepted,
        reason=decision.reason,
        category=decision.category.value if decision.category else None,
        repository=decision.repository,
        source_url=_extract_source_url(decision),
    )

    if not decision.accepted:
        # 200, not an error: the delivery was handled correctly, we simply chose
        # not to act. Returning a 4xx/5xx here would make the sender retry and
        # would pollute the webhook's delivery health in its UI.
        _log(
            logging.INFO,
            "event_dropped",
            delivery_id=delivery_id,
            event=event,
            repository=decision.repository,
            reason=decision.reason,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "dropped", "reason": decision.reason},
        )

    assert decision.category is not None  # guaranteed by the evaluators

    playbook_ids = {
        TriageCategory.CI_FAILURE: settings.playbook_id_ci_failure,
        TriageCategory.ISSUE_TRIAGE: settings.playbook_id_issue_triage,
        TriageCategory.SECURITY: settings.playbook_id_security,
        # Scanner findings are remediated under the security playbook: the
        # inbound shape differs, the standard operating procedure does not.
        TriageCategory.VULN_SCAN: settings.playbook_id_security,
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

    _log(
        logging.INFO,
        "event_accepted",
        delivery_id=delivery_id,
        event=event,
        repository=decision.repository,
        category=decision.category.value,
        reason=decision.reason,
        playbook_id=devin_payload.get("playbook_id"),
        knowledge_ids=devin_payload.get("knowledge_ids"),
    )

    background_tasks.add_task(
        dispatch_to_devin,
        devin_client=request.app.state.devin_client,
        devin_payload=devin_payload,
        delivery_id=delivery_id,
        category=decision.category,
    )

    # 202, not 200: we have accepted responsibility for the event but the work
    # has not happened yet. The status code should not claim otherwise.
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "category": decision.category.value,
            "delivery_id": delivery_id,
        },
    )


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------
@app.get("/healthz", status_code=status.HTTP_200_OK)
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe.

    Intentionally does not touch the Devin API: a health check that depends on a
    third party will mark us unhealthy (and get us restarted or rotated out of
    the load balancer) during someone else's outage, exactly when we would still
    be able to accept and drop the majority of traffic correctly.
    """
    return {"status": "ok"}


@app.get("/deliveries", response_model=list[dict[str, Any]])
async def deliveries() -> list[dict[str, Any]]:
    """Most recent deliveries for the dashboard.

    Kept separate from the JSON log trail so the UI can poll without accessing
    logs, and to make the audit surface small enough to reason about: read the
    ledger, read one delivery, write nothing.
    """
    return [record.model_dump() for record in ledger.list_all()]


# Static dashboard files live in `dashboard/`. Mounting at `/dashboard` lets the
# SPA read from `/stats`, `/deliveries` and `/deliveries/{id}` on the same origin.
app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")


@app.get("/", include_in_schema=False)
async def root() -> Response:
    """Redirect browsers to the dashboard instead of a 404."""
    return Response(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/dashboard/index.html"})


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
) -> Response:
    """Single ingress for GitHub webhooks.

    Strict ordering, and the order is the security property:
      1. read the raw body
      2. verify the HMAC over those exact bytes -> 401 if it fails
      3. only then parse JSON
      4. apply the default-deny governance filter
      5. translate and hand off to a background task, answering 202 immediately
    """
    delivery_id = x_github_delivery or "unknown"
    settings: Settings = get_settings()
    ledger.received(delivery_id, source="github", event=x_github_event)

    # 1. Raw bytes. Nothing may consume or transform the body before this point.
    raw_body = await request.body()

    # 2. Authenticate before parsing. Unverified bytes are never fed to a parser
    #    or to any business logic — an unauthenticated caller should not be able
    #    to reach anything more complex than a byte comparison.
    if not verify_signature(raw_body, x_hub_signature_256, settings.github_webhook_secret):
        ledger.verified(delivery_id, ok=False)
        _log(
            logging.WARNING,
            "signature_invalid",
            delivery_id=delivery_id,
            event=x_github_event,
            has_signature_header=x_hub_signature_256 is not None,
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "invalid signature"},
        )
    ledger.verified(delivery_id, ok=True)

    # 3. Parse. A malformed body from an authenticated sender is a 400, not a
    #    500: retrying it would never succeed.
    try:
        payload: dict[str, Any] = json.loads(raw_body)
    except json.JSONDecodeError:
        _log(logging.WARNING, "payload_unparseable", delivery_id=delivery_id, event=x_github_event)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "malformed json"},
        )

    # 4./5. Governance, then the shared translate-and-dispatch tail.
    decision: TriageDecision = evaluate_payload(
        event=x_github_event,
        payload=payload,
        allowed_repositories=settings.allowed_repositories,
        allowed_issue_labels=settings.allowed_issue_labels,
    )
    return _handle_decision(
        decision=decision,
        delivery_id=delivery_id,
        settings=settings,
        request=request,
        background_tasks=background_tasks,
        event=x_github_event,
    )


@app.post("/events/scan")
async def scan_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None),
    x_delivery_id: str | None = Header(default=None),
) -> Response:
    """Ingress for scanner findings — Snyk, Dependabot, a nightly audit job.

    WHY a second ingress and not a second deployment: remediation events do not
    only come from GitHub, but the policy, the budget and the audit trail must
    still be singular. This endpoint differs from the GitHub one only in the
    secret it verifies against and the evaluator it calls; everything after the
    decision is the same code path, which is what makes "point your events here"
    a credible offer to another team.

    The expected body is the normalised shape, not a vendor schema:

        {"repository": "apache/superset", "severity": "critical",
         "id": "SNYK-PYTHON-...", "package": "flask", "scanner": "snyk"}
    """
    delivery_id = x_delivery_id or uuid.uuid4().hex
    settings: Settings = get_settings()
    ledger.received(delivery_id, source="scan", event="scan_finding")

    raw_body = await request.body()
    if not verify_signature(raw_body, x_hub_signature_256, settings.effective_scan_secret):
        ledger.verified(delivery_id, ok=False)
        _log(
            logging.WARNING,
            "signature_invalid",
            delivery_id=delivery_id,
            event="scan_finding",
            has_signature_header=x_hub_signature_256 is not None,
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "invalid signature"},
        )
    ledger.verified(delivery_id, ok=True)

    try:
        payload: dict[str, Any] = json.loads(raw_body)
    except json.JSONDecodeError:
        _log(logging.WARNING, "payload_unparseable", delivery_id=delivery_id, event="scan_finding")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "malformed json"},
        )

    decision = evaluate_scan_payload(
        payload=payload,
        allowed_repositories=settings.allowed_repositories,
    )
    return _handle_decision(
        decision=decision,
        delivery_id=delivery_id,
        settings=settings,
        request=request,
        background_tasks=background_tasks,
        event="scan_finding",
    )


@app.get("/stats")
async def stats() -> dict[str, Any]:
    """Aggregate answer to "how would I know this is working?".

    Counters are keyed by decision reason rather than by a coarse
    accepted/dropped split, because the useful questions are diagnostic: is the
    filter dropping everything for one bad allowlist entry, is a scanner
    flooding us below the severity threshold, are dispatches failing on auth?
    Each of those is a distinct key here and needs no log search.
    """
    settings = get_settings()
    snapshot = ledger.stats()
    snapshot["budget"] = {
        "max_daily_sessions": settings.max_daily_sessions,
        "sessions_today": snapshot["sessions_today"],
        "remaining": max(0, settings.max_daily_sessions - snapshot["sessions_today"]),
    }
    return snapshot


@app.get("/deliveries/{delivery_id}")
async def delivery(delivery_id: str) -> Response:
    """Full lifecycle of one delivery: received -> verified -> decided -> dispatched.

    This is the audit artefact. Given a delivery id from a sender's UI, it
    answers what we did with that event and which Devin session — if any — it
    became, without granting access to logs.
    """
    record: DeliveryRecord | None = ledger.get(delivery_id)
    if record is None:
        # Bounded retention is a documented property, not a failure: say so
        # rather than implying the delivery never happened.
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "unknown or expired delivery id"},
        )
    return JSONResponse(status_code=status.HTTP_200_OK, content=record.model_dump())


def _category_hours_estimate(category: str | None, settings: Settings) -> float:
    """Conservative human-hours estimate for a category."""
    return {
        "ci_failure": settings.human_hours_ci_failure,
        "issue_triage": settings.human_hours_issue_triage,
        "security": settings.human_hours_security,
        "vuln_scan": settings.human_hours_vuln_scan,
    }.get(category or "", 0.0)


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


@app.get("/metrics")
async def metrics() -> dict[str, Any]:
    """Executive ROI view: throughput, lead time, hours invested, hours saved.

    WHY computed server-side: the estimates are configurable policy and the
    timestamps live in the ledger; the dashboard should not reimplement the math.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    accepted = [r for r in ledger.list_all(limit=500) if r.decision == "accepted"]

    total_human_hours = 0.0
    devin_hours = 0.0
    resolved = 0
    in_flight = 0
    lead_times_seconds: list[float] = []

    for record in accepted:
        estimate = _category_hours_estimate(record.category, settings)
        total_human_hours += estimate

        received = _parse_iso(record.received_at)
        dispatched = next((s["at"] for s in record.stages if s["stage"] == "dispatched"), None)
        dispatched_dt = _parse_iso(dispatched)
        resolved_dt = _parse_iso(record.resolved_at)

        if dispatched_dt and received:
            lead_times_seconds.append((dispatched_dt - received).total_seconds())

        if record.pull_request_url or record.status in ("completed", "done"):
            resolved += 1
            end = resolved_dt or now
            start = dispatched_dt or received or now
            devin_hours += max(0.0, (end - start).total_seconds()) / 3600.0
        elif record.status in ("failed",):
            # Failed sessions still consume wall-clock time; do not claim savings.
            end = resolved_dt or now
            start = dispatched_dt or received or now
            devin_hours += max(0.0, (end - start).total_seconds()) / 3600.0
        else:
            in_flight += 1

    avg_lead_seconds = sum(lead_times_seconds) / len(lead_times_seconds) if lead_times_seconds else 0.0
    hours_saved = max(0.0, total_human_hours - devin_hours)

    return {
        "sessions_total": len(accepted),
        "sessions_resolved": resolved,
        "sessions_in_flight": in_flight,
        "sessions_failed": sum(1 for r in accepted if r.status == "failed"),
        "avg_lead_time_seconds": round(avg_lead_seconds, 2),
        "avg_lead_time_ms": round(avg_lead_seconds * 1000, 1),
        "total_human_hours_estimated": round(total_human_hours, 2),
        "total_devin_hours": round(devin_hours, 2),
        "total_hours_saved": round(hours_saved, 2),
        "roi_multiplier": round(total_human_hours / max(devin_hours, 0.01), 2),
        "category_estimates": {
            "ci_failure": settings.human_hours_ci_failure,
            "issue_triage": settings.human_hours_issue_triage,
            "security": settings.human_hours_security,
            "vuln_scan": settings.human_hours_vuln_scan,
        },
    }


@app.post("/deliveries/{delivery_id}/refresh")
async def refresh_delivery(delivery_id: str, request: Request) -> Response:
    """Poll the Devin sessions API for this delivery and update the ledger.

    WHY explicit refresh rather than automatic polling: webhooks are
    asynchronous, but we do not want the gatekeeper to busy-loop against the
    Devin API. The dashboard can trigger a refresh when a user expands a row
    or on a slow timer, keeping the audit trail fresh without background load.
    """
    record = ledger.get(delivery_id)
    if record is None:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": "unknown delivery"})
    if not record.session_id:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": "delivery has no session"})

    devin_client: DevinClient = request.app.state.devin_client
    try:
        session = await devin_client.get_session(record.session_id)
    except httpx.HTTPStatusError as exc:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"detail": f"devin api error {exc.response.status_code}"},
        )
    except httpx.HTTPError as exc:
        return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content={"detail": str(exc)})

    session_status = session.get("status") or session.get("state")
    pull_requests = session.get("pull_requests") or session.get("pull_request") or []
    pr_url: str | None = None
    if isinstance(pull_requests, list) and pull_requests:
        first = pull_requests[0]
        pr_url = first if isinstance(first, str) else (first.get("url") or first.get("html_url"))
    elif isinstance(pull_requests, dict):
        pr_url = pull_requests.get("url") or pull_requests.get("html_url")

    resolved_at: str | None = None
    if session_status in ("completed", "done", "stopped", "failed"):
        # Mark resolved at the moment we observe a terminal state.
        resolved_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    ledger.update_session(
        delivery_id,
        status=session_status,
        pull_request_url=pr_url,
        resolved_at=resolved_at,
    )
    return JSONResponse(status_code=status.HTTP_200_OK, content=record.model_dump())
