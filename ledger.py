"""Delivery ledger: the audit trail and the spend counter.

WHY this exists at all:
A workflow run ends when the job ends, but a Devin session lives for minutes or
hours afterwards. Something has to be able to answer, after the fact, "what did
we receive, what did we decide, and what did that decision cost?" The ledger is
that something — one place holding the lifecycle of every delivery, which is
what both the audit story (/deliveries/{id}) and the leadership story (/stats)
read from.

WHY in memory:
The ledger is deliberately a bounded ring buffer plus counters, not a database.
At webhook volume the interesting window is hours, the container is the unit of
deployment, and adding Postgres would mean operating a store, running
migrations, and reconciling two sources of truth against the Devin sessions API
— which already holds the durable record of every session. Losing the last few
hundred deliveries on restart costs an audit convenience, not correctness. The
interface below is narrow on purpose: swapping the implementation for Redis is a
constructor change, not a refactor.
"""

from __future__ import annotations

import threading
from collections import Counter, OrderedDict
from datetime import date, datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class DeliveryRecord(BaseModel):
    """Everything known about one inbound delivery, in the order it happened."""

    delivery_id: str
    source: str
    received_at: str
    event: str | None = None
    repository: str | None = None
    verified: bool = False
    decision: str | None = None
    reason: str | None = None
    category: str | None = None
    session_id: str | None = None
    session_url: str | None = None
    error: str | None = None
    # WHY a stage list rather than a single status field: the question an
    # auditor asks is "how far did this get, and when", which a terminal status
    # cannot answer. received -> verified -> decided -> dispatched is exactly
    # the sequence of trust boundaries the event crossed.
    stages: list[dict[str, str]] = Field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Ledger:
    """Bounded, thread-safe record of deliveries plus aggregate counters.

    Thread-safe rather than asyncio-only because FastAPI runs sync dependencies
    on a threadpool, and a counter that is only correct under one concurrency
    model is a latent bug rather than a simplification.
    """

    def __init__(self, max_records: int = 500) -> None:
        self._max_records = max_records
        self._records: OrderedDict[str, DeliveryRecord] = OrderedDict()
        self._counters: Counter[str] = Counter()
        # Sessions are counted per UTC day so the budget cap resets on a
        # boundary an operator can reason about, independent of deploy time.
        self._session_day: date = datetime.now(timezone.utc).date()
        self._sessions_today = 0
        self._lock = threading.Lock()

    # --- writes ----------------------------------------------------------
    def received(self, delivery_id: str, source: str, event: str | None) -> None:
        with self._lock:
            record = DeliveryRecord(
                delivery_id=delivery_id,
                source=source,
                event=event,
                received_at=_now(),
            )
            record.stages.append({"stage": "received", "at": record.received_at})
            self._records[delivery_id] = record
            self._records.move_to_end(delivery_id)
            while len(self._records) > self._max_records:
                self._records.popitem(last=False)
            self._counters["received"] += 1

    def verified(self, delivery_id: str, ok: bool) -> None:
        with self._lock:
            self._counters["signature_valid" if ok else "signature_invalid"] += 1
            record = self._records.get(delivery_id)
            if record is None:
                return
            record.verified = ok
            record.stages.append(
                {"stage": "verified" if ok else "signature_rejected", "at": _now()}
            )

    def decided(
        self,
        delivery_id: str,
        accepted: bool,
        reason: str,
        category: str | None,
        repository: str | None,
    ) -> None:
        with self._lock:
            # Reason-coded counters are the point: "dropped" alone cannot tell an
            # operator whether the filter is tuned correctly or silently
            # discarding everything because of one wrong allowlist entry.
            self._counters["accepted" if accepted else f"dropped:{reason}"] += 1
            record = self._records.get(delivery_id)
            if record is None:
                return
            record.decision = "accepted" if accepted else "dropped"
            record.reason = reason
            record.category = category
            record.repository = repository
            record.stages.append({"stage": "decided", "at": _now()})

    def reserve_session(self) -> None:
        """Count a session against today's budget at decision time.

        WHY at decision rather than on a successful dispatch: dispatch happens in
        a background task, so a burst of events would all pass a cap that is only
        incremented after the API returns, and the cap would be exceeded by
        however many requests are in flight. Reserving when we decide makes the
        budget a real bound; `dispatch_failed` returns the reservation so a
        failing Devin API cannot silently consume the day's quota.
        """
        with self._lock:
            self._roll_day_locked()
            self._sessions_today += 1

    def dispatch_succeeded(
        self, delivery_id: str, session_id: str | None, session_url: str | None
    ) -> None:
        with self._lock:
            self._counters["dispatch_succeeded"] += 1
            record = self._records.get(delivery_id)
            if record is None:
                return
            record.session_id = session_id
            record.session_url = session_url
            record.stages.append({"stage": "dispatched", "at": _now()})

    def dispatch_failed(self, delivery_id: str, error: str) -> None:
        with self._lock:
            self._counters["dispatch_failed"] += 1
            self._sessions_today = max(0, self._sessions_today - 1)
            record = self._records.get(delivery_id)
            if record is None:
                return
            record.error = error
            record.stages.append({"stage": "dispatch_failed", "at": _now()})

    # --- reads -----------------------------------------------------------
    def sessions_today(self) -> int:
        """Sessions dispatched in the current UTC day — the budget numerator."""
        with self._lock:
            self._roll_day_locked()
            return self._sessions_today

    def get(self, delivery_id: str) -> DeliveryRecord | None:
        with self._lock:
            return self._records.get(delivery_id)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            self._roll_day_locked()
            counters = dict(self._counters)
            return {
                "counters": counters,
                "sessions_today": self._sessions_today,
                "deliveries_retained": len(self._records),
                "dropped_total": sum(v for k, v in counters.items() if k.startswith("dropped:")),
            }

    # --- internals -------------------------------------------------------
    def _roll_day_locked(self) -> None:
        today = datetime.now(timezone.utc).date()
        if today != self._session_day:
            self._session_day = today
            self._sessions_today = 0
