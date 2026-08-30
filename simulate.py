"""Replay signed sample events against a running gatekeeper.

WHY this ships with the project: a webhook endpoint is awkward to demonstrate —
it needs a public URL and a real event to fire. This script signs the fixtures
in `examples/events/` with the same HMAC scheme GitHub uses and posts them to a
local instance, so the accept / drop / reject behaviour is reproducible offline
and in CI. It is a demo and test harness, never part of the serving path.

    python simulate.py --url http://localhost:8000 --secret "$GITHUB_WEBHOOK_SECRET"
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import pathlib
import uuid

import httpx

EVENTS_DIR = pathlib.Path(__file__).parent / "examples" / "events"

# (fixture, X-GitHub-Event, what a reviewer should see)
SCENARIOS: list[tuple[str, str, str]] = [
    ("workflow_run_failure.json", "workflow_run", "accepted -> 202, ci_failure"),
    ("issue_labeled_security.json", "issues", "accepted -> 202, security"),
    ("issue_labeled_ignored.json", "issues", "dropped -> 200, label not allowlisted"),
]


def sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--secret", required=True)
    args = parser.parse_args()

    endpoint = f"{args.url.rstrip('/')}/webhook/github"

    with httpx.Client(timeout=10.0) as client:
        health = client.get(f"{args.url.rstrip('/')}/healthz")
        print(f"healthz -> {health.status_code} {health.text}")

        for fixture, event, expectation in SCENARIOS:
            body = (EVENTS_DIR / fixture).read_bytes()
            response = client.post(
                endpoint,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": event,
                    "X-GitHub-Delivery": str(uuid.uuid4()),
                    "X-Hub-Signature-256": sign(args.secret, body),
                },
            )
            print(f"{fixture:<32} -> {response.status_code} {response.text}   ({expectation})")

        # Negative case last, so the demo ends on the security property: a
        # payload that is valid in every respect except its signature.
        body = (EVENTS_DIR / "issue_labeled_security.json").read_bytes()
        response = client.post(
            endpoint,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "issues",
                "X-GitHub-Delivery": str(uuid.uuid4()),
                "X-Hub-Signature-256": sign("wrong-secret", body),
            },
        )
        print(f"{'forged signature':<32} -> {response.status_code} {response.text}   (must be 401)")
        assert response.status_code == 401, "forged signature was not rejected"


if __name__ == "__main__":
    main()
