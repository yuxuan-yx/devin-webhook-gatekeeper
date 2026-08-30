# Devin Gatekeeper

Event-driven, governed automation that turns GitHub events into autonomous Devin
sessions — and produces a pull request, an audit trail, and a metric.

```
GitHub event ─▶ Gatekeeper ─▶ Devin cloud sandbox ─▶ PR + audit trail
               verify · govern · translate      clone → reproduce → fix → test
```

The gatekeeper is the thin, boring, auditable layer that a platform team owns.
It answers three questions on every event, in this order:

| step | question | where |
| --- | --- | --- |
| **Verify** | is this event authentic? | `services.verify_signature` — HMAC-SHA256 over raw bytes, constant time, checked *before* the JSON is parsed |
| **Govern** | should we spend a session on it? | `services.evaluate_payload` — default-deny: repo allowlist, then a closed set of trigger rules |
| **Translate** | what exactly do we ask Devin? | `services.build_devin_payload` — category → playbook, repo knowledge injected, prompt built from identifiers only |

## Two trigger paths, one policy

The same three functions run under two topologies. Pick per environment; they
cannot disagree, because the CI path imports the service's logic rather than
copying it.

| | **A. GitHub Actions** (`dispatch.py`) | **B. Webhook service** (`main.py`) |
| --- | --- | --- |
| Trigger | workflow on `issues`/`workflow_run` in the target repo | GitHub webhook → FastAPI |
| Ingress | none — runs inside GitHub | public HTTPS endpoint required |
| Auth | the runner (secrets scoped to the repo) | HMAC signature verification |
| Dispatch | synchronous, so the run page shows the real session id | `BackgroundTasks`, 202 in milliseconds (GitHub retries after ~10s) |
| Best for | fastest adoption, per-repo opt-in | many repos behind one governed choke point |

## Quick start

### A. GitHub Actions (no deployment needed)

In the repository you want triaged (e.g. your fork of `apache/superset`):

1. Add repo secret `DEVIN_API_KEY` (a service-user API key or PAT, prefix
   `cog_`) and repo variable `DEVIN_ORG_ID` (prefix `org-`, from Settings →
   Devin API); optionally repo variables `PLAYBOOK_ID_*` /
   `KNOWLEDGE_ID_REPO_CONTEXT`.
2. Copy [`examples/superset-fork/devin-triage.yml`](examples/superset-fork/devin-triage.yml)
   to `.github/workflows/devin-triage.yml`.
3. Label an issue `needs-devin-triage` or `security-cve`, or let CI fail.

The run summary shows the decision, the playbook used, and a link to the Devin
session; the session link is also posted back as an issue comment.

### B. Webhook service

```bash
cp .env.example .env          # fill GITHUB_WEBHOOK_SECRET, DEVIN_API_KEY, DEVIN_ORG_ID
docker compose up --build     # http://localhost:8000/healthz
```

Point a GitHub webhook at `https://<host>/webhook/github`, content type
`application/json`, same secret. For local testing, expose it with
`ngrok http 8000` or `cloudflared tunnel --url http://localhost:8000`.

## Simulate the workflow (no GitHub, no Devin account)

```bash
# 1. the service path: signed accept / drop / forged-signature cases
python simulate.py --secret "$GITHUB_WEBHOOK_SECRET"

# 2. the Actions path: replay a saved event exactly as a runner would
GITHUB_EVENT_NAME=issues \
GITHUB_EVENT_PATH=examples/events/issue_labeled_security.json \
DEVIN_API_KEY=... DEVIN_ORG_ID=org-... python dispatch.py

# 3. the policy layer, in isolation
pip install pytest && python -m pytest tests -q
```

`simulate.py` ends on the negative case: a payload that is valid in every
respect except its signature must come back `401`.

## Observability — "how would I know this is working?"

Three levels, from operator to executive:

- **Structured JSON logs** on every path (`signature_invalid`, `event_dropped`,
  `event_accepted`, `devin_dispatch_succeeded`, `devin_dispatch_failed`), each
  carrying a correlation id — the `X-GitHub-Delivery` header for webhooks, the
  run id for Actions — and the Devin `session_id` on success.
- **Per-run summaries.** Every Actions dispatch renders a table on the run page:
  event, repository, category, playbook, session link.
- **Fleet report** (`report.py`, scheduled in
  [`.github/workflows/fleet-report.yml`](.github/workflows/fleet-report.yml)):
  sessions dispatched, in flight, and the share that produced a pull request,
  broken down by trigger category. Sessions are attributed via the
  `category:` / `github-delivery:` tags stamped at dispatch, so reporting needs
  no database of its own.

```
2 sessions dispatched · 1 in flight · 1 produced a pull request (50.0%)
```

## Design decisions worth defending

- **Verify before parse.** Unauthenticated bytes never reach a parser; an
  attacker's reachable surface is one constant-time byte comparison.
- **Default-deny governance.** Every accepted event costs money. Triggers are a
  closed set with a repository allowlist, so a new GitHub event type or a
  webhook pasted into the wrong repo can never cause spend. Dropped events
  return `200` with a reason code — dropping is a correct outcome, not an error,
  and returning `4xx` would make GitHub retry.
- **Identifiers, not prose, in prompts.** Issue titles and bodies are
  attacker-controlled. The prompt carries issue numbers and URLs; the agent
  fetches the untrusted text itself, where it is unambiguously data. Enforced by
  a test.
- **Category → playbook.** A CI failure and a CVE need different procedures.
  Routing to a category-specific playbook keeps prompts short and lets an SOP be
  tuned without redeploying this service.
- **Idempotency.** Retries are inevitable; every dispatch is tagged with its
  correlation id and marked idempotent so a redelivery cannot double-spend.
- **One app-scoped `httpx` client**, created in the FastAPI lifespan — not one
  per request, which would discard the connection pool and risk a closed client
  under a background task.
- **Single Uvicorn worker, scale with replicas.** One event loop, one connection
  pool, one predictable drain on restart.

## Layout

```
main.py            FastAPI wiring: routes, lifespan, ordering of the three steps
dispatch.py        GitHub Actions entrypoint (same policy, no ingress)
report.py          fleet analytics from the Devin sessions API
services.py        verify · govern · translate · DevinClient  (no framework imports)
config.py          CoreSettings (shared) + Settings (adds the webhook secret)
observability.py   JSON log formatter, run-summary and job-output helpers
action.yml         composite action published to adopting repositories
simulate.py        signed replay harness for demos and manual testing
tests/             policy tests: security, governance, translation
examples/          sample events + the workflow to drop into the target repo
docs/              executive pitch board
```

## Roadmap

1. **Now** — CI failure triage, labeled-issue triage, dependency/CVE remediation.
2. **Next** — incident-driven triggers from Datadog / PagerDuty; auto-labelling
   from scanner output so no human has to apply the label.
3. **Later** — scheduled maintenance fleets: nightly E2E on staging, feature-flag
   cleanup after release, mass migrations run as parallel sessions.
