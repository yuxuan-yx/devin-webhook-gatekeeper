"""Application configuration.

WHY a dedicated settings module:
The gatekeeper is deployed as an immutable container image. Anything that can
differ between environments (secrets, API base URLs, governance policy) must
therefore come from the environment, never from the image. Centralising that in
one Pydantic Settings object gives us fail-fast validation at process start: if
a required secret is missing, the container dies immediately instead of
silently failing on the first webhook at 3am.

WHY two classes:
The service (main.py) and the offline fleet report (report.py) share every knob
that describes *policy* and *Devin*, but only the service verifies inbound
signatures. Modelling that as `CoreSettings` + a `Settings` subclass means a
read-only process cannot be forced to invent a fake webhook secret just to
boot, and neither can drift away from the shared governance defaults.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreSettings(BaseSettings):
    """Configuration shared by every process (the service and the fleet report)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # WHY: an unknown env var is almost always a typo in a deploy manifest.
        # We ignore rather than error because container platforms inject many
        # unrelated variables (HOSTNAME, PATH, KUBERNETES_*) into the process.
        extra="ignore",
    )

    # --- Secrets ---------------------------------------------------------
    # WHY no default: this is required. Pydantic raises at load time if it is
    # absent, which surfaces a misconfigured deploy during rollout (failing
    # readiness) instead of as a stream of 500s later.
    devin_api_key: str = Field(..., description="Bearer token for the Devin API.")

    # --- Devin API -------------------------------------------------------
    devin_api_base_url: str = Field(
        default="https://api.devin.ai/v3",
        description="Base URL of the Devin API. Overridable to point at a mock during testing.",
    )
    devin_org_id: str = Field(
        default="",
        description=(
            "Organization the sessions belong to (prefix: org-). Required by the v3 API, "
            "which scopes sessions under an org and is what service-user (cog_) tokens "
            "authenticate against. Leave empty only when pointing at the legacy v1 API "
            "with a legacy apk_ key."
        ),
    )
    devin_request_timeout_seconds: float = Field(
        default=10.0,
        description=(
            "Timeout for the outbound Devin call. WHY bounded: the dispatch runs in a "
            "background task; an unbounded request would pin a worker task forever if "
            "the upstream hangs."
        ),
    )

    # --- Translation layer -----------------------------------------------
    # WHY separate playbook IDs per category: a CI failure and a security CVE
    # require entirely different investigative procedures. Routing to a
    # category-specific playbook keeps prompts short and deterministic, and
    # lets the playbooks be tuned independently without redeploying this service.
    playbook_id_ci_failure: str = Field(
        default="",
        description="Playbook used for failed workflow_run events.",
    )
    playbook_id_issue_triage: str = Field(
        default="",
        description="Playbook used for issues labeled needs-devin-triage.",
    )
    playbook_id_security: str = Field(
        default="",
        description="Playbook used for issues labeled security-cve.",
    )
    knowledge_id_repo_context: str = Field(
        default="",
        description=(
            "Knowledge note carrying repo-specific context (build commands, layout). "
            "Injected on every dispatch so the session does not rediscover it each time."
        ),
    )

    # --- Governance ------------------------------------------------------
    # WHY an allowlist rather than a blocklist: this endpoint is public and
    # every accepted event costs money (an autonomous Devin session). A
    # default-deny posture means a misconfigured webhook on some other repo,
    # or a new GitHub event type, can never trigger spend.
    allowed_repositories: frozenset[str] = Field(
        default=frozenset({"apache/superset"}),
        description="full_name values (owner/repo) permitted to trigger a dispatch.",
    )
    allowed_issue_labels: frozenset[str] = Field(
        default=frozenset({"needs-devin-triage", "security-cve"}),
        description="Labels that opt an issue into autonomous triage.",
    )

    # --- Budget ----------------------------------------------------------
    # WHY a hard cap rather than an alert: an alert tells you afterwards that a
    # loop (a label toggled by another bot, a scanner replaying its backlog)
    # spent the quarter's budget overnight. A cap makes the failure mode
    # "nothing happened" instead of "everything happened", which is the only
    # acceptable default when the action is autonomous and billable.
    max_daily_sessions: int = Field(
        default=20,
        description=(
            "Sessions this instance may dispatch per UTC day. Beyond it, otherwise "
            "acceptable events are dropped with reason daily_cap_exceeded."
        ),
    )

    # --- Observability ---------------------------------------------------
    log_level: str = Field(default="INFO", description="Root log level for the JSON logger.")


class Settings(CoreSettings):
    """Configuration for the webhook service, which additionally holds a secret."""

    github_webhook_secret: str = Field(
        ...,
        description=(
            "Shared secret configured on the GitHub webhook; used for HMAC-SHA256 "
            "verification. Required only by the service, which is the only "
            "process that accepts inbound requests."
        ),
    )
    scan_webhook_secret: str = Field(
        default="",
        description=(
            "Shared secret for the scanner ingress (/events/scan). Separate from the "
            "GitHub secret so a compromised scanner integration cannot forge GitHub "
            "events; falls back to the GitHub secret when unset."
        ),
    )

    @property
    def effective_scan_secret(self) -> str:
        """Secret used to verify scanner deliveries."""
        return self.scan_webhook_secret or self.github_webhook_secret


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide Settings singleton (webhook service).

    WHY cached: Settings parses the environment and validates it. Doing that per
    request would be wasted work, and — more importantly — we want a single
    immutable view of configuration for the process lifetime so behaviour cannot
    drift mid-flight.
    """
    return Settings()


@lru_cache(maxsize=1)
def get_core_settings() -> CoreSettings:
    """Return the settings subset available to processes with no ingress."""
    return CoreSettings()
