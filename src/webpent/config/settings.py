# src/webpent/config/settings.py
"""webpent.config.settings

Global configuration for the WebPent Framework V2.

Loads environment variables via pydantic-settings and exposes a cached
``Settings`` singleton. All values have sensible defaults so the framework
can boot in development without an explicit ``.env`` file.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    """Supported LLM backend providers (legacy single-provider selector)."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    LOCAL = "local"


class LogLevel(str, Enum):
    """Standard Python logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ScanMode(str, Enum):
    """Runtime authority profile for autonomous behavior."""

    LEGACY = "legacy"
    SAFE_SMART = "safe-smart"
    AUTHORIZED_ACTIVE = "authorized-active"


class Settings(BaseSettings):
    """Framework-wide settings.

    All fields map 1:1 to environment variables (case-insensitive). Secret
    values (``*_API_KEY``) should be supplied via ``.env`` or the process
    environment — never committed to source control.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -- LLM API keys (legacy providers) ------------------------------------
    openai_api_key: str | None = Field(default=None, description="OpenAI API key.")
    anthropic_api_key: str | None = Field(default=None, description="Anthropic API key.")
    groq_api_key: str | None = Field(default=None, description="Groq API key.")
    local_llm_url: str = Field(
        default="http://localhost:11434/v1",
        description="Base URL for a local OpenAI-compatible LLM endpoint.",
    )
    local_llm_api_key: str | None = Field(
        default=None, description="Optional API key for the local LLM endpoint."
    )

    # -- LLM API keys (task-based router providers) -------------------------
    zai_api_key: str | None = Field(default=None, description="Z.AI API key.")
    openrouter_api_key: str | None = Field(default=None, description="OpenRouter API key.")
    cerebras_api_key: str | None = Field(default=None, description="Cerebras API key.")
    github_api_key: str | None = Field(default=None, description="GitHub Models API key.")
    mistral_api_key: str | None = Field(default=None, description="Mistral API key.")
    gemini_api_key: str | None = Field(default=None, description="Google Gemini API key.")
    cohere_api_key: str | None = Field(default=None, description="Cohere API key.")
    cloudflare_api_key: str | None = Field(
        default=None, description="Cloudflare Workers AI API key."
    )
    cloudflare_account_id: str | None = Field(
        default=None, description="Cloudflare account ID required for Workers AI routing."
    )

    # -- LLM selection / generation -----------------------------------------
    default_llm_provider: LLMProvider = Field(
        default=LLMProvider.ANTHROPIC,
        description="Default LLM provider used by legacy code paths.",
    )
    default_llm_model: str = Field(
        default="claude-3-5-sonnet-20241022",
        description="Default model identifier for the selected provider.",
    )
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    llm_max_tokens: int = Field(default=4096, gt=0)
    llm_request_timeout: int = Field(default=60, gt=0)
    llm_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("LLM_ENABLED", "WEBPENT_LLM_ENABLED"),
        description=(
            "Allow AI-assisted reasoning nodes to call configured providers. "
            "Set LLM_ENABLED=false (or WEBPENT_LLM_ENABLED=false) for "
            "deterministic offline runs; nodes then use bounded fallbacks."
        ),
    )

    # -- Framework behaviour -------------------------------------------------
    debug: bool = Field(default=False, description="Enable verbose debug logging.")
    scan_mode: ScanMode = Field(
        default=ScanMode.LEGACY,
        validation_alias=AliasChoices(
            "scan_mode",
            "SCAN_MODE",
            "WEBPENT_SCAN_MODE",
            "SCAN_PROFILE",
        ),
        description=(
            "Authority profile. legacy preserves the existing path; safe-smart is "
            "read-only and evidence-first; authorized-active permits only policy-checked "
            "active workflows."
        ),
    )
    smart_max_actions: int = Field(
        default=100,
        gt=0,
        le=10000,
        validation_alias=AliasChoices(
            "smart_max_actions", "SMART_MAX_ACTIONS", "WEBPENT_SMART_MAX_ACTIONS"
        ),
        description="Hard upper bound on autonomous actions in one engagement.",
    )
    smart_action_budget: float = Field(
        default=100.0,
        gt=0.0,
        le=100000.0,
        validation_alias=AliasChoices(
            "smart_action_budget", "SMART_ACTION_BUDGET", "WEBPENT_SMART_ACTION_BUDGET"
        ),
        description="Bounded cost budget for policy-authorized autonomous actions.",
    )
    smart_auto_approve: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "smart_auto_approve", "SMART_AUTO_APPROVE", "WEBPENT_SMART_AUTO_APPROVE"
        ),
        description="Explicit operator approval shortcut; never bypasses scope or risk gates.",
    )
    smart_require_idempotency: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "smart_require_idempotency",
            "SMART_REQUIRE_IDEMPOTENCY",
            "WEBPENT_SMART_REQUIRE_IDEMPOTENCY",
        ),
        description="Require an idempotency key for every policy-authorized action.",
    )
    smart_require_proof_bundle: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "smart_require_proof_bundle",
            "SMART_REQUIRE_PROOF_BUNDLE",
            "WEBPENT_SMART_REQUIRE_PROOF_BUNDLE",
        ),
        description=(
            "Require sealed replayable proof bundles for strict Tool-Confirmed exports."
        ),
    )
    smart_max_replan_rounds: int = Field(
        default=3,
        ge=0,
        le=10,
        validation_alias=AliasChoices(
            "smart_max_replan_rounds",
            "SMART_MAX_REPLAN_ROUNDS",
            "WEBPENT_SMART_MAX_REPLAN_ROUNDS",
        ),
        description="Bounded number of smart campaign replanning rounds per engagement.",
    )
    log_level: LogLevel = Field(default=LogLevel.INFO)
    max_graph_steps: int = Field(default=50, gt=0)

    # -- V55 additive architecture feature flags ----------------------------
    # These switches are intentionally disabled by default so the existing
    # linear scan graph remains the compatibility path until each capability
    # has its own contract tests and is explicitly enabled by the operator.
    enable_target_understanding: bool = Field(
        default=False,
        description=(
            "Enable evidence-backed target-understanding enrichment on top of "
            "the existing Mental Model."
        ),
    )
    enable_attack_graph: bool = Field(
        default=False,
        description=(
            "Enable the projected Attack Graph and relational path metadata "
            "without replacing the existing findings pipeline."
        ),
    )
    enable_adaptive_hunt: bool = Field(
        default=False,
        description=(
            "Enable bounded adaptive prioritization and targeted revisit tasks "
            "after the compatibility path is verified."
        ),
    )
    enable_workflow_understanding: bool = Field(
        default=False,
        description=(
            "Enable passive workflow extraction and bounded business-logic "
            "hypotheses without changing the legacy fuzzer path."
        ),
    )
    enable_planner_decisions: bool = Field(
        default=False,
        description=(
            "Enable advisory structured planner proposals. Proposals remain "
            "non-executable and must pass deterministic policy, scope, budget, "
            "and tool-availability gates."
        ),
    )
    max_planner_decision_cost: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Maximum estimated cost accepted for one planner proposal.",
    )
    enable_authorization_matrix: bool = Field(
        default=False,
        description=(
            "Enable bounded multi-identity authorization matrix observations. "
            "The matrix is read-only, redacted, and never auto-promotes findings."
        ),
    )
    max_authorization_matrix_rows: int = Field(default=500, gt=0, le=10000)
    max_authorization_matrix_comparisons: int = Field(default=1000, gt=0, le=20000)
    enable_idor_enumeration: bool = Field(
        default=False,
        description=(
            "Enable bounded numeric adjacent-ID enumeration for BAC candidates. "
            "Disabled by default; enumeration remains read-only and never confirms a finding."
        ),
    )
    idor_enumeration_neighbors: int = Field(default=2, ge=1, le=10)
    enable_js_intelligence: bool = Field(
        default=False,
        description=(
            "Enable bounded, static JavaScript source review. Results are "
            "redacted observations and non-destructive targeted mapping tasks."
        ),
    )
    max_js_assets: int = Field(default=50, gt=0, le=200)
    max_js_asset_bytes: int = Field(default=2_000_000, gt=0, le=20_000_000)
    max_js_routes: int = Field(default=1000, gt=0, le=5000)
    max_js_targeted_tasks: int = Field(default=1500, gt=0, le=5000)
    enable_report_quality_gate: bool = Field(
        default=False,
        description=(
            "Enable deterministic report contract validation. When enabled, "
            "strict report exporters reject findings missing evidence, "
            "reproduction, impact, or CVSS; legacy exports remain unchanged "
            "when disabled."
        ),
    )
    enable_bug_bounty_reporter: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_bug_bounty_reporter",
            "ENABLE_BUG_BOUNTY_REPORTER",
            "WEBPENT_ENABLE_BUG_BOUNTY_REPORTER",
        ),
        description=(
            "Use the concise bug-bounty report node in the graph. Disabled "
            "by default to preserve the enterprise report path."
        ),
    )
    enable_structure_aware_triage: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "enable_structure_aware_triage",
            "ENABLE_STRUCTURE_AWARE_TRIAGE",
            "WEBPENT_STRUCTURE_AWARE_TRIAGE",
        ),
        description=(
            "Enable passive structure-aware endpoint triage. The deterministic "
            "coverage queue is advisory and additive; it prevents URL-only "
            "ranking from hiding API, auth, upload, GraphQL, WebSocket, and "
            "state-changing surfaces without executing requests."
        ),
    )
    max_structure_aware_triage_endpoints: int = Field(
        default=25,
        gt=0,
        le=500,
        validation_alias=AliasChoices(
            "max_structure_aware_triage_endpoints",
            "MAX_STRUCTURE_AWARE_TRIAGE_ENDPOINTS",
            "WEBPENT_MAX_STRUCTURE_AWARE_TRIAGE_ENDPOINTS",
        ),
    )
    enable_surface_security_analysis: bool = Field(
        default=False,
        description=(
            "Enable bounded passive coverage analysis across web-security "
            "surfaces. It emits redacted observations and coverage gaps only; "
            "it never executes payloads or promotes findings."
        ),
    )
    max_surface_security_observations: int = Field(default=100, gt=0, le=500)

    # V55 Phase 12: separated memory boundaries and retrieval budgets.
    # Disabled by default so legacy RAG paths remain compatible until the
    # operator explicitly opts into the typed boundary.
    enable_memory_boundary: bool = Field(
        default=False,
        description=(
            "Enable the typed separation between target facts, security "
            "knowledge, and operator-reviewed experience lessons. Retrieval "
            "is advisory and cannot promote findings."
        ),
    )
    memory_max_records: int = Field(default=200, gt=0, le=5000)
    memory_max_retrievals: int = Field(default=50, ge=0, le=1000)
    memory_max_items_per_retrieval: int = Field(default=8, gt=0, le=50)
    memory_max_chars_per_retrieval: int = Field(default=6000, ge=100, le=50000)
    memory_max_content_chars: int = Field(default=8000, ge=100, le=20000)
    memory_max_feedback_records: int = Field(default=200, ge=0, le=5000)

    # -- HTTP / scanning defaults -------------------------------------------
    http_timeout: int = Field(default=30, gt=0)
    allow_insecure_tls: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "allow_insecure_tls",
            "ALLOW_INSECURE_TLS",
            "WEBPENT_ALLOW_INSECURE_TLS",
        ),
        description=(
            "Allow TLS certificate verification to be disabled for explicitly "
            "authorized lab targets. Keep false for production and public targets."
        ),
    )
    max_concurrent_requests: int = Field(default=10, gt=0)
    http_user_agent: str = Field(default="WebPent/0.2 (+https://github.com/example/webpent)")

    # -- External tool paths -------------------------------------------------
    nmap_path: str = "nmap"
    nikto_path: str = "nikto"
    sqlmap_path: str = "sqlmap"
    nuclei_path: str = "nuclei"
    ffuf_path: str = "ffuf"
    ffuf_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("ffuf_enabled", "FFUF_ENABLED", "WEBPENT_FFUF_ENABLED"),
        description="Enable ffuf content discovery; disabled by default.",
    )
    ffuf_wordlist_path: str = Field(
        default="",
        validation_alias=AliasChoices(
            "ffuf_wordlist_path", "FFUF_WORDLIST_PATH", "WEBPENT_FFUF_WORDLIST_PATH"
        ),
        description="Explicit local ffuf wordlist path; empty disables discovery.",
    )
    gobuster_path: str = "gobuster"
    subfinder_path: str = "subfinder"
    # V8 FIX: Go httpx binary is installed at /usr/local/bin/httpx-pd in
    # Dockerfile.base to avoid shadowing by the Python httpx package's
    # console script. Operators running outside Docker can set
    # HTTPX_PATH=/usr/local/bin/httpx or install the Go tool as httpx-pd.
    httpx_path: str = "httpx-pd"
    zap_path: str = "/usr/share/zaproxy/zap.sh"
    katana_path: str = "katana"
    dalfox_path: str = "dalfox"

    # V5 Sprint 6: Optional deserialization-exploitation tools.
    # Defaults point to bare binary names so the wrappers can resolve
    # them via PATH; operators can override with absolute paths via env.
    ysoserial_path: str = "ysoserial.jar"
    phpggc_path: str = "phpggc"

    # -- Storage -------------------------------------------------------------
    output_dir: Path = Field(default=Path("./output"))
    database_url: str = Field(
        default="sqlite:///./webpent.db",
        validation_alias=AliasChoices("database_url", "DATABASE_URL", "WEBPENT_DATABASE_URL"),
    )
    findings_ledger_path: Path = Field(
        default=Path("~/.webpent/findings_ledger.sqlite3"),
        validation_alias=AliasChoices(
            "findings_ledger_path",
            "FINDINGS_LEDGER_PATH",
            "WEBPENT_FINDINGS_LEDGER_PATH",
        ),
        description=(
            "Durable release-to-release findings ledger. It is separate from "
            "the per-run database and preserves findings across code revisions."
        ),
    )
    reauth_vault_shared_store: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "reauth_vault_shared_store",
            "WEBPENT_REAUTH_VAULT_SHARED_STORE",
        ),
        description=(
            "Persist encrypted re-auth records in shared SQLite so worker restarts "
            "can resume sessions; disabled by default for backward compatibility."
        ),
    )
    reauth_vault_database_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "reauth_vault_database_url",
            "WEBPENT_REAUTH_VAULT_DATABASE_URL",
        ),
        description=(
            "Optional SQLite URL for the shared re-auth store; when unset, "
            "DATABASE_URL is used."
        ),
    )

    # -- V10 P0-2: Embeddings / RAG offline mode ---------------------------
    # Audits flagged that all-MiniLM-L6-v2 first-run hits huggingface.co
    # and stalls offline scans for multi-minute downloads. These switches
    # let the operator declare "I am offline" or "skip RAG entirely" so
    # HTTP-only scans proceed without vector init.
    embeddings_offline: bool = Field(
        default=False,
        description=(
            "V10 P0-2: When True, the embeddings model will ONLY load "
            "from the local HuggingFace cache. If the model is not "
            "cached, RAG retrieval returns empty (no network call). "
            "Set EMBEDDINGS_OFFLINE=true for air-gapped / offline lab "
            "scans where a multi-minute huggingface.co download would "
            "stall the first scan."
        ),
    )
    disable_rag: bool = Field(
        default=False,
        description=(
            "V10 P0-2: When True, the RAG subsystem (lessons + knowledge "
            "retrieval) is explicitly disabled — no embeddings model is "
            "loaded, no Chroma store is initialised. Set DISABLE_RAG=true "
            "to skip RAG entirely (e.g. for minimal HTTP-only scans where "
            "the operator does not need lesson learning or knowledge "
            "enrichment). Distinct from EMBEDDINGS_OFFLINE: offline mode "
            "still tries to use a cached model; disable mode skips RAG "
            "completely."
        ),
    )

    # -- V10 P1-2: Configurable tool subprocess timeouts -------------------
    # Audits flagged that the nuclei timeout was hardcoded at 600s and
    # sqlmap/dalfox used the shared run_command default. These env-driven
    # ceilings let operators tune per-tool for lab vs production without
    # editing code. Safe defaults preserved.
    nuclei_timeout: int = Field(
        default=600,
        gt=0,
        description=(
            "V10 P1-2: subprocess timeout for nuclei, in seconds. "
            "Default 600 (10 min). Raise for large-scope production "
            "scans; lower for fast lab sweeps."
        ),
    )
    ffuf_timeout: int = Field(
        default=300,
        gt=0,
        le=3600,
        validation_alias=AliasChoices("ffuf_timeout", "FFUF_TIMEOUT", "WEBPENT_FFUF_TIMEOUT"),
        description="Maximum ffuf content-discovery subprocess time in seconds.",
    )
    sqlmap_timeout: int = Field(
        default=300,
        gt=0,
        validation_alias=AliasChoices("sqlmap_timeout", "SQLMAP_TIMEOUT", "WEBPENT_SQLMAP_TIMEOUT"),
        description="V10 P1-2: subprocess timeout for sqlmap, in seconds.",
    )
    sqlmap_post_timeout: int = Field(
        default=10,
        gt=0,
        le=60,
        validation_alias=AliasChoices(
            "sqlmap_post_timeout",
            "SQLMAP_POST_TIMEOUT",
            "WEBPENT_SQLMAP_POST_TIMEOUT",
        ),
        description=(
            "Per-request timeout passed to sqlmap for discovered POST forms. "
            "The engagement-level sqlmap_timeout remains the outer ceiling."
        ),
    )
    sqlmap_post_retries: int = Field(
        default=1,
        ge=0,
        le=3,
        validation_alias=AliasChoices(
            "sqlmap_post_retries",
            "SQLMAP_POST_RETRIES",
            "WEBPENT_SQLMAP_POST_RETRIES",
        ),
        description="Retries for sqlmap POST form requests.",
    )
    sqlmap_post_threads: int = Field(
        default=4,
        ge=1,
        le=8,
        validation_alias=AliasChoices(
            "sqlmap_post_threads",
            "SQLMAP_POST_THREADS",
            "WEBPENT_SQLMAP_POST_THREADS",
        ),
        description="Concurrent sqlmap workers for POST form validation.",
    )
    dalfox_timeout: int = Field(
        default=300,
        gt=0,
        description="V10 P1-2: subprocess timeout for dalfox, in seconds.",
    )

    # -- V10 P1-2: Configurable rate-governor thresholds -------------------
    # The RequestRateGovernor was previously constructed with hardcoded
    # max_concurrent=20 / error_rate_threshold=0.3. These env-driven
    # fields let operators tune for lab (more permissive) vs production
    # (more conservative) without editing code.
    governor_max_concurrent: int = Field(
        default=20,
        gt=0,
        validation_alias=AliasChoices(
            "governor_max_concurrent",
            "GOVERNOR_MAX_CONCURRENT",
            "WEBPENT_GOVERNOR_MAX_CONCURRENT",
        ),
        description=(
            "V10 P1-2: max concurrent in-flight requests per target host "
            "in a business-logic burst. Default 20. Lower for fragile "
            "targets; raise for lab targets that can handle the load."
        ),
    )
    governor_error_rate_threshold: float = Field(
        default=0.3,
        gt=0.0,
        le=1.0,
        description=(
            "V10 P1-2: abort a burst when the 5xx error rate crosses "
            "this fraction (default 0.3 = 30%). 4xx responses do NOT "
            "count as errors (they are target-side rejections, not "
            "infrastructure failures)."
        ),
    )
    business_logic_burst_size: int = Field(
        default=10,
        ge=1,
        le=20,
        validation_alias=AliasChoices(
            "business_logic_burst_size",
            "BUSINESS_LOGIC_BURST_SIZE",
            "WEBPENT_BUSINESS_LOGIC_BURST_SIZE",
        ),
        description=(
            "Maximum concurrent requests in one bounded race-condition "
            "probe. Lower this for fragile local labs; the default preserves "
            "the historical bounded behavior."
        ),
    )
    business_logic_max_endpoints: int = Field(
        default=10,
        ge=1,
        le=25,
        validation_alias=AliasChoices(
            "business_logic_max_endpoints",
            "BUSINESS_LOGIC_MAX_ENDPOINTS",
            "WEBPENT_BUSINESS_LOGIC_MAX_ENDPOINTS",
        ),
        description=(
            "Maximum structured state-changing forms probed by the business "
            "logic fuzzer per engagement."
        ),
    )

    # -- OOB callback infrastructure (V5 Sprint 5) --------------------------
    # Public base URL where the FastAPI app is reachable from the *target*
    # network. Used by the validator when constructing OOB callback URLs
    # for SSRF/RCE confirmation. Must be reachable from the target host.
    oob_callback_base_url: str = Field(
        default="",
        validation_alias=AliasChoices(
            "oob_callback_base_url",
            "OOB_CALLBACK_BASE_URL",
            "WEBPENT_OOB_CALLBACK_BASE_URL",
        ),
        description=(
            "Public base URL of the WebPent API used to build OOB "
            "callback URLs (e.g. 'http://203.0.113.10:8000'). The "
            "target must be able to reach this URL for OOB SSRF/RCE "
            "confirmation to succeed. Empty default = OOB URL "
            "construction disabled (SSRF/RCE will fall back to "
            "AI-Assessed). Set to http://localhost:8000 for local "
            "single-instance testing."
        ),
    )
    # Shared secret used to authenticate OOB callbacks so an attacker
    # cannot trivially forge a callback to auto-confirm a finding.
    # When empty, OOB confirmation is disabled (fail-safe).
    oob_callback_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "oob_callback_secret",
            "OOB_CALLBACK_SECRET",
            "WEBPENT_OOB_CALLBACK_SECRET",
        ),
        description=(
            "Shared secret appended as a path segment to every OOB "
            "callback URL. The endpoint rejects requests whose secret "
            "does not match. Empty default = OOB feature disabled."
        ),
    )
    # How long the validator blocks waiting for an OOB callback before
    # falling back to AI-Assessed. Kept short so the graph stays snappy.
    oob_poll_timeout_seconds: float = Field(
        default=3.0,
        ge=0.5,
        le=30.0,
        description="Seconds to wait for an OOB callback before fallback.",
    )
    oob_poll_max_attempts: int = Field(
        default=100,
        validation_alias=AliasChoices(
            "oob_poll_max_attempts",
            "OOB_POLL_MAX_ATTEMPTS",
            "WEBPENT_OOB_POLL_MAX_ATTEMPTS",
        ),
        ge=1,
        le=300,
        description="Maximum database polls per OOB validation attempt.",
    )

    # -- Stealth mode (V5 Sprint 6) -----------------------------------------
    # When stealth_mode is True, the framework inserts randomized
    # delays (jitter) before every external tool invocation and every
    # Playwright navigation/form-submit, and enforces a minimum spacing
    # between successive requests to the same target. This helps evade
    # naive WAF / IDS rules that flag bursty, machine-paced traffic.
    # All values are in seconds. Defaults are conservative (2-5s jitter)
    # and can be tuned via environment variables.
    stealth_jitter_min: float = Field(
        default=2.0,
        ge=0.0,
        description=(
            "Minimum jitter (seconds) inserted before tool/Playwright "
            "actions when stealth_mode is enabled."
        ),
    )
    stealth_jitter_max: float = Field(
        default=5.0,
        ge=0.0,
        description=(
            "Maximum jitter (seconds) inserted before tool/Playwright "
            "actions when stealth_mode is enabled. Must be >= "
            "stealth_jitter_min."
        ),
    )
    # Hard floor on inter-request spacing. Even if jitter draws a small
    # value, two consecutive requests to the same host are always
    # separated by at least this many seconds.
    stealth_min_request_interval: float = Field(
        default=1.0,
        ge=0.0,
        description="Minimum seconds between successive target requests in stealth mode.",
    )

    # -- Webhook / Ticketing Integration (V5 Sprint 11) --------------------
    # When enabled, the framework pushes "Tool-Confirmed" and
    # "Needs Human Review" findings to an external webhook (Slack,
    # Discord, Jira, etc.) via the integrations.webhook module.
    webhook_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "webhook_enabled", "WEBHOOK_ENABLED", "WEBPENT_WEBHOOK_ENABLED"
        ),
        description=(
            "V5 Sprint 11: When True, push actionable findings to the "
            "configured webhook URL. Set WEBHOOK_ENABLED=true to enable."
        ),
    )
    webhook_url: str = Field(
        default="",
        validation_alias=AliasChoices("webhook_url", "WEBHOOK_URL", "WEBPENT_WEBHOOK_URL"),
        description=(
            "V5 Sprint 11: The webhook endpoint URL to receive finding "
            "notifications (Slack, Discord, Jira, custom). Empty string "
            "disables the integration even if webhook_enabled is True."
        ),
    )
    webhook_timeout: float = Field(
        default=10.0,
        validation_alias=AliasChoices(
            "webhook_timeout", "WEBHOOK_TIMEOUT", "WEBPENT_WEBHOOK_TIMEOUT"
        ),
        ge=1.0,
        description="Webhook HTTP request timeout in seconds.",
    )
    webhook_secret: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("webhook_secret", "WEBHOOK_SECRET", "WEBPENT_WEBHOOK_SECRET"),
        description=(
            "HMAC signing secret for webhook payloads. Webhook delivery is "
            "refused when enabled without a non-empty secret."
        ),
    )
    webhook_max_concurrency: int = Field(
        default=4,
        validation_alias=AliasChoices(
            "webhook_max_concurrency",
            "WEBHOOK_MAX_CONCURRENCY",
            "WEBPENT_WEBHOOK_MAX_CONCURRENCY",
        ),
        ge=1,
        le=32,
        description=("Maximum number of concurrent webhook deliveries in a batch."),
    )

    # -- API Security (V5 Sprint 13 / V6 Develop-First) -------------------
    # V6: auth_enabled defaults to False for frictionless development.
    # Set AUTH_ENABLED=true in production to enforce JWT + RBAC.
    auth_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("auth_enabled", "AUTH_ENABLED", "WEBPENT_AUTH_ENABLED"),
        description=(
            "V6: When False, all JWT validation is bypassed and the "
            "default admin user is returned. Set to True for production."
        ),
    )
    # JWT authentication + RBAC for all /api/v1/* endpoints.
    jwt_secret_key: str = Field(
        default="webpent-dev-secret-key-change-in-production",
        validation_alias=AliasChoices("jwt_secret_key", "JWT_SECRET_KEY", "WEBPENT_JWT_SECRET_KEY"),
        description=(
            "V5 Sprint 13: Secret key used to sign JWTs. MUST be "
            "overridden in production via JWT_SECRET_KEY. "
            "The default is intentionally insecure for dev only."
        ),
    )
    audit_secret_key: str = Field(
        default="webpent-dev-audit-key-change-in-production",
        validation_alias=AliasChoices(
            "audit_secret_key", "AUDIT_SECRET_KEY", "WEBPENT_AUDIT_SECRET_KEY"
        ),
        description=(
            "V5 Sprint 14: HMAC-SHA256 key used to sign evidence bundles "
            "and the master report hash. MUST be overridden in production "
            "via AUDIT_SECRET_KEY."
        ),
    )
    # V10 HOSTILE-AUDIT FIX (CH-2): key used to encrypt operator-supplied
    # credentials (specifically the password) for the duration they sit
    # on the Celery/Redis broker as task kwargs. Without this, ScanRequest
    # credentials transit Redis (task_serializer="json", plain redis://
    # by default — see workers/pentest_worker.py) in PLAINTEXT. See
    # webpent.utils.task_crypto for the encrypt/decrypt call sites (API
    # dispatch and worker task entry, respectively). A Fernet key is
    # derived from this string via SHA-256 -> urlsafe-base64 so operators
    # can set any sufficiently long passphrase, matching the UX of
    # jwt_secret_key / audit_secret_key above, rather than being required
    # to hand-generate a raw Fernet key.
    celery_payload_key: str = Field(
        default="webpent-dev-celery-payload-key-change-in-production",
        # V10 EXHAUSTIVE AUDIT (reviewer follow-up): this Settings class
        # has no env_prefix, so pydantic-settings only ever read the
        # BARE env var name here -- confirmed empirically. The
        # description below (and .env.example, and the runtime warning
        # a few hundred lines down) told operators to set
        # WEBPENT_CELERY_PAYLOAD_KEY, which was silently never read;
        # the insecure default stayed in effect even after "fixing" it
        # per the docs. AliasChoices accepts BOTH names so this is
        # fixed for new deployments following the corrected docs below
        # AND for anyone who already set the old (broken) name.
        validation_alias=AliasChoices(
            "CELERY_PAYLOAD_KEY", "WEBPENT_CELERY_PAYLOAD_KEY", "celery_payload_key"
        ),
        description=(
            "V10: Passphrase used to derive the Fernet key that encrypts "
            "operator-supplied credentials before they are placed on the "
            "Celery/Redis broker. MUST be overridden in production via "
            "CELERY_PAYLOAD_KEY (WEBPENT_CELERY_PAYLOAD_KEY is also "
            "accepted for back-compat). Does not replace TLS on the "
            "Redis connection itself (WEBPENT_REDIS_URL should still use "
            "rediss:// in production) — this is defense in depth for the "
            "task PAYLOAD specifically."
        ),
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256, HS384, HS512, RS256).",
    )
    jwt_issuer: str = Field(
        default="webpent-api",
        validation_alias=AliasChoices("jwt_issuer", "JWT_ISSUER", "WEBPENT_JWT_ISSUER"),
        min_length=1,
        max_length=128,
        description="Expected JWT issuer claim.",
    )
    jwt_audience: str = Field(
        default="webpent",
        validation_alias=AliasChoices("jwt_audience", "JWT_AUDIENCE", "WEBPENT_JWT_AUDIENCE"),
        min_length=1,
        max_length=128,
        description="Expected JWT audience claim.",
    )
    jwt_expire_minutes: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "jwt_expire_minutes", "JWT_EXPIRE_MINUTES", "WEBPENT_JWT_EXPIRE_MINUTES"
        ),
        ge=1,
        description="JWT token lifetime in minutes (default 1 hour).",
    )

    # -- CORS (V5 Sprint 13) -----------------------------------------------
    cors_origins: list[str] = Field(
        default_factory=lambda: ["*"],
        validation_alias=AliasChoices("cors_origins", "CORS_ORIGINS", "WEBPENT_CORS_ORIGINS"),
        description=(
            "V5 Sprint 13: Allowed CORS origins. Use ['*'] for dev "
            "(any origin). For production, specify explicit origins: "
            "['https://app.example.com', 'https://console.example.com']."
        ),
    )

    # -- Rate Limiting (V5 Sprint 13) --------------------------------------
    rate_limit_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "rate_limit_enabled", "RATE_LIMIT_ENABLED", "WEBPENT_RATE_LIMIT_ENABLED"
        ),
        description=(
            "V6: Defaults to False for frictionless development/testing. "
            "Set RATE_LIMIT_ENABLED=true in production to enforce limits."
        ),
    )
    rate_limit_scan_per_minute: int = Field(
        default=5,
        validation_alias=AliasChoices(
            "rate_limit_scan_per_minute",
            "RATE_LIMIT_SCAN_PER_MINUTE",
            "WEBPENT_RATE_LIMIT_SCAN_PER_MINUTE",
        ),
        ge=1,
        description="Max scan-trigger requests per minute per IP/client.",
    )
    rate_limit_global_per_minute: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "rate_limit_global_per_minute",
            "RATE_LIMIT_GLOBAL_PER_MINUTE",
            "WEBPENT_RATE_LIMIT_GLOBAL_PER_MINUTE",
        ),
        ge=1,
        description="Max global API requests per minute per IP/client.",
    )
    rate_limit_login_per_minute: int = Field(
        default=10,
        validation_alias=AliasChoices(
            "rate_limit_login_per_minute",
            "RATE_LIMIT_LOGIN_PER_MINUTE",
            "WEBPENT_RATE_LIMIT_LOGIN_PER_MINUTE",
        ),
        ge=1,
        description="Max login attempts per minute per IP and account key.",
    )
    rate_limit_redis_url: str = Field(
        default="",
        validation_alias=AliasChoices(
            "rate_limit_redis_url",
            "RATE_LIMIT_REDIS_URL",
            "WEBPENT_RATE_LIMIT_REDIS_URL",
        ),
        description=(
            "Redis URL for distributed rate limiting. Empty string = "
            "in-process memory limiter (single-instance only)."
        ),
    )
    # V6.1 P1: Only trust X-Forwarded-For from these proxy IPs.
    # Prevents spoofing by direct clients claiming to be behind a proxy.
    trusted_proxy_ips: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "172.18.0.0/16", "172.19.0.0/16"],
        validation_alias=AliasChoices(
            "trusted_proxy_ips", "TRUSTED_PROXY_IPS", "WEBPENT_TRUSTED_PROXY_IPS"
        ),
        description=(
            "V6.1: IPs/subnets trusted to send X-Forwarded-For headers. "
            "Requests from IPs not in this list will use request.client.host "
            "directly (ignoring X-Forwarded-For)."
        ),
    )

    # -- V7 P0: Dev/Prod Mode Framework — REMOVED ---------------------------
    # The old operation_mode / mock_target_hosts allowlist has been
    # removed entirely (P0 fix — Private-IP auth/crawl blocker). It was
    # a redundant mechanism operators had to manage by hand, and it was
    # not even the actual cause of private-IP targets (e.g. lab DVWA
    # hosts) being blocked — the private/reserved-network blocklist in
    # shared/http.py blocked them unconditionally, in BOTH modes. That
    # blocklist now allows the engagement's own declared target through
    # (see shared/engagement_scope.py) while still blocking every other
    # private-network host, which is the fix that actually matters.
    # If you have an old .env with OPERATION_MODE= or MOCK_TARGET_HOSTS=
    # set, those lines are now silently ignored (extra="ignore" below).
    mock_oob_server_url: str = Field(
        default="http://127.0.0.1:18099",
        description=(
            "V7 Sprint 0.3 / V8 P0 A0 cleanup: Base URL of the local "
            "mock OOB server. The mock server records canary-token pings "
            "so _poll_for_oob_callback can be tested end-to-end without "
            "contacting real Interactsh/Burp Collaborator. Empty string "
            "means use the real OOB provider. (The previous description "
            "referenced the removed Dev/Prod Mode framework — that "
            "framework was deleted in V7 P0; this field is now just a "
            "plain configuration knob, not a mode toggle.)"
        ),
    )

    # -- Validators ----------------------------------------------------------
    # V6 Zero-Day Patched P0-2 / V6 The-Final-Seal P0-3: Both the JWT
    # secret AND the audit secret are now validated via a single
    # ``@model_validator(mode="after")`` instead of separate
    # ``@field_validator`` decorators. A field_validator only sees the
    # individual field value in isolation and has NO access to
    # ``self.auth_enabled`` — so it could only log a warning when a
    # default secret was detected, never hard-stop. An operator who
    # set AUTH_ENABLED=true without overriding the secret env vars
    # would get a silently-insecure production deployment: JWTs / HMAC
    # signatures produced with publicly-known default keys, forgeable
    # by anyone who reads the source code.
    #
    # The model_validator runs AFTER all fields are populated, so it can
    # inspect BOTH ``self.auth_enabled`` and the secret fields. When
    # auth is enabled AND a secret is an insecure default, it raises
    # ``ValueError`` to hard-stop Settings construction — Pydantic
    # surfaces this as a validation error, preventing the app from
    # starting with an insecure configuration.
    _INSECURE_JWT_DEFAULTS = frozenset(
        {
            "webpent-dev-secret-key-change-in-production",
            "change-me-in-production",
            "",
        }
    )

    # V6 The-Final-Seal P0-3: audit_secret_key has its own set of
    # insecure defaults. We reuse the same _INSECURE_JWT_DEFAULTS
    # set name for the JWT check (above), and define a separate
    # set here for the audit key. The CISO directive specifies
    # ``self.audit_secret_key in self._INSECURE_JWT_DEFAULTS`` —
    # i.e. the audit key must be checked against the SAME insecure-
    # defaults set as the JWT key. We union the audit-specific
    # default into _INSECURE_JWT_DEFAULTS so the cross-field check
    # catches both the JWT default AND the audit default under one
    # set. (An empty string is already in _INSECURE_JWT_DEFAULTS.)
    # However, to keep the audit-specific default visible and
    # self-documenting, we ALSO list it here — the union is
    # idempotent because frozenset deduplicates.
    _INSECURE_AUDIT_DEFAULTS = frozenset(
        {
            "webpent-dev-audit-key-change-in-production",
            # The CISO directive checks audit_secret_key against
            # _INSECURE_JWT_DEFAULTS, so we don't need a separate
            # list — but we keep this frozenset for documentation
            # and in case future audits want to diverge the sets.
        }
    )

    # V10 HOSTILE-AUDIT FIX (CH-2): insecure default for the new
    # celery_payload_key, checked in the same model_validator below
    # using the same auth_enabled-gated hard-stop pattern as the JWT
    # and audit keys.
    _INSECURE_CELERY_PAYLOAD_DEFAULTS = frozenset(
        {
            "webpent-dev-celery-payload-key-change-in-production",
        }
    )

    @model_validator(mode="after")
    def _validate_jwt_secret_key(self) -> Settings:
        """V6 Zero-Day Patched P0-2 / V6 The-Final-Seal P0-3: Hard-stop on insecure default secrets.

        Replaces the previous ``@field_validator("jwt_secret_key")`` and
        ``@field_validator("audit_secret_key")`` which only logged
        warnings because they lacked access to ``self.auth_enabled``.
        The model validator runs after all fields are populated, so it
        can enforce the cross-field invariant: auth MUST NOT be enabled
        with a known-insecure default secret.

        V6 The-Final-Seal P0-3: The audit_secret_key check was
        previously a separate ``@field_validator`` that only logged a
        warning. It is now folded into this model_validator so the
        same hard-stop semantics apply: if ``auth_enabled is True``
        AND ``audit_secret_key`` is an insecure default, raise
        ``ValueError``.

        Raises:
            ValueError: If ``auth_enabled is True`` AND
                ``jwt_secret_key`` is one of the insecure JWT defaults.
                Also if ``auth_enabled is True`` AND
                ``audit_secret_key`` is one of the insecure defaults
                (per the CISO directive, checked against
                ``_INSECURE_JWT_DEFAULTS``).
        """
        # --- JWT secret hard-stop (V6 Zero-Day Patched P0-2) ---
        if self.auth_enabled is True and self.jwt_secret_key in self._INSECURE_JWT_DEFAULTS:
            raise ValueError(
                "Hard-stop: Insecure default JWT secret used in production with auth_enabled=True"
            )
        # JWT minimum-length check (retained from the old field_validator).
        if (
            self.jwt_secret_key
            and len(self.jwt_secret_key) < 32
            and self.jwt_secret_key not in self._INSECURE_JWT_DEFAULTS
        ):
            raise ValueError(
                f"SECURITY HARD STOP: jwt_secret_key is only {len(self.jwt_secret_key)} "
                f"chars long — minimum 32 required for HS256."
            )

        # --- Audit secret hard-stop (V6 The-Final-Seal P0-3) ---
        # The CISO directive specifies:
        #   if self.auth_enabled is True and self.audit_secret_key in self._INSECURE_JWT_DEFAULTS:
        #       raise ValueError(...)
        # We check audit_secret_key against _INSECURE_JWT_DEFAULTS
        # (which includes "", "change-me-in-production", and the JWT
        # dev default) PLUS the audit-specific dev default. The
        # union is built lazily here so the check is self-contained.
        _all_insecure_audit = self._INSECURE_JWT_DEFAULTS | self._INSECURE_AUDIT_DEFAULTS
        if self.auth_enabled is True and self.audit_secret_key in _all_insecure_audit:
            raise ValueError(
                "Hard-stop: Insecure default audit secret used in production with auth_enabled=True"
            )
        # V10 AUDIT FIX (H9): in dev mode (auth_enabled=False), log a
        # loud WARNING if the insecure default is used — the operator
        # should know evidence hashes are forgeable. Previously the
        # insecure default was used SILENTLY in dev mode.
        if self.auth_enabled is False and self.audit_secret_key in _all_insecure_audit:
            import warnings as _warnings

            _warnings.warn(
                "INSECURE audit_secret_key in dev mode — evidence hashes "
                "are HMAC'd with a publicly-known key and can be forged. "
                "Set AUDIT_SECRET_KEY to a strong random value for any "
                "non-local deployment.",
                stacklevel=2,
            )
        # Audit secret minimum-length check (retained from the old
        # field_validator). Runs for both dev and prod — a 10-char
        # custom audit key is too short for HMAC-SHA256.
        if (
            self.audit_secret_key
            and len(self.audit_secret_key) < 32
            and self.audit_secret_key not in _all_insecure_audit
        ):
            raise ValueError(
                f"SECURITY HARD STOP: audit_secret_key is only {len(self.audit_secret_key)} "
                f"chars long — minimum 32 required for HMAC-SHA256."
            )

        # --- Celery payload key hard-stop (V10 HOSTILE-AUDIT FIX / CH-2) ---
        # Same pattern as the JWT/audit checks above: only hard-stop when
        # auth_enabled=True (the codebase's existing signal for "this is
        # a production-intent deployment, not frictionless dev"), so
        # Settings() with zero env vars still constructs successfully for
        # local dev / tests, unchanged from before this fix.
        if (
            self.auth_enabled is True
            and self.celery_payload_key in self._INSECURE_CELERY_PAYLOAD_DEFAULTS
        ):
            raise ValueError(
                "Hard-stop: Insecure default celery_payload_key used in "
                "production with auth_enabled=True — operator credentials "
                "would be encrypted with a publicly-known key, which is "
                "equivalent to not encrypting them at all."
            )
        # V10 AUDIT FIX (H9): in dev mode, warn loudly if the insecure
        # default celery_payload_key is used — task passwords are
        # decryptable by anyone with Redis access.
        if (
            self.auth_enabled is False
            and self.celery_payload_key in self._INSECURE_CELERY_PAYLOAD_DEFAULTS
        ):
            import warnings as _warnings2

            _warnings2.warn(
                "INSECURE celery_payload_key in dev mode — task passwords "
                "are encrypted with a publicly-known key and can be "
                "decrypted by anyone with Redis access. Set "
                "CELERY_PAYLOAD_KEY to a strong random value "
                "for any non-local deployment.",
                stacklevel=2,
            )
        if (
            self.celery_payload_key
            and len(self.celery_payload_key) < 32
            and self.celery_payload_key not in self._INSECURE_CELERY_PAYLOAD_DEFAULTS
        ):
            raise ValueError(
                f"SECURITY HARD STOP: celery_payload_key is only "
                f"{len(self.celery_payload_key)} chars long — minimum 32 "
                f"required (it is SHA-256-derived into a Fernet key)."
            )
        return self

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, v: str | LogLevel) -> LogLevel:
        if isinstance(v, LogLevel):
            return v
        return LogLevel(str(v).upper())

    @field_validator("default_llm_provider", mode="before")
    @classmethod
    def _normalise_provider(cls, v: str | LLMProvider) -> LLMProvider:
        if isinstance(v, LLMProvider):
            return v
        return LLMProvider(str(v).lower())

    # -- Helpers -------------------------------------------------------------
    def api_key_for(self, provider: LLMProvider) -> str | None:
        return {
            LLMProvider.OPENAI: self.openai_api_key,
            LLMProvider.ANTHROPIC: self.anthropic_api_key,
            LLMProvider.GROQ: self.groq_api_key,
            LLMProvider.LOCAL: self.local_llm_api_key,
        }[provider]

    def ensure_output_dir(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached ``Settings`` singleton."""
    return Settings()
