# src/webpent/cli.py
"""webpent.cli

Professional CLI for the WebPent Framework V4.5 using Typer + Rich.

Usage:
    webpent scan --url https://target.com
    webpent scan --url https://target.com --creds admin:password
    webpent scan --url https://target.com --creds admin:password --auto-approve
    webpent scan --url https://target.com --cookies "PHPSESSID=abc123; security=low"
    webpent scan --url https://target.com --portswigger
    webpent preflight
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from webpent.api.scan_registry import (
    get_thread_ids_by_engagement_id,
    register_scan,
)
from webpent.cli.loaders import load_cookie_file, load_creds_file, load_payload_file
from webpent.config.settings import ScanMode, get_settings
from webpent.graph.builder import build_graph
from webpent.graph.checkpoints import get_checkpointer
from webpent.memory.db import get_db_manager
from webpent.shared.coverage_ledger import CoverageIntelligence
from webpent.shared.finding_aggregation import aggregate_findings, default_engagement_id
from webpent.shared.persistent_finding_ledger import (
    PersistentFindingLedger,
    current_release_id,
)
from webpent.state.initial_state import build_initial_state

app = typer.Typer(
    name="webpent",
    help="WebPent Framework V4.5 — Autonomous Pentesting with HITL & RAG",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _parse_credentials(creds: str | None) -> dict[str, str]:
    """Parse a 'user:pass' string into a credentials dict."""
    if not creds:
        return {}
    if ":" not in creds:
        err_console.print("[red]Error:[/red] Credentials must be in 'user:pass' format.")
        raise typer.Exit(1)
    parts = creds.split(":", 1)
    return {"username": parts[0], "password": parts[1]}


def _parse_cookies(cookies: str | None) -> dict[str, str]:
    """Parse a 'name1=value1; name2=value2' string into a session-cookie dict.

    Same format as a browser/curl 'Cookie:' header value, so operators
    can paste it directly from DevTools. Mirrors the API's
    ``ScanRequest.session_cookies`` field (``dict[str, str]``) — see
    ``api/app.py``. Threaded into ``initial_state["session_cookies"]``,
    where ``auth_node`` picks it up, validates it, and (if valid) skips
    Playwright login — same precedence as the API path.
    """
    if not cookies:
        return {}
    result: dict[str, str] = {}
    for pair in cookies.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            err_console.print(
                f"[red]Error:[/red] Malformed --cookies segment '{pair}' — "
                "expected 'name=value' pairs separated by ';'."
            )
            raise typer.Exit(1)
        name, value = pair.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            err_console.print(f"[red]Error:[/red] Empty cookie name in --cookies segment '{pair}'.")
            raise typer.Exit(1)
        result[name] = value
    return result


def _load_json_list(path: str | None, *, label: str, max_items: int) -> list[Any]:
    """Load a bounded JSON list from an operator-controlled local file.

    Values are returned to the graph but never printed. This keeps CLI support
    useful for offline JWT/advisory inputs without putting secrets in logs.
    """
    if not path:
        return []
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]Error:[/red] Cannot read {label} file: {exc}")
        raise typer.Exit(1) from exc
    if not isinstance(payload, list):
        err_console.print(f"[red]Error:[/red] {label} file must contain a JSON array")
        raise typer.Exit(1)
    if len(payload) > max_items:
        err_console.print(f"[red]Error:[/red] {label} file exceeds {max_items} entries")
        raise typer.Exit(1)
    return payload


def _parse_report_formats(value: str | None) -> list[str] | None:
    """Normalize a comma-separated report selection without accepting unknown formats."""
    if value is None:
        return None
    allowed = {"json", "html", "pdf", "md", "all"}
    selected = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not selected or any(item not in allowed for item in selected):
        err_console.print(
            "[red]Error:[/red] --report-format accepts json, html, pdf, md, or all"
        )
        raise typer.Exit(1)
    if "all" in selected:
        return ["all"]
    return list(dict.fromkeys(selected))


def _perform_preflight_check() -> bool:
    """Launch Playwright Chromium once to verify availability.

    Returns True if the browser launches successfully, False otherwise.
    """
    console.print("[dim]Pre-flight: Checking Playwright Chromium...[/dim]")
    try:
        from playwright.sync_api import sync_playwright

        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        browser.close()
        pw.stop()
        console.print("[green]✓ Playwright Chromium available.[/green]")
        return True
    except Exception as exc:
        console.print(
            f"[yellow]⚠ Playwright unavailable: {exc}[/yellow]\n"
            "[dim]  Execution sandbox will be skipped gracefully.[/dim]"
        )
        return False


@app.command()
def scan(
    url: str = typer.Option(
        ..., "--url", "-u", help="Target URL (must include http:// or https://)."
    ),
    creds: str | None = typer.Option(
        None, "--creds", "-c", help="Credentials in 'user:pass' format for authenticated scanning."
    ),
    second_creds: list[str] = typer.Option(  # noqa: B008
        [],
        "--second-creds",
        help=(
            "Additional authenticated identity in 'user:pass' format. "
            "Repeat the option for bounded cross-user IDOR/BAC probes; "
            "password values are never displayed or report-persisted."
        ),
    ),
    cookies: str | None = typer.Option(
        None,
        "--cookies",
        help=(
            "Operator-supplied session cookies for authenticated scanning "
            "without Playwright login, e.g. 'PHPSESSID=abc123; security=low'. "
            "Same format as a browser/curl Cookie header — paste directly "
            "from DevTools. Mirrors the API's session_cookies field: "
            "auth_node validates the session and, if valid, skips "
            "Playwright login. Takes precedence over --creds if both are "
            "given."
        ),
    ),
    portswigger: bool = typer.Option(
        False, "--portswigger", help="Optimise for PortSwigger Web Security Academy labs."
    ),
    auto_approve: bool = typer.Option(
        False, "--auto-approve", help="Bypass HITL pause for automated CI/CD scanning."
    ),
    mode: str | None = typer.Option(
        None,
        "--mode",
        help=(
            "Per-engagement authority profile: legacy, safe-smart, or "
            "authorized-active. Defaults to settings/environment."
        ),
    ),
    thread_id: str | None = typer.Option(
        None, "--thread-id", help="LangGraph thread ID for checkpoint resumption."
    ),
    engagement_id: str | None = typer.Option(
        None,
        "--engagement-id",
        help=(
            "Logical scope shared by repeated scans. Defaults to a stable target scope; "
            "use a new value to start an isolated campaign."
        ),
    ),
    client_id: str | None = typer.Option(
        None,
        "--client-id",
        help=(
            "Stable customer/client identifier used to isolate advisory lessons "
            "from other clients. Required for lesson persistence and retrieval."
        ),
    ),
    stealth: bool = typer.Option(
        False,
        "--stealth",
        help=(
            "V5 Sprint 6: Enable stealth mode — insert randomized jitter "
            "(default 2–5s) and enforce minimum inter-request spacing "
            "before external tools and Playwright actions to evade "
            "WAF / IDS rate-based detection."
        ),
    ),
    skip_recon: bool = typer.Option(
        False,
        "--skip-recon",
        help=(
            "V6.1 / V7 Phase 5: Bypass the recon + crawler nodes entirely "
            "and go straight to hypothesis. Useful for fast targeted scans "
            "against a single known endpoint when you do not want to spend "
            "time on subdomain enumeration or crawling. NOTE: this is the "
            "all-or-nothing flag — it also skips nuclei. For local/private-IP "
            "targets where you only want to skip subfinder (but keep nuclei "
            "and httpx), simply do not pass this flag; the recon agent now "
            "auto-detects bare-IP targets and skips subfinder for them "
            "automatically. Mirrors the API's ScanRequest.skip_recon field."
        ),
    ),
    jwt_weak_secrets_file: str | None = typer.Option(
        None,
        "--jwt-weak-secrets-file",
        help="Local JSON array of bounded JWT HMAC candidates for offline analysis.",
    ),
    jwt_public_key_available: bool = typer.Option(
        False,
        "--jwt-public-key-available",
        help="Mark that the operator has a public key available for JWT advisory analysis.",
    ),
    disclosed_reports_file: str | None = typer.Option(
        None,
        "--disclosed-reports-file",
        help="Local JSON array of disclosed report text/records used only as advisory context.",
    ),
    report_format: str | None = typer.Option(
        None,
        "--report-format",
        help="Report output: json, html, pdf, md, or all; comma-separated values are supported.",
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Disable LLM assistance for this run without changing .env.",
    ),
    payload_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--payload-file",
        help="Bounded text file of custom payloads, one payload per line.",
    ),
    creds_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--creds-file",
        help="JSON file containing one credential object or named credential profiles.",
    ),
    cookie_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--cookie-file",
        help="JSON or Netscape cookie-jar file for authenticated scanning.",
    ),
) -> None:
    """Trigger a full pentest engagement against a target."""

    # --- Validate URL and optional per-run authority profile ---
    if not url.startswith(("http://", "https://")):
        err_console.print("[red]Error:[/red] URL must start with http:// or https://")
        raise typer.Exit(1)
    try:
        resolved_mode = ScanMode(mode) if mode is not None else get_settings().scan_mode
    except ValueError as exc:
        err_console.print(
            "[red]Error:[/red] --mode must be one of: legacy, safe-smart, authorized-active"
        )
        raise typer.Exit(1) from exc

    # --- Parse credentials / session cookies / bounded identities ---
    credentials = _parse_credentials(creds)
    operator_cookies = _parse_cookies(cookies)
    custom_payloads: list[str] = []
    if payload_file is not None:
        try:
            custom_payloads = load_payload_file(payload_file)
        except ValueError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc
    if cookie_file is not None:
        try:
            file_cookies = load_cookie_file(cookie_file)
        except ValueError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc
        operator_cookies = {**file_cookies, **operator_cookies}
    file_profiles: dict[str, Any] = {}
    if creds_file is not None:
        try:
            loaded_creds = load_creds_file(creds_file)
        except ValueError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc
        if {"username", "password"}.issubset(loaded_creds):
            credentials = {**loaded_creds, **credentials}
        else:
            file_profiles = loaded_creds
    selected_report_formats = _parse_report_formats(report_format)
    if len(second_creds) > 7:
        err_console.print("[red]Error:[/red] at most 7 --second-creds identities are allowed")
        raise typer.Exit(1)
    identity_profiles: dict[str, dict[str, object]] = {}
    for index, raw_identity in enumerate(second_creds, start=2):
        parsed_identity = _parse_credentials(raw_identity)
        if not parsed_identity:
            err_console.print("[red]Error:[/red] every --second-creds value must use 'user:pass'")
            raise typer.Exit(1)
        identity_profiles[f"identity-{index}"] = {
            "name": f"identity-{index}",
            "role": "secondary",
            "credentials": parsed_identity,
        }
    for name, profile in file_profiles.items():
        identity_profiles[str(name)] = {
            "name": str(name),
            "role": str(profile.get("role", "secondary")),
            "credentials": dict(profile),
        }
    jwt_candidates = _load_json_list(jwt_weak_secrets_file, label="JWT candidates", max_items=64)
    disclosed_report_corpus = _load_json_list(
        disclosed_reports_file, label="disclosed reports", max_items=200
    )
    if any(not isinstance(item, str) or not item or len(item) > 128 for item in jwt_candidates):
        err_console.print(
            "[red]Error:[/red] JWT candidates must be non-empty strings up to 128 chars"
        )
        raise typer.Exit(1)
    if any(not isinstance(item, (str, dict)) for item in disclosed_report_corpus):
        err_console.print("[red]Error:[/red] disclosed reports must be strings or JSON objects")
        raise typer.Exit(1)

    # --- Pre-flight health check ---
    playwright_enabled = _perform_preflight_check()

    # --- Resolve run and cumulative engagement IDs ---
    resolved_thread_id = thread_id or str(uuid4())
    resolved_engagement_id = engagement_id or default_engagement_id(url, client_id)

    # --- Display engagement header ---
    header = Table(show_header=False, border_style="steel_blue", expand=False)
    header.add_column("Key", style="dim")
    header.add_column("Value", style="bold")
    header.add_row("Target", url)
    header.add_row("Thread ID", resolved_thread_id)
    header.add_row("Engagement ID", resolved_engagement_id)
    header.add_row("Auto-Approve", "Yes" if auto_approve else "No")
    header.add_row("Mode", resolved_mode.value)
    header.add_row("PortSwigger", "Yes" if portswigger else "No")
    header.add_row(
        "Credentials",
        f"{credentials.get('username', '(none)')}:***" if credentials else "(none)",
    )
    header.add_row(
        "Session Cookies",
        f"{', '.join(sorted(operator_cookies.keys()))} (values hidden)"
        if operator_cookies
        else "(none)",
    )
    header.add_row("Playwright", "Available" if playwright_enabled else "Disabled")
    header.add_row("Stealth Mode", "ON (jitter + rate-limit)" if stealth else "Off")
    header.add_row("LLM", "Disabled for this run" if no_llm else "Configured setting")
    header.add_row("Custom Payloads", str(len(custom_payloads)) if custom_payloads else "None")
    header.add_row(
        "Credential Profiles", str(len(identity_profiles)) if identity_profiles else "None"
    )
    header.add_row("Report Format", report_format or "all (default)")
    header.add_row("Skip Recon", "Yes (bypass recon/crawler/scope/waf)" if skip_recon else "No")
    header.add_row(
        "JWT Candidates",
        f"{len(jwt_candidates)} (values hidden)" if jwt_candidates else "Default bounded set",
    )
    header.add_row(
        "Disclosed Reports",
        str(len(disclosed_report_corpus)) if disclosed_report_corpus else "None",
    )

    console.print(
        Panel(
            header,
            title="[bold]WebPent V4.5 — Engagement Initialised[/bold]",
            border_style="steel_blue",
        )
    )

    if stealth:
        console.print(
            "[dim yellow]Stealth mode enabled: tool invocations and "
            "Playwright actions will be paced with randomized jitter.[/dim yellow]"
        )

    # --- Build and invoke the graph ---
    from webpent.models.targets import Target

    settings = get_settings()
    target = Target(url=url, is_portswigger_lab=portswigger)

    # V10 HOSTILE P1-2 FIX: credentials are threaded via state["credentials"]
    # (see initial_state below) — the same secure path the API/worker uses.
    # The previous version ALSO stuffed username:/password: into
    # target.description, which gets persisted in the LangGraph checkpoint
    # (SqliteSaver) as plaintext — the exact problem FIX-10 was designed
    # to prevent. auth_node reads state["credentials"], NOT
    # target.description (V4.5 Integration Fix removed the regex
    # extraction). The description stuffing was dead code that created a
    # plaintext-password-in-checkpoint risk. Deleted.

    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    # V7 P0 FIX: declare this engagement's own target host so the SSRF
    # guard (shared/http.py) allows connecting to it even if it is a
    # private/reserved-network address (e.g. a lab DVWA VM). Mirrors
    # the same call in workers/pentest_worker.py::run_pentest_task —
    # the CLI is a separate entry point that also invokes the graph
    # directly and needs the allowlist set independently.
    token = set_engagement_target_hosts(target.url)
    try:
        from webpent.auth.reauth_vault import (
            seal_identity_profiles,
            seal_reauth_secret,
            seal_session_cookies,
        )

        # Keep operator secrets in the worker-memory vault, never in the
        # initial graph state that can be checkpointed.
        _cli_password = (credentials or {}).get("password", "") or ""
        if _cli_password:
            seal_reauth_secret(resolved_thread_id, _cli_password)
        if operator_cookies:
            seal_session_cookies(resolved_thread_id, operator_cookies)
        if identity_profiles:
            seal_identity_profiles(resolved_thread_id, identity_profiles)
        safe_credentials = dict(credentials or {})
        if "password" in safe_credentials:
            safe_credentials["password"] = ""

        with get_checkpointer() as checkpointer:
            graph = build_graph(checkpointer=checkpointer, auto_approve=auto_approve)

            initial_state = build_initial_state(
                target,
                thread_id=resolved_thread_id,
                client_id=client_id or "",
                engagement_id=resolved_engagement_id,
                credentials=safe_credentials,
                session_cookies={},
                identity_profiles={},
                jwt_weak_secret_candidates=jwt_candidates,
                jwt_public_key_available=jwt_public_key_available,
                disclosed_report_corpus=disclosed_report_corpus,
                llm_override=False if no_llm else None,
                custom_payloads=custom_payloads,
                report_formats=selected_report_formats,
                playwright_enabled=playwright_enabled,
                skip_recon=skip_recon,
                stealth_mode=stealth,
                scan_mode=resolved_mode,
                action_ledger_path=str(settings.action_ledger_path),
            )

            config = {
                "recursion_limit": settings.max_graph_steps,
                "configurable": {"thread_id": resolved_thread_id},
            }

            if _cli_password:
                console.print(
                    f"[dim]V10 P1-2: sealed reauth vault for thread_id={resolved_thread_id}[/dim]"
                )
            del _cli_password

            register_scan(
                resolved_thread_id,
                f"cli:{resolved_thread_id}",
                target_url=url,
                owner_username="",
                client_id=client_id or "",
                engagement_id=resolved_engagement_id,
            )
            console.print("\n[bold blue][*] Invoking LangGraph orchestrator...[/bold blue]\n")
            from webpent.shared.llm import llm_enabled_override

            if stealth:
                from webpent.shared.stealth import reset_stealth_telemetry

                reset_stealth_telemetry()
            with llm_enabled_override(False if no_llm else None):
                final_state = graph.invoke(initial_state, config=config)

    except Exception as exc:
        err_console.print(f"[red]ERROR: Engagement failed — {exc}[/red]")
        raise typer.Exit(1) from exc
    finally:
        # V7 P0 FIX: release the allowlist so a long-lived interactive
        # shell (or test runner) that invokes multiple engagements in
        # the same process never carries a stale target forward.
        clear_engagement_target_hosts(token)
        # V10 HOSTILE P1-2: clear the reauth vault (same as the worker).
        # Best-effort — never raises.
        try:
            from webpent.auth.reauth_vault import clear_reauth_secret

            clear_reauth_secret(resolved_thread_id)
        except Exception:
            pass

    # --- Persist and project cumulative results ---
    findings = list(final_state.get("findings") or [])
    try:
        db = get_db_manager()
        db.init_db()
        run_findings = [
            finding.model_copy(update={"thread_id": resolved_thread_id})
            for finding in findings
        ]
        for finding in run_findings:
            db.save_finding(finding)
        register_scan(
            resolved_thread_id,
            f"cli:{resolved_thread_id}",
            target_url=url,
            owner_username="",
            client_id=client_id or "",
            engagement_id=resolved_engagement_id,
        )
        sibling_threads = get_thread_ids_by_engagement_id(
            resolved_engagement_id,
            owner_username="",
            client_id=client_id or "",
        )
        findings = aggregate_findings(
            db.get_findings_by_threads(sibling_threads or [resolved_thread_id])
        )
        findings = PersistentFindingLedger(settings.findings_ledger_path).merge(
            resolved_engagement_id,
            findings,
            release_id=current_release_id(),
            thread_id=resolved_thread_id,
        )
    except Exception as exc:
        # Reporting must not turn a completed scan into a failed scan. Keep
        # the graph result as a safe fallback if local persistence is degraded.
        console.print(f"[yellow]⚠ Cumulative findings unavailable: {exc}[/yellow]")

    # --- Display results ---
    if stealth:
        from webpent.shared.stealth import get_stealth_summary

        telemetry = get_stealth_summary()
        console.print(
            "[cyan]Stealth telemetry:[/cyan] "
            f"jitter={telemetry['jitter_calls']} calls, "
            f"rate-limit={telemetry['rate_limit_calls']} calls, "
            f"sleep={telemetry['total_sleep_seconds']:.3f}s"
        )

    if findings:
        table = Table(
            title=f"Findings ({len(findings)})",
            title_style="bold white",
            border_style="grey50",
            header_style="bold cyan",
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Severity", width=10)
        table.add_column("Confidence Level", width=18)
        table.add_column("Title", min_width=30, max_width=60)
        table.add_column("URL", min_width=30, max_width=50)

        sev_styles = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "blue",
        }

        for idx, f in enumerate(findings, 1):
            sev = str(getattr(f, "severity", "info")).lower()
            sev_text = Text(sev.upper(), style=sev_styles.get(sev, "white"))
            conf_level = getattr(f, "confidence_level", "Pending")
            table.add_row(str(idx), sev_text, conf_level, f.title, f.url)

        console.print(table)
    else:
        console.print("[dim]No findings discovered.[/dim]")

    # --- Summary panel ---
    output_dir = settings.ensure_output_dir()
    report_names = ["json", "html", "pdf", "md"]
    if selected_report_formats and "all" not in selected_report_formats:
        report_names = selected_report_formats
    report_label = ", ".join(report_names)
    console.print(
        Panel(
            f"[bold green]Engagement Completed[/bold green]\n\n"
            f"  [dim]Thread ID[/dim]    {resolved_thread_id}\n"
            f"  [dim]Findings[/dim]     {len(findings)}\n"
            f"  [dim]Reports[/dim]      {report_label} in {output_dir}\n"
            f"  [dim]Database[/dim]     {settings.database_url}\n"
            f"  [dim]Release[/dim]      {current_release_id()}\n"
            f"  [dim]Ledger[/dim]       {settings.findings_ledger_path}\n",
            border_style="green",
        )
    )


@app.command()
def preflight() -> None:
    """Run pre-flight health checks for all tools and Playwright."""
    console.print("[bold blue]WebPent V4.5 — Pre-flight Health Check[/bold blue]\n")

    # Playwright
    pw_ok = _perform_preflight_check()

    # External tools
    import shutil

    # V8 FIX: check for httpx-pd (the Go ProjectDiscovery tool), not
    # httpx (which resolves to the Python httpx CLI after pip install).
    tools = ["nuclei", "subfinder", "httpx-pd", "katana", "dalfox", "sqlmap"]
    table = Table(title="Tool Availability", border_style="grey50", header_style="bold cyan")
    table.add_column("Tool", width=15)
    table.add_column("Status", width=10)

    for tool in tools:
        if shutil.which(tool):
            table.add_row(tool, "[green]✓ Available[/green]")
        else:
            table.add_row(tool, "[red]✗ Missing[/red]")

    console.print(table)

    try:
        from webpent.shared.preflight import _check_llm_providers

        llm_status = _check_llm_providers()
        llm_table = Table(
            title="LLM Provider Status", border_style="grey50", header_style="bold cyan"
        )
        llm_table.add_column("Setting", width=24)
        llm_table.add_column("Value")
        llm_table.add_row("LLM enabled", str(llm_status.get("enabled", False)))
        llm_table.add_row("Status", str(llm_status.get("status", "unknown")))
        providers = llm_status.get("configured_providers") or []
        llm_table.add_row("Configured providers", ", ".join(map(str, providers)) or "None")
        dead = llm_status.get("dead_providers") or []
        llm_table.add_row("Circuit-breaker dead", ", ".join(map(str, dead)) or "None")
        chains = llm_status.get("fallback_chains") or {}
        chain_text = "; ".join(
            f"{task}: {' -> '.join(models) if models else 'deterministic'}"
            for task, models in chains.items()
        )
        llm_table.add_row("Fallback chains", chain_text or "deterministic")
        console.print(llm_table)
    except Exception as exc:
        console.print(f"[yellow]LLM diagnostics unavailable: {type(exc).__name__}[/yellow]")

    if not pw_ok:
        console.print("\n[yellow]⚠ Playwright is disabled — sandbox will skip gracefully.[/yellow]")


def main() -> None:
    """Entry point for the webpent CLI."""
    app()


if __name__ == "__main__":
    main()


# V55 Phase 8: additive, manifest-backed CLI surface. The original `scan`
# command remains unchanged; these commands are local/read-only by default.
scope_app = typer.Typer(
    name="scope",
    help="Manage validated, versioned engagement scope entries.",
    no_args_is_help=True,
)
app.add_typer(scope_app, name="scope")


def _manifest_or_exit(value: str) -> tuple[Path, dict[str, Any]]:
    from webpent.cli.manifest import load_manifest

    try:
        return load_manifest(value)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command("init")
def init_engagement(
    name: str = typer.Argument(..., help="Human-readable engagement name."),
    manifest: str = typer.Option(
        "webpent-engagement.json", "--manifest", "-f", help="Manifest output path."
    ),
) -> None:
    """Create a versioned local engagement manifest without secrets."""
    from webpent.cli.manifest import default_manifest, manifest_path, save_manifest

    path = manifest_path(manifest)
    if path.exists():
        err_console.print(f"[red]Error:[/red] manifest already exists: {path}")
        raise typer.Exit(1)
    try:
        save_manifest(path, default_manifest(name))
    except (OSError, TypeError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] cannot create manifest: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Created engagement manifest:[/green] {path}")


@scope_app.command("add")
def scope_add(
    value: str = typer.Argument(..., help="In-scope HTTP(S) URL without credentials."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """Add one normalized, scope-validated URL to an engagement manifest."""
    from webpent.cli.manifest import add_scope_entry, save_manifest

    path, document = _manifest_or_exit(manifest)
    try:
        entry = add_scope_entry(document, value)
        save_manifest(path, document)
    except (OSError, TypeError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] invalid scope entry: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Scope recorded:[/green] {entry['url']}")


@scope_app.command("show")
def scope_show(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """Display scope entries without exposing secrets or cookies."""
    _path, document = _manifest_or_exit(manifest)
    entries = document.get("scope", [])
    if not entries:
        console.print("[dim]Scope is empty.[/dim]")
        return
    table = Table(title="Engagement Scope", border_style="grey50", header_style="bold cyan")
    table.add_column("#", justify="right", width=4)
    table.add_column("URL")
    table.add_column("Host")
    for index, item in enumerate(entries, 1):
        if isinstance(item, dict):
            table.add_row(str(index), str(item.get("url", "")), str(item.get("host", "")))
    console.print(table)


@scope_app.command("remove")
def scope_remove(
    value: str = typer.Argument(..., help="Exact normalized URL to remove."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """Remove one scope URL after the same validation used by `scope add`."""
    from webpent.cli.manifest import remove_scope_entry, save_manifest

    path, document = _manifest_or_exit(manifest)
    try:
        removed = remove_scope_entry(document, value)
        if removed:
            save_manifest(path, document)
    except (OSError, TypeError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] invalid scope entry: {exc}")
        raise typer.Exit(1) from exc
    console.print(
        "[green]Scope removed.[/green]" if removed else "[yellow]Scope entry not found.[/yellow]"
    )


@app.command("hunt")
def hunt(
    url: str | None = typer.Option(
        None, "--url", "-u", help="Target URL for a new or existing run."
    ),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    time_budget: int = typer.Option(900, "--time-budget", min=1, max=86400),
    request_budget: int = typer.Option(1000, "--request-budget", min=1, max=100000),
    llm_budget: float = typer.Option(10.0, "--llm-budget", min=0.0, max=10000.0),
    thread_id: str | None = typer.Option(None, "--thread-id"),
    execute: bool = typer.Option(
        False, "--execute", help="Actually invoke the existing scan command."
    ),
) -> None:
    """Plan a bounded hunt run; execution is explicit and delegates to legacy `scan`."""
    from datetime import datetime, timezone

    from webpent.cli.manifest import add_scope_entry, save_manifest

    path, document = _manifest_or_exit(manifest)
    if not url and not document.get("scope"):
        err_console.print("[red]Error:[/red] provide --url or add scope first")
        raise typer.Exit(1)
    target_url = url or str(document["scope"][0].get("url", ""))
    try:
        if url:
            add_scope_entry(document, url)
        run = {
            "id": thread_id or str(uuid4()),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "target_ref": "scope:0" if document.get("scope") else "(none)",
            "time_budget_seconds": time_budget,
            "request_budget": request_budget,
            "llm_budget": llm_budget,
            "status": "planned" if not execute else "delegated_to_scan",
        }
        document.setdefault("runs", []).append(run)
        save_manifest(path, document)
    except (OSError, TypeError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] cannot record hunt: {exc}")
        raise typer.Exit(1) from exc
    if not execute:
        console.print(
            f"[green]Hunt planned:[/green] {target_url}\n"
            f"[dim]Budgets: {time_budget}s / {request_budget} requests / {llm_budget} LLM units. "
            "No network requests were made; pass --execute to delegate to scan.[/dim]"
        )
        return
    scan(url=target_url, thread_id=thread_id)


@app.command("graph")
def graph_command(
    action: str = typer.Argument("summary", help="summary or export."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    output: str | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Show or export redacted Mental/Attack Graph summaries from a manifest."""
    path, document = _manifest_or_exit(manifest)
    if action not in {"summary", "export"}:
        err_console.print("[red]Error:[/red] graph action must be summary or export")
        raise typer.Exit(1)
    graph = document.get("graph") if isinstance(document.get("graph"), dict) else {}
    mental = graph.get("mental_model") if isinstance(graph.get("mental_model"), dict) else {}
    attack = graph.get("attack_graph") if isinstance(graph.get("attack_graph"), dict) else {}
    summary = {
        "mental_nodes": len(mental.get("nodes", {}))
        if isinstance(mental.get("nodes"), dict)
        else 0,
        "mental_edges": len(mental.get("edges", []))
        if isinstance(mental.get("edges"), list)
        else 0,
        "attack_nodes": len(attack.get("nodes", {}))
        if isinstance(attack.get("nodes"), dict)
        else 0,
        "attack_edges": len(attack.get("edges", []))
        if isinstance(attack.get("edges"), list)
        else 0,
    }
    if action == "summary":
        console.print(json.dumps(summary, indent=2))
        return
    if not output:
        err_console.print("[red]Error:[/red] graph export requires --output")
        raise typer.Exit(1)
    export_path = Path(output).expanduser()
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_path.write_text(
        json.dumps({"summary": summary, "graph": graph}, indent=2) + "\n", encoding="utf-8"
    )
    console.print(f"[green]Graph export written:[/green] {export_path}")


@app.command("coverage")
def coverage_command(
    state_file: Path = typer.Option(  # noqa: B008
        ..., "--state", help="Path to a redacted state JSON artifact."
    ),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table or json."),
) -> None:
    """Show measured campaign coverage from an operator-provided state artifact."""
    if output not in {"table", "json"}:
        err_console.print("[red]Error:[/red] coverage output must be table or json")
        raise typer.Exit(1)
    try:
        state = json.loads(state_file.expanduser().read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]Error:[/red] cannot read state artifact: {exc}")
        raise typer.Exit(1) from exc
    if not isinstance(state, dict):
        err_console.print("[red]Error:[/red] state artifact must contain a JSON object")
        raise typer.Exit(1)
    metrics = CoverageIntelligence().metrics(state)
    if output == "json":
        console.print(json.dumps(metrics, indent=2))
        return
    table = Table(title="Coverage Metrics", border_style="cyan")
    table.add_column("Metric")
    table.add_column("Value")
    for key, value in metrics.items():
        table.add_row(str(key), str(value))
    console.print(table)


@app.command("findings")
def findings_command(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    status: str | None = typer.Option(None, "--status"),
    severity: str | None = typer.Option(None, "--severity"),
    confidence: str | None = typer.Option(None, "--confidence"),
) -> None:
    """List redacted finding metadata with optional lifecycle filters."""
    _path, document = _manifest_or_exit(manifest)
    rows = document.get("findings", [])
    if status:
        rows = [
            row
            for row in rows
            if isinstance(row, dict) and str(row.get("status", "")).lower() == status.lower()
        ]
    if severity:
        rows = [
            row
            for row in rows
            if isinstance(row, dict) and str(row.get("severity", "")).lower() == severity.lower()
        ]
    if confidence:
        rows = [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("confidence", "")).lower() == confidence.lower()
        ]
    if not rows:
        console.print("[dim]No matching findings.[/dim]")
        return
    table = Table(title=f"Findings ({len(rows)})", border_style="grey50", header_style="bold cyan")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("Title")
    for row in rows:
        if isinstance(row, dict):
            table.add_row(
                str(row.get("id", "")),
                str(row.get("severity", "")),
                str(row.get("status", "")),
                str(row.get("confidence", "")),
                str(row.get("title", ""))[:120],
            )
    console.print(table)


@app.command("evidence")
def evidence_command(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """List canonical evidence references; raw bodies and secret values are never printed."""
    _path, document = _manifest_or_exit(manifest)
    refs = document.get("evidence_refs", [])
    if not refs:
        console.print("[dim]No evidence references recorded.[/dim]")
        return
    table = Table(title="Evidence References", border_style="grey50", header_style="bold cyan")
    table.add_column("ID")
    table.add_column("Kind")
    table.add_column("Hash")
    table.add_column("Redacted")
    for ref in refs:
        if isinstance(ref, dict):
            table.add_row(
                str(ref.get("id", "")),
                str(ref.get("kind", "")),
                str(ref.get("hash", ref.get("sha256", "")))[:32],
                "yes" if ref.get("redacted", True) else "no",
            )
    console.print(table)


@app.command("investigate")
def investigate_command(
    identifier: str = typer.Argument(..., help="Finding or hypothesis identifier."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    reason: str = typer.Option("operator-requested revisit", "--reason", max=240),
) -> None:
    """Create a bounded revisit task; no PoC or network action is executed."""
    from webpent.cli.manifest import save_manifest

    path, document = _manifest_or_exit(manifest)
    tasks = document.setdefault("investigations", [])
    if any(isinstance(item, dict) and item.get("id") == identifier for item in tasks):
        console.print("[yellow]Investigation already exists; no duplicate task created.[/yellow]")
        return
    task = {
        "id": identifier,
        "status": "pending",
        "reason": reason,
        "max_depth": 1,
        "max_steps": 3,
        "destructive_poc": False,
        "approval_required": True,
        "created_at": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat(),
    }
    tasks.append(task)
    save_manifest(path, document)
    console.print(f"[green]Bounded investigation queued:[/green] {identifier} (no execution)")


@app.command("report")
def report_command(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    output: str | None = typer.Option(None, "--output", "-o"),
    format: str = typer.Option("json", "--format", help="json or html"),
) -> None:
    """Export a redacted manifest-backed report in JSON or HTML."""
    import html

    _path, document = _manifest_or_exit(manifest)
    if format not in {"json", "html"}:
        err_console.print("[red]Error:[/red] report format must be json or html")
        raise typer.Exit(1)
    output_path = Path(output).expanduser() if output else Path("webpent-report." + format)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if format == "json":
        output_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    else:
        title = html.escape(str(document.get("engagement", {}).get("name", "WebPent Report")))
        findings = document.get("findings", [])
        items = "".join(
            f"<li>{html.escape(str(item.get('title', item.get('id', ''))))}</li>"
            for item in findings
            if isinstance(item, dict)
        )
        output_path.write_text(
            "<!doctype html><meta charset='utf-8'><title>"
            + title
            + "</title><h1>"
            + title
            + "</h1><h2>Findings</h2><ul>"
            + items
            + "</ul>",
            encoding="utf-8",
        )
    console.print(f"[green]Report written:[/green] {output_path}")
