# src/webpent/agents/execution_sandbox/agent.py
"""webpent.agents.execution_sandbox.agent

LangGraph node that actively exploits XSS payloads via Playwright by
submitting them into discovered forms and detecting triggered dialogs.

V3 Phase 1 upgrades the sandbox from a passive skeleton to an active
browser driver. For each finding's queued payloads, the node:

  1. Launches a headless Chromium browser via Playwright.
  2. Injects any cookies from ``auth_state``.
  3. Navigates to the finding's URL.
  4. Locates the first ``<form>`` and fills visible inputs with the payload.
  5. Registers a ``page.on("dialog", ...)`` listener for XSS detection.
  6. Clicks submit.
  7. If a dialog fires, mutates the finding to CONFIRMED.
"""

from __future__ import annotations

import contextlib
import logging
import time
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from langchain_core.messages import AIMessage

from webpent.memory.db import get_db_manager
from webpent.models.findings import Confidence, Finding, VulnClass
from webpent.models.proof_bundle import build_proof_bundle, validate_proof_bundle
from webpent.shared.poc_policy import derive_execution_risk, evaluate_execution_gate
from webpent.shared.stealth import apply_jitter, enforce_min_interval, extract_host
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_PLAYWRIGHT_CONFIRMED_MARKER = "confirmed-by:playwright-dialog"
_TEXT_INPUT_SELECTOR = (
    "input[type='text'], input[type='search'], input[type='url'], "
    "input[type='email'], input:not([type])"
)
_SUBMIT_SELECTOR = "input[type='submit'], button[type='submit'], button:not([type])"
_NAV_TIMEOUT_MS = 15_000
# V3.5 Phase 3: Hard wall-clock limit for each payload test (60 seconds).
# Prevents adversarial pages from hanging the worker indefinitely via
# infinite loops, excessive redirects, or deliberate slowdowns.
_PAYLOAD_TEST_TIMEOUT_S = 60


def _has_payloads(state: PentestState) -> bool:
    payloads = state.get("payloads_to_test") or {}
    return any(len(pl) > 0 for pl in payloads.values())


def _try_launch_browser(target_hostnames: list[str] | None = None):
    """Launch a headless Chromium instance, pinning DNS for known targets.

    V6 Final-Seal-Revised: ``target_hostnames`` (typically the distinct
    hosts across the findings this sandbox run is about to test) are
    resolved and pinned via ``--host-resolver-rules`` BEFORE the browser
    exists, closing the DNS-rebinding TOCTOU race for those hosts
    without touching TLS SNI (see ``shared/http.py``'s
    ``build_host_resolver_rules_args`` docstring for why URL rewriting
    was the wrong mechanism). Hosts discovered only at request time
    (redirects, subresources) remain covered by the block-only route
    handler installed via ``install_playwright_ssrf_guard``.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.error(
            "playwright is not installed. Install it with "
            "'pip install playwright' and run 'playwright install chromium'."
        )
        return None, None
    launch_args: list[str] = []
    if target_hostnames:
        try:
            from webpent.shared.http import build_host_resolver_rules_args
            launch_args = build_host_resolver_rules_args(*target_hostnames)
        except Exception as exc:
            logger.warning(
                "Failed to build --host-resolver-rules for %s (%s) — "
                "launching without DNS pinning; the route-handler block "
                "remains active as a backstop.",
                target_hostnames, exc,
            )
    try:
        pw = sync_playwright().start()
        from webpent.shared.capability_manifest import resolve_browser_executable

        executable_path = resolve_browser_executable()
        launch_kwargs: dict[str, Any] = {"headless": True, "args": launch_args}
        if executable_path:
            launch_kwargs["executable_path"] = executable_path
        browser = pw.chromium.launch(**launch_kwargs)
        return pw, browser
    except Exception as exc:
        logger.error("Failed to launch Chromium: %s", exc)
        with contextlib.suppress(Exception):
            if "pw" in locals() and pw is not None:
                pw.stop()
        return None, None


def _inject_cookies(context, url: str, auth_state: dict[str, Any]) -> None:
    # V4.5 Sprint 2: Inject cookies from both auth_state and login session.
    cookies = auth_state.get("cookies") if auth_state else None
    if cookies and isinstance(cookies, list):
        try:
            context.add_cookies(cookies)
            logger.debug("Injected %d auth_state cookie(s) for %s", len(cookies), url)
        except Exception as exc:
            logger.warning("Failed to inject auth_state cookies for %s: %s", url, exc)

    # V4.5 Sprint 2: Also inject cookies from the pre-authentication login.
    if _LAST_LOGIN_COOKIES:
        login_cookies = [
            {"name": k, "value": v, "domain": urlparse(url).hostname or "", "path": "/"}
            for k, v in _LAST_LOGIN_COOKIES.items()
        ]
        try:
            context.add_cookies(login_cookies)
            logger.debug("Injected %d login cookie(s) for %s", len(login_cookies), url)
        except Exception as exc:
            logger.warning("Failed to inject login cookies for %s: %s", url, exc)


def _fill_form_and_submit(page, payload: str) -> bool:
    """Fill the first form on the page with ``payload`` and submit.

    V3.5: Now supports ``<input type="file">`` elements. Upon detecting
    a file input, a benign temporary file is generated and uploaded via
    Playwright's ``set_input_files()``. The temp file is deleted in a
    ``finally`` block.
    """
    import os
    import tempfile

    temp_file_path: str | None = None

    try:
        form = page.query_selector("form")
        if form is None:
            logger.debug("No <form> found on page — cannot inject payload")
            return False

        filled = 0

        # --- Handle text inputs ---
        inputs = form.query_selector_all(_TEXT_INPUT_SELECTOR)
        for inp in inputs:
            try:
                inp.fill(payload)
                filled += 1
            except Exception:
                continue

        # --- Handle file inputs (V3.5) ---
        file_inputs = form.query_selector_all("input[type='file']")
        if file_inputs:
            # Generate a benign temporary file with the payload text.
            # This allows testing file-upload endpoints for injection
            # vulnerabilities (e.g., web shell upload, XXE via SVG).
            try:
                fd, temp_file_path = tempfile.mkstemp(
                    suffix=".txt", prefix="webpent_test_"
                )
                with os.fdopen(fd, "w") as f:
                    f.write(payload)
                logger.debug("Created temp file for upload: %s", temp_file_path)
            except Exception as exc:
                logger.warning("Failed to create temp file for upload: %s", exc)
                temp_file_path = None

            if temp_file_path is not None:
                for finp in file_inputs:
                    try:
                        # Use locator's set_input_files for file upload
                        # ``page.locator(selector).set_input_files(path)``
                        # is the recommended Playwright API.
                        finp.set_input_files(temp_file_path)
                        filled += 1
                    except Exception as exc:
                        logger.debug("File input upload failed: %s", exc)
                        continue

        if filled == 0:
            logger.debug("Form found but no fillable inputs — skipping")
            return False

        submit = form.query_selector(_SUBMIT_SELECTOR) or page.query_selector(_SUBMIT_SELECTOR)
        if submit is None:
            logger.debug("No submit button found — trying form.submit()")
            try:
                page.evaluate("(el) => el.submit()", form)
            except Exception:
                logger.debug("form.submit() failed")
                return False
        else:
            try:
                submit.click()
            except Exception as exc:
                logger.debug("Submit click failed: %s", exc)
                return False
        return True
    except Exception as exc:
        logger.warning("Form fill/submit failed: %s", exc)
        return False
    finally:
        # V3.5: Explicitly delete the temporary file to prevent
        # accumulation of payload files on disk.
        if temp_file_path is not None:
            try:
                os.unlink(temp_file_path)
                logger.debug("Deleted temp file: %s", temp_file_path)
            except Exception as exc:
                logger.debug("Failed to delete temp file %s: %s", temp_file_path, exc)


def _test_payload_with_browser(
    browser, url: str, payload: str, auth_state: dict[str, Any],
    stealth_mode: bool = False,
) -> bool:
    """Test a single payload against ``url`` via Playwright with a hard deadline.

    V3.5 Phase 3: Enforces a strict wall-clock limit of
    :data:`_PAYLOAD_TEST_TIMEOUT_S` seconds per payload test. If the
    limit is exceeded, a ``TimeoutError`` is raised and caught, and the
    payload is marked as failed. This prevents adversarial pages from
    hanging the worker indefinitely.

    V5 Sprint 6: When ``stealth_mode`` is True, inserts randomized
    jitter before the initial navigation and before the form-submit
    action, and enforces the configured minimum inter-request interval
    for the target host. Both delays are accounted against the
    wall-clock deadline so stealth never causes the test to exceed its
    time budget silently.

    Returns ``True`` if a JavaScript dialog was triggered (XSS confirmed).
    """
    context = None
    page = None
    dialog_triggered = False
    start_time = time.time()

    # V5 Sprint 6: pre-navigation stealth delay. Skip if doing so would
    # blow the per-payload deadline — stealth must never cause a test
    # to time out without attempting the actual navigation.
    if stealth_mode:
        elapsed = time.time() - start_time
        if elapsed < _PAYLOAD_TEST_TIMEOUT_S - 1.0:
            apply_jitter(stealth_mode, label=f"playwright-navigate:{url}")
            enforce_min_interval(stealth_mode, extract_host(url))

    try:
        context = browser.new_context()
        # V6 Zero-Day Patched P0-1: Install SSRF route guard BEFORE
        # context.new_page() / page.goto(). Without this, Playwright
        # would navigate to internal IPs (169.254.169.254, redis:6379,
        # 127.0.0.1) — turning the browser into an SSRF proxy. The
        # guard aborts blocked-host requests with accessdenied.
        from webpent.shared.http import install_playwright_ssrf_guard
        install_playwright_ssrf_guard(context)
        _inject_cookies(context, url, auth_state)
        page = context.new_page()
        page.set_default_navigation_timeout(_NAV_TIMEOUT_MS)

        def _on_dialog(dialog) -> None:
            nonlocal dialog_triggered
            dialog_triggered = True
            logger.info(
                "Dialog detected (%s) at %s — XSS confirmed with payload: %s",
                dialog.type, url, payload[:80],
            )
            with contextlib.suppress(Exception):
                dialog.dismiss()

        page.on("dialog", _on_dialog)

        # --- Navigation (with deadline check) ---
        try:
            page.goto(url, wait_until="domcontentloaded")
        except Exception as exc:
            logger.warning("Navigation to %s failed: %s", url, exc)
            return False

        elapsed = time.time() - start_time
        if elapsed > _PAYLOAD_TEST_TIMEOUT_S:
            raise TimeoutError(
                f"Payload test exceeded {_PAYLOAD_TEST_TIMEOUT_S}s deadline "
                f"during navigation (elapsed: {elapsed:.1f}s)"
            )

        # --- Form fill and submit (with deadline check) ---
        # V5 Sprint 6: pre-submit stealth delay. Insert jitter before
        # the form-fill/submit action so the click does not follow the
        # navigation too quickly (a classic bot-detection signal).
        if stealth_mode:
            elapsed = time.time() - start_time
            if elapsed < _PAYLOAD_TEST_TIMEOUT_S - 1.0:
                apply_jitter(stealth_mode, label=f"playwright-submit:{url}")
                enforce_min_interval(stealth_mode, extract_host(url))

        submitted = _fill_form_and_submit(page, payload)
        if not submitted:
            return False

        elapsed = time.time() - start_time
        if elapsed > _PAYLOAD_TEST_TIMEOUT_S:
            raise TimeoutError(
                f"Payload test exceeded {_PAYLOAD_TEST_TIMEOUT_S}s deadline "
                f"during form submission (elapsed: {elapsed:.1f}s)"
            )

        # --- Post-submit wait (capped by remaining deadline) ---
        remaining_ms = max(
            0,
            int((_PAYLOAD_TEST_TIMEOUT_S - (time.time() - start_time)) * 1000),
        )
        wait_ms = min(2000, remaining_ms)
        if wait_ms > 0:
            with contextlib.suppress(Exception):
                page.wait_for_timeout(wait_ms)

        # V4.5 Sprint 3: Stored XSS detection — if no dialog triggered
        # immediately after form submission, revisit the target URL to
        # check if the payload was stored and fires on page load.
        if not dialog_triggered:
            remaining_ms = max(
                0,
                int((_PAYLOAD_TEST_TIMEOUT_S - (time.time() - start_time)) * 1000),
            )
            if remaining_ms > 1000:
                logger.debug(
                    "No immediate dialog — revisiting %s for Stored XSS check",
                    url,
                )
                with contextlib.suppress(Exception):
                    page.goto(url, wait_until="domcontentloaded")
                    revisit_wait = min(2000, remaining_ms)
                    page.wait_for_timeout(revisit_wait)

        return dialog_triggered

    except TimeoutError as exc:
        logger.warning(
            "Payload test for %s hit wall-clock deadline: %s", url, exc
        )
        return False
    except Exception as exc:
        logger.warning("Playwright payload test failed for %s: %s", url, exc)
        return False
    finally:
        if page is not None:
            with contextlib.suppress(Exception):
                page.close()
        if context is not None:
            with contextlib.suppress(Exception):
                context.close()


def _test_finding_payloads(
    browser, finding: Finding, payloads: list[str], auth_state: dict[str, Any],
    stealth_mode: bool = False, thread_id: str | None = None,
) -> Finding:
    for payload in payloads:
        confirmed = _test_payload_with_browser(
            browser, finding.url, payload, auth_state,
            stealth_mode=stealth_mode,
        )
        if confirmed:
            negative_control_payload = "webpent-neutral-control"
            negative_control_triggered = _test_payload_with_browser(
                browser,
                finding.url,
                negative_control_payload,
                auth_state,
                stealth_mode=stealth_mode,
            )
            evidence = {
                "validator": "playwright_xss_replay",
                "positive_payload": payload,
                "positive_signal": True,
                "causal_signal": True,
                "negative_control_payload": negative_control_payload,
                "negative_control_complete": not negative_control_triggered,
                "negative_control_signal": negative_control_triggered,
            }
            if negative_control_triggered:
                logger.warning(
                    "Playwright XSS promotion blocked for %s: neutral control also triggered",
                    finding.id,
                )
                return finding.model_copy(
                    update={
                        "confidence_level": "Needs Human Review",
                        "evidence": {
                            **(finding.evidence or {}),
                            **evidence,
                            "promotion_guard": {
                                "status": "blocked",
                                "reason": "negative_control_triggered",
                            },
                        },
                    }
                )
            bundle = build_proof_bundle(
                engagement_id=str(
                    (finding.evidence or {}).get("engagement_id") or "runtime-unbound"
                ),
                finding_id=str(finding.id),
                evidence=[
                    {"payload": payload, "triggered": True},
                    {"payload": negative_control_payload, "triggered": False},
                ],
                evidence_refs=[
                    f"playwright:{finding.id}:positive",
                    f"playwright:{finding.id}:negative-control",
                ],
                negative_control={"payload": negative_control_payload, "triggered": False},
            ).seal(actor="playwright_execution_sandbox")
            if not validate_proof_bundle(bundle, require_negative_control=True):
                return finding.model_copy(
                    update={
                        "confidence_level": "Needs Human Review",
                        "evidence": {
                            **(finding.evidence or {}),
                            **evidence,
                            "promotion_guard": {
                                "status": "blocked",
                                "reason": "proof_bundle_validation_failed",
                            },
                        },
                    }
                )
            logger.info(
                "Playwright CONFIRMED XSS for finding %s (%s) — upgrading confidence",
                finding.id, finding.title,
            )
            confirmed_finding = finding.model_copy(
                update={
                    "confidence": Confidence.CONFIRMED.value,
                    "payload": f"{_PLAYWRIGHT_CONFIRMED_MARKER}: {payload}",
                    "confidence_level": "Tool-Confirmed",
                    "evidence": {
                        **(finding.evidence or {}),
                        **evidence,
                        "proof_bundle_sealed": True,
                        "proof_bundle": bundle.model_dump(mode="json"),
                        "promotion_guard": {
                            "status": "passed",
                            "proof_bundle_sealed": True,
                        },
                    },
                }
            )
            # V3.5 Obsidian Master Fix: Incrementally persist the confirmed
            # finding to the database immediately, rather than waiting for
            # graph execution to conclude. This prevents data loss if the
            # worker crashes or times out after Playwright confirmation.
            # V10 P0-C: stamp thread_id so the mid-scan save is visible
            # to the API's per-thread query even if the worker never
            # reaches its final _persist_findings call.
            # V10 AUDIT FIX (C2): previously referenced `state.get(...)`
            # but `state` was NOT in scope (function signature lacked
            # it) → NameError caught by except → save_finding NEVER
            # executed. Now `thread_id` is passed as an explicit param.
            try:
                # V6 DX-Final P0 FIX (CISO audit): use shared singleton.
                # V10 P0-C + AUDIT C2: stamp thread_id before saving.
                if thread_id and not getattr(confirmed_finding, "thread_id", None):
                    confirmed_finding = confirmed_finding.model_copy(
                        update={"thread_id": thread_id}
                    )
                get_db_manager().save_finding(confirmed_finding)
                logger.info(
                    "Incrementally persisted Playwright-confirmed finding %s",
                    finding.id,
                )
            except Exception as exc:
                logger.error(
                    "Failed to incrementally persist finding %s: %s",
                    finding.id, exc,
                )
                # V10 P1-3 FIX: stamp ``persistence_failed=True`` on the
                # finding's evidence dict so downstream consumers (the
                # reporter, the API, the operator) can distinguish a
                # genuinely-confirmed finding whose DB write failed from
                # a cleanly-persisted one. Without this flag, the
                # in-memory ``confirmed_finding`` says "Tool-Confirmed"
                # while the DB has no row — a silent discrepancy that
                # the operator cannot detect from the API surface.
                confirmed_finding = confirmed_finding.model_copy(
                    update={
                        "evidence": {
                            **(confirmed_finding.evidence or {}),
                            "persistence_failed": True,
                        }
                    }
                )
            return confirmed_finding
    logger.info(
        "Playwright did not confirm XSS for finding %s — keeping original confidence",
        finding.id,
    )
    return finding


def _perform_login(
    browser: Any, url: str, credentials: dict[str, str]
) -> None:
    """V4.5 Sprint 2: Perform authenticated login via Playwright.

    Navigates to the target URL, locates login fields, fills credentials,
    and submits the form. The browser context retains session cookies
    for subsequent payload tests.

    This function is best-effort — if login fails, the sandbox proceeds
    with unauthenticated testing.
    """
    context = None
    page = None
    try:
        context = browser.new_context()
        # V6 Zero-Day Patched P0-1: Install SSRF route guard BEFORE
        # new_page() / goto(). Same rationale as the main sandbox
        # context — the login navigation must not be allowed to reach
        # internal networks.
        from webpent.shared.http import install_playwright_ssrf_guard
        install_playwright_ssrf_guard(context)
        page = context.new_page()
        page.set_default_navigation_timeout(_NAV_TIMEOUT_MS)

        try:
            page.goto(url, wait_until="domcontentloaded")
        except Exception as exc:
            logger.warning("Login navigation to %s failed: %s", url, exc)
            return

        # Locate the password field — the most reliable login indicator.
        try:
            password_input = page.locator("input[type='password']").first
            password_input.wait_for(state="visible", timeout=5000)
        except Exception:
            logger.info("No password field found at %s — skipping login", url)
            return

        # Try to find a username/email field.
        username_input = None
        for selector in [
            "input[type='text']",
            "input[type='email']",
            "input[name='username']",
            "input[name='user']",
            "input[name='email']",
            "input:not([type])",
        ]:
            try:
                username_input = page.locator(selector).first
                username_input.wait_for(state="visible", timeout=2000)
                break
            except Exception:
                continue

        if username_input is None:
            logger.info("No username field found — skipping login")
            return

        username = credentials.get("username", "")
        password = credentials.get("password", "")

        try:
            username_input.fill(username)
            password_input.fill(password)
        except Exception as exc:
            logger.warning("Failed to fill login fields: %s", exc)
            return

        # Submit the form.
        try:
            submit = page.locator(
                "button[type='submit'], input[type='submit'], "
                "button:has-text('Login'), button:has-text('Log in')"
            ).first
            submit.click(timeout=5000)
        except Exception:
            try:
                password_input.press("Enter")
            except Exception as exc:
                logger.warning("Failed to submit login form: %s", exc)
                return

        # Wait for post-login navigation.
        with contextlib.suppress(Exception):
            page.wait_for_load_state("networkidle", timeout=10_000)

        logger.info("Login completed — session cookies retained in browser context")
    except Exception as exc:
        logger.warning("Playwright login failed: %s", exc)
    finally:
        with contextlib.suppress(Exception):
            if page is not None:
                page.close()
        # Note: context is NOT closed here — the caller's browser retains
        # the context's cookies for subsequent payload tests via the
        # auth_state injection mechanism. The context will be cleaned up
        # when the browser is closed in the finally block of
        # execution_sandbox_node.
        # However, since each payload test creates its own context, we
        # need to extract cookies and pass them via auth_state.
        if context is not None:
            try:
                cookies = context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies if c.get("name")}
                if cookie_dict:
                    logger.info(
                        "Extracted %d session cookie(s) for authenticated testing",
                        len(cookie_dict),
                    )
                    # Store in a module-level variable for _inject_cookies
                    _LAST_LOGIN_COOKIES.clear()
                    _LAST_LOGIN_COOKIES.update(cookie_dict)
            except Exception:
                pass


# Module-level dict to store login cookies between _perform_login and payload tests.
_LAST_LOGIN_COOKIES: dict[str, str] = {}


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def execution_sandbox_node(state: PentestState) -> dict:
    """LangGraph node implementing active browser-based XSS exploitation.

    V4.5 Sprint 2: Adds Playwright pre-flight health check and
    authenticated login before payload execution.

    V5 Sprint 6: Reads ``stealth_mode`` from state and threads it
    through to per-payload tests so jitter is applied before each
    navigation and form-submit action.

    V7 P0: Dev Mode (and the pre-exploitation pause it used to force
    regardless of ``auto_approve``) has been removed. The graph's
    ``interrupt_before=[NODE_EXECUTION_SANDBOX]`` (see
    ``graph/builder.py``) pauses by default. P2 adds a second,
    defense-in-depth gate here: auto-approved high-risk work is surfaced
    for human approval and destructive work is rejected even if a caller
    bypasses the compile-time interrupt.
    """
    # V9 P0 [round-2 wiring audit]: _LAST_LOGIN_COOKIES is a
    # module-level dict (see bottom of file) shared by every call to
    # this node in this worker process, across ALL engagements. It is
    # only ever cleared+repopulated on a successful login later in
    # this function — nothing previously reset it on entry. A worker
    # process that has already handled one engagement (Celery prefork
    # workers persist across many tasks; so does a single asyncio
    # process) would silently inject a PRIOR engagement's still-cached
    # session cookies into THIS engagement's browser context whenever
    # this node runs without a fresh successful login overwriting them
    # first (e.g. this engagement has no `credentials` in state at
    # all, relying solely on operator-supplied session_cookies) — the
    # same cross-engagement leakage class the engagement-scope
    # ContextVar was deliberately built to prevent (see
    # shared/engagement_scope.py and pentest_worker.py's `finally:
    # clear_engagement_target_hosts(token)`), just not applied here.
    # Clearing at entry scopes the cache to this single node
    # invocation, which is its only legitimate use (populated by
    # _perform_login below, read by _inject_cookies for each finding
    # tested further down in this SAME call).
    _LAST_LOGIN_COOKIES.clear()

    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    payloads_to_test: dict[str, list[str]] = dict(state.get("payloads_to_test") or {})
    auth_state: dict[str, Any] = state.get("auth_state") or {}
    credentials: dict[str, str] = state.get("credentials") or {}
    playwright_enabled: bool = state.get("playwright_enabled", True)
    # V5 Sprint 6: read stealth flag from graph state (set by CLI --stealth).
    stealth_mode: bool = bool(state.get("stealth_mode", False))
    # V10 AUDIT FIX (C2): read thread_id from state so it can be passed
    # to _test_finding_payloads for mid-scan persistence stamping.
    thread_id: str | None = state.get("thread_id") or None

    logger.info(
        "Execution sandbox (Playwright) phase entered for target=%s "
        "(%d findings with payloads, stealth=%s)",
        target.url, len(payloads_to_test), stealth_mode,
    )

    # V7 P0 + P2: compile-time HITL remains the primary gate, while this
    # execution-side check protects resumed or directly-invoked nodes.
    gate = evaluate_execution_gate(state)
    gate_record = {
        "status": gate.status,
        "risk_level": derive_execution_risk(state),
        "reason": gate.reason,
        "human_approval_required": gate.status == "needs_approval",
    }
    if not gate.allowed:
        logger.warning(
            "Execution sandbox blocked by safety gate: status=%s risk=%s",
            gate.status,
            gate_record["risk_level"],
        )
        return {
            "execution_gate": gate_record,
            "messages": [
                AIMessage(
                    content=(
                        "Execution sandbox blocked by safety policy: "
                        f"{gate.status} ({gate_record['risk_level']})."
                    )
                )
            ],
            "current_phase": "sandbox_execution",
        }

    # V4.5 Sprint 2: Pre-flight health check — skip if disabled.
    if not playwright_enabled:
        logger.info("Playwright disabled by pre-flight check — skipping sandbox")
        return {
            "execution_gate": gate_record,
            "messages": [AIMessage(content="Execution sandbox: Playwright disabled (pre-flight).")],
            "current_phase": "sandbox_execution",
        }

    if not _has_payloads(state):
        logger.info("No payloads to test — skipping Playwright execution")
        return {
            "execution_gate": gate_record,
            "messages": [AIMessage(content="Execution sandbox: no payloads queued — skipping.")],
            "current_phase": "sandbox_execution",
        }

    findings_by_id: dict[UUID, Finding] = {f.id: f for f in findings}

    # V6 Final-Seal-Revised: pin DNS for every distinct host among the
    # findings about to be tested, so Playwright's TCP connections go
    # straight to a pre-validated IP without a second, connection-time
    # DNS lookup (closing the rebinding race) — see _try_launch_browser.
    _target_hosts = sorted({
        urlparse(f.url).hostname
        for f in findings
        if f.url and urlparse(f.url).hostname
    })
    pw, browser = _try_launch_browser(_target_hosts)
    if browser is None:
        logger.error("Could not launch Playwright browser — skipping sandbox execution")
        return {
            "execution_gate": gate_record,
            "messages": [AIMessage(content="Execution sandbox: Playwright unavailable — skipped.")],
            "current_phase": "sandbox_execution",
        }

    # V4.5 Sprint 2: Perform authenticated login if credentials are provided.
    if credentials:
        logger.info("Credentials provided — performing pre-authentication login")
        # V5 Sprint 6: pace the login navigation in stealth mode so the
        # auth flow does not stand out as machine-paced traffic.
        if stealth_mode:
            apply_jitter(stealth_mode, label=f"playwright-login:{target.url}")
            enforce_min_interval(stealth_mode, extract_host(target.url))
        _perform_login(browser, target.url, credentials)

    confirmed_count = 0
    tested_count = 0

    try:
        for finding_id_str, payloads in payloads_to_test.items():
            try:
                finding_id = UUID(finding_id_str)
            except ValueError:
                logger.warning("Malformed finding ID: %r", finding_id_str)
                continue

            finding = findings_by_id.get(finding_id)
            if finding is None:
                logger.warning("Finding %s not in state — skipping", finding_id)
                continue
            if not payloads:
                continue
            # V9 P0 [round-2 wiring audit]: defense-in-depth — as of
            # this fix, payload_generator_node only ever seeds
            # payloads_to_test for XSS findings (see
            # _PAYLOAD_CONSUMING_CLASSES there), so this should always
            # be true. This check protects a RESUMED engagement whose
            # checkpointed state was written before that fix (a stale
            # sqli/csrf/ssrf/rce/deserialization entry). Without it, a
            # non-XSS finding would be form-submitted with an
            # LLM-generated "payload" string and, if any unrelated
            # on-page JS happens to fire a dialog, get wrongly marked
            # Confidence.CONFIRMED via the playwright-dialog marker
            # despite having no relationship to that finding's actual
            # vuln_class.
            if finding.vuln_class != VulnClass.XSS.value:
                logger.debug(
                    "Skipping browser payload test for finding %s: "
                    "vuln_class=%s is not browser-payload-driven "
                    "(stale payloads_to_test entry from before the "
                    "wiring fix, or a resumed pre-fix checkpoint).",
                    finding_id, finding.vuln_class,
                )
                continue

            tested_count += 1
            updated = _test_finding_payloads(
                browser, finding, payloads, auth_state,
                stealth_mode=stealth_mode,
                thread_id=thread_id,
            )
            if updated.confidence == Confidence.CONFIRMED.value:
                confirmed_count += 1
                findings_by_id[finding_id] = updated
    finally:
        with contextlib.suppress(Exception):
            if browser is not None:
                browser.close()
        with contextlib.suppress(Exception):
            if pw is not None:
                pw.stop()

    updated_findings: list[Finding] = [
        findings_by_id[f.id] for f in findings if f.id in findings_by_id
    ]

    summary = (
        f"Execution sandbox (Playwright) completed. Tested {tested_count} "
        f"finding(s); {confirmed_count} confirmed via dialog detection."
    )
    logger.info(summary)

    return {
        "findings": updated_findings,
        "execution_gate": gate_record,
        "messages": [AIMessage(content=summary)],
        "current_phase": "sandbox_execution",
    }
