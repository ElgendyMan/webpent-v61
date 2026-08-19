"""Read-only subdomain takeover verification.

The detector is deliberately evidence-first.  It never claims takeover from a
CNAME alone: it requires an in-scope hostname, a provider signature, and an
HTTP response fingerprint consistent with an unclaimed resource.  DNS and HTTP
failures are retained as observations rather than promoted to findings.
"""

from __future__ import annotations

import logging
import re
import socket
from typing import Any
from urllib.parse import urlparse

from webpent.models.findings import Finding, Severity
from webpent.models.targets import Target
from webpent.shared.http import make_safe_httpx_client

logger = logging.getLogger(__name__)

_PROVIDER_SIGNATURES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "github-pages": (
        ("github.io",),
        (
            "There isn't a GitHub Pages site here.",
            "For root URLs",
        ),
    ),
    "heroku": (("herokuapp.com",), ("No such app", "no-such-app")),
    "azure": (
        ("azurewebsites.net", "cloudapp.azure.com"),
        ("404 Web Site not found", "ResourceNotFound"),
    ),
    "aws-s3-website": (
        ("s3-website", "amazonaws.com"),
        ("NoSuchBucket", "The specified bucket does not exist"),
    ),
    "netlify": (("netlify.app", "netlify.com"), ("Not found - Request ID", "NETLIFY_NOT_FOUND")),
    "vercel": (("vercel.app",), ("DEPLOYMENT_NOT_FOUND", "The deployment could not be found")),
}


def _candidate_hosts(state: dict[str, Any]) -> list[str]:
    """Collect hosts already discovered by the engagement; never enumerate out of scope."""
    target: Target | None = state.get("target")
    values: list[Any] = []
    if target:
        values.extend([target.domain, urlparse(target.url).hostname])
    for key in ("subdomains", "hosts", "live_hosts", "recon_results"):
        values.append(state.get(key))
    crawled = state.get("crawled_data") or {}
    values.append(crawled)

    hosts: set[str] = set()
    host_re = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                visit(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            candidate = value.strip().lower()
            parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
            host = parsed.hostname or candidate.split("/")[0].split(":")[0]
            if host and host_re.fullmatch(host):
                hosts.add(host.rstrip("."))

    for value in values:
        visit(value)
    return sorted(hosts)


def _resolve_cname(host: str) -> str | None:
    """Resolve a CNAME without failing the scan when optional dnspython is absent."""
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(host, "CNAME", lifetime=3.0)
        for answer in answers:
            return str(answer.target).rstrip(".").lower()
    except Exception:
        pass
    try:
        _name, aliases, _addresses = socket.gethostbyname_ex(host)
        for alias in aliases:
            if alias and alias.lower() != host.lower():
                return alias.rstrip(".").lower()
    except Exception:
        return None
    return None


def _provider_for_cname(cname: str | None) -> tuple[str, tuple[str, ...]] | None:
    if not cname:
        return None
    lower = cname.lower().rstrip(".")
    for provider, (cname_markers, body_markers) in _PROVIDER_SIGNATURES.items():
        if any(marker in lower for marker in cname_markers):
            return provider, body_markers
    return None


def _safe_headers(response: Any) -> dict[str, str]:
    blocked = {"set-cookie", "authorization", "proxy-authorization", "cookie"}
    return {str(k): str(v) for k, v in response.headers.items() if str(k).lower() not in blocked}


def verify_subdomain_takeover(
    target: Target,
    hosts: list[str] | None = None,
    *,
    timeout: float = 8.0,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return confirmed findings, observations, and coverage gaps."""
    findings: list[Finding] = []
    observations: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    candidates = hosts or _candidate_hosts({"target": target})

    for host in candidates:
        url = f"https://{host}/"
        if not target.is_in_scope(url):
            observations.append({"host": host, "status": "out_of_scope", "evidence": {}})
            continue
        cname = _resolve_cname(host)
        provider = _provider_for_cname(cname)
        row: dict[str, Any] = {"host": host, "cname": cname, "status": "inconclusive"}
        if not provider:
            row["status"] = "no_provider_signature"
            observations.append(row)
            continue
        provider_name, body_markers = provider
        row["provider"] = provider_name
        try:
            with make_safe_httpx_client(
                timeout=timeout, follow_redirects=False, verify=True
            ) as client:
                response = client.get(
                    url, headers={"User-Agent": "WebPent/readonly-takeover-check"}
                )
            body = response.text[:20000]
            matched = [marker for marker in body_markers if marker.lower() in body.lower()]
            row.update(
                {
                    "status_code": response.status_code,
                    "matched_markers": matched,
                    "headers": _safe_headers(response),
                }
            )
            if matched:
                row["status"] = "provider_fingerprint_match"
                finding = Finding(
                    title=f"Potential {provider_name} subdomain takeover at {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"The in-scope hostname {host} resolves to a {provider_name} service "
                        "and returned a provider-specific unclaimed-resource fingerprint. "
                        "This is a read-only confirmation candidate; ownership must be "
                        "verified before remediation."
                    ),
                    tool_name="subdomain_takeover_agent",
                    payload=None,
                    url=url,
                    confidence_level="Tool-Confirmed",
                    vuln_class="subdomain_takeover",
                    reasoning=(
                        "CNAME provider signature and provider-specific HTTP fingerprint matched."
                    ),
                    evidence_bundle={
                        "hostname": host,
                        "cname": cname,
                        "provider": provider_name,
                        "status_code": response.status_code,
                        "matched_markers": matched,
                        "headers": _safe_headers(response),
                    },
                    references=[
                        "https://owasp.org/www-community/attacks/Hostile_subdomain_takeover"
                    ],
                    business_impact=(
                        "An abandoned DNS alias can allow an attacker to claim the delegated "
                        "service and serve content under the organization’s hostname."
                    ),
                )
                findings.append(finding)
            else:
                row["status"] = "provider_responded_without_takeover_fingerprint"
        except Exception as exc:
            row["status"] = "probe_failed"
            row["error_type"] = type(exc).__name__
            gaps.append(
                {
                    "host": host,
                    "reason": "HTTP verification failed",
                    "error_type": type(exc).__name__,
                }
            )
        observations.append(row)
    return findings, observations, gaps


def subdomain_takeover_node(state: dict[str, Any]) -> dict[str, Any]:
    target: Target | None = state.get("target")
    if target is None:
        return {
            "current_phase": "subdomain_takeover",
            "errors": ["No target configured for takeover check."],
        }
    findings, observations, gaps = verify_subdomain_takeover(target, _candidate_hosts(state))
    return {
        "findings": findings,
        "subdomain_takeover_observations": observations,
        "subdomain_takeover_coverage_gaps": gaps,
        "current_phase": "subdomain_takeover",
    }


__all__ = [
    "verify_subdomain_takeover",
    "subdomain_takeover_node",
    "_resolve_cname",
    "_candidate_hosts",
]
