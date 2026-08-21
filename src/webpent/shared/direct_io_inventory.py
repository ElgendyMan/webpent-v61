"""Complete direct-I/O transport inventory and static enforcement helpers.

G-02 contract: every external transport entry point is either implemented in a
hardened boundary or explicitly catalogued as a constrained exception.  The
inventory is intentionally source-based so a newly added direct transport
cannot hide behind a capability name or an adapter description.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

DIRECT_IMPORT_ROOTS = frozenset(
    {
        "httpx",
        "requests",
        "aiohttp",
        "urllib.request",
        "socket",
        "subprocess",
        "playwright",
        "selenium",
        "websockets",
        "boto3",
        "botocore",
        "paramiko",
    }
)

DIRECT_CALLS = frozenset(
    {
        "httpx.Client",
        "httpx.AsyncClient",
        "httpx.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "requests.Session",
        "requests.request",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "aiohttp.ClientSession",
        "urllib.request.urlopen",
        "socket.create_connection",
        "socket.socket",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.getfqdn",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "sync_playwright",
        "async_playwright",
        "webdriver.Remote",
        "websockets.connect",
        "boto3.client",
        "boto3.resource",
        "paramiko.SSHClient",
    }
)

SAFE_BOUNDARY_CALLS = frozenset(
    {
        "make_safe_httpx_client",
        "make_safe_httpx_async_client",
        "run_command",
    }
)

# The only files allowed to instantiate a raw external transport.  Callers
# must use the safe boundary helpers or the explicitly catalogued constrained
# exception below.
APPROVED_DIRECT_FILES = {
    "src/webpent/shared/http.py": "hardened_httpx_and_dns_boundary",
    "src/webpent/tools/utils/subprocess.py": "bounded_subprocess_boundary",
    "src/webpent/cli/git_source.py": "bounded_git_source_subprocess",
    "src/webpent/shared/capability_manifest.py": "read_only_tool_capability_probe",
    "src/webpent/shared/preflight.py": "read_only_playwright_capability_probe",

    "src/webpent/agents/authentication/agent.py": "scoped_playwright_auth_flow",
    "src/webpent/agents/execution_sandbox/agent.py": "scoped_playwright_xss_replay",
    "src/webpent/agents/validator/agent.py": "scoped_playwright_csrf_replay",
    "src/webpent/cli/__init__.py": "bounded_playwright_preflight",
    "src/webpent/agents/request_smuggling/agent.py": "scoped_raw_tcp_validator",
    "src/webpent/agents/subdomain_takeover/agent.py": "scoped_dns_resolution_validator",
}

# Logical transports are listed separately because API, GraphQL, upload and
# OOB are protocols over HTTP rather than separate socket implementations.
LOGICAL_TRANSPORTS = {
    "http": {
        "boundary": "webpent.shared.http.make_safe_httpx_client",
        "authority": "ActionAuthority/action_family=http_read|validation",
        "proof": "response evidence plus verifier contract where promotion is requested",
    },
    "browser": {
        "boundary": "Playwright sites listed in APPROVED_DIRECT_FILES",
        "authority": "scope checks, playwright_enabled, and action policy",
        "proof": "browser observation; confirmation additionally requires ProofBundle",
    },
    "api": {
        "boundary": "http",
        "authority": "API testing action family and target-origin scope",
        "proof": "replay observation and strict verifier",
    },
    "graphql": {
        "boundary": "http",
        "authority": "API/validation action family and target-origin scope",
        "proof": "query/response replay observation and strict verifier",
    },
    "file_upload": {
        "boundary": "http",
        "authority": "form_submit/file_upload policy and target-origin scope",
        "proof": "upload response/replay observation and strict verifier",
    },
    "oob": {
        "boundary": "http plus configured callback receiver",
        "authority": "OOB preconditions, callback secret and target scope",
        "proof": "correlated callback plus negative control and strict verifier",
    },
    "subprocess": {
        "boundary": "webpent.tools.utils.subprocess.run_command or catalogued probes",
        "authority": "tool allowlist, timeout, argv validation and action policy",
        "proof": "bounded tool result; no confirmation without verifier evidence",
    },
    "raw_tcp_dns": {
        "boundary": "catalogued request_smuggling/subdomain_takeover validators",
        "authority": "target scope and validator-specific bounded controls",
        "proof": "validator observation; no implicit promotion",
    },
}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _import_names(node: ast.Import | ast.ImportFrom) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    module = node.module or ""
    return [module if alias.name == "*" else f"{module}.{alias.name}" for alias in node.names]


def _is_direct_import(name: str) -> bool:
    return any(name == root or name.startswith(f"{root}.") for root in DIRECT_IMPORT_ROOTS)


def classify_symbol(symbol: str, kind: str) -> str:
    if kind == "import" and symbol.startswith("playwright"):
        return "browser_implementation"
    if symbol in {"httpx.Client", "make_safe_httpx_client"}:
        return "http_sync"
    if symbol in {"httpx.AsyncClient", "make_safe_httpx_async_client"}:
        return "http_async"
    if symbol in {"sync_playwright", "async_playwright"} or symbol.startswith("playwright"):
        return "browser_playwright"
    if symbol.startswith("socket."):
        return "raw_tcp_dns"
    if symbol.startswith("subprocess.") or symbol.startswith("asyncio.create_subprocess"):
        return "subprocess"
    if symbol == "run_command":
        return "subprocess_boundary"
    if kind == "import" and symbol.startswith("httpx"):
        return "http_implementation"
    if kind == "import" and symbol.startswith("playwright"):
        return "browser_implementation"
    if kind == "import" and symbol == "socket":
        return "raw_tcp_dns_implementation"
    if kind == "import" and symbol == "subprocess":
        return "subprocess_implementation"
    return "unclassified"


def scan_direct_io(root: Path) -> list[dict[str, Any]]:
    """Return sorted direct-I/O and approved-boundary source records."""
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = path.relative_to(root.parent).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for name in _import_names(node):
                    if _is_direct_import(name):
                        kind = "import"
                        records.append(
                            {
                                "file": relative,
                                "line": node.lineno,
                                "kind": kind,
                                "symbol": name,
                                "transport": classify_symbol(name, kind),
                            }
                        )
            elif isinstance(node, ast.Call):
                symbol = _dotted(node.func)
                if symbol in DIRECT_CALLS:
                    kind = "call"
                elif symbol in SAFE_BOUNDARY_CALLS:
                    kind = "safe_boundary_call"
                else:
                    continue
                records.append(
                    {
                        "file": relative,
                        "line": node.lineno,
                        "kind": kind,
                        "symbol": symbol,
                        "transport": classify_symbol(symbol, kind),
                    }
                )
    records.sort(key=lambda item: (str(item["file"]), int(item["line"]), str(item["kind"])))
    return records


def inventory_key(record: dict[str, Any]) -> tuple[str, int, str, str, str]:
    return (
        str(record["file"]),
        int(record["line"]),
        str(record["kind"]),
        str(record["symbol"]),
        str(record["transport"]),
    )
