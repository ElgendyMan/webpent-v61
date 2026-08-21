"""Contracts for the v72 shared LLM routing and cache boundary."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import webpent.shared.llm as llm_router

PROJECT_ROOT = Path(__file__).parents[1]
DETERMINISTIC_MARKER = "# NOTE: deterministic agent"
EXPECTED_AGENT_COUNT = 33

CALLER_MODULES = (
    "src/webpent/agents/validator/agent.py",
    "src/webpent/agents/payload_generator/agent.py",
    "src/webpent/agents/payload_optimizer/agent.py",
    "src/webpent/agents/reporter/agent.py",
    "src/webpent/agents/reflection/agent.py",
    "src/webpent/agents/cvss_engine/agent.py",
    "src/webpent/agents/cross_reasoning/agent.py",
    "src/webpent/agents/business_impact/agent.py",
    "src/webpent/agents/executive_summary/agent.py",
    "src/webpent/agents/exploit_chainer/agent.py",
    "src/webpent/agents/devils_advocate/agent.py",
    "src/webpent/agents/waf_detector/agent.py",
    "src/webpent/agents/rabbit_hole/agent.py",
    "src/webpent/agents/planner/agent.py",
    "src/webpent/agents/crawler/agent.py",
)



def _shared_llm_imports(tree: ast.AST) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "webpent.shared.llm":
            imported.update(alias.asname or alias.name for alias in node.names)
    return imported



def _called_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.add(node.func.id)
    return names



def _assert_no_direct_provider_imports(tree: ast.AST, relative_path: str) -> None:
    provider_imports = {
        "langchain_anthropic",
        "langchain_cohere",
        "langchain_google_genai",
        "langchain_mistralai",
        "langchain_openai",
    }
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not imported_modules.intersection(provider_imports), relative_path


def test_all_agents_have_explicit_llm_or_deterministic_contract() -> None:
    """Every agent must be guarded by the router or explicitly deterministic."""
    paths = sorted((PROJECT_ROOT / "src/webpent/agents").glob("*/agent.py"))
    assert len(paths) == EXPECTED_AGENT_COUNT
    for path in paths:
        relative_path = str(path.relative_to(PROJECT_ROOT))
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        _assert_no_direct_provider_imports(tree, relative_path)
        if DETERMINISTIC_MARKER in source:
            continue
        imports = _shared_llm_imports(tree)
        calls = _called_names(tree)
        assert "try_get_llm" in imports or "get_cached_llm" in imports, relative_path
        assert calls.intersection({"try_get_llm", "get_cached_llm"}), relative_path


def test_all_plan_llm_callers_use_the_shared_guarded_router() -> None:
    """Every listed caller must route through the shared optional-LLM boundary."""
    for relative_path in CALLER_MODULES:
        path = PROJECT_ROOT / relative_path
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = _shared_llm_imports(tree)
        calls = _called_names(tree)

        assert "try_get_llm" in imports or "get_cached_llm" in imports, relative_path
        assert calls.intersection({"try_get_llm", "get_cached_llm"}), relative_path

        _assert_no_direct_provider_imports(tree, relative_path)



def test_cached_llm_entries_are_isolated_by_task_type(monkeypatch) -> None:
    """A cached analysis model must never be returned for a code task."""
    llm_router.clear_cached_llms()
    fake_settings = SimpleNamespace(llm_enabled=True)
    built: list[llm_router.TaskType] = []
    models: dict[llm_router.TaskType, object] = {}

    monkeypatch.setattr(llm_router, "get_settings", lambda: fake_settings)
    monkeypatch.setattr(llm_router, "_resolve_primary_provider", lambda _task_type: None)

    def fake_get(task_type: llm_router.TaskType):
        model = SimpleNamespace(task_type=task_type)
        built.append(task_type)
        models[task_type] = model
        return model

    monkeypatch.setattr(llm_router, "get_llm", fake_get)

    analysis = llm_router.get_cached_llm(llm_router.TaskType.ANALYSIS)
    code = llm_router.get_cached_llm(llm_router.TaskType.CODE)

    assert analysis is models[llm_router.TaskType.ANALYSIS]
    assert code is models[llm_router.TaskType.CODE]
    assert analysis is not code
    assert built == [llm_router.TaskType.ANALYSIS, llm_router.TaskType.CODE]

    metrics = llm_router.get_llm_cache_metrics()
    assert metrics["misses"] == 2
    assert metrics["hits"] == 0

    llm_router.clear_cached_llms()



def test_explicit_settings_remain_outside_default_cache(monkeypatch) -> None:
    """Custom provider settings cannot reuse a process-wide default entry."""
    llm_router.clear_cached_llms()
    explicit = SimpleNamespace(llm_enabled=True)
    cached = SimpleNamespace(source="cached")
    uncached = SimpleNamespace(source="explicit")

    monkeypatch.setattr(llm_router, "get_settings", lambda: explicit)
    monkeypatch.setattr(llm_router, "get_cached_llm", lambda _task_type: cached)
    monkeypatch.setattr(llm_router, "get_llm", lambda _task_type, *, settings: uncached)

    assert llm_router.try_get_llm(llm_router.TaskType.CODE, settings=explicit) is uncached
    assert llm_router.try_get_llm(llm_router.TaskType.CODE) is cached

    llm_router.clear_cached_llms()
