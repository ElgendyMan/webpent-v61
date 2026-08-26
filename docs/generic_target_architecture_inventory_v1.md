# Generic Target-Neutral Architecture Inventory v1

## Purpose

This inventory records the repository boundaries used by the Generic Target-Neutral architecture plan. It is an engineering control document, not a qualification result and not a replacement for frozen P10 governance artifacts.

## Package boundary map

| Boundary | Current repository locations | Allowed responsibility | Target-specific literals allowed? |
|---|---|---|---|
| Generic core | `src/webpent/shared/`, `src/webpent/agents/`, `src/webpent/contracts/`, `src/webpent/models/`, `src/webpent/state/` | Runtime orchestration, contracts, safety, redaction, proof, replay, metrics, lifecycle, generic agent behavior | No routes, selectors, challenge IDs, or target-family branches |
| Target adapters | `src/webpent/adapters/juice_shop/adapter.py`, `src/webpent/adapters/mock_target/adapter.py`, `src/webpent/benchmark/waptlab_target_adapter.py`, and future explicit adapter modules | Origin binding, workflow execution, case mapping, target-local projection, target-local extensions | Yes, only inside the explicit adapter module |
| Target inventories/profiles | `src/webpent/profiles/juice_shop/cases.py`, target-local semantic registries and fixtures | Declarative case inventory, preconditions, workflow bindings, semantic profile declarations | Yes, only inside the target profile/inventory boundary |
| Benchmarks/governance | `docs/juice_shop_p10_*.json`, `docs/p10_*.json`, `audit/`, `benchmarks/` | Frozen truth, review packets, evaluation policy, benchmark records, audit reports | Yes, but never imported as runtime configuration |
| Test targets and fixtures | `tests/`, `tests/fixtures/`, target-specific test modules | Contract tests, fake receipts, mock adapters, redaction and replay tests | Target-specific values only in target-scoped tests |

## Baseline findings

The repository already has an explicit `TargetAdapter` protocol, `RegisteredTargetAdapter`, target-origin registration, semantic profile registries, and target-scoped campaign extensions. The shared runner and validator consume registered extension contracts rather than embedding WAPTLab behavior. This is the correct direction and must be preserved.

The initial generic-core scan found one forbidden target route literal in `src/webpent/shared/semantic_observations.py`: the generic directory-shape heuristic contained `/ftp/`. That literal was removed because a route name is not a target-neutral directory semantic. The heuristic now recognizes only generic directory-listing shapes such as `Index of`, `Directory listing`, and `Parent Directory`; a target adapter may register its own target-local profile and route mapping separately.

The scan did not identify direct imports of Juice Shop or WAPTLab adapter modules from the generic-core roots. The old `src/webpent/benchmark/juice_shop_*.py` paths remain compatibility shims only; the executable Juice Shop implementation is now under `src/webpent/adapters/juice_shop/` and `src/webpent/profiles/juice_shop/`. The new guard is `scripts/check_generic_target_neutrality.py` and fails closed on forbidden target literals and imports in the generic-core roots.

## Reference handling decisions

| Reference type | Decision | Rationale |
|---|---|---|
| Target route or route fragment | Keep in explicit adapter/profile | The route is not a generic proof condition and must not enter shared code |
| Target selector or browser locator | Keep in explicit adapter workflow executor | Browser actions are target-local and require a reviewed workflow contract |
| Target-specific semantic profile name | Keep in target adapter registry | A generic observation engine may evaluate a generic rule only when explicitly supplied by the adapter |
| Generic semantic shape | Keep in shared observation engine | It is bounded, redacted, and does not identify a target |
| Frozen P10 path/workflow values | Keep only in frozen benchmark artifacts and target adapter mapping | Frozen governance files are not runtime configuration and must not be edited to make code pass |
| Target-specific campaign callback | Keep behind `CampaignExtensionSpec` and live registration | Callback objects must not enter descriptors or checkpoints |

## Guardrail invocation

```text
PYTHONPATH=src .venv/bin/python scripts/check_generic_target_neutrality.py
```

The guard is expected to be part of CI before merge of changes touching shared/core packages. A failure is a boundary violation, not a reason to weaken the scanner or to move frozen governance values.

## Current limitations

This inventory does not claim that the platform is P10-qualified or universally target-neutral at runtime. Workflow canonicalization, a second-target swap suite, complete per-case causal contracts, and live sealed/replayable evidence remain separate gates. In particular, the P10 gap matrix remains the source of truth for the current 11-case proof gaps.

## Validation gate result

The bounded fixture validation passed without network I/O: full contract tests, target swap tests, redaction tests, sealed/replay tests, neutrality scanning, and fail-closed manifest checks all passed. A live Juice Shop run was not started because no loopback target listener was present and the frozen P10 governance state still has `reviewer_approval=false`, null metrics, and no full-run approval. Therefore no live causal signal, negative control, sealed bundle, replay result, or benchmark metric is claimed by this implementation cycle.

> Juice Shop is a validation target, not the product architecture. Generic readiness must be demonstrated with an explicit second adapter and target-neutral proof tests, not inferred from Juice Shop results.
