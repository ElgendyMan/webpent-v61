# WebPent IRTA v2 — Autonomous Research Hardening

## What changed

This release adds an independent deterministic target generator, adversarial auth/response mutations, a bounded evidence-aware research loop, false-positive suppression with clean-reason bundles, disposable stateful business-logic workflows, difficulty tiers, benchmark construction, and cross-run learning measurements. All additions are isolated under `src/webpent/irta/`.

## What was not changed

No existing feature was deleted. Existing validators, frozen ground truth, qualification thresholds, RTA transport constraints, and official governance gates were not modified. The Generic Core contains no target-specific logic.

## Tests

The focused IRTA suite contains 13 tests and passes. Ruff and compileall pass for the new code. The complete repository run is recorded in `reports/IRTA-v2-Autonomous-Research-Hardening-Report.md` and retains seven legacy/local-lab failures without masking or reclassifying them.

## Metrics

The independent benchmark constructs 10 generated targets, 4 difficulty tiers, and 160 planned case slots. Unexecuted cases are fail-closed and remain blocked; they are not counted as TP, TN, FP, or FN. Existing RTA metrics remain historical local evidence and do not represent official qualification.

## Known limitations

The generated targets are executable specifications, not live servers. Live loopback adapters still require separate authorized fixture work and independent causal ground truth. Adversarial mutations are modeled at the contract level and require same-condition live validation before any detection-quality claim. The seven legacy blockers remain documented.

## Governance status

The project remains **NOT_QUALIFIED**. `official_isolated_p10_runs_authorized=false` remains in force. P10, P9, VIP qualification, Bug Bounty access, external targets, real credentials, destructive actions, and policy changes remain closed.

## Reproduction steps

```bash
cd /tmp/webpent-work
PYTHONPATH=src pytest -q tests/irta
ruff check src/webpent/irta tests/irta
python3 -m compileall -q src/webpent/irta tests/irta
PYTHONPATH=src python3 -c "from webpent.irta.metrics import IrtaBenchmark; print(IrtaBenchmark().build(tuple(range(10))))"
```

The full repository verification is reproducible with:

```bash
PYTHONPATH=src:integrations/bbscout/src pytest -q
ruff check .
python3 -m compileall -q src tests benchmarks
```
