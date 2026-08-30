# WebPent Post-IRTA v2 — Final Project Audit 2026

## 1. Current reality

The repository is a substantial security-research and bounded local-validation system. It contains research intelligence, target knowledge, attack-graph, campaign, DCVU, RTA, IRTA v2, evidence, governance, and regression components. The repository inventory records **539 source Python modules, 366 test-related Python files, 17 benchmark-related modules, and 148 report files** according to the audit scanners. The test-quality classifier recognizes 363 `test_*.py` modules across contract, integration, capability, and benchmark categories; this is a file-level classification, not a claim that every test proves a security capability.

The current Git baseline is the IRTA v2 release commit and the audit has not modified validators, frozen ground truth, thresholds, or official authorization. The full suite baseline recorded 2,270 passed and 7 failures. Ruff and compileall pass. The seven failures are preserved local-lab/attestation blockers.

## 2. Verified capabilities

The following are verified at their stated scope: deterministic independent target-contract generation; four immutable adversarial mutation modes; a bounded five-stage research-loop facade; fail-closed negative-intelligence classification; disposable stateful workflow invariants; local RTA discovery and HTTP mapping; and the existence of DCVU/RTA regression and evidence mechanisms. The IRTA benchmark can construct ten independent seeded targets and four difficulty tiers without fabricating detection observations.

## 3. Partial capabilities

ProofBundle machinery is present, but case-specific independent sealed/replayed coverage is incomplete. Authorization reasoning is demonstrated in controlled local cases, but cross-target detection-quality portability is not established. Business-logic capability is represented by a pure disposable workflow fixture, not by live stateful target evidence. Real authentication is intentionally limited to synthetic controlled contexts. The autonomous controller and research loop are bounded and policy-gated rather than unrestricted.

## 4. Missing or unverified VIP requirements

The audit found no proof that the system is currently a VIP Smart Autonomous Bug Hunter. Missing or unverified requirements include independently approved live causal cases across the target/classes threshold, longitudinal evidence that memory improves future detection, broad browser/JavaScript intelligence, stable multi-target TP/FP/FN quality, independently replayed case-specific ProofBundles at the required scale, official isolated runs, independent review, and external authorized portability. These remain future work and are not represented as current achievements.

## 5. Technical debt and blockers

The seven retained full-suite failures concern local causal-lab readiness, WebGoat/crAPI runtime/source attestation, Option B packet/runner behavior, and source-backed inventory prerequisites. Same-basename scans found 49 candidate groups and placeholder scans found 30 marker-bearing files; neither result proves duplication or dead code. These require targeted ownership and dependency review rather than deletion during an audit.

## 6. Recommended roadmap

The next phase should repair the seven blockers one at a time under the existing governance boundary, beginning with reproducible local runtime/source attestation and the missing Juice Shop source prerequisite. Each repair must have a before/after regression record and must not alter ground truth or convert blocked cases into failures. After readiness, the project needs independently reviewed candidate/control observations, causal oracles, redacted sealed/replayed ProofBundles, and repeated same-condition runs across multiple targets. Only after those gates close should an Owner Decision Packet consider official isolated runs. External targets and Bug Bounty remain out of scope until formal authorization.

## 7. Truth and governance decision

The truthful status is **IRTA v2 engineering-complete for additive local contracts and audit-ready infrastructure, but not VIP-qualified**. `official_isolated_p10_runs_authorized=false` remains mandatory. P10/P9/VIP remain closed, Bug Bounty remains blocked, and no claim of external readiness is supported.

## References

[1]: `reports/audit/repository_inventory.json` — repository inventory generated from the current tree.
[2]: `reports/audit/test_quality_matrix.json` — conservative test-quality classification.
[3]: `docs/audit/feature_matrix.md` — feature traceability matrix.
[4]: `docs/audit/claim_validation_report.md` — claim evidence classification.
[5]: `docs/audit/benchmark_integrity_report.md` — benchmark boundary review.
[6]: `reports/IRTA-v2-Autonomous-Research-Hardening-Report.md` — IRTA v2 implementation report.
