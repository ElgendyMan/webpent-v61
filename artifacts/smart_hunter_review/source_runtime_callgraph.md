# Source/runtime callgraph review

The current graph reaches `smart_campaigns` and `smart_campaigns_execution` before returning to the legacy strategist/validator path. `KnowledgeGapEngine`, `SmartNextBestActionEngine`, and `ResearchSession` are called by the smart campaign adapter. `ActionExecutor` is used by the bounded smart executor. `ProofBundle` is consumed by the report-quality gate. The distinct controller-owned services listed in Phase 13 are not all registered as graph nodes; this remains a qualification gap.
