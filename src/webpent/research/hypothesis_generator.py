"""Deterministic, evidence-linked hypothesis generation."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

from webpent.attack_graph.chain_reasoning import VulnerabilityChainReasoner
from webpent.intelligence.contracts import ResearchHypothesis
from webpent.knowledge.model_v2 import KnowledgeEntityKind, TargetKnowledgeV2
from webpent.models.attack_graph import AttackGraph
from webpent.models.findings import Severity, VulnClass


@dataclass(frozen=True)
class VulnerabilityPattern:
    """A safe pattern description; it does not contain payloads or actions."""

    name: str
    vuln_class: VulnClass
    required_capability: str
    risk: Severity
    required_relations: tuple[str, ...]
    required_entity_kinds: tuple[KnowledgeEntityKind, ...]
    evidence_needed: tuple[str, ...]
    validation_steps: tuple[str, ...]


DEFAULT_PATTERNS: tuple[VulnerabilityPattern, ...] = (
    VulnerabilityPattern(
        name="object_authorization_boundary",
        vuln_class=VulnClass.IDOR,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("can_access", "exposes"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.RESOURCE),
        evidence_needed=(
            "owner baseline response",
            "non-owner candidate response",
            "independent negative control",
        ),
        validation_steps=(
            "compare owner and non-owner response semantics",
            "check an unrelated protected object as negative control",
            "require the existing causal oracle and replayable evidence",
        ),
    ),
    VulnerabilityPattern(
        name="sensitive_observation_exposure",
        vuln_class=VulnClass.INFO_DISCLOSURE,
        required_capability="http_read",
        risk=Severity.MEDIUM,
        required_relations=("exposes",),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT,),
        evidence_needed=(
            "redacted response semantics",
            "sensitivity classification",
            "negative control",
        ),
        validation_steps=(
            "confirm the observation is reproducible",
            "classify impact without retaining raw content",
            "require an independent non-sensitive control",
        ),
    ),
)


class HypothesisGenerator:
    """Generate ranked hypotheses from explicit model and graph facts only."""

    def __init__(self, patterns: tuple[VulnerabilityPattern, ...] = DEFAULT_PATTERNS) -> None:
        self.patterns = tuple(sorted(patterns, key=lambda item: item.name))

    def generate(
        self,
        knowledge: TargetKnowledgeV2,
        graph: AttackGraph,
    ) -> tuple[ResearchHypothesis, ...]:
        if knowledge.engagement_id == "" or knowledge.target_id == "":
            return ()
        chains = VulnerabilityChainReasoner(max_hops=4, max_chains=64).derive(graph)
        hypotheses: list[ResearchHypothesis] = []
        for pattern in self.patterns:
            for endpoint in sorted(
                knowledge.entities_of_kind(KnowledgeEntityKind.ENDPOINT),
                key=lambda entity: entity.entity_id,
            ):
                related = [
                    edge
                    for edge in graph.edges
                    if edge.source_id == endpoint.entity_id or edge.target_id == endpoint.entity_id
                ]
                relation_names = {str(edge.kind) for edge in related}
                if not set(pattern.required_relations).intersection(relation_names):
                    continue
                available_kinds = {
                    node.kind
                    for node in graph.nodes.values()
                    if node.id == endpoint.entity_id
                    or any(
                        edge.source_id == endpoint.entity_id and edge.target_id == node.id
                        for edge in related
                    )
                }
                if any(
                    kind.value not in {str(value) for value in available_kinds}
                    for kind in pattern.required_entity_kinds
                ) and pattern.vuln_class == VulnClass.IDOR:
                    continue
                refs = tuple(
                    dict.fromkeys(
                        [
                            *endpoint.evidence_refs,
                            *(ref for edge in related for ref in edge.evidence_refs),
                        ]
                    )
                )[:32]
                chain = self._chain_for_endpoint(chains, endpoint.entity_id)
                chain_nodes = list(chain.node_ids) if chain else [endpoint.entity_id]
                chain_text = [f"node:{node_id}" for node_id in chain_nodes]
                chain_text.extend(f"relation:{edge.kind}" for edge in related[:6])
                hypothesis_key = (
                    f"{knowledge.engagement_id}|{knowledge.target_id}|{pattern.name}|"
                    f"{endpoint.entity_id}"
                )
                hypotheses.append(
                    ResearchHypothesis(
                        id=uuid5(NAMESPACE_URL, hypothesis_key),
                        target_url=endpoint.canonical_key,
                        reason=(
                            f"{pattern.name} is plausible for the observed endpoint; "
                            "the model does not establish exploitability."
                        ),
                        evidence_needed=list(pattern.evidence_needed),
                        attack_plan=list(pattern.validation_steps),
                        risk=pattern.risk,
                        confidence=min(0.85, max(0.2, endpoint.confidence)),
                        vuln_class=pattern.vuln_class,
                        evidence_refs=list(refs),
                        affected_asset=endpoint.canonical_key,
                        reasoning_chain=chain_text[:16],
                        required_capability=pattern.required_capability,
                    )
                )
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return tuple(
            sorted(
                hypotheses,
                key=lambda item: (
                    -item.confidence,
                    -severity_order.get(
                        item.risk.value if hasattr(item.risk, "value") else str(item.risk),
                        0,
                    ),
                    -len(item.evidence_needed),
                    str(item.id),
                ),
            )
        )

    @staticmethod
    def _chain_for_endpoint(chains, endpoint_id: str):
        for chain in chains:
            if endpoint_id in chain.node_ids:
                return chain
        return None


__all__ = ["DEFAULT_PATTERNS", "HypothesisGenerator", "VulnerabilityPattern"]
