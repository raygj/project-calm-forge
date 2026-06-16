"""Intent validator — compile architecture to semantic graph and check design-time invariants.

Two-phase pipeline:
  1. compile_to_graph      — normalise CALM instantiation or Workload KG node to
                             a canonical semantic graph dict
  2. InvariantEngine.validate — check invariants; default engine is OPAEngine
     (OPA is invoked separately for the existing calm.violations rules)

The computation engine is injectable via the InvariantEngine protocol (ADR-0025).
OPAEngine is the default. ManifoldEngine (ADR-0030 Phase 2) is a stub that
raises NotImplementedError until the Holonomy SDK is available.

SARIF 2.1.0 serialization for CI integration (GitHub Actions, Tekton, etc.).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# InvariantEngine protocol (ADR-0025)
# ---------------------------------------------------------------------------

@runtime_checkable
class InvariantEngine(Protocol):
    """Pluggable computation engine for graph invariant checking.

    Implementations:
      OPAEngine     — default, pure-Python + optional OPA (current behaviour)
      ManifoldEngine — stub for ADR-0030 Phase 2 Holonomy SDK
    """

    def validate(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        """Check invariants on a compiled semantic graph.

        Args:
            graph: Output of compile_to_graph(). Keys: workload_id,
                   declared_capabilities, components, edges,
                   compliance_scope, allowed_regions, policies.

        Returns:
            List of finding dicts with rule, severity, message.
        """
        ...


class OPAEngine:
    """Default invariant engine — pure-Python semantic checks.

    OPA evaluation (Rego policies) is handled separately in
    validate_architecture_intent because OPA needs the raw architecture
    dict, not the compiled graph. The ManifoldEngine (ADR-0030 Phase 2)
    will replace both this engine and the OPA call with a single geometric
    holonomy check.
    """

    def __init__(
        self,
        placement_policies: list[dict[str, Any]] | None = None,
    ):
        self.placement_policies = placement_policies or []

    def validate(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        return check_graph_invariants(graph, self.placement_policies)


class ManifoldEngine:
    """Holonomy engine — pure-Python consistency check with a curvature score.

    Replaces the OPA capability-ceiling approximation with a structured
    consistency check expressed as a continuous curvature score. curvature=0
    means the semantic graph is internally coherent; curvature>0 means sections
    don't glue cleanly (excess capabilities, gluing violations, or compliance drift).

    Three curvature contributions (see _holonomy_validate):
      - Section excess: component has capabilities outside declared set
      - Gluing violation: requires_capability edge references missing cap
      - Compliance drift: regulated scope with no region, or PII without scope

    Args:
        curvature_threshold: Curvature at or above which a violation is raised
                             (default 0.01). Below threshold raises a warning.
    """

    def __init__(self, curvature_threshold: float = 0.01):
        self.curvature_threshold = curvature_threshold

    def validate(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        sheaf = _graph_to_sheaf(graph)
        result = _holonomy_validate(graph, sheaf)
        return _holonomy_result_to_findings(result, self.curvature_threshold)


def _graph_to_sheaf(graph: dict[str, Any]) -> dict[str, Any]:
    """Convert a canonical semantic graph to a sheaf structure for the Holonomy SDK.

    Each component becomes a local section; edges become gluing conditions;
    declared_capabilities + compliance_scope form the global section.
    The SDK checks that local sections glue consistently (holonomy = 0).
    """
    sections = [
        {
            "id": comp["id"],
            "capabilities": comp.get("capabilities", []),
            "constraints": [],
        }
        for comp in graph.get("components", [])
    ]
    gluing_conditions = [
        {
            "from": edge.get("from", ""),
            "to": edge.get("to", ""),
            "edge_type": edge.get("@type", ""),
        }
        for edge in graph.get("edges", [])
    ]
    global_section = {
        "declared_capabilities": graph.get("declared_capabilities", []),
        "compliance_scope": graph.get("compliance_scope", []),
    }
    return {
        "sections": sections,
        "gluing_conditions": gluing_conditions,
        "global_section": global_section,
    }


_SENSITIVE_CAPS = {"pii_read", "pii_write", "cardholder_data_read", "cardholder_data_write"}
_COMPLIANCE_FAMILIES = {"PCI-DSS", "HIPAA", "GDPR"}


def _holonomy_validate(graph: dict[str, Any], sheaf: dict[str, Any]) -> dict[str, Any]:
    """Pure-Python consistency check — the holonomy metaphor made concrete.

    Measures how much the semantic graph deviates from structural consistency.
    curvature = 0 means every section glues cleanly to the global section.
    curvature > 0 means something declared doesn't match something observed.

    Three curvature contributions:
      1. Section excess — a component has capabilities outside declared_capabilities
      2. Gluing violation — a requires_capability edge points to a cap the
         component doesn't actually have in its own section
      3. Compliance drift — regulated scope with no region constraint, or PII
         capabilities with no compliance scope
    """
    curvature = 0.0
    explanations: list[str] = []

    declared = set(sheaf["global_section"].get("declared_capabilities", []))
    section_map = {s["id"]: s for s in sheaf["sections"]}

    # 1. Section excess: component capabilities not in declared set
    for section in sheaf["sections"]:
        excess = set(section.get("capabilities", [])) - declared
        if excess:
            curvature += len(excess) / max(len(declared), 1)
            explanations.append(
                f"{section['id']}: undeclared capabilities {sorted(excess)}"
            )

    # 2. Gluing conditions: requires_capability edge must match source section
    for condition in sheaf["gluing_conditions"]:
        if not _sections_compatible(condition, section_map):
            curvature += 0.5
            explanations.append(
                f"Gluing violation: {condition['from']} → {condition['to']} "
                f"via {condition['edge_type']}"
            )

    # 3. Compliance drift: regulated scope without region, or PII without compliance
    compliance = set(sheaf["global_section"].get("compliance_scope", []))
    allowed_regions = graph.get("allowed_regions", [])

    if compliance and not allowed_regions:
        for scope in compliance:
            if any(scope.upper().startswith(f) for f in _COMPLIANCE_FAMILIES):
                curvature += 0.5
                explanations.append(
                    f"Compliance scope {scope!r} requires region constraints (none declared)"
                )
                break

    if declared & _SENSITIVE_CAPS and not compliance:
        curvature += 0.25
        explanations.append("PII/cardholder capabilities declared without compliance scope")

    return {
        "valid": curvature == 0.0,
        "curvature": round(curvature, 4),
        "explanation": "; ".join(explanations) if explanations else "coherent",
    }


def _sections_compatible(condition: dict[str, Any], section_map: dict[str, Any]) -> bool:
    """Return False when a requires_capability edge references a missing capability."""
    if condition.get("edge_type") != "requires_capability":
        return True
    source = section_map.get(condition.get("from", ""))
    if source is None:
        return True
    cap = condition.get("to", "").replace("capability:", "")
    return cap in source.get("capabilities", [])


def _holonomy_result_to_findings(
    result: dict[str, Any],
    curvature_threshold: float = 0.01,
) -> list[dict[str, Any]]:
    """Convert a holonomy SDK result to the standard findings list.

    SDK result shape: { "valid": bool, "curvature": float, "explanation": str }

    curvature = 0           → [] (clean)
    0 < curvature < threshold → warning holonomy-curvature-nonzero
    curvature >= threshold   → error holonomy-ceiling-violated
    """
    curvature = result.get("curvature", 0.0)
    explanation = result.get("explanation", "")
    if curvature <= 0.0:
        return []
    if curvature < curvature_threshold:
        return [{
            "rule": "holonomy-curvature-nonzero",
            "severity": "warning",
            "message": (
                f"Semantic graph has non-zero holonomy (curvature={curvature:.4f}) — "
                f"below violation threshold ({curvature_threshold}). {explanation}"
            ),
        }]
    return [{
        "rule": "holonomy-ceiling-violated",
        "severity": "error",
        "message": (
            f"Holonomy check failed: curvature={curvature:.4f} ≥ threshold={curvature_threshold} — "
            f"capability sections do not glue consistently. {explanation}"
        ),
    }]

# ---------------------------------------------------------------------------
# Semantic graph form (internal normalised representation)
# ---------------------------------------------------------------------------
# {
#   "workload_id":          str,
#   "declared_capabilities": [str],     -- flat union across all components
#   "components": [{"id": str, "name": str, "capabilities": [str]}],
#   "edges":      [{"@type": str, "from": str, "to": str}],
#   "compliance_scope":  [str],         -- e.g. ["PCI-DSS-v4:req-3"]
#   "allowed_regions":   [str],
#   "policies":   [{...}],
# }


# ---------------------------------------------------------------------------
# Compile: CALM instantiation or Workload KG node → semantic graph
# ---------------------------------------------------------------------------

def compile_to_graph(source: dict[str, Any]) -> dict[str, Any]:
    """Normalise a CALM architecture or Workload KG node to semantic graph form.

    Detects format by @type field (Workload KG) or presence of nodes array
    with unique-id fields (CALM instantiation).
    """
    if source.get("@type") == "Workload":
        return _from_workload_node(source)
    return _from_calm_instantiation(source)


def _from_workload_node(node: dict[str, Any]) -> dict[str, Any]:
    workload_id = node.get("@id", "workload:unknown")
    components = []
    for comp in node.get("nodes", []):
        components.append({
            "id": comp.get("@id", ""),
            "name": comp.get("name", ""),
            "capabilities": comp.get("declared_capabilities", []),
        })
    return {
        "workload_id": workload_id,
        "declared_capabilities": node.get("declared_capabilities", []),
        "components": components,
        "edges": node.get("edges", []),
        "compliance_scope": node.get("compliance_scope", []),
        "allowed_regions": _extract_allowed_regions_from_policies(node.get("policies", [])),
        "policies": node.get("policies", []),
    }


def _from_calm_instantiation(calm: dict[str, Any]) -> dict[str, Any]:
    """Extract semantic graph from a CALM instantiation JSON."""
    title = calm.get("metadata", {}).get("name", calm.get("title", "unknown"))
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    workload_id = f"workload:{slug}"

    components = []
    edges = []
    for node in calm.get("nodes", []):
        node_id = node.get("unique-id", node.get("name", ""))
        caps = node.get("required-capabilities", [])
        components.append({"id": node_id, "name": node_id, "capabilities": caps})
        for cap in caps:
            edges.append({
                "@type": "requires_capability",
                "from": node_id,
                "to": f"capability:{cap}",
            })

    all_caps = sorted({cap for comp in components for cap in comp["capabilities"]})

    meta = calm.get("metadata", {})
    meta_data = meta.get("data", meta)
    compliance_raw = meta_data.get("compliance", "") or meta.get("compliance", "")
    compliance_scope: list[str] = (
        compliance_raw if isinstance(compliance_raw, list)
        else ([compliance_raw] if compliance_raw else [])
    )

    regions_raw = (
        meta_data.get("data-residency")
        or meta_data.get("region")
        or meta.get("data-residency")
        or []
    )
    allowed_regions: list[str] = (
        regions_raw if isinstance(regions_raw, list)
        else ([regions_raw] if regions_raw else [])
    )

    return {
        "workload_id": workload_id,
        "declared_capabilities": all_caps,
        "components": components,
        "edges": edges,
        "compliance_scope": compliance_scope,
        "allowed_regions": allowed_regions,
        "policies": [],
    }


def _extract_allowed_regions_from_policies(policies: list[dict[str, Any]]) -> list[str]:
    for p in policies:
        if p.get("predicate_type") == "compliance_boundary":
            return p.get("allowed_regions", [])
    return []


# ---------------------------------------------------------------------------
# Invariant checks (pure Python — no OPA)
# ---------------------------------------------------------------------------

_SENSITIVE_CAPABILITIES = {"pii_read", "pii_write", "cardholder_data_read", "cardholder_data_write"}
_COMPLIANCE_FAMILIES_REQUIRING_REGIONS = {"PCI-DSS", "HIPAA", "GDPR"}


def check_graph_invariants(
    graph: dict[str, Any],
    placement_policies: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Run all design-time invariant checks. Returns list of violation dicts.

    placement_policies: optional list of PlacementPolicy KG nodes for the workload.
    When provided, Concert risk constraints are enforced.
    """
    findings: list[dict[str, Any]] = []
    _check_compliance_requires_region(graph, findings)
    _check_pii_requires_compliance(graph, findings)
    _check_capability_ceiling_policy(graph, findings)
    if placement_policies:
        _check_concert_risk_placement(graph, placement_policies, findings)
    return findings


def _check_compliance_requires_region(
    graph: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    """Regulated compliance families require explicit region constraints."""
    scope = graph.get("compliance_scope", [])
    regions = graph.get("allowed_regions", [])
    if regions:
        return
    for entry in scope:
        matched_family = next(
            (f for f in _COMPLIANCE_FAMILIES_REQUIRING_REGIONS if entry.upper().startswith(f)),
            None,
        )
        if matched_family:
            findings.append({
                "rule": "compliance-requires-region-constraint",
                "severity": "error",
                "message": (
                    f"Compliance scope {entry!r} requires allowed_regions to be declared "
                    f"— data residency must be explicit for {matched_family} workloads"
                ),
            })
            return  # one finding per workload


def _check_pii_requires_compliance(
    graph: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    """Components requiring PII capabilities must have a compliance scope."""
    scope = graph.get("compliance_scope", [])
    if scope:
        return
    for comp in graph.get("components", []):
        sensitive = _SENSITIVE_CAPABILITIES & set(comp.get("capabilities", []))
        if sensitive:
            findings.append({
                "rule": "pii-requires-compliance-scope",
                "severity": "error",
                "message": (
                    f"Component {comp['id']!r} requires sensitive capabilities {sorted(sensitive)} "
                    f"but no compliance_scope is declared — add HIPAA, GDPR, or PCI-DSS scope"
                ),
            })


def _check_concert_risk_placement(
    graph: dict[str, Any],
    placement_policies: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """Concert risk assessment has blocked one or more environments for this workload."""
    workload_id = graph.get("workload_id", "")
    for policy in placement_policies:
        blocked = policy.get("blocked_environments", [])
        if not blocked:
            continue
        risk_score = policy.get("risk_score", 0.0)
        risk_level = policy.get("risk_level", "unknown")
        findings.append({
            "rule": "concert-risk-placement-block",
            "severity": "error",
            "message": (
                f"Concert risk assessment for {workload_id!r} has blocked "
                f"{len(blocked)} environment(s) "
                f"(risk_score={risk_score:.2f}, level={risk_level}): "
                f"{', '.join(blocked)} — resolve Concert risk before deploying"
            ),
        })


def _check_capability_ceiling_policy(
    graph: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    """Any Workload with declared capabilities must carry the capability-ceiling policy."""
    if not graph.get("declared_capabilities"):
        return
    policies = graph.get("policies", [])
    has_ceiling = any(
        p.get("predicate_type") == "capability_ceiling" for p in policies
    )
    if not has_ceiling:
        findings.append({
            "rule": "capability-ceiling-policy-required",
            "severity": "warning",
            "message": (
                f"Workload {graph['workload_id']!r} declares capabilities but has no "
                f"capability_ceiling policy — add a policy with evaluated_by: "
                f"calm.manifest.capability_subset_check to enforce the manifests_as invariant"
            ),
        })


# ---------------------------------------------------------------------------
# Full validate-intent pipeline
# ---------------------------------------------------------------------------

def validate_architecture_intent(
    architecture: dict[str, Any],
    decorator: dict[str, Any] | None = None,
    run_opa: bool = True,
    kg_dir: Path | None = None,
    engine: InvariantEngine | None = None,
    record_curvature: bool = False,
) -> dict[str, Any]:
    """Full validate-intent pipeline.

    1. Compile architecture to semantic graph
    2. Optionally load Concert PlacementPolicy nodes from kg_dir
    3. Run invariant checks via engine (default: OPAEngine)

    The engine parameter follows the InvariantEngine protocol (ADR-0025).
    When engine is None, an OPAEngine is constructed with run_opa and
    placement_policies arguments (backward compatible).

    When record_curvature=True and engine is ManifoldEngine, appends the
    curvature score to <kg_dir>/_fabric/curvature-history.jsonl.

    Returns:
      valid:       bool (True = no error-severity violations)
      violations:  list[{rule, severity, message}]
      graph:       compiled semantic graph (for diagnostics)
      opa_result:  raw OPA result dict or None (only when OPAEngine runs OPA)
    """
    graph = compile_to_graph(architecture)

    placement_policies: list[dict[str, Any]] = []
    if kg_dir is not None:
        from .intake import load_placement_policies
        placement_policies = load_placement_policies(kg_dir, graph.get("workload_id"))

    if engine is None:
        engine = OPAEngine(placement_policies=placement_policies)

    violations = engine.validate(graph)

    # Preserve opa_result in the response when using OPAEngine with run_opa=True
    opa_result = None
    if run_opa and isinstance(engine, OPAEngine):
        try:
            from .opa_gate import validate_intent as opa_validate_intent
            opa_result = opa_validate_intent(architecture, decorator)
        except Exception:
            pass

    # Persist curvature sample when engine is ManifoldEngine and kg_dir is given
    if record_curvature and isinstance(engine, ManifoldEngine) and kg_dir is not None:
        from .drift_evaluator import record_curvature as _record_curvature
        sheaf = _graph_to_sheaf(graph)
        holonomy = _holonomy_validate(graph, sheaf)
        _record_curvature(graph.get("workload_id", "unknown"), holonomy["curvature"], kg_dir)

    has_errors = any(v.get("severity") == "error" for v in violations)
    return {
        "valid": not has_errors,
        "violations": violations,
        "graph": graph,
        "opa_result": opa_result,
    }


# ---------------------------------------------------------------------------
# SARIF 2.1.0 serialization
# ---------------------------------------------------------------------------

def to_sarif(
    result: dict[str, Any],
    architecture_uri: str = "architecture.json",
    tool_version: str = "0.5.0",
) -> dict[str, Any]:
    """Serialise a validate-intent result to SARIF 2.1.0 format."""
    sarif_results = []
    for v in result.get("violations", []):
        severity = v.get("severity", "warning")
        level = "error" if severity == "error" else "warning"
        sarif_results.append({
            "ruleId": v.get("rule", "unknown"),
            "level": level,
            "message": {"text": v.get("message", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": architecture_uri},
                    }
                }
            ],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "calm-forge",
                        "version": tool_version,
                        "informationUri": "https://github.com/finos/architecture-as-code",
                        "rules": _sarif_rules(),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": result.get("valid", False),
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }


def _sarif_rules() -> list[dict[str, Any]]:
    return [
        {
            "id": "compliance-requires-region-constraint",
            "shortDescription": {"text": "Regulated compliance scope requires region constraints"},
            "helpUri": "https://calmforge.io/rules/compliance-requires-region-constraint",
        },
        {
            "id": "pii-requires-compliance-scope",
            "shortDescription": {"text": "PII capabilities require a compliance scope"},
            "helpUri": "https://calmforge.io/rules/pii-requires-compliance-scope",
        },
        {
            "id": "capability-ceiling-policy-required",
            "shortDescription": {"text": "Workloads with capabilities must declare capability-ceiling policy"},
            "helpUri": "https://calmforge.io/rules/capability-ceiling-policy-required",
        },
    ]
