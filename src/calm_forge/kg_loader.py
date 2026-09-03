"""Load and parse CALM Forge knowledge graph JSON-LD intent contract files."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_KG_DIR = Path(__file__).parent / "knowledge_graph"


def load_patterns(kg_dir: Path | None = None) -> list[dict[str, Any]]:
    """Load all JSON-LD Workload pattern files from the KG directory.

    Skips files that are not valid JSON or do not have @type == Workload.
    Returns patterns sorted by name.
    """
    directory = kg_dir or _KG_DIR
    patterns: list[dict[str, Any]] = []

    if not directory.exists():
        return patterns

    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        # A non-object JSON file in this directory is not a pattern — migration
        # records and provenance live here too. Skip rather than crash on .get().
        if isinstance(data, dict) and data.get("@type") == "Workload":
            patterns.append(data)

    return patterns


def extract_policies(pattern: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract Policy predicate nodes from a Workload pattern."""
    return [p for p in pattern.get("policies", []) if p.get("@type") == "Policy"]


def extract_capabilities(pattern: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract Capability declaration nodes from a Workload pattern."""
    return [
        c
        for c in pattern.get("capability_declarations", [])
        if c.get("@type") == "Capability"
    ]


def extract_compliance(pattern: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract Compliance nodes from a Workload pattern."""
    return [
        c
        for c in pattern.get("compliance_nodes", [])
        if c.get("@type") == "Compliance"
    ]


def extract_placements(pattern: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract Placement nodes (brownfield/intake patterns only)."""
    return [
        p
        for p in pattern.get("placement_nodes", [])
        if p.get("@type") == "Placement"
    ]


def pattern_summary(pattern: dict[str, Any]) -> dict[str, Any]:
    """Return a structured summary suitable for MCP tool responses.

    Agents should receive a concise summary, not raw JSON-LD.
    """
    policies = extract_policies(pattern)

    # Collect required capabilities from edges and component declarations
    required_caps: set[str] = set()
    for edge in pattern.get("edges", []):
        if edge.get("@type") == "requires_capability":
            cap_id = edge.get("to", "")
            # Strip the "capability:" prefix for readability
            cap_name = cap_id.replace("capability:", "") if cap_id else cap_id
            required_caps.add(cap_name)
    for node in pattern.get("nodes", []):
        for cap in node.get("declared_capabilities", []):
            required_caps.add(cap)

    predicate_types: list[str] = sorted(
        {p.get("predicate_type", "") for p in policies if p.get("predicate_type")}
    )
    enforcement_modes: list[str] = sorted(
        {p.get("enforcement_mode", "") for p in policies if p.get("enforcement_mode")}
    )

    return {
        "id": pattern.get("@id", ""),
        "name": pattern.get("name", ""),
        "version": pattern.get("version", ""),
        "purpose": pattern.get("purpose", ""),
        "owner": pattern.get("owner", ""),
        "compliance_scope": pattern.get("compliance_scope", []),
        "policy_count": len(policies),
        "predicate_types": predicate_types,
        "enforcement_modes": enforcement_modes,
        "capabilities_required": sorted(required_caps),
        "intake_source": pattern.get("_provenance", {}).get("intake_source"),
        "tags": pattern.get("tags", []),
    }


def load_summaries(kg_dir: Path | None = None) -> list[dict[str, Any]]:
    """Load all patterns and return their summaries."""
    return [pattern_summary(p) for p in load_patterns(kg_dir)]


# ---------------------------------------------------------------------------
# Round-trip constraint
# ---------------------------------------------------------------------------

_REQUIRED_WORKLOAD_FIELDS = {
    "@context", "@type", "@id", "version", "name", "purpose", "owner",
    "_provenance",
}
_REQUIRED_POLICY_FIELDS = {
    "@type", "@id", "predicate_type", "enforcement_mode", "evaluated_by", "provenance",
}


def validate_planes(pattern: dict[str, Any]) -> list[str]:
    """Class/plane gaps for a Workload document (MP-08, ADR-005 §1).

    Thin re-export so callers of this module do not need to know that the plane rules
    live in :mod:`calm_forge.kg_plane`.
    """
    from .kg_plane import validate_document

    return validate_document(pattern)


def assert_round_trip_ready(pattern: dict[str, Any]) -> list[str]:
    """Validate a Workload pattern has the minimum fields required for round-trip reconstruction.

    Returns a list of gap descriptions. Empty list means the pattern is round-trip ready
    for the fields it claims to capture.

    Note: Full CALM JSON round-trip (including node-type, interfaces, and relationship
    details) requires the CALM→KG compile step from ADR-0027 (Phase 2). This function
    validates the intent contract fields that Phase 1 captures.
    """
    gaps: list[str] = []

    # Top-level Workload fields
    for field in sorted(_REQUIRED_WORKLOAD_FIELDS):
        if field not in pattern:
            gaps.append(f"Workload missing required field: {field}")

    # Every Policy node must have required fields
    for policy in extract_policies(pattern):
        pid = policy.get("@id", "<unknown>")
        for field in sorted(_REQUIRED_POLICY_FIELDS):
            if field not in policy:
                gaps.append(f"Policy {pid} missing required field: {field}")

    # Every Policy must have predicate-type-specific required fields
    for policy in extract_policies(pattern):
        pid = policy.get("@id", "<unknown>")
        ptype = policy.get("predicate_type", "")
        if ptype == "placement_constraint" and not policy.get("required_labels"):
            gaps.append(f"Policy {pid}: placement_constraint missing required_labels")
        if ptype == "compliance_boundary" and not policy.get("allowed_regions"):
            gaps.append(f"Policy {pid}: compliance_boundary missing allowed_regions")
        if ptype == "capability_requirement" and not policy.get("required_capability"):
            gaps.append(f"Policy {pid}: capability_requirement missing required_capability")
        if ptype == "drift_threshold" and policy.get("max_deviation_hours") is None:
            gaps.append(f"Policy {pid}: drift_threshold missing max_deviation_hours")

    # Every authored node declares its class and plane — required, no default (MP-08)
    gaps.extend(validate_planes(pattern))

    # Provenance block must have authored_by and authored_at
    prov = pattern.get("_provenance", {})
    if not prov.get("authored_by"):
        gaps.append("_provenance missing authored_by")
    if not prov.get("authored_at"):
        gaps.append("_provenance missing authored_at")

    return gaps
