"""KG query engine — predicate filtering and typed edge traversal over a live KG directory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Map CLI-friendly type aliases to @type values and subdirectories
_TYPE_MAP: dict[str, tuple[str, str]] = {
    "executionenvironment": ("ExecutionEnvironment", "environments"),
    "environment":          ("ExecutionEnvironment", "environments"),
    "env":                  ("ExecutionEnvironment", "environments"),
    "placement":            ("Placement",            "placements"),
    "workload":             ("Workload",             "workloads"),
    "controlimplementation": ("ControlImplementation", "controls"),
    "control":              ("ControlImplementation", "controls"),
    "toscapolicy":          ("ToscaPolicy",           "business_intent"),
    "tosca":                ("ToscaPolicy",           "business_intent"),
    "businessintent":       ("ToscaPolicy",           "business_intent"),
    "dataset":              ("Dataset",               "data_management"),
    "job":                  ("Job",                   "data_management"),
    "datamanagement":       ("Dataset",               "data_management"),
    "datacontract":         ("DataContract",          "data_management"),
    "contract":             ("DataContract",          "data_management"),
    "contracteddataset":    ("ContractedDataset",     "data_management"),
    "requirement":          ("Requirement",           "requirements"),
    "actor":                ("Actor",                 "requirements"),
    "targetstate":          ("TargetState",           "requirements"),
    "image":                ("Image",                 "supply_chain"),
    "layer":                ("Layer",                 "supply_chain"),
    "package":              ("Package",               "supply_chain"),
    "archetype":            ("Archetype",             "supply_chain"),
    "archetypesuite":       ("ArchetypeSuite",        "supply_chain"),
    "suite":                ("ArchetypeSuite",        "supply_chain"),
    "supplychain":          ("Image",                 "supply_chain"),
    # Reference nodes (ADR-012). They carry no plane, so `plane_of` returns None and
    # `--plane` correctly excludes them — see the docstring below.
    "accountabilityanchor": ("AccountabilityAnchor",  "reference/anchors"),
    "anchor":               ("AccountabilityAnchor",  "reference/anchors"),
}


def kg_query(
    kg_dir: Path,
    node_type: str,
    where: list[str],
    follow: str | None = None,
    namespace: str | None = None,
    plane: str | None = None,
) -> list[dict[str, Any]]:
    """Query the live KG.

    node_type: one of Placement, ExecutionEnvironment, Workload (or alias)
    where:     list of "dot.path=value" predicates (all must match)
    follow:    edge type to traverse from matched nodes (e.g. "manifests_as")
    namespace: optional namespace name. "*" aggregates across all namespaces.
    plane:     optional authoring plane (MP-08/MP-09).

    **An unfiltered query returns every plane and labels each result.** Defaulting to
    ``architecture`` would make the multi-plane graph invisible to every existing
    caller — a plane dimension nobody sees is a plane dimension nobody uses.

    **Reference nodes never appear in a plane-filtered result.** They have no plane
    (ADR-012 §1), so excluding them is correct rather than a gap; a reference node
    surfacing under ``--plane`` would read as authoring, which is the taxonomy
    collapse the two-field design exists to prevent.

    Returns a list of result dicts:
      {"node": <node>, "related": [...], "namespace": <ns>, "plane": <plane|None>}
    """
    if plane is not None:
        from .kg_plane import PLANES, PlaneError

        if plane not in PLANES:
            raise PlaneError(
                f"unknown plane {plane!r} — planes are added by ADR (ADR-005 §7); "
                f"known: {sorted(PLANES)}"
            )
    if namespace == "*":
        return _kg_query_all_namespaces(kg_dir, node_type, where, follow, plane)
    from .kg_namespace import resolve_kg_dir
    effective_dir = resolve_kg_dir(kg_dir, namespace)
    return _kg_query_single(effective_dir, node_type, where, follow, namespace or "", plane)


def _kg_query_single(
    kg_dir: Path,
    node_type: str,
    where: list[str],
    follow: str | None,
    namespace: str,
    plane: str | None = None,
) -> list[dict[str, Any]]:
    from .kg_plane import plane_of

    canonical_type, subdir = _resolve_type(node_type)
    nodes = _load_nodes(kg_dir / subdir, canonical_type)

    predicates = [_parse_predicate(w) for w in (where or [])]
    matched = [n for n in nodes if all(p(n) for p in predicates)]
    if plane is not None:
        matched = [n for n in matched if plane_of(n) == plane]

    results: list[dict[str, Any]] = []
    for node in matched:
        related: list[dict[str, Any]] = []
        if follow:
            related = _follow_edges(node, canonical_type, kg_dir, follow)
        results.append({
            "node": node, "related": related, "namespace": namespace,
            "plane": plane_of(node),
        })

    return results


def _kg_query_all_namespaces(
    kg_dir: Path,
    node_type: str,
    where: list[str],
    follow: str | None,
    plane: str | None = None,
) -> list[dict[str, Any]]:
    from .kg_namespace import list_namespaces
    results: list[dict[str, Any]] = []
    for ns_name, ns_dir in list_namespaces(kg_dir):
        results.extend(_kg_query_single(ns_dir, node_type, where, follow, ns_name, plane))
    return results


# ---------------------------------------------------------------------------
# Type resolution
# ---------------------------------------------------------------------------

def _resolve_type(node_type: str) -> tuple[str, str]:
    key = node_type.lower()
    if key not in _TYPE_MAP:
        known = sorted({k for k in _TYPE_MAP if len(k) > 3})
        raise ValueError(f"Unknown node type {node_type!r}. Known: {known}")
    return _TYPE_MAP[key]


# ---------------------------------------------------------------------------
# Predicate parsing and evaluation
# ---------------------------------------------------------------------------

def _parse_predicate(expr: str):
    """Parse "dot.path=value" into a callable predicate."""
    if "=" not in expr:
        raise ValueError(f"Invalid --where expression {expr!r}: expected 'path=value'")
    path, _, value = expr.partition("=")
    path_parts = path.strip().split(".")
    value = value.strip()

    def predicate(node: dict[str, Any]) -> bool:
        actual = _resolve_path(node, path_parts)
        if actual is None:
            return False
        if isinstance(actual, list):
            return value in actual
        return str(actual) == value

    return predicate


def _resolve_path(node: dict[str, Any], parts: list[str]) -> Any:
    """Walk a dot-separated path into a dict, returning None if any step is missing."""
    current: Any = node
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


# ---------------------------------------------------------------------------
# Edge traversal
# ---------------------------------------------------------------------------

def _follow_edges(
    node: dict[str, Any],
    node_type: str,
    kg_dir: Path,
    edge_type: str,
) -> list[dict[str, Any]]:
    """Follow typed edges from a node and return related node records."""
    if edge_type == "manifests_as":
        return _follow_manifests_as(node, node_type, kg_dir)
    return []


def _follow_manifests_as(
    node: dict[str, Any],
    node_type: str,
    kg_dir: Path,
) -> list[dict[str, Any]]:
    related: list[dict[str, Any]] = []

    if node_type == "Placement":
        # Edge lives on the Placement node: from=workload, to=placement
        for edge in node.get("edges", []):
            if edge.get("@type") != "manifests_as":
                continue
            workload_id = edge.get("from", "")
            wl_node = _find_node_by_id(kg_dir / "workloads", workload_id)
            related.append({
                "edge_type": "manifests_as",
                "direction": "from",
                "node": wl_node or {"@id": workload_id, "@type": "Workload", "_unresolved": True},
                "edge_data": {
                    "capabilities_granted": edge.get("capabilities_granted", []),
                    "manifested_at": edge.get("manifested_at", ""),
                    "attestation_level": edge.get("attestation_level", ""),
                },
            })

    elif node_type == "Workload":
        # Scan all Placements for manifests_as edges pointing to this workload
        workload_id = node.get("@id", "")
        for path in sorted((kg_dir / "placements").glob("*.json")):
            try:
                p_node = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            if p_node.get("@type") != "Placement":
                continue
            for edge in p_node.get("edges", []):
                if edge.get("@type") == "manifests_as" and edge.get("from") == workload_id:
                    related.append({
                        "edge_type": "manifests_as",
                        "direction": "to",
                        "node": p_node,
                        "edge_data": {
                            "capabilities_granted": edge.get("capabilities_granted", []),
                            "manifested_at": edge.get("manifested_at", ""),
                            "attestation_level": edge.get("attestation_level", ""),
                        },
                    })

    return related


def _find_node_by_id(directory: Path, node_id: str) -> dict[str, Any] | None:
    if not directory.exists():
        return None
    for path in directory.glob("*.json"):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@id") == node_id:
            return node
    return None


# ---------------------------------------------------------------------------
# Node loader
# ---------------------------------------------------------------------------

def _load_nodes(directory: Path, type_val: str) -> list[dict[str, Any]]:
    if not directory.exists():
        return []
    nodes = []
    for path in sorted(directory.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") == type_val:
            nodes.append(node)
    return nodes
