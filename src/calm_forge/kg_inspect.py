"""KG inspection — summarise the state of a live knowledge graph directory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def kg_status(kg_dir: Path, namespace: str | None = None) -> dict[str, Any]:
    """Return a structured summary of a live KG directory.

    When namespace is None or "", reports on kg_dir directly (root namespace).
    When namespace is "*", aggregates across all namespaces.
    Otherwise reports on kg_dir/<namespace>.

    Walks environments/, placements/, workloads/ and drift-events.json.
    Returns counts, breakdowns, and the overall drift status.
    """
    if namespace == "*":
        return _kg_status_all_namespaces(kg_dir)
    from .kg_namespace import resolve_kg_dir
    effective_dir = resolve_kg_dir(kg_dir, namespace)
    result: dict[str, Any] = {
        "kg_dir": str(effective_dir),
        "namespace": namespace or "",
        "environments": _summarise_environments(effective_dir / "environments"),
        "placements": _summarise_placements(effective_dir / "placements"),
        "workloads": _summarise_workloads(effective_dir / "workloads"),
        "policies": _summarise_policies(effective_dir / "policies"),
        "deployments": _summarise_deployments(effective_dir / "deployments"),
        "drift_events": _summarise_events(effective_dir / "drift-events.json"),
        "bootstrap_history": _summarise_bootstrap_history(Path(kg_dir)),
        "curvature_trends": _summarise_curvature_trends(Path(kg_dir)),
    }
    result["overall_status"] = _overall_status(result)
    return result


def _kg_status_all_namespaces(kg_dir: Path) -> dict[str, Any]:
    """Aggregate kg_status across all namespaces."""
    from .kg_namespace import list_namespaces
    namespaces = list_namespaces(kg_dir)
    per_ns: list[dict[str, Any]] = []
    totals: dict[str, Any] = {
        "environments": {"count": 0, "by_status": {}},
        "placements": {"count": 0, "by_drift_status": {}, "last_evaluated": None, "manifests_as_edges": 0},
        "workloads": {"count": 0, "reconstructed": 0, "review_required": 0, "requires_capability_edges": 0},
        "policies": {"count": 0, "by_source": {}, "blocking": 0},
        "deployments": {"requests": 0, "statuses": 0, "pending": 0, "completed": 0, "drift_violations": 0},
        "drift_events": {"count": 0, "last_timestamp": None},
    }
    for ns_name, ns_dir in namespaces:
        ns_result = kg_status(ns_dir, namespace=None)
        ns_result["namespace"] = ns_name
        per_ns.append(ns_result)
        _merge_totals(totals, ns_result)
    totals["overall_status"] = _overall_status(totals)
    return {
        "kg_dir": str(kg_dir),
        "namespace": "*",
        "namespaces": per_ns,
        **totals,
    }


def _merge_totals(totals: dict, ns: dict) -> None:
    e = ns["environments"]
    totals["environments"]["count"] += e["count"]
    for k, v in e.get("by_status", {}).items():
        totals["environments"]["by_status"][k] = totals["environments"]["by_status"].get(k, 0) + v

    p = ns["placements"]
    totals["placements"]["count"] += p["count"]
    totals["placements"]["manifests_as_edges"] += p.get("manifests_as_edges", 0)
    for k, v in p.get("by_drift_status", {}).items():
        totals["placements"]["by_drift_status"][k] = totals["placements"]["by_drift_status"].get(k, 0) + v
    ts = p.get("last_evaluated")
    if ts and (totals["placements"]["last_evaluated"] is None or ts > totals["placements"]["last_evaluated"]):
        totals["placements"]["last_evaluated"] = ts

    w = ns["workloads"]
    totals["workloads"]["count"] += w["count"]
    totals["workloads"]["reconstructed"] += w.get("reconstructed", 0)
    totals["workloads"]["review_required"] += w.get("review_required", 0)
    totals["workloads"]["requires_capability_edges"] += w.get("requires_capability_edges", 0)

    pol = ns.get("policies", {})
    totals["policies"]["count"] += pol.get("count", 0)
    totals["policies"]["blocking"] += pol.get("blocking", 0)
    for k, v in pol.get("by_source", {}).items():
        totals["policies"]["by_source"][k] = totals["policies"]["by_source"].get(k, 0) + v

    dep = ns.get("deployments", {})
    for k in ("requests", "statuses", "pending", "completed", "drift_violations"):
        totals["deployments"][k] += dep.get(k, 0)

    ev = ns["drift_events"]
    totals["drift_events"]["count"] += ev["count"]
    ts = ev.get("last_timestamp")
    if ts and (totals["drift_events"]["last_timestamp"] is None or ts > totals["drift_events"]["last_timestamp"]):
        totals["drift_events"]["last_timestamp"] = ts


# ---------------------------------------------------------------------------
# Per-type summaries
# ---------------------------------------------------------------------------

def _summarise_environments(env_dir: Path) -> dict[str, Any]:
    nodes = _load_nodes(env_dir, "@type", "ExecutionEnvironment")
    by_status: dict[str, int] = {}
    for n in nodes:
        s = n.get("status", "unknown")
        by_status[s] = by_status.get(s, 0) + 1
    return {"count": len(nodes), "by_status": by_status}


def _summarise_placements(place_dir: Path) -> dict[str, Any]:
    nodes = _load_nodes(place_dir, "@type", "Placement")
    by_drift: dict[str, int] = {}
    last_evaluated: str | None = None
    manifests_as_count = 0
    for n in nodes:
        ds = n.get("drift_state", {})
        status = ds.get("status", "unknown")
        by_drift[status] = by_drift.get(status, 0) + 1
        ts = ds.get("last_evaluated")
        if ts and (last_evaluated is None or ts > last_evaluated):
            last_evaluated = ts
        for edge in n.get("edges", []):
            if edge.get("@type") == "manifests_as":
                manifests_as_count += 1
    return {
        "count": len(nodes),
        "by_drift_status": by_drift,
        "last_evaluated": last_evaluated,
        "manifests_as_edges": manifests_as_count,
    }


def _summarise_workloads(wl_dir: Path) -> dict[str, Any]:
    nodes = _load_nodes(wl_dir, "@type", "Workload")
    reconstructed = sum(
        1 for n in nodes
        if n.get("_provenance", {}).get("provenance") == "reconstructed"
    )
    review_required = sum(1 for n in nodes if n.get("review_required"))
    requires_capability_edges = sum(
        sum(1 for e in n.get("edges", []) if e.get("@type") == "requires_capability")
        for n in nodes
    )
    return {
        "count": len(nodes),
        "reconstructed": reconstructed,
        "review_required": review_required,
        "requires_capability_edges": requires_capability_edges,
    }


def _summarise_policies(policy_dir: Path) -> dict[str, Any]:
    nodes = _load_nodes(policy_dir, "@type", "PlacementPolicy")
    by_source: dict[str, int] = {}
    blocked_count = 0
    for n in nodes:
        src = n.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        if n.get("blocked_environments"):
            blocked_count += 1
    return {"count": len(nodes), "by_source": by_source, "blocking": blocked_count}


def _summarise_deployments(deploy_dir: Path) -> dict[str, Any]:
    requests = _load_nodes(deploy_dir, "@type", "DeploymentRequest")
    statuses = _load_nodes(deploy_dir, "@type", "DeploymentStatus")
    pending = sum(1 for n in requests if n.get("status") == "pending")
    completed = sum(1 for n in statuses if n.get("outcome") in ("success", "partial"))
    drift_violations = sum(
        1 for n in statuses
        if (n.get("drift_result") or {}).get("drift_detected")
    )
    return {
        "requests": len(requests),
        "statuses": len(statuses),
        "pending": pending,
        "completed": completed,
        "drift_violations": drift_violations,
    }


def _summarise_events(event_file: Path) -> dict[str, Any]:
    if not event_file.exists():
        return {"count": 0, "last_timestamp": None}
    events = []
    for line in event_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    last_ts = max((e.get("timestamp", "") for e in events), default=None) or None
    return {"count": len(events), "last_timestamp": last_ts}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_nodes(directory: Path, type_key: str, type_val: str) -> list[dict[str, Any]]:
    if not directory.exists():
        return []
    nodes = []
    for path in sorted(directory.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get(type_key) == type_val:
            nodes.append(node)
    return nodes


def _summarise_curvature_trends(kg_dir: Path) -> list[dict[str, Any]]:
    from .drift_evaluator import curvature_trend, load_curvature_history
    history = load_curvature_history(kg_dir)
    workload_ids = list(dict.fromkeys(r["workload_id"] for r in history))
    return [curvature_trend(wid, kg_dir) for wid in workload_ids]


def _summarise_bootstrap_history(kg_dir: Path) -> dict[str, Any]:
    from .kg_bootstrap import load_bootstrap_history
    history = load_bootstrap_history(kg_dir)
    if not history:
        return {"runs": 0, "last_run": None, "last_total_nodes": 0}
    last = history[-1]
    return {
        "runs": len(history),
        "last_run": last.get("timestamp"),
        "last_total_nodes": last.get("total_nodes", 0),
    }


def _overall_status(result: dict[str, Any]) -> str:
    violations = result["placements"]["by_drift_status"].get("violation", 0)
    if violations > 0:
        return "VIOLATION"
    placements = result["placements"]["count"]
    if placements == 0:
        return "NO_PLACEMENTS"
    pending = result["placements"]["by_drift_status"].get("pending_first_evaluation", 0)
    if pending == placements:
        return "UNEVALUATED"
    return "CLEAN"
