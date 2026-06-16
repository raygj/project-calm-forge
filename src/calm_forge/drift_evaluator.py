"""Drift evaluator — compare declared placement intent against observed Placement KG nodes."""
from __future__ import annotations

import datetime
import json
import re
from pathlib import Path
from typing import Any


def evaluate_drift(calm: dict[str, Any], kg_dir: Path) -> dict[str, Any]:
    """Compare declared placement intent in a CALM spec against observed Placement nodes.

    Returns drift findings: matches, violations (placed in undeclared zone),
    and warnings (declared zone with no observed placement).
    """
    declared_zones = _declared_zones(calm)
    workload_name = _derive_workload_name(calm)
    placements = _load_placements(kg_dir, workload_name)

    if not placements:
        return {
            "workload": workload_name,
            "declared_zones": declared_zones,
            "observed_placements": [],
            "drift_detected": False,
            "status": "no_placements_found",
            "findings": [],
        }

    observed_regions = [p.get("region", "") for p in placements]
    findings: list[dict[str, Any]] = []

    for placement in placements:
        region = placement.get("region", "")
        if declared_zones and region not in declared_zones:
            findings.append({
                "severity": "violation",
                "placement_id": placement.get("@id", ""),
                "observed_region": region,
                "declared_zones": declared_zones,
                "message": (
                    f"Workload placed in {region!r} — not in declared zones {declared_zones}"
                ),
            })
        # Capability-ceiling check: capabilities_granted ⊆ declared_capabilities
        # (manifests_as invariant from ADR-0024)
        _check_capability_ceiling(placement, kg_dir, findings)

    for zone in declared_zones:
        if zone not in observed_regions:
            findings.append({
                "severity": "warning",
                "zone": zone,
                "message": f"Declared zone {zone!r} has no observed placement",
            })

    violations = [f for f in findings if f["severity"] == "violation"]
    return {
        "workload": workload_name,
        "declared_zones": declared_zones,
        "observed_placements": [
            {
                "id": p.get("@id"),
                "region": p.get("region"),
                "environment": p.get("environment_id"),
                "namespace": p.get("namespace"),
            }
            for p in placements
        ],
        "drift_detected": len(violations) > 0,
        "status": "violation" if violations else "ok",
        "findings": findings,
    }


def write_drift_state(
    result: dict[str, Any],
    kg_dir: Path,
    backend: Any | None = None,
) -> list[Path]:
    """Update drift_state on each evaluated Placement node file in kg_dir.

    When backend is provided (a KGBackend instance), the updated Placement node
    is also synced to the graph index via backend.upsert_node() after the file
    write. Both paths stay in sync; neither is primary. File is written first.
    The caller owns the backend lifecycle — this function never closes it.

    Returns the list of paths written.
    """
    workload_name = result["workload"]
    place_dir = kg_dir / "placements"
    if not place_dir.exists():
        return []

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    violation_by_placement: dict[str, list[dict[str, Any]]] = {}
    for f in result["findings"]:
        if f.get("severity") == "violation":
            pid = f.get("placement_id", "")
            violation_by_placement.setdefault(pid, []).append(f)

    written: list[Path] = []
    for path in sorted(place_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") != "Placement":
            continue
        wid = node.get("workload_id", "")
        if not (workload_name in wid or wid == f"workload:{workload_name}"):
            continue

        placement_id = node.get("@id", "")
        node_violations = violation_by_placement.get(placement_id, [])
        node["drift_state"] = {
            "last_evaluated": now,
            "status": "violation" if node_violations else "ok",
            "deviation_hours": None,
            "findings": node_violations,
        }
        path.write_text(json.dumps(node, indent=2))
        written.append(path)

        if backend is not None:
            backend.upsert_node(node)

    return written


def emit_drift_event(result: dict[str, Any], event_file: Path) -> None:
    """Append a structured calm.drift.evaluated event to event_file."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    event = {
        "event_type": "calm.drift.evaluated",
        "timestamp": now,
        "workload": result["workload"],
        "status": result["status"],
        "declared_zones": result["declared_zones"],
        "observed_regions": [p["region"] for p in result.get("observed_placements", [])],
        "findings": result["findings"],
    }
    event_file.parent.mkdir(parents=True, exist_ok=True)
    with event_file.open("a") as fh:
        fh.write(json.dumps(event) + "\n")


def drift_check_post_deploy(
    deployment_status: dict,
    kg_dir: Path,
    backend: Any | None = None,
) -> dict:
    """Run a post-deploy drift check for a completed deployment.

    Loads the Workload KG node to get the CALM spec, runs evaluate_drift(),
    writes drift state to placement nodes, and emits a drift event. Updates
    the deployment_status node's drift_result in-place and returns the full
    drift result.

    When backend is provided, drift_state is also synced to the graph index.
    The caller owns the backend lifecycle.

    Args:
        deployment_status: A DeploymentStatus node dict (from intake_deployment_completion).
        kg_dir:            KG directory containing placements/ and workloads/.
        backend:           Optional KGBackend to sync updated Placement nodes into.

    Returns:
        drift result dict from evaluate_drift() with an added "deployment_status_id" key.
    """
    workload_id = deployment_status.get("workload_id", "")
    workload = _load_workload(kg_dir, workload_id)

    if workload is None:
        result = {
            "workload": workload_id,
            "declared_zones": [],
            "observed_placements": [],
            "drift_detected": False,
            "status": "no_workload_found",
            "findings": [],
            "deployment_status_id": deployment_status.get("@id"),
        }
    else:
        result = evaluate_drift(workload, kg_dir)
        result["deployment_status_id"] = deployment_status.get("@id")
        write_drift_state(result, kg_dir, backend=backend)
        emit_drift_event(result, kg_dir / "drift-events.json")

    deployment_status["drift_result"] = {
        "status": result["status"],
        "drift_detected": result.get("drift_detected", False),
        "findings_count": len(result.get("findings", [])),
    }
    return result


def _try_get_backend(kg_dir: Path) -> Any | None:
    """Resolve a KGBackend from environment variables, or None if not configured.

    Reads CALM_FORGE_KG_BACKEND. When set to "kuzu", constructs a KuzuBackend
    using CALM_FORGE_KG_DB_PATH or the default path <kg_dir>/.calm_forge/kg.db.
    When set to "falkordb", constructs a FalkorDBBackend from CALM_FORGE_KG_URL.
    Returns None for "filesystem" or when the backend package is not installed.

    Emits a warning to stderr when the backend is explicitly configured but
    cannot be constructed (missing install, bad path, etc.).
    """
    import os
    import sys

    backend_type = os.environ.get("CALM_FORGE_KG_BACKEND", "")
    if not backend_type or backend_type == "filesystem":
        return None

    if backend_type == "kuzu":
        db_path = os.environ.get("CALM_FORGE_KG_DB_PATH") or str(
            Path(kg_dir) / ".calm_forge" / "kg.db"
        )
        try:
            from .kg_kuzu_backend import KuzuBackend
            return KuzuBackend(db_path=db_path)
        except ImportError:
            print(
                "WARNING: CALM_FORGE_KG_BACKEND=kuzu but kuzu is not installed. "
                "Run: pip install calm-forge[graph]",
                file=sys.stderr,
            )
            return None
        except Exception as exc:
            print(f"WARNING: Could not open Kuzu backend at {db_path}: {exc}", file=sys.stderr)
            return None

    if backend_type == "falkordb":
        url = os.environ.get("CALM_FORGE_KG_URL", "")
        if not url:
            print(
                "WARNING: CALM_FORGE_KG_BACKEND=falkordb requires CALM_FORGE_KG_URL "
                "(e.g. redis://localhost:6379).",
                file=sys.stderr,
            )
            return None
        try:
            from .kg_falkordb_backend import FalkorDBBackend
            return FalkorDBBackend(url=url)
        except ImportError:
            print(
                "WARNING: CALM_FORGE_KG_BACKEND=falkordb but falkordb is not installed. "
                "Run: pip install calm-forge[graph]",
                file=sys.stderr,
            )
            return None
        except Exception as exc:
            print(f"WARNING: Could not connect FalkorDB backend at {url}: {exc}", file=sys.stderr)
            return None

    print(
        f"WARNING: Unknown CALM_FORGE_KG_BACKEND={backend_type!r}. "
        "Valid: kuzu, falkordb, filesystem",
        file=sys.stderr,
    )
    return None


def _check_capability_ceiling(
    placement: dict[str, Any],
    kg_dir: Path,
    findings: list[dict[str, Any]],
) -> None:
    """Add a violation finding if capabilities_granted exceeds declared_capabilities.

    Skipped when no Workload node with declared capabilities exists in the live KG
    — we can only enforce the invariant when ground truth has been authored.
    """
    workload_id = placement.get("workload_id", "")
    workload = _load_workload(kg_dir, workload_id)
    if workload is None:
        return
    declared = _get_declared_capabilities(workload)
    if not declared:
        return

    for edge in placement.get("edges", []):
        if edge.get("@type") != "manifests_as":
            continue
        granted = set(edge.get("capabilities_granted", []))
        excess = granted - declared
        if excess:
            findings.append({
                "severity": "violation",
                "rule": "capability-ceiling",
                "placement_id": placement.get("@id", ""),
                "excess_capabilities": sorted(excess),
                "message": (
                    f"capabilities_granted exceeds declared: {sorted(excess)}"
                ),
            })


def _load_workload(kg_dir: Path, workload_id: str) -> dict[str, Any] | None:
    wl_dir = kg_dir / "workloads"
    if not wl_dir.exists():
        return None
    for path in wl_dir.glob("*.json"):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@id") == workload_id:
            return node
    return None


def _get_declared_capabilities(workload: dict[str, Any]) -> set[str]:
    """Collect declared capabilities from a Workload node.

    Checks flat declared_capabilities first, then walks component nodes.
    Returns empty set when no capabilities are declared.
    """
    flat = workload.get("declared_capabilities", [])
    if flat:
        return set(flat)
    result: set[str] = set()
    for component in workload.get("nodes", []):
        result.update(component.get("declared_capabilities", []))
    return result


def _declared_zones(calm: dict[str, Any]) -> list[str]:
    """Extract declared zones from CALM metadata (data-residency field).

    Checks metadata.data-residency, metadata.data.data-residency, and
    metadata.data.region in that order.
    """
    metadata = calm.get("metadata", {})
    zones = (
        metadata.get("data-residency")
        or metadata.get("data", {}).get("data-residency")
        or metadata.get("data", {}).get("region")
    )
    if isinstance(zones, str):
        return [zones]
    return list(zones) if zones else []


def _derive_workload_name(calm: dict[str, Any]) -> str:
    """Derive a slug workload name from the CALM metadata title."""
    title = calm.get("metadata", {}).get("name", calm.get("title", "unknown"))
    title = re.split(r"\s*[—–]\s*|\s+-\s+", title)[0].strip()
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def _load_placements(kg_dir: Path, workload_name: str) -> list[dict[str, Any]]:
    """Load Placement nodes from kg_dir/placements/ matching the workload name."""
    place_dir = kg_dir / "placements"
    if not place_dir.exists():
        return []

    placements: list[dict[str, Any]] = []
    for path in sorted(place_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") != "Placement":
            continue
        wid = node.get("workload_id", "")
        if workload_name in wid or wid == f"workload:{workload_name}":
            placements.append(node)
    return placements


# ---------------------------------------------------------------------------
# Curvature trending
# ---------------------------------------------------------------------------

_CURVATURE_HISTORY_FILE = "_fabric/curvature-history.jsonl"


def record_curvature(workload_id: str, curvature: float, kg_dir: Path) -> None:
    """Append a curvature sample for a workload to the history log.

    Args:
        workload_id: Workload identifier (e.g. "workload:fraud-v1").
        curvature:   ManifoldEngine curvature score for this run.
        kg_dir:      KG directory root.
    """
    fabric_dir = Path(kg_dir) / "_fabric"
    fabric_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "workload_id": workload_id,
        "curvature": curvature,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    history_path = Path(kg_dir) / _CURVATURE_HISTORY_FILE
    with history_path.open("a") as fh:
        fh.write(json.dumps(record) + "\n")


def load_curvature_history(
    kg_dir: Path,
    workload_id: str | None = None,
) -> list[dict[str, Any]]:
    """Read the curvature history log, optionally filtered by workload_id."""
    path = Path(kg_dir) / _CURVATURE_HISTORY_FILE
    if not path.exists():
        return []
    records = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if workload_id is None or rec.get("workload_id") == workload_id:
            records.append(rec)
    return records


def curvature_trend(
    workload_id: str,
    kg_dir: Path,
    window: int = 10,
) -> dict[str, Any]:
    """Compute the curvature trend for a workload over the last N samples.

    Args:
        workload_id: Workload identifier.
        kg_dir:      KG directory root.
        window:      Number of most-recent samples to consider.

    Returns:
        dict with:
          workload_id:  str
          samples:      list[{curvature, timestamp}]
          slope:        float  (positive = degrading, negative = improving)
          trend:        "improving" | "stable" | "degrading" | "insufficient-data"
    """
    history = load_curvature_history(kg_dir, workload_id)
    samples = history[-window:] if len(history) > window else history

    if len(samples) < 2:
        return {
            "workload_id": workload_id,
            "samples": samples,
            "slope": 0.0,
            "trend": "insufficient-data",
        }

    values = [s["curvature"] for s in samples]
    n = len(values)
    xs = list(range(n))
    x_mean = sum(xs) / n
    y_mean = sum(values) / n
    numerator = sum((xs[i] - x_mean) * (values[i] - y_mean) for i in range(n))
    denominator = sum((x - x_mean) ** 2 for x in xs)
    slope = round(numerator / denominator, 6) if denominator != 0 else 0.0

    _STABLE_THRESHOLD = 1e-6
    if abs(slope) <= _STABLE_THRESHOLD:
        trend = "stable"
    elif slope < 0:
        trend = "improving"
    else:
        trend = "degrading"

    return {
        "workload_id": workload_id,
        "samples": samples,
        "slope": slope,
        "trend": trend,
    }
