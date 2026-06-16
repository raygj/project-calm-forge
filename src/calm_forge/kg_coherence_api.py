"""KG coherence API — XC_ADR-008 federation endpoint.

Exposes three read-only endpoints for cross-commune coherence queries.
Stateless: every request reads from the filesystem. The Reasoner owns the cache (30s TTL).

Endpoints:
  GET  /graph/coherence?workload_id=X[&agent_id=Y]
  POST /graph/shadow   {"agent_workload_ids": [...]}
  GET  /graph/drift?workload_id=X[&status=<filter>]
  GET  /graph/adjacent?workload_id=X[&basis=<filter>]   (ADR-FORGE-KG-002)

KG directory is configured via CALM_FORGE_KG_DIR env var or by calling
configure_coherence_kg_dir() at app startup.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .coherence_auth import require_coherence_auth

router = APIRouter(
    prefix="/graph",
    tags=["coherence"],
    dependencies=[Depends(require_coherence_auth)],
)

# ---------------------------------------------------------------------------
# Startup configuration
# ---------------------------------------------------------------------------

_kg_dir: Path | None = None


def configure_coherence_kg_dir(kg_dir: Path | str) -> None:
    global _kg_dir
    _kg_dir = Path(kg_dir)


def _get_kg_dir() -> Path:
    if _kg_dir is not None:
        return _kg_dir
    env = os.environ.get("CALM_FORGE_KG_DIR")
    if env:
        return Path(env)
    raise HTTPException(
        status_code=503,
        detail="KG directory not configured. Set CALM_FORGE_KG_DIR or call configure_coherence_kg_dir().",
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class CoherenceResponse(BaseModel):
    workload_id: str
    curvature: float
    coherence_lag: str | None
    calm_forge_last_sync: str | None
    federation_available: bool
    placements: list[dict[str, Any]]


class ShadowAgent(BaseModel):
    """A runtime agent reference, normalized by the Reasoner before POST.

    workload_id  : SPIFFE-prefix-stripped match key (e.g. "workload:payments")
    trust_domain : the agent's SPIFFE trust domain (bare name or trust_domain:<name>)
    """
    workload_id: str
    trust_domain: str


class ShadowRequest(BaseModel):
    """Either field may be used; `agents` enables trust-domain-scoped matching.

    agent_workload_ids : legacy flat list — advisory-only matching (no trust
                         domain scoping). Kept for pre-ADR-0024-extension callers.
    agents             : trust-scoped agent references — enables the canonical
                         ADR-0024 match predicate.
    """
    agent_workload_ids: list[str] = []
    agents: list[ShadowAgent] = []


class ShadowResponse(BaseModel):
    shadow_agents: list[str]
    unmatched_authored: list[str]
    unmatched_reconstructed: list[str]
    calm_forge_last_sync: str | None
    scoped: bool = False
    trust_domain_mismatches: list[dict[str, Any]] = []


class DriftResponse(BaseModel):
    workload_id: str | None
    placements: list[dict[str, Any]]
    calm_forge_last_sync: str | None


class AdjacentNeighbor(BaseModel):
    workload_id: str
    basis: list[str]
    shared_trust_domains: list[str] = []
    shared_environments: list[str] = []


class AdjacentResponse(BaseModel):
    workload_id: str
    neighbors: list[AdjacentNeighbor]
    bases_evaluated: list[str]
    calm_forge_last_sync: str | None


# ---------------------------------------------------------------------------
# Core query functions (used by endpoints and directly in tests)
# ---------------------------------------------------------------------------


def query_coherence(kg_dir: Path, workload_id: str) -> dict[str, Any]:
    """Return coherence state for a workload: curvature, lag, drift placements."""
    from .drift_evaluator import load_curvature_history
    from .kg_query import _load_nodes

    all_placements = _load_nodes(kg_dir / "placements", "Placement")
    placements = [p for p in all_placements if p.get("workload_id") == workload_id]

    # Latest curvature sample for this workload
    history = load_curvature_history(kg_dir, workload_id)
    curvature = history[-1]["curvature"] if history else 0.0
    last_curvature_ts = history[-1]["timestamp"] if history else None

    # Latest evaluation timestamp across placements
    last_eval: str | None = None
    for p in placements:
        ts = p.get("drift_state", {}).get("last_evaluated") or p.get("last_evaluated")
        if ts and (last_eval is None or ts > last_eval):
            last_eval = ts

    calm_forge_last_sync = last_curvature_ts or last_eval

    coherence_lag = _compute_lag(calm_forge_last_sync)

    return {
        "workload_id": workload_id,
        "curvature": curvature,
        "coherence_lag": coherence_lag,
        "calm_forge_last_sync": calm_forge_last_sync,
        "federation_available": True,
        "placements": [_placement_summary(p) for p in placements],
    }


def query_shadow(
    kg_dir: Path,
    agent_workload_ids: list[str] | None = None,
    agents: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Diff runtime agent workload IDs against declared CALM Forge workloads.

    CALM Forge does no SPIFFE normalization — caller (Reasoner) strips the
    SPIFFE prefix and extracts the trust domain before POST.

    Two modes:

    Scoped (agents provided) — the canonical ADR-0024 match predicate:
        agent matches workload iff
          agent.workload_id == workload["@id"]
          AND agent.trust_domain ∈ workload.trust_domains
      An agent whose key matches a workload but whose trust domain is not in
      the workload's declared trust_domains is a shadow agent, and the
      near-miss is reported in trust_domain_mismatches for operator triage.
      Trust domain values are compared after stripping the canonical
      "trust_domain:" ID prefix from both sides, so "prod.fsi" and
      "trust_domain:prod.fsi" are equivalent.

    Legacy (agent_workload_ids provided) — flat set difference, no trust
      domain scoping. Advisory only — governance signal, not a revocation
      input. Kept for pre-ADR-0024-extension callers.

    Returns:
      shadow_agents           : agent IDs present in runtime with no CALM Forge workload
      unmatched_authored      : authored workloads with no corresponding runtime agent
      unmatched_reconstructed : reconstructed workloads with no corresponding runtime agent
      scoped                  : True when the trust-domain-scoped predicate was applied
      trust_domain_mismatches : key-matched agents rejected on trust domain (scoped mode)
    """
    from .kg_query import _load_nodes

    workload_nodes = _load_nodes(kg_dir / "workloads", "Workload")

    authored_ids = {
        w["@id"] for w in workload_nodes
        if w.get("_provenance", {}).get("provenance") != "reconstructed"
    }
    reconstructed_ids = {
        w["@id"] for w in workload_nodes
        if w.get("_provenance", {}).get("provenance") == "reconstructed"
    }

    calm_forge_last_sync = _last_sync_timestamp(kg_dir)

    if agents:
        workload_domains = {
            w["@id"]: {_norm_trust_domain(d) for d in w.get("trust_domains", [])}
            for w in workload_nodes
        }

        shadow_agents: list[str] = []
        mismatches: list[dict[str, Any]] = []
        matched_workload_ids: set[str] = set()

        for agent in agents:
            aid = agent["workload_id"]
            adomain = _norm_trust_domain(agent["trust_domain"])
            declared = workload_domains.get(aid)
            if declared is None:
                shadow_agents.append(aid)
            elif adomain in declared:
                matched_workload_ids.add(aid)
            else:
                # Key matched, trust domain did not — shadow per ADR-0024
                # match predicate, surfaced separately for operator triage.
                shadow_agents.append(aid)
                mismatches.append({
                    "agent_workload_id": aid,
                    "agent_trust_domain": agent["trust_domain"],
                    "workload_trust_domains": sorted(declared),
                })

        return {
            "shadow_agents": sorted(set(shadow_agents)),
            "unmatched_authored": sorted(authored_ids - matched_workload_ids),
            "unmatched_reconstructed": sorted(reconstructed_ids - matched_workload_ids),
            "calm_forge_last_sync": calm_forge_last_sync,
            "scoped": True,
            "trust_domain_mismatches": mismatches,
        }

    all_kg_ids = authored_ids | reconstructed_ids
    agent_set = set(agent_workload_ids or [])

    return {
        "shadow_agents": sorted(agent_set - all_kg_ids),
        "unmatched_authored": sorted(authored_ids - agent_set),
        "unmatched_reconstructed": sorted(reconstructed_ids - agent_set),
        "calm_forge_last_sync": calm_forge_last_sync,
        "scoped": False,
        "trust_domain_mismatches": [],
    }


def _norm_trust_domain(value: str) -> str:
    """Strip the canonical trust_domain: ID prefix for comparison."""
    return value.removeprefix("trust_domain:")


_ENABLED_BASES = ("shared_trust_domain", "co_located")
_PHASE_GATED_BASES = ("blast_radius",)


def query_adjacent(
    kg_dir: Path,
    workload_id: str,
    basis: str | None = None,
) -> dict[str, Any]:
    """Evaluate the canonical adjacency predicate (ADR-FORGE-KG-002).

    adjacent(w1, w2) holds iff at least one enabled basis relation holds.
    Every neighbor carries which basis fired and the supporting evidence —
    a correlation decision that cannot name its basis must not be acted on.

    Bases:
      shared_trust_domain — norm(w1.trust_domains) ∩ norm(w2.trust_domains) ≠ ∅
      co_located          — placements share an ExecutionEnvironment
                            (matched on Placement.workload_id / environment_id,
                            so reconstructed workloads participate)
      blast_radius        — PHASE-GATED: raises NotImplementedError until
                            DEPENDS_ON edges land (see ADR-FORGE-KG-002).

    Args:
        basis: restrict evaluation to a single basis; None evaluates all
               enabled bases. Unknown basis raises ValueError.
    """
    from .kg_query import _load_nodes

    if basis is not None and basis in _PHASE_GATED_BASES:
        raise NotImplementedError(
            f"basis {basis!r} is phase-gated: DEPENDS_ON edges are not yet "
            "ingested into the graph tier. See ADR-FORGE-KG-002 acceptance criteria."
        )
    if basis is not None and basis not in _ENABLED_BASES:
        raise ValueError(
            f"Unknown adjacency basis {basis!r}. "
            f"Enabled: {', '.join(_ENABLED_BASES)}; phase-gated: {', '.join(_PHASE_GATED_BASES)}"
        )

    bases = (basis,) if basis else _ENABLED_BASES
    neighbors: dict[str, dict[str, Any]] = {}

    if "shared_trust_domain" in bases:
        workload_nodes = _load_nodes(kg_dir / "workloads", "Workload")
        own = next((w for w in workload_nodes if w.get("@id") == workload_id), None)
        own_domains = {
            _norm_trust_domain(d) for d in (own or {}).get("trust_domains", [])
        }
        if own_domains:
            for w in workload_nodes:
                wid = w.get("@id", "")
                if wid == workload_id:
                    continue
                shared = own_domains & {
                    _norm_trust_domain(d) for d in w.get("trust_domains", [])
                }
                if shared:
                    entry = neighbors.setdefault(
                        wid, {"workload_id": wid, "basis": [],
                              "shared_trust_domains": [], "shared_environments": []},
                    )
                    entry["basis"].append("shared_trust_domain")
                    entry["shared_trust_domains"] = sorted(shared)

    if "co_located" in bases:
        placements = _load_nodes(kg_dir / "placements", "Placement")
        own_envs = {
            p.get("environment_id", "") for p in placements
            if p.get("workload_id") == workload_id and p.get("environment_id")
        }
        if own_envs:
            for p in placements:
                wid = p.get("workload_id", "")
                env = p.get("environment_id", "")
                if wid == workload_id or not wid or env not in own_envs:
                    continue
                entry = neighbors.setdefault(
                    wid, {"workload_id": wid, "basis": [],
                          "shared_trust_domains": [], "shared_environments": []},
                )
                if "co_located" not in entry["basis"]:
                    entry["basis"].append("co_located")
                if env not in entry["shared_environments"]:
                    entry["shared_environments"].append(env)

    for entry in neighbors.values():
        entry["shared_environments"].sort()

    return {
        "workload_id": workload_id,
        "neighbors": sorted(neighbors.values(), key=lambda n: n["workload_id"]),
        "bases_evaluated": list(bases),
        "calm_forge_last_sync": _last_sync_timestamp(kg_dir),
    }


def query_drift(kg_dir: Path, workload_id: str | None, status: str | None) -> dict[str, Any]:
    """Return placement drift state, optionally filtered by workload_id and status."""
    from .kg_query import _load_nodes

    all_placements = _load_nodes(kg_dir / "placements", "Placement")

    results = all_placements
    if workload_id:
        results = [p for p in results if p.get("workload_id") == workload_id]
    if status:
        results = [
            p for p in results
            if p.get("drift_state", {}).get("status") == status
        ]

    calm_forge_last_sync = _last_sync_timestamp(kg_dir)

    return {
        "workload_id": workload_id,
        "placements": [_placement_summary(p) for p in results],
        "calm_forge_last_sync": calm_forge_last_sync,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/coherence", response_model=CoherenceResponse)
async def coherence_endpoint(workload_id: str, agent_id: str | None = None) -> CoherenceResponse:
    """Coherence state for a workload: curvature, lag, and drift placements.

    agent_id is accepted for future use (cross-commune JOIN context) but is not
    required — CALM Forge does not hold runtime agent state.
    """
    kg_dir = _get_kg_dir()
    result = query_coherence(kg_dir, workload_id)
    return CoherenceResponse(**result)


@router.post("/shadow", response_model=ShadowResponse)
async def shadow_endpoint(req: ShadowRequest) -> ShadowResponse:
    """Shadow detection: which runtime agents have no declared CALM Forge workload.

    Caller (Reasoner) must normalize agent IDs — strip SPIFFE prefix — before POST.
    Send `agents` (with trust_domain) for the canonical ADR-0024 scoped predicate;
    `agent_workload_ids` falls back to the legacy advisory flat diff.
    """
    kg_dir = _get_kg_dir()
    result = query_shadow(
        kg_dir,
        agent_workload_ids=req.agent_workload_ids,
        agents=[a.model_dump() for a in req.agents],
    )
    return ShadowResponse(**result)


@router.get("/adjacent", response_model=AdjacentResponse)
async def adjacent_endpoint(workload_id: str, basis: str | None = None) -> AdjacentResponse:
    """Canonical adjacency predicate (ADR-FORGE-KG-002).

    Returns workloads adjacent to workload_id with the basis relation(s) that
    fired and supporting evidence. basis=blast_radius returns 501 until
    DEPENDS_ON ingestion lands (phase gate); unknown basis returns 400.
    """
    kg_dir = _get_kg_dir()
    try:
        result = query_adjacent(kg_dir, workload_id, basis=basis)
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return AdjacentResponse(**result)


@router.get("/drift", response_model=DriftResponse)
async def drift_endpoint(workload_id: str | None = None, status: str | None = None) -> DriftResponse:
    """Drift state for placements, optionally filtered by workload_id and/or drift status."""
    kg_dir = _get_kg_dir()
    result = query_drift(kg_dir, workload_id, status)
    return DriftResponse(**result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _placement_summary(p: dict[str, Any]) -> dict[str, Any]:
    drift = p.get("drift_state", {})
    return {
        "id": p.get("@id"),
        "workload_id": p.get("workload_id"),
        "region": p.get("region"),
        "drift_status": drift.get("status"),
        "deviation_hours": drift.get("deviation_hours"),
        "last_evaluated": drift.get("last_evaluated") or p.get("last_evaluated"),
        "observed_capabilities": p.get("observed_capabilities", []),
    }


def _compute_lag(last_sync: str | None) -> str | None:
    """Compute ISO-8601 duration between last_sync and now.

    WIRE-FORMAT CONTRACT (reasoner--calm-forge handshake, 2026-06-12):
    coherence_lag is always either null or an ISO-8601 duration of the exact
    shape "PT<integer>S" (whole seconds, never negative). The Reasoner parses
    this format; changing it silently degrades every shadow proposal to medium
    confidence. Treat any change here as a contract amendment, not a refactor.
    """
    if not last_sync:
        return None
    try:
        last = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - last
        total_seconds = int(delta.total_seconds())
        if total_seconds < 0:
            total_seconds = 0
        return f"PT{total_seconds}S"
    except (ValueError, TypeError):
        return None


def _last_sync_timestamp(kg_dir: Path) -> str | None:
    """Return the most recent curvature or bootstrap timestamp as a proxy for last sync."""
    from .kg_bootstrap import load_bootstrap_history
    history = load_bootstrap_history(kg_dir)
    if history:
        return history[-1].get("timestamp")
    return None
