"""FalkorDBBackend — Redis-protocol scale-out implementation of KGBackend.

Tier 2 of the two-tier backend plan (ADR-FORGE-KG-001).
Use when the KG outgrows a single embedded index: shared access from
multiple processes/hosts, or node counts beyond Kuzu's comfortable range.
JSON-LD files remain authoritative; this is the query index.

Install: pip install calm-forge[graph]
Connect: CALM_FORGE_KG_BACKEND=falkordb CALM_FORGE_KG_URL=redis://host:6379

FalkorDB is schemaless — the node/edge property layout intentionally mirrors
the Kuzu schema (kg_kuzu_backend.py) so Cypher written for one tier runs on
the other.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .kg_kuzu_backend import KGInvariantViolation, _list, _load_dir

_DEFAULT_GRAPH = "calm_forge_kg"

_INDEXED_LABELS = (
    "Workload",
    "ExecutionEnvironment",
    "Placement",
    "PlacementPolicy",
    "TrustDomain",
)


class FalkorDBBackend:
    """FalkorDB (Redis-protocol) graph backend.

    Property layout matches KuzuBackend so the three canonical ADR queries
    (blast radius, repave candidates, resilience gap) are tier-portable.

    Args:
        url:        Redis URL, e.g. "redis://localhost:6379". Required unless
                    a graph handle is injected.
        graph_name: FalkorDB graph key (default: calm_forge_kg).
        graph:      Pre-built graph handle (testing / connection reuse).
    """

    def __init__(
        self,
        url: str | None = None,
        graph_name: str = _DEFAULT_GRAPH,
        graph: Any | None = None,
    ) -> None:
        self._db = None
        if graph is not None:
            self._graph = graph
        else:
            if not url:
                raise ValueError("FalkorDBBackend requires url or an injected graph")
            try:
                from falkordb import FalkorDB
            except ImportError as exc:
                raise ImportError(
                    "FalkorDBBackend requires: pip install calm-forge[graph]"
                ) from exc
            self._db = FalkorDB.from_url(url)
            self._graph = self._db.select_graph(graph_name)
        self._ensure_indexes()

    # ------------------------------------------------------------------
    # KGBackend protocol
    # ------------------------------------------------------------------

    def load(self, kg_dir: str | Path) -> None:
        """Ingest all JSON-LD files from kg_dir into the FalkorDB index.

        Same ordering and invariant enforcement as KuzuBackend.load():
        TrustDomain → Workload → ExecutionEnvironment → Placement →
        PlacementPolicy; capabilities_granted ⊆ declared_capabilities is
        checked at Placement load time for authored workloads.

        Raises:
            KGInvariantViolation: if a MANIFESTS_AS edge grants capabilities
                beyond the source Workload's declared set (authored workloads only).
        """
        kg_dir = Path(kg_dir)

        workload_caps: dict[str, set[str]] = {}

        for node in _load_dir(kg_dir / "trust_domains", "TrustDomain"):
            self.upsert_node(node)

        for node in _load_dir(kg_dir / "workloads", "Workload"):
            self.upsert_node(node)
            if node.get("_provenance", {}).get("provenance") != "reconstructed":
                workload_caps[node["@id"]] = set(node.get("declared_capabilities", []))

        for node in _load_dir(kg_dir / "environments", "ExecutionEnvironment"):
            self.upsert_node(node)

        for node in _load_dir(kg_dir / "placements", "Placement"):
            for edge in node.get("edges", []):
                if edge.get("@type") == "manifests_as":
                    from_id = edge.get("from", "")
                    granted = set(edge.get("capabilities_granted", []))
                    declared = workload_caps.get(from_id)
                    if declared is not None and not granted.issubset(declared):
                        excess = granted - declared
                        raise KGInvariantViolation(
                            f"MANIFESTS_AS edge from {from_id!r} grants capabilities "
                            f"beyond declared set: {sorted(excess)}. "
                            f"Declared: {sorted(declared)}, Granted: {sorted(granted)}"
                        )
            self.upsert_node(node)

        for node in _load_dir(kg_dir / "policies", "PlacementPolicy"):
            self.upsert_node(node)

    def query(self, cypher: str, params: dict | None = None) -> list[dict[str, Any]]:
        """Execute a Cypher query. Returns list of result records as dicts."""
        result = self._graph.query(cypher, params or {})
        cols = [h[1] if isinstance(h, (list, tuple)) else h for h in result.header]
        return [dict(zip(cols, row)) for row in result.result_set]

    def upsert_node(self, node: dict) -> None:
        """Insert or update a node from a JSON-LD dict, dispatching on @type."""
        node_type = node.get("@type")
        if node_type == "Workload":
            self._upsert_workload(node)
        elif node_type == "TrustDomain":
            self._upsert_trust_domain(node)
        elif node_type == "ExecutionEnvironment":
            self._upsert_environment(node)
        elif node_type == "Placement":
            self._upsert_placement(node)
        elif node_type == "PlacementPolicy":
            self._upsert_policy(node)
        # Unknown types are silently skipped — future node types don't break load.

    def upsert_edge(self, edge: dict) -> None:
        """Insert or update an edge from a JSON-LD edge dict."""
        edge_type = edge.get("@type", "").lower()
        if edge_type == "manifests_as":
            self._upsert_manifests_as_edge(edge)
        elif edge_type == "placed_on":
            self._upsert_placed_on_edge(edge)

    def close(self) -> None:
        if self._db is not None:
            conn = getattr(self._db, "connection", None)
            if conn is not None and hasattr(conn, "close"):
                conn.close()

    # ------------------------------------------------------------------
    # Node upserts
    # ------------------------------------------------------------------

    def _upsert_workload(self, node: dict) -> None:
        prov = node.get("_provenance", {})
        self._graph.query(
            "MERGE (w:Workload {id: $id}) "
            "SET w.declared_capabilities = $declared_capabilities, "
            "    w.compliance_scope = $compliance_scope, "
            "    w.provenance = $provenance, "
            "    w.name = $name, "
            "    w.tags = $tags, "
            "    w.review_required = $review_required, "
            "    w.trust_domains = $trust_domains",
            {
                "id": node.get("@id", ""),
                "declared_capabilities": node.get("declared_capabilities", []),
                "compliance_scope": _list(node.get("compliance_scope")),
                "provenance": prov.get("provenance", "authored"),
                "name": node.get("name", ""),
                "tags": _list(node.get("tags")),
                "review_required": bool(node.get("review_required", False)),
                "trust_domains": _list(node.get("trust_domains")),
            },
        )

    def _upsert_trust_domain(self, node: dict) -> None:
        self._graph.query(
            "MERGE (t:TrustDomain {id: $id}) "
            "SET t.spiffe_uri_prefix = $spiffe_uri_prefix, "
            "    t.commune = $commune, "
            "    t.peer_trust_domains = $peer_trust_domains",
            {
                "id": node.get("@id", ""),
                "spiffe_uri_prefix": node.get("spiffe_uri_prefix", ""),
                "commune": node.get("commune", ""),
                "peer_trust_domains": _list(node.get("peer_trust_domains")),
            },
        )

    def _upsert_environment(self, node: dict) -> None:
        labels = node.get("labels", {})
        compliance_label = labels.get("compliance", "")
        labels_compliance = [compliance_label] if compliance_label else []

        self._graph.query(
            "MERGE (e:ExecutionEnvironment {id: $id}) "
            "SET e.region = $region, "
            "    e.status = $status, "
            "    e.advertised_capabilities = $advertised_capabilities, "
            "    e.labels_compliance = $labels_compliance, "
            "    e.repave_friendly = $repave_friendly",
            {
                "id": node.get("@id", ""),
                "region": node.get("region", ""),
                "status": node.get("status", "unknown"),
                "advertised_capabilities": _list(node.get("advertised_capabilities")),
                "labels_compliance": labels_compliance,
                "repave_friendly": bool(node.get("repave_friendly", False)),
            },
        )

    def _upsert_placement(self, node: dict) -> None:
        node_id = node.get("@id", "")
        drift = node.get("drift_state", {})
        deviation = drift.get("deviation_hours")

        self._graph.query(
            "MERGE (p:Placement {id: $id}) "
            "SET p.workload_id = $workload_id, "
            "    p.environment_id = $environment_id, "
            "    p.region = $region, "
            "    p.observed_capabilities = $observed_capabilities, "
            "    p.drift_state_status = $drift_state_status, "
            "    p.drift_state_deviation_hours = $drift_state_deviation_hours, "
            "    p.last_evaluated = $last_evaluated",
            {
                "id": node_id,
                "workload_id": node.get("workload_id", ""),
                "environment_id": node.get("environment_id", ""),
                "region": node.get("region", ""),
                "observed_capabilities": _list(node.get("observed_capabilities")),
                "drift_state_status": drift.get("status", "pending_first_evaluation"),
                "drift_state_deviation_hours": float(deviation) if deviation is not None else 0.0,
                "last_evaluated": drift.get("last_evaluated") or "",
            },
        )

        for edge in node.get("edges", []):
            if edge.get("@type") == "manifests_as":
                self._upsert_manifests_as_edge({
                    "@type": "manifests_as",
                    "from": edge.get("from", ""),
                    "to": node_id,
                    "capabilities_granted": edge.get("capabilities_granted", []),
                    "manifested_at": edge.get("manifested_at", ""),
                    "attestation_level": edge.get("attestation_level", ""),
                })

        env_id = node.get("environment_id", "")
        if env_id:
            self._upsert_placed_on_edge({"from": node_id, "to": env_id})

    def _upsert_policy(self, node: dict) -> None:
        self._graph.query(
            "MERGE (pp:PlacementPolicy {id: $id}) "
            "SET pp.workload_id = $workload_id, "
            "    pp.source = $source, "
            "    pp.risk_score = $risk_score, "
            "    pp.risk_level = $risk_level, "
            "    pp.constraint = $constraint",
            {
                "id": node.get("@id", ""),
                "workload_id": node.get("workload_id", ""),
                "source": node.get("source", ""),
                "risk_score": float(node.get("risk_score", 0.0)),
                "risk_level": node.get("risk_level", "low"),
                "constraint": node.get("constraint", "no_constraint"),
            },
        )

    # ------------------------------------------------------------------
    # Edge upserts
    # ------------------------------------------------------------------

    def _upsert_manifests_as_edge(self, edge: dict) -> None:
        from_id = edge.get("from", "")
        to_id = edge.get("to", "")
        if not from_id or not to_id:
            return
        # Only insert if both endpoints exist — silently skip dangling edges.
        self._graph.query(
            "MATCH (w:Workload {id: $from_id}), (p:Placement {id: $to_id}) "
            "MERGE (w)-[r:MANIFESTS_AS]->(p) "
            "SET r.capabilities_granted = $capabilities_granted, "
            "    r.manifested_at = $manifested_at, "
            "    r.attestation_level = $attestation_level",
            {
                "from_id": from_id,
                "to_id": to_id,
                "capabilities_granted": _list(edge.get("capabilities_granted")),
                "manifested_at": edge.get("manifested_at", ""),
                "attestation_level": edge.get("attestation_level", ""),
            },
        )

    def _upsert_placed_on_edge(self, edge: dict) -> None:
        from_id = edge.get("from", "")
        to_id = edge.get("to", "")
        if not from_id or not to_id:
            return
        self._graph.query(
            "MATCH (p:Placement {id: $from_id}), (e:ExecutionEnvironment {id: $to_id}) "
            "MERGE (p)-[:PLACED_ON]->(e)",
            {"from_id": from_id, "to_id": to_id},
        )

    # ------------------------------------------------------------------
    # Indexes
    # ------------------------------------------------------------------

    def _ensure_indexes(self) -> None:
        """Create id indexes per label. FalkorDB errors on re-create — tolerated."""
        for label in _INDEXED_LABELS:
            try:
                self._graph.query(f"CREATE INDEX FOR (n:{label}) ON (n.id)")
            except Exception:
                pass
