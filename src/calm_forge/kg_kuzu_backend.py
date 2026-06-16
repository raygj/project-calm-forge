"""KuzuBackend — Kuzu embedded graph database implementation of KGBackend.

Tier 1 of the two-tier backend plan (ADR-FORGE-KG-001).
Zero infra dependency: ships as a Python package, no daemon required.
JSON-LD files remain authoritative; this is the query index.

Install: pip install calm-forge[graph]
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class KGInvariantViolation(Exception):
    """capabilities_granted ⊆ declared_capabilities invariant failed at load time.

    A MANIFESTS_AS edge carries capabilities that exceed the source Workload's
    declared set, meaning runtime exceeded design intent.
    """


class KuzuBackend:
    """Kuzu embedded graph backend.

    Schema covers the three canonical ADR queries:
      1. Blast radius  — Placement -PLACED_ON-> ExecutionEnvironment
      2. Repave candidates — same traversal, drift + repave filters
      3. Resilience gap — Workload -MANIFESTS_AS-> Placement -PLACED_ON-> Environment (3-hop)

    Node load order: Workload → ExecutionEnvironment → Placement → PlacementPolicy.
    Invariant check runs at Placement load time so declared_capabilities are already indexed.
    """

    def __init__(self, db_path: str | Path) -> None:
        try:
            import kuzu
        except ImportError as exc:
            raise ImportError("KuzuBackend requires: pip install calm-forge[graph]") from exc

        self._kuzu = kuzu
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = kuzu.Database(str(self._db_path))
        self._conn = kuzu.Connection(self._db)
        self._ensure_schema()

    # ------------------------------------------------------------------
    # KGBackend protocol
    # ------------------------------------------------------------------

    def load(self, kg_dir: str | Path) -> None:
        """Ingest all JSON-LD files from kg_dir into the Kuzu index.

        Load order: Workload → ExecutionEnvironment → Placement → PlacementPolicy.
        Invariant (capabilities_granted ⊆ declared_capabilities) is enforced at
        Placement load time. Reconstructed workloads without declared_capabilities
        are skipped for the invariant check — their gap is a schema gap, not a
        compliance violation.

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
        result = self._conn.execute(cypher, parameters=params or {})
        # A single Cypher statement yields one QueryResult; kuzu types execute()
        # as QueryResult | list[QueryResult] to cover multi-statement queries.
        if isinstance(result, list):
            result = result[0]
        cols = result.get_column_names()
        rows = []
        while result.has_next():
            rows.append(dict(zip(cols, result.get_next())))
        return rows

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
        self._conn.close()
        self._db.close()

    # ------------------------------------------------------------------
    # Node upserts
    # ------------------------------------------------------------------

    def _upsert_workload(self, node: dict) -> None:
        node_id = node.get("@id", "")
        prov = node.get("_provenance", {})
        self._conn.execute(
            "MERGE (w:Workload {id: $id}) "
            "SET w.declared_capabilities = $declared_capabilities, "
            "    w.compliance_scope = $compliance_scope, "
            "    w.provenance = $provenance, "
            "    w.name = $name, "
            "    w.tags = $tags, "
            "    w.review_required = $review_required, "
            "    w.trust_domains = $trust_domains",
            parameters={
                "id": node_id,
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
        """Upsert a TrustDomain node (shared type, ADR-0024 2026-05-30 extension)."""
        self._conn.execute(
            "MERGE (t:TrustDomain {id: $id}) "
            "SET t.spiffe_uri_prefix = $spiffe_uri_prefix, "
            "    t.commune = $commune, "
            "    t.peer_trust_domains = $peer_trust_domains",
            parameters={
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

        self._conn.execute(
            "MERGE (e:ExecutionEnvironment {id: $id}) "
            "SET e.region = $region, "
            "    e.status = $status, "
            "    e.advertised_capabilities = $advertised_capabilities, "
            "    e.labels_compliance = $labels_compliance, "
            "    e.repave_friendly = $repave_friendly",
            parameters={
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

        self._conn.execute(
            "MERGE (p:Placement {id: $id}) "
            "SET p.workload_id = $workload_id, "
            "    p.environment_id = $environment_id, "
            "    p.region = $region, "
            "    p.observed_capabilities = $observed_capabilities, "
            "    p.drift_state_status = $drift_state_status, "
            "    p.drift_state_deviation_hours = $drift_state_deviation_hours, "
            "    p.last_evaluated = $last_evaluated",
            parameters={
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

        # Upsert edges stored inline on the Placement node
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

        # Upsert PLACED_ON edge if environment_id is known
        env_id = node.get("environment_id", "")
        if env_id:
            self._upsert_placed_on_edge({"from": node_id, "to": env_id})

    def _upsert_policy(self, node: dict) -> None:
        self._conn.execute(
            "MERGE (pp:PlacementPolicy {id: $id}) "
            "SET pp.workload_id = $workload_id, "
            "    pp.source = $source, "
            "    pp.risk_score = $risk_score, "
            "    pp.risk_level = $risk_level, "
            "    pp.constraint = $constraint",
            parameters={
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
        self._conn.execute(
            "MATCH (w:Workload {id: $from_id}), (p:Placement {id: $to_id}) "
            "MERGE (w)-[r:MANIFESTS_AS]->(p) "
            "SET r.capabilities_granted = $capabilities_granted, "
            "    r.manifested_at = $manifested_at, "
            "    r.attestation_level = $attestation_level",
            parameters={
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
        self._conn.execute(
            "MATCH (p:Placement {id: $from_id}), (e:ExecutionEnvironment {id: $to_id}) "
            "MERGE (p)-[:PLACED_ON]->(e)",
            parameters={"from_id": from_id, "to_id": to_id},
        )

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        stmts = [
            # Node tables
            """CREATE NODE TABLE IF NOT EXISTS Workload(
                id STRING,
                declared_capabilities STRING[],
                compliance_scope STRING[],
                provenance STRING,
                name STRING,
                tags STRING[],
                review_required BOOLEAN,
                trust_domains STRING[],
                PRIMARY KEY(id)
            )""",
            """CREATE NODE TABLE IF NOT EXISTS TrustDomain(
                id STRING,
                spiffe_uri_prefix STRING,
                commune STRING,
                peer_trust_domains STRING[],
                PRIMARY KEY(id)
            )""",
            """CREATE NODE TABLE IF NOT EXISTS ExecutionEnvironment(
                id STRING,
                region STRING,
                status STRING,
                advertised_capabilities STRING[],
                labels_compliance STRING[],
                repave_friendly BOOLEAN,
                PRIMARY KEY(id)
            )""",
            """CREATE NODE TABLE IF NOT EXISTS Placement(
                id STRING,
                workload_id STRING,
                environment_id STRING,
                region STRING,
                observed_capabilities STRING[],
                drift_state_status STRING,
                drift_state_deviation_hours FLOAT,
                last_evaluated STRING,
                PRIMARY KEY(id)
            )""",
            """CREATE NODE TABLE IF NOT EXISTS PlacementPolicy(
                id STRING,
                workload_id STRING,
                source STRING,
                risk_score FLOAT,
                risk_level STRING,
                constraint STRING,
                PRIMARY KEY(id)
            )""",
            # Relationship tables
            """CREATE REL TABLE IF NOT EXISTS MANIFESTS_AS(
                FROM Workload TO Placement,
                capabilities_granted STRING[],
                manifested_at STRING,
                attestation_level STRING
            )""",
            """CREATE REL TABLE IF NOT EXISTS PLACED_ON(
                FROM Placement TO ExecutionEnvironment
            )""",
        ]
        for stmt in stmts:
            self._conn.execute(stmt)

        # Migration: databases created before the TrustDomain extension lack
        # the trust_domains column on Workload. CREATE ... IF NOT EXISTS does
        # not alter existing tables, so add the column explicitly.
        try:
            self._conn.execute(
                "ALTER TABLE Workload ADD IF NOT EXISTS trust_domains STRING[]"
            )
        except Exception:
            # Older Kuzu without ADD IF NOT EXISTS — fall back to plain ADD
            # and tolerate "already exists".
            try:
                self._conn.execute("ALTER TABLE Workload ADD trust_domains STRING[]")
            except Exception:
                pass


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _load_dir(directory: Path, expected_type: str) -> list[dict[str, Any]]:
    if not directory.exists():
        return []
    nodes = []
    for path in sorted(directory.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") == expected_type:
            nodes.append(node)
    return nodes


def _list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [str(value)]
