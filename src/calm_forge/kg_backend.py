"""KGBackend protocol — stable interface for KG query and traversal.

Implementations:
  FilesystemBackend  — file-based; flat single-node Cypher subset, no dependency
  KuzuBackend        — embedded Cypher graph index (Tier 1, optional dep)
  FalkorDBBackend    — Redis-protocol scale-out (Tier 2, optional dep + server)

JSON-LD files remain authoritative. Backends are query indexes.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Protocol


class KGBackend(Protocol):
    """Stable interface for KG query and traversal operations."""

    def load(self, kg_dir: str) -> None:
        """Ingest JSON-LD files from kg_dir into the backend index."""
        ...

    def query(self, cypher: str, params: dict | None = None) -> list[dict[str, Any]]:
        """Execute a Cypher query. Returns list of result records."""
        ...

    def upsert_node(self, node: dict) -> None:
        """Insert or update a node from a JSON-LD dict."""
        ...

    def upsert_edge(self, edge: dict) -> None:
        """Insert or update an edge from a JSON-LD edge dict."""
        ...

    def close(self) -> None:
        """Release resources."""
        ...


class FilesystemBackend:
    """File-based KGBackend — flat Cypher subset over JSON-LD files.

    query() supports single-node patterns with property-equality filters:

        MATCH (p:Placement {workload_id: $wid}) RETURN p.id AS id
        MATCH (p:Placement) WHERE p.drift_state_status = $s RETURN p.id, p.region
        MATCH (w:Workload) RETURN count(w) AS n

    Property names match the Kuzu/FalkorDB flattening (id, drift_state_status,
    provenance, ...) so flat queries are portable across all three backends.
    Relationship traversal, multi-node patterns, and anything else outside the
    subset raise NotImplementedError — traversal is what the graph tiers are for.

    Predicate access can also go through the typed helpers below.
    """

    def __init__(self, kg_dir: str | Path) -> None:
        self.kg_dir = Path(kg_dir)

    def load(self, kg_dir: str) -> None:
        self.kg_dir = Path(kg_dir)

    def query(self, cypher: str, params: dict | None = None) -> list[dict[str, Any]]:
        return _execute_flat_query(self.kg_dir, cypher, params or {})

    def upsert_node(self, node: dict) -> None:
        pass

    def upsert_edge(self, edge: dict) -> None:
        pass

    def close(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Predicate helpers used by kg_coherence_api
    # ------------------------------------------------------------------

    def workloads(self) -> list[dict[str, Any]]:
        from .kg_query import _load_nodes
        return _load_nodes(self.kg_dir / "workloads", "Workload")

    def placements_for_workload(self, workload_id: str) -> list[dict[str, Any]]:
        from .kg_query import _load_nodes
        all_placements = _load_nodes(self.kg_dir / "placements", "Placement")
        return [p for p in all_placements if p.get("workload_id") == workload_id]

    def placements_by_drift_status(self, status: str) -> list[dict[str, Any]]:
        from .kg_query import _load_nodes
        all_placements = _load_nodes(self.kg_dir / "placements", "Placement")
        return [
            p for p in all_placements
            if p.get("drift_state", {}).get("status") == status
        ]


def get_backend(config: dict) -> KGBackend:
    """Factory — returns the configured KGBackend instance.

    Config keys (also read from env vars if not present in dict):
      kg_backend   : "filesystem" | "kuzu" | "falkordb"  (default: "filesystem")
      kg_db_path   : path for Kuzu local DB              (default: .calm_forge/kg)
      kg_url       : Redis URL for FalkorDB              (required for falkordb)
      kg_dir       : KG directory for filesystem backend
    """
    import os
    backend = config.get("kg_backend") or os.environ.get("CALM_FORGE_KG_BACKEND", "filesystem")

    if backend == "filesystem":
        kg_dir = config.get("kg_dir") or os.environ.get("CALM_FORGE_KG_DIR", ".calm_forge/kg")
        return FilesystemBackend(kg_dir=kg_dir)

    if backend == "kuzu":
        try:
            from .kg_kuzu_backend import KuzuBackend
        except ImportError as exc:
            raise ImportError(
                "Kuzu backend requires: pip install calm-forge[graph]"
            ) from exc
        db_path = config.get("kg_db_path") or os.environ.get("CALM_FORGE_KG_DB_PATH", ".calm_forge/kg")
        return KuzuBackend(db_path=db_path)

    if backend == "falkordb":
        try:
            from .kg_falkordb_backend import FalkorDBBackend
        except ImportError as exc:
            raise ImportError(
                "FalkorDB backend requires: pip install calm-forge[graph]"
            ) from exc
        url = config.get("kg_url") or os.environ.get("CALM_FORGE_KG_URL")
        if not url:
            raise ValueError("FalkorDB backend requires kg_url or CALM_FORGE_KG_URL")
        return FalkorDBBackend(url=url)

    raise ValueError(f"Unknown KG backend: {backend!r}. Valid: filesystem, kuzu, falkordb")


# ---------------------------------------------------------------------------
# Flat Cypher subset interpreter (FilesystemBackend.query)
# ---------------------------------------------------------------------------

_LABEL_DIRS: dict[str, str] = {
    "Workload": "workloads",
    "ExecutionEnvironment": "environments",
    "Placement": "placements",
    "PlacementPolicy": "policies",
    "TrustDomain": "trust_domains",
}

_FLAT_QUERY = re.compile(
    r"^\s*MATCH\s*\(\s*(?P<var>\w+)\s*:\s*(?P<label>\w+)\s*"
    r"(?:\{(?P<props>[^}]*)\})?\s*\)\s*"
    r"(?:WHERE\s+(?P<where>.+?)\s+)?"
    r"RETURN\s+(?P<returns>.+?)\s*;?\s*$",
    re.IGNORECASE | re.DOTALL,
)

_PROP_FILTER = re.compile(r"^\s*(\w+)\s*:\s*\$(\w+)\s*$")
_WHERE_CLAUSE = re.compile(r"^\s*(\w+)\.(\w+)\s*=\s*\$(\w+)\s*$")
_RETURN_ITEM = re.compile(r"^\s*(\w+)\.(\w+)(?:\s+AS\s+(\w+))?\s*$", re.IGNORECASE)
_RETURN_COUNT = re.compile(r"^\s*count\s*\(\s*(\w+)\s*\)(?:\s+AS\s+(\w+))?\s*$", re.IGNORECASE)


def _unsupported(cypher: str, reason: str) -> NotImplementedError:
    return NotImplementedError(
        f"FilesystemBackend supports only flat single-node queries ({reason}). "
        f"Query: {cypher.strip()!r}. For traversal, install calm-forge[graph] "
        "and configure kg_backend=kuzu (or falkordb)."
    )


def _execute_flat_query(
    kg_dir: Path, cypher: str, params: dict[str, Any]
) -> list[dict[str, Any]]:
    from .kg_query import _load_nodes

    if "-[" in cypher or "]-" in cypher:
        raise _unsupported(cypher, "no relationship patterns")

    m = _FLAT_QUERY.match(cypher)
    if m is None:
        raise _unsupported(cypher, "unrecognized syntax")

    var = m.group("var")
    label = m.group("label")
    directory = _LABEL_DIRS.get(label)
    if directory is None:
        raise _unsupported(cypher, f"unknown label {label!r}")

    # Collect property-equality filters from {prop: $param} and WHERE clauses
    filters: list[tuple[str, Any]] = []

    if m.group("props"):
        for pair in m.group("props").split(","):
            pm = _PROP_FILTER.match(pair)
            if pm is None:
                raise _unsupported(cypher, "inline props must be prop: $param")
            prop, param = pm.groups()
            filters.append((prop, _require_param(params, param, cypher)))

    if m.group("where"):
        for clause in re.split(r"\s+AND\s+", m.group("where"), flags=re.IGNORECASE):
            wm = _WHERE_CLAUSE.match(clause)
            if wm is None or wm.group(1) != var:
                raise _unsupported(cypher, "WHERE must be <var>.prop = $param [AND ...]")
            filters.append((wm.group(2), _require_param(params, wm.group(3), cypher)))

    nodes = _load_nodes(kg_dir / directory, label)
    matched = [
        n for n in nodes
        if all(_node_prop(n, prop) == value for prop, value in filters)
    ]

    # Projections
    returns = [r for r in m.group("returns").split(",")]
    count_only = _RETURN_COUNT.match(m.group("returns"))
    if count_only is not None:
        if count_only.group(1) != var:
            raise _unsupported(cypher, "count() variable mismatch")
        alias = count_only.group(2) or f"count({var})"
        return [{alias: len(matched)}]

    projections: list[tuple[str, str]] = []  # (prop, output name)
    for item in returns:
        rm = _RETURN_ITEM.match(item)
        if rm is None or rm.group(1) != var:
            raise _unsupported(cypher, "RETURN must be <var>.prop [AS alias]")
        prop = rm.group(2)
        projections.append((prop, rm.group(3) or f"{var}.{prop}"))

    return [
        {name: _node_prop(n, prop) for prop, name in projections}
        for n in matched
    ]


def _require_param(params: dict[str, Any], name: str, cypher: str) -> Any:
    if name not in params:
        raise ValueError(f"Missing query parameter ${name} for query: {cypher.strip()!r}")
    return params[name]


def _node_prop(node: dict[str, Any], prop: str) -> Any:
    """Resolve a flattened property name against a JSON-LD node.

    Mirrors the Kuzu/FalkorDB property layout so flat queries are portable.
    """
    if prop == "id":
        return node.get("@id")
    if prop == "provenance":
        return node.get("_provenance", {}).get("provenance", node.get("provenance"))
    if prop == "drift_state_status":
        return node.get("drift_state", {}).get("status")
    if prop == "drift_state_deviation_hours":
        return node.get("drift_state", {}).get("deviation_hours")
    if prop == "last_evaluated":
        return node.get("drift_state", {}).get("last_evaluated") or node.get("last_evaluated")
    if prop == "labels_compliance":
        compliance = node.get("labels", {}).get("compliance", "")
        return [compliance] if compliance else node.get("labels_compliance", [])
    return node.get(prop)
