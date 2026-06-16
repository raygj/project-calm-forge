"""Multi-root read-only view across multiple on-disk KG directories.

"Federation" is reserved for XC_ADR-008 cross-commune HTTP federation.
This module is local fan-out only — multiple KG roots on the same filesystem.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_CONFIG_FILE = "_fabric/multi_root.json"


class MultiRootError(Exception):
    """Raised when a registered root no longer exists or circular membership is detected."""


@dataclass
class MultiRootConfig:
    roots: list[Path]
    name: str = "default"
    description: str = ""


def load_multi_root_config(kg_dir: Path) -> MultiRootConfig | None:
    config_path = kg_dir / _CONFIG_FILE
    if not config_path.exists():
        return None
    data = json.loads(config_path.read_text())
    roots = [Path(r) for r in data.get("roots", [])]
    return MultiRootConfig(
        roots=roots,
        name=data.get("name", "default"),
        description=data.get("description", ""),
    )


def save_multi_root_config(config: MultiRootConfig, kg_dir: Path) -> Path:
    fabric_dir = kg_dir / "_fabric"
    fabric_dir.mkdir(parents=True, exist_ok=True)
    config_path = fabric_dir / "multi_root.json"
    data = {
        "name": config.name,
        "description": config.description,
        "roots": [str(r) for r in config.roots],
    }
    config_path.write_text(json.dumps(data, indent=2))
    return config_path


def _validate_roots(roots: list[Path], context_kg_dir: Path | None = None) -> None:
    for root in roots:
        if not root.exists():
            raise MultiRootError(f"KG root does not exist: {root}")
        if context_kg_dir and root.resolve() == context_kg_dir.resolve():
            raise MultiRootError(f"Circular multi-root membership: root {root} lists itself")


def multi_root_kg_status(roots: list[Path], namespace: str | None = None) -> dict[str, Any]:
    from .kg_inspect import kg_status

    _validate_roots(roots)

    members: list[dict[str, Any]] = []
    totals: dict[str, Any] = {
        "environments": {"count": 0},
        "placements": {"count": 0},
        "workloads": {"count": 0},
        "policies": {"count": 0},
    }

    for root in roots:
        member_status = kg_status(root, namespace)
        member_status["root"] = str(root)
        members.append(member_status)

        totals["environments"]["count"] += member_status.get("environments", {}).get("count", 0)
        totals["placements"]["count"] += member_status.get("placements", {}).get("count", 0)
        totals["workloads"]["count"] += member_status.get("workloads", {}).get("count", 0)
        totals["policies"]["count"] += member_status.get("policies", {}).get("count", 0)

    return {
        "members": members,
        "totals": totals,
        "root_count": len(roots),
    }


def multi_root_kg_query(
    roots: list[Path],
    node_type: str | None = None,
    where: dict | None = None,
    follow: str | None = None,
) -> list[dict[str, Any]]:
    from .kg_query import kg_query

    if not roots:
        return []

    _validate_roots(roots)

    seen: dict[str, dict[str, Any]] = {}

    for root in roots:
        results = kg_query(root, node_type or "Workload", list(where or []), follow)
        for entry in results:
            node = entry.get("node", {})
            node_id = node.get("@id")
            entry["_multi_root"] = str(root)
            if node_id:
                seen[node_id] = entry
            else:
                seen[str(len(seen))] = entry

    return list(seen.values())


def multi_root_fabric_feed(roots: list[Path]) -> dict[str, Any]:
    from .dashboard import build_fabric_feed

    _validate_roots(roots)

    all_workloads: list[dict[str, Any]] = []
    for root in roots:
        feed = build_fabric_feed(root)
        all_workloads.extend(feed.get("workloads", []))

    return {
        "workloads": all_workloads,
        "member_count": len(roots),
        "total_workloads": len(all_workloads),
    }


class MultiRootKGView:
    def __init__(self, roots: list[Path]) -> None:
        self.roots = roots

    def status(self, namespace: str | None = None) -> dict[str, Any]:
        return multi_root_kg_status(self.roots, namespace)

    def query(
        self,
        node_type: str | None = None,
        where: dict | None = None,
        follow: str | None = None,
    ) -> list[dict[str, Any]]:
        return multi_root_kg_query(self.roots, node_type=node_type, where=where, follow=follow)

    def fabric_feed(self) -> dict[str, Any]:
        return multi_root_fabric_feed(self.roots)
