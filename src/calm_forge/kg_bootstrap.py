"""KG bootstrap — seed a fresh KG from connected intake sources in one pass."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HISTORY_FILE = "_fabric/bootstrap-history.jsonl"


@dataclass
class BootstrapConfig:
    kg_dir: Path
    sources: list[str] = field(default_factory=list)
    # Per-source fixture paths (used when live clients aren't available)
    acm_fixture_path: Path | None = None
    ansible_fixture_path: Path | None = None
    concert_fixture_path: Path | None = None
    concert_live: bool = False
    concert_app_names: list[str] | None = None
    namespace: str | None = None
    backstage_path: Path | None = None
    terraform_state_paths: list[Path] = field(default_factory=list)


@dataclass
class BootstrapResult:
    sources_run: list[str]
    nodes_written: dict[str, int]
    errors: dict[str, str]

    def to_dict(self) -> dict:
        return {
            "sources_run": self.sources_run,
            "nodes_written": self.nodes_written,
            "errors": self.errors,
            "total_nodes": sum(self.nodes_written.values()),
        }


def kg_bootstrap(config: BootstrapConfig) -> BootstrapResult:
    """Seed a KG directory from all enabled intake sources in one pass.

    Each source failure is captured in ``errors`` without aborting the others.
    A record is appended to ``<kg_dir>/_fabric/bootstrap-history.jsonl`` on
    completion.

    Args:
        config: BootstrapConfig specifying which sources to run and where to
                write nodes.

    Returns:
        BootstrapResult with per-source node counts and any errors.
    """
    from .intake import (
        intake_acm,
        intake_acm_from_file,
        intake_ansible,
        intake_ansible_from_file,
        intake_concert,
        intake_concert_from_file,
        intake_concert_live,
        write_environment_nodes,
        write_placement_nodes,
        write_policy_nodes,
        write_workload_nodes,
    )
    from .intake_backstage import intake_backstage_from_file
    from .intake_terraform import intake_terraform_from_file
    from .kg_namespace import resolve_kg_dir

    kg_dir = Path(config.kg_dir).resolve()
    target = resolve_kg_dir(kg_dir, config.namespace)
    target.mkdir(parents=True, exist_ok=True)

    sources_run: list[str] = []
    nodes_written: dict[str, int] = {}
    errors: dict[str, str] = {}

    # Track ACM environments so Ansible can resolve cluster → env @id
    acm_env_nodes: list[dict] = []

    # ACM
    if "acm" in config.sources:
        try:
            if config.acm_fixture_path:
                nodes = intake_acm_from_file(config.acm_fixture_path)
            else:
                nodes = intake_acm({"clusters": []})
            paths = write_environment_nodes(nodes, target)
            acm_env_nodes = nodes
            sources_run.append("acm")
            nodes_written["acm"] = len(paths)
        except Exception as exc:  # noqa: BLE001
            errors["acm"] = str(exc)

    # Ansible (benefits from ACM env nodes for cluster resolution)
    if "ansible" in config.sources:
        try:
            if config.ansible_fixture_path:
                nodes = intake_ansible_from_file(
                    config.ansible_fixture_path,
                    environments=acm_env_nodes or None,
                )
            else:
                nodes = intake_ansible({"jobs": []}, environments=acm_env_nodes or None)
            paths = write_placement_nodes(nodes, target)
            sources_run.append("ansible")
            nodes_written["ansible"] = len(paths)
        except Exception as exc:  # noqa: BLE001
            errors["ansible"] = str(exc)

    # Concert
    if "concert" in config.sources:
        try:
            if config.concert_live:
                nodes = intake_concert_live(app_names=config.concert_app_names)
            elif config.concert_fixture_path:
                nodes = intake_concert_from_file(config.concert_fixture_path)
            else:
                nodes = intake_concert({"applications": []})
            paths = write_policy_nodes(nodes, target)
            sources_run.append("concert")
            nodes_written["concert"] = len(paths)
        except Exception as exc:  # noqa: BLE001
            errors["concert"] = str(exc)

    # Backstage
    if "backstage" in config.sources:
        try:
            if config.backstage_path is None:
                raise ValueError("backstage source requires backstage_path to be set")
            result = intake_backstage_from_file(config.backstage_path)
            env_paths = write_environment_nodes(result["environments"], target)
            wl_paths = write_workload_nodes(result["workloads"], target)
            sources_run.append("backstage")
            nodes_written["backstage"] = len(env_paths) + len(wl_paths)
        except Exception as exc:  # noqa: BLE001
            errors["backstage"] = str(exc)

    # Terraform
    if "terraform" in config.sources:
        try:
            combined: list[dict] = []
            seen: set[tuple[str, str]] = set()
            for tf_path in config.terraform_state_paths:
                for node in intake_terraform_from_file(tf_path):
                    key = (node["workload_id"], node["region"])
                    if key not in seen:
                        seen.add(key)
                        combined.append(node)
            paths = write_placement_nodes(combined, target)
            sources_run.append("terraform")
            nodes_written["terraform"] = len(paths)
        except Exception as exc:  # noqa: BLE001
            errors["terraform"] = str(exc)

    _append_history(kg_dir, sources_run, nodes_written, errors)

    return BootstrapResult(
        sources_run=sources_run,
        nodes_written=nodes_written,
        errors=errors,
    )


def _append_history(
    kg_dir: Path,
    sources_run: list[str],
    nodes_written: dict[str, int],
    errors: dict[str, str],
) -> None:
    fabric_dir = kg_dir / "_fabric"
    fabric_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sources_run": sources_run,
        "nodes_written": nodes_written,
        "errors": errors,
        "total_nodes": sum(nodes_written.values()),
    }
    history_path = kg_dir / _HISTORY_FILE
    with history_path.open("a") as fh:
        fh.write(json.dumps(record) + "\n")


def load_bootstrap_history(kg_dir: Path) -> list[dict[str, Any]]:
    """Read the bootstrap history log for a KG directory."""
    path = Path(kg_dir) / _HISTORY_FILE
    if not path.exists():
        return []
    records = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records
