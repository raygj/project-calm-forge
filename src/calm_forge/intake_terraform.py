"""Terraform state JSON → Placement KG node intake."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def intake_terraform(state: dict) -> list[dict]:
    """Convert a parsed Terraform state dict to Placement KG nodes.

    Args:
        state: Parsed .tfstate JSON dict.

    Returns:
        List of deduplicated Placement nodes, one per (workload_id, region) pair.
    """
    seen: set[tuple[str, str]] = set()
    placements: list[dict] = []

    for resource in state.get("resources", []):
        resource_type = resource.get("type", "")
        resource_name = resource.get("name", "")

        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
            tags = attrs.get("tags") or {}

            region = _extract_region(attrs, tags)
            if region is None:
                continue

            workload_id = _extract_workload_id(tags, resource_name)
            key = (workload_id, region)
            if key in seen:
                continue
            seen.add(key)

            environment_id = f"env:terraform:{resource_type}.{resource_name}"
            placement_id = f"placement:{workload_id}:{region}"

            placements.append({
                "@context": "https://calmforge.io/kg/v1/context.jsonld",
                "@type": "Placement",
                "@id": placement_id,
                "workload_id": workload_id,
                "region": region,
                "environment_id": environment_id,
                "source": "terraform",
                "_provenance": {
                    "source": "terraform",
                    "authored_by": "calm-forge/intake-terraform",
                },
            })

    return placements


def intake_terraform_from_file(path: str | Path) -> list[dict]:
    """Read a .tfstate JSON file and return Placement KG nodes."""
    return intake_terraform(json.loads(Path(path).read_text()))


def _extract_region(attrs: dict[str, Any], tags: dict[str, Any]) -> str | None:
    if tags.get("region"):
        return tags["region"]
    if attrs.get("region"):
        return attrs["region"]
    az = attrs.get("availability_zone", "")
    if az:
        return re.sub(r"[a-z]$", "", az)
    return None


def _extract_workload_id(tags: dict[str, Any], resource_name: str) -> str:
    if tags.get("workload"):
        val = tags["workload"]
        return val if val.startswith("workload:") else f"workload:{val}"
    if tags.get("calm_workload_id"):
        return tags["calm_workload_id"]
    return f"workload:{resource_name}"
