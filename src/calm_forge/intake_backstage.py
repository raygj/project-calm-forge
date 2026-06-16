"""Backstage catalog YAML → KG node intake."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def intake_backstage(catalog: str | dict | list) -> dict[str, list]:
    """Convert Backstage catalog entities to ExecutionEnvironment and Workload KG nodes.

    Args:
        catalog: YAML string, a single parsed entity dict, or a list of entities.

    Returns:
        {"environments": [...], "workloads": [...]}
    """
    if isinstance(catalog, str):
        docs = list(yaml.safe_load_all(catalog))
        entities = [d for d in docs if d]
    elif isinstance(catalog, dict):
        entities = [catalog]
    else:
        entities = list(catalog)

    environments: list[dict] = []
    workloads: list[dict] = []

    for entity in entities:
        kind = entity.get("kind", "")
        if kind == "Resource":
            spec_type = entity.get("spec", {}).get("type", "")
            if spec_type == "kubernetes-cluster":
                environments.append(_resource_to_env_node(entity))
        elif kind == "Component":
            workloads.append(_component_to_workload_node(entity))

    return {"environments": environments, "workloads": workloads}


def intake_backstage_from_file(path: str | Path) -> dict[str, list]:
    """Read a catalog-info.yaml file and return KG nodes."""
    return intake_backstage(Path(path).read_text())


def _resource_to_env_node(entity: dict[str, Any]) -> dict[str, Any]:
    annotations = entity.get("metadata", {}).get("annotations", {})

    labels: dict[str, str] = {}
    for key, val in annotations.items():
        if key.startswith("calm.io/label-"):
            label_name = key[len("calm.io/label-"):]
            labels[label_name] = str(val)

    caps_raw = annotations.get("calm.io/advertised-capabilities", "")
    advertised_capabilities = [c.strip() for c in caps_raw.split(",") if c.strip()] if caps_raw else []

    return {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "ExecutionEnvironment",
        "@id": annotations.get("calm.io/environment-id", ""),
        "status": annotations.get("calm.io/cluster-status", "unknown"),
        "region": annotations.get("calm.io/region", ""),
        "advertised_capabilities": advertised_capabilities,
        "labels": labels,
        "_provenance": {
            "source": "backstage",
            "authored_by": "calm-forge/intake-backstage",
            "authored_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def _component_to_workload_node(entity: dict[str, Any]) -> dict[str, Any]:
    metadata = entity.get("metadata", {})
    annotations = metadata.get("annotations", {})
    spec = entity.get("spec", {})

    review_required_raw = annotations.get("calm.io/review-required", "false")
    review_required = str(review_required_raw).lower() == "true"

    declared_caps_raw = annotations.get("calm.io/declared-capabilities", "")
    declared_capabilities = [c.strip() for c in declared_caps_raw.split(",") if c.strip()] if declared_caps_raw else []

    compliance_raw = annotations.get("calm.io/compliance-scope", "")
    compliance_scope = [c.strip() for c in compliance_raw.split(",") if c.strip()] if compliance_raw else []

    owner = annotations.get("calm.io/owner") or spec.get("owner", "")

    node: dict[str, Any] = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Workload",
        "@id": annotations.get("calm.io/workload-id", ""),
        "name": metadata.get("name", ""),
        "review_required": review_required,
        "owner": owner,
        "_provenance": {
            "source": "backstage",
            "provenance": annotations.get("calm.io/provenance", ""),
            "authored_by": "calm-forge/intake-backstage",
            "authored_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    if declared_capabilities:
        node["declared_capabilities"] = declared_capabilities
    if compliance_scope:
        node["compliance_scope"] = compliance_scope

    return node
