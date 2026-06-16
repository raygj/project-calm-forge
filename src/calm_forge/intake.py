"""ACM, Ansible AAP, TFE, and Concert intake — populate KG nodes from live systems."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# ACM cluster inventory → ExecutionEnvironment nodes
# ---------------------------------------------------------------------------


def intake_acm(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce ExecutionEnvironment KG nodes from an ACM cluster inventory dict."""
    return [_cluster_to_env_node(c) for c in fixture.get("clusters", [])]


def intake_acm_from_file(fixture_path: str | Path) -> list[dict[str, Any]]:
    """Load ACM cluster inventory from a JSON file and produce ExecutionEnvironment nodes."""
    return intake_acm(json.loads(Path(fixture_path).read_text()))


def _cluster_to_env_node(cluster: dict[str, Any]) -> dict[str, Any]:
    name = cluster["name"]
    return {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "ExecutionEnvironment",
        "@id": f"env:acm:{name}",
        "provider_type": "openshift",
        "provider_ref": f"acm-cluster-sp:{name}",
        "region": cluster.get("region", ""),
        "substrate": cluster.get("substrate", "x86"),
        "labels": cluster.get("labels", {}),
        "advertised_capabilities": cluster.get("capabilities", []),
        "status": cluster.get("status", "unknown"),
        "_provenance": {
            "authored_by": "calm-forge/intake-acm",
            "authored_at": datetime.now(timezone.utc).isoformat(),
            "intake_source": "acm-fixture",
        },
    }


# ---------------------------------------------------------------------------
# AAP job state → Placement nodes
# ---------------------------------------------------------------------------


def intake_ansible(
    fixture: dict[str, Any],
    environments: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Produce Placement KG nodes from an AAP job state dict.

    environments: list of ExecutionEnvironment nodes (from intake_acm) used to
    resolve cluster name → environment @id. If omitted, @id is inferred from
    the cluster name.
    """
    env_index: dict[str, str] = {}
    for env in environments or []:
        cluster_name = env.get("@id", "").replace("env:acm:", "")
        env_index[cluster_name] = env["@id"]

    return [_job_to_placement_node(j, env_index) for j in fixture.get("jobs", [])]


def intake_ansible_from_file(
    fixture_path: str | Path,
    environments: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Load AAP job state from a JSON file and produce Placement nodes."""
    return intake_ansible(json.loads(Path(fixture_path).read_text()), environments)


def _job_to_placement_node(
    job: dict[str, Any],
    env_index: dict[str, str],
) -> dict[str, Any]:
    cluster_name = job.get("target_cluster", "")
    env_id = env_index.get(cluster_name, f"env:acm:{cluster_name}")
    workload_name = job.get("workload_name", "")
    placement_id = f"placement:{workload_name}:{cluster_name}"
    workload_id = f"workload:{workload_name}"
    observed_capabilities = job.get("observed_capabilities", [])
    finished = job.get("finished", "")
    return {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Placement",
        "@id": placement_id,
        "workload_id": workload_id,
        "environment_id": env_id,
        "placed_at": finished,
        "placed_by": "aap/intake-ansible",
        "namespace": job.get("namespace", ""),
        "region": job.get("region", ""),
        "attestation_level": "software",
        "observed_capabilities": observed_capabilities,
        "edges": [
            {
                "@type": "manifests_as",
                "from": workload_id,
                "to": placement_id,
                "manifested_at": finished,
                "attestation_level": "software",
                "capabilities_granted": observed_capabilities,
            }
        ],
        "drift_state": {
            "last_evaluated": None,
            "status": "pending_first_evaluation",
            "deviation_hours": None,
            "findings": [],
        },
        "_provenance": {
            "authored_by": "calm-forge/intake-ansible",
            "authored_at": datetime.now(timezone.utc).isoformat(),
            "intake_source": "aap-fixture",
        },
    }


# ---------------------------------------------------------------------------
# HCP Terraform workspace metadata → Workload nodes
# ---------------------------------------------------------------------------


def intake_tfe(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce Workload KG nodes from a TFE workspace inventory dict.

    fixture shape: {"workspaces": [{name, terraform_version, tags, vcs_repo,
    working_directory, variables, resources, created_at, updated_at}, ...]}

    Nodes carry provenance: reconstructed and review_required: true — they
    represent workloads inferred from TFE state, not declared via CALM.
    """
    return [_workspace_to_workload_node(ws) for ws in fixture.get("workspaces", [])]


def intake_tfe_from_file(fixture_path: str | Path) -> list[dict[str, Any]]:
    """Load TFE workspace inventory from a JSON file and produce Workload nodes."""
    return intake_tfe(json.loads(Path(fixture_path).read_text()))


def _workspace_to_workload_node(ws: dict[str, Any]) -> dict[str, Any]:
    name = ws.get("name", "")
    slug = _slugify(name)
    tags = ws.get("tags", [])
    vcs = ws.get("vcs_repo") or {}
    resources = ws.get("resources", [])
    resource_types = sorted({r.get("type", "") for r in resources if r.get("type")})

    return {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Workload",
        "@id": f"workload:{slug}",
        "name": name,
        "terraform_version": ws.get("terraform_version", ""),
        "vcs_repo": vcs.get("identifier", "") or vcs.get("repository-http-url", ""),
        "working_directory": ws.get("working_directory", ""),
        "tags": tags,
        "resource_types": resource_types,
        "resource_count": len(resources),
        "created_at": ws.get("created_at", ""),
        "updated_at": ws.get("updated_at", ""),
        "review_required": True,
        "_provenance": {
            "authored_by": "calm-forge/intake-tfe",
            "authored_at": datetime.now(timezone.utc).isoformat(),
            "intake_source": "tfe-fixture",
            "provenance": "reconstructed",
        },
    }


def _slugify(name: str) -> str:
    import re as _re
    return _re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


# ---------------------------------------------------------------------------
# KG node writers
# ---------------------------------------------------------------------------


def write_environment_nodes(nodes: list[dict[str, Any]], output_dir: Path) -> list[Path]:
    """Write ExecutionEnvironment nodes as JSON-LD to <output_dir>/environments/."""
    env_dir = output_dir / "environments"
    env_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].replace("env:acm:", "").replace("/", "-")
        path = env_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written


def write_workload_nodes(nodes: list[dict[str, Any]], output_dir: Path) -> list[Path]:
    """Write Workload nodes as JSON-LD to <output_dir>/workloads/."""
    wl_dir = output_dir / "workloads"
    wl_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].replace("workload:", "").replace("/", "-")
        path = wl_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written


def write_placement_nodes(nodes: list[dict[str, Any]], output_dir: Path) -> list[Path]:
    """Write Placement nodes as JSON-LD to <output_dir>/placements/."""
    place_dir = output_dir / "placements"
    place_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].replace("placement:", "").replace(":", "__").replace("/", "-")
        path = place_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# Concert risk export → PlacementPolicy nodes
# ---------------------------------------------------------------------------

_RISK_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def intake_concert(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce PlacementPolicy KG nodes from a Concert risk export dict.

    Concert export shape:
      {
        "applications": [
          {
            "name":                 str          workload name (maps to workload:<name>)
            "risk_score":           float 0-1    Concert risk score
            "risk_level":           str          "low"|"medium"|"high"|"critical"
            "blocked_environments": [str]        env IDs that must not be targeted
            "allowed_environments": [str]        empty = unrestricted (except blocked)
            "evaluated_at":         str          ISO-8601 timestamp
          }
        ]
      }
    """
    return [_app_to_placement_policy(app) for app in fixture.get("applications", [])]


def intake_concert_from_file(fixture_path: str | Path) -> list[dict[str, Any]]:
    return intake_concert(json.loads(Path(fixture_path).read_text()))


def intake_concert_live(
    app_names: list[str] | None = None,
    client=None,
) -> list[dict[str, Any]]:
    """Fetch Concert risk data from the live API and produce PlacementPolicy nodes.

    Args:
        app_names: Optional list of application names to filter. None = all apps.
        client:    Concert client instance. When None, uses ConcertClient.from_env()
                   which returns a FixtureConcertClient when env vars are absent.

    Returns:
        List of PlacementPolicy KG nodes (same shape as intake_concert()).
    """
    if client is None:
        from .concert_client import ConcertClient
        client = ConcertClient.from_env()
    export = client.get_risk_export(app_names=app_names)
    return intake_concert(export)


def _app_to_placement_policy(app: dict[str, Any]) -> dict[str, Any]:
    name = app["name"]
    risk_score = app.get("risk_score", 0.0)
    risk_level = app.get("risk_level", "low")
    blocked = app.get("blocked_environments", [])
    allowed = app.get("allowed_environments", [])
    evaluated_at = app.get("evaluated_at", datetime.now(timezone.utc).isoformat())
    constraint = "placement_requires_isolation" if blocked else "no_constraint"
    return {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "PlacementPolicy",
        "@id": f"policy:concert:{name}",
        "workload_id": f"workload:{name}",
        "source": "concert",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "constraint": constraint,
        "blocked_environments": blocked,
        "allowed_environments": allowed,
        "generated_at": evaluated_at,
        "_provenance": {
            "authored_by": "calm-forge/intake-concert",
            "authored_at": datetime.now(timezone.utc).isoformat(),
            "intake_source": "concert-export",
        },
    }


def write_policy_nodes(nodes: list[dict[str, Any]], output_dir: Path) -> list[Path]:
    """Write PlacementPolicy nodes as JSON-LD to <output_dir>/policies/."""
    policy_dir = output_dir / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].replace("policy:concert:", "concert-").replace("/", "-")
        path = policy_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# DeploymentRequest KG nodes
# ---------------------------------------------------------------------------


def write_deployment_request(node: dict[str, Any], output_dir: Path) -> Path:
    """Write a DeploymentRequest node to <output_dir>/deployments/."""
    deploy_dir = output_dir / "deployments"
    deploy_dir.mkdir(parents=True, exist_ok=True)
    safe = node["@id"].replace("deploy-req:", "").replace("/", "-").replace(":", "__")
    path = deploy_dir / f"{safe}.json"
    path.write_text(json.dumps(node, indent=2))
    return path


def load_deployment_requests(
    kg_dir: Path,
    workload_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Load DeploymentRequest nodes from <kg_dir>/deployments/."""
    deploy_dir = kg_dir / "deployments"
    if not deploy_dir.exists():
        return []
    results = []
    for path in sorted(deploy_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") != "DeploymentRequest":
            continue
        if workload_id and node.get("workload_id") != workload_id:
            continue
        if status and node.get("status") != status:
            continue
        results.append(node)
    return results


def load_placement_policies(kg_dir: Path, workload_id: str | None = None) -> list[dict[str, Any]]:
    """Load PlacementPolicy nodes from <kg_dir>/policies/, optionally filtered by workload_id."""
    policy_dir = kg_dir / "policies"
    if not policy_dir.exists():
        return []
    policies = []
    for path in sorted(policy_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") != "PlacementPolicy":
            continue
        if workload_id and node.get("workload_id") != workload_id:
            continue
        policies.append(node)
    return policies


# ---------------------------------------------------------------------------
# DeploymentStatus KG nodes (P4-002)
# ---------------------------------------------------------------------------


def intake_deployment_completion(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce DeploymentStatus KG nodes from an ACM/Ansible completion payload.

    Fixture shape mirrors intake_ansible jobs, extended with deployment_request_id:
      {
        "jobs": [
          {
            "id":                    str
            "workload_name":         str
            "target_cluster":        str
            "finished":              str  ISO-8601
            "outcome":               str  "success" | "failed" | "partial"
            "observed_capabilities": [str]
            "deployment_request_id": str  (optional — links to DeploymentRequest @id)
          }
        ]
      }
    """
    return [_job_to_deployment_status(j) for j in fixture.get("jobs", [])]


def _job_to_deployment_status(job: dict[str, Any]) -> dict[str, Any]:
    workload_name = job.get("workload_name", "unknown")
    cluster = job.get("target_cluster", "unknown")
    outcome = job.get("outcome", "success")
    observed_at = job.get("finished", datetime.now(timezone.utc).isoformat())
    sha_input = f"{workload_name}:{cluster}:{observed_at}"
    node_id = f"deploy-status:{workload_name}:{abs(hash(sha_input)) % 10**8:08d}"
    return {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "DeploymentStatus",
        "@id": node_id,
        "deployment_request_id": job.get("deployment_request_id"),
        "workload_id": f"workload:{workload_name}",
        "environment_id": f"env:acm:{cluster}",
        "observed_at": observed_at,
        "outcome": outcome,
        "observed_capabilities": job.get("observed_capabilities", []),
        "drift_result": None,
        "_provenance": {
            "authored_by": "calm-forge/intake-deployment-completion",
            "authored_at": datetime.now(timezone.utc).isoformat(),
            "intake_source": "aap-completion",
        },
    }


def write_deployment_status(node: dict[str, Any], output_dir: Path) -> Path:
    """Write a DeploymentStatus node to <output_dir>/deployments/."""
    deploy_dir = output_dir / "deployments"
    deploy_dir.mkdir(parents=True, exist_ok=True)
    safe = node["@id"].replace("deploy-status:", "status-").replace("/", "-").replace(":", "__")
    path = deploy_dir / f"{safe}.json"
    path.write_text(json.dumps(node, indent=2))
    return path


def load_deployment_statuses(
    kg_dir: Path,
    workload_id: str | None = None,
    deployment_request_id: str | None = None,
) -> list[dict[str, Any]]:
    """Load DeploymentStatus nodes from <kg_dir>/deployments/."""
    deploy_dir = kg_dir / "deployments"
    if not deploy_dir.exists():
        return []
    results = []
    for path in sorted(deploy_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") != "DeploymentStatus":
            continue
        if workload_id and node.get("workload_id") != workload_id:
            continue
        if deployment_request_id and node.get("deployment_request_id") != deployment_request_id:
            continue
        results.append(node)
    return results
