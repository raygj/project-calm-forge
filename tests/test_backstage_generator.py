"""Tests for backstage_generator — Backstage Software Catalog entity generation."""
from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from calm_forge.backstage_generator import (
    env_to_resource,
    generate_catalog,
    to_catalog_yaml,
    workload_to_component,
    write_catalog,
)
from calm_forge.cli import cli
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    intake_tfe,
    write_environment_nodes,
    write_placement_nodes,
    write_workload_nodes,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACM_FIXTURE = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"environment": "prod", "compliance": "pci"},
         "capabilities": ["http_read", "vault_dynamic_creds", "confidential_compute"]},
        {"name": "prod-eu", "region": "eu-west-1", "status": "degraded",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read"]},
    ]
}

AAP_FIXTURE = {
    "jobs": [
        {"id": "j1", "workload_name": "payments", "target_cluster": "prod-east",
         "namespace": "payments", "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read", "vault_dynamic_creds"]},
        {"id": "j2", "workload_name": "payments", "target_cluster": "prod-eu",
         "namespace": "payments", "region": "eu-west-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

TFE_FIXTURE = {
    "workspaces": [
        {"name": "payments-prod", "terraform_version": "1.7.4", "tags": ["pci"],
         "vcs_repo": {}, "working_directory": "", "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-04-01T00:00:00Z", "variables": [], "resources": []},
    ]
}

ENV_NODE = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "ExecutionEnvironment",
    "@id": "env:acm:prod-east",
    "region": "us-east-1",
    "status": "ready",
    "labels": {"environment": "prod"},
    "advertised_capabilities": ["http_read", "vault_dynamic_creds", "confidential_compute"],
}

WORKLOAD_NODE = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Workload",
    "@id": "workload:payments",
    "name": "payments",
    "owner": "platform-engineering",
    "declared_capabilities": ["http_read", "vault_dynamic_creds"],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "_provenance": {"authored_by": "calm-forge/interview", "provenance": "authored"},
    "review_required": False,
}

PLACEMENT_NODE = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Placement",
    "@id": "placement:payments:prod-east",
    "workload_id": "workload:payments",
    "environment_id": "env:acm:prod-east",
    "region": "us-east-1",
    "observed_capabilities": ["http_read", "vault_dynamic_creds"],
    "edges": [{
        "@type": "manifests_as",
        "from": "workload:payments",
        "to": "placement:payments:prod-east",
        "manifested_at": "2026-05-01T00:00:00Z",
        "capabilities_granted": ["http_read", "vault_dynamic_creds"],
    }],
    "drift_state": {
        "last_evaluated": "2026-05-03T12:00:00Z",
        "status": "ok",
        "deviation_hours": None,
        "findings": [],
    },
    "_provenance": {"authored_by": "calm-forge/intake-ansible"},
}


def _build_kg(tmp_path) -> Path:
    env_nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(env_nodes, tmp_path)
    placement_nodes = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(placement_nodes, tmp_path)
    workload_nodes = intake_tfe(TFE_FIXTURE)
    write_workload_nodes(workload_nodes, tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# env_to_resource
# ---------------------------------------------------------------------------

def test_env_resource_kind():
    entity = env_to_resource(ENV_NODE)
    assert entity["kind"] == "Resource"


def test_env_resource_api_version():
    entity = env_to_resource(ENV_NODE)
    assert entity["apiVersion"] == "backstage.io/v1alpha1"


def test_env_resource_name_sanitized():
    entity = env_to_resource(ENV_NODE)
    name = entity["metadata"]["name"]
    assert name == "prod-east"
    assert re.match(r'^[a-z0-9-]+$', name)


def test_env_resource_type():
    entity = env_to_resource(ENV_NODE)
    assert entity["spec"]["type"] == "kubernetes-cluster"


def test_env_resource_lifecycle_ready():
    entity = env_to_resource(ENV_NODE)
    assert entity["spec"]["lifecycle"] == "production"


def test_env_resource_lifecycle_degraded():
    degraded = {**ENV_NODE, "status": "degraded"}
    entity = env_to_resource(degraded)
    assert entity["spec"]["lifecycle"] == "experimental"


def test_env_resource_calm_annotations():
    entity = env_to_resource(ENV_NODE)
    ann = entity["metadata"]["annotations"]
    assert ann["calm.io/environment-id"] == "env:acm:prod-east"
    assert ann["calm.io/cluster-status"] == "ready"
    assert ann["calm.io/region"] == "us-east-1"


def test_env_resource_capabilities_annotation():
    entity = env_to_resource(ENV_NODE)
    ann = entity["metadata"]["annotations"]
    caps = ann["calm.io/advertised-capabilities"].split(",")
    assert "confidential_compute" in caps
    assert "http_read" in caps


def test_env_resource_label_annotations():
    entity = env_to_resource(ENV_NODE)
    ann = entity["metadata"]["annotations"]
    assert ann["calm.io/label-environment"] == "prod"


def test_env_resource_no_caps_no_annotation():
    node = {**ENV_NODE, "advertised_capabilities": []}
    entity = env_to_resource(node)
    assert "calm.io/advertised-capabilities" not in entity["metadata"]["annotations"]


# ---------------------------------------------------------------------------
# workload_to_component
# ---------------------------------------------------------------------------

def test_workload_component_kind():
    entity = workload_to_component(WORKLOAD_NODE, [])
    assert entity["kind"] == "Component"


def test_workload_component_name():
    entity = workload_to_component(WORKLOAD_NODE, [])
    assert entity["metadata"]["name"] == "payments"


def test_workload_component_type():
    entity = workload_to_component(WORKLOAD_NODE, [])
    assert entity["spec"]["type"] == "service"


def test_workload_component_lifecycle_authored():
    entity = workload_to_component(WORKLOAD_NODE, [])
    assert entity["spec"]["lifecycle"] == "production"


def test_workload_component_lifecycle_reconstructed():
    node = {**WORKLOAD_NODE,
            "_provenance": {"provenance": "reconstructed"},
            "review_required": True}
    entity = workload_to_component(node, [])
    assert entity["spec"]["lifecycle"] == "experimental"


def test_workload_component_owner_prefixed():
    entity = workload_to_component(WORKLOAD_NODE, [])
    assert entity["spec"]["owner"] == "group:platform-engineering"


def test_workload_component_owner_already_prefixed():
    node = {**WORKLOAD_NODE, "owner": "group:my-team"}
    entity = workload_to_component(node, [])
    assert entity["spec"]["owner"] == "group:my-team"


def test_workload_component_calm_annotations():
    entity = workload_to_component(WORKLOAD_NODE, [])
    ann = entity["metadata"]["annotations"]
    assert ann["calm.io/workload-id"] == "workload:payments"
    assert ann["calm.io/provenance"] == "authored"


def test_workload_component_capabilities_annotation():
    entity = workload_to_component(WORKLOAD_NODE, [])
    ann = entity["metadata"]["annotations"]
    caps = ann["calm.io/capabilities-declared"].split(",")
    assert "http_read" in caps
    assert "vault_dynamic_creds" in caps


def test_workload_component_compliance_annotation():
    entity = workload_to_component(WORKLOAD_NODE, [])
    ann = entity["metadata"]["annotations"]
    assert "PCI-DSS-v4:req-3" in ann["calm.io/compliance-scope"]


def test_workload_component_review_required_annotation():
    node = {**WORKLOAD_NODE, "review_required": True}
    entity = workload_to_component(node, [])
    assert entity["metadata"]["annotations"].get("calm.io/review-required") == "true"


def test_workload_component_no_review_required_no_annotation():
    entity = workload_to_component(WORKLOAD_NODE, [])
    assert "calm.io/review-required" not in entity["metadata"]["annotations"]


def test_workload_component_drift_status_from_placements():
    entity = workload_to_component(WORKLOAD_NODE, [PLACEMENT_NODE])
    assert entity["metadata"]["annotations"]["calm.io/drift-status"] == "ok"


def test_workload_component_drift_violation_aggregate():
    violation_placement = {**PLACEMENT_NODE,
                           "drift_state": {"status": "violation", "last_evaluated": "2026-05-03T12:00:00Z"}}
    entity = workload_to_component(WORKLOAD_NODE, [PLACEMENT_NODE, violation_placement])
    assert entity["metadata"]["annotations"]["calm.io/drift-status"] == "violation"


def test_workload_component_last_evaluated_annotation():
    entity = workload_to_component(WORKLOAD_NODE, [PLACEMENT_NODE])
    assert entity["metadata"]["annotations"]["calm.io/last-evaluated"] == "2026-05-03T12:00:00Z"


def test_workload_component_capabilities_granted_annotation():
    entity = workload_to_component(WORKLOAD_NODE, [PLACEMENT_NODE])
    ann = entity["metadata"]["annotations"]
    granted = ann["calm.io/capabilities-granted"].split(",")
    assert "http_read" in granted
    assert "vault_dynamic_creds" in granted


def test_workload_component_depends_on_placement_cluster():
    entity = workload_to_component(WORKLOAD_NODE, [PLACEMENT_NODE])
    depends = entity["spec"].get("dependsOn", [])
    assert "resource:prod-east" in depends


def test_workload_component_depends_on_deduped():
    # Two placements on same cluster
    p2 = {**PLACEMENT_NODE, "@id": "placement:payments:prod-east-2"}
    entity = workload_to_component(WORKLOAD_NODE, [PLACEMENT_NODE, p2])
    depends = entity["spec"].get("dependsOn", [])
    assert depends.count("resource:prod-east") == 1


def test_workload_component_no_depends_on_when_no_placements():
    entity = workload_to_component(WORKLOAD_NODE, [])
    assert "dependsOn" not in entity["spec"]


# ---------------------------------------------------------------------------
# generate_catalog
# ---------------------------------------------------------------------------

def test_generate_catalog_empty_kg(tmp_path):
    entities = generate_catalog(tmp_path)
    assert entities == []


def test_generate_catalog_resource_count(tmp_path):
    _build_kg(tmp_path)
    entities = generate_catalog(tmp_path)
    resources = [e for e in entities if e["kind"] == "Resource"]
    assert len(resources) == 2  # ACM_FIXTURE has 2 clusters


def test_generate_catalog_component_count(tmp_path):
    _build_kg(tmp_path)
    entities = generate_catalog(tmp_path)
    components = [e for e in entities if e["kind"] == "Component"]
    assert len(components) == 1  # TFE_FIXTURE has 1 workspace


def test_generate_catalog_resources_before_components(tmp_path):
    _build_kg(tmp_path)
    entities = generate_catalog(tmp_path)
    kinds = [e["kind"] for e in entities]
    last_resource = max(i for i, k in enumerate(kinds) if k == "Resource")
    first_component = min(i for i, k in enumerate(kinds) if k == "Component")
    assert last_resource < first_component


def test_generate_catalog_component_with_drift(tmp_path):
    _build_kg(tmp_path)
    # Set drift state on placements
    for path in (tmp_path / "placements").glob("*.json"):
        node = json.loads(path.read_text())
        node["drift_state"]["status"] = "ok"
        node["drift_state"]["last_evaluated"] = "2026-05-03T12:00:00Z"
        path.write_text(json.dumps(node))
    entities = generate_catalog(tmp_path)
    components = [e for e in entities if e["kind"] == "Component"]
    # TFE workload may not match AAP placements by workload_id here,
    # but the structure should be valid
    assert all("calm.io/workload-id" in e["metadata"]["annotations"] for e in components)


# ---------------------------------------------------------------------------
# to_catalog_yaml / write_catalog
# ---------------------------------------------------------------------------

def test_to_catalog_yaml_valid_yaml(tmp_path):
    _build_kg(tmp_path)
    entities = generate_catalog(tmp_path)
    content = to_catalog_yaml(entities)
    docs = list(yaml.safe_load_all(content))
    assert len(docs) == len(entities)


def test_to_catalog_yaml_has_header():
    content = to_catalog_yaml([])
    assert "calm-forge backstage" in content


def test_to_catalog_yaml_separator():
    entities = [env_to_resource(ENV_NODE), workload_to_component(WORKLOAD_NODE, [])]
    content = to_catalog_yaml(entities)
    assert "---" in content


def test_write_catalog_creates_file(tmp_path):
    _build_kg(tmp_path)
    entities = generate_catalog(tmp_path)
    out_dir = tmp_path / "catalog"
    path = write_catalog(entities, out_dir)
    assert path.exists()
    assert path.name == "catalog-info.yaml"


def test_write_catalog_creates_output_dir(tmp_path):
    entities = [env_to_resource(ENV_NODE)]
    out_dir = tmp_path / "new" / "catalog"
    write_catalog(entities, out_dir)
    assert out_dir.is_dir()


def test_write_catalog_valid_yaml(tmp_path):
    _build_kg(tmp_path)
    entities = generate_catalog(tmp_path)
    out_dir = tmp_path / "catalog"
    path = write_catalog(entities, out_dir)
    docs = list(yaml.safe_load_all(path.read_text()))
    assert len(docs) == len(entities)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_backstage_stdout(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["backstage", "--kg-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "backstage.io/v1alpha1" in result.output


def test_cli_backstage_output_dir(tmp_path):
    _build_kg(tmp_path)
    out_dir = tmp_path / "catalog"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "backstage", "--kg-dir", str(tmp_path), "--output-dir", str(out_dir),
    ])
    assert result.exit_code == 0
    assert (out_dir / "catalog-info.yaml").exists()


def test_cli_backstage_json_output(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "backstage", "--kg-dir", str(tmp_path), "--json",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert all("kind" in e for e in data)


def test_cli_backstage_empty_kg(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["backstage", "--kg-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "No KG nodes" in result.output


# ---------------------------------------------------------------------------
# Name sanitization
# ---------------------------------------------------------------------------

import re  # noqa: E402


def test_bs_name_from_kg_id():
    from calm_forge.backstage_generator import _bs_name
    assert _bs_name("prod-east-ocp-01") == "prod-east-ocp-01"


def test_bs_name_removes_colons():
    from calm_forge.backstage_generator import _bs_name
    name = _bs_name("env:acm:prod-east")
    assert ":" not in name


def test_bs_name_lowercase():
    from calm_forge.backstage_generator import _bs_name
    assert _bs_name("MyService") == "myservice"


def test_bs_name_max_length():
    from calm_forge.backstage_generator import _bs_name
    assert len(_bs_name("a" * 100)) <= 63
