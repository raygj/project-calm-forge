"""Tests for ACM/Ansible intake and drift evaluation."""
from __future__ import annotations

import json

from calm_forge.drift_evaluator import emit_drift_event, evaluate_drift, write_drift_state
from calm_forge.intake import (
    intake_acm,
    intake_acm_from_file,
    intake_ansible,
    intake_ansible_from_file,
    intake_tfe,
    intake_tfe_from_file,
    write_environment_nodes,
    write_placement_nodes,
    write_workload_nodes,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACM_FIXTURE = {
    "clusters": [
        {
            "name": "prod-east-ocp-01",
            "region": "us-east-1",
            "status": "ready",
            "substrate": "x86",
            "labels": {"environment": "prod", "compliance": "pci"},
            "capabilities": ["http_read", "vault_dynamic_creds"],
        },
        {
            "name": "prod-eu-west-ocp-01",
            "region": "eu-west-1",
            "status": "ready",
            "substrate": "x86",
            "labels": {"environment": "prod", "compliance": "pci"},
            "capabilities": ["http_read", "vault_dynamic_creds"],
        },
    ]
}

AAP_FIXTURE = {
    "jobs": [
        {
            "id": "job-001",
            "workload_name": "pci-multi-region-payments",
            "target_cluster": "prod-east-ocp-01",
            "namespace": "payments-prod",
            "region": "us-east-1",
            "finished": "2026-04-25T14:32:00Z",
            "observed_capabilities": ["http_read", "vault_dynamic_creds"],
        },
        {
            "id": "job-002",
            "workload_name": "pci-multi-region-payments",
            "target_cluster": "prod-eu-west-ocp-01",
            "namespace": "payments-prod",
            "region": "eu-west-1",
            "finished": "2026-04-25T14:35:00Z",
            "observed_capabilities": ["http_read", "vault_dynamic_creds"],
        },
    ]
}

PCI_CALM = {
    "metadata": {
        "name": "PCI Multi-Region Payments",
        "data": {"data-residency": ["us-east-1", "eu-west-1"]},
    },
    "nodes": [],
    "relationships": [],
}


# ---------------------------------------------------------------------------
# intake_acm
# ---------------------------------------------------------------------------

def test_intake_acm_node_types():
    nodes = intake_acm(ACM_FIXTURE)
    assert all(n["@type"] == "ExecutionEnvironment" for n in nodes)


def test_intake_acm_count():
    nodes = intake_acm(ACM_FIXTURE)
    assert len(nodes) == 2


def test_intake_acm_ids():
    nodes = intake_acm(ACM_FIXTURE)
    ids = {n["@id"] for n in nodes}
    assert "env:acm:prod-east-ocp-01" in ids
    assert "env:acm:prod-eu-west-ocp-01" in ids


def test_intake_acm_region():
    nodes = intake_acm(ACM_FIXTURE)
    by_id = {n["@id"]: n for n in nodes}
    assert by_id["env:acm:prod-east-ocp-01"]["region"] == "us-east-1"
    assert by_id["env:acm:prod-eu-west-ocp-01"]["region"] == "eu-west-1"


def test_intake_acm_capabilities():
    nodes = intake_acm(ACM_FIXTURE)
    assert "http_read" in nodes[0]["advertised_capabilities"]


def test_intake_acm_labels():
    nodes = intake_acm(ACM_FIXTURE)
    assert nodes[0]["labels"]["compliance"] == "pci"


def test_intake_acm_provenance():
    nodes = intake_acm(ACM_FIXTURE)
    prov = nodes[0]["_provenance"]
    assert prov["authored_by"] == "calm-forge/intake-acm"
    assert prov["intake_source"] == "acm-fixture"


def test_intake_acm_empty():
    nodes = intake_acm({"clusters": []})
    assert nodes == []


def test_intake_acm_from_file(tmp_path):
    fixture_path = tmp_path / "acm.json"
    fixture_path.write_text(json.dumps(ACM_FIXTURE))
    nodes = intake_acm_from_file(fixture_path)
    assert len(nodes) == 2


# ---------------------------------------------------------------------------
# intake_ansible
# ---------------------------------------------------------------------------

def test_intake_ansible_node_types():
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    assert all(n["@type"] == "Placement" for n in placements)


def test_intake_ansible_count():
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    assert len(placements) == 2


def test_intake_ansible_ids():
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    ids = {n["@id"] for n in placements}
    assert "placement:pci-multi-region-payments:prod-east-ocp-01" in ids


def test_intake_ansible_environment_resolution():
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    by_id = {n["@id"]: n for n in placements}
    p = by_id["placement:pci-multi-region-payments:prod-east-ocp-01"]
    assert p["environment_id"] == "env:acm:prod-east-ocp-01"


def test_intake_ansible_environment_fallback():
    placements = intake_ansible(AAP_FIXTURE, environments=None)
    # Without env_nodes, should infer ID from cluster name
    assert placements[0]["environment_id"] == "env:acm:prod-east-ocp-01"


def test_intake_ansible_workload_id():
    placements = intake_ansible(AAP_FIXTURE)
    assert placements[0]["workload_id"] == "workload:pci-multi-region-payments"


def test_intake_ansible_region():
    placements = intake_ansible(AAP_FIXTURE)
    regions = {p["region"] for p in placements}
    assert regions == {"us-east-1", "eu-west-1"}


def test_intake_ansible_drift_state():
    placements = intake_ansible(AAP_FIXTURE)
    ds = placements[0]["drift_state"]
    assert ds["status"] == "pending_first_evaluation"
    assert ds["last_evaluated"] is None


def test_intake_ansible_from_file(tmp_path):
    fixture_path = tmp_path / "aap.json"
    fixture_path.write_text(json.dumps(AAP_FIXTURE))
    placements = intake_ansible_from_file(fixture_path)
    assert len(placements) == 2


def test_intake_ansible_manifests_as_edge_present():
    placements = intake_ansible(AAP_FIXTURE)
    p = placements[0]
    edges = p.get("edges", [])
    assert len(edges) == 1
    assert edges[0]["@type"] == "manifests_as"


def test_intake_ansible_manifests_as_from_to():
    placements = intake_ansible(AAP_FIXTURE)
    p = next(n for n in placements if "prod-east-ocp-01" in n["@id"])
    edge = p["edges"][0]
    assert edge["from"] == "workload:pci-multi-region-payments"
    assert edge["to"] == "placement:pci-multi-region-payments:prod-east-ocp-01"


def test_intake_ansible_manifests_as_capabilities_granted():
    placements = intake_ansible(AAP_FIXTURE)
    p = next(n for n in placements if "prod-east-ocp-01" in n["@id"])
    edge = p["edges"][0]
    assert set(edge["capabilities_granted"]) == {"http_read", "vault_dynamic_creds"}


def test_intake_ansible_manifests_as_attestation_level():
    placements = intake_ansible(AAP_FIXTURE)
    edge = placements[0]["edges"][0]
    assert edge["attestation_level"] == "software"


def test_intake_ansible_manifests_as_manifested_at():
    placements = intake_ansible(AAP_FIXTURE)
    p = next(n for n in placements if "prod-east-ocp-01" in n["@id"])
    edge = p["edges"][0]
    assert edge["manifested_at"] == "2026-04-25T14:32:00Z"


# ---------------------------------------------------------------------------
# write_environment_nodes / write_placement_nodes
# ---------------------------------------------------------------------------

def test_write_environment_nodes(tmp_path):
    nodes = intake_acm(ACM_FIXTURE)
    written = write_environment_nodes(nodes, tmp_path)
    assert len(written) == 2
    for p in written:
        assert p.exists()
        data = json.loads(p.read_text())
        assert data["@type"] == "ExecutionEnvironment"


def test_write_environment_nodes_creates_subdir(tmp_path):
    nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(nodes, tmp_path)
    assert (tmp_path / "environments").is_dir()


def test_write_placement_nodes(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    written = write_placement_nodes(placements, tmp_path)
    assert len(written) == 2
    for p in written:
        assert p.exists()
        data = json.loads(p.read_text())
        assert data["@type"] == "Placement"


def test_write_placement_nodes_creates_subdir(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(placements, tmp_path)
    assert (tmp_path / "placements").is_dir()


# ---------------------------------------------------------------------------
# evaluate_drift
# ---------------------------------------------------------------------------

def _write_kg(tmp_path, calm, env_nodes=None, placement_nodes=None):
    if env_nodes:
        write_environment_nodes(env_nodes, tmp_path)
    if placement_nodes:
        write_placement_nodes(placement_nodes, tmp_path)
    return tmp_path


def test_drift_ok(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    assert result["drift_detected"] is False
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_drift_no_placements(tmp_path):
    result = evaluate_drift(PCI_CALM, tmp_path)
    assert result["status"] == "no_placements_found"
    assert result["drift_detected"] is False


def test_drift_violation(tmp_path):
    # Place workload in us-west-2 (not in declared zones)
    bad_placement = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Placement",
        "@id": "placement:pci-multi-region-payments:bad-cluster",
        "workload_id": "workload:pci-multi-region-payments",
        "environment_id": "env:acm:bad-cluster",
        "region": "us-west-2",
        "namespace": "payments-prod",
        "placed_at": "2026-04-25T18:00:00Z",
        "placed_by": "aap/intake-ansible",
        "attestation_level": "software",
        "observed_capabilities": [],
        "drift_state": {"last_evaluated": None, "status": "pending_first_evaluation",
                        "deviation_hours": None, "findings": []},
        "_provenance": {"authored_by": "test", "authored_at": "2026-04-25T18:00:00Z",
                        "intake_source": "test"},
    }
    write_placement_nodes([bad_placement], tmp_path)
    result = evaluate_drift(PCI_CALM, tmp_path)
    assert result["drift_detected"] is True
    assert result["status"] == "violation"
    violations = [f for f in result["findings"] if f["severity"] == "violation"]
    assert len(violations) == 1
    assert "us-west-2" in violations[0]["message"]


def test_drift_warning_missing_zone(tmp_path):
    # Only place workload in one of two declared zones
    only_us = {
        "jobs": [
            {
                "id": "job-001",
                "workload_name": "pci-multi-region-payments",
                "target_cluster": "prod-east-ocp-01",
                "namespace": "payments-prod",
                "region": "us-east-1",
                "finished": "2026-04-25T14:32:00Z",
                "observed_capabilities": [],
            }
        ]
    }
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(only_us, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    assert result["drift_detected"] is False
    warnings = [f for f in result["findings"] if f["severity"] == "warning"]
    assert any("eu-west-1" in w["message"] for w in warnings)


def test_drift_workload_name_derivation(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    assert result["workload"] == "pci-multi-region-payments"


def test_drift_observed_placements_shape(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    for p in result["observed_placements"]:
        assert "id" in p
        assert "region" in p
        assert "environment" in p


# ---------------------------------------------------------------------------
# P1-021 — write_drift_state
# ---------------------------------------------------------------------------

def test_write_drift_state_updates_placement_nodes(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    written = write_drift_state(result, tmp_path)
    assert len(written) == 2
    for path in written:
        node = json.loads(path.read_text())
        ds = node["drift_state"]
        assert ds["status"] == "ok"
        assert ds["last_evaluated"] is not None
        assert ds["findings"] == []


def test_write_drift_state_violation_status(tmp_path):
    bad_placement = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Placement",
        "@id": "placement:pci-multi-region-payments:bad-cluster",
        "workload_id": "workload:pci-multi-region-payments",
        "environment_id": "env:acm:bad-cluster",
        "region": "us-west-2",
        "namespace": "payments-prod",
        "placed_at": "2026-04-28T00:00:00Z",
        "placed_by": "aap/intake-ansible",
        "attestation_level": "software",
        "observed_capabilities": [],
        "drift_state": {"last_evaluated": None, "status": "pending_first_evaluation",
                        "deviation_hours": None, "findings": []},
        "_provenance": {"authored_by": "test", "authored_at": "2026-04-28T00:00:00Z",
                        "intake_source": "test"},
    }
    write_placement_nodes([bad_placement], tmp_path)
    result = evaluate_drift(PCI_CALM, tmp_path)
    write_drift_state(result, tmp_path)
    node_path = tmp_path / "placements" / "pci-multi-region-payments__bad-cluster.json"
    node = json.loads(node_path.read_text())
    assert node["drift_state"]["status"] == "violation"
    assert len(node["drift_state"]["findings"]) == 1


def test_write_drift_state_returns_empty_when_no_placements_dir(tmp_path):
    result = evaluate_drift(PCI_CALM, tmp_path)
    written = write_drift_state(result, tmp_path)
    assert written == []


def test_write_drift_state_skips_other_workloads(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    other_calm = {
        "metadata": {"name": "other-workload", "data": {"data-residency": ["us-east-1"]}},
        "nodes": [], "relationships": [],
    }
    result = evaluate_drift(other_calm, tmp_path)
    written = write_drift_state(result, tmp_path)
    assert written == []


# ---------------------------------------------------------------------------
# P1-022 — emit_drift_event
# ---------------------------------------------------------------------------

def test_emit_drift_event_creates_file(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    event_file = tmp_path / "events" / "drift.json"
    emit_drift_event(result, event_file)
    assert event_file.exists()


def test_emit_drift_event_payload_shape(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    event_file = tmp_path / "drift-events.json"
    emit_drift_event(result, event_file)
    event = json.loads(event_file.read_text().strip())
    assert event["event_type"] == "calm.drift.evaluated"
    assert event["workload"] == "pci-multi-region-payments"
    assert event["status"] == "ok"
    assert "timestamp" in event
    assert "declared_zones" in event
    assert "observed_regions" in event
    assert "findings" in event


def test_emit_drift_event_appends(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    _write_kg(tmp_path, PCI_CALM, env_nodes, placements)
    result = evaluate_drift(PCI_CALM, tmp_path)
    event_file = tmp_path / "drift-events.json"
    emit_drift_event(result, event_file)
    emit_drift_event(result, event_file)
    lines = [line for line in event_file.read_text().strip().splitlines() if line]
    assert len(lines) == 2


def test_emit_drift_event_violation_status(tmp_path):
    bad_placement = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Placement",
        "@id": "placement:pci-multi-region-payments:bad-cluster",
        "workload_id": "workload:pci-multi-region-payments",
        "environment_id": "env:acm:bad-cluster",
        "region": "us-west-2",
        "namespace": "payments-prod",
        "placed_at": "2026-04-28T00:00:00Z",
        "placed_by": "aap/intake-ansible",
        "attestation_level": "software",
        "observed_capabilities": [],
        "drift_state": {"last_evaluated": None, "status": "pending_first_evaluation",
                        "deviation_hours": None, "findings": []},
        "_provenance": {"authored_by": "test", "authored_at": "2026-04-28T00:00:00Z",
                        "intake_source": "test"},
    }
    write_placement_nodes([bad_placement], tmp_path)
    result = evaluate_drift(PCI_CALM, tmp_path)
    event_file = tmp_path / "drift-events.json"
    emit_drift_event(result, event_file)
    event = json.loads(event_file.read_text().strip())
    assert event["status"] == "violation"
    assert len(event["findings"]) >= 1


# ---------------------------------------------------------------------------
# P2-001 — capability-ceiling check (manifests_as invariant)
# ---------------------------------------------------------------------------

_WORKLOAD_WITH_CAPS = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Workload",
    "@id": "workload:test-wl",
    "name": "test-wl",
    "declared_capabilities": ["http_read", "vault_dynamic_creds"],
    "_provenance": {"authored_by": "test", "authored_at": "2026-05-01T00:00:00Z"},
}

_PLACEMENT_WITHIN_CEILING = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Placement",
    "@id": "placement:test-wl:cluster-a",
    "workload_id": "workload:test-wl",
    "environment_id": "env:acm:cluster-a",
    "region": "us-east-1",
    "namespace": "test",
    "placed_at": "2026-05-01T00:00:00Z",
    "placed_by": "aap/intake-ansible",
    "attestation_level": "software",
    "observed_capabilities": ["http_read"],
    "edges": [{
        "@type": "manifests_as",
        "from": "workload:test-wl",
        "to": "placement:test-wl:cluster-a",
        "manifested_at": "2026-05-01T00:00:00Z",
        "attestation_level": "software",
        "capabilities_granted": ["http_read"],
    }],
    "drift_state": {"last_evaluated": None, "status": "pending_first_evaluation",
                    "deviation_hours": None, "findings": []},
    "_provenance": {"authored_by": "test", "authored_at": "2026-05-01T00:00:00Z",
                    "intake_source": "test"},
}

_PLACEMENT_EXCEEDS_CEILING = {
    **_PLACEMENT_WITHIN_CEILING,
    "@id": "placement:test-wl:cluster-b",
    "observed_capabilities": ["http_read", "admin_exec"],
    "edges": [{
        "@type": "manifests_as",
        "from": "workload:test-wl",
        "to": "placement:test-wl:cluster-b",
        "manifested_at": "2026-05-01T00:00:00Z",
        "attestation_level": "software",
        "capabilities_granted": ["http_read", "admin_exec"],
    }],
}


def test_capability_ceiling_no_violation_when_within(tmp_path):
    (tmp_path / "workloads").mkdir()
    (tmp_path / "workloads" / "test-wl.json").write_text(json.dumps(_WORKLOAD_WITH_CAPS))
    write_placement_nodes([_PLACEMENT_WITHIN_CEILING], tmp_path)
    calm = {"metadata": {"name": "test-wl", "data": {"data-residency": ["us-east-1"]}},
            "nodes": [], "relationships": []}
    result = evaluate_drift(calm, tmp_path)
    cap_findings = [f for f in result["findings"] if f.get("rule") == "capability-ceiling"]
    assert cap_findings == []


def test_capability_ceiling_violation_when_exceeded(tmp_path):
    (tmp_path / "workloads").mkdir()
    (tmp_path / "workloads" / "test-wl.json").write_text(json.dumps(_WORKLOAD_WITH_CAPS))
    write_placement_nodes([_PLACEMENT_EXCEEDS_CEILING], tmp_path)
    calm = {"metadata": {"name": "test-wl", "data": {"data-residency": ["us-east-1"]}},
            "nodes": [], "relationships": []}
    result = evaluate_drift(calm, tmp_path)
    cap_findings = [f for f in result["findings"] if f.get("rule") == "capability-ceiling"]
    assert len(cap_findings) == 1
    assert "admin_exec" in cap_findings[0]["excess_capabilities"]


def test_capability_ceiling_skipped_without_workload(tmp_path):
    write_placement_nodes([_PLACEMENT_EXCEEDS_CEILING], tmp_path)
    calm = {"metadata": {"name": "test-wl", "data": {"data-residency": ["us-east-1"]}},
            "nodes": [], "relationships": []}
    result = evaluate_drift(calm, tmp_path)
    cap_findings = [f for f in result["findings"] if f.get("rule") == "capability-ceiling"]
    assert cap_findings == []


def test_capability_ceiling_skipped_when_no_declared_caps(tmp_path):
    workload_no_caps = {**_WORKLOAD_WITH_CAPS, "declared_capabilities": []}
    (tmp_path / "workloads").mkdir()
    (tmp_path / "workloads" / "test-wl.json").write_text(json.dumps(workload_no_caps))
    write_placement_nodes([_PLACEMENT_EXCEEDS_CEILING], tmp_path)
    calm = {"metadata": {"name": "test-wl", "data": {"data-residency": ["us-east-1"]}},
            "nodes": [], "relationships": []}
    result = evaluate_drift(calm, tmp_path)
    cap_findings = [f for f in result["findings"] if f.get("rule") == "capability-ceiling"]
    assert cap_findings == []


def test_capability_ceiling_component_declared_caps(tmp_path):
    workload_component_caps = {
        **_WORKLOAD_WITH_CAPS,
        "declared_capabilities": [],
        "nodes": [
            {"@type": "WorkloadComponent", "@id": "workload:test-wl:svc",
             "declared_capabilities": ["http_read", "vault_dynamic_creds"]},
        ],
    }
    (tmp_path / "workloads").mkdir()
    (tmp_path / "workloads" / "test-wl.json").write_text(json.dumps(workload_component_caps))
    write_placement_nodes([_PLACEMENT_WITHIN_CEILING], tmp_path)
    calm = {"metadata": {"name": "test-wl", "data": {"data-residency": ["us-east-1"]}},
            "nodes": [], "relationships": []}
    result = evaluate_drift(calm, tmp_path)
    cap_findings = [f for f in result["findings"] if f.get("rule") == "capability-ceiling"]
    assert cap_findings == []


# ---------------------------------------------------------------------------
# P1-017 — intake_tfe / Workload nodes
# ---------------------------------------------------------------------------

TFE_FIXTURE = {
    "workspaces": [
        {
            "name": "pci-payments-prod-us-east-1",
            "terraform_version": "1.7.4",
            "tags": ["pci", "prod", "payments"],
            "vcs_repo": {"identifier": "org/payments-infra"},
            "working_directory": "stacks/payments",
            "created_at": "2025-09-01T12:00:00Z",
            "updated_at": "2026-04-20T08:30:00Z",
            "variables": [],
            "resources": [
                {"type": "aws_eks_cluster", "name": "payments-eks", "address": "aws_eks_cluster.payments-eks", "module": ""},
                {"type": "aws_rds_cluster", "name": "payments-db", "address": "aws_rds_cluster.payments-db", "module": ""},
            ],
        },
        {
            "name": "fraud-detection-pipeline",
            "terraform_version": "1.6.0",
            "tags": ["fraud", "prod"],
            "vcs_repo": {},
            "working_directory": "",
            "created_at": "2025-11-01T00:00:00Z",
            "updated_at": "2026-03-10T00:00:00Z",
            "variables": [],
            "resources": [],
        },
    ]
}


def test_intake_tfe_node_types():
    nodes = intake_tfe(TFE_FIXTURE)
    assert all(n["@type"] == "Workload" for n in nodes)


def test_intake_tfe_count():
    nodes = intake_tfe(TFE_FIXTURE)
    assert len(nodes) == 2


def test_intake_tfe_ids():
    nodes = intake_tfe(TFE_FIXTURE)
    ids = {n["@id"] for n in nodes}
    assert "workload:pci-payments-prod-us-east-1" in ids
    assert "workload:fraud-detection-pipeline" in ids


def test_intake_tfe_reconstructed_provenance():
    nodes = intake_tfe(TFE_FIXTURE)
    for n in nodes:
        assert n["_provenance"]["provenance"] == "reconstructed"
        assert n["_provenance"]["authored_by"] == "calm-forge/intake-tfe"


def test_intake_tfe_review_required():
    nodes = intake_tfe(TFE_FIXTURE)
    assert all(n["review_required"] is True for n in nodes)


def test_intake_tfe_tags():
    nodes = intake_tfe(TFE_FIXTURE)
    by_id = {n["@id"]: n for n in nodes}
    assert "pci" in by_id["workload:pci-payments-prod-us-east-1"]["tags"]


def test_intake_tfe_resource_types():
    nodes = intake_tfe(TFE_FIXTURE)
    by_id = {n["@id"]: n for n in nodes}
    types = by_id["workload:pci-payments-prod-us-east-1"]["resource_types"]
    assert "aws_eks_cluster" in types
    assert "aws_rds_cluster" in types


def test_intake_tfe_resource_count():
    nodes = intake_tfe(TFE_FIXTURE)
    by_id = {n["@id"]: n for n in nodes}
    assert by_id["workload:pci-payments-prod-us-east-1"]["resource_count"] == 2
    assert by_id["workload:fraud-detection-pipeline"]["resource_count"] == 0


def test_intake_tfe_vcs_repo():
    nodes = intake_tfe(TFE_FIXTURE)
    by_id = {n["@id"]: n for n in nodes}
    assert by_id["workload:pci-payments-prod-us-east-1"]["vcs_repo"] == "org/payments-infra"


def test_intake_tfe_empty():
    assert intake_tfe({"workspaces": []}) == []


def test_intake_tfe_from_file(tmp_path):
    fixture_path = tmp_path / "tfe.json"
    fixture_path.write_text(json.dumps(TFE_FIXTURE))
    nodes = intake_tfe_from_file(fixture_path)
    assert len(nodes) == 2


def test_write_workload_nodes(tmp_path):
    nodes = intake_tfe(TFE_FIXTURE)
    written = write_workload_nodes(nodes, tmp_path)
    assert len(written) == 2
    for p in written:
        assert p.exists()
        data = json.loads(p.read_text())
        assert data["@type"] == "Workload"


def test_write_workload_nodes_creates_subdir(tmp_path):
    nodes = intake_tfe(TFE_FIXTURE)
    write_workload_nodes(nodes, tmp_path)
    assert (tmp_path / "workloads").is_dir()
