"""Tests for kg_loader — KG JSON-LD pattern loading and summarisation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.kg_loader import (
    extract_capabilities,
    extract_compliance,
    extract_placements,
    extract_policies,
    load_patterns,
    load_summaries,
    pattern_summary,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MINIMAL_WORKLOAD = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Workload",
    "@id": "workload:test:v1",
    "version": "1.0.0",
    "name": "test-workload",
    "purpose": "Test workload for unit tests",
    "owner": "test-team",
    "compliance_scope": ["PCI-DSS-v4:req-1"],
    "_provenance": {"authored_by": "test", "authored_at": "2026-04-21T00:00:00Z"},
    "nodes": [
        {
            "@type": "WorkloadComponent",
            "@id": "workload:test:v1:web",
            "name": "web",
            "declared_capabilities": ["http_read", "tls_termination"],
        }
    ],
    "policies": [
        {
            "@type": "Policy",
            "@id": "workload:test:v1:policy:placement",
            "predicate_type": "placement_constraint",
            "required_labels": {"environment": "prod"},
            "enforcement_mode": "enforce",
            "evaluated_by": "calm.placement.label_constraint",
            "provenance": "authored",
            "rationale": "Must run in prod",
        },
        {
            "@type": "Policy",
            "@id": "workload:test:v1:policy:region",
            "predicate_type": "compliance_boundary",
            "allowed_regions": ["us-east-1", "eu-west-1"],
            "enforcement_mode": "enforce",
            "evaluated_by": "calm.placement.region_constraint",
            "provenance": "authored",
            "rationale": "Data residency",
        },
    ],
    "capability_declarations": [
        {
            "@type": "Capability",
            "@id": "capability:http_read",
            "capability_type": "network",
        }
    ],
    "compliance_nodes": [
        {
            "@type": "Compliance",
            "@id": "compliance:PCI-DSS-v4:req-1",
            "framework": "PCI-DSS-v4",
            "control_id": "req-1",
            "requirement_text": "Install and maintain network security controls",
        }
    ],
    "edges": [
        {"@type": "requires_capability", "from": "workload:test:v1:web", "to": "capability:http_read"},
    ],
}

_NON_WORKLOAD = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Capability",
    "@id": "capability:http_read",
}


@pytest.fixture()
def kg_dir_with_workload(tmp_path: Path) -> Path:
    (tmp_path / "test-workload.json").write_text(json.dumps(_MINIMAL_WORKLOAD))
    return tmp_path


@pytest.fixture()
def kg_dir_mixed(tmp_path: Path) -> Path:
    (tmp_path / "workload.json").write_text(json.dumps(_MINIMAL_WORKLOAD))
    (tmp_path / "capability.json").write_text(json.dumps(_NON_WORKLOAD))
    (tmp_path / "bad.json").write_text("not json {{{")
    return tmp_path


# ---------------------------------------------------------------------------
# load_patterns
# ---------------------------------------------------------------------------


def test_load_patterns_returns_only_workloads(kg_dir_mixed: Path) -> None:
    patterns = load_patterns(kg_dir_mixed)
    assert len(patterns) == 1
    assert patterns[0]["@type"] == "Workload"


def test_load_patterns_skips_invalid_json(kg_dir_mixed: Path) -> None:
    patterns = load_patterns(kg_dir_mixed)
    assert all(isinstance(p, dict) for p in patterns)


def test_load_patterns_empty_dir(tmp_path: Path) -> None:
    assert load_patterns(tmp_path) == []


def test_load_patterns_missing_dir() -> None:
    assert load_patterns(Path("/nonexistent/kg/dir")) == []


# ---------------------------------------------------------------------------
# extract_policies
# ---------------------------------------------------------------------------


def test_extract_policies_returns_policy_nodes(kg_dir_with_workload: Path) -> None:
    pattern = load_patterns(kg_dir_with_workload)[0]
    policies = extract_policies(pattern)
    assert len(policies) == 2
    assert all(p["@type"] == "Policy" for p in policies)


def test_extract_policies_predicate_types(kg_dir_with_workload: Path) -> None:
    pattern = load_patterns(kg_dir_with_workload)[0]
    types = {p["predicate_type"] for p in extract_policies(pattern)}
    assert types == {"placement_constraint", "compliance_boundary"}


# ---------------------------------------------------------------------------
# extract_capabilities
# ---------------------------------------------------------------------------


def test_extract_capabilities(kg_dir_with_workload: Path) -> None:
    pattern = load_patterns(kg_dir_with_workload)[0]
    caps = extract_capabilities(pattern)
    assert len(caps) == 1
    assert caps[0]["@type"] == "Capability"


# ---------------------------------------------------------------------------
# extract_compliance
# ---------------------------------------------------------------------------


def test_extract_compliance(kg_dir_with_workload: Path) -> None:
    pattern = load_patterns(kg_dir_with_workload)[0]
    compliance = extract_compliance(pattern)
    assert len(compliance) == 1
    assert compliance[0]["framework"] == "PCI-DSS-v4"


# ---------------------------------------------------------------------------
# extract_placements
# ---------------------------------------------------------------------------


def test_extract_placements_none_in_greenfield(kg_dir_with_workload: Path) -> None:
    pattern = load_patterns(kg_dir_with_workload)[0]
    assert extract_placements(pattern) == []


# ---------------------------------------------------------------------------
# pattern_summary
# ---------------------------------------------------------------------------


def test_pattern_summary_shape(kg_dir_with_workload: Path) -> None:
    pattern = load_patterns(kg_dir_with_workload)[0]
    summary = pattern_summary(pattern)

    assert summary["id"] == "workload:test:v1"
    assert summary["name"] == "test-workload"
    assert summary["version"] == "1.0.0"
    assert summary["policy_count"] == 2
    assert set(summary["predicate_types"]) == {"placement_constraint", "compliance_boundary"}
    assert "http_read" in summary["capabilities_required"]
    assert "PCI-DSS-v4:req-1" in summary["compliance_scope"]


def test_pattern_summary_enforcement_modes(kg_dir_with_workload: Path) -> None:
    pattern = load_patterns(kg_dir_with_workload)[0]
    summary = pattern_summary(pattern)
    assert summary["enforcement_modes"] == ["enforce"]


# ---------------------------------------------------------------------------
# load_summaries
# ---------------------------------------------------------------------------


def test_load_summaries_returns_list(kg_dir_with_workload: Path) -> None:
    summaries = load_summaries(kg_dir_with_workload)
    assert len(summaries) == 1
    assert summaries[0]["name"] == "test-workload"


def test_load_summaries_real_kg_dir() -> None:
    """Smoke test against the real built-in KG patterns."""
    from calm_forge.kg_loader import _KG_DIR

    summaries = load_summaries(_KG_DIR)
    assert len(summaries) >= 2
    names = [s["name"] for s in summaries]
    assert "3-tier-pci" in names
    assert "fraud-detection-pipeline" in names
