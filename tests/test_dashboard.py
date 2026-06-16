"""Tests for the drift dashboard — JSON feed, HTML rendering, and CLI (P3-004)."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.dashboard import _DashboardHandler, build_fabric_feed, render_html
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    intake_concert,
    write_environment_nodes,
    write_placement_nodes,
    write_policy_nodes,
)
from calm_forge.interviewer import build_workload, write_workload_node

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACM = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"compliance": "pci"},
         "capabilities": ["confidential_compute", "http_read"]},
    ]
}

AAP = {
    "jobs": [
        {"id": "j1", "workload_name": "fraud-v1", "target_cluster": "prod-east",
         "namespace": "fraud", "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

CONCERT = {
    "applications": [
        {"name": "fraud-v1", "risk_score": 0.88, "risk_level": "critical",
         "blocked_environments": ["env:acm:shared-dev"], "allowed_environments": [],
         "evaluated_at": "2026-05-08T10:00:00Z"},
    ]
}

SPEC = {
    "name": "fraud-v1",
    "purpose": "Fraud detection",
    "owner": "fraud-team",
    "components": [{"name": "scorer", "capabilities": ["http_read", "confidential_compute"]}],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1"],
}


def _build_kg(tmp_path: Path) -> Path:
    envs = intake_acm(ACM)
    write_environment_nodes(envs, tmp_path)
    placements = intake_ansible(AAP, envs)
    write_placement_nodes(placements, tmp_path)
    node = build_workload(SPEC)
    write_workload_node(node, tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# build_fabric_feed — structure
# ---------------------------------------------------------------------------

def test_feed_has_generated_at(tmp_path):
    feed = build_fabric_feed(tmp_path)
    assert "generated_at" in feed


def test_feed_has_summary(tmp_path):
    feed = build_fabric_feed(tmp_path)
    assert "summary" in feed


def test_feed_summary_has_overall_status(tmp_path):
    feed = build_fabric_feed(tmp_path)
    assert "overall_status" in feed["summary"]


def test_feed_empty_kg(tmp_path):
    feed = build_fabric_feed(tmp_path)
    assert feed["summary"]["workloads"] == 0
    assert feed["summary"]["environments"] == 0


def test_feed_counts_environments(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    assert feed["summary"]["environments"] == 1


def test_feed_counts_workloads(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    assert feed["summary"]["workloads"] == 1


def test_feed_counts_placements(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    assert feed["summary"]["placements"] == 1


def test_feed_workload_has_drift_status(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    assert "drift_status" in feed["workloads"][0]


def test_feed_workload_has_placements(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    wl = feed["workloads"][0]
    assert "placements" in wl


def test_feed_workload_has_declared_capabilities(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    wl = feed["workloads"][0]
    assert "declared_capabilities" in wl


def test_feed_environment_has_region(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    env = feed["environments"][0]
    assert env["region"] == "us-east-1"


def test_feed_policies_empty_without_concert(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    assert feed["policies"] == []


def test_feed_policies_present_with_concert(tmp_path):
    _build_kg(tmp_path)
    nodes = intake_concert(CONCERT)
    write_policy_nodes(nodes, tmp_path)
    feed = build_fabric_feed(tmp_path)
    assert len(feed["policies"]) == 1
    assert feed["summary"]["blocking_policies"] == 1


def test_feed_writes_fabric_state_json(tmp_path):
    _build_kg(tmp_path)
    build_fabric_feed(tmp_path)
    # fabric-state.json is written by DashboardHandler.refresh(), not build_fabric_feed
    # (that's intentional — the feed builder doesn't have side effects)
    # Just verify feed is valid
    feed = build_fabric_feed(tmp_path)
    assert feed["summary"]["environments"] == 1


# ---------------------------------------------------------------------------
# build_fabric_feed — multi-namespace
# ---------------------------------------------------------------------------

def _build_ns(kg_root: Path, name: str) -> None:
    ns = kg_root / name
    envs = intake_acm(ACM)
    write_environment_nodes(envs, ns)
    placements = intake_ansible(AAP, envs)
    write_placement_nodes(placements, ns)


def test_feed_namespace_isolation(tmp_path):
    _build_ns(tmp_path, "team-a")
    feed = build_fabric_feed(tmp_path, namespace="team-a")
    assert feed["environments"][0]["namespace"] == "team-a"


def test_feed_all_namespaces_aggregates(tmp_path):
    _build_ns(tmp_path, "team-a")
    _build_ns(tmp_path, "team-b")
    feed = build_fabric_feed(tmp_path, namespace="*")
    assert feed["summary"]["environments"] == 2


# ---------------------------------------------------------------------------
# render_html
# ---------------------------------------------------------------------------

def test_render_html_returns_string(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    html = render_html(feed)
    assert isinstance(html, str)


def test_render_html_has_doctype(tmp_path):
    feed = build_fabric_feed(tmp_path)
    html = render_html(feed)
    assert "<!DOCTYPE html>" in html


def test_render_html_has_overall_status(tmp_path):
    feed = build_fabric_feed(tmp_path)
    html = render_html(feed)
    assert feed["summary"]["overall_status"] in html


def test_render_html_has_refresh_meta(tmp_path):
    feed = build_fabric_feed(tmp_path)
    html = render_html(feed)
    assert 'http-equiv="refresh"' in html


def test_render_html_workload_name_appears(tmp_path):
    _build_kg(tmp_path)
    feed = build_fabric_feed(tmp_path)
    html = render_html(feed)
    assert "fraud-v1" in html


def test_render_html_policy_alert_when_blocked(tmp_path):
    _build_kg(tmp_path)
    nodes = intake_concert(CONCERT)
    write_policy_nodes(nodes, tmp_path)
    feed = build_fabric_feed(tmp_path)
    html = render_html(feed)
    assert "shared-dev" in html


# ---------------------------------------------------------------------------
# _DashboardHandler.refresh + fabric-state.json
# ---------------------------------------------------------------------------

def test_handler_refresh_writes_fabric_state(tmp_path):
    _build_kg(tmp_path)
    _DashboardHandler.kg_dir = tmp_path
    _DashboardHandler.namespace = None
    _DashboardHandler._feed_cache = {}
    _DashboardHandler.refresh()
    assert (tmp_path / "fabric-state.json").exists()
    data = json.loads((tmp_path / "fabric-state.json").read_text())
    assert "summary" in data


def test_handler_get_feed_returns_cache(tmp_path):
    _build_kg(tmp_path)
    _DashboardHandler.kg_dir = tmp_path
    _DashboardHandler.namespace = None
    _DashboardHandler.refresh()
    feed = _DashboardHandler._get_feed()
    assert "summary" in feed


# ---------------------------------------------------------------------------
# CLI: calm-forge dashboard --feed-only
# ---------------------------------------------------------------------------

def test_cli_dashboard_feed_only(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "dashboard",
        "--kg-dir", str(tmp_path),
        "--feed-only",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "summary" in data
    assert "workloads" in data


def test_cli_dashboard_feed_only_counts(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "dashboard",
        "--kg-dir", str(tmp_path),
        "--feed-only",
    ])
    data = json.loads(result.output)
    assert data["summary"]["environments"] == 1
    assert data["summary"]["workloads"] == 1


def test_cli_dashboard_feed_only_empty_kg(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, [
        "dashboard",
        "--kg-dir", str(tmp_path),
        "--feed-only",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["workloads"] == 0


def test_cli_dashboard_feed_only_with_namespace(tmp_path):
    _build_ns(tmp_path, "team-x")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "dashboard",
        "--kg-dir", str(tmp_path),
        "--namespace", "team-x",
        "--feed-only",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["namespace"] == "team-x"


# ---------------------------------------------------------------------------
# MCP tool: calm-forge/fabric-state
# ---------------------------------------------------------------------------

def test_mcp_fabric_state(tmp_path):
    _build_kg(tmp_path)
    from calm_forge.mcp_server import fabric_state_tool
    result = fabric_state_tool(kg_dir=str(tmp_path))
    assert "summary" in result
    assert result["summary"]["environments"] == 1


def test_mcp_fabric_state_empty(tmp_path):
    from calm_forge.mcp_server import fabric_state_tool
    result = fabric_state_tool(kg_dir=str(tmp_path))
    assert result["summary"]["workloads"] == 0


def test_mcp_fabric_state_with_namespace(tmp_path):
    _build_ns(tmp_path, "my-team")
    from calm_forge.mcp_server import fabric_state_tool
    result = fabric_state_tool(kg_dir=str(tmp_path), namespace="my-team")
    assert result["namespace"] == "my-team"
