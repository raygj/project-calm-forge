"""Tests for P6-002 — KG federation: FederatedKGView and supporting functions."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    intake_tfe,
    write_environment_nodes,
    write_placement_nodes,
    write_workload_nodes,
)
from calm_forge.kg_multi_root import (
    MultiRootConfig as FederationConfig,
)
from calm_forge.kg_multi_root import (
    MultiRootError as FederationError,
)
from calm_forge.kg_multi_root import (
    MultiRootKGView as FederatedKGView,
)
from calm_forge.kg_multi_root import (
    load_multi_root_config as load_federation_config,
)
from calm_forge.kg_multi_root import (
    multi_root_fabric_feed as federated_fabric_feed,
)
from calm_forge.kg_multi_root import (
    multi_root_kg_query as federated_kg_query,
)
from calm_forge.kg_multi_root import (
    multi_root_kg_status as federated_kg_status,
)
from calm_forge.kg_multi_root import (
    save_multi_root_config as save_federation_config,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACM_FIXTURE_A = {
    "clusters": [
        {"name": "prod-us-east-1", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {}, "capabilities": ["http_read"]},
    ]
}

ACM_FIXTURE_B = {
    "clusters": [
        {"name": "prod-eu-west-1", "region": "eu-west-1", "status": "ready",
         "substrate": "x86", "labels": {}, "capabilities": ["http_read"]},
    ]
}

AAP_FIXTURE_A = {
    "jobs": [
        {"id": "j1", "workload_name": "payments", "target_cluster": "prod-us-east-1",
         "namespace": "payments", "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

AAP_FIXTURE_B = {
    "jobs": [
        {"id": "j2", "workload_name": "inventory", "target_cluster": "prod-eu-west-1",
         "namespace": "inventory", "region": "eu-west-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

TFE_FIXTURE_A = {
    "workspaces": [
        {"name": "payments-prod", "terraform_version": "1.7.4", "tags": ["pci"],
         "vcs_repo": {}, "working_directory": "", "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-04-01T00:00:00Z", "variables": [], "resources": []},
    ]
}

TFE_FIXTURE_B = {
    "workspaces": [
        {"name": "inventory-prod", "terraform_version": "1.7.4", "tags": [],
         "vcs_repo": {}, "working_directory": "", "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-04-01T00:00:00Z", "variables": [], "resources": []},
    ]
}


def _build_kg(tmp_path: Path, acm_fixture, aap_fixture, tfe_fixture) -> Path:
    env_nodes = intake_acm(acm_fixture)
    write_environment_nodes(env_nodes, tmp_path)
    placement_nodes = intake_ansible(aap_fixture, env_nodes)
    write_placement_nodes(placement_nodes, tmp_path)
    workload_nodes = intake_tfe(tfe_fixture)
    write_workload_nodes(workload_nodes, tmp_path)
    return tmp_path


@pytest.fixture
def kg_a(tmp_path):
    root = tmp_path / "kg_a"
    root.mkdir()
    return _build_kg(root, ACM_FIXTURE_A, AAP_FIXTURE_A, TFE_FIXTURE_A)


@pytest.fixture
def kg_b(tmp_path):
    root = tmp_path / "kg_b"
    root.mkdir()
    return _build_kg(root, ACM_FIXTURE_B, AAP_FIXTURE_B, TFE_FIXTURE_B)


@pytest.fixture
def primary_kg(tmp_path):
    root = tmp_path / "primary"
    root.mkdir()
    return root


# ---------------------------------------------------------------------------
# FederationConfig / load / save
# ---------------------------------------------------------------------------

def test_save_creates_federation_json(primary_kg):
    cfg = FederationConfig(roots=[primary_kg / "other"])
    written = save_federation_config(cfg, primary_kg)
    assert written == primary_kg / "_fabric" / "multi_root.json"
    assert written.exists()


def test_load_returns_none_when_absent(primary_kg):
    assert load_federation_config(primary_kg) is None


def test_round_trip_preserves_roots(primary_kg, kg_a, kg_b):
    cfg = FederationConfig(roots=[kg_a, kg_b], name="test-fed", description="round trip")
    save_federation_config(cfg, primary_kg)
    loaded = load_federation_config(primary_kg)
    assert loaded is not None
    assert loaded.roots == [kg_a, kg_b]
    assert loaded.name == "test-fed"
    assert loaded.description == "round trip"


def test_roots_stored_as_strings_loaded_as_paths(primary_kg, kg_a):
    cfg = FederationConfig(roots=[kg_a])
    save_federation_config(cfg, primary_kg)
    raw = json.loads((primary_kg / "_fabric" / "multi_root.json").read_text())
    assert isinstance(raw["roots"][0], str)
    loaded = load_federation_config(primary_kg)
    assert all(isinstance(r, Path) for r in loaded.roots)


# ---------------------------------------------------------------------------
# federated_kg_status
# ---------------------------------------------------------------------------

def test_status_members_length(kg_a, kg_b):
    result = federated_kg_status([kg_a, kg_b])
    assert len(result["members"]) == 2


def test_status_totals_environments_is_sum(kg_a, kg_b):
    from calm_forge.kg_inspect import kg_status
    count_a = kg_status(kg_a)["environments"]["count"]
    count_b = kg_status(kg_b)["environments"]["count"]
    result = federated_kg_status([kg_a, kg_b])
    assert result["totals"]["environments"]["count"] == count_a + count_b


def test_status_each_member_has_root_key(kg_a, kg_b):
    result = federated_kg_status([kg_a, kg_b])
    for member in result["members"]:
        assert "root" in member


def test_status_single_root_matches_plain_kg_status(kg_a):
    from calm_forge.kg_inspect import kg_status
    plain = kg_status(kg_a)
    fed = federated_kg_status([kg_a])
    assert fed["totals"]["environments"]["count"] == plain["environments"]["count"]
    assert fed["totals"]["workloads"]["count"] == plain["workloads"]["count"]


def test_status_root_count(kg_a, kg_b):
    result = federated_kg_status([kg_a, kg_b])
    assert result["root_count"] == 2


# ---------------------------------------------------------------------------
# federated_kg_query
# ---------------------------------------------------------------------------

def test_query_returns_nodes_from_both_roots(kg_a, kg_b):
    results = federated_kg_query([kg_a, kg_b], node_type="Workload")
    assert len(results) >= 2


def test_query_deduplicates_by_id(kg_a):
    results = federated_kg_query([kg_a, kg_a], node_type="Workload")
    ids = [r["node"]["@id"] for r in results if "node" in r]
    assert len(ids) == len(set(ids))


def test_query_results_have_federation_root_key(kg_a, kg_b):
    results = federated_kg_query([kg_a, kg_b], node_type="Workload")
    for entry in results:
        assert "_multi_root" in entry


def test_query_empty_roots_returns_empty_list():
    result = federated_kg_query([])
    assert result == []


def test_query_where_dict_filters_by_value(kg_a, kg_b):
    """`where` is typed as a dict; it must filter by value, not degrade to keys.

    Regression: the body did `list(where or [])`, and `list({"region": "..."})`
    yields `["region"]` — bare keys with no value — which kg_query rejects as a
    malformed predicate. Every non-empty federated filter raised ValueError.
    """
    results = federated_kg_query(
        [kg_a, kg_b], node_type="ExecutionEnvironment", where={"region": "eu-west-1"}
    )
    regions = {r["node"].get("region") for r in results if "node" in r}
    assert regions == {"eu-west-1"}


def test_query_empty_where_dict_matches_everything(kg_a):
    filtered = federated_kg_query([kg_a], node_type="ExecutionEnvironment", where={})
    unfiltered = federated_kg_query([kg_a], node_type="ExecutionEnvironment")
    assert len(filtered) == len(unfiltered)


# ---------------------------------------------------------------------------
# federated_fabric_feed
# ---------------------------------------------------------------------------

def test_fabric_feed_workloads_from_all_roots(kg_a, kg_b):
    from calm_forge.dashboard import build_fabric_feed
    feed_a = build_fabric_feed(kg_a)
    feed_b = build_fabric_feed(kg_b)
    combined = len(feed_a["workloads"]) + len(feed_b["workloads"])
    result = federated_fabric_feed([kg_a, kg_b])
    assert len(result["workloads"]) == combined


def test_fabric_feed_member_count(kg_a, kg_b):
    result = federated_fabric_feed([kg_a, kg_b])
    assert result["member_count"] == 2


def test_fabric_feed_total_workloads_equals_len_workloads(kg_a, kg_b):
    result = federated_fabric_feed([kg_a, kg_b])
    assert result["total_workloads"] == len(result["workloads"])


# ---------------------------------------------------------------------------
# FederatedKGView
# ---------------------------------------------------------------------------

def test_view_status_delegates(kg_a, kg_b):
    view = FederatedKGView([kg_a, kg_b])
    result = view.status()
    assert "members" in result
    assert result["root_count"] == 2


def test_view_query_delegates(kg_a, kg_b):
    view = FederatedKGView([kg_a, kg_b])
    results = view.query(node_type="Workload")
    assert isinstance(results, list)
    for entry in results:
        assert "_multi_root" in entry


def test_view_fabric_feed_delegates(kg_a, kg_b):
    view = FederatedKGView([kg_a, kg_b])
    result = view.fabric_feed()
    assert "workloads" in result
    assert result["member_count"] == 2


# ---------------------------------------------------------------------------
# FederationError
# ---------------------------------------------------------------------------

def test_federation_error_raised_for_missing_root(tmp_path):
    missing = tmp_path / "nonexistent"
    with pytest.raises(FederationError, match="does not exist"):
        federated_kg_status([missing])


def test_federation_error_raised_in_query_for_missing_root(tmp_path):
    missing = tmp_path / "nonexistent"
    with pytest.raises(FederationError, match="does not exist"):
        federated_kg_query([missing], node_type="Workload")


# ---------------------------------------------------------------------------
# Deprecated kg_federation shim — public re-export API must stay intact.
# Guards against linters/refactors silently stripping the back-compat aliases
# (a partial F401 suppression once let an autofix drop 7 of these).
# ---------------------------------------------------------------------------

def test_kg_federation_shim_reexports_full_api():
    import calm_forge.kg_federation as shim

    expected = {
        "FederationConfig",
        "FederationError",
        "FederatedKGView",
        "load_federation_config",
        "federated_fabric_feed",
        "federated_kg_query",
        "federated_kg_status",
        "save_federation_config",
    }
    assert expected.issubset(set(shim.__all__))
    for name in expected:
        assert getattr(shim, name) is not None
