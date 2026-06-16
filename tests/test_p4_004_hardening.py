"""Tests for P4-004 — Concert API client, OPA hardening, namespace RBAC."""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from calm_forge.concert_client import ConcertAPIError, ConcertClient, FixtureConcertClient
from calm_forge.intake import intake_concert_live
from calm_forge.kg_namespace import (
    NamespaceAccessDenied,
    NamespacePolicy,
    check_namespace_access,
    load_namespace_policy,
    validate_namespace_access,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CONCERT_EXPORT = {
    "applications": [
        {
            "name": "fraud-v1",
            "risk_score": 0.88,
            "risk_level": "critical",
            "blocked_environments": ["env:acm:shared-dev"],
            "allowed_environments": [],
            "evaluated_at": "2026-05-08T10:00:00Z",
        }
    ]
}


# ---------------------------------------------------------------------------
# ConcertClient.from_env
# ---------------------------------------------------------------------------

def test_from_env_returns_fixture_client_when_no_env():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CALM_FORGE_CONCERT_URL", None)
        os.environ.pop("CALM_FORGE_CONCERT_API_KEY", None)
        client = ConcertClient.from_env()
    assert isinstance(client, FixtureConcertClient)


def test_from_env_returns_concert_client_when_env_set():
    with patch.dict(os.environ, {
        "CALM_FORGE_CONCERT_URL": "https://concert.example.com",
        "CALM_FORGE_CONCERT_API_KEY": "test-key",
    }):
        client = ConcertClient.from_env()
    assert isinstance(client, ConcertClient)


def test_from_env_fixture_client_uses_fixture_path(tmp_path):
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(CONCERT_EXPORT))
    with patch.dict(os.environ, {
        "CALM_FORGE_CONCERT_FIXTURE": str(fixture_file),
    }):
        os.environ.pop("CALM_FORGE_CONCERT_URL", None)
        os.environ.pop("CALM_FORGE_CONCERT_API_KEY", None)
        client = ConcertClient.from_env()
    assert isinstance(client, FixtureConcertClient)
    result = client.get_risk_export()
    assert len(result["applications"]) == 1


# ---------------------------------------------------------------------------
# FixtureConcertClient
# ---------------------------------------------------------------------------

def test_fixture_client_no_fixture_raises(tmp_path):
    client = FixtureConcertClient(fixture_path=None)
    with pytest.raises(ConcertAPIError, match="No Concert fixture"):
        client.get_risk_export()


def test_fixture_client_reads_fixture(tmp_path):
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(CONCERT_EXPORT))
    client = FixtureConcertClient(fixture_path=fixture_file)
    result = client.get_risk_export()
    assert result["applications"][0]["name"] == "fraud-v1"


def test_fixture_client_filters_by_app_names(tmp_path):
    export = {
        "applications": [
            {"name": "fraud-v1", "risk_score": 0.8, "risk_level": "high",
             "blocked_environments": [], "allowed_environments": [], "evaluated_at": "2026-05-08T10:00:00Z"},
            {"name": "payments-v1", "risk_score": 0.2, "risk_level": "low",
             "blocked_environments": [], "allowed_environments": [], "evaluated_at": "2026-05-08T10:00:00Z"},
        ]
    }
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(export))
    client = FixtureConcertClient(fixture_path=fixture_file)
    result = client.get_risk_export(app_names=["fraud-v1"])
    assert len(result["applications"]) == 1
    assert result["applications"][0]["name"] == "fraud-v1"


def test_fixture_client_missing_file_raises(tmp_path):
    client = FixtureConcertClient(fixture_path=tmp_path / "nonexistent.json")
    with pytest.raises(ConcertAPIError):
        client.get_risk_export()


def test_fixture_client_invalid_json_raises(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json")
    client = FixtureConcertClient(fixture_path=bad_file)
    with pytest.raises(ConcertAPIError):
        client.get_risk_export()


# ---------------------------------------------------------------------------
# ConcertClient HTTP (mocked)
# ---------------------------------------------------------------------------

def test_concert_client_calls_correct_endpoint():
    client = ConcertClient("https://concert.example.com", "key")
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(CONCERT_EXPORT).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        result = client.get_risk_export()

    call_args = mock_open.call_args
    req = call_args[0][0]
    assert "risk-export" in req.full_url
    assert result["applications"][0]["name"] == "fraud-v1"


def test_concert_client_filters_by_app_names_in_url():
    client = ConcertClient("https://concert.example.com", "key")
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(CONCERT_EXPORT).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        client.get_risk_export(app_names=["fraud-v1"])

    req = mock_open.call_args[0][0]
    assert "fraud-v1" in req.full_url


def test_concert_client_raises_on_http_error():
    import urllib.error
    client = ConcertClient("https://concert.example.com", "key", retries=0)
    with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
        url=None, code=403, msg="Forbidden", hdrs=None, fp=None
    )):
        with pytest.raises(ConcertAPIError) as exc_info:
            client.get_risk_export()
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# intake_concert_live
# ---------------------------------------------------------------------------

def test_intake_concert_live_uses_fixture_client(tmp_path):
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(CONCERT_EXPORT))
    client = FixtureConcertClient(fixture_path=fixture_file)
    nodes = intake_concert_live(client=client)
    assert len(nodes) == 1
    assert nodes[0]["@type"] == "PlacementPolicy"


def test_intake_concert_live_produces_correct_workload_id(tmp_path):
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(CONCERT_EXPORT))
    client = FixtureConcertClient(fixture_path=fixture_file)
    nodes = intake_concert_live(client=client)
    assert nodes[0]["workload_id"] == "workload:fraud-v1"


def test_intake_concert_live_filters_app_names(tmp_path):
    export = {
        "applications": [
            {"name": "fraud-v1", "risk_score": 0.8, "risk_level": "high",
             "blocked_environments": [], "allowed_environments": [], "evaluated_at": "2026-05-08T10:00:00Z"},
            {"name": "payments-v1", "risk_score": 0.2, "risk_level": "low",
             "blocked_environments": [], "allowed_environments": [], "evaluated_at": "2026-05-08T10:00:00Z"},
        ]
    }
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(export))
    client = FixtureConcertClient(fixture_path=fixture_file)
    nodes = intake_concert_live(app_names=["fraud-v1"], client=client)
    assert len(nodes) == 1


# ---------------------------------------------------------------------------
# Namespace RBAC — check_namespace_access
# ---------------------------------------------------------------------------

def _write_policy(kg_dir: Path, policy: dict) -> None:
    fabric_dir = kg_dir / "_fabric"
    fabric_dir.mkdir(parents=True, exist_ok=True)
    (fabric_dir / "namespace-policy.json").write_text(json.dumps(policy))


def test_check_namespace_access_permissive_when_no_policy(tmp_path):
    assert check_namespace_access(tmp_path, "team-a", "alice") is True


def test_check_namespace_access_deny_principal(tmp_path):
    _write_policy(tmp_path / "team-a", {"deny_principals": ["mallory"]})
    assert check_namespace_access(tmp_path, "team-a", "mallory") is False


def test_check_namespace_access_allow_listed_principal(tmp_path):
    _write_policy(tmp_path / "team-a", {"allowed_principals": ["alice", "bob"]})
    assert check_namespace_access(tmp_path, "team-a", "alice") is True


def test_check_namespace_access_deny_unlisted_when_allowlist_set(tmp_path):
    _write_policy(tmp_path / "team-a", {"allowed_principals": ["alice"]})
    assert check_namespace_access(tmp_path, "team-a", "carol") is False


def test_check_namespace_access_deny_beats_allow(tmp_path):
    _write_policy(tmp_path / "team-a", {
        "allowed_principals": ["alice"],
        "deny_principals": ["alice"],
    })
    assert check_namespace_access(tmp_path, "team-a", "alice") is False


def test_check_namespace_access_empty_policy_is_permissive(tmp_path):
    _write_policy(tmp_path / "team-a", {})
    assert check_namespace_access(tmp_path, "team-a", "anyone") is True


# ---------------------------------------------------------------------------
# validate_namespace_access
# ---------------------------------------------------------------------------

def test_validate_namespace_access_allowed_does_not_raise(tmp_path):
    validate_namespace_access(tmp_path, "team-a", "alice")  # no policy = permissive


def test_validate_namespace_access_denied_raises(tmp_path):
    _write_policy(tmp_path / "team-a", {"deny_principals": ["mallory"]})
    with pytest.raises(NamespaceAccessDenied) as exc_info:
        validate_namespace_access(tmp_path, "team-a", "mallory")
    assert exc_info.value.principal == "mallory"
    assert exc_info.value.namespace == "team-a"


def test_namespace_access_denied_is_permission_error(tmp_path):
    _write_policy(tmp_path / "team-a", {"deny_principals": ["mallory"]})
    with pytest.raises(PermissionError):
        validate_namespace_access(tmp_path, "team-a", "mallory")


# ---------------------------------------------------------------------------
# load_namespace_policy
# ---------------------------------------------------------------------------

def test_load_namespace_policy_returns_none_when_absent(tmp_path):
    assert load_namespace_policy(tmp_path, "team-a") is None


def test_load_namespace_policy_returns_dataclass(tmp_path):
    _write_policy(tmp_path, {"allowed_principals": ["alice"], "deny_principals": []})
    policy = load_namespace_policy(tmp_path, "team-a")
    assert isinstance(policy, NamespacePolicy)
    assert policy.allowed_principals == ["alice"]


def test_load_namespace_policy_invalid_json_returns_none(tmp_path):
    fabric = tmp_path / "_fabric"
    fabric.mkdir()
    (fabric / "namespace-policy.json").write_text("not json")
    assert load_namespace_policy(tmp_path, "team-a") is None
