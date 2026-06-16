"""Tests for OPA intent validation gate (P1-012).

All subprocess calls are mocked — no real OPA binary needed.
The graceful-degradation path (OPA not available → valid=True with warning)
is the default happy path for tests that don't explicitly mock OPA as available.
"""
from __future__ import annotations

import json
from pathlib import Path
from subprocess import TimeoutExpired
from unittest.mock import MagicMock, patch

from calm_forge.opa_gate import (
    _resolve_bundle,
    _run_opa_eval,
    get_bundle_path,
    set_bundle,
    start_bundle_watcher,
    stop_bundle_watcher,
    validate_intent,
)

_BUILTIN_BUNDLE = Path(__file__).parent.parent / "src" / "calm_forge" / "opa_policies"

_MINIMAL_CALM = {
    "nodes": [{"unique-id": "svc-1", "node-type": "service"}],
    "relationships": [],
    "metadata": {"application-name": "test"},
}

_MINIMAL_DECORATOR = {"data": {"environment": "staging"}}


# ---------------------------------------------------------------------------
# 1. OPA not available → graceful degradation
# ---------------------------------------------------------------------------


def test_opa_not_available_returns_valid_with_warning():
    with patch("calm_forge.opa_gate.is_opa_available", return_value=False):
        result = validate_intent(_MINIMAL_CALM, _MINIMAL_DECORATOR)
    assert result["valid"] is True
    assert result["violations"] == []
    assert result["opa_available"] is False
    assert "warning" in result
    assert result["warning"] is not None
    assert "OPA CLI not found" in result["warning"]


# ---------------------------------------------------------------------------
# 2. OPA available, no violations
# ---------------------------------------------------------------------------


def test_opa_available_no_violations():
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", return_value=[]),
    ):
        result = validate_intent(_MINIMAL_CALM, _MINIMAL_DECORATOR)
    assert result["valid"] is True
    assert result["violations"] == []
    assert result["opa_available"] is True


# ---------------------------------------------------------------------------
# 3. OPA available, violations present
# ---------------------------------------------------------------------------


def test_opa_available_with_violations():
    violation = {
        "rule": "pci-placement",
        "severity": "error",
        "message": "PCI workloads must target prod-pci-* clusters. Got environment: 'staging'",
    }
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", return_value=[violation]),
    ):
        result = validate_intent(_MINIMAL_CALM, _MINIMAL_DECORATOR)
    assert result["valid"] is False
    assert len(result["violations"]) == 1
    assert result["violations"][0]["rule"] == "pci-placement"


# ---------------------------------------------------------------------------
# 4. OPA timeout
# ---------------------------------------------------------------------------


def test_opa_timeout():
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch(
            "calm_forge.opa_gate._run_opa_eval",
            side_effect=TimeoutExpired(cmd="opa", timeout=30),
        ),
    ):
        result = validate_intent(_MINIMAL_CALM, _MINIMAL_DECORATOR)
    assert result["valid"] is False
    assert result["violations"][0]["rule"] == "opa-timeout"


# ---------------------------------------------------------------------------
# 5. OPA runtime error captured
# ---------------------------------------------------------------------------


def test_opa_error_captured():
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch(
            "calm_forge.opa_gate._run_opa_eval",
            side_effect=RuntimeError("rego compilation failed"),
        ),
    ):
        result = validate_intent(_MINIMAL_CALM, _MINIMAL_DECORATOR)
    assert result["valid"] is False
    assert result["violations"][0]["rule"] == "opa-error"
    assert "rego compilation failed" in result["violations"][0]["message"]


# ---------------------------------------------------------------------------
# 6. _run_opa_eval parses output correctly
# ---------------------------------------------------------------------------


def test_run_opa_eval_parses_output():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps({
        "result": [
            {
                "expressions": [
                    {
                        "value": [
                            {
                                "rule": "pci-placement",
                                "severity": "error",
                                "message": "test",
                            }
                        ]
                    }
                ]
            }
        ]
    })

    with patch("subprocess.run", return_value=mock_result):
        violations = _run_opa_eval(
            {"calm": _MINIMAL_CALM, "decorator": _MINIMAL_DECORATOR},
            _BUILTIN_BUNDLE,
        )
    assert len(violations) == 1
    assert violations[0]["rule"] == "pci-placement"


# ---------------------------------------------------------------------------
# 7. _run_opa_eval handles undefined result (empty result list)
# ---------------------------------------------------------------------------


def test_run_opa_eval_undefined_result():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps({"result": []})

    with patch("subprocess.run", return_value=mock_result):
        violations = _run_opa_eval(
            {"calm": _MINIMAL_CALM, "decorator": _MINIMAL_DECORATOR},
            _BUILTIN_BUNDLE,
        )
    assert violations == []


# ---------------------------------------------------------------------------
# 8. _resolve_bundle with local path
# ---------------------------------------------------------------------------


def test_resolve_bundle_local_path(tmp_path):
    resolved = _resolve_bundle(tmp_path)
    assert resolved == tmp_path


def test_resolve_bundle_local_path_string(tmp_path):
    resolved = _resolve_bundle(str(tmp_path))
    assert isinstance(resolved, Path)
    assert resolved == tmp_path


# ---------------------------------------------------------------------------
# 9. _resolve_bundle with HTTP URL calls download
# ---------------------------------------------------------------------------


def test_resolve_bundle_http_url(tmp_path):
    fake_bundle = tmp_path / "bundle"
    fake_bundle.mkdir()

    with patch("calm_forge.opa_gate._download_bundle", return_value=fake_bundle) as mock_dl:
        result = _resolve_bundle("https://example.com/calm-policies.tar.gz")
    mock_dl.assert_called_once_with("https://example.com/calm-policies.tar.gz")
    assert result == fake_bundle


# ---------------------------------------------------------------------------
# 10. set_bundle updates path
# ---------------------------------------------------------------------------


def test_set_bundle_updates_path(tmp_path):
    set_bundle(str(tmp_path))
    assert get_bundle_path() == tmp_path


# ---------------------------------------------------------------------------
# 11. set_bundle(None) uses built-in
# ---------------------------------------------------------------------------


def test_set_bundle_none_uses_builtin():
    # Clear env var if set
    import os
    os.environ.pop("CALM_FORGE_OPA_BUNDLE", None)
    set_bundle(None)
    bp = get_bundle_path()
    # Should be the built-in bundle directory
    assert "opa_policies" in str(bp)


# ---------------------------------------------------------------------------
# 12. Bundle watcher starts and stops cleanly
# ---------------------------------------------------------------------------


def test_bundle_watcher_starts_and_stops():
    # Reset to built-in (local path) so watcher doesn't skip
    set_bundle(None)
    start_bundle_watcher(interval_seconds=60)
    # Give the thread a moment to start
    import time
    time.sleep(0.05)
    stop_bundle_watcher()
    # After stopping, watcher thread should be None
    from calm_forge import opa_gate
    assert opa_gate._watcher_thread is None


# ---------------------------------------------------------------------------
# 13. validate_intent with warning=None for OPA available + no violations
# ---------------------------------------------------------------------------


def test_validate_intent_warning_none_when_opa_ok():
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", return_value=[]),
    ):
        result = validate_intent(_MINIMAL_CALM, _MINIMAL_DECORATOR)
    assert result["warning"] is None


# ---------------------------------------------------------------------------
# 14. validate_intent with no decorator (defaults to empty dict)
# ---------------------------------------------------------------------------


def test_validate_intent_no_decorator():
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=False),
    ):
        result = validate_intent(_MINIMAL_CALM)
    assert result["valid"] is True
    assert result["opa_available"] is False


# ---------------------------------------------------------------------------
# 15. Warning-only violations (all severity=warning) → valid=True
# ---------------------------------------------------------------------------


def test_validate_intent_warning_violations_still_valid():
    violation = {
        "rule": "production-replica-minimum",
        "severity": "warning",
        "message": "Service 'svc-1' has 1 replica(s) — production requires >= 2",
    }
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", return_value=[violation]),
    ):
        result = validate_intent(_MINIMAL_CALM, _MINIMAL_DECORATOR)
    # Warnings don't make it invalid — only severity=error does
    assert result["valid"] is True
    assert len(result["violations"]) == 1
