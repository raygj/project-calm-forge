"""Tests for P4-001 — GitOps deployment emission."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.agent_session import run_agent_session
from calm_forge.gitops_emitter import FilesystemEmitter, GitBranchEmitter, GitOpsEmitter
from calm_forge.intake import load_deployment_requests, write_deployment_request

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FILES = {
    "main.tf": 'resource "aws_s3_bucket" "b" { bucket = "test" }',
    "variables.tf": 'variable "region" { default = "us-east-1" }',
}

SHA = "a" * 64
SLUG = "fraud-v1"

_EXAMPLES = Path(__file__).parent.parent / "examples" / "fraud-detection-workload-portability"

SPEC = {
    "name": "fraud-v1",
    "purpose": "Fraud detection",
    "owner": "fraud-team",
    "components": [{"name": "scorer", "capabilities": ["http_read"]}],
    "compliance_scope": [],
    "allowed_regions": [],
}

CALM = json.loads((_EXAMPLES / "instantiation.json").read_text())
DECORATOR = json.loads((_EXAMPLES / "decorator.json").read_text())
CATALOG = json.loads((_EXAMPLES / "catalog.json").read_text())


# ---------------------------------------------------------------------------
# GitOpsEmitter protocol
# ---------------------------------------------------------------------------

def test_filesystem_emitter_satisfies_protocol():
    assert isinstance(FilesystemEmitter(Path("/tmp")), GitOpsEmitter)


# ---------------------------------------------------------------------------
# FilesystemEmitter
# ---------------------------------------------------------------------------

def test_filesystem_emitter_creates_dest_dir(tmp_path):
    emitter = FilesystemEmitter(tmp_path / "gitops")
    emitter.emit(SLUG, SHA, FILES)
    dest = tmp_path / "gitops" / SLUG / SHA[:8]
    assert dest.exists()


def test_filesystem_emitter_writes_all_files(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    result = emitter.emit(SLUG, SHA, FILES)
    for fname in FILES:
        assert any(fname in p for p in result["artifact_paths"])


def test_filesystem_emitter_file_content_correct(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    emitter.emit(SLUG, SHA, FILES)
    dest = tmp_path / SLUG / SHA[:8]
    assert (dest / "main.tf").read_text() == FILES["main.tf"]


def test_filesystem_emitter_writes_manifest(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    emitter.emit(SLUG, SHA, FILES)
    dest = tmp_path / SLUG / SHA[:8]
    manifest_path = dest / "_manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text())
    assert manifest["workload_slug"] == SLUG
    assert manifest["attestation_sha"] == SHA
    assert set(manifest["files"]) == set(FILES.keys())


def test_filesystem_emitter_returns_target_path(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    result = emitter.emit(SLUG, SHA, FILES)
    assert result["target_path"] == str(tmp_path / SLUG / SHA[:8])


def test_filesystem_emitter_target_branch_is_none(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    result = emitter.emit(SLUG, SHA, FILES)
    assert result["target_branch"] is None


def test_filesystem_emitter_emitter_type(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    result = emitter.emit(SLUG, SHA, FILES)
    assert result["emitter_type"] == "filesystem"


def test_filesystem_emitter_artifact_paths_includes_manifest(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    result = emitter.emit(SLUG, SHA, FILES)
    assert any("_manifest.json" in p for p in result["artifact_paths"])


def test_filesystem_emitter_idempotent(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    emitter.emit(SLUG, SHA, FILES)
    result = emitter.emit(SLUG, SHA, FILES)  # second call should not raise
    assert result["emitter_type"] == "filesystem"


def test_filesystem_emitter_empty_files(tmp_path):
    emitter = FilesystemEmitter(tmp_path)
    result = emitter.emit(SLUG, SHA, {})
    assert result["target_path"] is not None
    dest = Path(result["target_path"])
    assert (dest / "_manifest.json").exists()


# ---------------------------------------------------------------------------
# GitBranchEmitter — non-git-repo degradation
# ---------------------------------------------------------------------------

def test_git_branch_emitter_degrades_gracefully(tmp_path):
    # tmp_path is not a git repo
    emitter = GitBranchEmitter(tmp_path, base_branch="main")
    result = emitter.emit(SLUG, SHA, FILES)
    assert result["emitter_type"] == "git-branch-degraded"
    assert "warning" in result


def test_git_branch_emitter_still_writes_files_on_degrade(tmp_path):
    emitter = GitBranchEmitter(tmp_path, base_branch="main")
    result = emitter.emit(SLUG, SHA, FILES)
    for fname in FILES:
        assert any(fname in p for p in result["artifact_paths"])


# ---------------------------------------------------------------------------
# write_deployment_request + load_deployment_requests
# ---------------------------------------------------------------------------

def _make_request_node(workload_id="workload:fraud-v1", sha8="abcd1234", status="pending"):
    return {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "DeploymentRequest",
        "@id": f"deploy-req:fraud-v1:{sha8}",
        "workload_id": workload_id,
        "attestation_sha": sha8 * 8,
        "artifact_paths": [],
        "target_branch": None,
        "target_path": "/tmp/gitops/fraud-v1/abcd1234",
        "requested_at": "2026-05-08T00:00:00+00:00",
        "requested_by": "calm-forge/agent-run",
        "status": status,
        "_provenance": {},
    }


def test_write_deployment_request_creates_deployments_dir(tmp_path):
    node = _make_request_node()
    write_deployment_request(node, tmp_path)
    assert (tmp_path / "deployments").exists()


def test_write_deployment_request_writes_file(tmp_path):
    node = _make_request_node()
    path = write_deployment_request(node, tmp_path)
    assert path.exists()
    assert json.loads(path.read_text())["@type"] == "DeploymentRequest"


def test_load_deployment_requests_empty(tmp_path):
    assert load_deployment_requests(tmp_path) == []


def test_load_deployment_requests_returns_node(tmp_path):
    node = _make_request_node()
    write_deployment_request(node, tmp_path)
    loaded = load_deployment_requests(tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["@id"] == node["@id"]


def test_load_deployment_requests_filters_by_workload(tmp_path):
    write_deployment_request(_make_request_node("workload:fraud-v1", "aaa11111"), tmp_path)
    write_deployment_request(_make_request_node("workload:other", "bbb22222"), tmp_path)
    results = load_deployment_requests(tmp_path, workload_id="workload:fraud-v1")
    assert len(results) == 1
    assert results[0]["workload_id"] == "workload:fraud-v1"


def test_load_deployment_requests_filters_by_status(tmp_path):
    write_deployment_request(_make_request_node(sha8="aaa11111", status="pending"), tmp_path)
    write_deployment_request(_make_request_node(sha8="bbb22222", status="submitted"), tmp_path)
    results = load_deployment_requests(tmp_path, status="submitted")
    assert len(results) == 1
    assert results[0]["status"] == "submitted"


# ---------------------------------------------------------------------------
# agent_session deploy integration
# ---------------------------------------------------------------------------

def test_session_deploy_skipped_without_gitops_target(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    deploy_step = next(s for s in result["steps"] if s["step"] == "deploy")
    assert deploy_step["result"]["skipped"] is True


def test_session_deploy_skipped_without_artifacts(tmp_path):
    # No calm/decorator/catalog → generate is skipped → deploy skipped
    result = run_agent_session({"spec": SPEC}, tmp_path, gitops_target=tmp_path / "gitops")
    deploy_step = next(s for s in result["steps"] if s["step"] == "deploy")
    assert deploy_step["result"]["skipped"] is True


def test_session_deploy_runs_with_gitops_target(tmp_path):
    gitops = tmp_path / "gitops"
    result = run_agent_session(
        {"spec": SPEC, "calm": CALM, "decorator": DECORATOR, "catalog": CATALOG},
        tmp_path,
        gitops_target=gitops,
    )
    assert result["deployment_request_id"] is not None


def test_session_deploy_returns_deployment_target(tmp_path):
    gitops = tmp_path / "gitops"
    result = run_agent_session(
        {"spec": SPEC, "calm": CALM, "decorator": DECORATOR, "catalog": CATALOG},
        tmp_path,
        gitops_target=gitops,
    )
    assert result["deployment_target"] is not None
    assert Path(result["deployment_target"]).exists()


def test_session_deploy_writes_deployment_request_node(tmp_path):
    gitops = tmp_path / "gitops"
    result = run_agent_session(
        {"spec": SPEC, "calm": CALM, "decorator": DECORATOR, "catalog": CATALOG},
        tmp_path,
        gitops_target=gitops,
    )
    nodes = load_deployment_requests(tmp_path)
    assert len(nodes) == 1
    assert nodes[0]["@id"] == result["deployment_request_id"]


def test_session_deploy_request_status_is_pending(tmp_path):
    gitops = tmp_path / "gitops"
    run_agent_session(
        {"spec": SPEC, "calm": CALM, "decorator": DECORATOR, "catalog": CATALOG},
        tmp_path,
        gitops_target=gitops,
    )
    nodes = load_deployment_requests(tmp_path)
    assert nodes[0]["status"] == "pending"


def test_session_deploy_no_gitops_target_result_keys(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert "deployment_request_id" in result
    assert "deployment_target" in result
    assert result["deployment_request_id"] is None
    assert result["deployment_target"] is None
