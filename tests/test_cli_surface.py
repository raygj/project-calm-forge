"""CLI surface tests — the commands a user actually types.

These cover `src/calm_forge/cli.py`, which for a long time was the least-tested
module in the repo despite being the only interface most people touch. The
emphasis is on paths where being wrong is expensive: fail-closed security
guards, exit codes, and the error messages that tell an operator what to do.

Passport CLI paths live in tests/test_passport_cli.py; KG inspection paths in
tests/test_kg_inspect.py. This file covers what neither of those claims.
"""

from __future__ import annotations

from unittest import mock

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _serve(runner: CliRunner, args: list[str], env: dict[str, str] | None = None):
    """Invoke `serve` with uvicorn stubbed, returning (result, uvicorn_mock).

    Every assertion here is about what the CLI decides *before* it hands off to
    uvicorn, so the handoff itself is the natural seam to cut.
    """
    with mock.patch("uvicorn.run") as uvicorn_run, mock.patch(
        "calm_forge.opa_gate.is_opa_available", return_value=False
    ), mock.patch("calm_forge.opa_gate.set_bundle"):
        result = runner.invoke(cli, ["serve", *args], env=env or {})
    return result, uvicorn_run


# ---------------------------------------------------------------------------
# serve — TLS / mTLS guards
#
# The rule these share: a TLS option that cannot be honoured must stop the
# server, never downgrade it. An operator who typed a security flag and got a
# running process will believe the flag took effect.
# ---------------------------------------------------------------------------

SPIFFE = {"CALM_FORGE_COHERENCE_AUTH": "spiffe"}
MTLS = ["--ssl-certfile", "c.pem", "--ssl-keyfile", "k.pem", "--ssl-ca-certs", "ca.pem"]


def test_spiffe_without_any_tls_is_refused(runner):
    result, uvicorn_run = _serve(runner, [], env=SPIFFE)

    assert result.exit_code == 1
    assert not uvicorn_run.called, "cleartext federation must never start"
    assert "requires mTLS" in result.output


def test_spiffe_with_server_tls_but_no_client_verification_is_refused(runner):
    """One-way TLS is not enough: SPIFFE authenticates the *caller*."""
    result, uvicorn_run = _serve(
        runner, ["--ssl-certfile", "c.pem", "--ssl-keyfile", "k.pem"], env=SPIFFE
    )

    assert result.exit_code == 1
    assert not uvicorn_run.called
    assert "requires mTLS" in result.output


def test_spiffe_with_full_mtls_starts_and_demands_client_certs(runner):
    import ssl as _ssl

    result, uvicorn_run = _serve(runner, MTLS, env=SPIFFE)

    assert result.exit_code == 0
    kwargs = uvicorn_run.call_args.kwargs
    assert kwargs["ssl_ca_certs"] == "ca.pem"
    assert kwargs["ssl_cert_reqs"] == _ssl.CERT_REQUIRED
    assert "https://" in result.output
    assert "SPIFFE" in result.output


def test_ca_certs_without_a_server_cert_is_refused_not_ignored(runner):
    """Regression: this used to bind cleartext, silently.

    `--ssl-ca-certs` alone produced empty ssl_kwargs, so uvicorn served plain
    HTTP while the operator believed client certificates were being verified.
    Its sibling error (cert without key) failed loudly; this one said nothing.
    """
    result, uvicorn_run = _serve(runner, ["--ssl-ca-certs", "ca.pem"])

    assert result.exit_code == 1
    assert not uvicorn_run.called
    assert "--ssl-ca-certs requires" in result.output


@pytest.mark.parametrize("half", [["--ssl-certfile", "c.pem"], ["--ssl-keyfile", "k.pem"]])
def test_half_a_server_certificate_is_refused(runner, half):
    result, uvicorn_run = _serve(runner, half)

    assert result.exit_code == 1
    assert not uvicorn_run.called
    assert "must be given together" in result.output


def test_plain_http_is_allowed_when_nothing_was_asked_for(runner):
    """No TLS flags is a coherent request for local dev — it must still work."""
    result, uvicorn_run = _serve(runner, [])

    assert result.exit_code == 0
    assert uvicorn_run.called
    assert not any(k.startswith("ssl") for k in uvicorn_run.call_args.kwargs)
    assert "http://" in result.output


# ---------------------------------------------------------------------------
# serve — auth and dependency handling
# ---------------------------------------------------------------------------


def test_no_auth_starts_but_says_so_loudly(runner):
    with mock.patch("calm_forge.jwt_auth.disable_auth") as disable:
        result, uvicorn_run = _serve(runner, ["--no-auth"])

    assert result.exit_code == 0
    assert disable.called
    assert uvicorn_run.called
    assert "authentication disabled" in result.output


def test_missing_api_extras_explains_the_install(runner):
    """The failure an operator hits first should name the fix."""
    import builtins

    real_import = builtins.__import__

    def no_uvicorn(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("No module named 'uvicorn'")
        return real_import(name, *args, **kwargs)

    with mock.patch.object(builtins, "__import__", side_effect=no_uvicorn):
        result = runner.invoke(cli, ["serve"])

    assert result.exit_code == 1
    assert "calm-forge[api]" in result.output


def test_opa_absence_is_a_warning_not_a_failure(runner):
    """OPA is an enhancement to serving, not a precondition for it."""
    result, uvicorn_run = _serve(runner, [])

    assert result.exit_code == 0
    assert uvicorn_run.called
    assert "OPA CLI not found" in result.output


def test_local_opa_bundle_starts_a_watcher(runner):
    with mock.patch("uvicorn.run"), mock.patch(
        "calm_forge.opa_gate.is_opa_available", return_value=True
    ), mock.patch("calm_forge.opa_gate.set_bundle"), mock.patch(
        "calm_forge.opa_gate.start_bundle_watcher"
    ) as watcher:
        result = runner.invoke(cli, ["serve", "--opa-bundle", "policies/"])

    assert result.exit_code == 0
    assert watcher.called
    assert "Bundle watcher started" in result.output


@pytest.mark.parametrize("remote", ["https://example.test/bundle.tar.gz", "oci://reg.test/b:v1"])
def test_remote_opa_bundle_does_not_start_a_filesystem_watcher(runner, remote):
    """You cannot inotify a URL — watching one would be a no-op that looks live."""
    with mock.patch("uvicorn.run"), mock.patch(
        "calm_forge.opa_gate.is_opa_available", return_value=True
    ), mock.patch("calm_forge.opa_gate.set_bundle"), mock.patch(
        "calm_forge.opa_gate.start_bundle_watcher"
    ) as watcher:
        result = runner.invoke(cli, ["serve", "--opa-bundle", remote])

    assert result.exit_code == 0
    assert not watcher.called


# ---------------------------------------------------------------------------
# kg export / import / federate
#
# The KG-inspection unit tests (test_kg_inspect.py) cover status/query. What
# they don't cover is the bundle roundtrip and federation membership — the
# operational verbs for moving a graph between machines.
# ---------------------------------------------------------------------------

_ACM = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read"]},
    ]
}
_AAP = {
    "jobs": [
        {"id": "j1", "workload_name": "payments", "target_cluster": "prod-east",
         "namespace": "payments", "region": "us-east-1",
         "finished": "2026-05-01T00:00:00Z", "observed_capabilities": ["http_read"]},
    ]
}
_TFE = {
    "workspaces": [
        {"name": "payments-prod", "terraform_version": "1.7.4", "tags": ["pci"],
         "vcs_repo": {}, "working_directory": "", "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-04-01T00:00:00Z", "variables": [], "resources": []},
    ]
}


def _build_kg(path):
    """A small but fully-populated KG directory (env + placement + workload)."""
    from calm_forge.intake import (
        intake_acm,
        intake_ansible,
        intake_tfe,
        write_environment_nodes,
        write_placement_nodes,
        write_workload_nodes,
    )

    env_nodes = intake_acm(_ACM)
    write_environment_nodes(env_nodes, path)
    write_placement_nodes(intake_ansible(_AAP, env_nodes), path)
    write_workload_nodes(intake_tfe(_TFE), path)
    return path


def test_export_import_roundtrip(runner, tmp_path):
    kg = _build_kg(tmp_path / "kg")
    bundle = tmp_path / "bundle.zip"

    exported = runner.invoke(cli, ["kg", "export", str(kg), "--output", str(bundle)])
    assert exported.exit_code == 0
    assert bundle.exists()
    assert "Exported" in exported.output

    imported = runner.invoke(cli, ["kg", "import", str(bundle), str(tmp_path / "restored")])
    assert imported.exit_code == 0
    assert "Imported" in imported.output


def test_import_into_nonempty_dir_is_refused_without_overwrite(runner, tmp_path):
    """A bundle must never clobber an existing graph unless the operator says so."""
    kg = _build_kg(tmp_path / "kg")
    bundle = tmp_path / "bundle.zip"
    runner.invoke(cli, ["kg", "export", str(kg), "--output", str(bundle)])
    target = tmp_path / "restored"
    runner.invoke(cli, ["kg", "import", str(bundle), str(target)])

    blocked = runner.invoke(cli, ["kg", "import", str(bundle), str(target)])
    assert blocked.exit_code == 1
    assert "not empty" in blocked.output

    allowed = runner.invoke(cli, ["kg", "import", str(bundle), str(target), "--overwrite"])
    assert allowed.exit_code == 0


def test_federate_add_list_remove_lifecycle(runner, tmp_path):
    kg = _build_kg(tmp_path / "kg")
    member = _build_kg(tmp_path / "member")

    empty = runner.invoke(cli, ["kg", "federate", "--kg-dir", str(kg), "--list"])
    assert empty.exit_code == 0
    assert "No federation members" in empty.output

    added = runner.invoke(cli, ["kg", "federate", "--kg-dir", str(kg), "--add", str(member)])
    assert added.exit_code == 0
    assert "Added" in added.output

    listed = runner.invoke(cli, ["kg", "federate", "--kg-dir", str(kg), "--list"])
    assert str(member) in listed.output

    removed = runner.invoke(cli, ["kg", "federate", "--kg-dir", str(kg), "--remove", str(member)])
    assert removed.exit_code == 0
    assert "Removed" in removed.output


def test_federate_add_nonexistent_root_is_refused(runner, tmp_path):
    kg = _build_kg(tmp_path / "kg")
    result = runner.invoke(
        cli, ["kg", "federate", "--kg-dir", str(kg), "--add", str(tmp_path / "ghost")]
    )
    assert result.exit_code != 0
    assert "does not exist" in result.output


def test_federate_remove_absent_member_is_a_noop_not_an_error(runner, tmp_path):
    kg = _build_kg(tmp_path / "kg")
    member = _build_kg(tmp_path / "member")
    result = runner.invoke(cli, ["kg", "federate", "--kg-dir", str(kg), "--remove", str(member)])
    assert result.exit_code == 0
    assert "was not in the federation" in result.output


def test_federate_with_no_action_flag_explains_itself(runner, tmp_path):
    kg = _build_kg(tmp_path / "kg")
    result = runner.invoke(cli, ["kg", "federate", "--kg-dir", str(kg)])
    assert result.exit_code != 0
    assert "Specify --add, --remove, or --list" in result.output


def test_status_json_reports_node_counts(runner, tmp_path):
    import json

    kg = _build_kg(tmp_path / "kg")
    result = runner.invoke(cli, ["kg", "status", "--kg-dir", str(kg), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["environments"]["count"] == 1
    assert data["placements"]["count"] == 1
    assert data["workloads"]["count"] == 1


# ---------------------------------------------------------------------------
# intake-acm → intake-ansible → drift
#
# The whole point of the drift loop is that it exits non-zero when the fabric
# has moved off declared intent. That exit code is what a CI gate keys on, so
# it is the single most important thing to pin about this command.
# ---------------------------------------------------------------------------


def _populate_kg_via_cli(runner, tmp_path):
    """Build a KG the way an operator does — through the intake CLIs, not helpers.

    Returns the kg directory. One cluster in us-east-1, one placement of
    `payments` onto it.
    """
    import json

    acm = tmp_path / "acm.json"
    acm.write_text(json.dumps(_ACM))
    aap = tmp_path / "aap.json"
    aap.write_text(json.dumps(_AAP))
    kg = tmp_path / "kg"

    r1 = runner.invoke(cli, ["intake-acm", "--fixture", str(acm), "--output-dir", str(kg)])
    assert r1.exit_code == 0, r1.output
    r2 = runner.invoke(
        cli,
        ["intake-ansible", "--fixture", str(aap),
         "--env-dir", str(kg / "environments"), "--output-dir", str(kg)],
    )
    assert r2.exit_code == 0, r2.output
    return kg


def _workload(tmp_path, name, zones):
    import json

    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps({"metadata": {"name": "payments", "data-residency": zones}}))
    return path


def test_drift_ok_when_placement_matches_declared_zone(runner, tmp_path):
    kg = _populate_kg_via_cli(runner, tmp_path)
    wl = _workload(tmp_path, "ok", ["us-east-1"])

    result = runner.invoke(cli, ["drift", "--workload", str(wl), "--kg-dir", str(kg), "--no-writeback"])

    assert result.exit_code == 0
    assert "DRIFT: OK" in result.output


def test_drift_exits_nonzero_when_placed_outside_declared_zone(runner, tmp_path):
    """The load-bearing assertion: a placement outside declared intent fails CI."""
    kg = _populate_kg_via_cli(runner, tmp_path)
    wl = _workload(tmp_path, "bad", ["eu-west-1"])

    result = runner.invoke(cli, ["drift", "--workload", str(wl), "--kg-dir", str(kg), "--no-writeback"])

    assert result.exit_code == 1
    assert "VIOLATION" in result.output
    assert "not in declared zones" in result.output


def test_drift_with_no_placements_advises_intake_first(runner, tmp_path):
    empty_kg = tmp_path / "empty"
    empty_kg.mkdir()
    wl = _workload(tmp_path, "ok", ["us-east-1"])

    result = runner.invoke(cli, ["drift", "--workload", str(wl), "--kg-dir", str(empty_kg), "--no-writeback"])

    assert result.exit_code == 0
    assert "No placement nodes found" in result.output


def test_drift_event_file_is_written_when_requested(runner, tmp_path):
    kg = _populate_kg_via_cli(runner, tmp_path)
    wl = _workload(tmp_path, "ok", ["us-east-1"])
    events = tmp_path / "events.json"

    result = runner.invoke(
        cli,
        ["drift", "--workload", str(wl), "--kg-dir", str(kg),
         "--no-writeback", "--event-file", str(events)],
    )

    assert result.exit_code == 0
    assert events.exists()
    assert "Event appended" in result.output


# ---------------------------------------------------------------------------
# generate / validate — error paths
#
# These are the messages a user sees when their input is malformed. A wrong
# exit code here means a broken spec sails through a pipeline; a vague message
# means they can't tell what to fix.
# ---------------------------------------------------------------------------


def _write(path, text):
    path.write_text(text)
    return path


def test_generate_rejects_malformed_json(runner, tmp_path):
    bad = _write(tmp_path / "bad.json", "{not json")
    empty = _write(tmp_path / "empty.json", "{}")
    result = runner.invoke(
        cli,
        ["generate", "--calm", str(bad), "--decorator", str(empty),
         "--catalog", str(empty), "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 1
    assert "Invalid JSON" in result.output


def test_generate_rejects_structurally_empty_decorator(runner, tmp_path):
    """An empty `{}` is valid JSON but not a usable decorator — say which key."""
    empty = _write(tmp_path / "empty.json", "{}")
    result = runner.invoke(
        cli,
        ["generate", "--calm", str(empty), "--decorator", str(empty),
         "--catalog", str(empty), "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "data" in result.output


def test_validate_rejects_malformed_json(runner, tmp_path):
    bad = _write(tmp_path / "bad.json", "{not json")
    result = runner.invoke(cli, ["validate", "--calm", str(bad)])
    assert result.exit_code == 1
    assert "Invalid JSON" in result.output


def test_validate_names_every_missing_section(runner, tmp_path):
    """A structurally-empty spec should list all gaps at once, not one at a time."""
    empty = _write(tmp_path / "empty.json", "{}")
    result = runner.invoke(cli, ["validate", "--calm", str(empty)])
    assert result.exit_code == 1
    assert "nodes" in result.output
    assert "relationships" in result.output
    assert "metadata" in result.output


def test_interview_from_spec_emits_a_workload_node(runner, tmp_path):
    import json

    spec = _write(tmp_path / "spec.json", json.dumps({"workload": {"name": "payments"}}))
    result = runner.invoke(
        cli, ["interview", "--spec", str(spec), "--output-dir", str(tmp_path / "kg"), "--json"]
    )
    assert result.exit_code == 0
    node = json.loads(result.output)
    assert node["@type"] == "Workload"
    assert node["@id"].startswith("workload:")
