"""CLI tests for the passport group + generate --passport (APP-012)."""
from __future__ import annotations

import glob
import json
from pathlib import Path

from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.passport import verify_passport as verify_passport_dict

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "fsi-3tier"
_KG = Path(__file__).resolve().parents[1] / "src" / "calm_forge" / "knowledge_graph" / "3-tier-pci.json"


def _passports_in(directory: str) -> list[dict]:
    return [json.loads(Path(f).read_text()) for f in glob.glob(f"{directory}/**/*.passport.json", recursive=True)]


def test_emit_from_kg_and_verify(tmp_path):
    runner = CliRunner()
    out = tmp_path / "kg"
    key = tmp_path / "issuer.pem"
    res = runner.invoke(cli, [
        "passport", "emit", "--kg", str(_KG),
        "--trust-domain", "prod.fsi", "--output-dir", str(out), "--key", str(key),
    ])
    assert res.exit_code == 0, res.output
    passports = _passports_in(str(out))
    assert len(passports) == 2
    assert key.exists()  # key generated + saved

    # every emitted passport verifies through the CLI
    for f in glob.glob(f"{out}/*.passport.json"):
        v = runner.invoke(cli, ["passport", "verify", f])
        assert v.exit_code == 0, v.output
        assert "VERIFIED" in v.output


def test_emit_from_calm_lifts_metadata(tmp_path):
    runner = CliRunner()
    out = tmp_path / "calm"
    res = runner.invoke(cli, [
        "passport", "emit", "--calm", str(_EXAMPLES / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(out), "--key", str(tmp_path / "k.pem"),
    ])
    assert res.exit_code == 0, res.output
    passports = _passports_in(str(out))
    assert passports
    assert all(p["graph_ref"]["edge_id"].startswith("kg://edges/v1/") for p in passports)


def test_emit_requires_exactly_one_source(tmp_path):
    runner = CliRunner()
    # neither
    r1 = runner.invoke(cli, ["passport", "emit", "--output-dir", str(tmp_path / "a")])
    assert r1.exit_code != 0
    # both
    r2 = runner.invoke(cli, [
        "passport", "emit", "--kg", str(_KG), "--calm", str(_EXAMPLES / "instantiation.json"),
        "--output-dir", str(tmp_path / "b"),
    ])
    assert r2.exit_code != 0


def test_verify_rejects_tampered(tmp_path):
    runner = CliRunner()
    out = tmp_path / "kg"
    runner.invoke(cli, [
        "passport", "emit", "--kg", str(_KG),
        "--trust-domain", "prod.fsi", "--output-dir", str(out), "--key", str(tmp_path / "k.pem"),
    ])
    target = glob.glob(f"{out}/*.passport.json")[0]
    doc = json.loads(Path(target).read_text())
    doc["network_binding"]["port_unspecified"] = False
    doc["network_binding"]["port"] = 22  # tamper the signed body
    Path(target).write_text(json.dumps(doc))
    v = runner.invoke(cli, ["passport", "verify", target])
    assert v.exit_code == 1
    assert "INVALID" in v.output


def test_generate_with_passport_emits_hcl_and_passports(tmp_path):
    runner = CliRunner()
    out = tmp_path / "gen"
    res = runner.invoke(cli, [
        "generate",
        "--calm", str(_EXAMPLES / "instantiation.json"),
        "--decorator", str(_EXAMPLES / "decorator.json"),
        "--catalog", str(_EXAMPLES / "catalog.json"),
        "--output-dir", str(out), "--passport",
        "--trust-domain", "prod.fsi", "--key", str(tmp_path / "k.pem"),
    ])
    assert res.exit_code == 0, res.output
    assert (out / "components.tfstack.hcl").exists()          # existing emit intact
    assert _passports_in(str(out))                            # passports alongside
    assert "signed passport" in res.output


def test_passport_diff_reports_shadow_and_contraction(tmp_path):
    runner = CliRunner()
    passports = tmp_path / "passports"
    runner.invoke(cli, [
        "passport", "emit", "--calm", str(_EXAMPLES / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(passports), "--key", str(tmp_path / "k.pem"),
    ])
    # one flow matches a claim (conformant), one is undeclared (shadow); one claim unobserved (contraction)
    doc = [json.loads(Path(f).read_text()) for f in glob.glob(f"{passports}/*.passport.json")]
    conformant = doc[0]["network_binding"]
    flows = tmp_path / "flows.json"
    flows.write_text(json.dumps([
        {"source": conformant["source_workload_urn"], "destination": conformant["destination_workload_urn"],
         "transport": conformant["transport"], "port": conformant["port"]},
        {"source": "wl:payments-portal/analytics", "destination": "wl:payments-portal/database",
         "transport": "tcp", "port": 5432},
    ]))
    res = runner.invoke(cli, [
        "passport", "diff", "--flows", str(flows), "--passports", str(passports), "--now", "1800000000",
    ])
    assert res.exit_code == 1  # findings present → CI-gating exit
    assert "SHADOW" in res.output
    assert "CONTRACTION" in res.output


def test_passport_diff_json_and_clean_exit(tmp_path):
    runner = CliRunner()
    passports = tmp_path / "passports"
    runner.invoke(cli, [
        "passport", "emit", "--calm", str(_EXAMPLES / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(passports), "--key", str(tmp_path / "k.pem"),
    ])
    # observe exactly the declared edges → conformant, clean exit
    doc = [json.loads(Path(f).read_text()) for f in glob.glob(f"{passports}/*.passport.json")]
    flows = tmp_path / "flows.json"
    flows.write_text(json.dumps([
        {"source": p["network_binding"]["source_workload_urn"],
         "destination": p["network_binding"]["destination_workload_urn"],
         "transport": p["network_binding"]["transport"], "port": p["network_binding"]["port"]}
        for p in doc
    ]))
    res = runner.invoke(cli, [
        "passport", "diff", "--flows", str(flows), "--passports", str(passports),
        "--now", "1800000000", "--json",
    ])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["shadow"] == [] and payload["contraction"] == []
    assert len(payload["conformant"]) == len(doc)


def test_revoke_from_diff_closes_the_loop(tmp_path):
    """Contraction candidate → signed tombstone → re-diff shows it resolved."""
    runner = CliRunner()
    passports = tmp_path / "passports"
    runner.invoke(cli, [
        "passport", "emit", "--calm", str(_EXAMPLES / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(passports), "--key", str(tmp_path / "k.pem"),
    ])
    # observe only the first declared edge → the other becomes a contraction candidate
    doc = [json.loads(Path(f).read_text()) for f in sorted(glob.glob(f"{passports}/*.passport.json"))]
    nb = doc[0]["network_binding"]
    flows = tmp_path / "flows.json"
    flows.write_text(json.dumps([{
        "source": nb["source_workload_urn"], "destination": nb["destination_workload_urn"],
        "transport": nb["transport"], "port": nb["port"],
    }]))

    before = runner.invoke(cli, ["passport", "diff", "--flows", str(flows),
                                 "--passports", str(passports), "--now", "1800000000"])
    assert before.exit_code == 1
    assert "CONTRACTION" in before.output

    rev = runner.invoke(cli, ["passport", "revoke", "--passports", str(passports),
                              "--from-diff", str(flows), "--key", str(tmp_path / "k.pem"),
                              "--now", "1800000000"])
    assert rev.exit_code == 0, rev.output
    assert "tombstone" in rev.output
    tombstones = glob.glob(f"{passports}/*.revoke.passport.json")
    assert len(tombstones) == 1
    ts = json.loads(Path(tombstones[0]).read_text())
    assert ts["claim"]["tense"] == "will-be"
    assert ts["claim"]["authority_class"] == "autonomic-contraction"

    after = runner.invoke(cli, ["passport", "diff", "--flows", str(flows),
                                "--passports", str(passports), "--now", "1800000000"])
    assert after.exit_code == 0, after.output  # loop closed


def test_revoke_requires_exactly_one_selector(tmp_path):
    runner = CliRunner()
    passports = tmp_path / "p"
    passports.mkdir()
    r = runner.invoke(cli, ["passport", "revoke", "--passports", str(passports)])
    assert r.exit_code != 0


def test_renew_extends_a_lapsing_grant_in_place(tmp_path):
    """Emit a short-lived grant, renew it, and confirm the window moved out while
    the edge_id (and so the passport's identity) held."""
    runner = CliRunner()
    passports = tmp_path / "passports"
    emit = runner.invoke(cli, [
        "passport", "emit", "--calm", str(_EXAMPLES / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(passports),
        "--key", str(tmp_path / "k.pem"), "--ttl-days", "5",
    ])
    assert emit.exit_code == 0, emit.output
    before = _passports_in(str(passports))
    assert before
    by_edge = {p["graph_ref"]["edge_id"]: p["lifecycle"]["expires_at"] for p in before}

    renew = runner.invoke(cli, [
        "passport", "renew", "--passports", str(passports),
        "--key", str(tmp_path / "k.pem"), "--within-days", "30", "--ttl-days", "90",
    ])
    assert renew.exit_code == 0, renew.output
    assert "Renewed" in renew.output

    after = _passports_in(str(passports))
    for p in after:
        assert verify_passport_dict(p)
        assert p["lifecycle"]["expires_at"] > by_edge[p["graph_ref"]["edge_id"]]
    # No new edges were minted — same identities, superseded in place.
    assert {p["graph_ref"]["edge_id"] for p in after} == set(by_edge)


def test_renew_with_nothing_due_changes_nothing(tmp_path):
    runner = CliRunner()
    passports = tmp_path / "passports"
    runner.invoke(cli, [
        "passport", "emit", "--calm", str(_EXAMPLES / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(passports),
        "--key", str(tmp_path / "k.pem"), "--ttl-days", "365",
    ])
    before = {p["passport_id"] for p in _passports_in(str(passports))}

    renew = runner.invoke(cli, [
        "passport", "renew", "--passports", str(passports),
        "--key", str(tmp_path / "k.pem"), "--within-days", "30",
    ])
    assert renew.exit_code == 0
    assert "nothing to renew" in renew.output
    # Untouched: same passport_ids, none re-issued.
    assert {p["passport_id"] for p in _passports_in(str(passports))} == before


def test_generate_passport_and_fortinet_share_edge_id(tmp_path):
    runner = CliRunner()
    out = tmp_path / "gen"
    res = runner.invoke(cli, [
        "generate",
        "--calm", str(_EXAMPLES / "instantiation.json"),
        "--decorator", str(_EXAMPLES / "decorator.json"),
        "--catalog", str(_EXAMPLES / "catalog.json"),
        "--output-dir", str(out), "--passport", "--fortinet", "--validate",
        "--trust-domain", "prod.fsi", "--key", str(tmp_path / "k.pem"),
    ])
    assert res.exit_code == 0, res.output
    assert (out / "fortinet" / "fortinet.tf").exists()
    assert (out / "fortinet" / "candidate.conf").exists()
    assert "HCL validation passed" in res.output  # fortinet.tf validated too

    # every passport's edge_id appears in both Fortinet artifacts (APP-021)
    conf = (out / "fortinet" / "candidate.conf").read_text()
    hcl = (out / "fortinet" / "fortinet.tf").read_text()
    passports = _passports_in(str(out))
    assert passports
    for p in passports:
        eid = p["graph_ref"]["edge_id"]
        assert eid in conf and eid in hcl
