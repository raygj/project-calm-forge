"""End-to-end passport integration sweep + reverse-diff golden corpus.

APP-060 — drive the full path as a user would, across *every* example that has a
CALM instantiation: generate --passport --fortinet --validate → schema-validate and
signature-verify every emitted passport → prove edge_id parity across all three
artifacts → reverse-diff → revoke → re-diff.

APP-063 — the diff report is byte-compared against a checked-in golden. The report
carries no uuids or timestamps, so it is deterministic; regenerate with
UPDATE_PASSPORT_GOLDEN=1 pytest tests/test_passport_integration.py -k golden
"""

from __future__ import annotations

import glob
import json
import os
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.edge_id import edge_id_for_binding
from calm_forge.passport import (
    build_network_binding,
    edges_from_calm_architecture,
    validate_passport,
    verify_passport,
)
from calm_forge.passport_diff import diff

ROOT = Path(__file__).parent.parent
EXAMPLES_DIR = ROOT / "examples"
APP_DIR = EXAMPLES_DIR / "attested-policy-passport"
FLOWS = APP_DIR / "observed-flows.json"
GOLDEN_DIR = APP_DIR / "expected-output"

# Every example carrying a CALM instantiation — the passport path must hold for all
# of them, not just the two the crawl build was developed against.
ALL_CALM_EXAMPLES = [
    "fsi-3tier",
    "fsi-event-driven",
    "fsi-microservices-mesh",
    "fsi-mongodb-multiregion",
    "fraud-detection-workload-portability",
    "pci-multiregion",
]


def _passports_in(directory) -> list[dict]:
    return [
        json.loads(Path(f).read_text())
        for f in sorted(glob.glob(f"{directory}/**/*.passport.json", recursive=True))
    ]


def _flows_from(passports) -> list[dict]:
    """Synthesize observed flows that exactly match the declared edges."""
    flows = []
    for p in passports:
        nb = p["network_binding"]
        if nb.get("port_unspecified"):
            continue
        flows.append({
            "source": nb["source_workload_urn"],
            "destination": nb["destination_workload_urn"],
            "transport": nb["transport"],
            "port": nb["port"],
        })
    return flows


# ---------------------------------------------------------------------------
# APP-060 — full path, every example
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("example", ALL_CALM_EXAMPLES)
def test_generate_passport_and_fortinet_for_every_example(example, tmp_path):
    """intent → HCL + signed passports + Fortinet (both forms), all validating."""
    ex = EXAMPLES_DIR / example
    out = tmp_path / example
    res = CliRunner().invoke(cli, [
        "generate",
        "--calm", str(ex / "instantiation.json"),
        "--decorator", str(ex / "decorator.json"),
        "--catalog", str(ex / "catalog.json"),
        "--output-dir", str(out),
        "--passport", "--fortinet", "--validate",
        "--trust-domain", "prod.fsi", "--key", str(out / "keys" / "issuer.pem"),
    ])
    assert res.exit_code == 0, res.output

    passports = _passports_in(out)
    assert passports, f"{example} produced no passports"

    for p in passports:
        validate_passport(p)                 # raises on schema violation
        assert verify_passport(p) is True    # signature holds over the JCS body
        assert p["graph_ref"]["edge_id"].startswith("kg://edges/v1/")

    # the edge_id is the join key — it must appear in both Fortinet artifacts
    conf = (out / "fortinet" / "candidate.conf").read_text()
    hcl = (out / "fortinet" / "fortinet.tf").read_text()
    for p in passports:
        eid = p["graph_ref"]["edge_id"]
        assert eid in conf, f"{example}: {eid} missing from candidate.conf"
        assert eid in hcl, f"{example}: {eid} missing from fortinet.tf"


@pytest.mark.parametrize("example", ALL_CALM_EXAMPLES)
def test_reverse_loop_closes_for_every_example(example, tmp_path):
    """Declared edges observed → conformant; unobserved → revoked → clean."""
    runner = CliRunner()
    ex = EXAMPLES_DIR / example
    passports_dir = tmp_path / "passports"
    key = tmp_path / "keys" / "issuer.pem"
    now = str(int(time.time()))

    emit = runner.invoke(cli, [
        "passport", "emit", "--calm", str(ex / "instantiation.json"),
        "--trust-domain", "prod.fsi",
        "--output-dir", str(passports_dir), "--key", str(key),
    ])
    assert emit.exit_code == 0, emit.output
    declared = _passports_in(passports_dir)
    assert declared

    # A claim whose port could not be resolved is an underspecified declaration, not a
    # grant of every port. It must never be judged — in either direction (APP-092).
    underspecified = {
        p["graph_ref"]["edge_id"]
        for p in declared
        if p["network_binding"].get("port_unspecified")
    }

    # observe every declared edge that *can* be observed
    flows = tmp_path / "flows.json"
    flows.write_text(json.dumps(_flows_from(declared)))
    clean = runner.invoke(cli, [
        "passport", "diff", "--flows", str(flows),
        "--passports", str(passports_dir), "--now", now, "--json",
    ])
    payload = json.loads(clean.output)
    assert payload["shadow"] == [], f"{example}: declared traffic read as shadow"
    assert payload["contraction"] == [], f"{example}: conformant traffic read as contraction"
    assert {e["edge_id"] for e in payload["unadjudicable"]} == underspecified
    # a declaration gap is not a security finding — it must not fail the run
    assert clean.exit_code == 0

    # observe nothing → every claim becomes a contraction candidate...
    flows.write_text(json.dumps([]))
    stale = runner.invoke(cli, [
        "passport", "diff", "--flows", str(flows),
        "--passports", str(passports_dir), "--now", now,
    ])
    assert stale.exit_code == 1
    assert "CONTRACTION" in stale.output

    # ...which a signed tombstone resolves, autonomically
    rev = runner.invoke(cli, [
        "passport", "revoke", "--passports", str(passports_dir),
        "--from-diff", str(flows), "--key", str(key), "--now", now,
    ])
    assert rev.exit_code == 0, rev.output
    for ts in glob.glob(f"{passports_dir}/*.revoke.passport.json"):
        doc = json.loads(Path(ts).read_text())
        assert doc["claim"]["authority_class"] == "autonomic-contraction"
        assert verify_passport(doc) is True

    closed = runner.invoke(cli, [
        "passport", "diff", "--flows", str(flows),
        "--passports", str(passports_dir), "--now", now,
    ])
    assert closed.exit_code == 0, closed.output


def test_underspecified_claim_never_produces_a_false_finding(tmp_path):
    """The APP-092 regression guard.

    An unresolved-port claim used to hash to ``port=any``, which no concrete flow can
    equal. Matching by edge_id alone therefore fired *twice* on one edge: the traffic
    looked unclaimed (SHADOW) and the claim looked unobserved (CONTRACTION) — both
    false, and the shadow was the dangerous one, since SHADOW is the bucket that wakes
    a human for governed expansion. Real traffic on an underspecified path is now a
    reported gap carrying the port we observed, and nothing else.
    """
    runner = CliRunner()
    key = tmp_path / "k.pem"
    passports_dir = tmp_path / "passports"
    ex = EXAMPLES_DIR / "fraud-detection-workload-portability"
    now = "1771770600"

    emit = runner.invoke(cli, [
        "passport", "emit", "--calm", str(ex / "instantiation.json"),
        "--trust-domain", "prod.fsi",
        "--output-dir", str(passports_dir), "--key", str(key),
    ])
    assert emit.exit_code == 0, emit.output
    declared = _passports_in(passports_dir)
    gaps = [p for p in declared if p["network_binding"].get("port_unspecified")]
    assert gaps, "fixture must contain an underspecified edge for this to mean anything"

    # traffic *does* flow on the underspecified path, on a port nobody declared
    nb = gaps[0]["network_binding"]
    flows = tmp_path / "flows.json"
    flows.write_text(json.dumps([{
        "source": nb["source_workload_urn"],
        "destination": nb["destination_workload_urn"],
        "transport": nb["transport"],
        "port": 7777,
    }]))

    res = runner.invoke(cli, [
        "passport", "diff", "--flows", str(flows),
        "--passports", str(passports_dir), "--now", now, "--json",
    ])
    payload = json.loads(res.output)

    eid = gaps[0]["graph_ref"]["edge_id"]
    assert eid not in {e["edge_id"] for e in payload["shadow"]}
    assert eid not in {e["edge_id"] for e in payload["contraction"]}

    finding = next(e for e in payload["unadjudicable"] if e["edge_id"] == eid)
    # the finding carries its own remediation: the port the intent should declare
    assert finding["observed_port"] == 7777
    assert finding["port_source"] == "unresolved"


def test_authored_wildcard_is_permission_not_a_gap():
    """`port_wildcard` and `port_unspecified` share an edge_id but not a meaning.

    Both hash to ``port=any`` — they describe the same L4 tuple, so they must. An
    authored wildcard is a real grant, so traffic under it is conformant and flagged
    for narrowing; an unresolved port grants nothing and is reported as a gap.
    """
    def claim(**port_fields):
        nb = {
            "source_workload_urn": "wl:app/a", "destination_workload_urn": "wl:app/b",
            "transport": "tcp", **port_fields,
        }
        return {
            "passport_version": "0.1",
            "graph_ref": {"edge_id": edge_id_for_binding(nb)},
            "claim": {"claim_type": "grant"},
            "lifecycle": {"issued_at": 0, "expires_at": 9999999999},
            "network_binding": nb,
        }

    wildcard = claim(port_wildcard=True, port_source="wildcard")
    unresolved = claim(port_unspecified=True, port_source="unresolved")
    assert wildcard["graph_ref"]["edge_id"] == unresolved["graph_ref"]["edge_id"]

    flow = {"source": "wl:app/a", "destination": "wl:app/b", "transport": "tcp", "port": 9092}

    granted = diff([wildcard], [flow], now=1000)
    assert len(granted.conformant) == 1
    assert "narrowing candidate" in granted.conformant[0].detail
    assert granted.conformant[0].observed_port == 9092
    assert not granted.has_findings and not granted.has_gaps

    ignorant = diff([unresolved], [flow], now=1000)
    assert not ignorant.conformant and not ignorant.has_findings
    assert ignorant.has_gaps


# ---------------------------------------------------------------------------
# APP-063 — byte-for-byte golden corpus
# ---------------------------------------------------------------------------


def _diff_json(runner, passports_dir, now) -> str:
    res = runner.invoke(cli, [
        "passport", "diff", "--flows", str(FLOWS),
        "--passports", str(passports_dir), "--now", now, "--json",
    ])
    assert res.exit_code in (0, 1), res.output
    return res.output


def _assert_golden(name: str, actual: str) -> None:
    path = GOLDEN_DIR / name
    if os.environ.get("UPDATE_PASSPORT_GOLDEN"):
        path.write_text(actual)
        return
    assert actual == path.read_text(), (
        f"{name} drifted from the golden. Re-run with UPDATE_PASSPORT_GOLDEN=1 "
        f"only if the change is intended."
    )


def test_reverse_diff_matches_golden_corpus(tmp_path):
    """The demo corpus produces exactly the checked-in verdicts, before and after."""
    runner = CliRunner()
    passports_dir = tmp_path / "passports"
    key = tmp_path / "keys" / "issuer.pem"
    now = str(int(time.time()))  # grants are live; verdicts turn on expiry, not wall clock

    runner.invoke(cli, [
        "passport", "emit", "--calm", str(EXAMPLES_DIR / "fsi-3tier" / "instantiation.json"),
        "--trust-domain", "prod.fsi",
        "--output-dir", str(passports_dir), "--key", str(key),
    ])

    _assert_golden("diff-before-revoke.json", _diff_json(runner, passports_dir, now))

    rev = runner.invoke(cli, [
        "passport", "revoke", "--passports", str(passports_dir),
        "--from-diff", str(FLOWS), "--key", str(key), "--now", now, "--grace-days", "30",
    ])
    assert rev.exit_code == 0, rev.output

    _assert_golden("diff-after-revoke.json", _diff_json(runner, passports_dir, now))


def test_reference_passport_is_real_and_matches_the_demo_stack():
    """The checked-in reference passport is not a mock-up in the fake sense: it
    schema-validates, its signature verifies, and its edge_id is the *same* id the
    demo's reverse diff reports as CONFORMANT. Documentation that can go stale
    silently isn't documentation."""
    ref = json.loads((APP_DIR / "payments-portal-web-to-api.passport.json").read_text())

    validate_passport(ref)
    assert verify_passport(ref) is True

    golden = json.loads((GOLDEN_DIR / "diff-before-revoke.json").read_text())
    conformant_ids = {e["edge_id"] for e in golden["conformant"]}
    assert ref["graph_ref"]["edge_id"] in conformant_ids

    # every optional field is populated — this artifact is the field reference
    assert ref["ownership"]["application_name"] == "payments-portal"
    assert ref["intent_metadata"]["compliance_scope"]
    assert ref["graph_ref"]["authored_by"]
    assert ref["network_binding"]["app_protocol"] == ["HTTPS", "mTLS"]

    # ...and it describes the *current* binding shape. A reference that quietly
    # lags the emitter is worse than none: it documents a passport we no longer
    # issue. Compare against what the pipeline actually produces for this edge.
    live = next(
        e for e in edges_from_calm_architecture(
            json.loads((EXAMPLES_DIR / "fsi-3tier" / "instantiation.json").read_text()),
            trust_domain="prod.fsi", system="payments-portal",
        )
        if e["destination_workload"] == "api-service"
    )
    binding = build_network_binding(live)
    assert set(binding) <= set(ref["network_binding"]), (
        "reference passport is missing fields the emitter now produces — regenerate it"
    )
    assert ref["network_binding"]["port_source"] == binding["port_source"]


def test_reference_passport_covers_the_contraction_edge():
    """The reference pair covers both live verdicts, not just the happy one. This
    passport is the *granted but unobserved* edge — the claim the autonomic loop
    contracts. A corpus that only ships the conformant case documents half the loop."""
    ref = json.loads((APP_DIR / "payments-portal-api-to-db.passport.json").read_text())

    validate_passport(ref)
    assert verify_passport(ref) is True

    golden = json.loads((GOLDEN_DIR / "diff-before-revoke.json").read_text())
    contraction_ids = {e["edge_id"] for e in golden["contraction"]}
    assert ref["graph_ref"]["edge_id"] in contraction_ids

    live = next(
        e for e in edges_from_calm_architecture(
            json.loads((EXAMPLES_DIR / "fsi-3tier" / "instantiation.json").read_text()),
            trust_domain="prod.fsi", system="payments-portal",
        )
        if e["destination_workload"] == "database"
    )
    binding = build_network_binding(live)
    assert set(binding) <= set(ref["network_binding"]), (
        "reference passport is missing fields the emitter now produces — regenerate it"
    )
    assert ref["network_binding"]["port_source"] == binding["port_source"]
    # enrichment is descriptive only: it must never move the edge id
    assert ref["graph_ref"]["edge_id"] == edge_id_for_binding(binding)


def test_golden_encodes_the_safety_model():
    """The two goldens are the authority split, checked in: contraction resolves
    autonomically, the shadow does not — granting it needs a human at the PAP."""
    before = json.loads((GOLDEN_DIR / "diff-before-revoke.json").read_text())
    after = json.loads((GOLDEN_DIR / "diff-after-revoke.json").read_text())

    assert before["contraction"] and not after["contraction"]
    assert before["shadow"] == after["shadow"] != []
