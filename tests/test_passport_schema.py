"""Contract tests for the Attested Policy Passport (APP-001).

Locks the committed schema + signed example as a self-consistent contract:
the example validates against the schema, its edge_id recomputes from the
network binding, and its Ed25519 signature verifies over the JCS-canonicalized
body. These tests are deliberately import-free (they load the shipped JSON
artifacts by path) so they independently verify what edge_id.py / the passport
builder must reproduce.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "src" / "calm_forge" / "schemas"
_SCHEMA = json.loads((_SCHEMA_DIR / "passport.schema.json").read_text())
_EXAMPLE = json.loads((_SCHEMA_DIR / "example.passport.json").read_text())


# ---------------------------------------------------------------------------
# Helpers — kept independent of calm_forge.edge_id on purpose (APP-000 §5).
# ---------------------------------------------------------------------------

def _jcs(obj: dict) -> bytes:
    """RFC 8785 subset used by the passport: sorted keys, compact separators.

    Valid for the passport body, whose values are only str / int / float / bool.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _port_token(binding: dict) -> str:
    if binding.get("port_unspecified"):
        return "any"
    rng = binding.get("port_range")
    if rng is not None:
        lo, hi = int(rng["from"]), int(rng["to"])
        if lo > hi:
            lo, hi = hi, lo
        return str(lo) if lo == hi else f"{lo}-{hi}"
    return str(int(binding["port"]))


def _recompute_edge_id(binding: dict) -> str:
    canonical = (
        f"edge/v1|src={binding['source_workload_urn'].lower()}"
        f"|dst={binding['destination_workload_urn'].lower()}"
        f"|l4={binding['transport'].lower()}|port={_port_token(binding)}"
    )
    return "kg://edges/v1/" + hashlib.sha256(canonical.encode()).hexdigest()


def _body_without_proof(passport: dict) -> dict:
    return {k: v for k, v in passport.items() if k != "proof"}


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

def test_example_validates_against_schema():
    jsonschema.validate(_EXAMPLE, _SCHEMA)


def test_graph_ref_guardrail():
    """No passport is valid without a graph_ref.edge_id — the KG-sell invariant."""
    assert _EXAMPLE["graph_ref"]["edge_id"], "graph_ref.edge_id missing"
    broken = copy.deepcopy(_EXAMPLE)
    del broken["graph_ref"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(broken, _SCHEMA)


def test_edge_id_recomputes_from_binding():
    assert _recompute_edge_id(_EXAMPLE["network_binding"]) == _EXAMPLE["graph_ref"]["edge_id"]


def test_signature_verifies_over_canonical_body():
    proof = _EXAMPLE["proof"]
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(proof["public_key_b64"]))
    pub.verify(base64.b64decode(proof["signature_b64"]), _jcs(_body_without_proof(_EXAMPLE)))


def test_tampered_body_fails_signature():
    tampered = copy.deepcopy(_EXAMPLE)
    tampered["network_binding"]["port"] = 9999  # any change to the signed body
    proof = tampered["proof"]
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(proof["public_key_b64"]))
    with pytest.raises(InvalidSignature):
        pub.verify(base64.b64decode(proof["signature_b64"]), _jcs(_body_without_proof(tampered)))


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda p: p["graph_ref"].__setitem__("edge_id", "not-a-kg-uri"), id="bad-edge-id"),
        pytest.param(lambda p: p["network_binding"].__setitem__("transport", "sctp"), id="bad-transport"),
        pytest.param(lambda p: p["claim"].__setitem__("authority_class", "freeform"), id="bad-authority"),
        pytest.param(lambda p: p["network_binding"].pop("port"), id="no-port-spec"),
        pytest.param(lambda p: p.__setitem__("surprise", 1), id="additional-property"),
    ],
)
def test_schema_rejects_malformed(mutate):
    broken = copy.deepcopy(_EXAMPLE)
    mutate(broken)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(broken, _SCHEMA)


def test_port_range_and_collapse_are_consistent():
    """A degenerate range collapses to the single-port id (APP-000 §5)."""
    single = {**_EXAMPLE["network_binding"]}
    ranged = {k: v for k, v in single.items() if k != "port"}
    ranged["port_range"] = {"from": single["port"], "to": single["port"]}
    assert _recompute_edge_id(ranged) == _recompute_edge_id(single)

    spread = {k: v for k, v in single.items() if k != "port"}
    spread["port_range"] = {"from": 8080, "to": 8090}
    assert _recompute_edge_id(spread) != _recompute_edge_id(single)
