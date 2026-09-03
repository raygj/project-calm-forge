"""Structural checks on the semconv/forge registry (MP-26, ADR-014 / ADR-009 §1-2).

Weaver (`weaver registry check`) is the authoritative validator and is wired into CI as
its own pinned step (MP-51). Weaver is a Rust binary that is not present in the Python
test environment, so these tests do NOT reimplement Weaver's schema validation. They lock
the *contract* of the v0.1 registry — the exact five resource attributes, three log
events, their types, stability, and examples, and the forge.anchor.ref-not-seal.ref
decision — so the vocabulary the emitters depend on cannot drift silently between Weaver
runs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_REGISTRY_DIR = Path(__file__).resolve().parents[1] / "semconv" / "forge"
_MODEL_DIR = _REGISTRY_DIR / "model"

_EXPECTED_ATTRIBUTES = {
    "forge.passport.id": "string",
    "forge.passport.edge_digest": "string",
    "forge.passport.expires": "int",
    "forge.anchor.ref": "string",
    "forge.workload.urn": "string",
}

_EXPECTED_EVENTS = {
    "forge.passport.announced",
    "forge.passport.expiring",
    "forge.passport.superseded",
}

# The current schema value for ADR-014 §3's experimental → stable lifecycle, plus the
# terminal states a later revision may reach.
_VALID_STABILITY = {"development", "stable", "release_candidate", "deprecated"}


def _load_groups() -> list[dict]:
    groups: list[dict] = []
    for path in sorted(_MODEL_DIR.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        groups.extend(doc.get("groups", []))
    return groups


def _attributes() -> dict[str, dict]:
    attrs: dict[str, dict] = {}
    for group in _load_groups():
        if group.get("type") != "attribute_group":
            continue
        for attr in group.get("attributes", []):
            if "id" in attr:
                attrs[attr["id"]] = attr
    return attrs


def _events() -> dict[str, dict]:
    return {
        group["name"]: group
        for group in _load_groups()
        if group.get("type") == "event"
    }


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def test_registry_manifest_names_forge_at_v0_1() -> None:
    manifest = yaml.safe_load((_REGISTRY_DIR / "manifest.yaml").read_text())
    assert manifest["name"] == "forge"
    assert manifest["schema_url"].endswith("/0.1.0")
    assert "semconv_version" not in manifest
    assert "schema_base_url" not in manifest


# ---------------------------------------------------------------------------
# Resource attributes — exactly the five from ADR-009 §1
# ---------------------------------------------------------------------------


def test_exactly_the_five_resource_attributes_are_registered() -> None:
    assert set(_attributes()) == set(_EXPECTED_ATTRIBUTES)


def test_attribute_types_match_the_contract() -> None:
    attrs = _attributes()
    for name, expected_type in _EXPECTED_ATTRIBUTES.items():
        assert attrs[name]["type"] == expected_type, name


def test_every_attribute_carries_stability_brief_and_examples() -> None:
    for name, attr in _attributes().items():
        assert attr.get("stability") in _VALID_STABILITY, name
        assert attr.get("brief", "").strip(), name
        assert attr.get("examples"), name


def test_placement_cardinality_rule_is_registry_metadata_not_tribal_knowledge() -> None:
    # ADR-009 §1: resource/log records only, never metric datapoint attributes.
    attrs = _attributes()
    for name in ("forge.passport.id", "forge.passport.expires", "forge.workload.urn"):
        assert "metric" in attrs[name].get("note", "").lower(), name


# ---------------------------------------------------------------------------
# The rename: forge.anchor.ref, not forge.seal.ref (ADR-010 §6 / ADR-014 A1)
# ---------------------------------------------------------------------------


def test_anchor_ref_is_registered_and_shaped_like_a_kg_pointer() -> None:
    attr = _attributes()["forge.anchor.ref"]
    assert any(str(ex).startswith("kg://anchor/") for ex in attr["examples"])


def test_seal_ref_is_not_a_registered_id_and_has_no_deprecation_entry() -> None:
    # It was never published, so a deprecation mark would falsely imply prior use.
    # (Prose mentioning the rename is expected — it must not be a registered entry.)
    assert "forge.seal.ref" not in _attributes()
    assert "forge.seal.ref" not in _events()
    for attr in _attributes().values():
        assert attr.get("stability") != "deprecated"
        assert "deprecated" not in attr


def test_anchor_note_records_the_rename_and_the_no_deprecation_reasoning() -> None:
    note = _attributes()["forge.anchor.ref"].get("note", "").lower()
    assert "seal.ref" in note
    assert "deprecation" in note


def test_workload_urn_example_uses_the_wl_join_key_shape() -> None:
    attr = _attributes()["forge.workload.urn"]
    assert any(str(ex).startswith("wl:") for ex in attr["examples"])


# ---------------------------------------------------------------------------
# Log events — exactly the three from ADR-009 §2
# ---------------------------------------------------------------------------


def test_exactly_the_three_log_events_are_registered() -> None:
    assert set(_events()) == _EXPECTED_EVENTS


def test_every_event_carries_stability_and_brief() -> None:
    for name, event in _events().items():
        assert event.get("stability") in _VALID_STABILITY, name
        assert event.get("brief", "").strip(), name


def test_announced_event_references_all_five_attributes() -> None:
    announced = _events()["forge.passport.announced"]
    refs = {a["ref"] for a in announced.get("attributes", []) if "ref" in a}
    assert refs == set(_EXPECTED_ATTRIBUTES)


def test_every_event_attribute_ref_resolves_to_a_registered_attribute() -> None:
    known = set(_attributes())
    for name, event in _events().items():
        for attr in event.get("attributes", []):
            ref = attr.get("ref")
            assert ref in known, f"{name} references unregistered {ref}"


# ---------------------------------------------------------------------------
# Generated constants (MP-52) — the Python module emitters import
# ---------------------------------------------------------------------------


def test_generated_constants_match_the_registry() -> None:
    from calm_forge import semconv

    assert semconv.RESOURCE_ATTRIBUTES == set(_EXPECTED_ATTRIBUTES)
    assert semconv.LOG_EVENTS == _EXPECTED_EVENTS
    assert semconv.FORGE_ANCHOR_REF == "forge.anchor.ref"
    assert not hasattr(semconv, "FORGE_SEAL_REF")


def test_generated_file_is_marked_as_weaver_output() -> None:
    text = (
        Path(__file__).resolve().parents[1] / "src" / "calm_forge" / "semconv.py"
    ).read_text()
    assert "Generated by Weaver" in text
    assert "Do not edit by hand" in text
    assert "forge.seal.ref" not in text
