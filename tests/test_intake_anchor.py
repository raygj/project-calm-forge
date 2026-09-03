"""MP-20 — application registry → AccountabilityAnchor reference nodes (ADR-010 §1/§6).

Five behaviours here look like defects to anyone reading the module cold, and a
well-meant cleanup would invert every one of them. Each has a test naming the reason:

1. **A violating entry produces no node at all**, not a node with a warning attached.
   A half-valid anchor is indistinguishable from a valid one at every downstream
   reader, so there is nowhere later to catch it.
2. **``identity_class`` is never inferred**, however obvious the id looks. Guessing
   silently anchors an application to a robot, and the report renders identically.
3. **A non-human accountable party is refused**, even though it resolves fine. It is
   worse than an unanchored edge precisely *because* it resolves (ADR-010 §6a).
4. **PII is refused, not scrubbed.** Scrubbing lets a registry keep shipping personal
   data into an intake that keeps quietly discarding it.
5. **Anchor nodes carry no ``plane`` key** — not ``None``, absent. They are reference
   nodes; ``kg_plane.validate_node`` rejects a reference node that carries the key.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.intake_anchor import (
    IDENTITY_CLASSES,
    NODE_TYPE_ANCHOR,
    AnchorIntakeError,
    anchor_node_id,
    apply_mapping,
    assert_no_pii,
    identity_node_id,
    intake_anchors,
    intake_anchors_from_file,
    write_anchor_nodes,
)
from calm_forge.kg_plane import NODE_CLASS_REFERENCE, plane_of, validate_node
from calm_forge.kg_query import kg_query


def registry(*entries, name="test-registry"):
    return {"registry": name, "entries": list(entries)}


def entry(anchor_id="APP-1", accountable=None, associated=None, **extra):
    out = {"anchor_id": anchor_id}
    if accountable is not None:
        out["accountable"] = accountable
    if associated is not None:
        out["associated"] = associated
    out.update(extra)
    return out


HUMAN = {"id": "E1000", "identity_class": "human"}


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------

def test_a_valid_entry_yields_one_anchor_node():
    result = intake_anchors(registry(entry(accountable=HUMAN)))
    assert result["gaps"] == []
    (node,) = result["reference_nodes"]
    assert node["@type"] == NODE_TYPE_ANCHOR
    assert node["@id"] == "kg://anchor/APP-1"
    assert node["accountable_for"] == HUMAN
    assert node["associated_with"] == []
    assert node["source"] == "test-registry"


def test_the_anchor_node_is_a_reference_node_with_no_plane_key():
    (node,) = intake_anchors(registry(entry(accountable=HUMAN)))["reference_nodes"]
    assert node["node_class"] == NODE_CLASS_REFERENCE
    # Absent, not None. kg_plane rejects a reference node that carries the key at all.
    assert "plane" not in node
    assert validate_node(node) == []
    assert plane_of(node) is None


def test_associated_identities_may_be_any_class_including_non_human():
    result = intake_anchors(registry(entry(
        accountable=HUMAN,
        associated=[
            {"id": "E2000", "identity_class": "human", "role": "delegate"},
            {"id": "FID-x", "identity_class": "functional_id"},
            {"id": "SID-y", "identity_class": "system_id"},
            {"id": "dl-payments", "identity_class": "distribution_list"},
        ])))
    assert result["gaps"] == []
    (node,) = result["reference_nodes"]
    assert [i["identity_class"] for i in node["associated_with"]] == [
        "human", "functional_id", "system_id", "distribution_list"]
    assert node["associated_with"][0]["role"] == "delegate"


def test_application_and_props_pass_through_when_present():
    (node,) = intake_anchors(registry(entry(
        accountable=HUMAN,
        application={"name": "payments", "criticality": "tier-1"},
        props={"cost_center": "CC-1"})))["reference_nodes"]
    assert node["application"]["criticality"] == "tier-1"
    assert node["props"] == {"cost_center": "CC-1"}


def test_absent_application_and_props_are_omitted_not_nulled():
    (node,) = intake_anchors(registry(entry(accountable=HUMAN)))["reference_nodes"]
    assert "application" not in node
    assert "props" not in node


# ---------------------------------------------------------------------------
# Edges point up (ADR-010 §6b)
# ---------------------------------------------------------------------------

def test_every_edge_points_up_at_the_anchor():
    result = intake_anchors(registry(entry(
        accountable=HUMAN,
        associated=[{"id": "FID-x", "identity_class": "functional_id"}])))
    assert [e["to"] for e in result["edges"]] == ["kg://anchor/APP-1"] * 2
    assert [e["@type"] for e in result["edges"]] == ["accountable_for", "associated_with"]
    assert result["edges"][0]["from"] == "kg://identity/human/E1000"
    assert result["edges"][1]["from"] == "kg://identity/functional_id/FID-x"


def test_identity_guids_are_namespaced_by_class():
    # The same string id under two classes is two different identities. Collapsing them
    # would let a service account inherit a human's edges.
    assert identity_node_id({"id": "X", "identity_class": "human"}) != \
        identity_node_id({"id": "X", "identity_class": "robot"})


def test_spiffe_ids_survive_slugging_into_a_usable_guid():
    gid = identity_node_id({"id": "spiffe://acme/ns/pay/sa/web", "identity_class": "spiffe"})
    assert gid == "kg://identity/spiffe/spiffe-acme-ns-pay-sa-web"


def test_anchor_node_id_slugs_unsafe_characters():
    assert anchor_node_id("APP 10/432") == "kg://anchor/APP-10-432"
    assert anchor_node_id("///") == "kg://anchor/unknown"


# ---------------------------------------------------------------------------
# Rule 1 — exactly one human, fail closed
# ---------------------------------------------------------------------------

def test_a_set_of_accountable_parties_is_refused_with_no_node():
    result = intake_anchors(registry(entry(accountable=[HUMAN, {"id": "E2", "identity_class": "human"}])))
    assert result["reference_nodes"] == []
    assert result["edges"] == []
    assert "exactly one human" in result["gaps"][0]


def test_a_single_element_list_is_accepted_as_the_one_accountable_party():
    # Registries that always emit arrays are common; one element is unambiguous.
    result = intake_anchors(registry(entry(accountable=[HUMAN])))
    assert result["gaps"] == []
    assert result["reference_nodes"][0]["accountable_for"] == HUMAN


def test_an_empty_accountable_list_is_refused():
    result = intake_anchors(registry(entry(accountable=[])))
    assert result["reference_nodes"] == []
    assert "exactly one human" in result["gaps"][0]


def test_a_missing_accountable_party_is_refused():
    result = intake_anchors(registry(entry()))
    assert result["reference_nodes"] == []
    assert "no accountable party" in result["gaps"][0]


def test_a_violating_entry_does_not_suppress_a_valid_sibling():
    result = intake_anchors(registry(
        entry("APP-BAD"),
        entry("APP-GOOD", accountable=HUMAN)))
    assert [n["anchor_id"] for n in result["reference_nodes"]] == ["APP-GOOD"]
    assert len(result["gaps"]) == 1


# ---------------------------------------------------------------------------
# Rule 2 — identity_class is declared, never inferred
# ---------------------------------------------------------------------------

def test_an_undeclared_identity_class_is_refused_however_obvious_the_id_looks():
    result = intake_anchors(registry(entry(accountable={"id": "employee-12345"})))
    assert result["reference_nodes"] == []
    assert "never inferred" in result["gaps"][0]


def test_an_unknown_identity_class_is_refused_by_name():
    result = intake_anchors(registry(entry(accountable={"id": "E1", "identity_class": "wizard"})))
    assert "unknown identity_class 'wizard'" in result["gaps"][0]
    assert "human" in result["gaps"][0]


def test_an_identity_without_an_id_is_refused():
    result = intake_anchors(registry(entry(accountable={"identity_class": "human"})))
    assert "has no id" in result["gaps"][0]


def test_a_non_object_identity_is_refused():
    result = intake_anchors(registry(entry(accountable="E1000")))
    assert "identity must be an object" in result["gaps"][0]


def test_a_bad_associated_identity_is_reported_without_losing_the_anchor():
    # associated_with is informational, so one malformed entry must not cost the anchor.
    result = intake_anchors(registry(entry(
        accountable=HUMAN, associated=[{"id": "no-class"}, {"id": "ok", "identity_class": "robot"}])))
    assert len(result["reference_nodes"]) == 1
    assert [i["id"] for i in result["reference_nodes"][0]["associated_with"]] == ["ok"]
    assert len(result["gaps"]) == 1


def test_associated_must_be_a_list():
    result = intake_anchors(registry(entry(accountable=HUMAN, associated={"id": "x"})))
    assert "associated must be a list" in result["gaps"][0]
    assert len(result["reference_nodes"]) == 1


# ---------------------------------------------------------------------------
# Rule 3 — no non-human accountable party (ADR-010 §6a)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("klass", [c for c in IDENTITY_CLASSES if c != "human"])
def test_no_non_human_class_may_be_accountable(klass):
    result = intake_anchors(registry(entry(accountable={"id": "x", "identity_class": klass})))
    assert result["reference_nodes"] == []
    assert f"is a {klass}, not a human" in result["gaps"][0]


def test_a_distribution_list_is_refused_as_the_chain_terminating_in_an_inbox():
    result = intake_anchors(registry(entry(
        accountable={"id": "payments-oncall@", "identity_class": "distribution_list"})))
    assert result["reference_nodes"] == []


# ---------------------------------------------------------------------------
# Rule 4 — PII is refused, not scrubbed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", ["email", "ownerEmailAddress", "phone", "mobile",
                                 "postal_address", "upn", "givenName", "surname"])
def test_personal_data_keys_are_refused(key):
    with pytest.raises(AnchorIntakeError, match="personal-data field"):
        assert_no_pii({"@id": "kg://anchor/x", "accountable_for": {"id": "E1", key: "v"}})


def test_an_email_shaped_value_is_refused_even_under_an_innocent_key():
    with pytest.raises(AnchorIntakeError, match="email-shaped value"):
        assert_no_pii({"props": {"contact": "jane@acme.com"}})


def test_a_redacted_pii_key_is_still_refused():
    # The key itself tells every downstream reader where the email goes.
    with pytest.raises(AnchorIntakeError, match="personal-data field"):
        assert_no_pii({"props": {"owner_email": "REDACTED"}})


def test_name_keys_that_name_things_rather_than_people_are_exempt():
    assert_no_pii({"application": {"name": "payments"}, "registry_name": "acme"})


def test_pii_in_a_registry_entry_refuses_the_node_and_reports_it():
    result = intake_anchors(registry(entry(
        accountable=HUMAN, props={"owner_email": "jane@acme.com"})))
    assert result["reference_nodes"] == []
    assert result["edges"] == []
    assert "personal-data field" in result["gaps"][0]


def test_pii_nested_in_a_list_is_found():
    with pytest.raises(AnchorIntakeError):
        assert_no_pii({"associated_with": [{"id": "a"}, {"id": "b", "email": "x@y.co"}]})


# ---------------------------------------------------------------------------
# The field mapping is data, not code (ADR-010 §6b)
# ---------------------------------------------------------------------------

VENDOR_EXPORT = {
    "registry": "vendor-cmdb",
    "applications": [
        {"app_code": "SVC-77",
         "owner": {"emp_no": "E9", "person_type": "EMP"},
         "support_contacts": [{"emp_no": "FID-1", "person_type": "SVC"}]},
    ],
}

VENDOR_MAPPING = {
    "entries": "applications",
    "fields": {"anchor_id": "app_code", "accountable": "owner",
               "associated": "support_contacts", "id": "emp_no",
               "identity_class": "person_type"},
    "identity_classes": {"EMP": "human", "SVC": "service_account"},
}


def test_a_vendor_export_intakes_cleanly_through_a_mapping_alone():
    result = intake_anchors(VENDOR_EXPORT, mapping=VENDOR_MAPPING)
    assert result["gaps"] == []
    (node,) = result["reference_nodes"]
    assert node["@id"] == "kg://anchor/SVC-77"
    assert node["accountable_for"] == {"id": "E9", "identity_class": "human"}
    assert node["associated_with"][0]["identity_class"] == "service_account"


def test_the_same_export_without_its_mapping_yields_nothing():
    # Proves the mapping is doing the work, not a lucky field-name overlap.
    result = intake_anchors(VENDOR_EXPORT)
    assert result["reference_nodes"] == []


def test_a_registry_already_speaking_the_contract_needs_no_mapping():
    doc = registry(entry(accountable=HUMAN))
    assert apply_mapping(doc, None) is doc
    assert intake_anchors(doc, mapping={})["gaps"] == []


def test_unmapped_fields_pass_through_under_their_own_names():
    result = intake_anchors(
        {"entries": [{"anchor_id": "A", "accountable": HUMAN, "props": {"k": "v"}}]},
        mapping={"fields": {"anchor_id": "app_code"}})
    assert result["reference_nodes"][0]["props"] == {"k": "v"}


def test_mapping_leaves_the_source_document_unmutated():
    doc = json.loads(json.dumps(VENDOR_EXPORT))
    intake_anchors(doc, mapping=VENDOR_MAPPING)
    assert doc == VENDOR_EXPORT


def test_a_non_object_entry_under_a_mapping_is_refused():
    with pytest.raises(AnchorIntakeError, match="entries must be objects"):
        apply_mapping({"applications": ["not-an-object"]}, VENDOR_MAPPING)


def test_a_non_dict_identity_survives_remapping_to_be_reported_later():
    result = intake_anchors({"applications": [{"app_code": "A", "owner": "E9"}]},
                            mapping=VENDOR_MAPPING)
    assert "identity must be an object" in result["gaps"][0]


def test_associated_that_is_not_a_list_passes_mapping_through_to_the_gap_report():
    result = intake_anchors({"applications": [{"app_code": "A", "owner": {"emp_no": "E9", "person_type": "EMP"},
                                               "support_contacts": "nope"}]},
                            mapping=VENDOR_MAPPING)
    assert any("associated must be a list" in g for g in result["gaps"])


# ---------------------------------------------------------------------------
# Document-level refusals
# ---------------------------------------------------------------------------

def test_a_non_object_registry_document_is_refused():
    with pytest.raises(AnchorIntakeError, match="registry documents are objects"):
        intake_anchors(["not", "a", "document"])  # type: ignore[arg-type]


def test_a_registry_with_no_entries_yields_nothing_without_erroring():
    result = intake_anchors({"registry": "empty"})
    assert result == {"reference_nodes": [], "edges": [], "gaps": []}


def test_a_null_entries_key_is_treated_as_empty():
    assert intake_anchors({"registry": "r", "entries": None})["reference_nodes"] == []


def test_a_non_object_entry_is_reported_not_raised():
    result = intake_anchors({"entries": ["nope", entry(accountable=HUMAN)]})
    assert "must be an object" in result["gaps"][0]
    assert len(result["reference_nodes"]) == 1


def test_an_entry_without_an_anchor_id_is_refused():
    result = intake_anchors({"entries": [{"accountable": HUMAN}]})
    assert "no anchor_id" in result["gaps"][0]


def test_a_duplicate_anchor_id_is_refused_rather_than_last_write_wins():
    # Silently picking one would make accountability depend on export ordering.
    result = intake_anchors(registry(
        entry("APP-1", accountable=HUMAN),
        entry("APP-1", accountable={"id": "E2", "identity_class": "human"})))
    assert len(result["reference_nodes"]) == 1
    assert result["reference_nodes"][0]["accountable_for"]["id"] == "E1000"
    assert "duplicate anchor id" in result["gaps"][0]


def test_an_unnamed_registry_still_records_a_source():
    (node,) = intake_anchors({"entries": [entry(accountable=HUMAN)]})["reference_nodes"]
    assert node["source"] == "<unnamed-registry>"


def test_the_source_key_is_an_accepted_alias_for_registry():
    (node,) = intake_anchors({"source": "s", "entries": [entry(accountable=HUMAN)]})["reference_nodes"]
    assert node["source"] == "s"


# ---------------------------------------------------------------------------
# File I/O and the query surface
# ---------------------------------------------------------------------------

def test_round_trip_through_disk(tmp_path):
    reg = tmp_path / "reg.json"
    reg.write_text(json.dumps(registry(entry(accountable=HUMAN))))
    result = intake_anchors_from_file(reg)
    paths = write_anchor_nodes(result["reference_nodes"], tmp_path / "kg")
    assert paths == [tmp_path / "kg" / "reference" / "anchors" / "APP-1.json"]
    assert json.loads(paths[0].read_text())["@id"] == "kg://anchor/APP-1"


def test_a_mapping_file_is_read_from_disk(tmp_path):
    (tmp_path / "reg.json").write_text(json.dumps(VENDOR_EXPORT))
    (tmp_path / "map.json").write_text(json.dumps(VENDOR_MAPPING))
    result = intake_anchors_from_file(tmp_path / "reg.json", mapping_path=tmp_path / "map.json")
    assert result["gaps"] == []
    assert result["reference_nodes"][0]["@id"] == "kg://anchor/SVC-77"


def test_a_non_object_json_file_is_refused(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]")
    with pytest.raises(AnchorIntakeError, match="expected a JSON object"):
        intake_anchors_from_file(bad)


def test_written_anchors_are_queryable_and_carry_no_plane(tmp_path):
    result = intake_anchors(registry(entry(accountable=HUMAN)))
    write_anchor_nodes(result["reference_nodes"], tmp_path)
    hits = kg_query(tmp_path, "anchor", [])
    assert [h["node"]["@id"] for h in hits] == ["kg://anchor/APP-1"]
    assert hits[0]["plane"] is None


def test_anchors_never_appear_in_a_plane_filtered_query(tmp_path):
    # A reference node surfacing under --plane would read as authoring, which is the
    # taxonomy collapse the two-field design exists to prevent (ADR-012 §1).
    write_anchor_nodes(intake_anchors(registry(entry(accountable=HUMAN)))["reference_nodes"],
                       tmp_path)
    for plane in ("architecture", "controls", "business_intent"):
        assert kg_query(tmp_path, "anchor", [], plane=plane) == []


def test_the_full_type_name_resolves_as_well_as_the_alias(tmp_path):
    write_anchor_nodes(intake_anchors(registry(entry(accountable=HUMAN)))["reference_nodes"],
                       tmp_path)
    assert len(kg_query(tmp_path, "AccountabilityAnchor", [])) == 1


def test_the_shipped_example_registry_demonstrates_all_four_outcomes():
    result = intake_anchors_from_file(Path("examples/registry/acme-appreg.json"))
    assert len(result["reference_nodes"]) == 1
    assert len(result["gaps"]) == 3
    joined = " ".join(result["gaps"])
    assert "not a human" in joined
    assert "exactly one human" in joined
    assert "never inferred" in joined
