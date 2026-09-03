"""MP-49 — ODCS data contracts → the declared side of data_management (ADR-011 §7).

Five behaviours a cleanup would plausibly invert, each with the reason it must not:

1. **The observed-side join is computed on read, never stored.** Stored, it enters the
   node's content digest, and refining the join rule would re-digest every contract in
   the estate — our code change presented as their intent changing.
2. **An underivable join is reported, never guessed.** A fabricated correspondence makes
   an uncontracted dataset look contracted, inverting the finding it exists to raise.
3. **Segments the physical name already carries are not added again.** Naive prefixing
   yields `analytics.mart.mart.settled`, which joins to nothing and looks real.
4. **Accountability is not minted from a contract.** ODCS team entries become
   `associated_with` only; the registry is the sole system of record for
   `accountable_for` (ADR-010 §1).
5. **Non-v3 contracts are refused by name**, not parsed to an empty result.
"""
from __future__ import annotations

import json

import pytest
import yaml

from calm_forge.intake_odcs import (
    NODE_TYPE_CONTRACT,
    NODE_TYPE_CONTRACTED_DATASET,
    OdcsIntakeError,
    contract_node_id,
    contracted_dataset_node_id,
    intake_odcs,
    intake_odcs_from_file,
    load_contract,
    observed_dataset_ids,
    write_contract_nodes,
)
from calm_forge.kg_plane import PLANE_DATA_MANAGEMENT, plane_of, validate_node
from calm_forge.kg_query import kg_query

SERVER = {"server": "wh", "type": "postgres", "host": "wh.internal", "port": 5432,
          "database": "analytics", "schema": "mart"}


def contract(**overrides):
    base = {
        "apiVersion": "v3.0.2",
        "kind": "DataContract",
        "id": "payments-v1",
        "name": "Payments",
        "version": "1.0.0",
        "status": "active",
        "servers": [SERVER],
        "schema": [{"name": "settled", "physicalName": "settled",
                    "properties": [{"name": "amount", "logicalType": "number",
                                    "classification": "internal"}]}],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------

def test_a_contract_yields_a_contract_node_and_one_node_per_schema_object():
    result = intake_odcs(contract())
    assert result["gaps"] == []
    (node,) = result["contract_nodes"]
    (dataset,) = result["contracted_dataset_nodes"]
    assert node["@type"] == NODE_TYPE_CONTRACT
    assert node["@id"] == contract_node_id("payments-v1")
    assert dataset["@type"] == NODE_TYPE_CONTRACTED_DATASET
    assert dataset["@id"] == contracted_dataset_node_id("payments-v1", "settled")
    assert dataset["contract"] == node["@id"]


def test_nodes_are_authored_on_the_data_management_plane_and_validate():
    result = intake_odcs(contract())
    for node in [*result["contract_nodes"], *result["contracted_dataset_nodes"]]:
        assert validate_node(node) == []
        assert plane_of(node) == PLANE_DATA_MANAGEMENT


def test_governing_contract_fields_are_carried():
    result = intake_odcs(contract(
        domain="payments", tenant="acme", dataProduct="settlement",
        tags=["pci", "tier-1"],
        description={"purpose": "p", "limitations": "l", "usage": "u"},
        slaProperties=[{"property": "latency", "value": 24, "unit": "h"}]))
    (node,) = result["contract_nodes"]
    assert node["domain"] == "payments"
    assert node["data_product"] == "settlement"
    assert node["purpose"] == "p" and node["limitations"] == "l" and node["usage"] == "u"
    assert node["sla"] == [{"property": "latency", "value": 24, "unit": "h"}]


def test_tags_are_sorted_so_export_order_is_not_drift():
    a = intake_odcs(contract(tags=["b", "a"]))["contract_nodes"][0]
    b = intake_odcs(contract(tags=["a", "b"]))["contract_nodes"][0]
    assert a == b


def test_properties_are_sorted_by_name_so_column_order_is_not_drift():
    forward = intake_odcs(contract(schema=[{"name": "t", "properties": [
        {"name": "a"}, {"name": "b"}]}]))["contracted_dataset_nodes"][0]
    reverse = intake_odcs(contract(schema=[{"name": "t", "properties": [
        {"name": "b"}, {"name": "a"}]}]))["contracted_dataset_nodes"][0]
    assert forward == reverse


def test_only_governing_property_fields_are_admitted():
    (dataset,) = intake_odcs(contract(schema=[{"name": "t", "properties": [
        {"name": "c", "classification": "restricted", "required": True,
         "displayHint": "bold", "examples": ["x"]}]}]))["contracted_dataset_nodes"]
    (prop,) = dataset["properties"]
    assert prop["classification"] == "restricted" and prop["required"] is True
    assert "displayHint" not in prop and "examples" not in prop


def test_quality_rules_reach_the_node_because_they_are_the_projectable_part():
    (dataset,) = intake_odcs(contract(schema=[{
        "name": "t", "quality": [{"rule": "rowCount", "mustBeGreaterThan": 0}],
        "properties": [{"name": "c", "quality": [{"rule": "nullCheck"}]}],
    }]))["contracted_dataset_nodes"]
    assert dataset["quality"] == [{"rule": "rowCount", "mustBeGreaterThan": 0}]
    assert dataset["properties"][0]["quality"] == [{"rule": "nullCheck"}]


def test_a_property_without_a_name_is_skipped():
    (dataset,) = intake_odcs(contract(schema=[{"name": "t", "properties": [
        {"logicalType": "string"}, {"name": "ok"}]}]))["contracted_dataset_nodes"]
    assert [p["name"] for p in dataset["properties"]] == ["ok"]


# ---------------------------------------------------------------------------
# The derived join
# ---------------------------------------------------------------------------

def test_the_join_is_not_stored_on_the_node():
    (dataset,) = intake_odcs(contract())["contracted_dataset_nodes"]
    assert "observed_as" not in dataset
    assert observed_dataset_ids(dataset) != []


def test_the_derived_id_follows_the_openlineage_naming_spec():
    (dataset,) = intake_odcs(contract())["contracted_dataset_nodes"]
    assert observed_dataset_ids(dataset) == [
        "kg://openlineage/dataset/postgres://wh.internal:5432/analytics.mart.settled"]


@pytest.mark.parametrize("physical", ["settled", "mart.settled", "analytics.mart.settled"])
def test_a_physical_name_is_not_requalified_with_segments_it_already_carries(physical):
    # All three name the same table, so all three must resolve to one id. Naive prefixing
    # would give analytics.mart.mart.settled, which joins to nothing and looks real.
    (dataset,) = intake_odcs(contract(schema=[
        {"name": "t", "physicalName": physical}]))["contracted_dataset_nodes"]
    assert observed_dataset_ids(dataset) == [
        "kg://openlineage/dataset/postgres://wh.internal:5432/analytics.mart.settled"]


def test_a_server_without_a_port_omits_it_from_the_namespace():
    server = {k: v for k, v in SERVER.items() if k != "port"}
    (dataset,) = intake_odcs(contract(servers=[server]))["contracted_dataset_nodes"]
    assert observed_dataset_ids(dataset)[0].startswith(
        "kg://openlineage/dataset/postgres://wh.internal/")


def test_an_unknown_server_type_still_derives_an_id_under_its_own_scheme():
    (dataset,) = intake_odcs(contract(servers=[
        {"type": "duckdb", "host": "h", "database": "d"}]))["contracted_dataset_nodes"]
    assert observed_dataset_ids(dataset) == ["kg://openlineage/dataset/duckdb://h/d.settled"]


def test_several_servers_give_several_candidate_ids():
    (dataset,) = intake_odcs(contract(servers=[
        SERVER, {**SERVER, "host": "dr.internal"}]))["contracted_dataset_nodes"]
    assert len(observed_dataset_ids(dataset)) == 2


def test_a_contract_with_no_server_reports_an_unjoinable_dataset():
    result = intake_odcs(contract(servers=[]))
    (dataset,) = result["contracted_dataset_nodes"]
    assert observed_dataset_ids(dataset) == []
    assert "no observed-side correspondence can be derived" in result["gaps"][0]


def test_a_server_without_a_host_cannot_be_joined_through():
    result = intake_odcs(contract(servers=[{"type": "postgres", "database": "d"}]))
    assert observed_dataset_ids(result["contracted_dataset_nodes"][0]) == []
    assert result["gaps"] != []


def test_a_malformed_server_entry_is_dropped_before_it_reaches_a_node():
    result = intake_odcs(contract(servers=["not-a-mapping", SERVER]))
    assert result["contract_nodes"][0]["servers"] == [SERVER]
    assert len(observed_dataset_ids(result["contracted_dataset_nodes"][0])) == 1


def test_the_join_guards_a_malformed_server_it_is_handed_directly():
    # The intake filters these out, so this guard is only reachable by a caller deriving
    # from a hand-built node. It still has to hold: observed_dataset_ids is public.
    assert observed_dataset_ids(
        {"physical_name": "t", "servers": ["not-a-mapping", SERVER]}) == [
        "kg://openlineage/dataset/postgres://wh.internal:5432/analytics.mart.t"]


def test_a_node_with_no_physical_name_derives_nothing():
    assert observed_dataset_ids({"servers": [SERVER]}) == []


def test_the_name_is_used_when_no_physical_name_was_declared():
    (dataset,) = intake_odcs(contract(schema=[{"name": "settled"}]))["contracted_dataset_nodes"]
    assert dataset["physical_name"] == "settled"
    assert observed_dataset_ids(dataset) != []


# ---------------------------------------------------------------------------
# Ownership without accountability
# ---------------------------------------------------------------------------

def test_team_members_become_associated_with_edges_only():
    result = intake_odcs(contract(team=[
        {"username": "steward", "role": "Data Steward"},
        {"username": "producer", "role": "Producer"}]))
    kinds = {e["@type"] for e in result["edges"]}
    assert "associated_with" in kinds
    assert "accountable_for" not in kinds


def test_no_edge_in_this_intake_ever_asserts_accountability():
    # The registry is the single system of record. Two sources of truth for who answers
    # is indistinguishable from none the first time they disagree.
    result = intake_odcs(contract(team=[{"username": "u", "role": "Owner"}]))
    assert all(e["@type"] != "accountable_for" for e in result["edges"])


def test_a_team_member_without_a_username_is_skipped_with_a_gap():
    result = intake_odcs(contract(team=[{"role": "Owner"}]))
    assert "no username" in result["gaps"][0]
    assert result["contract_nodes"][0]["team"] == []


def test_an_email_shaped_value_on_a_team_member_is_refused():
    result = intake_odcs(contract(team=[{"username": "u", "email": "u@acme.com"}]))
    assert "refusing an email-shaped value" in result["gaps"][0]
    assert result["contract_nodes"][0]["team"] == []


def test_a_non_mapping_team_entry_is_reported():
    result = intake_odcs(contract(team=["steward"]))
    assert "not a mapping" in result["gaps"][0]


def test_identity_edges_point_up_at_the_contract():
    result = intake_odcs(contract(team=[{"username": "steward"}]))
    edge = next(e for e in result["edges"] if e["@type"] == "associated_with")
    assert edge["from"] == "kg://identity/human/steward"
    assert edge["to"] == contract_node_id("payments-v1")


def test_declares_edges_run_from_contract_to_dataset():
    result = intake_odcs(contract())
    edge = next(e for e in result["edges"] if e["@type"] == "declares")
    assert edge["from"] == contract_node_id("payments-v1")
    assert edge["to"] == contracted_dataset_node_id("payments-v1", "settled")


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

def test_a_non_datacontract_kind_is_refused_by_name():
    with pytest.raises(OdcsIntakeError, match="unsupported ODCS kind 'DataProduct'"):
        intake_odcs(contract(kind="DataProduct"))


def test_a_v2_contract_is_refused_rather_than_read_as_empty():
    with pytest.raises(OdcsIntakeError, match="apiVersion 'v2.2.2'"):
        intake_odcs(contract(apiVersion="v2.2.2"))


def test_a_non_mapping_document_is_refused():
    with pytest.raises(OdcsIntakeError, match="is a mapping"):
        intake_odcs(["not", "a", "contract"])


def test_a_contract_with_no_id_or_name_is_refused():
    doc = contract()
    doc.pop("id")
    doc.pop("name")
    with pytest.raises(OdcsIntakeError, match="needs an id"):
        intake_odcs(doc)


def test_the_name_stands_in_when_no_id_was_given():
    doc = contract()
    doc.pop("id")
    assert intake_odcs(doc)["contract_nodes"][0]["contract_id"] == "Payments"


def test_a_contract_with_no_schema_objects_is_reported():
    result = intake_odcs(contract(schema=[]))
    assert result["contracted_dataset_nodes"] == []
    assert "declares no schema objects" in result["gaps"][0]


def test_a_schema_object_without_a_name_is_skipped():
    result = intake_odcs(contract(schema=[{"physicalName": "x"}, {"name": "ok"}]))
    assert [d["name"] for d in result["contracted_dataset_nodes"]] == ["ok"]
    assert "has no name" in result["gaps"][0]


def test_a_document_with_no_kind_or_apiversion_is_accepted():
    # Both are optional in practice; refusing on absence would reject valid contracts.
    doc = contract()
    doc.pop("kind")
    doc.pop("apiVersion")
    assert intake_odcs(doc)["gaps"] == []


# ---------------------------------------------------------------------------
# File I/O and the query surface
# ---------------------------------------------------------------------------

def test_yaml_and_json_forms_of_one_contract_agree(tmp_path):
    as_yaml = tmp_path / "c.yaml"
    as_json = tmp_path / "c.json"
    as_yaml.write_text(yaml.safe_dump(contract()))
    as_json.write_text(json.dumps(contract()))
    assert intake_odcs_from_file(as_yaml) == intake_odcs_from_file(as_json)


def test_malformed_yaml_names_its_file(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("a:\n  - b\n :::\n")
    with pytest.raises(OdcsIntakeError, match="c.yaml"):
        load_contract(path)


def test_written_nodes_are_queryable(tmp_path):
    result = intake_odcs(contract())
    paths = write_contract_nodes(result, tmp_path)
    assert len(paths) == 2
    assert len(kg_query(tmp_path, "contract", [])) == 1
    assert len(kg_query(tmp_path, "contracteddataset", [])) == 1


def test_written_nodes_answer_a_plane_filtered_query(tmp_path):
    write_contract_nodes(intake_odcs(contract()), tmp_path)
    assert len(kg_query(tmp_path, "datacontract", [], plane=PLANE_DATA_MANAGEMENT)) == 1
    assert kg_query(tmp_path, "datacontract", [], plane="controls") == []


def test_the_shipped_example_contract_joins_to_the_observed_side():
    result = intake_odcs_from_file("examples/odcs/seller-payments.odcs.yaml")
    assert result["gaps"] == []
    (dataset,) = result["contracted_dataset_nodes"]
    assert observed_dataset_ids(dataset) == [
        "kg://openlineage/dataset/postgres://warehouse.internal:5432/analytics.mart.settled"]
    assert {p["name"] for p in dataset["properties"]} == {"amount", "pan_token", "txn_ts"}
