"""MP-54 — the requirements plane (ADR-015).

Six behaviours a cleanup would plausibly invert. Each is load-bearing:

1. **`realized_by` is derived, never stored — and authoring it is refused.** Stored, it
   enters the node's content digest, so generating an artifact mutates the intent it was
   generated from, and `REQUIREMENTS_NEWER_THAN_CODE` compares against a moving value.
2. **An unknown `requirements_schema` raises.** Falling back to the newest known reader
   silently misreads valid documents (MP-02).
3. **A ratified requirement needs acceptance that projects into a test skeleton.**
   Prose-in-Gherkin-clothing is the named risk; the projection is the detector.
4. **A non-human actor yields `associated_with` only.** Never `accountable_for` — the
   registry is the sole system of record, and a chain ending in an agent answers nobody.
5. **Workflow fields are refused.** Forge is not a requirements-management tool.
6. **Assertions name properties, never platforms.** `compute_type: isolated_ephemeral`,
   not `runtime: lambda` — the graph must not change when a deployment technology does.
"""
from __future__ import annotations

import json

import pytest
import yaml

from calm_forge.intake_requirements import (
    NODE_TYPE_ACTOR,
    NODE_TYPE_REQUIREMENT,
    NODE_TYPE_TARGET_STATE,
    PLANE_REQUIREMENTS,
    RequirementsIntakeError,
    acceptance_skeletons,
    actor_node_id,
    intake_requirements,
    intake_requirements_from_file,
    load_requirements,
    realized_by,
    requirement_node_id,
    target_state_node_id,
    write_requirements_nodes,
)
from calm_forge.kg_plane import PLANES, plane_of, validate_node
from calm_forge.kg_query import kg_query

TAG = {"node_class": "authored", "plane": "requirements"}
HUMAN = {"id": "actor:customer", "name": "Customer", "kind": "human", **TAG}
AGENT = {"id": "actor:bot", "name": "Bot", "kind": "agent",
         "anchor_ref": "kg://anchor/APP-1", **TAG}
BLOCK = {"given": "g", "when": "w", "then": "a transaction is recorded"}


def doc(**overrides):
    base = {
        "requirements_schema": "0.1",
        "actors": [dict(HUMAN)],
        "requirements": [{"id": "req:pay/record", "actor": "actor:customer",
                          "story": "As a customer I want my payment recorded.",
                          "status": "ratified", "acceptance": [dict(BLOCK)], **TAG}],
        "target_states": [{"id": "ts:pay/zero-trust",
                           "assertions": {"compute_type": "isolated_ephemeral"}, **TAG}],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Shape and plane registration
# ---------------------------------------------------------------------------

def test_the_sixth_plane_is_registered():
    # Without this, nodes_in_plane raises and node_versions never walks the containers,
    # so every requirement node reads as deleted.
    assert PLANE_REQUIREMENTS in PLANES


def test_a_document_yields_one_node_per_entry():
    result = intake_requirements(doc())
    assert result["gaps"] == []
    assert [n["@type"] for n in result["actor_nodes"]] == [NODE_TYPE_ACTOR]
    assert [n["@type"] for n in result["requirement_nodes"]] == [NODE_TYPE_REQUIREMENT]
    assert [n["@type"] for n in result["target_state_nodes"]] == [NODE_TYPE_TARGET_STATE]


def test_every_node_validates_and_carries_the_plane():
    result = intake_requirements(doc())
    for node in [*result["actor_nodes"], *result["requirement_nodes"],
                 *result["target_state_nodes"]]:
        assert validate_node(node) == []
        assert plane_of(node) == PLANE_REQUIREMENTS


def test_authored_ids_become_kg_guids():
    result = intake_requirements(doc())
    assert result["actor_nodes"][0]["@id"] == actor_node_id("actor:customer")
    assert result["actor_nodes"][0]["@id"] == "kg://requirements/actor/customer"
    assert result["requirement_nodes"][0]["@id"] == requirement_node_id("req:pay/record")
    assert result["target_state_nodes"][0]["@id"] == target_state_node_id("ts:pay/zero-trust")


def test_assertions_are_sorted_so_authoring_order_is_not_drift():
    a = intake_requirements(doc(target_states=[{"id": "ts:x", "assertions": {
        "b": 1, "a": 2}, **TAG}]))["target_state_nodes"][0]
    b = intake_requirements(doc(target_states=[{"id": "ts:x", "assertions": {
        "a": 2, "b": 1}, **TAG}]))["target_state_nodes"][0]
    assert a == b


def test_a_requirement_naming_an_undeclared_actor_is_reported():
    result = intake_requirements(doc(actors=[]))
    assert "has no holder" in result["gaps"][0]


# ---------------------------------------------------------------------------
# 1 — realized_by is derived, and authoring it is refused
# ---------------------------------------------------------------------------

def test_realized_by_is_never_stored_on_a_node():
    result = intake_requirements(doc(target_states=[{
        "id": "ts:x", "assertions": {"a": 1}, "realizes": ["kg://odcs/contract/c"], **TAG}]))
    (node,) = result["target_state_nodes"]
    assert "realized_by" not in node


def test_realized_by_derives_from_inbound_realizes_edges():
    result = intake_requirements(doc(target_states=[{
        "id": "ts:x", "assertions": {"a": 1},
        "realizes": ["kg://odcs/contract/c", "kg://edges/v1/abc"], **TAG}]))
    (node,) = result["target_state_nodes"]
    assert realized_by(node, result["edges"]) == ["kg://edges/v1/abc", "kg://odcs/contract/c"]


def test_generating_more_artifacts_does_not_change_the_intent_node():
    # The whole point. Adding a realizes edge changes what the requirement produced; it
    # must not change the requirement.
    one = intake_requirements(doc(target_states=[{
        "id": "ts:x", "assertions": {"a": 1}, "realizes": ["kg://odcs/contract/c"], **TAG}]))
    two = intake_requirements(doc(target_states=[{
        "id": "ts:x", "assertions": {"a": 1},
        "realizes": ["kg://odcs/contract/c", "kg://edges/v1/new"], **TAG}]))
    assert one["target_state_nodes"][0]["realizes"] != two["target_state_nodes"][0]["realizes"]
    # ...but what the author wrote about the intent itself is untouched:
    strip = lambda n: {k: v for k, v in n.items() if k != "realizes"}  # noqa: E731
    assert strip(one["target_state_nodes"][0]) == strip(two["target_state_nodes"][0])


def test_authoring_realized_by_is_refused_not_silently_dropped():
    # A document carrying it was authored against the wrong model; dropping it silently
    # would let that model persist.
    result = intake_requirements(doc(target_states=[{
        "id": "ts:x", "assertions": {"a": 1}, "realized_by": ["kg://x/y"], **TAG}]))
    assert result["target_state_nodes"] == []
    assert "derived on read" in result["gaps"][0]


def test_realized_by_of_an_unknown_node_is_empty():
    assert realized_by({}, [{"@type": "realizes", "from": "x", "to": "y"}]) == []


def test_realized_by_ignores_other_predicates():
    node = {"@id": "n"}
    edges = [{"@type": "associated_with", "from": "n", "to": "kg://anchor/A"},
             {"@type": "realizes", "from": "n", "to": "kg://odcs/contract/c"}]
    assert realized_by(node, edges) == ["kg://odcs/contract/c"]


# ---------------------------------------------------------------------------
# 2 — version dispatch raises
# ---------------------------------------------------------------------------

def test_an_unknown_schema_version_raises():
    with pytest.raises(RequirementsIntakeError, match="unknown requirements_schema '0.2'"):
        intake_requirements(doc(requirements_schema="0.2"))


def test_a_missing_schema_version_raises():
    d = doc()
    d.pop("requirements_schema")
    with pytest.raises(RequirementsIntakeError, match="no requirements_schema"):
        intake_requirements(d)


def test_a_non_mapping_document_raises():
    with pytest.raises(RequirementsIntakeError, match="is a mapping"):
        intake_requirements(["not", "a", "document"])


# ---------------------------------------------------------------------------
# 3 — ratified means executable
# ---------------------------------------------------------------------------

def test_acceptance_projects_into_test_skeleton_names():
    (node,) = intake_requirements(doc())["requirement_nodes"]
    assert acceptance_skeletons(node) == ["test_00_a-transaction-is-recorded"]


def test_a_ratified_requirement_with_no_acceptance_is_refused():
    result = intake_requirements(doc(requirements=[{
        "id": "req:x", "actor": "actor:customer", "story": "s", "status": "ratified", **TAG}]))
    assert result["requirement_nodes"] == []
    assert "ratified with no acceptance" in result["gaps"][0]


def test_a_draft_requirement_needs_no_acceptance():
    result = intake_requirements(doc(requirements=[{
        "id": "req:x", "actor": "actor:customer", "story": "s", "status": "draft", **TAG}]))
    assert len(result["requirement_nodes"]) == 1
    assert result["gaps"] == []


def test_an_incomplete_gherkin_block_is_refused():
    result = intake_requirements(doc(requirements=[{
        "id": "req:x", "actor": "actor:customer", "story": "s", "status": "draft",
        "acceptance": [{"given": "g", "when": "w"}], **TAG}]))
    assert "missing ['then']" in result["gaps"][0]


def test_acceptance_must_be_a_list():
    result = intake_requirements(doc(requirements=[{
        "id": "req:x", "actor": "actor:customer", "story": "s",
        "status": "draft", "acceptance": "given a thing", **TAG}]))
    assert "must be a list" in result["gaps"][0]


def test_a_non_mapping_acceptance_block_is_reported():
    result = intake_requirements(doc(requirements=[{
        "id": "req:x", "actor": "actor:customer", "story": "s",
        "status": "draft", "acceptance": ["given a thing"], **TAG}]))
    assert "is not a mapping" in result["gaps"][0]


def test_skeletons_skip_malformed_blocks_rather_than_crashing():
    assert acceptance_skeletons({"acceptance": ["nope", dict(BLOCK)]}) == [
        "test_01_a-transaction-is-recorded"]


def test_a_requirement_with_no_acceptance_projects_nothing():
    assert acceptance_skeletons({"acceptance": []}) == []
    assert acceptance_skeletons({}) == []


@pytest.mark.parametrize("field,value", [("status", "in_progress"), ("priority", "urgent")])
def test_unknown_enums_are_reported(field, value):
    result = intake_requirements(doc(requirements=[{
        "id": "req:x", "actor": "actor:customer", "story": "s", field: value, **TAG}]))
    assert f"{field} {value!r}" in result["gaps"][0]


# ---------------------------------------------------------------------------
# 4 — accountability is referenced, never asserted
# ---------------------------------------------------------------------------

def test_an_agent_actor_yields_associated_with_only():
    result = intake_requirements(doc(actors=[dict(AGENT)]))
    kinds = {e["@type"] for e in result["edges"]}
    assert kinds == {"associated_with"}
    assert "accountable_for" not in kinds


def test_no_edge_from_this_intake_ever_asserts_accountability():
    result = intake_requirements(doc(actors=[dict(HUMAN), dict(AGENT)]))
    assert all(e["@type"] != "accountable_for" for e in result["edges"])


@pytest.mark.parametrize("kind", ["system", "agent"])
def test_an_internal_non_human_actor_without_an_anchor_is_refused(kind):
    result = intake_requirements(doc(actors=[{
        "id": "actor:x", "name": "X", "kind": kind, **TAG}]))
    assert result["actor_nodes"] == []
    assert "accountability never leaves the human" in result["gaps"][0]


def test_a_human_actor_needs_no_anchor():
    result = intake_requirements(doc(actors=[dict(HUMAN)]))
    assert len(result["actor_nodes"]) == 1
    assert result["edges"] == []


def test_a_seal_scheme_anchor_ref_is_refused():
    # "seal" and "license" are display aliases and never reach a GUID (ADR-010 §1).
    result = intake_requirements(doc(actors=[{
        "id": "actor:x", "name": "X", "kind": "agent",
        "anchor_ref": "kg://seal/28841", **TAG}]))
    assert "is not a kg://anchor/ reference" in result["gaps"][0]


def test_an_unknown_actor_kind_is_refused():
    result = intake_requirements(doc(actors=[{
        "id": "actor:x", "name": "X", "kind": "daemon", **TAG}]))
    assert "kind 'daemon'" in result["gaps"][0]


def test_an_actor_without_an_id_or_name_is_reported():
    assert "no id" in intake_requirements(doc(actors=[{"name": "X", "kind": "human"}]))["gaps"][0]
    assert "no name" in intake_requirements(
        doc(actors=[{"id": "actor:x", "kind": "human"}]))["gaps"][0]


# ---------------------------------------------------------------------------
# 5 — the scope guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["sprint", "assignee", "story_points", "epic_link",
                                   "comments", "due_date", "reporter", "workflow_state"])
def test_workflow_fields_are_refused(field):
    result = intake_requirements(doc(requirements=[{
        "id": "req:x", "actor": "actor:customer", "story": "s",
        "status": "draft", field: "anything", **TAG}]))
    assert result["requirement_nodes"] == []
    assert "workflow state, not generative intent" in result["gaps"][0]


def test_the_scope_guard_covers_actors_and_target_states_too():
    assert "workflow state" in intake_requirements(doc(actors=[
        {**HUMAN, "assignee": "x"}]))["gaps"][0]
    assert "workflow state" in intake_requirements(doc(target_states=[
        {"id": "ts:x", "assertions": {"a": 1}, "sprint": 4, **TAG}]))["gaps"][0]


# ---------------------------------------------------------------------------
# 6 — assertions name properties, not platforms
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", ["runtime", "vendor", "instance_type", "sku"])
def test_a_platform_shaped_assertion_is_refused(key):
    result = intake_requirements(doc(target_states=[{
        "id": "ts:x", "assertions": {key: "lambda"}, **TAG}]))
    assert result["target_state_nodes"] == []
    assert "names a platform, not a property" in result["gaps"][0]


def test_a_property_shaped_assertion_is_accepted():
    result = intake_requirements(doc(target_states=[{
        "id": "ts:x", "assertions": {"compute_type": "isolated_ephemeral"}, **TAG}]))
    assert result["gaps"] == []


def test_a_target_state_with_no_assertions_is_refused():
    result = intake_requirements(doc(target_states=[{"id": "ts:x", "assertions": {}, **TAG}]))
    assert "constrains nothing" in result["gaps"][0]


def test_a_target_state_without_an_id_is_reported():
    assert "no id" in intake_requirements(doc(target_states=[{"assertions": {"a": 1}}]))["gaps"][0]


# ---------------------------------------------------------------------------
# Malformed entries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", ["actors", "requirements", "target_states"])
def test_a_non_mapping_entry_is_reported_not_raised(section):
    result = intake_requirements(doc(**{section: ["nope"]}))
    assert "not a mapping" in result["gaps"][0]


def test_a_requirement_without_an_actor_or_story_is_reported():
    result = intake_requirements(doc(requirements=[{"id": "req:x", "status": "draft", **TAG}]))
    joined = " ".join(result["gaps"])
    assert "no actor" in joined and "no story" in joined


def test_a_requirement_without_an_id_is_reported():
    assert "no id" in intake_requirements(doc(requirements=[{"story": "s"}]))["gaps"][0]


def test_empty_sections_are_fine():
    result = intake_requirements({"requirements_schema": "0.1"})
    assert result == {"actor_nodes": [], "requirement_nodes": [], "target_state_nodes": [],
                      "edges": [], "gaps": []}


# ---------------------------------------------------------------------------
# File I/O and the query surface
# ---------------------------------------------------------------------------

def test_yaml_and_json_forms_agree(tmp_path):
    (tmp_path / "d.yaml").write_text(yaml.safe_dump(doc()))
    (tmp_path / "d.json").write_text(json.dumps(doc()))
    assert intake_requirements_from_file(tmp_path / "d.yaml") == \
        intake_requirements_from_file(tmp_path / "d.json")


def test_malformed_yaml_names_its_file(tmp_path):
    path = tmp_path / "d.yaml"
    path.write_text("a:\n  - b\n :::\n")
    with pytest.raises(RequirementsIntakeError, match="d.yaml"):
        load_requirements(path)


def test_written_nodes_are_queryable_by_type(tmp_path):
    result = intake_requirements(doc())
    paths = write_requirements_nodes(result, tmp_path)
    assert len(paths) == 3
    assert len(kg_query(tmp_path, "actor", [])) == 1
    assert len(kg_query(tmp_path, "requirement", [])) == 1
    assert len(kg_query(tmp_path, "targetstate", [])) == 1


def test_written_nodes_answer_a_plane_filtered_query(tmp_path):
    write_requirements_nodes(intake_requirements(doc()), tmp_path)
    assert len(kg_query(tmp_path, "requirement", [], plane=PLANE_REQUIREMENTS)) == 1
    assert kg_query(tmp_path, "requirement", [], plane="controls") == []


def test_the_shipped_example_compiles_clean():
    result = intake_requirements_from_file(
        "examples/requirements/payments-portal.requirements.yaml")
    assert result["gaps"] == []
    assert len(result["actor_nodes"]) == 2
    assert len(result["requirement_nodes"]) == 2
    ratified = next(n for n in result["requirement_nodes"] if n["status"] == "ratified")
    assert len(acceptance_skeletons(ratified)) == 2
    assert realized_by(ratified, result["edges"]) == ["kg://odcs/contract/payments-settled-v1"]
    agent = next(n for n in result["actor_nodes"] if n["kind"] == "agent")
    assert {e["@type"] for e in result["edges"] if e["from"] == agent["@id"]} == \
        {"associated_with"}
