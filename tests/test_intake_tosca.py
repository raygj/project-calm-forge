"""TOSCA intake — MP-21 (ADR-005 §4).

The OSCAL adapter (MP-16) is the template, so the load-bearing behaviours are the same
ones, one altitude up. Each is pinned with the reason in the test body:

1. **Policy-type property defaults are scoped by the type's declarations, not applied
   type-wide.** A sibling type's default must not leak onto a policy of another type —
   the property-inheritance trap the backlog warns about.
2. **A policy's own assignment is exempt from scoping** and always applies.
3. **A required property nobody resolves is reported, never defaulted.**
4. **TOSCA values are not re-coerced.** ``"1.10"`` stays ``"1.10"`` — unlike OSCAL, the
   value arrives already typed and re-typing would mangle it.
5. **Policy nodes land in the business_intent plane**, and ``business_intent_nodes`` is a
   container ``node_versions`` walks — otherwise a live template reads as deleted.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.intake_tosca import (
    NODE_ID_PREFIX,
    ToscaIntakeError,
    intake_tosca,
    intake_tosca_from_file,
    policy_node_id,
    policy_type_index,
    property_variables,
    resolve_properties,
    service_template,
    type_property_definitions,
    write_business_intent_nodes,
)
from calm_forge.kg_plane import PLANE_BUSINESS_INTENT, node_versions, validate_node

DEFINITIONS = {
    "tosca_definitions_version": "tosca_simple_yaml_1_3",
    "policy_types": {
        "forge.policies.Root": {
            "properties": {
                "business_owner": {"type": "string", "required": True},
                "justification": {"type": "string", "required": True},
            },
        },
        "forge.policies.Availability": {
            "derived_from": "forge.policies.Root",
            "properties": {
                "sla_target": {"type": "string", "default": "99.9"},
                "max_unavailability_minutes": {"type": "integer", "default": 43},
                "multi_region": {"type": "boolean", "default": False},
            },
        },
        "forge.policies.Placement": {
            "derived_from": "forge.policies.Root",
            "properties": {
                "residency": {"type": "string", "required": True},
                "allowed_regions": {"type": "list", "required": False},
            },
        },
    },
}


def service(**policy_overrides):
    policy = {
        "type": "forge.policies.Availability",
        "description": "the web->api path must stay up",
        "properties": {
            "business_owner": "payments-platform-lead",
            "justification": "auth requests fail if web->api is down",
            "sla_target": "99.95",
            "multi_region": True,
        },
        "targets": ["web", "api"],
    }
    policy.update(policy_overrides)
    return {
        "tosca_definitions_version": "tosca_simple_yaml_1_3",
        "metadata": {"template_name": "payments-portal"},
        "topology_template": {
            "node_templates": {
                "web": {"type": "tosca.nodes.WebServer",
                        "metadata": {"governs": "workload:pp:web"}},
                "api": {"type": "tosca.nodes.WebApplication",
                        "metadata": {"governs": ["workload:pp:api", "kg://edges/v1/abc"]}},
            },
            "policies": [{"web-to-api-availability": policy}],
        },
    }


# ---------------------------------------------------------------------------
# Type inheritance
# ---------------------------------------------------------------------------

def test_property_definitions_walk_the_derived_from_chain():
    types = policy_type_index(DEFINITIONS)
    defs, missing = type_property_definitions("forge.policies.Availability", types)
    assert missing == []
    # own properties plus the two required ones inherited from Root
    assert set(defs) == {
        "sla_target", "max_unavailability_minutes", "multi_region",
        "business_owner", "justification",
    }


def test_a_child_type_overrides_an_ancestors_default():
    """Most-derived declaration wins, so a child tightening a parent's default is the one
    that lands — not the parent's."""
    types = policy_type_index({
        "tosca_definitions_version": "x",
        "policy_types": {
            "base": {"properties": {"p": {"type": "string", "default": "loose"}}},
            "child": {"derived_from": "base",
                      "properties": {"p": {"type": "string", "default": "tight"}}},
        },
    })
    defs, _ = type_property_definitions("child", types)
    assert defs["p"]["default"] == "tight"


def test_a_missing_ancestor_is_reported_not_guessed():
    types = policy_type_index({
        "tosca_definitions_version": "x",
        "policy_types": {"child": {"derived_from": "nonexistent",
                                   "properties": {"p": {"type": "string"}}}},
    })
    _defs, missing = type_property_definitions("child", types)
    assert missing == ["nonexistent"]


def test_a_derived_from_cycle_does_not_hang():
    types = policy_type_index({
        "tosca_definitions_version": "x",
        "policy_types": {
            "a": {"derived_from": "b", "properties": {}},
            "b": {"derived_from": "a", "properties": {}},
        },
    })
    defs, missing = type_property_definitions("a", types)
    assert defs == {} and missing == []


# ---------------------------------------------------------------------------
# Resolution order and scope
# ---------------------------------------------------------------------------

def test_type_default_applies_and_records_itself():
    types = policy_type_index(DEFINITIONS)
    resolved, _unresolved, _missing = resolve_properties(
        "forge.policies.Availability", types=types,
        assignments={"business_owner": "x", "justification": "y"},
    )
    assert resolved["max_unavailability_minutes"] == {
        "value": 43, "set_by": "policy-type-default", "type": "integer",
    }


def test_the_policy_assignment_is_the_strongest_layer():
    types = policy_type_index(DEFINITIONS)
    resolved, _u, _m = resolve_properties(
        "forge.policies.Availability", types=types,
        assignments={"business_owner": "x", "justification": "y", "sla_target": "99.99"},
    )
    assert resolved["sla_target"]["set_by"] == "policy"
    assert resolved["sla_target"]["value"] == "99.99"


def test_a_sibling_types_default_does_not_leak_onto_this_policy():
    """The load-bearing scoping rule — the property-inheritance trap. A Placement policy
    must not carry Availability's max_unavailability_minutes just because both types exist
    in the same definitions document. The type's own declarations ARE the scope."""
    types = policy_type_index(DEFINITIONS)
    resolved, _u, _m = resolve_properties(
        "forge.policies.Placement", types=types,
        assignments={"business_owner": "x", "justification": "y", "residency": "eu-west-1"},
    )
    assert "max_unavailability_minutes" not in resolved
    assert "sla_target" not in resolved
    assert "multi_region" not in resolved


def test_the_policy_layer_is_exempt_from_scoping():
    """A property assigned on the policy applies even when the type does not declare it —
    it is written on exactly one policy and cannot be misdirected, so discarding it would
    drop the most specific statement in the document. Its declared type is simply unknown."""
    types = policy_type_index(DEFINITIONS)
    resolved, _u, _m = resolve_properties(
        "forge.policies.Placement", types=types,
        assignments={"residency": "eu-west-1", "vendor_knob": "on"},
    )
    assert resolved["vendor_knob"] == {"value": "on", "set_by": "policy", "type": None}


def test_a_required_property_nobody_resolves_is_reported_not_defaulted():
    types = policy_type_index(DEFINITIONS)
    resolved, unresolved, _m = resolve_properties(
        "forge.policies.Placement", types=types,
        assignments={"business_owner": "x", "justification": "y"},
    )
    assert unresolved == ["residency"]
    assert "residency" not in resolved


def test_an_optional_property_left_unset_is_not_a_gap():
    """TOSCA properties are required unless required: false. allowed_regions is optional,
    so its absence is legitimate, not a hole to report."""
    types = policy_type_index(DEFINITIONS)
    _r, unresolved, _m = resolve_properties(
        "forge.policies.Placement", types=types,
        assignments={"business_owner": "x", "justification": "y", "residency": "eu-west-1"},
    )
    assert unresolved == []


def test_with_no_types_the_policy_supplies_its_own_scope():
    resolved, unresolved, missing = resolve_properties(
        "forge.policies.Availability", types=None,
        assignments={"sla_target": "99.9"},
    )
    assert resolved["sla_target"]["value"] == "99.9"
    assert unresolved == [] and missing == []


def test_tosca_values_are_not_re_coerced():
    """OSCAL carries strings and must type them; TOSCA arrives already typed, so re-typing
    a dotted numeral would reintroduce the exact "1.10" -> 1.1 mangling the OSCAL adapter
    avoids. Pass-through, always."""
    resolved, _u, _m = resolve_properties(
        None, assignments={"version": "1.10", "count": 5, "flag": True},
    )
    assert resolved["version"]["value"] == "1.10"
    assert resolved["count"]["value"] == 5
    assert resolved["flag"]["value"] is True


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def test_nodes_land_in_the_business_intent_plane():
    """Never architecture. A business_intent node in the architecture plane is invisible
    to every cross-plane finding, which is what ADR-005's no-default plane rule exists to
    prevent."""
    result = intake_tosca(service(), definitions=DEFINITIONS)
    node = result["business_intent_nodes"][0]
    assert node["plane"] == PLANE_BUSINESS_INTENT
    assert node["node_class"] == "authored"
    assert validate_node(node) == []


def test_node_id_follows_the_committed_guid_scheme():
    """ADR-006 already commits kg://tosca/policy/<template>/<policy> as the business_intent
    ref a passport points at, so intake must mint exactly that."""
    node = intake_tosca(service(), definitions=DEFINITIONS)["business_intent_nodes"][0]
    assert node["@id"] == f"{NODE_ID_PREFIX}/payments-portal/web-to-api-availability"
    assert policy_node_id("payments-portal", "web-to-api-availability") == node["@id"]


def test_re_running_intake_against_an_updated_template_updates_rather_than_orphans():
    first = intake_tosca(service(), definitions=DEFINITIONS)["business_intent_nodes"][0]
    tightened = service()
    tightened["topology_template"]["policies"][0][
        "web-to-api-availability"]["properties"]["sla_target"] = "99.99"
    second = intake_tosca(tightened, definitions=DEFINITIONS)["business_intent_nodes"][0]
    assert first["@id"] == second["@id"]
    assert first["properties"]["sla_target"]["value"] == "99.95"
    assert second["properties"]["sla_target"]["value"] == "99.99"


def test_one_node_per_policy():
    doc = service()
    doc["topology_template"]["policies"].append(
        {"db-data-residency": {
            "type": "forge.policies.Placement",
            "properties": {"business_owner": "a", "justification": "b",
                           "residency": "eu-west-1"},
            "targets": ["db"],
        }}
    )
    doc["topology_template"]["node_templates"]["db"] = {
        "type": "tosca.nodes.Database", "metadata": {"governs": "workload:pp:db"}}
    nodes = intake_tosca(doc, definitions=DEFINITIONS)["business_intent_nodes"]
    assert len(nodes) == 2
    assert len({n["@id"] for n in nodes}) == 2


def test_governs_edges_are_emitted_from_the_policy_node_outward():
    result = intake_tosca(service(), definitions=DEFINITIONS)
    node = result["business_intent_nodes"][0]
    assert result["edges"] == [
        {"@type": "governs", "from": node["@id"], "to": "kg://edges/v1/abc"},
        {"@type": "governs", "from": node["@id"], "to": "workload:pp:api"},
        {"@type": "governs", "from": node["@id"], "to": "workload:pp:web"},
    ]


def test_governs_unions_the_policy_and_its_targets_metadata():
    doc = service()
    doc["topology_template"]["policies"][0]["web-to-api-availability"]["metadata"] = {
        "governs": "workload:pp:portal"}
    node = intake_tosca(doc, definitions=DEFINITIONS)["business_intent_nodes"][0]
    assert node["governs"] == [
        "kg://edges/v1/abc", "workload:pp:api", "workload:pp:portal", "workload:pp:web",
    ]


def test_a_policy_with_no_type_is_reported_not_silently_dropped():
    doc = service()
    doc["topology_template"]["policies"] = [{"nameless": {"properties": {}}}]
    result = intake_tosca(doc, definitions=DEFINITIONS)
    assert result["business_intent_nodes"] == []
    assert "has no type" in result["gaps"][0]


def test_unresolved_required_property_reaches_the_gap_list_and_the_node():
    doc = service(**{"type": "forge.policies.Placement",
                     "properties": {"business_owner": "a", "justification": "b"},
                     "targets": ["web"]})
    result = intake_tosca(doc, definitions=DEFINITIONS)
    assert result["business_intent_nodes"][0]["unresolved_properties"] == ["residency"]
    assert "would have a hole" in result["gaps"][0]


def test_a_policy_type_absent_from_definitions_is_reported():
    doc = service(**{"type": "forge.policies.Unknown",
                     "properties": {"x": "y"}, "targets": []})
    result = intake_tosca(doc, definitions=DEFINITIONS)
    assert any("not in the supplied definitions" in g for g in result["gaps"])


def test_property_variables_are_computed_not_stored():
    node = intake_tosca(service(), definitions=DEFINITIONS)["business_intent_nodes"][0]
    assert "property_values" not in node
    variables = property_variables(node)
    assert variables["sla_target"] == "99.95"
    assert variables["max_unavailability_minutes"] == 43
    assert variables["multi_region"] is True


def test_the_template_name_can_be_overridden():
    doc = service()
    del doc["metadata"]
    node = intake_tosca(doc, definitions=DEFINITIONS,
                        template_name="explicit")["business_intent_nodes"][0]
    assert node["@id"] == f"{NODE_ID_PREFIX}/explicit/web-to-api-availability"


def test_a_template_with_no_name_is_refused():
    """The GUID needs a stable template name to key on; guessing one would orphan the node
    on the next import."""
    doc = service()
    del doc["metadata"]
    with pytest.raises(ToscaIntakeError, match="template name"):
        intake_tosca(doc, definitions=DEFINITIONS)


def test_policies_as_a_dict_are_also_accepted():
    doc = service()
    doc["topology_template"]["policies"] = {
        "web-to-api-availability": doc["topology_template"]["policies"][0][
            "web-to-api-availability"]}
    nodes = intake_tosca(doc, definitions=DEFINITIONS)["business_intent_nodes"]
    assert nodes[0]["policy_name"] == "web-to-api-availability"


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

def test_a_type_definitions_library_is_refused_by_name():
    """It is a valid --definitions input, not a service template. Reading it to zero
    policies would be indistinguishable from a topology that declares none."""
    with pytest.raises(ToscaIntakeError, match="type-definitions library"):
        service_template(DEFINITIONS)


def test_a_non_tosca_document_is_refused():
    with pytest.raises(ToscaIntakeError, match="not a TOSCA document"):
        service_template({"topology_template": {}})


def test_a_document_with_no_topology_template_is_refused():
    with pytest.raises(ToscaIntakeError, match="no topology_template"):
        service_template({"tosca_definitions_version": "x", "metadata": {}})


def test_a_non_object_topology_template_is_refused():
    with pytest.raises(ToscaIntakeError, match="not an object"):
        service_template({"tosca_definitions_version": "x", "topology_template": []})


def test_a_json_array_on_disk_is_refused(tmp_path):
    bad = tmp_path / "not-tosca.json"
    bad.write_text("[]")
    with pytest.raises(ToscaIntakeError, match="objects, got list"):
        intake_tosca_from_file(bad)


# ---------------------------------------------------------------------------
# Graph integration
# ---------------------------------------------------------------------------

def test_business_intent_nodes_are_walked_by_node_versions():
    """node_versions is the left-hand side of every cross-plane comparison. A node missing
    from that map reads as deleted, and ORPHANED_POLICY would fire on every artifact
    compiled from a perfectly live template."""
    nodes = intake_tosca(service(), definitions=DEFINITIONS)["business_intent_nodes"]
    doc = {"@id": "workload:pp", "node_class": "authored", "plane": "architecture",
           "business_intent_nodes": nodes}
    versions = node_versions([doc])
    assert nodes[0]["@id"] in versions
    assert versions[nodes[0]["@id"]].startswith("sha256:")


def test_a_touched_but_unchanged_template_produces_the_same_node_version():
    def versions():
        nodes = intake_tosca(service(), definitions=DEFINITIONS)["business_intent_nodes"]
        return node_versions([{"@id": "w", "node_class": "authored",
                               "plane": "architecture", "business_intent_nodes": nodes}])
    assert versions() == versions()


# ---------------------------------------------------------------------------
# Files and CLI
# ---------------------------------------------------------------------------

def test_write_nodes_lands_them_under_business_intent(tmp_path):
    nodes = intake_tosca(service(), definitions=DEFINITIONS)["business_intent_nodes"]
    paths = write_business_intent_nodes(nodes, tmp_path)
    assert paths[0].parent.name == "business_intent"
    assert json.loads(paths[0].read_text())["@id"] == nodes[0]["@id"]


def test_intake_from_file_reads_the_shipped_example():
    result = intake_tosca_from_file(
        "examples/tosca/payments-portal-service.json",
        definitions_path="examples/tosca/payments-portal-policy-types.json",
    )
    by_name = {n["policy_name"]: n for n in result["business_intent_nodes"]}
    assert set(by_name) == {"web-to-api-availability", "db-data-residency"}

    avail = by_name["web-to-api-availability"]
    assert avail["@id"] == (
        "kg://tosca/policy/payments-portal/web-to-api-availability")
    # the type default lands where the policy did not override it
    assert avail["properties"]["max_unavailability_minutes"] == {
        "value": 43, "set_by": "policy-type-default", "type": "integer"}
    # the placement policy carries none of the availability type's properties
    assert set(by_name["db-data-residency"]["properties"]) == {
        "business_owner", "justification", "residency", "allowed_regions"}
    assert result["gaps"] == []


def test_cli_writes_business_intent_nodes(tmp_path):
    res = CliRunner().invoke(cli, [
        "intake-tosca",
        "--service-template", "examples/tosca/payments-portal-service.json",
        "--definitions", "examples/tosca/payments-portal-policy-types.json",
        "--output-dir", str(tmp_path),
    ])
    assert res.exit_code == 0, res.output
    assert len(list((tmp_path / "business_intent").glob("*.json"))) == 2
    assert "governs ->" in res.output


def test_cli_exits_nonzero_when_a_required_property_is_left_unresolved(tmp_path):
    doc = service(**{"type": "forge.policies.Placement",
                     "properties": {"business_owner": "a", "justification": "b"},
                     "targets": ["web"]})
    svc = tmp_path / "svc.json"
    defs = tmp_path / "defs.json"
    svc.write_text(json.dumps(doc))
    defs.write_text(json.dumps(DEFINITIONS))
    res = CliRunner().invoke(cli, [
        "intake-tosca", "--service-template", str(svc), "--definitions", str(defs),
        "--output-dir", str(tmp_path / "kg"),
    ])
    assert res.exit_code == 1
    assert "residency" in res.output
    assert len(list((tmp_path / "kg" / "business_intent").glob("*.json"))) == 1


def test_cli_query_finds_business_intent_nodes_by_plane(tmp_path):
    CliRunner().invoke(cli, [
        "intake-tosca",
        "--service-template", "examples/tosca/payments-portal-service.json",
        "--definitions", "examples/tosca/payments-portal-policy-types.json",
        "--output-dir", str(tmp_path),
    ])
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(tmp_path), "--type", "tosca",
        "--plane", "business_intent", "--json",
    ])
    assert res.exit_code == 0, res.output
    assert {r["node"]["policy_name"] for r in json.loads(res.output)} == {
        "web-to-api-availability", "db-data-residency"}


def test_business_intent_nodes_are_absent_from_an_architecture_plane_query(tmp_path):
    CliRunner().invoke(cli, [
        "intake-tosca",
        "--service-template", "examples/tosca/payments-portal-service.json",
        "--definitions", "examples/tosca/payments-portal-policy-types.json",
        "--output-dir", str(tmp_path),
    ])
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(tmp_path), "--type", "tosca",
        "--plane", "architecture", "--json",
    ])
    assert json.loads(res.output) == []
