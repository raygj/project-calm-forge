"""OSCAL intake — MP-16 (ADR-005 §4).

Several behaviours here are the kind a later "cleanup" inverts because the simpler
version looks obviously right. Each is pinned with the reason in the test body:

1. **Profile and control-implementation set-parameters are scoped by the catalog's
   declarations, not applied catalog-wide.** They carry a param-id and no control.
2. **A profile without its catalog is refused**, because there is nothing to scope with.
3. **Unresolved parameters are reported, never defaulted.**
4. **Dotted numerals stay strings.** ``"1.10"`` floated is ``1.1``.
5. **Controls nodes land in the controls plane**, and `controls_nodes` is a container
   `node_versions` walks — otherwise a live catalog reads as deleted.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.intake_oscal import (
    NODE_ID_PREFIX,
    OscalIntakeError,
    catalog_defaults,
    control_node_id,
    intake_oscal,
    intake_oscal_from_file,
    parameter_variables,
    profile_overrides,
    resolve_parameters,
    typed_value,
    write_controls_nodes,
)
from calm_forge.kg_plane import PLANE_CONTROLS, node_versions, validate_node

CATALOG = {
    "catalog": {
        "uuid": "cat-1",
        "groups": [{
            "id": "g1",
            "controls": [
                {
                    "id": "req-3.5.1",
                    "params": [
                        {"id": "allowed-algorithms", "values": ["AES-256", "KMS"]},
                        {"id": "minimum-key-length", "values": ["128"]},
                    ],
                    "controls": [{
                        "id": "req-3.5.1.1",
                        "params": [{"id": "nested-param", "values": ["yes"]}],
                    }],
                },
                {
                    "id": "req-4.2.1",
                    "params": [{"id": "minimum-tls-version", "values": ["1.2"]}],
                },
                {
                    "id": "req-3.6.1",
                    "params": [{
                        "id": "key-rotation-days",
                        "select": {"how-many": "one", "choice": ["90", "365"]},
                    }],
                },
            ],
        }],
    }
}

PROFILE = {
    "profile": {
        "uuid": "prof-1",
        "modify": {"set-parameters": [
            {"param-id": "allowed-algorithms", "values": ["AES-256"]},
            {"param-id": "key-rotation-days", "values": ["90"]},
        ]},
    }
}


def component_definition(**overrides):
    req = {
        "uuid": "req-uuid-1",
        "control-id": "req-3.5.1",
        "description": "encrypted at rest",
    }
    req.update(overrides)
    return {
        "component-definition": {
            "uuid": "cd-1",
            "components": [{
                "uuid": "comp-1",
                "type": "service",
                "title": "database tier",
                "props": [{"name": "governs", "value": "workload:pci:db"}],
                "control-implementations": [{
                    "uuid": "impl-1",
                    "source": "#cat-1",
                    "set-parameters": [{"param-id": "minimum-key-length", "values": ["256"]}],
                    "implemented-requirements": [req],
                }],
            }],
        }
    }


# ---------------------------------------------------------------------------
# Typing
# ---------------------------------------------------------------------------

def test_booleans_and_integers_are_typed():
    assert typed_value(["true"]) is True
    assert typed_value(["FALSE"]) is False
    assert typed_value(["256"]) == 256
    assert typed_value(["-3"]) == -3


def test_dotted_numerals_stay_strings():
    """A control catalog's dotted numeral is a version far more often than a quantity,
    and floating "1.10" yields 1.1 — which then sorts, compares and renders wrong
    everywhere downstream, silently. Casting later loses nothing; guessing loses the
    value."""
    assert typed_value(["1.10"]) == "1.10"
    assert typed_value(["1.2"]) == "1.2"
    assert typed_value(["99.9"]) == "99.9"


def test_zero_padded_numerals_stay_strings():
    """0644 is a file mode and 007 is a code. Neither is a count."""
    assert typed_value(["0644"]) == "0644"
    assert typed_value(["007"]) == "007"


def test_multi_valued_parameters_stay_lists():
    assert typed_value(["AES-256", "KMS"]) == ["AES-256", "KMS"]
    assert typed_value(["1", "2"]) == [1, 2]


# ---------------------------------------------------------------------------
# Catalog and profile reading
# ---------------------------------------------------------------------------

def test_catalog_defaults_flatten_nested_groups_and_controls():
    defaults = catalog_defaults(CATALOG)
    assert defaults["req-3.5.1"]["allowed-algorithms"] == ["AES-256", "KMS"]
    assert defaults["req-3.5.1.1"]["nested-param"] == ["yes"]


def test_a_select_only_param_has_no_default():
    """Picking a value out of the constraint list would be Forge authoring a control
    decision. The param is declared with no default, which is what makes it surface as
    unresolved instead of as an arbitrary choice."""
    assert catalog_defaults(CATALOG)["req-3.6.1"]["key-rotation-days"] == []


def test_profile_overrides_read_modify_set_parameters():
    assert profile_overrides(PROFILE)["allowed-algorithms"] == ["AES-256"]


# ---------------------------------------------------------------------------
# Resolution order and scope
# ---------------------------------------------------------------------------

def test_strongest_layer_wins_and_records_itself():
    resolved, _ = resolve_parameters(
        "req-3.5.1",
        catalog_defaults=catalog_defaults(CATALOG),
        profile_overrides=profile_overrides(PROFILE),
        implementation_params={"minimum-key-length": ["256"]},
        requirement_params={"allowed-algorithms": ["KMS"]},
    )
    assert resolved["allowed-algorithms"]["set_by"] == "implemented-requirement"
    assert resolved["allowed-algorithms"]["value"] == "KMS"
    assert resolved["minimum-key-length"]["set_by"] == "component-implementation"
    assert resolved["minimum-key-length"]["value"] == 256


def test_the_raw_values_survive_alongside_the_typed_one():
    """Typing is a convenience for generators. The audit answer is what the catalog
    literally said."""
    resolved, _ = resolve_parameters(
        "req-3.5.1", catalog_defaults=catalog_defaults(CATALOG),
    )
    assert resolved["minimum-key-length"]["raw"] == ["128"]
    assert resolved["minimum-key-length"]["value"] == 128


def test_profile_parameters_do_not_leak_onto_controls_that_never_declared_them():
    """The load-bearing scoping rule. Profile set-parameters name a param-id and no
    control, so applying them wholesale attaches a key-rotation value to a TLS control —
    and the generated policy then carries a variable the catalog never scoped there.
    The catalog's declarations for the control ARE the scope."""
    resolved, _ = resolve_parameters(
        "req-4.2.1",
        catalog_defaults=catalog_defaults(CATALOG),
        profile_overrides=profile_overrides(PROFILE),
    )
    assert "key-rotation-days" not in resolved
    assert "allowed-algorithms" not in resolved
    assert set(resolved) == {"minimum-tls-version"}


def test_implementation_parameters_are_scoped_the_same_way():
    resolved, _ = resolve_parameters(
        "req-4.2.1",
        catalog_defaults=catalog_defaults(CATALOG),
        implementation_params={"minimum-key-length": ["256"]},
    )
    assert "minimum-key-length" not in resolved


def test_the_requirement_layer_is_exempt_from_scoping():
    """set-parameters on an implemented-requirement is written against exactly one
    requirement. It cannot be misdirected, so it applies even when the catalog does not
    declare the param — refusing it would discard the most specific statement in the
    document."""
    resolved, _ = resolve_parameters(
        "req-4.2.1",
        catalog_defaults=catalog_defaults(CATALOG),
        requirement_params={"vendor-specific-knob": ["on"]},
    )
    assert resolved["vendor-specific-knob"]["value"] == "on"


def test_with_no_catalog_the_implementation_supplies_its_own_scope():
    resolved, unresolved = resolve_parameters(
        "req-4.2.1", implementation_params={"minimum-tls-version": ["1.3"]},
    )
    assert resolved["minimum-tls-version"]["value"] == "1.3"
    assert unresolved == []


def test_a_declared_parameter_nobody_resolves_is_reported_not_defaulted():
    resolved, unresolved = resolve_parameters(
        "req-3.6.1", catalog_defaults=catalog_defaults(CATALOG),
    )
    assert unresolved == ["key-rotation-days"]
    assert resolved == {}


def test_the_profile_can_resolve_what_the_catalog_left_open():
    resolved, unresolved = resolve_parameters(
        "req-3.6.1",
        catalog_defaults=catalog_defaults(CATALOG),
        profile_overrides=profile_overrides(PROFILE),
    )
    assert unresolved == []
    assert resolved["key-rotation-days"] == {
        "value": 90, "raw": ["90"], "set_by": "profile",
    }


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def test_nodes_land_in_the_controls_plane():
    """Never architecture. A controls node in the architecture plane is invisible to
    every cross-plane finding, which is what ADR-005's no-default plane rule exists to
    prevent."""
    result = intake_oscal(component_definition(), catalog=CATALOG)
    node = result["controls_nodes"][0]
    assert node["plane"] == PLANE_CONTROLS
    assert node["node_class"] == "authored"
    assert validate_node(node) == []


def test_node_id_follows_the_scheme_and_is_keyed_on_the_requirement_uuid():
    node = intake_oscal(component_definition(), catalog=CATALOG)["controls_nodes"][0]
    assert node["@id"] == f"{NODE_ID_PREFIX}/req-3.5.1/req-uuid-1"
    assert control_node_id("req-3.5.1", "req-uuid-1") == node["@id"]


def test_re_running_intake_against_an_updated_catalog_updates_rather_than_orphans():
    """Keyed on the requirement uuid, which OSCAL keeps stable across catalog re-issues.
    An id that moved on every import would make ORPHANED_POLICY fire on routine
    re-intake, which is exactly the signal it must not produce."""
    first = intake_oscal(component_definition(), catalog=CATALOG)["controls_nodes"][0]
    tightened = json.loads(json.dumps(CATALOG))
    tightened["catalog"]["groups"][0]["controls"][0]["params"][0]["values"] = ["AES-256"]
    second = intake_oscal(component_definition(), catalog=tightened)["controls_nodes"][0]

    assert first["@id"] == second["@id"]
    assert first["parameters"]["allowed-algorithms"]["value"] == ["AES-256", "KMS"]
    assert second["parameters"]["allowed-algorithms"]["value"] == "AES-256"


def test_one_node_per_implemented_requirement_not_per_control():
    """Two components can implement the same control differently. Collapsing them loses
    the component that actually carries the obligation."""
    cd = component_definition()
    impl = cd["component-definition"]["components"][0]["control-implementations"][0]
    impl["implemented-requirements"].append(
        {"uuid": "req-uuid-2", "control-id": "req-3.5.1"}
    )
    nodes = intake_oscal(cd, catalog=CATALOG)["controls_nodes"]
    assert len(nodes) == 2
    assert len({n["@id"] for n in nodes}) == 2


def test_governs_edges_are_emitted_from_the_controls_node_outward():
    result = intake_oscal(component_definition(), catalog=CATALOG)
    node = result["controls_nodes"][0]
    assert result["edges"] == [
        {"@type": "governs", "from": node["@id"], "to": "workload:pci:db"}
    ]


def test_governs_unions_component_implementation_and_requirement_props():
    cd = component_definition(props=[{"name": "governs", "value": "kg://edges/v1/abc"}])
    node = intake_oscal(cd, catalog=CATALOG)["controls_nodes"][0]
    assert node["governs"] == ["kg://edges/v1/abc", "workload:pci:db"]


def test_a_requirement_with_no_control_id_is_reported_not_silently_dropped():
    cd = component_definition()
    cd["component-definition"]["components"][0]["control-implementations"][0][
        "implemented-requirements"
    ] = [{"uuid": "orphan"}]
    result = intake_oscal(cd, catalog=CATALOG)
    assert result["controls_nodes"] == []
    assert "has no control-id" in result["gaps"][0]


def test_unresolved_parameters_reach_the_gap_list_and_the_node():
    cd = component_definition(**{"control-id": "req-3.6.1"})
    result = intake_oscal(cd, catalog=CATALOG)
    assert result["controls_nodes"][0]["unresolved_parameters"] == ["key-rotation-days"]
    assert "would have a hole" in result["gaps"][0]


def test_parameter_variables_are_computed_not_stored():
    """A second copy of the same fact is a second thing that can go stale."""
    node = intake_oscal(component_definition(), catalog=CATALOG)["controls_nodes"][0]
    assert "parameter_values" not in node
    assert parameter_variables(node) == {
        "allowed-algorithms": ["AES-256", "KMS"], "minimum-key-length": 256,
    }


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

def test_a_profile_without_its_catalog_is_refused():
    """Not applied unscoped, and not silently ignored either. The profile's whole content
    is set-parameters keyed by param-id with no control attached."""
    with pytest.raises(OscalIntakeError, match="without its catalog"):
        intake_oscal(component_definition(), profile=PROFILE)


@pytest.mark.parametrize("model", [
    "system-security-plan", "assessment-results", "plan-of-action-and-milestones",
])
def test_unsupported_oscal_models_are_refused_by_name(model):
    """Parsing an SSP to an empty result is indistinguishable from a document with no
    controls in it. MP-16 covers component-definition plus catalog/profile only, and
    partial support that reads as complete is worse than no support."""
    with pytest.raises(OscalIntakeError, match=model):
        intake_oscal({model: {"uuid": "x"}})


def test_a_document_that_is_not_a_component_definition_is_refused():
    with pytest.raises(OscalIntakeError, match="component-definition"):
        intake_oscal({"catalog": {"uuid": "x"}})


def test_a_non_object_root_is_refused():
    with pytest.raises(OscalIntakeError, match="not an object"):
        intake_oscal({"component-definition": []})


# ---------------------------------------------------------------------------
# Graph integration
# ---------------------------------------------------------------------------

def test_controls_nodes_are_walked_by_node_versions():
    """`node_versions` is the left-hand side of every cross-plane comparison. A controls
    node missing from that map reads as *deleted*, and ORPHANED_POLICY would fire on
    every artifact compiled from a perfectly live catalog."""
    nodes = intake_oscal(component_definition(), catalog=CATALOG)["controls_nodes"]
    doc = {"@id": "workload:pci", "node_class": "authored", "plane": "architecture",
           "controls_nodes": nodes}
    versions = node_versions([doc])
    assert nodes[0]["@id"] in versions
    assert versions[nodes[0]["@id"]].startswith("sha256:")


def test_a_touched_but_unchanged_catalog_produces_the_same_node_version():
    """Identity by content, not by clock — the same discipline the drift evaluator
    depends on, verified end to end from OSCAL."""
    def versions():
        nodes = intake_oscal(component_definition(), catalog=CATALOG)["controls_nodes"]
        return node_versions([{"@id": "w", "node_class": "authored",
                               "plane": "architecture", "controls_nodes": nodes}])
    assert versions() == versions()


# ---------------------------------------------------------------------------
# Files and CLI
# ---------------------------------------------------------------------------

def test_write_controls_nodes_lands_them_under_controls(tmp_path):
    nodes = intake_oscal(component_definition(), catalog=CATALOG)["controls_nodes"]
    paths = write_controls_nodes(nodes, tmp_path)
    assert paths[0].parent.name == "controls"
    assert json.loads(paths[0].read_text())["@id"] == nodes[0]["@id"]


def test_intake_from_file_reads_the_shipped_example():
    result = intake_oscal_from_file(
        "examples/oscal/pci-component-definition.json",
        catalog_path="examples/oscal/pci-catalog.json",
        profile_path="examples/oscal/pci-profile.json",
    )
    by_control = {n["control_id"]: n for n in result["controls_nodes"]}
    assert set(by_control) == {"req-3.5.1", "req-3.6.1", "req-4.2.1"}
    assert by_control["req-3.5.1"]["parameters"]["allowed-encryption-algorithms"] == {
        "value": "AES-256", "raw": ["AES-256"], "set_by": "profile",
    }
    # the TLS control carries no stored-data parameters
    assert set(by_control["req-4.2.1"]["parameters"]) == {
        "minimum-tls-version", "mutual-tls-required",
    }
    assert result["gaps"] == []


def test_cli_writes_controls_nodes(tmp_path):
    res = CliRunner().invoke(cli, [
        "intake-oscal",
        "--component-definition", "examples/oscal/pci-component-definition.json",
        "--catalog", "examples/oscal/pci-catalog.json",
        "--profile", "examples/oscal/pci-profile.json",
        "--output-dir", str(tmp_path),
    ])
    assert res.exit_code == 0, res.output
    assert len(list((tmp_path / "controls").glob("*.json"))) == 3
    assert "governs ->" in res.output


def test_cli_exits_nonzero_when_a_parameter_is_left_unresolved(tmp_path):
    """The nodes are still written — the catalog is what it is — but a policy generated
    from an unresolved parameter has a hole, and that must not pass a pipeline
    silently."""
    res = CliRunner().invoke(cli, [
        "intake-oscal",
        "--component-definition", "examples/oscal/pci-component-definition.json",
        "--catalog", "examples/oscal/pci-catalog.json",
        "--output-dir", str(tmp_path),
    ])
    assert res.exit_code == 1
    assert "key-rotation-days" in res.output
    assert len(list((tmp_path / "controls").glob("*.json"))) == 3


def test_cli_query_finds_controls_nodes_by_plane(tmp_path):
    CliRunner().invoke(cli, [
        "intake-oscal",
        "--component-definition", "examples/oscal/pci-component-definition.json",
        "--catalog", "examples/oscal/pci-catalog.json",
        "--profile", "examples/oscal/pci-profile.json",
        "--output-dir", str(tmp_path),
    ])
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(tmp_path), "--type", "control",
        "--plane", "controls", "--json",
    ])
    assert res.exit_code == 0, res.output
    assert {r["node"]["control_id"] for r in json.loads(res.output)} == {
        "req-3.5.1", "req-3.6.1", "req-4.2.1",
    }


def test_controls_nodes_are_absent_from_an_architecture_plane_query(tmp_path):
    CliRunner().invoke(cli, [
        "intake-oscal",
        "--component-definition", "examples/oscal/pci-component-definition.json",
        "--catalog", "examples/oscal/pci-catalog.json",
        "--profile", "examples/oscal/pci-profile.json",
        "--output-dir", str(tmp_path),
    ])
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(tmp_path), "--type", "control",
        "--plane", "architecture", "--json",
    ])
    assert json.loads(res.output) == []


def test_a_pre_typed_parameter_value_passes_through():
    """OSCAL carries strings, but a hand-built or pre-processed document may already
    hold a number. Coercion must not choke on what it does not need to coerce."""
    assert typed_value([256]) == 256
    assert typed_value([None]) is None


def test_a_prop_with_no_name_is_skipped_rather_than_keyed_on_none():
    cd = component_definition(props=[{"value": "workload:pci:nameless"}])
    node = intake_oscal(cd, catalog=CATALOG)["controls_nodes"][0]
    assert node["governs"] == ["workload:pci:db"]


def test_a_catalog_param_with_no_id_is_skipped():
    catalog = json.loads(json.dumps(CATALOG))
    catalog["catalog"]["groups"][0]["controls"][1]["params"].append({"values": ["x"]})
    assert set(catalog_defaults(catalog)["req-4.2.1"]) == {"minimum-tls-version"}


def test_a_json_array_on_disk_is_refused_as_an_oscal_document(tmp_path):
    bad = tmp_path / "not-oscal.json"
    bad.write_text("[]")
    with pytest.raises(OscalIntakeError, match="objects, got list"):
        intake_oscal_from_file(bad)
