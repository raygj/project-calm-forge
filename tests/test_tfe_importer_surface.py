"""Surface tests for tfe_importer — the brownfield TFE → CALM import path.

These cover the pure transform functions that consume raw Terraform Enterprise
state (no live TFE client needed): state-resource parsing, import-block
generation, id sanitisation, and the migration plan. The network-backed
TFEClient methods are out of scope here.
"""

from __future__ import annotations

from calm_forge.tfe_importer import (
    _parse_state_resources,
    _sanitize_id,
    generate_import_blocks,
    generate_migration_plan,
)

# ---------------------------------------------------------------------------
# _parse_state_resources — raw tfstate JSON → flat resource records
# ---------------------------------------------------------------------------


def test_parse_state_resources_flattens_instances():
    raw = {
        "resources": [
            {"type": "aws_instance", "name": "web", "provider": "provider[\"aws\"]",
             "instances": [{"attributes": {"id": "i-abc123"}}]},
            {"type": "aws_db_instance", "name": "db", "module": "module.data",
             "instances": [{"attributes": {"id": "db-xyz"}}]},
        ]
    }
    parsed = _parse_state_resources(raw)

    assert len(parsed) == 2
    web = next(r for r in parsed if r["name"] == "web")
    assert web["type"] == "aws_instance"
    assert web["address"] == "aws_instance.web"
    assert web["id"] == "i-abc123"


def test_parse_state_resources_prefixes_module_in_address():
    raw = {
        "resources": [
            {"type": "aws_db_instance", "name": "db", "module": "module.data",
             "instances": [{"attributes": {"id": "db-xyz"}}]},
        ]
    }
    parsed = _parse_state_resources(raw)
    assert parsed[0]["address"] == "module.data.aws_db_instance.db"


def test_parse_state_resources_tolerates_missing_attributes():
    """A resource instance with no attributes must not crash the parse — it
    yields an empty id, which the import-block path then skips."""
    raw = {"resources": [{"type": "aws_instance", "name": "web", "instances": [{}]}]}
    parsed = _parse_state_resources(raw)
    assert parsed[0]["id"] == ""


def test_parse_state_resources_empty_state_is_empty_list():
    assert _parse_state_resources({}) == []


# ---------------------------------------------------------------------------
# _sanitize_id — CALM hyphenated id → HCL-safe underscore id
# ---------------------------------------------------------------------------


def test_sanitize_id_replaces_non_word_characters():
    assert _sanitize_id("web-service") == "web_service"
    assert _sanitize_id("payments.api/v2") == "payments_api_v2"


def test_sanitize_id_leaves_valid_identifiers_untouched():
    assert _sanitize_id("already_valid_1") == "already_valid_1"


# ---------------------------------------------------------------------------
# generate_import_blocks — declarative Terraform import blocks
#
# The load-bearing contract: `to` is the ORIGINAL workspace resource address,
# verbatim — the same form generator._generate_import_blocks_from_calm emits.
# A component-prefixed address would not exist in the generated Stacks config
# and the import would silently fail to bind.
# ---------------------------------------------------------------------------


def _workspace(name, resources):
    return {"name": name, "resources": resources}


def test_import_block_to_is_the_raw_workspace_address():
    ws = _workspace("payments-prod", [
        {"type": "aws_instance", "name": "web", "address": "aws_instance.web", "id": "i-abc"},
    ])
    out = generate_import_blocks([ws])

    assert "  to = aws_instance.web" in out
    assert '  id = "i-abc"' in out
    # The component-prefixed form must NOT appear — that was the discarded draft.
    assert "component." not in out


def test_import_block_skips_resources_with_no_id():
    """A resource with no id in state can't be imported — emit a visible SKIP
    comment rather than a broken import block."""
    ws = _workspace("payments-prod", [
        {"type": "aws_instance", "name": "web", "address": "aws_instance.web", "id": ""},
    ])
    out = generate_import_blocks([ws])

    assert "# SKIP: aws_instance.web" in out
    assert "import {" not in out


def test_import_blocks_are_grouped_by_workspace():
    out = generate_import_blocks([
        _workspace("ws-a", [{"type": "aws_instance", "name": "a",
                             "address": "aws_instance.a", "id": "i-a"}]),
        _workspace("ws-b", [{"type": "aws_s3_bucket", "name": "b",
                             "address": "aws_s3_bucket.b", "id": "b-b"}]),
    ])
    assert "# --- Imports from workspace: ws-a ---" in out
    assert "# --- Imports from workspace: ws-b ---" in out


# ---------------------------------------------------------------------------
# generate_migration_plan — human-readable cutover doc
# ---------------------------------------------------------------------------


def test_migration_plan_summarises_workspaces_and_clusters():
    workspaces = [
        _workspace("ws-a", [{"type": "aws_instance", "name": "a",
                            "address": "aws_instance.a", "id": "i-a"}]),
    ]
    clusters = [{
        "proposed_name": "web-service",
        "workspaces": ["ws-a"],
        "environments": ["prod"],
        "total_resources": 1,
        "tags": ["pci"],
        "resource_summary": {"aws_instance": 1},
    }]
    plan = generate_migration_plan(workspaces, clusters)

    assert "# Workspace → Stacks Migration Plan" in plan
    assert "**Workspaces:** 1" in plan
    assert "**Total Resources:** 1" in plan
    assert "web-service" in plan
    assert "aws_instance: 1" in plan
