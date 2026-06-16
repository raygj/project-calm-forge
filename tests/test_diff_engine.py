"""Tests for diff_engine.py — CALM structural diff and impact classification."""

from calm_forge.diff_engine import diff_calm

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_calm(nodes=None, relationships=None, metadata=None):
    return {
        "nodes": nodes or [],
        "relationships": relationships or [],
        "metadata": metadata or {"application-name": "test-app"},
    }


NODE_A = {
    "unique-id": "svc-a",
    "node-type": "service",
    "name": "Service A",
    "engine": "python",
}

NODE_B = {
    "unique-id": "svc-b",
    "node-type": "database",
    "name": "Database B",
    "engine": "postgresql",
}

NODE_A_MODIFIED = {
    "unique-id": "svc-a",
    "node-type": "service",
    "name": "Service A (renamed)",  # non-breaking field change
    "engine": "python",
}

NODE_A_TYPE_CHANGED = {
    "unique-id": "svc-a",
    "node-type": "database",  # breaking: node-type changed
    "name": "Service A",
    "engine": "python",
}

REL_1 = {
    "unique-id": "rel-1",
    "protocol": "HTTPS",
    "authentication": "mTLS-vault-pki",
    "relationship-type": {
        "connects": {
            "source": {"node": "svc-a"},
            "destination": {"node": "svc-b"},
        }
    },
}


# ---------------------------------------------------------------------------
# Test: identical specs → impact=none
# ---------------------------------------------------------------------------

def test_identical_specs_impact_none():
    calm = _make_calm(nodes=[NODE_A, NODE_B], relationships=[REL_1])
    result = diff_calm(calm, calm)
    assert result["impact"] == "none"
    assert result["nodes"]["added"] == []
    assert result["nodes"]["removed"] == []
    assert result["nodes"]["modified"] == []
    assert result["relationships"]["added"] == []
    assert result["relationships"]["removed"] == []
    assert result["relationships"]["modified"] == []


def test_identical_specs_all_counts_zero():
    calm = _make_calm(nodes=[NODE_A])
    result = diff_calm(calm, calm)
    tf = result["estimated_terraform"]
    assert tf["creates"] == 0
    assert tf["updates"] == 0
    assert tf["destroys"] == 0


def test_identical_specs_opa_not_required():
    calm = _make_calm(nodes=[NODE_A])
    result = diff_calm(calm, calm)
    assert result["opa_revalidation_required"] is False


# ---------------------------------------------------------------------------
# Test: add a node → impact=additive, creates=1
# ---------------------------------------------------------------------------

def test_add_node_impact_additive():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A, NODE_B])
    result = diff_calm(before, after)
    assert result["impact"] == "additive"
    assert len(result["nodes"]["added"]) == 1
    assert result["nodes"]["added"][0]["unique-id"] == "svc-b"
    assert result["nodes"]["removed"] == []


def test_add_node_creates_count():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A, NODE_B])
    result = diff_calm(before, after)
    assert result["estimated_terraform"]["creates"] == 1
    assert result["estimated_terraform"]["destroys"] == 0


# ---------------------------------------------------------------------------
# Test: remove a node → impact=breaking, destroys=1
# ---------------------------------------------------------------------------

def test_remove_node_impact_breaking():
    before = _make_calm(nodes=[NODE_A, NODE_B])
    after = _make_calm(nodes=[NODE_A])
    result = diff_calm(before, after)
    assert result["impact"] == "breaking"
    assert len(result["nodes"]["removed"]) == 1
    assert result["nodes"]["removed"][0]["unique-id"] == "svc-b"


def test_remove_node_destroys_count():
    before = _make_calm(nodes=[NODE_A, NODE_B])
    after = _make_calm(nodes=[NODE_A])
    result = diff_calm(before, after)
    assert result["estimated_terraform"]["destroys"] == 1
    assert result["estimated_terraform"]["creates"] == 0


# ---------------------------------------------------------------------------
# Test: modify a non-breaking field → impact=mutative
# ---------------------------------------------------------------------------

def test_modify_non_breaking_field_impact_mutative():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A_MODIFIED])
    result = diff_calm(before, after)
    assert result["impact"] == "mutative"
    assert len(result["nodes"]["modified"]) == 1
    mod = result["nodes"]["modified"][0]
    assert mod["before"]["unique-id"] == "svc-a"
    assert mod["after"]["name"] == "Service A (renamed)"


def test_modify_non_breaking_field_updates_count():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A_MODIFIED])
    result = diff_calm(before, after)
    assert result["estimated_terraform"]["updates"] == 1
    assert result["estimated_terraform"]["creates"] == 0
    assert result["estimated_terraform"]["destroys"] == 0


def test_mutative_opa_required():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A_MODIFIED])
    result = diff_calm(before, after)
    assert result["opa_revalidation_required"] is True


# ---------------------------------------------------------------------------
# Test: change node-type → impact=breaking, compliance_changes populated
# ---------------------------------------------------------------------------

def test_change_node_type_impact_breaking():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A_TYPE_CHANGED])
    result = diff_calm(before, after)
    assert result["impact"] == "breaking"


def test_change_node_type_compliance_changes():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A_TYPE_CHANGED])
    result = diff_calm(before, after)
    assert len(result["compliance_changes"]) >= 1
    cc = next(c for c in result["compliance_changes"] if c["field"] == "node-type")
    assert cc["element"] == "svc-a"
    assert cc["kind"] == "node"
    assert cc["before"] == "service"
    assert cc["after"] == "database"


def test_change_node_type_opa_required():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A_TYPE_CHANGED])
    result = diff_calm(before, after)
    assert result["opa_revalidation_required"] is True


# ---------------------------------------------------------------------------
# Test: add + remove simultaneously → impact=breaking takes priority
# ---------------------------------------------------------------------------

def test_add_and_remove_impact_breaking():
    """Adding and removing at same time → breaking (removal wins)."""
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_B])  # A removed, B added
    result = diff_calm(before, after)
    assert result["impact"] == "breaking"
    assert len(result["nodes"]["added"]) == 1
    assert len(result["nodes"]["removed"]) == 1
    assert result["estimated_terraform"]["creates"] == 1
    assert result["estimated_terraform"]["destroys"] == 1


# ---------------------------------------------------------------------------
# Test: metadata changes captured
# ---------------------------------------------------------------------------

def test_metadata_changes_captured():
    before = _make_calm(metadata={"application-name": "app-v1", "team": "payments"})
    after = _make_calm(metadata={"application-name": "app-v2", "team": "payments"})
    result = diff_calm(before, after)
    assert "application-name" in result["metadata"]["changed"]
    chg = result["metadata"]["changed"]["application-name"]
    assert chg["before"] == "app-v1"
    assert chg["after"] == "app-v2"
    # unchanged field should not appear
    assert "team" not in result["metadata"]["changed"]


def test_metadata_no_changes_empty():
    calm = _make_calm(metadata={"application-name": "app"})
    result = diff_calm(calm, calm)
    assert result["metadata"]["changed"] == {}


# ---------------------------------------------------------------------------
# Test: summary string format
# ---------------------------------------------------------------------------

def test_summary_format_breaking_remove():
    before = _make_calm(nodes=[NODE_A, NODE_B])
    after = _make_calm(nodes=[NODE_A])
    result = diff_calm(before, after)
    assert result["summary"].startswith("[BREAKING]")
    assert "-1 node(s)" in result["summary"]


def test_summary_format_additive():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A, NODE_B])
    result = diff_calm(before, after)
    assert result["summary"].startswith("[ADDITIVE]")
    assert "+1 node(s)" in result["summary"]


def test_summary_format_none():
    calm = _make_calm(nodes=[NODE_A])
    result = diff_calm(calm, calm)
    assert result["summary"].startswith("[NONE]")
    assert "no changes" in result["summary"]


def test_summary_format_mutative():
    before = _make_calm(nodes=[NODE_A])
    after = _make_calm(nodes=[NODE_A_MODIFIED])
    result = diff_calm(before, after)
    assert result["summary"].startswith("[MUTATIVE]")
    assert "modified" in result["summary"]


# ---------------------------------------------------------------------------
# Test: opa_revalidation_required for breaking
# ---------------------------------------------------------------------------

def test_breaking_opa_required():
    before = _make_calm(nodes=[NODE_A, NODE_B])
    after = _make_calm(nodes=[NODE_A])
    result = diff_calm(before, after)
    assert result["opa_revalidation_required"] is True


# ---------------------------------------------------------------------------
# Test: relationship changes
# ---------------------------------------------------------------------------

def test_add_relationship_impact_additive():
    before = _make_calm(nodes=[NODE_A, NODE_B], relationships=[])
    after = _make_calm(nodes=[NODE_A, NODE_B], relationships=[REL_1])
    result = diff_calm(before, after)
    assert result["impact"] == "additive"
    assert result["estimated_terraform"]["creates"] == 1


def test_remove_relationship_impact_breaking():
    before = _make_calm(nodes=[NODE_A, NODE_B], relationships=[REL_1])
    after = _make_calm(nodes=[NODE_A, NODE_B], relationships=[])
    result = diff_calm(before, after)
    assert result["impact"] == "breaking"
    assert result["estimated_terraform"]["destroys"] == 1


# ---------------------------------------------------------------------------
# Test: compliance fields in relationships
# ---------------------------------------------------------------------------

def test_relationship_auth_change_compliance():
    rel_modified = {**REL_1, "authentication": "basic"}
    before = _make_calm(relationships=[REL_1])
    after = _make_calm(relationships=[rel_modified])
    result = diff_calm(before, after)
    cc = [c for c in result["compliance_changes"] if c["field"] == "authentication"]
    assert len(cc) == 1
    assert cc[0]["element"] == "rel-1"
    assert cc[0]["kind"] == "relationship"
    assert cc[0]["before"] == "mTLS-vault-pki"
    assert cc[0]["after"] == "basic"
