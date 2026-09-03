"""tfpolicy emitter — pins the canonical mapping, the authority bridge, and goldens.

The ADR names this file: regression on any predicate → tfpolicy translation drift.
"""

from __future__ import annotations

from pathlib import Path

from calm_forge.generator import generate_stack
from calm_forge.hcl_validator import validate_hcl_syntax
from calm_forge.tfpolicy_writer import (
    PREDICATE_COST_GOVERNANCE,
    PREDICATE_DATA_CLASSIFICATION_TAG,
    PREDICATE_ENCRYPTION_AT_REST,
    PREDICATE_NO_PUBLIC_ENDPOINTS,
    enforcement_level_for_authority,
    predicates_for,
    write_tfpolicy_policies,
    write_tfpolicy_tests,
)

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "fsi-3tier"
EXPECTED_DIR = EXAMPLES_DIR / "expected-output"

_PCI_CONFIDENTIAL = {
    "application-name": "payments-portal",
    "compliance-scope": "pci-dss",
    "data-classification": "confidential",
}
_GENERAL_INTERNAL = {
    "application-name": "reporting",
    "compliance-scope": "general",
    "data-classification": "internal",
}


# ---------------------------------------------------------------------------
# The APP bridge — authority_class → enforcement_level (canonical, normative)
# ---------------------------------------------------------------------------

def test_authority_class_maps_to_enforcement_level():
    # governed-expansion is irreversible → must block
    assert enforcement_level_for_authority("governed-expansion") == "mandatory"
    # autonomic-contraction is reversible → a warning is acceptable
    assert enforcement_level_for_authority("autonomic-contraction") == "advisory"


def test_unknown_authority_defaults_to_soft_mandatory():
    assert enforcement_level_for_authority(None) == "soft-mandatory"
    assert enforcement_level_for_authority("something-new") == "soft-mandatory"


# ---------------------------------------------------------------------------
# predicates_for — the shared vocabulary that makes parity provable
# ---------------------------------------------------------------------------

def test_pci_confidential_enforces_all_four_predicates():
    preds = predicates_for(_PCI_CONFIDENTIAL)
    assert preds == [
        PREDICATE_ENCRYPTION_AT_REST,
        PREDICATE_NO_PUBLIC_ENDPOINTS,
        PREDICATE_COST_GOVERNANCE,
        PREDICATE_DATA_CLASSIFICATION_TAG,
    ]


def test_general_internal_enforces_only_cost():
    # no pci → no encryption/public-endpoint; not confidential → no tag; cost always
    assert predicates_for(_GENERAL_INTERNAL) == [PREDICATE_COST_GOVERNANCE]


# ---------------------------------------------------------------------------
# Emission — structure, beta tagging, validity
# ---------------------------------------------------------------------------

def test_policies_include_a_block_per_predicate():
    hcl = write_tfpolicy_policies(_PCI_CONFIDENTIAL)
    assert 'policy "enforce_encryption_at_rest"' in hcl
    assert 'policy "deny_public_endpoints"' in hcl
    assert 'policy "cost_advisory"' in hcl
    assert 'policy "require_data_classification_tag"' in hcl
    # compliance predicates block; cost tiers span advisory→mandatory
    assert 'enforcement_level = "mandatory"' in hcl
    assert 'enforcement_level = "advisory"' in hcl
    assert 'enforcement_level = "soft-mandatory"' in hcl


def test_emitted_policies_are_beta_tagged():
    assert "[BETA" in write_tfpolicy_policies(_PCI_CONFIDENTIAL)
    assert "[BETA" in write_tfpolicy_tests(_PCI_CONFIDENTIAL)


def test_non_pci_omits_compliance_policies():
    hcl = write_tfpolicy_policies(_GENERAL_INTERNAL)
    assert "enforce_encryption_at_rest" not in hcl
    assert "deny_public_endpoints" not in hcl
    assert "require_data_classification_tag" not in hcl
    assert 'policy "cost_advisory"' in hcl  # cost still present


def test_tests_track_the_emitted_policies():
    tests = write_tfpolicy_tests(_PCI_CONFIDENTIAL)
    # a test exists for exactly the policies emitted — agreement by construction
    assert "enforce_encryption_at_rest_passes" in tests
    assert "require_data_classification_tag_passes" in tests
    general = write_tfpolicy_tests(_GENERAL_INTERNAL)
    assert "enforce_encryption_at_rest_passes" not in general
    assert "cost_advisory_passes" in general


def test_emitted_hcl_passes_the_syntax_gate():
    assert validate_hcl_syntax(write_tfpolicy_policies(_PCI_CONFIDENTIAL)) == []
    assert validate_hcl_syntax(write_tfpolicy_tests(_PCI_CONFIDENTIAL)) == []


# ---------------------------------------------------------------------------
# Byte-for-byte golden (mirrors the Sentinel roundtrip)
# ---------------------------------------------------------------------------

def test_tfpolicy_roundtrip(tmp_path):
    files = generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
        full=True, policy_framework="tfpolicy",
    )
    for name in ("policies.policy.hcl", "policies.policytest.hcl"):
        actual = (tmp_path / "tfpolicy" / name).read_text()
        expected = (EXPECTED_DIR / "tfpolicy" / name).read_text()
        assert actual == expected, f"{name} drifted from golden"
    # tfpolicy selected → sentinel not emitted
    assert "tfpolicy/policies.policy.hcl" in files
    assert "sentinel/policies.sentinel" not in files


def test_generate_default_framework_is_sentinel_only(tmp_path):
    """Back-compat: --full with no framework flag emits sentinel, not tfpolicy."""
    files = generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
        full=True,
    )
    assert "sentinel/policies.sentinel" in files
    assert not any(k.startswith("tfpolicy/") for k in files)


def test_generate_all_emits_both_frameworks(tmp_path):
    files = generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
        full=True, policy_framework="all",
    )
    assert "sentinel/policies.sentinel" in files
    assert "tfpolicy/policies.policy.hcl" in files
    assert "tfpolicy/policies.policytest.hcl" in files
