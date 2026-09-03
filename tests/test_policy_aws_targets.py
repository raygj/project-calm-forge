"""AWS resource-type ratification (ADR §5) — Sentinel + tfpolicy target AWS resources.

When a stack's ``cloud-provider`` is AWS, both emitters must reference AWS resource types
(not the azurerm/kubernetes default), driven by the shared policy_targets map so they can't
drift. The two version-sensitive rows (S3 SSE, security-group ingress) are asserted to be
present as TODO(aws-sme) markers, not guessed resource rules.
"""

from __future__ import annotations

from calm_forge.hcl_validator import validate_hcl_syntax
from calm_forge.policy_targets import (
    AWS_ENCRYPTION_AT_REST,
    AWS_NO_PUBLIC_ENDPOINTS,
    cloud_provider_of,
)
from calm_forge.sentinel_writer import write_sentinel_policies
from calm_forge.tfpolicy_writer import write_tfpolicy_policies, write_tfpolicy_tests

_PCI = {
    "application-name": "payments-portal",
    "compliance-scope": "pci-dss",
    "data-classification": "confidential",
}
_AWS = [{"data": {"cloud-provider": "aws"}}]
_AZURE = [{"data": {"cloud-provider": "azure"}}]

# The ratified, stable AWS resource types (High-confidence rows).
_AWS_TYPES = {"aws_ebs_volume", "aws_db_instance", "aws_lb"}


# ---------------------------------------------------------------------------
# provider resolution
# ---------------------------------------------------------------------------


def test_cloud_provider_defaults_to_azure_when_unspecified():
    assert cloud_provider_of([]) == "azure"
    assert cloud_provider_of([{"data": {}}]) == "azure"


def test_cloud_provider_reads_the_decorator():
    assert cloud_provider_of(_AWS) == "aws"


# ---------------------------------------------------------------------------
# tfpolicy — AWS branch
# ---------------------------------------------------------------------------


def test_tfpolicy_aws_targets_aws_resources_only():
    out = write_tfpolicy_policies(_PCI, None, _AWS)
    for rtype in _AWS_TYPES:
        assert rtype in out
    assert "azurerm" not in out
    assert "kubernetes" not in out
    assert validate_hcl_syntax(out) == []


def test_tfpolicy_aws_flags_version_sensitive_rows_as_todo():
    out = write_tfpolicy_policies(_PCI, None, _AWS)
    assert "TODO(aws-sme)" in out
    assert "S3 server-side encryption" in out
    assert "security-group ingress" in out


def test_tfpolicy_tests_mock_aws_resources_the_policy_actually_checks():
    """A test that mocks a type the policy never inspects passes vacuously — the mock
    type must match the AWS resources the emitted policy checks."""
    tests = write_tfpolicy_tests(_PCI, None, _AWS)
    assert "aws_ebs_volume" in tests
    assert "aws_lb" in tests
    assert "azurerm" not in tests


# ---------------------------------------------------------------------------
# sentinel — AWS branch (parity: same resources, other syntax)
# ---------------------------------------------------------------------------


def test_sentinel_aws_targets_the_same_aws_resources():
    out = write_sentinel_policies(_PCI, None, _AWS)
    for rtype in _AWS_TYPES:
        assert rtype in out
    assert "azurerm" not in out
    assert "TODO(aws-sme)" in out
    # Predicate rules still present — parity holds at the predicate level.
    assert 'rule "enforce_encryption_at_rest"' in out
    assert 'rule "deny_public_endpoints"' in out


def test_sentinel_aws_filter_variables_are_unique():
    """aws_db_instance is checked by BOTH encryption and public-access predicates.

    Sentinel's filter variables share one flat namespace, so if the variable name were
    derived from the resource type alone, the two predicates would each define
    `aws_db_instance_violations` — a redefinition, and the first rule would silently bind
    the second predicate's filter. The names must be scoped per predicate.
    """
    out = write_sentinel_policies(_PCI, None, _AWS)
    filter_vars = [
        line.split(" = filter")[0].strip()
        for line in out.splitlines()
        if " = filter tfplan" in line
    ]
    assert len(filter_vars) == len(set(filter_vars)), f"duplicate filter var: {filter_vars}"
    # And the collision-prone one is present under both scopes.
    assert "encryption_aws_db_instance_violations" in filter_vars
    assert "public_aws_db_instance_violations" in filter_vars


def test_both_emitters_reference_the_same_aws_resource_set():
    """The consistency guarantee: run both on an AWS stack, get the same targets.

    This is what stops `--policy-framework all` from enforcing on one framework and
    silently no-opping on the other.
    """
    tf = write_tfpolicy_policies(_PCI, None, _AWS)
    sent = write_sentinel_policies(_PCI, None, _AWS)
    shared = {t.resource_type for t in AWS_ENCRYPTION_AT_REST + AWS_NO_PUBLIC_ENDPOINTS}
    for rtype in shared:
        assert rtype in tf, f"{rtype} missing from tfpolicy"
        assert rtype in sent, f"{rtype} missing from sentinel"


# ---------------------------------------------------------------------------
# regression — azure default is untouched
# ---------------------------------------------------------------------------


def test_azure_default_is_unchanged_in_both_emitters():
    tf = write_tfpolicy_policies(_PCI, None, _AZURE)
    sent = write_sentinel_policies(_PCI, None, _AZURE)
    assert "azurerm_storage_account" in tf and "aws_" not in tf
    assert "azurerm_storage_account" in sent and "aws_" not in sent
