"""Tests for v0.2 expanded outputs — Vault, Sentinel, Ansible artifacts."""

from pathlib import Path

import yaml

from calm_forge.ansible_writer import write_eda_rulebook
from calm_forge.generator import generate_stack

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "fsi-3tier"
EXPECTED_DIR = EXAMPLES_DIR / "expected-output"


def _generate_full(tmp_path):
    """Helper: run full generation and return files dict."""
    return generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
        full=True,
    )


# --- Backward compatibility ---

def test_default_generates_three_files_only(tmp_path):
    """Without --full, only 3 HCL files are generated."""
    files = generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
        full=False,
    )
    assert set(files.keys()) == {
        "components.tfstack.hcl",
        "variables.tfstack.hcl",
        "deployments.tfdeploy.hcl",
    }
    assert not (tmp_path / "vault").exists()
    assert not (tmp_path / "sentinel").exists()
    assert not (tmp_path / "ansible").exists()


def test_full_generates_nine_files(tmp_path):
    """With --full, all 9 output files are generated (including dcm/application.json)."""
    files = _generate_full(tmp_path)
    expected_keys = {
        "components.tfstack.hcl",
        "variables.tfstack.hcl",
        "deployments.tfdeploy.hcl",
        "vault/policies.hcl",
        "vault/pki-config.hcl",
        "sentinel/policies.sentinel",
        "ansible/inventory.yml",
        "ansible/eda-rulebook.yml",
        "dcm/application.json",
    }
    assert set(files.keys()) == expected_keys
    for name in expected_keys:
        assert (tmp_path / name).exists()


# --- Vault policies ---

def test_vault_policies_roundtrip(tmp_path):
    """Generated vault/policies.hcl matches expected output."""
    _generate_full(tmp_path)
    actual = (tmp_path / "vault" / "policies.hcl").read_text()
    expected = (EXPECTED_DIR / "vault" / "policies.hcl").read_text()
    assert actual == expected


def test_vault_policies_content(tmp_path):
    """Vault policies contain expected policy paths."""
    files = _generate_full(tmp_path)
    policies = files["vault/policies.hcl"]

    # Service policies
    assert 'path "pki/payments-portal/issue/web-frontend"' in policies
    assert 'path "pki/payments-portal/issue/api-service"' in policies
    assert 'path "database/creds/api-service"' in policies
    assert 'path "transit/encrypt/payments-portal"' in policies

    # Database auditor policy
    assert 'path "database/config/payments-portal-database"' in policies

    # KV config for all non-system nodes
    assert 'path "kv/data/payments-portal/web-frontend/*"' in policies
    assert 'path "kv/data/payments-portal/api-service/*"' in policies
    assert 'path "kv/data/payments-portal/database/*"' in policies


# --- Vault PKI config ---

def test_vault_pki_roundtrip(tmp_path):
    """Generated vault/pki-config.hcl matches expected output."""
    _generate_full(tmp_path)
    actual = (tmp_path / "vault" / "pki-config.hcl").read_text()
    expected = (EXPECTED_DIR / "vault" / "pki-config.hcl").read_text()
    assert actual == expected


def test_vault_pki_content(tmp_path):
    """PKI config contains mounts, roles, and database engine."""
    files = _generate_full(tmp_path)
    pki = files["vault/pki-config.hcl"]

    # PKI mount
    assert 'resource "vault_mount" "pki_payments_portal"' in pki
    assert 'path                      = "pki/payments-portal"' in pki

    # Service roles
    assert 'resource "vault_pki_secret_backend_role" "web_frontend"' in pki
    assert 'resource "vault_pki_secret_backend_role" "api_service"' in pki
    assert "web-frontend.payments-portal-prod.svc" in pki

    # Database engine
    assert 'resource "vault_mount" "db_payments_portal"' in pki
    assert 'resource "vault_database_secret_backend_connection" "database"' in pki
    assert 'resource "vault_database_secret_backend_role" "api_service"' in pki
    assert "default_ttl         = 1800" in pki  # 30m FSI standard
    assert "max_ttl             = 7200" in pki  # 2h FSI standard


# --- Sentinel policies ---

def test_sentinel_roundtrip(tmp_path):
    """Generated sentinel/policies.sentinel matches expected output."""
    _generate_full(tmp_path)
    actual = (tmp_path / "sentinel" / "policies.sentinel").read_text()
    expected = (EXPECTED_DIR / "sentinel" / "policies.sentinel").read_text()
    assert actual == expected


def test_sentinel_pci_policies(tmp_path):
    """PCI-scoped sentinel includes encryption + no-public-endpoints rules."""
    files = _generate_full(tmp_path)
    sentinel = files["sentinel/policies.sentinel"]

    assert 'rule "enforce_encryption_at_rest"' in sentinel
    assert 'rule "deny_public_endpoints"' in sentinel
    assert 'enforcement_level = "hard-mandatory"' in sentinel


def test_sentinel_cost_policies(tmp_path):
    """Sentinel includes 3-tier cost governance rules."""
    files = _generate_full(tmp_path)
    sentinel = files["sentinel/policies.sentinel"]

    assert 'rule "cost_advisory"' in sentinel
    assert 'rule "cost_soft_limit"' in sentinel
    assert 'rule "cost_hard_limit"' in sentinel
    assert "< 500" in sentinel
    assert "< 5000" in sentinel
    assert "< 25000" in sentinel


def test_sentinel_tagging_policy(tmp_path):
    """Confidential data classification triggers tagging requirement."""
    files = _generate_full(tmp_path)
    sentinel = files["sentinel/policies.sentinel"]

    assert 'rule "require_data_classification_tag"' in sentinel
    assert '"data-classification"' in sentinel


# --- Ansible inventory ---

def test_inventory_roundtrip(tmp_path):
    """Generated ansible/inventory.yml matches expected output."""
    _generate_full(tmp_path)
    actual = (tmp_path / "ansible" / "inventory.yml").read_text()
    expected = (EXPECTED_DIR / "ansible" / "inventory.yml").read_text()
    assert actual == expected


def test_inventory_structure(tmp_path):
    """Inventory has correct groups, hosts, and vault connection vars."""
    import yaml
    files = _generate_full(tmp_path)
    inv = yaml.safe_load(files["ansible/inventory.yml"].split("# =")[2].split("\n", 1)[1])

    all_vars = inv["all"]["vars"]
    assert all_vars["application_name"] == "payments-portal"
    assert all_vars["vault_auth_method"] == "approle"
    assert all_vars["namespace"] == "payments-portal-prod"

    children = inv["all"]["children"]
    assert "services" in children
    assert "databases" in children
    assert "web-frontend" in children["services"]["hosts"]
    assert "api-service" in children["services"]["hosts"]
    assert "database" in children["databases"]["hosts"]


# --- Ansible EDA rulebook ---

def test_eda_rulebook_roundtrip(tmp_path):
    """Generated ansible/eda-rulebook.yml matches expected output."""
    _generate_full(tmp_path)
    actual = (tmp_path / "ansible" / "eda-rulebook.yml").read_text()
    expected = (EXPECTED_DIR / "ansible" / "eda-rulebook.yml").read_text()
    assert actual == expected


def test_eda_rulebook_rules(tmp_path):
    """EDA rulebook contains drift, agent, DB, cert, and credential rules."""
    files = _generate_full(tmp_path)
    rulebook = files["ansible/eda-rulebook.yml"]

    # Service rules
    assert "web-frontend config drift remediation" in rulebook
    assert "api-service config drift remediation" in rulebook
    assert "web-frontend agent health restore" in rulebook

    # Database rule
    assert "database connection pool monitoring" in rulebook

    # Relationship-derived rules
    assert "Certificate auto-renewal" in rulebook
    assert "cert-rotation-vault-pki" in rulebook
    assert "Credential rotation monitoring" in rulebook
    assert "credential-rotation-monitor" in rulebook


# --- EDA rulebook drift source (P1-022) ---

_MINIMAL_COMPONENT_MAP = {}
_MINIMAL_REL_COMPONENTS = []
_MINIMAL_METADATA = {"application-name": "test-app"}


def test_eda_rulebook_no_drift_source_by_default():
    content = write_eda_rulebook(_MINIMAL_COMPONENT_MAP, _MINIMAL_REL_COMPONENTS, _MINIMAL_METADATA)
    assert "file_watcher" not in content
    assert "drift-remediation" not in content


def test_eda_rulebook_drift_source_added_when_file_given():
    content = write_eda_rulebook(
        _MINIMAL_COMPONENT_MAP, _MINIMAL_REL_COMPONENTS, _MINIMAL_METADATA,
        drift_event_file="/var/log/calm-forge/drift-events.json",
    )
    assert "ansible.eda.file_watcher" in content
    assert "/var/log/calm-forge/drift-events.json" in content


def test_eda_rulebook_drift_violation_rule_added():
    content = write_eda_rulebook(
        _MINIMAL_COMPONENT_MAP, _MINIMAL_REL_COMPONENTS, _MINIMAL_METADATA,
        drift_event_file="/var/log/calm-forge/drift-events.json",
    )
    assert "Respond to calm drift violation" in content
    assert "drift-remediation.yml" in content


def test_eda_rulebook_drift_rule_structure():
    content = write_eda_rulebook(
        _MINIMAL_COMPONENT_MAP, _MINIMAL_REL_COMPONENTS, _MINIMAL_METADATA,
        drift_event_file="/tmp/drift-events.json",
    )
    rulebook = yaml.safe_load(content)
    rule_names = [r["name"] for r in rulebook[0]["rules"]]
    assert "Respond to calm drift violation" in rule_names
    sources = rulebook[0]["sources"]
    source_keys = [list(s.keys())[0] for s in sources]
    assert "ansible.eda.file_watcher" in source_keys
    assert "ansible.eda.webhook" in source_keys
