"""Roundtrip tests — example JSON → HCL → compare to expected output."""

from pathlib import Path

from calm_forge.generator import generate_stack, validate_architecture

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "fsi-3tier"
EXPECTED_DIR = EXAMPLES_DIR / "expected-output"


def test_roundtrip_components(tmp_path):
    """Generated components.tfstack.hcl matches expected output."""
    generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
    )

    actual = (tmp_path / "components.tfstack.hcl").read_text()
    expected = (EXPECTED_DIR / "components.tfstack.hcl").read_text()
    assert actual == expected


def test_roundtrip_variables(tmp_path):
    """Generated variables.tfstack.hcl matches expected output."""
    generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
    )

    actual = (tmp_path / "variables.tfstack.hcl").read_text()
    expected = (EXPECTED_DIR / "variables.tfstack.hcl").read_text()
    assert actual == expected


def test_roundtrip_deployments(tmp_path):
    """Generated deployments.tfdeploy.hcl matches expected output."""
    generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
    )

    actual = (tmp_path / "deployments.tfdeploy.hcl").read_text()
    expected = (EXPECTED_DIR / "deployments.tfdeploy.hcl").read_text()
    assert actual == expected


def test_all_three_files_generated(tmp_path):
    """All three HCL files are created in the output directory."""
    files = generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
    )

    assert set(files.keys()) == {
        "components.tfstack.hcl",
        "variables.tfstack.hcl",
        "deployments.tfdeploy.hcl",
    }
    for name in files:
        assert (tmp_path / name).exists()


def test_validate_valid_architecture():
    """A valid CALM instantiation passes validation."""
    import json
    arch = json.loads((EXAMPLES_DIR / "instantiation.json").read_text())
    errors = validate_architecture(arch)
    assert errors == []


def test_validate_missing_nodes():
    """Missing nodes array is caught."""
    errors = validate_architecture({"relationships": [], "metadata": {}})
    assert any("nodes" in e for e in errors)


def test_validate_missing_metadata():
    """Missing metadata is caught."""
    errors = validate_architecture({
        "nodes": [{"unique-id": "x", "node-type": "service"}],
        "relationships": [],
    })
    assert any("metadata" in e for e in errors)


def test_component_wiring_mtls(tmp_path):
    """Services in mTLS relationship get vault_pki_path wired."""
    generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
    )

    components = (tmp_path / "components.tfstack.hcl").read_text()

    # Both web-frontend and api-service should reference vault_pki_mtls
    assert "component.vault_pki_mtls.outputs.pki_path" in components
    # The PKI component should list both services in allowed_domains
    assert "web-frontend.${var.namespace}.svc" in components
    assert "api-service.${var.namespace}.svc" in components


def test_component_wiring_dynamic_creds(tmp_path):
    """API service connecting to DB gets vault dynamic creds wired."""
    generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
    )

    components = (tmp_path / "components.tfstack.hcl").read_text()

    # api_service should reference database connection and vault creds
    assert "component.database.outputs.connection_string" in components
    assert "component.vault_dynamic_db_creds.outputs.creds_path" in components


def test_pci_deployment_gets_approval_gates(tmp_path):
    """PCI-scoped deployments get auto_approve checks."""
    generate_stack(
        str(EXAMPLES_DIR / "instantiation.json"),
        str(EXAMPLES_DIR / "decorator.json"),
        str(EXAMPLES_DIR / "catalog.json"),
        str(tmp_path),
    )

    deployments = (tmp_path / "deployments.tfdeploy.hcl").read_text()

    assert "deployment_auto_approve" in deployments
    assert "production_gate" in deployments
    assert "no_destroys" in deployments
