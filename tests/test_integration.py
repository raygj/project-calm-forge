"""Integration tests — full CLI pipeline against all 4 FSI examples.

Tests invoke the CLI via Click's CliRunner (same code path as a real terminal
invocation). Covers:
  - `generate` (default + --full) for all 4 examples, with baseline comparison
  - `validate` for all 4 examples plus invalid-input cases
  - `import` with a mocked TFE API (no live server required)
"""

import json
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

ALL_EXAMPLES = [
    "fsi-3tier",
    "fsi-event-driven",
    "fsi-microservices-mesh",
    "fsi-mongodb-multiregion",
]

FULL_ARTIFACTS = [
    "components.tfstack.hcl",
    "variables.tfstack.hcl",
    "deployments.tfdeploy.hcl",
    "vault/policies.hcl",
    "vault/pki-config.hcl",
    "sentinel/policies.sentinel",
    "ansible/inventory.yml",
    "ansible/eda-rulebook.yml",
]


# ---------------------------------------------------------------------------
# generate command
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("example", ALL_EXAMPLES)
def test_generate_exits_zero(example, tmp_path):
    """calm-forge generate exits 0 for all FSI examples."""
    ex = EXAMPLES_DIR / example
    result = CliRunner().invoke(cli, [
        "generate",
        "--calm", str(ex / "instantiation.json"),
        "--decorator", str(ex / "decorator.json"),
        "--catalog", str(ex / "catalog.json"),
        "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("example", ALL_EXAMPLES)
def test_generate_produces_three_files(example, tmp_path):
    """Default generate writes exactly 3 HCL files and no Vault/Sentinel/Ansible dirs."""
    ex = EXAMPLES_DIR / example
    CliRunner().invoke(cli, [
        "generate",
        "--calm", str(ex / "instantiation.json"),
        "--decorator", str(ex / "decorator.json"),
        "--catalog", str(ex / "catalog.json"),
        "--output-dir", str(tmp_path),
    ])
    assert (tmp_path / "components.tfstack.hcl").exists()
    assert (tmp_path / "variables.tfstack.hcl").exists()
    assert (tmp_path / "deployments.tfdeploy.hcl").exists()
    assert not (tmp_path / "vault").exists()
    assert not (tmp_path / "sentinel").exists()
    assert not (tmp_path / "ansible").exists()


@pytest.mark.parametrize("example", ALL_EXAMPLES)
def test_generate_full_produces_all_artifacts(example, tmp_path):
    """generate --full produces all 8 artifacts for all FSI examples."""
    ex = EXAMPLES_DIR / example
    result = CliRunner().invoke(cli, [
        "generate",
        "--calm", str(ex / "instantiation.json"),
        "--decorator", str(ex / "decorator.json"),
        "--catalog", str(ex / "catalog.json"),
        "--output-dir", str(tmp_path),
        "--full",
    ])
    assert result.exit_code == 0, result.output
    for artifact in FULL_ARTIFACTS:
        assert (tmp_path / artifact).exists(), f"Missing: {artifact} ({example})"


@pytest.mark.parametrize("example", ALL_EXAMPLES)
def test_generate_components_matches_baseline(example, tmp_path):
    """components.tfstack.hcl matches expected baseline for every example."""
    ex = EXAMPLES_DIR / example
    CliRunner().invoke(cli, [
        "generate",
        "--calm", str(ex / "instantiation.json"),
        "--decorator", str(ex / "decorator.json"),
        "--catalog", str(ex / "catalog.json"),
        "--output-dir", str(tmp_path),
    ])
    actual = (tmp_path / "components.tfstack.hcl").read_text()
    expected = (ex / "expected-output" / "components.tfstack.hcl").read_text()
    assert actual == expected, f"components.tfstack.hcl mismatch for {example}"


@pytest.mark.parametrize("example", ALL_EXAMPLES)
def test_generate_full_artifacts_match_baselines(example, tmp_path):
    """All --full artifacts match expected baselines for every example."""
    ex = EXAMPLES_DIR / example
    CliRunner().invoke(cli, [
        "generate",
        "--calm", str(ex / "instantiation.json"),
        "--decorator", str(ex / "decorator.json"),
        "--catalog", str(ex / "catalog.json"),
        "--output-dir", str(tmp_path),
        "--full",
    ])
    for artifact in FULL_ARTIFACTS:
        actual = (tmp_path / artifact).read_text()
        expected = (ex / "expected-output" / artifact).read_text()
        assert actual == expected, f"{artifact} mismatch for {example}"


def test_generate_missing_input_exits_nonzero(tmp_path):
    """generate exits non-zero when a required input file does not exist."""
    result = CliRunner().invoke(cli, [
        "generate",
        "--calm", str(tmp_path / "nonexistent.json"),
        "--decorator", str(tmp_path / "nonexistent.json"),
        "--catalog", str(tmp_path / "nonexistent.json"),
        "--output-dir", str(tmp_path),
    ])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("example", ALL_EXAMPLES)
def test_validate_passes_all_examples(example):
    """validate exits 0 and reports Valid for every FSI instantiation.json."""
    ex = EXAMPLES_DIR / example
    result = CliRunner().invoke(cli, [
        "validate",
        "--calm", str(ex / "instantiation.json"),
    ])
    assert result.exit_code == 0, result.output
    assert "Valid" in result.output


def test_validate_rejects_invalid_json(tmp_path):
    """validate exits non-zero for a file that is not valid JSON."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    result = CliRunner().invoke(cli, ["validate", "--calm", str(bad)])
    assert result.exit_code != 0


def test_validate_rejects_missing_nodes(tmp_path):
    """validate exits non-zero when the nodes array is absent."""
    bad = tmp_path / "no-nodes.json"
    bad.write_text(json.dumps({"relationships": [], "metadata": {}}))
    result = CliRunner().invoke(cli, ["validate", "--calm", str(bad)])
    assert result.exit_code != 0


def test_validate_rejects_missing_metadata(tmp_path):
    """validate exits non-zero when metadata is absent."""
    bad = tmp_path / "no-meta.json"
    bad.write_text(json.dumps({
        "nodes": [{"unique-id": "x", "node-type": "service"}],
        "relationships": [],
    }))
    result = CliRunner().invoke(cli, ["validate", "--calm", str(bad)])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# import command — TFE API mocked with urllib.request.urlopen
# ---------------------------------------------------------------------------


class _MockResponse:
    """Minimal context-manager response object for urlopen mocking."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _tfe_urlopen(workspace_names):
    """Return a urlopen side-effect that simulates TFE API responses."""

    def _open(req):
        url = req.full_url

        if "current-state-version" in url:
            body = json.dumps({"data": {}}).encode()
        elif "/vars" in url:
            body = json.dumps({"data": [], "links": {}}).encode()
        elif "/workspaces" in url:
            # List workspaces
            data = [
                {
                    "id": f"ws-{name}",
                    "attributes": {
                        "name": name,
                        "created-at": "2024-01-01T00:00:00Z",
                        "updated-at": "2024-01-01T00:00:00Z",
                        "terraform-version": "1.9.0",
                        "vcs-repo": {},
                        "working-directory": "",
                    },
                    "relationships": {},
                }
                for name in workspace_names
            ]
            body = json.dumps({"data": data, "links": {}}).encode()
        else:
            body = json.dumps({"data": [], "links": {}}).encode()

        return _MockResponse(body)

    return _open


def test_import_produces_artifacts(tmp_path):
    """import produces all expected output files given a mocked TFE."""
    with patch("urllib.request.urlopen",
               side_effect=_tfe_urlopen(["payments-api-prod", "payments-db-prod"])):
        result = CliRunner().invoke(cli, [
            "import",
            "--tfe-host", "tfe.example.com",
            "--tfe-token", "fake-token",
            "--org", "payments",
            "--output-dir", str(tmp_path),
        ])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "calm-instantiation.json").exists()
    assert (tmp_path / "decorator.json").exists()
    assert (tmp_path / "migration-plan.md").exists()
    assert (tmp_path / "import-blocks.tf").exists()
    assert (tmp_path / "cluster-proposal.json").exists()
    assert (tmp_path / "workspace-inventory.json").exists()


def test_import_calm_output_is_valid(tmp_path):
    """Generated calm-instantiation.json is valid CALM JSON with required keys."""
    with patch("urllib.request.urlopen",
               side_effect=_tfe_urlopen(["payments-api-prod"])):
        CliRunner().invoke(cli, [
            "import",
            "--tfe-host", "tfe.example.com",
            "--tfe-token", "fake-token",
            "--org", "payments",
            "--output-dir", str(tmp_path),
        ])

    calm = json.loads((tmp_path / "calm-instantiation.json").read_text())
    assert "nodes" in calm
    assert "relationships" in calm
    assert "metadata" in calm
    assert calm["metadata"]["imported"] is True
    assert calm["metadata"]["application-name"] == "payments"


def test_import_connection_error_exits_nonzero(tmp_path):
    """import exits non-zero and prints an error on TFE API failure."""
    def _raise(req):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=None,
        )

    with patch("urllib.request.urlopen", side_effect=_raise):
        result = CliRunner().invoke(cli, [
            "import",
            "--tfe-host", "tfe.example.com",
            "--tfe-token", "bad-token",
            "--org", "bad-org",
            "--output-dir", str(tmp_path),
        ])

    assert result.exit_code != 0
