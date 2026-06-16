"""Tests for the CALM Forge FastAPI application (P1-006).

Auth is disabled at module level so the TestClient can hit all endpoints
without tokens. Auth-specific tests re-enable it selectively.
"""

import json
import re
from pathlib import Path
from unittest.mock import patch

import calm_forge.jwt_auth as jwt_auth

# Disable auth BEFORE importing the app so the dependency is already set
jwt_auth.disable_auth()

from fastapi.testclient import TestClient  # noqa: E402

from calm_forge.api import app  # noqa: E402

client = TestClient(app)

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "fsi-3tier"

# ---------------------------------------------------------------------------
# Load FSI-3tier fixtures once
# ---------------------------------------------------------------------------

_CALM = json.loads((EXAMPLES_DIR / "instantiation.json").read_text())
_DECORATOR = json.loads((EXAMPLES_DIR / "decorator.json").read_text())
_CATALOG = json.loads((EXAMPLES_DIR / "catalog.json").read_text())

# Minimal invalid CALM (missing nodes)
_INVALID_CALM = {"relationships": [], "metadata": {}}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def test_health():
    """GET / returns 200 with status=ok."""
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "calm-forge"
    assert body["version"] == "0.4.0"


# ---------------------------------------------------------------------------
# /generate
# ---------------------------------------------------------------------------


def test_generate_valid_returns_files():
    """POST /generate with valid FSI-3tier input returns files and attestation_sha."""
    resp = client.post("/generate", json={
        "calm": _CALM,
        "decorator": _DECORATOR,
        "catalog": _CATALOG,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "files" in body
    assert "components.tfstack.hcl" in body["files"]
    assert "variables.tfstack.hcl" in body["files"]
    assert "deployments.tfdeploy.hcl" in body["files"]

    # attestation_sha must be 64-char hex
    sha = body["attestation_sha"]
    assert len(sha) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", sha)


def test_generate_full_flag():
    """POST /generate with full=True returns all 8 artifact keys."""
    resp = client.post("/generate", json={
        "calm": _CALM,
        "decorator": _DECORATOR,
        "catalog": _CATALOG,
        "full": True,
    })
    assert resp.status_code == 200, resp.text
    files = resp.json()["files"]
    for name in [
        "components.tfstack.hcl",
        "variables.tfstack.hcl",
        "deployments.tfdeploy.hcl",
        "vault/policies.hcl",
        "vault/pki-config.hcl",
        "sentinel/policies.sentinel",
        "ansible/inventory.yml",
        "ansible/eda-rulebook.yml",
    ]:
        assert name in files, f"Missing artifact: {name}"


def test_generate_invalid_calm_returns_422():
    """POST /generate with missing nodes returns 422."""
    resp = client.post("/generate", json={
        "calm": _INVALID_CALM,
        "decorator": _DECORATOR,
        "catalog": _CATALOG,
    })
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /validate
# ---------------------------------------------------------------------------


def test_validate_valid_calm():
    """POST /validate with valid FSI-3tier CALM returns valid=True."""
    resp = client.post("/validate", json={"calm": _CALM})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["errors"] == []


def test_validate_missing_nodes():
    """POST /validate with missing nodes returns valid=False with errors."""
    resp = client.post("/validate", json={"calm": _INVALID_CALM})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert len(body["errors"]) > 0


# ---------------------------------------------------------------------------
# /validate-intent
# ---------------------------------------------------------------------------


def test_validate_intent_valid():
    """POST /validate-intent with valid CALM returns valid=True (OPA graceful degradation)."""
    resp = client.post("/validate-intent", json={"calm": _CALM})
    assert resp.status_code == 200
    body = resp.json()
    # Valid FSI-3tier CALM produces no error-severity violations whether OPA is
    # present (CI installs it) or absent (graceful degradation) — both => valid=True.
    assert body["valid"] is True
    assert "violations" in body
    assert "opa_available" in body
    # If OPA unavailable, warning key is present and non-null
    if not body["opa_available"]:
        assert body.get("warning") is not None


def test_validate_intent_opa_degradation_fields():
    """POST /validate-intent response always includes opa_available and bundle fields."""
    resp = client.post("/validate-intent", json={"calm": _CALM})
    assert resp.status_code == 200
    body = resp.json()
    assert "opa_available" in body
    assert "bundle" in body
    assert isinstance(body["violations"], list)


# ---------------------------------------------------------------------------
# /import (TFE mocked)
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


def test_import_with_mocked_tfe():
    """POST /import with mocked TFE returns files dict and attestation_sha."""
    with patch("urllib.request.urlopen",
               side_effect=_tfe_urlopen(["payments-api-prod", "payments-db-prod"])):
        resp = client.post("/import", json={
            "tfe_host": "tfe.example.com",
            "tfe_token": "fake-token",
            "org": "payments",
        })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "files" in body
    assert "calm-instantiation.json" in body["files"]
    assert "decorator.json" in body["files"]
    assert "migration-plan.md" in body["files"]
    sha = body["attestation_sha"]
    assert len(sha) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", sha)


def test_import_invalid_org_returns_422():
    """POST /import where TFE finds no workspaces returns 422."""

    def _empty_urlopen(req):
        body = json.dumps({"data": [], "links": {}}).encode()
        return _MockResponse(body)

    with patch("urllib.request.urlopen", side_effect=_empty_urlopen):
        resp = client.post("/import", json={
            "tfe_host": "tfe.example.com",
            "tfe_token": "fake-token",
            "org": "nonexistent-org",
        })

    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------


def test_auth_no_token_returns_401():
    """With auth enabled and no token, POST /validate returns 401."""
    jwt_auth.enable_auth()
    try:
        resp = client.post("/validate", json={"calm": _CALM})
        assert resp.status_code == 401
    finally:
        jwt_auth.disable_auth()


def test_auth_bad_jwks_url_returns_503():
    """With auth enabled and JWKS URL set but unreachable, POST /validate returns 401 or 503."""
    jwt_auth.enable_auth()
    jwt_auth.set_jwks_url("https://unreachable.example.com/.well-known/jwks.json")
    try:
        resp = client.post(
            "/validate",
            json={"calm": _CALM},
            headers={"Authorization": "Bearer fake.token.here"},
        )
        # PyJWT will fail trying to contact the JWKS URL — expect 401 (invalid token)
        # or 503 if it explicitly raises before decoding; either is acceptable
        assert resp.status_code in (401, 503)
    finally:
        jwt_auth.disable_auth()
        jwt_auth.set_jwks_url("")
