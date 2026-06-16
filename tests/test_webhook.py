"""Tests for the GitHub push webhook handler (P1-009)."""

import hashlib
import hmac
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

import calm_forge.webhook as webhook_module
from calm_forge.webhook import handle_webhook

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "fsi-3tier"

_CALM_CONTENT = (EXAMPLES_DIR / "instantiation.json").read_text()
_DECORATOR_CONTENT = (EXAMPLES_DIR / "decorator.json").read_text()
_CATALOG_CONTENT = (EXAMPLES_DIR / "catalog.json").read_text()


def _make_signature(secret: str, body: bytes) -> str:
    """Compute GitHub-style HMAC-SHA256 signature."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _push_payload(files: list[str]) -> dict:
    """Build a minimal GitHub push event payload."""
    return {
        "repository": {
            "name": "my-repo",
            "owner": {"login": "my-org"},
        },
        "after": "abc123def456",
        "commits": [
            {
                "id": "abc123def456",
                "added": files,
                "modified": [],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Signature validation
# ---------------------------------------------------------------------------


def test_valid_signature_passes():
    """Valid HMAC signature passes without raising."""
    secret = "test-secret"
    body = b'{"test": true}'
    sig = _make_signature(secret, body)

    with patch.dict(os.environ, {"CALM_FORGE_WEBHOOK_SECRET": secret}):
        # Re-read env var by patching the module-level variable
        original = webhook_module._WEBHOOK_SECRET
        webhook_module._WEBHOOK_SECRET = secret
        try:
            # Should not raise
            from calm_forge.webhook import _validate_signature
            _validate_signature(body, sig)
        finally:
            webhook_module._WEBHOOK_SECRET = original


def test_invalid_signature_raises_401():
    """Invalid HMAC signature raises HTTPException 401."""
    original = webhook_module._WEBHOOK_SECRET
    webhook_module._WEBHOOK_SECRET = "test-secret"
    try:
        from calm_forge.webhook import _validate_signature
        with pytest.raises(HTTPException) as exc_info:
            _validate_signature(b"body", "sha256=invalid")
        assert exc_info.value.status_code == 401
    finally:
        webhook_module._WEBHOOK_SECRET = original


def test_missing_webhook_secret_raises_500():
    """Missing webhook secret raises HTTPException 500."""
    original = webhook_module._WEBHOOK_SECRET
    webhook_module._WEBHOOK_SECRET = ""
    try:
        from calm_forge.webhook import _validate_signature
        with pytest.raises(HTTPException) as exc_info:
            _validate_signature(b"body", "sha256=anything")
        assert exc_info.value.status_code == 500
    finally:
        webhook_module._WEBHOOK_SECRET = original


# ---------------------------------------------------------------------------
# Push payload with no .calm.json files
# ---------------------------------------------------------------------------


def test_no_calm_files_returns_zero_processed():
    """Push with no .calm.json files returns {'processed': 0}."""
    secret = "test-secret"
    payload = _push_payload(["src/main.py", "README.md"])
    body = json.dumps(payload).encode()
    sig = _make_signature(secret, body)

    webhook_module._WEBHOOK_SECRET = secret
    try:
        result = handle_webhook(body, sig, payload)
        assert result == {"processed": 0}
    finally:
        webhook_module._WEBHOOK_SECRET = ""


# ---------------------------------------------------------------------------
# Push payload with .calm.json files — mock GitHub API + generator
# ---------------------------------------------------------------------------


class _FakeHTTPResponse:
    """Fake urllib response."""

    def __init__(self, content: str):
        self._content = content.encode()

    def read(self):
        return self._content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_valid_push_processes_calm_file(tmp_path):
    """Push with .calm.json file calls generate and processes the file."""
    secret = "test-secret"
    payload = _push_payload(["architectures/payments.calm.json"])
    body = json.dumps(payload).encode()
    sig = _make_signature(secret, body)

    # Prepare local catalog + decorator to avoid needing GitHub fetch
    webhook_module._WEBHOOK_SECRET = secret
    webhook_module._CATALOG_PATH = str(EXAMPLES_DIR / "catalog.json")
    webhook_module._DECORATOR_PATH = str(EXAMPLES_DIR / "decorator.json")
    webhook_module._TARGET_OWNER = ""
    webhook_module._TARGET_REPO = ""

    def _fake_urlopen(req):
        # Only the CALM file needs to be fetched via GitHub API
        return _FakeHTTPResponse(_CALM_CONTENT)

    try:
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            result = handle_webhook(body, sig, payload)

        assert result["processed"] == 1
        assert "errors" not in result
    finally:
        webhook_module._WEBHOOK_SECRET = ""
        webhook_module._CATALOG_PATH = ""
        webhook_module._DECORATOR_PATH = ""


def test_github_fetch_error_captured_in_errors():
    """If GitHub file fetch fails, the error is captured and processed count stays 0."""
    import urllib.error

    secret = "test-secret"
    payload = _push_payload(["architectures/payments.calm.json"])
    body = json.dumps(payload).encode()
    sig = _make_signature(secret, body)

    webhook_module._WEBHOOK_SECRET = secret
    webhook_module._CATALOG_PATH = str(EXAMPLES_DIR / "catalog.json")
    webhook_module._DECORATOR_PATH = str(EXAMPLES_DIR / "decorator.json")

    def _raise(req):
        raise urllib.error.HTTPError(
            url=req.full_url, code=404, msg="Not Found", hdrs=None, fp=None
        )

    try:
        with patch("urllib.request.urlopen", side_effect=_raise):
            result = handle_webhook(body, sig, payload)

        assert result["processed"] == 0
        assert "errors" in result
        assert result["errors"][0]["file"] == "architectures/payments.calm.json"
    finally:
        webhook_module._WEBHOOK_SECRET = ""
        webhook_module._CATALOG_PATH = ""
        webhook_module._DECORATOR_PATH = ""
