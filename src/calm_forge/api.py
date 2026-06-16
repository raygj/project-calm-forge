"""FastAPI application for CALM Forge.

Thin wrapper around the core generator engine.
The engine stays pure — all I/O is handled here via tempfiles.
"""
import hashlib
import json
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from .generator import generate_stack, validate_architecture
from .jwt_auth import verify_jwt
from .kg_coherence_api import configure_coherence_kg_dir
from .kg_coherence_api import router as coherence_router
from .opa_gate import rebuild_builtin_bundle
from .opa_gate import validate_intent as opa_validate_intent
from .tfe_importer import import_workspaces
from .webhook import handle_webhook as _handle_webhook


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Rebuild the built-in OPA bundle from KG Policy nodes on startup
    # so the bundle always reflects the current knowledge graph state.
    rebuild_builtin_bundle()
    # Configure coherence KG dir from env if set
    import os
    if kg_dir := os.environ.get("CALM_FORGE_KG_DIR"):
        from pathlib import Path
        configure_coherence_kg_dir(Path(kg_dir))
    yield


app = FastAPI(
    title="CALM Forge API",
    description="Architecture intent to governed infrastructure",
    version="0.4.0",
    lifespan=lifespan,
)

app.include_router(coherence_router)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GenerateRequest(BaseModel):
    calm: dict[str, Any]
    decorator: dict[str, Any]
    catalog: dict[str, Any]
    full: bool = False
    include_imports: bool = False


class GenerateResponse(BaseModel):
    files: dict[str, str]
    attestation_sha: str


class ValidateRequest(BaseModel):
    calm: dict[str, Any]


class ValidateResponse(BaseModel):
    valid: bool
    errors: list[str]


class ValidateIntentRequest(BaseModel):
    calm: dict[str, Any]
    decorator: dict[str, Any] | None = None


class ValidateIntentResponse(BaseModel):
    valid: bool
    violations: list[dict[str, Any]]
    opa_available: bool = True
    bundle: str = ""
    warning: str | None = None


class ImportRequest(BaseModel):
    tfe_host: str
    tfe_token: str
    org: str
    workspace_filter: str | None = None


class ImportResponse(BaseModel):
    files: dict[str, str]
    attestation_sha: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _attestation_sha(files: dict[str, str]) -> str:
    """SHA-256 of sorted file names + contents concatenated."""
    h = hashlib.sha256()
    for name in sorted(files.keys()):
        h.update(name.encode())
        h.update(files[name].encode())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/")
async def health() -> dict[str, str]:
    """Health check."""
    return {"status": "ok", "service": "calm-forge", "version": "0.4.0"}


@app.post("/generate", response_model=GenerateResponse)
async def generate(
    req: GenerateRequest,
    _: None = Depends(verify_jwt),
) -> GenerateResponse:
    """Generate Terraform Stack HCL and optional full artifact set from CALM JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        calm_path = tmp / "calm.json"
        calm_path.write_text(json.dumps(req.calm))

        decorator_path = tmp / "decorator.json"
        decorator_path.write_text(json.dumps(req.decorator))

        catalog_path = tmp / "catalog.json"
        catalog_path.write_text(json.dumps(req.catalog))

        out_dir = tmp / "output"
        out_dir.mkdir()

        try:
            files = generate_stack(
                str(calm_path),
                str(decorator_path),
                str(catalog_path),
                str(out_dir),
                full=req.full,
                include_imports=req.include_imports,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ConnectionError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    return GenerateResponse(
        files=files,
        attestation_sha=_attestation_sha(files),
    )


@app.post("/validate", response_model=ValidateResponse)
async def validate(
    req: ValidateRequest,
    _: None = Depends(verify_jwt),
) -> ValidateResponse:
    """Validate a CALM architecture JSON."""
    errors = validate_architecture(req.calm)
    return ValidateResponse(valid=len(errors) == 0, errors=errors)


@app.post("/validate-intent", response_model=ValidateIntentResponse)
async def validate_intent(
    req: ValidateIntentRequest,
    _: None = Depends(verify_jwt),
) -> ValidateIntentResponse:
    """Validate architecture intent against OPA policy bundle."""
    result = opa_validate_intent(req.calm, req.decorator)
    return ValidateIntentResponse(**result)


@app.post("/import", response_model=ImportResponse)
async def import_endpoint(
    req: ImportRequest,
    _: None = Depends(verify_jwt),
) -> ImportResponse:
    """Import TFE workspaces and generate CALM JSON + migration artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            files = import_workspaces(
                tfe_host=req.tfe_host,
                tfe_token=req.tfe_token,
                org=req.org,
                output_dir=tmpdir,
                workspace_filter=req.workspace_filter,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ConnectionError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    return ImportResponse(
        files=files,
        attestation_sha=_attestation_sha(files),
    )


@app.post("/webhook")
async def webhook(request: Request) -> dict:
    """GitHub push webhook — regenerate artifacts on .calm.json changes."""
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    payload = await request.json()
    return _handle_webhook(body, signature, payload)
