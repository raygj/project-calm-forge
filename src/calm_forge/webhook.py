"""GitHub push webhook handler for CALM Forge.

Listens for push events, detects changed .calm.json files,
runs the generator, and commits artifacts to a target repository.

Configuration (environment variables):
  CALM_FORGE_WEBHOOK_SECRET   GitHub HMAC-SHA256 webhook secret
  CALM_FORGE_CATALOG_PATH     Path to catalog.json
  CALM_FORGE_DECORATOR_PATH   Path to decorator.json
  CALM_FORGE_GH_TOKEN         GitHub token for reading source and committing artifacts
  CALM_FORGE_TARGET_OWNER     Target repo owner
  CALM_FORGE_TARGET_REPO      Target repo name
  CALM_FORGE_TARGET_BRANCH    Target branch (default: main)
"""
import hashlib
import hmac
import json
import os
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from fastapi import HTTPException

from .generator import generate_stack

_WEBHOOK_SECRET: str = os.getenv("CALM_FORGE_WEBHOOK_SECRET", "")
_CATALOG_PATH: str = os.getenv("CALM_FORGE_CATALOG_PATH", "")
_DECORATOR_PATH: str = os.getenv("CALM_FORGE_DECORATOR_PATH", "")
_GH_TOKEN: str = os.getenv("CALM_FORGE_GH_TOKEN", "")
_TARGET_OWNER: str = os.getenv("CALM_FORGE_TARGET_OWNER", "")
_TARGET_REPO: str = os.getenv("CALM_FORGE_TARGET_REPO", "")
_TARGET_BRANCH: str = os.getenv("CALM_FORGE_TARGET_BRANCH", "main")


def _validate_signature(body: bytes, signature: str) -> None:
    """Validate X-Hub-Signature-256 HMAC against the request body."""
    if not _WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    expected = "sha256=" + hmac.new(
        _WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


def _get_changed_calm_files(payload: dict) -> list[dict]:
    """Extract added + modified .calm.json files from all commits in the push payload."""
    changed = []
    repo = payload.get("repository", {})
    owner = (repo.get("owner") or {}).get("login", "")
    repo_name = repo.get("name", "")
    ref = payload.get("after", "")  # HEAD SHA after the push

    seen = set()
    for commit in payload.get("commits", []):
        for filepath in commit.get("added", []) + commit.get("modified", []):
            if filepath.endswith(".calm.json") and filepath not in seen:
                seen.add(filepath)
                changed.append({
                    "path": filepath,
                    "owner": owner,
                    "repo": repo_name,
                    "ref": ref,
                })

    return changed


def _fetch_github_file(owner: str, repo: str, path: str, ref: str) -> str:
    """Fetch file content from GitHub API. Returns decoded text content."""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {_GH_TOKEN}")
    req.add_header("Accept", "application/vnd.github.raw+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")

    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode() if exc.fp else ""
        raise ConnectionError(
            f"GitHub API {exc.code} fetching {path}: {body}"
        ) from exc


def _get_file_sha(owner: str, repo: str, path: str, branch: str) -> str | None:
    """Get the blob SHA of an existing file (needed for GitHub update via PUT)."""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {_GH_TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            return data.get("sha")
    except urllib.error.HTTPError:
        return None


def _commit_github_file(path: str, content: str, message: str) -> None:
    """Create or update a file in the target repo via GitHub Contents API."""
    import base64

    if not _TARGET_OWNER or not _TARGET_REPO:
        return  # No target configured; skip commit

    url = f"https://api.github.com/repos/{_TARGET_OWNER}/{_TARGET_REPO}/contents/{path}"

    # Check if file already exists to get its SHA (required for updates)
    existing_sha = _get_file_sha(_TARGET_OWNER, _TARGET_REPO, path, _TARGET_BRANCH)

    payload: dict = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
        "branch": _TARGET_BRANCH,
    }
    if existing_sha:
        payload["sha"] = existing_sha

    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="PUT")
    req.add_header("Authorization", f"Bearer {_GH_TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")

    try:
        with urllib.request.urlopen(req):
            pass
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode() if exc.fp else ""
        raise ConnectionError(
            f"GitHub API {exc.code} committing {path}: {body_text}"
        ) from exc


def handle_deployment_completion(
    payload: dict,
    kg_dir: Path,
    run_drift_check: bool = True,
) -> dict:
    """Process a deployment completion event from ACM/Ansible AAP.

    1. Parse the completion payload into DeploymentStatus KG nodes.
    2. Write each node to kg_dir/deployments/.
    3. Optionally run a post-deploy drift check and update each node's drift_result.

    Args:
        payload:         ACM/Ansible completion payload (same shape as intake_ansible).
        kg_dir:          KG directory to write DeploymentStatus nodes into.
        run_drift_check: When True, run drift_check_post_deploy for each status node.

    Returns:
        dict with keys: processed (int), nodes (list of DeploymentStatus dicts),
        drift_results (list, only present when run_drift_check=True).
    """
    from .drift_evaluator import _try_get_backend, drift_check_post_deploy
    from .intake import intake_deployment_completion, write_deployment_status

    nodes = intake_deployment_completion(payload)
    written: list[dict] = []
    drift_results: list[dict] = []

    backend = _try_get_backend(kg_dir) if run_drift_check else None
    try:
        for node in nodes:
            write_deployment_status(node, kg_dir)
            written.append(node)
            if run_drift_check:
                drift_result = drift_check_post_deploy(node, kg_dir, backend=backend)
                write_deployment_status(node, kg_dir)  # re-write with drift_result populated
                drift_results.append(drift_result)
    finally:
        if backend is not None:
            backend.close()

    result: dict = {"processed": len(written), "nodes": written}
    if run_drift_check:
        result["drift_results"] = drift_results
    return result


def handle_webhook(body: bytes, signature: str, payload: dict) -> dict:
    """Process a GitHub push webhook payload.

    1. Validate HMAC signature.
    2. Find changed .calm.json files.
    3. For each: fetch content, generate artifacts, commit to target repo.
    4. Return summary.
    """
    _validate_signature(body, signature)

    changed_files = _get_changed_calm_files(payload)
    if not changed_files:
        return {"processed": 0}

    processed = 0
    errors = []

    for file_info in changed_files:
        try:
            _process_calm_file(file_info)
            processed += 1
        except (ConnectionError, ValueError) as exc:
            errors.append({"file": file_info["path"], "error": str(exc)})

    result: dict = {"processed": processed}
    if errors:
        result["errors"] = errors
    return result


def _process_calm_file(file_info: dict) -> None:
    """Fetch a single .calm.json, run the generator, and commit artifacts."""
    calm_content = _fetch_github_file(
        file_info["owner"],
        file_info["repo"],
        file_info["path"],
        file_info["ref"],
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Write CALM file
        calm_path = tmp / "calm.json"
        calm_path.write_text(calm_content)

        # Resolve catalog + decorator (local files or GitHub)
        catalog_path = tmp / "catalog.json"
        if _CATALOG_PATH and Path(_CATALOG_PATH).exists():
            catalog_path.write_text(Path(_CATALOG_PATH).read_text())
        elif _CATALOG_PATH and _GH_TOKEN:
            # Try fetching from the source repo
            src_owner = file_info["owner"]
            src_repo = file_info["repo"]
            catalog_content = _fetch_github_file(
                src_owner, src_repo, _CATALOG_PATH, file_info["ref"]
            )
            catalog_path.write_text(catalog_content)
        else:
            raise ValueError(
                "CALM_FORGE_CATALOG_PATH not configured or file not found"
            )

        decorator_path = tmp / "decorator.json"
        if _DECORATOR_PATH and Path(_DECORATOR_PATH).exists():
            decorator_path.write_text(Path(_DECORATOR_PATH).read_text())
        elif _DECORATOR_PATH and _GH_TOKEN:
            src_owner = file_info["owner"]
            src_repo = file_info["repo"]
            decorator_content = _fetch_github_file(
                src_owner, src_repo, _DECORATOR_PATH, file_info["ref"]
            )
            decorator_path.write_text(decorator_content)
        else:
            raise ValueError(
                "CALM_FORGE_DECORATOR_PATH not configured or file not found"
            )

        out_dir = tmp / "output"
        out_dir.mkdir()

        files = generate_stack(
            str(calm_path),
            str(decorator_path),
            str(catalog_path),
            str(out_dir),
            full=True,
        )

        # Derive output path prefix from CALM filename
        calm_stem = Path(file_info["path"]).stem.replace(".calm", "")
        commit_message = f"chore: regenerate artifacts for {file_info['path']}"

        for artifact_name in files:
            artifact_path = f"generated/{calm_stem}/{artifact_name}"
            content = (out_dir / artifact_name).read_text()
            _commit_github_file(artifact_path, content, commit_message)
