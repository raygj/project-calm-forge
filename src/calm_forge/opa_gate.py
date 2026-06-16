"""OPA intent validation gate for CALM Forge.

Validates CALM architecture intent against enterprise policy bundles
before the conversion engine runs. Uses the OPA CLI binary.

If OPA is not installed, validation is skipped with a warning (graceful degradation).

See ADR-003 for integration model, bundle architecture, and evaluation context decisions.

Configuration:
  CALM_FORGE_OPA_BUNDLE   Path or URL to policy bundle (default: built-in)

Bundle sources:
  local path    /path/to/bundle/
  HTTP URL      https://server/calm-policies.tar.gz
  OCI URL       oci://registry.corp.com/calm-policies:latest
"""
from __future__ import annotations

import json
import os
import subprocess
import tarfile
import tempfile
import threading
import urllib.request
from pathlib import Path

_BUILTIN_BUNDLE = Path(__file__).parent / "opa_policies"
_KG_DIR = Path(__file__).parent / "knowledge_graph"

# Module-level bundle path — updated by set_bundle() or env var at import time
_bundle_lock = threading.Lock()
_bundle_path: Path | str = _BUILTIN_BUNDLE

# Hot-reload state
_watcher_thread: threading.Thread | None = None
_watcher_stop = threading.Event()


# ---------------------------------------------------------------------------
# Public: bundle management
# ---------------------------------------------------------------------------


def set_bundle(path: str | None) -> None:
    """Set the OPA policy bundle path.

    If path is None, check CALM_FORGE_OPA_BUNDLE env var.
    If env var not set, use the built-in bundle.
    """
    global _bundle_path
    if path is None:
        path = os.environ.get("CALM_FORGE_OPA_BUNDLE")
    with _bundle_lock:
        if path:
            _bundle_path = Path(path) if not path.startswith(("http", "oci://")) else path
        else:
            _bundle_path = _BUILTIN_BUNDLE


def get_bundle_path() -> Path | str:
    """Return the current bundle path (thread-safe)."""
    with _bundle_lock:
        return _bundle_path


def rebuild_builtin_bundle(kg_dir: Path | None = None) -> Path:
    """Recompile the built-in OPA bundle from KG Policy predicate nodes.

    Reads all Workload patterns from the KG directory, extracts Policy nodes
    whose predicate_type is evaluable at pre-generation time (placement_constraint,
    compliance_boundary), and writes generated Rego to the built-in bundle directory.

    Safe to call multiple times — idempotent. Returns the bundle path.
    See ADR-003 §3 and kg_compiler.py for evaluation context decisions.
    """
    from calm_forge.kg_compiler import compile_all
    from calm_forge.kg_loader import extract_policies, load_patterns

    patterns = load_patterns(kg_dir or _KG_DIR)
    all_policies: list[dict] = []
    for pattern in patterns:
        all_policies.extend(extract_policies(pattern))

    bundle_files = compile_all(all_policies)

    for filename, content in bundle_files.items():
        (_BUILTIN_BUNDLE / filename).write_text(content)

    return _BUILTIN_BUNDLE


# ---------------------------------------------------------------------------
# Public: OPA availability
# ---------------------------------------------------------------------------


def is_opa_available() -> bool:
    """Return True if the OPA CLI binary is available and responds to `opa version`."""
    try:
        result = subprocess.run(
            ["opa", "version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Public: intent validation
# ---------------------------------------------------------------------------


def validate_intent(
    calm: dict,
    decorator: dict | None = None,
    bundle_path: str | Path | None = None,
) -> dict:
    """Validate CALM architecture intent against OPA policy bundle.

    Returns a dict with keys:
      valid         bool
      violations    list of {rule, severity, message}
      opa_available bool
      bundle        str (path or URL used)
      warning       str | None (set when OPA is unavailable)
    """
    if not is_opa_available():
        return {
            "valid": True,
            "violations": [],
            "opa_available": False,
            "bundle": "",
            "warning": (
                "OPA CLI not found — intent validation skipped. "
                "Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
            ),
        }

    effective_bundle: Path | str
    if bundle_path is not None:
        effective_bundle = _resolve_bundle(bundle_path)
    else:
        effective_bundle = _resolve_bundle(get_bundle_path())

    opa_input = {
        "calm": calm,
        "decorator": decorator or {},
    }

    try:
        violations = _run_opa_eval(opa_input, effective_bundle)
    except subprocess.TimeoutExpired:
        return {
            "valid": False,
            "violations": [
                {
                    "rule": "opa-timeout",
                    "severity": "error",
                    "message": "OPA evaluation timed out",
                }
            ],
            "opa_available": True,
            "bundle": str(effective_bundle),
            "warning": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "valid": False,
            "violations": [
                {
                    "rule": "opa-error",
                    "severity": "error",
                    "message": str(exc),
                }
            ],
            "opa_available": True,
            "bundle": str(effective_bundle),
            "warning": None,
        }

    has_errors = any(v.get("severity") == "error" for v in violations)
    return {
        "valid": not has_errors,
        "violations": violations,
        "opa_available": True,
        "bundle": str(effective_bundle),
        "warning": None,
    }


# ---------------------------------------------------------------------------
# Public: drift evaluation
# ---------------------------------------------------------------------------


def evaluate_drift(
    workload: dict,
    placement: dict,
    policies: list[dict] | None = None,
    bundle_path: str | Path | None = None,
) -> dict:
    """Evaluate a Placement node against a Workload's declared intent for drift.

    Input to OPA: { "workload": workload, "placement": placement, "policies": policies }
    Query target: data.calm.drift.drift_violations

    Returns a dict with keys:
      compliant       bool
      violations      list of {rule, severity, message}
      opa_available   bool
      warning         str | None
    """
    if not is_opa_available():
        return {
            "compliant": True,
            "violations": [],
            "opa_available": False,
            "warning": "OPA CLI not found — drift evaluation skipped.",
        }

    effective_bundle: Path | str
    if bundle_path is not None:
        effective_bundle = _resolve_bundle(bundle_path)
    else:
        effective_bundle = _resolve_bundle(get_bundle_path())

    opa_input = {
        "workload": workload,
        "placement": placement,
        "policies": policies or [],
    }

    try:
        violations = _run_opa_eval(
            opa_input,
            effective_bundle,
            query="data.calm.drift.drift_violations",
        )
    except subprocess.TimeoutExpired:
        return {
            "compliant": False,
            "violations": [{"rule": "opa-timeout", "severity": "error", "message": "OPA drift evaluation timed out"}],
            "opa_available": True,
            "warning": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "compliant": False,
            "violations": [{"rule": "opa-error", "severity": "error", "message": str(exc)}],
            "opa_available": True,
            "warning": None,
        }

    has_errors = any(v.get("severity") == "error" for v in violations)
    return {
        "compliant": not has_errors,
        "violations": violations,
        "opa_available": True,
        "warning": None,
    }


# ---------------------------------------------------------------------------
# Public: bundle watcher
# ---------------------------------------------------------------------------


def start_bundle_watcher(interval_seconds: int = 5) -> None:
    """Start a background daemon thread that polls bundle mtime for changes.

    Only works for local paths. No-op if bundle is a URL or watcher already running.
    """
    global _watcher_thread, _watcher_stop

    current = get_bundle_path()
    if isinstance(current, str) and current.startswith(("http", "oci://")):
        return

    if _watcher_thread is not None and _watcher_thread.is_alive():
        return

    _watcher_stop.clear()

    def _watch() -> None:
        last_mtime: float | None = None
        while not _watcher_stop.is_set():
            try:
                bundle = get_bundle_path()
                p = Path(bundle)
                if p.exists():
                    mtime = p.stat().st_mtime
                    if last_mtime is not None and mtime != last_mtime:
                        set_bundle(str(p))
                    last_mtime = mtime
            except Exception:  # noqa: BLE001
                pass
            _watcher_stop.wait(interval_seconds)

    _watcher_thread = threading.Thread(target=_watch, daemon=True, name="opa-bundle-watcher")
    _watcher_thread.start()


def stop_bundle_watcher() -> None:
    """Signal the watcher thread to stop and join it."""
    global _watcher_thread
    _watcher_stop.set()
    if _watcher_thread is not None:
        _watcher_thread.join(timeout=15)
        _watcher_thread = None


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _run_opa_eval(
    opa_input: dict,
    bundle_path: Path | str,
    query: str = "data.calm.violations",
) -> list[dict]:
    """Run OPA eval and return a list of violation dicts.

    Writes input to a temp JSON file, invokes OPA, and parses the result.
    Returns [] when OPA produces an undefined result (no violations).
    Raises RuntimeError on non-zero OPA exit.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as fh:
        json.dump(opa_input, fh)
        input_file = fh.name

    try:
        result = subprocess.run(
            [
                "opa",
                "eval",
                "--data",
                str(bundle_path),
                "--input",
                input_file,
                "--format",
                "json",
                query,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        Path(input_file).unlink(missing_ok=True)

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    output = json.loads(result.stdout)
    results = output.get("result", [])
    if not results:
        # OPA returned undefined — no violations
        return []

    value = results[0]["expressions"][0]["value"]
    if value is None:
        return []
    return list(value)


def _resolve_bundle(source: str | Path) -> Path | str:
    """Resolve a bundle source to a usable local path or URL string."""
    if isinstance(source, str):
        if source.startswith("oci://"):
            return _pull_oci_bundle(source)
        if source.startswith(("http://", "https://")):
            return _download_bundle(source)
    return Path(source)


def _download_bundle(url: str) -> Path:
    """Download a bundle from HTTP/HTTPS to a local temp directory."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="calm-forge-bundle-"))
    filename = url.split("/")[-1] or "bundle.tar.gz"
    dest = tmp_dir / filename
    urllib.request.urlretrieve(url, str(dest))
    if filename.endswith((".tar.gz", ".tgz")):
        with tarfile.open(str(dest), "r:gz") as tf:
            tf.extractall(str(tmp_dir))
        dest.unlink()
    return tmp_dir


def _pull_oci_bundle(oci_url: str) -> Path:
    """Pull an OCI bundle using the OPA CLI."""
    bare_url = oci_url[len("oci://"):]
    tmp_dir = Path(tempfile.mkdtemp(prefix="calm-forge-oci-"))
    subprocess.run(
        ["opa", "bundle", "pull", "--output", str(tmp_dir), bare_url],
        check=True,
        capture_output=True,
    )
    return tmp_dir
