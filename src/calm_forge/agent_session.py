"""Agent autonomy session — orchestrates the CALM Forge pipeline autonomously.

Decision protocol:
  1. kg-status       — KG health check
  2. kg-query        — check for existing Workload by name
  3. interview       — author Workload node (if spec provided and not existing)
  4. validate-intent — check graph invariants; block on error-severity violations
  5. generate        — produce governed artifacts (if calm+decorator+catalog provided)
  6. backstage       — update developer portal catalog

The session is idempotent: re-running with the same spec is safe. If a Workload
with the given name already exists in the KG it is used and the interview is
skipped.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run_agent_session(
    request: dict,
    kg_dir: Path,
    output_dir: Path | None = None,
    gitops_target: Path | None = None,
) -> dict:
    """Execute the autonomous agent pipeline.

    Args:
        request: dict with optional keys:
            spec                 Workload spec dict (for interview)
            calm                 CALM instantiation JSON dict (optional)
            decorator            Deployment decorator dict (for generate)
            catalog              Module catalog dict (for generate)
            backstage_output_dir str path to write catalog-info.yaml
        kg_dir:        Path to the live KG directory.
        output_dir:    Path to write generated artifacts (only used when
                       calm+decorator+catalog are all present in request).
        gitops_target: Path to write deployment artifacts via FilesystemEmitter.
                       When None the deploy step is skipped.

    Returns:
        dict with keys: status, workload_id, workload_authored, violations,
        artifacts, catalog_entities, deployment_request_id, deployment_target,
        steps, message.
    """
    return _AgentSession(request, kg_dir, output_dir, gitops_target).run()


class _AgentSession:
    def __init__(
        self,
        request: dict,
        kg_dir: Path,
        output_dir: Path | None,
        gitops_target: Path | None = None,
    ):
        self.request = request
        self.kg_dir = kg_dir
        self.output_dir = output_dir
        self.gitops_target = gitops_target
        self.steps: list[dict] = []
        self.workload_node: dict | None = None
        self.workload_authored = False
        self.deployment_request_id: str | None = None
        self.deployment_target: str | None = None

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def run(self) -> dict:
        # Step 1: KG status
        from .kg_inspect import kg_status
        self._log("kg-status", kg_status(self.kg_dir))

        # Step 2: Check for existing Workload
        spec = self.request.get("spec")
        existing = self._find_existing_workload(spec)
        self._log("kg-query", {
            "checked_for": spec.get("name") if spec else None,
            "found_existing": existing is not None,
            "existing_id": existing.get("@id") if existing else None,
        })

        # Step 3: Interview
        if existing:
            self.workload_node = existing
        elif spec:
            self.workload_node, self.workload_authored = self._interview(spec)
        else:
            self._log("interview", {"skipped": True, "reason": "no spec provided"})

        # Step 4: Validate intent
        arch = self.request.get("calm") or self.workload_node
        if arch is None:
            return self._result("error", "no architecture to validate: provide spec or calm")

        blocked, violations = self._validate_intent(arch)
        if blocked:
            errors = [v for v in violations if v.get("severity") == "error"]
            return self._result(
                "blocked",
                f"{len(errors)} error-severity violation(s): "
                + "; ".join(v["rule"] for v in errors),
                violations=violations,
            )

        # Step 5: Generate (optional)
        artifacts = self._generate()

        # Step 6: Deploy (optional — requires gitops_target + artifacts)
        self._deploy(artifacts)

        # Step 7: Backstage
        catalog_entities = self._backstage()

        return {
            "status": "success",
            "message": "",
            "workload_id": self.workload_node.get("@id") if self.workload_node else None,
            "workload_authored": self.workload_authored,
            "violations": violations,
            "artifacts": artifacts,
            "catalog_entities": catalog_entities,
            "deployment_request_id": self.deployment_request_id,
            "deployment_target": self.deployment_target,
            "steps": self.steps,
        }

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _find_existing_workload(self, spec: dict | None) -> dict | None:
        if not spec or not spec.get("name"):
            return None
        from .kg_query import kg_query
        for entry in kg_query(self.kg_dir, "Workload", [], None):
            node = entry["node"]
            if (node.get("name") == spec["name"]
                    or node.get("@id") == f"workload:{spec['name']}"):
                return node
        return None

    def _interview(self, spec: dict) -> tuple[dict, bool]:
        from .interviewer import build_workload, write_workload_node
        node = build_workload(spec)
        write_workload_node(node, self.kg_dir)
        edges = node.get("edges", [])
        req_caps = [e for e in edges if e.get("@type") == "requires_capability"]
        self._log("interview", {
            "workload_id": node["@id"],
            "authored": True,
            "declared_capabilities": node.get("declared_capabilities", []),
            "requires_capability_edges": len(req_caps),
        })
        return node, True

    def _validate_intent(self, arch: dict) -> tuple[bool, list[dict]]:
        from .intent_validator import validate_architecture_intent
        decorator = self.request.get("decorator")
        result = validate_architecture_intent(arch, decorator, run_opa=True)
        violations = result.get("violations", [])
        errors = [v for v in violations if v.get("severity") == "error"]
        self._log("validate-intent", {"valid": result["valid"], "violations": violations})
        return bool(errors), violations

    def _generate(self) -> dict | None:
        calm_d = self.request.get("calm")
        dec_d = self.request.get("decorator")
        cat_d = self.request.get("catalog")
        if not (calm_d and dec_d and cat_d):
            self._log("generate", {
                "skipped": True,
                "reason": "calm, decorator, and catalog are all required for artifact generation",
            })
            return None

        from .generator import generate_stack
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "calm.json").write_text(json.dumps(calm_d))
            (tmp_path / "decorator.json").write_text(json.dumps(dec_d))
            (tmp_path / "catalog.json").write_text(json.dumps(cat_d))
            out_path = self.output_dir or (tmp_path / "output")
            files = generate_stack(
                str(tmp_path / "calm.json"),
                str(tmp_path / "decorator.json"),
                str(tmp_path / "catalog.json"),
                str(out_path),
                full=False,
            )

        combined = "".join(files[k] for k in sorted(files))
        sha = hashlib.sha256(combined.encode()).hexdigest()
        result = {"files": files, "file_count": len(files), "attestation_sha": sha}
        self._log("generate", {"file_count": len(files), "attestation_sha": sha})
        return result

    def _deploy(self, artifacts: dict | None) -> None:
        if not self.gitops_target:
            self._log("deploy", {"skipped": True, "reason": "no gitops_target provided"})
            return
        if not artifacts:
            self._log("deploy", {"skipped": True, "reason": "no artifacts to deploy"})
            return

        from .gitops_emitter import FilesystemEmitter
        from .intake import write_deployment_request

        workload_id = self.workload_node.get("@id", "workload:unknown") if self.workload_node else "workload:unknown"
        slug = re.sub(r"[^a-z0-9]+", "-", workload_id.replace("workload:", "").lower()).strip("-")
        attestation_sha = artifacts["attestation_sha"]

        emitter = FilesystemEmitter(self.gitops_target)
        emission = emitter.emit(slug, attestation_sha, artifacts["files"])

        node = {
            "@context": "https://calmforge.io/kg/v1/context.jsonld",
            "@type": "DeploymentRequest",
            "@id": f"deploy-req:{slug}:{attestation_sha[:8]}",
            "workload_id": workload_id,
            "attestation_sha": attestation_sha,
            "artifact_paths": emission["artifact_paths"],
            "target_branch": emission.get("target_branch"),
            "target_path": emission["target_path"],
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "requested_by": "calm-forge/agent-run",
            "status": "pending",
            "_provenance": {
                "authored_by": "calm-forge/agent-session",
                "authored_at": datetime.now(timezone.utc).isoformat(),
            },
        }
        write_deployment_request(node, self.kg_dir)

        self.deployment_request_id = node["@id"]
        self.deployment_target = emission["target_path"]
        self._log("deploy", {
            "deployment_request_id": node["@id"],
            "target_path": emission["target_path"],
            "artifact_count": len(emission["artifact_paths"]),
            "emitter_type": emission["emitter_type"],
        })

    def _backstage(self) -> list[dict]:
        from .backstage_generator import generate_catalog, write_catalog
        entities = generate_catalog(self.kg_dir)
        written = None
        out = self.request.get("backstage_output_dir")
        if out:
            path = write_catalog(entities, Path(out))
            written = str(path)
        resources = sum(1 for e in entities if e.get("kind") == "Resource")
        components = sum(1 for e in entities if e.get("kind") == "Component")
        self._log("backstage", {
            "entities": len(entities),
            "resources": resources,
            "components": components,
            "written": written,
        })
        return entities

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _log(self, step: str, result: Any) -> None:
        self.steps.append({"step": step, "result": result})

    def _result(self, status: str, message: str = "", **kwargs) -> dict:
        base: dict = {
            "status": status,
            "message": message,
            "workload_id": self.workload_node.get("@id") if self.workload_node else None,
            "workload_authored": self.workload_authored,
            "deployment_request_id": self.deployment_request_id,
            "deployment_target": self.deployment_target,
            "steps": self.steps,
        }
        base.update(kwargs)
        return base
