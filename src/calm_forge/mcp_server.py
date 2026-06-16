"""MCP server for CALM Forge — 9 agent-callable tools via stdio transport.

Tools:
  calm-forge/generate        CALM + decorator + catalog → Stacks HCL + artifacts
  calm-forge/validate        Validate CALM instantiation JSON
  calm-forge/validate-intent Architecture intent validation (OPA stub, full in Sprint 4)
  calm-forge/import          TFE workspace → CALM + migration plan
  calm-forge/diff            Structural diff, impact classification
  calm-forge/catalog         List available modules from a catalog
  calm-forge/patterns        List CALM architecture patterns from knowledge graph
  calm-forge/intake-acm      ACM cluster inventory → ExecutionEnvironment KG nodes
  calm-forge/intake-ansible  AAP job state → Placement KG nodes

Start with: calm-forge mcp
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .diff_engine import diff_calm
from .generator import generate_stack, validate_architecture
from .hcl_validator import validate_hcl_syntax
from .tfe_importer import import_workspaces

mcp = FastMCP("calm-forge")

_KG_DIR = Path(__file__).parent / "knowledge_graph"


# ---------------------------------------------------------------------------
# Tool: calm-forge/generate
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/generate")
def generate_tool(
    calm: dict,
    decorator: dict,
    catalog: dict,
    full: bool = False,
    include_imports: bool = False,
) -> dict:
    """Generate Terraform Stack HCL from CALM architecture + decorator + catalog.

    Returns generated file contents, attestation SHA, file count, and any
    HCL syntax errors found in the generated output.
    """
    return _generate(calm, decorator, catalog, full, include_imports)


def _generate(
    calm: dict,
    decorator: dict,
    catalog: dict,
    full: bool = False,
    include_imports: bool = False,
) -> dict:
    """Implementation for the generate tool."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        calm_path = tmp_path / "calm.json"
        decorator_path = tmp_path / "decorator.json"
        catalog_path = tmp_path / "catalog.json"

        calm_path.write_text(json.dumps(calm))
        decorator_path.write_text(json.dumps(decorator))
        catalog_path.write_text(json.dumps(catalog))

        files = generate_stack(
            str(calm_path),
            str(decorator_path),
            str(catalog_path),
            str(tmp_path / "output"),
            full=full,
            include_imports=include_imports,
        )

        # Compute attestation SHA over all file contents (sorted for determinism)
        combined = "".join(files[k] for k in sorted(files))
        attestation_sha = hashlib.sha256(combined.encode()).hexdigest()

        # Validate HCL syntax on .hcl outputs
        hcl_errors: list[str] = []
        for name, content in files.items():
            if name.endswith(".hcl"):
                errs = validate_hcl_syntax(content)
                for err in errs:
                    hcl_errors.append(f"{name}: {err}")

        return {
            "files": files,
            "file_count": len(files),
            "attestation_sha": attestation_sha,
            "hcl_errors": hcl_errors,
        }


# ---------------------------------------------------------------------------
# Tool: calm-forge/validate
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/validate")
def validate_tool(calm: dict) -> dict:
    """Validate a CALM instantiation JSON dict.

    Returns valid=True and an empty errors list when the architecture is
    structurally correct. Returns valid=False and a list of error strings
    when problems are detected.
    """
    return _validate(calm)


def _validate(calm: dict) -> dict:
    """Implementation for the validate tool."""
    errors = validate_architecture(calm)
    return {
        "valid": len(errors) == 0,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/validate-intent
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/validate-intent")
def validate_intent_tool(calm: dict, decorator: dict | None = None) -> dict:
    """Validate CALM architecture intent against OPA policy bundle."""
    return _validate_intent(calm, decorator)


def _validate_intent(calm: dict, decorator: dict | None = None) -> dict:
    """Implementation for the validate-intent tool."""
    from .opa_gate import validate_intent as opa_validate_intent
    return opa_validate_intent(calm, decorator)


# ---------------------------------------------------------------------------
# Tool: calm-forge/import
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/import")
def import_tool(
    tfe_host: str,
    tfe_token: str,
    org: str,
    workspace_filter: str = "",
    no_tls_verify: bool = False,
) -> dict:
    """Import existing TFE workspaces into CALM format for Stacks migration.

    Reads workspace configs, variables, and state via the TFE API.
    Clusters workspaces into proposed Stacks components and generates
    CALM JSON, import blocks, and a migration plan.
    """
    return _import(tfe_host, tfe_token, org, workspace_filter, no_tls_verify)


def _import(
    tfe_host: str,
    tfe_token: str,
    org: str,
    workspace_filter: str = "",
    no_tls_verify: bool = False,
) -> dict:
    """Implementation for the import tool."""
    with tempfile.TemporaryDirectory() as tmp:
        files = import_workspaces(
            tfe_host=tfe_host,
            tfe_token=tfe_token,
            org=org,
            output_dir=tmp,
            workspace_filter=workspace_filter or None,
            tls_verify=not no_tls_verify,
        )
        return {
            "files": files,
            "file_count": len(files),
        }


# ---------------------------------------------------------------------------
# Tool: calm-forge/diff
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/diff")
def diff_tool(before: dict, after: dict) -> dict:
    """Compute a structural diff between two CALM instantiation dicts.

    Returns added/removed/modified nodes and relationships, impact
    classification (breaking/mutative/additive/none), estimated Terraform
    operation counts, compliance-sensitive field changes, and a summary.
    """
    return _diff(before, after)


def _diff(before: dict, after: dict) -> dict:
    """Implementation for the diff tool."""
    return diff_calm(before, after)


# ---------------------------------------------------------------------------
# Tool: calm-forge/catalog
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/catalog")
def catalog_tool(catalog: dict | None = None) -> dict:
    """List available modules from a catalog, or return catalog schema info.

    When catalog is None, returns documentation about the expected catalog
    schema. When a catalog dict is provided, returns the list of node types
    and a summary of available modules.
    """
    return _catalog(catalog)


def _catalog(catalog: dict | None = None) -> dict:
    """Implementation for the catalog tool."""
    if catalog is None:
        return {
            "schema": {
                "catalog-version": "string — catalog format version",
                "description": "string — human-readable description",
                "modules": {
                    "<node-type>": {
                        "default": "string — default module source",
                        "variants": {
                            "<variant-name>": {
                                "source": "string — module source URL",
                                "description": "string",
                                "match": "dict — matching criteria",
                            }
                        },
                    }
                },
            },
            "note": (
                "Pass a catalog dict to list available modules. "
                "See examples/fsi-3tier/catalog.json for a reference catalog."
            ),
        }

    modules = catalog.get("modules", {})
    node_types = sorted(modules.keys())
    modules_summary: list[dict] = []
    for nt in node_types:
        mod = modules[nt]
        variants = list(mod.get("variants", {}).keys())
        modules_summary.append({
            "node_type": nt,
            "default": mod.get("default") or mod.get("source", ""),
            "variants": variants,
            "variant_count": len(variants),
        })

    return {
        "node_types": node_types,
        "modules": modules_summary,
        "total": len(node_types),
        "catalog_version": catalog.get("catalog-version", "unknown"),
        "description": catalog.get("description", ""),
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/patterns
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/patterns")
def patterns_tool(filter_text: str = "") -> dict:
    """List CALM architecture patterns from the knowledge graph.

    Loads JSON-LD pattern files from the embedded knowledge graph directory.
    Optionally filter by name or tags using a plain-text search string.
    """
    return _patterns(filter_text)


def _patterns(filter_text: str = "") -> dict:
    """Implementation for the patterns tool."""
    from calm_forge.kg_loader import load_patterns, pattern_summary

    summaries = [pattern_summary(p) for p in load_patterns(_KG_DIR)]

    if filter_text:
        needle = filter_text.lower()
        summaries = [
            s for s in summaries
            if needle in s.get("name", "").lower()
            or needle in s.get("purpose", "").lower()
            or any(needle in t.lower() for t in s.get("tags", []))
            or any(needle in c.lower() for c in s.get("compliance_scope", []))
            or any(needle in cap.lower() for cap in s.get("capabilities_required", []))
        ]

    return {
        "patterns": summaries,
        "total": len(summaries),
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/intake-acm
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/intake-acm")
def intake_acm_tool(
    fixture: dict,
    output_dir: str = "",
) -> dict:
    """Populate ExecutionEnvironment KG nodes from ACM cluster inventory.

    Accepts an ACM cluster inventory dict (same shape as examples/acm-inventory.json)
    and produces ExecutionEnvironment nodes in the knowledge graph. When output_dir
    is provided, writes nodes as JSON-LD files to <output_dir>/environments/.

    Returns environment node IDs, regions, labels, and advertised capabilities.
    """
    return _intake_acm(fixture, output_dir)


def _intake_acm(fixture: dict, output_dir: str) -> dict:
    """Implementation for the intake-acm tool."""
    from .intake import intake_acm, write_environment_nodes

    nodes = intake_acm(fixture)
    written: list[str] = []
    if output_dir:
        paths = write_environment_nodes(nodes, Path(output_dir))
        written = [str(p) for p in paths]

    return {
        "environments": [
            {
                "id": n["@id"],
                "region": n.get("region"),
                "labels": n.get("labels", {}),
                "capabilities": n.get("advertised_capabilities", []),
            }
            for n in nodes
        ],
        "count": len(nodes),
        "written": written,
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/intake-ansible
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/intake-ansible")
def intake_ansible_tool(
    fixture: dict,
    environments: list | None = None,
    output_dir: str = "",
) -> dict:
    """Populate Placement KG nodes from AAP job state.

    Accepts an AAP job state dict (same shape as examples/aap-jobs.json) and
    produces Placement nodes linking workloads to ExecutionEnvironments.
    Pass environments (output of intake-acm) to resolve cluster → environment IDs.
    When output_dir is provided, writes nodes as JSON-LD files to
    <output_dir>/placements/.

    Returns placement node IDs, workload IDs, regions, and namespaces.
    """
    return _intake_ansible(fixture, environments or [], output_dir)


def _intake_ansible(fixture: dict, environments: list, output_dir: str) -> dict:
    """Implementation for the intake-ansible tool."""
    from .intake import intake_ansible, write_placement_nodes

    nodes = intake_ansible(fixture, environments)
    written: list[str] = []
    if output_dir:
        paths = write_placement_nodes(nodes, Path(output_dir))
        written = [str(p) for p in paths]

    return {
        "placements": [
            {
                "id": n["@id"],
                "workload_id": n.get("workload_id"),
                "environment_id": n.get("environment_id"),
                "region": n.get("region"),
                "namespace": n.get("namespace"),
            }
            for n in nodes
        ],
        "count": len(nodes),
        "written": written,
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/intake-tfe
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/intake-tfe")
def intake_tfe_tool(
    fixture: dict,
    output_dir: str = "",
) -> dict:
    """Populate Workload KG nodes from HCP Terraform workspace metadata.

    Accepts a TFE workspace inventory dict (same shape as examples/tfe-workspaces.json)
    and produces Workload nodes tagged provenance:reconstructed. These represent
    workloads inferred from TFE state rather than declared via CALM specs.
    When output_dir is provided, writes nodes as JSON-LD files to
    <output_dir>/workloads/.

    Returns workload node IDs, names, tags, resource counts, and review_required flag.
    """
    return _intake_tfe(fixture, output_dir)


def _intake_tfe(fixture: dict, output_dir: str) -> dict:
    """Implementation for the intake-tfe tool."""
    from .intake import intake_tfe, write_workload_nodes

    nodes = intake_tfe(fixture)
    written: list[str] = []
    if output_dir:
        paths = write_workload_nodes(nodes, Path(output_dir))
        written = [str(p) for p in paths]

    return {
        "workloads": [
            {
                "id": n["@id"],
                "name": n.get("name"),
                "tags": n.get("tags", []),
                "resource_count": n.get("resource_count", 0),
                "review_required": n.get("review_required", True),
                "provenance": n["_provenance"]["provenance"],
            }
            for n in nodes
        ],
        "count": len(nodes),
        "written": written,
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/interview
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/interview")
def _interview(
    spec: dict | None = None,
    output_dir: str | None = None,
    proposal: dict | None = None,
    kg_dir: str | None = None,
) -> dict:
    """Author a new Workload KG node from a structured spec or a remediation proposal.

    Produces a complete Workload node in ADR-0024 format with typed
    requires_capability and authored_in edges. The node is written to
    <output_dir>/workloads/ if output_dir is provided.

    Use this tool when a user describes a new service and you need to produce
    a canonical KG node for it. Call calm-forge/kg-status first to check
    whether a similar Workload already exists before authoring a new one.

    When proposal is provided, routes through interview_from_proposal to
    pre-populate the spec with violation context from a RemediationProposal.

    Args:
        spec: Workload description with keys:
          name             (str) workload name
          purpose          (str) one-line description
          owner            (str) owning team
          components       (list) [{name, role?, capabilities: [str]}]
          compliance_scope (list) compliance IDs, e.g. ["PCI-DSS-v4:req-3"]
          allowed_regions  (list) e.g. ["us-east-1", "eu-west-1"]
        output_dir: Optional path to write the node (workloads/ subdir created).
        proposal:   RemediationProposal dict from reconcile (propose=True). When
                    provided, pre-populates the spec with violation context.
        kg_dir:     KG directory path (required when proposal is provided to load
                    the current Workload node).
    """
    from .interviewer import build_workload, interview_from_proposal, write_workload_node

    if proposal is not None:
        result = interview_from_proposal(proposal, Path(kg_dir) if kg_dir else Path("."))
        node = result["workload"]
        written = None
        if output_dir:
            path = write_workload_node(node, Path(output_dir))
            written = str(path)
        caps = node.get("declared_capabilities", [])
        edges = node.get("edges", [])
        req_caps = [e for e in edges if e.get("@type") == "requires_capability"]
        return {
            "node": node,
            "summary": {
                "id": node["@id"],
                "components": len(node.get("nodes", [])),
                "declared_capabilities": caps,
                "requires_capability_edges": len(req_caps),
                "compliance_scope": node.get("compliance_scope", []),
            },
            "written": written,
            "prefilled_fields": result["prefilled_fields"],
            "proposal_confidence": result["proposal_confidence"],
        }

    node = build_workload(spec or {})
    written = None
    if output_dir:
        path = write_workload_node(node, Path(output_dir))
        written = str(path)

    caps = node.get("declared_capabilities", [])
    edges = node.get("edges", [])
    req_caps = [e for e in edges if e.get("@type") == "requires_capability"]
    return {
        "node": node,
        "summary": {
            "id": node["@id"],
            "components": len(node.get("nodes", [])),
            "declared_capabilities": caps,
            "requires_capability_edges": len(req_caps),
            "compliance_scope": node.get("compliance_scope", []),
        },
        "written": written,
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/backstage
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/backstage")
def _backstage(kg_dir: str, output_dir: str | None = None) -> dict:
    """Generate Backstage / Red Hat DevHub Software Catalog entities from a live KG.

    Reads ExecutionEnvironment, Workload, and Placement nodes and emits
    Backstage catalog entities using the calm.io/ annotation namespace.
    Returns the entities as a list of dicts (Backstage catalog format).

    Call calm-forge/kg-status first to verify the KG is populated before
    generating catalog entries.

    Args:
        kg_dir:     Path to the live KG directory.
        output_dir: Optional path to write catalog-info.yaml.
    """
    from .backstage_generator import generate_catalog, write_catalog

    entities = generate_catalog(Path(kg_dir))
    written = None
    if output_dir:
        path = write_catalog(entities, Path(output_dir))
        written = str(path)

    resources = sum(1 for e in entities if e.get("kind") == "Resource")
    components = sum(1 for e in entities if e.get("kind") == "Component")
    return {
        "entities": entities,
        "count": len(entities),
        "resources": resources,
        "components": components,
        "written": written,
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/kg-status
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/kg-status")
def _kg_status(kg_dir: str, namespace: str | None = None) -> dict:
    """Return a structured summary of a live KG directory.

    Reports node counts, drift status breakdown, edge counts, last evaluated
    timestamp, and overall drift status (CLEAN / VIOLATION / UNEVALUATED /
    NO_PLACEMENTS). Use this before generating artifacts to decide whether
    intake is needed or drift is stale.

    Args:
        kg_dir:    Path to the live KG directory (must contain environments/,
                   placements/, or workloads/ subdirectories).
        namespace: Optional namespace name. Pass "*" to aggregate all namespaces.
    """
    from .kg_inspect import kg_status
    return kg_status(Path(kg_dir), namespace=namespace)


# ---------------------------------------------------------------------------
# Tool: calm-forge/kg-query
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/kg-query")
def _kg_query(
    kg_dir: str,
    node_type: str,
    where: list[str] | None = None,
    follow: str | None = None,
    namespace: str | None = None,
) -> dict:
    """Query the live knowledge graph with predicate filters and optional edge traversal.

    Returns matched nodes, optionally enriched with related nodes via typed
    edge traversal (e.g. follow manifests_as from Placement → Workload).

    Args:
        kg_dir:     Path to the live KG directory.
        node_type:  Node type to query: "Placement", "ExecutionEnvironment",
                    "Workload" (aliases "env", "placement", "workload" accepted).
        where:      List of "dot.path=value" filter predicates, all must match.
                    Examples: ["drift_state.status=violation", "region=us-east-1"]
                    Array fields use containment: ["advertised_capabilities=confidential_compute"]
        follow:     Edge type to traverse from each matched node.
                    Currently supported: "manifests_as"
        namespace:  Optional namespace name. Pass "*" to query all namespaces.
    """
    from .kg_query import kg_query
    results = kg_query(Path(kg_dir), node_type, where or [], follow, namespace=namespace)
    return {"results": results, "count": len(results)}


# ---------------------------------------------------------------------------
# Tool: calm-forge/kg-federate-status
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/kg-federate-status")
def kg_federate_status_tool(roots: list[str], namespace: str | None = None) -> dict:
    """Return a federated status summary across multiple KG roots.

    Calls kg_status on each root and returns merged totals plus per-member
    breakdowns. Read-only — no writes are performed.

    Args:
        roots:     List of KG root directory paths to federate across.
        namespace: Optional namespace name passed to each root's kg_status.
    """
    from .kg_multi_root import MultiRootError, multi_root_kg_status
    try:
        return multi_root_kg_status([Path(r) for r in roots], namespace=namespace)
    except MultiRootError as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Tool: calm-forge/kg-federate-query
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/kg-federate-query")
def kg_federate_query_tool(
    roots: list[str],
    node_type: str | None = None,
    where: dict | None = None,
) -> list[dict]:
    """Query across multiple KG roots and return deduplicated results.

    Nodes with the same @id from multiple roots are deduplicated (last root
    wins). Each result node gains a ``_federation_root`` key with its source
    path. Read-only — no writes are performed.

    Args:
        roots:     List of KG root directory paths to query across.
        node_type: Node type alias (Workload, Placement, ExecutionEnvironment).
        where:     Dict of filter predicates (passed as list to kg_query).
    """
    from .kg_multi_root import MultiRootError, multi_root_kg_query
    try:
        return multi_root_kg_query([Path(r) for r in roots], node_type=node_type, where=where)
    except MultiRootError as exc:
        return [{"error": str(exc)}]


# ---------------------------------------------------------------------------
# Tool: calm-forge/fabric-state
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/fabric-state")
def fabric_state_tool(
    kg_dir: str,
    namespace: str | None = None,
) -> dict:
    """Return a full fabric state snapshot for agent consumption.

    Returns all Workloads, their Placements (with drift state and capability
    grants), ExecutionEnvironments, and PlacementPolicy alerts. Includes a
    summary with overall drift status.

    Use this to get a real-time picture of the entire fabric in a single call.
    For targeted queries use calm-forge/kg-query instead.

    Args:
        kg_dir:    Path to the live KG directory.
        namespace: Optional namespace. Pass "*" for all namespaces.
    """
    from .dashboard import build_fabric_feed
    return build_fabric_feed(Path(kg_dir), namespace=namespace)


# ---------------------------------------------------------------------------
# Tool: calm-forge/intake-concert
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/intake-concert")
def intake_concert_tool(
    fixture: dict | None = None,
    output_dir: str = "",
    namespace: str | None = None,
    live: bool = False,
    app_names: list[str] | None = None,
) -> dict:
    """Populate PlacementPolicy KG nodes from a Concert risk export.

    Reads Concert application risk assessments and writes PlacementPolicy nodes
    to <output_dir>/policies/. Policies with blocked_environments trigger a
    concert-risk-placement-block error in validate-intent, blocking deployment
    until the Concert risk is resolved.

    Args:
        fixture:    Concert risk export dict (used when live=False).
        output_dir: Path to write policy nodes (optional).
        namespace:  Namespace subdirectory (optional, for multi-tenant KG).
        live:       When True, fetch from the live Concert API instead of fixture.
                    Requires CALM_FORGE_CONCERT_URL + CALM_FORGE_CONCERT_API_KEY
                    env vars (or CALM_FORGE_CONCERT_FIXTURE for CI fallback).
        app_names:  Optional list of application names to filter (live=True only).
    """
    from .intake import intake_concert, intake_concert_live, write_policy_nodes
    from .kg_namespace import resolve_kg_dir

    if live:
        nodes = intake_concert_live(app_names=app_names)
    else:
        nodes = intake_concert(fixture or {})
    written: list[str] = []
    if output_dir:
        paths = write_policy_nodes(nodes, resolve_kg_dir(Path(output_dir), namespace))
        written = [str(p) for p in paths]

    return {
        "policies": [
            {
                "id": n["@id"],
                "workload_id": n.get("workload_id"),
                "risk_score": n.get("risk_score"),
                "risk_level": n.get("risk_level"),
                "blocked_environments": n.get("blocked_environments", []),
                "constraint": n.get("constraint"),
            }
            for n in nodes
        ],
        "count": len(nodes),
        "blocking": sum(1 for n in nodes if n.get("blocked_environments")),
        "written": written,
    }


# ---------------------------------------------------------------------------
# Tool: calm-forge/agent-run
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/agent-run")
def agent_run_tool(
    kg_dir: str,
    spec: dict | None = None,
    calm: dict | None = None,
    decorator: dict | None = None,
    catalog: dict | None = None,
    output_dir: str | None = None,
    backstage_output_dir: str | None = None,
    gitops_target: str | None = None,
) -> dict:
    """Run the autonomous CALM Forge agent pipeline.

    Executes the full decision protocol in order:
      1. kg-status       — check KG health and drift freshness
      2. kg-query        — check whether a Workload with this name already exists
      3. interview       — author a new Workload KG node from spec (if not existing)
      4. validate-intent — check graph invariants; blocks on error-severity violations
      5. generate        — produce governed artifacts (requires calm+decorator+catalog)
      6. backstage       — update the Backstage / DevHub Software Catalog

    The session is idempotent: re-running with the same spec is safe.

    Args:
        kg_dir:               Path to the live KG directory.
        spec:                 Workload spec dict for interview. Keys: name, purpose,
                              owner, components [{name, capabilities}],
                              compliance_scope, allowed_regions.
        calm:                 CALM instantiation JSON dict (optional — if provided,
                              used for generate; validate-intent uses calm if no spec).
        decorator:            Deployment decorator dict (required for generate).
        catalog:              Module catalog dict (required for generate).
        output_dir:           Path to write generated artifacts (optional).
        backstage_output_dir: Path to write catalog-info.yaml (optional).
        gitops_target:        Path to write deployment artifacts via FilesystemEmitter.
                              When set, a DeploymentRequest KG node is written to
                              kg_dir/deployments/ after artifact generation.

    Returns:
        Session result with: status (success/blocked/error), workload_id,
        workload_authored, violations, artifacts, catalog_entities,
        deployment_request_id, deployment_target, steps.
    """
    from .agent_session import run_agent_session

    request = {
        "spec": spec,
        "calm": calm,
        "decorator": decorator,
        "catalog": catalog,
        "backstage_output_dir": backstage_output_dir,
    }
    return run_agent_session(
        request,
        Path(kg_dir),
        Path(output_dir) if output_dir else None,
        gitops_target=Path(gitops_target) if gitops_target else None,
    )


# ---------------------------------------------------------------------------
# Tool: calm-forge/reconcile
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/reconcile")
def reconcile_tool(
    kg_dir: str,
    dry_run: bool = True,
    propose: bool = False,
) -> dict:
    """Run the drift reconciliation loop against a live KG.

    Reads fabric-state.json (or builds a live feed), detects workloads with
    drift violations, and proposes or executes remediation actions:

      redeploy   — re-emit a DeploymentRequest for capability-ceiling violations
                   that have a pending deployment in flight
      update_kg  — correct the Workload's allowed_regions to match observed
                   reality when Concert does not block the observed region
      escalate   — append a structured record to _fabric/escalations.jsonl
                   for human review (all other cases)

    Args:
        kg_dir:   Path to the live KG directory.
        dry_run:  When True (default), return proposals without writing anything.
                  Set to False to execute actions.

    Returns:
        dict with keys:
          proposals  list of ReconciliationProposal dicts (workload_id, action,
                     reason, deployment_request_id, dry_run, violations)
          executed   list of workload_ids where action was taken (dry_run=False)
          dry_run    bool
    """
    from .reconciler import reconcile as run_reconcile
    return run_reconcile(Path(kg_dir), dry_run=dry_run, propose=propose)


# ---------------------------------------------------------------------------
# Tools: calm-forge/kg-export  calm-forge/kg-import
# ---------------------------------------------------------------------------

@mcp.tool(name="calm-forge/kg-bootstrap")
def kg_bootstrap_tool(
    kg_dir: str,
    sources: list[str] | None = None,
    acm_fixture_path: str | None = None,
    ansible_fixture_path: str | None = None,
    concert_fixture_path: str | None = None,
    concert_live: bool = False,
    namespace: str | None = None,
    backstage_path: str | None = None,
    terraform_state_paths: list[str] | None = None,
) -> dict:
    """Seed a KG directory from connected intake sources in one pass.

    Args:
        kg_dir:                Target KG directory (created if absent).
        sources:               List of sources to run: "acm", "ansible", "concert", "backstage", "terraform".
        acm_fixture_path:      Path to ACM fixture JSON (omit to use empty fixture).
        ansible_fixture_path:  Path to Ansible/AAP fixture JSON.
        concert_fixture_path:  Path to Concert fixture JSON.
        concert_live:          When True, call live Concert API instead of fixture.
        namespace:             Write nodes into a namespace subdirectory.
        backstage_path:        Path to Backstage catalog-info.yaml.
        terraform_state_paths: Paths to .tfstate JSON files.

    Returns:
        BootstrapResult dict with sources_run, nodes_written, errors, total_nodes.
    """
    from .kg_bootstrap import BootstrapConfig, kg_bootstrap
    cfg = BootstrapConfig(
        kg_dir=Path(kg_dir),
        sources=sources or [],
        acm_fixture_path=Path(acm_fixture_path) if acm_fixture_path else None,
        ansible_fixture_path=Path(ansible_fixture_path) if ansible_fixture_path else None,
        concert_fixture_path=Path(concert_fixture_path) if concert_fixture_path else None,
        concert_live=concert_live,
        namespace=namespace,
        backstage_path=Path(backstage_path) if backstage_path else None,
        terraform_state_paths=[Path(p) for p in (terraform_state_paths or [])],
    )
    return kg_bootstrap(cfg).to_dict()


@mcp.tool(name="calm-forge/kg-export")
def kg_export_tool(
    kg_dir: str,
    output_path: str | None = None,
) -> dict:
    """Export a KG directory to a portable bundle zip.

    Args:
        kg_dir:      Path to the source KG directory.
        output_path: Destination zip path. Defaults to <kg_dir>/../kg-bundle.zip.

    Returns:
        dict with key ``bundle_path`` (str).
    """
    from .kg_bundle import kg_export
    bundle = kg_export(Path(kg_dir), Path(output_path) if output_path else None)
    return {"bundle_path": str(bundle)}


@mcp.tool(name="calm-forge/kg-import")
def kg_import_tool(
    bundle_path: str,
    target_kg_dir: str,
    overwrite: bool = False,
) -> dict:
    """Import a KG bundle zip into a target directory.

    Args:
        bundle_path:    Path to the bundle zip produced by kg-export.
        target_kg_dir:  Destination directory. Created if absent.
        overwrite:      Allow writing into a non-empty target. Defaults to False.

    Returns:
        dict with keys ``imported`` (int), ``skipped`` (int), ``conflicts`` (list[str]).
    """
    from .kg_bundle import kg_import
    return kg_import(Path(bundle_path), Path(target_kg_dir), overwrite=overwrite)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run_mcp_server() -> None:
    """Entry point for calm-forge mcp command."""
    from calm_forge.opa_gate import rebuild_builtin_bundle
    rebuild_builtin_bundle()
    mcp.run()
