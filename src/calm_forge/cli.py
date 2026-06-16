"""Click CLI entrypoint for CALM Forge."""

import json
import sys
from pathlib import Path

import click

from .generator import generate_stack, validate_architecture


@click.group()
@click.version_option(package_name="calm-forge")
def cli():
    """CALM Forge — Architecture intent to Terraform Stacks HCL."""


@cli.command()
@click.option("--calm", required=True, type=click.Path(exists=True),
              help="CALM instantiation JSON file")
@click.option("--decorator", required=True, type=click.Path(exists=True),
              help="CALM deployment decorator JSON file")
@click.option("--catalog", required=True, type=click.Path(exists=True),
              help="Module catalog JSON file")
@click.option("--output-dir", required=True, type=click.Path(),
              help="Directory for generated HCL files")
@click.option("--full", is_flag=True, default=False,
              help="Generate all operational artifacts (Vault, Sentinel, Ansible)")
@click.option("--include-imports", is_flag=True, default=False,
              help="Include import blocks for brownfield resource adoption (use with imported CALM)")
@click.option("--validate", "validate_hcl", is_flag=True, default=False,
              help="Validate generated HCL files for syntax correctness")
def generate(calm, decorator, catalog, output_dir, full, include_imports, validate_hcl):
    """Generate Terraform Stack HCL from CALM architecture + decorator + catalog.

    Use --full to also generate Vault policies/PKI, Sentinel policies,
    and Ansible inventory/EDA rulebooks.

    Use --include-imports with CALM specs produced by `calm-forge import`
    to generate import blocks that adopt existing infrastructure into Stacks
    without re-creating it.

    Use --validate to run a lightweight HCL syntax check on generated files.
    """
    try:
        files = generate_stack(
            calm, decorator, catalog, output_dir,
            full=full, include_imports=include_imports,
        )
    except json.JSONDecodeError as exc:
        click.secho(f"Invalid JSON in {exc.doc}: {exc.msg}", fg="red", err=True)
        sys.exit(1)
    except ValueError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
    except FileNotFoundError as exc:
        click.secho(f"Missing input: {exc}", fg="red", err=True)
        sys.exit(2)

    label = "full operational artifact set" if full else "Terraform Stack configuration"
    if include_imports:
        label += " (with import blocks)"
    click.secho(f"Generated {label}:", fg="green")
    for name in files:
        click.echo(f"  {Path(output_dir) / name}")
    click.echo()
    click.echo(f"Source: {Path(calm).name}")
    click.echo(f"Catalog: {Path(catalog).name}")
    click.echo(f"Decorator: {Path(decorator).name}")

    if validate_hcl:
        from .hcl_validator import validate_hcl_syntax

        hcl_files = [name for name in files if name.endswith(".hcl")]
        all_errors = []
        for name in hcl_files:
            content = (Path(output_dir) / name).read_text()
            errors = validate_hcl_syntax(content)
            for err in errors:
                all_errors.append(f"{name}: {err}")

        if all_errors:
            for err in all_errors:
                click.secho(f"HCL error: {err}", fg="red", err=True)
            sys.exit(1)
        else:
            click.secho(
                f"HCL validation passed: {len(hcl_files)} file{'s' if len(hcl_files) != 1 else ''} OK",
                fg="green",
            )


@cli.command()
@click.option("--calm", required=True, type=click.Path(exists=True),
              help="CALM instantiation JSON file to validate")
def validate(calm):
    """Validate a CALM instantiation JSON file."""
    try:
        architecture = json.loads(Path(calm).read_text())
    except json.JSONDecodeError as exc:
        click.secho(f"Invalid JSON: {exc}", fg="red", err=True)
        sys.exit(1)

    errors = validate_architecture(architecture)
    if errors:
        click.secho("Validation failed:", fg="red", err=True)
        for err in errors:
            click.echo(f"  - {err}", err=True)
        sys.exit(1)
    else:
        click.secho(f"Valid CALM instantiation: {Path(calm).name}", fg="green")


@cli.command("validate-intent")
@click.option("--architecture", required=True, type=click.Path(exists=True),
              help="CALM instantiation JSON or Workload KG node to validate")
@click.option("--decorator", "decorator_file", default=None, type=click.Path(exists=True),
              help="CALM deployment decorator JSON (optional)")
@click.option("--sarif", "emit_sarif", is_flag=True, default=False,
              help="Emit SARIF 2.1.0 output instead of human-readable summary")
@click.option("--output", "output_file", default=None, type=click.Path(),
              help="Write output to this file (default: stdout)")
@click.option("--no-opa", is_flag=True, default=False,
              help="Skip OPA evaluation (run semantic checks only)")
@click.option("--kg-dir", "kg_dir", default=None, type=click.Path(exists=True),
              help="KG directory to load PlacementPolicy nodes (enables Concert risk checks)")
def validate_intent_cmd(architecture, decorator_file, emit_sarif, output_file, no_opa, kg_dir):
    """Validate architecture intent against semantic graph invariants.

    Compiles the architecture to a semantic graph and checks design-time
    invariants: compliance-requires-region, pii-requires-compliance,
    capability-ceiling-policy-required. Optionally runs OPA for
    calm.violations rules (requires OPA CLI).

    Exits 0 when clean, 1 when error-severity violations are found.

    \b
    Examples:
      calm-forge validate-intent --architecture instantiation.json
      calm-forge validate-intent --architecture instantiation.json --decorator decorator.json
      calm-forge validate-intent --architecture workload.json --sarif --output results.sarif.json
    """
    import json as _json
    from pathlib import Path as _Path

    from .intent_validator import to_sarif, validate_architecture_intent

    arch_path = _Path(architecture)
    try:
        arch = _json.loads(arch_path.read_text())
    except _json.JSONDecodeError as exc:
        click.secho(f"Invalid JSON in {architecture}: {exc}", fg="red", err=True)
        sys.exit(2)

    decorator: dict | None = None
    if decorator_file:
        try:
            decorator = _json.loads(_Path(decorator_file).read_text())
        except _json.JSONDecodeError as exc:
            click.secho(f"Invalid JSON in {decorator_file}: {exc}", fg="red", err=True)
            sys.exit(2)

    result = validate_architecture_intent(
        arch, decorator, run_opa=not no_opa,
        kg_dir=_Path(kg_dir) if kg_dir else None,
    )

    if emit_sarif:
        output = _json.dumps(to_sarif(result, architecture_uri=str(arch_path)), indent=2)
    else:
        output = _format_validate_intent(result, arch_path.name)

    if output_file:
        _Path(output_file).write_text(output)
        click.echo(f"Results written to {output_file}")
    else:
        click.echo(output)

    if not result["valid"]:
        sys.exit(1)


def _format_validate_intent(result: dict, arch_name: str) -> str:
    """Human-readable validate-intent summary."""
    import io
    out = io.StringIO()
    violations = result["violations"]
    errors = [v for v in violations if v.get("severity") == "error"]
    warnings = [v for v in violations if v.get("severity") != "error"]

    graph = result.get("graph", {})
    wl_id = graph.get("workload_id", arch_name)
    caps = graph.get("declared_capabilities", [])
    compliance = graph.get("compliance_scope", [])

    print(f"\nvalidate-intent: {arch_name}", file=out)
    print("─" * 50, file=out)
    print(f"  Workload:              {wl_id}", file=out)
    print(f"  Capabilities declared: {', '.join(caps) or '(none)'}", file=out)
    if compliance:
        print(f"  Compliance scope:      {', '.join(compliance)}", file=out)
    opa = result.get("opa_result")
    if opa and not opa.get("opa_available"):
        print(f"  OPA:                   {click.style('not available — semantic checks only', fg='yellow')}", file=out)
    print("─" * 50, file=out)

    if not violations:
        print(f"  {click.style('CLEAN', fg='green', bold=True)} — no violations", file=out)
    else:
        for v in errors:
            print(f"  {click.style('ERROR', fg='red', bold=True)}   [{v['rule']}]", file=out)
            print(f"         {v['message']}", file=out)
        for v in warnings:
            print(f"  {click.style('WARNING', fg='yellow')} [{v['rule']}]", file=out)
            print(f"         {v['message']}", file=out)
        status = click.style("VIOLATION", fg="red", bold=True) if errors else click.style("WARNINGS", fg="yellow", bold=True)
        print("─" * 50, file=out)
        print(f"  Status: {status}  ({len(errors)} error(s), {len(warnings)} warning(s))", file=out)

    print(file=out)
    return out.getvalue()


# ---------------------------------------------------------------------------
# Import command — brownfield workspace adoption
# ---------------------------------------------------------------------------

@cli.command("import")
@click.option("--tfe-host", required=True, envvar="TFE_HOST",
              help="TFE/HCP Terraform hostname (e.g., tfe.company.com)")
@click.option("--tfe-token", required=True, envvar="TFE_TOKEN",
              help="TFE API token (or set TFE_TOKEN env var)")
@click.option("--org", required=True,
              help="TFE organization name")
@click.option("--workspace-filter", default=None,
              help="Glob filter for workspace names (e.g., 'payments-*')")
@click.option("--output-dir", required=True, type=click.Path(),
              help="Directory for import artifacts")
@click.option("--no-tls-verify", is_flag=True, default=False,
              help="Skip TLS verification (air-gapped / self-signed certs)")
def import_cmd(tfe_host, tfe_token, org, workspace_filter, output_dir,
               no_tls_verify):
    """Import existing TFE workspaces into CALM format for Stacks migration.

    Reads workspace configs, variables, and state via the TFE API.
    Clusters workspaces into proposed Stacks components.
    Generates CALM JSON, import blocks, and a migration plan.

    \b
    Typical workflow:
      1. calm-forge import --tfe-host tfe.corp.com --org payments --output-dir /tmp/import
      2. Review /tmp/import/migration-plan.md and edit calm-instantiation.json
      3. calm-forge generate --calm /tmp/import/calm-instantiation.json \\
           --decorator /tmp/import/decorator.json --catalog catalog.json \\
           --output-dir /tmp/stacks --full --include-imports
    """
    from .tfe_importer import import_workspaces

    try:
        files = import_workspaces(
            tfe_host=tfe_host,
            tfe_token=tfe_token,
            org=org,
            output_dir=output_dir,
            workspace_filter=workspace_filter,
            tls_verify=not no_tls_verify,
        )
    except ValueError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
    except ConnectionError as exc:
        click.secho(f"TFE API error: {exc}", fg="red", err=True)
        sys.exit(3)

    click.secho("Import complete:", fg="green")
    for name in files:
        click.echo(f"  {Path(output_dir) / name}")

    click.echo()
    click.secho("Next steps:", fg="yellow")
    click.echo("  1. Review migration-plan.md")
    click.echo("  2. Edit calm-instantiation.json if needed")
    click.echo("  3. Run: calm-forge generate \\")
    click.echo(f"       --calm {Path(output_dir) / 'calm-instantiation.json'} \\")
    click.echo(f"       --decorator {Path(output_dir) / 'decorator.json'} \\")
    click.echo("       --catalog <your-catalog.json> \\")
    click.echo("       --output-dir <stacks-output> --full --include-imports")


# ---------------------------------------------------------------------------
# Serve command — start the FastAPI server
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--opa-bundle",
    default=None,
    envvar="CALM_FORGE_OPA_BUNDLE",
    help="OPA policy bundle: local path, https:// URL, or oci:// URL. Default: built-in policies.",
)
def mcp(opa_bundle):
    """Start the CALM Forge MCP server (stdio transport).

    Connects to any MCP-capable agent (Claude Desktop, Cursor, etc.).
    Exposes 7 tools for generating and validating governed infrastructure.

    Requires: pip install 'calm-forge[api]'
    """
    from .opa_gate import is_opa_available, set_bundle, start_bundle_watcher

    set_bundle(opa_bundle)

    if is_opa_available():
        click.secho("OPA available — intent validation active", fg="green")
        if opa_bundle and not opa_bundle.startswith(("http", "oci://")):
            start_bundle_watcher()
            click.secho(f"Bundle watcher started: {opa_bundle}", fg="green")
    else:
        click.secho(
            "OPA CLI not found — install OPA to enable intent validation "
            "(https://www.openpolicyagent.org/docs/latest/#running-opa)",
            fg="yellow",
        )

    try:
        from .mcp_server import run_mcp_server
    except ImportError:
        click.secho(
            "MCP dependencies not installed. Run: pip install 'calm-forge[api]'",
            fg="red",
            err=True,
        )
        sys.exit(1)
    run_mcp_server()


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host")
@click.option("--port", default=8080, show_default=True, type=int, help="Bind port")
@click.option("--no-auth", is_flag=True, default=False,
              help="Disable JWT authentication (local dev only)")
@click.option("--reload", is_flag=True, default=False,
              help="Enable hot-reload (development)")
@click.option(
    "--opa-bundle",
    default=None,
    envvar="CALM_FORGE_OPA_BUNDLE",
    help="OPA policy bundle: local path, https:// URL, or oci:// URL. Default: built-in policies.",
)
@click.option("--ssl-certfile", default=None, envvar="CALM_FORGE_SSL_CERTFILE",
              help="Server TLS certificate (enables HTTPS)")
@click.option("--ssl-keyfile", default=None, envvar="CALM_FORGE_SSL_KEYFILE",
              help="Server TLS private key")
@click.option("--ssl-ca-certs", default=None, envvar="CALM_FORGE_SSL_CA_CERTS",
              help="CA bundle for client cert verification (enables mTLS — required "
                   "for CALM_FORGE_COHERENCE_AUTH=spiffe)")
def serve(host, port, no_auth, reload, opa_bundle, ssl_certfile, ssl_keyfile, ssl_ca_certs):
    """Start the CALM Forge API server.

    Requires API dependencies: pip install 'calm-forge[api]'

    For prod federation (ADR-P3-001 §5), serve with SPIFFE/mTLS:

      CALM_FORGE_COHERENCE_AUTH=spiffe calm-forge serve \\
        --ssl-certfile svid.pem --ssl-keyfile svid.key --ssl-ca-certs trust-bundle.pem
    """
    try:
        import uvicorn
    except ImportError:
        click.secho(
            "API dependencies not installed. Run: pip install 'calm-forge[api]'",
            fg="red", err=True,
        )
        sys.exit(1)

    if no_auth:
        from .jwt_auth import disable_auth
        disable_auth()
        click.secho("Warning: JWT authentication disabled (--no-auth)", fg="yellow")

    from .opa_gate import is_opa_available, set_bundle, start_bundle_watcher

    set_bundle(opa_bundle)

    if is_opa_available():
        click.secho("OPA available — intent validation active", fg="green")
        if opa_bundle and not opa_bundle.startswith(("http", "oci://")):
            start_bundle_watcher()
            click.secho(f"Bundle watcher started: {opa_bundle}", fg="green")
    else:
        click.secho(
            "OPA CLI not found — install OPA to enable intent validation "
            "(https://www.openpolicyagent.org/docs/latest/#running-opa)",
            fg="yellow",
        )

    import os as _os

    coherence_auth_mode = _os.environ.get("CALM_FORGE_COHERENCE_AUTH", "none")
    ssl_kwargs = {}
    if ssl_certfile and ssl_keyfile:
        ssl_kwargs["ssl_certfile"] = ssl_certfile
        ssl_kwargs["ssl_keyfile"] = ssl_keyfile
        if ssl_ca_certs:
            import ssl as _ssl
            ssl_kwargs["ssl_ca_certs"] = ssl_ca_certs
            ssl_kwargs["ssl_cert_reqs"] = _ssl.CERT_REQUIRED
            click.secho("mTLS enabled — client certificates required", fg="green")
    elif ssl_certfile or ssl_keyfile:
        click.secho("--ssl-certfile and --ssl-keyfile must be given together", fg="red", err=True)
        sys.exit(1)

    if coherence_auth_mode == "spiffe" and "ssl_ca_certs" not in ssl_kwargs:
        click.secho(
            "Error: CALM_FORGE_COHERENCE_AUTH=spiffe requires mTLS. "
            "Provide --ssl-certfile, --ssl-keyfile, and --ssl-ca-certs "
            "(cleartext federation is rejected in production — ADR-0024).",
            fg="red", err=True,
        )
        sys.exit(1)

    scheme = "https" if ssl_kwargs else "http"
    click.secho(f"Starting CALM Forge API on {scheme}://{host}:{port}", fg="green")
    if coherence_auth_mode == "spiffe":
        click.secho("Coherence endpoint auth: SPIFFE (prod federation mode)", fg="green")
    uvicorn.run("calm_forge.api:app", host=host, port=port, reload=reload, **ssl_kwargs)


# ---------------------------------------------------------------------------
# Backstage / DevHub entity provider
# ---------------------------------------------------------------------------

@cli.command("backstage")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="KG directory (contains environments/, placements/, workloads/)")
@click.option("--output-dir", default=None, type=click.Path(),
              help="Directory to write catalog-info.yaml (default: print to stdout)")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Emit entities as JSON array instead of YAML")
def backstage_cmd(kg_dir, output_dir, as_json):
    """Generate Backstage / Red Hat DevHub Software Catalog entities from a live KG.

    Reads ExecutionEnvironment, Workload, and Placement nodes and emits
    Backstage catalog entities using the calm.io/ annotation namespace.

    \b
    Output:
      Resource   (kind: kubernetes-cluster)  — one per ExecutionEnvironment
      Component  (kind: service)             — one per Workload, dependsOn the
                                               clusters it is placed on

    \b
    Examples:
      calm-forge backstage --kg-dir /tmp/kg --output-dir /tmp/catalog
      calm-forge backstage --kg-dir /tmp/kg              # prints YAML to stdout
    """
    import json as _json
    from pathlib import Path as _Path

    from .backstage_generator import generate_catalog, to_catalog_yaml, write_catalog

    entities = generate_catalog(_Path(kg_dir))

    if not entities:
        click.echo("No KG nodes found — run intake-acm / intake-ansible first.")
        return

    if as_json:
        click.echo(_json.dumps(entities, indent=2))
        return

    if output_dir:
        path = write_catalog(entities, _Path(output_dir))
        click.secho(f"\nBackstage catalog written: {path}", fg="green")
        click.echo(f"  Entities: {len(entities)}")
        resources = sum(1 for e in entities if e.get("kind") == "Resource")
        components = sum(1 for e in entities if e.get("kind") == "Component")
        click.echo(f"    Resource   (cluster):  {resources}")
        click.echo(f"    Component  (workload):  {components}")
        click.echo()
    else:
        click.echo(to_catalog_yaml(entities))


# ---------------------------------------------------------------------------
# Intake commands — populate KG nodes from live systems or fixtures
# ---------------------------------------------------------------------------


@cli.command("intake-acm")
@click.option("--fixture", required=True, type=click.Path(exists=True),
              help="ACM cluster inventory JSON fixture (e.g., examples/acm-inventory.json)")
@click.option("--output-dir", required=True, type=click.Path(),
              help="Directory to write ExecutionEnvironment JSON-LD nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_acm_cmd(fixture, output_dir, namespace):
    """Populate ExecutionEnvironment KG nodes from ACM cluster inventory.

    Reads an ACM cluster inventory fixture and writes one ExecutionEnvironment
    JSON-LD node per cluster to <output_dir>/environments/.

    \b
    Typical workflow:
      1. calm-forge intake-acm --fixture examples/acm-inventory.json --output-dir /tmp/kg
      2. calm-forge intake-ansible --fixture examples/aap-jobs.json \\
             --env-dir /tmp/kg/environments --output-dir /tmp/kg
      3. calm-forge drift --workload examples/pci-multiregion/instantiation.json \\
             --kg-dir /tmp/kg
    """
    from pathlib import Path as _Path

    from .intake import intake_acm_from_file, write_environment_nodes
    from .kg_namespace import resolve_kg_dir
    nodes = intake_acm_from_file(fixture)
    paths = write_environment_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))
    click.secho(f"Wrote {len(paths)} ExecutionEnvironment node(s):", fg="green")
    for p in paths:
        click.echo(f"  {p}")


@cli.command("intake-ansible")
@click.option("--fixture", required=True, type=click.Path(exists=True),
              help="AAP job state JSON fixture (e.g., examples/aap-jobs.json)")
@click.option("--env-dir", default=None, type=click.Path(exists=True),
              help="Directory containing ExecutionEnvironment JSON-LD nodes (from intake-acm)")
@click.option("--output-dir", required=True, type=click.Path(),
              help="Directory to write Placement JSON-LD nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_ansible_cmd(fixture, env_dir, output_dir, namespace):
    """Populate Placement KG nodes from Ansible AAP job state.

    Reads an AAP job state fixture and writes one Placement JSON-LD node per
    job to <output_dir>/placements/. Pass --env-dir to resolve cluster names
    to ExecutionEnvironment IDs from a prior intake-acm run.
    """
    import json as _json
    from pathlib import Path as _Path

    from .intake import intake_ansible_from_file, write_placement_nodes

    environments = []
    if env_dir:
        for path in sorted(_Path(env_dir).glob("*.json")):
            try:
                node = _json.loads(path.read_text())
                if node.get("@type") == "ExecutionEnvironment":
                    environments.append(node)
            except (ValueError, OSError):
                pass

    from .kg_namespace import resolve_kg_dir
    nodes = intake_ansible_from_file(fixture, environments)
    paths = write_placement_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))
    click.secho(f"Wrote {len(paths)} Placement node(s):", fg="green")
    for p in paths:
        click.echo(f"  {p}")


@cli.command("intake-tfe")
@click.option("--fixture", required=True, type=click.Path(exists=True),
              help="TFE workspace inventory JSON fixture")
@click.option("--output-dir", required=True, type=click.Path(),
              help="Directory to write Workload JSON-LD nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_tfe_cmd(fixture, output_dir, namespace):
    """Populate Workload KG nodes from HCP Terraform workspace metadata.

    Reads a TFE workspace inventory fixture and writes one Workload JSON-LD
    node per workspace to <output_dir>/workloads/. Nodes are tagged
    provenance:reconstructed and review_required:true — they represent
    workloads inferred from TFE state, not declared via CALM.

    \b
    Typical workflow:
      1. calm-forge intake-acm --fixture examples/acm-inventory.json --output-dir /tmp/kg
      2. calm-forge intake-ansible --fixture examples/aap-jobs.json \\
             --env-dir /tmp/kg/environments --output-dir /tmp/kg
      3. calm-forge intake-tfe --fixture examples/tfe-workspaces.json --output-dir /tmp/kg
      4. calm-forge drift --workload examples/pci-multiregion/instantiation.json \\
             --kg-dir /tmp/kg
    """
    from pathlib import Path as _Path

    from .intake import intake_tfe_from_file, write_workload_nodes
    from .kg_namespace import resolve_kg_dir
    nodes = intake_tfe_from_file(fixture)
    paths = write_workload_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))
    click.secho(f"Wrote {len(paths)} Workload node(s):", fg="green")
    for p in paths:
        click.echo(f"  {p}")


@cli.command("intake-concert")
@click.option("--fixture", required=True, type=click.Path(exists=True),
              help="Concert risk export JSON (applications[{name, risk_score, blocked_environments}])")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write PlacementPolicy nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_concert_cmd(fixture, output_dir, namespace):
    """Populate PlacementPolicy KG nodes from a Concert risk export.

    Reads a Concert application risk export and writes PlacementPolicy nodes
    to <output_dir>/policies/. When a PlacementPolicy has blocked_environments,
    validate-intent will emit a concert-risk-placement-block error for that
    workload, blocking deployment until the risk is resolved.

    \b
    Concert export format:
      {
        "applications": [
          {
            "name": "fraud-detection",
            "risk_score": 0.87,
            "risk_level": "critical",
            "blocked_environments": ["env:acm:shared-dev-01"],
            "allowed_environments": [],
            "evaluated_at": "2026-05-08T10:00:00Z"
          }
        ]
      }
    """
    from pathlib import Path as _Path

    from .intake import intake_concert_from_file, write_policy_nodes
    from .kg_namespace import resolve_kg_dir

    nodes = intake_concert_from_file(fixture)
    paths = write_policy_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))
    click.secho(f"Wrote {len(paths)} PlacementPolicy node(s):", fg="green")
    for p in paths:
        click.echo(f"  {p}")
    for node in nodes:
        blocked = node.get("blocked_environments", [])
        if blocked:
            click.secho(
                f"  {node['@id']}: risk={node['risk_score']:.2f} ({node['risk_level']})  "
                f"blocked: {', '.join(blocked)}",
                fg="yellow",
            )


@cli.command("interview")
@click.option("--spec", "spec_file", default=None, type=click.Path(exists=True),
              help="JSON file containing workload spec (non-interactive mode)")
@click.option("--output-dir", default=None, type=click.Path(),
              help="KG directory to write the Workload node to (workloads/ subdir)")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Print the produced Workload node as JSON (also printed in interactive mode)")
@click.option("--from-proposal", "escalation_id", default=None,
              help="Escalation ID (or 0-based index) to load from _fabric/escalations.jsonl")
@click.option("--kg-dir", "kg_dir", default=None, type=click.Path(exists=True),
              help="KG directory (required with --from-proposal)")
def interview_cmd(spec_file, output_dir, as_json, escalation_id, kg_dir):
    """Author a new Workload node through a guided interview.

    Without --spec, launches an interactive session. With --spec, reads the
    workload description from a JSON file and produces the node non-interactively.

    \b
    Spec file format:
      {
        "name": "payments-v2",
        "purpose": "Real-time payment processing",
        "owner": "platform-engineering",
        "components": [
          {"name": "api-gateway", "capabilities": ["http_read", "http_write"]},
          {"name": "processor",   "capabilities": ["vault_dynamic_creds", "pii_read"]}
        ],
        "compliance_scope": ["PCI-DSS-v4:req-3"],
        "allowed_regions": ["us-east-1", "eu-west-1"]
      }
    """
    import json as _json
    from pathlib import Path as _Path

    from .interviewer import (
        build_workload,
        interview_from_proposal,
        interview_interactive,
        write_workload_node,
    )

    if escalation_id is not None:
        if not kg_dir:
            click.secho("--kg-dir is required with --from-proposal", fg="red", err=True)
            sys.exit(1)
        kg_path = _Path(kg_dir)
        escalation_file = kg_path / "_fabric" / "escalations.jsonl"
        if not escalation_file.exists():
            click.secho(f"No escalations file found: {escalation_file}", fg="red", err=True)
            sys.exit(1)
        records = [
            _json.loads(line)
            for line in escalation_file.read_text().splitlines()
            if line.strip()
        ]
        record = None
        if escalation_id.isdigit():
            idx = int(escalation_id)
            if 0 <= idx < len(records):
                record = records[idx]
        if record is None:
            for r in records:
                if r.get("@id") == escalation_id:
                    record = r
                    break
        if record is None:
            click.secho(f"Escalation not found: {escalation_id}", fg="red", err=True)
            sys.exit(1)
        proposal = record.get("remediation_proposal")
        if not proposal:
            click.secho("Escalation has no remediation_proposal — re-run reconcile with --propose", fg="yellow", err=True)
            sys.exit(1)
        result = interview_from_proposal(proposal, kg_path)
        click.echo(_json.dumps(result["workload"], indent=2))
        return

    if spec_file:
        spec = _json.loads(_Path(spec_file).read_text())
    else:
        spec = interview_interactive()

    node = build_workload(spec)

    written_path = None
    if output_dir:
        written_path = write_workload_node(node, _Path(output_dir))

    if as_json or not output_dir:
        click.echo(_json.dumps(node, indent=2))
        return

    slug = node["@id"]
    caps = node.get("declared_capabilities", [])
    edges = node.get("edges", [])
    req_caps = [e for e in edges if e.get("@type") == "requires_capability"]
    click.secho(f"\nWorkload authored: {slug}", fg="green", bold=True)
    click.echo(f"  Components:            {len(node.get('nodes', []))}")
    click.echo(f"  Declared capabilities: {', '.join(caps) or '(none)'}")
    click.echo(f"  requires_capability edges: {len(req_caps)}")
    if node.get("compliance_scope"):
        click.echo(f"  Compliance scope:      {', '.join(node['compliance_scope'])}")
    if written_path:
        click.echo(f"  Written to:            {written_path}")
    click.echo()


@cli.group("kg")
def kg_group():
    """Inspect and query the live knowledge graph."""


@kg_group.command("status")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="KG directory (contains environments/, placements/, workloads/)")
@click.option("--namespace", default=None,
              help="Namespace to inspect (subdirectory). '*' aggregates all namespaces.")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON instead of formatted summary")
@click.option("--federated", is_flag=True, default=False,
              help="Use federation config from --kg-dir and report across all member roots")
def kg_status_cmd(kg_dir, namespace, as_json, federated):
    """Show a summary of what's in a live knowledge graph directory.

    Reports node counts by type, drift status breakdown across Placement nodes,
    reconstructed Workload count, drift event log stats, and overall status.
    """
    import json as _json
    from pathlib import Path as _Path

    from .kg_inspect import kg_status

    if federated:
        from .kg_multi_root import MultiRootError as FederationError
        from .kg_multi_root import load_multi_root_config, multi_root_kg_status
        cfg = load_multi_root_config(_Path(kg_dir))
        if cfg is None:
            raise click.UsageError(f"No multi-root config found at {kg_dir}/_fabric/multi_root.json")
        try:
            result = multi_root_kg_status(cfg.roots, namespace)
        except FederationError as exc:
            raise click.UsageError(str(exc))
        if as_json:
            click.echo(_json.dumps(result, indent=2))
            return
        click.echo(f"\nFederated KG Status — {len(cfg.roots)} root(s)")
        click.echo("─" * 50)
        totals = result["totals"]
        click.echo(f"  {'Environments':<22} {totals['environments']['count']}")
        click.echo(f"  {'Placements':<22} {totals['placements']['count']}")
        click.echo(f"  {'Workloads':<22} {totals['workloads']['count']}")
        click.echo(f"  {'Policies':<22} {totals['policies']['count']}")
        click.echo()
        for member in result["members"]:
            click.echo(f"  Root: {member['root']}")
            click.echo(f"    environments: {member['environments']['count']}  "
                       f"placements: {member['placements']['count']}  "
                       f"workloads: {member['workloads']['count']}")
        click.echo()
        return

    status = kg_status(_Path(kg_dir), namespace=namespace)

    if as_json:
        click.echo(_json.dumps(status, indent=2))
        return

    sep = "─" * 50

    click.echo(f"\nKnowledge Graph: {kg_dir}")
    click.echo(sep)

    # Environments
    env = status["environments"]
    by_s = "  ".join(f"{k}: {v}" for k, v in sorted(env["by_status"].items()))
    click.echo(f"  {'ExecutionEnvironment':<22} {env['count']:<4}  {by_s}")

    # Placements
    pl = status["placements"]
    by_d_parts = []
    for k, v in sorted(pl["by_drift_status"].items()):
        color = "red" if k == "violation" else ("yellow" if k == "pending_first_evaluation" else "green")
        by_d_parts.append(click.style(f"{k}: {v}", fg=color))
    pl_edge_note = f"  manifests_as: {pl['manifests_as_edges']}" if pl.get("manifests_as_edges") else ""
    click.echo(f"  {'Placement':<22} {pl['count']:<4}  {'  '.join(by_d_parts)}{pl_edge_note}")

    # Workloads
    wl = status["workloads"]
    wl_detail = ""
    if wl["reconstructed"]:
        wl_detail = click.style(
            f"reconstructed · review required: {wl['review_required']}", fg="yellow"
        )
    wl_edge_note = f"  requires_capability: {wl['requires_capability_edges']}" if wl.get("requires_capability_edges") else ""
    click.echo(f"  {'Workload':<22} {wl['count']:<4}  {wl_detail}{wl_edge_note}")

    click.echo(sep)

    # Drift events
    ev = status["drift_events"]
    last_ts = ev["last_timestamp"] or "—"
    click.echo(f"  {'Drift events':<22} {ev['count']:<4}  last: {last_ts}")

    # Last evaluated
    last_eval = pl["last_evaluated"] or "—"
    click.echo(f"  {'Last evaluated':<22}       {last_eval}")

    # Overall status
    overall = status["overall_status"]
    color = "green" if overall == "CLEAN" else ("red" if overall == "VIOLATION" else "yellow")
    click.echo(f"  {'Status':<22}       {click.style(overall, fg=color, bold=True)}")
    click.echo()


@kg_group.command("query")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="KG directory (contains environments/, placements/, workloads/)")
@click.option("--type", "node_type", required=True,
              help="Node type to query: Placement, ExecutionEnvironment, Workload (or alias env/placement/workload)")
@click.option("--where", multiple=True, metavar="PATH=VALUE",
              help="Filter predicate, e.g. drift_state.status=violation (repeatable, all must match)")
@click.option("--follow", default=None,
              help="Edge type to traverse from matched nodes, e.g. manifests_as")
@click.option("--namespace", default=None,
              help="Namespace to query (subdirectory). '*' queries all namespaces.")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON instead of formatted results")
@click.option("--federated", is_flag=True, default=False,
              help="Use federation config from --kg-dir and query across all member roots")
def kg_query_cmd(kg_dir, node_type, where, follow, namespace, as_json, federated):
    """Query the live knowledge graph with predicate filters and optional edge traversal.

    \b
    Examples:
      calm-forge kg query --kg-dir /tmp/kg --type Placement --where drift_state.status=violation
      calm-forge kg query --kg-dir /tmp/kg --type ExecutionEnvironment --where status=ready
      calm-forge kg query --kg-dir /tmp/kg --type Placement --where region=us-east-1 --follow manifests_as
      calm-forge kg query --kg-dir /tmp/kg --type Workload --follow manifests_as
    """
    import json as _json
    from pathlib import Path as _Path

    from .kg_query import kg_query

    if federated:
        from .kg_multi_root import MultiRootError as FederationError
        from .kg_multi_root import load_multi_root_config, multi_root_kg_query
        cfg = load_multi_root_config(_Path(kg_dir))
        if cfg is None:
            raise click.UsageError(f"No multi-root config found at {kg_dir}/_fabric/multi_root.json")
        try:
            results = multi_root_kg_query(cfg.roots, node_type=node_type, where=list(where), follow=follow)
        except FederationError as exc:
            raise click.UsageError(str(exc))
        if as_json:
            click.echo(_json.dumps(results, indent=2))
            return
        if not results:
            click.echo(f"No {node_type} nodes matched across federation.")
            return
        for entry in results:
            node = entry.get("node", {})
            node_id = node.get("@id", "?")
            ntype = node.get("@type", node_type)
            root_label = click.style(f"  [{entry.get('_federation_root', '?')}]", fg="cyan")
            click.echo(click.style(f"{ntype}  {node_id}", bold=True) + root_label)
            _print_node_summary(node, ntype)
            click.echo()
        return

    try:
        results = kg_query(_Path(kg_dir), node_type, list(where), follow, namespace=namespace)
    except ValueError as exc:
        raise click.UsageError(str(exc))

    if as_json:
        click.echo(_json.dumps(results, indent=2))
        return

    if not results:
        click.echo(f"No {node_type} nodes matched.")
        return

    for entry in results:
        node = entry["node"]
        node_id = node.get("@id", "?")
        ntype = node.get("@type", node_type)
        click.echo(click.style(f"{ntype}  {node_id}", bold=True))

        # Print a handful of informative fields per type
        _print_node_summary(node, ntype)

        for rel in entry.get("related", []):
            rel_node = rel["node"]
            rel_id = rel_node.get("@id", "?")
            rel_type = rel_node.get("@type", "?")
            direction = "←" if rel["direction"] == "from" else "→"
            edge_label = rel["edge_type"]
            caps = rel["edge_data"].get("capabilities_granted", [])
            cap_str = f"  capabilities_granted: {', '.join(caps)}" if caps else ""
            unresolved = " (unresolved)" if rel_node.get("_unresolved") else ""
            click.echo(f"  └─ {edge_label} {direction} {click.style(rel_type, fg='cyan')}  {rel_id}{unresolved}")
            if cap_str:
                click.echo(f"       {cap_str}")
            ts = rel["edge_data"].get("manifested_at", "")
            if ts:
                click.echo(f"       manifested_at: {ts}")
        click.echo()


def _print_node_summary(node: dict, ntype: str) -> None:
    """Print a compact set of key fields for a node."""
    if ntype == "Placement":
        _kv("  region", node.get("region", ""))
        ds = node.get("drift_state", {})
        status_val = ds.get("status", "")
        color = "red" if status_val == "violation" else ("yellow" if "pending" in status_val else "green")
        _kv("  drift_state.status", click.style(status_val, fg=color))
        _kv("  observed_capabilities", ", ".join(node.get("observed_capabilities", [])))
    elif ntype == "ExecutionEnvironment":
        _kv("  region", node.get("region", ""))
        status_val = node.get("status", "")
        color = "green" if status_val == "ready" else "red"
        _kv("  status", click.style(status_val, fg=color))
        _kv("  advertised_capabilities", ", ".join(node.get("advertised_capabilities", [])))
    elif ntype == "Workload":
        _kv("  name", node.get("name", ""))
        prov = node.get("_provenance", {}).get("provenance", "")
        _kv("  provenance", prov)
        caps = []
        for comp in node.get("nodes", []):
            caps.extend(comp.get("declared_capabilities", []))
        caps.extend(node.get("declared_capabilities", []))
        if caps:
            _kv("  declared_capabilities", ", ".join(sorted(set(caps))))


def _kv(label: str, value: str) -> None:
    if value:
        click.echo(f"{label:<30} {value}")


@kg_group.command("bootstrap")
@click.option("--kg-dir", required=True, type=click.Path(), help="Target KG directory (created if absent)")
@click.option("--acm", "use_acm", is_flag=True, default=False, help="Run ACM intake")
@click.option("--acm-fixture", default=None, type=click.Path(exists=True), help="ACM fixture JSON path")
@click.option("--ansible", "use_ansible", is_flag=True, default=False, help="Run Ansible intake")
@click.option("--ansible-fixture", default=None, type=click.Path(exists=True), help="Ansible fixture JSON path")
@click.option("--concert", "use_concert", is_flag=True, default=False, help="Run Concert intake")
@click.option("--concert-fixture", default=None, type=click.Path(exists=True), help="Concert fixture JSON path")
@click.option("--concert-live", is_flag=True, default=False, help="Call live Concert API instead of fixture")
@click.option("--namespace", default=None, help="Write nodes into a namespace subdirectory")
@click.option("--backstage", "backstage_path", default=None, type=click.Path(exists=True), help="Path to catalog-info.yaml")
@click.option("--terraform", "terraform_paths", multiple=True, type=click.Path(exists=True), help="Path to a .tfstate JSON file (repeatable)")
def kg_bootstrap_cmd(kg_dir, use_acm, acm_fixture, use_ansible, ansible_fixture,
                     use_concert, concert_fixture, concert_live, namespace,
                     backstage_path, terraform_paths):
    """Bootstrap a KG from connected intake sources in one pass.

    \b
    Examples:
      calm-forge kg bootstrap --kg-dir /tmp/kg --acm --acm-fixture examples/acm-inventory.json \\
                               --ansible --ansible-fixture examples/aap-jobs.json \\
                               --concert --concert-fixture examples/concert.json
    """
    from pathlib import Path as _Path

    from .kg_bootstrap import BootstrapConfig, kg_bootstrap

    sources = []
    if use_acm:
        sources.append("acm")
    if use_ansible:
        sources.append("ansible")
    if use_concert:
        sources.append("concert")
    if backstage_path:
        sources.append("backstage")
    if terraform_paths:
        sources.append("terraform")

    if not sources:
        click.secho("No sources specified — pass at least one of --acm, --ansible, --concert, --backstage, --terraform", fg="yellow")
        return

    cfg = BootstrapConfig(
        kg_dir=_Path(kg_dir),
        sources=sources,
        acm_fixture_path=_Path(acm_fixture) if acm_fixture else None,
        ansible_fixture_path=_Path(ansible_fixture) if ansible_fixture else None,
        concert_fixture_path=_Path(concert_fixture) if concert_fixture else None,
        concert_live=concert_live,
        namespace=namespace,
        backstage_path=_Path(backstage_path) if backstage_path else None,
        terraform_state_paths=[_Path(p) for p in terraform_paths],
    )
    result = kg_bootstrap(cfg)

    for source in result.sources_run:
        count = result.nodes_written.get(source, 0)
        click.secho(f"  {source}: {count} node(s) written", fg="green")
    for source, err in result.errors.items():
        click.secho(f"  {source}: ERROR — {err}", fg="red")

    total = sum(result.nodes_written.values())
    click.secho(f"Bootstrap complete: {total} total node(s)", fg="cyan")


@kg_group.command("export")
@click.argument("kg_dir", type=click.Path(exists=True))
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(),
    help="Destination zip path (default: <kg_dir>/../kg-bundle.zip)",
)
def kg_export_cmd(kg_dir, output_path):
    """Export a KG directory to a portable bundle zip.

    \b
    Examples:
      calm-forge kg export /tmp/kg
      calm-forge kg export /tmp/kg --output /tmp/my-bundle.zip
    """
    from pathlib import Path as _Path

    from .kg_bundle import kg_export

    bundle = kg_export(_Path(kg_dir), _Path(output_path) if output_path else None)
    click.secho(f"Exported: {bundle}", fg="green")


@kg_group.command("import")
@click.argument("bundle_path", type=click.Path(exists=True))
@click.argument("target_kg_dir", type=click.Path())
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Allow writing into a non-empty target directory",
)
def kg_import_cmd(bundle_path, target_kg_dir, overwrite):
    """Import a bundle zip into a target KG directory.

    \b
    Examples:
      calm-forge kg import bundle.zip /tmp/kg-restored
      calm-forge kg import bundle.zip /tmp/kg-restored --overwrite
    """
    from pathlib import Path as _Path

    from .kg_bundle import KGBundleError, kg_import

    try:
        result = kg_import(_Path(bundle_path), _Path(target_kg_dir), overwrite=overwrite)
    except KGBundleError as exc:
        click.secho(f"Import failed: {exc}", fg="red", err=True)
        raise SystemExit(1)

    click.secho(
        f"Imported {result['imported']} file(s), skipped {result['skipped']}",
        fg="green",
    )
    if result["conflicts"]:
        click.secho(f"Conflicts ({len(result['conflicts'])}):", fg="yellow")
        for c in result["conflicts"]:
            click.secho(f"  {c}", fg="yellow")


@kg_group.command("federate")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="Primary KG directory where federation.json is stored")
@click.option("--add", "add_root", default=None, type=click.Path(),
              help="Add a root path to the federation")
@click.option("--remove", "remove_root", default=None, type=click.Path(),
              help="Remove a root path from the federation")
@click.option("--list", "list_roots", is_flag=True, default=False,
              help="List current federation member roots")
def kg_federate_cmd(kg_dir, add_root, remove_root, list_roots):
    """Manage federation membership for a KG directory.

    \b
    Examples:
      calm-forge kg federate --kg-dir /tmp/primary --add /tmp/prod-us-east-1
      calm-forge kg federate --kg-dir /tmp/primary --add /tmp/prod-eu-west-1
      calm-forge kg federate --kg-dir /tmp/primary --list
      calm-forge kg federate --kg-dir /tmp/primary --remove /tmp/prod-eu-west-1
    """
    from pathlib import Path as _Path

    from .kg_multi_root import MultiRootConfig as FederationConfig
    from .kg_multi_root import load_multi_root_config as load_federation_config
    from .kg_multi_root import save_multi_root_config as save_federation_config

    primary = _Path(kg_dir)

    if add_root:
        root_path = _Path(add_root)
        if not root_path.exists():
            raise click.UsageError(f"Root path does not exist: {root_path}")
        cfg = load_federation_config(primary) or FederationConfig(roots=[])
        if root_path not in cfg.roots:
            cfg.roots.append(root_path)
        written = save_federation_config(cfg, primary)
        click.secho(f"Added {root_path} → {written}", fg="green")
        return

    if remove_root:
        root_path = _Path(remove_root)
        cfg = load_federation_config(primary) or FederationConfig(roots=[])
        before = len(cfg.roots)
        cfg.roots = [r for r in cfg.roots if r != root_path]
        save_federation_config(cfg, primary)
        if len(cfg.roots) < before:
            click.secho(f"Removed {root_path}", fg="green")
        else:
            click.secho(f"{root_path} was not in the federation", fg="yellow")
        return

    if list_roots:
        cfg = load_federation_config(primary)
        if cfg is None or not cfg.roots:
            click.echo("No federation members configured.")
            return
        for root in cfg.roots:
            click.echo(str(root))
        return

    raise click.UsageError("Specify --add, --remove, or --list")


@kg_group.command("load")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="KG directory containing JSON-LD files (environments/, placements/, workloads/)")
@click.option("--backend", "backend_type", default="kuzu", show_default=True,
              type=click.Choice(["kuzu", "falkordb"]),
              help="Graph index tier to load into")
@click.option("--db-path", default=None,
              help="Kuzu database path (default: <kg-dir>/.calm_forge/kg.db)")
@click.option("--url", default=None, envvar="CALM_FORGE_KG_URL",
              help="FalkorDB Redis URL (required for --backend falkordb)")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output result as JSON")
def kg_load_cmd(kg_dir, backend_type, db_path, url, as_json):
    """Load the KG into a graph index for Cypher traversal queries.

    Ingests all JSON-LD nodes from the KG directory into the embedded Kuzu
    database (default) or a FalkorDB server. Idempotent — safe to re-run;
    existing nodes are updated in place. Enforces the capabilities_granted ⊆
    declared_capabilities invariant at load time and raises an error if any
    authored workload violates it.

    \b
    Examples:
      calm-forge kg load --kg-dir /tmp/kg
      calm-forge kg load --kg-dir /tmp/kg --db-path /tmp/kg.db
      calm-forge kg load --kg-dir /tmp/kg --backend falkordb --url redis://localhost:6379
    """
    import json as _json
    from pathlib import Path as _Path

    try:
        from .kg_kuzu_backend import KGInvariantViolation
    except ImportError:  # pragma: no cover — module has no hard deps
        raise SystemExit(1)

    kg_path = _Path(kg_dir)
    resolved_db_path = None

    if backend_type == "falkordb":
        if not url:
            click.secho(
                "--backend falkordb requires --url (or CALM_FORGE_KG_URL)",
                fg="red", err=True,
            )
            raise SystemExit(1)
        try:
            from .kg_falkordb_backend import FalkorDBBackend
            backend = FalkorDBBackend(url=url)
        except ImportError:
            click.secho(
                "FalkorDB backend not installed. Run: pip install calm-forge[graph]",
                fg="red", err=True,
            )
            raise SystemExit(1)
        target = url
    else:
        try:
            from .kg_kuzu_backend import KuzuBackend
        except ImportError:
            click.secho(
                "Kuzu backend not installed. Run: pip install calm-forge[graph]",
                fg="red", err=True,
            )
            raise SystemExit(1)
        resolved_db_path = _Path(db_path) if db_path else kg_path / ".calm_forge" / "kg.db"
        backend = KuzuBackend(db_path=resolved_db_path)
        target = str(resolved_db_path)

    try:
        backend.load(kg_path)
    except KGInvariantViolation as exc:
        click.secho(f"Invariant violation: {exc}", fg="red", err=True)
        raise SystemExit(1)
    finally:
        backend.close()

    # Count what was indexed
    from .kg_inspect import kg_status
    status = kg_status(kg_path)
    result = {
        "backend": backend_type,
        "target": target,
        "indexed": {
            "workloads": status["workloads"]["count"],
            "environments": status["environments"]["count"],
            "placements": status["placements"]["count"],
            "policies": status.get("policies", {}).get("count", 0),
        },
    }

    if as_json:
        click.echo(_json.dumps(result, indent=2))
        return

    label = "Kuzu" if backend_type == "kuzu" else "FalkorDB"
    click.echo(f"\nKG loaded into {label}: {target}")
    click.echo("─" * 50)
    for k, v in result["indexed"].items():
        click.echo(f"  {k:<22} {v}")
    click.echo()


@cli.command("dashboard")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="KG directory (contains environments/, placements/, workloads/)")
@click.option("--port", default=8080, show_default=True, type=int, help="HTTP port")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address")
@click.option("--namespace", default=None,
              help="Namespace to display. '*' shows all namespaces.")
@click.option("--watch", is_flag=True, default=False,
              help="Watch KG dir for changes and refresh feed automatically")
@click.option("--reconcile", is_flag=True, default=False,
              help="Auto-reconcile drift violations when fabric-state changes (requires --watch)")
@click.option("--feed-only", is_flag=True, default=False,
              help="Print the JSON feed to stdout and exit (no server)")
def dashboard_cmd(kg_dir, port, host, namespace, watch, reconcile, feed_only):
    """Start the CALM Forge drift dashboard.

    Serves two endpoints:
      GET /api/fabric   JSON fabric state snapshot (all workloads, drift state,
                        capability grants, policy alerts)
      GET /             Minimal HTML dashboard with auto-refresh

    Also writes <kg-dir>/fabric-state.json on each refresh for EDA integration.
    With --watch, the feed refreshes automatically when KG files change.

    \b
    Examples:
      calm-forge dashboard --kg-dir /tmp/kg
      calm-forge dashboard --kg-dir /tmp/kg --namespace '*' --watch
      calm-forge dashboard --kg-dir /tmp/kg --feed-only | jq '.summary'
    """
    import json as _json
    from pathlib import Path as _Path

    from .dashboard import build_fabric_feed, serve_dashboard

    kg_path = _Path(kg_dir)

    if feed_only:
        feed = build_fabric_feed(kg_path, namespace=namespace)
        click.echo(_json.dumps(feed, indent=2))
        return

    click.secho("\nCALM Forge Drift Dashboard", fg="green", bold=True)
    click.echo(f"  KG:        {kg_dir}")
    if namespace:
        click.echo(f"  Namespace: {namespace}")
    click.echo(f"  Endpoints: http://{host}:{port}/")
    click.echo(f"             http://{host}:{port}/api/fabric")
    if watch:
        click.secho("  Watching KG for changes…", fg="cyan")
    click.echo()

    try:
        serve_dashboard(kg_path, port=port, host=host, namespace=namespace, watch=watch, reconcile=reconcile)
    except KeyboardInterrupt:
        click.echo("\nDashboard stopped.")


@cli.command("reconcile")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="KG directory")
@click.option("--dry-run", is_flag=True, default=False,
              help="Show proposals without executing (default is to execute)")
@click.option("--once", is_flag=True, default=False,
              help="Run a single pass and exit (default: loop until interrupted)")
@click.option("--interval-seconds", default=300, show_default=True, type=int,
              help="Seconds between reconciliation passes (ignored with --once)")
@click.option("--propose", is_flag=True, default=False,
              help="Attach remediation proposals to escalation actions")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Emit result as JSON")
def reconcile_cmd(kg_dir, dry_run, once, interval_seconds, propose, as_json):
    """Run the drift reconciliation loop.

    Reads fabric-state.json (or builds a live feed), detects workloads with
    drift violations, and proposes or executes remediation:

    \b
      redeploy   — re-emit DeploymentRequest for capability-ceiling violations
      update_kg  — correct Workload allowed_regions to match observed reality
      escalate   — append to _fabric/escalations.jsonl for human review

    Use --propose to attach structured remediation suggestions to escalations.

    \b
    Examples:
      calm-forge reconcile --kg-dir /tmp/kg --dry-run
      calm-forge reconcile --kg-dir /tmp/kg --once
      calm-forge reconcile --kg-dir /tmp/kg --once --propose
    """
    import json as _json
    import time as _time
    from pathlib import Path as _Path

    from .reconciler import reconcile as run_reconcile

    kg_path = _Path(kg_dir)

    def _run_once():
        result = run_reconcile(kg_path, dry_run=dry_run, propose=propose)
        if as_json:
            click.echo(_json.dumps(result, indent=2))
        else:
            proposals = result.get("proposals", [])
            mode = "DRY RUN" if dry_run else "EXECUTING"
            click.secho(f"\nReconcile ({mode}) — {len(proposals)} proposal(s)", bold=True)
            for p in proposals:
                color = {"redeploy": "cyan", "update_kg": "yellow", "escalate": "red"}.get(p["action"], "white")
                click.echo(f"  [{click.style(p['action'].upper(), fg=color)}] {p['workload_id']}")
                click.echo(f"    {p['reason']}")
                if p.get("remediation_proposal"):
                    rp = p["remediation_proposal"]
                    click.secho(f"    Proposal ({rp['confidence']}): {rp['rationale']}", fg="cyan")
            if not proposals:
                click.secho("  No violations to reconcile.", fg="green")
        return result

    if once:
        _run_once()
        return

    try:
        while True:
            _run_once()
            _time.sleep(interval_seconds)
    except KeyboardInterrupt:
        click.echo("\nReconciliation loop stopped.")


@cli.command("agent-run")
@click.option("--kg-dir", required=True, type=click.Path(),
              help="KG directory (will be created if it does not exist)")
@click.option("--spec", "spec_file", default=None, type=click.Path(exists=True),
              help="Workload spec JSON file (for interview step)")
@click.option("--calm", "calm_file", default=None, type=click.Path(exists=True),
              help="CALM instantiation JSON (for validate-intent + generate)")
@click.option("--decorator", "decorator_file", default=None, type=click.Path(exists=True),
              help="Deployment decorator JSON (required for generate)")
@click.option("--catalog", "catalog_file", default=None, type=click.Path(exists=True),
              help="Module catalog JSON (required for generate)")
@click.option("--output-dir", default=None, type=click.Path(),
              help="Directory for generated artifacts")
@click.option("--backstage-output-dir", default=None, type=click.Path(),
              help="Directory to write Backstage catalog-info.yaml")
@click.option("--gitops-target", default=None, type=click.Path(),
              help="Directory to write deployment artifacts (FilesystemEmitter)")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Emit full session result as JSON")
def agent_run_cmd(kg_dir, spec_file, calm_file, decorator_file, catalog_file,
                  output_dir, backstage_output_dir, gitops_target, as_json):
    """Run the autonomous CALM Forge agent pipeline.

    Executes the decision protocol: kg-status → kg-query → interview →
    validate-intent → generate → backstage. Blocks on error-severity
    validate-intent violations. Generate step requires --calm, --decorator,
    and --catalog.

    \b
    Examples:
      calm-forge agent-run --kg-dir /tmp/kg --spec workload-spec.json
      calm-forge agent-run --kg-dir /tmp/kg --spec workload-spec.json \\
          --calm instantiation.json --decorator decorator.json --catalog catalog.json \\
          --output-dir /tmp/artifacts
    """
    import json as _json
    from pathlib import Path as _Path

    from .agent_session import run_agent_session

    kg_path = _Path(kg_dir)
    kg_path.mkdir(parents=True, exist_ok=True)

    def _load(path):
        return _json.loads(_Path(path).read_text()) if path else None

    request = {
        "spec": _load(spec_file),
        "calm": _load(calm_file),
        "decorator": _load(decorator_file),
        "catalog": _load(catalog_file),
        "backstage_output_dir": backstage_output_dir,
    }

    result = run_agent_session(
        request,
        kg_path,
        _Path(output_dir) if output_dir else None,
        gitops_target=_Path(gitops_target) if gitops_target else None,
    )

    if as_json:
        click.echo(_json.dumps(result, indent=2))
        return

    _print_agent_run_result(result)
    if result["status"] in ("blocked", "error"):
        sys.exit(1)


def _print_agent_run_result(result: dict) -> None:
    status = result["status"]
    color = "green" if status == "success" else ("red" if status in ("blocked", "error") else "yellow")
    click.secho(f"\nAgent session: {status.upper()}", fg=color, bold=True)
    if result.get("message"):
        click.echo(f"  {result['message']}")
    if result.get("workload_id"):
        authored = " (authored)" if result.get("workload_authored") else " (existing)"
        click.echo(f"  Workload: {result['workload_id']}{authored}")
    click.echo()
    for step in result.get("steps", []):
        name = step["step"]
        r = step["result"]
        if name == "kg-status":
            overall = r.get("overall_status", "?")
            col = "green" if overall == "CLEAN" else ("red" if overall == "VIOLATION" else "yellow")
            click.echo(f"  {'kg-status':<18} {click.style(overall, fg=col)}")
        elif name == "kg-query":
            found = r.get("found_existing")
            note = f"found existing: {r.get('existing_id')}" if found else "no existing Workload"
            click.echo(f"  {'kg-query':<18} {note}")
        elif name == "interview":
            if r.get("skipped"):
                click.echo(f"  {'interview':<18} skipped ({r.get('reason', '')})")
            else:
                caps = len(r.get("declared_capabilities", []))
                click.echo(f"  {'interview':<18} authored {r.get('workload_id')}  ({caps} capabilities)")
        elif name == "validate-intent":
            valid = r.get("valid")
            viols = r.get("violations", [])
            errors = [v for v in viols if v.get("severity") == "error"]
            warns = [v for v in viols if v.get("severity") != "error"]
            note = click.style("CLEAN", fg="green") if valid else click.style(
                f"{len(errors)} error(s), {len(warns)} warning(s)", fg="red"
            )
            click.echo(f"  {'validate-intent':<18} {note}")
        elif name == "generate":
            if r.get("skipped"):
                click.echo(f"  {'generate':<18} skipped ({r.get('reason', '')})")
            else:
                click.echo(f"  {'generate':<18} {r.get('file_count', 0)} artifact(s)  sha: {r.get('attestation_sha', '')[:12]}…")
        elif name == "backstage":
            if r.get("skipped"):
                click.echo(f"  {'backstage':<18} skipped")
            else:
                written = f"  → {r['written']}" if r.get("written") else ""
                click.echo(f"  {'backstage':<18} {r.get('entities', 0)} entit{'y' if r.get('entities') == 1 else 'ies'}{written}")
    click.echo()


@cli.command("drift")
@click.option("--workload", required=True, type=click.Path(exists=True),
              help="CALM instantiation JSON file")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="Directory containing Placement and ExecutionEnvironment KG nodes")
@click.option("--no-writeback", is_flag=True, default=False,
              help="Skip writing drift state back to Placement KG nodes (default: write back)")
@click.option("--emit-events", is_flag=True, default=False,
              help="Emit a structured calm.drift.evaluated event after evaluation")
@click.option("--event-file", default=None, type=click.Path(),
              help="File path to append drift events (implies --emit-events)")
def drift_cmd(workload, kg_dir, no_writeback, emit_events, event_file):
    """Evaluate drift between declared placement intent and observed placements.

    Compares the declared zones in a CALM spec against Placement nodes written
    by intake-acm + intake-ansible. Reports violations (placed in undeclared
    zone) and warnings (declared zone with no observed placement).

    By default, writes drift_state back to each Placement node (use --no-writeback
    to suppress). Use --emit-events / --event-file to feed an EDA file-watcher.
    """
    import json as _json
    from pathlib import Path as _Path

    from .drift_evaluator import (
        _try_get_backend,
        emit_drift_event,
        evaluate_drift,
        write_drift_state,
    )

    kg_path = _Path(kg_dir)
    calm = _json.loads(_Path(workload).read_text())
    result = evaluate_drift(calm, kg_path)

    if result["status"] == "no_placements_found":
        click.secho("No placement nodes found — run intake-acm + intake-ansible first", fg="yellow")
        return

    if not no_writeback:
        backend = _try_get_backend(kg_path)
        written = write_drift_state(result, kg_path, backend=backend)
        if backend is not None:
            backend.close()
        if written:
            click.secho(f"Wrote drift_state to {len(written)} placement node(s)", fg="cyan")

    if event_file or emit_events:
        target = _Path(event_file) if event_file else _Path("/var/log/calm-forge/drift-events.json")
        emit_drift_event(result, target)
        click.secho(f"Event appended: {target}", fg="cyan")

    click.echo(f"Workload:  {result['workload']}")
    click.echo(f"Declared:  {result['declared_zones']}")
    click.echo(f"Observed:  {[p['region'] for p in result['observed_placements']]}")
    click.echo()

    if not result["drift_detected"] and not result["findings"]:
        click.secho("DRIFT: OK — observed placements match declared intent", fg="green")
        return

    for finding in result["findings"]:
        color = "red" if finding["severity"] == "violation" else "yellow"
        click.secho(f"{finding['severity'].upper()}: {finding['message']}", fg=color)

    if result["drift_detected"]:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# compile-policies command — regenerate OPA bundle from KG predicate nodes
# ---------------------------------------------------------------------------


@cli.command("compile-policies")
@click.option(
    "--kg-dir",
    default=None,
    type=click.Path(exists=True),
    help="Path to knowledge graph directory (default: built-in)",
)
def compile_policies(kg_dir):
    """Recompile the built-in OPA bundle from knowledge graph Policy predicate nodes.

    Reads Workload patterns, extracts typed Policy predicates, and generates
    Rego rules. Replaces calm_violations.rego and calm_drift.rego in the
    built-in bundle. Run this after adding or modifying KG patterns.
    """
    from pathlib import Path as _Path

    from .opa_gate import rebuild_builtin_bundle

    bundle_path = rebuild_builtin_bundle(_Path(kg_dir) if kg_dir else None)
    click.secho(f"Bundle rebuilt: {bundle_path}", fg="green")
    for f in sorted(bundle_path.glob("*.rego")):
        click.secho(f"  {f.name} ({f.stat().st_size} bytes)", fg="cyan")


