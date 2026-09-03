"""Click CLI entrypoint for CALM Forge."""

import json
import sys
import time
from pathlib import Path

import click

from .generator import generate_stack, validate_architecture

_DEFAULT_ISSUER = "spiffe://calm-forge.local/ns/platform/sa/calm-forge"
_DEFAULT_TTL_DAYS = 365

from .kg_plane import PLANES as _PLANES  # noqa: E402  (option choices need it at import)


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
@click.option("--passport", "emit_passport", is_flag=True, default=False,
              help="Also emit a signed Attested Policy Passport per relationship edge")
@click.option("--trust-domain", default="calm-forge.local",
              help="SPIFFE trust domain for passport identities (should-be)")
@click.option("--issuer", default=_DEFAULT_ISSUER,
              help="SPIFFE id of the passport issuer (signer)")
@click.option("--key", "key_path", default=None, type=click.Path(),
              help="Ed25519 signing key (PEM). Generated + saved here if absent.")
@click.option("--environment", default="production",
              type=click.Choice(["production", "staging", "development", "test"]),
              help="Environment recorded in passport intent metadata")
@click.option("--fortinet", "emit_fortinet", is_flag=True, default=False,
              help="Also emit Fortinet candidate config (HCL + FortiOS CLI) per edge")
@click.option("--policy-framework", default="sentinel",
              type=click.Choice(["sentinel", "tfpolicy", "all"]),
              help="Policy language for the --full set: sentinel (default), tfpolicy "
                   "[BETA], or all. OPA is emitted via validate-intent, not here.")
@click.option("--passport-version", default="0.1", type=click.Choice(["0.1", "0.2"]),
              help="Passport wire format for --passport. 0.2 carries per-plane "
                   "graph_refs; the architecture edge_id is identical either way.")
@click.option("--sign-provenance", is_flag=True, default=False,
              help="Also write a signed DSSE envelope beside the SLSA provenance, using "
                   "--key. Without it the provenance is a truthful build record but not "
                   "tamper-evident, so downstream must not treat it as an attestation.")
def generate(calm, decorator, catalog, output_dir, full, include_imports, validate_hcl,
             emit_passport, trust_domain, issuer, key_path, environment, emit_fortinet,
             policy_framework, passport_version, sign_provenance):
    """Generate Terraform Stack HCL from CALM architecture + decorator + catalog.

    Use --full to also generate Vault policies/PKI, Sentinel policies,
    and Ansible inventory/EDA rulebooks.

    Use --include-imports with CALM specs produced by `calm-forge import`
    to generate import blocks that adopt existing infrastructure into Stacks
    without re-creating it.

    Use --validate to run a lightweight HCL syntax check on generated files.
    """
    provenance_key = _load_or_create_key(key_path)[0] if sign_provenance else None
    try:
        files = generate_stack(
            calm, decorator, catalog, output_dir,
            full=full, include_imports=include_imports,
            policy_framework=policy_framework,
            signing_key=provenance_key,
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

    from .provenance import PROVENANCE_ENVELOPE_FILENAME, PROVENANCE_FILENAME
    click.echo(f"\nSLSA provenance: {Path(output_dir) / PROVENANCE_FILENAME}")
    if sign_provenance:
        click.secho(
            f"  signed (DSSE): {Path(output_dir) / PROVENANCE_ENVELOPE_FILENAME}", fg="green"
        )
    else:
        click.secho(
            "  unsigned — a build record, not an attestation (use --sign-provenance)",
            fg="yellow",
        )

    if emit_passport:
        emitted = _emit_passports_from_calm(
            calm, Path(output_dir) / "passports", trust_domain=trust_domain, issuer=issuer,
            key_path=key_path, environment=environment, passport_version=passport_version,
        )
        click.secho(f"\nEmitted {len(emitted)} signed passport(s):", fg="green")
        for path in emitted:
            click.echo(f"  {path}")

    if emit_fortinet:
        fortinet_paths = _emit_fortinet_from_calm(calm, output_dir)
        click.secho(f"\nEmitted Fortinet candidate config ({len(fortinet_paths)} files):", fg="green")
        for path in fortinet_paths:
            click.echo(f"  {path}")

    if validate_hcl:
        from .hcl_validator import validate_hcl_syntax

        to_validate = [name for name in files if name.endswith(".hcl")]
        if emit_fortinet:
            to_validate.append("fortinet/fortinet.tf")  # APP-062: Fortinet HCL through the same gate
        # tfpolicy .policy.hcl / .policytest.hcl are HCL — gate them too. They're already
        # in `files` (they end in .hcl), so no explicit append needed.
        all_errors = []
        for name in to_validate:
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
                f"HCL validation passed: {len(to_validate)} file{'s' if len(to_validate) != 1 else ''} OK",
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

    # Asking for client-cert verification without a server cert to carry it is
    # unsatisfiable: uvicorn would bind cleartext and the operator would believe
    # mTLS was on. Refuse rather than downgrade in silence (ADR-0024).
    if ssl_ca_certs and "ssl_ca_certs" not in ssl_kwargs:
        click.secho(
            "Error: --ssl-ca-certs requires --ssl-certfile and --ssl-keyfile. "
            "Client certificate verification cannot be enabled on a cleartext listener.",
            fg="red", err=True,
        )
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


@cli.command("intake-oscal")
@click.option("--component-definition", required=True, type=click.Path(exists=True),
              help="OSCAL Component Definition JSON")
@click.option("--catalog", default=None, type=click.Path(exists=True),
              help="OSCAL Catalog JSON — supplies each control's declared parameter defaults")
@click.option("--profile", default=None, type=click.Path(exists=True),
              help="OSCAL Profile JSON — baseline tailoring via modify.set-parameters")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write controls-plane nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_oscal_cmd(component_definition, catalog, profile, output_dir, namespace):
    """Compile an OSCAL Component Definition into controls-plane KG nodes.

    One ControlImplementation node per implemented requirement, written to
    <output_dir>/controls/ and tagged plane=controls. Parameters resolve through
    catalog -> profile -> control-implementation -> implemented-requirement, and each
    resolved value records which layer set it.

    \b
    Scope: component-definition plus catalog/profile parameter resolution only.
    Any other OSCAL model is refused by name rather than read to an empty result.

    Exits 1 when a declared parameter is left unresolved. The nodes are still written --
    the catalog is what it is -- but a policy generated from an unresolved parameter has
    a hole in it, and that must not pass a pipeline silently.
    """
    from pathlib import Path as _Path

    from .intake_oscal import intake_oscal_from_file, write_controls_nodes
    from .kg_namespace import resolve_kg_dir

    result = intake_oscal_from_file(
        component_definition, catalog_path=catalog, profile_path=profile
    )
    nodes = result["controls_nodes"]
    paths = write_controls_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))
    click.secho(f"Wrote {len(paths)} ControlImplementation node(s) to the controls plane:",
                fg="green")
    for node, path in zip(nodes, paths):
        click.echo(f"  {node['control_id']:<12} {path}")
        for target in node["governs"]:
            click.echo(f"      governs -> {target}")

    edges = result["edges"]
    if edges:
        click.echo(f"\n{len(edges)} governs edge(s) — controls plane to the objects "
                   f"they constrain.")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} gap(s):", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


@cli.command("intake-tosca")
@click.option("--service-template", "service_template_path", required=True,
              type=click.Path(exists=True),
              help="TOSCA Service Template JSON (topology_template with policies)")
@click.option("--definitions", default=None, type=click.Path(exists=True),
              help="TOSCA type-definitions JSON — supplies policy_type property defaults "
                   "and the derived_from chain")
@click.option("--template-name", default=None,
              help="Service template name used in node GUIDs (defaults to "
                   "metadata.template_name)")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write business_intent-plane nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_tosca_cmd(service_template_path, definitions, template_name, output_dir, namespace):
    """Compile a TOSCA Service Template into business_intent-plane KG nodes.

    One ToscaPolicy node per policy, written to <output_dir>/business_intent/ and tagged
    plane=business_intent. Properties resolve through policy-type-default -> policy, each
    resolved value recording which layer set it, and each policy's governs set joins to
    the architecture plane through the workload URNs / edge ids its targets map to.

    \b
    Scope: topology_template policies plus policy_type property resolution only. A TOSCA
    type-definitions library (node_types/policy_types with no topology_template) is refused
    by name -- pass it via --definitions.

    Exits 1 when a declared required property is left unresolved. The nodes are still
    written -- the template is what it is -- but a policy generated from an unresolved
    property has a hole in it, and that must not pass a pipeline silently.
    """
    from pathlib import Path as _Path

    from .intake_tosca import intake_tosca_from_file, write_business_intent_nodes
    from .kg_namespace import resolve_kg_dir

    result = intake_tosca_from_file(
        service_template_path, definitions_path=definitions, template_name=template_name
    )
    nodes = result["business_intent_nodes"]
    paths = write_business_intent_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))
    click.secho(f"Wrote {len(paths)} ToscaPolicy node(s) to the business_intent plane:",
                fg="green")
    for node, path in zip(nodes, paths):
        click.echo(f"  {node['policy_name']:<28} {path}")
        for target in node["governs"]:
            click.echo(f"      governs -> {target}")

    edges = result["edges"]
    if edges:
        click.echo(f"\n{len(edges)} governs edge(s) — business_intent plane to the "
                   f"objects they constrain.")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} gap(s):", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


@cli.command("intake-anchors")
@click.option("--registry", required=True, type=click.Path(exists=True),
              help="Application registry export (JSON)")
@click.option("--mapping", default=None, type=click.Path(exists=True),
              help="Field mapping aliasing this deployment's export onto the canonical "
                   "contract. Data, not code -- no per-deployment fork of the intake")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write anchor reference nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_anchors_cmd(registry, mapping, output_dir, namespace):
    """Compile an application registry into AccountabilityAnchor reference nodes.

    One anchor per application, written to <output_dir>/reference/anchors/ with
    node_class=reference and no plane -- the registry names things, it authors no
    intent (ADR-012 §1).

    \b
    Three rules fail closed, and a violating entry yields a gap and NO node:
      * accountable_for binds exactly one human (ADR-010 §6)
      * identity_class is declared, never inferred from the shape of an id
      * no personal data enters a node -- resolution to a person is graph-side
        and access-controlled (ADR-010 §2)

    Exits 1 when any entry is refused. A half-valid anchor is indistinguishable from a
    valid one at every downstream reader, so there is nowhere later to catch it.
    """
    from pathlib import Path as _Path

    from .intake_anchor import intake_anchors_from_file, write_anchor_nodes
    from .kg_namespace import resolve_kg_dir

    result = intake_anchors_from_file(registry, mapping_path=mapping)
    nodes = result["reference_nodes"]
    paths = write_anchor_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))
    click.secho(f"Wrote {len(paths)} AccountabilityAnchor node(s) to the reference graph:",
                fg="green")
    for node, path in zip(nodes, paths):
        click.echo(f"  {node['anchor_id']:<12} {path}")
        click.echo(f"      accountable_for -> {node['accountable_for']['id']}")
        if node["associated_with"]:
            click.echo(f"      associated_with -> {len(node['associated_with'])} identity(ies)")

    edges = result["edges"]
    if edges:
        click.echo(f"\n{len(edges)} identity edge(s) -- every one points *up* at an "
                   f"anchor (ADR-010 §6b).")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} refused entry/entries:", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


@cli.command("intake-openlineage")
@click.option("--events", required=True, type=click.Path(exists=True),
              help="OpenLineage event stream: a JSON array or newline-delimited JSON")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write data_management-plane nodes")
@click.option("--position", default=None,
              help="The transport's resumable offset (broker offset, file cursor). "
                   "Recorded verbatim in the watermark and never invented")
@click.option("--retraction-window", default=None, type=int,
              help="Report edges not seen in their job's last N runs. Counted in RUNS, "
                   "never in time -- a clock here would make the same estate answer "
                   "differently depending on when it was asked")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_openlineage_cmd(events, output_dir, position, retraction_window, namespace):
    """Reduce an OpenLineage event stream into data_management-plane KG nodes.

    A run is never a node. Runs collapse onto distinct (job, dataset, direction)
    edges, so millions of runs give a handful of edges and at-least-once
    redelivery is idempotent.

    \b
    Only the schema, ownership and lifecycle dataset facets enter node content.
    Everything else -- row counts, durations, run ids, event timestamps -- is
    DROPPED rather than stored-and-excluded: a field that must be scrubbed before
    comparison is the MP-44 trap rebuilt one layer up.

    \b
    --retraction-window REPORTS candidates; it never retracts. Retraction is an
    attested act that fails closed (ADR-011 §6c) and runs through the API with an
    attester supplied, because an unrecorded retraction is a governance mutation
    with no author.
    """
    from pathlib import Path as _Path

    from .intake_openlineage import (
        intake_openlineage_from_file,
        retraction_candidates,
        write_data_management_nodes,
    )
    from .kg_namespace import resolve_kg_dir

    result = intake_openlineage_from_file(events, position=position)
    paths = write_data_management_nodes(result, resolve_kg_dir(_Path(output_dir), namespace))

    click.secho(f"Reduced {result['watermark']['events_read']} terminal run event(s) to "
                f"{len(result['job_nodes'])} job(s) and {len(result['dataset_nodes'])} "
                f"dataset(s):", fg="green")
    for node, path in zip([*result["job_nodes"], *result["dataset_nodes"]], paths):
        click.echo(f"  {node['@type']:<8} {node['@id']}")
    click.echo(f"\n{len(result['edges'])} lineage edge(s):")
    for edge in result["edges"]:
        click.echo(f"  {edge['from']} --{edge['@type']}--> {edge['to']}")

    mark = result["watermark"]
    click.echo(f"\nWatermark: {mark['events_read']} event(s), position="
               f"{mark['position']!r}, digest {mark['reduced_digest'][:23]}...")
    if mark["position"] is None:
        click.secho("  No transport position supplied -- recorded as absent rather than "
                    "invented. This graph is not resumable from its own watermark.",
                    fg="yellow")

    if retraction_window is not None:
        candidates = retraction_candidates(
            result["observations"], result["run_counts"], window=retraction_window)
        if candidates:
            click.secho(f"\n{len(candidates)} retraction candidate(s) -- reported, NOT "
                        f"retracted:", fg="yellow", bold=True)
            for candidate in candidates:
                click.secho(f"  {candidate['edge_key']}", fg="yellow")
                click.secho(f"      unseen for {candidate['runs_since_last_seen']} of "
                            f"{candidate['job_run_count']} run(s), window "
                            f"{candidate['window']}", fg="yellow")
        else:
            click.echo(f"\nNo edge unseen for {retraction_window} run(s).")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} gap(s):", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


@cli.command("intake-odcs")
@click.option("--contract", required=True, type=click.Path(exists=True),
              help="ODCS data contract (YAML or JSON)")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write declared-side data_management nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_odcs_cmd(contract, output_dir, namespace):
    """Compile an ODCS data contract into declared-side data_management nodes.

    intake-openlineage reads what happened; this reads what was promised. Together
    they are the plane's drift pair (ADR-011 §7b).

    \b
    The observed-side join is DERIVED on read, never stored: a stored derivation would
    enter the node's content digest, so refining the join rule later would re-digest
    every contract and present our code change as their intent changing.

    \b
    A contract whose datasets cannot be joined is reported, never guessed at. A
    fabricated correspondence would make an uncontracted dataset look contracted,
    which is the DATASET_OBSERVED_NOT_CONTRACTED finding inverted.

    Exits 1 when any gap is reported.
    """
    from pathlib import Path as _Path

    from .intake_odcs import (
        intake_odcs_from_file,
        observed_dataset_ids,
        write_contract_nodes,
    )
    from .kg_namespace import resolve_kg_dir

    result = intake_odcs_from_file(contract)
    paths = write_contract_nodes(result, resolve_kg_dir(_Path(output_dir), namespace))

    node = result["contract_nodes"][0]
    click.secho(f"Wrote {len(paths)} declared-side node(s) to the data_management plane:",
                fg="green")
    click.echo(f"  {node['@type']:<18} {node['@id']}")
    for dataset in result["contracted_dataset_nodes"]:
        click.echo(f"  {dataset['@type']:<18} {dataset['@id']}")
        for observed in observed_dataset_ids(dataset):
            click.echo(f"      joins observed -> {observed}")

    edges = result["edges"]
    if edges:
        click.echo(f"\n{len(edges)} edge(s): `declares` within the plane, "
                   f"`associated_with` to the identities the contract names.")
        click.echo("  Accountability is NOT asserted here -- the application registry "
                   "is the system of record for that (ADR-010 §1).")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} gap(s):", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


@cli.command("intake-requirements")
@click.option("--document", required=True, type=click.Path(exists=True),
              help="Requirements document (YAML or JSON)")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write requirements-plane nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_requirements_cmd(document, output_dir, namespace):
    """Compile generative intent into requirements-plane KG nodes.

    Actors, requirements with embedded Gherkin acceptance, and target states,
    written to <output_dir>/requirements/. This is the one plane whose schema Forge
    mints rather than adopts (ADR-015 §6), so the document's requirements_schema
    version is the reader-dispatch key -- an unknown version RAISES.

    \b
    Three rules fail closed:
      * realized_by is never authored -- it derives on read from inbound realizes
        edges. Stored, it would enter the node's digest, so generating an artifact
        would mutate the intent it was generated from.
      * a ratified requirement needs acceptance that projects into a test skeleton.
        A block that cannot project was never executable.
      * workflow fields are refused. Forge is not a requirements-management tool.

    An internal system or agent actor must carry an anchor_ref, and it yields an
    associated_with edge only -- autonomy lives in the execution; accountability
    never leaves the human (ADR-010 §6a).
    """
    from pathlib import Path as _Path

    from .intake_requirements import (
        acceptance_skeletons,
        intake_requirements_from_file,
        realized_by,
        write_requirements_nodes,
    )
    from .kg_namespace import resolve_kg_dir

    result = intake_requirements_from_file(document)
    paths = write_requirements_nodes(result, resolve_kg_dir(_Path(output_dir), namespace))
    edges = result["edges"]

    click.secho(f"Wrote {len(paths)} node(s) to the requirements plane:", fg="green")
    for node in result["actor_nodes"]:
        anchor = node.get("anchor_ref")
        suffix = f"  associated_with -> {anchor}" if anchor else ""
        click.echo(f"  {node['kind']:<7} {node['actor_id']}{suffix}")
    for node in result["requirement_nodes"]:
        click.echo(f"  {node['status']:<11} {node['requirement_id']}")
        for skeleton in acceptance_skeletons(node):
            click.echo(f"      projects -> {skeleton}")
        for target in realized_by(node, edges):
            click.echo(f"      realizes -> {target}")
    for node in result["target_state_nodes"]:
        click.echo(f"  target      {node['target_state_id']}")
        for key, value in node["assertions"].items():
            click.echo(f"      {key} = {value}")
        for target in realized_by(node, edges):
            click.echo(f"      realizes -> {target}")

    if edges:
        click.echo(f"\n{len(edges)} edge(s). `realizes` points forward through generation; "
                   f"`associated_with` never asserts accountability.")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} gap(s):", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


@cli.command("intake-archetypes")
@click.option("--suite", required=True, type=click.Path(exists=True),
              help="Archetype suite document (YAML or JSON)")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write supply_chain-plane suite + archetype nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def intake_archetypes_cmd(suite, output_dir, namespace):
    """Compile an archetype suite into supply_chain-plane KG nodes (MP-32).

    Mechanical half only: node shape, coverage-evidence schema, content digest.
    A suite with zero personas is valid. A persona without coverage evidence is
    a gap and is not written — a guessed name must not land with a real digest.

    The suite digest is computed on read from content (no clock) and printed;
    it is never stored on the node.
    """
    from pathlib import Path as _Path

    from .intake_archetypes import (
        intake_archetypes_from_file,
        persona_count,
        represented_classes,
        suite_digest,
        write_archetype_nodes,
    )
    from .kg_namespace import resolve_kg_dir

    result = intake_archetypes_from_file(suite)
    paths = write_archetype_nodes(result, resolve_kg_dir(_Path(output_dir), namespace))
    suite_node = result["suite_nodes"][0]
    archetypes = result["archetype_nodes"]
    digest = suite_digest(suite_node["suite_version"], archetypes)

    click.secho(
        f"Wrote {len(paths)} supply_chain node(s) — suite {suite_node['suite_version']}:",
        fg="green",
    )
    click.echo(f"  {suite_node['@type']:<16} {suite_node['@id']}")
    click.echo(f"  digest           sha256:{digest}")
    click.echo(f"  personas         {persona_count(archetypes)} (derived, not stored)")
    classes = represented_classes(archetypes)
    if classes:
        click.echo(f"  covers           {', '.join(classes)} (derived)")
    for node in archetypes:
        n_classes = len((node.get("coverage") or {}).get("workload_classes") or [])
        click.echo(f"  {node['@type']:<16} {node['name']}  ({n_classes} class(es) evidenced)")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} gap(s):", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


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


def _load_or_create_key(key_path):
    """Load an Ed25519 key from PEM, generating + saving one if absent."""
    from .passport import generate_keypair, load_private_key, save_private_key

    if key_path and Path(key_path).exists():
        return load_private_key(key_path), False
    key = generate_keypair()
    if key_path:
        Path(key_path).parent.mkdir(parents=True, exist_ok=True)
        save_private_key(key, key_path)
        return key, True
    return key, True


def _join_inventory(edges, inventory):
    """Fill ports the intent left unresolved from an inventory file (APP-093).

    Reports what it did rather than doing it silently: a port learned from the
    fabric is weaker evidence than one declared in intent, and the operator
    should still go declare it.
    """
    if not inventory:
        return edges
    from .passport_seams import load_inventory, resolve_ports_from_inventory

    before = sum(1 for e in edges if e.get("port_unspecified"))
    edges, unresolved = resolve_ports_from_inventory(edges, load_inventory(inventory))
    filled = before - len(unresolved)
    if filled:
        click.secho(f"Inventory resolved {filled} undeclared port(s) "
                    f"— marked port_source=inventory, still worth declaring.", fg="cyan")
    for edge in unresolved:
        ambiguous = edge.get("port_ambiguous")
        why = (f"listens on {ambiguous} — ambiguous" if ambiguous
               else "not in inventory either")
        click.secho(f"  ! no port for {edge['source_workload_urn']} → "
                    f"{edge['destination_workload_urn']}: {why}", fg="yellow")
    return edges


def _resolve_signer(*, key_path, issuer, spire, spire_socket, trust_domain):
    """Return ``(signing_key, issuer)`` for emission.

    With ``--spire``, identity comes from the live SPIRE Workload API: the workload signs with
    its own SVID key (EC P-256 → ``ecdsa-p256``) and the issuer is the SVID's SPIFFE id — real
    attestation, not a should-be. Otherwise a local Ed25519 key + the given issuer (crawl).
    """
    if spire:
        from .passport_seams import SpireWorkloadApiProvider
        from .spire_client import DEFAULT_SOCKET, SpiffeSocketClient

        client = SpiffeSocketClient(spire_socket or DEFAULT_SOCKET)
        provider = SpireWorkloadApiProvider(client, trust_domain=trust_domain)
        return provider.signing_key(), provider.spiffe_id()
    key, _ = _load_or_create_key(key_path)
    return key, issuer


def _emit_passports_from_calm(calm, dest_dir, *, trust_domain, issuer, key_path,
                              environment, ttl_days=_DEFAULT_TTL_DAYS, inventory=None,
                              signing_key=None, passport_version=None):
    """Emit one signed passport per CALM relationship edge into ``dest_dir``.

    ``passport_version`` selects the wire format; ``None`` keeps the emitter default
    (v0.1). v0.2 emits only the architecture plane — the CLI has no plane intake to
    populate controls or business_intent from, and inventing an absence marker for a
    plane we simply have not read would launder ignorance into a governed statement
    (ADR-005 §5).
    """
    from .passport import (
        build_passport,
        context_from_calm,
        edges_from_calm_architecture,
        write_passport,
    )

    architecture = json.loads(Path(calm).read_text())
    edges = edges_from_calm_architecture(architecture, trust_domain=trust_domain)
    edges = _join_inventory(edges, inventory)
    ctx = context_from_calm(architecture)
    key = signing_key if signing_key is not None else _load_or_create_key(key_path)[0]

    issued_at = int(time.time())
    expires_at = issued_at + ttl_days * 86400
    out = Path(dest_dir)

    paths = []
    for edge in edges:
        justification = edge.get("description") or (
            f"{edge['source_workload']} → {edge['destination_workload']}"
            f" over {(edge.get('app_protocol') or ['tcp'])[0]}"
        )
        intent = {
            "business_justification": justification,
            "environment": environment,
            "requested_by": issuer,
            **ctx["intent"],
        }
        passport = build_passport(
            edge, intent, key, issuer,
            issued_at=issued_at, expires_at=expires_at, ownership=ctx["ownership"],
            **({"version": passport_version} if passport_version else {}),
        )
        paths.append(write_passport(passport, out))
    return paths


def _emit_fortinet_from_calm(calm, output_dir):
    """Emit Fortinet candidate config (HCL + CLI) into <output_dir>/fortinet/."""
    from .fortinet_writer import write_fortinet
    from .passport import context_from_calm, edges_from_calm_architecture

    architecture = json.loads(Path(calm).read_text())
    edges = edges_from_calm_architecture(architecture, trust_domain="calm-forge.local")
    compliance = context_from_calm(architecture)["intent"].get("compliance_scope")
    out = Path(output_dir) / "fortinet"
    out.mkdir(parents=True, exist_ok=True)

    paths = []
    for name, content in write_fortinet(edges, compliance=compliance).items():
        path = out / name
        path.write_text(content)
        paths.append(path)
    return paths


@cli.group("passport")
def passport_group():
    """Emit and verify Attested Policy Passports — signed projections of KG edges."""


@passport_group.command("emit")
@click.option("--calm", type=click.Path(exists=True), help="CALM instantiation JSON")
@click.option("--kg", "kg_file", type=click.Path(exists=True), help="KG Workload JSON")
@click.option("--output-dir", required=True, type=click.Path(),
              help="Directory to write <edge-hash>.passport.json files")
@click.option("--trust-domain", default="calm-forge.local",
              help="SPIFFE trust domain for passport identities (should-be)")
@click.option("--issuer", default=_DEFAULT_ISSUER, help="SPIFFE id of the issuer (signer)")
@click.option("--key", "key_path", default=None, type=click.Path(),
              help="Ed25519 signing key (PEM). Generated + saved here if absent.")
@click.option("--environment", default="production",
              type=click.Choice(["production", "staging", "development", "test"]))
@click.option("--ttl-days", default=_DEFAULT_TTL_DAYS, type=int, help="Passport lifetime in days")
@click.option("--inventory", default=None, type=click.Path(exists=True),
              help="Inventory listener table (JSON) — fills ports the intent leaves "
                   "undeclared. Never overrides a declared port; fills are stamped "
                   "port_source=inventory.")
@click.option("--spire", is_flag=True, default=False,
              help="Sign with a live SPIRE X509-SVID (Workload API) instead of a local key. "
                   "The issuer becomes the SVID's SPIFFE id — real attestation (APP-080).")
@click.option("--spire-socket", default=None,
              help="SPIRE agent Workload API socket (default: the SPIFFE CSI mount).")
@click.option("--passport-version", default="0.1", type=click.Choice(["0.1", "0.2"]),
              help="Wire format. 0.2 carries per-plane graph_refs; the architecture "
                   "edge_id is byte-identical either way, so joins survive the bump.")
def passport_emit_cmd(calm, kg_file, output_dir, trust_domain, issuer, key_path,
                      environment, ttl_days, inventory, spire, spire_socket,
                      passport_version):
    """Emit a signed passport per relationship edge from a CALM or KG source.

    graph_ref.edge_id is derived from the L4 identity tuple, so a claim and an
    observed flow of the same edge hash identically. With --spire, the signing
    identity is a live SPIRE SVID; otherwise SPIFFE ids are *should-be*.
    """
    if bool(calm) == bool(kg_file):
        raise click.UsageError("Provide exactly one of --calm or --kg.")

    from .passport import (
        build_passport,
        edges_from_kg_workload,
        ownership_from_kg,
        write_passport,
    )

    signing_key, issuer = _resolve_signer(
        key_path=key_path, issuer=issuer, spire=spire,
        spire_socket=spire_socket, trust_domain=trust_domain,
    )
    if spire:
        click.secho(f"Signing with live SPIRE SVID — issuer {issuer}", fg="cyan")

    if calm:
        paths = _emit_passports_from_calm(
            calm, output_dir, trust_domain=trust_domain, issuer=issuer,
            key_path=key_path, environment=environment, ttl_days=ttl_days,
            inventory=inventory, signing_key=signing_key,
            passport_version=passport_version,
        )
    else:
        kg_doc = json.loads(Path(kg_file).read_text())
        edges = _join_inventory(
            edges_from_kg_workload(kg_doc, trust_domain=trust_domain), inventory
        )
        ownership = ownership_from_kg(kg_doc)
        compliance = kg_doc.get("compliance_scope")
        key = signing_key
        issued_at = int(time.time())
        expires_at = issued_at + ttl_days * 86400
        paths = []
        for edge in edges:
            intent = {
                "business_justification":
                    f"{edge['source_workload']} → {edge['destination_workload']}"
                    f" over {(edge.get('app_protocol') or ['tcp'])[0]}",
                "environment": environment,
                "requested_by": issuer,
            }
            if compliance:
                intent["compliance_scope"] = compliance
            passport = build_passport(
                edge, intent, key, issuer,
                issued_at=issued_at, expires_at=expires_at, ownership=ownership,
                version=passport_version,
            )
            paths.append(write_passport(passport, Path(output_dir)))

    if not paths:
        click.secho("No relationship edges found — nothing emitted.", fg="yellow")
        return
    click.secho(f"Emitted {len(paths)} signed passport(s):", fg="green")
    for path in paths:
        click.echo(f"  {path}")


@passport_group.command("announce")
@click.argument("passport_file", type=click.Path(exists=True))
@click.option(
    "--anchor-ref",
    default=None,
    help="Accountability pointer, kg://anchor/<id> (ADR-010). Omitted when unknown "
         "— never invented.",
)
@click.option(
    "--supersedes",
    default=None,
    help="Previous passport id. Adds the forge.passport.superseded event (ADR-009 §2).",
)
def passport_announce_cmd(passport_file, anchor_ref, supersedes):
    """Emit the OTel announcement for a signed passport (ADR-009).

    Attribute names come from the generated semconv constants, so an unregistered
    forge.* name cannot appear in the payload (ADR-014 §1). This is a join
    accelerator, never proof.
    """
    from .passport_announce import announcement

    passport = json.loads(Path(passport_file).read_text())
    payload = announcement(
        passport, anchor_ref=anchor_ref, superseded_passport_id=supersedes
    )
    click.echo(json.dumps(payload, indent=2, sort_keys=True))


@passport_group.command("diff")
@click.option("--flows", required=True, type=click.Path(exists=True),
              help="Observed flows (JSON list or CSV) — identity-resolved stand-in for NetFlow")
@click.option("--passports", "passports_dir", required=True, type=click.Path(exists=True),
              help="Directory of *.passport.json claims")
@click.option("--now", type=int, default=None, help="Evaluation epoch (defaults to now)")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit raw JSON")
def passport_diff_cmd(flows, passports_dir, now, as_json):
    """Reverse diff: observed flows vs passport claims — the graph knows what the firewall doesn't.

    Prints SHADOW FLOW (traffic with no claim), CONTRACTION CANDIDATE (claim not observed
    or expired), and UNADJUDICABLE (the intent declares no port, so the edge cannot be
    judged either way). Exits non-zero on the first two, so CI can gate on drift —
    unadjudicable edges are a declaration gap, reported but not failed.
    """
    from .passport_diff import diff, load_observed_flows, load_passports

    now = now if now is not None else int(time.time())
    report = diff(load_passports(passports_dir), load_observed_flows(flows), now)

    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        click.secho(
            f"SHADOW {len(report.shadow)}  ·  CONTRACTION {len(report.contraction)}"
            f"  ·  conformant {len(report.conformant)}"
            f"  ·  UNADJUDICABLE {len(report.unadjudicable)}\n",
            bold=True,
        )
        for entry in report.shadow:
            click.secho(f"  SHADOW FLOW          {entry.source} → {entry.destination}", fg="red")
            click.echo(f"    {entry.detail} · {entry.edge_id}")
        for entry in report.contraction:
            click.secho(f"  CONTRACTION CANDIDATE {entry.source} → {entry.destination}", fg="yellow")
            click.echo(f"    {entry.detail} · {entry.edge_id}")
        for entry in report.unadjudicable:
            click.secho(f"  UNADJUDICABLE        {entry.source} → {entry.destination}", fg="cyan")
            click.echo(f"    {entry.detail} · {entry.edge_id}")
            if entry.observed_port is not None:
                # the remediation, not just the complaint
                click.echo(f"    observed on port {entry.observed_port} — declare it in intent")
        if not report.has_findings and not report.has_gaps:
            click.secho("  conformant — every flow has a current claim, every claim is observed.",
                        fg="green")
        elif not report.has_findings:
            click.secho("  no drift — but some edges could not be judged (see above).", fg="green")

    if report.has_findings:
        sys.exit(1)


@passport_group.command("revoke")
@click.option("--passports", "passports_dir", required=True, type=click.Path(exists=True),
              help="Directory of existing *.passport.json claims")
@click.option("--edge-id", default=None, help="Revoke this specific kg://edges/... id")
@click.option("--from-diff", "flows", default=None, type=click.Path(exists=True),
              help="Revoke every CONTRACTION CANDIDATE found against these observed flows")
@click.option("--output-dir", default=None, type=click.Path(),
              help="Where to write tombstones (defaults to --passports)")
@click.option("--issuer", default=_DEFAULT_ISSUER, help="SPIFFE id of the issuer (signer)")
@click.option("--key", "key_path", default=None, type=click.Path(),
              help="Ed25519 signing key (PEM). Generated + saved here if absent.")
@click.option("--grace-days", default=30, type=int,
              help="Days until the tombstone expires — the 'DELETE AFTER' date")
@click.option("--now", type=int, default=None, help="Evaluation epoch (defaults to now)")
def passport_revoke_cmd(passports_dir, edge_id, flows, output_dir, issuer, key_path,
                        grace_days, now):
    """Emit a signed `revoke` tombstone for a claim — contraction as a first-class object.

    The tombstone reuses the grant's binding, so it shares its graph_ref.edge_id and
    supersedes it in the reverse diff. Posture flips to the contraction side of the safety
    split: tense=will-be, authority_class=autonomic-contraction.
    """
    if bool(edge_id) == bool(flows):
        raise click.UsageError("Provide exactly one of --edge-id or --from-diff.")

    from .passport import (
        build_revoke_body,
        edge_id_of,
        sign_passport,
        validate_passport,
        write_passport,
    )
    from .passport_diff import diff, load_observed_flows, load_passports

    now = now if now is not None else int(time.time())
    passports = load_passports(passports_dir)

    if edge_id:
        targets = [edge_id]
    else:
        report = diff(passports, load_observed_flows(flows), now)
        targets = [entry.edge_id for entry in report.contraction]

    if not targets:
        click.secho("No contraction candidates — nothing to revoke.", fg="green")
        return

    # latest grant per edge_id is the thing being revoked
    grants = {}
    for p in passports:
        if p["claim"]["claim_type"] != "grant":
            continue
        eid = edge_id_of(p)
        if eid not in grants or p["lifecycle"]["issued_at"] >= grants[eid]["lifecycle"]["issued_at"]:
            grants[eid] = p

    key, _ = _load_or_create_key(key_path)
    out = Path(output_dir) if output_dir else Path(passports_dir)
    written = []
    for target in targets:
        grant = grants.get(target)
        if grant is None:
            click.secho(f"No grant found for {target} — skipped.", fg="yellow", err=True)
            continue
        body = build_revoke_body(grant, issued_at=now, expires_at=now + grace_days * 86400)
        tombstone = sign_passport(body, key, issuer)
        validate_passport(tombstone)
        written.append(write_passport(tombstone, out))

    click.secho(f"Emitted {len(written)} signed tombstone(s) "
                f"(tense=will-be, DELETE AFTER +{grace_days}d):", fg="yellow")
    for path in written:
        click.echo(f"  {path}")


@passport_group.command("renew")
@click.option("--passports", "passports_dir", required=True, type=click.Path(exists=True),
              help="Directory of existing *.passport.json claims")
@click.option("--output-dir", default=None, type=click.Path(),
              help="Where to write renewed grants (defaults to --passports, superseding in place)")
@click.option("--issuer", default=_DEFAULT_ISSUER, help="SPIFFE id of the issuer (signer)")
@click.option("--key", "key_path", default=None, type=click.Path(),
              help="Ed25519 signing key (PEM). Generated + saved here if absent.")
@click.option("--within-days", default=30, type=int,
              help="Renew grants lapsing within this many days")
@click.option("--ttl-days", default=90, type=int,
              help="Lifetime of the renewed grant from --now")
@click.option("--now", type=int, default=None, help="Evaluation epoch (defaults to now)")
def passport_renew_cmd(passports_dir, output_dir, issuer, key_path, within_days, ttl_days, now):
    """Re-attest grants that are about to lapse — the renewal half of the control loop.

    Every grant expiring within --within-days is re-signed with a fresh --ttl-days window.
    The renewed grant keeps its graph_ref.edge_id, so it supersedes the lapsing one in the
    reverse diff (same edge, later issued_at) rather than minting a second edge. Grants not
    yet due are left untouched. A grant left to lapse becomes a contraction candidate — this
    is what keeps it alive.
    """
    from .passport import edge_id_of, renew_passport, write_passport
    from .passport_diff import load_passports
    from .passport_seams import renewal_due

    now = now if now is not None else int(time.time())
    passports = load_passports(passports_dir)

    # Renew the latest grant per edge — a stale duplicate shouldn't be re-issued.
    grants: dict[str, dict] = {}
    for p in passports:
        if p["claim"]["claim_type"] != "grant":
            continue
        eid = edge_id_of(p)
        if eid not in grants or p["lifecycle"]["issued_at"] >= grants[eid]["lifecycle"]["issued_at"]:
            grants[eid] = p

    due = renewal_due(list(grants.values()), now, within_days=within_days)
    if not due:
        click.secho(f"No grants lapse within {within_days}d — nothing to renew.", fg="green")
        return

    key, _ = _load_or_create_key(key_path)
    out = Path(output_dir) if output_dir else Path(passports_dir)
    written = []
    for grant in due:
        renewed = renew_passport(
            grant, key, issuer, issued_at=now, expires_at=now + ttl_days * 86400
        )
        written.append(write_passport(renewed, out))

    click.secho(f"Renewed {len(written)} grant(s) "
                f"(fresh +{ttl_days}d window, edge_id preserved):", fg="green")
    for path in written:
        click.echo(f"  {path}")


@passport_group.command("verify")
@click.argument("passport_file", type=click.Path(exists=True))
def passport_verify_cmd(passport_file):
    """Verify a passport's Ed25519 signature and schema conformance."""
    from .passport import edge_id_of, validate_passport, verify_passport

    passport = json.loads(Path(passport_file).read_text())
    try:
        validate_passport(passport)
    except Exception as exc:  # jsonschema.ValidationError
        click.secho(f"SCHEMA INVALID: {exc}", fg="red", err=True)
        sys.exit(1)

    if verify_passport(passport):
        edge_id = edge_id_of(passport)
        click.secho(f"VERIFIED — signature valid, schema conformant\n  {edge_id}", fg="green")
    else:
        click.secho("SIGNATURE INVALID", fg="red", err=True)
        sys.exit(1)


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
@click.option("--plane", default=None,
              type=click.Choice(sorted(_PLANES)),
              help="Restrict to one authoring plane. Omit to return every plane — "
                   "results are labelled either way. Reference nodes belong to no "
                   "plane and never appear in a plane-filtered result.")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON instead of formatted results")
@click.option("--federated", is_flag=True, default=False,
              help="Use federation config from --kg-dir and query across all member roots")
def kg_query_cmd(kg_dir, node_type, where, follow, namespace, plane, as_json, federated):
    """Query the live knowledge graph with predicate filters and optional edge traversal.

    \b
    Examples:
      calm-forge kg query --kg-dir /tmp/kg --type Placement --where drift_state.status=violation
      calm-forge kg query --kg-dir /tmp/kg --type ExecutionEnvironment --where status=ready
      calm-forge kg query --kg-dir /tmp/kg --type Placement --where region=us-east-1 --follow manifests_as
      calm-forge kg query --kg-dir /tmp/kg --type Workload --follow manifests_as
      calm-forge kg query --kg-dir /tmp/kg --type Workload --plane controls
    """
    import json as _json
    from pathlib import Path as _Path

    from .kg_query import kg_query

    if federated and plane:
        raise click.UsageError(
            "--plane is not supported with --federated yet: member roots are queried "
            "through a separate path that has no plane filter. Query a single root, or "
            "filter the --json output."
        )

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
        results = kg_query(
            _Path(kg_dir), node_type, list(where), follow,
            namespace=namespace, plane=plane,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc))

    if as_json:
        click.echo(_json.dumps(results, indent=2))
        return

    if not results:
        scope = f" in plane {plane}" if plane else ""
        click.echo(f"No {node_type} nodes matched{scope}.")
        return

    for entry in results:
        node = entry["node"]
        node_id = node.get("@id", "?")
        ntype = node.get("@type", node_type)
        label = entry.get("plane")
        suffix = click.style(f"  [{label}]", fg="magenta") if label else ""
        click.echo(click.style(f"{ntype}  {node_id}", bold=True) + suffix)

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




@kg_group.command("drift")
@click.option("--kg-dir", required=True, type=click.Path(exists=True),
              help="KG directory holding the plane nodes (the current-state side)")
@click.option("--provenance", "provenance_paths", multiple=True, type=click.Path(exists=True),
              help="SLSA provenance file(s) from generated artifacts (repeatable)")
@click.option("--passports", "passports_dir", default=None, type=click.Path(exists=True),
              help="Directory of *.passport.json claims")
@click.option("--vsa", "vsa_paths", multiple=True, type=click.Path(exists=True),
              help="Standing SLSA VSA file(s) from gate runs (repeatable)")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON instead of formatted findings")
def kg_drift_cmd(kg_dir, provenance_paths, passports_dir, vsa_paths, as_json):
    """Cross-plane drift: every part verifies, but is the whole still coherent?

    Compares each artifact's and passport's digest-as-read against the graph's current
    content digests. Comparison is by content, never by clock — a source touched but
    not changed is not drift.

    \b
    Findings:
      CONTROLS_NEWER_THAN_POLICY  plane node moved since compile   -> recompile (autonomic)
      ORPHANED_POLICY             authoring gone, enforcement left -> escalate  (GOVERNED)
      PLANE_MISSING               required plane unauthored        -> author    (GOVERNED)
      STALE_ATTESTATION                 passport referent moved          -> re-issue  (autonomic)
      ARCHETYPES_NEWER_THAN_PROMOTION   suite tightened since VSA       -> escalate  (GOVERNED)
    """
    import json as _json
    from pathlib import Path as _Path

    from .cross_plane_drift import GOVERNED, evaluate
    from .kg_loader import load_patterns
    from .passport_diff import load_passports

    documents = load_patterns(_Path(kg_dir))
    supply_dir = _Path(kg_dir) / "supply_chain"
    if supply_dir.is_dir():
        for path in sorted(supply_dir.glob("*.json")):
            try:
                data = _json.loads(path.read_text())
            except (OSError, _json.JSONDecodeError):
                continue
            if isinstance(data, dict) and data.get("@id"):
                documents.append(data)
    statements = [_json.loads(_Path(p).read_text()) for p in provenance_paths]
    passports = load_passports(passports_dir) if passports_dir else []
    vsas = [_json.loads(_Path(p).read_text()) for p in vsa_paths]

    report = evaluate(documents, statements, passports, vsas=vsas)

    if as_json:
        click.echo(_json.dumps(report.to_dict(), indent=2))
        return

    # Waivers render in their own section, never mixed into findings: "not here on
    # purpose" and "required and unauthored" are different states, and collapsing them
    # at the reporting layer would undo ADR-005 §5 exactly where an operator reads it.
    if report.waivers:
        click.secho(f"\nWaived by policy ({len(report.waivers)}) — governed absence, not a finding:",
                    fg="cyan", bold=True)
        for w in report.waivers:
            click.echo(f"  {w.plane:<16} {w.subject}")
            click.echo(f"  {'':<16} waived by {w.waived_by or '<unnamed rule>'}")

    if not report.findings:
        click.secho("\nNo cross-plane drift.", fg="green")
        return

    for finding in report.findings:
        governed = finding.authority_class == GOVERNED
        colour = "red" if governed else "yellow"
        click.secho(f"\n{finding.finding_type}", fg=colour, bold=True)
        click.echo(f"  subject     {finding.subject}")
        if finding.plane:
            click.echo(f"  plane       {finding.plane}")
        if finding.node_id:
            click.echo(f"  node        {finding.node_id}")
        click.echo(f"  detail      {finding.detail}")
        click.echo(
            f"  action      {finding.remediation} "
            + click.style(
                "(GOVERNED — needs a human)" if governed else "(autonomic)", fg=colour
            )
        )

    counts = report.to_dict()["counts"]
    click.echo()
    click.secho(
        f"{counts['total']} finding(s): {counts['governed']} governed, "
        f"{counts['autonomic']} autonomic.",
        fg="red" if report.governed else "yellow",
    )
    # Governed findings assert that something is unauthorized or unauthored; acting on
    # them changes what the fabric permits, so they are the ones that fail a gate.
    if report.governed:
        sys.exit(1)


@cli.group("gate")
def gate_group():
    """The Gate — run archetype checks and emit signed SLSA VSAs (ADR-013)."""


@gate_group.command("run")
@click.option("--spec", "spec_path", required=True, type=click.Path(exists=True),
              help="Gate spec JSON: {artifact, suite, checks, input_attestations?}")
@click.option("--output-dir", required=True, type=click.Path(),
              help="Directory to write vsa.slsa.json (+ DSSE envelope, quarantine record)")
@click.option("--key", "key_path", default=None, type=click.Path(),
              help="Ed25519 signing key (PEM) for the DSSE-signed VSA. Generated + saved "
                   "here if absent. Without --key the VSA is written unsigned.")
def gate_run_cmd(spec_path, output_dir, key_path):
    """Run an artifact against its archetype checks and emit a VSA.

    The spec supplies the artifact descriptor, the archetype-suite (uri + digest, or
    content to hash), the checks to run, and the input attestations consumed. The verdict
    is PASSED iff every check passes; on FAILED a quarantine record is written and the
    command exits non-zero (fail closed for a promotion pipeline).
    """
    from pathlib import Path as _Path

    from .gate_runner import (
        RESULT_PASSED,
        artifact_descriptor,
        load_gate_spec,
        run_gate,
        suite_descriptor,
        write_gate_result,
    )
    from .passport import generate_keypair, load_private_key, save_private_key

    spec = load_gate_spec(spec_path)

    artifact = spec.get("artifact") or {}
    if "uri" in artifact and "digest" not in artifact:
        artifact = artifact_descriptor(artifact["uri"], artifact.get("digest_sha256", ""))

    suite_in = spec.get("suite") or {}
    if "digest" not in suite_in:
        suite = suite_descriptor(
            suite_in.get("uri", "kg://supply_chain/archetype-suite/unversioned"),
            content=suite_in.get("content"),
            digest_sha256=suite_in.get("digest_sha256"),
        )
    else:
        suite = suite_in

    key = None
    if key_path is not None:
        kp = _Path(key_path)
        if kp.exists():
            key = load_private_key(kp)
        else:
            key = generate_keypair()
            save_private_key(key, kp)

    result = run_gate(
        artifact=artifact,
        suite=suite,
        checks=spec.get("checks") or [],
        input_attestations=spec.get("input_attestations"),
        key=key,
    )
    paths = write_gate_result(result, output_dir)

    colour = "green" if result.passed else "red"
    click.secho(f"Gate {result.result} — {artifact.get('uri', '<artifact>')}", fg=colour, bold=True)
    for outcome in result.outcomes:
        mark = "ok  " if outcome.passed else "FAIL"
        arch = f" [{outcome.archetype}]" if outcome.archetype else ""
        click.echo(f"  {mark} {outcome.name}{arch}: {outcome.detail}")
    click.echo("")
    for path in paths:
        click.echo(f"  wrote {path}")

    if result.result != RESULT_PASSED:
        raise SystemExit(1)


@gate_group.command("countersign")
@click.option("--envelope", "envelope_path", required=True, type=click.Path(exists=True),
              help="DSSE-signed VSA from `gate run` (vsa.slsa.dsse.json)")
@click.option("--key", "key_path", required=True, type=click.Path(),
              help="Ed25519 countersigner key (PEM). Generated + saved here if absent.")
@click.option("--anchor-ref", required=True,
              help="kg://anchor/<id> of the accountable human (ADR-010). Required — "
                   "the countersignature resolves through this, never a name.")
@click.option("--output", "output_path", required=True, type=click.Path(),
              help="Where to write the countersigned envelope")
def gate_countersign_cmd(envelope_path, key_path, anchor_ref, output_path):
    """Add the app-tier countersignature on a gate VSA (ADR-013 §2).

    Two signatures, one subject: the automated gate and the accountable human
    approve the same digest. Promotion is governed-expansion — this is the human.
    """
    from pathlib import Path as _Path

    from .gate_admission import AdmissionError, countersign_envelope
    from .passport import generate_keypair, load_private_key, save_private_key

    envelope = json.loads(_Path(envelope_path).read_text())
    kp = _Path(key_path)
    if kp.exists():
        key = load_private_key(kp)
    else:
        key = generate_keypair()
        save_private_key(key, kp)
    try:
        signed = countersign_envelope(envelope, key, anchor_ref=anchor_ref)
    except AdmissionError as exc:
        click.secho(str(exc), fg="red", err=True)
        raise SystemExit(1) from exc
    out = _Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(signed, indent=2) + "\n")
    click.secho(f"Countersigned — {anchor_ref}", fg="green")
    click.echo(f"  wrote {out}")


@gate_group.command("admit")
@click.option("--envelope", "envelope_path", required=True, type=click.Path(exists=True),
              help="Countersigned DSSE VSA")
@click.option("--gate-key", "gate_key_path", required=True, type=click.Path(exists=True),
              help="Gate signer PEM — public key is derived (crawl-stage trust source)")
@click.option("--countersigner-key", "counter_key_path", required=True,
              type=click.Path(exists=True),
              help="Countersigner PEM — public key is derived")
@click.option("--pull", "pull_ref", required=True,
              help="The production pull reference. Must be a digest pin "
                   "(name@sha256:… or sha256:…). Tags are rejected.")
@click.option("--anchors", "anchors_path", required=True, type=click.Path(exists=True),
              help="AccountabilityAnchor nodes (JSON list or {reference_nodes: […]})")
@click.option("--gate-unavailable", is_flag=True, default=False,
              help="Gate is down. Promotion fails closed; quarantine is unaffected "
                   "(ADR-013 follow-up 7).")
def gate_admit_cmd(envelope_path, gate_key_path, counter_key_path, pull_ref,
                   anchors_path, gate_unavailable):
    """Tier 3 admission: verify the VSA chain and enforce the digest pin.

    Stock DSSE verification of both signatures, subject digest matches the pull,
    countersignature resolves to a human via the anchor chain. Exits non-zero on
    any failure — fail closed (ADR-013 §1).
    """
    from pathlib import Path as _Path

    from .gate_admission import AdmissionError, admit, load_anchors
    from .passport import load_private_key, public_key_b64

    envelope = json.loads(_Path(envelope_path).read_text())
    try:
        decision = admit(
            envelope,
            gate_public_key_b64=public_key_b64(load_private_key(gate_key_path)),
            countersigner_public_key_b64=public_key_b64(load_private_key(counter_key_path)),
            pull_ref=pull_ref,
            anchors=load_anchors(anchors_path),
            gate_available=not gate_unavailable,
        )
    except AdmissionError as exc:
        click.secho(f"REFUSED — {exc}", fg="red", bold=True)
        raise SystemExit(1) from exc
    click.secho("ADMITTED", fg="green", bold=True)
    click.echo(f"  digest      sha256:{decision.subject_digest}")
    click.echo(f"  policy      sha256:{decision.policy_digest}")
    click.echo(f"  anchor      {decision.anchor_ref}")
    click.echo(f"  authority   {decision.authority_class}")


@cli.group("registry")
def registry_group():
    """Ingest vendor drops into the supply_chain plane (ADR-013 §5)."""


@registry_group.command("intake")
@click.option("--sbom", "sbom_path", required=True, type=click.Path(exists=True),
              help="CycloneDX or SPDX SBOM JSON for the drop")
@click.option("--image-ref", required=True, help="Human image tag (never the identity)")
@click.option("--image-digest", required=True,
              help="Image content digest (sha256:...) — the drop's identity")
@click.option("--layers", "layers_path", default=None, type=click.Path(exists=True),
              help="Optional layer map JSON: {layers:[{digest, packages:[purl|name]}]}")
@click.option("--output-dir", required=True, type=click.Path(),
              help="KG directory to write supply_chain-plane nodes")
@click.option("--namespace", default=None,
              help="Namespace subdirectory to write nodes into (multi-tenant KG)")
def registry_intake_cmd(sbom_path, image_ref, image_digest, layers_path, output_dir, namespace):
    """Ingest one vendor drop into supply_chain-plane image/layer/package nodes.

    The image node is keyed by its content digest, not its tag. Packages resolve from the
    SBOM; when a layer map is supplied the graph carries image → layer → package, otherwise
    image → package. Exits 1 if the drop yields gaps a reviewer should see (e.g. an SBOM
    with zero packages).
    """
    from pathlib import Path as _Path

    from .kg_namespace import resolve_kg_dir
    from .registry_intake import intake_drop_from_file, write_supply_chain_nodes

    result = intake_drop_from_file(
        sbom_path, image_ref=image_ref, image_digest=image_digest, layers_path=layers_path
    )
    nodes = result["supply_chain_nodes"]
    paths = write_supply_chain_nodes(nodes, resolve_kg_dir(_Path(output_dir), namespace))

    counts = {}
    for node in nodes:
        counts[node["@type"]] = counts.get(node["@type"], 0) + 1
    summary = ", ".join(f"{n} {t}" for t, n in sorted(counts.items()))
    click.secho(f"Wrote {len(paths)} supply_chain node(s) — {summary}", fg="green")
    click.echo(f"  {len(result['edges'])} within-plane edge(s)")

    gaps = result["gaps"]
    if gaps:
        click.secho(f"\n{len(gaps)} gap(s):", fg="yellow", bold=True)
        for gap in gaps:
            click.secho(f"  {gap}", fg="yellow")
        raise SystemExit(1)


@registry_group.command("affected")
@click.option("--before", "before_path", required=True, type=click.Path(exists=True),
              help="SBOM of drop N")
@click.option("--after", "after_path", required=True, type=click.Path(exists=True),
              help="SBOM of drop N+1")
@click.option("--archetypes", "archetypes_path", required=True, type=click.Path(exists=True),
              help="Archetype suite JSON: {archetypes:[{name, dependency_surface}]}")
def registry_affected_cmd(before_path, after_path, archetypes_path):
    """Select the archetypes the Gate must run for an N → N+1 drop diff.

    The diff is a traversal over two drops; an archetype is affected iff its dependency
    surface intersects the diff. The Gate runs exactly these, not the full suite.
    """
    import json as _json
    from pathlib import Path as _Path

    from .registry_intake import (
        diff_drops,
        intake_drop,
        select_affected_archetypes,
    )

    def _nodes(path):
        sbom = _json.loads(_Path(path).read_text())
        # image_ref/digest are irrelevant to the diff — key only on packages
        return intake_drop(sbom, image_ref=str(path), image_digest="sha256:" + "0" * 64)

    diff = diff_drops(_nodes(before_path), _nodes(after_path))
    suite = _json.loads(_Path(archetypes_path).read_text())
    archetypes = suite.get("archetypes", suite) if isinstance(suite, dict) else suite
    affected = select_affected_archetypes(diff, archetypes)

    click.secho(
        f"Diff: +{len(diff.added)} added, -{len(diff.removed)} removed, "
        f"~{len(diff.changed)} changed", fg="cyan")
    for change in diff.changed:
        click.echo(f"  ~ {change.ecosystem}/{change.name}: {change.from_version} → {change.to_version}")
    if affected:
        click.secho(f"\n{len(affected)} affected archetype(s) — the Gate runs these:", fg="green")
        for name in affected:
            click.echo(f"  {name}")
    else:
        click.secho("\nNo affected archetypes — diff touches nothing any persona exercises.",
                    fg="yellow")
