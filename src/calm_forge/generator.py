"""Core translation logic — CALM architecture + decorators → Terraform Stack files."""

import json
from pathlib import Path

from .ansible_writer import write_eda_rulebook, write_inventory
from .dcm_writer import write_dcm_application
from .hcl_writer import write_components, write_deployments, write_variables
from .provenance import (
    PROVENANCE_ENVELOPE_FILENAME,
    PROVENANCE_FILENAME,
    dsse_envelope,
    provenance_for_generated_files,
    render,
)
from .resolver import resolve_module, resolve_relationship_components
from .sentinel_writer import write_sentinel_policies
from .tfpolicy_writer import write_tfpolicy_policies, write_tfpolicy_tests
from .vault_writer import write_pki_config, write_vault_policies


def validate_architecture(architecture):
    """Check structural expectations on a CALM instantiation.

    Returns a list of error strings (empty = valid).
    """
    errors = []

    if "nodes" not in architecture:
        errors.append("Missing 'nodes' array")
    elif not isinstance(architecture["nodes"], list):
        errors.append("'nodes' must be an array")
    elif len(architecture["nodes"]) == 0:
        errors.append("'nodes' array is empty")

    if "relationships" not in architecture:
        errors.append("Missing 'relationships' array")
    elif not isinstance(architecture["relationships"], list):
        errors.append("'relationships' must be an array")

    if "metadata" not in architecture:
        errors.append("Missing 'metadata' object")
    elif not isinstance(architecture["metadata"], dict):
        errors.append("'metadata' must be an object")

    # Node-level checks
    for i, node in enumerate(architecture.get("nodes", [])):
        if "unique-id" not in node:
            errors.append(f"Node {i} missing 'unique-id'")
        if "node-type" not in node:
            errors.append(f"Node {i} missing 'node-type'")

    return errors


def validate_inputs(architecture, decorator, catalog,
                    calm_path, decorator_path, catalog_path):
    """Check structural expectations on decorator and catalog.

    Raises ValueError with a clear message if any check fails.
    """
    if not isinstance(decorator.get("data"), dict):
        raise ValueError(
            f"Decorator file '{decorator_path}' must have a 'data' key that is a dict"
        )
    if not isinstance(catalog.get("modules"), dict):
        raise ValueError(
            f"Catalog file '{catalog_path}' must have a 'modules' key that is a dict"
        )


def generate_stack(calm_path, decorator_path, catalog_path, output_dir,
                   full=False, include_imports=False, policy_framework="sentinel",
                   signing_key=None):
    """Main entry point: CALM architecture + decorator + catalog → output files.

    When full=False (default), generates 3 Terraform Stacks HCL files.
    When full=True, also generates Vault, Sentinel, and Ansible artifacts.

    ``policy_framework`` selects which policy language the full set emits:
    ``sentinel`` (default, back-compat), ``tfpolicy`` (native HCL policy, beta), or
    ``all`` (both). Each is an independent projection of the same CALM intent — no
    framework is translated from another. OPA is emitted via the validate-intent path,
    not here, so it is not a generate-time framework choice.
    When include_imports=True, generates import blocks for brownfield adoption.

    Every run emits SLSA v1.0 build provenance (ADR-007). When ``signing_key`` is
    supplied the statement is additionally written as a signed DSSE envelope; without
    one the statement is emitted unsigned — a truthful build record, but not
    tamper-evident, so downstream must not treat it as an attestation.

    Returns dict mapping filename → generated content.
    """
    try:
        architecture = json.loads(Path(calm_path).read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in '{calm_path}' at line {exc.lineno}, col {exc.colno}: {exc.msg}"
        ) from exc

    try:
        decorator = json.loads(Path(decorator_path).read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in '{decorator_path}' at line {exc.lineno}, col {exc.colno}: {exc.msg}"
        ) from exc

    try:
        catalog = json.loads(Path(catalog_path).read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in '{catalog_path}' at line {exc.lineno}, col {exc.colno}: {exc.msg}"
        ) from exc

    # Validate inputs before proceeding
    validate_inputs(architecture, decorator, catalog,
                    calm_path, decorator_path, catalog_path)

    # Validate
    errors = validate_architecture(architecture)
    if errors:
        raise ValueError(f"Invalid CALM architecture: {'; '.join(errors)}")

    decorators = [decorator]
    metadata = architecture.get("metadata", {})

    # Resolve modules for each node
    component_map = {}
    try:
        for node in architecture["nodes"]:
            module = resolve_module(node, catalog)
            component_map[node["unique-id"]] = {"node": node, "module": module}
    except KeyError as exc:
        raise ValueError(f"Missing expected key {exc} in architecture or catalog") from exc

    # Resolve relationship-derived components (Vault PKI, dynamic creds)
    rel_components = resolve_relationship_components(
        architecture.get("relationships", []),
        catalog,
    )

    # Generate HCL content
    components_hcl = write_components(
        component_map, rel_components, metadata, architecture,
    )
    variables_hcl = write_variables(component_map, metadata)
    deployments_hcl = write_deployments(decorators, metadata)

    # Write output files
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    files = {
        "components.tfstack.hcl": components_hcl,
        "variables.tfstack.hcl": variables_hcl,
        "deployments.tfdeploy.hcl": deployments_hcl,
    }

    # Expanded outputs (when --full flag is set)
    if full:
        files["dcm/application.json"] = write_dcm_application(architecture, decorator)
        files["vault/policies.hcl"] = write_vault_policies(
            component_map, rel_components, metadata,
        )
        files["vault/pki-config.hcl"] = write_pki_config(
            component_map, rel_components, metadata, decorators,
        )
        if policy_framework in ("sentinel", "all"):
            files["sentinel/policies.sentinel"] = write_sentinel_policies(
                metadata, component_map, decorators,
            )
        if policy_framework in ("tfpolicy", "all"):
            files["tfpolicy/policies.policy.hcl"] = write_tfpolicy_policies(
                metadata, component_map, decorators,
            )
            files["tfpolicy/policies.policytest.hcl"] = write_tfpolicy_tests(
                metadata, component_map, decorators,
            )
        files["ansible/inventory.yml"] = write_inventory(
            component_map, decorators, metadata,
        )
        files["ansible/eda-rulebook.yml"] = write_eda_rulebook(
            component_map, rel_components, metadata,
        )

    # Import blocks for brownfield adoption
    if include_imports:
        import_lines = _generate_import_blocks_from_calm(architecture)
        if import_lines:
            files["imports.tf"] = import_lines

    # SLSA v1.0 build provenance over the whole emitted set (ADR-007). Written last so
    # every artifact is a subject, and excluded from `files` so it never becomes a
    # subject of itself.
    provenance = provenance_for_generated_files(
        files,
        {"calm": calm_path, "decorator": decorator_path, "catalog": catalog_path},
        external_parameters={
            "full": full,
            "include_imports": include_imports,
            "policy_framework": policy_framework,
        },
    )

    for name, content in files.items():
        filepath = out / name
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)

    (out / PROVENANCE_FILENAME).write_text(render(provenance))
    if signing_key is not None:
        envelope = dsse_envelope(provenance, signing_key)
        (out / PROVENANCE_ENVELOPE_FILENAME).write_text(json.dumps(envelope, indent=2) + "\n")

    return files


def _generate_import_blocks_from_calm(architecture):
    """Generate import blocks from CALM nodes that have 'imported-from' metadata.

    CALM specs produced by `calm-forge import` annotate each node with
    the original workspace address and resource ID, enabling declarative
    import blocks that adopt existing infrastructure into Stacks.
    """
    lines = [
        "# ============================================================",
        "# GENERATED BY: CALM Forge — Import Blocks",
        "# These import blocks adopt existing infrastructure into Stacks",
        "# without re-creating resources. Remove after first successful apply.",
        "# ============================================================",
        "",
    ]

    has_imports = False

    for node in architecture.get("nodes", []):
        imported = node.get("imported-from")
        import_id = node.get("import-id")

        if not imported or not import_id:
            continue

        has_imports = True
        address = imported.get("address", "")
        workspace = imported.get("workspace", "")

        lines.append(f"# Source workspace: {workspace}")
        lines.append("import {")
        lines.append(f"  to = {address}")
        lines.append(f'  id = "{import_id}"')
        lines.append("}")
        lines.append("")

    if not has_imports:
        return ""

    return "\n".join(lines)
