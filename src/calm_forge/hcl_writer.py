"""HCL text generation — produces Terraform Stacks configuration files."""



def _sanitize_id(calm_id):
    """Convert CALM hyphenated ID to HCL-safe underscore ID."""
    return calm_id.replace("-", "_")


def _module_name_from_source(source):
    """Extract module name from registry source URL.

    e.g. 'registry.terraform.io/uhccp/vault-pki-mtls/v1.0.0' → 'vault-pki-mtls'
    """
    parts = source.rstrip("/").split("/")
    # Module name is second-to-last segment (before version)
    if len(parts) >= 2:
        return parts[-2]
    return parts[-1]


def _node_type_desc(node):
    """Build node type description for HCL comment."""
    parts = [node["node-type"]]
    if "engine" in node:
        parts.append(f"engine={node['engine']}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Wiring context — derived from CALM relationships
# ---------------------------------------------------------------------------

def _build_wiring_context(relationships, relationship_components):
    """Analyze relationships to determine inter-component wiring."""
    ctx = {
        "mtls_nodes": set(),
        "db_consumers": {},       # source_node_id → dest_node_id
    }

    for rel in relationships:
        rel_type_obj = rel.get("relationship-type", {})
        if "connects" not in rel_type_obj:
            continue

        connects = rel_type_obj["connects"]
        source_node = connects.get("source", {}).get("node")
        dest_node = connects.get("destination", {}).get("node")
        auth = rel.get("authentication")

        if auth == "mTLS-vault-pki":
            if source_node:
                ctx["mtls_nodes"].add(source_node)
            if dest_node:
                ctx["mtls_nodes"].add(dest_node)

        if auth == "vault-dynamic-credentials":
            if source_node and dest_node:
                ctx["db_consumers"][source_node] = dest_node

    return ctx


# ---------------------------------------------------------------------------
# Component blocks
# ---------------------------------------------------------------------------

def _write_service_inputs(lines, node, wiring):
    """Append service component input lines."""
    node_id = node["unique-id"]

    lines.append(f'    name             = "{node_id}"')
    lines.append( '    namespace        = var.namespace')
    lines.append(f'    container_image  = "{node.get("container-image", "")}"')
    lines.append(f'    replicas         = {node.get("replicas", 1)}')
    lines.append(f'    cpu_request      = "{node.get("cpu-request", "500m")}"')
    lines.append(f'    memory_request   = "{node.get("memory-request", "512Mi")}"')
    lines.append( '    port             = 8443')
    lines.append( '    protocol         = "HTTPS"')

    if node_id in wiring["mtls_nodes"]:
        lines.append( '    vault_pki_path   = component.vault_pki_mtls.outputs.pki_path')
        lines.append(f'    vault_role       = "{node_id}"')
        lines.append( '    service_mesh     = true')

    if node_id in wiring["db_consumers"]:
        db_hcl = _sanitize_id(wiring["db_consumers"][node_id])
        lines.append(f'    db_connection    = component.{db_hcl}.outputs.connection_string')
        lines.append( '    db_vault_path    = component.vault_dynamic_db_creds.outputs.creds_path')


def _write_database_inputs(lines, node, app_name):
    """Append database component input lines."""
    lines.append(f'    name           = "{app_name}-db"')
    lines.append( '    namespace      = var.namespace')
    lines.append(f'    version        = "{node.get("version", "")}"')
    lines.append(f'    storage_class  = "{node.get("storage-class", "")}"')
    lines.append(f'    storage_size   = "{node.get("storage-size", "")}"')
    lines.append( '    vault_addr     = var.vault_addr')
    lines.append( '    encryption_key = var.vault_transit_key')


def _write_node_component(node, module, wiring, app_name):
    """Generate a component block for a CALM node."""
    node_id = node["unique-id"]
    node_type = node["node-type"]
    hcl_id = _sanitize_id(node_id)

    lines = []
    lines.append(f"# --- Component: {node_id} ---")
    lines.append(f"# CALM node: {node_id} ({_node_type_desc(node)})")
    lines.append(f"# Module: {module['source']}")
    lines.append(f'component "{hcl_id}" {{')
    lines.append(f'  source = "{module["source"]}"')
    lines.append("")
    lines.append("  inputs = {")

    if node_type == "service":
        _write_service_inputs(lines, node, wiring)
    elif node_type == "database":
        _write_database_inputs(lines, node, app_name)

    lines.append("  }")
    lines.append("")
    lines.append("  providers = {")

    if node_type == "service":
        lines.append("    kubernetes = provider.kubernetes.ocp")
        lines.append("    vault      = provider.vault.this")
    elif node_type == "database":
        lines.append("    kubernetes = provider.kubernetes.ocp")
        lines.append("    vault      = provider.vault.this")
        lines.append("    helm       = provider.helm.this")

    lines.append("  }")
    lines.append("}")
    return lines


def _write_relationship_component(rc, app_name):
    """Generate a component block for a relationship-derived Vault component."""
    rel = rc["relationship"]
    source = rc["source"]
    rel_id = rel["unique-id"]
    auth = rel.get("authentication", "")

    module_name = _module_name_from_source(source)
    hcl_id = _sanitize_id(module_name)

    connects = rel["relationship-type"]["connects"]
    source_node = connects.get("source", {}).get("node", "")
    dest_node = connects.get("destination", {}).get("node", "")

    lines = []
    lines.append(f"# --- Component: {module_name} ---")
    lines.append(f"# CALM relationship: {rel_id} (authentication={auth})")
    lines.append(f"# Module: {source}")
    lines.append(f'component "{hcl_id}" {{')
    lines.append(f'  source = "{source}"')
    lines.append("")
    lines.append("  inputs = {")

    if auth == "mTLS-vault-pki":
        lines.append(f'    pki_mount_path    = "pki/{app_name}"')
        domains = []
        for nid in [source_node, dest_node]:
            if nid:
                domains.append(f'{nid}.${{var.namespace}}.svc')
        domain_str = ", ".join(f'"{d}"' for d in domains)
        lines.append(f'    allowed_domains   = [{domain_str}]')
        lines.append( '    max_ttl           = "24h"')
        lines.append( '    default_ttl       = "1h"')

    elif auth == "vault-dynamic-credentials":
        dest_hcl = _sanitize_id(dest_node) if dest_node else "database"
        lines.append(f'    db_mount_path     = "database/{app_name}"')
        lines.append(f'    db_connection_url = component.{dest_hcl}.outputs.connection_string')
        lines.append(f'    allowed_roles     = ["{source_node}"]')
        lines.append( '    default_ttl       = "1h"')
        lines.append( '    max_ttl           = "24h"')

    lines.append("  }")
    lines.append("")
    lines.append("  providers = {")
    lines.append("    vault = provider.vault.this")
    lines.append("  }")
    lines.append("}")
    return lines


# ---------------------------------------------------------------------------
# Public API — one function per output file
# ---------------------------------------------------------------------------

def write_components(component_map, relationship_components, metadata, architecture):
    """Generate components.tfstack.hcl content."""
    app_name = metadata.get("application-name", "unknown")
    schema = architecture.get("$schema", "")
    arch_id = architecture.get("$id", "")
    pattern_name = schema.rsplit("/", 1)[-1] if schema else "unknown"
    arch_name = arch_id.rsplit("/", 1)[-1] if arch_id else "unknown"

    lines = []
    lines.append("# ============================================================")
    lines.append("# GENERATED BY: CALM Forge v0.1")
    lines.append(f"# SOURCE:       {arch_name}")
    lines.append(f"# PATTERN:      {pattern_name}")
    # No generation timestamp. A wall clock in the artifact makes a no-op regenerate
    # produce a different content digest, which breaks the comparison basis every
    # cross-plane finding depends on (ADR-007 §1: by content, never by clock). The time
    # of the build lives in provenance.slsa.json's runDetails, where it is signed and
    # where nothing digests it as part of the artifact.
    lines.append("# DO NOT EDIT — regenerate from CALM source")
    lines.append("# ============================================================")
    lines.append("")

    # required_providers
    lines.append("required_providers {")
    lines.append("  kubernetes = {")
    lines.append('    source  = "hashicorp/kubernetes"')
    lines.append('    version = "~> 2.30"')
    lines.append("  }")
    lines.append("  vault = {")
    lines.append('    source  = "hashicorp/vault"')
    lines.append('    version = "~> 4.2"')
    lines.append("  }")
    lines.append("  helm = {")
    lines.append('    source  = "hashicorp/helm"')
    lines.append('    version = "~> 2.13"')
    lines.append("  }")
    lines.append("}")
    lines.append("")

    # Provider blocks
    lines.append('provider "kubernetes" "ocp" {')
    lines.append("  config_path = var.kubeconfig_path")
    lines.append("}")
    lines.append("")
    lines.append('provider "vault" "this" {')
    lines.append("  address = var.vault_addr")
    lines.append("  token   = var.vault_token")
    lines.append("}")
    lines.append("")
    lines.append('provider "helm" "this" {')
    lines.append("  kubernetes {")
    lines.append("    config_path = var.kubeconfig_path")
    lines.append("  }")
    lines.append("}")

    # Build wiring context
    relationships = architecture.get("relationships", [])
    wiring = _build_wiring_context(relationships, relationship_components)

    # Node-derived components
    for node_id, entry in component_map.items():
        module = entry["module"]
        if module is None:  # system node — skip
            continue
        lines.append("")
        lines.extend(_write_node_component(entry["node"], module, wiring, app_name))

    # Relationship-derived components (Vault PKI, dynamic creds)
    for rc in relationship_components:
        lines.append("")
        lines.extend(_write_relationship_component(rc, app_name))

    return "\n".join(lines) + "\n"


def write_variables(component_map, metadata):
    """Generate variables.tfstack.hcl content."""
    lines = []
    lines.append("# ============================================================")
    lines.append("# GENERATED BY: CALM Forge v0.1")
    lines.append("# ============================================================")
    lines.append("")

    variables = [
        ("namespace",         "string", "Kubernetes namespace for deployment",              False),
        ("kubeconfig_path",   "string", "Path to kubeconfig for target OCP cluster",        False),
        ("vault_addr",        "string", "Vault server address",                             False),
        ("vault_token",       "string", "Vault authentication token",                       True),
        ("vault_transit_key", "string", "Vault Transit key for database encryption at rest", False),
        ("environment",       "string", "Deployment environment",                           False),
    ]

    for i, (name, vtype, desc, sensitive) in enumerate(variables):
        lines.append(f'variable "{name}" {{')
        lines.append(f"  type        = {vtype}")
        lines.append(f'  description = "{desc}"')
        if sensitive:
            lines.append("  sensitive   = true")
        lines.append("}")
        if i < len(variables) - 1:
            lines.append("")

    return "\n".join(lines) + "\n"


def write_deployments(decorators, metadata):
    """Generate deployments.tfdeploy.hcl content."""
    decorator = decorators[0] if decorators else {}
    dec_id = decorator.get("unique-id", "unknown")
    compliance = metadata.get("compliance-scope", "general")
    app_name = metadata.get("application-name", "app")
    cost_center = metadata.get("cost-center", "unknown")

    lines = []
    lines.append("# ============================================================")
    lines.append("# GENERATED BY: CALM Forge v0.1")
    lines.append(f"# SOURCE:       {dec_id} (deployment decorator)")
    lines.append("# PLACEMENT:    Placement Engine decision — see rationale ref")
    lines.append("# ============================================================")
    lines.append("")
    lines.append('identity_token "vault" {')
    lines.append('  audience = ["vault.uhccp.internal"]')
    lines.append("}")
    lines.append("")

    for dec in decorators:
        data = dec.get("data", {})
        env = data.get("environment", "default")
        k8s = data.get("kubernetes", {})
        cluster = k8s.get("cluster", "default")
        region = data.get("region", "default")
        cloud = data.get("cloud-provider", "unknown")
        namespace = k8s.get("namespace", env)

        lines.append(f"# --- Deployment: {env} (from CALM deployment decorator) ---")
        lines.append(f"# Cluster: {cluster}")
        lines.append(f"# Region:  {region} ({cloud.capitalize()})")

        if compliance == "pci-dss":
            lines.append("# Reason:  PCI-DSS requires UK data residency, cluster has 40% headroom,")
            lines.append(f"#          cost within budget envelope {cost_center}")

        lines.append(f'deployment "{env}" {{')
        lines.append("  inputs = {")
        lines.append(f'    namespace         = "{namespace}"')
        lines.append(f'    kubeconfig_path   = "/etc/kubernetes/{cluster}.kubeconfig"')
        lines.append(f'    vault_addr        = "https://vault.{env}.{region}.uhccp.internal:8200"')
        lines.append( '    vault_token       = identity_token.vault.jwt')
        lines.append(f'    vault_transit_key = "{app_name}-transit"')
        lines.append(f'    environment       = "{env}"')
        lines.append("  }")
        lines.append("}")
    lines.append("")

    # PCI compliance gates
    if compliance == "pci-dss":
        lines.append("# --- Deployment group: production gate ---")
        lines.append('deployment_auto_approve "no_destroys" {')
        lines.append("  check {")
        lines.append("    condition = context.plan.changes.remove == 0")
        lines.append('    reason    = "Plan would destroy ${context.plan.changes.remove} resources. Manual approval required."')
        lines.append("  }")
        lines.append("}")
        lines.append("")
        lines.append('deployment_auto_approve "no_pci_scope_change" {')
        lines.append("  check {")
        lines.append("    condition = context.plan.applyable == true")
        lines.append('    reason    = "PCI-scoped deployment requires manual approval for any infrastructure change."')
        lines.append("  }")
        lines.append("}")
        lines.append("")
        lines.append('deployment_group "production_gate" {')
        lines.append("  auto_approve_checks = [")
        lines.append("    deployment_auto_approve.no_destroys")
        lines.append("  ]")
        lines.append("  # Note: PCI-scoped deployments always require manual approval")
        lines.append("  # deployment_auto_approve.no_pci_scope_change is informational")
        lines.append("}")
        lines.append("")

    # Auto-generate staging for production deployments
    for dec in decorators:
        data = dec.get("data", {})
        env = data.get("environment", "default")
        if env == "production":
            region = data.get("region", "default")
            lines.append("# --- Staging deployment (auto-generated for pre-prod validation) ---")
            lines.append('deployment "staging" {')
            lines.append("  inputs = {")
            lines.append(f'    namespace         = "{app_name}-staging"')
            lines.append(f'    kubeconfig_path   = "/etc/kubernetes/staging-{region}-ocp-01.kubeconfig"')
            lines.append(f'    vault_addr        = "https://vault.staging.{region}.uhccp.internal:8200"')
            lines.append( '    vault_token       = identity_token.vault.jwt')
            lines.append(f'    vault_transit_key = "{app_name}-transit-staging"')
            lines.append( '    environment       = "staging"')
            lines.append("  }")
            lines.append("}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"
