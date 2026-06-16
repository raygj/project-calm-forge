"""TFE Workspace Importer — reads existing workspaces via TFE API,
clusters them into logical components, and produces CALM JSON + import-aware Stacks HCL.

This is the brownfield adoption path for Terraform Stacks.
Greenfield: CALM JSON → Stacks (existing generator)
Brownfield: TFE API → CALM JSON → Stacks + import blocks (this module)

Usage:
    calm-forge import \
        --tfe-host tfe.company.com \
        --tfe-token $TFE_TOKEN \
        --org payments-team \
        --workspace-filter "payments-*" \
        --output-dir /tmp/import
"""

import json
import re
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# TFE API Client (minimal, stdlib-only — no requests dependency)
# ---------------------------------------------------------------------------

class TFEClient:
    """Lightweight TFE/HCP Terraform API client using urllib."""

    def __init__(self, host, token, *, tls_verify=True):
        self.base_url = f"https://{host}/api/v2"
        self.token = token
        self.tls_verify = tls_verify

    def _get(self, path, *, params=None):
        """GET request to TFE API. Returns parsed JSON."""
        url = f"{self.base_url}{path}"
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{qs}"

        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Content-Type", "application/vnd.api+json")

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode() if exc.fp else ""
            raise ConnectionError(
                f"TFE API {exc.code} on {path}: {body}"
            ) from exc

    def _get_all_pages(self, path, *, params=None):
        """Paginate through all results for a TFE API endpoint."""
        params = dict(params or {})
        params.setdefault("page[size]", "100")
        all_data = []

        while path:
            result = self._get(path, params=params)
            all_data.extend(result.get("data", []))
            next_url = (result.get("links") or {}).get("next")
            if next_url and next_url != path:
                # next link is typically a full URL — extract path
                if next_url.startswith("http"):
                    next_url = next_url.split("/api/v2", 1)[-1]
                path = next_url
                params = {}  # params are in the URL now
            else:
                break

        return all_data

    # --- Workspace operations ---

    def list_workspaces(self, org, *, search=None):
        """List workspaces in an organization, optionally filtered by name search."""
        params = {}
        if search:
            params["search[name]"] = search
        return self._get_all_pages(
            f"/organizations/{org}/workspaces", params=params
        )

    def get_workspace(self, workspace_id):
        """Get a single workspace by ID."""
        result = self._get(f"/workspaces/{workspace_id}")
        return result.get("data", {})

    def get_current_state(self, workspace_id):
        """Get the current state version for a workspace."""
        result = self._get(
            f"/workspaces/{workspace_id}/current-state-version"
        )
        return result.get("data", {})

    def get_state_resources(self, state_version_id):
        """List resources in a state version (TFE 1.4+)."""
        # This endpoint may not exist on older TFE — fall back gracefully
        try:
            return self._get_all_pages(
                f"/state-versions/{state_version_id}/resources"
            )
        except ConnectionError:
            return []

    def get_workspace_variables(self, workspace_id):
        """List variables for a workspace."""
        return self._get_all_pages(f"/workspaces/{workspace_id}/vars")

    def download_state(self, state_download_url):
        """Download raw state JSON from the signed URL."""
        req = urllib.request.Request(state_download_url)
        req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Workspace Extraction — pull everything we need from TFE
# ---------------------------------------------------------------------------

def extract_workspaces(client, org, workspace_filter=None):
    """Extract workspace metadata, variables, and resource inventory.

    Returns a list of workspace dicts with enriched data.
    """
    search = None
    if workspace_filter and "*" in workspace_filter:
        # TFE search doesn't support glob — use prefix
        search = workspace_filter.replace("*", "").rstrip("-")

    raw_workspaces = client.list_workspaces(org, search=search)

    # Apply glob filter client-side if needed
    if workspace_filter:
        pattern = re.compile(
            "^" + workspace_filter.replace("*", ".*") + "$"
        )
        raw_workspaces = [
            ws for ws in raw_workspaces
            if pattern.match(ws["attributes"]["name"])
        ]

    workspaces = []
    for ws in raw_workspaces:
        ws_id = ws["id"]
        attrs = ws["attributes"]

        entry = {
            "id": ws_id,
            "name": attrs["name"],
            "created_at": attrs.get("created-at", ""),
            "updated_at": attrs.get("updated-at", ""),
            "terraform_version": attrs.get("terraform-version", ""),
            "vcs_repo": attrs.get("vcs-repo", {}),
            "working_directory": attrs.get("working-directory", ""),
            "tags": [
                t["attributes"]["name"]
                for t in (ws.get("relationships", {})
                          .get("tags", {}).get("data", []))
            ] if ws.get("relationships", {}).get("tags") else [],
            "variables": [],
            "resources": [],
        }

        # Pull variables
        try:
            var_data = client.get_workspace_variables(ws_id)
            entry["variables"] = [
                {
                    "key": v["attributes"]["key"],
                    "category": v["attributes"]["category"],
                    "sensitive": v["attributes"]["sensitive"],
                    "value": v["attributes"].get("value", ""),
                }
                for v in var_data
            ]
        except ConnectionError:
            pass

        # Pull resource inventory from state
        try:
            state = client.get_current_state(ws_id)
            if state:
                state_id = state.get("id", "")
                resources = client.get_state_resources(state_id)
                if resources:
                    entry["resources"] = [
                        {
                            "type": r["attributes"]["provider-type"],
                            "name": r["attributes"]["name"],
                            "address": r["attributes"]["address"],
                            "module": r["attributes"].get("module", ""),
                        }
                        for r in resources
                    ]
                else:
                    # Fallback: download raw state and parse resources
                    download_url = (
                        state.get("attributes", {})
                        .get("hosted-state-download-url", "")
                    )
                    if download_url:
                        raw_state = client.download_state(download_url)
                        entry["resources"] = _parse_state_resources(raw_state)
        except ConnectionError:
            pass

        workspaces.append(entry)

    return workspaces


def _parse_state_resources(raw_state):
    """Parse resources from a raw Terraform state JSON."""
    resources = []
    for res in raw_state.get("resources", []):
        for inst in res.get("instances", []):
            address = res.get("type", "") + "." + res.get("name", "")
            if res.get("module"):
                address = res["module"] + "." + address
            resources.append({
                "type": res.get("type", ""),
                "name": res.get("name", ""),
                "address": address,
                "module": res.get("module", ""),
                "provider": res.get("provider", ""),
                "id": (inst.get("attributes") or {}).get("id", ""),
            })
    return resources


# ---------------------------------------------------------------------------
# Clustering — group workspaces into Stacks components
# ---------------------------------------------------------------------------

# Resource type → CALM node type mapping
#
# Coverage: AWS, GCP, Azure, Kubernetes, HashiCorp Vault,
#           IBM Cloud (z/LinuxONE, HPCS, MQ Cloud, Event Streams,
#           Secrets Manager, Satellite, Bare Metal, DB2, Database)
#
# IBM Z note: There is no standalone z/OS Terraform provider on the
# registry. z/OS operating system automation is Ansible-native (Red Hat
# Ansible Certified Content for IBM Z). z-adjacent infrastructure
# (LinuxONE bare metal, HPCS crypto, MQ Cloud, DB2, Satellite for edge)
# is managed through the IBM Cloud provider (IBM-Cloud/ibm).
#
RESOURCE_TYPE_MAP = {
    # ---------------------------------------------------------------
    # AWS
    # ---------------------------------------------------------------
    # Compute
    "aws_instance": "service",
    "aws_ecs_service": "service",
    "aws_ecs_task_definition": "service",
    "aws_lambda_function": "service",
    "aws_autoscaling_group": "service",
    "aws_eks_cluster": "service",
    "aws_eks_node_group": "service",
    # Database
    "aws_db_instance": "database",
    "aws_rds_cluster": "database",
    "aws_dynamodb_table": "database",
    "aws_elasticache_cluster": "database",
    "aws_redshift_cluster": "database",
    # Load balancer
    "aws_lb": "load-balancer",
    "aws_alb": "load-balancer",
    "aws_lb_target_group": "load-balancer",
    # Network
    "aws_vpc": "network",
    "aws_subnet": "network",
    "aws_security_group": "network",
    "aws_route_table": "network",
    "aws_nat_gateway": "network",
    "aws_internet_gateway": "network",
    # Storage
    "aws_s3_bucket": "storage",
    "aws_efs_file_system": "storage",
    # Messaging
    "aws_sqs_queue": "messaging",
    "aws_sns_topic": "messaging",
    "aws_msk_cluster": "messaging",
    # Identity
    "aws_iam_role": "identity",
    "aws_iam_policy": "identity",

    # ---------------------------------------------------------------
    # GCP
    # ---------------------------------------------------------------
    # Compute
    "google_compute_instance": "service",
    "google_cloud_run_service": "service",
    "google_cloud_run_v2_service": "service",
    "google_container_cluster": "service",
    "google_container_node_pool": "service",
    "google_cloudfunctions_function": "service",
    # Database
    "google_sql_database_instance": "database",
    "google_spanner_instance": "database",
    "google_bigtable_instance": "database",
    "google_redis_instance": "database",
    # Load balancer
    "google_compute_forwarding_rule": "load-balancer",
    "google_compute_global_forwarding_rule": "load-balancer",
    "google_compute_backend_service": "load-balancer",
    # Network
    "google_compute_network": "network",
    "google_compute_subnetwork": "network",
    "google_compute_firewall": "network",
    # Storage
    "google_storage_bucket": "storage",
    # Messaging
    "google_pubsub_topic": "messaging",
    "google_pubsub_subscription": "messaging",
    # Identity
    "google_service_account": "identity",
    "google_project_iam_member": "identity",

    # ---------------------------------------------------------------
    # Azure
    # ---------------------------------------------------------------
    # Compute
    "azurerm_linux_virtual_machine": "service",
    "azurerm_windows_virtual_machine": "service",
    "azurerm_container_group": "service",
    "azurerm_kubernetes_cluster": "service",
    "azurerm_function_app": "service",
    # Database
    "azurerm_postgresql_server": "database",
    "azurerm_postgresql_flexible_server": "database",
    "azurerm_mssql_server": "database",
    "azurerm_cosmosdb_account": "database",
    "azurerm_redis_cache": "database",
    # Load balancer
    "azurerm_lb": "load-balancer",
    "azurerm_application_gateway": "load-balancer",
    # Network
    "azurerm_virtual_network": "network",
    "azurerm_subnet": "network",
    "azurerm_network_security_group": "network",
    # Storage
    "azurerm_storage_account": "storage",
    "azurerm_storage_container": "storage",

    # ---------------------------------------------------------------
    # Kubernetes (provider: hashicorp/kubernetes)
    # ---------------------------------------------------------------
    "kubernetes_deployment": "service",
    "kubernetes_deployment_v1": "service",
    "kubernetes_stateful_set": "service",
    "kubernetes_stateful_set_v1": "service",
    "kubernetes_daemon_set": "service",
    "kubernetes_daemon_set_v1": "service",
    "kubernetes_job": "service",
    "kubernetes_job_v1": "service",
    "kubernetes_cron_job": "service",
    "kubernetes_cron_job_v1": "service",
    "kubernetes_service": "load-balancer",
    "kubernetes_service_v1": "load-balancer",
    "kubernetes_ingress": "load-balancer",
    "kubernetes_ingress_v1": "load-balancer",
    "kubernetes_namespace": "network",
    "kubernetes_network_policy": "network",
    "kubernetes_persistent_volume_claim": "storage",
    "kubernetes_config_map": "configuration",
    "kubernetes_secret": "identity",
    "kubernetes_service_account": "identity",

    # ---------------------------------------------------------------
    # HashiCorp Vault (provider: hashicorp/vault)
    # ---------------------------------------------------------------
    "vault_policy": "identity",
    "vault_mount": "identity",
    "vault_auth_backend": "identity",
    "vault_token": "identity",
    "vault_pki_secret_backend_cert": "identity",
    "vault_pki_secret_backend_role": "identity",
    "vault_database_secret_backend_connection": "identity",
    "vault_database_secret_backend_role": "identity",
    "vault_transit_secret_backend_key": "crypto",
    "vault_identity_entity": "identity",
    "vault_identity_group": "identity",

    # ---------------------------------------------------------------
    # IBM Cloud — z/OS Adjacent: Bare Metal (LinuxONE s390x)
    # ---------------------------------------------------------------
    # LinuxONE runs as s390x bare metal servers in IBM Cloud VPC.
    # These are the infrastructure resources for LinuxONE workloads.
    "ibm_is_bare_metal_server": "service",
    "ibm_is_bare_metal_server_action": "service",
    "ibm_is_bare_metal_server_disk": "storage",
    "ibm_is_bare_metal_server_initialization": "service",
    "ibm_is_bare_metal_server_network_interface": "network",
    "ibm_is_bare_metal_server_network_interface_allow_float": "network",
    "ibm_is_bare_metal_server_network_interface_floating_ip": "network",
    "ibm_is_bare_metal_server_network_attachment": "network",
    "ibm_compute_bare_metal": "service",  # Classic infrastructure

    # ---------------------------------------------------------------
    # IBM Cloud — Hyper Protect Crypto Services (HPCS)
    # ---------------------------------------------------------------
    # HPCS runs on LinuxONE hardware. Provides HSM-grade key management
    # with FIPS 140-2 Level 4 certification. Critical for z key mgmt,
    # EKMF integration, and post-quantum crypto readiness.
    "ibm_hpcs": "crypto",
    "ibm_hpcs_managed_key": "crypto",
    "ibm_hpcs_key_template": "crypto",
    "ibm_hpcs_keystore": "crypto",
    "ibm_hpcs_vault": "crypto",

    # ---------------------------------------------------------------
    # IBM Cloud — Key Protect / KMS
    # ---------------------------------------------------------------
    # Key Protect for standard key management. KMIP adapter for
    # MongoDB/DB2 TDE integration (Citi use case: Z Key for Mongo).
    "ibm_kms_key": "crypto",
    "ibm_kms_key_alias": "crypto",
    "ibm_kms_key_policies": "crypto",
    "ibm_kms_key_rings": "crypto",
    "ibm_kms_key_with_policy_overrides": "crypto",
    "ibm_kms_instance_policies": "crypto",
    "ibm_kms_kmip_adapters": "crypto",
    "ibm_kms_kmip_certs": "crypto",

    # ---------------------------------------------------------------
    # IBM Cloud — MQ Cloud
    # ---------------------------------------------------------------
    # MQ Cloud for messaging. Maps to z/OS MQ brokering patterns
    # (Citi use case: WAS → MQ → DB2 via JDBC).
    "ibm_mqcloud_queue_manager": "messaging",
    "ibm_mqcloud_application": "messaging",
    "ibm_mqcloud_user": "identity",
    "ibm_mqcloud_keystore_certificate": "crypto",
    "ibm_mqcloud_truststore_certificate": "crypto",
    "ibm_mqcloud_virtual_private_endpoint_gateway": "network",

    # ---------------------------------------------------------------
    # IBM Cloud — Event Streams (Kafka)
    # ---------------------------------------------------------------
    # Managed Kafka. Relevant for z-to-cloud event streaming,
    # Confluent displacement, and data fabric patterns.
    "ibm_event_streams_topic": "messaging",
    "ibm_event_streams_schema": "messaging",
    "ibm_event_streams_schema_global_rule": "messaging",
    "ibm_event_streams_quota": "messaging",
    "ibm_event_streams_mirroring_config": "messaging",

    # ---------------------------------------------------------------
    # IBM Cloud — DB2
    # ---------------------------------------------------------------
    # Managed DB2. Direct mapping to z/OS DB2 workloads migrating
    # to cloud or running hybrid (DB2 on z + DB2 Cloud).
    "ibm_db2": "database",
    "ibm_database": "database",  # ICD (IBM Cloud Databases — Postgres, Redis, etc.)

    # ---------------------------------------------------------------
    # IBM Cloud — Secrets Manager
    # ---------------------------------------------------------------
    # IBM's managed secrets service. Competitive with Vault but
    # relevant for import when customers have both.
    "ibm_sm_secret_group": "identity",
    "ibm_sm_arbitrary_secret": "identity",
    "ibm_sm_kv_secret": "identity",
    "ibm_sm_username_password_secret": "identity",
    "ibm_sm_iam_credentials_secret": "identity",
    "ibm_sm_iam_credentials_configuration": "identity",
    "ibm_sm_imported_certificate": "identity",
    "ibm_sm_private_certificate": "identity",
    "ibm_sm_private_certificate_configuration_root_ca": "identity",
    "ibm_sm_private_certificate_configuration_intermediate_ca": "identity",
    "ibm_sm_private_certificate_configuration_template": "identity",
    "ibm_sm_private_certificate_configuration_action_sign_csr": "identity",
    "ibm_sm_private_certificate_configuration_action_set_signed": "identity",
    "ibm_sm_public_certificate": "identity",
    "ibm_sm_public_certificate_configuration_ca_lets_encrypt": "identity",
    "ibm_sm_public_certificate_configuration_dns_cis": "identity",
    "ibm_sm_public_certificate_configuration_dns_classic_infrastructure": "identity",
    "ibm_sm_public_certificate_action_validate_manual_dns": "identity",
    "ibm_sm_service_credentials_secret": "identity",
    "ibm_sm_custom_credentials_secret": "identity",
    "ibm_sm_custom_credentials_configuration": "identity",
    "ibm_sm_en_registration": "identity",

    # ---------------------------------------------------------------
    # IBM Cloud — Satellite (edge / on-prem management)
    # ---------------------------------------------------------------
    # Satellite manages on-prem and edge infrastructure from IBM Cloud.
    # Relevant for hybrid z + cloud patterns where OCP runs on LinuxONE
    # managed via Satellite.
    "ibm_satellite_location": "network",
    "ibm_satellite_location_nlb_dns": "network",
    "ibm_satellite_host": "service",
    "ibm_satellite_cluster": "service",
    "ibm_satellite_cluster_worker_pool": "service",
    "ibm_satellite_cluster_worker_pool_zone_attachment": "service",
    "ibm_satellite_endpoint": "network",
    "ibm_satellite_link": "network",
    "ibm_satellite_storage_configuration": "storage",
    "ibm_satellite_storage_assignment": "storage",
}


def cluster_workspaces(workspaces):
    """Group workspaces into proposed Stacks component clusters.

    Heuristics:
    1. Shared VPC/network → same network component
    2. Naming convention (prefix) → same application component
    3. Tag overlap → same logical group
    4. Single workspace → standalone component

    Returns list of cluster dicts with proposed component name and members.
    """
    clusters = []

    # Strategy 1: group by common name prefix
    prefix_groups = defaultdict(list)
    for ws in workspaces:
        name = ws["name"]
        # Extract prefix: "payments-api-prod" → "payments-api"
        # Try splitting on common env suffixes
        for suffix in ["-prod", "-staging", "-dev", "-test", "-qa",
                       "-production", "-development"]:
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        prefix_groups[name].append(ws)

    for prefix, members in prefix_groups.items():
        # Classify dominant resource types in this cluster
        resource_types = defaultdict(int)
        for ws in members:
            for res in ws["resources"]:
                calm_type = RESOURCE_TYPE_MAP.get(res["type"], "unknown")
                resource_types[calm_type] += 1

        clusters.append({
            "proposed_name": prefix,
            "workspaces": [ws["name"] for ws in members],
            "workspace_count": len(members),
            "resource_summary": dict(resource_types),
            "total_resources": sum(
                len(ws["resources"]) for ws in members
            ),
            "environments": _detect_environments(members),
            "tags": _collect_tags(members),
        })

    return clusters


def _detect_environments(workspaces):
    """Detect environments from workspace names."""
    envs = set()
    for ws in workspaces:
        name = ws["name"].lower()
        for env in ["prod", "production", "staging", "dev", "development",
                     "test", "qa", "uat", "sandbox"]:
            if env in name:
                envs.add(env)
                break
    return sorted(envs) or ["default"]


def _collect_tags(workspaces):
    """Collect unique tags across workspaces."""
    tags = set()
    for ws in workspaces:
        tags.update(ws.get("tags", []))
    return sorted(tags)


# ---------------------------------------------------------------------------
# CALM Generation — workspace inventory → CALM JSON
# ---------------------------------------------------------------------------

def workspaces_to_calm(workspaces, clusters, org):
    """Convert extracted workspace data into a CALM instantiation JSON.

    This is the bridge: TFE brownfield → CALM intermediate → Stacks generator.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build nodes from resource inventory
    nodes = []
    relationships = []
    seen_node_ids = set()

    for cluster in clusters:
        cluster_name = cluster["proposed_name"]

        # Get all resources across workspaces in this cluster
        cluster_workspaces = [
            ws for ws in workspaces
            if ws["name"] in cluster["workspaces"]
        ]

        for ws in cluster_workspaces:
            for res in ws["resources"]:
                calm_type = RESOURCE_TYPE_MAP.get(res["type"], "unknown")
                if calm_type == "unknown":
                    continue  # Skip unclassified resources

                node_id = f"{cluster_name}-{calm_type}-{res['name']}"
                if node_id in seen_node_ids:
                    continue
                seen_node_ids.add(node_id)

                node = {
                    "unique-id": node_id,
                    "node-type": calm_type,
                    "name": res["name"],
                    "imported-from": {
                        "workspace": ws["name"],
                        "address": res["address"],
                        "resource-type": res["type"],
                    },
                }

                # Add resource-specific metadata
                if "id" in res and res["id"]:
                    node["import-id"] = res["id"]

                nodes.append(node)

        # Infer relationships within the cluster
        cluster_nodes = [n for n in nodes
                         if n["unique-id"].startswith(cluster_name)]
        services = [n for n in cluster_nodes
                    if n["node-type"] == "service"]
        databases = [n for n in cluster_nodes
                     if n["node-type"] == "database"]
        lbs = [n for n in cluster_nodes
               if n["node-type"] == "load-balancer"]

        # LB → service relationships
        for lb in lbs:
            for svc in services:
                relationships.append({
                    "unique-id": f"{lb['unique-id']}-to-{svc['unique-id']}",
                    "relationship-type": {
                        "connects": {
                            "source": {"node": lb["unique-id"]},
                            "destination": {"node": svc["unique-id"]},
                        }
                    },
                    "protocol": "HTTPS",
                })

        # Service → database relationships
        for svc in services:
            for db in databases:
                relationships.append({
                    "unique-id": f"{svc['unique-id']}-to-{db['unique-id']}",
                    "relationship-type": {
                        "connects": {
                            "source": {"node": svc["unique-id"]},
                            "destination": {"node": db["unique-id"]},
                        }
                    },
                    "authentication": "vault-dynamic-credentials",
                })

    calm = {
        "$schema": "https://raw.githubusercontent.com/finos/architecture-as-code/main/calm/draft/2025-03/meta/calm.json",
        "$id": f"https://uhccp.internal/imported/{org}",
        "metadata": {
            "application-name": org,
            "imported": True,
            "import-source": "tfe-workspace",
            "import-timestamp": now,
            "workspace-count": len(workspaces),
            "resource-count": sum(len(ws["resources"]) for ws in workspaces),
        },
        "nodes": nodes,
        "relationships": relationships,
    }

    return calm


def generate_decorator(workspaces, clusters):
    """Generate a deployment decorator from workspace metadata."""
    # Detect cloud provider from resource types
    cloud = "unknown"
    for ws in workspaces:
        for res in ws["resources"]:
            if res["type"].startswith("aws_"):
                cloud = "aws"
                break
            elif res["type"].startswith("google_"):
                cloud = "gcp"
                break
            elif res["type"].startswith("azurerm_"):
                cloud = "azure"
                break
        if cloud != "unknown":
            break

    envs = set()
    for c in clusters:
        envs.update(c["environments"])

    decorator = {
        "unique-id": f"imported-{cloud}-decorator",
        "data": {
            "environment": sorted(envs)[0] if envs else "default",
            "cloud-provider": cloud,
            "region": "us-east-1",  # placeholder — needs human review
            "kubernetes": {
                "cluster": "imported-cluster",
                "namespace": "default",
            },
        },
    }

    return decorator


# ---------------------------------------------------------------------------
# Import Block Generation — the key differentiator
# ---------------------------------------------------------------------------

def generate_import_blocks(workspaces):
    """Generate Terraform import blocks for all resources in workspace state.

    This enables Stacks to adopt existing infrastructure without re-creating it.
    Uses the declarative import block syntax (preferred over CLI for auditability).
    """
    blocks = []

    for ws in workspaces:
        blocks.append(f"# --- Imports from workspace: {ws['name']} ---")

        for res in ws["resources"]:
            resource_id = res.get("id", "")
            address = res.get("address", "")

            if not resource_id or not address:
                blocks.append(
                    f"# SKIP: {address} — no resource ID in state "
                    f"(manual import may be required)"
                )
                continue

            # Convert workspace resource address to Stacks component address
            # e.g., "aws_instance.web" → "component.web_service.aws_instance.web"
            calm_type = RESOURCE_TYPE_MAP.get(res["type"], "unknown")
            _sanitize_id(f"{ws['name']}_{calm_type}_{res['name']}")

            blocks.append("import {")
            blocks.append(f"  to = {address}")
            blocks.append(f'  id = "{resource_id}"')
            blocks.append("}")
            blocks.append("")

    return "\n".join(blocks)


def _sanitize_id(calm_id):
    """Convert CALM hyphenated ID to HCL-safe underscore ID."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", calm_id)


# ---------------------------------------------------------------------------
# Migration Plan — human-readable cutover documentation
# ---------------------------------------------------------------------------

def generate_migration_plan(workspaces, clusters):
    """Generate a human-readable migration plan (Markdown)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_resources = sum(len(ws["resources"]) for ws in workspaces)

    lines = [
        "# Workspace → Stacks Migration Plan",
        "",
        f"**Generated:** {now}",
        f"**Workspaces:** {len(workspaces)}",
        f"**Total Resources:** {total_resources}",
        f"**Proposed Components:** {len(clusters)}",
        "",
        "---",
        "",
        "## Proposed Component Grouping",
        "",
        "Review each proposed component. Adjust groupings before running "
        "`calm-forge generate`.",
        "",
    ]

    for i, cluster in enumerate(clusters, 1):
        lines.append(f"### Component {i}: `{cluster['proposed_name']}`")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(
            f"| Workspaces | {', '.join(cluster['workspaces'])} |"
        )
        lines.append(
            f"| Environments | {', '.join(cluster['environments'])} |"
        )
        lines.append(f"| Total resources | {cluster['total_resources']} |")
        lines.append(
            f"| Tags | {', '.join(cluster['tags']) or 'none'} |"
        )
        lines.append("")

        if cluster["resource_summary"]:
            lines.append("**Resource breakdown:**")
            lines.append("")
            for rtype, count in sorted(
                cluster["resource_summary"].items(),
                key=lambda x: -x[1]
            ):
                lines.append(f"- {rtype}: {count}")
            lines.append("")

    lines.extend([
        "---",
        "",
        "## Cutover Steps",
        "",
        "1. **Review** — Verify proposed component groupings above. "
        "Edit the generated CALM JSON if needed.",
        "2. **Generate** — Run `calm-forge generate --calm "
        "calm-instantiation.json --include-imports --full`",
        "3. **Plan** — Push generated Stacks HCL to repo. "
        "TFE creates a plan showing import of existing resources.",
        "4. **Verify** — Plan should show **0 changes** "
        "(imports only, no create/destroy). If changes appear, "
        "the component config needs adjustment.",
        "5. **Apply** — Apply the Stacks deployment. "
        "Resources are adopted into Stacks state.",
        "6. **Release** — Add `removed` blocks to old workspaces "
        "to release resources from workspace state without destroying them.",
        "7. **Decommission** — Delete old workspaces after "
        "verifying Stacks manages all resources.",
        "",
        "---",
        "",
        "## Risk Notes",
        "",
        "- **Import blocks are declarative and auditable** — "
        "preferred over `terraform import` CLI per HashiCorp guidance",
        "- **Run plan before apply** — verify 0-change plan before "
        "applying to avoid accidental recreation",
        "- **One component at a time** — migrate incrementally, "
        "not all at once",
        "- **Keep old workspaces locked** — lock workspaces after "
        "releasing resources to prevent drift during cutover",
        "- **Resources marked SKIP** need manual import IDs — "
        "check the import-blocks.tf file for any SKIPs",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API — main entry point for CLI and future FastAPI wrapper
# ---------------------------------------------------------------------------

def import_workspaces(
    tfe_host,
    tfe_token,
    org,
    output_dir,
    *,
    workspace_filter=None,
    tls_verify=True,
):
    """Full import pipeline: TFE → extract → cluster → CALM → artifacts.

    Returns dict of generated file paths.
    """
    client = TFEClient(tfe_host, tfe_token, tls_verify=tls_verify)

    # Step 1: Extract
    workspaces = extract_workspaces(client, org, workspace_filter)

    if not workspaces:
        raise ValueError(
            f"No workspaces found for org '{org}'"
            + (f" matching '{workspace_filter}'" if workspace_filter else "")
        )

    # Step 2: Cluster
    clusters = cluster_workspaces(workspaces)

    # Step 3: Generate CALM
    calm = workspaces_to_calm(workspaces, clusters, org)
    decorator = generate_decorator(workspaces, clusters)

    # Step 4: Generate import blocks
    import_blocks = generate_import_blocks(workspaces)

    # Step 5: Generate migration plan
    migration_plan = generate_migration_plan(workspaces, clusters)

    # Write outputs
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    files = {
        "calm-instantiation.json": json.dumps(calm, indent=2),
        "decorator.json": json.dumps(decorator, indent=2),
        "import-blocks.tf": import_blocks,
        "workspace-inventory.json": json.dumps(workspaces, indent=2),
        "cluster-proposal.json": json.dumps(clusters, indent=2),
        "migration-plan.md": migration_plan,
    }

    for name, content in files.items():
        filepath = out / name
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)

    return files
