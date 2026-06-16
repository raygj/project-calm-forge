package calm

import rego.v1

# ---------------------------------------------------------------------------
# Rule 1: PCI Placement
# PCI workloads must target prod-pci-* clusters
# ---------------------------------------------------------------------------
violation contains v if {
    input.decorator.data["compliance"] == "pci"
    env := input.decorator.data["environment"]
    not startswith(env, "prod-pci")
    v := {
        "rule": "pci-placement",
        "severity": "error",
        "message": sprintf(
            "PCI workloads must target prod-pci-* clusters. Got environment: '%v'",
            [env]
        ),
    }
}

# ---------------------------------------------------------------------------
# Rule 2: Dynamic Credentials Required
# Database nodes must have a vault-dynamic-credentials relationship
# ---------------------------------------------------------------------------
violation contains v if {
    some node in input.calm.nodes
    node["node-type"] == "database"
    node_id := node["unique-id"]
    not has_dynamic_creds(node_id)
    v := {
        "rule": "dynamic-creds-required",
        "severity": "error",
        "message": sprintf(
            "Database node '%v' must have a vault-dynamic-credentials authentication relationship",
            [node_id]
        ),
    }
}

has_dynamic_creds(node_id) if {
    some rel in input.calm.relationships
    rel["relationship-type"]["connects"]["destination"]["node"] == node_id
    rel["authentication"] == "vault-dynamic-credentials"
}

# ---------------------------------------------------------------------------
# Rule 3: Production Replica Minimum
# Production services must have replicas >= 2
# ---------------------------------------------------------------------------
violation contains v if {
    some node in input.calm.nodes
    node["node-type"] == "service"
    input.decorator.data["environment"] == "production"
    replicas := object.get(node, "replicas", 1)
    replicas < 2
    v := {
        "rule": "production-replica-minimum",
        "severity": "warning",
        "message": sprintf(
            "Service '%v' has %v replica(s) — production requires >= 2",
            [node["unique-id"], replicas]
        ),
    }
}

# ---------------------------------------------------------------------------
# violations: array form (primary query target)
# ---------------------------------------------------------------------------
violations := [v | v := violation[_]]
