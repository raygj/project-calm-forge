"""Module resolution — maps CALM nodes and relationships to Terraform modules."""


def resolve_module(node, catalog):
    """Map a CALM node to a Terraform module from the catalog.

    Resolution order:
    1. Variant match on node-type + metadata keys (most specific first)
    2. Default for node-type
    3. None for system nodes (deployment targets, not components)
    """
    node_type = node["node-type"]

    if node_type == "system":
        return None

    if node_type not in catalog["modules"]:
        available = ", ".join(sorted(catalog["modules"].keys()))
        raise ValueError(
            f"No module in catalog for node-type: '{node_type}'. "
            f"Check the node's 'node-type' field. "
            f"Available types: {available}"
        )

    type_entry = catalog["modules"][node_type]

    if "variants" in type_entry:
        for variant_name, variant in type_entry["variants"].items():
            if _matches_variant(node, variant["match"]):
                return {
                    "source": variant["source"],
                    "variant": variant_name,
                    "description": variant.get("description", ""),
                }

    return {"source": type_entry["default"], "variant": "default"}


def _matches_variant(node, match_criteria):
    """Check if a node satisfies all variant match criteria."""
    for key, value in match_criteria.items():
        if node.get(key) != value:
            return False
    return True


def resolve_relationship_components(relationships, catalog):
    """Find authentication-bearing relationships and resolve their Vault modules.

    A connects relationship with an authentication field (e.g. mTLS-vault-pki,
    vault-dynamic-credentials) generates an additional infrastructure component
    (Vault PKI engine, dynamic database credentials, etc.).
    """
    components = []

    for rel in relationships:
        rel_type_obj = rel.get("relationship-type", {})
        if "connects" not in rel_type_obj:
            continue

        auth = rel.get("authentication")
        if not auth:
            continue

        for _cat_key, entry in catalog["modules"].items():
            if not isinstance(entry, dict) or "match" not in entry:
                continue
            if entry["match"].get("authentication") == auth:
                components.append({
                    "relationship": rel,
                    "source": entry["source"],
                    "description": entry.get("description", ""),
                })
                break

    return components
