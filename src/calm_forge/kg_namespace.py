"""KG namespace resolution and RBAC — multi-tenant knowledge graph support.

Directory layout:
  <kg_root>/
    environments/          # root namespace (always present)
    placements/
    workloads/
    <namespace-a>/         # named namespace
      environments/
      placements/
      workloads/
    <namespace-b>/
      ...

Rules:
  - Root namespace: the kg_root itself.
  - Named namespaces: immediate subdirectories of kg_root that contain at
    least one of {environments/, placements/, workloads/}.
  - Excluded from namespace scan: environments/, placements/, workloads/,
    and any path starting with '_'.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_KG_SUBDIRS = {"environments", "placements", "workloads"}


# ---------------------------------------------------------------------------
# Namespace RBAC
# ---------------------------------------------------------------------------

@dataclass
class NamespacePolicy:
    """Access control policy for a KG namespace.

    Loaded from <kg_dir>/_fabric/namespace-policy.json.
    When no policy file exists, all access is permitted (permissive default).
    """
    namespace: str
    allowed_principals: list[str] = field(default_factory=list)
    deny_principals: list[str] = field(default_factory=list)


class NamespaceAccessDenied(PermissionError):
    """Raised when a principal is denied access to a namespace."""
    def __init__(self, principal: str, namespace: str):
        super().__init__(f"Principal {principal!r} is denied access to namespace {namespace!r}")
        self.principal = principal
        self.namespace = namespace


def load_namespace_policy(kg_dir: Path, namespace: str) -> NamespacePolicy | None:
    """Load a NamespacePolicy from <kg_dir>/_fabric/namespace-policy.json.

    Returns None when no policy file exists (permissive default).
    """
    policy_file = kg_dir / "_fabric" / "namespace-policy.json"
    if not policy_file.exists():
        return None
    try:
        data: dict[str, Any] = json.loads(policy_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return NamespacePolicy(
        namespace=namespace,
        allowed_principals=data.get("allowed_principals", []),
        deny_principals=data.get("deny_principals", []),
    )


def check_namespace_access(kg_root: Path, namespace: str, principal: str) -> bool:
    """Return True when the principal is allowed to access the namespace.

    Returns True (permissive) when no policy file exists.
    deny_principals takes precedence over allowed_principals.
    When allowed_principals is non-empty, principal must be in the list.
    """
    effective = resolve_kg_dir(kg_root, namespace)
    policy = load_namespace_policy(effective, namespace)
    if policy is None:
        return True
    if principal in policy.deny_principals:
        return False
    if policy.allowed_principals and principal not in policy.allowed_principals:
        return False
    return True


def validate_namespace_access(kg_root: Path, namespace: str, principal: str) -> None:
    """Raise NamespaceAccessDenied when the principal cannot access the namespace."""
    if not check_namespace_access(kg_root, namespace, principal):
        raise NamespaceAccessDenied(principal, namespace)


def resolve_kg_dir(kg_root: Path, namespace: str | None) -> Path:
    """Return the effective KG directory for a given namespace.

    namespace=None or "" → kg_root (backward compatible)
    namespace="payments-team" → kg_root / "payments-team"
    """
    if not namespace:
        return kg_root
    return kg_root / namespace


def list_namespaces(kg_root: Path) -> list[tuple[str, Path]]:
    """Return (name, path) for all namespaces under kg_root.

    Always includes ("", kg_root) for the root namespace.
    Named namespaces are immediate subdirs that look like KG directories.
    """
    namespaces: list[tuple[str, Path]] = [("", kg_root)]
    if not kg_root.exists():
        return namespaces
    for child in sorted(kg_root.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        if name in _KG_SUBDIRS or name.startswith("_"):
            continue
        if _is_kg_dir(child):
            namespaces.append((name, child))
    return namespaces


def _is_kg_dir(path: Path) -> bool:
    return any((path / sub).exists() for sub in _KG_SUBDIRS)
