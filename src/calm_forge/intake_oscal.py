"""OSCAL Component Definition → controls-plane nodes (MP-16, ADR-005 §4).

The cyber organization authors in OSCAL. Forge is the PAP that compiles what they
authored into the controls plane; the Rego / tfpolicy / Sentinel emitters read the
resolved parameters as variables at generation time. **The catalog is the source, the
policy is the projection** — there is no manual synchronization step between them and
therefore no window in which the catalog and the enforcement disagree.

Forge does not edit the catalog, translate OSCAL into CALM, or ask the controls team to
learn another language. Intake is one-way and lossless-enough-to-audit: every resolved
value records *which layer set it*.

Scope
-----
**Component Definitions, plus Catalog and Profile parameter resolution. Nothing else.**
Every other OSCAL model raises :class:`OscalIntakeError` naming itself
(:data:`UNSUPPORTED_MODELS`) rather than parsing to an empty result — partial support
that reads as complete is worse than no support, and an SSP silently yielding zero
controls nodes is indistinguishable from a catalog with no controls in it.

Parameter resolution
--------------------
Weakest to strongest, which is OSCAL's own baseline-tailoring order:

1. ``catalog``  — the control's declared ``params[].values`` (its default)
2. ``profile``  — ``modify.set-parameters`` (the baseline tightens it)
3. ``component-implementation`` — ``control-implementation.set-parameters``
4. ``implemented-requirement`` — ``set-parameters`` on the requirement itself

The strongest layer that supplies a value wins, and the winning layer is recorded on
the node as ``set_by``. A parameter the catalog declares and no layer resolves is
**reported, never defaulted** — see :func:`intake_oscal`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .kg_plane import NODE_CLASS_AUTHORED, PLANE_CONTROLS, PREDICATE_GOVERNS

#: The controls-plane node type. One per implemented requirement, not one per control:
#: two components can implement the same control differently, and collapsing them would
#: lose the component that actually carries the obligation.
NODE_TYPE_CONTROL = "ControlImplementation"

#: Node id scheme (ADR-005 assets, OSCAL integration note).
NODE_ID_PREFIX = "kg://oscal/control"

#: OSCAL models this adapter deliberately does not read. Listed so the refusal names
#: itself instead of failing as a parse error somewhere downstream.
UNSUPPORTED_MODELS = (
    "system-security-plan",
    "assessment-plan",
    "assessment-results",
    "plan-of-action-and-milestones",
    "mapping-collection",
)

#: Layers that may set a parameter, weakest first. The index doubles as the precedence.
PARAM_LAYERS = ("catalog", "profile", "component-implementation", "implemented-requirement")

#: Prop name carrying a graph object this control governs — a workload URN or an
#: ``kg://edges/v1/...`` edge id. Read from the component, the control-implementation,
#: and the implemented-requirement; the union is the node's ``governs`` set.
GOVERNS_PROP = "governs"

_INT_RE = re.compile(r"^-?(0|[1-9][0-9]*)$")


class OscalIntakeError(ValueError):
    """Raised when a document is not an OSCAL model this adapter reads."""


# ---------------------------------------------------------------------------
# Typing
# ---------------------------------------------------------------------------

def typed_value(values: list[Any]) -> Any:
    """OSCAL parameter values → a typed Python value.

    OSCAL carries every parameter value as a string, so a generator emitting Rego or
    HCL needs a type. Coercion is **deliberately limited to booleans and integers**.

    A dotted numeral in a control catalog is far more often a version or an identifier
    than a quantity, and floating ``"1.10"`` yields ``1.1`` — which then sorts, compares
    and renders wrong everywhere downstream, silently. Leaving it a string loses
    nothing: a generator that wants a float can cast one. Guessing loses the value.

    Integers are matched strictly, so ``"0644"`` and ``"007"`` stay strings — a
    zero-padded numeral is a mode or a code, not a count.
    """
    typed = [_scalar(v) for v in values]
    if len(typed) == 1:
        return typed[0]
    return typed


def _scalar(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    lowered = value.strip().lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if _INT_RE.match(value.strip()):
        return int(value.strip())
    return value


# ---------------------------------------------------------------------------
# Reading the OSCAL documents
# ---------------------------------------------------------------------------

def _root(document: dict[str, Any], expected: str) -> dict[str, Any]:
    """Unwrap an OSCAL root key, refusing models this adapter does not read."""
    for model in UNSUPPORTED_MODELS:
        if model in document:
            raise OscalIntakeError(
                f"{model!r} is not read by this adapter — MP-16 covers "
                f"component-definition plus catalog/profile parameter resolution only. "
                f"Parsing it to an empty result would be indistinguishable from a "
                f"document with no controls in it."
            )
    if expected not in document:
        raise OscalIntakeError(
            f"expected an OSCAL {expected!r} document; got root keys "
            f"{sorted(document)!r}"
        )
    root = document[expected]
    if not isinstance(root, dict):
        raise OscalIntakeError(f"OSCAL {expected!r} root is not an object")
    return root


def _props(obj: dict[str, Any]) -> dict[str, Any]:
    """``props[]`` flattened to name → value, multi-valued names becoming lists."""
    out: dict[str, Any] = {}
    for prop in obj.get("props", []) or []:
        name, value = prop.get("name"), prop.get("value")
        if not name:
            continue
        if name in out:
            existing = out[name]
            out[name] = [*existing, value] if isinstance(existing, list) else [existing, value]
        else:
            out[name] = value
    return out


def _governs(obj: dict[str, Any]) -> list[str]:
    value = _props(obj).get(GOVERNS_PROP)
    if value is None:
        return []
    return [str(v) for v in (value if isinstance(value, list) else [value])]


def _set_parameters(obj: dict[str, Any]) -> dict[str, list[Any]]:
    """``set-parameters[]`` → param-id → raw values."""
    out: dict[str, list[Any]] = {}
    for sp in obj.get("set-parameters", []) or []:
        param_id = sp.get("param-id")
        if param_id:
            out[param_id] = list(sp.get("values", []) or [])
    return out


def _catalog_controls(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """control-id → control, flattened across nested groups and controls."""
    found: dict[str, dict[str, Any]] = {}

    def walk(container: dict[str, Any]) -> None:
        for control in container.get("controls", []) or []:
            if control.get("id"):
                found[control["id"]] = control
            walk(control)
        for group in container.get("groups", []) or []:
            walk(group)

    walk(catalog)
    return found


def catalog_defaults(catalog_document: dict[str, Any]) -> dict[str, dict[str, list[Any]]]:
    """control-id → param-id → declared default values, from an OSCAL catalog.

    A param with a ``select`` and no ``values`` has **no default** and is omitted, so
    that it surfaces later as unresolved rather than as an arbitrary choice picked from
    the constraint list.
    """
    catalog = _root(catalog_document, "catalog")
    defaults: dict[str, dict[str, list[Any]]] = {}
    for control_id, control in _catalog_controls(catalog).items():
        params: dict[str, list[Any]] = {}
        for param in control.get("params", []) or []:
            pid = param.get("id")
            if not pid:
                continue
            params[pid] = list(param.get("values", []) or [])
        if params:
            defaults[control_id] = params
    return defaults


def profile_overrides(profile_document: dict[str, Any]) -> dict[str, list[Any]]:
    """param-id → values from a profile's ``modify.set-parameters``.

    Profile overrides are catalog-wide by param id, which is how OSCAL expresses them;
    they are not scoped per control.
    """
    profile = _root(profile_document, "profile")
    return _set_parameters(profile.get("modify", {}) or {})


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def resolve_parameters(
    control_id: str,
    *,
    catalog_defaults: dict[str, dict[str, list[Any]]] | None = None,
    profile_overrides: dict[str, list[Any]] | None = None,
    implementation_params: dict[str, list[Any]] | None = None,
    requirement_params: dict[str, list[Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Resolve one requirement's parameters through the four layers.

    Returns ``(resolved, unresolved)`` where ``resolved`` maps param-id to
    ``{"value": typed, "raw": [...], "set_by": <layer>}`` and ``unresolved`` lists
    param-ids the catalog declares that no layer supplied a value for.

    **Scope, not just precedence.** Profile and control-implementation ``set-parameters``
    are keyed by bare param-id with no control attached, so applying them wholesale
    attaches every baseline parameter to every control — a profile tightening
    ``key-rotation-days`` would land that value on a TLS control that never declared it,
    and the generated policy would carry a variable the catalog never scoped there. The
    catalog's ``params`` for the control **is** the scope: those two layers apply only to
    a param the control declares. The implemented-requirement layer is exempt, because it
    is written against one requirement and cannot be misdirected.

    With no catalog there is no declared set, so the two unscopable layers fall back to
    "whatever the implementation itself names" and the profile is refused upstream
    (:func:`intake_oscal`) rather than applied blind.

    An unresolved parameter is **never given a placeholder.** A policy generator that
    substitutes an empty allowed-set produces a rule that denies everything or permits
    everything depending on its shape, and either way the catalog never said so.
    """
    catalog_params = (catalog_defaults or {}).get(control_id, {})
    scoped = set(catalog_params) if catalog_defaults else None

    def in_scope(param_id: str) -> bool:
        return scoped is None or param_id in scoped

    layers: list[tuple[str, dict[str, list[Any]], bool]] = [
        ("catalog", catalog_params, False),
        ("profile", profile_overrides or {}, False),
        ("component-implementation", implementation_params or {}, False),
        ("implemented-requirement", requirement_params or {}, True),
    ]

    declared = set(catalog_params)
    resolved: dict[str, dict[str, Any]] = {}

    # Weakest first; each layer that supplies a non-empty value overwrites the previous,
    # so the last writer is the strongest layer that had something to say.
    for layer, params, exempt in layers:
        for param_id, values in params.items():
            if not exempt and not in_scope(param_id):
                continue
            declared.add(param_id)
            if not values:
                continue
            resolved[param_id] = {
                "value": typed_value(values),
                "raw": list(values),
                "set_by": layer,
            }

    unresolved = sorted(declared - set(resolved))
    return resolved, unresolved


def parameter_variables(node: dict[str, Any]) -> dict[str, Any]:
    """param-id → typed value, for a policy generator to read as variables.

    Computed on read rather than stored beside ``parameters``: a second copy of the same
    fact is a second thing that can go stale, which is the divergence the content-digest
    discipline exists to eliminate.
    """
    return {pid: p["value"] for pid, p in (node.get("parameters") or {}).items()}


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def intake_oscal(
    component_definition: dict[str, Any],
    *,
    catalog: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
) -> dict[str, list[Any]]:
    """Compile an OSCAL Component Definition into controls-plane nodes and edges.

    Returns ``{"controls_nodes": [...], "edges": [...], "gaps": [...]}``.

    One node per *implemented requirement*, tagged ``node_class: authored`` /
    ``plane: controls`` — never architecture. A controls node landing in the
    architecture plane would be invisible to every cross-plane finding, which is the
    exact failure ADR-005's no-default plane rule exists to prevent.

    ``governs`` edges join the controls plane to the architecture plane **in the graph**,
    one direction, from the controls node outward. The edge carries no plane of its own;
    its plane is its authoring node's (ADR-005 §1), which is what makes "a controls-plane
    fact about an architecture-plane object" expressible at all.
    """
    if profile is not None and catalog is None:
        # A profile tailors a catalog. Its set-parameters name a param-id and no control,
        # so without the catalog's declarations there is nothing to scope them against,
        # and applying them catalog-wide attaches every baseline value to every control.
        raise OscalIntakeError(
            "a profile was supplied without its catalog — profile set-parameters are "
            "keyed by param-id with no control attached, so they cannot be scoped, and "
            "applying them unscoped would attach baseline values to controls that never "
            "declared them"
        )

    root = _root(component_definition, "component-definition")
    defaults = catalog_defaults(catalog) if catalog else {}
    overrides = profile_overrides(profile) if profile else {}

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    gaps: list[str] = []

    for component in root.get("components", []) or []:
        component_governs = _governs(component)
        component_meta = {
            "uuid": component.get("uuid"),
            "title": component.get("title"),
            "type": component.get("type"),
        }

        for impl in component.get("control-implementations", []) or []:
            impl_params = _set_parameters(impl)
            impl_governs = _governs(impl)

            for req in impl.get("implemented-requirements", []) or []:
                control_id = req.get("control-id")
                if not control_id:
                    gaps.append(
                        f"{component.get('title', '<component>')}: implemented-requirement "
                        f"{req.get('uuid', '<no uuid>')} has no control-id — skipped"
                    )
                    continue

                resolved, unresolved = resolve_parameters(
                    control_id,
                    catalog_defaults=defaults,
                    profile_overrides=overrides,
                    implementation_params=impl_params,
                    requirement_params=_set_parameters(req),
                )
                for param_id in unresolved:
                    gaps.append(
                        f"{control_id}: parameter {param_id!r} is declared but no layer "
                        f"resolves it — a policy generated from this control would have "
                        f"a hole"
                    )

                node_id = control_node_id(control_id, req.get("uuid", ""))
                governs = sorted(set(component_governs) | set(impl_governs) | set(_governs(req)))

                nodes.append({
                    "@type": NODE_TYPE_CONTROL,
                    "@id": node_id,
                    "node_class": NODE_CLASS_AUTHORED,
                    "plane": PLANE_CONTROLS,
                    "control_id": control_id,
                    "implemented_requirement_uuid": req.get("uuid"),
                    "source": impl.get("source"),
                    "component": component_meta,
                    "description": req.get("description") or impl.get("description"),
                    "parameters": resolved,
                    "unresolved_parameters": unresolved,
                    "props": _props(req) or _props(impl) or _props(component),
                    "governs": governs,
                })
                edges.extend(
                    {"@type": PREDICATE_GOVERNS, "from": node_id, "to": target}
                    for target in governs
                )

    return {"controls_nodes": nodes, "edges": edges, "gaps": gaps}


def control_node_id(control_id: str, requirement_uuid: str) -> str:
    """Stable controls-plane node id.

    Keyed on the implemented-requirement uuid, which OSCAL guarantees stable across
    catalog re-issues, so re-running intake against an updated catalog **updates** the
    node rather than orphaning it — and ``ORPHANED_POLICY`` stays a real signal instead
    of firing on every routine re-import.
    """
    return f"{NODE_ID_PREFIX}/{_slug(control_id)}/{_slug(requirement_uuid)}"


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-") or "unknown"


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def _load(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise OscalIntakeError(f"{path}: OSCAL documents are objects, got {type(data).__name__}")
    return data


def intake_oscal_from_file(
    component_definition_path: str | Path,
    *,
    catalog_path: str | Path | None = None,
    profile_path: str | Path | None = None,
) -> dict[str, list[Any]]:
    """Read the OSCAL documents from disk and compile them."""
    cd = _load(component_definition_path)
    assert cd is not None
    return intake_oscal(cd, catalog=_load(catalog_path), profile=_load(profile_path))


def write_controls_nodes(nodes: list[dict[str, Any]], output_dir: Path) -> list[Path]:
    """Write controls-plane nodes as JSON-LD to ``<output_dir>/controls/``."""
    controls_dir = output_dir / "controls"
    controls_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].removeprefix(f"{NODE_ID_PREFIX}/").replace("/", "-")
        path = controls_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written
