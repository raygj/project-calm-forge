package calm.drift

import rego.v1

# ---------------------------------------------------------------------------
# Rule: Capability Ceiling (manifests_as invariant — ADR-0024)
# capabilities_granted must be a strict subset of declared_capabilities.
# Runtime can never exceed design intent.
#
# input shape:
#   {
#     "edges": [{"@type": "manifests_as", "capabilities_granted": [...], ...}],
#     "workload": {"declared_capabilities": [...]}   -- flat union of all components
#   }
# ---------------------------------------------------------------------------

violation contains v if {
    edge := input.edges[_]
    edge["@type"] == "manifests_as"
    granted := {c | c := edge.capabilities_granted[_]}
    declared := {c | c := input.workload.declared_capabilities[_]}
    extra := granted - declared
    count(extra) > 0
    v := {
        "rule": "capability-ceiling",
        "severity": "violation",
        "message": sprintf(
            "capabilities_granted exceeds declared_capabilities: %v",
            [extra]
        ),
    }
}

violations := [v | v := violation[_]]
