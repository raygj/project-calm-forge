"""Tests for dcm_writer — CALM architecture → DCM Application spec."""
from __future__ import annotations

import json

from calm_forge.dcm_writer import (
    _derive_name,
    _derive_placement_strategy,
    _derive_required_capabilities,
    _derive_service,
    _derive_tier,
    _derive_zones,
    write_dcm_application,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_ARCH_PCI = {
    "title": "Payments Portal — Production Architecture",
    "nodes": [
        {"unique-id": "web", "node-type": "service", "container-image": "registry/web:1.0"},
        {"unique-id": "api", "node-type": "service", "description": "Payment API — PCI Zone 1"},
        {"unique-id": "db", "node-type": "database"},
    ],
    "relationships": [],
    "metadata": {},
}

_ARCH_VM = {
    "title": "Legacy VM Workload",
    "nodes": [
        {"unique-id": "app", "node-type": "system", "description": "App server"},
    ],
    "relationships": [],
    "metadata": {},
}

_ARCH_MINIMAL = {
    "title": "Simple Service",
    "nodes": [{"unique-id": "svc", "node-type": "service"}],
    "relationships": [],
    "metadata": {},
}

_DECORATOR_WITH_REGION = {
    "data": {
        "region": "us-east-1",
        "environment": "production",
    }
}

_DECORATOR_WITH_DCM_OVERRIDES = {
    "data": {
        "region": "us-east-1",
        "dcm": {
            "tier": 1,
            "zones": ["us-east-1", "eu-west-1"],
        },
    }
}

_DECORATOR_EMPTY = {"data": {}}


# ---------------------------------------------------------------------------
# write_dcm_application — output is valid JSON with required keys
# ---------------------------------------------------------------------------


def test_output_is_valid_json() -> None:
    result = write_dcm_application(_ARCH_PCI, _DECORATOR_WITH_REGION)
    spec = json.loads(result)
    assert isinstance(spec, dict)


def test_output_has_required_keys() -> None:
    spec = json.loads(write_dcm_application(_ARCH_PCI, _DECORATOR_WITH_REGION))
    for key in ("name", "service", "tier", "zones"):
        assert key in spec


# ---------------------------------------------------------------------------
# _derive_name
# ---------------------------------------------------------------------------


def test_name_strips_production_architecture_suffix() -> None:
    arch = {"title": "Payments Portal — Production Architecture"}
    assert _derive_name(arch) == "payments-portal"


def test_name_strips_hyphen_variant_suffix() -> None:
    arch = {"title": "Fraud API - Production"}
    assert _derive_name(arch) == "fraud-api"


def test_name_is_slug() -> None:
    arch = {"title": "My App (v2)"}
    name = _derive_name(arch)
    assert name == "my-app-v2"


def test_name_falls_back_to_metadata() -> None:
    arch = {"metadata": {"name": "fallback-service"}}
    assert _derive_name(arch) == "fallback-service"


def test_name_falls_back_to_id_path() -> None:
    arch = {"$id": "https://example.com/architectures/my-service.json"}
    assert _derive_name(arch) == "my-service-json"


def test_name_unknown_when_no_title() -> None:
    assert _derive_name({}) == "unknown"


# ---------------------------------------------------------------------------
# _derive_service
# ---------------------------------------------------------------------------


def test_service_container_when_container_image_present() -> None:
    arch = {"nodes": [{"unique-id": "x", "container-image": "registry/img:1"}]}
    assert _derive_service(arch) == "container"


def test_service_container_when_node_type_service() -> None:
    arch = {"nodes": [{"unique-id": "x", "node-type": "service"}]}
    assert _derive_service(arch) == "container"


def test_service_webserver_when_no_container_signal() -> None:
    arch = {"nodes": [{"unique-id": "x", "node-type": "system"}]}
    assert _derive_service(arch) == "webserver"


def test_service_webserver_when_no_nodes() -> None:
    assert _derive_service({"nodes": []}) == "webserver"


# ---------------------------------------------------------------------------
# _derive_tier
# ---------------------------------------------------------------------------


def test_tier_explicit_override_wins() -> None:
    decorator = {"data": {"dcm": {"tier": 1}}}
    assert _derive_tier(_ARCH_VM, decorator) == 1


def test_tier_explicit_override_as_string_coerced() -> None:
    decorator = {"data": {"dcm": {"tier": "2"}}}
    assert _derive_tier(_ARCH_VM, decorator) == 2


def test_tier_pci_in_title_yields_1() -> None:
    arch = {"title": "PCI Payments App", "nodes": []}
    assert _derive_tier(arch, _DECORATOR_EMPTY) == 1


def test_tier_pci_in_node_description_yields_1() -> None:
    arch = {"title": "Payments App", "nodes": [{"description": "Cardholder data — PCI Zone 1"}]}
    assert _derive_tier(arch, _DECORATOR_EMPTY) == 1


def test_tier_default_is_2() -> None:
    assert _derive_tier(_ARCH_MINIMAL, _DECORATOR_EMPTY) == 2


# ---------------------------------------------------------------------------
# _derive_zones
# ---------------------------------------------------------------------------


def test_zones_explicit_list_from_dcm_override() -> None:
    decorator = {"data": {"dcm": {"zones": ["us-east-1", "eu-west-1"]}}}
    assert _derive_zones(decorator) == ["us-east-1", "eu-west-1"]


def test_zones_single_string_from_dcm_override_wrapped() -> None:
    decorator = {"data": {"dcm": {"zones": "us-east-1"}}}
    assert _derive_zones(decorator) == ["us-east-1"]


def test_zones_falls_back_to_decorator_region() -> None:
    assert _derive_zones(_DECORATOR_WITH_REGION) == ["us-east-1"]


def test_zones_empty_when_no_region() -> None:
    assert _derive_zones(_DECORATOR_EMPTY) == []


# ---------------------------------------------------------------------------
# Integration: full spec shape for PCI workload
# ---------------------------------------------------------------------------


def test_pci_arch_produces_tier1_container() -> None:
    spec = json.loads(write_dcm_application(_ARCH_PCI, _DECORATOR_WITH_REGION))
    assert spec["tier"] == 1
    assert spec["service"] == "container"
    assert spec["zones"] == ["us-east-1"]
    assert spec["name"] == "payments-portal"


def test_dcm_overrides_take_full_precedence() -> None:
    spec = json.loads(write_dcm_application(_ARCH_PCI, _DECORATOR_WITH_DCM_OVERRIDES))
    assert spec["tier"] == 1
    assert spec["zones"] == ["us-east-1", "eu-west-1"]


def test_vm_arch_default_tier2_webserver() -> None:
    spec = json.loads(write_dcm_application(_ARCH_VM, _DECORATOR_WITH_REGION))
    assert spec["tier"] == 2
    assert spec["service"] == "webserver"


# ---------------------------------------------------------------------------
# P1-018 — capability-based placement (fraud detection example)
# ---------------------------------------------------------------------------

_ARCH_FRAUD = {
    "title": "Fraud Detection Pipeline — Production Architecture",
    "nodes": [
        {
            "unique-id": "transaction-ingest",
            "node-type": "service",
            "container-image": "registry/fraud/ingest:3.2.1",
            "required-capabilities": ["packet_offload", "high_throughput_io"],
            "capability-profile": "network-offload",
        },
        {
            "unique-id": "ml-scoring",
            "node-type": "service",
            "container-image": "registry/fraud/scoring:1.8.0",
            "required-capabilities": ["confidential_compute", "memory_bandwidth_min_256gb"],
            "capability-profile": "confidential-inference",
        },
        {
            "unique-id": "external-state",
            "node-type": "service",
            "container-image": "registry/fraud/state:2.0.0",
            "required-capabilities": ["external_state_management", "sub_millisecond_read"],
            "capability-profile": "portable-state",
        },
        {
            "unique-id": "infra-placement-target",
            "node-type": "system",
        },
    ],
    "relationships": [],
    "metadata": {
        "placement-strategy": "capability_match",
    },
}

_DECORATOR_CAPABILITY = {
    "data": {
        "dcm": {
            "tier": 1,
            "placement_strategy": "capability_match",
            "zones": ["us-east-1", "eu-west-1"],
        }
    }
}


def test_derive_required_capabilities_collects_all_nodes():
    caps = _derive_required_capabilities(_ARCH_FRAUD)
    assert "confidential_compute" in caps
    assert "packet_offload" in caps
    assert "external_state_management" in caps
    assert "sub_millisecond_read" in caps


def test_derive_required_capabilities_deduplicates():
    arch = {"nodes": [
        {"required-capabilities": ["confidential_compute", "packet_offload"]},
        {"required-capabilities": ["confidential_compute"]},
    ]}
    caps = _derive_required_capabilities(arch)
    assert caps.count("confidential_compute") == 1


def test_derive_required_capabilities_sorted():
    caps = _derive_required_capabilities(_ARCH_FRAUD)
    assert caps == sorted(caps)


def test_derive_required_capabilities_empty_when_none_declared():
    assert _derive_required_capabilities(_ARCH_PCI) == []


def test_derive_required_capabilities_skips_system_nodes():
    caps = _derive_required_capabilities(_ARCH_FRAUD)
    # system node has no required-capabilities — just confirm no error
    assert isinstance(caps, list)


def test_derive_placement_strategy_from_decorator():
    assert _derive_placement_strategy(_ARCH_FRAUD, _DECORATOR_CAPABILITY) == "capability_match"


def test_derive_placement_strategy_from_metadata():
    assert _derive_placement_strategy(_ARCH_FRAUD, {"data": {}}) == "capability_match"


def test_derive_placement_strategy_default_zone_match():
    arch = {"nodes": [], "metadata": {}}
    assert _derive_placement_strategy(arch, {"data": {}}) == "zone_match"


def test_capability_arch_includes_required_capabilities_in_spec():
    spec = json.loads(write_dcm_application(_ARCH_FRAUD, _DECORATOR_CAPABILITY))
    assert "required_capabilities" in spec
    assert "confidential_compute" in spec["required_capabilities"]
    assert spec["placement_strategy"] == "capability_match"


def test_no_capabilities_arch_omits_required_capabilities():
    spec = json.loads(write_dcm_application(_ARCH_PCI, _DECORATOR_WITH_REGION))
    assert "required_capabilities" not in spec
    assert "placement_strategy" not in spec


def test_fraud_example_dcm_roundtrip():
    """DCM artifact for fraud detection example matches expected output."""
    import tempfile
    from pathlib import Path

    from calm_forge.generator import generate_stack

    example = Path("examples/fraud-detection-workload-portability")
    expected_dir = example / "expected-output"
    with tempfile.TemporaryDirectory() as tmp:
        generate_stack(
            str(example / "instantiation.json"),
            str(example / "decorator.json"),
            str(example / "catalog.json"),
            tmp,
            full=True,
        )
        actual = (Path(tmp) / "dcm" / "application.json").read_text()
        expected = (expected_dir / "dcm" / "application.json").read_text()
        assert actual == expected


def test_fraud_example_non_timestamped_roundtrip():
    """Non-timestamped artifacts match expected output."""
    import tempfile
    from pathlib import Path

    from calm_forge.generator import generate_stack

    example = Path("examples/fraud-detection-workload-portability")
    expected_dir = example / "expected-output"
    # These files have no embedded timestamps
    check = [
        "dcm/application.json",
        "vault/policies.hcl",
        "vault/pki-config.hcl",
        "sentinel/policies.sentinel",
        "ansible/inventory.yml",
        "ansible/eda-rulebook.yml",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        generate_stack(
            str(example / "instantiation.json"),
            str(example / "decorator.json"),
            str(example / "catalog.json"),
            tmp,
            full=True,
        )
        for name in check:
            actual = (Path(tmp) / name).read_text()
            expected = (expected_dir / name).read_text()
            assert actual == expected, f"Mismatch in {name}"


def test_fraud_example_capability_modules_in_components():
    """components.tfstack.hcl uses capability-matched module sources."""
    import tempfile
    from pathlib import Path

    from calm_forge.generator import generate_stack

    example = Path("examples/fraud-detection-workload-portability")
    with tempfile.TemporaryDirectory() as tmp:
        generate_stack(
            str(example / "instantiation.json"),
            str(example / "decorator.json"),
            str(example / "catalog.json"),
            tmp,
            full=True,
        )
        content = (Path(tmp) / "components.tfstack.hcl").read_text()
        assert "confidential-compute-workload" in content
        assert "portable-state-layer" in content
        assert "network-offload-service" in content
        # ml-scoring component block uses confidential-compute-workload module
        assert 'component "ml_scoring"' in content
        ml_block_start = content.index('component "ml_scoring"')
        ml_block = content[ml_block_start:ml_block_start + 300]
        assert "confidential-compute-workload" in ml_block
