"""Deprecated: use kg_multi_root for local fan-out, kg_coherence_api for XC_ADR-008 federation."""
from .kg_multi_root import (
    MultiRootConfig as FederationConfig,
)
from .kg_multi_root import (
    MultiRootError as FederationError,
)
from .kg_multi_root import (
    MultiRootKGView as FederatedKGView,
)
from .kg_multi_root import (
    load_multi_root_config as load_federation_config,
)
from .kg_multi_root import (
    multi_root_fabric_feed as federated_fabric_feed,
)
from .kg_multi_root import (
    multi_root_kg_query as federated_kg_query,
)
from .kg_multi_root import (
    multi_root_kg_status as federated_kg_status,
)
from .kg_multi_root import (
    save_multi_root_config as save_federation_config,
)

# Backward-compat re-export shim. Listing the aliases in __all__ marks them as
# this module's public API so linters keep them (they are intentionally unused here).
__all__ = [
    "FederationConfig",
    "FederationError",
    "FederatedKGView",
    "load_federation_config",
    "federated_fabric_feed",
    "federated_kg_query",
    "federated_kg_status",
    "save_federation_config",
]
