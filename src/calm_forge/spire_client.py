"""Live SPIRE Workload API adapter (APP-080).

The in-cluster implementation of the ``WorkloadApiClient`` seam: fetches this workload's
X.509-SVID from a SPIRE agent over the Workload API (unix socket, delivered by the SPIFFE
CSI driver) and reduces it to the ``Svid`` the passport signer needs.

Optional dependency — ``pip install 'calm-forge[spire]'`` (the ``spiffe`` library). It is
imported lazily so offline installs and the whole test suite never require it. The SVID leaf
key is EC P-256 in the standard SPIRE config, which the algorithm-aware signer handles as
``ecdsa-p256`` (see calm_forge.passport).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .passport_seams import Svid, WorkloadApiClient

DEFAULT_SOCKET = "unix:///spiffe-workload-api/spire-agent.sock"


class SpiffeSocketClient(WorkloadApiClient):
    """Fetch X.509-SVIDs from a live SPIRE agent Workload API socket."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET):
        # Accept a bare path or a unix:// URI; the library wants the URI form.
        self.socket_path = socket_path if "://" in socket_path else f"unix://{socket_path}"

    def fetch_x509_svid(self) -> Svid:
        try:
            from spiffe import WorkloadApiClient as _SpiffeClient
        except ImportError as exc:  # pragma: no cover - exercised in-cluster
            raise RuntimeError(
                "SPIRE support needs the 'spiffe' library. Install with: "
                "pip install 'calm-forge[spire]'"
            ) from exc

        with _SpiffeClient(socket_path=self.socket_path) as client:
            svid = client.fetch_x509_svid()

        key = svid.private_key
        if not isinstance(key, (Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
            raise RuntimeError(
                f"SVID key type {type(key).__name__} is not signable as a passport proof "
                "(supported: Ed25519, EC P-256). Check the SPIRE agent's SVID key config."
            )
        return Svid(private_key=key, spiffe_id=str(svid.spiffe_id))
