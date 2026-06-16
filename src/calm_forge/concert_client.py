"""Concert risk API client — live risk export with fixture fallback.

ConcertClient.from_env() reads CALM_FORGE_CONCERT_URL + CALM_FORGE_CONCERT_API_KEY.
When those env vars are absent, returns FixtureConcertClient (loads from
CALM_FORGE_CONCERT_FIXTURE or raises ConcertAPIError when that is also absent).

Both clients return the same fixture shape accepted by intake_concert():
  { "applications": [ { "name": ..., "risk_score": ..., ... } ] }
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class ConcertAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ConcertClient:
    """Live Concert REST API client.

    Args:
        base_url: Concert API base URL (no trailing slash).
        api_key:  API key for Authorization: Bearer header.
        timeout:  Request timeout in seconds (default 10).
        retries:  Number of retry attempts on transient errors (default 2).
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 10, retries: int = 2):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.retries = retries

    @classmethod
    def from_env(cls) -> "ConcertClient | FixtureConcertClient":
        """Return a ConcertClient when env vars are set, else FixtureConcertClient."""
        url = os.getenv("CALM_FORGE_CONCERT_URL", "")
        key = os.getenv("CALM_FORGE_CONCERT_API_KEY", "")
        if url and key:
            return cls(base_url=url, api_key=key)
        fixture_path = os.getenv("CALM_FORGE_CONCERT_FIXTURE", "")
        return FixtureConcertClient(fixture_path=fixture_path or None)

    def get_risk_export(self, app_names: list[str] | None = None) -> dict[str, Any]:
        """Fetch the Concert risk export for one or more application names.

        Args:
            app_names: Optional list of application names to filter the export.
                       When None, fetches all applications.

        Returns:
            dict matching the Concert export fixture shape:
              { "applications": [ { "name", "risk_score", "risk_level",
                                    "blocked_environments", "allowed_environments",
                                    "evaluated_at" } ] }

        Raises:
            ConcertAPIError: on HTTP error or network failure.
        """
        endpoint = f"{self.base_url}/api/v1/risk-export"
        if app_names:
            names_param = ",".join(app_names)
            endpoint = f"{endpoint}?names={names_param}"

        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(endpoint)
                req.add_header("Authorization", f"Bearer {self.api_key}")
                req.add_header("Accept", "application/json")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                body = exc.read().decode() if exc.fp else ""
                raise ConcertAPIError(
                    f"Concert API {exc.code} at {endpoint}: {body}", status_code=exc.code
                ) from exc
            except (urllib.error.URLError, OSError) as exc:
                last_exc = exc
                if attempt < self.retries:
                    continue
        raise ConcertAPIError(f"Concert API unreachable after {self.retries + 1} attempts: {last_exc}") from last_exc


class FixtureConcertClient:
    """Concert client backed by a local JSON fixture file.

    Used in CI and local development when CALM_FORGE_CONCERT_URL is absent.
    """

    def __init__(self, fixture_path: str | Path | None = None):
        self.fixture_path = Path(fixture_path) if fixture_path else None

    def get_risk_export(self, app_names: list[str] | None = None) -> dict[str, Any]:
        if self.fixture_path is None:
            raise ConcertAPIError(
                "No Concert fixture configured. Set CALM_FORGE_CONCERT_FIXTURE or "
                "CALM_FORGE_CONCERT_URL + CALM_FORGE_CONCERT_API_KEY."
            )
        try:
            data = json.loads(self.fixture_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ConcertAPIError(f"Could not read Concert fixture {self.fixture_path}: {exc}") from exc

        if app_names:
            apps = [a for a in data.get("applications", []) if a.get("name") in app_names]
            return {"applications": apps}
        return data
