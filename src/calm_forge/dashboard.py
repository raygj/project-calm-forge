"""Drift dashboard — real-time fabric state as JSON feed and minimal HTML view.

Two endpoints:
  GET /api/fabric   — JSON snapshot: all Workloads, Placements, drift state,
                      capability grants, policy alerts, per-namespace breakdown
  GET /             — minimal HTML table: fabric summary, drift status, policy flags

File-system watcher (--watch): re-generates the feed when KG files change.
The feed is also written to <kg_dir>/fabric-state.json on each refresh.

EDA integration: the feed is regenerated whenever a drift event lands in
drift-events.json (same file-watcher trigger).
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Feed generation
# ---------------------------------------------------------------------------

def build_fabric_feed(kg_dir: Path, namespace: str | None = None) -> dict[str, Any]:
    """Build a JSON fabric state snapshot from a live KG directory.

    namespace=None  — root namespace only
    namespace="*"   — all namespaces (aggregated)
    namespace=<name> — specific namespace
    """
    from .kg_inspect import kg_status

    status = kg_status(kg_dir, namespace=namespace)
    workloads = _collect_workloads(kg_dir, namespace)
    environments = _collect_environments(kg_dir, namespace)
    policies = _collect_policies(kg_dir, namespace)
    deployments = _collect_deployments(kg_dir, namespace)

    dep_summary = status.get("deployments", {})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kg_dir": str(kg_dir),
        "namespace": namespace or "",
        "summary": {
            "environments": status["environments"]["count"],
            "workloads": status["workloads"]["count"],
            "placements": status["placements"]["count"],
            "policies": status.get("policies", {}).get("count", 0),
            "blocking_policies": status.get("policies", {}).get("blocking", 0),
            "deployments_pending": dep_summary.get("pending", 0),
            "deployments_completed": dep_summary.get("completed", 0),
            "deployments_drift_violations": dep_summary.get("drift_violations", 0),
            "overall_status": status["overall_status"],
            "last_evaluated": status["placements"].get("last_evaluated"),
        },
        "workloads": workloads,
        "environments": environments,
        "policies": policies,
        "deployments": deployments,
    }


def _collect_workloads(kg_dir: Path, namespace: str | None) -> list[dict[str, Any]]:
    from .kg_namespace import list_namespaces, resolve_kg_dir
    from .kg_query import kg_query

    results = []
    if namespace == "*":
        dirs = [(n, d) for n, d in list_namespaces(kg_dir)]
    else:
        effective = resolve_kg_dir(kg_dir, namespace)
        dirs = [(namespace or "", effective)]

    for ns_name, ns_dir in dirs:
        wl_entries = kg_query(ns_dir, "Workload", [], follow="manifests_as")
        for entry in wl_entries:
            node = entry["node"]
            placements = []
            for rel in entry.get("related", []):
                if rel["direction"] == "to":
                    pnode = rel["node"]
                    placements.append({
                        "id": pnode.get("@id"),
                        "environment_id": pnode.get("environment_id"),
                        "region": pnode.get("region"),
                        "drift_status": pnode.get("drift_state", {}).get("status", "unknown"),
                        "capabilities_granted": rel["edge_data"].get("capabilities_granted", []),
                        "manifested_at": rel["edge_data"].get("manifested_at"),
                    })
            drift_statuses = [p["drift_status"] for p in placements]
            results.append({
                "id": node.get("@id"),
                "name": node.get("name", ""),
                "namespace": ns_name,
                "owner": node.get("owner", ""),
                "declared_capabilities": node.get("declared_capabilities", []),
                "compliance_scope": node.get("compliance_scope", []),
                "provenance": node.get("_provenance", {}).get("provenance", ""),
                "review_required": node.get("review_required", False),
                "drift_status": _aggregate_drift(drift_statuses),
                "placements": placements,
            })
    return results


def _collect_environments(kg_dir: Path, namespace: str | None) -> list[dict[str, Any]]:
    from .kg_namespace import list_namespaces, resolve_kg_dir
    from .kg_query import kg_query

    results = []
    if namespace == "*":
        dirs = [(n, d) for n, d in list_namespaces(kg_dir)]
    else:
        effective = resolve_kg_dir(kg_dir, namespace)
        dirs = [(namespace or "", effective)]

    for ns_name, ns_dir in dirs:
        for entry in kg_query(ns_dir, "ExecutionEnvironment", []):
            node = entry["node"]
            results.append({
                "id": node.get("@id"),
                "namespace": ns_name,
                "region": node.get("region"),
                "status": node.get("status"),
                "advertised_capabilities": node.get("advertised_capabilities", []),
                "labels": node.get("labels", {}),
            })
    return results


def _collect_policies(kg_dir: Path, namespace: str | None) -> list[dict[str, Any]]:
    from .intake import load_placement_policies
    from .kg_namespace import list_namespaces, resolve_kg_dir

    results = []
    if namespace == "*":
        dirs = [(n, d) for n, d in list_namespaces(kg_dir)]
    else:
        effective = resolve_kg_dir(kg_dir, namespace)
        dirs = [(namespace or "", effective)]

    for ns_name, ns_dir in dirs:
        for p in load_placement_policies(ns_dir):
            results.append({
                "id": p.get("@id"),
                "namespace": ns_name,
                "workload_id": p.get("workload_id"),
                "source": p.get("source"),
                "risk_score": p.get("risk_score"),
                "risk_level": p.get("risk_level"),
                "blocked_environments": p.get("blocked_environments", []),
                "generated_at": p.get("generated_at"),
            })
    return results


def _collect_deployments(kg_dir: Path, namespace: str | None) -> list[dict[str, Any]]:
    from .intake import load_deployment_requests, load_deployment_statuses
    from .kg_namespace import list_namespaces, resolve_kg_dir

    results = []
    if namespace == "*":
        dirs = [(n, d) for n, d in list_namespaces(kg_dir)]
    else:
        effective = resolve_kg_dir(kg_dir, namespace)
        dirs = [(namespace or "", effective)]

    for ns_name, ns_dir in dirs:
        for req in load_deployment_requests(ns_dir):
            status_nodes = load_deployment_statuses(ns_dir, deployment_request_id=req["@id"])
            latest_status = status_nodes[-1] if status_nodes else None
            results.append({
                "id": req["@id"],
                "namespace": ns_name,
                "workload_id": req.get("workload_id"),
                "requested_at": req.get("requested_at"),
                "status": req.get("status"),
                "observed_outcome": latest_status.get("outcome") if latest_status else None,
                "drift_result": latest_status.get("drift_result") if latest_status else None,
            })
    return results


def _aggregate_drift(statuses: list[str]) -> str:
    if not statuses:
        return "no_placements"
    if "violation" in statuses:
        return "violation"
    if all(s == "ok" for s in statuses):
        return "ok"
    return "mixed"


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def render_html(feed: dict[str, Any]) -> str:
    summary = feed["summary"]
    overall = summary["overall_status"]
    status_color = "#22c55e" if overall == "CLEAN" else ("#ef4444" if overall == "VIOLATION" else "#f59e0b")

    rows = ""
    for wl in feed.get("workloads", []):
        drift = wl["drift_status"]
        drift_color = "#22c55e" if drift == "ok" else ("#ef4444" if drift == "violation" else "#f59e0b")
        review = " ⚠" if wl.get("review_required") else ""
        ns = f" <small>[{wl['namespace']}]</small>" if wl.get("namespace") else ""
        placements_html = ", ".join(
            f"<span title='{p.get('environment_id', '')}'>{p.get('region', '?')}</span>"
            for p in wl.get("placements", [])
        ) or "—"
        rows += f"""
        <tr>
          <td>{wl.get('name', wl.get('id', '?'))}{ns}{review}</td>
          <td style="color:{drift_color}">{drift}</td>
          <td>{', '.join(wl.get('declared_capabilities', []))}</td>
          <td>{placements_html}</td>
          <td>{', '.join(wl.get('compliance_scope', []))}</td>
        </tr>"""

    policy_rows = ""
    for pol in feed.get("policies", []):
        if pol.get("blocked_environments"):
            policy_rows += f"""
        <tr style="color:#ef4444">
          <td>{pol.get('workload_id', '?')}</td>
          <td>{pol.get('source', '?')}</td>
          <td>{pol.get('risk_score', 0):.2f} ({pol.get('risk_level', '?')})</td>
          <td>{', '.join(pol.get('blocked_environments', []))}</td>
        </tr>"""

    generated = feed.get("generated_at", "")[:19].replace("T", " ")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="30">
  <title>CALM Forge — Fabric Drift Dashboard</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background:#0f172a; color:#e2e8f0; margin:0; padding:1.5rem; }}
    h1 {{ font-size:1.2rem; color:#94a3b8; font-weight:400; margin:0 0 1rem; }}
    .badge {{ display:inline-block; padding:.25rem .75rem; border-radius:9999px;
              font-size:.85rem; font-weight:600; background:{status_color}22; color:{status_color}; }}
    .summary {{ display:flex; gap:2rem; margin-bottom:1.5rem; flex-wrap:wrap; }}
    .stat {{ background:#1e293b; border-radius:.5rem; padding:.75rem 1.25rem; }}
    .stat-val {{ font-size:1.5rem; font-weight:700; }}
    .stat-lbl {{ font-size:.75rem; color:#64748b; text-transform:uppercase; letter-spacing:.05em; }}
    table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:.5rem; overflow:hidden; }}
    th {{ text-align:left; padding:.6rem 1rem; background:#0f172a; font-size:.75rem;
          text-transform:uppercase; letter-spacing:.05em; color:#64748b; }}
    td {{ padding:.6rem 1rem; border-top:1px solid #0f172a; font-size:.875rem; }}
    tr:hover td {{ background:#263143; }}
    h2 {{ font-size:.9rem; color:#64748b; text-transform:uppercase; letter-spacing:.05em;
          margin:1.5rem 0 .5rem; }}
    .footer {{ color:#475569; font-size:.75rem; margin-top:1.5rem; }}
  </style>
</head>
<body>
  <h1>CALM Forge — Fabric Drift Dashboard</h1>
  <div>
    <span class="badge">{overall}</span>
    &nbsp;
    <span style="color:#475569;font-size:.85rem">
      {summary['workloads']} workload(s) · {summary['placements']} placement(s) ·
      {summary['environments']} environment(s)
      {f'· <span style="color:#f59e0b">{summary["blocking_policies"]} policy alert(s)</span>'
       if summary.get('blocking_policies') else ''}
    </span>
  </div>

  <h2>Workloads</h2>
  <table>
    <thead>
      <tr>
        <th>Workload</th>
        <th>Drift</th>
        <th>Capabilities declared</th>
        <th>Placements</th>
        <th>Compliance</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  {'<h2>Policy Alerts</h2><table><thead><tr><th>Workload</th><th>Source</th><th>Risk</th><th>Blocked Environments</th></tr></thead><tbody>' + policy_rows + '</tbody></table>' if policy_rows else ''}

  <div class="footer">Generated {generated} UTC · auto-refreshes every 30s</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class _DashboardHandler(BaseHTTPRequestHandler):
    """Simple single-threaded handler for the dashboard server."""

    kg_dir: Path = Path(".")
    namespace: str | None = None
    federated: bool = False
    _feed_cache: dict[str, Any] = {}
    _cache_lock = threading.Lock()

    def do_GET(self):
        feed = self.__class__._get_feed()
        if self.path == "/api/fabric" or self.path.startswith("/api/fabric?"):
            body = json.dumps(feed, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/curvature/"):
            workload_id = self.path[len("/api/curvature/"):]
            from .drift_evaluator import curvature_trend
            trend = curvature_trend(workload_id, self.__class__.kg_dir)
            body = json.dumps(trend, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/" or self.path == "/index.html":
            body = render_html(feed).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):  # suppress default access log
        pass

    @classmethod
    def _get_feed(cls) -> dict[str, Any]:
        with cls._cache_lock:
            return cls._feed_cache.copy()

    @classmethod
    def refresh(cls) -> None:
        if cls.federated:
            from .kg_multi_root import load_multi_root_config, multi_root_fabric_feed
            cfg = load_multi_root_config(cls.kg_dir)
            if cfg is not None:
                feed = multi_root_fabric_feed(cfg.roots)
            else:
                feed = build_fabric_feed(cls.kg_dir, cls.namespace)
        else:
            feed = build_fabric_feed(cls.kg_dir, cls.namespace)
        with cls._cache_lock:
            cls._feed_cache = feed
        feed_path = cls.kg_dir / "fabric-state.json"
        try:
            feed_path.write_text(json.dumps(feed, indent=2))
        except OSError:
            pass


def serve_dashboard(
    kg_dir: Path,
    port: int = 8080,
    host: str = "127.0.0.1",
    namespace: str | None = None,
    watch: bool = False,
    reconcile: bool = False,
    federated: bool = False,
) -> None:
    """Start the dashboard HTTP server (blocking).

    GET /api/fabric  → JSON feed
    GET /            → HTML view

    reconcile=True: when fabric-state.json changes with drift violations,
    automatically run reconcile(kg_dir, dry_run=False) in a background thread.
    federated=True: use federated_fabric_feed when federation.json exists.
    """
    _DashboardHandler.kg_dir = kg_dir
    _DashboardHandler.namespace = namespace
    _DashboardHandler.federated = federated
    _DashboardHandler.refresh()

    def _on_change():
        _DashboardHandler.refresh()
        if reconcile:
            _reconcile_on_change(kg_dir)

    if watch:
        _start_watcher(kg_dir, _on_change)

    server = HTTPServer((host, port), _DashboardHandler)
    server.serve_forever()


def _reconcile_on_change(kg_dir: Path) -> None:
    """Run reconcile in a background thread when drift violations are detected."""
    feed = _DashboardHandler._get_feed()
    has_violations = any(
        wl.get("drift_status") == "violation"
        for wl in feed.get("workloads", [])
    )
    if not has_violations:
        return

    def _run():
        from .reconciler import reconcile as run_reconcile
        run_reconcile(kg_dir, dry_run=False)

    t = threading.Thread(target=_run, daemon=True)
    t.start()


def _start_watcher(kg_dir: Path, callback) -> None:
    """Poll the KG dir for mtime changes and call callback on change."""
    def _watch():
        last_mtimes: dict[str, float] = {}
        while True:
            changed = False
            for subdir in ("environments", "placements", "workloads", "policies", "deployments"):
                d = kg_dir / subdir
                if not d.exists():
                    continue
                for f in d.glob("*.json"):
                    mtime = f.stat().st_mtime
                    key = str(f)
                    if last_mtimes.get(key) != mtime:
                        last_mtimes[key] = mtime
                        changed = True
            events_file = kg_dir / "drift-events.json"
            if events_file.exists():
                mtime = events_file.stat().st_mtime
                if last_mtimes.get(str(events_file)) != mtime:
                    last_mtimes[str(events_file)] = mtime
                    changed = True
            if changed:
                callback()
            time.sleep(2)

    t = threading.Thread(target=_watch, daemon=True)
    t.start()
