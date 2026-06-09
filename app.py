#!/usr/bin/env python3
"""
Stats — Traefik access log parser & dashboard
Parses JSON access logs and serves a real-time traffic dashboard.
"""

import json
import os
import asyncio
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Stats", version="0.2.0")

VPS_IPS = {"51.210.179.59", "127.0.0.1", "::1"}

LOG_DIR = Path("/logs")
REFRESH_INTERVAL = 30

_stats_cache: dict = {}
_stats_ts: float = 0


def _parse_time(iso_str: str):
    if not iso_str:
        return None
    try:
        clean = iso_str.rstrip("Z")
        if "." in clean:
            clean = clean.split(".")[0]
        return datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")
    except (ValueError, IndexError):
        return None


def _ua_os(ua: str) -> str:
    if "Windows" in ua:
        return "Windows"
    if "Linux" in ua and "Android" not in ua:
        return "Linux"
    if "Mac" in ua:
        return "macOS"
    if "Android" in ua:
        return "Android"
    if "iOS" in ua or "iPhone" in ua:
        return "iOS"
    return "Non détecté"


def _new_domain_stats():
    """Return fresh per-domain stats dict."""
    return {
        "general": {
            "total_requests": 0, "valid_requests": 0, "failed_requests": 0,
            "unique_visitors": 0, "unique_files": 0,
        },
        "hosts": defaultdict(lambda: {"hits": 0, "visitors": set()}),
        "pages": defaultdict(lambda: {"hits": 0, "methods": set()}),
        "statuses": defaultdict(int),
        "browsers": defaultdict(lambda: {"hits": 0, "visitors": set()}),
        "os": defaultdict(lambda: {"hits": 0, "visitors": set()}),
        "not_found": defaultdict(int),
        "visitors_by_date": defaultdict(lambda: {"visitors": set(), "hits": 0}),
        "all_visitors": set(),
        "lines": 0,
    }


def _empty_api() -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    empty = {
        "general": {
            "start_date": "", "end_date": "", "date_time": now,
            "total_requests": 0, "valid_requests": 0, "failed_requests": 0,
            "unique_visitors": 0, "unique_files": 0,
        },
        "visitors": [], "requests": [], "hosts": [],
        "browsers": [], "os": [], "status_codes": [], "not_found": [],
        "domains": [], "by_domain": {},
    }
    return empty


def _to_flat(obj):
    return [
        {"hits": {"count": v["hits"]},
         "visitors": {"count": len(v["visitors"])},
         "data": k}
        for k, v in sorted(obj.items(), key=lambda x: -x[1]["hits"])
    ]


def _to_flat_pages(pages):
    return [
        {
            "hits": {"count": v["hits"]},
            "visitors": {"count": 0},
            "data": k,
            "method": list(v["methods"])[0] if v["methods"] else "GET",
        }
        for k, v in sorted(pages.items(), key=lambda x: -x[1]["hits"])
    ]


def _status_group(s: int) -> str:
    return f"{s // 100}xx"


def _build_section(d: dict) -> dict:
    """Convert internal domain stats to API format."""
    status_groups = defaultdict(int)
    for code, count in d["statuses"].items():
        status_groups[_status_group(code)] += count

    return {
        "general": {
            "start_date": min(d["visitors_by_date"].keys()) if d["visitors_by_date"] else "",
            "end_date": max(d["visitors_by_date"].keys()) if d["visitors_by_date"] else "",
            "total_requests": d["lines"],
            "valid_requests": d["lines"],
            "failed_requests": sum(1 for s in d["statuses"] if int(s) >= 500),
            "unique_visitors": len(d["all_visitors"]),
            "unique_files": len(d["pages"]),
        },
        "visitors": [
            {"hits": {"count": v["hits"]},
             "visitors": {"count": len(v["visitors"])},
             "bytes": {"count": 0},
             "data": k}
            for k, v in sorted(d["visitors_by_date"].items())
        ],
        "requests": _to_flat_pages(d["pages"]),
        "hosts": _to_flat(d["hosts"]),
        "browsers": _to_flat(d["browsers"]),
        "os": _to_flat(d["os"]),
        "status_codes": [
            {"hits": {"count": v}, "visitors": {"count": 0},
             "bytes": {"count": 0}, "data": k}
            for k, v in sorted(status_groups.items())
        ],
        "not_found": [
            {"hits": {"count": v}, "visitors": {"count": 0},
             "bytes": {"count": 0}, "data": k}
            for k, v in sorted(d["not_found"].items(), key=lambda x: -x[1])
        ],
    }


def _parse_logs() -> dict:
    """Parse all JSON log files and return stats with per-domain breakdown."""
    if not LOG_DIR.is_dir():
        return _empty_api()

    log_files = sorted(LOG_DIR.glob("*.log"), key=os.path.getmtime, reverse=True)
    if not log_files:
        return _empty_api()

    # Aggregate + per-domain
    agg = _new_domain_stats()
    per_domain = defaultdict(_new_domain_stats)

    for log_file in log_files:
        try:
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    client = e.get("ClientHost", "?")
                    host = e.get("RequestHost", "-")
                    if host in VPS_IPS:
                        continue
                    path = e.get("RequestPath", "/")
                    method = e.get("RequestMethod", "GET")
                    status = e.get("OriginStatus", 0) or e.get("DownstreamStatus", 0)
                    ua = e.get("RequestUserAgent", "-")
                    dt = _parse_time(e.get("StartLocal") or e.get("time", ""))

                    # Track in both aggregate and per-domain
                    for bucket in (agg, per_domain[host]):
                        bucket["lines"] += 1
                        bucket["hosts"][host]["hits"] += 1
                        bucket["hosts"][host]["visitors"].add(client)
                        bucket["pages"][host + path]["hits"] += 1
                        bucket["pages"][host + path]["methods"].add(method)
                        bucket["statuses"][status] += 1

                        bn = (ua.split("/")[0] if ua and ua != "-"
                              else "Non détecté")
                        bucket["browsers"][bn]["hits"] += 1
                        bucket["browsers"][bn]["visitors"].add(client)

                        osn = _ua_os(ua)
                        bucket["os"][osn]["hits"] += 1
                        bucket["os"][osn]["visitors"].add(client)

                        if status == 404:
                            bucket["not_found"][host + path] += 1

                        bucket["all_visitors"].add(client)
                        if dt:
                            date_str = dt.strftime("%Y-%m-%d")
                            bucket["visitors_by_date"][date_str]["visitors"].add(client)
                            bucket["visitors_by_date"][date_str]["hits"] += 1

        except (IOError, OSError):
            continue

    # Build output
    result = _build_section(agg)
    result["domains"] = sorted(per_domain.keys())
    result["by_domain"] = {
        d: _build_section(s) for d, s in sorted(per_domain.items())
    }
    return result


async def _refresh_stats():
    global _stats_cache, _stats_ts
    while True:
        _stats_cache = _parse_logs()
        _stats_ts = datetime.now(timezone.utc).timestamp()
        await asyncio.sleep(REFRESH_INTERVAL)


@app.on_event("startup")
async def startup():
    _stats_cache.update(_parse_logs())
    asyncio.create_task(_refresh_stats())


@app.get("/api/stats")
async def get_stats():
    return _stats_cache


@app.get("/api/system")
async def get_system():
    sys_path = Path("/system.json")
    if sys_path.exists():
        try:
            return json.loads(sys_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"error": "system.json not available"}


@app.get("/")
async def get_index():
    html_path = Path(__file__).parent / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>Stats dashboard</h1><p>index.html not found</p>",
                        status_code=404)
