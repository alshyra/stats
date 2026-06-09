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

from fastapi import FastAPI, responses
from fastapi.responses import HTMLResponse

app = FastAPI(title="Stats", version="0.1.0")

LOG_DIR = Path("/logs")
REFRESH_INTERVAL = 30  # seconds

# In-memory cached stats
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


def _empty_stats() -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        "general": {
            "start_date": "", "end_date": "", "date_time": now,
            "total_requests": 0, "valid_requests": 0, "failed_requests": 0,
            "unique_visitors": 0, "unique_files": 0,
        },
        "visitors": {"metadata": {}, "data": []},
        "requests": {"metadata": {}, "data": []},
        "hosts": {"metadata": {}, "data": []},
        "browsers": {"metadata": {}, "data": []},
        "os": {"metadata": {}, "data": []},
        "status_codes": {"metadata": {}, "data": []},
        "not_found": {"metadata": {}, "data": []},
    }


def _parse_logs() -> dict:
    """Parse all JSON log files in LOG_DIR and return stats dict."""
    if not LOG_DIR.is_dir():
        return _empty_stats()

    log_files = sorted(LOG_DIR.glob("*.log"), key=os.path.getmtime, reverse=True)
    if not log_files:
        return _empty_stats()

    hosts: dict = defaultdict(lambda: {"hits": 0, "visitors": set()})
    pages: dict = defaultdict(lambda: {"hits": 0, "methods": set()})
    statuses: dict = defaultdict(int)
    browsers: dict = defaultdict(lambda: {"hits": 0, "visitors": set()})
    os_list: dict = defaultdict(lambda: {"hits": 0, "visitors": set()})
    not_found: dict = defaultdict(int)
    visitors_by_date: dict = defaultdict(lambda: {"visitors": set(), "hits": 0})
    all_visitors: set = set()
    total_lines = 0

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

                    total_lines += 1
                    client = e.get("ClientHost", "?")
                    host = e.get("RequestHost", "-")
                    path = e.get("RequestPath", "/")
                    method = e.get("RequestMethod", "GET")
                    status = e.get("OriginStatus", 0) or e.get("DownstreamStatus", 0)
                    ua = e.get("RequestUserAgent", "-")
                    dt = _parse_time(e.get("StartLocal") or e.get("time", ""))

                    hosts[host]["hits"] += 1
                    hosts[host]["visitors"].add(client)
                    pages[path]["hits"] += 1
                    pages[path]["methods"].add(method)
                    statuses[status] += 1

                    browser_name = (ua.split("/")[0] if ua and ua != "-"
                                    else "Non détecté")
                    browsers[browser_name]["hits"] += 1
                    browsers[browser_name]["visitors"].add(client)

                    os_name = _ua_os(ua)
                    os_list[os_name]["hits"] += 1
                    os_list[os_name]["visitors"].add(client)

                    if status == 404:
                        not_found[path] += 1

                    all_visitors.add(client)
                    if dt:
                        date_str = dt.strftime("%Y-%m-%d")
                        visitors_by_date[date_str]["visitors"].add(client)
                        visitors_by_date[date_str]["hits"] += 1
        except (IOError, OSError):
            continue

    def to_flat(obj):
        return [
            {"hits": {"count": v["hits"]},
             "visitors": {"count": len(v["visitors"])},
             "data": k}
            for k, v in sorted(obj.items(), key=lambda x: -x[1]["hits"])
        ]

    def to_flat_pages():
        return [
            {
                "hits": {"count": v["hits"]},
                "visitors": {"count": 0},
                "data": k,
                "method": list(v["methods"])[0] if v["methods"] else "GET",
            }
            for k, v in sorted(pages.items(), key=lambda x: -x[1]["hits"])
        ]

    def status_group(s: int) -> str:
        return f"{s // 100}xx"

    status_groups: dict = defaultdict(int)
    for code, count in statuses.items():
        status_groups[status_group(code)] += count

    return {
        "general": {
            "start_date": min(visitors_by_date.keys()) if visitors_by_date else "",
            "end_date": max(visitors_by_date.keys()) if visitors_by_date else "",
            "date_time": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"),
            "total_requests": total_lines,
            "valid_requests": total_lines,
            "failed_requests": sum(1 for s in statuses if int(s) >= 500),
            "unique_visitors": len(all_visitors),
            "unique_files": len(pages),
        },
        "visitors": {
            "metadata": {},
            "data": [
                {"hits": {"count": v["hits"]},
                 "visitors": {"count": len(v["visitors"])},
                 "bytes": {"count": 0},
                 "data": k}
                for k, v in sorted(visitors_by_date.items())
            ],
        },
        "requests": {"metadata": {}, "data": to_flat_pages()},
        "hosts": {"metadata": {}, "data": to_flat(hosts)},
        "browsers": {"metadata": {}, "data": to_flat(browsers)},
        "os": {"metadata": {}, "data": to_flat(os_list)},
        "status_codes": {
            "metadata": {},
            "data": [
                {"hits": {"count": v}, "visitors": {"count": 0},
                 "bytes": {"count": 0}, "data": k}
                for k, v in sorted(status_groups.items())
            ],
        },
        "not_found": {
            "metadata": {},
            "data": [
                {"hits": {"count": v}, "visitors": {"count": 0},
                 "bytes": {"count": 0}, "data": k}
                for k, v in sorted(not_found.items(),
                                   key=lambda x: -x[1])
            ],
        },
    }


async def _refresh_stats():
    """Periodically refresh the cached stats."""
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


@app.get("/")
async def get_index():
    html_path = Path(__file__).parent / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>Stats dashboard</h1><p>index.html not found</p>",
                        status_code=404)
