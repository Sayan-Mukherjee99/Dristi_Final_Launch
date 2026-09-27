# Drishti v0.1 — Endpoint Agent Download Center
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter()

# Locate dist directory
CURRENT_FILE = Path(__file__).resolve()
WORKSPACE_ROOT = CURRENT_FILE.parents[3]  # server/app/api -> server/app -> server -> root
DIST_DIRS = [
    WORKSPACE_ROOT / "dist",
    WORKSPACE_ROOT / "endpoint-agent" / "dist",
]

PLATFORM_ALIASES = {
    # 2 Mac variants
    "macos-silicon": "Drishti-Endpoint-Agent-macOS-Silicon.pkg",
    "mac-silicon": "Drishti-Endpoint-Agent-macOS-Silicon.pkg",
    "mac-arm64": "Drishti-Endpoint-Agent-macOS-Silicon.pkg",
    "macos-silicon-app": "Drishti-Endpoint-Agent-macOS-Silicon.app.zip",
    "macos-intel": "Drishti-Endpoint-Agent-macOS-Intel.pkg",
    "mac-intel": "Drishti-Endpoint-Agent-macOS-Intel.pkg",
    "mac-x86_64": "Drishti-Endpoint-Agent-macOS-Intel.pkg",
    "macos-intel-app": "Drishti-Endpoint-Agent-macOS-Intel.app.zip",
    # 1 Linux variant
    "linux": "Drishti-Endpoint-Agent-Linux-x86_64.tar.gz",
    "linux-x86_64": "Drishti-Endpoint-Agent-Linux-x86_64.tar.gz",
    "linux-tar": "Drishti-Endpoint-Agent-Linux-x86_64.tar.gz",
    "linux-deb": "drishti-endpoint-agent_0.1.0_amd64.deb",
    "linux-amd64": "drishti-endpoint-agent_0.1.0_amd64.deb",
    "linux-arm64": "Drishti-Endpoint-Agent-Linux-arm64.tar.gz",
    "linux-arm64-deb": "drishti-endpoint-agent_0.1.0_arm64.deb",
}

MEDIA_TYPES = {
    ".pkg": "application/octet-stream",
    ".zip": "application/zip",
    ".gz": "application/gzip",
    ".deb": "application/vnd.debian.binary-package",
}


def _find_dist_file(filename: str) -> Path | None:
    for base in DIST_DIRS:
        cand = base / filename
        if cand.exists() and cand.is_file():
            return cand
    return None


def _calc_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@router.get("/downloads", response_model=None)
def list_available_downloads() -> dict[str, Any]:
    """Returns downloadable endpoint agent application packages for macOS (Silicon & Intel) and Linux."""
    downloads = []

    catalog_spec = [
        {
            "id": "macos-silicon",
            "name": "Drishti Endpoint Agent for macOS (Apple Silicon)",
            "os": "macOS",
            "arch": "Apple Silicon (M1/M2/M3/M4, arm64)",
            "file": "Drishti-Endpoint-Agent-macOS-Silicon.pkg",
            "format": ".pkg Installer",
            "download_url": "/api/downloads/macos-silicon",
            "install_cmd": "sudo installer -pkg Drishti-Endpoint-Agent-macOS-Silicon.pkg -target /",
        },
        {
            "id": "macos-silicon-app",
            "name": "Drishti Endpoint Agent App for macOS (Apple Silicon)",
            "os": "macOS",
            "arch": "Apple Silicon (M1/M2/M3/M4, arm64)",
            "file": "Drishti-Endpoint-Agent-macOS-Silicon.app.zip",
            "format": ".app (Standalone Zip)",
            "download_url": "/api/downloads/macos-silicon-app",
            "install_cmd": "unzip Drishti-Endpoint-Agent-macOS-Silicon.app.zip && open Drishti-Endpoint-Agent-macOS-Silicon.app",
        },
        {
            "id": "macos-intel",
            "name": "Drishti Endpoint Agent for macOS (Intel)",
            "os": "macOS",
            "arch": "Intel x86_64",
            "file": "Drishti-Endpoint-Agent-macOS-Intel.pkg",
            "format": ".pkg Installer",
            "download_url": "/api/downloads/macos-intel",
            "install_cmd": "sudo installer -pkg Drishti-Endpoint-Agent-macOS-Intel.pkg -target /",
        },
        {
            "id": "macos-intel-app",
            "name": "Drishti Endpoint Agent App for macOS (Intel)",
            "os": "macOS",
            "arch": "Intel x86_64",
            "file": "Drishti-Endpoint-Agent-macOS-Intel.app.zip",
            "format": ".app (Standalone Zip)",
            "download_url": "/api/downloads/macos-intel-app",
            "install_cmd": "unzip Drishti-Endpoint-Agent-macOS-Intel.app.zip && open Drishti-Endpoint-Agent-macOS-Intel.app",
        },
        {
            "id": "linux-x86_64",
            "name": "Drishti Endpoint Agent for Linux (x86_64)",
            "os": "Linux",
            "arch": "x86_64 / amd64",
            "file": "Drishti-Endpoint-Agent-Linux-x86_64.tar.gz",
            "format": ".tar.gz (Self-contained Bundle)",
            "download_url": "/api/downloads/linux",
            "install_cmd": "tar -xzf Drishti-Endpoint-Agent-Linux-x86_64.tar.gz && cd drishti-agent && sudo ./install.sh",
        },
        {
            "id": "linux-deb",
            "name": "Drishti Endpoint Agent for Debian / Ubuntu",
            "os": "Linux",
            "arch": "x86_64 / amd64",
            "file": "drishti-endpoint-agent_0.1.0_amd64.deb",
            "format": ".deb Package",
            "download_url": "/api/downloads/linux-deb",
            "install_cmd": "sudo dpkg -i drishti-endpoint-agent_0.1.0_amd64.deb",
        },
    ]

    for item in catalog_spec:
        filepath = _find_dist_file(item["file"])
        if filepath and filepath.exists():
            size_bytes = filepath.stat().st_size
            sha = _calc_sha256(filepath)
            downloads.append({
                **item,
                "available": True,
                "size_bytes": size_bytes,
                "size_formatted": f"{size_bytes / 1024:.1f} KB",
                "sha256": sha,
            })
        else:
            downloads.append({
                **item,
                "available": False,
                "size_bytes": 0,
                "size_formatted": "Not built",
                "sha256": None,
            })

    return {
        "status": "success",
        "total_packages": len(downloads),
        "platforms": {
            "macos": [d for d in downloads if d["os"] == "macOS"],
            "linux": [d for d in downloads if d["os"] == "Linux"],
        },
        "downloads": downloads,
    }


@router.get("/downloads/{target}")
def download_package(target: str) -> FileResponse:
    """Download a specific endpoint agent application package for macOS or Linux."""
    # Check if target is alias or exact filename
    filename = PLATFORM_ALIASES.get(target.lower(), target)
    filepath = _find_dist_file(filename)

    if not filepath or not filepath.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Requested package '{target}' is not available. Please verify the build in dist/.",
        )

    ext = filepath.suffix.lower()
    media_type = MEDIA_TYPES.get(ext, "application/octet-stream")

    return FileResponse(
        path=filepath,
        filename=filepath.name,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filepath.name}"',
            "Cache-Control": "no-cache",
        },
    )


@router.get("/downloads-ui", response_class=HTMLResponse)
def downloads_html_page() -> str:
    """Interactive download center landing page."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Drishti — Download Endpoint Agents</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(22, 28, 45, 0.7);
      --border: rgba(255, 255, 255, 0.1);
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.3);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body {
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
    }
    .header { text-align: center; max-width: 700px; margin-bottom: 40px; }
    .header h1 { font-size: 2.2rem; font-weight: 700; color: #fff; margin-bottom: 12px; }
    .header h1 span { color: var(--accent); }
    .header p { color: var(--text-muted); font-size: 1.05rem; line-height: 1.6; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 24px;
      max-width: 1050px;
      width: 100%;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px;
      backdrop-filter: blur(12px);
      display: flex;
      flex-direction: column;
      transition: transform 0.2s, border-color 0.2s;
    }
    .card:hover {
      transform: translateY(-4px);
      border-color: var(--accent);
      box-shadow: 0 12px 30px var(--accent-glow);
    }
    .badge {
      display: inline-block;
      align-self: flex-start;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      margin-bottom: 16px;
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.3);
    }
    .card h2 { font-size: 1.4rem; margin-bottom: 8px; color: #fff; }
    .card p.desc { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 20px; flex-grow: 1; }
    .btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--accent);
      color: #0b1120;
      text-decoration: none;
      padding: 12px 20px;
      border-radius: 10px;
      font-weight: 600;
      font-size: 0.95rem;
      transition: background 0.2s, opacity 0.2s;
      margin-top: 10px;
    }
    .btn:hover { opacity: 0.9; }
    .btn.secondary {
      background: transparent;
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    .btn.secondary:hover {
      background: rgba(56, 189, 248, 0.1);
    }
    .cmd {
      background: #0f172a;
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 10px 12px;
      font-family: monospace;
      font-size: 0.8rem;
      color: #38bdf8;
      margin-top: 14px;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Drishti <span>Endpoint Agent</span> Downloads</h1>
    <p>Install the native paired security telemetry agent on your endpoints to enable continuous packet tracking, AI forecasting, and real-time threat intelligence.</p>
  </div>
  <div class="grid">
    <!-- Mac Silicon -->
    <div class="card">
      <span class="badge">macOS ARM64</span>
      <h2>Apple Silicon</h2>
      <p class="desc">Native build tailored for Apple Silicon (M1, M2, M3, M4) Macs. Includes launchd daemon, socket telemetry, and automated certificate registration.</p>
      <a class="btn" href="/api/downloads/macos-silicon">Download .pkg Installer</a>
      <a class="btn secondary" href="/api/downloads/macos-silicon-app">Download .app (Zip)</a>
      <div class="cmd">sudo installer -pkg Drishti-Endpoint-Agent-macOS-Silicon.pkg -target /</div>
    </div>
    <!-- Mac Intel -->
    <div class="card">
      <span class="badge">macOS x86_64</span>
      <h2>Intel Mac</h2>
      <p class="desc">Optimized binary for Intel-based Macs. Features full hardware, process, and socket telemetry collection with zero kernel extension requirements.</p>
      <a class="btn" href="/api/downloads/macos-intel">Download .pkg Installer</a>
      <a class="btn secondary" href="/api/downloads/macos-intel-app">Download .app (Zip)</a>
      <div class="cmd">sudo installer -pkg Drishti-Endpoint-Agent-macOS-Intel.pkg -target /</div>
    </div>
    <!-- Linux -->
    <div class="card">
      <span class="badge">Linux x86_64</span>
      <h2>Linux</h2>
      <p class="desc">Native distribution package for Ubuntu, Debian, RedHat, and generic Linux x86_64 systems with systemd background service installer.</p>
      <a class="btn" href="/api/downloads/linux">Download .tar.gz Bundle</a>
      <a class="btn secondary" href="/api/downloads/linux-deb">Download Debian .deb</a>
      <div class="cmd">tar -xzf Drishti-Endpoint-Agent-Linux-x86_64.tar.gz && sudo ./install.sh</div>
    </div>
  </div>
</body>
</html>
"""
