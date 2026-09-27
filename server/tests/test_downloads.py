# Tests for Drishti Endpoint Agent Download Center (2 Mac & 1 Linux apps)
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_list_available_downloads(client):
    """Verify catalog lists all 2 Mac variants and Linux variant with valid checksums and sizes."""
    response = client.get("/api/downloads")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["total_packages"] >= 5

    # Check platforms grouping
    platforms = data["platforms"]
    assert "macos" in platforms
    assert "linux" in platforms

    macos_pkgs = {p["id"]: p for p in platforms["macos"]}
    assert "macos-silicon" in macos_pkgs
    assert "macos-silicon-app" in macos_pkgs
    assert "macos-intel" in macos_pkgs
    assert "macos-intel-app" in macos_pkgs

    linux_pkgs = {p["id"]: p for p in platforms["linux"]}
    assert "linux-x86_64" in linux_pkgs
    assert "linux-deb" in linux_pkgs

    # Verify all are built and available
    for pkg in data["downloads"]:
        assert pkg["available"] is True, f"Package {pkg['file']} should be available"
        assert pkg["size_bytes"] > 0
        assert pkg["sha256"] is not None and len(pkg["sha256"]) == 64


def test_download_macos_silicon_pkg(client):
    """Verify downloading macOS Apple Silicon (.pkg) returns correct binary attachment."""
    response = client.get("/api/downloads/macos-silicon")
    assert response.status_code == 200
    assert "Drishti-Endpoint-Agent-macOS-Silicon.pkg" in response.headers.get("Content-Disposition", "")
    assert len(response.content) > 10000


def test_download_macos_silicon_app_zip(client):
    """Verify downloading macOS Apple Silicon standalone app zip."""
    response = client.get("/api/downloads/macos-silicon-app")
    assert response.status_code == 200
    assert "Drishti-Endpoint-Agent-macOS-Silicon.app.zip" in response.headers.get("Content-Disposition", "")
    assert len(response.content) > 10000


def test_download_macos_intel_pkg(client):
    """Verify downloading macOS Intel (.pkg) returns correct binary attachment."""
    response = client.get("/api/downloads/macos-intel")
    assert response.status_code == 200
    assert "Drishti-Endpoint-Agent-macOS-Intel.pkg" in response.headers.get("Content-Disposition", "")
    assert len(response.content) > 10000


def test_download_macos_intel_app_zip(client):
    """Verify downloading macOS Intel standalone app zip."""
    response = client.get("/api/downloads/macos-intel-app")
    assert response.status_code == 200
    assert "Drishti-Endpoint-Agent-macOS-Intel.app.zip" in response.headers.get("Content-Disposition", "")
    assert len(response.content) > 10000


def test_download_linux_tarball(client):
    """Verify downloading Linux x86_64 standalone tarball bundle."""
    response = client.get("/api/downloads/linux")
    assert response.status_code == 200
    assert "Drishti-Endpoint-Agent-Linux-x86_64.tar.gz" in response.headers.get("Content-Disposition", "")
    assert len(response.content) > 10000


def test_download_linux_deb(client):
    """Verify downloading Debian/Ubuntu .deb package."""
    response = client.get("/api/downloads/linux-deb")
    assert response.status_code == 200
    assert "drishti-endpoint-agent_0.1.0_amd64.deb" in response.headers.get("Content-Disposition", "")
    assert len(response.content) > 10000


def test_download_html_landing_page(client):
    """Verify downloads interactive landing page renders cleanly."""
    response = client.get("/downloads-ui")
    assert response.status_code == 200
    assert "text/html" in response.headers["Content-Type"]
    assert "Apple Silicon" in response.text
    assert "Intel Mac" in response.text
    assert "Linux" in response.text


def test_download_not_found(client):
    """Verify requesting non-existent package returns 404."""
    response = client.get("/api/downloads/nonexistent-os-bundle")
    assert response.status_code == 404
