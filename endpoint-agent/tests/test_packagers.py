# Drishti — Endpoint Agent Packager Unit Tests (macOS Silicon/Intel & Linux)
from __future__ import annotations

import io
import shutil
import struct
import sys
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from build_macos_pkg import (
    delete_existing_pkg_files,
    generate_macos_app,
    generate_macos_pkg,
    get_architecture_specs,
)
from build_linux_package import (
    build_linux_appdir,
    build_linux_deb,
    build_linux_tarball,
    create_ar_archive,
)


@pytest.fixture
def agent_dir():
    return Path(__file__).resolve().parent.parent


def test_delete_existing_pkg_files():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        sub_dir = temp_dir / "subdir"
        sub_dir.mkdir()
        pkg1 = temp_dir / "old_agent.pkg"
        pkg2 = sub_dir / "legacy_bundle.pkg"
        pkg1.write_bytes(b"dummy pkg content")
        pkg2.write_bytes(b"dummy pkg content")

        assert pkg1.exists()
        assert pkg2.exists()

        deleted = delete_existing_pkg_files([temp_dir])
        assert len(deleted) == 2
        assert not pkg1.exists()
        assert not pkg2.exists()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_architecture_specs():
    silicon = get_architecture_specs("silicon")
    assert silicon["host_arch"] == "arm64"
    assert "Silicon" in silicon["pkg_filename"]
    assert "arm64" in silicon["python_search"] or "homebrew" in silicon["python_search"]

    intel = get_architecture_specs("intel")
    assert intel["host_arch"] == "x86_64"
    assert "Intel" in intel["pkg_filename"]
    assert "/usr/local" in intel["python_search"]

    with pytest.raises(ValueError):
        get_architecture_specs("unknown_arch")


def test_macos_silicon_and_intel_pkg_generation(agent_dir):
    temp_dir = Path(tempfile.mkdtemp())
    try:
        # 1. Silicon Package
        pkg_silicon = temp_dir / "Silicon.pkg"
        generate_macos_pkg(agent_dir, pkg_silicon, arch="silicon")
        assert pkg_silicon.exists()
        assert pkg_silicon.stat().st_size > 1000

        with open(pkg_silicon, "rb") as f:
            hdr = f.read(28)
            magic, hdr_size, ver, toc_c, toc_u, cksum_alg = struct.unpack(">4sHHQQI", hdr)
            assert magic == b"xar!"
            toc_comp = f.read(toc_c)
            toc = zlib.decompress(toc_comp).decode("utf-8")
            assert "PackageInfo" in toc
            assert "Payload" in toc
            assert "Scripts" in toc

        # 2. Intel Package
        pkg_intel = temp_dir / "Intel.pkg"
        generate_macos_pkg(agent_dir, pkg_intel, arch="intel")
        assert pkg_intel.exists()
        assert pkg_intel.stat().st_size > 1000

        with open(pkg_intel, "rb") as f:
            hdr = f.read(28)
            magic, hdr_size, ver, toc_c, toc_u, cksum_alg = struct.unpack(">4sHHQQI", hdr)
            assert magic == b"xar!"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_macos_silicon_and_intel_app_generation(agent_dir):
    temp_dir = Path(tempfile.mkdtemp())
    try:
        app_silicon = temp_dir / "Silicon.app"
        generate_macos_app(agent_dir, app_silicon, arch="silicon")
        assert (app_silicon / "Contents" / "Info.plist").exists()
        assert (app_silicon / "Contents" / "MacOS" / "drishti-agent").exists()
        assert (app_silicon / "Contents" / "Resources" / "agent" / "cli.py").exists()

        info_plist_text = (app_silicon / "Contents" / "Info.plist").read_text(encoding="utf-8")
        assert "arm64" in info_plist_text
        assert "Silicon" in info_plist_text

        zip_silicon = temp_dir / "Silicon.app.zip"
        assert zip_silicon.exists()
        assert zip_silicon.stat().st_size > 1000

        # Intel App
        app_intel = temp_dir / "Intel.app"
        generate_macos_app(agent_dir, app_intel, arch="intel")
        info_plist_intel = (app_intel / "Contents" / "Info.plist").read_text(encoding="utf-8")
        assert "x86_64" in info_plist_intel
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_linux_tarball_generation(agent_dir):
    temp_dir = Path(tempfile.mkdtemp())
    try:
        tar_path = temp_dir / "Drishti-Agent-Linux-x86_64.tar.gz"
        build_linux_tarball(agent_dir, tar_path, arch="x86_64")
        assert tar_path.exists()
        assert tar_path.stat().st_size > 1000

        with tarfile.open(tar_path, "r:gz") as tar:
            names = tar.getnames()
            assert "install.sh" in names
            assert "uninstall.sh" in names
            assert "drishti-agent.service" in names
            assert "drishti-agent/cli.py" in names
            assert "drishti-agent/linux/platform.py" in names
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_linux_deb_generation(agent_dir):
    temp_dir = Path(tempfile.mkdtemp())
    try:
        deb_path = temp_dir / "drishti-agent_0.1.0_amd64.deb"
        build_linux_deb(agent_dir, deb_path, arch="amd64")
        assert deb_path.exists()
        assert deb_path.stat().st_size > 1000

        with open(deb_path, "rb") as f:
            magic = f.read(8)
            assert magic == b"!<arch>\n"
            member1_hdr = f.read(60)
            assert member1_hdr[:16].strip() == b"debian-binary"
            d1 = f.read(4)
            assert d1 == b"2.0\n"
            member2_hdr = f.read(60)
            assert member2_hdr[:16].strip() == b"control.tar.gz"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_linux_appdir_generation(agent_dir):
    temp_dir = Path(tempfile.mkdtemp())
    try:
        appdir_path = temp_dir / "Drishti.AppDir"
        build_linux_appdir(agent_dir, appdir_path)
        assert (appdir_path / "AppRun").exists()
        assert (appdir_path / "drishti-agent.desktop").exists()
        assert (appdir_path / "opt" / "drishti" / "endpoint-agent" / "cli.py").exists()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
