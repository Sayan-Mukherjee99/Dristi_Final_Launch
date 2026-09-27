#!/usr/bin/env python3
"""
Drishti Endpoint Agent - Linux Distributable Package & Application Builder
Generates:
  1. Standalone distributable tarballs with automated installer & systemd service:
     - Drishti-Endpoint-Agent-Linux-x86_64.tar.gz
     - Drishti-Endpoint-Agent-Linux-arm64.tar.gz
  2. Native Debian / Ubuntu (.deb) packages:
     - drishti-endpoint-agent_0.1.0_amd64.deb
     - drishti-endpoint-agent_0.1.0_arm64.deb
  3. Standalone Linux Application Directory (AppDir) for desktop & portable usage:
     - Drishti-Endpoint-Agent-Linux.AppDir
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import stat
import sys
import tarfile
import time
from pathlib import Path


def create_ar_archive(members: list[tuple[str, bytes]], output_file: Path) -> None:
    """
    Creates a standard Unix 'ar' archive containing the given (filename, content_bytes) members.
    Compatible with Debian dpkg / apt packages.
    """
    buf = io.BytesIO()
    # Magic header for ar archive
    buf.write(b"!<arch>\n")

    timestamp = int(time.time())

    for name, content in members:
        # Member name max 16 chars, formatted as 'name/' or 'name' padded
        ident = f"{name:<16}"[:16].encode("ascii")
        mtime = f"{timestamp:<12}"[:12].encode("ascii")
        uid = f"{0:<6}"[:6].encode("ascii")
        gid = f"{0:<6}"[:6].encode("ascii")
        mode = f"{100644:<8}"[:8].encode("ascii")
        size_str = f"{len(content):<10}"[:10].encode("ascii")
        trailer = b"\x60\x0a"

        header = ident + mtime + uid + gid + mode + size_str + trailer
        buf.write(header)
        buf.write(content)
        # 2-byte alignment: pad with newline if size is odd
        if len(content) % 2 != 0:
            buf.write(b"\n")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(buf.getvalue())


# ──────────────────────────────────────────────────────────────
# SYSTEM SCRIPTS AND CONFIG TEMPLATES
# ──────────────────────────────────────────────────────────────

LAUNCHER_SCRIPT = """#!/usr/bin/env bash
# Drishti Endpoint Agent - Linux Launcher
set -e

AGENT_HOME="/opt/drishti/endpoint-agent"
if [ ! -d "$AGENT_HOME" ]; then
    AGENT_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
cd "$AGENT_HOME"

# Load global configuration if present
if [ -f "/etc/drishti/agent.conf" ]; then
    set -a
    . "/etc/drishti/agent.conf"
    set +a
fi

# Detect Python 3 interpreter
PYTHON_BIN=""
for candidate in "$AGENT_HOME/.venv/bin/python" /usr/bin/python3 /usr/local/bin/python3 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[Drishti] ERROR: Python 3 not found on this Linux system." >&2
    echo "[Drishti] Please install python3 (e.g., 'sudo apt install python3 python3-venv' or 'sudo dnf install python3')." >&2
    exit 1
fi

# Setup isolated venv if psutil is not available
if ! "$PYTHON_BIN" -c "import psutil" >/dev/null 2>&1; then
    if [ ! -d "$AGENT_HOME/.venv" ]; then
        echo "[Drishti] Setting up isolated agent environment at $AGENT_HOME/.venv..."
        "$PYTHON_BIN" -m venv "$AGENT_HOME/.venv" >/dev/null 2>&1 || true
        if [ -f "$AGENT_HOME/.venv/bin/pip" ]; then
            "$AGENT_HOME/.venv/bin/pip" install -r "$AGENT_HOME/requirements.txt" -q >/dev/null 2>&1 || true
        fi
    fi
    if [ -f "$AGENT_HOME/.venv/bin/python" ]; then
        PYTHON_BIN="$AGENT_HOME/.venv/bin/python"
    fi
fi

exec "$PYTHON_BIN" "$AGENT_HOME/cli.py" "$@"
"""

SYSTEMD_UNIT = """[Unit]
Description=Drishti Autonomous Endpoint Security Agent
Documentation=https://github.com/Subhadip-Paul2006/dhristi
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/drishti/endpoint-agent
ExecStart=/opt/drishti/endpoint-agent/drishti-agent-launcher.sh
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
EnvironmentFile=-/etc/drishti/agent.conf

[Install]
WantedBy=multi-user.target
"""

INSTALL_SH = """#!/usr/bin/env bash
# Drishti Endpoint Agent - Automated Linux Installer
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "[Drishti] Installer requires root privileges. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

INSTALL_DIR="/opt/drishti/endpoint-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/drishti-agent"

echo "================================================================="
echo "       Drishti Endpoint Agent — Linux Installation              "
echo "================================================================="

echo "[*] Creating target directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "/etc/drishti"
mkdir -p "/usr/local/bin"
mkdir -p "/etc/systemd/system"
mkdir -p "/usr/share/applications"

echo "[*] Installing agent files to $INSTALL_DIR..."
cp -r "$SOURCE_DIR"/* "$INSTALL_DIR/"
cp "$SCRIPT_DIR/drishti-agent-launcher.sh" "$INSTALL_DIR/drishti-agent-launcher.sh"
chmod -R 755 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/drishti-agent-launcher.sh"

echo "[*] Installing global CLI launcher: /usr/local/bin/drishti-endpoint-agent"
ln -sf "$INSTALL_DIR/drishti-agent-launcher.sh" "/usr/local/bin/drishti-endpoint-agent"
chmod 755 "/usr/local/bin/drishti-endpoint-agent"

if [ ! -f "/etc/drishti/agent.conf" ]; then
    echo "[*] Installing default configuration: /etc/drishti/agent.conf"
    cat << 'EOF' > /etc/drishti/agent.conf
# Drishti Endpoint Agent Configuration
DRISHTI_SERVER_URL=http://localhost:8000
EOF
    chmod 644 "/etc/drishti/agent.conf"
fi

if [ -f "$SCRIPT_DIR/drishti-agent.desktop" ]; then
    cp "$SCRIPT_DIR/drishti-agent.desktop" "/usr/share/applications/drishti-agent.desktop"
    chmod 644 "/usr/share/applications/drishti-agent.desktop"
fi

# Systemd integration
if command -v systemctl >/dev/null 2>&1; then
    echo "[*] Configuring systemd service: drishti-agent.service"
    cp "$SCRIPT_DIR/drishti-agent.service" "/etc/systemd/system/drishti-agent.service"
    chmod 644 "/etc/systemd/system/drishti-agent.service"
    systemctl daemon-reload
    systemctl enable drishti-agent.service >/dev/null 2>&1 || true
    echo "[+] Enabled drishti-agent.service"
fi

echo "================================================================="
echo "  Drishti Endpoint Agent installed successfully!"
echo "  Target Directory : $INSTALL_DIR"
echo "  CLI Command      : drishti-endpoint-agent"
echo "  Systemd Service  : sudo systemctl start drishti-agent"
echo "  Configuration    : /etc/drishti/agent.conf"
echo "================================================================="
exit 0
"""

UNINSTALL_SH = """#!/usr/bin/env bash
# Drishti Endpoint Agent - Automated Linux Uninstaller
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "[Drishti] Uninstaller requires root privileges. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

echo "[*] Stopping and disabling systemd service..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop drishti-agent.service 2>/dev/null || true
    systemctl disable drishti-agent.service 2>/dev/null || true
    rm -f "/etc/systemd/system/drishti-agent.service"
    systemctl daemon-reload 2>/dev/null || true
fi

echo "[*] Removing executables and application entries..."
rm -f "/usr/local/bin/drishti-endpoint-agent"
rm -f "/usr/share/applications/drishti-agent.desktop"

echo "[*] Removing installation directory /opt/drishti/endpoint-agent..."
rm -rf "/opt/drishti/endpoint-agent"

echo "[+] Drishti Endpoint Agent uninstalled successfully."
exit 0
"""

DESKTOP_ENTRY = """[Desktop Entry]
Type=Application
Name=Drishti Endpoint Agent
GenericName=Security Telemetry Endpoint
Comment=Drishti Autonomous Network Security Endpoint Agent
Exec=/usr/local/bin/drishti-endpoint-agent
Icon=security-high
Terminal=true
Categories=System;Security;Monitor;
"""

DEFAULT_CONF = """# Drishti Endpoint Agent Configuration
DRISHTI_SERVER_URL=http://localhost:8000
"""

APPDIR_APPRUN = """#!/usr/bin/env bash
# AppRun entrypoint for Drishti Linux AppDir
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="$HERE/usr/bin:$PATH"
exec "$HERE/drishti-agent-launcher.sh" "$@"
"""


# ──────────────────────────────────────────────────────────────
# PACKAGING FUNCTIONS
# ──────────────────────────────────────────────────────────────

def collect_agent_files(agent_root: Path) -> dict[str, bytes]:
    """Reads all agent source files, returning relative posix paths mapped to content bytes."""
    exclude_dirs = {".pytest_cache", "__pycache__", "tests", ".venv", ".build-venv", "dist", "build"}
    files_map: dict[str, bytes] = {}

    for root, dirs, files in os.walk(agent_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if f.endswith(".pyc") or f.endswith(".pyo") or f.startswith(".") or f.startswith("build_"):
                continue
            src_file = Path(root) / f
            rel_path = src_file.relative_to(agent_root).as_posix()
            files_map[rel_path] = src_file.read_bytes()

    return files_map


def build_linux_tarball(agent_root: Path, output_file: Path, arch: str = "x86_64") -> Path:
    """Builds a standalone Linux distribution tarball (.tar.gz) with automated installer."""
    print(f"[*] Generating Linux standalone tarball [{arch}] -> {output_file.name}...")
    files_map = collect_agent_files(agent_root)

    with tarfile.open(output_file, "w:gz") as tar:
        # Add root installer scripts
        scripts = [
            ("install.sh", INSTALL_SH.encode("utf-8"), 0o755),
            ("uninstall.sh", UNINSTALL_SH.encode("utf-8"), 0o755),
            ("drishti-agent-launcher.sh", LAUNCHER_SCRIPT.encode("utf-8"), 0o755),
            ("drishti-agent.service", SYSTEMD_UNIT.encode("utf-8"), 0o644),
            ("drishti-agent.desktop", DESKTOP_ENTRY.encode("utf-8"), 0o644),
            ("agent.conf.default", DEFAULT_CONF.encode("utf-8"), 0o644),
        ]
        for name, content, mode in scripts:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(content)
            ti.mode = mode
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(content))

        # Add drishti-agent payload
        for rel_path, content in files_map.items():
            dest_name = f"drishti-agent/{rel_path}"
            mode = 0o755 if rel_path in ("cli.py", "agent.py") else 0o644
            ti = tarfile.TarInfo(name=dest_name)
            ti.size = len(content)
            ti.mode = mode
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(content))

    print(f"[+] Successfully generated Linux tarball: {output_file} ({output_file.stat().st_size} bytes)")
    return output_file


def build_linux_deb(agent_root: Path, output_file: Path, arch: str = "amd64") -> Path:
    """
    Constructs a standard Debian/Ubuntu package (.deb) archive:
      - debian-binary (2.0)
      - control.tar.gz (control, postinst, prerm)
      - data.tar.gz (installed payload tree)
    """
    print(f"[*] Generating Debian/Ubuntu package [{arch}] -> {output_file.name}...")
    files_map = collect_agent_files(agent_root)

    # 1. debian-binary
    debian_binary = b"2.0\n"

    # 2. control.tar.gz
    installed_size_kb = max(1, sum(len(c) for c in files_map.values()) // 1024)
    control_content = f"""Package: drishti-endpoint-agent
Version: 0.1.0
Section: utils
Priority: optional
Architecture: {arch}
Depends: python3 (>= 3.9)
Maintainer: Drishti Team <support@drishti.local>
Installed-Size: {installed_size_kb}
Description: Drishti Autonomous Endpoint Security Agent
 Authorized endpoint telemetry collector and network intelligence agent
 for high-fidelity device discovery and attack path forecasting.
""".encode("utf-8")

    postinst_script = f"""#!/bin/sh
set -e
chmod -R 755 /opt/drishti/endpoint-agent
chmod +x /opt/drishti/endpoint-agent/drishti-agent-launcher.sh
ln -sf /opt/drishti/endpoint-agent/drishti-agent-launcher.sh /usr/local/bin/drishti-endpoint-agent
chmod 755 /usr/local/bin/drishti-endpoint-agent

if [ ! -f /etc/drishti/agent.conf ]; then
    mkdir -p /etc/drishti
    cp /etc/drishti/agent.conf.default /etc/drishti/agent.conf
    chmod 644 /etc/drishti/agent.conf
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable drishti-agent.service || true
fi
exit 0
""".encode("utf-8")

    prerm_script = """#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop drishti-agent.service || true
    systemctl disable drishti-agent.service || true
fi
rm -f /usr/local/bin/drishti-endpoint-agent
exit 0
""".encode("utf-8")

    control_buf = io.BytesIO()
    with tarfile.open(fileobj=control_buf, mode="w:gz") as ctar:
        for fname, fcontent, fmode in [
            ("./control", control_content, 0o644),
            ("./postinst", postinst_script, 0o755),
            ("./prerm", prerm_script, 0o755),
        ]:
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(fcontent)
            ti.mode = fmode
            ti.mtime = int(time.time())
            ctar.addfile(ti, io.BytesIO(fcontent))
    control_tar_gz = control_buf.getvalue()

    # 3. data.tar.gz
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as dtar:
        # Directories
        for d in [
            "./opt/drishti/endpoint-agent",
            "./etc/drishti",
            "./etc/systemd/system",
            "./usr/local/bin",
            "./usr/share/applications",
        ]:
            ti = tarfile.TarInfo(name=d)
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            ti.mtime = int(time.time())
            dtar.addfile(ti)

        # Config and system files
        for fname, fcontent, fmode in [
            ("./opt/drishti/endpoint-agent/drishti-agent-launcher.sh", LAUNCHER_SCRIPT.encode("utf-8"), 0o755),
            ("./etc/systemd/system/drishti-agent.service", SYSTEMD_UNIT.encode("utf-8"), 0o644),
            ("./etc/drishti/agent.conf.default", DEFAULT_CONF.encode("utf-8"), 0o644),
            ("./usr/share/applications/drishti-agent.desktop", DESKTOP_ENTRY.encode("utf-8"), 0o644),
        ]:
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(fcontent)
            ti.mode = fmode
            ti.mtime = int(time.time())
            dtar.addfile(ti, io.BytesIO(fcontent))

        # Payload files
        for rel_path, content in files_map.items():
            dest = f"./opt/drishti/endpoint-agent/{rel_path}"
            mode = 0o755 if rel_path in ("cli.py", "agent.py") else 0o644
            ti = tarfile.TarInfo(name=dest)
            ti.size = len(content)
            ti.mode = mode
            ti.mtime = int(time.time())
            dtar.addfile(ti, io.BytesIO(content))

    data_tar_gz = data_buf.getvalue()

    # Assemble deb ar archive
    ar_members = [
        ("debian-binary", debian_binary),
        ("control.tar.gz", control_tar_gz),
        ("data.tar.gz", data_tar_gz),
    ]
    create_ar_archive(ar_members, output_file)
    print(f"[+] Successfully generated Debian package: {output_file} ({output_file.stat().st_size} bytes)")
    return output_file


def build_linux_appdir(agent_root: Path, output_dir: Path) -> Path:
    """Builds a portable Linux AppDir application bundle."""
    print(f"[*] Generating Linux AppDir application bundle -> {output_dir.name}...")
    if output_dir.exists():
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    agent_target = output_dir / "opt" / "drishti" / "endpoint-agent"
    agent_target.mkdir(parents=True, exist_ok=True)

    files_map = collect_agent_files(agent_root)
    for rel_path, content in files_map.items():
        dst = agent_target / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(content)
        if rel_path in ("cli.py", "agent.py"):
            dst.chmod(0o755)

    (output_dir / "AppRun").write_text(APPDIR_APPRUN, encoding="utf-8")
    (output_dir / "AppRun").chmod(0o755)

    (output_dir / "drishti-agent-launcher.sh").write_text(LAUNCHER_SCRIPT, encoding="utf-8")
    (output_dir / "drishti-agent-launcher.sh").chmod(0o755)

    (output_dir / "drishti-agent.desktop").write_text(DESKTOP_ENTRY, encoding="utf-8")
    (output_dir / "drishti-agent.service").write_text(SYSTEMD_UNIT, encoding="utf-8")
    (output_dir / "install.sh").write_text(INSTALL_SH, encoding="utf-8")
    (output_dir / "install.sh").chmod(0o755)
    (output_dir / "uninstall.sh").write_text(UNINSTALL_SH, encoding="utf-8")
    (output_dir / "uninstall.sh").chmod(0o755)

    print(f"[+] Successfully created Linux AppDir: {output_dir}")
    return output_dir


def main():
    parser = argparse.ArgumentParser(description="Drishti Endpoint Agent Linux Packager")
    parser.add_argument(
        "--arch",
        choices=["x86_64", "arm64", "all"],
        default="all",
        help="Target Linux architecture (default: all)",
    )
    args = parser.parse_args()

    agent_dir = Path(__file__).resolve().parent
    workspace_root = agent_dir.parent

    dist_dir_local = agent_dir / "dist"
    dist_dir_workspace = workspace_root / "dist"
    dist_dir_local.mkdir(parents=True, exist_ok=True)
    dist_dir_workspace.mkdir(parents=True, exist_ok=True)

    architectures = ["x86_64", "arm64"] if args.arch == "all" else [args.arch]

    for arch in architectures:
        deb_arch = "amd64" if arch == "x86_64" else "arm64"

        # 1. Standalone Tarball
        tar_name = f"Drishti-Endpoint-Agent-Linux-{arch}.tar.gz"
        local_tar = dist_dir_local / tar_name
        workspace_tar = dist_dir_workspace / tar_name
        build_linux_tarball(agent_dir, local_tar, arch=arch)
        shutil.copy2(local_tar, workspace_tar)
        print(f"[+] Mirrored {tar_name} to workspace: {workspace_tar}")

        # 2. Debian / Ubuntu .deb package
        deb_name = f"drishti-endpoint-agent_0.1.0_{deb_arch}.deb"
        local_deb = dist_dir_local / deb_name
        workspace_deb = dist_dir_workspace / deb_name
        build_linux_deb(agent_dir, local_deb, arch=deb_arch)
        shutil.copy2(local_deb, workspace_deb)
        print(f"[+] Mirrored {deb_name} to workspace: {workspace_deb}")

    # 3. Portable AppDir
    appdir_name = "Drishti-Endpoint-Agent-Linux.AppDir"
    local_appdir = dist_dir_local / appdir_name
    workspace_appdir = dist_dir_workspace / appdir_name
    build_linux_appdir(agent_dir, local_appdir)
    if workspace_appdir.exists():
        shutil.rmtree(workspace_appdir)
    shutil.copytree(local_appdir, workspace_appdir)
    print(f"[+] Mirrored {appdir_name} to workspace: {workspace_appdir}")

    print("\n[✓] All requested Linux packages and applications built successfully!")


if __name__ == "__main__":
    main()
