#!/usr/bin/env python3
"""
Drishti Endpoint Agent - macOS Distributable Installer (.pkg) & App Builder
Generates separate Apple Silicon (arm64, M1-M4) and Intel (x86_64) packages and apps:
  - Drishti-Endpoint-Agent-macOS-Silicon.pkg & Drishti-Endpoint-Agent-macOS-Silicon.app
  - Drishti-Endpoint-Agent-macOS-Intel.pkg & Drishti-Endpoint-Agent-macOS-Intel.app
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import shutil
import struct
import sys
import zipfile
import zlib
from pathlib import Path


def delete_existing_pkg_files(paths: list[Path]) -> list[Path]:
    """Deletes existing .pkg files across specified directory paths."""
    deleted = []
    for base_dir in paths:
        if base_dir.exists() and base_dir.is_dir():
            for pkg_file in base_dir.rglob("*.pkg"):
                try:
                    pkg_file.unlink()
                    deleted.append(pkg_file)
                    print(f"[-] Deleted existing legacy package: {pkg_file}")
                except Exception as e:
                    print(f"[!] Warning: failed to delete {pkg_file}: {e}")
    return deleted


def make_cpio_entry(filename: str, content: bytes, mode: int = 0o100644, ino: int = 1, mtime: int = 1726000000) -> bytes:
    """Creates a single entry in standard SVR4 portable cpio (newc: 070701)."""
    filename = filename.replace("\\", "/").lstrip("/")
    name_bytes = filename.encode("utf-8") + b"\x00"
    name_len = len(name_bytes)
    filesize = len(content)

    header = (
        f"070701"
        f"{ino:08X}"
        f"{mode:08X}"
        f"{0:08X}"       # uid (root)
        f"{0:08X}"       # gid (wheel)
        f"{1:08X}"       # nlink
        f"{mtime:08X}"   # mtime
        f"{filesize:08X}"
        f"{0:08X}"       # major
        f"{0:08X}"       # minor
        f"{0:08X}"       # rmajor
        f"{0:08X}"       # rminor
        f"{name_len:08X}"
        f"00000000"     # chksum
    ).encode("ascii")

    pad1_len = (4 - ((110 + name_len) % 4)) % 4
    pad2_len = (4 - (filesize % 4)) % 4

    return header + name_bytes + (b"\x00" * pad1_len) + content + (b"\x00" * pad2_len)


def make_cpio_trailer(ino: int = 999999) -> bytes:
    """Creates the standard cpio TRAILER!!! marker."""
    trailer_name = b"TRAILER!!!\x00"
    name_len = len(trailer_name)
    header = (
        f"070701"
        f"{ino:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{1:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{name_len:08X}"
        f"00000000"
    ).encode("ascii")
    pad1_len = (4 - ((110 + name_len) % 4)) % 4
    return header + trailer_name + (b"\x00" * pad1_len)


def build_xar_package(files: list[tuple[str, bytes]], output_path: Path) -> None:
    """
    Constructs an Apple Flat Package XAR archive with SHA-1 TOC checksum.
    `files` is a list of (name, bytes) tuples for files in the archive (PackageInfo, Payload, Scripts, etc.).
    """
    heap_data = bytearray()
    heap_data.extend(b"\x00" * 20)  # SHA-1 TOC checksum placeholder

    file_nodes = []
    for idx, (name, data) in enumerate(files, start=1):
        offset = len(heap_data)
        length = len(data)
        sha1 = hashlib.sha1(data).hexdigest()
        heap_data.extend(data)

        file_nodes.append(f"""  <file id="{idx}">
   <data>
    <length>{length}</length>
    <offset>{offset}</offset>
    <size>{length}</size>
    <extracted-checksum style="sha1">{sha1}</extracted-checksum>
    <archived-checksum style="sha1">{sha1}</archived-checksum>
   </data>
   <type>file</type>
   <name>{name}</name>
  </file>""")

    files_xml = "\n".join(file_nodes)
    toc_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <checksum style="sha1">
   <size>20</size>
   <offset>0</offset>
  </checksum>
{files_xml}
 </toc>
</xar>""".encode("utf-8")

    toc_uncompressed = len(toc_xml)
    toc_comp = zlib.compress(toc_xml)
    toc_compressed = len(toc_comp)

    toc_sha1 = hashlib.sha1(toc_comp).digest()
    heap_data[0:20] = toc_sha1

    magic = b"xar!"
    header_size = 28
    version = 1
    cksum_alg = 1  # SHA-1
    header = struct.pack(">4sHHQQI", magic, header_size, version, toc_compressed, toc_uncompressed, cksum_alg)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(header + toc_comp + bytes(heap_data))


def get_architecture_specs(arch: str) -> dict[str, str]:
    """Returns architecture-specific build parameters."""
    normalized = arch.lower().strip()
    if normalized in ("silicon", "arm64", "apple_silicon", "aarch64"):
        return {
            "arch_key": "silicon",
            "arch_name": "Apple Silicon",
            "host_arch": "arm64",
            "pkg_filename": "Drishti-Endpoint-Agent-macOS-Silicon.pkg",
            "app_name": "Drishti-Endpoint-Agent-macOS-Silicon.app",
            "identifier": "com.drishti.endpointagent.silicon",
            "python_search": '"$AGENT_HOME/.venv/bin/python" /opt/homebrew/bin/python3 /usr/bin/python3 /usr/local/bin/python3 python3',
            "min_macos_ver": "11.0",
        }
    elif normalized in ("intel", "x86_64", "x64"):
        return {
            "arch_key": "intel",
            "arch_name": "Intel x86_64",
            "host_arch": "x86_64",
            "pkg_filename": "Drishti-Endpoint-Agent-macOS-Intel.pkg",
            "app_name": "Drishti-Endpoint-Agent-macOS-Intel.app",
            "identifier": "com.drishti.endpointagent.intel",
            "python_search": '"$AGENT_HOME/.venv/bin/python" /usr/local/bin/python3 /usr/bin/python3 python3',
            "min_macos_ver": "10.15",
        }
    else:
        raise ValueError(f"Unsupported macOS architecture: {arch}. Choose 'silicon' or 'intel'.")


def generate_macos_pkg(agent_root: Path, output_file: Path, arch: str = "silicon") -> None:
    """Builds an architecture-specific macOS .pkg installer."""
    spec = get_architecture_specs(arch)
    arch_name = spec["arch_name"]
    host_arch = spec["host_arch"]
    identifier = spec["identifier"]
    python_search = spec["python_search"]

    print(f"[*] Packaging Drishti Endpoint Agent for macOS [{arch_name} ({host_arch})] -> {output_file.name}...")

    # Architecture-tuned launcher script
    launcher_sh = f"""#!/usr/bin/env bash
# Drishti Endpoint Agent - macOS [{arch_name}] Launcher
set -e

AGENT_HOME="/Library/Application Support/Drishti/endpoint-agent"
cd "$AGENT_HOME"

# Load global configuration if present
if [ -f "/etc/drishti/agent.conf" ]; then
    set -a
    . "/etc/drishti/agent.conf"
    set +a
fi

# Detect Python 3 prioritizing {arch_name} environment
PYTHON_BIN=""
for candidate in {python_search}; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[Drishti] ERROR: Python 3 not found on this {arch_name} macOS system." >&2
    echo "[Drishti] Please install Python 3 via Homebrew or Xcode Command Line Tools." >&2
    exit 1
fi

# Auto-setup venv if psutil is not yet installed in host environment
if ! "$PYTHON_BIN" -c "import psutil" >/dev/null 2>&1; then
    if [ ! -d "$AGENT_HOME/.venv" ]; then
        echo "[Drishti] Setting up {arch_name} endpoint agent isolated environment..."
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
""".encode("utf-8")

    # Architecture-specific LaunchDaemon plist
    launchd_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{identifier}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/Drishti/endpoint-agent/drishti-agent-launcher.sh</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/drishti-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/drishti-agent.err</string>
    <key>WorkingDirectory</key>
    <string>/Library/Application Support/Drishti/endpoint-agent</string>
</dict>
</plist>
""".encode("utf-8")

    default_conf = b"""# Drishti Endpoint Agent Configuration
# Set the backend URL for your Drishti server instance:
DRISHTI_SERVER_URL=http://localhost:8000
"""

    postinstall_sh = f"""#!/bin/bash
set -e

AGENT_DIR="/Library/Application Support/Drishti/endpoint-agent"
chmod -R 755 "$AGENT_DIR"
chmod +x "$AGENT_DIR/drishti-agent-launcher.sh"

mkdir -p "/usr/local/bin"
ln -sf "$AGENT_DIR/drishti-agent-launcher.sh" "/usr/local/bin/drishti-endpoint-agent"
chmod 755 "/usr/local/bin/drishti-endpoint-agent"

mkdir -p "/etc/drishti"
if [ ! -f "/etc/drishti/agent.conf" ]; then
    cat << 'EOF' > /etc/drishti/agent.conf
# Drishti Endpoint Agent Configuration
DRISHTI_SERVER_URL=http://localhost:8000
EOF
    chmod 644 "/etc/drishti/agent.conf"
fi

if [ -d "/Library/LaunchDaemons" ]; then
    cp "$AGENT_DIR/com.drishti.endpointagent.plist" "/Library/LaunchDaemons/{identifier}.plist"
    chmod 644 "/Library/LaunchDaemons/{identifier}.plist"
    chown root:wheel "/Library/LaunchDaemons/{identifier}.plist" 2>/dev/null || true
fi

echo "================================================================="
echo "  Drishti Endpoint Agent [{arch_name}] installed successfully!"
echo "  Architecture: {host_arch}"
echo "  Target: $AGENT_DIR"
echo "  Command: drishti-endpoint-agent"
echo "  Configuration: /etc/drishti/agent.conf or --server <URL>"
echo "================================================================="
exit 0
""".encode("utf-8")

    target_prefix = "Library/Application Support/Drishti/endpoint-agent"
    cpio_parts = []
    ino = 100

    for d in [
        target_prefix,
        f"{target_prefix}/common",
        f"{target_prefix}/macos",
        f"{target_prefix}/linux",
        f"{target_prefix}/collectors",
        f"{target_prefix}/transport",
        f"{target_prefix}/storage",
        "usr/local/bin",
        "etc/drishti",
    ]:
        ino += 1
        cpio_parts.append(make_cpio_entry(d, b"", mode=0o040755, ino=ino))

    ino += 1
    cpio_parts.append(make_cpio_entry(f"{target_prefix}/drishti-agent-launcher.sh", launcher_sh, mode=0o100755, ino=ino))
    ino += 1
    cpio_parts.append(make_cpio_entry(f"{target_prefix}/com.drishti.endpointagent.plist", launchd_plist, mode=0o100644, ino=ino))
    ino += 1
    cpio_parts.append(make_cpio_entry("etc/drishti/agent.conf.default", default_conf, mode=0o100644, ino=ino))

    exclude_dirs = {".pytest_cache", "__pycache__", "tests", ".venv", ".build-venv", "dist", "build"}
    for root, dirs, files in os.walk(agent_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if f.endswith(".pyc") or f.endswith(".pyo") or f.startswith(".") or f.startswith("build_"):
                continue
            src_file = Path(root) / f
            rel_path = src_file.relative_to(agent_root).as_posix()
            dest_path = f"{target_prefix}/{rel_path}"

            with open(src_file, "rb") as sf:
                content = sf.read()

            ino += 1
            mode = 0o100755 if f in ("cli.py", "agent.py") else 0o100644
            cpio_parts.append(make_cpio_entry(dest_path, content, mode=mode, ino=ino))

    ino += 1
    cpio_parts.append(make_cpio_trailer(ino=ino))
    payload_raw = b"".join(cpio_parts)
    payload_gz = gzip.compress(payload_raw, mtime=0)

    scripts_parts = [
        make_cpio_entry("postinstall", postinstall_sh, mode=0o100755, ino=1),
        make_cpio_trailer(ino=2),
    ]
    scripts_raw = b"".join(scripts_parts)
    scripts_gz = gzip.compress(scripts_raw, mtime=0)

    install_kbytes = max(1, (len(payload_raw) + 1023) // 1024)
    package_info = f"""<pkg-info format-version="2" identifier="{identifier}" version="0.1.0" install-location="/" auth="root" hostArchitectures="{host_arch}">
    <payload installKBytes="{install_kbytes}" numberOfFiles="{ino - 100}"/>
    <scripts>
        <postinstall file="./postinstall"/>
    </scripts>
</pkg-info>""".encode("utf-8")

    xar_entries = [
        ("PackageInfo", package_info),
        ("Payload", payload_gz),
        ("Scripts", scripts_gz),
    ]

    build_xar_package(xar_entries, output_file)
    print(f"[+] Successfully generated {arch_name} package: {output_file} ({output_file.stat().st_size} bytes)")


def generate_macos_app(agent_root: Path, output_app_dir: Path, arch: str = "silicon") -> Path:
    """Builds a standalone macOS Application bundle (.app) and zips it."""
    spec = get_architecture_specs(arch)
    arch_name = spec["arch_name"]
    host_arch = spec["host_arch"]
    identifier = spec["identifier"]
    python_search = spec["python_search"]
    min_ver = spec["min_macos_ver"]

    app_contents = output_app_dir / "Contents"
    macos_dir = app_contents / "MacOS"
    resources_dir = app_contents / "Resources"
    agent_bundle_dir = resources_dir / "agent"

    if output_app_dir.exists():
        shutil.rmtree(output_app_dir)

    macos_dir.mkdir(parents=True, exist_ok=True)
    agent_bundle_dir.mkdir(parents=True, exist_ok=True)

    # Info.plist
    info_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleName</key>
    <string>Drishti Endpoint Agent</string>
    <key>CFBundleDisplayName</key>
    <string>Drishti Endpoint Agent ({arch_name})</string>
    <key>CFBundleIdentifier</key>
    <string>{identifier}</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleExecutable</key>
    <string>drishti-agent</string>
    <key>LSMinimumSystemVersion</key>
    <string>{min_ver}</string>
    <key>LSArchitecturePriority</key>
    <array>
        <string>{host_arch}</string>
    </array>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
"""
    (app_contents / "Info.plist").write_text(info_plist, encoding="utf-8")
    (app_contents / "PkgInfo").write_bytes(b"APPL????")

    # Executable launcher in Contents/MacOS/drishti-agent
    launcher_script = f"""#!/usr/bin/env bash
# Drishti Endpoint Agent - macOS App Launcher [{arch_name}]
DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
APP_HOME="$(cd "$DIR/../Resources/agent" && pwd)"
cd "$APP_HOME"

PYTHON_BIN=""
for candidate in {python_search}; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    osascript -e 'display alert "Drishti Endpoint Agent" message "Python 3 is required for {arch_name}. Please install Python 3 via Xcode Command Line Tools or Homebrew."'
    exit 1
fi

exec "$PYTHON_BIN" "$APP_HOME/cli.py" "$@"
"""
    launcher_path = macos_dir / "drishti-agent"
    launcher_path.write_text(launcher_script, encoding="utf-8")
    launcher_path.chmod(0o755)

    # Copy agent source tree into Contents/Resources/agent
    exclude_dirs = {".pytest_cache", "__pycache__", "tests", ".venv", ".build-venv", "dist", "build"}
    for root, dirs, files in os.walk(agent_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if f.endswith(".pyc") or f.endswith(".pyo") or f.startswith(".") or f.startswith("build_"):
                continue
            src_file = Path(root) / f
            rel_path = src_file.relative_to(agent_root)
            dest_file = agent_bundle_dir / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest_file)

    print(f"[+] Built {arch_name} App Bundle: {output_app_dir}")

    # Create distributable zip of the .app
    zip_path = output_app_dir.parent / f"{output_app_dir.name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(output_app_dir):
            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(output_app_dir.parent)
                zf.write(full_path, rel_path)
    print(f"[+] Packaged {arch_name} App zip: {zip_path} ({zip_path.stat().st_size} bytes)")
    return output_app_dir


def main():
    parser = argparse.ArgumentParser(description="Drishti Endpoint Agent macOS Packager")
    parser.add_argument(
        "--arch",
        choices=["silicon", "intel", "all"],
        default="all",
        help="Target architecture: silicon (arm64), intel (x86_64), or all (default)",
    )
    args = parser.parse_args()

    agent_dir = Path(__file__).resolve().parent
    workspace_root = agent_dir.parent

    dist_dir_local = agent_dir / "dist"
    dist_dir_workspace = workspace_root / "dist"
    dist_dir_local.mkdir(parents=True, exist_ok=True)
    dist_dir_workspace.mkdir(parents=True, exist_ok=True)

    # 1. Delete all existing legacy .pkg files
    print("[*] Deleting any existing .pkg files...")
    delete_existing_pkg_files([agent_dir, workspace_root, dist_dir_local, dist_dir_workspace])

    targets = ["silicon", "intel"] if args.arch == "all" else [args.arch]

    for target_arch in targets:
        spec = get_architecture_specs(target_arch)
        pkg_name = spec["pkg_filename"]
        app_name = spec["app_name"]

        # Build .pkg installer
        target_pkg_local = dist_dir_local / pkg_name
        target_pkg_workspace = dist_dir_workspace / pkg_name
        generate_macos_pkg(agent_dir, target_pkg_local, arch=target_arch)
        shutil.copy2(target_pkg_local, target_pkg_workspace)
        print(f"[+] Mirrored {pkg_name} to workspace: {target_pkg_workspace}")

        # Build .app application bundle & zip
        app_dir_local = dist_dir_local / app_name
        app_dir_workspace = dist_dir_workspace / app_name
        generate_macos_app(agent_dir, app_dir_local, arch=target_arch)
        if app_dir_workspace.exists():
            shutil.rmtree(app_dir_workspace)
        shutil.copytree(app_dir_local, app_dir_workspace)

        zip_local = dist_dir_local / f"{app_name}.zip"
        zip_workspace = dist_dir_workspace / f"{app_name}.zip"
        if zip_local.exists():
            shutil.copy2(zip_local, zip_workspace)
        print(f"[+] Mirrored {app_name} to workspace: {app_dir_workspace}")

    print("\n[✓] All requested macOS packages and applications built successfully!")


if __name__ == "__main__":
    main()
