# Drishti Endpoint Agent — Multi-Platform Architecture

## Architecture Overview
The Drishti Endpoint Agent provides authorized device-level visibility as a companion to Drishti's network discovery engine.

```text
Drishti Endpoint Agent
│
├── common/        # Cross-platform identity, config, lifecycle, and platform abstractions
├── macos/         # macOS genuine OS, TCC, and hardware adapters
├── linux/         # Linux genuine OS, systemd, /proc, and hardware adapters
├── windows/       # Windows genuine OS, services, and hardware adapters
├── collectors/    # Unified telemetry contracts (Processes, Sockets, Software, Hardware)
├── transport/     # Zero-dependency HTTP transport client with retry & backoff
├── storage/       # Local credential and persistent identity storage (chmod 0600 on POSIX)
├── agent.py       # Main agent lifecycle orchestrator
└── cli.py         # Command-line entrypoint with SIGINT/SIGTERM handlers
```

---

## Supported Platforms & Build Artifacts

| Platform | Architecture | Installer / Package | Standalone App |
| :--- | :--- | :--- | :--- |
| **macOS** | **Apple Silicon (arm64)** | `Drishti-Endpoint-Agent-macOS-Silicon.pkg` | `Drishti-Endpoint-Agent-macOS-Silicon.app` |
| **macOS** | **Intel (x86_64)** | `Drishti-Endpoint-Agent-macOS-Intel.pkg` | `Drishti-Endpoint-Agent-macOS-Intel.app` |
| **Linux** | **x86_64 / amd64** | `drishti-endpoint-agent_0.1.0_amd64.deb`<br>`Drishti-Endpoint-Agent-Linux-x86_64.tar.gz` | `Drishti-Endpoint-Agent-Linux.AppDir` |
| **Linux** | **arm64 / aarch64** | `drishti-endpoint-agent_0.1.0_arm64.deb`<br>`Drishti-Endpoint-Agent-Linux-arm64.tar.gz` | `Drishti-Endpoint-Agent-Linux.AppDir` |
| **Windows** | **x86_64** | `Drishti-Endpoint-Agent-Windows.exe` | — |

---

## Building Packages

### macOS (Silicon & Intel)
Builds both architecture-specific flat packages (`.pkg`) and desktop `.app` application bundles:
```bash
python endpoint-agent/build_macos_pkg.py --arch all
# Or individually:
python endpoint-agent/build_macos_pkg.py --arch silicon
python endpoint-agent/build_macos_pkg.py --arch intel
```

### Linux (Debian, Ubuntu, RHEL, Fedora, Arch)
Builds native `.deb` packages, standalone `.tar.gz` bundles with `systemd` unit and `install.sh`, and portable `AppDir`:
```bash
python endpoint-agent/build_linux_package.py --arch all
# Or individually:
python endpoint-agent/build_linux_package.py --arch x86_64
python endpoint-agent/build_linux_package.py --arch arm64
```

---

## Installation Guide

### macOS Installation
Double-click the package corresponding to your Mac architecture:
- Apple Silicon (M1/M2/M3/M4): `dist/Drishti-Endpoint-Agent-macOS-Silicon.pkg`
- Intel: `dist/Drishti-Endpoint-Agent-macOS-Intel.pkg`

Or via CLI:
```bash
sudo installer -pkg dist/Drishti-Endpoint-Agent-macOS-Silicon.pkg -target /
```

### Linux Installation

#### Option 1: Debian / Ubuntu (.deb)
```bash
sudo dpkg -i dist/drishti-endpoint-agent_0.1.0_amd64.deb
sudo systemctl start drishti-agent
```

#### Option 2: Standalone Tarball (Generic Linux)
```bash
tar -xzf dist/Drishti-Endpoint-Agent-Linux-x86_64.tar.gz
cd Drishti-Endpoint-Agent-Linux-x86_64
sudo ./install.sh
sudo systemctl start drishti-agent
```

---

## Running in Development Mode
```bash
python endpoint-agent/cli.py --server http://localhost:8000
```
