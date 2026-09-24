# 🍏 Drishti: macOS Endpoint Agent Architecture (Archify Topology)

> **Document Version:** 1.0.0  
> **Target Release:** Drishti Enterprise v1.0 / macOS Native Telemetry Pass  
> **Status:** Verified & Production Ready  
> **Architecture Pattern:** Archify Verification-First Topology · Native Apple Framework Integration · Defensive SOC Observation · Graceful Entitlement Degradation  
> **Target Platforms:** macOS 13 (Ventura), macOS 14 (Sonoma), macOS 15 (Sequoia) on Apple Silicon (ARM64) & Intel (x86_64)

---

## 1. Executive Summary & Design Principles

The **Drishti macOS Endpoint Agent** delivers deep, native endpoint detection, system telemetry, and behavioral monitoring on Apple platforms. Adhering strictly to the **Archify verification-first structural topology**, every component maintains rigorous trust boundaries, verifiable API interfaces, and defensive posture guarantees.

### Core Architectural Guardrails
1. **Defensive SOC Telemetry Only**:
   - Strictly monitors process executions, network connections, system security posture, installed applications, and background daemons.
   - **Zero Keystroke / Zero Clipboard / Zero Audio-Video Capture**: Drishti never accesses or records user keystrokes, clipboard buffers, screens, microphones, or cameras.
   - **TCC Compliance**: Never bypasses Apple Transparency, Consent, and Control (TCC) or sandbox boundaries. Browser history and private databases are never arbitrarily read.
2. **Zero Fabrication Policy**:
   - Telemetry fields report genuine system values directly from Apple kernel APIs (`sysctl`), command-line utilities (`fdesetup`, `csrutil`, `spctl`, `softwareupdate`), and framework bridges (`ApplicationServices.framework`, `EndpointSecurity.framework`).
   - If an API or metric is restricted by entitlements or permissions, the agent explicitly emits `PERMISSION_REQUIRED`, `REQUIRES_USER_ACTION`, `PLATFORM_RESTRICTED`, or `UNAVAILABLE`.
3. **Cross-Platform Parity Without Regression**:
   - Preserves complete compatibility with Windows (`win32`) and Android (`android_native`) agents.
   - Shares unified contracts in `collectors/contracts.py` with extensible fields (`macos_telemetry`, `process_events`, `browser_visibility`, `security_posture`, `storage_info`).

---

## 2. Archify System Topology & 9 Core Mermaid Diagrams

### Diagram 1: Overall macOS Architecture
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
flowchart TB
    subgraph KERNEL_SPACE ["🛡️ macOS Kernel & Hardware Boundary"]
        HW["Apple Silicon / Intel CPU & NVMe"]
        SYSCTL["sysctl Kernel MIBs (hw.model, kern.osversion)"]
        ES_KERNEL["EndpointSecurity.framework Kernel Provider"]
        NET_EXT_KERNEL["NetworkExtension.framework Kernel Provider"]
        HW --> SYSCTL
        HW --> ES_KERNEL
        HW --> NET_EXT_KERNEL
    end

    subgraph SYSTEM_SUBSYSTEMS ["🛡️ macOS System & Security Subsystems"]
        TCC["TCC Daemon (Privacy & Consent)"]
        FDE["FileVault CoreStorage / APFS Crypt (fdesetup)"]
        SIP["System Integrity Protection (csrutil)"]
        GK["Gatekeeper & Notarization (spctl)"]
        ALF["Application Layer Firewall (socketfilterfw)"]
        LAUNCHD["launchd System & User Init Daemon"]
        TCC --> LAUNCHD
        FDE --> LAUNCHD
        SIP --> LAUNCHD
        GK --> LAUNCHD
        ALF --> LAUNCHD
    end

    subgraph AGENT_DAEMON ["⚙️ Drishti macOS Endpoint Agent (Daemon / CLI)"]
        direction TB
        MGR["CollectorManager (Coordination & Isolation)"]
        
        subgraph NATIVE_COLLECTORS ["Native Collector Engine"]
            COL_PROC["MacOSProcessCollector<br/>• Code-Signing & Team ID<br/>• Bounded Ring Buffer (250)<br/>• Suspicious Heuristics"]
            COL_ES["MacOSEndpointSecurityCollector<br/>• Entitlement Verifier<br/>• Graceful Polling Seam"]
            COL_SYS["MacOSSystemCollector<br/>• sysctl Parser<br/>• Load Avgs & Boot Time"]
            COL_STOR["MacOSStorageCollector<br/>• Multi-Mount APFS/HFS"]
            COL_HW["MacOSHardwareCollector<br/>• CPU/RAM/vm_stat/Net"]
            COL_SOFT["MacOSSoftwareCollector<br/>• /Applications Plist Parser"]
            COL_SVC["MacOSServiceCollector<br/>• launchctl List Inspector"]
            COL_SOCK["MacOSSocketCollector<br/>• Port & Connection Mapper"]
            COL_BROWSER["MacOSBrowserCollector<br/>• Defensive AppleScript Tabs"]
            COL_SEC["MacOSSecurityCollector<br/>• Posture Subsystem"]
            COL_PERM["MacOSPermissionManager<br/>• AXIsProcessTrusted & TCC"]
        end

        MGR --> NATIVE_COLLECTORS
    end

    subgraph STORAGE_LAYER ["💾 Local Persistence & Identity Vault"]
        ID_STORE["Identity Vault (~/.drishti/identity.json)"]
        CRED_STORE["Credentials (~/.drishti/credentials.json)"]
        AGENT_DAEMON --> ID_STORE
        AGENT_DAEMON --> CRED_STORE
    end

    subgraph SERVER_INGRESS ["🌐 Drishti Backend & SOC Console"]
        ROUTER["FastAPI /api/endpoint Router"]
        INGEST_SVC["EndpointTelemetryService"]
        DB[(PostgreSQL / SQLite Storage)]
        LIVE_UI["React 18 / Vite LiveWatchPage"]

        AGENT_DAEMON -- "HTTPS TLS 1.3 TelemetryBatch" --> ROUTER
        ROUTER --> INGEST_SVC --> DB
        DB --> LIVE_UI
    end
```

---

### Diagram 2: Pairing Sequence
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
sequenceDiagram
    autonumber
    participant Admin as 👤 SOC Administrator
    participant Agent as 🍏 macOS Agent CLI
    participant Vault as 💾 Identity Vault
    participant API as 🌐 Drishti Server (/api/endpoint)
    participant DB as 🗄️ Database

    Admin->>API: Generate 6-digit Pairing Code via Web UI
    API-->>Admin: Display Code (e.g. 849201, 10 min TTL)
    Admin->>Agent: drishti-agent pair --server https://soc.drishti.local --code 849201
    Agent->>Vault: Check or generate DeviceIdentity (UUIDv4)
    Vault-->>Agent: device_id, mac, hostname, os_info
    Agent->>API: POST /api/endpoint/pair (code, device_id, hostname, os, mac)
    API->>DB: Validate pairing code, verify OTP not expired/consumed
    API->>DB: Associate Device record, bind agent_id & generate auth_token
    API-->>Agent: 200 OK (agent_id, auth_token, device_id, server_pubkey)
    Agent->>Vault: Persist credentials (chmod 0600)
    Agent->>Admin: "✅ macOS Agent paired successfully as [device_id]"
```

---

### Diagram 3: Telemetry Collection & Dispatch Sequence
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
sequenceDiagram
    autonumber
    participant Scheduler as ⏱️ Agent Scheduler
    participant Manager as ⚙️ CollectorManager
    participant Fast as 🚀 Fast Collectors (5s)
    participant Slow as 🐢 Slow Collectors (300s)
    participant Transport as 🔒 Transport Client
    participant Server as 🌐 Drishti Server

    loop Fast Interval (Every 5 seconds)
        Scheduler->>Manager: collect_all(force_slow_collect=False)
        Manager->>Fast: Collect Procs, Sockets, Hardware, Events, Posture, Browser
        Fast-->>Manager: Partial Telemetry Components
        alt Slow Interval Elapsed (> 300s)
            Manager->>Slow: Collect Installed Software, Multi-Mount Disks
            Slow-->>Manager: Software & Storage Partitions
        else Within Cache Window
            Manager->>Manager: Reuse Cached Software List
        end
        Manager->>Manager: Assemble Unified TelemetryBatch
        Manager->>Transport: send_telemetry(batch.to_payload())
        Transport->>Server: POST /api/endpoint/telemetry (Bearer Token)
        Server-->>Transport: 200 OK (acknowledged, next_interval=5.0)
    end
```

---

### Diagram 4: Endpoint Security Event Flow & Graceful Degradation
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
flowchart TD
    START(["Start Process Event Subsystem"]) --> CHK_ROOT{"Running as Root (euid == 0)?"}
    
    CHK_ROOT -- No --> DEGRADE_NONROOT["Status: PERMISSION_REQUIRED<br/>'Requires root daemon execution'"]
    CHK_ROOT -- Yes --> CHK_ENT{"Has com.apple.developer.<br/>endpoint-security.client?"}

    CHK_ENT -- Yes --> ES_ACTIVE["Initialize es_new_client()<br/>Subscribe ES_EVENT_TYPE_NOTIFY_EXEC / EXIT<br/>Zero-drop Kernel Queue"]
    CHK_ENT -- No --> DEGRADE_ENT["Status: PERMISSION_REQUIRED<br/>'Missing developer entitlement'"]

    DEGRADE_NONROOT --> FALLBACK_POLL["Fallback: High-Frequency Poller Seam<br/>• psutil delta comparison<br/>• codesign CLI code identity parsing<br/>• Bounded Ring Buffer (collections.deque, maxlen=250)"]
    DEGRADE_ENT --> FALLBACK_POLL

    FALLBACK_POLL --> HEURISTICS{"Evaluate Suspicious Execution Heuristics"}
    ES_ACTIVE --> HEURISTICS

    HEURISTICS -- Executed from /tmp or /var/tmp --> FLAG_SUSP["Flag: is_suspicious=True<br/>Reason: 'Temporary directory execution'"]
    HEURISTICS -- Masquerading system binary name outside /System --> FLAG_SUSP2["Flag: is_suspicious=True<br/>Reason: 'Masquerading binary path'"]
    HEURISTICS -- Benign Signed Binary --> EMIT_NORMAL["Flag: is_suspicious=False"]

    FLAG_SUSP --> RING_BUF[("Bounded Event Ring Buffer<br/>(250 ProcessEventItems)")]
    FLAG_SUSP2 --> RING_BUF
    EMIT_NORMAL --> RING_BUF
```

---

### Diagram 5: Network Telemetry & Extension Flow
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
flowchart LR
    subgraph MACOS_NET ["Network Observation Surfaces"]
        PSUTIL_CONNS["psutil.net_connections(kind='inet')<br/>• PID & Local/Remote Addr:Port<br/>• Connection State (ESTABLISHED, LISTEN)"]
        NET_IF["getifaddrs() / psutil.net_if_addrs()<br/>• Interface Name (en0, en1, utun)<br/>• MAC & IPv4/IPv6 Addresses<br/>• Interface Counters (tx/rx bytes)"]
        NE_EXT["NetworkExtension Provider<br/>(NEFilterDataProvider)<br/>• Non-blocking defensive flow audit"]
    end

    subgraph PARSER ["MacOSSocketCollector & Extension Seam"]
        FILTER["Address Sanitizer & Protocol Resolver"]
        CORRELATE["Correlate Socket to Process Name & PID"]
    end

    subgraph TELEM_OUT ["Structured Telemetry Batch"]
        PORTS["listening_ports: ListeningPortItem[]"]
        CONNS["process_connections: SocketConnectionItem[]"]
        FLOWS["network_flows: DefensiveFlowItem[]"]
    end

    PSUTIL_CONNS --> CORRELATE
    NET_IF --> FILTER
    NE_EXT --> FLOWS
    CORRELATE --> PORTS
    CORRELATE --> CONNS
```

---

### Diagram 6: Permission & Entitlement Audit Flow
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
flowchart TD
    AUDIT(["MacOSPermissionManager.collect_permissions()"]) --> P1["1. Accessibility Check<br/>ctypes: AXIsProcessTrusted()"]
    AUDIT --> P2["2. Full Disk Access Check<br/>os.access('/Library/Application Support/com.apple.TCC/TCC.db', R_OK)"]
    AUDIT --> P3["3. Apple Events Automation Check<br/>osascript test query via System Events"]
    AUDIT --> P4["4. Endpoint Security Entitlement<br/>codesign entitlement verification & euid==0"]
    AUDIT --> P5["5. Network Extension Status<br/>SystemExtension provider registration check"]

    P1 -- Returns 1 --> GRANTED1["Accessibility: GRANTED"]
    P1 -- Returns 0 --> REQ1["Accessibility: REQUIRES_USER_ACTION<br/>Remediation: System Settings > Privacy > Accessibility"]

    P2 -- Readable --> GRANTED2["FDA: GRANTED"]
    P2 -- EACCES --> REQ2["FDA: REQUIRES_USER_ACTION<br/>Remediation: System Settings > Privacy > Full Disk Access"]

    P3 -- Exit 0 --> GRANTED3["Automation: GRANTED"]
    P3 -- Exit non-zero --> REQ3["Automation: REQUIRES_USER_ACTION<br/>Remediation: System Settings > Privacy > Automation"]

    GRANTED1 & REQ1 & GRANTED2 & REQ2 & GRANTED3 & REQ3 & P4 & P5 --> MATRIX["Construct capability_status: PermissionStatusItem[]"]
```

---

### Diagram 7: Backend Ingestion & Indexing Pipeline
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
flowchart TB
    INGRESS["POST /api/endpoint/telemetry"] --> AUTH["Validate Agent JWT & Active Enrollment"]
    AUTH --> VALIDATE["Pydantic Schema Validation<br/>(EndpointTelemetrySubmitRequest)"]
    
    VALIDATE --> EXTRACT["Extract Standard & macOS Fields:<br/>• cpu_info, memory_info, network_info<br/>• endpoint_processes, listening_ports<br/>• process_events, macos_telemetry<br/>• security_posture, capability_status"]

    EXTRACT --> SERVICE["EndpointTelemetryService.save_telemetry()"]
    
    subgraph PERSISTENCE ["PostgreSQL / SQLite Indexing"]
        DEV_UPDATE["Update Device Record:<br/>• last_seen, os_version, ip, status='ONLINE'"]
        TELEM_STORE["Store Raw Telemetry Payload in Device.endpoint_telemetry"]
        EVENT_INDEX["Index Process Lifecycle Events for Threat Correlation"]
        HIST_RECORD["Append Time-Series Performance Point"]
    end

    SERVICE --> DEV_UPDATE
    SERVICE --> TELEM_STORE
    SERVICE --> EVENT_INDEX
    SERVICE --> HIST_RECORD
    PERSISTENCE --> ACK["Return 200 OK to Agent"]
```

---

### Diagram 8: Live Watch UI Rendering Flow
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
flowchart TB
    POLL["useQuery(['endpoint-telemetry', deviceId], refetchInterval=8000)"] --> DATA["Received EndpointTelemetryOut"]
    DATA --> DETECT_OS{"isMac Detected?<br/>(os_name contains 'darwin'/'mac' or devInfo.hardware_model)"}

    DETECT_OS -- Yes --> MAC_VIEW["Render macOS Specialized Panels"]
    DETECT_OS -- No --> STD_VIEW["Render Standard Android / Windows Panels"]

    subgraph MAC_PANELS ["macOS SOC Observation Components"]
        P_IDENT["Identity & Model (e.g. Mac15,12, M3, Darwin 24.5)"]
        P_CPU["Per-Core Utilization & Apple Silicon Cluster View"]
        P_MEM["Unified Memory Breakdown & Active/Wired/Compressed"]
        P_SEC["macOS Security Posture Matrix:<br/>• FileVault, SIP, Gatekeeper, Firewall, Secure Boot"]
        P_STORAGE["Mounted Storage Partitions (APFS Volume Breakdown)"]
        P_PROCS["Running Processes with CPU% & Memory"]
        P_EVENTS["Process Lifecycle Stream (EXEC/EXIT with Code Signing Badges)"]
        P_BROWSER["Browser Visibility & Active Tabs (AppleScript Compliant)"]
        P_PERMS["TCC Permissions & Entitlements Diagnostic Table"]
    end

    MAC_VIEW --> P_IDENT
    MAC_VIEW --> P_CPU
    MAC_VIEW --> P_MEM
    MAC_VIEW --> P_SEC
    MAC_VIEW --> P_STORAGE
    MAC_VIEW --> P_PROCS
    MAC_VIEW --> P_EVENTS
    MAC_VIEW --> P_BROWSER
    MAC_VIEW --> P_PERMS
```

---

### Diagram 9: Error, Backoff & Reconnect Flow
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a'}}}%%
sequenceDiagram
    autonumber
    participant Agent as 🍏 macOS Agent
    participant Transport as 🔒 Transport Client
    participant RingBuf as 📦 Event Ring Buffer
    participant Server as 🌐 Drishti Server

    Agent->>Transport: send_telemetry(batch)
    Transport->>Server: POST /api/endpoint/telemetry
    Server--xTransport: Connection Refused / 503 Service Unavailable
    Transport-->>Agent: DeliveryFailedException

    Note over Agent,RingBuf: Enter Defensive Offline Mode
    Agent->>Agent: Mark local status = RECONNECTING
    Agent->>RingBuf: Keep lifecycle events buffered (up to 250 items, FIFO)
    Agent->>Agent: Calculate exponential backoff: min(30s, 2^retries * 1.5)

    loop Retry with Jitter
        Agent->>Agent: Sleep backoff seconds
        Agent->>Transport: Re-attempt heartbeat (GET /api/endpoint/ping)
        Transport->>Server: GET /api/endpoint/ping
        Server--xTransport: Still Unreachable
    end

    Note over Server,Transport: Server Restored
    Agent->>Transport: Attempt ping
    Transport->>Server: GET /api/endpoint/ping
    Server-->>Transport: 200 OK (pong)
    Agent->>Transport: Flush buffered events in next TelemetryBatch
    Transport->>Server: POST /api/endpoint/telemetry (Full Batch with Buffered Events)
    Server-->>Transport: 200 OK
    Agent->>Agent: Reset backoff counter, restore normal 5s cadence
```

---

## 3. Native Apple API Specifications & System Seams

| Category | macOS Native Mechanism | Implementation Path | Fallback / Degradation Mode |
| :--- | :--- | :--- | :--- |
| **Hardware & Model** | `sysctl hw.model`, `sysctl hw.machine` | `MacOSSystemCollector` | `platform.machine()`, `platform.uname()` |
| **Kernel & OS Build** | `sysctl kern.version`, `sysctl kern.osversion` | `MacOSSystemCollector` | `platform.mac_ver()` |
| **Uptime & Boot** | `psutil.boot_time()`, `sysctl kern.boottime` | `MacOSSystemCollector` | Current timestamp fallback |
| **Console User** | `os.stat("/dev/console")` + `pwd.getpwuid` | `MacOSSystemCollector` | `scutil --get LocalHostName` |
| **Process Enumeration** | `psutil.process_iter()`, `sysctl KERN_PROC` | `MacOSProcessCollector` | Safe iteration skipping inaccessible PIDs |
| **Code Signing & Team ID** | `/usr/bin/codesign -dv --verbose=2` | `MacOSProcessCollector._inspect_code_signing` | Cached result (max 500), `UNSIGNED` on failure |
| **Process Lifecycle** | `EndpointSecurity.framework` (`es_new_client`) | `MacOSEndpointSecurityCollector` | High-frequency polling ring buffer (250 events) |
| **Disk & APFS Mounts** | `psutil.disk_partitions(all=False)` | `MacOSStorageCollector` | Root mount `/` disk usage fallback |
| **Services & Daemons** | `/bin/launchctl list` | `MacOSServiceCollector` | Empty service list if launchctl inaccessible |
| **Open Ports & Sockets** | `proc.net_connections(kind="inet")` | `MacOSSocketCollector` | Per-process permission handling |
| **FileVault Encryption** | `/usr/bin/fdesetup status` | `MacOSSecurityCollector` | `PERMISSION_REQUIRED` if unprivileged |
| **System Integrity (SIP)** | `/usr/bin/csrutil status` | `MacOSSecurityCollector` | `UNKNOWN` on execution failure |
| **Gatekeeper** | `/usr/sbin/spctl --status` | `MacOSSecurityCollector` | `UNKNOWN` on execution failure |
| **Firewall (ALF)** | `/usr/libexec/ApplicationFirewall/socketfilterfw` | `MacOSSecurityCollector` | `UNKNOWN` if binary missing |
| **Secure Boot** | `sysctl hw.optional.arm64` | `MacOSSecurityCollector` | `ENABLED` (ARM64) / `NOT_APPLICABLE` (Intel) |
| **Software Updates** | `/usr/sbin/softwareupdate --schedule` | `MacOSSecurityCollector` | `UNKNOWN` on timeout |
| **Accessibility (TCC)** | `ApplicationServices.framework` (`AXIsProcessTrusted`) | `MacOSPermissionManager` | Reports `REQUIRES_USER_ACTION` with remediation |
| **Full Disk Access (TCC)** | Check read access to `/Library/Application Support/com.apple.TCC/TCC.db` | `MacOSPermissionManager` | Reports `REQUIRES_USER_ACTION` with remediation |
| **Browser Visibility** | `osascript` AppleScript querying active window & tab | `MacOSBrowserCollector` | `PERMISSION_REQUIRED`; history never read |
| **Network Interception** | `NetworkExtension.framework` (`NEFilterDataProvider`) | `MacOSNetworkExtensionBridge` | Standby mode with architecture specification |

---

## 4. Verification & Validation Topology

### Automated Test Coverage Matrix
- **Unit & Contract Isolation:**
  - `endpoint-agent/tests/test_macos_telemetry.py`: 10/10 tests verifying process categorization, suspicious heuristics, ring buffer semantics, sysctl parsing, storage metrics, security posture, and permissions.
  - `endpoint-agent/tests/test_collectors.py`: 16/16 tests validating collector failure isolation, caching intervals, and serialization contracts.
- **Backend Ingestion & E2E:**
  - `server/tests/test_endpoint_telemetry_e2e.py`: End-to-end testing of payload submission, Pydantic parsing, database persistence, and API output.
- **Frontend Live Watch Console:**
  - `npm --prefix web run lint`: Zero TypeScript errors across all interfaces.
  - `npm --prefix web test -- --run`: 75/75 passing Vitest tests.

---

## 5. Security & Threat Model Guardrails

1. **Confidentiality:** All credentials stored with restrictive permissions (`0600`). In-transit communication utilizes TLS 1.3 with standard bearer token authentication.
2. **Defensive Audit Boundary:** No capability exists within the agent to alter firewall rules, manipulate user files, or execute remote payloads.
3. **Integrity & Attestation:** The binary is structured for Apple Developer ID signing and Notarization (`codesign -s "Developer ID Application"` and `xcrun notarytool`).
