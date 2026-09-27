# Drishti v0.1 — Real-time Packet Harm Inspector & Threat Classifier | Phase 01
from __future__ import annotations

import math
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from app.schemas.tracking import FlaggedPacketOut

# Well-known sensitive and attack-target service ports
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP (Cleartext File Transfer)",
    22: "SSH (Secure Shell Management)",
    23: "Telnet (Unencrypted Legacy Terminal)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Cleartext Web)",
    135: "RPC (Windows Remote Procedure Call)",
    137: "NetBIOS (Name Service)",
    139: "NetBIOS (Session Service)",
    445: "SMB (Server Message Block)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis (In-Memory Datastore)",
    8080: "HTTP-Proxy / Alternative Web",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _format_tcp_flags(flags: dict[str, bool] | str | None) -> str:
    if not flags:
        return ""
    if isinstance(flags, str):
        return flags.strip().upper()
    active_flags: list[str] = []
    if flags.get("SYN"):
        active_flags.append("SYN")
    if flags.get("ACK"):
        active_flags.append("ACK")
    if flags.get("RST"):
        active_flags.append("RST")
    if flags.get("FIN"):
        active_flags.append("FIN")
    if flags.get("PSH"):
        active_flags.append("PSH")
    if flags.get("URG"):
        active_flags.append("URG")
    return ",".join(active_flags)


class PacketInspector:
    """Real-time packet inspection engine that classifies individual network packets into
    HARMFUL, SUSPICIOUS, or NORMAL with explicit SOC-grade explainability.
    """

    def __init__(self, target_ip: str) -> None:
        self.target_ip = target_ip.strip()
        self.packets: deque[dict[str, Any]] = deque(maxlen=400)
        self.harmful_packet_count: int = 0
        self.suspicious_packet_count: int = 0
        self.normal_packet_count: int = 0
        self.total_inspected: int = 0

    def inspect_and_record(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int | str,
        length: int,
        tcp_flags: dict[str, bool] | str | None = None,
        ttl: int | None = None,
        tcp_window: int | None = None,
        payload: bytes | None = None,
        timestamp: float | None = None,
        active_attack_category: str | None = None,
        current_pps: float = 0.0,
        current_syn_count: int = 0,
        unique_dst_ports: int = 1,
    ) -> dict[str, Any]:
        """Classify a single packet and store it in the rolling inspection window."""
        self.total_inspected += 1
        ts_float = timestamp if timestamp is not None else datetime.now(timezone.utc).timestamp()
        dt_val = datetime.fromtimestamp(ts_float, tz=timezone.utc)

        src = (src_ip or "").strip()
        dst = (dst_ip or "").strip()
        proto_num = protocol if isinstance(protocol, int) else (6 if protocol == "TCP" else (17 if protocol == "UDP" else 1))
        proto_label = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else "OTHER"))

        # Refined application protocol detection
        if dst_port == 53 or src_port == 53:
            proto_label = "DNS"
        elif dst_port == 443 or src_port == 443:
            proto_label = "HTTPS"
        elif dst_port == 80 or src_port == 80:
            proto_label = "HTTP"
        elif dst_port == 22 or src_port == 22:
            proto_label = "SSH"
        elif dst_port == 445 or src_port == 445:
            proto_label = "SMB"
        elif dst_port == 3389 or src_port == 3389:
            proto_label = "RDP"
        elif dst_port == 23 or src_port == 23:
            proto_label = "Telnet"

        flag_str = _format_tcp_flags(tcp_flags)
        is_syn_only = "SYN" in flag_str and "ACK" not in flag_str
        is_rst = "RST" in flag_str
        is_fin_only = "FIN" in flag_str and "ACK" not in flag_str

        # Payload analysis
        payload_entropy = _shannon_entropy(payload) if payload else 0.0
        payload_preview: str | None = None
        if payload and len(payload) > 0:
            try:
                text = payload[:120].decode("ascii", errors="replace")
                payload_preview = "".join(c if (c.isprintable() or c in " \t\r\n") else "." for c in text).strip()
            except Exception:
                payload_preview = payload[:32].hex()

        # ── CLASSIFICATION LOGIC ───────────────────────────────────────────
        verdict = "NORMAL"
        severity = "benign"
        threat_type = "Benign Traffic"
        reason = "Standard legitimate network transport complying with protocol specification."
        mitre_ref: str | None = None
        remediation_hint: str | None = None
        is_harmful = False

        # RULE 1: TCP Stealth Scans (Illegal Flag Combinations)
        if proto_num == 6:
            if "SYN" in flag_str and "FIN" in flag_str:
                verdict = "HARMFUL"
                severity = "high"
                threat_type = "Malformed TCP (SYN+FIN Scan)"
                reason = "Illegal TCP flag combination (SYN and FIN set simultaneously). Classic stealth evasion technique used to map listening ports while evading stateful firewalls."
                mitre_ref = "T1046 (Network Service Discovery)"
                remediation_hint = "Configure host firewall (pfctl / iptables) to drop invalid TCP flag combinations (`tcp-flags SYN,FIN SYN,FIN`)."
                is_harmful = True
            elif "FIN" in flag_str and "PSH" in flag_str and "URG" in flag_str:
                verdict = "HARMFUL"
                severity = "high"
                threat_type = "Stealth Xmas Scan Probe"
                reason = "Xmas tree scan signature detected (FIN, PSH, and URG flags set). Designed to elicit closed-port responses without logging standard connection handshakes."
                mitre_ref = "T1046 (Network Service Discovery)"
                remediation_hint = "Drop unsolicited packets with FIN, PSH, URG flags enabled on border interfaces."
                is_harmful = True
            elif flag_str == "" and length == 40:
                verdict = "HARMFUL"
                severity = "high"
                threat_type = "Null Flag Scan Probe"
                reason = "NULL scan signature (TCP segment with no control flags set). Probes TCP stack response behavior to infer open ports."
                mitre_ref = "T1046 (Network Service Discovery)"
                remediation_hint = "Filter out packets with all TCP flags cleared (`tcp-flags ALL NONE`)."
                is_harmful = True

        # RULE 2: DoS / TCP SYN Flood Packet
        if not is_harmful and proto_num == 6 and is_syn_only:
            if (active_attack_category == "DoS") or (current_syn_count > 100) or (current_pps > 400.0):
                verdict = "HARMFUL"
                severity = "critical"
                threat_type = "DoS / TCP SYN Flood Packet"
                reason = f"Unacknowledged TCP SYN packet targeting port {dst_port}. Part of an elevated volumetric connection burst ({current_syn_count} SYNs observed) exhausting TCP half-open connection queues."
                mitre_ref = "Network Denial of Service: Direct Network Flood (T1498.001) / CAPEC-486"
                remediation_hint = f"Enable TCP SYN cookies (`sysctl -w net.ipv4.tcp_syncookies=1`) and rate-limit inbound SYN packets on port {dst_port}."
                is_harmful = True
            elif current_syn_count > 30 and unique_dst_ports > 3:
                verdict = "SUSPICIOUS"
                severity = "high"
                threat_type = "Elevated SYN Probing"
                reason = f"High-frequency SYN probe to port {dst_port} without completed handshake."
                mitre_ref = "T1046 (Network Service Discovery)"
                remediation_hint = "Monitor source IP connection rate and enforce firewall connection limits."

        # RULE 3: Port Scan / Reconnaissance Probe
        if not is_harmful:
            is_sensitive_port = dst_port in SENSITIVE_PORTS
            if (active_attack_category == "PortScan") or (unique_dst_ports >= 5 and is_syn_only):
                port_desc = SENSITIVE_PORTS.get(dst_port, f"Port {dst_port}")
                verdict = "HARMFUL"
                severity = "high"
                threat_type = f"Port Scan Probe ({port_desc.split(' ')[0]})"
                reason = f"Active reconnaissance probe sent to {dst}:{dst_port} ({port_desc}). The sender is surveying listening services across the target to discover exploitable vulnerabilities."
                mitre_ref = "Network Service Discovery (T1046)"
                remediation_hint = f"Restrict access to port {dst_port} using firewall rules. Disable unneeded listening daemons."
                is_harmful = True
            elif is_sensitive_port and dst_port in (23, 445, 139, 3389, 5900, 21):
                port_desc = SENSITIVE_PORTS[dst_port]
                verdict = "SUSPICIOUS"
                severity = "medium"
                threat_type = f"Sensitive Service Probe ({port_desc.split(' ')[0]})"
                reason = f"Traffic targeting sensitive management/sharing port {dst_port} ({port_desc}). Unencrypted or high-risk administrative protocol exposed to network."
                mitre_ref = "Exploit Public-Facing Application (T1190) / T1046"
                remediation_hint = f"Ensure port {dst_port} is strictly isolated to trusted internal administrative subnets only."

        # RULE 4: Volumetric Bandwidth Flooding
        if not is_harmful and self.total_inspected >= 30:
            if current_pps > 600.0 or (length >= 1400 and current_pps > 250.0):
                verdict = "HARMFUL"
                severity = "critical"
                threat_type = "Volumetric Burst Packet"
                reason = f"High-bandwidth packet ({length} bytes) transmitted during an extreme volumetric traffic surge ({current_pps:.1f} pkts/s)."
                mitre_ref = "Network Denial of Service (T1498)"
                remediation_hint = "Apply network traffic shaping or upstream ISP DDoS filtering."
                is_harmful = True

        # RULE 5: High Entropy / Suspicious Payload
        if not is_harmful and payload_entropy > 7.1 and length > 64 and dst_port not in (443, 8443, 22):
            verdict = "SUSPICIOUS"
            severity = "medium"
            threat_type = "High-Entropy Obfuscated Payload"
            reason = f"Unusual high Shannon entropy ({payload_entropy:.2f} bits/byte) on non-TLS port {dst_port}. Typical indicator of encrypted command-and-control payloads or obfuscated shellcode."
            mitre_ref = "Obfuscated Files or Information (T1027)"
            remediation_hint = "Inspect application payload at endpoint level with Deep Packet Inspection (DPI) or EDR."

        # RULE 6: Insecure Cleartext Protocol Exposure
        if not is_harmful and verdict == "NORMAL" and dst_port in (23, 21, 80):
            if payload_preview and any(kw in payload_preview.lower() for kw in ("pass", "user", "login", "auth", "token", "key")):
                verdict = "SUSPICIOUS"
                severity = "high"
                threat_type = "Cleartext Credential Exposure"
                reason = f"Unencrypted {proto_label} packet on port {dst_port} transmitting potential authentication keywords in cleartext."
                mitre_ref = "Unsecured Credentials (T1552) / CWE-319"
                remediation_hint = "Enforce TLS encryption (HTTPS/SSH) and deprecate cleartext transmission protocols."
            elif dst_port == 23:
                verdict = "SUSPICIOUS"
                severity = "medium"
                threat_type = "Unencrypted Telnet Transmission"
                reason = "Telnet transmits all sessions, usernames, and passwords in plain text vulnerable to network eavesdropping."
                mitre_ref = "Cleartext Transmission of Sensitive Information (CWE-319)"
                remediation_hint = "Migrate administration from Telnet (port 23) to SSH (port 22)."

        # Tally stats
        if is_harmful:
            self.harmful_packet_count += 1
        elif verdict == "SUSPICIOUS":
            self.suspicious_packet_count += 1
        else:
            self.normal_packet_count += 1

        record = {
            "id": str(uuid.uuid4()),
            "timestamp": dt_val,
            "src_ip": src,
            "src_port": src_port,
            "dst_ip": dst,
            "dst_port": dst_port,
            "protocol": proto_label,
            "length": length,
            "tcp_flags": flag_str or None,
            "severity": severity,
            "verdict": verdict,
            "threat_type": threat_type,
            "reason": reason,
            "mitre_ref": mitre_ref,
            "payload_preview": payload_preview,
            "is_harmful": is_harmful,
            "remediation_hint": remediation_hint,
        }

        self.packets.append(record)
        return record

    def get_flagged_packets(
        self,
        limit: int = 100,
        filter_verdict: str | None = None,
    ) -> list[FlaggedPacketOut]:
        """Return inspected packets prioritizing HARMFUL and SUSPICIOUS packets first."""
        all_pkts = list(self.packets)

        if filter_verdict:
            fv_upper = filter_verdict.upper()
            if fv_upper == "HARMFUL":
                all_pkts = [p for p in all_pkts if p["is_harmful"] or p["verdict"] == "HARMFUL"]
            elif fv_upper == "SUSPICIOUS":
                all_pkts = [p for p in all_pkts if p["verdict"] == "SUSPICIOUS"]
            elif fv_upper == "NORMAL":
                all_pkts = [p for p in all_pkts if p["verdict"] == "NORMAL"]

        # Sort: HARMFUL first, then SUSPICIOUS, then newest timestamp
        def _sort_key(p: dict[str, Any]) -> tuple[int, float]:
            priority = 0 if p["is_harmful"] else (1 if p["verdict"] == "SUSPICIOUS" else 2)
            ts = p["timestamp"].timestamp() if isinstance(p["timestamp"], datetime) else 0.0
            return (priority, -ts)

        all_pkts.sort(key=_sort_key)

        out: list[FlaggedPacketOut] = []
        for p in all_pkts[:limit]:
            out.append(
                FlaggedPacketOut(
                    id=p["id"],
                    timestamp=p["timestamp"],
                    src_ip=p["src_ip"],
                    src_port=p["src_port"],
                    dst_ip=p["dst_ip"],
                    dst_port=p["dst_port"],
                    protocol=p["protocol"],
                    length=p["length"],
                    tcp_flags=p.get("tcp_flags"),
                    severity=p["severity"],
                    verdict=p["verdict"],
                    threat_type=p["threat_type"],
                    reason=p["reason"],
                    mitre_ref=p.get("mitre_ref"),
                    payload_preview=p.get("payload_preview"),
                    is_harmful=p["is_harmful"],
                    remediation_hint=p.get("remediation_hint"),
                )
            )
        return out
