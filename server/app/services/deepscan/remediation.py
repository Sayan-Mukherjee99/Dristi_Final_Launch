# Drishti v0.1 — Deep Scan Service Vulnerability & Remediation Engine
"""Enriches detected open ports & services with vulnerability scores, CVE associations,
finding states, and actionable remediation solutions."""
from __future__ import annotations

from typing import Any


def enrich_service_port(
    svc: dict[str, Any],
    all_cves: list[dict[str, Any]],
) -> dict[str, Any]:
    """Enriches a detected service/port dict with vulnerability score, severity, status,
    associated CVEs, and a clear, actionable remediation solution."""
    port = int(svc.get("port", 0))
    proto = str(svc.get("protocol", "tcp")).lower()
    s_name = str(svc.get("service_name") or "").lower()
    prod = str(svc.get("product") or "").lower()
    ver = str(svc.get("version") or "").strip()

    # Match CVEs to this specific port / service
    matched_cves: list[dict[str, Any]] = []
    for c in all_cves:
        c_port = c.get("port")
        c_aff = str(c.get("affected_service") or "").lower()
        if c_port is not None and int(c_port) == port:
            matched_cves.append(c)
        elif prod and prod in c_aff:
            matched_cves.append(c)
        elif s_name and s_name in c_aff:
            matched_cves.append(c)

    # Sort matching CVEs by CVSS descending
    matched_cves.sort(key=lambda x: float(x.get("cvss", 0.0)), reverse=True)
    cve_ids = [c["id"] for c in matched_cves if "id" in c]

    if matched_cves:
        top_cve = matched_cves[0]
        vuln_score = round(float(top_cve.get("cvss", 7.0)), 1)
        sev = str(top_cve.get("severity") or "high").lower()
        state = "VULNERABLE"
        cve_names = ", ".join(cve_ids[:2])
        prod_display = svc.get("product") or svc.get("service_name") or f"port {port}"
        solution = (
            f"Upgrade {prod_display} to the latest security patch release to resolve {cve_names}. "
            f"If patching cannot be performed immediately, restrict network access to port {port} "
            f"using host firewall rules or network segmentation."
        )
        steps = [
            f"Update {prod_display} using the official system package manager or vendor repository.",
            f"Restrict inbound access on port {port}/{proto} to authorized administrative IPs only.",
            "Review service configuration to disable unauthenticated or deprecated legacy features.",
            "Verify remediated port status by executing a follow-up Drishti deep scan.",
        ]
    else:
        # Check known high-risk / cleartext exposure ports
        if port == 23:
            vuln_score = 7.5
            sev = "high"
            state = "EXPOSED"
            solution = "Immediately disable and remove the Telnet service. Telnet transmits all data, including credentials, in unencrypted cleartext."
            steps = [
                "Stop and disable telnet daemon (`sudo systemctl disable --now telnet.socket` or telnetd).",
                "Switch all remote terminal administration to encrypted SSH (port 22).",
                "Block inbound port 23 on the device and network firewalls.",
            ]
        elif port in (445, 139):
            vuln_score = 7.0
            sev = "high"
            state = "EXPOSED"
            solution = "Disable SMBv1 legacy protocol, enforce SMB signing and encryption (SMB 3.1.1), and restrict SMB access strictly to the local LAN."
            steps = [
                "Verify SMBv1 is disabled (`Set-SmbServerConfiguration -EnableSMB1Protocol $false` or in smb.conf).",
                "Block TCP ports 445 and 139 at the internet boundary router.",
                "Enforce SMB encryption and signing for all file share clients.",
            ]
        elif port == 3389:
            vuln_score = 6.5
            sev = "medium"
            state = "EXPOSED"
            solution = "Protect Remote Desktop Protocol (RDP) by mandating Network Level Authentication (NLA), enforcing multi-factor authentication (MFA), and tunneling via VPN."
            steps = [
                "Enable 'Require computers to use Network Level Authentication' in System Remote Settings.",
                "Never expose port 3389 directly to the public internet.",
                "Enforce strong password policies, account lockout thresholds, and MFA.",
            ]
        elif port == 5900:
            vuln_score = 6.0
            sev = "medium"
            state = "EXPOSED"
            solution = "VNC carries risk of cleartext authentication and screen eavesdropping. Enforce strong VNC passwords and tunnel VNC over SSH or VPN."
            steps = [
                "Bind VNC server strictly to localhost (127.0.0.1:5900).",
                "Access VNC remotely only through an encrypted SSH tunnel (`ssh -L 5900:localhost:5900 user@host`).",
                "Update VNC server software to the latest release.",
            ]
        elif port == 21:
            vuln_score = 5.3
            sev = "medium"
            state = "EXPOSED"
            solution = "Disable cleartext FTP service. FTP passes usernames and passwords across the wire in plaintext."
            steps = [
                "Migrate file transfer workflows to SFTP (over SSH port 22).",
                "If FTP is required, configure FTPS (FTP over TLS) with mandatory explicit encryption.",
                "Disable anonymous FTP logins and unnecessary user accounts.",
            ]
        elif port == 80:
            vuln_score = 4.0
            sev = "medium"
            state = "EXPOSED"
            solution = "Unencrypted HTTP traffic is vulnerable to interception. Enforce an automatic 301 Permanent Redirect to HTTPS (port 443) and enable HSTS."
            steps = [
                "Configure web server to redirect all HTTP requests on port 80 to https:// (port 443).",
                "Install a valid SSL/TLS certificate (e.g., via Let's Encrypt / Certbot).",
                "Add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
            ]
        elif port == 22:
            vuln_score = 0.0
            sev = "secure"
            state = "SECURE"
            solution = "SSH service detected. Maintain strong security posture by disabling password authentication and enforcing public-key (Ed25519) logins."
            steps = [
                "Ensure 'PasswordAuthentication no' and 'PermitRootLogin no' are configured in /etc/ssh/sshd_config.",
                "Use modern SSH key pairs (ssh-keygen -t ed25519).",
                "Deploy fail2ban or firewall rate-limiting to prevent brute-force attempts.",
            ]
        elif port == 443:
            vuln_score = 0.0
            sev = "secure"
            state = "SECURE"
            solution = "Encrypted HTTPS service detected. Keep TLS configuration hardened to TLS 1.2+ (preferably TLS 1.3) and maintain valid certificates."
            steps = [
                "Verify deprecation of TLS 1.0 and TLS 1.1 in web server configuration.",
                "Automate SSL/TLS certificate renewal before expiration.",
                "Use strong cipher suites and enable OCSP stapling.",
            ]
        elif port == 53:
            vuln_score = 0.0
            sev = "secure"
            state = "SECURE"
            solution = "DNS service detected. Restrict recursive lookups to authorized local clients only to prevent DNS amplification and poisoning."
            steps = [
                "Disable open DNS recursion or restrict recursion to the local subnet.",
                "Enable DNSSEC validation on the DNS resolver.",
                "Keep DNS server software updated.",
            ]
        else:
            vuln_score = 0.0
            sev = "secure"
            state = "SECURE"
            s_label = svc.get("service_name") or f"port {port}"
            solution = f"Open port {port} ({s_label}) detected with no known vulnerabilities. Ensure the service is only exposed to authorized network segments."
            steps = [
                f"Verify whether {s_label} needs to be listening on external interfaces or can be bound to localhost (127.0.0.1).",
                f"Implement firewall rules to restrict access to port {port}/{proto} from trusted IP ranges only.",
                "Ensure the underlying software package is regularly updated with vendor security patches.",
            ]

    return {
        **svc,
        "vulnerability_score": vuln_score,
        "severity": sev,
        "finding_state": state,
        "cve_ids": cve_ids,
        "cves": matched_cves,
        "solution": solution,
        "remediation_steps": steps,
    }
