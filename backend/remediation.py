"""
Remediation engine for DDoS Shield.

Provides actionable fix recommendations for each vulnerability found
during security assessment, including:
- Risk description and impact
- Step-by-step fix instructions
- CLI commands to run
- Auto-fix support (in simulation: marks as fixed)
- Firewall rule suggestions
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger("ddos_shield.remediation")


# ---------------------------------------------------------------------------
# Remediation recommendation types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Remediation:
    """A single remediation action for a vulnerability."""
    vuln_id: str
    category: str  # close_port, update_service, enable_encryption, firewall, credentials, segmentation
    risk_level: str
    title: str
    description: str
    impact: str
    steps: tuple[str, ...]
    commands: tuple[str, ...]
    firewall_rule: str
    estimated_effort: str  # quick, moderate, complex
    auto_fixable: bool

    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id,
            "category": self.category,
            "risk_level": self.risk_level,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "steps": list(self.steps),
            "commands": list(self.commands),
            "firewall_rule": self.firewall_rule,
            "estimated_effort": self.estimated_effort,
            "auto_fixable": self.auto_fixable,
        }


# ---------------------------------------------------------------------------
# Remediation database keyed by service name
# ---------------------------------------------------------------------------

_REMEDIATION_DB: dict[str, dict] = {
    "telnet": {
        "category": "close_port",
        "title": "Disable Telnet — use SSH instead",
        "description": (
            "Telnet transmits all data including credentials in plaintext. "
            "Any attacker on the network can capture login sessions."
        ),
        "impact": "Eliminates plaintext credential exposure and remote command injection risk",
        "steps": (
            "1. Verify SSH is available on the device (port 22)",
            "2. Connect via SSH to confirm access",
            "3. Disable the Telnet service",
            "4. Block port 23 in the firewall",
            "5. Verify Telnet is no longer accessible",
        ),
        "commands": (
            "sudo systemctl stop telnet.socket",
            "sudo systemctl disable telnet.socket",
            "sudo ufw deny 23/tcp",
            "sudo ufw reload",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 23 -j DROP",
        "effort": "quick",
        "auto_fixable": True,
    },
    "ftp": {
        "category": "update_service",
        "title": "Replace FTP with SFTP/SCP",
        "description": (
            "FTP transmits credentials and files in plaintext. "
            "Replace with SFTP (SSH File Transfer Protocol) for encrypted transfers."
        ),
        "impact": "Prevents credential sniffing and file interception during transfers",
        "steps": (
            "1. Ensure SSH/SFTP is enabled on the server",
            "2. Test SFTP access with existing SSH credentials",
            "3. Migrate FTP users to SFTP accounts",
            "4. Disable the FTP service",
            "5. Block port 21 in the firewall",
        ),
        "commands": (
            "sudo systemctl stop vsftpd",
            "sudo systemctl disable vsftpd",
            "sudo ufw deny 21/tcp",
            "sudo ufw deny 20/tcp",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 21 -j DROP",
        "effort": "moderate",
        "auto_fixable": True,
    },
    "snmp": {
        "category": "update_service",
        "title": "Upgrade to SNMPv3 with authentication",
        "description": (
            "SNMP v1/v2c use community strings sent in plaintext. "
            "SNMPv3 adds authentication and encryption."
        ),
        "impact": "Prevents unauthorized network device monitoring and configuration changes",
        "steps": (
            "1. Check current SNMP version on the device",
            "2. Configure SNMPv3 with auth (SHA) and privacy (AES)",
            "3. Remove default community strings ('public', 'private')",
            "4. Restrict SNMP access to management subnet only",
            "5. Test monitoring with SNMPv3 credentials",
        ),
        "commands": (
            "sudo net-snmp-config --create-snmpv3-user -a SHA -x AES -A authpass -X privpass admin",
            "sudo sed -i 's/^rocommunity/#rocommunity/' /etc/snmp/snmpd.conf",
            "sudo systemctl restart snmpd",
        ),
        "firewall_rule": "iptables -A INPUT -p udp --dport 161 -s ! 192.168.1.0/24 -j DROP",
        "effort": "moderate",
        "auto_fixable": False,
    },
    "rdp": {
        "category": "enable_encryption",
        "title": "Secure RDP with NLA and VPN",
        "description": (
            "RDP exposed to the network is a primary target for brute-force "
            "and exploit attacks (BlueKeep, etc.)."
        ),
        "impact": "Prevents unauthorized remote access and known RDP exploits",
        "steps": (
            "1. Enable Network Level Authentication (NLA) in Windows settings",
            "2. Restrict RDP to specific IP ranges via firewall",
            "3. Require VPN connection before RDP access",
            "4. Enable account lockout after 5 failed attempts",
            "5. Keep Windows fully patched (especially KB updates for RDP)",
        ),
        "commands": (
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f',
            "netsh advfirewall firewall add rule name='RDP-Restrict' dir=in action=allow protocol=TCP localport=3389 remoteip=192.168.1.0/24",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 3389 -s ! 192.168.1.0/24 -j DROP",
        "effort": "moderate",
        "auto_fixable": False,
    },
    "smb": {
        "category": "update_service",
        "title": "Restrict SMB and disable SMBv1",
        "description": (
            "SMB has been exploited by WannaCry (EternalBlue) and other major attacks. "
            "SMBv1 is especially dangerous and should be disabled."
        ),
        "impact": "Prevents EternalBlue-class attacks and unauthorized file share access",
        "steps": (
            "1. Disable SMBv1 protocol on all devices",
            "2. Restrict SMB access to internal network only",
            "3. Require SMB signing (prevents relay attacks)",
            "4. Apply all Windows security patches",
            "5. Audit share permissions and remove unnecessary shares",
        ),
        "commands": (
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
            "sudo ufw deny from any to any port 445",
            "sudo ufw allow from 192.168.1.0/24 to any port 445",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 445 -s ! 192.168.1.0/24 -j DROP",
        "effort": "moderate",
        "auto_fixable": True,
    },
    "redis": {
        "category": "credentials",
        "title": "Enable Redis authentication and bind to localhost",
        "description": (
            "Redis without authentication allows arbitrary command execution "
            "including writing files to disk (used for RCE attacks)."
        ),
        "impact": "Prevents unauthorized data access and remote code execution",
        "steps": (
            "1. Edit redis.conf to set a strong password",
            "2. Bind Redis to 127.0.0.1 (localhost only)",
            "3. Rename dangerous commands (FLUSHALL, CONFIG, etc.)",
            "4. Restart Redis service",
            "5. Update application connection strings with password",
        ),
        "commands": (
            "sudo sed -i 's/# requirepass foobared/requirepass YOUR_STRONG_PASSWORD/' /etc/redis/redis.conf",
            "sudo sed -i 's/bind 0.0.0.0/bind 127.0.0.1/' /etc/redis/redis.conf",
            "sudo systemctl restart redis",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 6379 -s ! 127.0.0.1 -j DROP",
        "effort": "quick",
        "auto_fixable": True,
    },
    "mongodb": {
        "category": "credentials",
        "title": "Enable MongoDB authentication",
        "description": (
            "MongoDB without authentication exposes the entire database "
            "to anyone who can reach the port."
        ),
        "impact": "Prevents unauthorized database access and data exfiltration",
        "steps": (
            "1. Create an admin user with strong password",
            "2. Enable authentication in mongod.conf",
            "3. Bind to localhost or private network interface",
            "4. Restart MongoDB",
            "5. Update application connection strings",
        ),
        "commands": (
            "mongosh --eval \"db.createUser({user:'admin', pwd:'STRONG_PASS', roles:['root']})\"",
            "sudo sed -i 's/#security:/security:\\n  authorization: enabled/' /etc/mongod.conf",
            "sudo systemctl restart mongod",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 27017 -s ! 127.0.0.1 -j DROP",
        "effort": "quick",
        "auto_fixable": True,
    },
    "http": {
        "category": "enable_encryption",
        "title": "Enable HTTPS and redirect HTTP",
        "description": (
            "HTTP transmits all data in plaintext. Enable HTTPS with TLS "
            "to encrypt data in transit."
        ),
        "impact": "Prevents data interception and man-in-the-middle attacks on web traffic",
        "steps": (
            "1. Obtain a TLS certificate (Let's Encrypt is free)",
            "2. Configure the web server for HTTPS (port 443)",
            "3. Set up HTTP-to-HTTPS redirect",
            "4. Enable HSTS header for strict transport security",
            "5. Test with SSL Labs (ssllabs.com/ssltest)",
        ),
        "commands": (
            "sudo certbot --nginx -d yourdomain.com",
            "sudo nginx -t && sudo systemctl reload nginx",
        ),
        "firewall_rule": "",
        "effort": "moderate",
        "auto_fixable": False,
    },
    "mqtt": {
        "category": "credentials",
        "title": "Enable MQTT authentication and TLS",
        "description": (
            "MQTT brokers without authentication allow anyone to subscribe "
            "to all topics and publish malicious commands to IoT devices."
        ),
        "impact": "Prevents unauthorized IoT device control and data interception",
        "steps": (
            "1. Configure password file for Mosquitto",
            "2. Set allow_anonymous to false",
            "3. Generate TLS certificates for encrypted connections",
            "4. Configure listener for port 8883 (MQTT over TLS)",
            "5. Update all IoT devices with credentials",
        ),
        "commands": (
            "sudo mosquitto_passwd -c /etc/mosquitto/passwd iot_user",
            "echo 'allow_anonymous false' | sudo tee -a /etc/mosquitto/conf.d/auth.conf",
            "echo 'password_file /etc/mosquitto/passwd' | sudo tee -a /etc/mosquitto/conf.d/auth.conf",
            "sudo systemctl restart mosquitto",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 1883 -s ! 192.168.1.0/24 -j DROP",
        "effort": "moderate",
        "auto_fixable": False,
    },
    "vnc": {
        "category": "enable_encryption",
        "title": "Tunnel VNC through SSH",
        "description": (
            "VNC often uses weak authentication and no encryption. "
            "All screen data and keystrokes are visible to network sniffers."
        ),
        "impact": "Prevents credential capture and screen data interception",
        "steps": (
            "1. Restrict VNC to listen on localhost only",
            "2. Set up SSH tunneling for VNC access",
            "3. Set a strong VNC password",
            "4. Block port 5900 from external access",
            "5. Consider replacing VNC with a more secure alternative",
        ),
        "commands": (
            "ssh -L 5900:localhost:5900 user@server",
            "sudo ufw deny 5900/tcp",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 5900 -s ! 127.0.0.1 -j DROP",
        "effort": "quick",
        "auto_fixable": True,
    },
    "elasticsearch": {
        "category": "credentials",
        "title": "Enable Elasticsearch security features",
        "description": (
            "Elasticsearch without authentication exposes all indexed data "
            "and allows remote code execution through scripting."
        ),
        "impact": "Prevents unauthorized data access and search cluster manipulation",
        "steps": (
            "1. Enable X-Pack security in elasticsearch.yml",
            "2. Set up built-in user passwords",
            "3. Configure TLS for transport and HTTP layers",
            "4. Bind to private interface only",
            "5. Restrict network access to application servers",
        ),
        "commands": (
            "echo 'xpack.security.enabled: true' >> /etc/elasticsearch/elasticsearch.yml",
            "bin/elasticsearch-setup-passwords auto",
            "sudo systemctl restart elasticsearch",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 9200 -s ! 192.168.1.0/24 -j DROP",
        "effort": "moderate",
        "auto_fixable": False,
    },
    "memcached": {
        "category": "close_port",
        "title": "Bind Memcached to localhost and disable UDP",
        "description": (
            "Memcached exposed to the internet can be used for massive "
            "DDoS amplification attacks (up to 50,000x amplification factor)."
        ),
        "impact": "Prevents DDoS amplification abuse and unauthorized cache access",
        "steps": (
            "1. Bind Memcached to 127.0.0.1 only",
            "2. Disable UDP listener (used in amplification)",
            "3. Restrict access with firewall rules",
            "4. Restart Memcached",
        ),
        "commands": (
            "sudo sed -i 's/-l 0.0.0.0/-l 127.0.0.1/' /etc/memcached.conf",
            "echo '-U 0' | sudo tee -a /etc/memcached.conf",
            "sudo systemctl restart memcached",
        ),
        "firewall_rule": "iptables -A INPUT -p tcp --dport 11211 -s ! 127.0.0.1 -j DROP",
        "effort": "quick",
        "auto_fixable": True,
    },
}

# Generic remediation for unknown risky ports
_GENERIC_CLOSE_PORT = {
    "category": "close_port",
    "title": "Close unnecessary port",
    "description": "This port exposes a service that may not be needed. Close it to reduce attack surface.",
    "impact": "Reduces the device's attack surface",
    "steps": (
        "1. Verify if the service on this port is needed",
        "2. If not needed, stop and disable the service",
        "3. Block the port in the firewall",
        "4. Verify the port is no longer accessible",
    ),
    "commands": (),
    "firewall_rule": "",
    "effort": "quick",
    "auto_fixable": True,
}


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def get_remediation(service: str, port: int, risk_level: str) -> Remediation:
    """
    Get a remediation recommendation for a specific vulnerability.
    """
    db_entry = _REMEDIATION_DB.get(service.lower(), _GENERIC_CLOSE_PORT)

    vuln_id = f"{service}-{port}"
    fw_rule = db_entry.get("firewall_rule", "")
    if not fw_rule and port:
        fw_rule = f"iptables -A INPUT -p tcp --dport {port} -j DROP"

    commands = db_entry.get("commands", ())
    if not commands and port:
        commands = (
            f"sudo ufw deny {port}/tcp",
            "sudo ufw reload",
        )

    return Remediation(
        vuln_id=vuln_id,
        category=db_entry["category"],
        risk_level=risk_level,
        title=db_entry["title"],
        description=db_entry["description"],
        impact=db_entry.get("impact", "Reduces security risk"),
        steps=tuple(db_entry.get("steps", ())),
        commands=tuple(commands),
        firewall_rule=fw_rule,
        estimated_effort=db_entry.get("effort", "moderate"),
        auto_fixable=db_entry.get("auto_fixable", False),
    )


def get_device_remediations(
    ip: str,
    mac: str,
    vulnerabilities: list[dict],
) -> list[dict]:
    """
    Get all remediation recommendations for a device's vulnerabilities.
    """
    remediations = []
    for vuln in vulnerabilities:
        rem = get_remediation(
            service=vuln.get("service", "unknown"),
            port=vuln.get("port", 0),
            risk_level=vuln.get("risk_level", "LOW"),
        )
        remediations.append({
            **rem.to_dict(),
            "device_ip": ip,
            "device_mac": mac,
        })
    return remediations


# ---------------------------------------------------------------------------
# Auto-fix tracking (simulation only)
# ---------------------------------------------------------------------------

_applied_fixes: dict[str, list[str]] = {}  # ip -> list of vuln_ids


def apply_fix(ip: str, vuln_id: str) -> dict:
    """
    Mark a vulnerability as fixed (simulation mode).

    In real mode, this would execute the actual commands.
    In simulation, it just records the fix.
    """
    fixes = _applied_fixes.setdefault(ip, [])
    if vuln_id not in fixes:
        fixes.append(vuln_id)

    logger.info("Applied fix %s on %s", vuln_id, ip)
    return {
        "success": True,
        "ip": ip,
        "vuln_id": vuln_id,
        "message": f"Fix applied: {vuln_id}",
        "applied_fixes": list(fixes),
    }


def get_applied_fixes(ip: str | None = None) -> dict:
    """Get list of applied fixes, optionally filtered by IP."""
    if ip:
        return {"ip": ip, "fixes": list(_applied_fixes.get(ip, []))}
    return dict(_applied_fixes)


# ---------------------------------------------------------------------------
# Firewall rule suggestions
# ---------------------------------------------------------------------------

def get_firewall_suggestions(assessments: list[dict]) -> list[dict]:
    """
    Generate firewall rule suggestions based on all vulnerability assessments.
    """
    rules: list[dict] = []
    seen_ports: set[int] = set()

    for assessment in assessments:
        for vuln in assessment.get("vulnerabilities", []):
            port = vuln.get("port", 0)
            service = vuln.get("service", "")
            risk = vuln.get("risk_level", "LOW")

            if port in seen_ports:
                continue
            seen_ports.add(port)

            if risk in ("CRITICAL", "HIGH"):
                rem = get_remediation(service, port, risk)
                if rem.firewall_rule:
                    rules.append({
                        "port": port,
                        "service": service,
                        "risk_level": risk,
                        "rule_iptables": rem.firewall_rule,
                        "rule_ufw": f"sudo ufw deny {port}/tcp" if port else "",
                        "rule_pfctl": f"block in on egress proto tcp from any to any port {port}" if port else "",
                        "description": rem.title,
                        "applied": False,
                    })

    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rules.sort(key=lambda r: risk_order.get(r["risk_level"], 9))
    return rules
