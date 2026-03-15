import os
import json
import time
import uuid
import re
import threading
import socket
import paramiko
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template, request, Response, stream_with_context, jsonify
from openai import OpenAI

try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    print("[WARNING] netmiko not installed. Run: pip install netmiko")

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

# ── In-memory store ────────────────────────────────────────────────────────────
security_events = []
chat_sessions   = {}
source_status   = {
    "suricata":  {"connected": False, "last_update": None, "error": None},
    "auth":      {"connected": False, "last_update": None, "error": None},
    "syslog":    {"connected": False, "last_update": None, "error": None},
    "ufw":       {"connected": False, "last_update": None, "error": None},
    "kern":      {"connected": False, "last_update": None, "error": None},
    "cisco":     {"connected": False, "last_update": None, "error": None},
    "fortigate": {"connected": False, "last_update": None, "error": None},
    "syslog_rx": {"connected": False, "last_update": None, "error": None},
}

# ── Threat Intelligence ────────────────────────────────────────────────────────
ip_activity = defaultdict(lambda: {
    "auth_failures": [],
    "port_scan_ports": set(),
    "port_scan_times": [],
    "ufw_blocks": [],
    "ufw_block_ports": [],
    "ssh_attempts": [],
    "icmp_times": [],
    "first_seen": None,
    "last_seen": None,
    "total_events": 0,
    "flagged": False,
    "slow_scan_alerted": False,
    "alerted_types": set(),
    "alert_cooldown": {},
    "brute_force_count": 0,
})

pending_alerts = []
alert_lock = threading.Lock()

# ── Blocked / Rate-limited IP store ───────────────────────────────────────────
managed_ips = {}  # ip -> {ip, mode, device_id, timestamp, command, active}
managed_ips_lock = threading.Lock()

# ── Device Registry ────────────────────────────────────────────────────────────
device_registry = {}
device_registry_lock = threading.Lock()

def register_device(device_id, device_type, host, username, password, secret="", name=""):
    with device_registry_lock:
        device_registry[device_id] = {
            "id": device_id,
            "name": name or host,
            "type": device_type,   # cisco_ios, fortigate, linux
            "host": host,
            "username": username,
            "password": password,
            "secret": secret,
            "connected": False,
            "last_seen": None,
            "error": None,
        }

# Pre-register Ubuntu server
UBUNTU_HOST    = os.environ.get("UBUNTU_HOST",    "192.168.100.20")
WINDOWS_HOST   = os.environ.get("WINDOWS_HOST",   "192.168.100.1")
UBUNTU_USER    = os.environ.get("UBUNTU_USER",    "ventiator")
UBUNTU_PASS    = os.environ.get("UBUNTU_PASS",    "12345")
FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "192.168.108.200")
FORTIGATE_USER = os.environ.get("FORTIGATE_USER", "admin")
FORTIGATE_PASS = os.environ.get("FORTIGATE_PASS", "Hackathon2026!")

register_device("ubuntu-main", "linux", UBUNTU_HOST, UBUNTU_USER, UBUNTU_PASS,
                name=f"Ubuntu Server ({UBUNTU_HOST})")

register_device("fortigate-main", "fortigate", FORTIGATE_HOST, FORTIGATE_USER, FORTIGATE_PASS,
                name=f"Fortigate FW ({FORTIGATE_HOST})")

LOG_SOURCES = {
    "suricata": "/var/log/suricata/eve.json",
    "auth":     "/var/log/auth.log",
    "syslog":   "/var/log/syslog",
    "ufw":      "/var/log/ufw.log",
    "kern":     "/var/log/kern.log",
}

SURICATA_SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


# ── IP Activity Tracking ───────────────────────────────────────────────────────
def update_ip_activity(ip: str, event_type: str, event: dict = None):
    if not ip or ip == "unknown":
        return
    now = datetime.utcnow()
    activity = ip_activity[ip]
    if event:
        ts_raw = event.get("timestamp", "")
        try:
            event_time = datetime.fromisoformat(ts_raw.rstrip("Z"))
        except Exception:
            event_time = now
    else:
        event_time = now

    if not activity["first_seen"]:
        activity["first_seen"] = event_time.isoformat()
    current_last = activity["last_seen"]
    if not current_last or event_time.isoformat() > current_last:
        activity["last_seen"] = event_time.isoformat()
    activity["total_events"] += 1

    if event_type == "AUTH_FAILURE":
        activity["auth_failures"].append(event_time)
        activity["auth_failures"] = [t for t in activity["auth_failures"]
                                      if (now - t).total_seconds() < 300]
    elif event_type == "PORT_SCAN":
        activity["port_scan_times"].append(event_time)
        activity["port_scan_times"] = [t for t in activity["port_scan_times"]
                                        if (now - t).total_seconds() < 60]
    elif event_type == "FIREWALL_BLOCK":
        activity["ufw_blocks"].append(event_time)
        activity["ufw_blocks"] = [t for t in activity["ufw_blocks"]
                                   if (now - t).total_seconds() < 300]
        dest_port = (event or {}).get("dest_port", 0)
        activity["ufw_block_ports"].append((event_time, dest_port))
        activity["ufw_block_ports"] = [(t, p) for t, p in activity["ufw_block_ports"]
                                        if (now - t).total_seconds() < 600]
    elif event_type in ("AUTH_FAILURE", "SSH"):
        activity["ssh_attempts"].append(event_time)
        activity["ssh_attempts"] = [t for t in activity["ssh_attempts"]
                                     if (now - t).total_seconds() < 300]


# ── Threat Analysis ────────────────────────────────────────────────────────────
def analyze_threats(event: dict):
    ip = event.get("source_ip", "unknown")
    if not ip or ip == "unknown" or ip == UBUNTU_HOST or ip == WINDOWS_HOST:
        return None

    update_ip_activity(ip, event.get("event_type", ""), event)
    activity = ip_activity[ip]
    now = datetime.utcnow()

    # Detect source device type from event
    event_source = event.get("source", "")
    is_fortigate = "fortigate" in event_source.lower()
    is_cisco     = "cisco" in event_source.lower()

    def should_alert(alert_type, cooldown_secs=60):
        last = activity["alert_cooldown"].get(alert_type)
        if last and (now - last).total_seconds() < cooldown_secs:
            return False
        activity["alert_cooldown"][alert_type] = now
        return True

    alerts = []

    if len(activity["auth_failures"]) >= 5:
        activity["brute_force_count"] = len(activity["auth_failures"])
        if should_alert("BRUTE_FORCE_DETECTED", 999999):
            if is_fortigate:
                action = f"config firewall address\nedit BLOCK_{ip}\nset subnet {ip} 255.255.255.255\nnext\nend"
                detail = f"{len(activity['auth_failures'])} failed admin logins from {ip} — Fortigate under attack"
                bf_device_id = get_device_id_from_source(event_source, "fortigate")
            elif is_cisco:
                action = f"ip access-list extended CYBRIXBLOCKLIST\n deny ip host {ip} any log"
                detail = f"{len(activity['auth_failures'])} failed logins from {ip} — Cisco device targeted"
                bf_device_id = get_device_id_from_source(event_source, "cisco_ios")
            else:
                action = f"iptables -A INPUT -s {ip} -j DROP"
                detail = f"{len(activity['auth_failures'])} failed logins in 5 minutes from {ip}"
                bf_device_id = "ubuntu-main"
            alerts.append({
                "type": "BRUTE_FORCE_DETECTED", "severity": "CRITICAL", "ip": ip,
                "detail": detail,
                "action": action,
                "kill_chain": "Credential Access",
                "live_counter_key": f"brute_{ip}",
                "device_source": "fortigate" if is_fortigate else ("cisco" if is_cisco else "linux"),
                "device_id": bf_device_id,
            })

    recent_port_hits = len(activity["port_scan_times"])
    if 2 <= recent_port_hits <= 5:
        alerts.append({
            "type": "SLOW_SCAN_DETECTED", "severity": "HIGH", "ip": ip,
            "detail": f"Low-rate port scan — {recent_port_hits} probes (possible -T0 evasion)",
            "action": f"ufw deny from {ip}",
            "kill_chain": "Reconnaissance",
        })

    unique_ports = set(p for _, p in activity["ufw_block_ports"] if p > 0)
    if len(unique_ports) >= 3 and should_alert("SLOW_SCAN_DETECTED", 120):
        activity["slow_scan_alerted"] = True
        alerts.append({
            "type": "SLOW_SCAN_DETECTED", "severity": "HIGH", "ip": ip,
            "detail": f"Stealthy slow port scan via UFW — {len(unique_ports)} unique ports: {sorted(unique_ports)}",
            "action": f"ufw deny from {ip} && iptables -A INPUT -s {ip} -j DROP",
            "kill_chain": "Reconnaissance (Evasion)",
        })

    if len(activity["ufw_blocks"]) >= 3 and len(activity["ssh_attempts"]) >= 1 and should_alert("PERSISTENT_ATTACKER", 120):
        alerts.append({
            "type": "PERSISTENT_ATTACKER", "severity": "CRITICAL", "ip": ip,
            "detail": f"IP blocked {len(activity['ufw_blocks'])}x by firewall AND attempting SSH — persistent threat",
            "action": f"iptables -A INPUT -s {ip} -j DROP && fail2ban-client set sshd banip {ip}",
            "kill_chain": "Persistence",
        })

    has_scan = len(activity["port_scan_times"]) >= 1
    has_auth = len(activity["auth_failures"]) >= 1
    if has_scan and has_auth and not activity["flagged"] and should_alert("COORDINATED_ATTACK", 300):
        activity["flagged"] = True
        alerts.append({
            "type": "COORDINATED_ATTACK", "severity": "CRITICAL", "ip": ip,
            "detail": f"Same IP doing recon (port scan) AND credential attack — kill chain in progress!",
            "action": f"iptables -A INPUT -s {ip} -j DROP",
            "kill_chain": "Recon → Credential Access",
        })

    if activity["total_events"] >= 50 and should_alert("HIGH_VOLUME_ATTACK", 120):
        alerts.append({
            "type": "HIGH_VOLUME_ATTACK", "severity": "CRITICAL", "ip": ip,
            "detail": f"{activity['total_events']} total events from this IP — possible DoS/flood",
            "action": f"iptables -A INPUT -s {ip} -j DROP",
            "kill_chain": "Impact",
        })

    # Rule 6: Malware detected by Fortigate/Suricata
    if event.get("event_type") == "MALWARE_DETECTED" and should_alert("MALWARE_DETECTED", 300):
        safe_ip = ip.replace(".", "_")
        nl = chr(10)
        if is_fortigate:
            mal_action = f"config firewall address{nl}edit CYBRIX_BLOCK_{safe_ip}{nl}set subnet {ip} 255.255.255.255{nl}next{nl}end"
            mal_device_source = "fortigate"
            mal_device_id = get_device_id_from_source(event_source, "fortigate")
        elif is_cisco:
            mal_action = f"ip access-list extended CYBRIXBLOCKLIST{nl} deny ip host {ip} any log"
            mal_device_source = "cisco"
            mal_device_id = get_device_id_from_source(event_source, "cisco_ios")
        else:
            mal_action = f"iptables -A INPUT -s {ip} -j DROP"
            mal_device_source = "linux"
            mal_device_id = "ubuntu-main"
        alerts.append({
            "type": "MALWARE_DETECTED",
            "severity": "CRITICAL",
            "ip": ip,
            "detail": f"Malware detected from {ip} — {event.get('description', '')[:80]}",
            "action": mal_action,
            "kill_chain": "Delivery / Installation",
            "device_source": mal_device_source,
            "device_id": mal_device_id,
        })

    # Rule 7: IDS/IPS alert from Fortigate/Suricata
    if event.get("event_type") == "IDS_ALERT" and should_alert("IDS_ALERT", 120):
        if is_fortigate:
            ids_action = f"config firewall address\nedit BLOCK_{ip}\nset subnet {ip} 255.255.255.255\nnext\nend"
            ids_device_source = "fortigate"
            ids_device_id = "fortigate-main"
        elif is_cisco:
            ids_action = f"ip access-list extended CYBRIXBLOCKLIST\n deny ip host {ip} any log"
            ids_device_source = "cisco"
            ids_device_id = event.get("source", "")
        else:
            ids_action = f"iptables -A INPUT -s {ip} -j DROP"
            ids_device_source = "linux"
            ids_device_id = "ubuntu-main"
        alerts.append({
            "type": "IDS_ALERT_DETECTED",
            "severity": "HIGH",
            "ip": ip,
            "detail": f"IDS/IPS alert from {ip} — {event.get('description', '')[:80]}",
            "action": ids_action,
            "kill_chain": "Exploitation",
            "device_source": ids_device_source,
            "device_id": ids_device_id,
        })

    # Rule 8: Policy violation repeated (Fortigate URL/web filter only)
    # Only alert if source is Fortigate and severity is meaningful
    if (event.get("event_type") == "POLICY_VIOLATION"
            and is_fortigate
            and activity["total_events"] >= 5
            and should_alert("POLICY_VIOLATION", 300)):
        forti_action = f"config firewall address\nedit BLOCK_{ip}\nset subnet {ip} 255.255.255.255\nnext\nend"
        forti_dev_id = get_device_id_from_source(event_source, "fortigate")
        alerts.append({
            "type": "POLICY_VIOLATION_REPEATED",
            "severity": "HIGH",
            "ip": ip,
            "detail": f"Repeated policy violations from {ip} on Fortigate — possible data exfiltration attempt",
            "action": forti_action,
            "kill_chain": "Exfiltration",
            "device_source": "fortigate",
            "device_id": forti_dev_id,
        })

    if alerts:
        return alerts[0]
    return None


def get_device_id_for_host(host_ip: str, device_type: str = None) -> str:
    """Find the registered device_id for a given host IP."""
    with device_registry_lock:
        for dev_id, dev in device_registry.items():
            if dev["host"] == host_ip:
                if device_type is None or dev["type"] == device_type:
                    return dev_id
    # Fallback defaults
    if device_type == "fortigate":
        return "fortigate-main"
    if device_type == "cisco_ios":
        return f"cisco_ios-{host_ip.replace('.','_')}"
    return "ubuntu-main"


def get_device_id_from_source(event_source: str, device_type: str) -> str:
    """Extract device IP from event source string and look up device_id.
    Handles: 'Fortigate-Syslog (192.168.108.200)', 'Cisco (10.0.0.1)', etc.
    """
    # Extract IP from source string like "Fortigate-Syslog (192.168.108.200)"
    ip_m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", event_source)
    if ip_m:
        return get_device_id_for_host(ip_m.group(1), device_type)
    return get_device_id_for_host("", device_type)


def queue_alert(alert: dict, triggering_event: dict):
    with alert_lock:
        pending_alerts.append({
            "alert": alert, "event": triggering_event,
            "timestamp": datetime.utcnow().isoformat(),
            "id": str(uuid.uuid4())[:8],
        })
        if len(pending_alerts) > 20:
            pending_alerts.pop(0)


# ── Log Parsers ────────────────────────────────────────────────────────────────
def parse_suricata(line: str):
    try:
        raw = json.loads(line.strip())
    except Exception:
        return None

    event_type = raw.get("event_type", "")
    if event_type not in ("alert", "dns", "http", "ssh", "anomaly", "tls"):
        return None

    src_ip    = raw.get("src_ip", "unknown")
    dest_ip   = raw.get("dest_ip", "unknown")
    src_port  = raw.get("src_port", 0)
    dest_port = raw.get("dest_port", 0)
    proto     = raw.get("proto", "")
    ts        = raw.get("timestamp", datetime.utcnow().isoformat() + "Z")

    if event_type == "alert":
        alert     = raw.get("alert", {})
        sev_num   = alert.get("severity", 3)
        severity  = SURICATA_SEVERITY_MAP.get(sev_num, "MEDIUM")
        category  = alert.get("category", "IDS Alert")
        signature = alert.get("signature", "Unknown signature")
        cat_lower = category.lower()
        if "brute" in cat_lower or "auth" in cat_lower:       ev_label = "BRUTE_FORCE"
        elif "scan" in cat_lower or "recon" in cat_lower:     ev_label = "PORT_SCAN"
        elif "sql" in cat_lower or "injection" in cat_lower:  ev_label = "SQL_INJECTION"
        elif "malware" in cat_lower or "trojan" in cat_lower: ev_label = "MALWARE_DETECTED"
        elif "exploit" in cat_lower:                          ev_label = "COMMAND_INJECTION"
        elif "dos" in cat_lower or "flood" in cat_lower:      ev_label = "SUSPICIOUS_TRAFFIC"
        else:                                                  ev_label = "IDS_ALERT"
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": severity, "event_type": ev_label,
            "source_ip": src_ip, "dest_ip": dest_ip,
            "source_port": src_port, "dest_port": dest_port, "service": proto,
            "description": f"{signature} [{category}]",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [f"Investigate {src_ip}", f"iptables -A INPUT -s {src_ip} -j DROP"],
            "confidence_score": round(1.0 - (sev_num - 1) * 0.1, 2),
            "requires_human_review": sev_num <= 2, "source": "Suricata IDS",
        }

    if event_type == "ssh":
        client_sw = raw.get("ssh", {}).get("client", {}).get("software_version", "")
        if "paramiko" in client_sw.lower() and src_ip in (WINDOWS_HOST, UBUNTU_HOST):
            return None
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "MEDIUM", "event_type": "AUTH_FAILURE",
            "source_ip": src_ip, "dest_ip": dest_ip,
            "source_port": src_port, "dest_port": dest_port, "service": "SSH",
            "description": f"SSH connection from {src_ip} client={client_sw}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [f"Monitor {src_ip} for brute force"],
            "confidence_score": 0.80, "requires_human_review": False, "source": "Suricata SSH",
        }

    if event_type == "anomaly":
        atype = raw.get("anomaly", {}).get("type", "unknown")
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "SUSPICIOUS_TRAFFIC",
            "source_ip": src_ip, "dest_ip": dest_ip,
            "source_port": src_port, "dest_port": dest_port, "service": proto,
            "description": f"Network anomaly: {atype}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [f"Investigate {src_ip}"],
            "confidence_score": 0.75, "requires_human_review": True, "source": "Suricata Anomaly",
        }

    if event_type == "dns":
        qname = raw.get("dns", {}).get("rrname", "")
        desc  = f"DNS query: {qname}"
    elif event_type == "http":
        h    = raw.get("http", {})
        desc = f"{h.get('http_method','')} {h.get('url','')} -> {h.get('status','')}"
    else:
        desc = f"TLS connection to {dest_ip}"

    return {
        "id": str(uuid.uuid4())[:8], "timestamp": ts,
        "severity": "INFO", "event_type": "NORMAL",
        "source_ip": src_ip, "dest_ip": dest_ip,
        "source_port": src_port, "dest_port": dest_port, "service": event_type.upper(),
        "description": desc, "raw_log": line.strip(), "action_taken": "ALLOWED",
        "recommended_actions": [], "confidence_score": 0.99,
        "requires_human_review": False, "source": f"Suricata {event_type.upper()}",
    }


def parse_auth(line: str):
    m_ts = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
    if m_ts:
        try:
            ts = datetime.strptime(f"{datetime.utcnow().year} {m_ts.group(1)}", "%Y %b %d %H:%M:%S").isoformat() + "Z"
        except Exception:
            ts = datetime.utcnow().isoformat() + "Z"
    else:
        ts = datetime.utcnow().isoformat() + "Z"

    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "AUTH_FAILURE",
            "source_ip": ip, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 22, "service": "SSH",
            "description": f"Failed SSH login for user '{user}' from {ip}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [f"Block {ip}: iptables -A INPUT -s {ip} -j DROP", "Enable fail2ban for SSH"],
            "confidence_score": 0.95, "requires_human_review": False, "source": "auth.log",
        }

    m = re.search(r"Invalid user (\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "AUTH_FAILURE",
            "source_ip": ip, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 22, "service": "SSH",
            "description": f"SSH user enumeration — invalid user '{user}' tried from {ip}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [f"Possible user enumeration from {ip}"],
            "confidence_score": 0.90, "requires_human_review": True, "source": "auth.log",
        }

    m = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        severity = "MEDIUM" if user == "root" else "INFO"
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": severity, "event_type": "AUTH_FAILURE" if user == "root" else "NORMAL",
            "source_ip": ip, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 22, "service": "SSH",
            "description": f"Successful SSH login: user='{user}' from {ip}",
            "raw_log": line.strip(), "action_taken": "ALLOWED",
            "recommended_actions": ["Verify this login was authorized"] if user == "root" else [],
            "confidence_score": 0.99, "requires_human_review": user == "root", "source": "auth.log",
        }

    m = re.search(r"sudo:\s+(\S+)\s+.*COMMAND=(.*)", line)
    if m:
        user, cmd = m.group(1), m.group(2).strip()
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "MEDIUM", "event_type": "PRIVILEGE_ESCALATION",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0, "service": "sudo",
            "description": f"Sudo command by '{user}': {cmd[:80]}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": ["Verify sudo usage is authorized"],
            "confidence_score": 0.85, "requires_human_review": True, "source": "auth.log",
        }

    return None


def parse_ufw(line: str):
    if "[UFW BLOCK]" not in line and "[UFW ALLOW]" not in line:
        return None

    ts = datetime.utcnow().isoformat() + "Z"
    action   = "BLOCK" if "[UFW BLOCK]" in line else "ALLOW"
    severity = "MEDIUM" if action == "BLOCK" else "INFO"

    src_ip   = re.search(r"SRC=(\S+)", line)
    dst_ip   = re.search(r"DST=(\S+)", line)
    src_port = re.search(r"SPT=(\d+)", line)
    dst_port = re.search(r"DPT=(\d+)", line)
    proto    = re.search(r"PROTO=(\S+)", line)

    src_ip   = src_ip.group(1)   if src_ip   else "unknown"
    dst_ip   = dst_ip.group(1)   if dst_ip   else UBUNTU_HOST
    src_port = int(src_port.group(1)) if src_port else 0
    dst_port = int(dst_port.group(1)) if dst_port else 0
    proto    = proto.group(1)    if proto    else "UNKNOWN"

    return {
        "id": str(uuid.uuid4())[:8], "timestamp": ts,
        "severity": severity, "event_type": "FIREWALL_BLOCK" if action == "BLOCK" else "NORMAL",
        "source_ip": src_ip, "dest_ip": dst_ip,
        "source_port": src_port, "dest_port": dst_port, "service": proto,
        "description": f"UFW {action}: {src_ip}:{src_port} → {dst_ip}:{dst_port} [{proto}]",
        "raw_log": line.strip(), "action_taken": action,
        "recommended_actions": [f"Investigate repeated blocks from {src_ip}"] if action == "BLOCK" else [],
        "confidence_score": 0.99, "requires_human_review": False, "source": "UFW Firewall",
        "dest_port": dst_port,
    }


def parse_kern(line: str):
    ts = datetime.utcnow().isoformat() + "Z"
    line_lower = line.lower()
    if "oom" in line_lower or "out of memory" in line_lower:
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "SUSPICIOUS_TRAFFIC",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0, "service": "kernel",
            "description": f"Kernel OOM event — possible DoS: {line.strip()[:100]}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": ["Check for memory exhaustion attack (DoS)"],
            "confidence_score": 0.80, "requires_human_review": True, "source": "kern.log",
        }
    return None


def parse_syslog(line: str):
    ts = datetime.utcnow().isoformat() + "Z"
    line_lower = line.lower()
    if "segfault" in line_lower or "core dumped" in line_lower:
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "SUSPICIOUS_TRAFFIC",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0, "service": "syslog",
            "description": f"Process crash/segfault: {line.strip()[:120]}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": ["Investigate potential exploitation attempt"],
            "confidence_score": 0.75, "requires_human_review": True, "source": "syslog",
        }
    return None


# ── Cisco IOS Log Parser ───────────────────────────────────────────────────────
def parse_cisco_log(line: str, device_host: str = "cisco"):
    """Parse Cisco IOS syslog messages (show logging output)."""
    line = line.strip()
    if not line:
        return None

    ts = datetime.utcnow().isoformat() + "Z"

    # Cisco syslog format: *Mar  1 00:00:46.003: %LINEPROTO-5-UPDOWN: ...
    # or: 000123: *Mar  1 00:00:46.003: %SEC-6-IPACCESSLOGP: ...
    severity_map = {
        "0": "CRITICAL", "1": "CRITICAL", "2": "CRITICAL",
        "3": "HIGH", "4": "MEDIUM", "5": "LOW",
        "6": "INFO", "7": "INFO",
    }

    # Extract Cisco facility-severity-mnemonic
    m = re.search(r"%([A-Z_]+)-(\d)-([A-Z_]+):\s*(.*)", line)
    if not m:
        return None

    facility  = m.group(1)
    sev_num   = m.group(2)
    mnemonic  = m.group(3)
    message   = m.group(4).strip()
    severity  = severity_map.get(sev_num, "INFO")

    # Detect attack-relevant mnemonics
    event_type = "NORMAL"
    src_ip, src_port, dst_ip, dst_port = device_host, 0, device_host, 0

    # ACL deny logs — most important for firewall blocking
    if mnemonic in ("IPACCESSLOGP", "IPACCESSLOGNP", "IPACCESSLOGDP", "IPACCESSLOGRP",
                    "IPACCESSLOGSM", "IPACCESSLOGFP"):
        event_type = "FIREWALL_BLOCK"
        severity   = "MEDIUM"
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)\((\d+)\).*?(\d+\.\d+\.\d+\.\d+)\((\d+)\)", message)
        if ip_m:
            src_ip   = ip_m.group(1)
            src_port = int(ip_m.group(2))
            dst_ip   = ip_m.group(3)
            dst_port = int(ip_m.group(4))
        else:
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
            if ip_m:
                src_ip = ip_m.group(1)

    # Login failures — SEC_LOGIN is real IOS mnemonic
    elif mnemonic in ("LOGIN_FAILED", "SEC_LOGIN_FAILED", "AUTHFAIL",
                      "BADPASSWD", "NOPASSWD"):
        event_type = "AUTH_FAILURE"
        severity   = "HIGH"
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
        if ip_m:
            src_ip = ip_m.group(1)

    # Successful logins worth noting
    elif mnemonic in ("LOGIN_SUCCESS", "SEC_LOGIN_SUCCESS"):
        event_type = "NORMAL"
        severity   = "INFO"
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
        if ip_m:
            src_ip = ip_m.group(1)

    # Interface down events
    elif mnemonic == "UPDOWN" and "down" in message.lower():
        event_type = "SUSPICIOUS_TRAFFIC"
        severity   = "MEDIUM"

    # Security/deny events
    elif facility in ("SEC", "IPSEC") or "DENY" in mnemonic or "BLOCK" in mnemonic:
        event_type = "FIREWALL_BLOCK"
        severity   = "MEDIUM"
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
        if ip_m:
            src_ip = ip_m.group(1)

    # Port scan / sweep detection
    elif mnemonic in ("PORTSCANDETECT", "SWEEPDETECT", "SCANNING"):
        event_type = "PORT_SCAN"
        severity   = "HIGH"
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
        if ip_m:
            src_ip = ip_m.group(1)

    # Skip routine noise
    elif facility in ("SYS", "LINEPROTO", "LINK", "OSPF", "BGP", "CDP", "SNMP"):
        return None

    # Skip INFO/DEBUG normal events
    elif severity in ("INFO", "LOW") and event_type == "NORMAL":
        return None

    return {
        "id": str(uuid.uuid4())[:8], "timestamp": ts,
        "severity": severity, "event_type": event_type,
        "source_ip": src_ip, "dest_ip": dst_ip,
        "source_port": src_port, "dest_port": dst_port,
        "service": facility,
        "description": f"[Cisco {facility}-{sev_num}-{mnemonic}] {message[:100]}",
        "raw_log": line, "action_taken": "LOGGED",
        "recommended_actions": [],
        "confidence_score": 0.85,
        "requires_human_review": severity in ("CRITICAL", "HIGH"),
        "source": f"Cisco ({device_host})",
    }


# ── Fortigate Log Parser ───────────────────────────────────────────────────────
def parse_fortigate_log(line: str, device_host: str = "fortigate"):
    """Parse Fortigate key=value log format."""
    line = line.strip()
    if not line:
        return None

    # Parse key=value pairs (Fortigate default format)
    fields = {}
    for m in re.finditer(r'(\w+)=(".*?"|[^\s]+)', line):
        key = m.group(1)
        val = m.group(2).strip('"')
        fields[key] = val

    if not fields:
        return None

    ts_raw = fields.get("date", "") + "T" + fields.get("time", "")
    try:
        ts = datetime.fromisoformat(ts_raw).isoformat() + "Z"
    except Exception:
        ts = datetime.utcnow().isoformat() + "Z"

    action   = fields.get("action", "").lower()
    logtype  = fields.get("type", "").lower()
    subtype  = fields.get("subtype", "").lower()
    src_ip   = fields.get("srcip", fields.get("src", "unknown"))
    dst_ip   = fields.get("dstip", fields.get("dst", device_host))
    src_port = int(fields.get("srcport", fields.get("sport", 0)))
    dst_port = int(fields.get("dstport", fields.get("dport", 0)))
    proto    = fields.get("proto", fields.get("service", "UNKNOWN"))
    msg      = fields.get("msg", fields.get("message", ""))
    level    = fields.get("level", "information").lower()
    policyid = fields.get("policyid", "")

    level_map = {
        "emergency": "CRITICAL", "alert": "CRITICAL", "critical": "CRITICAL",
        "error": "HIGH", "warning": "HIGH", "notice": "MEDIUM",
        "information": "INFO", "debug": "INFO",
    }
    severity = level_map.get(level, "INFO")

    # Determine event type
    if action in ("deny", "block", "dropped", "reset"):
        event_type = "FIREWALL_BLOCK"
        severity   = max(severity, "MEDIUM") if severity == "INFO" else severity
    elif subtype in ("ssh", "admin") and "fail" in msg.lower():
        event_type = "AUTH_FAILURE"
        severity   = "HIGH"
    elif subtype == "virus" or "virus" in msg.lower():
        event_type = "MALWARE_DETECTED"
        severity   = "CRITICAL"
    elif subtype in ("ips", "intrusion") or "attack" in msg.lower():
        event_type = "IDS_ALERT"
        severity   = "HIGH"
    elif subtype == "webfilter" and action == "blocked":
        event_type = "POLICY_VIOLATION"
        severity   = "MEDIUM"
    elif action in ("accept", "allow"):
        event_type = "NORMAL"
        severity   = "INFO"
    else:
        event_type = "NORMAL"

    # Filter out noisy normal traffic — timeouts, closes, internal Fortigate system traffic
    if event_type == "NORMAL":
        return None
    # Filter Fortigate's own internal traffic (policy=0 = implicit deny of Fortigate management traffic)
    if policyid == "0" and action in ("timeout", "close", ""):
        return None
    # Filter pure timeout/close events that are not security relevant
    if action in ("timeout", "close") and event_type not in ("FIREWALL_BLOCK", "AUTH_FAILURE", "IDS_ALERT", "MALWARE_DETECTED"):
        return None

    description = msg or f"Fortigate {logtype}/{subtype}: {action} {src_ip}:{src_port} → {dst_ip}:{dst_port} [{proto}]"
    if policyid:
        description += f" (policy={policyid})"

    return {
        "id": str(uuid.uuid4())[:8], "timestamp": ts,
        "severity": severity, "event_type": event_type,
        "source_ip": src_ip, "dest_ip": dst_ip,
        "source_port": src_port, "dest_port": dst_port,
        "service": proto,
        "description": description[:150],
        "raw_log": line, "action_taken": action.upper() if action else "LOGGED",
        "recommended_actions": [f"Investigate {src_ip}"] if event_type in ("FIREWALL_BLOCK", "IDS_ALERT") else [],
        "confidence_score": 0.90,
        "requires_human_review": severity in ("CRITICAL", "HIGH"),
        "source": f"Fortigate ({device_host})",
    }


# ── Syslog Receiver (UDP 514) ──────────────────────────────────────────────────
def syslog_receiver():
    """
    Listens on UDP port 514 for syslog messages pushed by Cisco/Fortigate.
    Devices can be configured to send logs here in real-time.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 514))
        source_status["syslog_rx"]["connected"] = True
        print("[SYSLOG-RX] Listening on UDP 514 for pushed syslog messages...")

        while True:
            data, addr = sock.recvfrom(4096)
            line = data.decode("utf-8", errors="ignore").strip()
            sender_ip = addr[0]

            if not line:
                continue

            source_status["syslog_rx"]["last_update"] = datetime.utcnow().isoformat()

            # Detect sender type immediately to update status pill
            if "date=" in line and "type=" in line:
                source_status["fortigate"]["connected"] = True
                source_status["fortigate"]["last_update"] = datetime.utcnow().isoformat()
            elif re.search(r"%[A-Z_]+-\d-[A-Z_]+:", line):
                source_status["cisco"]["connected"] = True
                source_status["cisco"]["last_update"] = datetime.utcnow().isoformat()

            # Detect sender type and parse accordingly
            event = None
            if "date=" in line and "type=" in line:
                # Fortigate key=value format
                event = parse_fortigate_log(line, device_host=sender_ip)
                if event:
                    event["source"] = f"Fortigate-Syslog ({sender_ip})"
                    # Mark fortigate as connected when we receive syslog from it
                    source_status["fortigate"]["connected"] = True
                    source_status["fortigate"]["last_update"] = datetime.utcnow().isoformat()
                    source_status["fortigate"]["error"] = None
            elif re.search(r"%[A-Z_]+-\d-[A-Z_]+:", line):
                # Cisco IOS format
                event = parse_cisco_log(line, device_host=sender_ip)
                if event:
                    event["source"] = f"Cisco-Syslog ({sender_ip})"
                    source_status["cisco"]["connected"] = True
                    source_status["cisco"]["last_update"] = datetime.utcnow().isoformat()
            else:
                # Generic syslog — try both parsers
                event = parse_cisco_log(line, device_host=sender_ip) or \
                        parse_fortigate_log(line, device_host=sender_ip)

            if event:
                security_events.insert(0, event)
                if len(security_events) > 1000:
                    security_events.pop()
                print(f"[SYSLOG-RX] {event['severity']} {event['event_type']} from {sender_ip} — {event['description'][:60]}")
                threat = analyze_threats(event)
                if threat:
                    queue_alert(threat, event)

    except PermissionError:
        print("[SYSLOG-RX] Permission denied on port 514. Try: sudo setcap cap_net_bind_service=+ep python3")
        print("[SYSLOG-RX] Or use port 5514 and configure devices to send there.")
        source_status["syslog_rx"]["error"] = "Permission denied on port 514"
    except Exception as e:
        source_status["syslog_rx"]["error"] = str(e)
        print(f"[SYSLOG-RX] Error: {e}")


# ── Cisco Device Poller (via netmiko) ─────────────────────────────────────────
def poll_cisco_device(device_id: str):
    """
    Connects to a Cisco IOS device via SSH using netmiko,
    pulls 'show logging' every 30 seconds, parses new entries.
    """
    if not NETMIKO_AVAILABLE:
        print(f"[CISCO] netmiko not available. Install with: pip install netmiko")
        return

    device_info = device_registry.get(device_id)
    if not device_info:
        return

    host = device_info["host"]
    seen_lines = set()
    print(f"[CISCO] Starting poller for {host}...")

    while True:
        conn = None
        try:
            # Build connection params — only pass secret if actually set
            conn_params = {
                "device_type": "cisco_ios",
                "host": host,
                "username": device_info["username"],
                "password": device_info["password"],
                "timeout": 20,
                "session_timeout": 60,
                "conn_timeout": 20,
            }
            secret = device_info.get("secret", "").strip()
            if secret:
                conn_params["secret"] = secret

            conn = ConnectHandler(**conn_params)

            # Enter enable mode only if secret provided
            if secret:
                conn.enable()

            with device_registry_lock:
                device_registry[device_id]["connected"] = True
                device_registry[device_id]["error"] = None
            source_status["cisco"]["connected"] = True
            source_status["cisco"]["error"] = None
            print(f"[CISCO] Connected to {host}!")

            while True:
                try:
                    # Use show logging without pipe filter for compatibility
                    # with all IOS versions — filter in Python instead
                    output = conn.send_command("show logging", read_timeout=30)
                    lines  = output.splitlines()

                    for line in lines:
                        line = line.strip()
                        if not line or "%" not in line:
                            continue
                        line_hash = hash(line)
                        if line_hash in seen_lines:
                            continue
                        seen_lines.add(line_hash)

                        event = parse_cisco_log(line, device_host=host)
                        if event:
                            security_events.insert(0, event)
                            if len(security_events) > 1000:
                                security_events.pop()
                            source_status["cisco"]["last_update"] = datetime.utcnow().isoformat()
                            with device_registry_lock:
                                device_registry[device_id]["last_seen"] = datetime.utcnow().isoformat()
                            print(f"[CISCO] {event['severity']} {event['event_type']} — {event['description'][:60]}")
                            threat = analyze_threats(event)
                            if threat:
                                queue_alert(threat, event)

                    # Prune seen_lines to prevent unbounded growth
                    if len(seen_lines) > 5000:
                        seen_lines = set(list(seen_lines)[-2000:])

                except Exception as inner_e:
                    print(f"[CISCO] Command error on {host}: {inner_e}. Reconnecting...")
                    break  # Break inner loop to reconnect

                time.sleep(30)

        except Exception as e:
            source_status["cisco"]["connected"] = False
            source_status["cisco"]["error"] = str(e)
            with device_registry_lock:
                if device_id in device_registry:
                    device_registry[device_id]["connected"] = False
                    device_registry[device_id]["error"] = str(e)
            print(f"[CISCO] Error connecting to {host}: {e}. Retrying in 30s...")
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
        time.sleep(30)


# ── Fortigate Device Poller (via netmiko) ─────────────────────────────────────
def poll_fortigate_device(device_id: str):
    """
    Connects to a Fortigate device via SSH,
    pulls recent log entries every 30 seconds.
    """
    if not NETMIKO_AVAILABLE:
        print("[FORTIGATE] netmiko not available.")
        return

    device_info = device_registry.get(device_id)
    if not device_info:
        return

    host = device_info["host"]
    seen_lines = set()
    print(f"[FORTIGATE] Starting poller for {host}...")

    while True:
        try:
            conn = ConnectHandler(
                device_type="fortinet",
                host=host,
                username=device_info["username"],
                password=device_info["password"],
                timeout=15,
            )

            with device_registry_lock:
                device_registry[device_id]["connected"] = True
                device_registry[device_id]["error"] = None
            source_status["fortigate"]["connected"] = True
            source_status["fortigate"]["error"] = None
            print(f"[FORTIGATE] Connected to {host}!")

            while True:
                # Pull last 50 traffic/event log lines
                output = conn.send_command("execute log filter reset")
                conn.send_command("execute log filter category 0")  # traffic
                log_output = conn.send_command("execute log display")

                for line in log_output.splitlines():
                    if not line.strip() or "date=" not in line:
                        continue
                    line_hash = hash(line.strip())
                    if line_hash in seen_lines:
                        continue
                    seen_lines.add(line_hash)

                    event = parse_fortigate_log(line, device_host=host)
                    if event:
                        security_events.insert(0, event)
                        if len(security_events) > 1000:
                            security_events.pop()
                        source_status["fortigate"]["last_update"] = datetime.utcnow().isoformat()
                        with device_registry_lock:
                            device_registry[device_id]["last_seen"] = datetime.utcnow().isoformat()
                        print(f"[FORTIGATE] {event['severity']} {event['event_type']} — {event['description'][:60]}")
                        threat = analyze_threats(event)
                        if threat:
                            queue_alert(threat, event)

                if len(seen_lines) > 5000:
                    seen_lines = set(list(seen_lines)[-2000:])

                time.sleep(30)

        except Exception as e:
            err_msg = str(e)
            # Fortigate SSH polling is optional — syslog push is the primary method
            # Don't spam console with SSH errors, just log briefly
            if "SSHException" in err_msg or "banner" in err_msg.lower() or "10054" in err_msg:
                print(f"[FORTIGATE] SSH polling unavailable for {host} (syslog push is active). Pausing SSH polling.")
                time.sleep(300)  # Wait 5 minutes before retrying instead of 30s
            else:
                source_status["fortigate"]["error"] = err_msg
                with device_registry_lock:
                    if device_id in device_registry:
                        device_registry[device_id]["connected"] = False
                        device_registry[device_id]["error"] = err_msg
                print(f"[FORTIGATE] Error connecting to {host}: {e}. Retrying in 30s...")
                time.sleep(30)


# ── AI Auto-Remediation (THE UNIQUE FEATURE) ──────────────────────────────────
def ai_auto_remediate(ip: str, device_id: str, action_type: str = "block", mode: str = "block", hitcount: int = 3):
    """
    AI-driven auto-remediation: automatically pushes a block rule
    to the target device when a critical threat is confirmed.
    Returns (success: bool, message: str, command_used: str)
    """
    device_info = device_registry.get(device_id)
    if not device_info:
        return False, f"Device {device_id} not found in registry", ""

    host        = device_info["host"]
    device_type = device_info["type"]

    try:
        if device_type == "linux":
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=device_info["username"],
                        password=device_info["password"], timeout=10)

            if mode == "ratelimit":
                # Rate limit using hashlimit — properly allows exactly N connections/min
                # hashlimit resets the counter correctly unlike recent module
                safe_ip = ip.replace(".", "_")
                name = f"CYBRIX_RL_{safe_ip}"
                # Remove any existing rate-limit rules for this IP
                cleanup = [
                    f"sudo iptables -D INPUT -s {ip} -p tcp --dport 22 -m hashlimit --hashlimit-name {name} --hashlimit-above {hitcount}/min --hashlimit-mode srcip --hashlimit-burst {hitcount} -j DROP 2>/dev/null || true",
                ]
                # New rule: drop connections that exceed hitcount per minute
                # hashlimit-above N/min = allow N, drop anything above N per minute
                # hashlimit-burst = allow initial burst of N before limiting kicks in
                apply_cmds = [
                    f"sudo iptables -I INPUT 1 -s {ip} -p tcp --dport 22 -m hashlimit --hashlimit-name {name} --hashlimit-above {hitcount}/min --hashlimit-mode srcip --hashlimit-burst {hitcount} -j DROP",
                ]
                commands = cleanup + apply_cmds
                cmd = f"iptables hashlimit: allow max {hitcount} SSH/min from {ip}, drop the rest"
                success_msg = f"Rate-limited {ip} on {host} — max {hitcount} SSH connections per minute (resets every 60s)"
            else:
                # Full block: UFW + iptables both to cover all chain orderings
                commands = [
                    f"sudo ufw insert 1 deny from {ip} to any",
                    f"sudo iptables -I INPUT 1 -s {ip} -j DROP",
                ]
                cmd = f"ufw insert 1 deny from {ip} && iptables -I INPUT 1 -s {ip} -j DROP"
                success_msg = f"Blocked {ip} on {host} — DROP rule verified (UFW + iptables)"

            err = ""
            exit_code = 0
            for c in commands:
                stdin, stdout, stderr = ssh.exec_command(c)
                code = stdout.channel.recv_exit_status()
                e = stderr.read().decode().strip()
                if code != 0 and "2>/dev/null" not in c:
                    exit_code = code
                    err = e

            # Verify rule exists
            _, vout1, _ = ssh.exec_command(f"sudo iptables -L INPUT -n | grep {ip}")
            _, vout2, _ = ssh.exec_command(f"sudo ufw status | grep {ip}")
            verified = ip in vout1.read().decode() or ip in vout2.read().decode()

            ssh.close()

            if verified:
                return True, success_msg, cmd
            else:
                return False, f"Rule not found after applying — check sudo permissions on {host}: {err}", cmd

        elif device_type == "cisco_ios" and NETMIKO_AVAILABLE:
            conn_params = {
                "device_type": "cisco_ios",
                "host": host,
                "username": device_info["username"],
                "password": device_info["password"],
                "timeout": 20,
            }
            secret = device_info.get("secret", "").strip()
            if secret:
                conn_params["secret"] = secret

            conn = ConnectHandler(**conn_params)
            if secret:
                conn.enable()

            # Add deny ACE to named ACL SOCX-BLOCKLIST
            # Note: Cisco ACL names cannot contain hyphens in some IOS versions
            cmds = [
                "ip access-list extended CYBRIXBLOCKLIST",
                f" deny ip host {ip} any log",
                " exit",
            ]
            conn.send_config_set(cmds)
            conn.save_config()
            conn.disconnect()
            cmd = f"ip access-list extended CYBRIXBLOCKLIST / deny ip host {ip} any log"
            return True, f"Blocked {ip} on Cisco {host} via ACL CYBRIXBLOCKLIST", cmd

        elif device_type == "fortigate":
            # Fortigate: use paramiko directly (more compatible than netmiko for Fortigate)
            safe_ip = ip.replace(".", "_")
            name    = f"CYBRIX_BLOCK_{safe_ip}"

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                host,
                username=device_info["username"],
                password=device_info["password"],
                timeout=15,
                look_for_keys=False,
                allow_agent=False,
            )

            # Use invoke_shell for interactive Fortigate CLI
            shell = ssh.invoke_shell()
            time.sleep(1)
            shell.recv(4096)  # Clear banner

            # Send commands with small delays
            fortigate_cmds = [
                "config firewall address" + chr(10),
                f"edit {name}" + chr(10),
                f"set subnet {ip} 255.255.255.255" + chr(10),
                "next" + chr(10),
                "end" + chr(10),
            ]
            for c in fortigate_cmds:
                shell.send(c)
                time.sleep(0.5)

            # Verify it was created
            shell.send(f"show firewall address {name}" + chr(10))
            time.sleep(1)
            output = ""
            if shell.recv_ready():
                output = shell.recv(4096).decode("utf-8", errors="ignore")

            ssh.close()

            cmd = f"config firewall address / edit {name} / set subnet {ip} 255.255.255.255"

            if name in output or ip in output:
                return True, f"Blocked {ip} on Fortigate {host} — address object {name} created and verified", cmd
            else:
                # Created but couldn't verify — still likely succeeded
                return True, f"Block command sent to Fortigate {host} for {ip} — verify with: show firewall address {name}", cmd

        else:
            return False, f"Device type '{device_type}' not supported for auto-remediation", ""

    except Exception as e:
        return False, f"Auto-remediation failed on {host}: {str(e)}", ""


# ── Ubuntu SSH Log Tailer (existing logic) ────────────────────────────────────
PARSERS = {
    "suricata": parse_suricata,
    "auth":     parse_auth,
    "ufw":      parse_ufw,
    "kern":     parse_kern,
    "syslog":   parse_syslog,
}


def tail_log(source_name: str, log_path: str):
    while True:
        ssh_client = None
        try:
            print(f"[{source_name}] Connecting to {UBUNTU_HOST}...")
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=UBUNTU_HOST, username=UBUNTU_USER,
                               password=UBUNTU_PASS, timeout=10)
            source_status[source_name]["connected"] = True
            source_status[source_name]["error"]     = None
            with device_registry_lock:
                if "ubuntu-main" in device_registry:
                    device_registry["ubuntu-main"]["connected"] = True
            print(f"[{source_name}] Connected! Tailing {log_path}...")

            channel = ssh_client.get_transport().open_session()
            channel.exec_command(f"tail -n 0 -F {log_path} 2>/dev/null")

            parser = PARSERS[source_name]
            buffer = ""
            while True:
                if channel.recv_ready():
                    chunk  = channel.recv(4096).decode("utf-8", errors="ignore")
                    buffer += chunk
                    lines  = buffer.split("\n")
                    buffer = lines[-1]
                    for line in lines[:-1]:
                        if not line.strip():
                            continue
                        event = parser(line)
                        if event:
                            security_events.insert(0, event)
                            if len(security_events) > 1000:
                                security_events.pop()
                            source_status[source_name]["last_update"] = datetime.utcnow().isoformat()
                            print(f"[{source_name}] {event['severity']} {event['event_type']} — {event['description'][:60]}")
                            threat = analyze_threats(event)
                            if threat:
                                print(f"[THREAT] ⚠️  {threat['type']} from {threat['ip']} — {threat['detail']}")
                                queue_alert(threat, event)

                if channel.exit_status_ready():
                    break
                time.sleep(0.1)

        except Exception as e:
            source_status[source_name]["connected"] = False
            source_status[source_name]["error"]     = str(e)
            print(f"[{source_name}] Error: {e}. Retrying in 10s...")
        finally:
            if ssh_client:
                ssh_client.close()
        time.sleep(10)


# ── System Prompts ─────────────────────────────────────────────────────────────
SOC_SYSTEM_PROMPT = f"""You are an elite SOC/XDR analyst monitoring a multi-vendor network.

INFRASTRUCTURE (loaded from environment configuration):
- Protected Linux server: {UBUNTU_HOST} (Ubuntu + Suricata IDS + auth.log + UFW + kern.log)
- SOC tool host: {WINDOWS_HOST} (Windows running CYBRIX — NEVER treat as attacker, ignore its paramiko SSH)
- Fortigate firewall: {FORTIGATE_HOST} (enterprise firewall — syslog push UDP 514, always active)
- Cisco IOS devices: any device added via + ADD DEVICE (SSH polling every 30s)
- Sources: Suricata IDS, auth.log, UFW, kern.log, syslog, Cisco IOS logs, Fortigate logs
- Any unrecognized IP generating security events = potential attacker — analyze accordingly

FORTIGATE LOG INTERPRETATION:
- Source format: "Fortigate-Syslog (192.168.108.200)" or "Fortigate (host)"
- Event types: FIREWALL_BLOCK (deny/block/dropped), AUTH_FAILURE (admin login fail),
  MALWARE_DETECTED (virus/antivirus), IDS_ALERT (IPS/intrusion/botnet), POLICY_VIOLATION (webfilter)
- Fortigate blocks threats at the PERIMETER before they reach internal servers
- policy=0 means Fortigate's own management traffic — NOT an attack
- srcip is the attacker, dstip is the target — analyze accordingly
- Fortigate showing as OFFLINE in device list is NORMAL (SSH polling disabled, syslog push is active)
- If Fortigate syslog events exist → Fortigate IS online and protecting the network

CISCO IOS LOG INTERPRETATION:
- Source format: "Cisco (host_ip)"
- Key mnemonics: IPACCESSLOGP/IPACCESSLOGNP = ACL deny (firewall block)
  SEC_LOGIN_FAILED/AUTHFAIL = login failure, UPDOWN = interface state change
- Cisco format: [FACILITY-SEVERITY-MNEMONIC] message
- Severity levels: 0-2=CRITICAL, 3=HIGH, 4=MEDIUM, 5=LOW, 6-7=INFO
- ACL blocks show: "denied tcp src_ip(src_port) -> dst_ip(dst_port)"

CRITICAL — HOW TO REASON ABOUT ATTACK STATUS:
Each event includes a timestamp like [14:32:05(45s ago)].
The ATTACKER IP STATUS section shows per-IP silence windows:
- 🔴 ACTIVE = events within last 30s → attack IS ongoing
- 🟡 QUIET = 30–120s silence → attack MAY have paused
- ✅ SILENT = 120s+ silence → attack has almost certainly STOPPED
When asked "is the attack still happening?" — ALWAYS check IP STATUS first and report exact last_seen time.
When timestamps show events from hours ago with no recent activity → attacks have STOPPED, say so clearly.

UFW RULE ORDERING WARNING:
When suggesting UFW deny rules, always add: "After adding, run sudo ufw status numbered — the DENY must appear BEFORE any general ALLOW rule for the same port, or it will be bypassed."

RESPONSE FORMAT:
**What:** one sentence — what is happening and who is involved
**Risk:** why this matters
**Kill Chain:** stage (Recon / Initial Access / Credential Access / Persistence / Impact)
**Action:**
```
exact command
```

SEVERITY RULES:
- 🔴 CRITICAL/🟠 HIGH: full format, be urgent
- 🟡 MEDIUM: What + Risk + command
- 🟢 LOW/⚪ INFO: What only — one sentence

STYLE:
- **bold** attacker IPs and commands
- Never repeat yourself, never add disclaimers
- For Cisco: use ACL commands — ip access-list extended CYBRIXBLOCKLIST / deny ip host <IP> any log
- For Fortigate: use address objects — CYBRIX_BLOCK_x_x_x_x format (underscores not hyphens)
  Full block: config firewall address → edit CYBRIX_BLOCK_x / set subnet x.x.x.x 255.255.255.255
- For Linux: suggest iptables/ufw commands
- If IP is {WINDOWS_HOST} → that is the SOC system running CYBRIX, NEVER an attacker
- If IP is {FORTIGATE_HOST} → that is the Fortigate firewall itself — attacks targeting it are attacks ON the firewall
- If IP is {UBUNTU_HOST} → that is the protected server — outbound events from it are internal activity

HOW TO ANSWER COMMON QUESTIONS:

Q: "is there an attack on fortigate/cisco right now?"
A: Check IP STATUS section. Look for events from Fortigate/Cisco sources. If ACTIVE → describe the attack type (IPS, brute force, firewall block) and the attacker IP. If SILENT → state how long ago, say attack stopped.

Q: "what is fortigate/cisco detecting?"
A: List ALL event types seen from that source: FIREWALL_BLOCK (perimeter blocks), IDS_ALERT (IPS detections), MALWARE_DETECTED (virus/botnet), POLICY_VIOLATION (URL blocks), AUTH_FAILURE (admin login attempts). Group by severity.

Q: "how do I block IP X on fortigate?"
A: Give the full 3-step process:
1. Create address object:
   config firewall address
   edit CYBRIX_BLOCK_x_x_x_x
   set subnet x.x.x.x 255.255.255.255
   next
   end
2. Apply in firewall policy (place ABOVE existing allow rules)
3. Verify: show firewall address CYBRIX_BLOCK_x_x_x_x

Q: "how do I block IP X on cisco?"
A: Give the full process:
1. Add to ACL: ip access-list extended CYBRIXBLOCKLIST / deny ip host x.x.x.x any log / exit / write memory
2. Apply to interface if not already: interface Gi0/0 / ip access-group CYBRIXBLOCKLIST in
3. Verify: show ip access-lists CYBRIXBLOCKLIST

Q: "how do I unblock/remove block on fortigate?"
A: config firewall address / delete CYBRIX_BLOCK_x_x_x_x / end

Q: "how do I unblock on cisco?"
A: ip access-list extended CYBRIXBLOCKLIST / no deny ip host x.x.x.x any log / exit / write memory

Q: "is fortigate blocking the attack?"
A: Look for FIREWALL_BLOCK events from Fortigate source. If present → yes, Fortigate is actively blocking. Describe what ports/protocols are being blocked and from which IPs.

Q: "what commands ran automatically?"
A: Look for AUTO_REMEDIATION events in the event stream. These show exactly what CYBRIX executed automatically on each device.

Q: "show me all blocked IPs"
A: List all IPs that have AUTO_REMEDIATION BLOCKED events or appear in FIREWALL_BLOCK events from any source."""


ALERT_SYSTEM_PROMPT = """You are an elite SOC analyst receiving an AUTOMATED THREAT ALERT from CYBRIX.
A behavioral detection engine flagged suspicious activity that may have evaded signature-based IDS.

Your job:
1. Explain what is happening — be URGENT and clear
2. Identify kill chain stage
3. Give EXACT commands to stop it RIGHT NOW adapted to the device type
4. Explain what happens if no action is taken

DEVICE-SPECIFIC COMMANDS:
- Linux/Ubuntu: sudo ufw insert 1 deny from <IP> to any && sudo iptables -I INPUT 1 -s <IP> -j DROP
- Fortigate: config firewall address → edit CYBRIX_BLOCK_x_x_x_x → set subnet <IP> 255.255.255.255 → next → end
- Cisco IOS: ip access-list extended CYBRIXBLOCKLIST → deny ip host <IP> any log → exit → write memory

FORTIGATE CONTEXT: Source "Fortigate-Syslog" = syslog push event (real-time). policy=0 = management traffic not attack.
CISCO CONTEXT: Source "Cisco (IP)" = SSH polling event. IPACCESSLOG* = ACL deny. SEC_LOGIN_FAILED = login failure.

Be direct and actionable. Start with ⚠️ ALERT and threat type.
Format remediation as numbered steps with exact commands."""


def get_events_context():
    now = datetime.utcnow()
    if not security_events:
        return "No security events yet. All log sources are being monitored."

    critical_events = [e for e in security_events if e["severity"] == "CRITICAL"][:5]
    high_events     = [e for e in security_events if e["severity"] == "HIGH"][:4]
    medium_events   = [e for e in security_events if e["severity"] == "MEDIUM"][:3]
    selected = (critical_events + high_events + medium_events)[:10]
    if not selected:
        selected = security_events[:5]

    lines = [f"=== LIVE SECURITY EVENTS (as of {now.strftime('%H:%M:%S')} UTC) ==="]
    for ev in selected:
        ts_raw = ev.get("timestamp", "")
        try:
            ts_dt = datetime.fromisoformat(ts_raw.rstrip("Z"))
            age_secs = int((now - ts_dt).total_seconds())
            age_str = f"{age_secs}s ago" if age_secs < 60 else (f"{age_secs//60}m ago" if age_secs < 3600 else f"{age_secs//3600}h ago")
            ts_display = f"{ts_dt.strftime('%H:%M:%S')}({age_str})"
        except Exception:
            ts_display = ts_raw[:19] if ts_raw else "unknown"
        lines.append(
            f"[{ev['severity']}][{ts_display}][{ev['source']}] {ev['event_type']} "
            f"src:{ev['source_ip']} dst:{ev['dest_ip']}:{ev['dest_port']} — {ev['description']}"
        )

    lines.append("\n=== ATTACKER IP STATUS ===")
    hostile_ips = [ip for ip in ip_activity
                   if ip not in (UBUNTU_HOST, WINDOWS_HOST) and ip_activity[ip]["total_events"] > 0]
    if hostile_ips:
        for ip in hostile_ips:
            act = ip_activity[ip]
            last_seen_str = act.get("last_seen")
            if last_seen_str:
                try:
                    last_dt = datetime.fromisoformat(last_seen_str)
                    silence_secs = int((now - last_dt).total_seconds())
                    if silence_secs < 30:
                        status = "🔴 ACTIVE (last event <30s ago)"
                    elif silence_secs < 120:
                        status = f"🟡 QUIET for {silence_secs}s — may have paused"
                    else:
                        status = f"✅ SILENT for {silence_secs // 60}m — attack likely stopped"
                    lines.append(
                        f"IP {ip}: {status} | auth_failures={len(act['auth_failures'])} "
                        f"last_seen={last_seen_str[:19]}"
                    )
                except Exception:
                    pass
    else:
        lines.append("No hostile IPs tracked yet.")

    # Device summary
    lines.append("\n=== CONNECTED DEVICES ===")
    with device_registry_lock:
        for dev_id, dev in device_registry.items():
            status = "✅ ONLINE" if dev["connected"] else "❌ OFFLINE"
            lines.append(f"{dev['name']} [{dev['type']}]: {status}")

    critical = sum(1 for e in security_events if e["severity"] == "CRITICAL")
    high     = sum(1 for e in security_events if e["severity"] == "HIGH")
    unique_ips = len(set(e["source_ip"] for e in security_events))
    lines.append(f"\nSTATS: Total:{len(security_events)} Critical:{critical} High:{high} UniqueIPs:{unique_ips}")
    return "\n".join(lines)


# ── Flask Routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events", methods=["GET"])
def get_events():
    severity_filter = request.args.get("severity", "ALL")
    source_filter   = request.args.get("source", "ALL")
    limit = int(request.args.get("limit", 100))

    filtered = security_events
    if severity_filter != "ALL":
        filtered = [e for e in filtered if e["severity"] == severity_filter]
    if source_filter != "ALL":
        filtered = [e for e in filtered if source_filter.lower() in e["source"].lower()]

    return jsonify({
        "events": filtered[:limit],
        "total":  len(security_events),
        "sources": source_status,
        "stats": {
            "critical":        sum(1 for e in security_events if e["severity"] == "CRITICAL"),
            "high":            sum(1 for e in security_events if e["severity"] == "HIGH"),
            "medium":          sum(1 for e in security_events if e["severity"] == "MEDIUM"),
            "low":             sum(1 for e in security_events if e["severity"] == "LOW"),
            "info":            sum(1 for e in security_events if e["severity"] == "INFO"),
            "unique_ips":      len(set(e["source_ip"] for e in security_events)),
            "requires_review": sum(1 for e in security_events if e.get("requires_human_review")),
        }
    })


@app.route("/api/status", methods=["GET"])
def status():
    return jsonify(source_status)


@app.route("/api/alerts/pending", methods=["GET"])
def get_pending_alerts():
    """Returns alerts newer than the client's last seen timestamp."""
    since = request.args.get("since", "")
    with alert_lock:
        if since:
            # Only return alerts newer than what client has seen
            alerts = [a for a in pending_alerts if a["timestamp"] > since]
        else:
            alerts = list(pending_alerts)
        # Keep alerts for 60 seconds then auto-clean
        now = datetime.utcnow().isoformat()
        cutoff = (datetime.utcnow() - timedelta(seconds=60)).isoformat()
        # Remove alerts older than 60s
        to_remove = [a for a in pending_alerts if a["timestamp"] < cutoff]
        for a in to_remove:
            pending_alerts.remove(a)
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/ip_activity", methods=["GET"])
def get_ip_activity():
    result = {}
    for ip, data in ip_activity.items():
        result[ip] = {
            "first_seen":    data["first_seen"],
            "last_seen":     data["last_seen"],
            "total_events":  data["total_events"],
            "auth_failures": len(data["auth_failures"]),
            "ufw_blocks":    len(data["ufw_blocks"]),
            "flagged":       data["flagged"],
        }
    return jsonify(result)


@app.route("/api/ingest", methods=["POST"])
def ingest_events():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    new_events = data if isinstance(data, list) else [data]
    for ev in new_events:
        ev.setdefault("id", str(uuid.uuid4())[:8])
        ev.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
        ev.setdefault("severity", "INFO")
        ev.setdefault("source", "REST API")
        security_events.insert(0, ev)
    return jsonify({"ingested": len(new_events), "total": len(security_events)})


# ── Device Management API ──────────────────────────────────────────────────────
@app.route("/api/devices", methods=["GET"])
def get_devices():
    with device_registry_lock:
        devices = list(device_registry.values())
    # Don't expose passwords
    safe = [{k: v for k, v in d.items() if k not in ("password", "secret")} for d in devices]
    return jsonify({"devices": safe})


@app.route("/api/devices", methods=["POST"])
def add_device():
    """Add a new network device (Cisco/Fortigate) to be monitored."""
    data        = request.get_json()
    device_type = data.get("type", "cisco_ios")
    host        = data.get("host", "")
    username    = data.get("username", "")
    password    = data.get("password", "")
    secret      = data.get("secret", "")
    name        = data.get("name", host)

    if not host or not username or not password:
        return jsonify({"error": "host, username, password are required"}), 400

    device_id = f"{device_type}-{host.replace('.', '_')}"
    register_device(device_id, device_type, host, username, password, secret, name)

    # Start the appropriate polling thread
    if device_type == "cisco_ios":
        t = threading.Thread(target=poll_cisco_device, args=(device_id,), daemon=True)
        t.start()
        msg = f"Cisco device {host} added — SSH polling started (show logging every 30s)"
    elif device_type == "fortigate":
        # Fortigate uses syslog push — no SSH polling needed
        # Just register it for remediation purposes
        msg = f"Fortigate {host} registered — receiving logs via syslog push (UDP 514)"
    else:
        msg = f"Linux device {host} registered."

    return jsonify({"status": "ok", "device_id": device_id, "message": msg})


@app.route("/api/devices/<device_id>", methods=["DELETE"])
def remove_device(device_id):
    with device_registry_lock:
        if device_id in device_registry:
            del device_registry[device_id]
            return jsonify({"status": "removed"})
    return jsonify({"error": "Device not found"}), 404


@app.route("/api/remediate", methods=["POST"])
def remediate():
    """
    AI Auto-Remediation endpoint.
    Automatically pushes a block rule to the specified device.
    """
    data      = request.get_json()
    ip        = data.get("ip", "")
    device_id = data.get("device_id", "ubuntu-main")
    mode      = data.get("mode", "block")      # "block" or "ratelimit"
    hitcount  = int(data.get("hitcount", 3))   # max connections per 60s for rate-limit

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    success, message, command = ai_auto_remediate(ip, device_id, mode=mode, hitcount=hitcount)

    # Record in managed IPs store
    if success:
        with managed_ips_lock:
            managed_ips[ip] = {
                "ip": ip,
                "mode": mode,
                "device_id": device_id,
                "device_name": device_registry.get(device_id, {}).get("name", device_id),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "command": command,
                "active": True,
                "message": message,
                "hitcount": hitcount if mode == "ratelimit" else None,
            }

    # Log the remediation as a security event
    event = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": "INFO" if success else "HIGH",
        "event_type": "AUTO_REMEDIATION",
        "source_ip": ip,
        "dest_ip": device_registry.get(device_id, {}).get("host", "unknown"),
        "source_port": 0, "dest_port": 0,
        "service": "CYBRIX",
        "description": f"{'✅' if success else '❌'} Auto-remediation: {message}",
        "raw_log": command,
        "action_taken": "BLOCKED" if success else "FAILED",
        "recommended_actions": [],
        "confidence_score": 1.0,
        "requires_human_review": not success,
        "source": "CYBRIX Auto-Remediation",
    }
    security_events.insert(0, event)

    return jsonify({
        "success": success,
        "message": message,
        "command": command,
        "ip": ip,
        "device_id": device_id,
    })


@app.route("/api/managed_ips", methods=["GET"])
def get_managed_ips():
    """Returns all active blocked/rate-limited IPs."""
    with managed_ips_lock:
        active = [v for v in managed_ips.values() if v.get("active", True)]
    return jsonify({"managed_ips": active})


@app.route("/api/managed_ips/<path:ip>", methods=["DELETE"])
def unblock_ip(ip):
    """Remove block/rate-limit for an IP on its device."""
    with managed_ips_lock:
        entry = managed_ips.get(ip)
    if not entry:
        return jsonify({"error": "IP not found in managed list"}), 404

    device_id   = entry["device_id"]
    mode        = entry["mode"]
    device_info = device_registry.get(device_id, {})
    host        = device_info.get("host", "")

    try:
        device_type = device_info.get("type", "linux")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=device_info["username"],
                    password=device_info["password"], timeout=10,
                    look_for_keys=False, allow_agent=False)

        if device_type == "fortigate":
            # Fortigate: delete address object via interactive shell
            safe_ip = ip.replace(".", "_")
            name    = f"CYBRIX_BLOCK_{safe_ip}"
            shell   = ssh.invoke_shell()
            time.sleep(1)
            shell.recv(4096)  # Clear banner
            fortigate_cmds = [
                "config firewall address" + chr(10),
                f"delete {name}" + chr(10),
                "end" + chr(10),
            ]
            for c in fortigate_cmds:
                shell.send(c)
                time.sleep(0.5)
            ssh.close()

        elif device_type == "cisco_ios":
            # Cisco: remove from ACL
            if NETMIKO_AVAILABLE:
                ssh.close()
                conn_params = {
                    "device_type": "cisco_ios",
                    "host": host,
                    "username": device_info["username"],
                    "password": device_info["password"],
                    "timeout": 20,
                }
                secret = device_info.get("secret", "").strip()
                if secret:
                    conn_params["secret"] = secret
                conn = ConnectHandler(**conn_params)
                if secret:
                    conn.enable()
                cmds = [
                    "ip access-list extended CYBRIXBLOCKLIST",
                    f" no deny ip host {ip} any log",
                    " exit",
                ]
                conn.send_config_set(cmds)
                conn.save_config()
                conn.disconnect()
            else:
                ssh.close()

        else:
            # Linux: iptables + ufw
            if mode == "ratelimit":
                safe_ip = ip.replace(".", "_")
                name    = f"CYBRIX_RL_{safe_ip}"
                hitcount_val = entry.get("hitcount", 3)
                cmds = [
                    f"sudo iptables -D INPUT -s {ip} -p tcp --dport 22 -m hashlimit --hashlimit-name {name} --hashlimit-above {hitcount_val}/min --hashlimit-mode srcip --hashlimit-burst {hitcount_val} -j DROP 2>/dev/null || true",
                ]
            else:
                cmds = [
                    f"sudo ufw delete deny from {ip} to any 2>/dev/null || true",
                    f"sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true",
                ]
            for c in cmds:
                stdin, stdout, stderr = ssh.exec_command(c)
                stdout.channel.recv_exit_status()
            ssh.close()

        with managed_ips_lock:
            if ip in managed_ips:
                del managed_ips[ip]  # Remove completely, not just mark inactive

        # Log the unblock
        event = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": "INFO",
            "event_type": "AUTO_REMEDIATION",
            "source_ip": ip,
            "dest_ip": host,
            "source_port": 0, "dest_port": 0,
            "service": "CYBRIX",
            "description": f"✅ Unblocked {ip} on {host} (was: {mode})",
            "raw_log": "", "action_taken": "UNBLOCKED",
            "recommended_actions": [],
            "confidence_score": 1.0,
            "requires_human_review": False,
            "source": "CYBRIX Management",
        }
        security_events.insert(0, event)

        return jsonify({"success": True, "message": f"Removed {mode} rule for {ip} on {host}"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/alerts/active", methods=["GET"])
def get_active_alerts():
    active = {}
    for ip, data in ip_activity.items():
        if data["brute_force_count"] >= 5:
            active[f"brute_{ip}"] = {
                "count": data["brute_force_count"],
                "ip": ip,
                "type": "BRUTE_FORCE_DETECTED",
            }
    return jsonify(active)


@app.route("/api/chat", methods=["POST"])
def chat():
    data       = request.get_json()
    message    = data.get("message", "")
    session_id = data.get("session_id") or str(uuid.uuid4())
    if session_id == "null": session_id = str(uuid.uuid4())
    if session_id not in chat_sessions:
        chat_sessions[session_id] = [{"role": "system", "content": SOC_SYSTEM_PROMPT}]

    if len(chat_sessions[session_id]) > 7:
        chat_sessions[session_id] = [chat_sessions[session_id][0]] + chat_sessions[session_id][-6:]

    context_message = f"LIVE DATA:\n{get_events_context()}\n\nQuestion: {message}"
    chat_sessions[session_id].append({"role": "user", "content": context_message})
    return jsonify({"session_id": session_id, "status": "ready"})


@app.route("/api/alert_chat", methods=["POST"])
def alert_chat():
    data    = request.get_json()
    alert   = data.get("alert", {})
    event   = data.get("event", {})
    session_id = data.get("session_id") or str(uuid.uuid4())
    if session_id == "null": session_id = str(uuid.uuid4())

    alert_context = f"""
=== AUTOMATED THREAT ALERT ===
Alert Type: {alert.get('type', 'UNKNOWN')}
Severity: {alert.get('severity', 'UNKNOWN')}
Attacker IP: {alert.get('ip', 'unknown')}
Detail: {alert.get('detail', '')}
Kill Chain Stage: {alert.get('kill_chain', 'Unknown')}
Suggested Action: {alert.get('action', '')}

=== TRIGGERING EVENT ===
Source: {event.get('source', '')}
Event Type: {event.get('event_type', '')}
Description: {event.get('description', '')}
Timestamp: {event.get('timestamp', '')}

=== CURRENT THREAT LANDSCAPE ===
{get_events_context()}

Analyze this threat and tell the SOC analyst:
1. What is happening RIGHT NOW
2. How serious is this
3. Exact steps to stop it immediately (adapt commands to the device type in the event source)
"""
    chat_sessions[session_id] = [
        {"role": "system", "content": ALERT_SYSTEM_PROMPT},
        {"role": "user", "content": alert_context}
    ]
    return jsonify({"session_id": session_id, "status": "ready"})


@app.route("/api/stream", methods=["GET"])
def stream():
    session_id = request.args.get("session_id")
    if not session_id or session_id == "null" or session_id not in chat_sessions:
        return jsonify({"error": "Invalid session"}), 400

    def generate():
        try:
            msgs = chat_sessions[session_id]
            last_user = next((m["content"] for m in reversed(msgs) if m["role"] == "user"), "")
            if "CRITICAL" in last_user:   max_tok = 400
            elif "HIGH" in last_user:     max_tok = 300
            elif "MEDIUM" in last_user:   max_tok = 200
            else:                         max_tok = 120

            # Retry up to 3 times on rate limit
            response = None
            for attempt in range(3):
                try:
                    response = client.chat.completions.create(
                        model="gpt-4.1",
                        messages=msgs,
                        stream=True,
                        temperature=0.2,
                        max_tokens=max_tok,
                        stream_options={"include_usage": True}
                    )
                    break
                except Exception as e:
                    if "rate_limit" in str(e).lower() or "429" in str(e):
                        wait = (attempt + 1) * 10
                        msg = json.dumps({"token": f"⏳ Rate limit hit, retrying in {wait}s..."})
                        yield f"data: {msg}\n\n"
                        time.sleep(wait)
                        continue
                    raise
            if response is None:
                err_msg = json.dumps({"error": "Rate limit exceeded after 3 retries. Please wait 30s and try again."})
                yield f"data: {err_msg}\n\n"
                return
            full_response = ""
            input_tokens = output_tokens = 0
            for chunk in response:
                if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                    token = chunk.choices[0].delta.content
                    full_response += token
                    yield f"data: {json.dumps({'token': token})}\n\n"
                if chunk.usage:
                    input_tokens  = chunk.usage.prompt_tokens
                    output_tokens = chunk.usage.completion_tokens
            chat_sessions[session_id].append({"role": "assistant", "content": full_response})
            cost = round((input_tokens * 2 + output_tokens * 8) / 1_000_000, 6)
            yield f"data: {json.dumps({'done': True, 'input_tokens': input_tokens, 'output_tokens': output_tokens, 'cost_usd': cost})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/reset", methods=["POST"])
def reset():
    data = request.get_json()
    session_id = data.get("session_id")
    if session_id in chat_sessions:
        chat_sessions[session_id] = [{"role": "system", "content": SOC_SYSTEM_PROMPT}]
    return jsonify({"status": "reset"})


# ── Start Background Threads ───────────────────────────────────────────────────
# Ubuntu log tailers
for src_name, src_path in LOG_SOURCES.items():
    threading.Thread(target=tail_log, args=(src_name, src_path), daemon=True).start()

# Syslog receiver (Cisco/Fortigate push logs to us on UDP 514)
threading.Thread(target=syslog_receiver, daemon=True).start()

# Note: Cisco/Fortigate pollers are started dynamically via POST /api/devices

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)