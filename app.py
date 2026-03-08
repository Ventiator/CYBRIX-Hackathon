import os
import json
import time
import uuid
import re
import threading
import paramiko
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template, request, Response, stream_with_context, jsonify
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

# In-memory store
security_events = []
chat_sessions   = {}
source_status   = {
    "suricata": {"connected": False, "last_update": None, "error": None},
    "auth":     {"connected": False, "last_update": None, "error": None},
    "syslog":   {"connected": False, "last_update": None, "error": None},
    "ufw":      {"connected": False, "last_update": None, "error": None},
    "kern":     {"connected": False, "last_update": None, "error": None},
}

# Threat Intelligence Store
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

UBUNTU_HOST = os.environ.get("UBUNTU_HOST", "192.168.100.20")
UBUNTU_USER = os.environ.get("UBUNTU_USER", "ventiator")
UBUNTU_PASS = os.environ.get("UBUNTU_PASS", "12345")

LOG_SOURCES = {
    "suricata": "/var/log/suricata/eve.json",
    "auth":     "/var/log/auth.log",
    "syslog":   "/var/log/syslog",
    "ufw":      "/var/log/ufw.log",
    "kern":     "/var/log/kern.log",
}

SURICATA_SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

def update_ip_activity(ip: str, event_type: str, event: dict = None):
    """Track per-IP behavior for anomaly detection."""
    if not ip or ip == "unknown":
        return

    now = datetime.utcnow()
    activity = ip_activity[ip]

    if not activity["first_seen"]:
        activity["first_seen"] = now.isoformat()
    activity["last_seen"] = now.isoformat()
    activity["total_events"] += 1

    if event_type == "AUTH_FAILURE":
        activity["auth_failures"].append(now)
        activity["auth_failures"] = [
            t for t in activity["auth_failures"]
            if (now - t).total_seconds() < 300
        ]

    elif event_type == "PORT_SCAN":
        activity["port_scan_times"].append(now)
        activity["port_scan_times"] = [
            t for t in activity["port_scan_times"]
            if (now - t).total_seconds() < 60
        ]

    elif event_type == "FIREWALL_BLOCK":
        activity["ufw_blocks"].append(now)
        activity["ufw_blocks"] = [
            t for t in activity["ufw_blocks"]
            if (now - t).total_seconds() < 300
        ]
        dest_port = (event or {}).get("dest_port", 0)
        activity["ufw_block_ports"].append((now, dest_port))
        activity["ufw_block_ports"] = [
            (t, p) for t, p in activity["ufw_block_ports"]
            if (now - t).total_seconds() < 600
        ]

    elif event_type in ("AUTH_FAILURE", "SSH"):
        activity["ssh_attempts"].append(now)
        activity["ssh_attempts"] = [
            t for t in activity["ssh_attempts"]
            if (now - t).total_seconds() < 300
        ]


def analyze_threats(event: dict):
    """
    Behavioral analysis — detects attacks that signature-based IDS misses.
    Returns a threat alert dict or None.
    """
    ip = event.get("source_ip", "unknown")
    if not ip or ip == "unknown" or ip == UBUNTU_HOST:
        return None

    update_ip_activity(ip, event.get("event_type", ""), event)
    activity = ip_activity[ip]
    now = datetime.utcnow()
    alerts = []

    def should_alert(alert_type, cooldown_secs=60):
        last = activity["alert_cooldown"].get(alert_type)
        if last and (now - last).total_seconds() < cooldown_secs:
            return False
        activity["alert_cooldown"][alert_type] = now
        return True

    # Rule 1: Brute Force — show once, then update counter via /api/alerts/active
    if len(activity["auth_failures"]) >= 5:
        activity["brute_force_count"] = len(activity["auth_failures"])
        if should_alert("BRUTE_FORCE_DETECTED", 999999):
            alerts.append({
                "type": "BRUTE_FORCE_DETECTED",
                "severity": "CRITICAL",
                "ip": ip,
                "detail": f"{len(activity['auth_failures'])} failed logins in 5 minutes from {ip}",
                "action": f"iptables -A INPUT -s {ip} -j DROP",
                "kill_chain": "Credential Access",
                "live_counter_key": f"brute_{ip}",
            })

    # Rule 2: Slow Scan — ports hit over long period (T0 evasion) 
    recent_port_hits = len(activity["port_scan_times"])
    if 2 <= recent_port_hits <= 5:
        alerts.append({
            "type": "SLOW_SCAN_DETECTED",
            "severity": "HIGH",
            "ip": ip,
            "detail": f"Low-rate port scan detected — {recent_port_hits} probes (possible -T0 evasion)",
            "action": f"ufw deny from {ip}",
            "kill_chain": "Reconnaissance",
        })

    # Rule 2b: Slow Scan via UFW port tracking
    unique_ports = set(p for _, p in activity["ufw_block_ports"] if p > 0)
    if len(unique_ports) >= 3 and should_alert("SLOW_SCAN_DETECTED", 120):
        activity["slow_scan_alerted"] = True
        alerts.append({
            "type": "SLOW_SCAN_DETECTED",
            "severity": "HIGH",
            "ip": ip,
            "detail": f"Stealthy slow port scan detected via UFW — {len(unique_ports)} unique ports probed over time: {sorted(unique_ports)}",
            "action": f"ufw deny from {ip} && iptables -A INPUT -s {ip} -j DROP",
            "kill_chain": "Reconnaissance (Evasion)",
        })

    # Rule 3: Persistent Attacker — UFW blocks + SSH attempts
    if len(activity["ufw_blocks"]) >= 3 and len(activity["ssh_attempts"]) >= 1 and should_alert("PERSISTENT_ATTACKER", 120):
        alerts.append({
            "type": "PERSISTENT_ATTACKER",
            "severity": "CRITICAL",
            "ip": ip,
            "detail": f"IP blocked {len(activity['ufw_blocks'])}x by UFW AND attempting SSH — persistent threat actor",
            "action": f"iptables -A INPUT -s {ip} -j DROP && fail2ban-client set sshd banip {ip}",
            "kill_chain": "Persistence",
        })

    # Rule 4: Coordinated Attack — port scan + auth failure same IP
    has_scan = len(activity["port_scan_times"]) >= 1
    has_auth = len(activity["auth_failures"]) >= 1
    if has_scan and has_auth and not activity["flagged"] and should_alert("COORDINATED_ATTACK", 300):
        activity["flagged"] = True
        alerts.append({
            "type": "COORDINATED_ATTACK",
            "severity": "CRITICAL",
            "ip": ip,
            "detail": f"Same IP doing recon (port scan) AND credential attack — kill chain in progress!",
            "action": f"iptables -A INPUT -s {ip} -j DROP",
            "kill_chain": "Recon → Credential Access",
        })

    # Rule 5: High event volume from single IP (DDoS/flood)
    if activity["total_events"] >= 50 and should_alert("HIGH_VOLUME_ATTACK", 120):
        alerts.append({
            "type": "HIGH_VOLUME_ATTACK",
            "severity": "CRITICAL",
            "ip": ip,
            "detail": f"{activity['total_events']} total events from this IP — possible DoS/flood",
            "action": f"iptables -A INPUT -s {ip} -j DROP",
            "kill_chain": "Impact",
        })

    if alerts:
        return alerts[0]

    return None


def queue_alert(alert: dict, triggering_event: dict):
    """Queue a threat alert to be sent to the chatbot."""
    with alert_lock:
        pending_alerts.append({
            "alert": alert,
            "event": triggering_event,
            "timestamp": datetime.utcnow().isoformat(),
            "id": str(uuid.uuid4())[:8],
        })
        if len(pending_alerts) > 20:
            pending_alerts.pop(0)


# Parsers
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
        if "brute" in cat_lower or "auth" in cat_lower:
            ev_label = "BRUTE_FORCE"
        elif "scan" in cat_lower or "recon" in cat_lower:
            ev_label = "PORT_SCAN"
        elif "sql" in cat_lower or "injection" in cat_lower:
            ev_label = "SQL_INJECTION"
        elif "malware" in cat_lower or "trojan" in cat_lower:
            ev_label = "MALWARE_DETECTED"
        elif "exploit" in cat_lower:
            ev_label = "COMMAND_INJECTION"
        elif "dos" in cat_lower or "flood" in cat_lower:
            ev_label = "SUSPICIOUS_TRAFFIC"
        else:
            ev_label = "IDS_ALERT"
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": severity, "event_type": ev_label,
            "source_ip": src_ip, "dest_ip": dest_ip,
            "source_port": src_port, "dest_port": dest_port,
            "service": proto,
            "description": f"{signature} [{category}]",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [
                f"Investigate {src_ip}",
                f"iptables -A INPUT -s {src_ip} -j DROP",
            ],
            "confidence_score": round(1.0 - (sev_num - 1) * 0.1, 2),
            "requires_human_review": sev_num <= 2,
            "source": "Suricata IDS",
        }

    if event_type == "ssh":
        client_sw = raw.get("ssh", {}).get("client", {}).get("software_version", "")
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "MEDIUM", "event_type": "AUTH_FAILURE",
            "source_ip": src_ip, "dest_ip": dest_ip,
            "source_port": src_port, "dest_port": dest_port,
            "service": "SSH",
            "description": f"SSH connection from {src_ip} client={client_sw}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [f"Monitor {src_ip} for brute force"],
            "confidence_score": 0.80,
            "requires_human_review": False, "source": "Suricata SSH",
        }

    if event_type == "anomaly":
        atype = raw.get("anomaly", {}).get("type", "unknown")
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "SUSPICIOUS_TRAFFIC",
            "source_ip": src_ip, "dest_ip": dest_ip,
            "source_port": src_port, "dest_port": dest_port,
            "service": proto,
            "description": f"Network anomaly: {atype}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [f"Investigate {src_ip}"],
            "confidence_score": 0.75,
            "requires_human_review": True, "source": "Suricata Anomaly",
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
        "source_port": src_port, "dest_port": dest_port,
        "service": event_type.upper(),
        "description": desc, "raw_log": line.strip(),
        "action_taken": "ALLOWED", "recommended_actions": [],
        "confidence_score": 0.99,
        "requires_human_review": False, "source": f"Suricata {event_type.upper()}",
    }


def parse_auth(line: str):
    m_ts = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
    if m_ts:
        try:
            ts = datetime.strptime(
                f"{datetime.utcnow().year} {m_ts.group(1)}",
                "%Y %b %d %H:%M:%S"
            ).isoformat() + "Z"
        except Exception:
            ts = datetime.utcnow().isoformat() + "Z"
    else:
        ts = datetime.utcnow().isoformat() + "Z"

    line_lower = line.lower()

    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "AUTH_FAILURE",
            "source_ip": ip, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 22,
            "service": "SSH",
            "description": f"Failed SSH login for user '{user}' from {ip}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [
                f"Block {ip}: iptables -A INPUT -s {ip} -j DROP",
                "Enable fail2ban for SSH"
            ],
            "confidence_score": 0.95,
            "requires_human_review": False, "source": "auth.log",
        }

    # NEW: SSH invalid user enumeration detection
    m = re.search(r"Invalid user (\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "AUTH_FAILURE",
            "source_ip": ip, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 22,
            "service": "SSH",
            "description": f"SSH user enumeration — invalid user '{user}' tried from {ip}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": [
                f"Possible user enumeration from {ip}",
                f"Block: iptables -A INPUT -s {ip} -j DROP"
            ],
            "confidence_score": 0.90,
            "requires_human_review": True, "source": "auth.log",
        }

    m = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        severity = "MEDIUM" if user == "root" else "INFO"
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": severity, "event_type": "AUTH_FAILURE" if user == "root" else "NORMAL",
            "source_ip": ip, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 22,
            "service": "SSH",
            "description": f"Successful SSH login: user='{user}' from {ip}",
            "raw_log": line.strip(), "action_taken": "ALLOWED",
            "recommended_actions": ["Verify this login was authorized"] if user == "root" else [],
            "confidence_score": 0.99,
            "requires_human_review": user == "root", "source": "auth.log",
        }

    m = re.search(r"sudo:.*?(\S+)\s*:.*COMMAND=(.*)", line)
    if m:
        user, cmd = m.group(1), m.group(2).strip()
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "MEDIUM", "event_type": "PRIVILEGE_ESCALATION",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0,
            "service": "sudo",
            "description": f"Sudo command by '{user}': {cmd}",
            "raw_log": line.strip(), "action_taken": "ALLOWED",
            "recommended_actions": ["Review if this sudo usage was authorized"],
            "confidence_score": 0.85,
            "requires_human_review": True, "source": "auth.log",
        }

    if "new user" in line_lower or "useradd" in line_lower:
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "PRIVILEGE_ESCALATION",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0,
            "service": "useradd",
            "description": f"New user account created: {line.strip()}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": ["Verify this user creation was authorized"],
            "confidence_score": 0.90,
            "requires_human_review": True, "source": "auth.log",
        }

    return None


def parse_ufw(line: str):
    if "UFW BLOCK" not in line and "UFW ALLOW" not in line:
        return None

    ts     = datetime.utcnow().isoformat() + "Z"
    action = "BLOCKED" if "UFW BLOCK" in line else "ALLOWED"
    severity = "MEDIUM" if action == "BLOCKED" else "INFO"

    src_ip = dest_ip = "unknown"
    src_port = dest_port = 0
    proto = "unknown"

    m = re.search(r"SRC=(\S+)", line)
    if m: src_ip = m.group(1)
    m = re.search(r"DST=(\S+)", line)
    if m: dest_ip = m.group(1)
    m = re.search(r"SPT=(\d+)", line)
    if m: src_port = int(m.group(1))
    m = re.search(r"DPT=(\d+)", line)
    if m: dest_port = int(m.group(1))
    m = re.search(r"PROTO=(\S+)", line)
    if m: proto = m.group(1)

    return {
        "id": str(uuid.uuid4())[:8], "timestamp": ts,
        "severity": severity, "event_type": "FIREWALL_BLOCK" if action == "BLOCKED" else "NORMAL",
        "source_ip": src_ip, "dest_ip": dest_ip,
        "source_port": src_port, "dest_port": dest_port,
        "service": proto,
        "description": f"UFW {action}: {src_ip}:{src_port} -> {dest_ip}:{dest_port} [{proto}]",
        "raw_log": line.strip(), "action_taken": action,
        "recommended_actions": [f"Review traffic from {src_ip}"] if action == "BLOCKED" else [],
        "confidence_score": 0.95,
        "requires_human_review": False, "source": "UFW Firewall",
    }


def parse_kern(line: str):
    line_lower = line.lower()
    ts = datetime.utcnow().isoformat() + "Z"

    if "iptables" in line_lower and ("drop" in line_lower or "reject" in line_lower):
        src_ip = dest_ip = "unknown"
        m = re.search(r"SRC=(\S+)", line)
        if m: src_ip = m.group(1)
        m = re.search(r"DST=(\S+)", line)
        if m: dest_ip = m.group(1)
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "MEDIUM", "event_type": "FIREWALL_BLOCK",
            "source_ip": src_ip, "dest_ip": dest_ip,
            "source_port": 0, "dest_port": 0,
            "service": "iptables",
            "description": f"iptables DROP: {src_ip} -> {dest_ip}",
            "raw_log": line.strip(), "action_taken": "BLOCKED",
            "recommended_actions": [f"Investigate {src_ip}"],
            "confidence_score": 0.90,
            "requires_human_review": False, "source": "kern.log",
        }

    if "oom" in line_lower or "out of memory" in line_lower:
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "SUSPICIOUS_TRAFFIC",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0,
            "service": "kernel",
            "description": f"Kernel OOM event — possible DoS: {line.strip()[:100]}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": ["Check for memory exhaustion attack (DoS)"],
            "confidence_score": 0.80,
            "requires_human_review": True, "source": "kern.log",
        }

    return None


def parse_syslog(line: str):
    line_lower = line.lower()
    ts = datetime.utcnow().isoformat() + "Z"

    if "segfault" in line_lower or "core dumped" in line_lower:
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "HIGH", "event_type": "SUSPICIOUS_TRAFFIC",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0,
            "service": "syslog",
            "description": f"Process crash/segfault detected: {line.strip()[:120]}",
            "raw_log": line.strip(), "action_taken": "LOGGED",
            "recommended_actions": ["Investigate potential exploitation attempt"],
            "confidence_score": 0.75,
            "requires_human_review": True, "source": "syslog",
        }

    if "cron" in line_lower and ("cmd" in line_lower or "exec" in line_lower):
        return {
            "id": str(uuid.uuid4())[:8], "timestamp": ts,
            "severity": "LOW", "event_type": "POLICY_VIOLATION",
            "source_ip": UBUNTU_HOST, "dest_ip": UBUNTU_HOST,
            "source_port": 0, "dest_port": 0,
            "service": "cron",
            "description": f"Cron job executed: {line.strip()[:120]}",
            "raw_log": line.strip(), "action_taken": "ALLOWED",
            "recommended_actions": ["Verify cron job is legitimate"],
            "confidence_score": 0.70,
            "requires_human_review": False, "source": "syslog",
        }

    return None


PARSERS = {
    "suricata": parse_suricata,
    "auth":     parse_auth,
    "ufw":      parse_ufw,
    "kern":     parse_kern,
    "syslog":   parse_syslog,
}


# Generic SSH tail thread
def tail_log(source_name: str, log_path: str):
    while True:
        ssh_client = None
        try:
            print(f"[{source_name}] Connecting to {UBUNTU_HOST}...")
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=UBUNTU_HOST, username=UBUNTU_USER,
                password=UBUNTU_PASS, timeout=10
            )
            source_status[source_name]["connected"] = True
            source_status[source_name]["error"]     = None
            print(f"[{source_name}] Connected! Tailing {log_path}...")

            channel = ssh_client.get_transport().open_session()
            channel.exec_command(f"tail -F {log_path} 2>/dev/null")

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


# SOC System Prompt
SOC_SYSTEM_PROMPT = """You are an elite AI-powered Security Operations Center (SOC) / XDR analyst.
You have real-time access to MULTIPLE live log sources from a monitored Linux server:
- Suricata IDS  → network attacks, port scans, brute force, malware signatures
- auth.log      → SSH logins, failed passwords, sudo usage, new users
- UFW Firewall  → blocked/allowed connections
- kern.log      → kernel events, iptables drops, OOM (DoS indicators)
- syslog        → process crashes, cron jobs (persistence indicators)

Your capabilities:
1. Analyze events from ALL sources and explain in plain language
2. Correlate across sources to detect attack campaigns:
   - port scan (Suricata) + brute force (auth.log) = coordinated attack
   - UFW block + kern drop from same IP = persistent attacker
   - segfault (syslog) after exploit attempt (Suricata) = successful exploitation
3. Identify attack kill chain stages: Recon → Exploit → Persistence → Exfiltration
4. Give exact remediation commands: iptables, fail2ban, ufw, passwd
5. Prioritize incidents by risk

Response style:
- Use 🔴 CRITICAL 🟠 HIGH 🟡 MEDIUM 🟢 LOW ⚪ INFO
- Always cite source log, timestamp, and IP
- For attacks: explain the kill chain
- For blocking: give exact commands
- When alerting about suspicious activity: be URGENT and DIRECT
You are the last line of defense. Be precise and actionable."""


ALERT_SYSTEM_PROMPT = """You are an elite SOC analyst receiving an AUTOMATED THREAT ALERT.
A behavioral detection engine has flagged suspicious activity that may have evaded signature-based IDS.

Your job:
1. Explain what is happening in plain English — be URGENT and clear
2. Identify the attack stage in the kill chain
3. Give the EXACT commands to stop it RIGHT NOW
4. Explain what could happen if no action is taken

Be direct, urgent, and actionable. Start with ⚠️ ALERT and the threat type.
Format remediation as numbered steps with exact commands."""


def get_events_context():
    recent = security_events[:50]
    if not recent:
        return "No security events yet. All log sources are being monitored."

    lines = ["=== LIVE SECURITY EVENTS — ALL SOURCES (last 50) ===\n"]
    for ev in recent:
        lines.append(
            f"[{ev['timestamp']}] [{ev['severity']}] [{ev['source']}] {ev['event_type']} | "
            f"src:{ev['source_ip']}:{ev.get('source_port','')} -> "
            f"dst:{ev['dest_ip']}:{ev['dest_port']} | "
            f"{ev['description']}"
        )

    critical   = sum(1 for e in security_events if e["severity"] == "CRITICAL")
    high       = sum(1 for e in security_events if e["severity"] == "HIGH")
    unique_ips = len(set(e["source_ip"] for e in security_events))
    sources    = list(set(e["source"] for e in security_events))
    lines.append(f"\n=== STATS === Total:{len(security_events)} | Critical:{critical} | High:{high} | Unique IPs:{unique_ips} | Sources:{sources}")
    return "\n".join(lines)


# Routes

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
    """Returns queued threat alerts for the frontend to display."""
    with alert_lock:
        alerts = list(pending_alerts)
        pending_alerts.clear()
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/ip_activity", methods=["GET"])
def get_ip_activity():
    """Returns behavioral tracking data per IP."""
    result = {}
    for ip, data in ip_activity.items():
        result[ip] = {
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
            "total_events": data["total_events"],
            "auth_failures": len(data["auth_failures"]),
            "ufw_blocks": len(data["ufw_blocks"]),
            "flagged": data["flagged"],
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


@app.route("/api/chat", methods=["POST"])
def chat():
    data       = request.get_json()
    message    = data.get("message", "")
    session_id = data.get("session_id", str(uuid.uuid4()))
    if session_id not in chat_sessions:
        chat_sessions[session_id] = [{"role": "system", "content": SOC_SYSTEM_PROMPT}]
    context_message = f"{get_events_context()}\n\nUser question: {message}"
    chat_sessions[session_id].append({"role": "user", "content": context_message})
    return jsonify({"session_id": session_id, "status": "ready"})


@app.route("/api/alert_chat", methods=["POST"])
def alert_chat():
    """
    Special endpoint — AI automatically explains a threat alert
    and tells the user what actions to take.
    """
    data    = request.get_json()
    alert   = data.get("alert", {})
    event   = data.get("event", {})
    session_id = data.get("session_id", str(uuid.uuid4()))

    # Build urgent context for the AI
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

Analyze this threat alert and tell the SOC analyst:
1. What is happening RIGHT NOW
2. How serious is this
3. Exact steps to stop it immediately
"""

    chat_sessions[session_id] = [
        {"role": "system", "content": ALERT_SYSTEM_PROMPT},
        {"role": "user", "content": alert_context}
    ]
    return jsonify({"session_id": session_id, "status": "ready"})


@app.route("/api/stream", methods=["GET"])
def stream():
    session_id = request.args.get("session_id")
    if not session_id or session_id not in chat_sessions:
        return jsonify({"error": "Invalid session"}), 400

    def generate():
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=chat_sessions[session_id],
                stream=True, temperature=0.3, max_tokens=1500
            )
            full_response = ""
            for chunk in response:
                if chunk.choices[0].delta and chunk.choices[0].delta.content:
                    token = chunk.choices[0].delta.content
                    full_response += token
                    yield f"data: {json.dumps({'token': token})}\n\n"
            chat_sessions[session_id].append({"role": "assistant", "content": full_response})
            yield f"data: {json.dumps({'done': True})}\n\n"
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


@app.route("/api/alerts/active", methods=["GET"])
def get_active_alerts():
    """Returns live counters for ongoing attacks — frontend polls this to update existing alert cards."""
    active = {}
    for ip, data in ip_activity.items():
        if data["brute_force_count"] >= 5:
            active[f"brute_{ip}"] = {
                "count": data["brute_force_count"],
                "ip": ip,
                "type": "BRUTE_FORCE_DETECTED",
            }
    return jsonify(active)


for src_name, src_path in LOG_SOURCES.items():
    threading.Thread(target=tail_log, args=(src_name, src_path), daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)