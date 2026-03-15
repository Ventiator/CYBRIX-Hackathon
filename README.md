# CYBRIX — AI-Powered Security Operations Center

> Real-time multi-vendor threat detection, AI analysis, and auto-remediation powered by GPT-4.1

![Status](https://img.shields.io/badge/Status-Live-green) ![Python](https://img.shields.io/badge/Python-3.10+-blue) ![AI](https://img.shields.io/badge/AI-GPT--4.1-orange) ![Devices](https://img.shields.io/badge/Devices-Ubuntu%20%7C%20Fortigate%20%7C%20Cisco-purple) ![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)

---

![CYBRIX Dashboard](screenshots/dashboard.png)

---

## What is CYBRIX?

CYBRIX is a real-time SOC (Security Operations Center) dashboard that monitors multiple network devices simultaneously, detects attacks using behavioral analysis, automatically blocks threats with one click on the actual device, and sends instant Slack/email notifications with threat intelligence enrichment.

### Supported Devices

| Device | Connection | What it monitors |
|--------|-----------|-----------------|
| Ubuntu + Suricata | SSH real-time tail | auth.log, ufw, kern.log, syslog, IDS alerts |
| Fortigate Firewall | Syslog push UDP 514 | Malware, IPS, firewall blocks, URL filter, botnet C&C |
| Cisco IOS | netmiko SSH polling | ACL logs, login failures, port scans |

---

## Features

### 🔴 Real-Time Threat Detection
- SSH brute force (5+ failures in 5 minutes → CRITICAL alert)
- Slow port scan / T0 evasion detection
- Coordinated kill-chain attacks (recon + credential access same IP)
- Persistent attacker detection
- Malware, IPS alerts, botnet C&C from Fortigate
- High volume DoS/flood detection

### 🤖 AI SOC Analyst (GPT-4.1)
- Answers natural language questions about your infrastructure
- Knows which device each event came from — gives device-specific commands
- Tracks attack silence windows — knows exactly when attacks stop
- Cross-device threat correlation and executive summary

### ⚡ Auto-Remediation
- **Ubuntu** — pushes UFW + iptables block rules via SSH, verifies rule exists
- **Fortigate** — creates firewall address object (`CYBRIX_BLOCK_x_x_x_x`) via paramiko
- **Cisco IOS** — adds deny ACE to `CYBRIXBLOCKLIST` ACL via netmiko
- **Rate limiting** — hashlimit SSH rate limiting (configurable connections/min)
- **Unblock** — removes rules from all device types instantly

### 🌍 Threat Intelligence Enrichment
- Every attacker IP automatically enriched with **IPInfo** (country, city, ISP)
- **VirusTotal** integration — shows how many vendors flagged the IP as malicious
- Results cached for 1 hour — no rate limit issues
- Shown inline on every threat popup: `📍 Athens GR | 🦠 23/90 vendors`

### 🔔 Notifications
- **Slack** — clean Block Kit messages with severity color, TI data, and remediation commands
- **Email** — SMTP alerts for CRITICAL/HIGH threats

### 📋 Command System
Type `!commands` directly in the AI chat for instant execution (no AI call):

| Command | Description |
|---------|-------------|
| `!help` | Show all commands |
| `!block <ip>` | Block IP on Ubuntu |
| `!block <ip> fortigate-main` | Block IP on Fortigate |
| `!block <ip> cisco-10_0_0_1` | Block IP on Cisco |
| `!ratelimit <ip> 3` | Rate limit to 3 SSH/min |
| `!unblock <ip>` | Remove block from device |
| `!updatelimit <ip> 5` | Change rate limit |
| `!listblocked` | Show all managed IPs |
| `!listdevices` | Show connected devices |
| `!status <ip>` | Show rules for IP |
| `!clearall` | Remove all CYBRIX rules |

### 🛡 Managed IPs Panel
- View all blocked/rate-limited IPs with device, mode, timestamp
- Edit rate limit per IP and click APPLY
- UNBLOCK removes rules from the actual device via SSH

### 🔔 Alert History
- Click the threat counter badge to open full alert history
- Full action buttons (BLOCK, RATE-LIMIT, COPY CMD, DISMISS) per alert
- Tracks remediated state — shows ✅ BLOCKED badge if already actioned

---

## Quick Start

### Option A — Python directly

```bash
# 1. Clone
git clone https://github.com/Ventiator/CYBRIX-Hackathon.git
cd CYBRIX-Hackathon

# 2. Install
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env with your credentials

# 4. Run
python app.py
```

Open **http://localhost:5000**

### Option B — Docker

```bash
docker build -t cybrix .
docker run -p 5000:5000 -p 514:514/udp --env-file .env cybrix
```

> **Note for Windows + Docker Desktop:** Docker Desktop uses a Linux VM isolated from Hyper-V. If your devices are on a Hyper-V internal switch, run with `python app.py` directly instead.

---

## Configuration (.env)

```env
# Required
OPENAI_API_KEY=your_openai_api_key

# Ubuntu Server
UBUNTU_HOST=192.168.100.20
UBUNTU_USER=your_username
UBUNTU_PASS=your_password

# Windows PC running CYBRIX
WINDOWS_HOST=192.168.100.1

# Fortigate (optional)
FORTIGATE_HOST=192.168.108.200
FORTIGATE_USER=admin
FORTIGATE_PASS=your_password

# VirusTotal (optional — free key at virustotal.com)
VT_API_KEY=your_vt_api_key

# Slack (optional — webhook from api.slack.com/apps)
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Email (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=your_app_password
ALERT_EMAIL=alerts@yourcompany.com
```

---

## Device Setup

### Ubuntu Server
```bash
# Enable SSH and UFW
sudo ufw allow 22/tcp && sudo ufw enable
sudo systemctl start suricata

# Allow passwordless iptables (required for auto-block)
sudo visudo
# Add: your_user ALL=(ALL) NOPASSWD: /sbin/iptables
```

### Fortigate
```
config log syslogd setting
    set status enable
    set server YOUR_CYBRIX_PC_IP
    set port 514
end

# Test it works
diagnose log test
```

Then click **+ ADD DEVICE** in dashboard to register for auto-block.

### Cisco IOS
```
ip ssh version 2
username admin privilege 15 secret YourPassword
line vty 0 4
 login local
 transport input ssh
logging on
logging buffered 10000
```

Add via **+ ADD DEVICE** in dashboard. After CYBRIX blocks an IP, apply ACL:
```
interface GigabitEthernet0/0
 ip access-group CYBRIXBLOCKLIST in
```

---

## Demo Scenario

### Live Attack (Ubuntu)
1. Start Hydra from Kali: `hydra -l root -P rockyou.txt ssh://UBUNTU_IP -t 4`
2. Watch AUTH_FAILURE events flood the dashboard
3. BRUTE FORCE DETECTED popup appears with threat intel
4. Click ⚡ BLOCK — rule pushed to Ubuntu, verified automatically
5. Ask AI: *"is the attack still happening?"* — correctly reports SILENT

### Fortigate Demo
1. In Fortigate CLI: `diagnose log test`
2. Malware, IPS, firewall blocks appear instantly
3. Ask AI: *"what is fortigate detecting right now?"*
4. Click ⚡ BLOCK — address object created on Fortigate
5. Verify: `show firewall address CYBRIX_BLOCK_x_x_x_x`

### AI Questions
```
is there an attack happening right now?
what is fortigate detecting right now?
tell me everything about ip 192.168.100.10
which is the most dangerous threat and what should I do first?
give me an executive summary of all security incidents
how do I block ip 1.2.3.4 on fortigate?
are there attacks on multiple devices simultaneously?
```

---

## Verify Blocks

**Ubuntu:**
```bash
sudo iptables -L INPUT -n | grep CYBRIX
sudo ufw status numbered
```

**Fortigate:**
```
show firewall address CYBRIX_BLOCK_x_x_x_x
```

**Cisco:**
```
show ip access-lists CYBRIXBLOCKLIST
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10 + Flask |
| AI | OpenAI GPT-4.1 |
| SSH Ubuntu/Fortigate | paramiko (invoke_shell for Fortigate) |
| SSH Cisco | netmiko (handles pagination + enable mode) |
| IDS | Suricata (eve.json real-time parsing) |
| Syslog Receiver | UDP 514 background thread |
| Threat Intel | VirusTotal API + IPInfo |
| Notifications | Slack Block Kit + SMTP Email |
| Frontend | HTML + CSS + Vanilla JS |

---

## File Structure

```
cybrix/
├── app.py              # Backend — parsers, AI, threat detection, remediation
├── templates/
│   └── index.html      # Dashboard UI
├── static/
│   ├── app.js          # Frontend logic
│   └── style.css       # Cyberpunk dark theme
├── Dockerfile
├── requirements.txt
├── .env.example        # Environment template
└── README.md
```

---

*Hackathon 2026*
