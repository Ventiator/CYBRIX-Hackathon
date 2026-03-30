# CYBRIX — AI-Powered Security Operations Center

> Real-time multi-vendor threat detection and auto-remediation powered by GPT-4.1

![Dashboard](https://img.shields.io/badge/Status-Live-green) ![Python](https://img.shields.io/badge/Python-3.10+-blue) ![AI](https://img.shields.io/badge/AI-GPT--4.1-orange) ![Devices](https://img.shields.io/badge/Devices-Ubuntu%20%7C%20Fortigate%20%7C%20Cisco-purple)

---

## What is CYBRIX?

CYBRIX is a real-time SOC (Security Operations Center) dashboard that monitors multiple network devices simultaneously, detects attacks using behavioral analysis, and automatically blocks threats with one click — on the actual device.

![d](https://media.discordapp.net/attachments/1480146658149798051/1484135062478782484/Screenshot_from_2026-03-19_12-22-00.png?ex=69cba07c&is=69ca4efc&hm=c5bcf59ca98d90ac18b793a2e2239c450d0f8f9446776d75d5343c6a5469c3cd&=&format=webp&quality=lossless)

### Supported Devices
| Device | Method | Capabilities |
|--------|--------|-------------|
| Ubuntu + Suricata | SSH real-time tail | auth.log, ufw, kern.log, syslog, IDS |
| Fortigate Firewall | Syslog push UDP 514 | Malware, IPS, firewall blocks, URL filter |
| Cisco IOS | netmiko SSH polling | ACL logs, login failures, port scans |

---

## Features

- 🔴 **Real-time threat detection** — brute force, port scans, malware, botnet C&C, coordinated attacks
- 🤖 **AI SOC Analyst** — GPT-4.1 answers questions about your infrastructure in natural language
- ⚡ **Auto-remediation** — one click blocks attacker on Ubuntu (iptables+UFW), Fortigate (address object), or Cisco (ACL)
- ⏱ **Rate limiting** — SSH rate limiting with configurable connections/minute
- 📋 **Command system** — type `!block`, `!ratelimit`, `!unblock`, `!listdevices` directly in chat
- 🔔 **Alert history** — full history of all threat alerts with action buttons
- 🛡 **Managed IPs** — view, edit, and unblock all managed IPs across all devices
- 🔍 **Search** — real-time search across all security events
- 🌍 **Threat Intelligence** — automatic IP enrichment with IPInfo (country, ISP) and VirusTotal (malicious vendor score)
- 🔔 **Notifications** — instant Slack (Block Kit) and Email alerts for CRITICAL/HIGH threats

---

## Quick Start

### 1. Clone
```bash
git clone https://github.com/yourusername/cybrix.git
cd cybrix
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Create .env file
```env
OPENAI_API_KEY=your_openai_api_key

UBUNTU_HOST=192.168.100.20
UBUNTU_USER=your_username
UBUNTU_PASS=your_password

WINDOWS_HOST=192.168.100.1

FORTIGATE_HOST=192.168.108.200
FORTIGATE_USER=admin
FORTIGATE_PASS=your_fortigate_password

# Threat Intelligence (optional — free key at virustotal.com)
VT_API_KEY=your_virustotal_api_key

# Slack notifications (optional — webhook from api.slack.com/apps)
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Email notifications (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=your_app_password
ALERT_EMAIL=alerts@yourcompany.com
```

### 4. Run
```bash
python app.py
```

Open browser at **http://localhost:5000**

---

## Docker

```bash
docker build -t cybrix .
docker run -p 5000:5000 -p 514:514/udp --env-file .env cybrix
```

---

## Device Setup

### Ubuntu Server
```bash
sudo ufw allow 22/tcp && sudo ufw enable
sudo systemctl start suricata
# Allow passwordless iptables for auto-block:
sudo visudo
# Add: your_user ALL=(ALL) NOPASSWD: /sbin/iptables
```

### Fortigate
```
config log syslogd setting
    set status enable
    set server YOUR_PC_IP
    set port 514
end
diagnose log test   # test it works
```

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
Then add via **+ ADD DEVICE** in the dashboard.

---

## Chat Commands

| Command | Description |
|---------|-------------|
| `!help` | Show all commands |
| `!block <ip>` | Block IP on Ubuntu |
| `!block <ip> fortigate-main` | Block IP on Fortigate |
| `!block <ip> cisco-10_0_0_1` | Block IP on Cisco |
| `!ratelimit <ip> 3` | Rate limit to 3 SSH/min |
| `!unblock <ip>` | Remove block from device |
| `!listblocked` | Show all managed IPs |
| `!listdevices` | Show connected devices |
| `!status <ip>` | Show rules for IP |

---

## Demo Questions for AI

```
is there an attack happening right now?
what is fortigate detecting right now?
tell me everything about ip 192.168.100.10
which is the most dangerous threat and what should I do first?
give me an executive summary of all security incidents
how do I block ip 1.2.3.4 on fortigate?
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

- **Backend:** Python 3.10 + Flask
- **AI:** OpenAI GPT-4.1
- **SSH Ubuntu/Fortigate:** paramiko
- **SSH Cisco:** netmiko
- **Frontend:** HTML + CSS + Vanilla JS
- **IDS:** Suricata (eve.json)
- **Syslog:** UDP 514 receiver
- **Threat Intel:** VirusTotal API + IPInfo

---

*Hackathon Project 2026*
