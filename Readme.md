ContextPrivesc

**AI-Powered Linux Privilege Escalation Scanner**

---

## Overview

ContextPrivesc is a Linux privilege escalation detection tool that performs comprehensive system enumeration, identifies vulnerabilities, and provides exploit commands. It features a web dashboard with real-time monitoring and DeepSeek AI integration for intelligent security analysis.

---

## Quick Start

```bash
# 1. Create directory
mkdir -p ~/contextprivesc/templates
cd ~/contextprivesc

# 2. Copy all project files to the directory

# 3. Install dependencies
sudo bash setup.sh

# 4. Start web server
sudo python3 web/server.py --port 8080

# 5. Open browser
firefox http://localhost:8080

Features
System Enumeration
OS detection and kernel version analysis

CPU, memory, disk information

Kernel exploit detection (DirtyCow, DirtyPipe, PwnKit)

/tmp writable check

User & Authentication
Current user info (whoami, uid, gid)

/etc/passwd and /etc/shadow readability

Writable /etc/passwd detection (CRITICAL)

Group membership (sudo, docker, lxd)

Passwordless accounts detection

Sudo Privileges
sudo -l enumeration

NOPASSWD rules detection

Sudo ALL privileges detection

Baron Samedit (CVE-2021-3156) check

Dangerous sudo binaries detection (bash, python, vim, etc.)

SUID Binaries
SUID file search

GTFOBins integration for exploit commands

Dangerous SUID binary detection

Cron Jobs
/etc/crontab analysis

Cron directory scanning

Writable cron file detection (CRITICAL)

Cron script injection vectors

File Permissions
/etc/shadow readable/writable (CRITICAL)

/etc/passwd readable/writable (CRITICAL)

/root directory accessible (CRITICAL)

.env file detection

Backup file discovery (.bak, .old, .swp)

Credentials in log files

Container Escape
Docker socket detection

Docker group membership check

LXD/LXC detection

CAP_SYS_ADMIN capability check

PATH Hijacking
Writable PATH directory detection (CRITICAL)

LD_PRELOAD check

Writable library path detection

Network Services
Listening ports enumeration

SSH configuration analysis

SSH private key discovery

Database Credentials
MySQL no password login

Redis no authentication

PostgreSQL configuration exposure

SQLite database file discovery

Web Dashboard
Live terminal output

Color-coded finding cards

VIEW DETAILS modal with exploit commands

One-click copy to clipboard

MITRE ATT&CK mapping display

Statistics counter (CRITICAL/WARNING/INFO)

START AI button for AI analysis

Output Formats
Color-coded terminal output

JSON output (findings.json)

Full log file (scan.log)

Metadata JSON (metadata.json)

Project Structure
text
contextprivesc/
│
├── core/                          # Core scanning engine
│   ├── __init__.py                # Package initializer
│   ├── scanner.py                 # Main scanning engine
│   ├── mitre_db.py                # MITRE ATT&CK database
│   ├── gtfobins_db.py             # GTFOBins exploit database
│   └── cve_lookup.py              # CVE lookup module
│
├── ai/                            # AI integration module
│   ├── __init__.py                # Package initializer
│   └── deepseek_client.py         # DeepSeek AI integration
│
├── web/                           # Web server module
│   ├── __init__.py                # Package initializer
│   ├── server.py                  # Flask web server
│   └── templates/
│       └── dashboard.html         # Web dashboard interface
│
├── utils/                         # Utilities module
│   ├── __init__.py                # Package initializer
│   └── constants.py               # Configuration constants
│
├── results/                       # Scan results storage (auto-created)
│
├── setup.sh                       # Installation script
└── README.md                      # Documentation

Directory Details
Directory	Purpose	Key Files
core/	Core scanning engine	scanner.py, mitre_db.py, gtfobins_db.py, cve_lookup.py
ai/	AI integration	deepseek_client.py
web/	Web server and dashboard	server.py, templates/dashboard.html
utils/	Utilities and constants	constants.py
results/	Scan output storage	Auto-generated JSON and log files

Installation
Prerequisites
Operating System: Kali Linux / Ubuntu 20.04+ / Debian 11+

RAM: 2GB minimum (4GB recommended)

Disk Space: 500MB

Python 3.8+

Internet connection (for AI API)

Step-by-Step Installation
bash
# 1. Create directory structure
mkdir -p ~/contextprivesc/{core,ai,web/templates,utils,results}
cd ~/contextprivesc

# 2. Create __init__.py files
touch core/__init__.py ai/__init__.py web/__init__.py utils/__init__.py

# 3. Copy all project files to respective directories

# 4. Run installation
sudo bash setup.sh

# 5. Verify installation
python3 -c "import flask; print('Flask OK')"
python3 -c "import requests; print('Requests OK')"

Usage
CLI Mode
bash
# Run comprehensive scan (2-5 minutes)
sudo python3 core/scanner.py

# Quick scan (30-60 seconds)
sudo python3 core/scanner.py --quick

# Full scan (5-10 minutes)
sudo python3 core/scanner.py --mode full

# JSON output only
sudo python3 core/scanner.py --json > results.json
Web Dashboard
bash
# Start web server (AI automatically enabled)
sudo python3 web/server.py --port 8080

# Open browser
firefox http://localhost:8080

Dashboard Usage
Click START SCAN button

Monitor real-time output in terminal panel

Click on finding cards to view details

Click VIEW DETAILS for full information and exploit commands

Click START AI after scan completes for AI analysis

AI Integration
ContextPrivesc integrates with DeepSeek AI (API key permanently embedded).

AI Features
Vulnerability prioritization

Exact exploit command generation

Step-by-step exploitation guide

Root access methodology

Remediation commands

API Configuration
python
# web/server.py (line 20-22)
DEEPSEEK_API_KEY = "sk-faf7fc01b0804802a1d1faa1cb36176f"
DEEPSEEK_API_BASE = "https://api.deepseek.com/v1"
No manual API key configuration required!

Output Format
Directory Structure
text
/tmp/contextprivesc_YYYYMMDD_HHMMSS/
├── findings.json      # All findings in JSON format
├── metadata.json      # Scan metadata
└── scan.log           # Full terminal log

findings.json Example
json
{
  "id": 1,
  "severity": "CRITICAL",
  "category": "Sudo",
  "title": "Baron Samedit (CVE-2021-3156)",
  "detail": "Sudo version vulnerable to heap overflow",
  "mitre_id": "T1068",
  "mitre_name": "Exploitation for Privilege Escalation",
  "exploit": "sudoedit -s / '$(python3 -c \"print(\\\"A\\\"*65536)\")'",
  "cve": "CVE-2021-3156",
  "timestamp": "2026-04-27T00:32:35.493221"
}

metadata.json Example
json
{
  "scan_time": "2026-04-27T00:32:35.474697",
  "hostname": "target-system",
  "kernel": "6.19.11+kali-amd64",
  "os": "Kali GNU/Linux Rolling",
  "user": "root",
  "uid": 0,
  "critical_count": 30,
  "warning_count": 24,
  "info_count": 13,
  "total_findings": 67,
  "output_directory": "/tmp/contextprivesc_20260427_003235"
}

Scan Findings Categories
What ContextPrivesc Detects
Category	Findings
System Information	OS, kernel version, CPU, memory, disk, hostname
Kernel Exploits	DirtyCow (CVE-2016-5195), DirtyPipe (CVE-2022-0847), PwnKit (CVE-2021-4034)
Sudo Vulnerabilities	NOPASSWD rules, ALL privileges, Baron Samedit (CVE-2021-3156)
SUID Binaries	bash, sh, python, perl, ruby, find, vim, vi, nano, less, more, awk, sed, cp, chmod, nmap, php, node, docker, git, tar, make, gcc, strace, gdb
Cron Jobs	Writable cron files, writable scripts, writable crontab
File Permissions	/etc/shadow read/write, /etc/passwd read/write, /etc/sudoers readable, /root readable, world-writable config files
Container Escape	Docker socket, docker group, LXD group, CAP_SYS_ADMIN capability
PATH Hijacking	Writable PATH directories (/usr/local/sbin, /usr/local/bin, /usr/sbin, /usr/bin, /sbin, /bin)
Network Services	Listening ports, SSH configuration (PermitRootLogin, PasswordAuthentication), SSH private keys
Database Credentials	MySQL no password, Redis no auth, PostgreSQL configuration, SQLite databases
Backup Files	.bak, .backup, .old, .swp files
Credentials	.env files, passwords in logs

Example Scan Results
text
============================================================
SCAN COMPLETE - NORMAL MODE
============================================================
CRITICAL Findings: 30
WARNING Findings:  24
INFO Findings:     13
Total Findings:    67
Results saved to:  /tmp/contextprivesc_20260427_003950
============================================================

Troubleshooting
Issue	Solution
Port already in use	sudo kill -9 $(sudo lsof -t -i :8080)
AI not configured	API key is embedded; clear browser cache (Ctrl+Shift+R)
No findings detected	Run as root: sudo python3 core/scanner.py
Flask not found	sudo apt-get install python3-flask
WebSocket errors	Check firewall; ensure port 8080 is open
Module not found	Ensure __init__.py files exist in all directories
Debug Mode
bash
# Run web server with debug
sudo python3 web/server.py --port 8080 --debug

# Test scanner directly
sudo python3 core/scanner.py --quick

Security Considerations
Important Warnings
Educational Use Only - For authorized testing and educational purposes only

Root Permission Required - Full system enumeration requires sudo access

API Key Exposure - API key visible in source; rotate for production

Output Sensitivity - Scan results contain sensitive system information

Best Practices
Always obtain authorization before scanning any system

Use in isolated environments for testing

Review findings offline in secure environment

Delete results after analysis if sensitive

Rotate API key for production deployments

License
text
MIT License

Copyright (c) 2024 ContextPrivesc Team

This tool is provided for EDUCATIONAL PURPOSES ONLY.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software for authorized security testing and educational purposes.

Unauthorized use against systems without explicit permission is PROHIBITED.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

Acknowledgments
DeepSeek AI - For providing the AI API

MITRE Corporation - For ATT&CK framework

GTFOBins Team - For privilege escalation binary database

Flask Community - For web framework

<div align="center">
Made for Security Researchers & Penetration Testers

Use Responsibly. Stay Ethical.

</div> 
