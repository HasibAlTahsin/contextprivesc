#  ContextPrivesc v1.0

<div align="center">

**AI-Powered Linux Privilege Escalation Scanner**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1+-red.svg)](https://flask.palletsprojects.com)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://linux.org)

*Comprehensive system enumeration • Intelligent vulnerability prioritization • Real-time web dashboard*

</div>


---

##  Overview

**ContextPrivesc** is an advanced Linux privilege escalation detection tool designed for security researchers, penetration testers, and CTF enthusiasts. It combines traditional enumeration techniques with intelligent analysis to deliver actionable security intelligence through a modern web interface.

### Key Capabilities

| Capability | Description |
|------------|-------------|
|  **System Enumeration** | Complete OS, kernel, hardware, and configuration analysis |
|  **Vulnerability Detection** | Identifies known CVEs, misconfigurations, and weak permissions |
|  **Exploit Generation** | Provides exact exploit commands via GTFOBins integration |
|  **AI Analysis** | DeepSeek-powered security analysis and attack chain recommendations |
|  **MITRE Mapping** | Automatic mapping to MITRE ATT&CK framework |
|  **Web Dashboard** | Real-time monitoring with intuitive, color-coded interface |

>  **Disclaimer:** This tool is for **educational purposes, CTF competitions, and authorized security testing only**. Unauthorized use against systems without explicit permission is prohibited.

---

##  Quick Start

```bash
# 1. Create project directory
mkdir -p ~/contextprivesc/templates
cd ~/contextprivesc

# 2. Copy all project files to their respective directories

# 3. Install dependencies
sudo bash setup.sh

# 4. Start web server
sudo python3 web/server.py --port 8080

# 5. Open browser
firefox http://localhost:8080
```

>  **Tip:** The web dashboard provides the best user experience. CLI mode is also available for automation.

---

##  Features

###  System Enumeration
| Feature | Description | Severity |
|---------|-------------|----------|
| OS Detection | Operating system identification and version parsing | INFO |
| Kernel Analysis | Kernel version check with exploit matching | INFO |
| Kernel Exploits | DirtyCow, DirtyPipe, PwnKit, OverlayFS detection | CRITICAL |
| Hardware Info | CPU, memory, disk, and architecture enumeration | INFO |
| /tmp Writable | Temporary directory permission analysis | WARNING |

###  User & Authentication
| Feature | Description | Severity |
|---------|-------------|----------|
| Current User | whoami, UID, GID, and group membership display | INFO |
| /etc/passwd | Readability check and user enumeration | INFO |
| /etc/shadow | Shadow file accessibility (password hash exposure) | CRITICAL |
| Writable Files | Detection of writable /etc/passwd, /etc/shadow, /etc/group | CRITICAL |
| Group Analysis | sudo, docker, lxd, and other privileged group checks | WARNING |
| Passwordless Accounts | Detection of accounts without password protection | CRITICAL |

###  Sudo Privilege Escalation
| Feature | Description | Severity |
|---------|-------------|----------|
| sudo -l | Enumeration of sudo privileges and NOPASSWD rules | INFO |
| NOPASSWD Rules | Detection of password-less sudo command execution | CRITICAL |
| Sudo ALL | Detection of unrestricted sudo ALL privileges | CRITICAL |
| Baron Samedit | CVE-2021-3156 heap overflow vulnerability check | CRITICAL |
| Dangerous Binaries | Detection of exploitable sudo binaries (bash, python, vim, etc.) | CRITICAL |

###  SUID/SGID Binaries
| Feature | Description | Severity |
|---------|-------------|----------|
| SUID File Search | Comprehensive search for SUID/SGID binaries | WARNING |
| GTFOBins Integration | Automatic exploit command lookup via GTFOBins database | CRITICAL |
| Non-Standard Paths | Detection of SUID binaries outside system directories | CRITICAL |
| World-Writable SUID | Detection of writable SUID binaries (code injection risk) | CRITICAL |

###  Cron Jobs & Scheduled Tasks
| Feature | Description | Severity |
|---------|-------------|----------|
| System Crontab | /etc/crontab analysis and command enumeration | INFO |
| Cron Directories | Scanning of cron.d, cron.daily, cron.hourly, etc. | WARNING |
| Writable Scripts | Detection of world-writable cron scripts | CRITICAL |
| PATH Hijacking | Detection of writable PATH directories in cron context | CRITICAL |

###  File Permissions & Interesting Files
| Feature | Description | Severity |
|---------|-------------|----------|
| /etc/shadow Access | Readable or writable shadow file detection | CRITICAL |
| /etc/passwd Access | Readable or writable passwd file detection | CRITICAL |
| /root Access | Root directory accessibility check | CRITICAL |
| .env Files | Detection of environment variable files with credentials | WARNING |
| Backup Files | Discovery of .bak, .old, .swp, .orig files | WARNING |
| Credentials in Logs | Detection of passwords/secrets in log files | WARNING |
| SSH Keys | Discovery of readable private SSH keys | CRITICAL |

###  Container & Virtualization Escape
| Feature | Description | Severity |
|---------|-------------|----------|
| Docker Detection | Detection of Docker container environment | CRITICAL |
| Docker Socket | Accessible /var/run/docker.sock detection | CRITICAL |
| Docker Group | User membership in docker group check | CRITICAL |
| LXD/LXC Detection | LXC container environment detection | CRITICAL |
| CAP_SYS_ADMIN | Dangerous Linux capability detection | CRITICAL |

###  PATH Injection & Library Hijacking
| Feature | Description | Severity |
|---------|-------------|----------|
| Writable PATH | Detection of writable directories in $PATH | CRITICAL |
| LD_PRELOAD | Check for LD_PRELOAD/LD_LIBRARY_PATH manipulation | WARNING |
| Library Paths | Detection of writable shared library directories | CRITICAL |

###  Network Services & Credentials
| Feature | Description | Severity |
|---------|-------------|----------|
| Listening Ports | Enumeration of active network services | INFO |
| SSH Configuration | Analysis of sshd_config for weak settings | WARNING |
| SSH Keys | Discovery of readable authorized_keys and private keys | CRITICAL |
| MySQL Access | Detection of passwordless MySQL root access | CRITICAL |
| Redis Access | Detection of unauthenticated Redis instances | CRITICAL |
| PostgreSQL Config | Exposure of pg_hba.conf with weak authentication | WARNING |

###  Web Dashboard Features
| Feature | Description |
|---------|-------------|
|  Live Terminal | Real-time scan output with color-coded severity |
|  Finding Cards | Interactive cards with severity badges and MITRE tags |
|  View Details | Modal popup with full vulnerability information |
|  Copy Exploit | One-click clipboard copy for exploit commands |
|  MITRE Mapping | Technique grouping by tactic with direct links |
|  Statistics | Live counter for CRITICAL/WARNING/INFO findings |
|  AI Analysis | Button to trigger AI-powered attack chain analysis |
|  CVE Lookup | NVD API integration for vulnerability details |

###  Output Formats
| Format | Description | Location |
|--------|-------------|----------|
| Terminal | Color-coded real-time output | Console |
| JSON | Structured findings with metadata | findings.json |
| Log | Complete scan log with timestamps | scan.log |
| Metadata | Scan summary and system information | metadata.json |

---

##  Project Structure

```
contextprivesc/
│
├── core/                          # Core scanning engine
│   ├── __init__.py                # Package initializer
│   ├── scanner.py                 # Main scanning engine (1000+ checks)
│   ├── mitre_db.py                # MITRE ATT&CK technique database
│   ├── gtfobins_db.py             # GTFOBins exploit command database
│   └── cve_lookup.py              # NVD CVE API integration module
│
├── ai/                            # AI integration module
│   ├── __init__.py                # Package initializer
│   └── deepseek_client.py         # DeepSeek API client implementation
│
├── web/                           # Web server module
│   ├── __init__.py                # Package initializer
│   ├── web_server.py              # Flask + SocketIO web server
│   └── templates/
│       └── index.html             # Modern dashboard interface
│
├── utils/                         # Utilities module
│   ├── __init__.py                # Package initializer
│   └── constants.py               # Configuration constants
│
├── results/                       # Scan results storage (auto-created)
│
├── setup.sh                       # Automated dependency installation
├── LICENSE                        # MIT License
└── README.md                      # This documentation file
```

### Directory Reference

| Directory | Purpose | Key Files |
|-----------|---------|-----------|
| `core/` | Core scanning engine with 1000+ checks | scanner.py, mitre_db.py, gtfobins_db.py |
| `ai/` | AI integration for intelligent analysis | deepseek_client.py |
| `web/` | Flask web server and dashboard UI | web_server.py, templates/index.html |
| `utils/` | Helper functions and constants | constants.py |
| `results/` | Auto-generated scan output | findings.json, metadata.json, scan.log |

---

##  Installation

### Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Operating System | Kali Linux / Ubuntu 20.04+ / Debian 11+ | Kali Linux (latest) |
| RAM | 2 GB | 4 GB |
| Disk Space | 500 MB | 1 GB |
| Python | 3.8+ | 3.10+ |
| Internet | Required for AI/CVE features | Stable connection |

### Step-by-Step Installation

```bash
# 1. Create directory structure
mkdir -p ~/contextprivesc/{core,ai,web/templates,utils,results}
cd ~/contextprivesc

# 2. Create __init__.py files for Python packages
touch core/__init__.py ai/__init__.py web/__init__.py utils/__init__.py

# 3. Copy all project files to their respective directories
#    (setup.sh, scanner.sh, web_server.py, mitre_db.py, gtfobins_db.py, templates/index.html)

# 4. Run automated installation
sudo bash setup.sh

# 5. Verify installation
python3 -c "from flask import Flask; print('✓ Flask OK')"
python3 -c "import mitre_db; print('✓ MITRE DB OK')"
python3 -c "import gtfobins_db; print('✓ GTFOBins OK')"
```

>  All checks should return `✓ ... OK`. If not, re-run `sudo bash setup.sh`.

---

##  Usage

### CLI Mode (Terminal)

```bash
# Run comprehensive scan (2-5 minutes)
sudo python3 core/scanner.py

# Quick scan mode (30-60 seconds)
sudo python3 core/scanner.py --quick

# Full scan with all checks (5-10 minutes)
sudo python3 core/scanner.py --mode full

# JSON output only for automation
sudo python3 core/scanner.py --json > results.json
```

### Web Dashboard Mode

```bash
# Start web server (default port: 5000)
sudo python3 web_server.py

# Custom port
sudo python3 web_server.py --port 8080

# With AI API key (optional)
sudo python3 web_server.py --api-key sk-ant-YOURKEY
```

### Dashboard Workflow

1. **Open Browser:** Navigate to `http://localhost:5000`
2. **Start Scan:** Click the green ** Start Scan** button
3. **Monitor Output:** Watch real-time findings in the terminal panel
4. **Review Findings:** Click cards to expand details and exploit commands
5. **AI Analysis:** Click ** START AI** after scan completion for attack chain recommendations
6. **Export Results:** Findings auto-save to `/tmp/contextprivesc_YYYYMMDD_HHMMSS/`

### Understanding Severity Levels

| Badge | Color | Meaning | Action Required |
|-------|-------|---------|----------------|
| CRITICAL | Red | Immediate root access possible | Address immediately |
| WARNING | Yellow | Potential escalation vector | Review and mitigate |
| INFO | Blue | System information, no immediate risk | Document for reference |

---

##  AI Integration

### DeepSeek AI Features

ContextPrivesc integrates with **DeepSeek AI** to provide intelligent security analysis:

| Feature | Description |
|---------|-------------|
|  Vulnerability Prioritization | Ranks findings by exploitability and business impact |
|  Exploit Command Generation | Provides exact, tested commands for each vulnerability |
|  Attack Chain Analysis | Maps optimal privilege escalation paths from user to root |
|  Metasploit Module Recommendations | Suggests specific Metasploit modules for exploitation |
|  Remediation Guidance | Provides exact commands to fix discovered vulnerabilities |


>  **Security Note:** For production deployments, rotate this API key and consider using environment variables.

### AI Prompt Structure

The AI receives a structured prompt containing:
- Target system metadata (hostname, OS, kernel, user)
- All CRITICAL findings with MITRE tags and exploit commands
- Top WARNING findings for context
- Request for: executive summary, attack chain, top vulnerabilities, Metasploit modules, manual commands, and remediation

### Example AI Output Sections

```markdown
## EXECUTIVE SUMMARY
Brief overview of the target's security posture and highest risk vulnerabilities.

## ATTACK CHAIN (Step by Step)
1. Initial reconnaissance: [findings]
2. First exploitation: [command]
3. Privilege escalation: [vulnerability]
4. Root access: [method]
5. Persistence: [technique]

## TOP 5 VULNERABILITIES
1. [CVE] Name — exact exploit command
2. ...

## METASPLOIT MODULES
- use exploit/...
- set RHOST ...
- run

## REMEDIATION
Top 5 fixes with exact commands.
```

---

##  Output Format

### Directory Structure

```
/tmp/contextprivesc_20260427_003235/
├── findings.json      # All findings in structured JSON format
├── metadata.json      # Scan metadata and system information
└── scan.log           # Complete terminal log with timestamps
```

### findings.json Example

```json
{
  "id": 1,
  "severity": "CRITICAL",
  "category": "Sudo",
  "title": "Baron Samedit (CVE-2021-3156)",
  "detail": "Sudo version 1.9.5p1 vulnerable to heap-based buffer overflow",
  "mitre_id": "T1068",
  "mitre_name": "Exploitation for Privilege Escalation",
  "mitre_url": "https://attack.mitre.org/techniques/T1068/",
  "exploit": "sudoedit -s / $(python3 -c 'print(\"A\"*65536)')",
  "cve": "CVE-2021-3156",
  "timestamp": "2026-04-27T00:32:35.493221"
}
```

### metadata.json Example

```json
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
```

---

##  Scan Categories Reference

### What ContextPrivesc Detects

| Category | Key Findings | MITRE Tactics |
|----------|-------------|---------------|
| **System Information** | OS, kernel, CPU, memory, disk, hostname | Discovery |
| **Kernel Exploits** | DirtyCow (CVE-2016-5195), DirtyPipe (CVE-2022-0847), PwnKit (CVE-2021-4034) | Privilege Escalation |
| **Sudo Vulnerabilities** | NOPASSWD rules, ALL privileges, Baron Samedit (CVE-2021-3156) | Privilege Escalation |
| **SUID Binaries** | bash, python, find, vim, nmap, docker with SUID bit | Privilege Escalation |
| **Cron Jobs** | Writable cron files, PATH hijacking, script injection | Execution, Persistence |
| **File Permissions** | /etc/shadow, /etc/passwd, /root, world-writable configs | Credential Access |
| **Container Escape** | Docker socket, docker group, LXD, CAP_SYS_ADMIN | Privilege Escalation |
| **PATH Hijacking** | Writable PATH directories, LD_PRELOAD manipulation | Defense Evasion |
| **Network Services** | Listening ports, SSH config, SSH keys | Lateral Movement |
| **Database Credentials** | MySQL no password, Redis no auth, PostgreSQL exposure | Credential Access |
| **Backup Files** | .bak, .old, .swp files with potential credentials | Credential Access |

### Example Scan Summary

```
============================================================
SCAN COMPLETE — NORMAL MODE
============================================================
 CRITICAL Findings: 30
 WARNING Findings:  24
 INFO Findings:     13
────────────────────────────────────────────────────────────
Total Findings:    67
Results saved to:  /tmp/contextprivesc_20260427_003950
============================================================
```

---

##  Troubleshooting

### Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| **Port already in use** | `sudo kill -9 $(sudo lsof -t -i :5000)` or use `--port 8080` |
| **Flask not found** | `pip3 install flask flask-socketio flask-cors eventlet --break-system-packages` |
| **No findings detected** | Ensure running as root: `sudo python3 core/scanner.py` |
| **WebSocket connection failed** | Check firewall; ensure port is open; try `--host 127.0.0.1` |
| **ModuleNotFoundError** | Verify `__init__.py` exists in all package directories |
| **AI not responding** | Check internet connection; verify API key; clear browser cache (Ctrl+Shift+R) |
| **NVD API timeout** | Rate limit: 5 requests/30 seconds; reduce concurrent CVE lookups |

### Debug Mode

```bash
# Run web server with debug output
sudo python3 web_server.py --port 5000 --debug

# Test scanner directly with verbose output
sudo python3 core/scanner.py --quick --verbose

# Check Flask imports
python3 -c "from flask import Flask; from flask_socketio import SocketIO; print('OK')"
```

### Browser Console Debugging

1. Press **F12** to open Developer Tools
2. Navigate to **Console** tab
3. Look for error messages (red text)
4. Check **Network** tab for failed API requests
5. Refresh with **Ctrl+Shift+R** to clear cache

---

##  Security Considerations

### Important Warnings

| Warning | Details |
|---------|---------|
| **Educational Use Only** | This tool is for authorized testing, CTFs, and educational purposes only |
| **Root Permission Required** | Full system enumeration requires sudo access; run responsibly |
| **API Key Exposure** | API key is visible in source code; rotate for production deployments |
| **Output Sensitivity** | Scan results contain sensitive system information; handle securely |
| **No Warranty** | Tool provided "AS IS"; test in isolated environments first |

### Best Practices

1.  **Always obtain explicit authorization** before scanning any system
2.  **Use isolated environments** (VMs, containers) for testing
3.  **Review findings offline** in a secure, air-gapped environment
4.  **Delete results after analysis** if they contain sensitive data
5.  **Rotate API keys** regularly for production deployments
6.  **Keep dependencies updated** — run `pip3 install --upgrade -r requirements.txt` periodically

---

##  License

```
MIT License

Copyright (c) 2024 ContextPrivesc Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

>  **Usage Terms:** This tool is provided for **EDUCATIONAL PURPOSES ONLY**. Unauthorized use against systems without explicit permission is **PROHIBITED**.

---

##  Acknowledgments

- **DeepSeek AI** — For providing the AI API that powers intelligent analysis
- **MITRE Corporation** — For the ATT&CK framework that enables threat intelligence mapping
- **GTFOBins Team** — For the comprehensive privilege escalation binary database
- **Flask Community** — For the robust web framework that powers our dashboard
- **Open Source Security Community** — For inspiration, best practices, and continuous learning

---

##  Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.0.0 | 2026-04-27 | Initial release with DeepSeek AI integration, web dashboard, and 1000+ checks |

---

<div align="center">

** Made for Security Researchers & Penetration Testers**

*Use Responsibly. Stay Ethical. Keep Learning.*

</div>
