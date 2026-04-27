#!/usr/bin/env python3
"""
ContextPrivesc - Web Dashboard Server with Permanent DeepSeek AI Integration
"""

import os
import sys
import json
import argparse
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

sys.path.insert(0, str(Path(__file__).parent.parent))

# ============================================================================
# PERMANENT API KEY CONFIGURATION
# ============================================================================
DEEPSEEK_API_KEY = "sk-faf7fc01b0804802a1d1faa1cb36176f"
DEEPSEEK_API_BASE = "https://api.deepseek.com/v1"
# ============================================================================

# DeepSeek AI Client
class DeepSeekClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = DEEPSEEK_API_BASE
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def chat(self, messages, max_tokens=1000):
        import requests
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": "deepseek-chat",
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.3
        }
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            return f"AI Error: {str(e)}"
    
    def analyze_findings(self, findings, metadata):
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        prompt = f"""System: {metadata.get('hostname', 'Unknown')}
OS: {metadata.get('os', 'Unknown')}
Kernel: {metadata.get('kernel', 'Unknown')}
Critical Issues: {len(critical)}
Total Findings: {len(findings)}

Critical Findings:
{json.dumps(critical[:15], indent=2)}

Provide:
1. MOST CRITICAL vulnerability to exploit first
2. EXACT exploit command
3. Step-by-step exploitation process
4. How to achieve root access
5. Remediation commands

Be technical and provide actual commands."""
        
        response = self.chat([
            {"role": "system", "content": "You are a Linux security expert. Provide exact commands."},
            {"role": "user", "content": prompt}
        ])
        
        return {
            "analysis": response,
            "timestamp": datetime.now().isoformat(),
            "critical_count": len(critical),
            "total_findings": len(findings),
            "provider": "deepseek"
        }

# Initialize AI client
ai_client = DeepSeekClient(DEEPSEEK_API_KEY)
AI_ENABLED = True

# Flask Application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global State
scan_state = {
    "scanning": False,
    "findings": [],
    "logs": [],
    "mode": "normal"
}
scan_process = None

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/status')
def status():
    return jsonify({
        "scanning": scan_state["scanning"],
        "findings_count": len(scan_state["findings"]),
        "critical": len([f for f in scan_state["findings"] if f.get("severity") == "CRITICAL"]),
        "warning": len([f for f in scan_state["findings"] if f.get("severity") == "WARNING"]),
        "info": len([f for f in scan_state["findings"] if f.get("severity") == "INFO"]),
        "ai_available": True
    })

@app.route('/api/findings')
def get_findings():
    return jsonify(scan_state["findings"])

@app.route('/api/ai/analyze')
def ai_analyze():
    if not scan_state["findings"]:
        return jsonify({"error": "No findings to analyze. Please run a scan first."}), 400
    
    try:
        metadata = {
            "hostname": os.uname().nodename,
            "os": "Kali Linux",
            "kernel": os.uname().release,
            "user": os.environ.get("USER", "unknown")
        }
        result = ai_client.analyze_findings(scan_state["findings"], metadata)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@socketio.on('connect')
def handle_connect():
    print("Client connected")
    emit('status', {"scanning": scan_state["scanning"], "findings_count": len(scan_state["findings"])})

@socketio.on('start_scan')
def start_scan():
    global scan_process, scan_state
    if scan_state["scanning"]:
        emit('error', {'message': 'Scan already running'})
        return
    
    scan_state["scanning"] = True
    scan_state["findings"] = []
    scan_state["logs"] = []
    
    thread = threading.Thread(target=run_scanner, args=(socketio,))
    thread.daemon = True
    thread.start()
    
    emit('scan_started', {'timestamp': datetime.now().isoformat()})

@socketio.on('stop_scan')
def stop_scan():
    global scan_process, scan_state
    scan_state["scanning"] = False
    if scan_process:
        scan_process.terminate()
    emit('scan_stopped', {'message': 'Scan stopped by user'})

@socketio.on('set_mode')
def set_mode(data):
    scan_state["mode"] = data.get("mode", "normal")
    print(f"Mode set to: {scan_state['mode']}")

def run_scanner(sio):
    global scan_process, scan_state
    
    scanner_path = Path(__file__).parent.parent / "core" / "scanner.py"
    cmd = [sys.executable, str(scanner_path), "--mode", scan_state["mode"]]
    
    print(f"Starting scanner: {' '.join(cmd)}")
    sio.emit('terminal_line', {'line': f"[INFO] Starting {scan_state['mode'].upper()} scan..."})
    
    try:
        scan_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        for line in iter(scan_process.stdout.readline, ''):
            if not scan_state["scanning"]:
                break
            
            line = line.rstrip()
            if line:
                scan_state["logs"].append(line)
                sio.emit('terminal_line', {'line': line})
                
                if line.startswith('{') and '"severity"' in line:
                    try:
                        finding = json.loads(line)
                        scan_state["findings"].append(finding)
                        sio.emit('new_finding', finding)
                    except:
                        pass
        
        scan_process.wait()
    except Exception as e:
        sio.emit('error', {'message': str(e)})
    finally:
        scan_state["scanning"] = False
        sio.emit('scan_complete', {
            'total': len(scan_state["findings"]),
            'critical': len([f for f in scan_state["findings"] if f.get("severity") == "CRITICAL"])
        })
        print(f"Scan complete. Found {len(scan_state['findings'])} findings")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ContextPrivesc Web Server")
    parser.add_argument("--port", type=int, default=5000, help="Server port (default: 5000)")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("  ContextPrivesc v1.0 - Web Dashboard")
    print("  AI-Powered Linux Privilege Escalation Scanner")
    print("="*80)
    print(f"  Web Interface: http://{args.host}:{args.port}")
    print(f"  DeepSeek AI: ENABLED (Permanent API Key)")
    print(f"  Debug Mode: {'ON' if args.debug else 'OFF'}")
    print("="*80 + "\n")
    
    socketio.run(app, host=args.host, port=args.port, debug=args.debug)
