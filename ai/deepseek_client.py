#!/usr/bin/env python3
import json
import requests
from datetime import datetime

class DeepSeekClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.deepseek.com/v1"
        self.headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
    
    def chat(self, messages, max_tokens=1000):
        try:
            resp = requests.post(f"{self.base_url}/chat/completions", headers=self.headers,
                                json={"model": "deepseek-chat", "messages": messages, "max_tokens": max_tokens, "temperature": 0.3}, timeout=30)
            return resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            return f"AI Error: {str(e)}"
    
    def analyze_findings(self, findings, metadata):
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        prompt = f"""System: {metadata.get('hostname', 'Unknown')}
OS: {metadata.get('os', 'Unknown')}
Kernel: {metadata.get('kernel', 'Unknown')}
Critical Issues: {len(critical)}
Critical Findings: {json.dumps(critical[:10], indent=2)}
Provide: 1. Most critical vulnerability 2. Exact exploit command 3. Step-by-step exploitation 4. Remediation"""
        response = self.chat([{"role": "system", "content": "You are a Linux security expert. Provide exact commands."},
                              {"role": "user", "content": prompt}])
        return {"analysis": response, "timestamp": datetime.now().isoformat(), "critical_count": len(critical)}
