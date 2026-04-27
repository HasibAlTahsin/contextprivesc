#!/bin/bash
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
echo "================================================================================"
echo "  ContextPrivesc v1.0 - Installation"
echo "================================================================================"
if [ "$EUID" -ne 0 ]; then echo -e "${RED}Error: Run with sudo${NC}"; exit 1; fi
echo -e "${BLUE}[1/4] Installing system packages...${NC}"
apt-get update -qq
apt-get install -y -qq python3-flask python3-requests curl wget netcat-openbsd nmap sysstat lsof net-tools procps 2>/dev/null || true
echo -e "${BLUE}[2/4] Installing Python packages...${NC}"
pip3 install flask-socketio flask-cors eventlet gevent --break-system-packages 2>/dev/null || true
echo -e "${BLUE}[3/4] Creating directories...${NC}"
mkdir -p results /var/log/contextprivesc /tmp/contextprivesc
echo -e "${BLUE}[4/4] Setting permissions...${NC}"
chmod +x core/scanner.py web/server.py 2>/dev/null || true
echo ""
echo -e "${GREEN}================================================================================"
echo -e "  Installation Complete!"
echo -e "================================================================================"
echo ""
echo "Quick Commands:"
echo "  Quick Scan:  sudo python3 core/scanner.py --quick"
echo "  Normal Scan: sudo python3 core/scanner.py"
echo "  Full Scan:   sudo python3 core/scanner.py --mode full"
echo "  Web Server:  sudo python3 web/server.py --port 8080"
echo "  With AI:     sudo python3 web/server.py --port 8080 --ai-key YOUR_KEY"
echo ""
