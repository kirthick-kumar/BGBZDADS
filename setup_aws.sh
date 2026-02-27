#!/bin/bash
# ============================================================
# AWS Full Setup — Amazon Linux 2023
# Run: bash setup_aws.sh
#
# Port layout:
#   22   = real SSH (UNCHANGED — do not touch)
#   2222 = Cowrie SSH honeypot (direct)
#   2323 = Cowrie Telnet honeypot (direct)
#   80   = nginx HTTP
#   8765 = WebSocket (dashboard)
#   8080 = HTTP API
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/probe_detector"
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")

echo "═══════════════════════════════════════════════════════"
echo " GCN Probe Detector — AWS Setup"
echo " Server IP: $AWS_IP"
echo " SSH stays on port 22 — NO port changes"
echo "═══════════════════════════════════════════════════════"

# ── 1. Install Cowrie ────────────────────────────────────────
echo ""
echo "[1/6] Installing Cowrie honeypot..."
cd ~
if [ ! -d cowrie ]; then
    git clone https://github.com/cowrie/cowrie.git
fi
cd cowrie

# Use python3.11 — Cowrie requires >=3.10
if [ ! -d cowrie-env ]; then
    python3.11 -m venv cowrie-env
fi
source cowrie-env/bin/activate
pip install --quiet -r requirements.txt
pip install -e . -q 2>/dev/null || true

# Config
if [ ! -f etc/cowrie.cfg ]; then
    cp etc/cowrie.cfg.dist etc/cowrie.cfg
fi
sed -i 's/hostname = svr04/hostname = prod-server-01/' etc/cowrie.cfg 2>/dev/null || true

# Set Cowrie SSH to listen on 2222, Telnet on 2323 (both direct)
sed -i 's|^listen_endpoints = .*|listen_endpoints = tcp:2222:interface=0.0.0.0|g' etc/cowrie.cfg
sed -i 's|^listen_endpoints = .*|listen_endpoints = tcp:2222:interface=0.0.0.0|g' etc/cowrie.cfg.dist

# Fix any duplicate listen_endpoints lines
python3 - << 'PYEOF'
import re

for fname in ['etc/cowrie.cfg', 'etc/cowrie.cfg.dist']:
    try:
        with open(fname, 'r') as f:
            lines = f.readlines()

        # Keep only first active listen_endpoints line
        seen = False
        out = []
        for line in lines:
            if line.startswith('listen_endpoints') and not line.strip().startswith('#'):
                if not seen:
                    out.append('listen_endpoints = tcp:2222:interface=0.0.0.0\n')
                    seen = True
            else:
                out.append(line)

        with open(fname, 'w') as f:
            f.writelines(out)
        print(f"    fixed: {fname}")
    except Exception as e:
        print(f"    skip: {fname}: {e}")
PYEOF

# Remove duplicate output_jsonlog then add once
python3 - << 'PYEOF'
import re
try:
    with open('etc/cowrie.cfg', 'r') as f:
        content = f.read()
    content = re.sub(r'\n\[output_jsonlog\][^\[]*', '', content)
    content += '\n[output_jsonlog]\nenabled = true\nlogfile = ${logpath}/cowrie.json\n'
    with open('etc/cowrie.cfg', 'w') as f:
        f.write(content)
    print("    output_jsonlog configured")
except Exception as e:
    print(f"    warning: {e}")
PYEOF

deactivate
cd ~
echo "[✓] Cowrie installed"

# ── 2. Start Cowrie ──────────────────────────────────────────
echo ""
echo "[2/6] Starting Cowrie on port 2222..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 2
cowrie-env/bin/cowrie start
sleep 3
cowrie-env/bin/cowrie status
deactivate
cd ~
echo "[✓] Cowrie started"

# ── 3. nginx ─────────────────────────────────────────────────
echo ""
echo "[3/6] Starting nginx on port 80..."
sudo systemctl start nginx
sudo systemctl enable nginx
echo "[✓] nginx started"

# ── 4. iptables ──────────────────────────────────────────────
echo ""
echo "[4/6] Configuring iptables..."
sudo bash "$SCRIPT_DIR/setup_iptables.sh"

# Allow all our service ports through iptables
sudo iptables -I INPUT -p tcp --dport 22   -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 80   -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 2323 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 8765 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
echo "[✓] iptables configured"

# ── 5. Deploy detection agent ────────────────────────────────
echo ""
echo "[5/6] Deploying detection agent..."
sudo mkdir -p $AGENT_DIR
sudo chown ec2-user:ec2-user $AGENT_DIR
cp "$SCRIPT_DIR/detection_agent.py" $AGENT_DIR/
[ -f "$SCRIPT_DIR/gcn_autoencoder.pth" ] && cp "$SCRIPT_DIR/gcn_autoencoder.pth" $AGENT_DIR/
[ -f "$SCRIPT_DIR/scaler.pkl" ]          && cp "$SCRIPT_DIR/scaler.pkl"           $AGENT_DIR/

sudo tee /etc/systemd/system/probe-detector.service > /dev/null << SVCEOF
[Unit]
Description=GCN Probe Detection Agent
After=network.target

[Service]
User=ec2-user
WorkingDirectory=${AGENT_DIR}
Environment=COWRIE_LOG=/home/ec2-user/cowrie/var/log/cowrie/cowrie.json
Environment=KERN_LOG=/var/log/kern.log
Environment=HTTP_LOG=/var/log/nginx/access.log
Environment=MODEL_PATH=${AGENT_DIR}/gcn_autoencoder.pth
Environment=SCALER_PATH=${AGENT_DIR}/scaler.pkl
Environment=WS_PORT=8765
Environment=HTTP_PORT=8080
Environment=PATH=/home/ec2-user/.local/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONPATH=/home/ec2-user/.local/lib/python3.9/site-packages
ExecStart=/usr/bin/python3 ${AGENT_DIR}/detection_agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

sudo systemctl daemon-reload
sudo systemctl enable probe-detector

sudo fuser -k 8765/tcp 2>/dev/null || true
sudo fuser -k 8080/tcp 2>/dev/null || true
sleep 1

sudo systemctl start probe-detector
sleep 3

if sudo systemctl is-active probe-detector --quiet; then
    echo "[✓] probe-detector running"
else
    echo "[!] probe-detector failed — running directly to show error:"
    cd $AGENT_DIR && python3 detection_agent.py &
    sleep 3
    kill %1 2>/dev/null || true
fi

# ── 6. Verify ────────────────────────────────────────────────
echo ""
echo "[6/6] Verifying..."
sleep 2
echo -n "  Cowrie:         "; cd ~/cowrie && source cowrie-env/bin/activate && cowrie-env/bin/cowrie status; deactivate; cd ~
echo -n "  nginx:          "; sudo systemctl is-active nginx
echo -n "  probe-detector: "; sudo systemctl is-active probe-detector
echo -n "  HTTP API:       "; curl -s http://localhost:8080/status | python3 -m json.tool 2>/dev/null | head -3 || echo "not responding"

echo ""
echo "═══════════════════════════════════════════════════════"
echo " SETUP COMPLETE"
echo "═══════════════════════════════════════════════════════"
echo " Server IP : $AWS_IP"
echo " SSH        : ssh -i key.pem ec2-user@${AWS_IP}         (port 22)"
echo " Dashboard  : open dashboard.html in browser"
echo "              serve it: python3 -m http.server 3000"
echo "              open: http://localhost:3000/dashboard.html?ip=${AWS_IP}"
echo " HTTP test  : curl http://${AWS_IP}"
echo " WebSocket  : ws://${AWS_IP}:8765"
echo ""
echo " AWS Security Group — open these ports:"
echo "   22, 80, 2222, 2323, 8765, 8080"
echo "═══════════════════════════════════════════════════════"
