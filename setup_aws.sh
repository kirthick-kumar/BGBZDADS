#!/bin/bash
# ============================================================
# Step 2: AWS Full Setup — Amazon Linux 2023
# Run: bash setup_aws.sh
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/probe_detector"
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")

echo "═══════════════════════════════════════════════════════"
echo " GCN Probe Detector — AWS Setup"
echo " Server IP: $AWS_IP"
echo "═══════════════════════════════════════════════════════"

# ── 1. Move real SSH to port 2222 ────────────────────────────
echo ""
echo "[1/7] Configuring SSH port..."
if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
    sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
    sudo sed -i 's/^Port 22$/Port 2222/' /etc/ssh/sshd_config
    grep -q "^Port" /etc/ssh/sshd_config || echo "Port 2222" | sudo tee -a /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo "[✓] Real SSH moved to port 2222"
else
    echo "[✓] SSH already on port 2222"
fi

# ── 2. Install Cowrie ────────────────────────────────────────
echo ""
echo "[2/7] Installing Cowrie honeypot..."
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
pip install -e . -q

# Config
if [ ! -f etc/cowrie.cfg ]; then
    cp etc/cowrie.cfg.dist etc/cowrie.cfg
fi
sed -i 's/hostname = svr04/hostname = prod-server-01/' etc/cowrie.cfg

# Set listen port to 2224 in both config files
sed -i 's|^listen_endpoints = .*|listen_endpoints = tcp:2224:interface=0.0.0.0|g' etc/cowrie.cfg
sed -i 's|^listen_endpoints = .*|listen_endpoints = tcp:2224:interface=0.0.0.0|g' etc/cowrie.cfg.dist

# Remove duplicate output_jsonlog sections then add once
python3 - << 'PYEOF'
import re
with open('etc/cowrie.cfg', 'r') as f:
    content = f.read()
# Remove any existing output_jsonlog blocks we may have added
content = re.sub(r'\n\[output_jsonlog\]\nenabled = true\nlogfile = \$\{logpath\}/cowrie\.json\n?', '', content)
# Add it once at the end
if '[output_jsonlog]' not in content:
    content += '\n[output_jsonlog]\nenabled = true\nlogfile = ${logpath}/cowrie.json\n'
with open('etc/cowrie.cfg', 'w') as f:
    f.write(content)
print("    cowrie.cfg updated")
PYEOF

deactivate
cd ~
echo "[✓] Cowrie installed"

# ── 3. Start Cowrie ──────────────────────────────────────────
echo ""
echo "[3/7] Starting Cowrie..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 1
cowrie-env/bin/cowrie start
sleep 2
cowrie-env/bin/cowrie status
deactivate
cd ~
echo "[✓] Cowrie started on port 2224"

# ── 4. nginx ─────────────────────────────────────────────────
echo ""
echo "[4/7] Starting nginx..."
sudo systemctl start nginx
sudo systemctl enable nginx
echo "[✓] nginx running on port 80"

# ── 5. iptables ──────────────────────────────────────────────
echo ""
echo "[5/7] Setting up iptables..."
sudo bash "$SCRIPT_DIR/setup_iptables.sh"
echo "[✓] iptables configured"

# ── 6. Deploy detection agent ────────────────────────────────
echo ""
echo "[6/7] Deploying detection agent..."
sudo mkdir -p $AGENT_DIR
sudo chown ec2-user:ec2-user $AGENT_DIR
cp "$SCRIPT_DIR/detection_agent.py" $AGENT_DIR/
[ -f "$SCRIPT_DIR/gcn_autoencoder.pth" ] && cp "$SCRIPT_DIR/gcn_autoencoder.pth" $AGENT_DIR/ && echo "    copied model"
[ -f "$SCRIPT_DIR/scaler.pkl" ]          && cp "$SCRIPT_DIR/scaler.pkl"           $AGENT_DIR/ && echo "    copied scaler"

# Write systemd service
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

# Kill any leftover processes on our ports
sudo fuser -k 8765/tcp 2>/dev/null || true
sudo fuser -k 8080/tcp 2>/dev/null || true
sleep 1

sudo systemctl start probe-detector
sleep 3

if sudo systemctl is-active probe-detector --quiet; then
    echo "[✓] probe-detector running"
else
    echo "[!] probe-detector failed — check: sudo journalctl -u probe-detector -n 30"
fi

# ── 7. Open ports in iptables ────────────────────────────────
echo ""
echo "[7/7] Opening firewall ports..."
sudo iptables -I INPUT -p tcp --dport 8765 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 80   -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || true
echo "[✓] Ports open"

echo ""
echo "═══════════════════════════════════════════════════════"
echo " SETUP COMPLETE"
echo "═══════════════════════════════════════════════════════"
echo " Server IP:  $AWS_IP"
echo " Admin SSH:  ssh -p 2222 -i your-key.pem ec2-user@${AWS_IP}"
echo " Dashboard:  open dashboard.html?ip=${AWS_IP} in Chrome"
echo " WebSocket:  ws://${AWS_IP}:8765"
echo " HTTP:       http://${AWS_IP}"
echo ""
echo " AWS Security Group — ensure these ports are open:"
echo "   22, 80, 2222, 8765, 8080"
echo ""
echo " Quick checks:"
echo "   sudo systemctl status probe-detector --no-pager"
echo "   curl http://localhost:8080/status"
echo "═══════════════════════════════════════════════════════"
