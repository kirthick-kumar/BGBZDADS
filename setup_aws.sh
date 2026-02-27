#!/bin/bash
# ============================================================
# AWS Amazon Linux 2023 — Full Setup (v2)
# Run as: sudo bash setup_aws.sh
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# NOTE: No set -e — we handle errors explicitly so one step
#       can't silently kill the rest of the script

AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
AGENT_DIR="/opt/probe_detector"

echo "═══════════════════════════════════════════════════════"
echo " GCN Probe Detector v2 — AWS Setup"
echo " Server IP: $AWS_IP"
echo "═══════════════════════════════════════════════════════"

# ── 1. System packages ───────────────────────────────────────
echo ""
echo "[1/9] Installing system packages..."
sudo yum install -y \
    python3 python3-pip python3-devel git gcc gcc-c++ make \
    openssl-devel libffi-devel bzip2-devel wget net-tools \
    nmap nmap-ncat telnet iptables iptables-services rsyslog
echo "[✓] System packages done"

# ── 2. Move real SSH to port 2222 ────────────────────────────
echo ""
echo "[2/9] Configuring SSH port..."
if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
    sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
    sudo sed -i 's/^Port 22$/Port 2222/' /etc/ssh/sshd_config
    grep -q "^Port" /etc/ssh/sshd_config || echo "Port 2222" | sudo tee -a /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo "[✓] Real SSH moved to port 2222"
else
    echo "[✓] SSH already on port 2222"
fi

# ── 3. Install Cowrie ────────────────────────────────────────
echo ""
echo "[3/9] Installing Cowrie..."
if ! id -u cowrie &>/dev/null; then
    sudo useradd -r -s /bin/bash -m cowrie
    echo "    Created cowrie user"
fi

sudo -u cowrie bash << 'COWRIE_SETUP'
cd ~
if [ ! -d cowrie ]; then
    echo "    Cloning Cowrie..."
    git clone https://github.com/cowrie/cowrie.git
fi
cd cowrie
if [ ! -d cowrie-env ]; then
    python3 -m venv cowrie-env
fi
source cowrie-env/bin/activate
pip install --quiet -r requirements.txt

if [ ! -f etc/cowrie.cfg ]; then
    cp etc/cowrie.cfg.dist etc/cowrie.cfg
    sed -i 's/hostname = svr04/hostname = prod-server-01/' etc/cowrie.cfg
fi

# Add JSON log output if not already present
if ! grep -q "output_jsonlog" etc/cowrie.cfg; then
    cat >> etc/cowrie.cfg << 'EOF'

[output_jsonlog]
enabled = true
logfile = ${logpath}/cowrie.json
EOF
fi
COWRIE_SETUP
echo "[✓] Cowrie installed"

# ── 4. iptables PROBE_LOG chain ──────────────────────────────
echo ""
echo "[4/9] Setting up iptables PROBE_LOG chain..."

# Flush + recreate cleanly (|| true so errors don't stop the script)
sudo iptables -F PROBE_LOG 2>/dev/null || true
sudo iptables -X PROBE_LOG 2>/dev/null || true
sudo iptables -N PROBE_LOG

sudo iptables -A PROBE_LOG -m limit --limit 60/min --limit-burst 100 \
    -j LOG --log-prefix "PROBE_LOG " --log-level 4
sudo iptables -A PROBE_LOG -j RETURN

# Remove old jump rules then re-add
sudo iptables -D INPUT -p tcp --syn -j PROBE_LOG 2>/dev/null || true
sudo iptables -D INPUT -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,3306,5432,6379,8080 \
    -j PROBE_LOG 2>/dev/null || true

sudo iptables -I INPUT 1 -p tcp --syn -j PROBE_LOG
sudo iptables -I INPUT 2 -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,3306,5432,6379,8080 \
    -j PROBE_LOG

# NAT: redirect honeypot ports to Cowrie
sudo iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 2>/dev/null || true
sudo iptables -t nat -D PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323 2>/dev/null || true
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323

# Ensure kern.log gets iptables messages
if ! grep -q "kern.warning" /etc/rsyslog.conf 2>/dev/null; then
    echo 'kern.warning /var/log/kern.log' | sudo tee -a /etc/rsyslog.conf
    sudo systemctl restart rsyslog
fi
echo "[✓] iptables PROBE_LOG chain ready"

# ── 5. Create agent directory ────────────────────────────────
echo ""
echo "[5/9] Creating agent directory..."
sudo mkdir -p $AGENT_DIR
sudo chown ec2-user:ec2-user $AGENT_DIR
echo "[✓] $AGENT_DIR ready"

# ── 6. Python deps ───────────────────────────────────────────
echo ""
echo "[6/9] Installing Python dependencies..."
export PATH=$HOME/.local/bin:$PATH
export PYTHONPATH=$HOME/.local/lib/python3.9/site-packages:$PYTHONPATH

python3 -m pip install --user --quiet \
    torch --index-url https://download.pytorch.org/whl/cpu

TORCH_VER=$(python3 -c "import torch; print(torch.__version__.split('+')[0])")
echo "    torch $TORCH_VER installed"

python3 -m pip install --user --quiet \
    torch-scatter torch-sparse \
    -f https://data.pyg.org/whl/torch-${TORCH_VER}+cpu.html

python3 -m pip install --user --quiet \
    torch-geometric websockets aiohttp aiohttp-cors \
    scikit-learn joblib numpy pandas

echo "[✓] Python deps installed"

# ── 7. Copy agent files ──────────────────────────────────────
echo ""
echo "[7/9] Copying agent files..."
cp "$SCRIPT_DIR/detection_agent.py" $AGENT_DIR/
[ -f "$SCRIPT_DIR/gcn_autoencoder.pth" ] && cp "$SCRIPT_DIR/gcn_autoencoder.pth" $AGENT_DIR/ && echo "    copied gcn_autoencoder.pth"
[ -f "$SCRIPT_DIR/scaler.pkl" ]          && cp "$SCRIPT_DIR/scaler.pkl"           $AGENT_DIR/ && echo "    copied scaler.pkl"
[ -f "$SCRIPT_DIR/threshold.txt" ]       && cp "$SCRIPT_DIR/threshold.txt"        $AGENT_DIR/ && echo "    copied threshold.txt"
echo "[✓] Files copied"

# ── 8. Systemd service ───────────────────────────────────────
echo ""
echo "[8/9] Creating systemd service..."
sudo tee /etc/systemd/system/probe-detector.service > /dev/null << EOF
[Unit]
Description=GCN Probe Detection Agent v2
After=network.target

[Service]
User=ec2-user
WorkingDirectory=${AGENT_DIR}
Environment=COWRIE_LOG=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
Environment=KERN_LOG=/var/log/kern.log
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
EOF

sudo systemctl daemon-reload
sudo systemctl enable probe-detector
sudo systemctl start probe-detector
sleep 2

if sudo systemctl is-active probe-detector --quiet; then
    echo "[✓] probe-detector service running"
else
    echo "[!] probe-detector failed to start — check: sudo journalctl -u probe-detector -n 30"
fi

# ── 9. Start Cowrie + open ports ─────────────────────────────
echo ""
echo "[9/9] Starting Cowrie and opening ports..."
sudo -u cowrie /home/cowrie/cowrie/bin/cowrie start 2>/dev/null || \
sudo -u cowrie bash -c "cd ~/cowrie && source cowrie-env/bin/activate && bin/cowrie start"

sudo iptables -I INPUT -p tcp --dport 8765 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || true

echo "[✓] Cowrie started, ports open"

echo ""
echo "═══════════════════════════════════════════════════════"
echo " SETUP COMPLETE"
echo "═══════════════════════════════════════════════════════"
echo " Admin SSH:  ssh -p 2222 -i your-key.pem ec2-user@${AWS_IP}"
echo " WebSocket:  ws://${AWS_IP}:8765"
echo " HTTP API:   http://${AWS_IP}:8080/status"
echo ""
echo " Quick checks:"
echo "   sudo systemctl status probe-detector --no-pager"
echo "   sudo -u cowrie /home/cowrie/cowrie/bin/cowrie status"
echo "   sudo tail -f /var/log/kern.log | grep PROBE_LOG"
echo "═══════════════════════════════════════════════════════"
