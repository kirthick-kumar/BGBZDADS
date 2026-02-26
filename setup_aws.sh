#!/bin/bash
# ============================================================
# AWS Amazon Linux 2023 — Full Setup (v2)
# Run as ec2-user with sudo privileges
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -e

AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")

echo "═══════════════════════════════════════════════════════"
echo " GCN Probe Detector v2 — AWS Setup"
echo " Server IP: $AWS_IP"
echo "═══════════════════════════════════════════════════════"

# ── 1. System packages ───────────────────────────────────────
sudo dnf update -y 2>/dev/null || sudo yum update -y
sudo dnf install -y python3 python3-pip git gcc openssl-devel \
  python3-devel iptables iptables-services rsyslog \
  nmap telnet 2>/dev/null || \
sudo yum install -y python3 python3-pip git gcc openssl-devel \
  python3-devel iptables iptables-services rsyslog

# ── 2. Move real SSH to port 2222 ────────────────────────────
if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
  sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
  sudo sed -i 's/^Port 22$/Port 2222/' /etc/ssh/sshd_config
  # Add if not present at all
  grep -q "^Port" /etc/ssh/sshd_config || echo "Port 2222" | sudo tee -a /etc/ssh/sshd_config
  sudo systemctl restart sshd
  echo "[✓] Real SSH moved to port 2222 — reconnect with: ssh -p 2222 ec2-user@${AWS_IP}"
fi

# ── 3. Install Cowrie ────────────────────────────────────────
if ! id -u cowrie &>/dev/null; then
  sudo useradd -r -s /bin/bash -m cowrie
fi

sudo -u cowrie bash << 'COWRIE_SETUP'
  cd ~
  if [ ! -d cowrie ]; then
    git clone https://github.com/cowrie/cowrie.git
  fi
  cd cowrie
  python3 -m venv cowrie-env
  source cowrie-env/bin/activate
  pip install --quiet -r requirements.txt

  # Config: enable JSON log, listen on 2222 and 2323
  cp etc/cowrie.cfg.dist etc/cowrie.cfg
  sed -i 's/hostname = svr04/hostname = prod-server-01/' etc/cowrie.cfg
  sed -i 's/listen_port = 2222/listen_port = 2222/' etc/cowrie.cfg

  # Enable JSON output
  cat >> etc/cowrie.cfg << 'EOF'

[output_jsonlog]
enabled = true
logfile = ${logpath}/cowrie.json
EOF
COWRIE_SETUP

echo "[✓] Cowrie installed"

# ── 4. iptables setup ────────────────────────────────────────
sudo bash setup_iptables.sh

# ── 5. Python deps for detection agent ──────────────────────
AGENT_DIR="/opt/probe_detector"
sudo mkdir -p $AGENT_DIR
sudo chown ec2-user:ec2-user $AGENT_DIR

pip3 install --user \
  torch --index-url https://download.pytorch.org/whl/cpu \
  2>/dev/null || pip3 install --user torch

pip3 install --user \
  torch-geometric \
  websockets \
  aiohttp \
  aiohttp-cors \
  scikit-learn \
  joblib \
  numpy

echo "[✓] Python deps installed"

# ── 6. Copy files ─────────────────────────────────────────────
cp "$SCRIPT_DIR/detection_agent.py" $AGENT_DIR/
[ -f "$SCRIPT_DIR/gcn_autoencoder.pth" ] && cp "$SCRIPT_DIR/gcn_autoencoder.pth" $AGENT_DIR/
[ -f "$SCRIPT_DIR/scaler.pkl" ] && cp "$SCRIPT_DIR/scaler.pkl"           $AGENT_DIR/
[ -f "$SCRIPT_DIR/threshold.txt" ] && cp "$SCRIPT_DIR/threshold.txt"        $AGENT_DIR/

# ── 7. Systemd service ───────────────────────────────────────
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
ExecStart=/usr/bin/python3 ${AGENT_DIR}/detection_agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable probe-detector
sudo systemctl start probe-detector

echo "[✓] probe-detector service started"

# ── 8. Start Cowrie ──────────────────────────────────────────
sudo -u cowrie /home/cowrie/cowrie/bin/cowrie start
echo "[✓] Cowrie started"

# ── 9. Open agent ports ──────────────────────────────────────
sudo iptables -I INPUT -p tcp --dport 8765 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 2222 -j ACCEPT   # real SSH

echo ""
echo "═══════════════════════════════════════════════════════"
echo " SETUP COMPLETE"
echo "═══════════════════════════════════════════════════════"
echo ""
echo " Admin SSH:    ssh -p 2222 -i your-key.pem ec2-user@${AWS_IP}"
echo " WebSocket:    ws://${AWS_IP}:8765"
echo " HTTP API:     http://${AWS_IP}:8080/status"
echo ""
echo " Verify iptables logging:"
echo "   sudo tail -f /var/log/kern.log | grep PROBE_LOG"
echo ""
echo " Verify Cowrie:"
echo "   sudo -u cowrie /home/cowrie/cowrie/bin/cowrie status"
echo "   sudo tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json"
echo ""
echo " Check agent:"
echo "   sudo journalctl -u probe-detector -f"
echo "═══════════════════════════════════════════════════════"
