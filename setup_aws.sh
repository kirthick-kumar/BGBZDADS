#!/bin/bash
# ============================================================
# AWS Full Setup — Amazon Linux 2023
# Run from the folder containing all project files:
#   bash setup_aws.sh
#
# Port layout:
#   22   = real SSH (UNCHANGED)
#   2222 = Cowrie SSH honeypot
#   2223 = Cowrie Telnet honeypot
#   80   = nginx HTTP
#   8765 = WebSocket (dashboard)
#   8080 = HTTP API
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/probe_detector"
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")

echo "======================================================="
echo " GCN Probe Detector — AWS Setup"
echo " Server IP: $AWS_IP"
echo "======================================================="

# ── 1. Cowrie ────────────────────────────────────────────────
echo ""
echo "[1/6] Installing Cowrie..."
cd ~

if [ ! -d cowrie ]; then
    git clone https://github.com/cowrie/cowrie.git
fi
cd cowrie

if [ ! -d cowrie-env ]; then
    python3.11 -m venv cowrie-env
fi
source cowrie-env/bin/activate
pip install --quiet -r requirements.txt
pip install -e . -q 2>/dev/null || true

# Always generate a CLEAN config from scratch using configparser
# This avoids ALL duplicate section/option errors from previous runs
echo "    Writing clean cowrie.cfg via configparser..."
python3 - << 'PYEOF'
import configparser

# Read the dist file as base
cfg = configparser.ConfigParser(strict=False)
cfg.read('etc/cowrie.cfg.dist')

# Ensure sections exist
for sec in ['honeypot', 'telnet', 'output_jsonlog']:
    if not cfg.has_section(sec):
        cfg.add_section(sec)

# Set required values
cfg.set('honeypot', 'hostname', 'prod-server-01')
cfg.set('honeypot', 'listen_endpoints', 'tcp:2222:interface=0.0.0.0')
cfg.set('telnet',   'enabled', 'true')
cfg.set('telnet',   'listen_endpoints', 'tcp:2223:interface=0.0.0.0')
cfg.set('output_jsonlog', 'enabled', 'true')
cfg.set('output_jsonlog', 'logfile',  '${logpath}/cowrie.json')

with open('etc/cowrie.cfg', 'w') as f:
    cfg.write(f)

print("    cowrie.cfg written OK")
PYEOF

deactivate
cd ~
echo "[OK] Cowrie installed"

# ── 2. Start Cowrie ──────────────────────────────────────────
echo ""
echo "[2/6] Starting Cowrie..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 2
cowrie-env/bin/cowrie start
sleep 3
cowrie-env/bin/cowrie status
deactivate
cd ~
echo -n "    Listening on: "
sudo ss -tlnp | grep -E "2222|2223" | awk '{print $4}' | tr '\n' ' '
echo ""
echo "[OK] Cowrie started"

# ── 3. nginx ─────────────────────────────────────────────────
echo ""
echo "[3/6] Starting nginx..."
sudo systemctl start nginx
sudo systemctl enable nginx

# Filter AWS health checks from access log (15.177.x.x flood)
sudo tee /etc/nginx/conf.d/filter_healthchecks.conf > /dev/null << 'EOF'
geo $loggable {
    default       1;
    15.177.0.0/16 0;
}
access_log /var/log/nginx/access.log combined if=$loggable;
EOF
sudo nginx -t 2>/dev/null && sudo systemctl reload nginx
echo "[OK] nginx on port 80"

# ── 4. iptables ──────────────────────────────────────────────
echo ""
echo "[4/6] Configuring iptables..."
sudo bash "$SCRIPT_DIR/setup_iptables.sh"
for port in 22 80 2222 2223 8765 8080; do
    sudo iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || true
done
echo "[OK] iptables done"

# ── 5. Detection agent ───────────────────────────────────────
echo ""
echo "[5/6] Deploying detection agent..."
sudo mkdir -p $AGENT_DIR
sudo chown ec2-user:ec2-user $AGENT_DIR
cp "$SCRIPT_DIR/detection_agent.py" $AGENT_DIR/

for f in gcn_autoencoder.pth scaler.pkl encoders.pkl threshold.txt; do
    [ -f "$SCRIPT_DIR/$f" ] && cp "$SCRIPT_DIR/$f" $AGENT_DIR/ && echo "    copied $f"
done

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
Environment=ENCODER_PATH=${AGENT_DIR}/encoders.pkl
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
sudo systemctl is-active probe-detector --quiet && echo "[OK] probe-detector running" || \
    (echo "[!] probe-detector failed:" && sudo journalctl -u probe-detector -n 15 --no-pager)

# ── 6. Verify ────────────────────────────────────────────────
echo ""
echo "[6/6] Final check..."
echo -n "  nginx:          "; sudo systemctl is-active nginx
echo -n "  probe-detector: "; sudo systemctl is-active probe-detector
echo -n "  Cowrie SSH:     "; sudo ss -tlnp | grep -c 2222 || echo 0
echo -n "  Cowrie Telnet:  "; sudo ss -tlnp | grep -c 2223 || echo 0
sleep 2
echo -n "  HTTP API:       "; curl -s http://localhost:8080/status | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK -',len(d['sessions']),'sessions')" 2>/dev/null || echo "not ready"

echo ""
echo "======================================================="
echo " DONE — $AWS_IP"
echo " Open dashboard: python3 -m http.server 3000"
echo "   then: http://localhost:3000/dashboard.html?ip=${AWS_IP}"
echo " Security Group ports: 22 80 2222 2223 8765 8080"
echo "======================================================="