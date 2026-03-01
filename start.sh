#!/bin/bash
# ============================================================
# START SCRIPT — run every time EC2 instance boots
# Place in ~/BGBZDADS/ and run: bash ~/BGBZDADS/start.sh
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/probe_detector"

echo "======================================================="
echo " GCN Probe Detector — Startup"
echo "======================================================="

# ── 1. iptables ──────────────────────────────────────────────
echo ""
echo "[1/4] Setting up iptables..."
sudo bash "$SCRIPT_DIR/setup_iptables.sh"
echo "[OK] iptables done"

# ── 2. Cowrie ────────────────────────────────────────────────
echo ""
echo "[2/4] Starting Cowrie..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 2
cowrie-env/bin/cowrie start
sleep 3
cowrie-env/bin/cowrie status
deactivate
cd "$SCRIPT_DIR"
echo -n "    Ports: "
sudo ss -tlnp | grep -E "2222|2223" | awk '{print $4}' | tr '\n' ' '
echo ""
echo "[OK] Cowrie started"

# ── 3. Services ──────────────────────────────────────────────
echo ""
echo "[3/4] Starting system services..."
sudo systemctl start nginx
sudo systemctl start postfix

# Fix kern.log + nginx log permissions for agent (ec2-user)
sudo chmod 644 /var/log/kern.log 2>/dev/null || true
sudo chmod 755 /var/log/nginx 2>/dev/null || true
sudo chmod 644 /var/log/nginx/access.log 2>/dev/null || true

# Make kern.log world-readable permanently via rsyslog
if ! grep -q "kern.warning" /etc/rsyslog.conf 2>/dev/null; then
    echo 'kern.warning /var/log/kern.log' | sudo tee -a /etc/rsyslog.conf
    sudo systemctl restart rsyslog
fi

echo -n "  nginx:   "; sudo systemctl is-active nginx
echo -n "  postfix: "; sudo systemctl is-active postfix

# ── 4. Detection agent ───────────────────────────────────────
echo ""
echo "[4/4] Starting detection agent..."

# Copy latest agent and model files from BGBZDADS if newer
for f in detection_agent.py gcn_autoencoder.pth scaler.pkl encoders.pkl threshold.txt; do
    [ -f "$SCRIPT_DIR/$f" ] && sudo cp "$SCRIPT_DIR/$f" "$AGENT_DIR/" 2>/dev/null || true
done

sudo fuser -k 8765/tcp 2>/dev/null || true
sudo fuser -k 8080/tcp 2>/dev/null || true
sleep 1
sudo systemctl restart probe-detector
sleep 4

sudo systemctl is-active probe-detector --quiet \
    && echo "[OK] probe-detector running" \
    || (echo "[!] FAILED — logs:" && sudo journalctl -u probe-detector -n 15 --no-pager)

# ── Verify ───────────────────────────────────────────────────
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
echo ""
echo "======================================================="
echo " ALL SYSTEMS GO — $AWS_IP"
echo "======================================================="
echo -n "  kern.log readable:  "; tail -1 /var/log/kern.log &>/dev/null && echo "yes" || echo "NO — fix permissions"
echo -n "  Cowrie SSH  (2222): "; sudo ss -tlnp | grep -c 2222 | tr -d '\n'; echo " listeners"
echo -n "  Cowrie Tel  (2223): "; sudo ss -tlnp | grep -c 2223 | tr -d '\n'; echo " listeners"
echo -n "  Postfix     (2525): "; sudo ss -tlnp | grep -c 2525 | tr -d '\n'; echo " listeners"
echo -n "  nginx         (80): "; sudo systemctl is-active nginx
echo -n "  probe-detector    : "; sudo systemctl is-active probe-detector
echo ""
echo " Verify kern.log:  tail -f /var/log/kern.log | grep PROBE_LOG"
echo " Verify agent:     sudo journalctl -u probe-detector -f"
echo " Dashboard:        http://localhost:3000/dashboard.html?ip=${AWS_IP}"
echo "======================================================="
