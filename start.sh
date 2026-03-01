#!/bin/bash
# ============================================================
# START SCRIPT — run this every time EC2 instance boots
# bash start.sh
# ============================================================
echo "======================================================="
echo " GCN Probe Detector — Startup"
echo "======================================================="

# ── 1. iptables ──────────────────────────────────────────────
echo ""
echo "[1/4] Setting up iptables..."

# Switch to legacy backend (required on AL2023)
sudo alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true

SCRIPT_DIR="$HOME/BGBZDADS"

# Run setup_iptables.sh from BGBZDADS folder
sudo bash "$SCRIPT_DIR/setup_iptables.sh"

# Allow all service ports
for port in 22 80 2222 2223 2525 8765 8080; do
    sudo iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || true
done

echo "[OK] iptables — PROBE_LOG active"
sudo iptables -L PROBE_LOG -n 2>/dev/null | head -5

# ── 2. Cowrie ────────────────────────────────────────────────
echo ""
echo "[2/4] Starting Cowrie honeypot..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 2
cowrie-env/bin/cowrie start
sleep 2
cowrie-env/bin/cowrie status
deactivate
cd ~
echo -n "    Ports: "
sudo ss -tlnp | grep -E "2222|2223" | awk '{print $4}' | tr '\n' ' '
echo ""
echo "[OK] Cowrie started"

# ── 3. Services ──────────────────────────────────────────────
echo ""
echo "[3/4] Starting system services..."
sudo systemctl start nginx
sudo systemctl start postfix

# Fix nginx log permissions for agent
sudo chmod 755 /var/log/nginx
sudo chmod 644 /var/log/nginx/access.log 2>/dev/null || true

echo -n "  nginx:   "; sudo systemctl is-active nginx
echo -n "  postfix: "; sudo systemctl is-active postfix

# ── 4. Detection agent ───────────────────────────────────────
echo ""
echo "[4/4] Starting detection agent..."
sudo fuser -k 8765/tcp 2>/dev/null || true
sudo fuser -k 8080/tcp 2>/dev/null || true
sleep 1
sudo systemctl restart probe-detector
sleep 3
sudo systemctl is-active probe-detector --quiet \
    && echo "[OK] probe-detector running" \
    || (echo "[!] FAILED:" && sudo journalctl -u probe-detector -n 10 --no-pager)

# ── Verify ───────────────────────────────────────────────────
echo ""
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
echo "======================================================="
echo " ALL SYSTEMS GO — $AWS_IP"
echo "======================================================="
echo -n "  iptables PROBE_LOG: "; sudo iptables -L PROBE_LOG -n 2>/dev/null | grep -c LOG || echo 0
echo -n "  Cowrie SSH  (2222): "; sudo ss -tlnp | grep -c 2222 || echo 0
echo -n "  Cowrie Tel  (2223): "; sudo ss -tlnp | grep -c 2223 || echo 0
echo -n "  Postfix     (2525): "; sudo ss -tlnp | grep -c 2525 || echo 0
echo -n "  nginx         (80): "; sudo systemctl is-active nginx
echo -n "  probe-detector    : "; sudo systemctl is-active probe-detector
echo ""
echo " Test kern.log:  sudo tail -f /var/log/kern.log | grep PROBE_LOG"
echo " Test agent:     sudo journalctl -u probe-detector -f"
echo " Dashboard:      http://localhost:3000/dashboard.html?ip=${AWS_IP}"
echo "======================================================="
