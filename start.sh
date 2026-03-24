#!/bin/bash
# ============================================================
# START SCRIPT — run every time EC2 instance reboots
# Usage: bash ~/BGBZDADS/start.sh
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================================="
echo " GCN Probe Detector — Startup"
echo "======================================================="

# ── 1. iptables ──────────────────────────────────────────────
echo ""
echo "[1/5] Setting up iptables..."
sudo bash "$SCRIPT_DIR/setup_iptables.sh"

# Allow service ports
for port in 22 80 2222 2223 2525 8765 8080; do
    sudo iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || true
done
echo "[OK] iptables done"

# ── 2. kern.log permissions ──────────────────────────────────
echo ""
echo "[2/5] Fixing kern.log..."
sudo touch /var/log/kern.log
sudo chmod 644 /var/log/kern.log
# Ensure journald forwards to syslog
sudo sed -i 's/#ForwardToSyslog=yes/ForwardToSyslog=yes/' /etc/systemd/journald.conf
sudo sed -i 's/ForwardToSyslog=no/ForwardToSyslog=yes/' /etc/systemd/journald.conf
sudo systemctl restart systemd-journald 2>/dev/null || true
sudo systemctl restart rsyslog 2>/dev/null || true
echo "[OK] kern.log ready"

# ── 3. Cowrie ────────────────────────────────────────────────
echo ""
echo "[3/5] Starting Cowrie honeypot..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 2
cowrie-env/bin/cowrie start
sleep 2
cowrie-env/bin/cowrie status
deactivate
cd ~
echo "[OK] Cowrie started"

# ── 4. Services ──────────────────────────────────────────────
echo ""
echo "[4/5] Starting system services..."
sudo systemctl start nginx
sudo systemctl start postfix

# Fix nginx log permissions
sudo chmod 755 /var/log/nginx
sudo chmod 644 /var/log/nginx/access.log 2>/dev/null || true

echo -n "  nginx:   "; sudo systemctl is-active nginx
echo -n "  postfix: "; sudo systemctl is-active postfix

# ── 5. Detection agent ───────────────────────────────────────
echo ""
echo "[5/5] Starting detection agent..."
sudo fuser -k 8765/tcp 2>/dev/null || true
sudo fuser -k 8080/tcp 2>/dev/null || true
sleep 1
sudo systemctl restart probe-detector
sleep 4
sudo systemctl is-active probe-detector --quiet \
    && echo "[OK] probe-detector running" \
    || (echo "[!] FAILED:" && sudo journalctl -u probe-detector -n 10 --no-pager)

# ── Summary ──────────────────────────────────────────────────
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
echo ""
echo "======================================================="
echo " ALL SYSTEMS GO — $AWS_IP"
echo "======================================================="
echo -n "  Cowrie SSH   (2222): "; sudo ss -tlnp | grep -c 2222  || echo 0
echo -n "  Cowrie Tel   (2223): "; sudo ss -tlnp | grep -c 2223  || echo 0
echo -n "  nginx          (80): "; sudo systemctl is-active nginx
echo -n "  Postfix      (2525): "; sudo systemctl is-active postfix
echo -n "  probe-detector    : "; sudo systemctl is-active probe-detector
echo ""
echo "  Dashboard: open dashboard.html → connect to $AWS_IP"
echo "  Login:     http://$AWS_IP  (root/root)"
echo "  Logs:      sudo journalctl -u probe-detector -f"
echo "  SMTP test: nc -w3 $AWS_IP 2525"
echo "  Attacks:   bash $SCRIPT_DIR/attack_demo.sh $AWS_IP"
echo "======================================================="
