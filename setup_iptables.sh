#!/bin/bash
# ============================================================
# Step 3: iptables PROBE_LOG setup
# Called by setup_aws.sh automatically
# Can also run standalone: sudo bash setup_iptables.sh
# ============================================================

echo "[*] Setting up iptables PROBE_LOG chain..."

# Flush and recreate PROBE_LOG chain cleanly
iptables -F PROBE_LOG 2>/dev/null || true
iptables -X PROBE_LOG 2>/dev/null || true
iptables -N PROBE_LOG

# Log matching packets with PROBE_LOG prefix (kern.log)
iptables -A PROBE_LOG -m limit --limit 60/min --limit-burst 100 \
    -j LOG --log-prefix "PROBE_LOG " --log-level 4
iptables -A PROBE_LOG -j RETURN

# Remove old jump rules
iptables -D INPUT -p tcp --syn -j PROBE_LOG 2>/dev/null || true
iptables -D INPUT -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,3306,5432,6379,8080 \
    -j PROBE_LOG 2>/dev/null || true

# Log ALL new TCP SYN packets (catches nmap wide port scans)
iptables -I INPUT 1 -p tcp --syn -j PROBE_LOG

# Also specifically log known service ports
iptables -I INPUT 2 -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,3306,5432,6379,8080 \
    -j PROBE_LOG

# NAT: redirect port 22 → 2224 (Cowrie SSH)
iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2224 2>/dev/null || true
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2224

# NAT: redirect port 23 → 2323 (Cowrie Telnet)
iptables -t nat -D PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323 2>/dev/null || true
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323

# Ensure kern.log receives iptables messages
if ! grep -q "kern.warning" /etc/rsyslog.conf 2>/dev/null; then
    echo 'kern.warning /var/log/kern.log' >> /etc/rsyslog.conf
    systemctl restart rsyslog 2>/dev/null || true
    echo "[✓] rsyslog kern.log rule added"
fi

echo "[✓] iptables PROBE_LOG chain active"
echo "[✓] Port 22 → 2224 (Cowrie), Port 23 → 2323 (Cowrie Telnet)"
echo ""
echo " Verify with:"
echo "   sudo tail -f /var/log/kern.log | grep PROBE_LOG"
