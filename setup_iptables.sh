#!/bin/bash
# ============================================================
# iptables Setup
# Port 22  = real SSH (untouched)
# Port 2222 = Cowrie SSH (direct, no redirect)
# Port 2323 = Cowrie Telnet (direct, no redirect)
# PROBE_LOG chain logs all new connections for detection
# ============================================================

echo "[*] Setting up iptables PROBE_LOG chain..."

# Flush and recreate PROBE_LOG chain cleanly
iptables -F PROBE_LOG 2>/dev/null || true
iptables -X PROBE_LOG 2>/dev/null || true
iptables -N PROBE_LOG

# Log with PROBE_LOG prefix → appears in /var/log/kern.log
iptables -A PROBE_LOG -m limit --limit 60/min --limit-burst 100 \
    -j LOG --log-prefix "PROBE_LOG " --log-level 4
iptables -A PROBE_LOG -j RETURN

# Remove old jump rules if any
iptables -D INPUT -p tcp --syn -j PROBE_LOG 2>/dev/null || true
iptables -D INPUT -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,2222,2323,3306,5432,6379,8080 \
    -j PROBE_LOG 2>/dev/null || true

# Log ALL new TCP SYN packets (catches nmap wide port scans)
iptables -I INPUT 1 -p tcp --syn -j PROBE_LOG

# Also specifically log known service ports including Cowrie ports
iptables -I INPUT 2 -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,2222,2323,3306,5432,6379,8080 \
    -j PROBE_LOG

# NO NAT REDIRECTS — SSH stays on 22, Cowrie listens on 2222/2323 directly
# Attackers who probe port 2222 or 2323 will hit Cowrie directly

# Ensure kern.log gets iptables messages
if ! grep -q "kern.warning" /etc/rsyslog.conf 2>/dev/null; then
    echo 'kern.warning /var/log/kern.log' >> /etc/rsyslog.conf
    systemctl restart rsyslog 2>/dev/null || true
    echo "[✓] rsyslog kern.log rule added"
fi

echo "[✓] PROBE_LOG chain active — all new TCP connections logged"
echo "[✓] Port 22 = real SSH (unchanged)"
echo "[✓] Port 2222/2323 = Cowrie (direct)"
echo ""
echo " Test: sudo tail -f /var/log/kern.log | grep PROBE_LOG"
