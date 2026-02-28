#!/bin/bash
# ============================================================
# iptables Setup — Amazon Linux 2023
# Uses iptables-legacy if nftables backend detected
# Port 22  = real SSH (untouched)
# Port 2222 = Cowrie SSH (direct)
# Port 2223 = Cowrie Telnet (direct)
# ============================================================

echo "[*] Checking iptables backend..."

# AL2023 uses nftables by default — switch to legacy
if iptables -L PROBE_LOG -n 2>&1 | grep -q "incompatible"; then
    echo "    nftables detected — switching to iptables-legacy"
    sudo alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || \
    sudo ln -sf /usr/sbin/iptables-legacy /usr/local/sbin/iptables 2>/dev/null || true
    echo "    switched to iptables-legacy"
fi

echo "[*] Setting up PROBE_LOG chain..."

# Flush and recreate chain cleanly
sudo iptables -F PROBE_LOG 2>/dev/null || true
sudo iptables -X PROBE_LOG 2>/dev/null || true
sudo iptables -N PROBE_LOG

# Log with PROBE_LOG prefix → /var/log/kern.log
sudo iptables -A PROBE_LOG \
    -m limit --limit 60/min --limit-burst 100 \
    -j LOG --log-prefix "PROBE_LOG " --log-level 4
sudo iptables -A PROBE_LOG -j RETURN

# Remove old jump rules
sudo iptables -D INPUT -p tcp --syn -j PROBE_LOG 2>/dev/null || true
sudo iptables -D INPUT -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,2222,2223,3306,5432,6379,8080 \
    -j PROBE_LOG 2>/dev/null || true

# Log ALL new TCP SYN (catches nmap wide scans)
sudo iptables -I INPUT 1 -p tcp --syn -j PROBE_LOG

# Also log specific service ports
sudo iptables -I INPUT 2 -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,2222,2223,2525,3306,5432,6379,8080 \
    -j PROBE_LOG

# Ensure kern.log receives iptables messages
if ! grep -q "kern.warning" /etc/rsyslog.conf 2>/dev/null; then
    echo 'kern.warning /var/log/kern.log' | sudo tee -a /etc/rsyslog.conf
    sudo systemctl restart rsyslog 2>/dev/null || true
    echo "[OK] rsyslog kern.log rule added"
fi

echo "[OK] PROBE_LOG chain active"
echo "[OK] Port 22 = real SSH (unchanged)"
echo "[OK] Port 2222/2223 = Cowrie (direct, no redirect)"
echo ""
echo " Test: sudo tail -f /var/log/kern.log | grep PROBE_LOG"
