#!/bin/bash
# ============================================================
# iptables Setup — Amazon Linux 2023
# Uses iptables with nf_tables backend (no legacy needed)
# ============================================================

echo "[*] Setting up PROBE_LOG chain..."

# Flush and recreate chain cleanly
sudo iptables -F PROBE_LOG 2>/dev/null || true
sudo iptables -X PROBE_LOG 2>/dev/null || true
sudo iptables -N PROBE_LOG

# Log WITHOUT rate limit (rate limit was silently dropping events)
sudo iptables -A PROBE_LOG -j LOG --log-prefix "PROBE_LOG " --log-level 4
sudo iptables -A PROBE_LOG -j RETURN

# Remove any stale jump rules
sudo iptables -D INPUT -p tcp --syn -j PROBE_LOG 2>/dev/null || true
sudo iptables -D INPUT -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,2222,2223,2525,3306,5432,6379,8080 \
    -j PROBE_LOG 2>/dev/null || true

# Log ALL new TCP SYN
sudo iptables -I INPUT 1 -p tcp --syn -j PROBE_LOG

# Log specific service ports (belt + suspenders)
sudo iptables -I INPUT 2 -p tcp -m state --state NEW \
    -m multiport --dports 21,22,23,25,80,443,2222,2223,2525,3306,5432,6379,8080 \
    -j PROBE_LOG

# Allow service ports
for port in 22 80 2222 2223 2525 8765 8080; do
    sudo iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || true
done

# Fix kern.log permissions so agent (ec2-user) can read it
sudo chmod 644 /var/log/kern.log 2>/dev/null || true

# Ensure rsyslog writes kern messages to kern.log
if ! grep -q "kern.warning" /etc/rsyslog.conf 2>/dev/null; then
    echo 'kern.warning /var/log/kern.log' | sudo tee -a /etc/rsyslog.conf
    sudo systemctl restart rsyslog
    echo "[OK] rsyslog kern.log rule added"
fi

echo "[OK] PROBE_LOG chain active"
sudo iptables -L PROBE_LOG -n
