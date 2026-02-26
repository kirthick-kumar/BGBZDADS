#!/bin/bash
# ============================================================
# iptables setup — runs on AWS before starting the agent
# Creates a PROBE_LOG chain that logs incoming packets
# so the detection agent can see nmap SYN scans
# ============================================================
set -e

echo "[*] Setting up iptables PROBE_LOG chain..."

# ── Flush any old PROBE_LOG chain ───────────────────────────
iptables -F PROBE_LOG 2>/dev/null || true
iptables -X PROBE_LOG 2>/dev/null || true

# ── Create chain ─────────────────────────────────────────────
iptables -N PROBE_LOG

# ── Log matching packets with tag ────────────────────────────
# Limit: 60/min per source to avoid log flooding
iptables -A PROBE_LOG -m limit --limit 60/min --limit-burst 100 \
  -j LOG --log-prefix "PROBE_LOG " --log-level 4

# ── Return to INPUT after logging ────────────────────────────
iptables -A PROBE_LOG -j RETURN

# ── Jump into PROBE_LOG chain from INPUT ─────────────────────
# Only log NEW connections on honeypot ports (not established/related)
# This catches nmap SYN scans without flooding on normal traffic

# Remove old jump rules first
iptables -D INPUT -p tcp -m state --state NEW \
  -m multiport --dports 21,22,23,25,80,443,3306,5432,6379,8080 \
  -j PROBE_LOG 2>/dev/null || true

iptables -D INPUT -p udp \
  -m multiport --dports 53,161,123 \
  -j PROBE_LOG 2>/dev/null || true

# Add jump rules
iptables -I INPUT 1 -p tcp -m state --state NEW \
  -m multiport --dports 21,22,23,25,80,443,3306,5432,6379,8080 \
  -j PROBE_LOG

iptables -I INPUT 2 -p udp \
  -m multiport --dports 53,161,123 \
  -j PROBE_LOG

echo "[✓] PROBE_LOG chain active"

# ── For nmap SYN scans that hit random ports ─────────────────
# Log ALL new TCP SYN packets (not just known ports)
# This is what catches wide port sweeps
iptables -D INPUT -p tcp --syn -j PROBE_LOG 2>/dev/null || true
iptables -I INPUT 3 -p tcp --syn -j PROBE_LOG

echo "[✓] SYN packet logging active (catches all nmap scans)"

# ── Save rules ───────────────────────────────────────────────
service iptables save 2>/dev/null || \
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
  iptables-save > /etc/sysconfig/iptables 2>/dev/null || true

# ── Also redirect port 22 → Cowrie ──────────────────────────
# Cowrie runs on 2222, real SSH on 2222 (after you change sshd_config)
iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 2>/dev/null || true
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -D PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323 2>/dev/null || true
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323

echo "[✓] Port forwarding: 22→2222 (Cowrie SSH), 23→2323 (Cowrie Telnet)"

# ── Ensure kern.log gets iptables messages ───────────────────
# On Amazon Linux 2023, rsyslog may need a kern rule
if ! grep -q "kern.warning" /etc/rsyslog.conf 2>/dev/null; then
  echo 'kern.warning /var/log/kern.log' >> /etc/rsyslog.conf
  systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null || true
  echo "[✓] rsyslog kern.log rule added"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo " iptables ready. Test with:"
echo "   tail -f /var/log/kern.log | grep PROBE_LOG"
echo " Then from your laptop:"
echo "   nmap -sS -p 22,80,443 $(curl -s ifconfig.me)"
echo "═══════════════════════════════════════════════════════"
