#!/bin/bash
# ============================================================
# Pre-demo verification — run on AWS server
# Checks every component and tells you if something is broken
# ============================================================
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
PASS=0; FAIL=0

check(){ 
  if eval "$2" &>/dev/null; then
    echo "  ✓  $1"; ((PASS++))
  else
    echo "  ✗  $1  ← FIX THIS"; ((FAIL++))
  fi
}

echo "═══════════════════════════════════════════════════════"
echo " Pre-Demo Verification   Server: $AWS_IP"  
echo "═══════════════════════════════════════════════════════"

echo ""
echo "[ Cowrie ]"
check "Cowrie process running"  "pgrep -f 'twistd.*cowrie'"
check "Cowrie JSON log exists"  "test -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json"
check "Cowrie log is recent"    "find /home/cowrie/cowrie/var/log/cowrie/cowrie.json -mmin -60"
check "Cowrie SSH port 2222"    "ss -tlnp | grep 2222"
check "Cowrie Telnet port 2323" "ss -tlnp | grep 2323"

echo ""
echo "[ iptables ]"
check "PROBE_LOG chain exists"  "iptables -L PROBE_LOG -n"
check "LOG rule in INPUT"       "iptables -L INPUT -n | grep PROBE_LOG"
check "SYN logging active"      "iptables -L INPUT -n | grep -i 'syn\|probe'"
check "Port 22→2222 NAT"       "iptables -t nat -L PREROUTING -n | grep 2222"
check "kern.log exists"         "test -f /var/log/kern.log"
check "kern.log writable"       "test -w /var/log/kern.log"

echo ""
echo "[ Detection Agent ]"
check "Agent service running"   "systemctl is-active probe-detector"
check "WebSocket port 8765"     "ss -tlnp | grep 8765"
check "HTTP port 8080"          "ss -tlnp | grep 8080"
check "HTTP /status responds"   "curl -sf http://localhost:8080/status"
check "Model file exists"       "test -f /opt/probe_detector/gcn_autoencoder.pth"
check "Scaler file exists"      "test -f /opt/probe_detector/scaler.pkl"

echo ""
echo "[ iptables Live Test ]"
echo "  Generating a test SYN packet to verify kern.log logging..."
# Send a SYN to ourselves on a logged port
timeout 2 nc -z 127.0.0.1 80 2>/dev/null || true
sleep 1
if grep -q "PROBE_LOG" /var/log/kern.log 2>/dev/null; then
  echo "  ✓  kern.log receiving PROBE_LOG entries"; ((PASS++))
else
  echo "  ✗  kern.log NOT receiving PROBE_LOG entries"
  echo "     → Run: sudo bash setup_iptables.sh"
  echo "     → Check: grep 'kern\.' /etc/rsyslog.conf"
  ((FAIL++))
fi

echo ""
echo "[ HTTP Inject Test ]"
echo "  Injecting a fake port-scan event to test pipeline..."
RESP=$(curl -sf -X POST http://localhost:8080/inject \
  -H 'Content-Type: application/json' \
  -d '{"ip":"9.9.9.9","type":"iptables.probe_log","service":"ssh","ports":[22,23,80,443,21,8080,3306,5432,25,110]}' \
  2>/dev/null)
if echo "$RESP" | grep -q '"ok"'; then
  echo "  ✓  Inject API working — check dashboard for 9.9.9.9 probe node"
  ((PASS++))
else
  echo "  ✗  Inject API failed: $RESP"
  ((FAIL++))
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo " Results: ${PASS} passed, ${FAIL} failed"
if [ $FAIL -eq 0 ]; then
  echo " ✓ ALL CHECKS PASSED — Ready for demo!"
  echo ""
  echo " Dashboard URL (open in browser):"
  echo "   dashboard.html?ip=${AWS_IP}"
  echo ""
  echo " Attack from laptop:"
  echo "   ./attack_demo.sh ${AWS_IP}  → choose option 6"
else
  echo " ✗ ${FAIL} issues found — fix before demo"
fi
echo "═══════════════════════════════════════════════════════"
