#!/bin/bash
# ============================================================
# Attack Demo Script — run from your laptop
# Usage: bash attack_demo.sh <AWS_PUBLIC_IP>
# NOTE: SSH honeypot is on port 2222 (not 22)
#       Port 22 = real SSH, leave it alone
# ============================================================
TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: bash attack_demo.sh <AWS_PUBLIC_IP>"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo " Probe Attack Demo   Target: $TARGET"
echo "═══════════════════════════════════════════════════════"

attack_portscan(){
    echo "[1] nmap SYN scan → Port Scan rule"
    nmap -sS -T4 -p 1-500 $TARGET 2>/dev/null || nmap -T4 -p 1-500 $TARGET
    echo "[✓] Done"
}

attack_service_scan(){
    echo "[2] nmap service scan → Multi-Service Probe rule"
    nmap -sV -T3 -p 21,2222,2323,25,80,443,3306,5432 $TARGET
    echo "[✓] Done"
}

attack_ssh_brute(){
    echo "[3] SSH brute force on port 2222 (Cowrie) → Brute Force rule"
    for user in root admin ubuntu pi ec2-user oracle; do
        for pass in password 123456 admin root toor letmein; do
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=2 \
                -o PasswordAuthentication=yes \
                -o PreferredAuthentications=password \
                -p 2222 \
                ${user}@${TARGET} exit 2>/dev/null &
            sleep 0.15
        done
    done
    wait
    echo "[✓] Done"
}

attack_rapid_conn(){
    echo "[4] Rapid connections → Rapid Connections rule"
    for i in $(seq 1 25); do
        nc -z -w1 $TARGET 2222 2>/dev/null &
        nc -z -w1 $TARGET 80   2>/dev/null &
        sleep 0.08
    done
    wait
    echo "[✓] Done"
}

attack_http(){
    echo "[5] HTTP visit → normal node (never blocked)"
    curl -s http://$TARGET > /dev/null && echo "    HTTP ok"
    echo "[✓] Done"
}

attack_full_demo(){
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " FULL DEMO SEQUENCE — watch the dashboard"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo ""
    echo "Step 1/4: Port scan (Port Scan rule)..."
    nmap -T4 -p 1-300 $TARGET 2>/dev/null || nmap -p 1-300 $TARGET
    sleep 5

    echo ""
    echo "Step 2/4: Service scan (Multi-Service Probe rule)..."
    nmap -sV -T3 -p 21,2222,2323,80,443 $TARGET 2>/dev/null || \
    nmap -T3 -p 21,2222,2323,80,443 $TARGET
    sleep 5

    echo ""
    echo "Step 3/4: Rapid connections (Rapid Connections rule)..."
    for i in $(seq 1 25); do
        nc -z -w1 $TARGET 2222 2>/dev/null &
        nc -z -w1 $TARGET 80   2>/dev/null &
        sleep 0.08
    done
    wait
    sleep 5

    echo ""
    echo "Step 4/4: SSH brute force on Cowrie port 2222 (Brute Force rule)..."
    for user in root admin ubuntu pi oracle; do
        for pass in password 123456 admin root toor; do
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=2 \
                -o PasswordAuthentication=yes \
                -o PreferredAuthentications=password \
                -p 2222 \
                ${user}@${TARGET} exit 2>/dev/null &
            sleep 0.2
        done
    done
    wait

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " DONE — dashboard should show:"
    echo "  • Red probe node for your IP"
    echo "  • Rules: Port Scan + Multi-Service + Brute Force"
    echo "  • Edges: host → ssh, http, port ranges"
    echo "  • IP auto-blocked"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

echo ""
echo "Select attack:"
echo "  1) nmap SYN scan              → Port Scan rule"
echo "  2) nmap service scan          → Multi-Service Probe"
echo "  3) SSH brute force (port 2222)→ Brute Force rule"
echo "  4) Rapid connections          → Rapid Connections rule"
echo "  5) HTTP visit                 → Normal node (no block)"
echo "  6) FULL DEMO (all rules)      ← USE THIS FOR PANEL"
echo ""
read -p "Choice [1-6]: " c
case $c in
    1) attack_portscan ;;
    2) attack_service_scan ;;
    3) attack_ssh_brute ;;
    4) attack_rapid_conn ;;
    5) attack_http ;;
    6) attack_full_demo ;;
    *) echo "Invalid choice"; exit 1 ;;
esac