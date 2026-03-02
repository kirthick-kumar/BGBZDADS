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

# ── 6: Normal access ─────────────────────────
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
    ok "Normal Access done"
}

# ── 7: HTTP path enumeration ──────────────────────────────────
attack_http_enum(){
    log "HTTP path enumeration → HTTP scan node"
    for path in / /admin /login /wp-admin /phpmyadmin /.env /config \
                /backup /api/v1 /shell /manager /console /dashboard \
                /administrator /wp-login.php /.git/config /server-status; do
        curl -s -o /dev/null --connect-timeout 2 \
            -H "User-Agent: Nikto/2.1.6" \
            "http://$TARGET$path" 2>/dev/null &
        sleep 0.15
    done
    wait
    ok "HTTP enumeration done"
}

# ── 8: HTTP login brute force ─────────────────────────────────
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

# ── 9: FULL DEMO ──────────────────────────────────────────────
attack_full_demo(){
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED} FULL DEMO SEQUENCE — watch the dashboard${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    echo ""; log "Phase 1/6: Service Scan — Multi-Service Probe..."
    nmap -T3 -p 22,2222,2223,80,443 $TARGET 2>/dev/null || true
    sleep 4

    echo ""; log "Phase 2/6: Rapid Connection Flood..."
    for i in $(seq 1 30); do
        nc -z -w1 $TARGET 2222 2>/dev/null &
        nc -z -w1 $TARGET 80   2>/dev/null &
        nc -z -w1 $TARGET 2223 2>/dev/null &
        sleep 0.05
    done
    wait
    sleep 4

    echo ""; log "Phase 3/6: HTTP Login Brute Force..."
    for user in admin root administrator; do
        for pass in password 123456 admin admin123; do
            curl -s -o /dev/null -X POST "http://$TARGET/" \
                -d "username=${user}&password=${pass}" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "User-Agent: Mozilla/5.0 zgrab/0.x" \
                --connect-timeout 2 2>/dev/null &
            sleep 0.1
        done
    done
    wait
    sleep 4

    echo ""; log "Phase 4/6: SSH Brute Force on Cowrie (port 2222)..."
    for user in root admin ubuntu pi; do
        for pass in password 123456 admin root; do
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
    sleep 4

    echo ""; log "Phase 5/6: Telnet Brute Force on Cowrie (port 2223)..."
    for user in root admin guest; do
        for pass in password admin 123456; do
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
    sleep 4

    echo ""; log "Phase 6/6: HTTP Path Enumeration..."
    for path in / /admin /login /wp-admin /phpmyadmin /.env /config /backup /api/v1; do
        curl -s -o /dev/null --connect-timeout 2 \
            -H "User-Agent: Nikto/2.1.6" \
            "http://$TARGET$path" 2>/dev/null &
        sleep 0.15
    done
    wait

    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN} DEMO COMPLETE — dashboard should show:${NC}"
    echo "  • Red probe node for your IP"
    echo "  • Service nodes: ssh (purple), http (blue), telnet (violet)"
    echo "  • Multi-Service + Rapid Conn + Brute Force detected"
    echo "  • GCN model prediction: PROBE"
    echo "  • IP auto-blocked"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── MENU ──────────────────────────────────────────────────────
echo "Select attack:"
echo "  1)  Service scan               → Multi-Service Probe"
echo "  2)  SSH brute force (2222)     → Brute Force rule"
echo "  3)  Telnet brute force (2223)  → Brute Force + Telnet node"
echo "  4)  Rapid connection flood     → Rapid Connections rule"
echo "  5)  OS fingerprint scan        → Aggressive detection"
echo "  6)  Normal Access sim          → Normal Access pattern"
echo "  7)  HTTP login & enumeration   → POST /login attack"
echo ""
read -p "Choice [1-7]: " c

case $c in
    1) attack_service_scan ;;
    2) attack_ssh_brute ;;
    3) attack_telnet_brute ;;
    4) attack_rapid_conn ;;
    5) attack_os_scan ;;
    6) normal_access ;;
    7) attack_http_login_brute ;;
    8) attack_full_demo ;;
    *) echo "Invalid choice"; exit 1 ;;
esac
