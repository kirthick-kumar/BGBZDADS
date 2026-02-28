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
ok(){ echo -e "${GREEN}[✓]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }

echo -e "${RED}"
echo "═══════════════════════════════════════════════════════"
echo "   PROBE ATTACK DEMO SUITE"
echo "   Target: $TARGET"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"

# ── ATTACK 1: Basic SYN port scan ────────────────────────────
attack_portscan(){
    log "Attack 1: nmap SYN scan → Port Scan rule"
    nmap -sS -T4 -p 1-500 $TARGET 2>/dev/null || nmap -T4 -p 1-500 $TARGET
    ok "Port scan done"
}

# ── ATTACK 2: Service/version scan ───────────────────────────
attack_service_scan(){
    log "Attack 2: Service version scan → Multi-Service Probe"
    nmap -sV -T3 -p 21,22,2222,2223,25,80,443,3306,5432,6379 $TARGET
    ok "Service scan done"
}

# ── ATTACK 3: SSH brute force on Cowrie ──────────────────────
attack_ssh_brute(){
    log "Attack 3: SSH brute force on port 2222 → Brute Force rule"
    USERS="root admin ubuntu pi oracle guest ec2-user deploy"
    PASSES="password 123456 admin root toor letmein qwerty 1234 pass"
    for user in $USERS; do
        for pass in $PASSES; do
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=2 \
                -o PasswordAuthentication=yes \
                -o PreferredAuthentications=password \
                -o LogLevel=quiet \
                -p 2222 \
                ${user}@${TARGET} exit 2>/dev/null &
            sleep 0.1
        done
    done
    wait
    ok "SSH brute force done"
}

# ── ATTACK 4: Telnet brute force on Cowrie ───────────────────
attack_telnet_brute(){
    log "Attack 4: Telnet brute force on port 2223 → Brute Force + Multi-Service"
    for user in root admin guest; do
        for pass in password admin 123456; do
            (
                sleep 1
                echo "$user"
                sleep 0.5
                echo "$pass"
                sleep 0.5
                echo "exit"
            ) | telnet $TARGET 2223 2>/dev/null &
            sleep 0.3
        done
    done
    wait
    ok "Telnet brute force done"
}

# ── ATTACK 5: Rapid connection flood ─────────────────────────
attack_rapid_conn(){
    log "Attack 5: Rapid connections → Rapid Connections rule"
    for i in $(seq 1 25); do
        nc -z -w1 $TARGET 2222 2>/dev/null &
        nc -z -w1 $TARGET 80   2>/dev/null &
        nc -z -w1 $TARGET 21   2>/dev/null &
        nc -z -w1 $TARGET 2223 2>/dev/null &
        sleep 0.08
    done
    wait
    ok "Rapid connections done"
}

# ── ATTACK 6: FTP probe ──────────────────────────────────────
attack_ftp(){
    log "Attack 6: FTP probe on port 21 → FTP service node"
    for i in $(seq 1 5); do
        (
            sleep 0.5
            echo "USER anonymous"
            sleep 0.3
            echo "PASS hacker@evil.com"
            sleep 0.3
            echo "LIST"
            sleep 0.3
            echo "QUIT"
        ) | nc -w3 $TARGET 21 2>/dev/null &
        sleep 0.5
    done
    wait
    ok "FTP probe done"
}

# ── ATTACK 7: Slow stealth scan ──────────────────────────────
attack_stealth(){
    log "Attack 7: Slow stealth scan (evades rate limits, builds graph gradually)"
    nmap -T1 -p 22,80,2222,2223,21,443,3306 $TARGET 2>/dev/null &
    PID=$!
    log "  Stealth scan running in background (PID: $PID)"
    log "  Watch graph build slowly on dashboard..."
    wait $PID
    ok "Stealth scan done"
}

# ── ATTACK 8: OS fingerprint scan ────────────────────────────
attack_os_scan(){
    log "Attack 8: OS fingerprint + aggressive scan"
    nmap -A -T4 -p 22,80,2222,2223 $TARGET 2>/dev/null || \
    nmap -T4 -p 22,80,2222,2223 $TARGET
    ok "OS scan done"
}

# ── ATTACK 9: Vulnerability scan ─────────────────────────────
attack_vuln_scan(){
    log "Attack 9: Vulnerability/script scan"
    nmap --script=banner,ssh-hostkey,http-headers,ftp-anon \
        -p 21,22,80,2222,2223 $TARGET 2>/dev/null || \
    nmap -T4 -p 21,22,80,2222,2223 $TARGET
    ok "Vuln scan done"
}

# ── ATTACK 10: Distributed multi-source sim ──────────────────
attack_distributed(){
    log "Attack 10: Simulated distributed attack (multiple IPs via SSH proxying)"
    warn "  This simulates attacks from multiple sources"
    warn "  Each attack rotates through different ports/services"
    # Wave 1: port scan
    nmap -T4 -p 1-100 $TARGET 2>/dev/null &
    sleep 2
    # Wave 2: service probe
    nc -z -w2 $TARGET 2222 2>/dev/null &
    nc -z -w2 $TARGET 2223 2>/dev/null &
    nc -z -w2 $TARGET 21   2>/dev/null &
    nc -z -w2 $TARGET 80   2>/dev/null &
    sleep 2
    # Wave 3: brute force
    for user in root admin; do
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
            -o PasswordAuthentication=yes \
            -o PreferredAuthentications=password \
            -o LogLevel=quiet \
            -p 2222 ${user}@${TARGET} exit 2>/dev/null &
        sleep 0.3
    done
    wait
    ok "Distributed attack simulation done"
}

# ── ATTACK 11: HTTP attack simulation ────────────────────────
attack_http_attack(){
    log "Attack 11: HTTP scanning + path enumeration"
    PATHS="/ /admin /login /wp-admin /phpmyadmin /.env /config /backup /api/v1 /shell"
    for path in $PATHS; do
        curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 2 \
            -H "User-Agent: Mozilla/5.0 zgrab/0.x" \
            "http://$TARGET$path" 2>/dev/null &
        sleep 0.2
    done
    wait
    ok "HTTP scan done"
}

# ── ATTACK 12: FULL DEMO ─────────────────────────────────────
attack_full_demo(){
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED} FULL DEMO SEQUENCE — watch the dashboard${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    echo ""; log "Phase 1/5: Reconnaissance — Port Scan..."
    nmap -T4 -p 1-300 $TARGET 2>/dev/null || nmap -p 1-300 $TARGET
    sleep 4

    echo ""; log "Phase 2/5: Service Enumeration — Multi-Service Probe..."
    nmap -sV -T3 -p 21,22,2222,2223,80,443 $TARGET 2>/dev/null || \
    nmap -T3 -p 21,22,2222,2223,80,443 $TARGET
    nc -z -w2 $TARGET 21   2>/dev/null
    nc -z -w2 $TARGET 2223 2>/dev/null
    sleep 4

    echo ""; log "Phase 3/5: Flood — Rapid Connections..."
    for i in $(seq 1 25); do
        nc -z -w1 $TARGET 2222 2>/dev/null &
        nc -z -w1 $TARGET 80   2>/dev/null &
        nc -z -w1 $TARGET 21   2>/dev/null &
        nc -z -w1 $TARGET 2223 2>/dev/null &
        sleep 0.08
    done
    wait
    sleep 4

    echo ""; log "Phase 4/5: SSH Brute Force on Cowrie (port 2222)..."
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
    sleep 4

    echo ""; log "Phase 5/5: Telnet Brute Force on Cowrie (port 2223)..."
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

    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN} DEMO COMPLETE — dashboard should show:${NC}"
    echo "  • Red probe node for your IP"
    echo "  • Rules: Port Scan + Multi-Service + Rapid Conn + Brute Force"
    echo "  • Service nodes: ssh, telnet, ftp, http (with distinct colors)"
    echo "  • Port range buckets for wide scan"
    echo "  • IP auto-blocked"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── MENU ─────────────────────────────────────────────────────
echo "Select attack:"
echo "  1)  nmap SYN scan              → Port Scan rule"
echo "  2)  nmap service scan          → Multi-Service Probe"
echo "  3)  SSH brute force (port 2222)→ Brute Force rule"
echo "  4)  Telnet brute force (2223)  → Multi-Service + Brute Force"
echo "  5)  Rapid connection flood     → Rapid Connections rule"
echo "  6)  FTP probe                  → FTP service node"
echo "  7)  Slow stealth scan          → Gradual graph build"
echo "  8)  OS fingerprint scan        → Aggressive detection"
echo "  9)  Vulnerability script scan  → Banner grab + scripts"
echo "  10) Distributed attack sim     → Multi-wave attack"
echo "  11) HTTP path enumeration      → HTTP attack node"
echo "  12) FULL DEMO (all phases)     ← USE THIS FOR PANEL"
echo ""
read -p "Choice [1-12]: " c
case $c in
    1)  attack_portscan ;;
    2)  attack_service_scan ;;
    3)  attack_ssh_brute ;;
    4)  attack_telnet_brute ;;
    5)  attack_rapid_conn ;;
    6)  attack_ftp ;;
    7)  attack_stealth ;;
    8)  attack_os_scan ;;
    9)  attack_vuln_scan ;;
    10) attack_distributed ;;
    11) attack_http_attack ;;
    12) attack_full_demo ;;
    *)  echo "Invalid choice"; exit 1 ;;
esac
