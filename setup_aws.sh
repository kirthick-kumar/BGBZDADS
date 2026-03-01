#!/bin/bash
# ============================================================
# AWS Full Setup — Amazon Linux 2023 — Run ONCE on new instance
# Place all files in same folder and run: bash setup_aws.sh
#
# Port layout:
#   22   = real SSH (unchanged)
#   2222 = Cowrie SSH honeypot
#   2223 = Cowrie Telnet honeypot
#   80   = nginx HTTP (Anna University login page)
#   2525 = Postfix SMTP (port 25 blocked by AWS)
#   8765 = WebSocket (dashboard)
#   8080 = HTTP API
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/probe_detector"
AWS_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")

echo "======================================================="
echo " GCN Probe Detector — AWS Setup"
echo " Server IP: $AWS_IP"
echo "======================================================="

# ── 1. Cowrie ────────────────────────────────────────────────
echo ""
echo "[1/7] Installing Cowrie..."
cd ~
if [ ! -d cowrie ]; then
    git clone https://github.com/cowrie/cowrie.git
fi
cd cowrie
if [ ! -d cowrie-env ]; then
    python3.11 -m venv cowrie-env
fi
source cowrie-env/bin/activate
pip install --quiet -r requirements.txt
pip install -e . -q 2>/dev/null || true

echo "    Writing clean cowrie.cfg..."
python3 - << 'PYEOF'
import configparser
cfg = configparser.ConfigParser(strict=False)
cfg.read('etc/cowrie.cfg.dist')
for sec in ['honeypot', 'telnet', 'output_jsonlog']:
    if not cfg.has_section(sec):
        cfg.add_section(sec)
cfg.set('honeypot', 'hostname',         'prod-server-01')
cfg.set('honeypot', 'listen_endpoints', 'tcp:2222:interface=0.0.0.0')
cfg.set('telnet',   'enabled',          'true')
cfg.set('telnet',   'listen_endpoints', 'tcp:2223:interface=0.0.0.0')
cfg.set('output_jsonlog', 'enabled',    'true')
cfg.set('output_jsonlog', 'logfile',    'var/log/cowrie/cowrie.json')
with open('etc/cowrie.cfg', 'w') as f:
    cfg.write(f)
print("    cowrie.cfg written OK")
PYEOF

deactivate
cd ~
echo "[OK] Cowrie installed"

# ── 2. Start Cowrie ──────────────────────────────────────────
echo ""
echo "[2/7] Starting Cowrie..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 2
cowrie-env/bin/cowrie start
sleep 3
cowrie-env/bin/cowrie status
deactivate
cd ~
echo "[OK] Cowrie started"

# ── 3. nginx + login page ────────────────────────────────────
echo ""
echo "[3/7] Installing nginx + login page..."
sudo systemctl start nginx
sudo systemctl enable nginx

# Deploy login and home pages
sudo mkdir -p /usr/share/nginx/html
[ -f "$SCRIPT_DIR/login.html" ] && sudo cp "$SCRIPT_DIR/login.html" /usr/share/nginx/html/index.html
[ -f "$SCRIPT_DIR/home.html"  ] && sudo cp "$SCRIPT_DIR/home.html"  /usr/share/nginx/html/home.html

sudo tee /etc/nginx/conf.d/portal.conf > /dev/null << 'NGEOF'
server {
    listen 80 default_server;
    root /usr/share/nginx/html;
    index index.html;
    location = /       { try_files /index.html =404; }
    location = /home   { try_files /home.html  =404; }
    location = /guest  { return 200 'Guest access disabled.'; add_header Content-Type text/plain; }
    location /         { try_files $uri /index.html; }
}
NGEOF

# Block AWS health check IPs from polluting logs
sudo tee /etc/nginx/conf.d/filter_healthchecks.conf > /dev/null << 'NGEOF'
geo $loggable {
    default       1;
    15.177.0.0/16 0;
}
access_log /var/log/nginx/access.log combined if=$loggable;
NGEOF

sudo nginx -t 2>/dev/null && sudo systemctl reload nginx

# Fix permissions so ec2-user can read nginx log
sudo usermod -aG nginx ec2-user
sudo chmod 755 /var/log/nginx
sudo chmod 644 /var/log/nginx/access.log 2>/dev/null || true

echo "[OK] nginx on port 80"

# ── 4. Postfix SMTP ──────────────────────────────────────────
echo ""
echo "[4/7] Installing Postfix SMTP on port 2525..."
sudo yum install -y postfix 2>/dev/null || true

sudo tee /etc/postfix/main.cf > /dev/null << 'PFEOF'
myhostname = mail.prod-server-01.local
mydomain = prod-server-01.local
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost
relay_domains =
mynetworks = 127.0.0.0/8
smtpd_banner = $myhostname ESMTP Postfix
disable_vrfy_command = no
smtpd_helo_required = no
mailbox_size_limit = 0
message_size_limit = 10240000
smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination
PFEOF

# AWS blocks port 25 — use 2525
sudo sed -i 's/^smtp      inet/# smtp      inet/' /etc/postfix/master.cf
sudo sed -i '/^2525 /d' /etc/postfix/master.cf
echo "2525      inet  n       -       n       -       -       smtpd" | sudo tee -a /etc/postfix/master.cf

sudo systemctl restart postfix
sudo systemctl enable postfix
sleep 1
echo -n "    Postfix: "; sudo systemctl is-active postfix
echo -n "    Port 2525: "; sudo ss -tlnp | grep 2525 | grep -c master || echo 0
echo "[OK] SMTP on port 2525"

# ── 5. iptables ──────────────────────────────────────────────
echo ""
echo "[5/7] Configuring iptables..."
sudo bash "$SCRIPT_DIR/setup_iptables.sh"
echo "[OK] iptables done"

# ── 6. Swap (prevents OOM kills on t2.micro) ─────────────────
echo ""
echo "[6/7] Setting up swap..."
if [ ! -f /swapfile ]; then
    sudo dd if=/dev/zero of=/swapfile bs=128M count=16 2>/dev/null
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    echo "[OK] 2GB swap created"
else
    sudo swapon /swapfile 2>/dev/null || true
    echo "[OK] swap already exists"
fi
free -m | grep Swap

# ── 7. Detection agent ───────────────────────────────────────
echo ""
echo "[7/7] Deploying detection agent..."
sudo mkdir -p $AGENT_DIR
sudo chown ec2-user:ec2-user $AGENT_DIR
cp "$SCRIPT_DIR/detection_agent.py" $AGENT_DIR/

for f in gcn_autoencoder.pth scaler.pkl encoders.pkl threshold.txt; do
    [ -f "$SCRIPT_DIR/$f" ] && cp "$SCRIPT_DIR/$f" $AGENT_DIR/ && echo "    copied $f"
done

sudo tee /etc/systemd/system/probe-detector.service > /dev/null << SVCEOF
[Unit]
Description=GCN Probe Detection Agent
After=network.target

[Service]
User=ec2-user
WorkingDirectory=${AGENT_DIR}
Environment=COWRIE_LOG=/home/ec2-user/cowrie/var/log/cowrie/cowrie.json
Environment=KERN_LOG=/var/log/kern.log
Environment=HTTP_LOG=/var/log/nginx/access.log
Environment=MODEL_PATH=${AGENT_DIR}/gcn_autoencoder.pth
Environment=SCALER_PATH=${AGENT_DIR}/scaler.pkl
Environment=ENCODER_PATH=${AGENT_DIR}/encoders.pkl
Environment=WS_PORT=8765
Environment=HTTP_PORT=8080
Environment=PATH=/home/ec2-user/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/bin/python3 ${AGENT_DIR}/detection_agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

sudo systemctl daemon-reload
sudo systemctl enable probe-detector
sudo fuser -k 8765/tcp 2>/dev/null || true
sudo fuser -k 8080/tcp 2>/dev/null || true
sleep 1
sudo systemctl start probe-detector
sleep 4
sudo systemctl is-active probe-detector --quiet \
    && echo "[OK] probe-detector running" \
    || (echo "[!] probe-detector failed:" && sudo journalctl -u probe-detector -n 15 --no-pager)

# ── Final verify ─────────────────────────────────────────────
echo ""
echo "======================================================="
echo " SETUP COMPLETE — $AWS_IP"
echo "======================================================="
echo -n "  nginx:           "; sudo systemctl is-active nginx
echo -n "  postfix (2525):  "; sudo systemctl is-active postfix
echo -n "  Cowrie SSH 2222: "; sudo ss -tlnp | grep -c 2222 | tr -d '\n'; echo " ok"
echo -n "  Cowrie Tel 2223: "; sudo ss -tlnp | grep -c 2223 | tr -d '\n'; echo " ok"
echo -n "  probe-detector:  "; sudo systemctl is-active probe-detector
echo -n "  kern.log perms:  "; ls -la /var/log/kern.log | awk '{print $1, $3, $4}'
echo ""
echo " Security Group — open these ports:"
echo "   22  80  2222  2223  2525  8765  8080"
echo ""
echo " Every reboot run:  bash ~/BGBZDADS/start.sh"
echo "======================================================="
