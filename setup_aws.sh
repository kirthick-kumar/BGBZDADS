#!/bin/bash
# ============================================================
# AWS Full Setup — Amazon Linux 2023
# Run from the folder containing all project files:
#   bash setup_aws.sh
#
# Port layout:
#   22   = real SSH (UNCHANGED)
#   25   = Postfix SMTP (real, for normal mail simulation)
#   2222 = Cowrie SSH honeypot
#   2223 = Cowrie Telnet honeypot
#   80   = nginx HTTP
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
echo "[1/6] Installing Cowrie..."
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

# Write clean config using configparser — avoids ALL duplicate errors
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
echo "[2/6] Starting Cowrie..."
cd ~/cowrie
source cowrie-env/bin/activate
cowrie-env/bin/cowrie stop 2>/dev/null || true
sleep 2
cowrie-env/bin/cowrie start
sleep 3
cowrie-env/bin/cowrie status
deactivate
cd ~
echo -n "    Listening on: "
sudo ss -tlnp | grep -E "2222|2223" | awk '{print $4}' | tr '\n' ' '
echo ""
echo "[OK] Cowrie started"

# ── 3. nginx ─────────────────────────────────────────────────
echo ""
echo "[3/6] Starting nginx..."
sudo systemctl start nginx
sudo systemctl enable nginx

# Filter AWS health checks (15.177.x.x) from nginx access log
sudo tee /etc/nginx/conf.d/filter_healthchecks.conf > /dev/null << 'EOF'
geo $loggable {
    default       1;
    15.177.0.0/16 0;
}
access_log /var/log/nginx/access.log combined if=$loggable;
EOF
# Deploy login page as nginx default
sudo mkdir -p /usr/share/nginx/html
sudo tee /usr/share/nginx/html/index.html > /dev/null << 'LOGINEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>SecureNet Portal — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#0a0e1a;
  background-image:radial-gradient(ellipse at 20% 50%,rgba(41,121,255,.08) 0%,transparent 60%),
                   radial-gradient(ellipse at 80% 20%,rgba(0,229,255,.05) 0%,transparent 50%);
  font-family:'\''Segoe UI'\'',system-ui,sans-serif;
}
body::before{
  content:'\'''\'';position:fixed;inset:0;pointer-events:none;
  background-image:linear-gradient(rgba(0,229,255,.015) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(0,229,255,.015) 1px,transparent 1px);
  background-size:40px 40px;
}
.card{
  width:420px;padding:48px 40px;
  background:rgba(6,13,26,.95);
  border:1px solid rgba(41,121,255,.2);
  border-radius:8px;
  box-shadow:0 0 60px rgba(0,0,0,.6),0 0 0 1px rgba(0,229,255,.05);
  position:relative;
}
.card::before{
  content:'\'''\'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,#2979ff,#00e5ff,transparent);
  border-radius:8px 8px 0 0;
}
.brand{text-align:center;margin-bottom:36px;}
.brand-icon{
  width:52px;height:52px;margin:0 auto 14px;
  background:rgba(41,121,255,.1);border:1px solid rgba(41,121,255,.3);
  border-radius:12px;display:flex;align-items:center;justify-content:center;
  font-size:24px;
}
.brand-name{
  font-size:20px;font-weight:700;
  background:linear-gradient(135deg,#2979ff,#00e5ff);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  letter-spacing:.5px;
}
.brand-sub{font-size:12px;color:#3a5575;margin-top:4px;letter-spacing:1.5px;text-transform:uppercase;}
h2{font-size:15px;color:#b0cce0;font-weight:500;margin-bottom:24px;text-align:center;}
.field{margin-bottom:18px;}
label{display:block;font-size:11px;color:#3a5575;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px;}
input{
  width:100%;padding:11px 14px;
  background:rgba(10,22,40,.8);
  border:1px solid rgba(23,45,80,.8);
  border-radius:5px;color:#b0cce0;font-size:14px;
  transition:border-color .2s,box-shadow .2s;outline:none;
}
input:focus{border-color:rgba(41,121,255,.5);box-shadow:0 0 0 3px rgba(41,121,255,.08);}
input::placeholder{color:#2a4060;}
.forgot{text-align:right;margin-top:6px;}
.forgot a{font-size:11px;color:#2979ff;text-decoration:none;opacity:.7;}
.forgot a:hover{opacity:1;}
.btn-login{
  width:100%;padding:12px;margin-top:8px;
  background:linear-gradient(135deg,#1a50c8,#2979ff);
  border:none;border-radius:5px;
  color:#fff;font-size:14px;font-weight:600;letter-spacing:.5px;
  cursor:pointer;transition:all .2s;
}
.btn-login:hover{background:linear-gradient(135deg,#2060d8,#3989ff);box-shadow:0 4px 20px rgba(41,121,255,.3);}
.btn-login:active{transform:scale(.98);}
.divider{display:flex;align-items:center;gap:12px;margin:20px 0;color:#2a4060;font-size:11px;}
.divider::before,.divider::after{content:'\'''\'';flex:1;height:1px;background:#0e2040;}
.btn-guest{
  width:100%;padding:10px;
  background:transparent;border:1px solid #172d50;
  border-radius:5px;color:#3a5575;font-size:13px;
  cursor:pointer;transition:all .2s;
}
.btn-guest:hover{border-color:#2979ff;color:#2979ff;}
.footer{text-align:center;margin-top:28px;font-size:11px;color:#2a4060;}
.footer span{color:#1a3a6a;}
.status-bar{
  display:flex;align-items:center;justify-content:center;gap:6px;
  margin-bottom:20px;padding:6px 12px;
  background:rgba(0,230,118,.04);border:1px solid rgba(0,230,118,.1);
  border-radius:4px;font-size:11px;color:#3a7a55;
}
.status-dot{width:6px;height:6px;border-radius:50%;background:#00e676;box-shadow:0 0 6px #00e676;animation:blink 2s infinite;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:.3;}}
.error{
  display:none;padding:10px 14px;margin-bottom:16px;
  background:rgba(255,23,68,.06);border:1px solid rgba(255,23,68,.2);
  border-radius:4px;font-size:12px;color:#ff6b6b;
}
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="brand-icon">🔒</div>
    <div class="brand-name">SecureNet</div>
    <div class="brand-sub">Enterprise Portal</div>
  </div>

  <div class="status-bar">
    <div class="status-dot"></div>
    <span>System operational — All services normal</span>
  </div>

  <h2>Sign in to your account</h2>

  <div class="error" id="err">Invalid username or password. Please try again.</div>

  <form onsubmit="doLogin(event)">
    <div class="field">
      <label>Username</label>
      <input type="text" id="username" placeholder="Enter username" autocomplete="username"/>
    </div>
    <div class="field">
      <label>Password</label>
      <input type="password" id="password" placeholder="Enter password" autocomplete="current-password"/>
      <div class="forgot"><a href="#">Forgot password?</a></div>
    </div>
    <button class="btn-login" type="submit">Sign In</button>
  </form>

  <div class="divider">or</div>
  <button class="btn-guest" onclick="guestLogin()">Continue as Guest</button>

  <div class="footer">
    Protected by <span>SecureNet Shield v2.4</span> &nbsp;·&nbsp;
    <span>TLS 1.3</span> &nbsp;·&nbsp;
    <span>SOC 2 Type II</span>
  </div>
</div>

<script>
function doLogin(e){
  e.preventDefault();
  var u=document.getElementById('\''username'\'').value;
  var p=document.getElementById('\''password'\'').value;
  if(!u||!p){ document.getElementById('\''err'\'').style.display='\''block'\''; return; }
  // Always reject for demo — shows failed login
  document.getElementById('\''err'\'').style.display='\''block'\'';
}
function guestLogin(){
  window.location.href='\''/guest'\'';
}
</script>
</body>
</html>

LOGINEOF

# Handle POST login attempts — always return 401 (for demo)
sudo tee /etc/nginx/conf.d/login.conf > /dev/null << 'NGEOF'
server {
    listen 80 default_server;
    root /usr/share/nginx/html;
    index index.html;

    location = / {
        try_files /index.html =404;
    }

    location = /home {
        try_files /home.html =404;
    }

    location = /guest {
        return 200 '<html><body style="background:#f2efe9;color:#1a1208;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;font-size:14px">Guest access is disabled. Please login.</body></html>';
        add_header Content-Type text/html;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
NGEOF

sudo nginx -t 2>/dev/null && sudo systemctl reload nginx

# Copy home.html
[ -f "$SCRIPT_DIR/home.html" ] && sudo cp "$SCRIPT_DIR/home.html" /usr/share/nginx/html/home.html

# Fix nginx log permissions so ec2-user (agent) can read them
sudo usermod -aG nginx ec2-user
sudo chmod 755 /var/log/nginx
sudo chmod 644 /var/log/nginx/access.log 2>/dev/null || true
echo "[OK] nginx on port 80 with login page"

# ── 4. Postfix SMTP ──────────────────────────────────────────
echo ""
echo "[4/7] Installing Postfix SMTP on port 25..."
sudo yum install -y postfix 2>/dev/null || true

# Configure as a null-relay (accepts mail, logs it, doesn't deliver externally)
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

# AWS blocks port 25 at network level — use port 2525 instead
sudo sed -i 's/^smtp      inet/# smtp      inet/' /etc/postfix/master.cf
# Remove any existing 2525 entry to avoid duplicates
sudo sed -i '/^2525 /d' /etc/postfix/master.cf
echo "2525      inet  n       -       n       -       -       smtpd" | sudo tee -a /etc/postfix/master.cf

sudo systemctl restart postfix
sudo systemctl enable postfix
sleep 1
echo -n "    Postfix SMTP: "; sudo systemctl is-active postfix
echo -n "    Port 2525:    "; sudo ss -tlnp | grep 2525 | grep -c master || echo "0"
echo "[OK] SMTP on port 2525 (AWS blocks port 25)"

# ── 5. iptables ──────────────────────────────────────────────
echo ""
echo "[5/7] Configuring iptables..."
sudo bash "$SCRIPT_DIR/setup_iptables.sh"
for port in 22 80 2222 2223 2525 8765 8080; do
    sudo iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || true
done
echo "[OK] iptables done"

# ── 6. Detection agent ───────────────────────────────────────
echo ""
echo "[6/7] Deploying detection agent..."
sudo mkdir -p $AGENT_DIR
sudo chown ec2-user:ec2-user $AGENT_DIR
cp "$SCRIPT_DIR/detection_agent.py" $AGENT_DIR/

# Copy model files if present
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
Environment=PYTHONPATH=/home/ec2-user/.local/lib/python3.9/site-packages
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
sleep 3
sudo systemctl is-active probe-detector --quiet \
    && echo "[OK] probe-detector running" \
    || (echo "[!] probe-detector failed:" && sudo journalctl -u probe-detector -n 15 --no-pager)

# ── 7. Verify ────────────────────────────────────────────────
echo ""
echo "[7/7] Final check..."
echo -n "  nginx:          "; sudo systemctl is-active nginx
echo -n "  probe-detector: "; sudo systemctl is-active probe-detector
echo -n "  Cowrie SSH:     "; sudo ss -tlnp | grep -c 2222 || echo 0
echo -n "  Cowrie Telnet:  "; sudo ss -tlnp | grep -c 2223 || echo 0
echo -n "  Postfix SMTP:   "; sudo systemctl is-active postfix
echo -n "  Port 2525:      "; sudo ss -tlnp | grep 2525 | grep -c master || echo 0
sleep 2
echo -n "  HTTP API:       "; curl -s http://localhost:8080/status \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK -',len(d['sessions']),'sessions')" \
    2>/dev/null || echo "not ready yet"

echo ""
echo "======================================================="
echo " DONE — $AWS_IP"
echo " Dashboard: python3 -m http.server 3000"
echo "   open: http://localhost:3000/dashboard.html?ip=${AWS_IP}"
echo " Security Group ports: 22 80 2222 2223 2525 8765 8080"
echo "======================================================="
