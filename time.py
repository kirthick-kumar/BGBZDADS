import subprocess
import time
import re
from collections import defaultdict, deque
import os

AWS_IP = "13.204.83.147"
AWS_PRIVATE_IP = "172.31.8.167"
THRESHOLD_CONN_PER_SEC = 10
WINDOW_SEC = 3

connections = defaultdict(deque)
print("✅ detection started")

cmd = [
    "ssh",
    "-tt",
    "-i", "probe_victim.pem",
    f"ec2-user@{AWS_IP}",
    "sudo /usr/sbin/tcpdump -i enX0 -nn tcp"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

print("🔌 SSH connected, sniffing live traffic...")

def block_ip(attacker_ip):
    print(f"🔒 Blocking {attacker_ip} on AWS...")
    os.system(
        f"ssh -i probe_victim.pem ec2-user@{AWS_IP} sudo iptables -A INPUT -s {attacker_ip} -j DROP"
    )

for line in proc.stdout:
    print("RAW:", line.strip())

    m = re.search(rf"IP\s+([\d.]+)\.\d+\s+>\s+{AWS_PRIVATE_IP}\.(\d+)", line)
    if not m:
        continue

    src_ip, dport = m.group(1), int(m.group(2))
    now = time.time()

    q = connections[src_ip]
    q.append(now)

    while q and now - q[0] > WINDOW_SEC:
        q.popleft()

    rate = len(q) / WINDOW_SEC

    print(f"📡 {src_ip} -> port {dport} | rate={rate:.1f}/s")

    if rate > THRESHOLD_CONN_PER_SEC:
        print(f"🚨 PROBE DETECTED from {src_ip}")
        block_ip(src_ip)
        break
