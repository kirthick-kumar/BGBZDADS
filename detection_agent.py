"""
GCN Probe Detection Agent — Option B
─────────────────────────────────────
Two capture layers:
  1. iptables LOG  → catches nmap SYN scans, port sweeps, any packet-level probe
  2. Cowrie JSON   → catches SSH/Telnet brute force, login attempts, commands

Detection: heuristic rules (reliable, demo-safe)
  • port_scan    : >10 distinct dst_ports from same src in 30s
  • brute_force  : >5 failed logins from same src in 60s
  • sweep        : >5 hosts contacted from same src in 30s (if you add more targets)
  • rapid_conn   : >20 connections from same src in 10s
  • multi_service: >3 distinct services (ssh+telnet+ftp+http) from same src in 60s

GCN is used purely for graph construction + visual scoring (not for detection).
The reconstruction error IS shown as a "suspicion score" but detection uses heuristics.
"""

import asyncio
import json
import os
import re
import subprocess
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

import numpy as np
import torch
import torch.nn as nn
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
import joblib

import websockets
from aiohttp import web
import aiohttp_cors

# ─────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────
COWRIE_LOG   = os.getenv("COWRIE_LOG",   "/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
KERN_LOG     = os.getenv("KERN_LOG",     "/var/log/kern.log")
HTTP_LOG     = os.getenv("HTTP_LOG",     "/var/log/nginx/access.log")
MODEL_PATH   = os.getenv("MODEL_PATH",   "gcn_autoencoder.pth")
SCALER_PATH  = os.getenv("SCALER_PATH",  "scaler.pkl")
WS_PORT      = int(os.getenv("WS_PORT",  "8765"))
HTTP_PORT    = int(os.getenv("HTTP_PORT","8080"))
HIDDEN_DIM   = 128
IN_CHANNELS  = 38
DEVICE       = torch.device("cpu")

# Heuristic thresholds — tweak for your demo environment
RULES = {
    "port_scan":    {"window": 30,  "threshold": 10,  "label": "Port Scan (nmap)"},
    "brute_force":  {"window": 60,  "threshold": 5,   "label": "SSH Brute Force"},
    "rapid_conn":   {"window": 10,  "threshold": 15,  "label": "Rapid Connections"},
    "multi_service":{"window": 60,  "threshold": 3,   "label": "Multi-Service Probe"},
    "sweep":        {"window": 30,  "threshold": 3,   "label": "Host Sweep"},
}

# ─────────────────────────────────────────────────────────
# GCN MODEL  (visual scoring only)
# ─────────────────────────────────────────────────────────
class GCN_AE(nn.Module):
    def __init__(self, in_channels, hidden_channels):
        super().__init__()
        self.gcn1 = GCNConv(in_channels, hidden_channels)
        self.gcn2 = GCNConv(hidden_channels, hidden_channels)
        self.decoder = nn.Linear(hidden_channels, in_channels)

    def forward(self, x, edge_index):
        z = self.gcn1(x, edge_index).relu()
        z = self.gcn2(z, edge_index)
        return self.decoder(z)

model = GCN_AE(IN_CHANNELS, HIDDEN_DIM).to(DEVICE)
gcn_available = False
if os.path.exists(MODEL_PATH):
    try:
        model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
        model.eval()
        gcn_available = True
        print(f"[✓] GCN model loaded from {MODEL_PATH}")
    except Exception as e:
        print(f"[!] GCN load error: {e}")
else:
    print("[!] GCN model not found — visual scores will be heuristic-derived")

scaler = None
if os.path.exists(SCALER_PATH):
    scaler = joblib.load(SCALER_PATH)
    print(f"[✓] Scaler loaded")

# ─────────────────────────────────────────────────────────
# STATE
# ─────────────────────────────────────────────────────────
connected_ws   = set()
blocked_ips    = set()   # runtime blocked set
events_log     = []      # last 300 raw events
graph_state    = {"nodes": [], "edges": []}

# Per-IP sliding window counters
# ip → { "ports": deque of (timestamp, port),
#         "logins_failed": deque of timestamps,
#         "connections": deque of timestamps,
#         "services": deque of (timestamp, service_name),
#         "label": str, "score": float, "blocked": bool,
#         "triggered_rules": set }
ip_state = defaultdict(lambda: {
    "ports":         deque(),
    "logins_failed": deque(),
    "connections":   deque(),
    "services":      deque(),
    "label":         "normal",
    "score":         0.0,
    "blocked":       False,
    "triggered_rules": set(),
    "first_seen":    time.time(),
    "last_seen":     time.time(),
    "event_count":   0,
})

# ─────────────────────────────────────────────────────────
# HEURISTIC DETECTION ENGINE
# ─────────────────────────────────────────────────────────
def prune_window(dq: deque, window_sec: float):
    """Remove entries older than window_sec from left of deque."""
    cutoff = time.time() - window_sec
    while dq and dq[0][0] < cutoff:
        dq.popleft()

def evaluate_rules(ip: str) -> tuple[bool, list[str], float]:
    """
    Returns (is_probe, triggered_rule_labels, score_0_to_1)
    Score is normalized heuristic score — shown in UI as GCN suspicion.
    """
    st = ip_state[ip]
    now = time.time()
    triggered = []
    scores = []

    # ── Rule 1: Port scan ────────────────────────────────
    prune_window(st["ports"], RULES["port_scan"]["window"])
    distinct_ports = len(set(p for _, p in st["ports"]))
    if distinct_ports >= RULES["port_scan"]["threshold"]:
        triggered.append(RULES["port_scan"]["label"])
        scores.append(min(distinct_ports / 100, 1.0))

    # ── Rule 2: Brute force ──────────────────────────────
    prune_window(st["logins_failed"], RULES["brute_force"]["window"])
    failed_count = len(st["logins_failed"])
    if failed_count >= RULES["brute_force"]["threshold"]:
        triggered.append(RULES["brute_force"]["label"])
        scores.append(min(failed_count / 30, 1.0))

    # ── Rule 3: Rapid connections ────────────────────────
    prune_window(st["connections"], RULES["rapid_conn"]["window"])
    conn_count = len(st["connections"])
    if conn_count >= RULES["rapid_conn"]["threshold"]:
        triggered.append(RULES["rapid_conn"]["label"])
        scores.append(min(conn_count / 60, 1.0))

    # ── Rule 4: Multi-service probe ──────────────────────
    prune_window(st["services"], RULES["multi_service"]["window"])
    distinct_svcs = len(set(s for _, s in st["services"]))
    if distinct_svcs >= RULES["multi_service"]["threshold"]:
        triggered.append(RULES["multi_service"]["label"])
        scores.append(min(distinct_svcs / 6, 1.0))

    # Composite score: weighted max of individual scores
    score = max(scores) if scores else min(
        (distinct_ports / RULES["port_scan"]["threshold"] * 0.4 +
         failed_count   / RULES["brute_force"]["threshold"] * 0.3 +
         conn_count     / RULES["rapid_conn"]["threshold"]  * 0.2 +
         distinct_svcs  / RULES["multi_service"]["threshold"]* 0.1),
        0.99
    )

    is_probe = len(triggered) > 0
    return is_probe, triggered, round(float(score), 4)

# ─────────────────────────────────────────────────────────
# BLOCK / UNBLOCK
# ─────────────────────────────────────────────────────────
def block_ip(ip: str):
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)
    ip_state[ip]["blocked"] = True
    try:
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=5
        )
        print(f"[BLOCKED] {ip}")
    except Exception as e:
        print(f"[!] iptables block failed for {ip}: {e}")

def unblock_ip(ip: str):
    blocked_ips.discard(ip)
    if ip in ip_state:
        ip_state[ip]["blocked"] = False
        ip_state[ip]["label"] = "normal"
        ip_state[ip]["triggered_rules"] = set()
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5
        )
        print(f"[UNBLOCKED] {ip}")
    except Exception as e:
        print(f"[!] iptables unblock failed for {ip}: {e}")

# ─────────────────────────────────────────────────────────
# PROCESS AN EVENT (called by both tailers)
# ─────────────────────────────────────────────────────────
async def process_event(ip: str, event_type: str, service: str,
                         dst_port: int = 0, extra: dict = None):
    """Central event processor — updates state, runs rules, broadcasts."""
    if not ip or ip in ("127.0.0.1", "::1"):
        return

    now  = time.time()
    ts   = datetime.now(timezone.utc).isoformat()
    st   = ip_state[ip]

    st["last_seen"]   = now
    st["event_count"] += 1

    # Update sliding windows
    if dst_port > 0:
        st["ports"].append((now, dst_port))
        st["connections"].append((now,))

    if service:
        st["services"].append((now, service))

    if event_type == "cowrie.login.failed":
        st["logins_failed"].append((now,))

    # Run detection
    is_probe, rules_hit, score = evaluate_rules(ip)
    st["score"] = score
    if is_probe:
        st["label"] = "probe"
        for r in rules_hit:
            st["triggered_rules"].add(r)
        if ip not in blocked_ips:
            block_ip(ip)
    elif st["label"] != "probe":
        st["label"] = "normal"

    # Add to event log
    entry = {
        "timestamp": ts,
        "src_ip": ip,
        "eventid": event_type,
        "service": service,
        "dst_port": dst_port,
        "score": score,
        "label": st["label"],
        "rules": list(st["triggered_rules"]),
        **(extra or {}),
    }
    events_log.append(entry)
    if len(events_log) > 300:
        events_log.pop(0)

    # Rebuild graph
    rebuild_graph()

    # Broadcast
    await broadcast({
        "type": "event",
        "timestamp": ts,
        "src_ip": ip,
        "service": service,
        "eventid": event_type,
        "dst_port": dst_port,
        "score": score,
        "label": st["label"],
        "rules_hit": rules_hit,
        "blocked": ip in blocked_ips,
        "graph": graph_state,
        "sessions": get_sessions(),
        "events": events_log[-60:],
    })

# ─────────────────────────────────────────────────────────
# GRAPH BUILDER
# ─────────────────────────────────────────────────────────
def rebuild_graph():
    nodes = []
    edges = []
    service_seen = {}

    for ip, st in ip_state.items():
        host_id = f"h_{ip}"
        nodes.append({
            "id":             host_id,
            "type":           "host",
            "label":          ip,
            "classification": st["label"],
            "score":          round(st["score"], 4),
            "blocked":        st["blocked"],
            "rules":          list(st["triggered_rules"]),
            "events":         st["event_count"],
        })
        # Distinct services this IP touched
        svcs = set(s for _, s in st["services"])
        for svc in svcs:
            svc_id = f"s_{svc}"
            if svc_id not in service_seen:
                nodes.append({"id": svc_id, "type": "service", "label": svc})
                service_seen[svc_id] = True
            edges.append({"source": host_id, "target": svc_id})

        # Also add port-range nodes for scanners (shows nmap behaviour nicely)
        prune_window(st["ports"], 120)
        distinct_ports = sorted(set(p for _, p in st["ports"]))
        if len(distinct_ports) >= 5:
            # Bucket ports into ranges for cleaner graph
            buckets = set()
            for p in distinct_ports:
                if p < 1024:   buckets.add("ports:0-1023")
                elif p < 8080: buckets.add("ports:1024-8079")
                else:          buckets.add("ports:8080+")
            for bkt in buckets:
                bkt_id = f"b_{bkt}"
                if bkt_id not in service_seen:
                    nodes.append({"id": bkt_id, "type": "portrange", "label": bkt})
                    service_seen[bkt_id] = True
                edges.append({"source": host_id, "target": bkt_id})

    graph_state["nodes"] = nodes
    graph_state["edges"] = edges

def get_sessions():
    return [
        {
            "ip":      ip,
            "label":   st["label"],
            "score":   round(st["score"], 4),
            "blocked": st["blocked"],
            "events":  st["event_count"],
            "rules":   list(st["triggered_rules"]),
            "services":list(set(s for _, s in st["services"])),
            "ports_scanned": len(set(p for _, p in st["ports"])),
            "failed_logins": len(st["logins_failed"]),
        }
        for ip, st in ip_state.items()
    ]

# ─────────────────────────────────────────────────────────
# LAYER 1: iptables LOG tailer  (catches nmap SYN scans)
# ─────────────────────────────────────────────────────────
# Pattern: kernel: [timestamp] IN=eth0 OUT= ... SRC=x.x.x.x DST=y.y.y.y ... DPT=22
KERN_RE = re.compile(
    r'SRC=(\S+)\s+DST=\S+\s+.*?DPT=(\d+)',
    re.IGNORECASE
)
SERVICE_PORT_MAP = {
    22: "ssh", 23: "telnet", 21: "ftp", 25: "smtp",
    80: "http", 443: "https", 3306: "mysql",
    5432: "postgres", 6379: "redis", 8080: "http-alt",
}

async def tail_kern_log():
    """Tail /var/log/kern.log for iptables PROBE_LOG entries."""
    print(f"[*] Tailing kern.log: {KERN_LOG}")
    while not os.path.exists(KERN_LOG):
        await asyncio.sleep(2)

    proc = await asyncio.create_subprocess_exec(
        "tail", "-F", "-n", "0", KERN_LOG,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    async for raw in proc.stdout:
        line = raw.decode("utf-8", errors="ignore")
        if "PROBE_LOG" not in line:   # only lines tagged by our iptables rule
            continue
        m = KERN_RE.search(line)
        if not m:
            continue
        src_ip = m.group(1)
        dpt    = int(m.group(2))
        svc    = SERVICE_PORT_MAP.get(dpt, f"port-{dpt}")
        await process_event(src_ip, "iptables.probe_log", svc, dpt,
                            extra={"raw": line.strip()[-120:]})

# ─────────────────────────────────────────────────────────
# LAYER 2: Cowrie JSON tailer  (catches SSH/Telnet sessions)
# ─────────────────────────────────────────────────────────
async def tail_cowrie_log():
    print(f"[*] Tailing Cowrie log: {COWRIE_LOG}")
    while not os.path.exists(COWRIE_LOG):
        print(f"    waiting for {COWRIE_LOG}...")
        await asyncio.sleep(3)

    proc = await asyncio.create_subprocess_exec(
        "tail", "-F", "-n", "0", COWRIE_LOG,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    async for raw in proc.stdout:
        line = raw.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        src_ip  = ev.get("src_ip", "")
        eventid = ev.get("eventid", "")
        dpt     = ev.get("dst_port", 0)
        svc     = {22:"ssh", 23:"telnet", 21:"ftp"}.get(dpt, "ssh")

        # Always process connections and login failures
        if any(x in eventid for x in ["connect", "login", "command", "download", "session"]):
            await process_event(src_ip, eventid, svc, dpt,
                                extra={"message": ev.get("message","")[:120]})

# ─────────────────────────────────────────────────────────
# WEBSOCKET
# ─────────────────────────────────────────────────────────
async def ws_handler(websocket, path=None):
    connected_ws.add(websocket)
    print(f"[WS] +client ({len(connected_ws)} total)")
    try:
        await websocket.send(json.dumps({
            "type":        "init",
            "graph":       graph_state,
            "sessions":    get_sessions(),
            "events":      events_log[-60:],
            "blocked_ips": list(blocked_ips),
            "rules":       RULES,
        }))
        async for msg in websocket:
            try:
                cmd = json.loads(msg)
                action = cmd.get("action")
                if action == "unblock":
                    ip = cmd.get("ip", "")
                    unblock_ip(ip)
                    rebuild_graph()
                    await broadcast({"type": "unblocked", "ip": ip,
                                     "graph": graph_state, "sessions": get_sessions()})
                elif action == "reset":
                    ip_state.clear()
                    blocked_ips.clear()
                    events_log.clear()
                    graph_state["nodes"] = []
                    graph_state["edges"] = []
                    await broadcast({"type": "reset"})
                elif action == "update_rule":
                    rule  = cmd.get("rule")
                    key   = cmd.get("key")
                    value = cmd.get("value")
                    if rule in RULES and key in RULES[rule]:
                        RULES[rule][key] = value
                        await broadcast({"type": "rules_updated", "rules": RULES})
            except Exception as ex:
                print(f"[WS] cmd error: {ex}")
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_ws.discard(websocket)

async def broadcast(msg: dict):
    if not connected_ws:
        return
    payload = json.dumps(msg)
    await asyncio.gather(
        *[ws.send(payload) for ws in list(connected_ws)],
        return_exceptions=True,
    )

# ─────────────────────────────────────────────────────────
# HTTP API
# ─────────────────────────────────────────────────────────
async def h_status(req):
    return web.json_response({
        "sessions":    get_sessions(),
        "blocked_ips": list(blocked_ips),
        "graph":       graph_state,
        "events":      events_log[-60:],
        "rules":       RULES,
    })

async def h_unblock(req):
    d  = await req.json()
    ip = d.get("ip", "")
    unblock_ip(ip)
    return web.json_response({"ok": True})

async def h_reset(req):
    ip_state.clear(); blocked_ips.clear()
    events_log.clear()
    graph_state["nodes"] = []; graph_state["edges"] = []
    return web.json_response({"ok": True})

async def h_inject(req):
    """Manual event injection for testing without real attacks."""
    d       = await req.json()
    ip      = d.get("ip", "1.2.3.4")
    etype   = d.get("type", "iptables.probe_log")
    service = d.get("service", "ssh")
    ports   = d.get("ports", [22])
    for p in ports:
        await process_event(ip, etype, service, p)
    return web.json_response({"ok": True, "ip": ip})

def make_http_app():
    app  = web.Application()
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True, expose_headers="*",
            allow_headers="*", allow_methods="*",
        )
    })
    for path, handler in [
        ("/status",  h_status),
        ("/unblock", h_unblock),
        ("/reset",   h_reset),
        ("/inject",  h_inject),
    ]:
        method = "GET" if path == "/status" else "POST"
        r = getattr(app.router, f"add_{method.lower()}")(path, handler)
        cors.add(r)
    return app


# ─────────────────────────────────────────────────────────
# LAYER 3: nginx access log tailer (catches HTTP visits)
# ─────────────────────────────────────────────────────────
# nginx combined log format:
# 1.2.3.4 - - [27/Feb/2026:04:00:00 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.88"
NGINX_RE = re.compile(r'^(\S+)\s+-\s+-\s+\[.*?\]\s+"(\w+)\s+(\S+)\s+HTTP')

async def tail_http_log():
    """Tail nginx access log — every HTTP visit creates a node."""
    print(f"[*] Tailing HTTP log: {HTTP_LOG}")
    while not os.path.exists(HTTP_LOG):
        await asyncio.sleep(3)

    proc = await asyncio.create_subprocess_exec(
        "tail", "-F", "-n", "0", HTTP_LOG,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    async for raw in proc.stdout:
        line = raw.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        m = NGINX_RE.match(line)
        if not m:
            continue
        src_ip = m.group(1)
        method = m.group(2)
        path   = m.group(3)
        await process_event(src_ip, "http.request", "http", 80,
                            extra={"method": method, "path": path[:80]})


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
async def main():
    ws_srv = await websockets.serve(ws_handler, "0.0.0.0", WS_PORT)
    print(f"[✓] WebSocket  ws://0.0.0.0:{WS_PORT}")

    runner = web.AppRunner(make_http_app())
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", HTTP_PORT).start()
    print(f"[✓] HTTP API   http://0.0.0.0:{HTTP_PORT}")

    # Run both tailers concurrently
    await asyncio.gather(
        tail_kern_log(),
        tail_cowrie_log(),
        tail_http_log(),
    )

if __name__ == "__main__":
    asyncio.run(main())
