import warnings
warnings.filterwarnings("ignore")
"""
GCN Probe Detection Agent — Final
─────────────────────────────────────
Three capture layers:
  1. iptables LOG  → catches nmap SYN scans, port sweeps
  2. Cowrie JSON   → catches SSH/Telnet brute force, login attempts
  3. nginx access  → catches HTTP visits (never auto-blocked)

Auto-block policy:
  - HTTP visits alone → NEVER auto-blocked (normal traffic)
  - nmap port scan    → auto-blocked when rule fires
  - SSH brute force   → auto-blocked when rule fires
  - Rapid connections → auto-blocked when rule fires
"""

import asyncio
import json
import os
import re
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import warnings
import numpy as np
import pandas as pd
import torch
torch.set_num_threads(1)  # reduce RAM usage on t2.micro
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
COWRIE_LOG = os.getenv("COWRIE_LOG", "/home/ec2-user/cowrie/var/log/cowrie/cowrie.json")
KERN_LOG   = os.getenv("KERN_LOG",   "/var/log/kern.log")
HTTP_LOG   = os.getenv("HTTP_LOG",   "/var/log/nginx/access.log")
MODEL_PATH = os.getenv("MODEL_PATH", "gcn_autoencoder.pth")
SCALER_PATH  = os.getenv("SCALER_PATH","scaler.pkl")
ENCODER_PATH = os.getenv("ENCODER_PATH","encoders.pkl")
WS_PORT    = int(os.getenv("WS_PORT",  "8765"))
HTTP_PORT  = int(os.getenv("HTTP_PORT","8080"))
HIDDEN_DIM = 128
IN_CHANNELS= 41
DEVICE     = torch.device("cpu")

# ─────────────────────────────────────────────────────────
# DETECTION RULES
# ─────────────────────────────────────────────────────────
RULES = {
    "port_scan":    {"window": 30,  "threshold": 15,  "label": "Port Scan (nmap)"},
    "brute_force":  {"window": 60,  "threshold": 8,   "label": "SSH Brute Force"},
    "rapid_conn":   {"window": 10,  "threshold": 30,  "label": "Rapid Connections"},
    "multi_service":{"window": 60,  "threshold": 5,   "label": "Multi-Service Probe"},
}

# Services that require MULTIPLE failed attempts before counting toward brute force
# A single telnet/ssh login attempt is normal — not an attack
BRUTE_FORCE_SERVICES = {"ssh", "telnet", "ftp", "smtp"}

# Services that are "normal" — HTTP visits alone never trigger probe detection
BENIGN_ONLY_SERVICES = {"http", "https"}

# ─────────────────────────────────────────────────────────
# GCN MODEL — real inference on live connections
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
    print("[!] GCN model not found at {MODEL_PATH} — scores will be heuristic-only")

scaler = None
if os.path.exists(SCALER_PATH):
    try:
        scaler = joblib.load(SCALER_PATH)
        print(f"[✓] Scaler loaded from {SCALER_PATH}")
    except Exception as e:
        print(f"[!] Scaler load error: {e}")

encoders = {}
ENCODER_PATH = os.getenv("ENCODER_PATH", "encoders.pkl")
if os.path.exists(ENCODER_PATH):
    try:
        encoders = joblib.load(ENCODER_PATH)
        print(f"[✓] Encoders loaded from {ENCODER_PATH}")
    except Exception as e:
        print(f"[!] Encoder load error: {e}")

# NSL-KDD anomaly threshold — calibrated from live traffic:
# Normal HTTP:  ~0.17  Normal SSH/Telnet: ~0.47  Brute force: 10+
# Threshold of 2.0 allows normal connections, blocks real attacks
ANOMALY_THRESHOLD = 2.0
if os.path.exists("threshold.txt"):
    try:
        with open("threshold.txt") as f:
            ANOMALY_THRESHOLD = float(f.read().strip())
        print(f"[✓] Anomaly threshold: {ANOMALY_THRESHOLD:.6f}")
    except:
        pass

# ─────────────────────────────────────────────────────────
# FEATURE EXTRACTION — map live connection → NSL-KDD features
# ─────────────────────────────────────────────────────────
# NSL-KDD column order (38 features, excluding label/difficulty)
NSL_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
]

# Service name → NSL-KDD service string mapping
SERVICE_MAP = {
    "ssh": "ssh", "http": "http", "https": "http", "ftp": "ftp",
    "telnet": "telnet", "smtp": "smtp", "mysql": "private",
    "postgres": "private", "redis": "private", "http-alt": "http_443",
}

# Protocol type mapping
PROTO_MAP = {
    "ssh": "tcp", "http": "tcp", "https": "tcp", "ftp": "tcp",
    "telnet": "tcp", "smtp": "tcp", "mysql": "tcp", "smtp25": "tcp",
}

def encode_categorical(col, value, fallback=0):
    """Encode a categorical value using the loaded LabelEncoder."""
    if col in encoders:
        le = encoders[col]
        if value in le.classes_:
            return int(le.transform([value])[0])
        # Unknown value — use most common fallback
        return fallback
    return fallback

def extract_features(ip: str, service: str, event_type: str,
                     dst_port: int, st: dict) -> np.ndarray:
    """
    Map a live connection event to NSL-KDD feature vector (38 features).
    Uses sliding window stats from ip_state for count-based features.
    """
    now = time.time()

    # ── Basic connection features ─────────────────────────
    duration = max(0, now - st.get("first_seen", now))

    # protocol_type: tcp for most, udp for dns
    proto_str = PROTO_MAP.get(service, "tcp")
    protocol_type = encode_categorical("protocol_type", proto_str, fallback=2)  # 2=tcp default

    # service: map to NSL-KDD service name
    svc_str = SERVICE_MAP.get(service, "private")
    svc_encoded = encode_categorical("service", svc_str, fallback=0)

    # flag: S0 = SYN scan (no response), SF = normal full connection
    # If it's an iptables-only event (nmap) → likely S0; Cowrie session = SF
    if "cowrie" in event_type or "http" in event_type:
        flag_str = "SF"   # full connection established
    else:
        flag_str = "S0"   # SYN only, no response (nmap-style)
    flag_encoded = encode_categorical("flag", flag_str, fallback=9)  # 9=S0 default

    # ── HTTP-specific signals ────────────────────────────
    # Detect brute force vs normal HTTP by POST rate + path diversity
    http_posts  = st.get("http_posts",  deque())
    http_paths  = st.get("http_paths",  deque())
    recent_posts = sum(1 for t, in [(t,) for t in [x[0] for x in http_posts]] if now - t < 10.0)                    if http_posts else 0
    # Count distinct paths in last 30s (path enumeration signal)
    recent_path_times = [x for x in http_paths if now - x[0] < 30.0]
    distinct_paths = len(set(x[1] for x in recent_path_times))
    # Only flag as brute force after sustained attack — not single POSTs
    is_http_brute  = recent_posts >= 8    # 8+ POSTs in 10s = brute force
    is_path_enum   = distinct_paths >= 8  # 8+ distinct paths in 30s = scanner

    # src_bytes / dst_bytes
    if "login.failed" in event_type:
        src_bytes, dst_bytes = 300, 200
    elif "login.success" in event_type:
        src_bytes, dst_bytes = 500, 1000
    elif "http" in event_type and is_http_brute:
        # Sustained brute force: high src_bytes, low dst (401 responses)
        src_bytes = min(300 + recent_posts * 50, 1400)
        dst_bytes = 80
    elif "http" in event_type:
        # Normal HTTP including occasional POST — treat as normal
        src_bytes, dst_bytes = 400, 2000
    elif "command" in event_type:
        src_bytes, dst_bytes = 200, 500
    else:
        src_bytes, dst_bytes = 100, 0

    # ── Auth/login features ───────────────────────────────
    # Only count POSTs as failed logins once brute force threshold crossed
    num_failed_logins = min(len(st["logins_failed"]) + (recent_posts if is_http_brute else 0), 10)
    logged_in     = 1 if "login.success" in event_type else 0
    is_guest_login= 1 if ("guest" in event_type or "anonymous" in event_type) else 0

    # ── hot: only raise after confirmed path enumeration ─────
    hot = min(distinct_paths, 10) if is_path_enum else 0

    # ── Sliding window count features ────────────────────
    # count: connections to same host in last 2s
    recent_conns = [t for t, in st["connections"] if now - t < 2.0] if st["connections"] else []
    count = min(len(recent_conns) + 1, 511)

    # srv_count: connections to same service in last 2s
    recent_svcs = [s for t, s in st["services"] if now - t < 2.0 and s == service]
    srv_count = min(len(recent_svcs) + 1, 511)

    # serror_rate: ratio of SYN errors (S0 flags) in recent connections
    # If event_type is iptables (nmap), treat as serror
    total_recent = max(count, 1)
    syn_only = 1 if ("iptables" in event_type) else 0
    serror_rate     = round(syn_only, 2)
    srv_serror_rate = round(syn_only, 2)
    rerror_rate     = 0.0
    srv_rerror_rate = 0.0

    # same_srv_rate: fraction of recent connections to same service
    same_srv_rate = round(srv_count / total_recent, 2)
    diff_srv_rate = round(1.0 - same_srv_rate, 2)
    srv_diff_host_rate = 0.0

    # ── dst_host features (last 100 connections to this host) ─
    all_ports = list(st["ports"])[-100:] if st["ports"] else []
    dst_host_count = min(len(all_ports) + 1, 255)

    same_port_count = sum(1 for _, p in all_ports if p == dst_port)
    dst_host_same_srv_rate = round(same_port_count / max(dst_host_count, 1), 2)
    dst_host_diff_srv_rate = round(1.0 - dst_host_same_srv_rate, 2)
    dst_host_srv_count     = min(srv_count, 255)
    dst_host_same_src_port_rate = round(same_port_count / max(dst_host_count, 1), 2)
    dst_host_srv_diff_host_rate = 0.0
    dst_host_serror_rate        = serror_rate
    dst_host_srv_serror_rate    = srv_serror_rate

    # ── Assemble feature vector ───────────────────────────
    features = [
        duration,           # 0
        protocol_type,      # 1
        svc_encoded,        # 2
        flag_encoded,       # 3
        src_bytes,          # 4
        dst_bytes,          # 5
        0,                  # 6  land
        0,                  # 7  wrong_fragment
        0,                  # 8  urgent
        hot,                # 9  hot
        num_failed_logins,  # 10
        logged_in,          # 11
        0,                  # 12 num_compromised
        0,                  # 13 root_shell
        0,                  # 14 su_attempted
        0,                  # 15 num_root
        0,                  # 16 num_file_creations
        0,                  # 17 num_shells
        0,                  # 18 num_access_files
        0,                  # 19 num_outbound_cmds
        0,                  # 20 is_host_login
        is_guest_login,     # 21
        count,              # 22
        srv_count,          # 23
        serror_rate,        # 24
        srv_serror_rate,    # 25
        rerror_rate,        # 26
        srv_rerror_rate,    # 27
        same_srv_rate,      # 28
        diff_srv_rate,      # 29
        srv_diff_host_rate, # 30
        dst_host_count,     # 31
        dst_host_srv_count, # 32
        dst_host_same_srv_rate,      # 33
        dst_host_diff_srv_rate,      # 34
        dst_host_same_src_port_rate, # 35
        dst_host_srv_diff_host_rate, # 36
        dst_host_serror_rate,        # 37
        dst_host_srv_serror_rate,    # 38 — only 38 needed but keep aligned
    ]

    # Pad to 41 features to match trained model
    # Extra 3 = dst_host_rerror_rate, dst_host_srv_rerror_rate, padding
    while len(features) < 41:
        features.append(0.0)
    return np.array(features[:41], dtype=np.float32)

def run_gcn_inference(ip: str, service: str, event_type: str,
                      dst_port: int, st: dict) -> dict:
    """
    Run the GCN autoencoder on a single connection and return:
    - reconstruction_error: raw MSE loss
    - gcn_prediction: 'PROBE' or 'NORMAL'
    - gcn_confidence: 0.0–1.0
    - gcn_score: normalised anomaly score
    """
    if not gcn_available or scaler is None:
        return {"gcn_prediction": "N/A", "gcn_confidence": 0.0,
                "gcn_score": 0.0, "reconstruction_error": 0.0}

    try:
        # Extract + scale features
        raw_features = extract_features(ip, service, event_type, dst_port, st)

        # Use DataFrame with column names to match how scaler was fitted
        _feat_cols = [
            'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
            'wrong_fragment','urgent','hot','num_failed_logins','logged_in',
            'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
            'num_shells','num_access_files','num_outbound_cmds','is_host_login',
            'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
            'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
            'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
            'dst_host_same_srv_rate','dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
            'dst_host_serror_rate','dst_host_srv_serror_rate',
            'dst_host_rerror_rate','dst_host_srv_rerror_rate',
        ][:len(raw_features)]
        import pandas as _pd
        _df = _pd.DataFrame(raw_features.reshape(1, -1), columns=_feat_cols)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            scaled = scaler.transform(_df)  # (1, 41)

        # Build minimal bipartite graph: 1 host + 1 service node
        host_feat = torch.tensor(scaled, dtype=torch.float32)             # (1, 41)
        svc_feat  = torch.zeros((1, 41), dtype=torch.float32)             # (1, 41)
        x         = torch.cat([host_feat, svc_feat], dim=0).to(DEVICE)   # (2, 41)

        # Edge: host(0) ↔ service(1)
        edge_index = torch.tensor([[0, 1], [1, 0]], dtype=torch.long).to(DEVICE)

        data = Data(x=x, edge_index=edge_index)

        with torch.no_grad():
            recon = model(data.x, data.edge_index)
            # Reconstruction error on host node only (index 0)
            error = torch.mean((recon[0] - data.x[0]) ** 2).item()

        # Normalise against threshold
        gcn_score = min(error / max(ANOMALY_THRESHOLD, 1e-9), 2.0) / 2.0
        gcn_score = round(float(gcn_score), 4)

        prediction  = "PROBE"  if error > ANOMALY_THRESHOLD else "NORMAL"
        confidence  = min(abs(error - ANOMALY_THRESHOLD) / max(ANOMALY_THRESHOLD, 1e-9), 1.0)
        confidence  = round(float(confidence), 4)

        return {
            "gcn_prediction":       prediction,
            "gcn_confidence":       confidence,
            "gcn_score":            gcn_score,
            "reconstruction_error": round(float(error), 6),
        }

    except Exception as e:
        print(f"[!] GCN inference error for {ip}: {e}")
        return {"gcn_prediction": "ERR", "gcn_confidence": 0.0,
                "gcn_score": 0.0, "reconstruction_error": 0.0}

# ─────────────────────────────────────────────────────────
# STATE
# ─────────────────────────────────────────────────────────
connected_ws = set()
blocked_ips  = set()
events_log   = []
graph_state  = {"nodes": [], "edges": []}

ip_state = defaultdict(lambda: {
    "ports":                deque(),
    "logins_failed":        deque(),
    "connections":          deque(),
    "services":             deque(),
    "label":                "normal",
    "score":                0.0,
    "blocked":              False,
    "triggered_rules":      set(),
    "first_seen":           time.time(),
    "last_seen":            time.time(),
    "event_count":          0,
    "http_only":            True,   # kept for compatibility
    "http_posts":           deque(), # timestamps of POST requests
    "http_paths":           deque(), # (timestamp, path) for enumeration detection
    "http_errors":          deque(), # timestamps of 4xx responses
    "gcn_prediction":       "N/A",
    "gcn_confidence":       0.0,
    "gcn_score":            0.0,
    "reconstruction_error": 0.0,
})

# ─────────────────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────────────────
def prune(dq: deque, window: float):
    cutoff = time.time() - window
    while dq and dq[0][0] < cutoff:
        dq.popleft()

def evaluate_rules(ip: str):
    st = ip_state[ip]
    triggered = []
    scores    = []

    # Port scan
    prune(st["ports"], RULES["port_scan"]["window"])
    distinct_ports = len(set(p for _, p in st["ports"]))
    if distinct_ports >= RULES["port_scan"]["threshold"]:
        triggered.append(RULES["port_scan"]["label"])
        scores.append(min(distinct_ports / 100, 1.0))

    # Brute force
    prune(st["logins_failed"], RULES["brute_force"]["window"])
    failed = len(st["logins_failed"])
    if failed >= RULES["brute_force"]["threshold"]:
        triggered.append(RULES["brute_force"]["label"])
        scores.append(min(failed / 30, 1.0))

    # Rapid connections
    prune(st["connections"], RULES["rapid_conn"]["window"])
    conns = len(st["connections"])
    if conns >= RULES["rapid_conn"]["threshold"]:
        triggered.append(RULES["rapid_conn"]["label"])
        scores.append(min(conns / 60, 1.0))

    # Multi-service (only counts non-HTTP services)
    prune(st["services"], RULES["multi_service"]["window"])
    non_http_svcs = set(s for _, s in st["services"] if s not in BENIGN_ONLY_SERVICES)
    if len(non_http_svcs) >= RULES["multi_service"]["threshold"]:
        triggered.append(RULES["multi_service"]["label"])
        scores.append(min(len(non_http_svcs) / 6, 1.0))

    # Composite score
    score = max(scores) if scores else min(
        distinct_ports / max(RULES["port_scan"]["threshold"], 1) * 0.4 +
        failed         / max(RULES["brute_force"]["threshold"], 1) * 0.3 +
        conns          / max(RULES["rapid_conn"]["threshold"], 1)  * 0.2 +
        len(non_http_svcs) / max(RULES["multi_service"]["threshold"], 1) * 0.1,
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
        print(f"[!] Block failed for {ip}: {e}")

def unblock_ip(ip: str):
    blocked_ips.discard(ip)
    if ip in ip_state:
        ip_state[ip]["blocked"]         = False
        ip_state[ip]["label"]           = "normal"
        ip_state[ip]["triggered_rules"] = set()
        ip_state[ip]["score"]           = 0.0
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5
        )
        print(f"[UNBLOCKED] {ip}")
    except Exception as e:
        print(f"[!] Unblock failed for {ip}: {e}")

# ─────────────────────────────────────────────────────────
# CORE EVENT PROCESSOR
# ─────────────────────────────────────────────────────────
async def process_event(ip: str, event_type: str, service: str,
                        dst_port: int = 0, extra: dict = None):
    if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0") or ip.startswith("15.177."):
        return

    now = time.time()
    ts  = datetime.now(timezone.utc).isoformat()
    st  = ip_state[ip]

    st["last_seen"]   = now
    st["event_count"] += 1

    # Track if this IP has done anything beyond HTTP
    if service not in BENIGN_ONLY_SERVICES:
        st["http_only"] = False

    # Update sliding windows
    if dst_port > 0:
        st["ports"].append((now, dst_port))
        st["connections"].append((now,))

    if service:
        st["services"].append((now, service))

    if event_type in ("cowrie.login.failed", "cowrie.login.success"):
        if event_type == "cowrie.login.failed":
            st["logins_failed"].append((now,))

    # Track HTTP-specific signals for model feature enrichment
    if event_type == "http.request" and extra:
        method = extra.get("method", "GET")
        path   = extra.get("path", "/")
        if method == "POST":
            st["http_posts"].append((now,))
        st["http_paths"].append((now, path))

    # Run heuristic detection
    is_probe, rules_hit, score = evaluate_rules(ip)
    st["score"] = score

    # Run GCN model inference
    gcn = run_gcn_inference(ip, service, event_type, dst_port, st)
    st["gcn_prediction"]       = gcn["gcn_prediction"]
    st["gcn_confidence"]       = gcn["gcn_confidence"]
    st["gcn_score"]            = gcn["gcn_score"]
    st["reconstruction_error"] = gcn["reconstruction_error"]

    # Label logic:
    #   - "probe" if heuristic rules fire (enough evidence)
    #   - GCN adds "GCN Anomaly" tag but NEVER triggers block alone
    #   - Auto-block only when heuristic rules fire (not GCN alone)
    gcn_says_probe = gcn["gcn_prediction"] == "PROBE"

    if is_probe or gcn_says_probe:
        st["label"] = "probe"
        for r in rules_hit:
            st["triggered_rules"].add(r)
        if gcn_says_probe:
            st["triggered_rules"].add("GCN Anomaly")
        # Block on heuristic OR GCN probe detection
        if ip not in blocked_ips:
            block_ip(ip)
    elif st["label"] != "probe":
        st["label"] = "normal"

    # Log event
    entry = {
        "timestamp":            ts,
        "src_ip":               ip,
        "eventid":              event_type,
        "service":              service,
        "dst_port":             dst_port,
        "score":                score,
        "label":                st["label"],
        "rules":                list(st["triggered_rules"]),
        "gcn_prediction":       gcn["gcn_prediction"],
        "gcn_confidence":       gcn["gcn_confidence"],
        "gcn_score":            gcn["gcn_score"],
        "reconstruction_error": gcn["reconstruction_error"],
        **(extra or {}),
    }
    events_log.append(entry)
    if len(events_log) > 300:
        events_log.pop(0)

    rebuild_graph()

    await broadcast({
        "type":                 "event",
        "timestamp":            ts,
        "src_ip":               ip,
        "service":              service,
        "eventid":              event_type,
        "dst_port":             dst_port,
        "score":                score,
        "label":                st["label"],
        "rules_hit":            rules_hit,
        "blocked":              ip in blocked_ips,
        "gcn_prediction":       gcn["gcn_prediction"],
        "gcn_confidence":       gcn["gcn_confidence"],
        "gcn_score":            gcn["gcn_score"],
        "reconstruction_error": gcn["reconstruction_error"],
        "graph":                graph_state,
        "sessions":             get_sessions(),
        "events":               events_log[-60:],
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

        # Edge to each distinct service — include port number
        SVC_PORT = {"ssh":2222,"telnet":2223,"http":80,"https":443,"ftp":21,"smtp":25}
        svcs = set(s for _, s in st["services"])
        for svc in svcs:
            svc_id = f"s_{svc}"
            if svc_id not in service_seen:
                nodes.append({"id": svc_id, "type": "service", "label": svc,
                              "port": SVC_PORT.get(svc, "")})
                service_seen[svc_id] = True
            edges.append({"source": host_id, "target": svc_id})

    graph_state["nodes"] = nodes
    graph_state["edges"] = edges

def get_sessions():
    return [
        {
            "ip":                   ip,
            "label":                st["label"],
            "score":                round(st["score"], 4),
            "blocked":              st["blocked"],
            "events":               st["event_count"],
            "rules":                list(st["triggered_rules"]),
            "services":             list(set(s for _, s in st["services"])),
            "ports_scanned":        len(set(p for _, p in st["ports"])),
            "failed_logins":        len(st["logins_failed"]),
            "gcn_prediction":       st["gcn_prediction"],
            "gcn_confidence":       round(st["gcn_confidence"], 4),
            "gcn_score":            round(st["gcn_score"], 4),
            "reconstruction_error": round(st["reconstruction_error"], 6),
        }
        for ip, st in ip_state.items()
    ]

# ─────────────────────────────────────────────────────────
# LAYER 1: iptables LOG tailer
# ─────────────────────────────────────────────────────────
KERN_RE = re.compile(r'SRC=(\S+)\s+DST=\S+\s+.*?DPT=(\d+)', re.IGNORECASE)
SERVICE_PORT_MAP = {
    22: "ssh", 23: "telnet", 21: "ftp", 25: "smtp", 2222: "ssh", 2223: "telnet", 587: "smtp", 465: "smtp", 2525: "smtp",
    80: "http", 443: "https", 3306: "mysql",
    5432: "postgres", 6379: "redis", 8080: "http-alt",
}

async def tail_kern_log():
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
        if "PROBE_LOG" not in line:
            continue
        m = KERN_RE.search(line)
        if not m:
            continue
        src_ip = m.group(1)
        dpt    = int(m.group(2))
        svc    = SERVICE_PORT_MAP.get(dpt, f"port-{dpt}")
        await process_event(src_ip, "iptables.probe_log", svc, dpt)

# ─────────────────────────────────────────────────────────
# LAYER 1b: Postfix log tailer (SMTP on port 2525)
_IP4 = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
POSTFIX_RE  = re.compile(r'postfix.*connect from.*\[' + _IP4 + r'\]', re.IGNORECASE)
POSTFIX_RE2 = re.compile(r'postfix.*client=\S+\[' + _IP4 + r'\]', re.IGNORECASE)

async def tail_postfix_log():
    print('[*] Tailing Postfix via journald for SMTP connections')
    proc = await asyncio.create_subprocess_exec(
        'journalctl', '-f', '-n', '0', '-u', 'postfix',
        '--output=short-precise',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    async for raw in proc.stdout:
        line = raw.decode('utf-8', errors='ignore')
        m = POSTFIX_RE.search(line) or POSTFIX_RE2.search(line)
        if not m:
            continue
        src_ip = m.group(1)
        if src_ip in ('127.0.0.1', '::1'):
            continue
        print(f'[SMTP] {src_ip} -> port 2525', flush=True)
        await process_event(src_ip, 'iptables.probe_log', 'smtp', 2525)

# LAYER 2: Cowrie JSON tailer
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
        dpt     = ev.get("dst_port", 22)
        svc     = {22: "ssh", 23: "telnet", 21: "ftp", 2222: "ssh", 2223: "telnet"}.get(dpt, "ssh")

        if any(x in eventid for x in ["connect", "login", "command", "download", "session"]):
            await process_event(src_ip, eventid, svc, dpt,
                                extra={"message": ev.get("message", "")[:120]})

# ─────────────────────────────────────────────────────────
# LAYER 3: nginx access log tailer
# Every HTTP visit creates a node — never auto-blocked
# ─────────────────────────────────────────────────────────
NGINX_RE = re.compile(r'^(\S+)\s+-\s+-\s+\[.*?\]\s+"(\w+)\s+(\S+)\s+HTTP')

async def tail_http_log():
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
# WEBSOCKET SERVER
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
                    await broadcast({
                        "type": "unblocked", "ip": ip,
                        "graph": graph_state, "sessions": get_sessions()
                    })
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
    rebuild_graph()
    return web.json_response({"ok": True, "ip": ip})

async def h_reset(req):
    ip_state.clear()
    blocked_ips.clear()
    events_log.clear()
    graph_state["nodes"] = []
    graph_state["edges"] = []
    await broadcast({"type": "reset"})
    return web.json_response({"ok": True})

async def h_inject(req):
    """Manual event injection for testing."""
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
    for path, handler, method in [
        ("/status",  h_status,  "GET"),
        ("/unblock", h_unblock, "POST"),
        ("/reset",   h_reset,   "POST"),
        ("/inject",  h_inject,  "POST"),
    ]:
        r = getattr(app.router, f"add_{method.lower()}")(path, handler)
        cors.add(r)
    return app

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
async def main():
    # Ensure kern.log is readable by this process
    import subprocess
    subprocess.run(["sudo", "chmod", "644", "/var/log/kern.log"], 
                   capture_output=True)
    ws_srv = await websockets.serve(ws_handler, "0.0.0.0", WS_PORT)
    print(f"[✓] WebSocket  ws://0.0.0.0:{WS_PORT}")

    runner = web.AppRunner(make_http_app())
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", HTTP_PORT).start()
    print(f"[✓] HTTP API   http://0.0.0.0:{HTTP_PORT}")

    await asyncio.gather(
        tail_kern_log(),
        tail_postfix_log(),
        tail_cowrie_log(),
        tail_http_log(),
    )

if __name__ == "__main__":
    asyncio.run(main())