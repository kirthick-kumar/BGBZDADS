import time
import json
import pandas as pd

WINDOW = 10
events = {}

def extract_features(log):
    ip = log["src_ip"]
    service = log.get("protocol", "ssh")
    now = time.time()

    events.setdefault(ip, []).append(now)
    events[ip] = [t for t in events[ip] if now - t < WINDOW]

    features = {
        "duration": 1,
        "protocol_type": service,
        "service": service,
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": len(events[ip]),
        "srv_count": len(events[ip])
    }

    return ip, features