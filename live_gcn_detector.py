import time, json, subprocess, joblib, torch, numpy as np
from datetime import datetime
from torch_geometric.data import Data
from your_model_file import GCN_AE   # paste your model class here

COWRIE_LOG = "/home/ec2-user/cowrie/var/log/cowrie/cowrie.json"
STATUS_FILE = "/home/ec2-user/live_status.json"

encoders = joblib.load("/home/ec2-user/encoders.pkl")
scaler   = joblib.load("/home/ec2-user/scaler.pkl")

DEVICE = torch.device("cpu")
MODEL_PATH = "/home/ec2-user/gcn_autoencoder.pth"
THRESHOLD = 0.05   # use your printed threshold

model = GCN_AE(41, 128).to(DEVICE)
model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
model.eval()

live_rows = []

def build_graph(X, service_ids):
    n = len(X)
    edges = []
    for i in range(n):
        edges.append([i, n + service_ids[i]])
        edges.append([n + service_ids[i], i])
    edge_index = torch.tensor(edges).t().contiguous()
    x = torch.zeros((n + max(service_ids) + 1, X.shape[1]))
    x[:n] = torch.tensor(X, dtype=torch.float)
    return Data(x=x, edge_index=edge_index)

blocked_ips = set()

with open(COWRIE_LOG) as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue

        log = json.loads(line)
        if "src_ip" not in log:
            continue

        row = {
            "protocol_type": log.get("protocol", "ssh"),
            "service": log.get("protocol", "ssh"),
            "flag": "S0",
            "duration": 1,
            "src_bytes": 0,
            "dst_bytes": 0,
            "count": 1,
            "srv_count": 1,
        }

        df = pd.DataFrame([row])

        for col in ["protocol_type", "service", "flag"]:
            df[col] = encoders[col].transform(df[col])

        X = scaler.transform(df)

        data = build_graph(X, df["service"].values)
        with torch.no_grad():
            recon = model(data.x, data.edge_index)
            err = torch.mean((recon - data.x) ** 2).item()

        is_probe = err > THRESHOLD

        if is_probe and log["src_ip"] not in blocked_ips:
            subprocess.run(["sudo", "/sbin/iptables", "-I", "INPUT", "-s", log["src_ip"], "-j", "DROP"])
            blocked_ips.add(log["src_ip"])

        status = {
            "ip": log["src_ip"],
            "score": err,
            "is_probe": bool(is_probe),
            "blocked": log["src_ip"] in blocked_ips,
            "time": datetime.utcnow().isoformat()
        }

        with open(STATUS_FILE, "w") as f:
            json.dump(status, f, indent=2)