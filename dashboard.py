import streamlit as st
import json
import time
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

STATUS_FILE = "/home/ec2-user/live_status.json"

st.set_page_config(layout="wide")
st.title("🛡️ Live GCN-based Probe Detection Dashboard")

placeholder = st.empty()

def plot_bipartite(G, hosts, services, title, host_space=1):
    pos = {}
    for i, node in enumerate(hosts):
        pos[node] = (0, i * host_space)
    for i, node in enumerate(services):
        pos[node] = (1, i)

    fig, ax = plt.subplots(figsize=(8,5))
    nx.draw(G, pos, with_labels=True, node_size=400, ax=ax)
    ax.set_title(title)
    ax.axis("off")
    st.pyplot(fig)

while True:
    with open(STATUS_FILE) as f:
        data = json.load(f)

    with placeholder.container():
        st.metric("🔴 Attacker IP", data["ip"])
        st.metric("🧠 Probe Detected", data["is_probe"])
        st.metric("🧱 Firewall", "Blocked" if data["blocked"] else "Allowed")
        st.metric("📈 Anomaly Score", round(data["score"], 4))

    time.sleep(2)
    st.experimental_rerun()