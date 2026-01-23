import torch
import numpy as np
import networkx as nx
from torch_geometric.data import Data
from model.architecture import GCNEncoder, GraphAutoEncoder
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def load_model(in_channels):
    encoder = GCNEncoder(
        in_channels=in_channels,
        hidden_channels=16,
        latent_channels=8
    )

    model = GraphAutoEncoder(encoder).to(DEVICE)

    # ✅ load weights only
    model.load_state_dict(
        torch.load("gcn_autoencoder.pth", map_location=DEVICE)
    )

    model.eval()
    return model

# --------------------------------------------------
# 1. Build bipartite graph (same as notebook)
# --------------------------------------------------
def build_bipartite_graph(df):
    G = nx.Graph()

    for _, row in df.iterrows():
        host = row["host"]
        service = row["service_node"]

        G.add_node(host, node_type="host")
        G.add_node(service, node_type="service")

        if G.has_edge(host, service):
            G[host][service]["weight"] += 1
        else:
            G.add_edge(host, service, weight=1)

    return G


# --------------------------------------------------
# 2. Node mapping
# --------------------------------------------------
def create_node_mapping(G):
    node_to_idx = {node: i for i, node in enumerate(G.nodes())}
    idx_to_node = {i: node for node, i in node_to_idx.items()}
    return node_to_idx, idx_to_node


# --------------------------------------------------
# 3. Feature extraction (same spirit as notebook)
# --------------------------------------------------
def extract_host_features(G):
    features = {}
    for node, data in G.nodes(data=True):
        if data["node_type"] == "host":
            degree = G.degree(node)
            service_diversity = len(G[node])
            features[node] = [degree, service_diversity]
    return features


def extract_service_features(G):
    features = {}
    for node, data in G.nodes(data=True):
        if data["node_type"] == "service":
            degree = G.degree(node)
            features[node] = [degree, 0]   # padding for alignment
    return features

def extract_node_features(G):
    features = {}

    max_degree = max(dict(G.degree()).values())

    for node, data in G.nodes(data=True):
        degree = G.degree(node)

        if data["node_type"] == "host":
            service_diversity = len(G[node])
            avg_weight = np.mean(
                [G[node][nbr]["weight"] for nbr in G[node]]
            ) if degree > 0 else 0
        else:
            service_diversity = 0
            avg_weight = np.mean(
                [G[node][nbr]["weight"] for nbr in G[node]]
            ) if degree > 0 else 0

        normalized_degree = degree / max_degree if max_degree > 0 else 0

        # 🔴 EXACTLY 4 FEATURES (same as training)
        features[node] = [
            degree,
            service_diversity,
            avg_weight,
            normalized_degree
        ]

    return features

# --------------------------------------------------
# 4. Build PyG tensors
# --------------------------------------------------
def preprocess_to_graph(df):
    G = build_bipartite_graph(df)
    node_to_idx, _ = create_node_mapping(G)

    node_features = extract_node_features(G)

    X = np.zeros((len(G.nodes()), 4))  # 🔴 MUST BE 4

    for node, idx in node_to_idx.items():
        X[idx] = node_features[node]

    X = torch.tensor(X, dtype=torch.float)

    edges, weights = [], []

    for u, v, data in G.edges(data=True):
        ui, vi = node_to_idx[u], node_to_idx[v]
        edges += [[ui, vi], [vi, ui]]
        weights += [data["weight"], data["weight"]]

    edge_index = torch.tensor(edges, dtype=torch.long).t()
    edge_weight = torch.tensor(weights, dtype=torch.float)

    if edge_weight.max() > 0:
        edge_weight = edge_weight / edge_weight.max()

    return Data(
        x=X,
        edge_index=edge_index,
        edge_weight=edge_weight
    )



_model = None
def detect_probe(uploaded_df):
    global _model

    data = preprocess_to_graph(uploaded_df)
    data = data.to(DEVICE)

    # ✅ build model AFTER we know feature size
    if _model is None:
        _model = load_model(data.x.shape[1])

    with torch.no_grad():
        z = _model(data.x, data.edge_index)
        error = (z.norm(dim=1)).mean()

    return error.item()


