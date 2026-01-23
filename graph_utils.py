import torch
from torch_geometric.data import Data
import numpy as np


def build_host_service_graph(
    host_features,
    service_features,
    edges
):
    """
    host_features: dict {host_id: feature_vector}
    service_features: dict {service_id: feature_vector}
    edges: list of (host_id, service_id)
    """

    # Assign node indices
    host_ids = list(host_features.keys())
    service_ids = list(service_features.keys())

    node_map = {}
    idx = 0

    for h in host_ids:
        node_map[h] = idx
        idx += 1

    for s in service_ids:
        node_map[s] = idx
        idx += 1

    # Node features
    x = []
    for h in host_ids:
        x.append(host_features[h])
    for s in service_ids:
        x.append(service_features[s])

    x = torch.tensor(np.array(x), dtype=torch.float)

    # Edge index (bidirectional)
    edge_index = []
    for h, s in edges:
        edge_index.append([node_map[h], node_map[s]])
        edge_index.append([node_map[s], node_map[h]])

    edge_index = torch.tensor(edge_index, dtype=torch.long).t()

    data = Data(x=x, edge_index=edge_index)

    return data, node_map
