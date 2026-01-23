import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv


class GCNEncoder(nn.Module):
    def __init__(self, in_dim, hidden_dim, latent_dim):
        super().__init__()
        self.conv1 = GCNConv(in_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, latent_dim)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        z = self.conv2(x, edge_index)
        return z


class InnerProductDecoder(nn.Module):
    def forward(self, z, edge_index):
        src, dst = edge_index
        return torch.sum(z[src] * z[dst], dim=1)


class GCN_Autoencoder(nn.Module):
    def __init__(self, in_dim, hidden_dim=64, latent_dim=32):
        super().__init__()
        self.encoder = GCNEncoder(in_dim, hidden_dim, latent_dim)
        self.decoder = InnerProductDecoder()

    def forward(self, x, edge_index):
        z = self.encoder(x, edge_index)
        edge_logits = self.decoder(z, edge_index)
        return z, edge_logits
