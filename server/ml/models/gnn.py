# Drishti v0.1 — graph neural network (GNN) model with sparse message passing | Phase 02
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


def sparse_neighborhood_message_passing(
    x: torch.Tensor,
    edge_index: torch.Tensor,
    add_self_loops: bool = True,
) -> torch.Tensor:
    """Performs sparse neighborhood message passing using scatter_add.

    Supports:
      - Sparse edge indices of shape [2, E] with automatic symmetric degree normalization:
        H' = D^(-1/2) * (A + I) * D^(-1/2) * X
      - Backward-compatible fallback for dense [N, N] adjacency matrices.
    """
    num_nodes = x.size(0)
    device = x.device

    if num_nodes == 0:
        return x

    # Backward compatibility with dense [N, N] normalized adjacency matrices
    if edge_index.dim() == 2 and edge_index.size(0) == edge_index.size(1) and edge_index.size(0) == num_nodes:
        return torch.matmul(edge_index, x)

    row, col = edge_index[0].long(), edge_index[1].long()
    if add_self_loops:
        loop_idx = torch.arange(num_nodes, dtype=torch.long, device=device)
        row = torch.cat([row, loop_idx], dim=0)
        col = torch.cat([col, loop_idx], dim=0)

    if row.numel() == 0:
        return torch.zeros_like(x)

    # In-degree computation for symmetric graph normalization D^(-1/2) * A * D^(-1/2)
    deg = torch.zeros(num_nodes, dtype=x.dtype, device=device)
    deg.scatter_add_(0, row, torch.ones_like(row, dtype=x.dtype))
    deg_inv_sqrt = deg.pow(-0.5)
    deg_inv_sqrt[torch.isinf(deg_inv_sqrt) | torch.isnan(deg_inv_sqrt)] = 0.0

    # Symmetric edge weights
    edge_weight = deg_inv_sqrt[row] * deg_inv_sqrt[col]

    # Message gathering and scatter-add aggregation
    messages = x[row] * edge_weight.unsqueeze(-1)
    aggr = torch.zeros_like(x)
    aggr.scatter_add_(0, col.unsqueeze(-1).expand_as(messages), messages)
    return aggr


class SparseGraphConvolution(nn.Module):
    """Sparse graph convolution layer using neighborhood message passing."""

    def __init__(self, in_features: int, out_features: int, add_self_loops: bool = True) -> None:
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.add_self_loops = add_self_loops
        self.linear = nn.Linear(in_features, out_features, bias=True)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        # x: [N, in_features], edge_index: [2, E] or [N, N]
        aggr = sparse_neighborhood_message_passing(x, edge_index, add_self_loops=self.add_self_loops)
        return self.linear(aggr)


# Backward-compatible alias
GraphConvolution = SparseGraphConvolution


class GraphNetworkDetector(nn.Module):
    """Graph Neural Network detector evaluating communication graph topology via sparse message passing.

    Consumes:
      - node_features: [N, node_in_dim=4]
      - edge_index: [2, E] sparse edge indices (or [N, N] dense adjacency for legacy callers)
    Produces:
      - logits: [1, num_classes=8]
      - graph_embedding: [1, 2 * hidden_dim=64]
    """

    def __init__(
        self,
        node_in_dim: int = 4,
        hidden_dim: int = 32,
        num_classes: int = 8,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.gc1 = SparseGraphConvolution(node_in_dim, hidden_dim)
        self.gc2 = SparseGraphConvolution(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes),
        )

    def forward(self, node_features: torch.Tensor, edge_index: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        if node_features is None or node_features.size(0) == 0:
            device = next(self.parameters()).device
            node_features = torch.zeros((1, self.gc1.in_features), device=device)
            edge_index = torch.empty((2, 0), dtype=torch.long, device=device)
        elif edge_index is None:
            edge_index = torch.empty((2, 0), dtype=torch.long, device=node_features.device)

        # Layer 1
        h1 = F.relu(self.gc1(node_features, edge_index))
        h1 = self.dropout(h1)
        # Layer 2
        h2 = F.relu(self.gc2(h1, edge_index))  # [N, hidden_dim]

        # Target node readout (index 0 is target device) + graph global mean
        target_embedding = h2[0:1]  # [1, hidden_dim]
        global_mean = torch.mean(h2, dim=0, keepdim=True)  # [1, hidden_dim]
        graph_embedding = torch.cat([target_embedding, global_mean], dim=1)  # [1, 2 * hidden_dim]

        logits = self.fc(graph_embedding)  # [1, num_classes]
        return logits, graph_embedding
