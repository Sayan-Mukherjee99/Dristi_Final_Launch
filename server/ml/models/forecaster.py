# Drishti v0.1 — future attack forecasting deep learning models | Phase 03
# Multi-step forecasting architectures: LSTM, Transformer, Temporal GNN, and Multimodal Fusion
# Optimized with fused single-GEMM horizon heads, sparse message passing, and scaled dot-product attention
from __future__ import annotations

import math
from typing import Any
import torch
import torch.nn as nn
import torch.nn.functional as F

from ml.models.gnn import SparseGraphConvolution, GraphConvolution
from ml.models.temporal import FastTransformerEncoderLayer, PositionalEncoding


class BaseForecaster(nn.Module):
    """Abstract base class for multi-step network behaviour forecasters.

    Predicts future behavior at horizon steps t+1, t+2, t+3 (default horizon=3).
    Output shape: [batch_size, horizon, num_classes]
    """

    def __init__(self, input_dim: int = 27, horizon: int = 3, num_classes: int = 5) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.horizon = horizon
        self.num_classes = num_classes


class LSTMForecaster(BaseForecaster):
    """Bidirectional LSTM with temporal attention and fused single-pass multi-step forecasting projection.

    Consumes sliding window sequence [B, seq_len=5, feature_dim=27].
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
      - temporal_emb: [B, hidden_dim * 2 = 128]
    """

    def __init__(
        self,
        input_dim: int = 27,
        hidden_dim: int = 64,
        num_layers: int = 2,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__(input_dim=input_dim, horizon=horizon, num_classes=num_classes)
        self.hidden_dim = hidden_dim
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.attention = nn.Linear(hidden_dim * 2, 1)

        # Fused multi-step projection head projecting to (horizon * num_classes) in a single GEMM pass
        self.fc_context = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        self.multi_step_head = nn.Linear(hidden_dim, horizon * num_classes)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # x: [B, seq_len, input_dim]
        lstm_out, _ = self.lstm(x)  # [B, seq_len, 2 * hidden_dim]
        attn_weights = F.softmax(self.attention(lstm_out), dim=1)  # [B, seq_len, 1]
        context = torch.sum(attn_weights * lstm_out, dim=1)  # [B, 2 * hidden_dim]

        # Single fused projection and zero-copy view reshape: [B, horizon * num_classes] -> [B, horizon, num_classes]
        features = self.fc_context(context)
        stacked_logits = self.multi_step_head(features).view(-1, self.horizon, self.num_classes)
        return stacked_logits, context


class TransformerForecaster(BaseForecaster):
    """Transformer Encoder with Scaled Dot-Product Attention and fused multi-step horizon projection.

    Consumes sliding window sequence [B, seq_len=5, feature_dim=27].
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
      - temporal_emb: [B, d_model = 64]
    """

    def __init__(
        self,
        input_dim: int = 27,
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 2,
        dim_feedforward: int = 128,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__(input_dim=input_dim, horizon=horizon, num_classes=num_classes)
        self.d_model = d_model
        self.input_projection = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model=d_model)
        self.layers = nn.ModuleList([
            FastTransformerEncoderLayer(
                d_model=d_model,
                nhead=nhead,
                dim_feedforward=dim_feedforward,
                dropout=dropout,
            )
            for _ in range(num_layers)
        ])

        # Fused multi-step horizon head: single GEMM kernel projecting to [B, horizon * num_classes]
        self.multi_step_head = nn.Linear(d_model, horizon * num_classes)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # x: [B, seq_len, input_dim]
        proj = self.input_projection(x)
        encoded = self.pos_encoder(proj)
        for layer in self.layers:
            encoded = layer(encoded)
        pooled = torch.mean(encoded, dim=1)  # [B, d_model]

        # Fused projection and reshape: [B, horizon, num_classes]
        stacked_logits = self.multi_step_head(pooled).view(-1, self.horizon, self.num_classes)
        return stacked_logits, pooled


class TemporalGraphForecaster(nn.Module):
    """Evaluates topology dynamics across temporal graphs via sparse message passing.

    Consumes:
      - node_features: [N, 4]
      - edge_index: [2, E] sparse edge indices (or [N, N] dense adjacency matrix for backward-compatibility)
      - temporal_graph_features: [B, 8] (node delta, edge delta, packet rate delta, new edge ratio, etc.)
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
      - graph_emb: [B, 64]
    """

    def __init__(
        self,
        node_in_dim: int = 4,
        spatial_hidden_dim: int = 32,
        temporal_graph_dim: int = 8,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.horizon = horizon
        self.num_classes = num_classes

        # Sparse GNN layers on communication graph topology
        self.gc1 = SparseGraphConvolution(node_in_dim, spatial_hidden_dim)
        self.gc2 = SparseGraphConvolution(spatial_hidden_dim, spatial_hidden_dim)
        self.dropout = nn.Dropout(dropout)

        # Temporal topological velocity encoder ([B, 8] -> [B, 32])
        self.temporal_encoder = nn.Sequential(
            nn.Linear(temporal_graph_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 32),
        )

        # Fused graph representation: (spatial target + spatial mean = 64) + velocity (32) -> 64
        self.graph_fusion = nn.Sequential(
            nn.Linear(spatial_hidden_dim * 2 + 32, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
        )

        # Fused multi-step horizon projection head: single linear projection to 3 * 5 = 15 logits
        self.multi_step_head = nn.Linear(64, horizon * num_classes)

    def forward(
        self,
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
        temporal_graph_features: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        if node_features is None or node_features.size(0) == 0:
            device = temporal_graph_features.device if temporal_graph_features is not None else next(self.parameters()).device
            node_features = torch.zeros((1, self.gc1.in_features), device=device)
            edge_index = torch.empty((2, 0), dtype=torch.long, device=device)
        elif edge_index is None:
            edge_index = torch.empty((2, 0), dtype=torch.long, device=node_features.device)

        # Spatial sparse convolution on current graph
        h1 = F.relu(self.gc1(node_features, edge_index))
        h1 = self.dropout(h1)
        h2 = F.relu(self.gc2(h1, edge_index))  # [N, spatial_hidden_dim]

        target_emb = h2[0:1]  # Target device is always index 0
        global_mean = torch.mean(h2, dim=0, keepdim=True)
        spatial_emb = torch.cat([target_emb, global_mean], dim=1)  # [1, 64]

        # Process temporal graph dynamics
        if temporal_graph_features is None:
            temporal_graph_features = torch.zeros((spatial_emb.size(0), 8), device=spatial_emb.device)
        elif temporal_graph_features.dim() == 1:
            temporal_graph_features = temporal_graph_features.unsqueeze(0)

        # Match batch size if needed
        if spatial_emb.size(0) != temporal_graph_features.size(0):
            spatial_emb = spatial_emb.expand(temporal_graph_features.size(0), -1)

        temp_velocity = self.temporal_encoder(temporal_graph_features)  # [B, 32]
        fused_graph = self.graph_fusion(torch.cat([spatial_emb, temp_velocity], dim=1))  # [B, 64]

        # Single fused projection and view reshape: [B, horizon * num_classes] -> [B, horizon, num_classes]
        stacked_logits = self.multi_step_head(fused_graph).view(-1, self.horizon, self.num_classes)
        return stacked_logits, fused_graph


class FusionForecaster(nn.Module):
    """Multimodal fusion forecaster combining temporal sequences with dynamic graph topology.

    Consumes:
      - temporal_emb: [B, temporal_dim] (128 from LSTM or 64 from Transformer)
      - graph_emb: [B, graph_dim] (64 from TemporalGraphForecaster)
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
    """

    def __init__(
        self,
        temporal_dim: int = 128,
        graph_dim: int = 64,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.horizon = horizon
        self.num_classes = num_classes
        fused_dim = temporal_dim + graph_dim

        self.backbone = nn.Sequential(
            nn.Linear(fused_dim, 128),
            nn.LayerNorm(128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.ReLU(),
        )

        # Fused multi-step head: single linear projection to 3 * 5 = 15 logits
        self.multi_step_head = nn.Linear(64, horizon * num_classes)

    def forward(self, temporal_emb: torch.Tensor, graph_emb: torch.Tensor) -> torch.Tensor:
        if temporal_emb.size(0) != graph_emb.size(0):
            graph_emb = graph_emb.expand(temporal_emb.size(0), -1)
        fused = torch.cat([temporal_emb, graph_emb], dim=1)
        hidden = self.backbone(fused)  # [B, 64]

        return self.multi_step_head(hidden).view(-1, self.horizon, self.num_classes)
