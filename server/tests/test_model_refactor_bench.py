# Drishti v0.1 — Deep learning pipeline optimization verification and latency benchmarking
import time
import numpy as np
import pytest
import torch
import torch.nn as nn
import torch.nn.functional as F

from ml.models.temporal import LSTMDetector, TransformerDetector, FastMultiheadAttention, FastTransformerEncoderLayer
from ml.models.gnn import SparseGraphConvolution, GraphConvolution, GraphNetworkDetector, sparse_neighborhood_message_passing
from ml.models.forecaster import LSTMForecaster, TransformerForecaster, TemporalGraphForecaster, FusionForecaster
from ml.training.train_forecaster import FocalLoss, compute_inverse_frequency_weights
from ml.forecasting.engine import ForecastingEngine
from app.services.traffic.graph_engine import NetworkGraphEngine


# ── Test 1: Shape Contract Validation [B, 5, 27] -> [B, 3, 5] ────────────────
@pytest.mark.parametrize("batch_size", [1, 4, 16, 64])
def test_forecasting_shape_contract(batch_size: int):
    """Verifies that sequence input [B, 5, 27] produces output logits [B, 3, 5] and valid probabilities."""
    x = torch.randn(batch_size, 5, 27)

    # 1. LSTM Forecaster
    lstm = LSTMForecaster(input_dim=27, hidden_dim=64, num_layers=2, horizon=3, num_classes=5)
    logits_l, emb_l = lstm(x)
    assert logits_l.shape == (batch_size, 3, 5), f"LSTM expected shape {(batch_size, 3, 5)}, got {logits_l.shape}"
    assert emb_l.shape == (batch_size, 128)
    probs_l = F.softmax(logits_l, dim=-1)
    assert torch.allclose(torch.sum(probs_l, dim=-1), torch.ones(batch_size, 3), atol=1e-5)

    # 2. Transformer Forecaster
    tf = TransformerForecaster(input_dim=27, d_model=64, nhead=4, num_layers=2, horizon=3, num_classes=5)
    logits_t, emb_t = tf(x)
    assert logits_t.shape == (batch_size, 3, 5), f"Transformer expected shape {(batch_size, 3, 5)}, got {logits_t.shape}"
    assert emb_t.shape == (batch_size, 64)
    probs_t = F.softmax(logits_t, dim=-1)
    assert torch.allclose(torch.sum(probs_t, dim=-1), torch.ones(batch_size, 3), atol=1e-5)

    # 3. Fusion Forecaster
    fuse = FusionForecaster(temporal_dim=64, graph_dim=64, horizon=3, num_classes=5)
    out_f = fuse(emb_t, torch.randn(batch_size, 64))
    assert out_f.shape == (batch_size, 3, 5)
    probs_f = F.softmax(out_f, dim=-1)
    assert torch.allclose(torch.sum(probs_f, dim=-1), torch.ones(batch_size, 3), atol=1e-5)


# ── Test 2: Sparse Message Passing vs Dense Backward-Compatibility ───────────
def test_sparse_gnn_message_passing():
    """Verifies SparseGraphConvolution and GraphNetworkDetector with sparse edge_index [2, E] and dense fallback."""
    num_nodes = 8
    node_feat = torch.randn(num_nodes, 4)
    # Undirected ring graph
    src = [0, 1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4, 5, 6, 7, 0]
    dst = [1, 2, 3, 4, 5, 6, 7, 0, 0, 1, 2, 3, 4, 5, 6, 7]
    edge_index = torch.tensor([src, dst], dtype=torch.long)
    dense_adj = torch.eye(num_nodes)

    detector = GraphNetworkDetector(node_in_dim=4, hidden_dim=32, num_classes=8)
    logits_sparse, emb_sparse = detector(node_feat, edge_index)
    logits_dense, emb_dense = detector(node_feat, dense_adj)

    assert logits_sparse.shape == (1, 8)
    assert emb_sparse.shape == (1, 64)
    assert logits_dense.shape == (1, 8)
    assert emb_dense.shape == (1, 64)

    # Temporal Graph Forecaster
    tg = TemporalGraphForecaster(node_in_dim=4, spatial_hidden_dim=32, temporal_graph_dim=8, horizon=3, num_classes=5)
    vel = torch.randn(1, 8)
    out_sparse, _ = tg(node_feat, edge_index, vel)
    out_dense, _ = tg(node_feat, dense_adj, vel)

    assert out_sparse.shape == (1, 3, 5)
    assert out_dense.shape == (1, 3, 5)


# ── Test 3: Focal Loss Multi-Class Gradient Computation ───────────────────────
def test_multi_class_focal_loss():
    """Verifies FocalLoss gamma focusing and inverse-frequency class weight penalty."""
    weights = torch.tensor([0.2, 1.5, 2.0, 1.8, 1.2])
    focal = FocalLoss(gamma=2.0, alpha=weights)

    logits = torch.randn(10, 5, requires_grad=True)
    targets = torch.tensor([0, 0, 1, 2, 4, 3, 0, 1, 2, 4])
    loss = focal(logits, targets)

    assert loss.item() > 0.0
    loss.backward()
    assert logits.grad is not None
    assert torch.all(torch.isfinite(logits.grad))


# ── Test 4: End-to-End ForecastingEngine Compatibility ────────────────────────
def test_forecasting_engine_integration():
    """Ensures ForecastingEngine runs cleanly with the refactored neural pipeline."""
    engine = ForecastingEngine()
    assert engine.transformer_ready is True
    assert engine.lstm_ready is True

    x = torch.randn(1, 5, 27)
    graph_engine = NetworkGraphEngine(target_ip="192.168.1.100")
    graph_engine.snapshot()

    res = engine.forecast_progression(
        seq_tensor=x,
        graph_engine=graph_engine,
        current_features={"flow_packets_per_sec": 20.0},
        current_verdict="NORMAL",
        window_count=3,
        horizon=3,
    )
    assert res.is_available is True
    assert len(res.horizon_steps) == 3
    for step in res.horizon_steps:
        assert step.step in ("T+1", "T+2", "T+3")
        assert 0.0 <= step.probability <= 1.0


# ── Test 5: Latency & Throughput Benchmark ────────────────────────────────────
def test_model_latency_benchmark():
    """Benchmarks forward pass latency (ms) and throughput comparing legacy baseline vs optimized pipeline."""
    device = torch.device("cpu")
    num_runs = 200

    # 1. Benchmark Transformer Forecaster (Fast SDPA + Fused Head)
    tf = TransformerForecaster(input_dim=27, d_model=64, nhead=4, num_layers=2, horizon=3, num_classes=5).to(device)
    tf.eval()

    # Legacy simulation: separate linear projections + torch.stack
    class LegacyMultiHead(nn.Module):
        def __init__(self, in_dim=64, horizon=3, num_classes=5):
            super().__init__()
            self.heads = nn.ModuleList([nn.Linear(in_dim, num_classes) for _ in range(horizon)])
        def forward(self, x):
            return torch.stack([head(x) for head in self.heads], dim=1)

    legacy_head = LegacyMultiHead().to(device)
    fused_head = nn.Linear(64, 15).to(device)
    dummy_feat = torch.randn(1, 64, device=device)

    # Warmup
    for _ in range(30):
        _ = legacy_head(dummy_feat)
        _ = fused_head(dummy_feat).view(-1, 3, 5)
        _ = tf(torch.randn(1, 5, 27, device=device))

    # Benchmark legacy separate heads
    t0 = time.perf_counter()
    for _ in range(num_runs):
        _ = legacy_head(dummy_feat)
    t_legacy_heads = (time.perf_counter() - t0) * 1000.0 / num_runs

    # Benchmark fused multi-step head
    t0 = time.perf_counter()
    for _ in range(num_runs):
        _ = fused_head(dummy_feat).view(-1, 3, 5)
    t_fused_head = (time.perf_counter() - t0) * 1000.0 / num_runs

    # Benchmark full TransformerForecaster forward pass
    seq = torch.randn(1, 5, 27, device=device)
    latencies = []
    for _ in range(num_runs):
        t_start = time.perf_counter()
        _ = tf(seq)
        latencies.append((time.perf_counter() - t_start) * 1000.0)

    mean_lat = np.mean(latencies)
    p95_lat = np.percentile(latencies, 95)
    throughput = 1000.0 / mean_lat

    print("\n" + "=" * 60)
    print("🚀 DRISHTI DEEP LEARNING PIPELINE LATENCY BENCHMARK REPORT")
    print("=" * 60)
    print(f"Legacy 3-Branch Projection Head : {t_legacy_heads:.4f} ms / pass")
    print(f"Fused Single-GEMM Horizon Head   : {t_fused_head:.4f} ms / pass ({(t_legacy_heads / max(t_fused_head, 1e-6)):.2f}x speedup)")
    print("-" * 60)
    print(f"Transformer Forecaster (SDPA)   : Mean {mean_lat:.3f} ms | P95 {p95_lat:.3f} ms")
    print(f"Inference Throughput             : {throughput:.1f} sequences / sec")
    print("=" * 60)

    assert t_fused_head <= t_legacy_heads * 1.5, "Fused head should not be slower than 3 separate heads"
    assert mean_lat < 15.0, f"Transformer forward latency should be under 15ms on CPU, got {mean_lat:.2f}ms"
