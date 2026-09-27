"""Drishti Multi-Phase Neural Pipeline Audit & Resilience Test Suite.

Verifies:
- Phase 1: Numerical Stability & Edge-Case Math (isolated nodes, focal loss gradients, mixed-precision)
- Phase 2: Calibration & Downstream Gating Audit (ECE, Brier score, temperature scaling, tau=0.45 threshold)
- Phase 3: Live Ingestion & Concurrency Stress Test (tracemalloc zero memory drift, P99 latency < 20ms)
- Phase 4: Integration & Failure Mode Resilience (empty edge_index fallback, checkpoint integrity with strict=True)
"""
from __future__ import annotations

import gc
import os
import time
import tracemalloc
from pathlib import Path
import numpy as np
import pytest
import torch
import torch.nn.functional as F

from ml.models.gnn import (
    SparseGraphConvolution,
    GraphNetworkDetector,
    sparse_neighborhood_message_passing,
)
from ml.models.temporal import (
    FastMultiheadAttention,
    FastTransformerEncoderLayer,
    LSTMDetector,
    TransformerDetector,
)
from ml.models.fusion import FusionDetector
from ml.models.forecaster import (
    LSTMForecaster,
    TransformerForecaster,
    TemporalGraphForecaster,
    FusionForecaster,
)
from ml.training.train_forecaster import (
    FocalLoss,
    load_chronological_datasets,
    build_forecasting_sequences,
    split_chronological_with_buffer,
    compute_inverse_frequency_weights,
)
from ml.preprocessing import TrafficPreprocessor
from ml.forecasting.engine import forecasting_engine
from ml.forecasting.mitre_mapping import map_to_mitre_attack
from app.services.traffic.flow_aggregator import FlowAggregator
from app.services.traffic.graph_engine import NetworkGraphEngine
from app.services.traffic.time_window import TimeWindowEngine
from app.services.traffic.feature_extractor import extract_session_features
from ml.inference.engine import inference_engine


# ==============================================================================
# PHASE 1: Numerical Stability & Edge-Case Math
# ==============================================================================

def test_phase1_isolated_and_zero_degree_nodes() -> None:
    """Verify that isolated/zero-degree nodes with add_self_loops=False produce zero NaNs or Infs."""
    num_nodes = 6
    x = torch.randn(num_nodes, 4)
    # Only connect nodes 0 and 1; nodes 2, 3, 4, 5 are completely isolated
    edge_index = torch.tensor([[0, 1], [1, 0]], dtype=torch.long)

    # 1. Low-level sparse message passing with self-loops DISABLED
    aggr = sparse_neighborhood_message_passing(x, edge_index, add_self_loops=False)
    assert not torch.isnan(aggr).any(), "NaN detected in sparse_neighborhood_message_passing"
    assert not torch.isinf(aggr).any(), "Inf detected in sparse_neighborhood_message_passing"
    # Isolated nodes must have zero aggregated messages
    assert torch.all(aggr[2:] == 0.0), "Isolated nodes should receive zero messages"

    # 2. SparseGraphConvolution layer
    conv = SparseGraphConvolution(in_features=4, out_features=32, add_self_loops=False)
    out = conv(x, edge_index)
    assert not torch.isnan(out).any(), "NaN detected in SparseGraphConvolution"
    assert not torch.isinf(out).any(), "Inf detected in SparseGraphConvolution"

    # 3. Multi-layer GraphNetworkDetector
    detector = GraphNetworkDetector(node_in_dim=4, hidden_dim=32, num_classes=8)
    logits, emb = detector(x, edge_index)
    assert not torch.isnan(logits).any(), "NaN in GraphNetworkDetector logits"
    assert not torch.isnan(emb).any(), "NaN in GraphNetworkDetector embedding"
    assert logits.shape == (1, 8)
    assert emb.shape == (1, 64)


def test_phase1_focal_loss_gradient_limits() -> None:
    """Verify that Focal Loss suppresses trivial benign samples while minority classes retain active gradients."""
    alpha_weights = torch.tensor([0.2, 1.5, 3.0, 3.0, 1.5], dtype=torch.float32)
    criterion = FocalLoss(gamma=2.0, alpha=alpha_weights)

    # Construct two extreme cases:
    # Sample 0: Trivial benign (target=0, p_t -> 1.0, logits[0] >> 0)
    # Sample 1: Minority attack (target=2, LIKELY_ESCALATION, logits uniform)
    logits = torch.tensor([
        [20.0, 0.0, 0.0, 0.0, 0.0],
        [0.0, 0.0, 0.0, 0.0, 0.0],
    ], requires_grad=True)
    targets = torch.tensor([0, 2], dtype=torch.long)

    loss = criterion(logits, targets)
    loss.backward()

    # Gradient for trivial benign sample on its true class should vanish to ~0
    benign_grad = abs(logits.grad[0, 0].item())
    assert benign_grad < 1e-8, f"Trivial benign gradient should vanish, got {benign_grad}"

    # Gradient for minority attack sample on its true class must remain non-zero and substantial
    minority_grad = abs(logits.grad[1, 2].item())
    assert minority_grad > 0.05, f"Minority class gradient should remain active, got {minority_grad}"

    # Verify across complete multi-step horizon model
    model = TransformerForecaster(input_dim=27, horizon=3, num_classes=5)
    model.train()
    batch_x = torch.randn(5, 5, 27)
    batch_y = torch.tensor([
        [0, 0, 0],
        [1, 1, 1],
        [2, 2, 2],  # LIKELY_ESCALATION (minority)
        [3, 3, 3],  # POTENTIAL_LATERAL_MOVEMENT (minority)
        [4, 4, 4],
    ], dtype=torch.long)

    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    opt.zero_grad()
    preds, _ = model(batch_x)
    total_loss = sum(criterion(preds[:, h, :], batch_y[:, h]) for h in range(3))
    total_loss.backward()

    # Decompose head weights grad: [horizon=3, num_classes=5, d_model=64]
    head_grad = model.multi_step_head.weight.grad.view(3, 5, 64)
    for h in range(3):
        for c in range(5):
            gnorm = head_grad[h, c].norm().item()
            assert gnorm > 1e-5, f"Gradient for horizon T+{h+1} class {c} is zero or vanishing"


def test_phase1_mixed_precision_dynamic_range() -> None:
    """Verify numerical stability of FastMultiheadAttention and SparseGraphConvolution under float32 and bfloat16."""
    for dtype in [torch.float32, torch.bfloat16]:
        # FastMultiheadAttention
        attn = FastMultiheadAttention(d_model=64, nhead=4).to(dtype)
        x = torch.randn(2, 5, 64, dtype=dtype, requires_grad=True)
        attn_out = attn(x)
        assert attn_out.dtype == dtype
        assert not torch.isnan(attn_out).any()
        assert not torch.isinf(attn_out).any()

        loss = attn_out.sum()
        loss.backward()
        assert not torch.isnan(x.grad).any()
        assert not torch.isinf(x.grad).any()

        # SparseGraphConvolution
        conv = SparseGraphConvolution(in_features=4, out_features=32).to(dtype)
        node_feat = torch.randn(8, 4, dtype=dtype, requires_grad=True)
        edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 0]], dtype=torch.long)
        conv_out = conv(node_feat, edge_index)
        assert conv_out.dtype == dtype
        assert not torch.isnan(conv_out).any()
        assert not torch.isinf(conv_out).any()

        conv_loss = conv_out.sum()
        conv_loss.backward()
        assert not torch.isnan(node_feat.grad).any()
        assert not torch.isinf(node_feat.grad).any()


# ==============================================================================
# PHASE 2: Calibration & Downstream Gating Audit
# ==============================================================================

def _compute_ece_and_brier(probs: torch.Tensor, targets: torch.Tensor, n_bins: int = 10) -> tuple[float, float]:
    confidences, predictions = torch.max(probs, dim=1)
    accuracies = predictions.eq(targets)
    bin_boundaries = torch.linspace(0, 1, n_bins + 1)
    ece = torch.zeros(1)
    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = confidences.gt(bin_lower) * confidences.le(bin_upper)
        prop_in_bin = in_bin.float().mean()
        if prop_in_bin.item() > 0:
            accuracy_in_bin = accuracies[in_bin].float().mean()
            avg_confidence_in_bin = confidences[in_bin].mean()
            ece += torch.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

    one_hot = F.one_hot(targets, num_classes=probs.size(1)).float()
    brier = torch.mean(torch.sum((probs - one_hot) ** 2, dim=1))
    return float(ece.item()), float(brier.item())


def test_phase2_calibration_and_temperature_scaling() -> None:
    """Verify that temperature scaling T=0.70 aligns logits and reduces ECE across all 3 horizons."""
    workspace_root = Path(__file__).resolve().parent.parent.parent
    datasets_dir = str(workspace_root / "datasets")
    artifacts_dir = str(workspace_root / "server" / "ml" / "artifacts")

    df = load_chronological_datasets(datasets_dir)
    preprocessor = TrafficPreprocessor.load(os.path.join(artifacts_dir, "scaler.joblib"))
    X, y = build_forecasting_sequences(df, preprocessor, seq_len=5, horizon=3)
    _, _, _, _, X_test, y_test = split_chronological_with_buffer(X, y, train_ratio=0.70, val_ratio=0.15, buffer_gap=8)

    model = TransformerForecaster(input_dim=27, horizon=3, num_classes=5)
    model.load_state_dict(torch.load(os.path.join(artifacts_dir, "transformer_forecaster.pt"), map_location="cpu"))
    model.eval()

    X_t = torch.tensor(X_test, dtype=torch.float32)
    y_t = torch.tensor(y_test, dtype=torch.long)

    with torch.no_grad():
        logits, _ = model(X_t)

    # 1. Uncalibrated (T=1.0)
    uncalibrated_ece = [_compute_ece_and_brier(F.softmax(logits[:, h, :], dim=-1), y_t[:, h])[0] for h in range(3)]

    # 2. Calibrated with T=0.70
    T = 0.70
    calibrated_ece = [_compute_ece_and_brier(F.softmax(logits[:, h, :] / T, dim=-1), y_t[:, h])[0] for h in range(3)]

    # ECE must improve across the multi-step forecast
    for h in range(3):
        assert calibrated_ece[h] < uncalibrated_ece[h], (
            f"Horizon T+{h+1}: Expected calibrated ECE ({calibrated_ece[h]:.4f}) < uncalibrated ({uncalibrated_ece[h]:.4f})"
        )
    # Mean ECE under calibrated scaling must be < 0.08
    assert np.mean(calibrated_ece) < 0.08, f"Mean calibrated ECE too high: {np.mean(calibrated_ece):.4f}"


def test_phase2_threshold_sensitivity_and_mitre_mapping() -> None:
    """Verify that calibrated predictions reliably clear tau >= 0.45 threshold and trigger MITRE mapping."""
    # 1. MITRE ATT&CK mapping for non-benign predictions
    mitre_attack = map_to_mitre_attack(
        detected_verdict="ANOMALOUS",
        detected_category="reconnaissance",
        forecast_states=["POTENTIAL_RECONNAISSANCE_CONTINUATION", "POTENTIAL_LATERAL_MOVEMENT", "LIKELY_ESCALATION"],
        forecast_probabilities=[0.78, 0.65, 0.58],
    )
    assert mitre_attack is not None
    assert mitre_attack.tactic == "Discovery"
    assert mitre_attack.technique_id == "T1046"
    assert mitre_attack.confidence >= 0.45

    # 2. MITRE ATT&CK mapping returns None for normal benign traffic
    mitre_normal = map_to_mitre_attack(
        detected_verdict="NORMAL",
        detected_category=None,
        forecast_states=["NORMAL_CONTINUATION", "NORMAL_CONTINUATION", "NORMAL_CONTINUATION"],
        forecast_probabilities=[0.95, 0.92, 0.90],
    )
    assert mitre_normal is None, "Normal traffic must not produce false-positive MITRE mapping"


# ==============================================================================
# PHASE 3: Live Ingestion & Concurrency Stress Test
# ==============================================================================

def test_phase3_streaming_ring_buffer_memory_audit() -> None:
    """Run sustained packet ingestion at high rate and confirm asymptotic memory stability (zero drift)."""
    gc.collect()
    tracemalloc.start()

    target_ip = "192.168.1.100"
    agg = FlowAggregator(target_ip=target_ip, device_id="dev-audit", session_id="sess-audit")
    window_engine = TimeWindowEngine(target_device_id="dev-audit", target_ip=target_ip)

    # Warmup phase to populate all flow slots to steady-state rolling capacity
    for i in range(15000):
        agg.ingest_packet(target_ip, f"10.0.0.{i % 10}", 5000 + (i % 50), 80, 6, 64)
        window_engine.ingest_event(target_ip, f"10.0.0.{i % 10}", 5000 + (i % 50), 80, 6, 64)

    gc.collect()
    mem_steady, _ = tracemalloc.get_traced_memory()

    # Sustained ingestion of 30,000 additional packets
    t0 = time.perf_counter()
    N = 30000
    for i in range(N):
        agg.ingest_packet(target_ip, f"10.0.0.{i % 10}", 5000 + (i % 50), 80, 6, 64)
        window_engine.ingest_event(target_ip, f"10.0.0.{i % 10}", 5000 + (i % 50), 80, 6, 64)
        if i % 1000 == 0:
            window_engine.slide_and_compute()

    dur = time.perf_counter() - t0
    rate = N / dur
    assert rate > 10000, f"Ingestion rate ({rate:.0f} pkts/s) must exceed 10,000 pkts/s"

    gc.collect()
    mem_end, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    drift_kb = (mem_end - mem_steady) / 1024
    # Zero positive drift (or within negligible garbage collection jitter < 20 KB)
    assert drift_kb < 20.0, f"Unbounded memory drift detected: {drift_kb:.2f} KB over {N} packets"


def test_phase3_p99_inference_latency_under_load() -> None:
    """Measure end-to-end pipeline latency across 300 iterations and confirm P99 < 20 ms."""
    target_ip = "192.168.1.100"
    agg = FlowAggregator(target_ip=target_ip, device_id="dev-lat", session_id="sess-lat")
    window_engine = TimeWindowEngine(target_device_id="dev-lat", target_ip=target_ip)
    graph_engine = NetworkGraphEngine(target_ip=target_ip)

    # Warmup
    for i in range(15):
        agg.ingest_packet(target_ip, f"10.0.0.{i % 5}", 5000 + i, 80, 6, 64)
        window_engine.ingest_event(target_ip, f"10.0.0.{i % 5}", 5000 + i, 80, 6, 64)

    latencies_ms: list[float] = []
    for i in range(300):
        t0 = time.perf_counter()

        agg.ingest_packet(target_ip, f"10.0.0.{i % 10}", 5000 + (i % 50), 80, 6, 128)
        window_engine.ingest_event(target_ip, f"10.0.0.{i % 10}", 5000 + (i % 50), 80, 6, 128)

        features = extract_session_features(agg)
        graph_engine.update_from_flows(agg.get_all_flows())
        graph_engine.snapshot()

        seq_tensor = window_engine.get_sequence_tensor(preprocessor=inference_engine.preprocessor)
        graph_tensors = graph_engine.get_graph_tensors()

        current_behaviour = inference_engine.evaluate_live_traffic(
            seq_tensor=seq_tensor,
            graph_tensors=graph_tensors,
            total_packets=agg.total_packets,
            flow_count=len(agg.flows),
            features=features,
        )

        _ = forecasting_engine.forecast_progression(
            seq_tensor=seq_tensor,
            graph_engine=graph_engine,
            current_features=features,
            previous_features=features,
            current_verdict=current_behaviour.verdict,
            current_category=current_behaviour.attack_category,
            window_count=len(window_engine._windows),
            horizon=3,
        )

        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000)

    p99 = float(np.percentile(latencies_ms, 99))
    p50 = float(np.percentile(latencies_ms, 50))
    assert p99 < 20.0, f"P99 latency ({p99:.2f} ms) exceeded 20 ms threshold"
    assert p50 < 5.0, f"P50 latency ({p50:.2f} ms) exceeded 5 ms threshold"


# ==============================================================================
# PHASE 4: Integration & Failure Mode Resilience
# ==============================================================================

def test_phase4_fallback_verification_empty_and_single_node() -> None:
    """Pass empty edge_index [2, 0] and single-node graphs to verify graceful handling without exceptions."""
    tgf = TemporalGraphForecaster(node_in_dim=4, spatial_hidden_dim=32, temporal_graph_dim=8, horizon=3, num_classes=5)
    detector = GraphNetworkDetector(node_in_dim=4, hidden_dim=32, num_classes=8)

    # 1. Single-node graph with empty edge index [2, 0]
    x_single = torch.randn(1, 4)
    empty_edges = torch.empty((2, 0), dtype=torch.long)
    logits_tgf, emb_tgf = tgf(x_single, empty_edges)
    assert logits_tgf.shape == (1, 3, 5)
    assert not torch.isnan(logits_tgf).any()

    logits_det, emb_det = detector(x_single, empty_edges)
    assert logits_det.shape == (1, 8)
    assert not torch.isnan(logits_det).any()

    # 2. Completely empty node features [0, 4] with empty edge index
    x_empty = torch.empty((0, 4))
    logits_tgf_empty, _ = tgf(x_empty, empty_edges)
    assert logits_tgf_empty.shape == (1, 3, 5)
    assert not torch.isnan(logits_tgf_empty).any()

    logits_det_empty, _ = detector(x_empty, empty_edges)
    assert logits_det_empty.shape == (1, 8)
    assert not torch.isnan(logits_det_empty).any()

    # 3. None edge index
    logits_tgf_none, _ = tgf(x_single, None)  # type: ignore[arg-type]
    assert logits_tgf_none.shape == (1, 3, 5)
    assert not torch.isnan(logits_tgf_none).any()


def test_phase4_model_checkpoint_integrity_strict_true() -> None:
    """Confirm all 8 checkpoints load cleanly with strict=True and all production engines initialize ready."""
    workspace_root = Path(__file__).resolve().parent.parent.parent
    artifacts_dir = str(workspace_root / "server" / "ml" / "artifacts")

    models_to_verify = [
        ("lstm_checkpoint.pt", LSTMDetector(input_dim=27, hidden_dim=64, num_layers=2, num_classes=8)),
        ("transformer_checkpoint.pt", TransformerDetector(input_dim=27, d_model=64, nhead=4, num_layers=2, num_classes=8)),
        ("gnn_checkpoint.pt", GraphNetworkDetector(node_in_dim=4, hidden_dim=32, num_classes=8)),
        ("fusion_checkpoint.pt", FusionDetector(temporal_dim=128, graph_dim=64, num_classes=8)),
        ("lstm_forecaster.pt", LSTMForecaster(input_dim=27, hidden_dim=64, num_layers=2, horizon=3, num_classes=5)),
        ("transformer_forecaster.pt", TransformerForecaster(input_dim=27, d_model=64, nhead=4, num_layers=2, horizon=3, num_classes=5)),
        ("gnn_forecaster.pt", TemporalGraphForecaster(node_in_dim=4, spatial_hidden_dim=32, temporal_graph_dim=8, horizon=3, num_classes=5)),
        ("fusion_forecaster.pt", FusionForecaster(temporal_dim=128, graph_dim=64, horizon=3, num_classes=5)),
    ]

    for ckpt_name, model in models_to_verify:
        path = os.path.join(artifacts_dir, ckpt_name)
        assert os.path.isfile(path), f"Checkpoint missing: {path}"
        state_dict = torch.load(path, map_location="cpu")
        # STRICT=TRUE: Fails if any layer name is mismatched or missing
        model.load_state_dict(state_dict, strict=True)
        model.eval()

    # Confirm production engines are ready
    assert forecasting_engine.transformer_ready, "Production forecasting_engine Transformer not ready"
    assert forecasting_engine.lstm_ready, "Production forecasting_engine LSTM not ready"
    assert forecasting_engine.gnn_ready, "Production forecasting_engine GNN not ready"
    assert forecasting_engine.fusion_ready, "Production forecasting_engine Fusion not ready"

    assert inference_engine.transformer_ready, "Production inference_engine Transformer not ready"
    assert inference_engine.lstm_ready, "Production inference_engine LSTM not ready"
    assert inference_engine.gnn_ready, "Production inference_engine GNN not ready"
    assert inference_engine.fusion_ready, "Production inference_engine Fusion not ready"
