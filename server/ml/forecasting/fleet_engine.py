# Drishti v0.1 — batched fleet neural forecasting engine | Phase 04 Fleet Paired Devices
from __future__ import annotations

import logging
from typing import Any
import numpy as np
import torch
import torch.nn.functional as F

from app.schemas.tracking import (
    CurrentBehaviourOut,
    ForecastResultOut,
    ForecastStepOut,
)
from app.services.traffic.feature_extractor import extract_session_features
from app.services.traffic.session_manager import ActiveTrackingSession
from ml.forecasting.engine import FORECAST_IDX_TO_LABEL, forecasting_engine
from ml.forecasting.explainability import generate_forecast_explanation
from ml.forecasting.mitre_mapping import map_to_mitre_attack
from ml.forecasting.risk_engine import calculate_composite_risk
from ml.inference.engine import inference_engine

logger = logging.getLogger("drishti")


class FleetForecastingEngine:
    """Executes high-throughput batched deep learning forward passes across multiple
    concurrent paired devices in a single fused GEMM kernel.
    """

    def __init__(self) -> None:
        pass

    def evaluate_fleet_batch(
        self,
        sessions: list[ActiveTrackingSession],
    ) -> dict[str, dict[str, Any]]:
        """Batched forward pass over N active paired devices.

        Returns mapping:
          device_id -> {
            "detection": CurrentBehaviourOut,
            "forecast": ForecastResultOut,
          }
        """
        if not sessions:
            return {}

        results: dict[str, dict[str, Any]] = {}
        seq_tensors: list[torch.Tensor] = []
        features_list: list[dict[str, float]] = []
        valid_sessions: list[ActiveTrackingSession] = []

        # 1. Prepare inputs per device
        for sess in sessions:
            try:
                # Update graph topology with observed flows
                sess.graph_engine.update_from_flows(sess.aggregator.get_all_flows())
                sess.graph_engine.snapshot()

                # Extract features and sliding sequence tensor
                feats = extract_session_features(sess.aggregator)
                seq_t = sess.window_engine.get_sequence_tensor(preprocessor=inference_engine.preprocessor)
                if not isinstance(seq_t, torch.Tensor):
                    seq_t = torch.tensor(seq_t, dtype=torch.float32)

                # Detection forward pass (per-device evaluated)
                graph_tensors = sess.graph_engine.get_graph_tensors()
                detection = inference_engine.evaluate_live_traffic(
                    seq_tensor=seq_t,
                    graph_tensors=graph_tensors,
                    total_packets=sess.aggregator.total_packets,
                    flow_count=len(sess.aggregator.flows),
                    features=feats,
                )
                sess.last_detection = detection

                seq_tensors.append(seq_t)
                features_list.append(feats)
                valid_sessions.append(sess)
            except Exception as ex:
                logger.warning("Error preparing device %s for fleet batch: %s", sess.device_id, ex)

        if not valid_sessions:
            return {}

        # 2. Batched Neural Forecast Pass: [B=N, seq_len=5, feature_dim=27]
        batch_seq = torch.cat(seq_tensors, dim=0)
        batch_probs: np.ndarray | None = None
        model_name = "TRANSFORMER_FORECASTER"
        temp = forecasting_engine.temperature

        try:
            with torch.no_grad():
                if forecasting_engine.transformer_ready and forecasting_engine.transformer_forecaster is not None:
                    logits, _ = forecasting_engine.transformer_forecaster(batch_seq)
                    scaled_logits = logits / max(0.01, temp)
                    batch_probs = F.softmax(scaled_logits, dim=-1).cpu().numpy()
                    model_name = "TRANSFORMER_FORECASTER"
                elif forecasting_engine.lstm_ready and forecasting_engine.lstm_forecaster is not None:
                    logits, _ = forecasting_engine.lstm_forecaster(batch_seq)
                    scaled_logits = logits / max(0.01, temp)
                    batch_probs = F.softmax(scaled_logits, dim=-1).cpu().numpy()
                    model_name = "LSTM_FORECASTER"
        except Exception as ex:
            logger.warning("Fleet batched neural pass failed: %s", ex)

        # 3. Formulate per-device forecasting results
        for idx, sess in enumerate(valid_sessions):
            feats = features_list[idx]
            detection = sess.last_detection or CurrentBehaviourOut(verdict="INSUFFICIENT_DATA", confidence=0.0)
            window_count = len(sess.window_engine._windows)

            if batch_probs is None or window_count < 2:
                # Gating fallback for insufficient history or inference failure
                fallback_forecast = ForecastResultOut(
                    is_available=False,
                    status="FORECAST UNAVAILABLE (INSUFFICIENT HISTORY)" if window_count < 2 else "FORECAST ERROR",
                    horizon_steps=[],
                    mitre_attack=None,
                    explainability=None,
                    composite_risk_score=0.0,
                    composite_risk_level="LOW",
                    model_used="NONE",
                )
                sess.last_forecast = fallback_forecast
                results[sess.device_id] = {
                    "detection": detection,
                    "forecast": fallback_forecast,
                }
                continue

            dev_dist = batch_probs[idx]  # [horizon=3, num_classes=5]
            graph_dynamics = sess.graph_engine.get_graph_dynamics_summary()

            horizon_steps_out: list[ForecastStepOut] = []
            forecast_state_names: list[str] = []
            forecast_probabilities: list[float] = []

            pps = feats.get("flow_packets_per_sec", 0.0)
            syn_count = feats.get("flag_syn_count", 0.0)
            unique_ports = int(feats.get("port_scan_score", 0))
            entropy = feats.get("payload_entropy", 0.0)

            for h in range(min(3, len(dev_dist))):
                step_name = f"T+{h+1}"
                step_dist = dev_dist[h]

                if (pps > 600.0 or syn_count > 150) and detection.verdict == "ANOMALOUS":
                    pred_class = "LIKELY_ESCALATION"
                    prob = float(min(0.96, max(step_dist[2], 0.78 - (h * 0.08))))
                elif unique_ports >= 4 and detection.verdict in ("ANOMALOUS", "SUSPICIOUS"):
                    pred_class = "POTENTIAL_RECONNAISSANCE_CONTINUATION"
                    prob = float(min(0.92, max(step_dist[4], 0.75 - (h * 0.07))))
                elif entropy > 7.1 and detection.verdict in ("ANOMALOUS", "SUSPICIOUS"):
                    pred_class = "POTENTIAL_LATERAL_MOVEMENT"
                    prob = float(min(0.88, max(step_dist[3], 0.68 - (h * 0.06))))
                else:
                    pred_idx = int(np.argmax(step_dist))
                    prob = float(step_dist[pred_idx])
                    pred_class = FORECAST_IDX_TO_LABEL.get(pred_idx, "NORMAL_CONTINUATION")

                step_signals = []
                if pred_class == "NORMAL_CONTINUATION":
                    step_signals.append("Traffic trajectory aligns with stable benign baseline")
                elif pred_class == "POTENTIAL_RECONNAISSANCE_CONTINUATION":
                    step_signals.append("Sequential destination probing expected to persist")
                elif pred_class == "LIKELY_ESCALATION":
                    step_signals.append("Volumetric flood or connection surge trajectory")
                elif pred_class == "POTENTIAL_LATERAL_MOVEMENT":
                    step_signals.append("High-entropy internal host-to-host pivoting risk")
                elif pred_class == "SUSPICIOUS_CONTINUATION":
                    step_signals.append("Sustained elevated anomalous connection retries")

                horizon_steps_out.append(
                    ForecastStepOut(
                        step=step_name,
                        state=pred_class,
                        probability=round(prob, 2),
                        status_label="PREDICTED",
                        contributing_signals=step_signals,
                    )
                )
                forecast_state_names.append(pred_class)
                forecast_probabilities.append(round(prob, 2))

            status_label = "FORECAST_READY"
            if all(p < 0.35 for p in forecast_probabilities):
                status_label = "LOW-CONFIDENCE FORECAST"

            # Deterministic MITRE ATT&CK & CAPEC mapping
            mitre_res = map_to_mitre_attack(
                detected_verdict=detection.verdict,
                detected_category=detection.attack_category,
                forecast_states=forecast_state_names,
                forecast_probabilities=forecast_probabilities,
            )

            # Explainability & Risk Scoring
            top_state = forecast_state_names[0] if forecast_state_names else "NORMAL_CONTINUATION"
            top_prob = forecast_probabilities[0] if forecast_probabilities else 0.5
            explain_res = generate_forecast_explanation(
                current_features=feats,
                previous_features=sess.previous_features,
                graph_dynamics=graph_dynamics,
                current_verdict=detection.verdict,
                top_forecast_state=top_state,
                top_probability=top_prob,
            )

            risk_score, risk_level, risk_formula = calculate_composite_risk(
                detected_verdict=detection.verdict,
                detected_category=detection.attack_category,
                forecast_steps=[s.model_dump() for s in horizon_steps_out],
                graph_dynamics=graph_dynamics,
            )

            sess.previous_features = dict(feats)
            forecast_out = ForecastResultOut(
                is_available=True,
                status=status_label,
                horizon_steps=horizon_steps_out,
                mitre_attack=mitre_res,
                explainability=explain_res,
                composite_risk_score=risk_score,
                composite_risk_level=risk_level,
                risk_formula=risk_formula,
                model_used=model_name,
            )
            sess.last_forecast = forecast_out

            results[sess.device_id] = {
                "detection": detection,
                "forecast": forecast_out,
            }

        return results


# Global singleton fleet forecasting engine
fleet_forecasting_engine = FleetForecastingEngine()
