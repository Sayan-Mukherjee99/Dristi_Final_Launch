# Drishti v0.1 — enterprise fleet communication graph & lateral movement engine | Phase 04
from __future__ import annotations

import logging
import time
from typing import Any
import networkx as nx
import numpy as np
try:
    import torch
except ImportError:
    torch = None

from app.services.traffic.session_manager import ActiveTrackingSession

logger = logging.getLogger("drishti")

# Known lateral movement administrative and remote execution ports
LATERAL_PORTS = {
    22: "SSH",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
}


class FleetGraphEngine:
    """Maintains an enterprise communication topology across all paired devices in the fleet.

    Detects cross-device lateral movement, host-to-host pivoting (CAPEC-292),
    and sparse topological dynamics across the fleet.
    """

    def __init__(self) -> None:
        self.fleet_graph = nx.DiGraph()
        self._last_update: float = 0.0

    def update_from_fleet_sessions(
        self, sessions: list[ActiveTrackingSession]
    ) -> list[dict[str, Any]]:
        """Constructs/updates enterprise fleet graph from all active paired sessions.

        Returns detected lateral movement pivot events between paired endpoints.
        """
        self.fleet_graph.clear()
        paired_ips = {s.target_ip: s.device_id for s in sessions if s.target_ip}
        lateral_events: list[dict[str, Any]] = []

        # 1. Register all paired devices as primary nodes
        for s in sessions:
            ip = s.target_ip
            if not ip:
                continue
            det = s.last_detection
            verdict = det.verdict if det else "INSUFFICIENT_DATA"
            risk = s.last_forecast.composite_risk_score if s.last_forecast else 0.0

            self.fleet_graph.add_node(
                ip,
                device_id=s.device_id,
                hostname=s.target_hostname or ip,
                is_paired=True,
                verdict=verdict,
                risk_score=risk,
                packet_count=s.aggregator.total_packets,
                byte_count=s.aggregator.total_bytes,
            )

        # 2. Add edges from all observed flows across all sessions
        for s in sessions:
            flows = s.aggregator.get_all_flows()
            for f in flows:
                src, dst = f.src_ip.strip(), f.dst_ip.strip()
                if not src or not dst:
                    continue

                for node_ip in (src, dst):
                    if not self.fleet_graph.has_node(node_ip):
                        self.fleet_graph.add_node(
                            node_ip,
                            device_id=paired_ips.get(node_ip),
                            hostname=node_ip,
                            is_paired=(node_ip in paired_ips),
                            verdict="EXTERNAL",
                            risk_score=0.0,
                            packet_count=0,
                            byte_count=0,
                        )

                # Edge attribution
                if not self.fleet_graph.has_edge(src, dst):
                    self.fleet_graph.add_edge(
                        src,
                        dst,
                        packets=0,
                        bytes=0,
                        ports=set(),
                        is_internal_pivot=False,
                    )

                edge = self.fleet_graph.edges[src, dst]
                edge["packets"] += f.total_packets
                edge["bytes"] += f.total_bytes
                edge["ports"].add(f.dst_port)

                # Check for cross-device lateral movement between two paired hosts
                if src in paired_ips and dst in paired_ips and src != dst:
                    edge["is_internal_pivot"] = True
                    src_sess = next((x for x in sessions if x.target_ip == src), None)
                    src_verdict = src_sess.last_detection.verdict if (src_sess and src_sess.last_detection) else "NORMAL"
                    src_risk = src_sess.last_forecast.composite_risk_score if (src_sess and src_sess.last_forecast) else 0.0

                    service_name = LATERAL_PORTS.get(f.dst_port, "TCP-Socket")
                    is_suspicious_pivot = src_verdict in ("ANOMALOUS", "SUSPICIOUS") or src_risk >= 4.0 or f.dst_port in LATERAL_PORTS

                    lateral_events.append({
                        "source_device_id": paired_ips[src],
                        "source_ip": src,
                        "source_verdict": src_verdict,
                        "destination_device_id": paired_ips[dst],
                        "destination_ip": dst,
                        "port": f.dst_port,
                        "service": service_name,
                        "is_suspicious_pivot": is_suspicious_pivot,
                        "mitre_tactic": "Lateral Movement",
                        "mitre_technique_id": "T1021",
                        "mitre_technique_name": "Remote Services",
                        "capec_id": "CAPEC-292",
                    })

        self._last_update = time.time()
        return lateral_events

    def get_sparse_fleet_tensors(self) -> tuple[Any, Any]:
        """Converts enterprise fleet graph into PyTorch (node_features, edge_index) tensors.

        node_features shape: [N_nodes, 4] -> [is_paired, log(packets+1), log(bytes+1), degree]
        edge_index shape: [2, E]
        """
        nodes = list(self.fleet_graph.nodes())
        n = len(nodes)
        if n == 0:
            if torch is None:
                return np.zeros((0, 4), dtype=np.float32), np.zeros((2, 0), dtype=np.int64)
            return torch.zeros((0, 4), dtype=torch.float32), torch.empty((2, 0), dtype=torch.long)

        node_idx = {node: i for i, node in enumerate(nodes)}

        # Node features: [N, 4]
        x = np.zeros((n, 4), dtype=np.float32)
        for i, node in enumerate(nodes):
            data = self.fleet_graph.nodes[node]
            x[i, 0] = 1.0 if data.get("is_paired", False) else 0.0
            x[i, 1] = np.log1p(float(data.get("packet_count", 0)))
            x[i, 2] = np.log1p(float(data.get("byte_count", 0)))
            x[i, 3] = float(self.fleet_graph.degree(node))

        # Sparse edge index: [2, E]
        edges = list(self.fleet_graph.edges())
        if not edges:
            edge_index = np.zeros((2, 0), dtype=np.int64)
        else:
            edge_index = np.array(
                [[node_idx[u], node_idx[v]] for u, v in edges],
                dtype=np.int64,
            ).T

        if torch is None:
            return x, edge_index
        return torch.tensor(x, dtype=torch.float32), torch.tensor(edge_index, dtype=torch.long)


# Global singleton fleet graph engine
fleet_graph_engine = FleetGraphEngine()
