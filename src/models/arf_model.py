"""
Adaptive Random Forest (ARF) model utilities:
- Canonical feature list
- Row canonicalization
- Lightweight streaming scaler
"""

import numpy as np
from typing import Dict

# Explicit canonical feature list (align with dataset cleaning script)
CANONICAL_FEATURES = [
    "ACK Flag Count", "URG Flag Count", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "Average Packet Size",
    "Fwd Packet Length Min", "Fwd Packet Length Max", "Fwd Packet Length Mean",
    "Bwd Packet Length Min", "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Duration", "Flow Bytes/s", "Fwd Packets/s", "Bwd Packets/s",
    "Flow IAT Max", "Bwd IAT Total", "Bwd IAT Mean",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Flow IAT Std",
    "RST Flag Count", "Total Fwd Packets"
]


FEATURE_ALIASES = {
    "ACK Flag Count": "ack_count",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_variance",
    "Average Packet Size": "avg_pkt_size",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Total Backward Packets": "bwd_pkts",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Flow Duration": "duration",
    "Flow Bytes/s": "flow_bytes_s",
    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",
    "Flow IAT Max": "iat_max",
    "Bwd IAT Total": "bwd_iat_total",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Avg Fwd Segment Size": "fwd_pkt_len_mean",
    "Avg Bwd Segment Size": "bwd_pkt_len_mean",
    "Flow IAT Std": "iat_std",
    "RST Flag Count": "rst_count",
    "Total Fwd Packets": "fwd_pkts",
}


def canonicalize_row(row: Dict[str, float]) -> Dict[str, float]:
    """
    Ensure a row has all canonical features with float values.
    Missing features default to 0.0.
    """
    return {
        feature: float(row.get(feature, row.get(FEATURE_ALIASES.get(feature, ""), 0.0)))
        for feature in CANONICAL_FEATURES
    }


class StandardFeatureScaler:
    """
    Lightweight online scaler for normalization.
    Tracks running mean and std for each feature.
    """
    def __init__(self):
        self.means = {f: 0.0 for f in CANONICAL_FEATURES}
        self.stds = {f: 1.0 for f in CANONICAL_FEATURES}
        self.count = 0

    def learn_one(self, row: Dict[str, float]) -> None:
        """
        Update running mean/std with a new row.
        """
        self.count += 1
        for f in CANONICAL_FEATURES:
            val = row.get(f, 0.0)
            delta = val - self.means[f]
            self.means[f] += delta / self.count
            # crude std update (replace with Welford for precision if needed)
            self.stds[f] = max(self.stds[f], np.std([val, self.means[f]]))

    def transform(self, row: Dict[str, float]) -> Dict[str, float]:
        """
        Normalize a row using current mean/std.
        """
        return {
            f: (row.get(f, 0.0) - self.means[f]) / (self.stds[f] if self.stds[f] else 1.0)
            for f in CANONICAL_FEATURES
        }


__all__ = ["CANONICAL_FEATURES", "canonicalize_row", "StandardFeatureScaler"]
