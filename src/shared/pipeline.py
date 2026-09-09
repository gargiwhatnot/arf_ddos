"""Shared feature and label handling.

The offline CIC-DDoS2019 files and the live controller do not use exactly the
same column names.  This module converts both inputs to one small, stable
feature schema so that a model trained offline can be used by the controller.
"""

from __future__ import annotations

import math
import re
from typing import Any, Mapping


CANONICAL_FEATURES = [
    "count",
    "bytes",
    "bytes_norm",
    "duration",
    "flow_pkts_s",
    "flow_bytes_s",
    "avg_pkt_size",
    "fwd_pkts",
    "bwd_pkts",
    "fwd_bytes",
    "bwd_bytes",
    "syn_count",
    "ack_count",
    "rst_count",
    "fwd_iat_mean",
    "fwd_iat_std",
    "bwd_iat_mean",
    "bwd_iat_std",
    "pkt_len_mean",
    "pkt_len_std",
    "iat_mean",
    "iat_std",
    "iat_max",
    "iat_min",
]


def _normal_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def _lookup(row: Mapping[str, Any], *names: str) -> Any:
    normalized = {_normal_key(key): value for key, value in row.items()}
    for name in names:
        key = _normal_key(name)
        if key in normalized:
            return normalized[key]
    return None


def as_float(value: Any, default: float = 0.0) -> float:
    """Convert a dataset/controller value to a finite float."""

    if value is None:
        return default
    try:
        number = float(str(value).strip().replace(",", ""))
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _first_number(row: Mapping[str, Any], *names: str) -> float:
    value = _lookup(row, *names)
    return as_float(value)


def _duration_seconds(row: Mapping[str, Any]) -> float:
    value = _lookup(row, "duration", "Flow Duration", "flow_duration")
    duration = as_float(value)

    # CICFlowMeter's Flow Duration is normally microseconds, while the live
    # collector already supplies seconds.  This keeps both representations
    # compatible without requiring a separate conversion step.
    if duration > 1000.0:
        return duration / 1_000_000.0
    return max(duration, 0.0)


def canonicalize_row(row: Mapping[str, Any]) -> dict[str, float]:
    """Return one numeric row shared by the dataset and live controller.

    Missing fields are represented by zero.  This is intentional: the
    controller only observes packet-level information available in its lab,
    while CICFlowMeter may provide additional columns offline.
    """

    fwd_pkts = _first_number(
        row,
        "fwd_pkts",
        "Total Fwd Packets",
        "Tot Fwd Pkts",
    )
    bwd_pkts = _first_number(
        row,
        "bwd_pkts",
        "Total Backward Packets",
        "Tot Bwd Pkts",
    )
    fwd_bytes = _first_number(
        row,
        "fwd_bytes",
        "Total Length of Fwd Packets",
        "Fwd Packet Length Total",
    )
    bwd_bytes = _first_number(
        row,
        "bwd_bytes",
        "Total Length of Bwd Packets",
        "Bwd Packet Length Total",
    )

    count_value = _lookup(row, "count", "total_packets", "total_pkts")
    count = as_float(count_value) if count_value is not None else fwd_pkts + bwd_pkts

    bytes_value = _lookup(row, "bytes", "total_bytes", "packet_bytes")
    total_bytes = (
        as_float(bytes_value)
        if bytes_value is not None
        else fwd_bytes + bwd_bytes
    )

    duration = _duration_seconds(row)

    flow_pkts_s = _first_number(
        row,
        "flow_pkts_s",
        "Flow Packets/s",
        "Flow Packets Per Second",
    )
    if flow_pkts_s == 0.0 and duration > 0.0:
        flow_pkts_s = count / duration

    flow_bytes_s = _first_number(
        row,
        "flow_bytes_s",
        "Flow Bytes/s",
        "Flow Bytes Per Second",
    )
    if flow_bytes_s == 0.0 and duration > 0.0:
        flow_bytes_s = total_bytes / duration

    avg_pkt_size = _first_number(
        row,
        "avg_pkt_size",
        "Average Packet Size",
        "Avg Bwd Segment Size",
    )
    if avg_pkt_size == 0.0 and count > 0.0:
        avg_pkt_size = total_bytes / count

    result = {
        "count": count,
        "bytes": total_bytes,
        "bytes_norm": _first_number(row, "bytes_norm") or total_bytes / 1500.0,
        "duration": duration,
        "flow_pkts_s": flow_pkts_s,
        "flow_bytes_s": flow_bytes_s,
        "avg_pkt_size": avg_pkt_size,
        "fwd_pkts": fwd_pkts,
        "bwd_pkts": bwd_pkts,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "syn_count": _first_number(row, "syn_count", "SYN Flag Count"),
        "ack_count": _first_number(row, "ack_count", "ACK Flag Count"),
        "rst_count": _first_number(row, "rst_count", "RST Flag Count"),
        "fwd_iat_mean": _first_number(row, "fwd_iat_mean", "Fwd IAT Mean"),
        "fwd_iat_std": _first_number(row, "fwd_iat_std", "Fwd IAT Std"),
        "bwd_iat_mean": _first_number(row, "bwd_iat_mean", "Bwd IAT Mean"),
        "bwd_iat_std": _first_number(row, "bwd_iat_std", "Bwd IAT Std"),
        "pkt_len_mean": _first_number(row, "pkt_len_mean", "Packet Length Mean"),
        "pkt_len_std": _first_number(row, "pkt_len_std", "Packet Length Std"),
        "iat_mean": _first_number(row, "iat_mean", "Flow IAT Mean"),
        "iat_std": _first_number(row, "iat_std", "Flow IAT Std"),
        "iat_max": _first_number(row, "iat_max", "Flow IAT Max"),
        "iat_min": _first_number(row, "iat_min", "Flow IAT Min"),
    }

    return {name: as_float(result.get(name)) for name in CANONICAL_FEATURES}


def normalize_label(label: Any, binary: bool = True) -> str:
    """Normalize dataset/model labels for the project.

    In binary mode every non-benign label is treated as DDoS.  This supports
    the many attack names in CIC-DDoS2019 while keeping the controller output
    simple: Normal versus DDoS.
    """

    raw = "" if label is None else str(label).strip()
    normalized = _normal_key(raw)

    if not binary:
        return raw or "UNKNOWN"

    normal_values = {
        "0",
        "benign",
        "normal",
        "normaltraffic",
        "background",
    }
    if normalized in normal_values or "benign" in normalized:
        return "Normal"
    return "DDoS"


def row_label(row: Mapping[str, Any], binary: bool = True) -> str:
    label = _lookup(row, "Label", "label", "class", "target")
    return normalize_label(label, binary=binary)


def is_attack_label(label: Any) -> bool:
    return normalize_label(label, binary=True) == "DDoS"
