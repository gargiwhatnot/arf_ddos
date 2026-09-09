"""Feature adapter for the supplied CICFlowMeter-style attack-type ARF.

The external ``arf_v6_balanced.pkl`` checkpoint was trained with lower-case
CICFlowMeter-style feature names and microsecond time values.  These helpers
build that exact input schema from a controller flow window.  They do not make
the attack-only model a Normal-versus-DDoS detector.
"""

from __future__ import annotations

from typing import Iterable, Mapping

from .pipeline import as_float


ATTACK_TYPE_FEATURES = (
    "ack_flag_count",
    "average_packet_size",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_packet_length_max",
    "bwd_packet_length_mean",
    "bwd_packet_length_min",
    "bwd_packet_length_std",
    "bwd_packets/s",
    "flow_bytes/s",
    "flow_duration",
    "flow_iat_max",
    "flow_iat_mean",
    "flow_iat_min",
    "flow_iat_std",
    "flow_packets/s",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_packet_length_max",
    "fwd_packet_length_mean",
    "fwd_packet_length_min",
    "fwd_packet_length_std",
    "fwd_packets/s",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "rst_flag_count",
    "total_backward_packets",
    "total_fwd_packets",
    "total_length_of_bwd_packets",
    "total_length_of_fwd_packets",
)

_MICROSECONDS_PER_SECOND = 1_000_000.0


def _stats(values: Iterable[float]) -> tuple[float, float, float, float]:
    materialized = [as_float(value) for value in values]
    if not materialized:
        return 0.0, 0.0, 0.0, 0.0
    mean = sum(materialized) / len(materialized)
    variance = (
        sum((value - mean) ** 2 for value in materialized)
        / (len(materialized) - 1)
        if len(materialized) > 1
        else 0.0
    )
    return mean, variance**0.5, max(materialized), min(materialized)


def _microseconds(value: float) -> float:
    return max(as_float(value), 0.0) * _MICROSECONDS_PER_SECOND


def build_attack_type_features(
    raw_features: Mapping[str, object],
    *,
    fwd_lengths: Iterable[float],
    bwd_lengths: Iterable[float],
    all_iats_seconds: Iterable[float],
    fwd_iats_seconds: Iterable[float],
    bwd_iats_seconds: Iterable[float],
) -> dict[str, float]:
    """Return all 31 fields expected by the attack-type checkpoint.

    Durations and inter-arrival times are converted to microseconds because
    the supplied checkpoint's split thresholds use CICFlowMeter time units.
    Packet sizes come from the controller's captured frame lengths, so this is
    a compatible demonstration adapter rather than a claim of dataset-perfect
    CICFlowMeter reproduction.
    """

    fwd_lengths = list(fwd_lengths)
    bwd_lengths = list(bwd_lengths)
    packet_lengths = fwd_lengths + bwd_lengths
    all_iats_seconds = list(all_iats_seconds)
    fwd_iats_seconds = list(fwd_iats_seconds)
    bwd_iats_seconds = list(bwd_iats_seconds)

    fwd_mean, fwd_std, fwd_max, fwd_min = _stats(fwd_lengths)
    bwd_mean, bwd_std, bwd_max, bwd_min = _stats(bwd_lengths)
    pkt_mean, pkt_std, _, _ = _stats(packet_lengths)
    iat_mean, iat_std, iat_max, iat_min = _stats(all_iats_seconds)
    fwd_iat_mean, fwd_iat_std, _, _ = _stats(fwd_iats_seconds)
    bwd_iat_mean, bwd_iat_std, _, _ = _stats(bwd_iats_seconds)

    duration = max(as_float(raw_features.get("duration")), 0.0)
    total_fwd = len(fwd_lengths)
    total_bwd = len(bwd_lengths)
    total_packets = total_fwd + total_bwd
    total_bytes = sum(packet_lengths)

    result = {
        "ack_flag_count": as_float(raw_features.get("ack_count")),
        "average_packet_size": total_bytes / total_packets if total_packets else 0.0,
        "bwd_iat_mean": _microseconds(bwd_iat_mean),
        "bwd_iat_std": _microseconds(bwd_iat_std),
        "bwd_packet_length_max": bwd_max,
        "bwd_packet_length_mean": bwd_mean,
        "bwd_packet_length_min": bwd_min,
        "bwd_packet_length_std": bwd_std,
        "bwd_packets/s": total_bwd / duration if duration else 0.0,
        "flow_bytes/s": total_bytes / duration if duration else 0.0,
        "flow_duration": _microseconds(duration),
        "flow_iat_max": _microseconds(iat_max),
        "flow_iat_mean": _microseconds(iat_mean),
        "flow_iat_min": _microseconds(iat_min),
        "flow_iat_std": _microseconds(iat_std),
        "flow_packets/s": total_packets / duration if duration else 0.0,
        "fwd_iat_mean": _microseconds(fwd_iat_mean),
        "fwd_iat_std": _microseconds(fwd_iat_std),
        "fwd_packet_length_max": fwd_max,
        "fwd_packet_length_mean": fwd_mean,
        "fwd_packet_length_min": fwd_min,
        "fwd_packet_length_std": fwd_std,
        "fwd_packets/s": total_fwd / duration if duration else 0.0,
        "packet_length_mean": pkt_mean,
        "packet_length_std": pkt_std,
        "packet_length_variance": pkt_std**2,
        "rst_flag_count": as_float(raw_features.get("rst_count")),
        "total_backward_packets": float(total_bwd),
        "total_fwd_packets": float(total_fwd),
        "total_length_of_bwd_packets": float(sum(bwd_lengths)),
        "total_length_of_fwd_packets": float(sum(fwd_lengths)),
    }
    return {name: as_float(result[name]) for name in ATTACK_TYPE_FEATURES}


__all__ = ["ATTACK_TYPE_FEATURES", "build_attack_type_features"]
