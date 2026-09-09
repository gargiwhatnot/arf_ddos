"""PacketIn flow aggregation and live ARF inference for the SDN controller."""

from __future__ import annotations

import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Iterable, Mapping

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    from scapy.all import Ether, IP, TCP, UDP
except ImportError:  # pragma: no cover - the controller VM supplies Scapy
    Ether = IP = TCP = UDP = None

from preprocessing import Preprocessor
from shared.attack_type_features import build_attack_type_features
from shared.attack_type_runtime import AttackTypeARF
from shared.arf_runtime import ARFDetector


logger = logging.getLogger("TrafficCollector")
logger.setLevel(logging.INFO)

_detector: ARFDetector | None = None
_detector_attempted = False
_attack_type_detector: AttackTypeARF | None = None
_attack_type_detector_attempted = False
_preprocessor = Preprocessor()


def configure(model_path: str | None = None, attack_threshold: float = 0.70) -> None:
    """Configure or disable the live ARF detector."""

    global _detector, _detector_attempted
    _detector_attempted = True
    if not model_path:
        _detector = None
        _preprocessor.set_scaler(None)
        logger.info("ARF detector disabled; feature collection remains active")
        return
    detector = ARFDetector(model_path, attack_threshold=attack_threshold)
    _detector = detector
    _preprocessor.set_scaler(detector.scaler)
    logger.info("ARF detector loaded from %s", model_path)


def configure_attack_type(model_path: str | None = None) -> None:
    """Configure the attack-family demo model without enabling mitigation."""

    global _attack_type_detector, _attack_type_detector_attempted
    _attack_type_detector_attempted = True
    if not model_path:
        _attack_type_detector = None
        logger.info("Attack-type ARF demo disabled")
        return
    _attack_type_detector = AttackTypeARF(model_path)
    logger.info(
        "Attack-type ARF demo loaded from %s; labels=%s; mitigation remains disabled",
        model_path,
        ",".join(_attack_type_detector.class_labels) or "unknown",
    )


def _timestamp(record: Mapping[str, Any]) -> float:
    try:
        return float(record.get("timestamp", time.time()))
    except (TypeError, ValueError):
        return time.time()


def _endpoint(src: str, sport: int, dst: str, dport: int) -> tuple:
    left = (src, int(sport or 0))
    right = (dst, int(dport or 0))
    return tuple(sorted((left, right)))


def _stats(values: Iterable[float]) -> tuple[float, float, float, float]:
    values = list(values)
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    mean = sum(values) / len(values)
    variance = (
        sum((value - mean) ** 2 for value in values) / (len(values) - 1)
        if len(values) > 1
        else 0.0
    )
    return mean, variance**0.5, max(values), min(values)


class TrafficCollector:
    """Build short, bidirectional flow windows from raw PacketIn records."""

    def collect(self, records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        if Ether is None:
            raise RuntimeError(
                "Scapy is required for packet parsing. Install project dependencies first."
            )

        flows: dict[tuple, dict[str, Any]] = {}

        for record in records:
            raw_hex = record.get("raw_data")
            if not raw_hex:
                continue
            try:
                raw_bytes = bytes.fromhex(str(raw_hex))
                packet = Ether(raw_bytes)
            except Exception:
                continue

            if not packet.haslayer(IP):
                continue

            ip = packet[IP]
            proto = int(ip.proto)
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            src_port = 0
            dst_port = 0
            syn = ack = rst = 0

            if proto == 6 and packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                flags = int(tcp.flags)
                syn = int(bool(flags & 0x02))
                ack = int(bool(flags & 0x10))
                rst = int(bool(flags & 0x04))
            elif proto == 17 and packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

            key = (_endpoint(src_ip, src_port, dst_ip, dst_port), proto)
            timestamp = _timestamp(record)
            current_endpoint = (src_ip, src_port)

            if key not in flows:
                flows[key] = {
                    "origin_endpoint": current_endpoint,
                    "origin_src": src_ip,
                    "origin_dst": dst_ip,
                    "origin_sport": src_port,
                    "origin_dport": dst_port,
                    "proto": proto,
                    "timestamps": [],
                    "fwd_lengths": [],
                    "bwd_lengths": [],
                    "fwd_iats": [],
                    "bwd_iats": [],
                    "all_iats": [],
                    "last_direction_timestamp": {},
                    "syn_count": 0,
                    "ack_count": 0,
                    "rst_count": 0,
                    "dpid": record.get("dpid"),
                    "in_port": record.get("in_port"),
                }

            flow = flows[key]
            direction = (
                "fwd" if current_endpoint == flow["origin_endpoint"] else "bwd"
            )
            packet_length = len(raw_bytes)

            if flow["timestamps"]:
                flow["all_iats"].append(timestamp - flow["timestamps"][-1])
            previous_direction_timestamp = flow["last_direction_timestamp"].get(direction)
            if previous_direction_timestamp is not None:
                flow[f"{direction}_iats"].append(
                    timestamp - previous_direction_timestamp
                )

            flow["timestamps"].append(timestamp)
            flow["last_direction_timestamp"][direction] = timestamp
            flow[f"{direction}_lengths"].append(packet_length)
            flow["syn_count"] += syn
            flow["ack_count"] += ack
            flow["rst_count"] += rst

        output = []
        for flow in flows.values():
            timestamps = flow["timestamps"]
            if not timestamps:
                continue

            duration = max(timestamps[-1] - timestamps[0], 0.0)
            fwd_lengths = flow["fwd_lengths"]
            bwd_lengths = flow["bwd_lengths"]
            packet_lengths = fwd_lengths + bwd_lengths
            all_iats = flow["all_iats"]
            fwd_iat_mean, fwd_iat_std, _, _ = _stats(flow["fwd_iats"])
            bwd_iat_mean, bwd_iat_std, _, _ = _stats(flow["bwd_iats"])
            pkt_len_mean, pkt_len_std, _, _ = _stats(packet_lengths)
            iat_mean, iat_std, iat_max, iat_min = _stats(all_iats)

            total_fwd = len(fwd_lengths)
            total_bwd = len(bwd_lengths)
            total_bytes = sum(packet_lengths)
            total_packets = total_fwd + total_bwd

            raw_features = {
                "count": total_packets,
                "bytes": total_bytes,
                "bytes_norm": total_bytes / 1500.0,
                "duration": duration,
                "flow_pkts_s": total_packets / duration if duration > 0 else 0.0,
                "flow_bytes_s": total_bytes / duration if duration > 0 else 0.0,
                "avg_pkt_size": total_bytes / total_packets if total_packets else 0.0,
                "fwd_pkts": total_fwd,
                "bwd_pkts": total_bwd,
                "fwd_bytes": sum(fwd_lengths),
                "bwd_bytes": sum(bwd_lengths),
                "syn_count": flow["syn_count"],
                "ack_count": flow["ack_count"],
                "rst_count": flow["rst_count"],
                "fwd_iat_mean": fwd_iat_mean,
                "fwd_iat_std": fwd_iat_std,
                "bwd_iat_mean": bwd_iat_mean,
                "bwd_iat_std": bwd_iat_std,
                "pkt_len_mean": pkt_len_mean,
                "pkt_len_std": pkt_len_std,
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "iat_max": iat_max,
                "iat_min": iat_min,
            }
            attack_type_features = build_attack_type_features(
                raw_features,
                fwd_lengths=fwd_lengths,
                bwd_lengths=bwd_lengths,
                all_iats_seconds=all_iats,
                fwd_iats_seconds=flow["fwd_iats"],
                bwd_iats_seconds=flow["bwd_iats"],
            )
            output.append(
                {
                    "metadata": {
                        "src_ip": flow["origin_src"],
                        "dst_ip": flow["origin_dst"],
                        "src_port": flow["origin_sport"],
                        "dst_port": flow["origin_dport"],
                        "protocol": flow["proto"],
                        "dpid": flow["dpid"],
                        "in_port": flow["in_port"],
                    },
                    "raw_features": raw_features,
                    "features": _preprocessor.normalize(raw_features),
                    "attack_type_features": attack_type_features,
                }
            )
        return output


def _load_detector_from_environment() -> None:
    global _detector_attempted
    if _detector_attempted:
        return
    _detector_attempted = True
    model_path = os.getenv("ARF_MODEL_PATH")
    if not model_path:
        default_model = SRC_ROOT.parent / "results" / "arf_controller.pkl"
        if default_model.exists():
            model_path = str(default_model)
    if not model_path:
        return
    try:
        configure(
            model_path,
            attack_threshold=float(os.getenv("ARF_ATTACK_THRESHOLD", "0.70")),
        )
    except Exception as error:
        logger.error("Could not load ARF model: %s", error)


def _load_attack_type_detector_from_environment() -> None:
    global _attack_type_detector_attempted
    if _attack_type_detector_attempted:
        return
    _attack_type_detector_attempted = True
    model_path = os.getenv("ARF_ATTACK_TYPE_MODEL_PATH")
    if not model_path:
        return
    try:
        configure_attack_type(model_path)
    except Exception as error:
        logger.error("Could not load attack-type ARF demo: %s", error)


def process(
    records: Iterable[Mapping[str, Any]],
    controller: Any | None = None,
) -> dict[str, Any]:
    """Process one controller window and optionally forward safe alerts."""

    materialized = list(records)
    if not materialized:
        return {"flow_count": 0, "alerts": []}

    _load_detector_from_environment()
    _load_attack_type_detector_from_environment()
    flow_rows = TrafficCollector().collect(materialized)
    feature_rows = [row["features"] for row in flow_rows]

    if _detector is not None and feature_rows:
        predictions = _detector.predict_batch(
            feature_rows, preprocessed=True
        )
    else:
        predictions = [
            {
                "prediction": "NOT_CONFIGURED",
                "raw_prediction": None,
                "probabilities": {},
                "attack_score": 0.0,
                "confidence": 0.0,
                "is_attack": False,
            }
            for _ in flow_rows
        ]

    attack_type_predictions = (
        _attack_type_detector.predict_batch(
            [row["attack_type_features"] for row in flow_rows]
        )
        if _attack_type_detector is not None and flow_rows
        else [None for _ in flow_rows]
    )

    alerts = []
    for row, prediction, attack_type_prediction in zip(
        flow_rows, predictions, attack_type_predictions
    ):
        metadata = row["metadata"]
        features = row["features"]
        raw_features = row["raw_features"]
        logger.info(
            "Flow %s:%s -> %s:%s proto=%s packets=%d bytes=%d | prediction=%s attack_score=%.3f",
            metadata["src_ip"],
            metadata["src_port"],
            metadata["dst_ip"],
            metadata["dst_port"],
            metadata["protocol"],
            int(raw_features["count"]),
            int(raw_features["bytes"]),
            prediction["prediction"],
            prediction["attack_score"],
        )
        if attack_type_prediction is not None:
            logger.info(
                "Attack-type ARF demo only | candidate=%s confidence=%.3f "
                "coverage=%d/%d | no mitigation from this model",
                attack_type_prediction["prediction"],
                attack_type_prediction["confidence"],
                attack_type_prediction["feature_coverage"],
                len(row["attack_type_features"]),
            )
        if prediction["is_attack"]:
            alert = {**metadata, **raw_features, **prediction}
            alerts.append(alert)
            if controller is not None:
                try:
                    controller.handle_detection(alert)
                except Exception:
                    logger.exception("Controller mitigation hook failed")

    return {
        "flow_count": len(flow_rows),
        "alerts": alerts,
        "attack_type_predictions": [
            prediction for prediction in attack_type_predictions if prediction is not None
        ],
    }
