"""PacketIn aggregation and processing logic for the SDN controller."""

from __future__ import annotations

import logging
import os
import pickle
from pathlib import Path
import sys
import time
from typing import Any, Iterable, Mapping

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    from scapy.all import Ether, IP, TCP, UDP
except ImportError:  # pragma: no cover - controller VM often provides Scapy
    Ether = IP = TCP = UDP = None

try:
    from shared.attack_type_features import build_attack_type_features
    from shared.attack_type_runtime import AttackTypeARF
except ImportError:  # pragma: no cover - optional attack-family demo modules
    def build_attack_type_features(*args, **kwargs):
        return {}

    class AttackTypeARF:
        def __init__(self, *args, **kwargs):
            self.class_labels = []

        def predict_batch(self, rows):
            return [None for _ in rows]

from controller.arf_runtime import ARFDetector

from controller.feature_pipeline import Preprocessor

logger = logging.getLogger("FlowAggregator")
logger.setLevel(logging.INFO)

UDP_SERVICE_LABELS = {
    69: "TFTP",
    111: "Portmap",
    137: "NetBIOS",
    389: "LDAP",
    1433: "MSSQL",
}

_detector: ARFDetector | None = None
_detector_attempted = False
_attack_type_detector: AttackTypeARF | None = None
_attack_type_detector_attempted = False
_preprocessor = Preprocessor()


def configure(model_path: str | None = None, attack_threshold: float = 0.25) -> None:
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
    """Configure the optional attack-family demo model."""

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


def _flow_key(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    proto: int,
    tcp_flags: int = 0,
) -> tuple:
    """Group by the logical flow instead of by ephemeral source ports.

    Attack traffic from Mininet often reuses a destination service while varying the
    source port for each packet. If we include the source port in the key, each packet
    becomes its own flow and the model sees mostly single-packet benign records.
    """
    if int(proto) == 6:
        common_service_ports = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433}
        if tcp_flags & 0x02:
            service_port = int(dst_port or 0)
        elif int(src_port or 0) in common_service_ports:
            service_port = int(src_port)
        else:
            service_port = int(dst_port or 0)
        return (tuple(sorted((src_ip, dst_ip))), int(proto), service_port)
    return (src_ip, dst_ip, int(proto), int(dst_port or 0))


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

            tcp_flags = flags if proto == 6 and packet.haslayer(TCP) else 0
            key = _flow_key(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                proto,
                tcp_flags=tcp_flags,
            )
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
            direction = "fwd" if current_endpoint == flow["origin_endpoint"] else "bwd"
            packet_length = len(raw_bytes)

            if flow["timestamps"]:
                flow["all_iats"].append(timestamp - flow["timestamps"][-1])
            previous_direction_timestamp = flow["last_direction_timestamp"].get(direction)
            if previous_direction_timestamp is not None:
                flow[f"{direction}_iats"].append(timestamp - previous_direction_timestamp)

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
            _, _, pkt_len_max, pkt_len_min = _stats(packet_lengths)
            _, _, fwd_pkt_len_max, fwd_pkt_len_min = _stats(fwd_lengths)
            _, _, bwd_pkt_len_max, bwd_pkt_len_min = _stats(bwd_lengths)

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
                "fwd_pkts_s": total_fwd / duration if duration > 0 else 0.0,
                "bwd_pkts_s": total_bwd / duration if duration > 0 else 0.0,
                "fwd_bytes": sum(fwd_lengths),
                "bwd_bytes": sum(bwd_lengths),
                "pkt_len_min": pkt_len_min,
                "pkt_len_max": pkt_len_max,
                "fwd_pkt_len_min": fwd_pkt_len_min,
                "fwd_pkt_len_max": fwd_pkt_len_max,
                "fwd_pkt_len_mean": sum(fwd_lengths) / total_fwd if total_fwd else 0.0,
                "bwd_pkt_len_min": bwd_pkt_len_min,
                "bwd_pkt_len_max": bwd_pkt_len_max,
                "bwd_pkt_len_mean": sum(bwd_lengths) / total_bwd if total_bwd else 0.0,
                "pkt_len_variance": pkt_len_std ** 2,
                "bwd_iat_total": sum(flow["bwd_iats"]),
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
        default_model = SRC_ROOT / "models" / "arf_model_major.pkl"
        if default_model.exists():
            model_path = str(default_model)
        else:
            legacy_model = SRC_ROOT.parent / "results" / "arf_controller.pkl"
            if legacy_model.exists():
                model_path = str(legacy_model)
    if not model_path:
        return
    try:
        configure(
            model_path,
            attack_threshold=float(os.getenv("ARF_ATTACK_THRESHOLD", "0.25")),
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


def process(records: Iterable[Mapping[str, Any]], controller: Any | None = None) -> dict[str, Any]:
    """Process one controller window and optionally forward safe alerts."""

    materialized = list(records)
    if not materialized:
        return {"flow_count": 0, "alerts": []}

    _load_detector_from_environment()
    _load_attack_type_detector_from_environment()
    collected_rows = TrafficCollector().collect(materialized)
    flow_rows = [
        row for row in collected_rows
        if int(row["metadata"].get("protocol", 0)) in (6, 17)
    ]
    ignored_flows = len(collected_rows) - len(flow_rows)
    if ignored_flows:
        logger.info(
            "Ignored %d non-TCP/UDP flow(s) from ARF detection",
            ignored_flows,
        )
    feature_rows = [row["features"] for row in flow_rows]

    if _detector is not None and feature_rows:
        predictions = _detector.predict_batch(feature_rows, preprocessed=True)
    else:
        predictions = [{
            "prediction": "NOT_CONFIGURED",
            "raw_prediction": None,
            "probabilities": {},
            "attack_score": 0.0,
            "confidence": 0.0,
            "is_attack": False,
        } for _ in flow_rows]

    attack_type_predictions = (
        _attack_type_detector.predict_batch(
            [row["attack_type_features"] for row in flow_rows]
        )
        if _attack_type_detector is not None and flow_rows
        else [None for _ in flow_rows]
    )

    alerts = []
    for row, prediction, attack_type_prediction in zip(flow_rows, predictions, attack_type_predictions):
        metadata = row["metadata"]
        features = row["features"]
        raw_features = row["raw_features"]
        protocol = int(metadata.get("protocol", 0))
        heuristic_min_packets = int(os.getenv("ARF_UDP_HEURISTIC_MIN_PACKETS", "50"))
        heuristic_min_bytes = int(os.getenv("ARF_UDP_HEURISTIC_MIN_BYTES", "4000"))
        syn_min_packets = int(os.getenv("ARF_SYN_HEURISTIC_MIN_PACKETS", "50"))
        syn_min_bytes = int(os.getenv("ARF_SYN_HEURISTIC_MIN_BYTES", "2000"))
        is_high_volume_udp = (
            protocol == 17
            and int(raw_features["count"]) >= heuristic_min_packets
            and int(raw_features["bytes"]) >= heuristic_min_bytes
        )
        if is_high_volume_udp:
            udp_label = UDP_SERVICE_LABELS.get(int(metadata.get("dst_port", 0)), "UDP")
            prediction = {
                **prediction,
                "prediction": udp_label,
                "raw_prediction": prediction["raw_prediction"],
                "attack_score": max(float(prediction["attack_score"]), 1.0),
                "confidence": max(float(prediction["confidence"]), 1.0),
                "is_attack": True,
            }
            logger.info(
                "High-volume UDP policy classified flow as %s: packets=%d bytes=%d",
                udp_label,
                int(raw_features["count"]),
                int(raw_features["bytes"]),
            )
        is_syn_flood = (
            protocol == 6
            and int(raw_features["count"]) >= syn_min_packets
            and int(raw_features["bytes"]) >= syn_min_bytes
            and int(raw_features["syn_count"]) >= syn_min_packets
        )
        if is_syn_flood:
            prediction = {
                **prediction,
                "prediction": "Syn",
                "raw_prediction": prediction["raw_prediction"],
                "attack_score": max(float(prediction["attack_score"]), 1.0),
                "confidence": max(float(prediction["confidence"]), 1.0),
                "is_attack": True,
            }
            logger.info(
                "TCP SYN policy classified flow as Syn: packets=%d syn=%d bytes=%d",
                int(raw_features["count"]),
                int(raw_features["syn_count"]),
                int(raw_features["bytes"]),
            )
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
                "Attack-type ARF demo only | candidate=%s confidence=%.3f coverage=%d/%d | no mitigation from this model",
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


__all__ = ["TrafficCollector", "configure", "configure_attack_type", "process"]
