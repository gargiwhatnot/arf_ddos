"""Replay a PCAP through the same collector used by the controller."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    from scapy.utils import PcapReader
except ImportError as error:  # pragma: no cover
    raise SystemExit("Scapy is required for PCAP replay.") from error

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--model", help="ARF checkpoint; omit for feature-only replay")
    parser.add_argument(
        "--attack-type-model",
        help="Attack-only River ARF for safe attack-family demonstration",
    )
    parser.add_argument("--window-packets", type=int, default=5000)
    args = parser.parse_args()

    pcap_path = Path(args.pcap).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    # Delay collector import so ``--help`` remains available on hosts where
    # Scapy's network-interface discovery is restricted.
    import traffic_collector

    if args.model:
        traffic_collector.configure(args.model)
    if args.attack_type_model:
        traffic_collector.configure_attack_type(args.attack_type_model)

    batch = []
    packets_seen = flow_count = alert_count = attack_type_count = 0

    def flush():
        nonlocal flow_count, alert_count, attack_type_count
        if not batch:
            return
        result = traffic_collector.process(batch)
        flow_count += result["flow_count"]
        alert_count += len(result["alerts"])
        attack_type_count += len(result.get("attack_type_predictions", []))
        batch.clear()

    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            try:
                timestamp = float(packet.time)
            except (TypeError, ValueError):
                timestamp = float(packets_seen)
            batch.append(
                {
                    "timestamp": timestamp,
                    "dpid": 0,
                    "in_port": 0,
                    "raw_data": bytes(packet).hex(),
                }
            )
            packets_seen += 1
            if len(batch) >= args.window_packets:
                flush()
    flush()

    print(f"Packets replayed: {packets_seen:,}")
    print(f"Flows observed  : {flow_count:,}")
    print(f"Alerts observed : {alert_count:,}")
    if args.attack_type_model:
        print(f"Attack-type candidates: {attack_type_count:,} (demo only; no mitigation)")


if __name__ == "__main__":
    main()
