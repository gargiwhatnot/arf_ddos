"""Convert a PCAP into controller-compatible labelled flow features."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    from scapy.utils import PcapReader
except ImportError as error:  # pragma: no cover
    raise SystemExit("Scapy is required for PCAP conversion.") from error

from shared.pipeline import CANONICAL_FEATURES
from traffic_collector import TrafficCollector


METADATA_FIELDS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "dpid",
    "in_port",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, help="Input PCAP path")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument(
        "--label",
        required=True,
        choices=["Normal", "DDoS"],
        help="Ground-truth label for this capture",
    )
    parser.add_argument("--window-packets", type=int, default=5000)
    parser.add_argument("--limit", type=int, default=0, help="0 means all packets")
    args = parser.parse_args()

    pcap_path = Path(args.pcap).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    fields = METADATA_FIELDS + CANONICAL_FEATURES + ["Label"]
    collector = TrafficCollector()
    batch = []
    packets_seen = flows_written = 0
    write_header = True

    def write_flows(flow_rows):
        nonlocal write_header, flows_written
        if not flow_rows:
            return
        with output_path.open("a", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            if write_header:
                writer.writeheader()
                write_header = False
            for row in flow_rows:
                flattened = {**row["metadata"], **row["features"], "Label": args.label}
                writer.writerow({field: flattened.get(field, 0) for field in fields})
                flows_written += 1

    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if args.limit and packets_seen >= args.limit:
                break
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
                write_flows(collector.collect(batch))
                batch.clear()

    write_flows(collector.collect(batch))
    print(f"Packets read : {packets_seen:,}")
    print(f"Flows written: {flows_written:,}")
    print(f"Output       : {output_path}")


if __name__ == "__main__":
    main()
