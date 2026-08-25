import logging, time, statistics
from collections import defaultdict
from scapy.all import Ether, IP, TCP, UDP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrafficCollector")

# Flow table keyed by 5-tuple
flows = defaultdict(lambda: {
    "timestamps": [],
    "fwd_lengths": [],
    "bwd_lengths": [],
    "fwd_iats": [],
    "bwd_iats": [],
    "syn_count": 0,
    "ack_count": 0,
    "rst_count": 0,
})

def process(records):
    if not records:
        return

    logger.info("Received %d traffic records", len(records))

    for rec in records:
        raw_bytes = bytes.fromhex(rec["raw_data"])
        ts = rec["timestamp"]

        try:
            pkt = Ether(raw_bytes)
        except Exception:
            continue

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        proto = ip.proto
        src, dst = ip.src, ip.dst
        sport, dport = None, None

        if proto == 6 and pkt.haslayer(TCP):  # TCP
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flags = tcp.flags
            syn = int(flags & 0x02 != 0)
            ack = int(flags & 0x10 != 0)
            rst = int(flags & 0x04 != 0)
        elif proto == 17 and pkt.haslayer(UDP):  # UDP
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            syn = ack = rst = 0
        else:
            sport = dport = 0
            syn = ack = rst = 0

        key = (src, dst, sport, dport, proto)
        flow = flows[key]

        # Direction: forward if src == flow initiator, else backward
        direction = "fwd" if len(flow["timestamps"]) == 0 or src == key[0] else "bwd"

        flow["timestamps"].append(ts)
        length = len(raw_bytes)

        if direction == "fwd":
            flow["fwd_lengths"].append(length)
            if len(flow["timestamps"]) > 1:
                flow["fwd_iats"].append(ts - flow["timestamps"][-2])
        else:
            flow["bwd_lengths"].append(length)
            if len(flow["timestamps"]) > 1:
                flow["bwd_iats"].append(ts - flow["timestamps"][-2])

        flow["syn_count"] += syn
        flow["ack_count"] += ack
        flow["rst_count"] += rst

    # Compute features per flow
    for key, f in flows.items():
        if not f["timestamps"]:
            continue
        duration = f["timestamps"][-1] - f["timestamps"][0]
        total_pkts_fwd = len(f["fwd_lengths"])
        total_pkts_bwd = len(f["bwd_lengths"])
        total_len_fwd = sum(f["fwd_lengths"])
        total_len_bwd = sum(f["bwd_lengths"])

        def safe_stats(arr):
            return (max(arr) if arr else 0,
                    min(arr) if arr else 0,
                    statistics.mean(arr) if arr else 0,
                    statistics.pstdev(arr) if len(arr) > 1 else 0,
                    statistics.pvariance(arr) if len(arr) > 1 else 0)

        fwd_max, fwd_min, fwd_mean, _, _ = safe_stats(f["fwd_lengths"])
        bwd_max, bwd_min, bwd_mean, _, _ = safe_stats(f["bwd_lengths"])
        pkt_lengths = f["fwd_lengths"] + f["bwd_lengths"]
        pkt_mean, pkt_std, pkt_var = (statistics.mean(pkt_lengths) if pkt_lengths else 0,
                                      statistics.pstdev(pkt_lengths) if len(pkt_lengths) > 1 else 0,
                                      statistics.pvariance(pkt_lengths) if len(pkt_lengths) > 1 else 0)

        iats = f["fwd_iats"] + f["bwd_iats"]
        iat_mean, iat_std, iat_max, iat_min = (statistics.mean(iats) if iats else 0,
                                               statistics.pstdev(iats) if len(iats) > 1 else 0,
                                               max(iats) if iats else 0,
                                               min(iats) if iats else 0)

        fwd_iat_mean = statistics.mean(f["fwd_iats"]) if f["fwd_iats"] else 0
        fwd_iat_std = statistics.pstdev(f["fwd_iats"]) if len(f["fwd_iats"]) > 1 else 0
        bwd_iat_mean = statistics.mean(f["bwd_iats"]) if f["bwd_iats"] else 0
        bwd_iat_std = statistics.pstdev(f["bwd_iats"]) if len(f["bwd_iats"]) > 1 else 0

        flow_bytes_s = (total_len_fwd + total_len_bwd) / duration if duration > 0 else 0
        flow_pkts_s = (total_pkts_fwd + total_pkts_bwd) / duration if duration > 0 else 0
        fwd_pkts_s = total_pkts_fwd / duration if duration > 0 else 0
        bwd_pkts_s = total_pkts_bwd / duration if duration > 0 else 0
        avg_pkt_size = pkt_mean

        logger.info("Flow %s -> %s:%s features:", key[0], key[1], key[3])
        logger.info("Duration=%.4f TotalFwd=%d TotalBwd=%d LenFwd=%d LenBwd=%d",
                    duration, total_pkts_fwd, total_pkts_bwd, total_len_fwd, total_len_bwd)
        logger.info("FwdLenMax=%d FwdLenMin=%d FwdLenMean=%.2f BwdLenMax=%d BwdLenMin=%d BwdLenMean=%.2f",
                    fwd_max, fwd_min, fwd_mean, bwd_max, bwd_min, bwd_mean)
        logger.info("FlowBytes/s=%.2f FlowPkts/s=%.2f FwdPkts/s=%.2f BwdPkts/s=%.2f",
                    flow_bytes_s, flow_pkts_s, fwd_pkts_s, bwd_pkts_s)
        logger.info("IATmean=%.4f IATstd=%.4f IATmax=%.4f IATmin=%.4f", iat_mean, iat_std, iat_max, iat_min)
        logger.info("FwdIATmean=%.4f FwdIATstd=%.4f BwdIATmean=%.4f BwdIATstd=%.4f",
                    fwd_iat_mean, fwd_iat_std, bwd_iat_mean, bwd_iat_std)
        logger.info("PktLenMean=%.2f PktLenStd=%.2f PktLenVar=%.2f AvgPktSize=%.2f",
                    pkt_mean, pkt_std, pkt_var, avg_pkt_size)
        logger.info("SYN=%d ACK=%d RST=%d", f["syn_count"], f["ack_count"], f["rst_count"])
