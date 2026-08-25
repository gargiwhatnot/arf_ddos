import logging
import time
from collections import defaultdict
from os_ken.lib.packet import packet, ethernet, ipv4, ipv6, tcp, udp, arp

class TrafficCollector:
    def __init__(self):
        self.logger = logging.getLogger("TrafficCollector")
        # SYN flood counters: src_ip -> dst_port -> count
        self.syn_counts = defaultdict(lambda: defaultdict(int))
        self.last_reset = time.time()

    def collect(self, msg, in_port, datapath):
        """
        Extract detailed packet information from PacketIn message and track traffic features.
        Returns a structured dictionary with protocol fields.
        """
        pkt = msg.data
        parsed_pkt = packet.Packet(pkt)

        details = {
            "dpid": datapath.id,
            "in_port": in_port,
            "ethernet": {},
            "ip": {},
            "tcp": {},
            "udp": {},
            "arp": {}
        }

        # Ethernet
        eth = parsed_pkt.get_protocol(ethernet.ethernet)
        if eth:
            details["ethernet"] = {
                "src_mac": eth.src,
                "dst_mac": eth.dst,
                "ethertype": eth.ethertype
            }
            self.logger.info("Ethernet src=%s dst=%s type=%s",
                             eth.src, eth.dst, eth.ethertype)

        # IPv4
        ip4 = parsed_pkt.get_protocol(ipv4.ipv4)
        if ip4:
            details["ip"] = {
                "version": 4,
                "src_ip": ip4.src,
                "dst_ip": ip4.dst,
                "proto": ip4.proto,
                "ttl": ip4.ttl
            }
            self.logger.info("IPv4 src=%s dst=%s proto=%s ttl=%s",
                             ip4.src, ip4.dst, ip4.proto, ip4.ttl)

        # IPv6
        ip6 = parsed_pkt.get_protocol(ipv6.ipv6)
        if ip6:
            details["ip"] = {
                "version": 6,
                "src_ip": ip6.src,
                "dst_ip": ip6.dst,
                "nxt": ip6.nxt,
                "hop_limit": ip6.hop_limit
            }
            self.logger.info("IPv6 src=%s dst=%s nxt=%s hop_limit=%s",
                             ip6.src, ip6.dst, ip6.nxt, ip6.hop_limit)

        # TCP
        tcp_seg = parsed_pkt.get_protocol(tcp.tcp)
        if tcp_seg:
            details["tcp"] = {
                "src_port": tcp_seg.src_port,
                "dst_port": tcp_seg.dst_port,
                "seq": tcp_seg.seq,
                "ack": tcp_seg.ack,
                "flags": tcp_seg.bits
            }
            self.logger.info("TCP src_port=%s dst_port=%s seq=%s ack=%s flags=%s",
                             tcp_seg.src_port, tcp_seg.dst_port,
                             tcp_seg.seq, tcp_seg.ack, tcp_seg.bits)

            # TCP SYN flood detection & traffic feature tracking
            if (tcp_seg.bits & 0x02) and eth:
                src_ip = ip4.src if ip4 else (ip6.src if ip6 else eth.src)
                self.syn_counts[src_ip][tcp_seg.dst_port] += 1
                now = time.time()
                if now - self.last_reset > 1:  # once per second
                    for ip, ports in self.syn_counts.items():
                        for port, count in ports.items():
                            if count > 1000:  # threshold
                                self.logger.warning("Possible SYN flood from %s to port %s: %d SYNs/sec",
                                                    ip, port, count)
                    self.syn_counts.clear()
                    self.last_reset = now

        # UDP
        udp_seg = parsed_pkt.get_protocol(udp.udp)
        if udp_seg:
            details["udp"] = {
                "src_port": udp_seg.src_port,
                "dst_port": udp_seg.dst_port,
                "length": udp_seg.total_length
            }
            self.logger.info("UDP src_port=%s dst_port=%s length=%s",
                             udp_seg.src_port, udp_seg.dst_port, udp_seg.total_length)

        # ARP
        arp_pkt = parsed_pkt.get_protocol(arp.arp)
        if arp_pkt:
            details["arp"] = {
                "src_ip": arp_pkt.src_ip,
                "dst_ip": arp_pkt.dst_ip,
                "src_mac": arp_pkt.src_mac,
                "dst_mac": arp_pkt.dst_mac,
                "opcode": arp_pkt.opcode
            }
            self.logger.info("ARP src_ip=%s dst_ip=%s src_mac=%s dst_mac=%s opcode=%s",
                             arp_pkt.src_ip, arp_pkt.dst_ip,
                             arp_pkt.src_mac, arp_pkt.dst_mac, arp_pkt.opcode)

        return details
