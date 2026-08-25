import logging, time
from collections import defaultdict
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, udp, arp, icmp

logging.basicConfig(level=logging.INFO)

class IDSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # SYN flood counters: src_ip -> dst_port -> count
        self.syn_counts = defaultdict(lambda: defaultdict(int))
        self.last_reset = time.time()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info("Switch connected: dpid=%s", dp.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info("Installed table-miss flow on dpid=%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        src, dst = eth.src, eth.dst

        # TCP SYN detection
        tcp_seg = pkt.get_protocol(tcp.tcp)
        if tcp_seg and (tcp_seg.bits & 0x02):  # SYN flag
            self.syn_counts[src][tcp_seg.dst_port] += 1
            now = time.time()
            if now - self.last_reset > 1:  # once per second
                for ip, ports in self.syn_counts.items():
                    for port, count in ports.items():
                        if count > 1000:  # threshold
                            self.logger.warning("Possible SYN flood from %s to port %s: %d SYNs/sec",
                                                ip, port, count)
                self.syn_counts.clear()
                self.last_reset = now

        # Learning switch logic
        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][src] = in_port
        out_port = self.mac_to_port[dp.id].get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # comment out this block
        # if out_port != ofp.OFPP_FLOOD:
        #     match = parser.OFPMatch(eth_type=eth.ethertype, eth_dst=dst)
        #     inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        #     mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
        #     dp.send_msg(mod)


        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        dp.send_msg(out)

if __name__ == "__main__":
    from os_ken.lib.hub import HubThread
    if not hasattr(HubThread, 'kill'):
        HubThread.kill = lambda self: None
    try:
        app_manager.AppManager.run_apps([__file__])
    except (KeyboardInterrupt, SystemExit):
        print("\n[+] Controller shut down gracefully.")
