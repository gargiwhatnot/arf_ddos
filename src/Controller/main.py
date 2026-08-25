import logging, time
from collections import deque
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet
from os_ken.lib import hub

# import your traffic_collector module
import traffic_collector

logging.basicConfig(level=logging.INFO)

class IDSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.traffic_buffer = deque(maxlen=5000)
        # spawn monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

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

        # buffer raw traffic record (no feature extraction here)
        record = {
            "timestamp": time.time(),
            "dpid": dp.id,
            "in_port": in_port,
            "raw_data": msg.data.hex()
        }
        self.traffic_buffer.append(record)

        # Learning switch logic
        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][src] = in_port
        out_port = self.mac_to_port[dp.id].get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        dp.send_msg(out)

    def _monitor(self):
        while True:
            hub.sleep(5)  # every 5 seconds
            self._flush_to_collector()

    def _flush_to_collector(self):
        if self.traffic_buffer:
            snapshot = list(self.traffic_buffer)
            try:
                # hand off to traffic_collector for feature extraction + ML pipeline
                traffic_collector.process(snapshot)
                self.logger.info("Sent %d records to traffic_collector", len(snapshot))
            except Exception as e:
                self.logger.error("Collector processing failed: %s", e)
            self.traffic_buffer.clear()

if __name__ == "__main__":
    from os_ken.lib.hub import HubThread
    if not hasattr(HubThread, 'kill'):
        HubThread.kill = lambda self: None
    try:
        app_manager.AppManager.run_apps([__file__])
    except (KeyboardInterrupt, SystemExit):
        print("\n[+] Controller shut down gracefully.")
