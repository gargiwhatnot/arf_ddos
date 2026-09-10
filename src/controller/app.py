"""OS-Ken controller app with event handlers and mitigation orchestration."""

from __future__ import annotations

import ipaddress
import logging
import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, packet
from os_ken.ofproto import ofproto_v1_3

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from controller.flow_aggregator import process as process_flows
# Mitigation is intentionally disabled; this controller is alert-only.

logging.basicConfig(level=logging.INFO)


class IDSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    LAB_NETWORK = ipaddress.ip_network("10.0.0.0/24")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.traffic_buffer = deque(maxlen=5000)
        attack_threshold = float(os.getenv("ARF_ATTACK_THRESHOLD", "0.25"))
        model_path = os.getenv("ARF_MODEL_PATH")
        if not model_path:
            default_model = PROJECT_ROOT / "src" / "models" / "arf_model_major.pkl"
            if default_model.exists():
                model_path = str(default_model)
            else:
                legacy_model = PROJECT_ROOT / "results" / "arf_controller.pkl"
                if legacy_model.exists():
                    model_path = str(legacy_model)
        try:
            from controller.flow_aggregator import configure as configure_flow_detector

            configure_flow_detector(model_path, attack_threshold)
        except Exception as error:
            self.logger.error("ARF configuration failed: %s", error)

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.logger.info("Switch connected: dpid=%s", dp.id)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=0,
            match=match,
            instructions=inst,
        )
        dp.send_msg(mod)
        self.logger.info("Installed table-miss flow on dpid=%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        self.datapaths[dp.id] = dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        self.traffic_buffer.append(
            {
                "timestamp": time.time(),
                "dpid": dp.id,
                "in_port": in_port,
                "raw_data": msg.data.hex(),
            }
        )

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        dp.send_msg(out)

    def _monitor(self):
        while True:
            hub.sleep(5)
            self._flush_to_collector()

    def _flush_to_collector(self):
        if not self.traffic_buffer:
            return
        snapshot = list(self.traffic_buffer)
        self.traffic_buffer.clear()
        try:
            result = process_flows(snapshot, controller=self)
            self.logger.info(
                "Processed %d PacketIn records into %d flow(s); alerts=%d",
                len(snapshot),
                result["flow_count"],
                len(result["alerts"]),
            )
        except Exception as error:
            self.logger.error("Collector processing failed: %s", error)

    def handle_detection(self, alert):
        # Alert-only mode: never install a drop rule for a model detection.
        self.logger.warning(
            "DDoS ALERT: %s:%s -> %s:%s proto=%s score=%.3f prediction=%s",
            alert.get("src_ip"),
            alert.get("src_port"),
            alert.get("dst_ip"),
            alert.get("dst_port"),
            alert.get("protocol"),
            float(alert.get("attack_score", 0.0)),
            alert.get("prediction"),
        )


__all__ = ["IDSController"]
