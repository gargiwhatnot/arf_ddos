"""OS-Ken OpenFlow 1.3 learning switch with ARF detection hooks."""

from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
import sys
import time
from collections import defaultdict, deque

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet
from os_ken.lib import hub

import traffic_collector

PROJECT_ROOT = Path(__file__).resolve().parents[2]

logging.basicConfig(level=logging.INFO)


class IDSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MITIGATION_COOKIE = 0xDD05
    LAB_NETWORK = ipaddress.ip_network("10.0.0.0/24")

    def __init__(self, *args, **kwargs):
        super(IDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.traffic_buffer = deque(maxlen=5000)
        self.alert_counts = defaultdict(int)
        self.mitigation_rules = {}

        self.victim_ip = os.getenv("MITIGATION_VICTIM_IP", "10.0.0.5")
        self.min_alerts = max(1, int(os.getenv("MITIGATION_MIN_ALERTS", "2")))
        self.rule_idle_timeout = max(
            0, int(os.getenv("MITIGATION_IDLE_TIMEOUT", "60"))
        )
        attack_threshold = float(os.getenv("ARF_ATTACK_THRESHOLD", "0.70"))
        model_path = os.getenv("ARF_MODEL_PATH")
        if not model_path:
            default_model = PROJECT_ROOT / "results" / "arf_controller.pkl"
            if default_model.exists():
                model_path = str(default_model)
        try:
            traffic_collector.configure(model_path, attack_threshold)
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
            result = traffic_collector.process(snapshot, controller=self)
            self.logger.info(
                "Processed %d PacketIn records into %d flow(s); alerts=%d",
                len(snapshot),
                result["flow_count"],
                len(result["alerts"]),
            )
        except Exception as error:
            self.logger.error("Collector processing failed: %s", error)

    def _is_lab_ip(self, value: str) -> bool:
        try:
            return ipaddress.ip_address(value) in self.LAB_NETWORK
        except ValueError:
            return False

    def handle_detection(self, alert):
        """Require repeated high-confidence alerts before installing a drop rule."""

        src_ip = str(alert.get("src_ip", ""))
        dst_ip = str(alert.get("dst_ip", ""))
        dpid = alert.get("dpid")

        if (
            not self._is_lab_ip(src_ip)
            or not self._is_lab_ip(dst_ip)
            or dst_ip != self.victim_ip
            or src_ip == self.victim_ip
        ):
            self.logger.warning(
                "Ignored detection outside configured lab victim scope: %s -> %s",
                src_ip,
                dst_ip,
            )
            return

        key = (dpid, src_ip, dst_ip)
        self.alert_counts[key] += 1
        count = self.alert_counts[key]
        self.logger.warning(
            "DDoS candidate %s -> %s: alert %d/%d, score=%.3f",
            src_ip,
            dst_ip,
            count,
            self.min_alerts,
            float(alert.get("attack_score", 0.0)),
        )

        if count >= self.min_alerts:
            self.install_drop_rule(dpid, src_ip, dst_ip)

    def install_drop_rule(self, dpid, src_ip: str, dst_ip: str):
        if not self._is_lab_ip(src_ip) or not self._is_lab_ip(dst_ip):
            return
        if dpid not in self.datapaths:
            self.logger.warning("No active datapath for mitigation dpid=%s", dpid)
            return

        key = (dpid, src_ip, dst_ip)
        installed_at = self.mitigation_rules.get(key)
        if installed_at is not None:
            if self.rule_idle_timeout == 0:
                return
            if time.time() - installed_at < self.rule_idle_timeout:
                return

        dp = self.datapaths[dpid]
        parser = dp.ofproto_parser
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
        )
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=self.MITIGATION_COOKIE,
            priority=200,
            match=match,
            instructions=[],
            idle_timeout=self.rule_idle_timeout,
        )
        dp.send_msg(mod)
        self.mitigation_rules[key] = time.time()
        self.logger.warning(
            "MITIGATION INSTALLED: drop IPv4 traffic %s -> %s on dpid=%s",
            src_ip,
            dst_ip,
            dpid,
        )


if __name__ == "__main__":
    from os_ken.lib.hub import HubThread

    if "--model" in sys.argv:
        idx = sys.argv.index("--model")
        if idx + 1 < len(sys.argv):
            os.environ["ARF_MODEL_PATH"] = sys.argv[idx + 1]
            sys.argv.pop(idx + 1)
        sys.argv.pop(idx)

    if not hasattr(HubThread, "kill"):
        HubThread.kill = lambda self: None
    try:
        app_manager.AppManager.run_apps([__file__])
    except (KeyboardInterrupt, SystemExit):
        print("\n[+] Controller shut down gracefully.")
