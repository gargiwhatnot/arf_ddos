"""Mitigation policy and repeated-alert enforcement for the SDN controller."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict

logger = logging.getLogger("MitigationPolicy")


class LabMitigator:
    """Keep all alert thresholding and OpenFlow drop logic isolated from the app loop."""

    def __init__(self, controller, victim_ip: str, min_alerts: int, rule_idle_timeout: int):
        self.controller = controller
        self.victim_ip = victim_ip
        self.min_alerts = max(1, int(min_alerts))
        self.rule_idle_timeout = max(0, int(rule_idle_timeout))
        self.alert_counts = defaultdict(int)
        self.mitigation_rules = {}
        controller.alert_counts = self.alert_counts
        controller.mitigation_rules = self.mitigation_rules

    def _is_lab_ip(self, value: str) -> bool:
        try:
            return ipaddress.ip_address(value) in self.controller.LAB_NETWORK
        except ValueError:
            return False

    def handle_detection(self, alert):
        src_ip = str(alert.get("src_ip", ""))
        dst_ip = str(alert.get("dst_ip", ""))
        dpid = alert.get("dpid")

        if (
            not self._is_lab_ip(src_ip)
            or not self._is_lab_ip(dst_ip)
            or dst_ip != self.victim_ip
            or src_ip == self.victim_ip
        ):
            logger.warning(
                "Ignored detection outside configured lab victim scope: %s -> %s",
                src_ip,
                dst_ip,
            )
            return

        key = (dpid, src_ip, dst_ip)
        self.alert_counts[key] += 1
        count = self.alert_counts[key]
        logger.warning(
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
        if dpid not in self.controller.datapaths:
            logger.warning("No active datapath for mitigation dpid=%s", dpid)
            return

        key = (dpid, src_ip, dst_ip)
        installed_at = self.mitigation_rules.get(key)
        if installed_at is not None:
            if self.rule_idle_timeout == 0:
                return
            if time.time() - installed_at < self.rule_idle_timeout:
                return

        dp = self.controller.datapaths[dpid]
        parser = dp.ofproto_parser
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
        )
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=self.controller.MITIGATION_COOKIE,
            priority=200,
            match=match,
            instructions=[],
            idle_timeout=self.rule_idle_timeout,
        )
        dp.send_msg(mod)
        self.mitigation_rules[key] = time.time()
        logger.warning(
            "MITIGATION INSTALLED: drop IPv4 traffic %s -> %s on dpid=%s",
            src_ip,
            dst_ip,
            dpid,
        )


__all__ = ["LabMitigator"]
