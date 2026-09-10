# Attack scripts

Run each script from a Mininet host or from the host machine while the topology is active.

## Examples

```bash
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/cicddos_demo.py
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/udp_flood.py 10.0.0.1 --count 25000 --burst 500
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/mssql_attack.py 10.0.0.1 --count 20000
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/udp_lag.py 10.0.0.1 --count 15000 --burst 250 --pause 0.02
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/syn_flood.py 10.0.0.1 --count 10000
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/portmap_attack.py 10.0.0.1 --count 10000
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/ldap_attack.py 10.0.0.1 --count 10000
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/tftp_attack.py 10.0.0.1 --count 10000
sudo /home/deep/files/arf_ddos/venv/bin/python attack_scripts/netbios_attack.py 10.0.0.1 --count 10000
```

The preferred demo for CIC-DDoS 2019 modeling is `cicddos_demo.py`.
Each script targets the default victim IP `10.0.0.1`.
Update the `TARGET` or `VICTIM` variable inside a file if your victim host uses a different IP.
All scripts have bounded defaults, so they stop without requiring `Ctrl+C`.

## Run from Mininet

Start the controller first, then connect Mininet to it. Run attack scripts from
the attacker host namespace so the packets enter the Open vSwitch and generate
PacketIn events for the controller:

```text
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/mssql_attack.py 10.0.0.1 --count 20000
```

The other attack commands can be run in the same form by replacing the script:

```text
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/udp_flood.py 10.0.0.1 --count 25000 --burst 500
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/syn_flood.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/portmap_attack.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/ldap_attack.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/tftp_attack.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/netbios_attack.py 10.0.0.1 --count 10000
```

For UDP-Lag, use burst mode so the controller receives dense windows of packets:

```text
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/udp_lag.py 10.0.0.1 --count 15000 --burst 250 --pause 0.02
```

## UDP Port Unreachable messages

Messages such as `ICMP Port Unreachable from 10.0.0.1` are normal when h1 has
no UDP service listening on the destination port. They confirm that the packets
reached h1; they do not mean that the attack script failed. The controller
detects the original UDP flow and ignores the ICMP response for ARF detection.

To test with a listening UDP endpoint instead, start the receiver on the same
port used by the attack. For the generic UDP attack, use port `33434`:

```text
mininet> h1 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('10.0.0.1', 33434)); print('UDP listener ready', flush=True); [s.recvfrom(65535) for _ in iter(int, 1)]" &
```

Then run the UDP attack from h2:

```text
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/udp_flood.py 10.0.0.1 --count 25000 --burst 500
```

Use these listener ports for the service-specific scripts:

```text
MSSQL:   1433
Portmap: 111
LDAP:    389
TFTP:    69
NetBIOS: 137
```

For example, before running the NetBIOS script, bind h1 to UDP/137:

```text
mininet> h1 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('10.0.0.1', 137)); print('NetBIOS test listener ready', flush=True); [s.recvfrom(65535) for _ in iter(int, 1)]" &
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/netbios_attack.py 10.0.0.1 --count 10000
```

Do not run the script only from the normal host shell when testing controller
detection; that bypasses the Mininet host namespace and switch path.
