# ARF DDoS Detection Controller

An OS-Ken/OpenFlow 1.3 controller that collects `PacketIn` traffic from
Mininet, builds short bidirectional flow windows, evaluates a pretrained River
Adaptive Random Forest (ARF) checkpoint, and emits alert-only DDoS detections.

The current implementation is designed around CIC-DDoS 2019-style flow
statistics. It does not install mitigation or drop rules.

## Features

- OS-Ken controller application using OpenFlow 1.3.
- Packet collection from connected switches through `PacketIn` events.
- Five-second monitoring and flow-processing loop.
- Scapy-based Ethernet, IPv4, TCP, and UDP parsing.
- River `ARFClassifier` checkpoint loading from `src/models/arf_model_major.pkl`.
- CIC-style canonical feature mapping for live flow rows.
- Bidirectional TCP aggregation so SYN packets and RST/ACK replies share a flow.
- ICMP exclusion from ARF attack detection to avoid control-traffic false alerts.
- Alert-only output with no automatic OpenFlow mitigation.
- Ready-to-run Mininet traffic generators for UDP, MSSQL, UDP-Lag, SYN,
  Portmap, LDAP, TFTP, and NetBIOS traffic patterns.

## Project layout

```text
arf_ddos/
├── attack_scripts/
│   ├── README.md
│   ├── cicddos_demo.py
│   ├── ldap_attack.py
│   ├── mssql_attack.py
│   ├── netbios_attack.py
│   ├── portmap_attack.py
│   ├── syn_flood.py
│   ├── tftp_attack.py
│   ├── udp_flood.py
│   ├── udp_lag.py
│   └── ...
├── src/
│   ├── main.py
│   ├── controller/
│   │   ├── app.py
│   │   ├── arf_runtime.py
│   │   ├── feature_pipeline.py
│   │   ├── flow_aggregator.py
│   │   ├── mitigation.py
│   │   └── model_runtime.py
│   └── models/
│       ├── arf_model.py
│       └── arf_model_major.pkl
├── requirements-project.txt
├── requirements.txt
└── README.md
```

## Runtime architecture

```text
Mininet hosts
    |
    v
Open vSwitch, OpenFlow 1.3
    |
    v
OS-Ken IDSController
    |-- stores PacketIn records
    |-- forwards packets using MAC learning
    |-- flushes a five-second buffer
    v
TrafficCollector
    |-- parses Ethernet/IP/TCP/UDP
    |-- groups logical flows
    |-- computes flow statistics
    v
ARFDetector
    |-- canonicalizes 29 CIC-style features
    |-- calls predict_one/predict_proba_one
    v
Alert-only policy
    |-- ignores ICMP for ARF detection
    |-- validates high-volume UDP and SYN patterns
    |-- logs DDoS ALERT
```

### `src/main.py`

The launcher sets the default model path and starts the OS-Ken application with
`app_manager.AppManager.run_apps(["controller.app"])`. It accepts an optional
model override:

```bash
python3 main.py --model /path/to/model.pkl
```

### `src/controller/app.py`

`IDSController`:

1. accepts OpenFlow 1.3 switch connections;
2. installs a table-miss flow that sends unmatched packets to the controller;
3. learns source MAC addresses and forwards packets with `PacketOut`;
4. buffers up to 5,000 PacketIn records;
5. flushes the buffer every five seconds;
6. logs detections without installing drop rules.

### `src/controller/flow_aggregator.py`

`TrafficCollector` parses raw packet bytes and creates flow rows. TCP flows are
grouped by endpoint pair and service port. UDP flows remain grouped by source,
destination, protocol, and destination port so high-volume service traffic is
kept together.

The collector ignores non-IPv4 packets and the processing stage ignores ICMP
flows for ARF detection. ICMP Port Unreachable responses are therefore not
reported as attack families.

### `src/controller/arf_runtime.py`

Loads the pickle checkpoint and calls River prediction methods. The runtime
reports:

- `prediction`: model label;
- `raw_prediction`: unchanged model label;
- `probabilities`: class probabilities when supported;
- `confidence`: highest class probability;
- `attack_score`: probability mass assigned to non-`BENIGN` classes;
- `is_attack`: whether the model prediction passes the configured threshold.

### `src/controller/feature_pipeline.py` and `src/models/arf_model.py`

These modules define the canonical feature names and map collector aliases to
the names expected by the checkpoint. Missing features default to `0.0`.

The current 29-feature contract is:

```text
ACK Flag Count
URG Flag Count
Min Packet Length
Max Packet Length
Packet Length Mean
Packet Length Std
Packet Length Variance
Average Packet Size
Fwd Packet Length Min
Fwd Packet Length Max
Fwd Packet Length Mean
Bwd Packet Length Min
Bwd Packet Length Max
Bwd Packet Length Mean
Total Backward Packets
Total Length of Fwd Packets
Total Length of Bwd Packets
Flow Duration
Flow Bytes/s
Fwd Packets/s
Bwd Packets/s
Flow IAT Max
Bwd IAT Total
Bwd IAT Mean
Avg Fwd Segment Size
Avg Bwd Segment Size
Flow IAT Std
RST Flag Count
Total Fwd Packets
```

The checkpoint and live collector must use the same feature meanings and units.
The controller does not pass destination port as one of these model features.

## Installation

The tested environment uses Python 3.14, a project virtual environment, OS-Ken
4.2.2, River, Scapy, and Mininet. Mininet and Open vSwitch are normally system
packages; the controller and Scapy dependencies are installed in the project
environment.

```bash
cd /home/deep/files/arf_ddos
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-project.txt
```

Install host tools required by the attack scripts if needed:

```bash
sudo apt-get install mininet openvswitch-switch hping3 iperf3
```

The Scapy attack scripts use the project interpreter explicitly:

```text
/home/deep/files/arf_ddos/venv/bin/python
```

## Start the controller

Use one terminal and leave it running:

```bash
cd /home/deep/files/arf_ddos/src
source ../venv/bin/activate
python3 main.py
```

Expected startup messages include:

```text
ARF detector loaded from .../src/models/arf_model_major.pkl
```

The OS-Ken OpenFlow server listens on port `6653` for the Mininet commands in
this README. It may also expose the compatibility port `6633`.

## Start Mininet

Use a separate terminal:

```bash
sudo mn --topo=linear,2 \
  --controller=remote,ip=127.0.0.1,port=6653 \
  --switch ovsk,protocols=OpenFlow13
```

The topology contains:

```text
h1 = victim, 10.0.0.1
h2 = attacker, 10.0.0.2
s1/s2 = Open vSwitch switches
```

Confirm connectivity and switch attachment:

```text
mininet> net
mininet> h1 ping -c 2 h2
```

The controller should log one switch-connected message per switch:

```text
Switch connected: dpid=1
Switch connected: dpid=2
```

## Run attacks from Mininet

Run the scripts from `h2`, not from the normal host shell. This ensures the
traffic traverses the Mininet interface, OVS, and controller path.

```text
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/udp_flood.py 10.0.0.1 --count 25000 --burst 500
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/mssql_attack.py 10.0.0.1 --count 20000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/udp_lag.py 10.0.0.1 --count 15000 --burst 250 --pause 0.02
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/syn_flood.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/portmap_attack.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/ldap_attack.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/tftp_attack.py 10.0.0.1 --count 10000
mininet> h2 /home/deep/files/arf_ddos/venv/bin/python /home/deep/files/arf_ddos/attack_scripts/netbios_attack.py 10.0.0.1 --count 10000
```

For the UDP-Lag script, dense bursts are controlled with `--burst` and
`--pause`. Every script has bounded defaults and accepts `--help`.

## Detection policies

The model remains the primary classifier, but the current live pipeline adds
traffic-shape checks because Mininet windows do not always match complete
CIC-DDoS 2019 flows.

### UDP policy

Default environment thresholds:

```text
ARF_UDP_HEURISTIC_MIN_PACKETS=50
ARF_UDP_HEURISTIC_MIN_BYTES=4000
```

A qualifying UDP flow is treated as an attack and labeled from the destination
service port:

```text
UDP/1433 -> MSSQL
UDP/389  -> LDAP
UDP/137  -> NetBIOS
UDP/69   -> TFTP
UDP/111  -> Portmap
other high-volume UDP -> UDP
```

### SYN policy

Default environment thresholds:

```text
ARF_SYN_HEURISTIC_MIN_PACKETS=50
ARF_SYN_HEURISTIC_MIN_BYTES=2000
```

A TCP flow must contain at least the configured number of packets and SYN flags
to be labeled `Syn`. Normal TCP data traffic does not satisfy this condition.

### Model threshold

The non-BENIGN model probability threshold defaults to `0.25`:

```bash
ARF_ATTACK_THRESHOLD=0.25 python3 main.py
```

## Alert output

Mitigation is disabled. The controller does not install a drop flow. A detected
flow is logged as an alert, for example:

```text
DDoS ALERT: 10.0.0.2:30031 -> 10.0.0.1:1433 proto=17 score=1.000 prediction=MSSQL
```

The earlier mitigation implementation remains in `src/controller/mitigation.py`
for reference, but it is not instantiated by `IDSController`.

## UDP listener behavior

If h1 has no application listening on the attack destination port, Linux sends:

```text
ICMP Port Unreachable
```

This means the packet reached h1 but no UDP service owned that port. It does not
mean the traffic failed, and ICMP flows are excluded from ARF detection.

Optional listener example for generic UDP/33434 traffic:

```text
mininet> h1 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('10.0.0.1', 33434)); print('UDP listener ready', flush=True); [s.recvfrom(65535) for _ in iter(int, 1)]" &
```

Use matching ports for service-specific tests:

```text
MSSQL=1433, Portmap=111, LDAP=389, TFTP=69, NetBIOS=137
```

## Cleanup

Stop a listener inside Mininet with:

```text
mininet> h1 ss -lunp
mininet> h1 fuser -k -n udp 137
```

Exit Mininet and clean stale namespaces/switches with:

```text
mininet> exit
sudo mn -c
```

Stop the controller with `Ctrl+C` in its terminal.

## Validation commands

Compile the source and attack scripts:

```bash
cd /home/deep/files/arf_ddos
./venv/bin/python -m py_compile src/controller/*.py src/models/*.py attack_scripts/*.py
```

Check script command-line interfaces without sending traffic:

```bash
for script in attack_scripts/*.py; do
  ./venv/bin/python "$script" --help >/dev/null || exit 1
done
```

```

The controller-level tests used during development exercise synthetic PacketIn
windows for all supported attack labels and verify the minimum UDP and SYN
thresholds. They do not replace evaluation on held-out CIC-DDoS data.

## Limitations

- The live feature vector is a 29-feature subset, not the complete CICFlowMeter
  feature set.
- Live five-second windows may not have the same distribution as complete
  CIC-DDoS 2019 flows.
- Port-based labels are a controller policy for high-volume UDP traffic; port
  is not part of the 29-feature ARF input.
- The attack scripts approximate CIC-DDoS traffic and are not exact PCAP replay.
- The controller is alert-only and does not automatically block traffic.
- `src/controller/model_runtime.py` is an older standalone runtime helper; the
  active application uses `src/controller/arf_runtime.py`.
```
