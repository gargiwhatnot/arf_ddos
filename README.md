# SDN DDoS Detection using Adaptive Random Forest

This project implements an isolated SDN-based DDoS detection workflow using
Mininet, Open vSwitch, OS-Ken/OpenFlow 1.3, packet capture, and River's
Adaptive Random Forest (ARF).

The live pipeline is:

```text
Mininet traffic
  -> Open vSwitch
  -> OS-Ken PacketIn window
  -> bidirectional flow features
  -> shared preprocessing/schema + training-fitted scaling
  -> ARF prediction
  -> lab-only repeated-alert mitigation
```

## Important project rule

Keep all lab traffic inside `10.0.0.0/24`. The controller mitigation code only
accepts an in-lab source and the configured in-lab victim (default
`10.0.0.5`). Do not point the traffic generators at an external address.

## Project structure

```text
src/shared/       Shared schema, preprocessing, and ARF runtime
src/Controller/   OS-Ken controller, collector, PCAP tools
src/ARF/          Dataset preparation, training, and evaluation
tests/            Fast local unit tests
datasets/         Local raw dataset files (not tracked)
processed/        Cleaned datasets (not tracked)
train_data/       Training split (not tracked)
test_data/        Testing split (not tracked)
results/          Checkpoints and metrics (not tracked)
```

## Install project dependencies

Run this in the project root:

```bash
python3 -m pip install -r requirements-project.txt
```

The existing VM may already provide OS-Ken, Mininet, Scapy, and tcpdump. The
requirements file is for the Python-side ARF and feature pipeline.

## Offline ARF workflow

Place CIC-DDoS2019 CSV files under `datasets/`. At least one normal-labelled
file (`BENIGN` or `Normal`) and one DDoS-labelled file are required for a
binary detector.

```bash
python3 src/ARF/preprocess.py --input-dir datasets
python3 src/ARF/verify_dataset.py
python3 src/ARF/split_dataset.py
python3 src/ARF/train_arf_v2.py
python3 src/ARF/evaluate.py
```

The cleaning step removes unusable/constant columns and duplicate or invalid
rows. The training script then fits a `StandardFeatureScaler` on training rows
only, applies it before ARF learning, and stores its means/scales inside
`results/arf_controller.pkl`. The live controller and evaluation load those
same saved statistics, so test/live rows are never used to fit preprocessing.
Evaluation never calls `learn_one()` and does not modify the checkpoint.

The controller checkpoint is self-describing: it stores the canonical feature
schema and training scaler. Raw or older River pickle files without that
metadata are rejected instead of being used with the wrong feature names.
Always train the controller model with `train_arf_v2.py`; do not rename an
attack-family or legacy raw checkpoint to `arf_controller.pkl`.

## Regular-traffic PCAP test

Convert the already captured normal PCAP to the same schema used by the
controller:

```bash
python3 src/Controller/pcap_to_csv.py \
  --pcap /tmp/udp_baseline.pcap \
  --output results/udp_baseline_features.csv \
  --label Normal
```

Replay it through the collector without changing the Mininet network:

```bash
python3 src/Controller/replay_pcap.py \
  --pcap /tmp/udp_baseline.pcap \
  --model results/arf_controller.pkl
```

The collector should report flow features and a normal
prediction. No mitigation should be installed for this test.

## Supplied attack-type ARF demonstration

The optional `arf_v6_balanced.pkl` checkpoint is an external River ARF with
16 DDoS-family labels, but no `Normal`/`BENIGN` class. It is therefore wired
as a safe **attack-type candidate** demonstration only: it logs a candidate
family and never installs a mitigation rule. Keep the binary Normal/DDoS ARF
as the decision-making model.

Inspect the checkpoint without changing it:

```bash
.venv/bin/python src/ARF/inspect_attack_type_model.py \
  --model /home/admin2233/Desktop/stuff/arf_v6_balanced.pkl
```

Replay a lab PCAP through the 31-feature adapter and the supplied ARF:

```bash
.venv/bin/python src/Controller/replay_pcap.py \
  --pcap /tmp/ddos_attack.pcap \
  --attack-type-model /home/admin2233/Desktop/stuff/arf_v6_balanced.pkl
```

For a live, log-only demonstration, set this before launching the controller:

```bash
export ARF_ATTACK_TYPE_MODEL_PATH=/home/admin2233/Desktop/stuff/arf_v6_balanced.pkl
```

The model expects CICFlowMeter-style features. The adapter derives all 31 from
each controller flow window and converts duration/IAT values to microseconds.
Because the original training CSV and benign class are unavailable, do not
report the candidate label as a completed Normal-versus-DDoS result.

## Live controller configuration

Set these variables before starting the existing OS-Ken launcher:

```bash
export PYTHONPATH="$PWD/src"
export ARF_MODEL_PATH="$PWD/results/arf_controller.pkl"
export ARF_ATTACK_THRESHOLD=0.70
export MITIGATION_VICTIM_IP=10.0.0.5
export MITIGATION_MIN_ALERTS=2
export MITIGATION_IDLE_TIMEOUT=60
```

Start the controller with the same OS-Ken command that is already working in
the VM. The controller will continue feature collection if no model is set,
but it will only predict and mitigate when `ARF_MODEL_PATH` points to a valid
checkpoint.

## Controlled attack test

Start the capture first, targeting only the Mininet victim:

```bash
sudo tcpdump -i s1-eth5 -nn -s 0 \
  -w /tmp/ddos_attack.pcap \
  'udp and dst host 10.0.0.5'
```

Then use the Mininet CLI to run the controlled multi-source test. Keep h5 as
the victim and use h1-h4 as sources; for example, run one UDP server on h5
and bounded `iperf3` client runs from h1-h4. Stop the capture after the test,
convert it with `--label DDoS`, and replay it through the collector for a
repeatable check.

The controller requires repeated high-confidence alerts before installing a
drop rule. Verify the result with:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

## Local code checks

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```
