# Packet Analyzer ML — Python Rewrite

A Python + ML reimplementation of the DPI engine, with machine learning traffic classification.

---

## Project Structure

```
packet_analyzer_ml/
├── src/
│   ├── pcap_reader.py       # Day 1 — Read .pcap files
│   ├── packet_parser.py     # Day 1 — Parse Ethernet/IP/TCP/UDP headers
│   ├── sni_extractor.py     # Day 1 — Extract domain from TLS/HTTP
│   ├── flow_tracker.py      # Day 2 — Track flows, build flow table
│   ├── rule_engine.py       # Day 2 — Block rules (IP/app/domain)
│   └── dpi_engine.py        # Day 2 — Main orchestrator
│
├── ml/
│   ├── feature_extractor.py # Day 3 — Per-flow ML features
│   ├── train.py             # Day 3 — Train classifier
│   └── predict.py           # Day 3 — Run inference
│
├── data/
│   └── test_dpi.pcap        # Sample capture file
│
├── reports/                 # Generated charts and reports
└── main.py                  # Entry point
```

---

## Setup

```bash
# Install dependencies
pip install scapy scikit-learn xgboost pandas numpy matplotlib joblib

# Clone original repo to get sample .pcap files
git clone https://github.com/perryvegehan/Packet_analyzer.git
cp Packet_analyzer/test_dpi.pcap data/
cp Packet_analyzer/output.pcap data/
```

---

## Day 1 Files

### `pcap_reader.py`
- Reads `.pcap` binary files using Scapy
- Lazy iteration (memory efficient) or eager load
- Returns `RawPacket` dataclass objects

### `packet_parser.py`
- Parses all network layers: Ethernet → IP → TCP/UDP
- Builds `FiveTuple` (the unique flow identifier)
- Returns `ParsedPacket` dataclass with all fields extracted

### `sni_extractor.py`
- Manually parses TLS Client Hello bytes to extract SNI
- Extracts HTTP Host header from plain HTTP
- Maps domain → `AppType` enum (YouTube, Facebook, Google, etc.)

---

## Quick Test (Day 1)

```bash
cd src

# Test each module individually
python pcap_reader.py ../data/test_dpi.pcap
python packet_parser.py ../data/test_dpi.pcap
python sni_extractor.py ../data/test_dpi.pcap
```
