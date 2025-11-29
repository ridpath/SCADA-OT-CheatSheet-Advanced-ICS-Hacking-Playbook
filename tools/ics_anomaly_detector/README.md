<!--
SEO Tags:
ICS anomaly detection, SCADA security tool, Suricata integration ICS, OPC UA parsing, Modbus fuzzing,
DNP3 monitoring, CIP protocol analysis, industrial ML detection, OT threat detection, MITRE ICS ATT&CK T0801 T0855 T0860,
ICS data drift, SCADA blue team detection, PLC anomaly detector, ICS cyber range defense
-->

# ICS Anomaly Detection & Suricata Integration Suite

> **Production-Grade ICS/SCADA Threat Detection Framework** using Machine Learning, Suricata, and Protocol Dissection  
> Designed for OT security testing, blue team validation, and anomaly detection.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ICS-T0801%2C%20T0855%2C%20T0860-orange)
![Tool Type](https://img.shields.io/badge/type-blue--team%2Fresearch-lightgrey)
![Status](https://img.shields.io/badge/status-experimental--release-yellow)

**Author**: [Ridpath](https://github.com/ridpath)  
**Tool Path**: `/tools/ics_anomaly_detector/ics_detector.py`

---

## Description

This tool implements a comprehensive anomaly detection framework for ICS/SCADA environments using:

- Machine learning ensemble models (Isolation Forest, One-Class SVM, LOF)
- Full protocol-level visibility (Modbus, OPC UA, S7Comm, CIP, DNP3)
- Suricata EVE/Redis integration for alert ingestion
- Prometheus metrics + REST API with FastAPI
- System health monitoring and ML drift detection

Ideal for cyber ranges, testbeds, or blue team defense R&D.

---

## Use Cases

- OT anomaly detection in live packet captures
- Blue team telemetry validation (Suricata + Elasticsearch)
- ICS protocol threat modeling
- SCADA cyber range detection pipeline simulation
- Government test bed detection tooling

---

## MITRE ATT&CK for ICS Coverage

| Technique | Description |
|----------|-------------|
| T0801 | Network Sniffing |
| T0855 | Modify Parameter |
| T0860 | Unsecured Protocols |
| T0811 | Denial of Service |
| T0835 | Program Download |

---

## Features

- Suricata integration via socket + Redis (EVE.json)
- OPC UA parser with anomaly scoring
- Live packet capture (Scapy + PyShark)
- REST API (FastAPI) + Prometheus telemetry
- JSONL export + Elasticsearch ingestion
- Data drift monitoring and re-training logic
- YAML-based configuration for production deployment

---

## Quickstart

Install dependencies:

```bash
pip install -r requirements.txt
```bash
Train a model:
```
python3 ics_detector.py train --samples 1000 --output models/latest_model.pkl
```
Run the API:
```bash
python3 ics_detector.py api --host 0.0.0.0 --port 8000
```
## API Endpoints

- GET / – Health check

- POST /api/v1/detect – Submit captured packets for anomaly detection

- GET /api/v1/health – System + model + Suricata health

- POST /api/v1/train – Trigger retraining with fresh data

## Config Yaml
```yaml
suricata:
  enabled: true
  socket_path: "/var/run/suricata/suricata-command.socket"
  rules_dir: "/var/lib/suricata/rules"
  eve_socket: "redis://localhost:6379/0"

opcua:
  enabled: true
  default_port: 4840
  security_policies: ["Basic256Sha256", "Basic256", "None"]
  monitored_namespaces: [2, 3, 4]

elasticsearch:
  enabled: true
  hosts: ["localhost:9200"]
  index_prefix: "ics-detection-"

monitoring:
  prometheus_port: 8000
  health_check_interval: 30
```

## Disclaimer

This tool is intended for authorized cybersecurity research and red/blue team simulation.
Do not run on live production ICS systems unless explicitly authorized.


## Future Ideas

- Docker/compose support
- Jupyter notebooks for modeling
- Grafana dashboards for detection metrics
- MISP/Sigma correlation export

