<!--
SEO Tags:
ICS cross-domain correlation engine, IT/OT threat detection, MITRE ICS ATT&CK SIEM,
industrial SOC automation tool, SCADA cyber defense, PLC anomaly detection,
multi-stage ICS attack detection, Elasticsearch ICS monitoring, GeoIP ICS security,
OT threat intelligence enrichment, ICS security analytics, cyber-physical intrusion detection
-->

# Cross‑Domain Correlation Engine for IT/OT Security

Advanced real‑time detection of **multi‑stage attacks** across **industrial and enterprise** environments through behavioral analytics and protocol‑aware correlation.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Tool Type](https://img.shields.io/badge/type-Defensive--ICS%2FSIEM-blue)
![Status](https://img.shields.io/badge/status-Active--Research-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ICS-T0859%20T0865%20T0830%20T0889-orange)

**Author**: [Ridpath](https://github.com/ridpath)  
**Tool Path**: `/tools/cross-domain-correlation-engine/cross_domain_correlation.py`

---

## Description

This engine continuously analyzes incoming activity across **IT and OT** networks and identifies coordinated cyber‑physical attacks using:

- Temporal correlation across multiple protocol events
- MITRE ATT&CK for ICS threat logic
- Machine learning anomaly scoring
- ICS asset and GeoIP enrichment
- Forensic alert record creation

Supports **online streaming ingestion** via:

- Socket event feeds  
- Python API event injection  
- RESTful JSON API  
- Elasticsearch indexing

---

## Features

| Capability                          | Description |
|-----------------------------------|-------------|
| Multi‑stage correlation rules     | Detects lateral IT‑to‑OT movement and multi‑protocol reconnaissance |
| Machine learning anomaly detection | Behavior baselines and outlier scoring |
| ICS protocol awareness            | S7Comm, CIP, OPC UA, TRITON, and IT services |
| GeoIP & asset intelligence        | Adds country, vendor, and vulnerability metadata |
| Real‑time alerting                | Email and Elasticsearch integration |
| API service mode                  | `/event` ingestion and `/alerts` retrieval |
| On‑disk historical buffering      | Retroactive analysis support |
| Smart rule chaining               | “Depends_on” correlation sequencing |

---

## MITRE ATT&CK for ICS Coverage

| Technique ID | Technique Name | Purpose |
|-------------|----------------|---------|
| T0859 | Command Execution | Unauthorized OT command operations |
| T0865 | Lateral Tool Transfer | IT→OT pivoting |
| T0830 | Protocol Tunneling | Multi‑protocol recon activity |
| T0889 | Compromise of Safety Systems | TRITON and SIS manipulation alerts |

---

## Requirements
```bash
pip install flask elasticsearch geoip2 scikit-learn numpy requests pyyaml
```


Optional:
- MaxMind GeoLite2‑City.mmdb (GeoIP enrichment)
- Elasticsearch (alert indexing)
- SMTP configuration for alerting

---

## Usage

Service Mode:
```bash
python3 cross_domain_correlation.py --mode service
```
REST API Mode:
```bash
python3 cross_domain_correlation.py --mode api --host 0.0.0.0 --port 5000
```
Send an event:
```
curl -X POST http://localhost:5000/event -H "Content-Type: application/json" -d '
{
  "timestamp": 1748791240,
  "source_ip": "192.168.1.100",
  "destination_ip": "192.168.2.50",
  "protocol": "S7COMM",
  "event_type": "PLC_Stop_Command",
  "severity": "HIGH",
  "details": {},
  "source_domain": "IT"
}'
```
Check alerts
```bash
curl http://localhost:5000/alerts?hours=12
```
## Disclaimer

This system is designed solely for authorized defense research and ICS network protection.
Unauthorized monitoring of production control systems may violate regulatory compliance requirements.

## Roadmap

- Adaptive rule auto‑generation

- US‑CISA CVE OT feed enrichment

- Suricata + Zeek event parsing

- MITRE ICS mapping per correlation output



