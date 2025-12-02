<!-- 
SEO: ICS detection rules, OT SIEM analytics, Suricata rules for SCADA, Zeek industrial protocol monitoring,
Stuxnet TRITON detection content, ICS malware pipeline, ICS cyber range defense,
critical infrastructure cyber defense, MITRE ATT&CK ICS detection, protocol anomaly monitoring,
PLC manipulation alerting, SCADA detection engineering
ics scada suricata zeek ot-security industrial-control-system critical-infrastructure
ics-detection blue-team plc stuxnet triton detection-engineering
mitre-attack-ics cyber-range ot-monitoring industrial-security

-->

# ICS Detection Rules & Security Monitoring Toolkit

Detection content designed for **ICS/SCADA testbeds**, **blue team training**,  
and **OT threat validation**. Includes Suricata rule packs and Zeek monitoring modules  
for malware signatures, **process manipulation**, **multi-protocol reconnaissance**,  
and safety system attacks.

[![Suricata Docs](https://img.shields.io/badge/Suricata-Documentation-red)](https://suricata.io/documentation/)
[![Zeek Docs](https://img.shields.io/badge/Zeek-Network%20Security-blue)](https://docs.zeek.org/)
![MITRE ICS](https://img.shields.io/badge/MITRE%20ATT%26CK-ICS-orange)
![Status](https://img.shields.io/badge/status-experimental-yellow)
![Type](https://img.shields.io/badge/type-detection%2Fblue--team-lightgrey)

Author: Ridpath  
Path: `/configs/`

---

## Detection Pipeline Overview

```
ICS Packet Capture (Span/TAP, PCAP Replay)
        │
        ▼
Suricata (Signatures + Flowbits) ─────────┐
        │                                  │
        ▼                                  │
Zeek (Behavioral + Protocol Analysis) ─────┘
        │
        ▼
Event Enrichment (MITRE / GeoIP / OT Assets)
        │
        ▼
SIEM Correlation (Elastic / Splunk / Chronicle)
        │
        ▼
Operator Alerting + Response
```

---

## Directory Structure

```
configs/
├── suricata_rules/
│   └── stuxnet_triton.rules     # Malware + sabotage signatures
└── zeek/
    └── ics_detection.zeek      # Protocol anomaly + access control detection
```

---

## Suricata ICS Malware Detection Rules

Includes:
- Stuxnet centrifuge speed manipulation (high/low)
- TRITON safety override attempts
- Unauthorized Modbus writes
- ICS protocol reconnaissance
- Multi-stage malicious sequences via flowbits

Deploy:
```bash
sudo cp suricata_rules/*.rules /etc/suricata/rules/
sudo systemctl restart suricata
```

Optional CI testing:
```bash
suricata-verify tests/
```

---

## Zeek Industrial Protocol Monitoring

Monitors:
- Modbus / S7Comm / EtherNet/IP write events
- PLC stop/start + logic download
- High-rate request anomalies
- Multi-protocol reconnaissance
- Safety-critical register manipulation

Enable:
```zeek
@load configs/zeek/ics_detection
```

Logs:
```
logs/current/ics_detection.log
```

---
## Zeek Deployment Automation

Zeek ICS anomaly monitoring modules are automatically validated and deployed with support for:

- Local Zeek environments
- Zeekctl clusters
- Docker/Containerized deployments
- Security Onion integration (optional)

Two scripts below included:

Local deployment (single host, direct OS install)  
Advanced deployment (cluster-aware, docker-aware)

---

### Local Deployment Script  
**File:** `zeek_deploy_local.sh`

```bash
#!/bin/bash
set -euo pipefail

ZEEK_SITE_DIR_DEFAULT="/usr/local/zeek/share/zeek/site"
ZEEK_SCRIPT_SRC="zeek/ics_detection.zeek"
LOG_FILE="/var/log/zeek_ics_deploy.log"

ZEEK_SITE_DIR="${1:-$ZEEK_SITE_DIR_DEFAULT}"

echo "================================================" | tee -a "$LOG_FILE"
echo "[Zeek ICS Deploy] $(date)" | tee -a "$LOG_FILE"
echo "Target Site Dir: $ZEEK_SITE_DIR" | tee -a "$LOG_FILE"
echo "================================================" | tee -a "$LOG_FILE"

if ! command -v zeek &>/dev/null; then
    echo "[ERROR] Zeek not found in PATH" | tee -a "$LOG_FILE"
    exit 1
fi

if [ ! -d "$ZEEK_SITE_DIR" ]; then
    echo "[ERROR] Zeek site directory does not exist: $ZEEK_SITE_DIR" | tee -a "$LOG_FILE"
    exit 1
fi

if [ ! -f "$ZEEK_SCRIPT_SRC" ]; then
    echo "[ERROR] Detection script missing: $ZEEK_SCRIPT_SRC" | tee -a "$LOG_FILE"
    exit 1
fi

BACKUP_DIR="$ZEEK_SITE_DIR/backup-$(date +%F-%H%M)"
echo "[+] Backing up existing scripts to $BACKUP_DIR"
sudo mkdir -p "$BACKUP_DIR"
sudo cp "$ZEEK_SITE_DIR"/*.zeek "$BACKUP_DIR"/ || true

echo "[+] Deploying ICS Detection Module"
sudo cp "$ZEEK_SCRIPT_SRC" "$ZEEK_SITE_DIR/"

echo "[+] Validating syntax"
zeek -C -c "$ZEEK_SITE_DIR/ics_detection.zeek" | tee -a "$LOG_FILE"

echo "[+] Deployment Complete"
echo "[✓] Zeek ICS detection module is ready" | tee -a "$LOG_FILE"
```

Run:
```bash
bash zeek_deploy_local.sh
```

Custom target:
```bash
bash zeek_deploy_local.sh /opt/security/zeek/site
```

---

### Advanced Deployment Script
**File:** `zeek_deploy_advanced.sh`  
Designed for:

- Zeekctl Clusters
- Docker containers running Zeek
- Security Onion environments

```bash
#!/bin/bash
set -euo pipefail

ZEEK_SCRIPT_SRC="zeek/ics_detection.zeek"
LOG_FILE="/var/log/zeek_ics_advanced_deploy.log"

ZEEK_SITE_DIR_DEFAULT="/usr/local/zeek/share/zeek/site"
ZEEKCTL_CONFIG="/usr/local/zeek/etc/node.cfg"

ZEEK_SITE_DIR="${1:-$ZEEK_SITE_DIR_DEFAULT}"

echo "================================================" | tee -a "$LOG_FILE"
echo "[Zeek ICS Deploy - Advanced Mode] $(date)" | tee -a "$LOG_FILE"
echo "Target Site Dir: $ZEEK_SITE_DIR" | tee -a "$LOG_FILE"
echo "================================================" | tee -a "$LOG_FILE"

if ! command -v zeek &>/dev/null; then
    echo "[ERROR] Zeek not installed" | tee -a "$LOG_FILE"
    exit 1
fi

if [ ! -f "$ZEEK_SCRIPT_SRC" ]; then
    echo "[ERROR] Missing ICS detection module: $ZEEK_SCRIPT_SRC" | tee -a "$LOG_FILE"
    exit 1
fi

# Security Onion support
if command -v so-zeek &>/dev/null; then
    echo "[+] Security Onion detected — using so-zeek sync"
    sudo cp "$ZEEK_SCRIPT_SRC" "/opt/so/saltstack/local/salt/zeek/policies/"
    sudo so-zeek-restart || sudo so-zeek-refresh
    echo "[✓] ICS module deployed via Security Onion"
    exit 0
fi

# Zeekctl cluster support
if command -v zeekctl &>/dev/null && [ -f "$ZEEKCTL_CONFIG" ]; then
    echo "[+] Zeekctl cluster detected — deploying to cluster nodes"
    sudo cp "$ZEEK_SCRIPT_SRC" "$ZEEK_SITE_DIR/"
    zeekctl check | tee -a "$LOG_FILE"
    zeekctl install | tee -a "$LOG_FILE"
    zeekctl restart || zeekctl deploy
    echo "[✓] ICS module deployed to cluster"
    exit 0
fi

# Fallback: container-aware mode
if command -v docker &>/dev/null; then
    echo "[i] Docker environment possible — manual instructions:"
    echo "  docker cp ics_detection.zeek <container>:/usr/local/zeek/share/zeek/site/"
fi

echo "[✓] Advanced deployment complete (standalone mode)"
```

Run:
```bash
bash zeek_deploy_advanced.sh
```

Cluster mode auto-detects Zeekctl  
Security Onion auto-detects so-zeek  
Docker gives instructions rather than failing

---

### Zeek Enablement Reminder

After deployment, ensure it is loaded:

```zeek
@load ics_detection
```

Location:  
`/usr/local/zeek/share/zeek/site/local.zeek`  
or Security Onion equivalent

---
---

## SIEM Integration Templates

### Elasticsearch Output
```
output:
  elasticsearch:
    enabled: true
    hosts: ["http://localhost:9200"]
    index: "ot-detections-%Y.%m.%d"
```

### Splunk HEC Mapping
```
[splunk_hec]
url = https://splunk:8088/services/collector
token = GENERATE_TOKEN_HERE
sourcetype = "ics-detection"
```

Recommended dashboards:  
- Stuxnet/Triton specific alerting  
- PLC manipulation timeline  
- OT access violations heatmap  

---

## Suricata Auto Load Deployment Script

Add this helper in the same folder:

File: `deploy_rules.sh`
```bash
#!/bin/bash

set -euo pipefail

RULE_DIR_DEFAULT="/etc/suricata/rules"
SURICATA_CFG_DEFAULT="/etc/suricata/suricata.yaml"
LOG_FILE="/var/log/suricata_ics_rule_deploy.log"

RULE_SRC="suricata_rules/*.rules"
BACKUP_DIR="/etc/suricata/rules-backup-$(date +%F-%H%M)"

RULE_DIR="${1:-$RULE_DIR_DEFAULT}"
SURICATA_CFG="${2:-$SURICATA_CFG_DEFAULT}"

echo "================================================" | tee -a "$LOG_FILE"
echo "[ICS Rule Deployment] $(date)" | tee -a "$LOG_FILE"
echo "Rule directory: $RULE_DIR" | tee -a "$LOG_FILE"
echo "Suricata config: $SURICATA_CFG" | tee -a "$LOG_FILE"
echo "================================================" | tee -a "$LOG_FILE"

if ! command -v suricata &> /dev/null; then
    echo "[ERROR] Suricata is not installed or not in PATH" | tee -a "$LOG_FILE"
    exit 1
fi

if [ ! -d "$RULE_DIR" ]; then
    echo "[ERROR] Rule directory not found: $RULE_DIR" | tee -a "$LOG_FILE"
    exit 1
fi

if ! ls $RULE_SRC 1> /dev/null 2>&1; then
    echo "[ERROR] No rules found in suricata_rules/" | tee -a "$LOG_FILE"
    exit 1
fi

echo "[+] Creating backup: $BACKUP_DIR" | tee -a "$LOG_FILE"
sudo mkdir -p "$BACKUP_DIR"
sudo cp "$RULE_DIR"/*.rules "$BACKUP_DIR/"

echo "[+] Deploying ICS rules from suricata_rules/" | tee -a "$LOG_FILE"
sudo cp $RULE_SRC "$RULE_DIR/"

echo "[+] Validating rule syntax..." | tee -a "$LOG_FILE"
sudo suricata -T -c "$SURICATA_CFG" | tee -a "$LOG_FILE"

echo "[+] Restarting Suricata service" | tee -a "$LOG_FILE"
sudo systemctl restart suricata

echo "[✓] ICS rules deployed and validated successfully!" | tee -a "$LOG_FILE"
echo "Log saved to $LOG_FILE"

```

Usage:
```bash
bash deploy_rules.sh
```

---

## MITRE ATT&CK ICS Coverage Highlights

| Technique | Category |
|----------|---------|
| T0801 | Network Sniffing |
| T0804 | Manipulation of Control |
| T0836 | Valid Command Abuse |
| T0855 | Modify Parameter |
| T0842 | Sniff Network Traffic |
| T0843 | Execution on Safety System |
| T0823 | Modify Control Logic |
| T0833 | Exploitation for Denial |

<!-- 
SEO:ICS-cybersecurity
SCADA-detection
Suricata-rules
Zeek-scripts
OT-blue-team
Industrial-protocol-security
Stuxnet
TRITON
ICS-anomaly-detection
-->

---

## Compliance and Safety

These detection packs are intended **only** for:
- Non-production test labs
- Cyber ranges
- Blue team R&D

Deploying in **live OT** may create false positives that disrupt operations.

---

## Roadmap

- DNP3 + OPC-UA rule extensions
- Sigma rule exports
- PCAP regression testing suite
- Elastic/Grafana analytic dashboards
- Red team emulation YAML feeds

