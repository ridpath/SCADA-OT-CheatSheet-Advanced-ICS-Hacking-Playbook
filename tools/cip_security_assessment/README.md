<!--
SEO Tags:
Rockwell CIP security tool, EtherNet/IP testing, ICS penetration toolkit, Allen-Bradley PLC exploitation, 
ControlLogix/CompactLogix fuzzing, pycomm3 exploit, OT red team tool, ICS attack simulation, 
MITRE ATT&CK ICS T0833 T0846 T0819, Rockwell buffer overflow, CIP protocol scanner, SCADA control override, 
OT cyber range tool, CIP protocol stress tester, industrial control system fuzzing, Rockwell PLC hacking
-->

# Rockwell CIP Security Assessment Toolkit

> Advanced **ICS/SCADA Red Team Tool** for EtherNet/IP & Rockwell Automation CIP Protocol  
> FOR **AUTHORIZED TESTING ONLY** – See disclaimer below

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ICS-T0833%2C%20T0846%2C%20T0819-orange)
![Tool Type](https://img.shields.io/badge/type-red--team%2Fresearch-lightgrey)
![Status](https://img.shields.io/badge/status-research--grade-success)

**Author**: [Ridpath](https://github.com/ridpath)  
**Tool Path**: `/tools/cip_security_assessment/cip_exploiter.py`  

---

## Description

This toolkit performs **deep protocol-level security testing** and **reconnaissance** against **Rockwell Automation PLCs** (Logix family) via **EtherNet/IP (CIP)**.

Features:

- Read/write tag operations with verification
- Controller mode manipulation (RUN/PROGRAM)
- Security scanning and hardening checks
- Buffer overflow and input fuzzing tests
- Multi-threaded stress tests
- JSON export and CLI automation

Built using the robust `pycomm3` library with layered error handling and retry logic.

---

## Use Cases

- ICS Red Team engagements
- OT security assessments of ControlLogix & CompactLogix devices
- Fuzzing and robustness testing of proprietary Rockwell CIP stacks
- Emulating known attack techniques from MITRE ATT&CK for ICS
- Testing segmentation and CIP access controls in industrial environments

---

## Legal & Ethical Disclaimer

This tool is provided **strictly for legal, authorized use** by trained professionals.  
Do not use this tool in live production environments or against systems you do not own.  
Misuse may violate laws and could lead to **process disruption, physical harm, or criminal liability**.

---

## Installation

```bash
# Python 3.10+ is recommended
pip install -r requirements.txt
```

## Usage
Example Usage

Get controller information:
```bash
python cip_exploiter.py info 192.168.1.100
```

Enumerate tags:
```bash
python cip_exploiter.py list-tags 192.168.1.100 --pattern "Pump"
```

Read/write:
```bash
python cip_exploiter.py read 192.168.1.100 MyTag
python cip_exploiter.py write 192.168.1.100 MyTag 123
```

Stress test:
```bash
python cip_exploiter.py stress-test 192.168.1.100 --duration 60 --threads 10
```

Buffer test:
```bash
python cip_exploiter.py buffer-test 192.168.1.100
```

## MITRE ATT&CK for ICS Coverage

| Technique ID | Technique Name              | Description                                         |
|--------------|-----------------------------|-----------------------------------------------------|
| T0819        | Modify Parameter            | Altering tag values in PLCs to impact system state |
| T0833        | Exploitation for Denial     | Causing service or logic disruptions               |
| T0846        | Program Download            | Unauthorized logic/program download to controller  |
| T0808        | Service Stop                | Forcing controller into PROGRAM or STOP mode       |
| T0825        | Denial of Control           | Interrupting control over physical processes       |

## Output Formats

CLI (human readable)

--json flag for structured JSON output

--output file.json for saving results

Log file: cip_security_assessment.log

## Security Best Practices

- Includes multi-layer retry logic

- Validates IP address and tag format

- Hardens against unintended writes

- Optional readback verification (HIGH level)

- Logs all security-impacting operations

