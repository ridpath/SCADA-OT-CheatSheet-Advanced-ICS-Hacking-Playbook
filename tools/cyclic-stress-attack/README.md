<!--
SEO Tags:
ICS cybersecurity, SCADA red teaming, PLC fuzzing, Modbus stress testing, industrial control system hacking, OT threat simulation, MITRE ICS ATT&CK, blue team detection rules, control loop manipulation, historian poisoning, anomaly detection telemetry, OT malware lab, ICS cyber range, OT cyber range, ICS protocol attack, ICS pen testing, OT CTF tools, ICS attack simulation, Modbus attack toolkit, red team OT, SCADA fuzzing, critical infrastructure testing, ICS MITRE T0858 T0804 T0814
Cyclic Stress Attack Simulator for ICS/SCADA Environments
This advanced Modbus-based simulation tool enables red teams and researchers to launch cyclic, slow-drift and **randomized control signal attacks** against **ICS/SCADA systems** in cyber ranges or testbeds. Designed for testing PLC resilience, blue team detections, historian poisoning, and protocol anomaly detection pipelines.

Supports **Modbus TCP**, coil/register manipulation, stealthy evasion, watchdog resets, and MITRE ICS ATT&CK alignment (e.g. T0858, T0804, T0814).

-->

# Cyclic Stress Attack Simulation 

> Simulation of kinetic process manipulation in OT environments.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ICS-T0858%2C%20T0814%2C%20T0804-orange)
![Status](https://img.shields.io/badge/status-research--grade-success)
![Tool Type](https://img.shields.io/badge/type-red--team%2Fblue--team-lightgrey)


**Author**: [Ridpath](https://github.com/ridpath)  
**Tool Path**: `/tools/cyclic-stress-attack/cyclic_stress_attack.py`  
**MITRE ICS ATT&CK**:
- T0858 – Unauthorized Command Message  
- T0804 – Manipulation of Control  
- T0814 – Modify Controller Tasking

This advanced Modbus based simulation tool enables red teams and researchers to launch **cyclic**, **slow-drift**, and **randomized control signal attacks** against **ICS/SCADA systems** in cyber ranges or testbeds. Designed for testing PLC resilience, blue team detections, historian poisoning, and protocol anomaly detection pipelines.

Supports **Modbus TCP**, coil/register manipulation, stealthy evasion, watchdog resets, and MITRE ICS ATT&CK alignment (e.g. T0858, T0804, T0814).
---

## Purpose

Simulates alternating normal/stress control values to test:

- PLC/historian response to malicious values
- Watchdog resets under abnormal load
- Blue team SIEM alerts and telemetry collection
- ML anomaly detection pipelines
- Historian poisoning stealth scenarios
- Operator interlock protections

---

## Features

| Capability | Description |
|-----------|-------------|
| `--attack-mode` | `cyclic`, `slow-drift`, `randomized`, `blend` (planned) |
| `--stealth`     | Adds jitter/timing variation |
| `--rotate-fc`   | Modbus FC rotation for DPI evasion |
| `--interlock-address` | Honors active state machine flags |
| `--poison-historian` | Sends fake tag values to historian registers |
| `--log-json`    | Structured telemetry logging for ML ingestion |
| `--dry-run`     | Simulate behavior without affecting live PLCs |
| `--register-type` | `coil` or `holding` support |
| `--watchdog-*`  | Periodic resets to avoid shutdowns |

---

## Usage

```bash
python3 cyclic_stress_attack.py 192.168.1.100 \
  --attack-mode slow-drift \
  --stealth \
  --variation 50 \
  --register 100 \
  --cycles 5 \
```

## Sample JSON Log Output
```json
{
  "event": "modbus_write",
  "technique_id": "T0858",
  "tactic": "Execution",
  "protocol": "modbus",
  "register": 100,
  "value": 2945,
  "cycle": 3,
  "mode": "slow-drift",
  "stealth": true,
  "timestamp": 1701201030.792
}
```
## Detection Engineering Value

Security tools that can use this:
- Suricata / Zeek custom rules
- SIGMA rule validation
- ELK log pipeline fuzz testing
- Chronicle / Splunk telemetry feedback
- Anomaly ML training (with --log-json output)

Red/Blue Team Scenarios:
- Simulate kinetic sabotage patterns
- Confirm historian poisoning resilience
- Test detection under jitter + stealth
- Evaluate alert noise from watchdog bypass

## Ethics & Legal Notice
This tool is for educational, research, and authorized red teaming only.

Do not use on any ICS/OT environment unless you have explicit legal permission.


## Future Ideas

Protocol blending (Modbus + CIP)

Scenario YAML runner (Caldera-style)

HMI manipulation / fake sensor values

Integration with OpenPLC or FactoryIO
