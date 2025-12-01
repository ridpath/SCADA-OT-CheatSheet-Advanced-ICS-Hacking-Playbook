<!--
SEO: ICS Security Framework, SCADA Exploitation Tools, OT Cybersecurity Offensive and Defensive Tooling,
ICS Protocol Exploits, Industrial Control System Penetration Testing, Critical Infrastructure Cyber Range,
Modbus Security Toolkit, Siemens S7Comm Exploitation, Rockwell Automation CIP Vulnerabilities, 
ICS Malware Simulation, Stuxnet Emulation, PLC Logic Tampering, ICS Network Reconnaissance,
ICS Intrusion Detection, ICS Anomaly Detection Machine Learning, Suricata ICS Rules, Zeek ICS Scripts,
MITRE ATT&CK for ICS Detection Engineering, SIEM IT/OT Correlation, Historian Security Assessment,
OT Threat Intelligence, Industrial Protocol Fuzzing, Control System Sabotage Simulation,
ICS Lateral Movement Detection, Safety System Integrity Validation, Engineering Workstation Monitoring,
ICS Adversary Emulation, OT Incident Response Tools, ICS Detection Playbooks, 
ICS Security Open Source, Critical Infrastructure Security Research, 
ICS/SCADA Red Team Tools, Blue Team Detection for OT Environments, 
Industrial Digital Twins, Process Impact Testing, OT Log Analysis, PLC Backdoor Detection,
CIP and Modbus Blended Attack Scenarios, Physical Process Safety Cyber Defense
-->


# ICS Security Tooling - Operational Arsenal

![domain](https://img.shields.io/badge/domain-ICS%2FSCADA-critical)
![license](https://img.shields.io/badge/license-MIT-blue)
![focus](https://img.shields.io/badge/focus-Offense%20%7C%20Defense%20%7C%20Simulation-black)

A complete suite of offensive, defensive, and threat emulation tooling for ICS/SCADA cyber ranges.  
Each tool includes MITRE ATT&CK for ICS mappings and structured logging for SIEM and ML pipelines.

---

## Tool Index

| Tool | Role | Status | ATT&CK ICS Techniques | Primary Protocol |
|------|------|--------|---------------------|-----------------|
| [cip_security_assessment](./tools/cip_security_assessment/) | ![role](https://img.shields.io/badge/role-Red%20Team-critical) | ![status](https://img.shields.io/badge/status-Research-success) | T0819,T0833,T0846,T0808,T0825 | ![rockwell](https://img.shields.io/badge/Rockwell-CIP-red) |
| [cross-domain-correlation-engine](./tools/cross-domain-correlation-engine/) | ![role](https://img.shields.io/badge/role-Defense-blue) | ![status](https://img.shields.io/badge/status-Active-green) | T0859,T0865,T0830,T0889 | ![elasticsearch](https://img.shields.io/badge/Elasticsearch-yellow) |
| [cyclic-stress-attack](./tools/cyclic-stress-attack/) | ![role](https://img.shields.io/badge/role-Red%20%2F%20Blue-purple) | ![status](https://img.shields.io/badge/status-Research-success) | T0858,T0814,T0804 | ![modbus](https://img.shields.io/badge/Modbus-TCP-blue) |
| [ics_anomaly_detector](./tools/ics_anomaly_detector/) | ![role](https://img.shields.io/badge/role-Defense-blue) | ![status](https://img.shields.io/badge/status-Experimental-yellow) | T0801,T0855,T0860,T0811,T0835 | ![suricata](https://img.shields.io/badge/Suricata-orange) ![opcua](https://img.shields.io/badge/OPC--UA-lightgrey) |
| [modbus-stealth-toolkit](./tools/modbus-stealth-toolkit/) | ![role](https://img.shields.io/badge/role-Red%20Team-critical) | ![status](https://img.shields.io/badge/status-Research-success) | T0836,T0857,T0801,T0842,T0814 | ![modbus](https://img.shields.io/badge/Modbus-TCP-lightblue) |
| [s7comm_security_framework](./tools/s7comm_security_framework/) | ![role](https://img.shields.io/badge/role-Red%20Team-critical) | ![status](https://img.shields.io/badge/status-Research-success) | T0801–T0833 | ![siemens](https://img.shields.io/badge/Siemens-S7Comm-green) |
| [stuxnet_simulator](./tools/stuxnet_simulator/) | ![role](https://img.shields.io/badge/role-Simulation%2FMalware-darkred) | ![status](https://img.shields.io/badge/status-Active--Simulation-red) | T0801,T0809,T0814,T0823,T0833,T0857 | ![malware](https://img.shields.io/badge/ICS-Malware-black) |

---
## Integration Matrix

| Objective | Primary Tools |
|---------|----------------|
| Historian poisoning resilience | modbus-stealth-toolkit and cyclic-stress-attack |
| ICS malware emulation | stuxnet_simulator and s7comm_security_framework |
| IT to OT pivot detection | stuxnet_simulator and correlation engine |
| Logic tamper detection | s7comm_security_framework and anomaly detector |
| Protocol evasion testing | modbus + cyclic stress stealth modes |


## Legal Notice

These tools can directly impact operational technology and physical processes.  
Use only in controlled environments under proper authorization.  
Users are responsible for complying with local and international law.

---

## Roadmap

- Protocol blending (CIP plus Modbus)
- MITRE export mapping and Navigator JSON
- Threat scenario automation with YAML
- Grafana dashboards for ML drift
- Honeypot integration


<!--
OT Security Tools: Modbus, S7, CIP, OPC UA detection, CI/CD for ICS security, 
Industrial anomaly detection, ICS packet capture, protocol-aware stealth payloads,
Cyber-physical attack simulations, ICS adversary capabilities research.
-->

