<!--
SEO Tags:
modbus toolkit, SCADA hacking tools, ICS cybersecurity, PLC spoofing, Modbus TCP fuzzing, red team OT, MITRE ICS ATT&CK T0836 T0857 T0801, passive sniffing ICS, OT protocol manipulation, SCADA CTF tool, stealth PLC write, control system pentesting
-->

# Modbus Stealth Attack Toolkit

> Modbus TCP exploitation & evasion toolset for red team use in ICS/SCADA cyber ranges.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ICS-T0836%2C%20T0857%2C%20T0801-orange)
![Tool Type](https://img.shields.io/badge/type-red--team-lightgrey)
![Status](https://img.shields.io/badge/status-research--grade-success)

**Author**: [Ridpath](https://github.com/ridpath)  
**Tool Path**: `/tools/modbus-stealth-toolkit/modbus_stealth_attack.py`  
---

## Summary

This toolkit enables stealthy interaction with **Modbus based PLCs** using techniques such as:

- **Spoofed packet injection**
- **Passive sniffing**
- **Fast-flip DoS simulations**
- **Coil reconnaissance**
- **MITRE-aligned evasion tactics**

> Designed for authorized red teaming in OT cyber ranges or lab environments.

---

## Capabilities

| Feature             | Description |
|---------------------|-------------|
| `stealth_coil_write` | Write without persistent connection |
| `send_spoofed_command` | Send forged Modbus packets with spoofed IPs |
| `reconnaissance_scan` | Scan for accessible coils (MITRE T0801) |
| `denial_of_service_attack` | Simulate DoS via rapid coil toggling |
| `passive_sniff`     | Capture Modbus packets without active traffic |
| `--dry-run`         | Simulate without sending packets |

---

## Usage Example

```bash
python3 modbus_stealth_attack.py write 192.168.1.10  --coil 12 --value true --spoof-ip 192.168.1.200
python3 modbus_stealth_attack.py recon 192.168.1.10 --start 0 --end 50 --loops 3
python3 modbus_stealth_attack.py dos 192.168.1.10 --coils 1,2,3,4 --duration 30
python3 modbus_stealth_attack.py sniff --iface eth0 --count 100 --pcap-file capture.pcap
```
## Sample JSON Telemetry (Structured Logging)
```json
{
  "event": "spoofed_command",
  "technique_id": "T0857",
  "tactic": "Inhibit Response Function",
  "target": "192.168.1.10",
  "coil": 12,
  "value": true,
  "spoof_ip": "192.168.1.200",
  "timestamp": 1701201030.792
}
```
## MITRE ICS ATT&CK Mapping
- T0836 – Valid Command Abuse
- T0857 – Inhibit Response Function
- T0801 – Remote System Discovery
- T0842 – Sniff Network Traffic
- T0814 – Modify Controller Tasking (DoS)

## Blue Team Detection Use
This toolkit helps simulate:
- Watchdog bypass via spoofed resets
- Coil scanning behavior
- Protocol evasion with altered TCP flags
- Historian poisoning (with variant)
- Passive ICS telemetry collection for ML

## Legal & Ethics Notice

This tool is for educational, authorized security testing only.
Never use against any OT/ICS systems without explicit written permission.

## Future Ideas

Protocol blending (Modbus + other ICS protocols)

Live ICS honeypot testing

Real-time alert correlation feed into SIEMs

ICS threat actor emulation via YAML scenarios
