# CIP/EtherNet/IP Protocol Quick Reference

## Protocol Overview
- **Protocol**: Common Industrial Protocol (CIP) over EtherNet/IP
- **Port**: TCP/44818, UDP/2222
- **OSI Layer**: Application Layer
- **Vendor**: Rockwell Automation (Allen-Bradley), ODVA
- **Primary Use**: ControlLogix, CompactLogix, MicroLogix PLCs

## Attack Tool Reference
**Implementation**: `tools/cip_security_assessment/cip_exploiter.py`
**Version**: 5.0
**Testing Guide**: `tools/cip_security_assessment/TESTING.md`

## EtherNet/IP Encapsulation Commands
| Command | Name | Purpose | MITRE |
|---------|------|---------|-------|
| 0x0000 | NOP | Keep-alive | - |
| 0x0004 | ListServices | Service discovery | T0888 |
| 0x0063 | ListIdentity | Device identification | T0888, T0868 |
| 0x0064 | ListInterfaces | Interface enumeration | T0888 |
| 0x0065 | RegisterSession | Session establishment | - |
| 0x0066 | UnregisterSession | Session termination | - |
| 0x006F | SendRRData | Request/Response data | T0801 |
| 0x0070 | SendUnitData | Unconnected send | T0855 |
| 0x0072 | IndicateStatus | Status notification | T0804 |
| 0x0073 | Cancel | Cancel request | - |

**Reference**: `cip_exploiter.py:131-142`

## CIP Service Codes
| Code | Service | MITRE | Tool Method |
|------|---------|-------|-------------|
| 0x01 | Get_Attributes_All | T0801, T0861 | `enumerate_cip_objects()` |
| 0x02 | Set_Attributes_All | T0855 | N/A |
| 0x0E | Get_Attribute_Single | T0801 | `enumerate_cip_objects()` |
| 0x10 | Set_Attribute_Single | T0855, T0836 | N/A |
| 0x05 | Reset | T0858, T0809 | N/A |
| 0x06 | Start | T0858, T0871 | N/A |
| 0x07 | Stop | T0858, T0809 | N/A |
| 0x4C | Read_Tag | T0801, T0861 | `read_tag()` |
| 0x4D | Write_Tag | T0855, T0836 | `write_tag()` |
| 0x52 | Read_Tag_Fragmented | T0801 | `read_large_tag()` |
| 0x53 | Write_Tag_Fragmented | T0855 | `write_large_tag()` |
| 0x4E | Read_Modify_Write_Tag | T0855 | N/A |

**Reference**: `cip_exploiter.py:44-73`

## CIP Object Classes
| Class | Name | Purpose | Security Relevance |
|-------|------|---------|---------------------|
| 0x01 | Identity | Device identification | Reconnaissance |
| 0x04 | Assembly | I/O data aggregation | Data manipulation |
| 0x06 | Connection Manager | Connection handling | DoS attacks |
| 0x37 | File | File operations | Project infection |
| 0x39 | Safety Supervisor | Safety I/O management | Safety bypass |
| 0x3A | Safety Validator | Safety validation | Safety manipulation |
| 0x3B | Safety Connection | Safety communications | Safety disruption |
| 0x5D | CIP Security | Security features | Security assessment |
| 0x67 | Control Supervisor | Control coordination | Control manipulation |
| 0x75 | TCP/IP Interface | Network configuration | Network attacks |
| 0x76 | Ethernet Link | Ethernet settings | Network monitoring |

**Reference**: `cip_exploiter.py:75-93`

## CIP Status Codes
| Code | Status | Meaning |
|------|--------|---------|
| 0x00 | SUCCESS | Operation successful |
| 0x01 | CONNECTION_FAILURE | Connection error |
| 0x03 | INVALID_PARAMETER_VALUE | Bad parameter |
| 0x05 | PATH_DESTINATION_UNKNOWN | Invalid object path |
| 0x08 | SERVICE_NOT_SUPPORTED | Service unavailable |
| 0x0F | PRIVILEGE_VIOLATION | Access denied |
| 0x10 | DEVICE_STATE_CONFLICT | Invalid device state |
| 0x16 | OBJECT_DOES_NOT_EXIST | Object not found |
| 0x1F | EMBEDDED_SERVICE_ERROR | Service-specific error |

**Reference**: `cip_exploiter.py:95-129`

## Packet Structure

### EtherNet/IP Encapsulation Header
```
Header (24 bytes):
  Command: 2 bytes (command code)
  Length: 2 bytes (data length)
  Session Handle: 4 bytes (session ID)
  Status: 4 bytes (status code)
  Sender Context: 8 bytes (sender context)
  Options: 4 bytes (protocol options)

Data: variable (CIP packet)
```
**Reference**: `cip_exploiter.py:151-165`

### CIP Packet Structure
```
Service: 1 byte (service code)
Request Path Size: 1 byte (path length in words)
Request Path: variable (object class/instance/attribute)
Request Data: variable (service-specific)
```
**Reference**: `cip_exploiter.py:194-225`

### Safety Packet Structure
```
Safety Header:
  Mode: 1 byte
  Sequence Number: 2 bytes
  Timestamp: 4 bytes
  
Safety Data: variable
CRC-16: 2 bytes (safety checksum)
```
**Reference**: `cip_exploiter.py:235-255`

## Attack Methods

### 1. Device Reconnaissance
```bash
# ListIdentity - enumerate all devices on network
python3 cip_exploiter.py --target 192.168.1.255 --broadcast enumerate

# Enumerate CIP objects
python3 cip_exploiter.py --target 192.168.1.10 enumerate-objects --output objects.json

# CIP Security object assessment
python3 cip_exploiter.py --target 192.168.1.10 cip-security-assess
```
**MITRE**: T0888 (Remote System Discovery), T0801 (Monitor Process State), T0868 (Detect Operating Mode)
**Tool Reference**: `cip_exploiter.py:500-600`

### 2. Tag Operations
```bash
# Read tag value
python3 cip_exploiter.py --target 192.168.1.10 --read-tag "Program:MainProgram.Speed"

# Write tag value
python3 cip_exploiter.py --target 192.168.1.10 --write-tag "Program:MainProgram.Speed" --value 5000 --type DINT

# Read large tag (fragmented)
python3 cip_exploiter.py --target 192.168.1.10 --read-large-tag "Program:MainProgram.LargeArray"
```
**MITRE**: T0801 (Monitor Process State), T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
**Tool Reference**: `cip_exploiter.py:650-750`

### 3. Safety I/O Exploitation
```bash
# Exploit Safety I/O (CIP Safety)
python3 cip_exploiter.py --target 192.168.1.10 safety-io-exploit --class 0x39 --instance 1
```
**MITRE**: T0855 (Unauthorized Command Message), T0878 (Alarm Suppression)
**Tool Reference**: `cip_exploiter.py:1100-1200`

### 4. Implicit Messaging Manipulation
```bash
# Manipulate Class 1 implicit connections
python3 cip_exploiter.py --target 192.168.1.10 implicit-msg --assembly 100 --data "AABBCCDD"
```
**MITRE**: T0855 (Unauthorized Command Message), T0856 (Spoof Reporting Message)
**Tool Reference**: `cip_exploiter.py:1200-1300`

### 5. Protocol Fuzzing
```bash
# Fuzz specific CIP class
python3 cip_exploiter.py --target 192.168.1.10 fuzz-class --class 0x04 --iterations 1000
```
**MITRE**: T0855 (Unauthorized Command Message)
**Tool Reference**: `cip_exploiter.py:1300-1400`

### 6. Configuration Manipulation
```bash
# Modify TCP/IP interface settings
python3 cip_exploiter.py --target 192.168.1.10 --modify-tcpip --ip 192.168.1.100

# Change device name
python3 cip_exploiter.py --target 192.168.1.10 --set-name "COMPROMISED_PLC"
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)

## Detection Signatures

### Suricata Rules
**File**: `configs/suricata_rules/ics_malware_detection.rules`

```
# CIP Safety I/O exploitation
alert tcp any any -> any 44818 (msg:"ICS: CIP Safety I/O Exploitation Attempt"; \
    content:"|00 6F|"; offset:0; depth:2; \
    content:"|39|"; distance:0; within:50; \
    reference:url,attack.mitre.org/techniques/T0855; \
    classtype:industrial-protocol; sid:400012; rev:1;)

# CIP implicit messaging manipulation
alert tcp any any -> any 44818 (msg:"ICS: CIP Implicit Messaging Manipulation"; \
    content:"|00 70|"; offset:0; depth:2; \
    content:"|04|"; distance:0; within:50; \
    threshold: type threshold, track by_src, count 5, seconds 10; \
    classtype:industrial-protocol; sid:400013; rev:1;)

# CIP Security object enumeration
alert tcp any any -> any 44818 (msg:"ICS: CIP Security Object Enumeration"; \
    content:"|00 6F|"; offset:0; depth:2; content:"|01|"; distance:24; depth:1; \
    content:"|5D|"; distance:0; within:10; \
    classtype:industrial-protocol; sid:400014; rev:1;)

# CIP protocol fuzzing
alert tcp any any -> any 44818 (msg:"ICS: CIP Protocol Fuzzing Detected"; \
    dsize:>500; content:"|00 6F|"; offset:0; depth:2; \
    threshold: type threshold, track by_src, count 10, seconds 30; \
    classtype:industrial-protocol; sid:400015; rev:1;)

# EtherNet/IP ListIdentity reconnaissance
alert udp any any -> any 2222 (msg:"ICS: EtherNet/IP ListIdentity Reconnaissance"; \
    content:"|00 63|"; offset:0; depth:2; \
    threshold: type threshold, track by_src, count 5, seconds 10; \
    classtype:industrial-protocol; sid:400016; rev:1;)
```

### Zeek Detection
**File**: `configs/zeek/ics_detection.zeek`

```zeek
# CIP service tracking
event enip_cip_service(c: connection, service: count, class: count, instance: count) {
    local severity = "MEDIUM";
    local operation = "";
    
    # Safety class access (0x39, 0x3A, 0x3B)
    if (class == 0x39 || class == 0x3A || class == 0x3B) {
        severity = "CRITICAL";
        operation = "SAFETY_IO_ACCESS";
        
        Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $protocol="CIP", $operation=operation, $severity=severity,
            $details=fmt("Service: 0x%02x, Class: 0x%02x, Instance: %d", service, class, instance)]);
    }
    
    # CIP Security object access (0x5D)
    if (class == 0x5D) {
        Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $protocol="CIP", $operation="SECURITY_OBJECT_ACCESS",
            $severity="HIGH", $details=fmt("Service: 0x%02x", service)]);
    }
}

# Implicit messaging monitoring (SendUnitData - 0x0070)
global implicit_msg_count: table[addr] of count &create_expire=10sec;

event enip_encap_command(c: connection, command: count) {
    if (command == 0x0070) {  # SendUnitData
        if (c$id$orig_h !in implicit_msg_count) {
            implicit_msg_count[c$id$orig_h] = 0;
        }
        implicit_msg_count[c$id$orig_h] += 1;
        
        if (implicit_msg_count[c$id$orig_h] >= 5) {
            Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
                $protocol="CIP", $operation="IMPLICIT_MSG_MANIPULATION",
                $severity="HIGH", $details=fmt("SendUnitData count: %d in 10s", implicit_msg_count[c$id$orig_h])]);
        }
    }
}

# ListIdentity broadcast monitoring
event enip_list_identity(c: connection) {
    if (c$id$resp_h == 255.255.255.255 || is_local_addr(c$id$resp_h)) {
        Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $protocol="EtherNet/IP", $operation="LIST_IDENTITY_SCAN",
            $severity="MEDIUM", $details="Network reconnaissance"]);
    }
}
```

## MITRE ATT&CK Mapping

### Reconnaissance (Tactic: TA0043)
- **T0888**: Remote System Information Discovery
  - Methods: ListIdentity, ListServices, enumerate_cip_objects()
- **T0801**: Monitor Process State
  - Methods: Read_Tag, Get_Attributes_All
- **T0868**: Detect Operating Mode
  - Methods: Identity object queries

### Discovery (Tactic: TA0102)
- **T0861**: Point & Tag Identification
  - Methods: Tag enumeration, object discovery

### Execution (Tactic: TA0104)
- **T0871**: Execution through API
  - Methods: Start service (0x06), Write_Tag

### Persistence (Tactic: TA0110)
- **T0843**: Program Download
  - Methods: File object manipulation
- **T0873**: Project File Infection
  - Methods: File write operations

### Defense Evasion (Tactic: TA0103)
- **T0849**: Exploit Public-Facing Application
  - Methods: Safety object manipulation

### Impact (Tactic: TA0105)
- **T0855**: Unauthorized Command Message
  - Methods: Write_Tag, Set_Attribute, Safety I/O manipulation
- **T0836**: Modify Parameter
  - Methods: Tag writes, attribute modifications
- **T0858**: Change Operating Mode
  - Methods: Start (0x06), Stop (0x07), Reset (0x05)
- **T0809**: Data Destruction
  - Methods: Reset service, Stop service
- **T0878**: Alarm Suppression
  - Methods: Safety I/O exploitation, implicit messaging
- **T0856**: Spoof Reporting Message
  - Methods: Implicit connection manipulation

### Inhibit Response (Tactic: TA0107)
- **T0803**: Block Command Message
  - Methods: Connection manipulation
- **T0804**: Block Reporting Message
  - Methods: SendUnitData manipulation

## Common Vulnerabilities

### Unauthenticated Access
- **Issue**: No authentication in standard CIP
- **Impact**: Any network client can read/write tags
- **Mitigation**: CIP Security object (Class 0x5D), network segmentation

### Broadcast Enumeration
- **Issue**: ListIdentity responds to UDP broadcast
- **Impact**: Complete network device discovery
- **Mitigation**: Firewall UDP/2222, monitor broadcast traffic

### Safety System Bypass
- **Issue**: CIP Safety objects accessible via standard CIP
- **Impact**: Safety I/O manipulation, alarm suppression
- **Mitigation**: Separate safety networks, dedicated safety PLCs

### Implicit Connection Spoofing
- **Issue**: Class 1 connections use predictable sequence numbers
- **Impact**: I/O data injection, process manipulation
- **Mitigation**: Connection monitoring, sequence validation

### No Encryption
- **Issue**: All traffic in cleartext (except CIP Security)
- **Impact**: Traffic analysis, replay attacks
- **Mitigation**: VPN, CIP Security implementation

## Defense Recommendations

### Network Layer
1. **Segmentation**: Isolate EtherNet/IP networks from IT
2. **Firewall Rules**: 
   - Restrict TCP/44818 to authorized engineering stations
   - Block UDP/2222 broadcasts or limit to local subnet
3. **IDS/IPS**: Deploy Suricata rules for CIP monitoring
4. **Network Monitoring**: Zeek scripts for protocol analysis

### Device Configuration
1. **CIP Security**: Enable CIP Security object (Class 0x5D) if supported
2. **Connection Limits**: Restrict maximum concurrent connections
3. **Tag Protection**: Implement tag-level access control
4. **Safety Networks**: Separate safety I/O on dedicated network

### Application Layer
1. **Tag Whitelisting**: Maintain list of authorized tags
2. **Write Protection**: Mark critical tags as read-only
3. **Change Detection**: Monitor tag value changes
4. **Session Management**: Track all CIP sessions

### Operational
1. **Baseline Traffic**: Establish normal CIP communication patterns
2. **Change Control**: Document all tag modifications
3. **Audit Logging**: Log all CIP operations with timestamps
4. **Incident Response**: Define procedures for anomalous CIP activity

## Protocol Limits
- **Max Packet Size**: 504 bytes (CIP data)
- **Max Tag Name Length**: 40 characters
- **Max Array Elements per Request**: Depends on data type
- **Max Connections**: Device-dependent (typically 8-32)
- **Max Services per MultiService**: 16 services

**Reference**: CIP Networks Library Volume 1, Revision 1.15

## Testing Checklist

### Reconnaissance Testing
- [ ] ListIdentity broadcast enumeration
- [ ] ListServices discovery
- [ ] CIP object enumeration
- [ ] Identity object queries
- [ ] CIP Security assessment

### Tag Operation Testing
- [ ] Read_Tag operations
- [ ] Write_Tag operations
- [ ] Fragmented tag reads
- [ ] Fragmented tag writes
- [ ] Read_Modify_Write operations

### Safety Testing
- [ ] Safety Supervisor access (0x39)
- [ ] Safety Validator access (0x3A)
- [ ] Safety Connection manipulation (0x3B)
- [ ] Safety I/O exploitation
- [ ] Alarm suppression testing

### Advanced Testing
- [ ] Implicit messaging manipulation
- [ ] Assembly object fuzzing
- [ ] Connection Manager attacks
- [ ] File object manipulation
- [ ] TCP/IP Interface modification

### Detection Validation
- [ ] Suricata rule triggering
- [ ] Zeek log generation
- [ ] SIEM alert verification
- [ ] False positive analysis
- [ ] PCAP validation

## References
- ODVA CIP Networks Library, Volume 1 & 2
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/cip_security_assessment/cip_exploiter.py`
- Detection Rules: `configs/suricata_rules/ics_malware_detection.rules`
- Zeek Monitor: `configs/zeek/ics_detection.zeek`
- Testing Guide: `tools/cip_security_assessment/TESTING.md`
