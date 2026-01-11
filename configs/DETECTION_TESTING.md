# ICS Detection Rules Testing Guide

## Overview

This guide provides comprehensive testing procedures for validating the accuracy and effectiveness of ICS detection rules in both Suricata and Zeek. Testing ensures detection rules trigger on malicious traffic while minimizing false positives on legitimate operations.

## Test Environment Setup

### Prerequisites

```bash
# Suricata installation
apt-get install suricata

# Zeek installation
apt-get install zeek

# Python tools for traffic generation
pip install scapy pymodbus snap7 pycomm3
```

### Test Network Configuration

```
Test Network: 192.168.100.0/24
- Attacker: 192.168.100.10
- PLC Target: 192.168.100.50
- HMI (Authorized): 192.168.100.51
- Safety System: 192.168.100.100
```

## Suricata Rule Testing

### Rule Validation

```bash
# Validate rule syntax
suricata -T -c /etc/suricata/suricata.yaml

# Test specific rule file
suricata -T -S configs/suricata_rules/ics_malware_detection.rules
```

### Test Case 1: Stuxnet S7Comm Centrifuge Manipulation

**Rule SID**: 500001, 500005

**Test Traffic Generation**:
```python
# tools/s7comm_security_framework/s7comm_exploit.py
python s7comm_exploit.py --target 192.168.100.50 --attack centrifuge-speed --speed 1410
```

**Expected Behavior**:
- SID 500001 should trigger on high-speed (>1400 Hz) manipulation
- Alert priority: 1 (Critical)
- Should set flowbit: stuxnet_candidate

**PCAP Validation**:
```bash
# Replay test PCAP
tcpreplay -i eth0 -t tests/pcaps/stuxnet_high_speed.pcap

# Check alerts
tail -f /var/log/suricata/fast.log | grep STUXNET_S7COMM
```

**False Positive Test**:
- Normal S7Comm reads (FC 0x04) should NOT trigger
- Speed writes in normal range (800-1400 Hz) should NOT trigger

### Test Case 2: Modbus File Transfer Operations

**Rule SID**: 400006

**Test Traffic Generation**:
```python
# tools/modbus-stealth-toolkit/modbus_stealth_attack.py
python modbus_stealth_attack.py --target 192.168.100.50 --mode file-read --file-number 1 --record-number 0
```

**Expected Behavior**:
- Triggers on Modbus FC 0x14, 0x15, 0x16, 0x17
- Threshold: 2 operations in 300 seconds
- MITRE: T0868 (Detect Program State)

**Validation**:
```bash
# Monitor alerts
suricata-json-parser /var/log/suricata/eve.json | grep MODBUS_FILE_TRANSFER
```

**False Positive Test**:
- Single file read operation should NOT trigger
- Standard Modbus read holding registers (FC 0x03) should NOT trigger

### Test Case 3: DNP3 Cold Restart Detection

**Rule SID**: 400004

**Test Traffic Generation**:
```python
from scapy.all import *
from scapy.layers.dnp3 import DNP3

# DNP3 cold restart packet
pkt = IP(dst="192.168.100.50")/TCP(dport=20000)/DNP3(control=0x0D)
send(pkt)
```

**Expected Behavior**:
- Triggers on DNP3 function code 0x0D
- Alert priority: 1 (Critical)
- Threshold: 1 occurrence in 3600 seconds

**False Positive Test**:
- Normal DNP3 read requests should NOT trigger
- DNP3 integrity poll should NOT trigger

### Test Case 4: CIP Safety I/O Exploitation

**Rule SID**: 400012

**Test Traffic Generation**:
```python
# tools/cip_security_assessment/cip_exploiter.py
python cip_exploiter.py --target 192.168.100.50 --action safety-io-exploit --class-id 0x39
```

**Expected Behavior**:
- Triggers on CIP Safety Object (0x39) access
- Sets flowbit: cip_safety_access
- MITRE: T0878 (Alarm Suppression)

**Validation**:
```bash
# Check for Safety I/O alerts
grep CIP_SAFETY_IO_EXPLOITATION /var/log/suricata/fast.log
```

**False Positive Test**:
- Normal CIP Identity Object (0x01) access should NOT trigger
- CIP Assembly Object (0x04) reads should NOT trigger

### Test Case 5: S7Comm Data Block Mass Export

**Rule SID**: 400010

**Test Traffic Generation**:
```python
# tools/s7comm_security_framework/s7comm_exploit.py
python s7comm_exploit.py --target 192.168.100.50 --action export-all-dbs --output ./export/
```

**Expected Behavior**:
- Triggers after 10 data block reads in 60 seconds
- Sets flowbit: s7comm_db_read
- MITRE: T0877 (I/O Image)

**Validation**:
```bash
# Monitor S7Comm DB export activity
suricata-json-parser /var/log/suricata/eve.json | jq 'select(.alert.signature_id==400010)'
```

**False Positive Test**:
- Single DB read from authorized HMI should NOT trigger
- Less than 10 reads in 60 seconds should NOT trigger

## Zeek Script Testing

### Script Loading

```bash
# Add to /opt/zeek/share/zeek/site/local.zeek
@load configs/zeek/ics_detection

# Check for syntax errors
zeek -r test.pcap configs/zeek/ics_detection.zeek
```

### Test Case 6: Multi-Protocol Reconnaissance

**Detection Logic**: `multi_protocol_sources` table tracks protocols per source

**Test Traffic Generation**:
```bash
# Scan multiple ICS protocols from single source
nmap -p 102,502,44818,20000 192.168.100.50
```

**Expected Behavior**:
- Triggers when source uses 3+ different ICS protocols
- Creates log entry in ics_detection.log
- Generates NOTICE with ICS_Anomaly type

**Validation**:
```bash
# Check Zeek logs
zeek-cut protocol source_ip event_type < ics_detection.log | grep Multi_Protocol_Reconnaissance
```

**False Positive Test**:
- Single HMI using 2 protocols (Modbus + S7Comm) should NOT trigger

### Test Case 7: DNP3 Unauthorized Write Detection

**Test Traffic Generation**:
```python
# tools/modbus-stealth-toolkit/modbus_stealth_attack.py (DNP3 mode)
python modbus_stealth_attack.py --target 192.168.100.50 --mode dnp3-write --protocol dnp3
```

**Expected Behavior**:
- Detects DNP3 FC 0x02 from unauthorized sources
- Source IP NOT in `authorized_writers` set
- Severity: HIGH

**Validation**:
```bash
# Check DNP3 anomaly logs
zeek-cut ts source_ip event_type severity details < ics_detection.log | grep DNP3.*Unauthorized_Write
```

**False Positive Test**:
- DNP3 writes from 192.168.100.51 (authorized HMI) should NOT trigger

### Test Case 8: Modbus File Transfer Operations

**Test Traffic Generation**:
```python
# Multiple file read operations
for i in range(3):
    python modbus_stealth_attack.py --target 192.168.100.50 --mode file-read --file-number $i
```

**Expected Behavior**:
- Tracks file transfer function codes: 0x14, 0x15, 0x16, 0x17
- Threshold: 2 operations in 5 minutes
- Updates `modbus_file_ops_count` table

**Validation**:
```bash
zeek-cut protocol event_type details < ics_detection.log | grep File_Transfer_Operation
```

### Test Case 9: S7Comm Symbol Table Extraction

**Test Traffic Generation**:
```python
# tools/s7comm_security_framework/s7comm_exploit.py
python s7comm_exploit.py --target 192.168.100.50 --action extract-symbols
```

**Expected Behavior**:
- Detects 5+ SZL read operations in 2 minutes
- Updates `s7comm_szl_read_count` table
- Event type: Symbol_Table_Extraction

**Validation**:
```bash
zeek-cut ts source_ip event_type details < ics_detection.log | grep Symbol_Table_Extraction
```

### Test Case 10: High-Rate Request Detection

**Test Traffic Generation**:
```bash
# Generate high-rate Modbus traffic
for i in {1..60}; do
    echo -e "\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A" | nc 192.168.100.50 502 &
done
```

**Expected Behavior**:
- SumStats framework tracks request rates
- Threshold: 50 requests per minute
- Separate tracking for Modbus, S7Comm, ENIP, DNP3

**Validation**:
```bash
# Check notices
zeek-cut ts note msg src < notice.log | grep "High.*request rate"
```

## False Positive Analysis

### Baseline Traffic Collection

1. **Capture 24-hour baseline**:
```bash
tcpdump -i eth0 -w baseline.pcap 'port 102 or port 502 or port 44818 or port 20000'
```

2. **Run detection against baseline**:
```bash
# Suricata
suricata -c /etc/suricata/suricata.yaml -r baseline.pcap -l logs/

# Zeek
zeek -r baseline.pcap configs/zeek/ics_detection.zeek
```

3. **Analyze false positives**:
```bash
# Count alerts by signature
cat logs/fast.log | cut -d']' -f2 | sort | uniq -c | sort -rn

# Identify noisy rules
zeek-cut event_type < ics_detection.log | sort | uniq -c | sort -rn
```

### Tuning Recommendations

**High False Positive Rate (>10 alerts/hour)**:

1. **Adjust thresholds**:
```
# In ics_detection.zeek
const request_rate_threshold: double = 100.0 &redef;  # Increase from 50
const db_export_threshold: count = 20 &redef;         # Increase from 10
```

2. **Add authorized sources**:
```
const authorized_writers: set[addr] = {
    192.168.1.50,
    192.168.1.51,
    192.168.1.52  # Add new authorized HMI
} &redef;
```

3. **Modify Suricata thresholds**:
```
# Change in rule
threshold:type threshold, track by_src, count 5, seconds 300;  # More lenient
```

### Known Legitimate Patterns

**Engineering Workstation Activity**:
- S7Comm data block reads during commissioning
- Modbus register scans for configuration
- Solution: Whitelist engineering subnet or extend thresholds during maintenance windows

**SCADA Polling**:
- Regular Modbus/DNP3 polls every 1-5 seconds
- Solution: Ensure polling rates below `request_rate_threshold`

**Firmware Updates**:
- S7Comm block downloads (FC 0x1A)
- Solution: Temporarily disable rules during planned updates

## Integration Testing

### SIEM Integration Test

**Splunk**:
```bash
# Forward Suricata EVE JSON to Splunk
monitor:///var/log/suricata/eve.json

# Search query
index=suricata alert.signature_id=400* | stats count by alert.signature
```

**Elastic Stack**:
```bash
# Filebeat configuration
filebeat.inputs:
- type: log
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true

# Kibana query
alert.signature_id:400* AND alert.severity:1
```

### Automated Testing

**Suricata-Verify Framework**:
```yaml
# tests/stuxnet_high_speed.yaml
requires:
  min-version: 6.0.0

args:
  - -S configs/suricata_rules/ics_malware_detection.rules

checks:
  - filter:
      count: 1
      match:
        event_type: alert
        alert.signature_id: 500001
        alert.signature: "STUXNET_S7COMM_CENTRIFUGE_MANIPULATION_HIGH_SPEED"
```

**Run tests**:
```bash
suricata-verify -D tests/ --suricata /usr/bin/suricata
```

### Continuous Integration

**GitHub Actions Workflow**:
```yaml
name: ICS Detection Rules CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Suricata
        run: apt-get install -y suricata
      - name: Validate Rules
        run: suricata -T -S configs/suricata_rules/ics_malware_detection.rules
      - name: Run Suricata-Verify
        run: suricata-verify -D tests/ --suricata /usr/bin/suricata
```

## Performance Impact Assessment

### Baseline Metrics

```bash
# Measure CPU/memory before adding rules
top -b -n 1 | grep suricata
ps aux | grep zeek

# Add rules and measure again
# Acceptable impact: <10% CPU increase, <50MB memory increase
```

### Rule Optimization

**Inefficient patterns**:
- Avoid: `pcre:"/.*complex_regex.*/"`
- Prefer: `content:"fixed_string"; fast_pattern;`

**Flowbit management**:
- Review flowbit usage to prevent memory leaks
- Set appropriate expiration times

## Test Results Documentation

### Test Report Template

```markdown
## Test Execution: [Date]

### Environment
- Suricata Version: X.X.X
- Zeek Version: X.X.X
- Test Network: 192.168.100.0/24

### Rule Coverage
- Total Rules Tested: XX
- Passed: XX
- Failed: XX
- False Positives: XX

### Findings
| Rule SID | Status | FP Rate | Notes |
|----------|--------|---------|-------|
| 500001   | PASS   | 0%      | Accurate detection |
| 400006   | PASS   | 2%      | Tuned threshold |

### Recommendations
1. Adjust threshold for SID 400010
2. Add whitelist for engineering subnet
3. Update documentation for SID 400012
```

## Troubleshooting

### Rule Not Triggering

1. **Verify packet structure**:
```bash
tcpdump -i eth0 -X -s0 port 502
```

2. **Check Suricata stats**:
```bash
suricatasc -c "dump-counters" | grep decoder
```

3. **Enable rule profiling**:
```yaml
# suricata.yaml
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
```

### Excessive False Positives

1. **Identify source**:
```bash
zeek-cut source_ip event_type < ics_detection.log | sort | uniq -c | sort -rn | head
```

2. **Review traffic**:
```bash
tcpdump -r baseline.pcap -w filtered.pcap "host 192.168.100.51"
zeek -r filtered.pcap configs/zeek/ics_detection.zeek
```

3. **Tune or suppress**:
```
# Add to Suricata suppress.conf
suppress gen_id 1, sig_id 400002, track by_src, ip 192.168.100.51
```

## Alignment with Attack Tools

### Cross-Reference Matrix

| Detection Rule | Tool | Method | Technique |
|----------------|------|--------|-----------|
| SID 500001/500005 | s7comm_exploit.py | centrifuge_speed_attack() | T0836 |
| SID 400006 | modbus_stealth_attack.py | read_file_record() | T0868 |
| SID 400008 | s7comm_exploit.py | s7commplus_probe() | T0885 |
| SID 400009 | s7comm_exploit.py | extract_symbol_table() | T0868 |
| SID 400010 | s7comm_exploit.py | export_all_data_blocks() | T0877 |
| SID 400012 | cip_exploiter.py | exploit_safety_io() | T0878 |
| SID 400013 | cip_exploiter.py | manipulate_implicit_messaging() | T0856 |

### Validation Commands

```bash
# Modbus file transfer detection
python tools/modbus-stealth-toolkit/modbus_stealth_attack.py --target 192.168.100.50 --mode file-read
grep MODBUS_FILE_TRANSFER /var/log/suricata/fast.log

# S7Comm symbol extraction detection
python tools/s7comm_security_framework/s7comm_exploit.py --target 192.168.100.50 --action extract-symbols
zeek-cut event_type < ics_detection.log | grep Symbol_Table_Extraction

# CIP Safety exploitation detection
python tools/cip_security_assessment/cip_exploiter.py --target 192.168.100.50 --action safety-io-exploit
grep CIP_SAFETY_IO_EXPLOITATION /var/log/suricata/fast.log
```

## Conclusion

Comprehensive testing of ICS detection rules requires:
1. Validation against known attack patterns
2. False positive analysis using baseline traffic
3. Performance impact assessment
4. Regular tuning based on operational feedback
5. Continuous integration with automated testing

Maintain test PCAPs in `tests/pcaps/` directory and document all tuning decisions in this guide.
