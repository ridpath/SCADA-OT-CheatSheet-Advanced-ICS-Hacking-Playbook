#!/usr/bin/env python3
"""Verify protocol implementation completeness"""
from pathlib import Path
import re

def check_protocol_tool(tool_path, protocol_name, expected_features):
    """Check if a protocol tool has all expected features"""
    if not tool_path.exists():
        return False, ["Tool file not found"]
    
    with open(tool_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    missing = []
    for feature in expected_features:
        if feature not in content:
            missing.append(feature)
    
    return len(missing) == 0, missing

# Define expected features for each protocol
protocols = {
    'Modbus': {
        'path': Path('../../../tools/modbus-stealth-toolkit/modbus_stealth_attack.py'),
        'features': ['read_coils', 'write_single_coil', 'read_holding_registers', 
                    'write_single_register', 'ModbusFunctionCode', 'ModbusPacket'],
        'testing': Path('../../../tools/modbus-stealth-toolkit/TESTING.md'),
    },
    'S7Comm': {
        'path': Path('../../../tools/s7comm_security_framework/s7comm_exploit.py'),
        'features': ['read_data_block', 'write_data_block', 'plc_control', 
                    'S7FunctionCode', 'S7Packet', 'extract_symbol_table'],
        'testing': Path('../../../tools/s7comm_security_framework/TESTING.md'),
    },
    'CIP': {
        'path': Path('../../../tools/cip_security_assessment/cip_exploiter.py'),
        'features': ['enumerate_cip_objects', 'exploit_safety_io', 'CIPServiceCode',
                    'CIPPacket', 'SafetyPacket', 'fuzz_cip_class'],
        'testing': Path('../../../tools/cip_security_assessment/TESTING.md'),
    },
    'OPC-UA': {
        'path': Path('../../../tools/opcua_security_framework/opcua_exploit.py'),
        'features': ['discover_endpoints', 'enumerate_nodes', 'test_certificate_bypass',
                    'create_malicious_subscription', 'fuzz_node_write'],
        'testing': Path('../../../tools/opcua_security_framework/TESTING.md'),
    },
    'PROFINET': {
        'path': Path('../../../tools/profinet_exploitation/profinet_exploit.py'),
        'features': ['discover_devices', 'set_device_name', 'inject_rt_frame',
                    'DCPPacket', 'RTFrame', 'reprogram_device_tftp'],
        'testing': Path('../../../tools/profinet_exploitation/TESTING.md'),
    },
    'BACnet': {
        'path': Path('../../../tools/bacnet_security_assessment/bacnet_assessment.py'),
        'features': ['discover_devices', 'write_property', 'enumerate_objects',
                    'BACnetPacket', 'reinitialize_device', 'atomic_write_file'],
        'testing': Path('../../../tools/bacnet_security_assessment/TESTING.md'),
    },
}

print("=" * 70)
print("PROTOCOL IMPLEMENTATION COMPLETENESS CHECK")
print("=" * 70)

all_complete = True
for protocol, info in protocols.items():
    print(f"\n{protocol} Protocol:")
    print("-" * 70)
    
    # Check tool implementation
    is_complete, missing = check_protocol_tool(info['path'], protocol, info['features'])
    
    if is_complete:
        print(f"  Tool Implementation: OK ({info['path'].name})")
    else:
        print(f"  Tool Implementation: INCOMPLETE")
        for feature in missing[:3]:
            print(f"    - Missing: {feature}")
        all_complete = False
    
    # Check testing guide
    if info['testing'].exists():
        size = info['testing'].stat().st_size
        print(f"  Testing Guide: OK ({size} bytes)")
    else:
        print(f"  Testing Guide: MISSING")
        all_complete = False
    
    # Check for MITRE mappings
    with open(info['path'], 'r', encoding='utf-8') as f:
        content = f.read()
        mitre_count = len(re.findall(r'T0\d{3}', content))
    
    print(f"  MITRE Mappings: {mitre_count} techniques referenced")

# Check detection rules
print("\n" + "=" * 70)
print("DETECTION COVERAGE")
print("=" * 70)

suricata_dir = Path('../../../configs/suricata_rules')
zeek_dir = Path('../../../configs/zeek')

suricata_files = list(suricata_dir.glob('*.rules'))
zeek_files = list(zeek_dir.glob('*.zeek'))

print(f"\nSuricata Rules: {len(suricata_files)} files")
for f in suricata_files:
    with open(f, 'r', encoding='utf-8') as rf:
        rule_count = len([l for l in rf.read().split('\n') if l.strip().startswith('alert')])
    print(f"  - {f.name}: {rule_count} rules")

print(f"\nZeek Scripts: {len(zeek_files)} files")
for f in zeek_files:
    size = f.stat().st_size
    print(f"  - {f.name}: {size} bytes")

# Check documentation
print("\n" + "=" * 70)
print("DOCUMENTATION")
print("=" * 70)

docs = {
    'Protocol References': Path('../../../docs/protocol_quick_reference'),
    'Attack Scenarios': Path('../../../docs/attack_scenarios'),
}

for doc_type, doc_path in docs.items():
    if doc_path.exists():
        files = list(doc_path.glob('*.md'))
        print(f"\n{doc_type}: {len(files)} files")
        for f in files[:5]:
            size = f.stat().st_size
            print(f"  - {f.name}: {size} bytes")
    else:
        print(f"\n{doc_type}: MISSING")
        all_complete = False

# Summary
print("\n" + "=" * 70)
if all_complete:
    print("RESULT: ALL PROTOCOLS COMPLETE")
else:
    print("RESULT: SOME COMPONENTS MISSING (see above)")
print("=" * 70)
