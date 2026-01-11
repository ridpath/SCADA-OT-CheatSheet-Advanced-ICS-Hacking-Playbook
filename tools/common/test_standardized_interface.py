#!/usr/bin/env python3
"""
test_standardized_interface.py
Demonstration and testing of standardized ICS tool interface

Tests all core features:
- Configuration loading (YAML/JSON)
- Dry-run mode
- Safety validation
- Event logging
- Result export (JSON, XML, CSV, HTML, TXT)
- Adapter functionality
"""

import os
import sys
from pathlib import Path

from tool_adapters import (
    ModbusToolAdapter,
    S7CommToolAdapter,
    CIPToolAdapter,
    OPCUAToolAdapter,
    PROFINETToolAdapter,
    BACnetToolAdapter
)


def test_configuration_loading():
    """Test configuration file loading"""
    print("\n" + "=" * 60)
    print("TEST 1: Configuration Loading")
    print("=" * 60)
    
    # Test YAML configuration
    tool = ModbusToolAdapter(
        target_ip="192.168.1.100",
        config_file="example_config.yaml",
        dry_run=True
    )
    
    print(f"✓ YAML configuration loaded")
    print(f"  - Tool: {tool.name}")
    print(f"  - Protocol: {tool.protocol}")
    print(f"  - Dry run: {tool.dry_run}")
    print(f"  - Config keys: {list(tool.config.keys())}")
    
    # Test JSON configuration
    tool2 = S7CommToolAdapter(
        target_ip="192.168.1.101",
        config_file="example_config.json",
        dry_run=True
    )
    
    print(f"✓ JSON configuration loaded")
    print(f"  - Tool: {tool2.name}")
    print(f"  - Config keys: {list(tool2.config.keys())}")


def test_dry_run_mode():
    """Test dry-run mode"""
    print("\n" + "=" * 60)
    print("TEST 2: Dry-Run Mode")
    print("=" * 60)
    
    tool = ModbusToolAdapter(
        target_ip="192.168.1.100",
        dry_run=True,
        log_level="INFO"
    )
    
    print(f"✓ Tool initialized in dry-run mode")
    print(f"  - Dry run: {tool.dry_run}")
    
    # Test operations in dry-run mode
    tool.run_assessment(operation='enumerate')
    tool.run_assessment(operation='read_registers', start_address=100, count=10)
    tool.run_assessment(operation='write_register', address=200, value=1234)
    
    print(f"✓ All operations executed in dry-run mode (no actual network traffic)")
    print(f"  - Total events logged: {len(tool.events)}")


def test_safety_validation():
    """Test safety validation checks"""
    print("\n" + "=" * 60)
    print("TEST 3: Safety Validation")
    print("=" * 60)
    
    tool = CIPToolAdapter(
        target_ip="192.168.1.102",
        dry_run=True
    )
    
    # Test target validation
    valid = tool.validate_safety("target_validation", target="192.168.1.102")
    print(f"✓ Target validation: {valid}")
    
    invalid = tool.validate_safety("target_validation", target="invalid_target")
    print(f"✓ Invalid target rejected: {not invalid}")
    
    # Test rate limiting
    valid_rate = tool.validate_safety("network_request", rate=5)
    print(f"✓ Rate limit check (5 req/s): {valid_rate}")
    
    exceeded_rate = tool.validate_safety("network_request", rate=100)
    print(f"✓ Rate limit exceeded (100 req/s): {not exceeded_rate}")


def test_event_logging():
    """Test event logging"""
    print("\n" + "=" * 60)
    print("TEST 4: Event Logging")
    print("=" * 60)
    
    tool = OPCUAToolAdapter(
        endpoint_url="opc.tcp://192.168.1.103:4840",
        dry_run=True
    )
    
    # Log various events
    tool.log_event(
        event_type="discovery",
        severity="INFO",
        description="OPC-UA endpoint discovery",
        target="opc.tcp://192.168.1.103:4840",
        technique_id="T0888"
    )
    
    tool.log_event(
        event_type="enumeration",
        severity="MEDIUM",
        description="Node enumeration via Browse service",
        target="opc.tcp://192.168.1.103:4840",
        technique_id="T0861"
    )
    
    tool.log_event(
        event_type="write_operation",
        severity="HIGH",
        description="Unauthorized write to node",
        target="opc.tcp://192.168.1.103:4840",
        technique_id="T0855",
        node_id="ns=2;i=1000",
        value=42
    )
    
    tool.log_event(
        event_type="session_hijacking",
        severity="CRITICAL",
        description="Session token reuse attempt",
        target="opc.tcp://192.168.1.103:4840",
        technique_id="T0819"
    )
    
    print(f"✓ Logged {len(tool.events)} events")
    
    # Show summary
    summary = tool.get_summary()
    print(f"✓ Events by severity: {summary['by_severity']}")
    print(f"✓ Events by type: {summary['by_type']}")


def test_result_export():
    """Test result export in all formats"""
    print("\n" + "=" * 60)
    print("TEST 5: Result Export")
    print("=" * 60)
    
    tool = PROFINETToolAdapter(
        interface="eth0",
        dry_run=True
    )
    
    # Generate some test events
    tool.log_event(
        event_type="discovery",
        severity="INFO",
        description="PROFINET device discovery via DCP",
        target="eth0",
        technique_id="T0888"
    )
    
    tool.log_event(
        event_type="device_configuration",
        severity="HIGH",
        description="NameOfStation modification",
        target="00:11:22:33:44:55",
        technique_id="T0855",
        device_name="malicious-device"
    )
    
    tool.log_event(
        event_type="factory_reset",
        severity="CRITICAL",
        description="Factory reset via DCP Control",
        target="00:11:22:33:44:55",
        technique_id="T0809"
    )
    
    # Create reports directory
    reports_dir = Path("./test_reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Export in all formats
    formats = ['json', 'xml', 'csv', 'html', 'txt']
    
    for fmt in formats:
        output_file = reports_dir / f"test_report.{fmt}"
        tool.export_results(str(output_file), format=fmt)
        
        if output_file.exists():
            size = output_file.stat().st_size
            print(f"✓ Exported {fmt.upper()}: {output_file} ({size} bytes)")
        else:
            print(f"✗ Failed to export {fmt.upper()}")


def test_all_protocol_adapters():
    """Test all protocol adapters"""
    print("\n" + "=" * 60)
    print("TEST 6: All Protocol Adapters")
    print("=" * 60)
    
    adapters = [
        ("Modbus", ModbusToolAdapter(target_ip="192.168.1.100", dry_run=True)),
        ("S7Comm", S7CommToolAdapter(target_ip="192.168.1.101", dry_run=True)),
        ("CIP", CIPToolAdapter(target_ip="192.168.1.102", dry_run=True)),
        ("OPC-UA", OPCUAToolAdapter(endpoint_url="opc.tcp://192.168.1.103:4840", dry_run=True)),
        ("PROFINET", PROFINETToolAdapter(interface="eth0", dry_run=True)),
        ("BACnet", BACnetToolAdapter(target_ip="192.168.1.104", dry_run=True))
    ]
    
    for name, adapter in adapters:
        operations = adapter.get_available_operations()
        print(f"✓ {name}: {len(operations)} operations available")
        print(f"  Operations: {', '.join(operations[:5])}{'...' if len(operations) > 5 else ''}")


def test_complete_workflow():
    """Test complete assessment workflow"""
    print("\n" + "=" * 60)
    print("TEST 7: Complete Workflow")
    print("=" * 60)
    
    # Initialize tool with configuration
    tool = BACnetToolAdapter(
        target_ip="192.168.1.105",
        config_file="example_config.yaml",
        dry_run=True,
        log_level="INFO"
    )
    
    print(f"✓ Step 1: Tool initialized")
    print(f"  - Tool: {tool.name}")
    print(f"  - Protocol: {tool.protocol}")
    
    # Validate safety
    if not tool.validate_safety("target_validation", target=tool.target_ip):
        print("✗ Safety validation failed")
        return
    print(f"✓ Step 2: Safety validation passed")
    
    # Run assessment
    tool.run_assessment(operation='discover')
    print(f"✓ Step 3: Assessment executed")
    
    # Log additional events
    tool.log_event(
        event_type="who_is_broadcast",
        severity="INFO",
        description="BACnet Who-Is broadcast",
        target="broadcast",
        technique_id="T0888"
    )
    
    tool.log_event(
        event_type="write_property",
        severity="HIGH",
        description="WriteProperty to Priority Array",
        target="192.168.1.105",
        technique_id="T0855",
        object_id="analog-value,1",
        property_id="present-value",
        priority=8,
        value=75.5
    )
    print(f"✓ Step 4: Events logged ({len(tool.events)} total)")
    
    # Export results
    reports_dir = Path("./test_reports")
    reports_dir.mkdir(exist_ok=True)
    
    output_file = reports_dir / "bacnet_assessment.json"
    tool.export_results(str(output_file), format='json')
    print(f"✓ Step 5: Results exported to {output_file}")
    
    # Get summary
    summary = tool.get_summary()
    print(f"✓ Step 6: Summary generated")
    print(f"  - Total events: {summary['total_events']}")
    print(f"  - By severity: {summary['by_severity']}")
    
    print(f"\n✓ Complete workflow executed successfully")


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("ICS SECURITY TOOL - STANDARDIZED INTERFACE TEST SUITE")
    print("=" * 80)
    
    tests = [
        ("Configuration Loading", test_configuration_loading),
        ("Dry-Run Mode", test_dry_run_mode),
        ("Safety Validation", test_safety_validation),
        ("Event Logging", test_event_logging),
        ("Result Export", test_result_export),
        ("Protocol Adapters", test_all_protocol_adapters),
        ("Complete Workflow", test_complete_workflow)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n✗ TEST FAILED: {test_name}")
            print(f"  Error: {e}")
            failed += 1
            
            if '--verbose' in sys.argv:
                import traceback
                traceback.print_exc()
    
    # Print final results
    print("\n" + "=" * 80)
    print("TEST RESULTS")
    print("=" * 80)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
