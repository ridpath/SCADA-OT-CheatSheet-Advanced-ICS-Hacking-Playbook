#!/usr/bin/env python3
"""
ics_tool_cli.py
Unified command-line interface for all ICS security assessment tools

Provides standardized access to Modbus, S7Comm, CIP, OPC-UA, PROFINET, and BACnet tools
with common configuration, dry-run, and export capabilities.

Usage:
    python ics_tool_cli.py modbus --target 192.168.1.100 --operation enumerate
    python ics_tool_cli.py s7comm --target 192.168.1.101 --config my_config.yaml --dry-run
    python ics_tool_cli.py opcua --endpoint opc.tcp://192.168.1.102:4840 --export report.json
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from tool_adapters import (
    ModbusToolAdapter,
    S7CommToolAdapter,
    CIPToolAdapter,
    OPCUAToolAdapter,
    PROFINETToolAdapter,
    BACnetToolAdapter
)


def setup_modbus_parser(subparsers):
    """Setup Modbus subparser"""
    parser = subparsers.add_parser('modbus', help='Modbus security assessment')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, default=502, help='Port (default: 502)')
    parser.add_argument('--unit-id', type=int, default=1, help='Unit ID (default: 1)')
    parser.add_argument('--operation', default='enumerate',
                       choices=['enumerate', 'read_registers', 'write_register', 'fuzz'],
                       help='Operation to perform')
    parser.add_argument('--start-address', type=int, default=0, help='Start address for read/write')
    parser.add_argument('--count', type=int, default=10, help='Number of registers to read')
    parser.add_argument('--value', type=int, help='Value to write')
    return parser


def setup_s7comm_parser(subparsers):
    """Setup S7Comm subparser"""
    parser = subparsers.add_parser('s7comm', help='S7Comm security assessment')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, default=102, help='Port (default: 102)')
    parser.add_argument('--rack', type=int, default=0, help='Rack number (default: 0)')
    parser.add_argument('--slot', type=int, default=2, help='Slot number (default: 2)')
    parser.add_argument('--operation', default='enumerate',
                       choices=['enumerate', 'read_db', 'write_db', 'extract_symbols', 'export_all_dbs'],
                       help='Operation to perform')
    return parser


def setup_cip_parser(subparsers):
    """Setup CIP subparser"""
    parser = subparsers.add_parser('cip', help='CIP/EtherNet/IP security assessment')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, default=44818, help='Port (default: 44818)')
    parser.add_argument('--operation', default='enumerate_objects',
                       choices=['enumerate_objects', 'cip_security_assess', 'fuzz_class', 'safety_io_exploit'],
                       help='Operation to perform')
    return parser


def setup_opcua_parser(subparsers):
    """Setup OPC-UA subparser"""
    parser = subparsers.add_parser('opcua', help='OPC-UA security assessment')
    parser.add_argument('--endpoint', required=True, help='OPC-UA endpoint URL (e.g., opc.tcp://host:4840)')
    parser.add_argument('--operation', default='discover_endpoints',
                       choices=['discover_endpoints', 'enumerate_nodes', 'test_certificate_bypass', 'create_subscription'],
                       help='Operation to perform')
    return parser


def setup_profinet_parser(subparsers):
    """Setup PROFINET subparser"""
    parser = subparsers.add_parser('profinet', help='PROFINET security assessment')
    parser.add_argument('--interface', required=True, help='Network interface (e.g., eth0)')
    parser.add_argument('--operation', default='discover',
                       choices=['discover', 'set_name', 'set_ip', 'factory_reset', 'inject_rt'],
                       help='Operation to perform')
    return parser


def setup_bacnet_parser(subparsers):
    """Setup BACnet subparser"""
    parser = subparsers.add_parser('bacnet', help='BACnet security assessment')
    parser.add_argument('--target', help='Target IP address (optional for broadcast)')
    parser.add_argument('--port', type=int, default=47808, help='Port (default: 47808)')
    parser.add_argument('--operation', default='discover',
                       choices=['discover', 'enumerate', 'write_property', 'priority_array', 'comm_control'],
                       help='Operation to perform')
    return parser


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Unified ICS Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Modbus enumeration
  python ics_tool_cli.py modbus --target 192.168.1.100 --operation enumerate

  # S7Comm with dry-run
  python ics_tool_cli.py s7comm --target 192.168.1.101 --dry-run --operation enumerate

  # CIP with configuration file
  python ics_tool_cli.py cip --target 192.168.1.102 --config my_config.yaml

  # OPC-UA with export
  python ics_tool_cli.py opcua --endpoint opc.tcp://192.168.1.103:4840 --export report.json

  # PROFINET device discovery
  python ics_tool_cli.py profinet --interface eth0 --operation discover

  # BACnet with HTML report
  python ics_tool_cli.py bacnet --operation discover --export report.html --format html
        '''
    )
    
    parser.add_argument('--config', help='Configuration file (YAML or JSON)')
    parser.add_argument('--dry-run', action='store_true', help='Dry-run mode (no actual operations)')
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Logging level')
    parser.add_argument('--export', help='Export results to file')
    parser.add_argument('--format', default='json',
                       choices=['json', 'xml', 'csv', 'html', 'txt'],
                       help='Export format (default: json)')
    
    subparsers = parser.add_subparsers(dest='protocol', help='Protocol to assess')
    subparsers.required = True
    
    setup_modbus_parser(subparsers)
    setup_s7comm_parser(subparsers)
    setup_cip_parser(subparsers)
    setup_opcua_parser(subparsers)
    setup_profinet_parser(subparsers)
    setup_bacnet_parser(subparsers)
    
    args = parser.parse_args()
    
    # Initialize tool based on protocol
    tool = None
    
    try:
        if args.protocol == 'modbus':
            tool = ModbusToolAdapter(
                target_ip=args.target,
                port=args.port,
                unit_id=args.unit_id,
                config_file=args.config,
                dry_run=args.dry_run,
                log_level=args.log_level
            )
            tool.run_assessment(
                operation=args.operation,
                start_address=getattr(args, 'start_address', 0),
                count=getattr(args, 'count', 10),
                value=getattr(args, 'value', None)
            )
        
        elif args.protocol == 's7comm':
            tool = S7CommToolAdapter(
                target_ip=args.target,
                port=args.port,
                rack=args.rack,
                slot=args.slot,
                config_file=args.config,
                dry_run=args.dry_run,
                log_level=args.log_level
            )
            tool.run_assessment(operation=args.operation)
        
        elif args.protocol == 'cip':
            tool = CIPToolAdapter(
                target_ip=args.target,
                port=args.port,
                config_file=args.config,
                dry_run=args.dry_run,
                log_level=args.log_level
            )
            tool.run_assessment(operation=args.operation)
        
        elif args.protocol == 'opcua':
            tool = OPCUAToolAdapter(
                endpoint_url=args.endpoint,
                config_file=args.config,
                dry_run=args.dry_run,
                log_level=args.log_level
            )
            tool.run_assessment(operation=args.operation)
        
        elif args.protocol == 'profinet':
            tool = PROFINETToolAdapter(
                interface=args.interface,
                config_file=args.config,
                dry_run=args.dry_run,
                log_level=args.log_level
            )
            tool.run_assessment(operation=args.operation)
        
        elif args.protocol == 'bacnet':
            tool = BACnetToolAdapter(
                target_ip=args.target,
                port=args.port,
                config_file=args.config,
                dry_run=args.dry_run,
                log_level=args.log_level
            )
            tool.run_assessment(operation=args.operation)
        
        # Export results if requested
        if args.export and tool:
            tool.export_results(args.export, format=args.format)
            print(f"\nResults exported to {args.export}")
        
        # Print summary
        if tool:
            summary = tool.get_summary()
            print("\n" + "=" * 60)
            print("ASSESSMENT SUMMARY")
            print("=" * 60)
            print(f"Tool: {summary['tool']}")
            print(f"Protocol: {summary['protocol']}")
            print(f"Total Events: {summary['total_events']}")
            print(f"Dry Run: {summary['dry_run']}")
            print("\nEvents by Severity:")
            for severity, count in summary['by_severity'].items():
                print(f"  {severity}: {count}")
            print("\nEvents by Type:")
            for event_type, count in summary['by_type'].items():
                print(f"  {event_type}: {count}")
            print("=" * 60)
    
    except KeyboardInterrupt:
        print("\n\nAssessment interrupted by user")
        sys.exit(1)
    
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        if args.log_level == 'DEBUG':
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
