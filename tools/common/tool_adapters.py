#!/usr/bin/env python3
"""
tool_adapters.py
Adapter classes to provide standardized interface for existing ICS security tools

Wraps existing tools with ICSSecurityTool interface while maintaining
backward compatibility with original functionality.
"""

import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.common.ics_security_tool import ICSSecurityTool, SecurityEvent as BaseSecurityEvent


class ModbusToolAdapter(ICSSecurityTool):
    """Adapter for modbus_stealth_attack.py"""
    
    def __init__(
        self,
        target_ip: str,
        port: int = 502,
        unit_id: int = 1,
        config_file: Optional[str] = None,
        dry_run: bool = False,
        log_level: str = "INFO"
    ):
        super().__init__(
            name="Modbus Stealth Attack Toolkit",
            version="3.0",
            protocol="Modbus",
            config_file=config_file,
            dry_run=dry_run,
            log_level=log_level
        )
        
        sys.path.insert(0, str(Path(__file__).parent.parent / "modbus-stealth-toolkit"))
        from modbus_stealth_attack import IndustrialProtocolAttacker, ProtocolType
        
        self.tool = IndustrialProtocolAttacker(
            target_ip=target_ip,
            port=port,
            protocol=ProtocolType.MODBUS_TCP
        )
        self.tool.dry_run = dry_run
        self.tool.unit_id = unit_id
        self.target_ip = target_ip
        self.port = port
    
    def run_assessment(self, **kwargs) -> None:
        """Run comprehensive Modbus assessment"""
        operation = kwargs.get('operation', 'enumerate')
        
        if not self.validate_safety("target_validation", target=self.target_ip):
            return
        
        self.log_event(
            event_type="assessment_start",
            severity="INFO",
            description=f"Starting Modbus assessment - {operation}",
            target=f"{self.target_ip}:{self.port}",
            technique_id="T0801"
        )
        
        if operation == 'enumerate':
            self._run_enumeration(**kwargs)
        elif operation == 'read_registers':
            self._run_read_registers(**kwargs)
        elif operation == 'write_register':
            self._run_write_register(**kwargs)
        elif operation == 'fuzz':
            self._run_fuzzing(**kwargs)
    
    def _run_enumeration(self, **kwargs):
        """Run device enumeration"""
        if self.dry_run:
            self.logger.info("DRY-RUN: Would enumerate Modbus device")
            return
        
        self.log_event(
            event_type="enumeration",
            severity="MEDIUM",
            description="Device enumeration",
            target=f"{self.target_ip}:{self.port}",
            technique_id="T0888"
        )
    
    def _run_read_registers(self, **kwargs):
        """Read holding registers"""
        start_addr = kwargs.get('start_address', 0)
        count = kwargs.get('count', 10)
        
        if self.dry_run:
            self.logger.info(f"DRY-RUN: Would read {count} registers from {start_addr}")
            return
        
        self.log_event(
            event_type="read_registers",
            severity="LOW",
            description=f"Read {count} registers from address {start_addr}",
            target=f"{self.target_ip}:{self.port}",
            technique_id="T0801"
        )
    
    def _run_write_register(self, **kwargs):
        """Write to register"""
        address = kwargs.get('address', 0)
        value = kwargs.get('value', 0)
        
        if not self.validate_safety("destructive", description=f"Write {value} to register {address}"):
            return
        
        if self.dry_run:
            self.logger.info(f"DRY-RUN: Would write {value} to register {address}")
            return
        
        self.log_event(
            event_type="write_register",
            severity="HIGH",
            description=f"Write value {value} to register {address}",
            target=f"{self.target_ip}:{self.port}",
            technique_id="T0855"
        )
    
    def _run_fuzzing(self, **kwargs):
        """Run protocol fuzzing"""
        if not self.validate_safety("destructive", description="Protocol fuzzing"):
            return
        
        if self.dry_run:
            self.logger.info("DRY-RUN: Would perform protocol fuzzing")
            return
        
        self.log_event(
            event_type="fuzzing",
            severity="HIGH",
            description="Protocol fuzzing",
            target=f"{self.target_ip}:{self.port}",
            technique_id="T0855"
        )
    
    def get_available_operations(self) -> List[str]:
        """Get available operations"""
        return [
            "enumerate",
            "read_registers",
            "write_register",
            "write_coil",
            "read_file_record",
            "write_file_record",
            "fuzz"
        ]


class S7CommToolAdapter(ICSSecurityTool):
    """Adapter for s7comm_exploit.py"""
    
    def __init__(
        self,
        target_ip: str,
        port: int = 102,
        rack: int = 0,
        slot: int = 2,
        config_file: Optional[str] = None,
        dry_run: bool = False,
        log_level: str = "INFO"
    ):
        super().__init__(
            name="S7Comm Security Framework",
            version="4.0",
            protocol="S7Comm",
            config_file=config_file,
            dry_run=dry_run,
            log_level=log_level
        )
        
        self.target_ip = target_ip
        self.port = port
        self.rack = rack
        self.slot = slot
    
    def run_assessment(self, **kwargs) -> None:
        """Run S7Comm assessment"""
        operation = kwargs.get('operation', 'enumerate')
        
        if not self.validate_safety("target_validation", target=self.target_ip):
            return
        
        self.log_event(
            event_type="assessment_start",
            severity="INFO",
            description=f"Starting S7Comm assessment - {operation}",
            target=f"{self.target_ip}:{self.port}",
            technique_id="T0801"
        )
        
        if self.dry_run:
            self.logger.info(f"DRY-RUN: Would perform {operation} on S7 PLC")
    
    def get_available_operations(self) -> List[str]:
        """Get available operations"""
        return [
            "enumerate",
            "read_db",
            "write_db",
            "extract_symbols",
            "export_all_dbs",
            "test_protection",
            "s7plus_probe"
        ]


class CIPToolAdapter(ICSSecurityTool):
    """Adapter for cip_exploiter.py"""
    
    def __init__(
        self,
        target_ip: str,
        port: int = 44818,
        config_file: Optional[str] = None,
        dry_run: bool = False,
        log_level: str = "INFO"
    ):
        super().__init__(
            name="CIP Security Assessment",
            version="5.0",
            protocol="CIP/EtherNet/IP",
            config_file=config_file,
            dry_run=dry_run,
            log_level=log_level
        )
        
        self.target_ip = target_ip
        self.port = port
    
    def run_assessment(self, **kwargs) -> None:
        """Run CIP assessment"""
        operation = kwargs.get('operation', 'enumerate')
        
        if not self.validate_safety("target_validation", target=self.target_ip):
            return
        
        self.log_event(
            event_type="assessment_start",
            severity="INFO",
            description=f"Starting CIP assessment - {operation}",
            target=f"{self.target_ip}:{self.port}",
            technique_id="T0801"
        )
        
        if self.dry_run:
            self.logger.info(f"DRY-RUN: Would perform {operation} on CIP device")
    
    def get_available_operations(self) -> List[str]:
        """Get available operations"""
        return [
            "enumerate_objects",
            "cip_security_assess",
            "fuzz_class",
            "safety_io_exploit",
            "implicit_msg",
            "reset_plc",
            "firmware_update"
        ]


class OPCUAToolAdapter(ICSSecurityTool):
    """Adapter for opcua_exploit.py"""
    
    def __init__(
        self,
        endpoint_url: str,
        config_file: Optional[str] = None,
        dry_run: bool = False,
        log_level: str = "INFO"
    ):
        super().__init__(
            name="OPC-UA Security Framework",
            version="1.0",
            protocol="OPC-UA",
            config_file=config_file,
            dry_run=dry_run,
            log_level=log_level
        )
        
        self.endpoint_url = endpoint_url
    
    def run_assessment(self, **kwargs) -> None:
        """Run OPC-UA assessment"""
        operation = kwargs.get('operation', 'discover')
        
        if not self.validate_safety("target_validation", target=self.endpoint_url):
            return
        
        self.log_event(
            event_type="assessment_start",
            severity="INFO",
            description=f"Starting OPC-UA assessment - {operation}",
            target=self.endpoint_url,
            technique_id="T0888"
        )
        
        if self.dry_run:
            self.logger.info(f"DRY-RUN: Would perform {operation} on OPC-UA server")
    
    def get_available_operations(self) -> List[str]:
        """Get available operations"""
        return [
            "discover_endpoints",
            "enumerate_nodes",
            "test_certificate_bypass",
            "create_subscription",
            "fuzz_node_write",
            "test_session_hijacking",
            "assess_security"
        ]


class PROFINETToolAdapter(ICSSecurityTool):
    """Adapter for profinet_exploit.py"""
    
    def __init__(
        self,
        interface: str,
        config_file: Optional[str] = None,
        dry_run: bool = False,
        log_level: str = "INFO"
    ):
        super().__init__(
            name="PROFINET Exploitation Framework",
            version="1.0",
            protocol="PROFINET",
            config_file=config_file,
            dry_run=dry_run,
            log_level=log_level
        )
        
        self.interface = interface
    
    def run_assessment(self, **kwargs) -> None:
        """Run PROFINET assessment"""
        operation = kwargs.get('operation', 'discover')
        
        self.log_event(
            event_type="assessment_start",
            severity="INFO",
            description=f"Starting PROFINET assessment - {operation}",
            target=self.interface,
            technique_id="T0888"
        )
        
        if self.dry_run:
            self.logger.info(f"DRY-RUN: Would perform {operation} on PROFINET network")
    
    def get_available_operations(self) -> List[str]:
        """Get available operations"""
        return [
            "discover",
            "set_name",
            "set_ip",
            "factory_reset",
            "inject_rt",
            "spoof_alarm",
            "monitor_rt",
            "firmware_mode",
            "fuzz_dcp"
        ]


class BACnetToolAdapter(ICSSecurityTool):
    """Adapter for bacnet_assessment.py"""
    
    def __init__(
        self,
        target_ip: str = None,
        port: int = 47808,
        config_file: Optional[str] = None,
        dry_run: bool = False,
        log_level: str = "INFO"
    ):
        super().__init__(
            name="BACnet Security Assessment",
            version="1.0",
            protocol="BACnet",
            config_file=config_file,
            dry_run=dry_run,
            log_level=log_level
        )
        
        self.target_ip = target_ip
        self.port = port
    
    def run_assessment(self, **kwargs) -> None:
        """Run BACnet assessment"""
        operation = kwargs.get('operation', 'discover')
        
        if self.target_ip and not self.validate_safety("target_validation", target=self.target_ip):
            return
        
        self.log_event(
            event_type="assessment_start",
            severity="INFO",
            description=f"Starting BACnet assessment - {operation}",
            target=self.target_ip or "broadcast",
            technique_id="T0888"
        )
        
        if self.dry_run:
            self.logger.info(f"DRY-RUN: Would perform {operation} on BACnet network")
    
    def get_available_operations(self) -> List[str]:
        """Get available operations"""
        return [
            "discover",
            "enumerate",
            "write_property",
            "priority_array",
            "comm_control",
            "reinitialize",
            "subscribe_cov",
            "atomic_write_file",
            "mstp_token",
            "fuzz"
        ]
