#!/usr/bin/env python3
"""
mock_plc_server.py
Multi-Protocol Mock PLC Server for Testing
Author: Ridpath
Version: 1.0

Purpose:
Provides mock PLC implementations for testing ICS security tools
Supports: Modbus TCP, S7Comm, OPC-UA, CIP/EtherNet/IP

DISCLAIMER:
FOR TESTING AND DEVELOPMENT PURPOSES ONLY.
"""

import socket
import struct
import threading
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import IntEnum
import asyncio


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProtocolType(IntEnum):
    """Supported protocol types"""
    MODBUS_TCP = 502
    S7COMM = 102
    OPCUA = 4840
    ENIP = 44818


@dataclass
class ModbusMemory:
    """Modbus memory model"""
    coils: Dict[int, bool] = field(default_factory=lambda: {i: False for i in range(65536)})
    discrete_inputs: Dict[int, bool] = field(default_factory=lambda: {i: False for i in range(65536)})
    holding_registers: Dict[int, int] = field(default_factory=lambda: {i: 0 for i in range(65536)})
    input_registers: Dict[int, int] = field(default_factory=lambda: {i: 0 for i in range(65536)})
    
    def reset(self):
        """Reset all memory to default values"""
        self.coils = {i: False for i in range(65536)}
        self.discrete_inputs = {i: False for i in range(65536)}
        self.holding_registers = {i: 0 for i in range(65536)}
        self.input_registers = {i: 0 for i in range(65536)}


class MockModbusServer:
    """Mock Modbus TCP Server"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 5020):
        self.host = host
        self.port = port
        self.memory = ModbusMemory()
        self.running = False
        self.server_socket = None
        self.server_thread = None
        
    def start(self):
        """Start Modbus server"""
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.5)
        logger.info(f"Mock Modbus server started on {self.host}:{self.port}")
        
    def stop(self):
        """Stop Modbus server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.server_thread:
            self.server_thread.join(timeout=2)
        logger.info("Mock Modbus server stopped")
        
    def _run_server(self):
        """Server main loop"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")
                    
    def _handle_client(self, client_socket: socket.socket):
        """Handle client connection"""
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                response = self._process_modbus_request(data)
                if response:
                    client_socket.send(response)
        except Exception as e:
            logger.debug(f"Client handler error: {e}")
        finally:
            client_socket.close()
            
    def _process_modbus_request(self, data: bytes) -> Optional[bytes]:
        """Process Modbus request and generate response"""
        if len(data) < 8:
            return None
            
        transaction_id = struct.unpack('>H', data[0:2])[0]
        protocol_id = struct.unpack('>H', data[2:4])[0]
        length = struct.unpack('>H', data[4:6])[0]
        unit_id = data[6]
        function_code = data[7]
        
        if protocol_id != 0:
            return None
            
        response_data = None
        
        if function_code == 0x01:
            response_data = self._read_coils(data[8:])
        elif function_code == 0x02:
            response_data = self._read_discrete_inputs(data[8:])
        elif function_code == 0x03:
            response_data = self._read_holding_registers(data[8:])
        elif function_code == 0x04:
            response_data = self._read_input_registers(data[8:])
        elif function_code == 0x05:
            response_data = self._write_single_coil(data[8:])
        elif function_code == 0x06:
            response_data = self._write_single_register(data[8:])
        elif function_code == 0x0F:
            response_data = self._write_multiple_coils(data[8:])
        elif function_code == 0x10:
            response_data = self._write_multiple_registers(data[8:])
        else:
            response_data = struct.pack('B', 0x80 | function_code) + struct.pack('B', 0x01)
            
        if response_data:
            mbap_header = struct.pack('>H', transaction_id)
            mbap_header += struct.pack('>H', 0)
            mbap_header += struct.pack('>H', len(response_data) + 2)
            mbap_header += struct.pack('B', unit_id)
            return mbap_header + response_data
            
        return None
        
    def _read_coils(self, pdu: bytes) -> bytes:
        """Read Coils (0x01)"""
        start_addr = struct.unpack('>H', pdu[0:2])[0]
        quantity = struct.unpack('>H', pdu[2:4])[0]
        
        if quantity < 1 or quantity > 2000:
            return struct.pack('B', 0x81) + struct.pack('B', 0x03)
            
        byte_count = (quantity + 7) // 8
        coil_bytes = []
        
        for i in range(byte_count):
            byte_val = 0
            for bit in range(8):
                addr = start_addr + i * 8 + bit
                if addr < start_addr + quantity:
                    if self.memory.coils.get(addr, False):
                        byte_val |= (1 << bit)
            coil_bytes.append(byte_val)
            
        return struct.pack('B', 0x01) + struct.pack('B', byte_count) + bytes(coil_bytes)
        
    def _read_discrete_inputs(self, pdu: bytes) -> bytes:
        """Read Discrete Inputs (0x02)"""
        start_addr = struct.unpack('>H', pdu[0:2])[0]
        quantity = struct.unpack('>H', pdu[2:4])[0]
        
        if quantity < 1 or quantity > 2000:
            return struct.pack('B', 0x82) + struct.pack('B', 0x03)
            
        byte_count = (quantity + 7) // 8
        input_bytes = []
        
        for i in range(byte_count):
            byte_val = 0
            for bit in range(8):
                addr = start_addr + i * 8 + bit
                if addr < start_addr + quantity:
                    if self.memory.discrete_inputs.get(addr, False):
                        byte_val |= (1 << bit)
            input_bytes.append(byte_val)
            
        return struct.pack('B', 0x02) + struct.pack('B', byte_count) + bytes(input_bytes)
        
    def _read_holding_registers(self, pdu: bytes) -> bytes:
        """Read Holding Registers (0x03)"""
        start_addr = struct.unpack('>H', pdu[0:2])[0]
        quantity = struct.unpack('>H', pdu[2:4])[0]
        
        if quantity < 1 or quantity > 125:
            return struct.pack('B', 0x83) + struct.pack('B', 0x03)
            
        byte_count = quantity * 2
        register_bytes = []
        
        for i in range(quantity):
            addr = start_addr + i
            value = self.memory.holding_registers.get(addr, 0)
            register_bytes.extend(struct.pack('>H', value))
            
        return struct.pack('B', 0x03) + struct.pack('B', byte_count) + bytes(register_bytes)
        
    def _read_input_registers(self, pdu: bytes) -> bytes:
        """Read Input Registers (0x04)"""
        start_addr = struct.unpack('>H', pdu[0:2])[0]
        quantity = struct.unpack('>H', pdu[2:4])[0]
        
        if quantity < 1 or quantity > 125:
            return struct.pack('B', 0x84) + struct.pack('B', 0x03)
            
        byte_count = quantity * 2
        register_bytes = []
        
        for i in range(quantity):
            addr = start_addr + i
            value = self.memory.input_registers.get(addr, 0)
            register_bytes.extend(struct.pack('>H', value))
            
        return struct.pack('B', 0x04) + struct.pack('B', byte_count) + bytes(register_bytes)
        
    def _write_single_coil(self, pdu: bytes) -> bytes:
        """Write Single Coil (0x05)"""
        addr = struct.unpack('>H', pdu[0:2])[0]
        value = struct.unpack('>H', pdu[2:4])[0]
        
        if value not in [0x0000, 0xFF00]:
            return struct.pack('B', 0x85) + struct.pack('B', 0x03)
            
        self.memory.coils[addr] = (value == 0xFF00)
        return struct.pack('B', 0x05) + pdu[0:4]
        
    def _write_single_register(self, pdu: bytes) -> bytes:
        """Write Single Register (0x06)"""
        addr = struct.unpack('>H', pdu[0:2])[0]
        value = struct.unpack('>H', pdu[2:4])[0]
        
        self.memory.holding_registers[addr] = value
        return struct.pack('B', 0x06) + pdu[0:4]
        
    def _write_multiple_coils(self, pdu: bytes) -> bytes:
        """Write Multiple Coils (0x0F)"""
        start_addr = struct.unpack('>H', pdu[0:2])[0]
        quantity = struct.unpack('>H', pdu[2:4])[0]
        byte_count = pdu[4]
        
        if quantity < 1 or quantity > 1968:
            return struct.pack('B', 0x8F) + struct.pack('B', 0x03)
            
        coil_bytes = pdu[5:5+byte_count]
        
        for i in range(quantity):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(coil_bytes):
                bit_value = (coil_bytes[byte_idx] >> bit_idx) & 0x01
                self.memory.coils[start_addr + i] = bool(bit_value)
                
        return struct.pack('B', 0x0F) + pdu[0:4]
        
    def _write_multiple_registers(self, pdu: bytes) -> bytes:
        """Write Multiple Registers (0x10)"""
        start_addr = struct.unpack('>H', pdu[0:2])[0]
        quantity = struct.unpack('>H', pdu[2:4])[0]
        byte_count = pdu[4]
        
        if quantity < 1 or quantity > 123:
            return struct.pack('B', 0x90) + struct.pack('B', 0x03)
            
        register_bytes = pdu[5:5+byte_count]
        
        for i in range(quantity):
            offset = i * 2
            if offset + 1 < len(register_bytes):
                value = struct.unpack('>H', register_bytes[offset:offset+2])[0]
                self.memory.holding_registers[start_addr + i] = value
                
        return struct.pack('B', 0x10) + pdu[0:4]


@dataclass
class S7Memory:
    """S7 memory model"""
    db_blocks: Dict[int, bytearray] = field(default_factory=dict)
    inputs: bytearray = field(default_factory=lambda: bytearray(65536))
    outputs: bytearray = field(default_factory=lambda: bytearray(65536))
    flags: bytearray = field(default_factory=lambda: bytearray(65536))
    
    def get_db(self, db_num: int, size: int = 1024) -> bytearray:
        """Get or create data block"""
        if db_num not in self.db_blocks:
            self.db_blocks[db_num] = bytearray(size)
        return self.db_blocks[db_num]


class MockS7Server:
    """Mock S7Comm Server"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 1020):
        self.host = host
        self.port = port
        self.memory = S7Memory()
        self.running = False
        self.server_socket = None
        self.server_thread = None
        self.plc_status = "RUN"
        
    def start(self):
        """Start S7 server"""
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.5)
        logger.info(f"Mock S7 server started on {self.host}:{self.port}")
        
    def stop(self):
        """Stop S7 server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.server_thread:
            self.server_thread.join(timeout=2)
        logger.info("Mock S7 server stopped")
        
    def _run_server(self):
        """Server main loop"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")
                    
    def _handle_client(self, client_socket: socket.socket):
        """Handle client connection"""
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                response = self._process_s7_request(data)
                if response:
                    client_socket.send(response)
        except Exception as e:
            logger.debug(f"Client handler error: {e}")
        finally:
            client_socket.close()
            
    def _process_s7_request(self, data: bytes) -> Optional[bytes]:
        """Process S7 request - basic COTP connection response"""
        if len(data) < 4:
            return None
            
        if data[0] == 0x03 and data[5] == 0xE0:
            cotp_response = bytes([
                0x03, 0x00, 0x00, 0x0B,
                0x02, 0xF0, 0x80,
                0x00, 0x01, 0x00, 0x01
            ])
            return cotp_response
            
        return None


class MockOPCUAServer:
    """Mock OPC-UA Server - Basic implementation"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 4841):
        self.host = host
        self.port = port
        self.running = False
        self.server = None
        
    async def init(self):
        """Initialize OPC-UA server"""
        try:
            from asyncua import Server
            self.server = Server()
            await self.server.init()
            self.server.set_endpoint(f"opc.tcp://{self.host}:{self.port}/freeopcua/server/")
            
            uri = "http://examples.freeopcua.github.io"
            idx = await self.server.register_namespace(uri)
            
            myobj = await self.server.nodes.objects.add_object(idx, "TestObject")
            myvar = await myobj.add_variable(idx, "TestVariable", 0.0)
            await myvar.set_writable()
            
            logger.info(f"Mock OPC-UA server initialized on {self.host}:{self.port}")
        except ImportError:
            logger.warning("asyncua not available, OPC-UA mock server disabled")
            
    async def start(self):
        """Start OPC-UA server"""
        if self.server:
            await self.server.start()
            self.running = True
            logger.info("Mock OPC-UA server started")
            
    async def stop(self):
        """Stop OPC-UA server"""
        if self.server:
            await self.server.stop()
            self.running = False
            logger.info("Mock OPC-UA server stopped")


class MockCIPServer:
    """Mock CIP/EtherNet/IP Server - Basic implementation"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 44818):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.server_thread = None
        
    def start(self):
        """Start CIP server"""
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.5)
        logger.info(f"Mock CIP/EtherNet/IP server started on {self.host}:{self.port}")
        
    def stop(self):
        """Stop CIP server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.server_thread:
            self.server_thread.join(timeout=2)
        logger.info("Mock CIP/EtherNet/IP server stopped")
        
    def _run_server(self):
        """Server main loop"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")
                    
    def _handle_client(self, client_socket: socket.socket):
        """Handle client connection - basic ListIdentity response"""
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                if len(data) >= 24:
                    command = struct.unpack('<H', data[0:2])[0]
                    
                    if command == 0x0063:
                        response = self._build_list_identity_response()
                        client_socket.send(response)
        except Exception as e:
            logger.debug(f"Client handler error: {e}")
        finally:
            client_socket.close()
            
    def _build_list_identity_response(self) -> bytes:
        """Build ListIdentity response"""
        header = struct.pack('<H', 0x0063)
        header += struct.pack('<H', 0x0000)
        header += struct.pack('<I', 0x00000000)
        header += struct.pack('<Q', 0x0000000000000000)
        header += struct.pack('<I', 0x00000000)
        header += struct.pack('<H', 0x0000)
        header += struct.pack('<H', 0x0001)
        
        return header


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Multi-Protocol Mock PLC Server")
    parser.add_argument("--modbus-port", type=int, default=5020, help="Modbus TCP port")
    parser.add_argument("--s7-port", type=int, default=1020, help="S7Comm port")
    parser.add_argument("--opcua-port", type=int, default=4841, help="OPC-UA port")
    parser.add_argument("--cip-port", type=int, default=44818, help="CIP/EtherNet/IP port")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    args = parser.parse_args()
    
    modbus_server = MockModbusServer(host=args.host, port=args.modbus_port)
    s7_server = MockS7Server(host=args.host, port=args.s7_port)
    cip_server = MockCIPServer(host=args.host, port=args.cip_port)
    
    modbus_server.start()
    s7_server.start()
    cip_server.start()
    
    try:
        logger.info("All mock servers running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down servers...")
        modbus_server.stop()
        s7_server.stop()
        cip_server.stop()
        logger.info("All servers stopped")
