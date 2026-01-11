#!/usr/bin/env python3
"""
test_modbus.py
Unit tests for Modbus Security Assessment Toolkit
Author: Ridpath
Version: 1.0

Tests cover:
- Packet structure validation
- Function code encoding
- CRC/LRC calculation
- TCP/RTU/ASCII conversion
- Security event logging
- Mock server interactions
"""

import pytest
import struct
import sys
import time
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent / "modbus-stealth-toolkit"))
sys.path.insert(0, str(Path(__file__).parent))

from modbus_stealth_attack import (
    ModbusFunctionCode,
    ModbusExceptionCode,
    ModbusPacket,
    ModbusTransportMode,
    ProtocolType,
    AttackTechnique,
    SecurityEvent,
    IndustrialProtocolAttacker
)
from mock_plc_server import MockModbusServer


class TestModbusPacketStructure:
    """Test Modbus packet structure and validation"""
    
    def test_tcp_packet_creation(self):
        """Test Modbus TCP packet creation"""
        packet = ModbusPacket(
            transaction_id=1,
            protocol_id=0,
            unit_id=1,
            function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS,
            data=struct.pack('>HH', 0, 10)
        )
        
        tcp_bytes = packet.to_tcp_bytes()
        
        assert len(tcp_bytes) >= 12
        assert tcp_bytes[0:2] == struct.pack('>H', 1)
        assert tcp_bytes[2:4] == struct.pack('>H', 0)
        assert tcp_bytes[7] == ModbusFunctionCode.READ_HOLDING_REGISTERS
        
    def test_tcp_packet_validation_valid(self):
        """Test valid TCP packet validation"""
        packet = ModbusPacket(
            transaction_id=1,
            protocol_id=0,
            unit_id=1,
            function_code=ModbusFunctionCode.READ_COILS,
            data=struct.pack('>HH', 0, 10)
        )
        
        tcp_bytes = packet.to_tcp_bytes()
        is_valid, error = ModbusPacket.validate_tcp_packet(tcp_bytes)
        
        assert is_valid is True
        assert error is None
        
    def test_tcp_packet_validation_too_short(self):
        """Test TCP packet validation with too short packet"""
        short_packet = b'\x00\x01\x00\x00'
        is_valid, error = ModbusPacket.validate_tcp_packet(short_packet)
        
        assert is_valid is False
        assert "too short" in error.lower()
        
    def test_tcp_packet_validation_invalid_protocol_id(self):
        """Test TCP packet validation with invalid protocol ID"""
        invalid_packet = struct.pack('>HHHB', 1, 99, 5, 1) + b'\x03\x00\x00'
        is_valid, error = ModbusPacket.validate_tcp_packet(invalid_packet)
        
        assert is_valid is False
        assert "protocol id" in error.lower()
        
    def test_rtu_packet_creation(self):
        """Test Modbus RTU packet creation with CRC"""
        packet = ModbusPacket(
            unit_id=1,
            function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS,
            data=struct.pack('>HH', 0, 10)
        )
        
        rtu_bytes = packet.to_rtu_bytes()
        
        assert len(rtu_bytes) >= 7
        assert rtu_bytes[0] == 1
        assert rtu_bytes[1] == ModbusFunctionCode.READ_HOLDING_REGISTERS
        
    def test_rtu_crc_calculation(self):
        """Test CRC-16 calculation for RTU"""
        test_data = b'\x01\x03\x00\x00\x00\x0A'
        crc = ModbusPacket._calculate_crc16(test_data)
        
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF
        
        packet = ModbusPacket(
            unit_id=1,
            function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS,
            data=struct.pack('>HH', 0, 10)
        )
        
        rtu_bytes = packet.to_rtu_bytes()
        is_valid, error = ModbusPacket.validate_rtu_packet(rtu_bytes)
        
        assert is_valid is True
        assert error is None
        
    def test_rtu_crc_validation_failure(self):
        """Test RTU CRC validation with corrupted packet"""
        packet = ModbusPacket(
            unit_id=1,
            function_code=ModbusFunctionCode.READ_COILS,
            data=struct.pack('>HH', 0, 10)
        )
        
        rtu_bytes = bytearray(packet.to_rtu_bytes())
        rtu_bytes[-1] ^= 0xFF
        
        is_valid, error = ModbusPacket.validate_rtu_packet(bytes(rtu_bytes))
        
        assert is_valid is False
        assert "crc" in error.lower()
        
    def test_ascii_packet_creation(self):
        """Test Modbus ASCII packet creation with LRC"""
        packet = ModbusPacket(
            unit_id=1,
            function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS,
            data=struct.pack('>HH', 0, 10)
        )
        
        ascii_bytes = packet.to_ascii_bytes()
        
        assert ascii_bytes[0:1] == b':'
        assert ascii_bytes[-2:] == b'\r\n'
        assert all(c in b'0123456789ABCDEF:\r\n' for c in ascii_bytes)
        
    def test_lrc_calculation(self):
        """Test LRC calculation for ASCII"""
        test_data = b'\x01\x03\x00\x00\x00\x0A'
        lrc = ModbusPacket._calculate_lrc(test_data)
        
        assert isinstance(lrc, int)
        assert 0 <= lrc <= 0xFF
        
        checksum = (sum(test_data) ^ 0xFF) + 1
        assert lrc == (checksum & 0xFF)


class TestModbusFunctionCodes:
    """Test Modbus function code enumeration"""
    
    def test_read_function_codes(self):
        """Test read function codes"""
        assert ModbusFunctionCode.READ_COILS == 0x01
        assert ModbusFunctionCode.READ_DISCRETE_INPUTS == 0x02
        assert ModbusFunctionCode.READ_HOLDING_REGISTERS == 0x03
        assert ModbusFunctionCode.READ_INPUT_REGISTERS == 0x04
        
    def test_write_function_codes(self):
        """Test write function codes"""
        assert ModbusFunctionCode.WRITE_SINGLE_COIL == 0x05
        assert ModbusFunctionCode.WRITE_SINGLE_REGISTER == 0x06
        assert ModbusFunctionCode.WRITE_MULTIPLE_COILS == 0x0F
        assert ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS == 0x10
        
    def test_file_transfer_function_codes(self):
        """Test file transfer function codes"""
        assert ModbusFunctionCode.READ_FILE_RECORD == 0x14
        assert ModbusFunctionCode.WRITE_FILE_RECORD == 0x15
        assert ModbusFunctionCode.MASK_WRITE_REGISTER == 0x16
        assert ModbusFunctionCode.READ_WRITE_MULTIPLE_REGISTERS == 0x17
        
    def test_diagnostic_function_codes(self):
        """Test diagnostic function codes"""
        assert ModbusFunctionCode.DIAGNOSTICS == 0x08
        assert ModbusFunctionCode.GET_COMM_EVENT_COUNTER == 0x0B
        assert ModbusFunctionCode.GET_COMM_EVENT_LOG == 0x0C
        assert ModbusFunctionCode.REPORT_SERVER_ID == 0x11


class TestModbusExceptionCodes:
    """Test Modbus exception code enumeration"""
    
    def test_exception_codes(self):
        """Test exception code values"""
        assert ModbusExceptionCode.ILLEGAL_FUNCTION == 0x01
        assert ModbusExceptionCode.ILLEGAL_DATA_ADDRESS == 0x02
        assert ModbusExceptionCode.ILLEGAL_DATA_VALUE == 0x03
        assert ModbusExceptionCode.SERVER_DEVICE_FAILURE == 0x04
        assert ModbusExceptionCode.ACKNOWLEDGE == 0x05
        assert ModbusExceptionCode.SERVER_DEVICE_BUSY == 0x06


class TestSecurityEvent:
    """Test security event logging"""
    
    def test_security_event_creation(self):
        """Test security event creation"""
        event = SecurityEvent(
            technique=AttackTechnique.REGISTER_READ,
            target_ip="192.168.1.100",
            port=502,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=time.time(),
            success=True,
            details={"registers_read": 10},
            mitre_technique="T0801",
            mitre_tactic="Collection"
        )
        
        assert event.technique == AttackTechnique.REGISTER_READ
        assert event.target_ip == "192.168.1.100"
        assert event.port == 502
        assert event.success is True
        assert event.mitre_technique == "T0801"
        
    def test_security_event_to_dict(self):
        """Test security event serialization to dict"""
        event = SecurityEvent(
            technique=AttackTechnique.COIL_WRITE,
            target_ip="10.0.0.1",
            port=502,
            protocol=ProtocolType.MODBUS_TCP,
            timestamp=1234567890.0,
            success=False,
            details={"error": "Connection refused"},
            error="Connection error",
            mitre_technique="T0836",
            mitre_tactic="Impair Process Control"
        )
        
        event_dict = event.to_dict()
        
        assert isinstance(event_dict, dict)
        assert event_dict["technique"] == "coil_write"
        assert event_dict["target_ip"] == "10.0.0.1"
        assert event_dict["port"] == 502
        assert event_dict["success"] is False
        assert event_dict["error"] == "Connection error"
        assert event_dict["mitre_technique"] == "T0836"


class TestAttackTechniques:
    """Test attack technique enumeration"""
    
    def test_technique_values(self):
        """Test attack technique enum values"""
        assert AttackTechnique.RECONNAISSANCE.value == "reconnaissance"
        assert AttackTechnique.COIL_WRITE.value == "coil_write"
        assert AttackTechnique.REGISTER_READ.value == "register_read"
        assert AttackTechnique.REGISTER_WRITE.value == "register_write"
        assert AttackTechnique.FILE_OPERATION.value == "file_operation"
        assert AttackTechnique.SPOOFING.value == "spoofing"
        assert AttackTechnique.DOS.value == "denial_of_service"
        assert AttackTechnique.FUZZING.value == "fuzzing"


class TestIndustrialProtocolAttacker:
    """Test IndustrialProtocolAttacker class"""
    
    def test_attacker_initialization_tcp(self):
        """Test TCP attacker initialization"""
        attacker = IndustrialProtocolAttacker(
            target_ip="192.168.1.100",
            port=502,
            protocol=ProtocolType.MODBUS_TCP,
            transport_mode=ModbusTransportMode.TCP
        )
        
        assert attacker.target_ip == "192.168.1.100"
        assert attacker.port == 502
        assert attacker.protocol == ProtocolType.MODBUS_TCP
        assert attacker.transport_mode == ModbusTransportMode.TCP
        
    def test_attacker_initialization_rtu(self):
        """Test RTU attacker initialization"""
        attacker = IndustrialProtocolAttacker(
            protocol=ProtocolType.MODBUS_RTU,
            transport_mode=ModbusTransportMode.RTU,
            serial_port="/dev/ttyUSB0",
            serial_config={"baudrate": 9600, "bytesize": 8}
        )
        
        assert attacker.protocol == ProtocolType.MODBUS_RTU
        assert attacker.transport_mode == ModbusTransportMode.RTU
        assert attacker.serial_port == "/dev/ttyUSB0"


@pytest.fixture(scope="module")
def mock_modbus_server():
    """Fixture to start/stop mock Modbus server"""
    server = MockModbusServer(host="127.0.0.1", port=5020)
    server.start()
    time.sleep(1)
    
    yield server
    
    server.stop()


class TestModbusServerInteraction:
    """Test interactions with mock Modbus server"""
    
    def test_read_holding_registers(self, mock_modbus_server):
        """Test reading holding registers from mock server"""
        packet = ModbusPacket(
            transaction_id=1,
            protocol_id=0,
            unit_id=1,
            function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS,
            data=struct.pack('>HH', 0, 5)
        )
        
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 5020))
            sock.send(packet.to_tcp_bytes())
            response = sock.recv(1024)
            
            assert len(response) >= 9
            assert response[7] == ModbusFunctionCode.READ_HOLDING_REGISTERS
            
            byte_count = response[8]
            assert byte_count == 10
            
        finally:
            sock.close()
            
    def test_write_single_register(self, mock_modbus_server):
        """Test writing single register to mock server"""
        packet = ModbusPacket(
            transaction_id=2,
            protocol_id=0,
            unit_id=1,
            function_code=ModbusFunctionCode.WRITE_SINGLE_REGISTER,
            data=struct.pack('>HH', 100, 1234)
        )
        
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 5020))
            sock.send(packet.to_tcp_bytes())
            response = sock.recv(1024)
            
            assert len(response) >= 12
            assert response[7] == ModbusFunctionCode.WRITE_SINGLE_REGISTER
            
            addr = struct.unpack('>H', response[8:10])[0]
            value = struct.unpack('>H', response[10:12])[0]
            
            assert addr == 100
            assert value == 1234
            
        finally:
            sock.close()
            
    def test_write_multiple_registers(self, mock_modbus_server):
        """Test writing multiple registers to mock server"""
        values = [100, 200, 300, 400, 500]
        register_bytes = b''.join(struct.pack('>H', v) for v in values)
        
        data = struct.pack('>HHB', 0, len(values), len(register_bytes)) + register_bytes
        
        packet = ModbusPacket(
            transaction_id=3,
            protocol_id=0,
            unit_id=1,
            function_code=ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
            data=data
        )
        
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 5020))
            sock.send(packet.to_tcp_bytes())
            response = sock.recv(1024)
            
            assert len(response) >= 12
            assert response[7] == ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS
            
        finally:
            sock.close()
            
    def test_read_coils(self, mock_modbus_server):
        """Test reading coils from mock server"""
        packet = ModbusPacket(
            transaction_id=4,
            protocol_id=0,
            unit_id=1,
            function_code=ModbusFunctionCode.READ_COILS,
            data=struct.pack('>HH', 0, 16)
        )
        
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 5020))
            sock.send(packet.to_tcp_bytes())
            response = sock.recv(1024)
            
            assert len(response) >= 9
            assert response[7] == ModbusFunctionCode.READ_COILS
            
            byte_count = response[8]
            assert byte_count == 2
            
        finally:
            sock.close()
            
    def test_write_single_coil(self, mock_modbus_server):
        """Test writing single coil to mock server"""
        packet = ModbusPacket(
            transaction_id=5,
            protocol_id=0,
            unit_id=1,
            function_code=ModbusFunctionCode.WRITE_SINGLE_COIL,
            data=struct.pack('>HH', 10, 0xFF00)
        )
        
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 5020))
            sock.send(packet.to_tcp_bytes())
            response = sock.recv(1024)
            
            assert len(response) >= 12
            assert response[7] == ModbusFunctionCode.WRITE_SINGLE_COIL
            
            addr = struct.unpack('>H', response[8:10])[0]
            value = struct.unpack('>H', response[10:12])[0]
            
            assert addr == 10
            assert value == 0xFF00
            
        finally:
            sock.close()
            
    def test_invalid_function_code(self, mock_modbus_server):
        """Test invalid function code handling"""
        packet = ModbusPacket(
            transaction_id=6,
            protocol_id=0,
            unit_id=1,
            function_code=0x99,
            data=struct.pack('>HH', 0, 10)
        )
        
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 5020))
            sock.send(packet.to_tcp_bytes())
            response = sock.recv(1024)
            
            assert len(response) >= 9
            
            function_code = response[7]
            assert function_code == 0x80 | 0x99
            
            exception_code = response[8]
            assert exception_code == ModbusExceptionCode.ILLEGAL_FUNCTION
            
        finally:
            sock.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
