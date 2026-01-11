#!/usr/bin/env python3
"""
test_s7comm.py
Unit tests for S7Comm Security Framework
Author: Ridpath
Version: 1.0

Tests cover:
- S7 packet structure validation
- TPKT/COTP header encoding
- Function code enumeration
- Packet serialization/deserialization
- Symbol table structure
- Mock server interactions
"""

import pytest
import struct
import sys
import time
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent / "s7comm_security_framework"))
sys.path.insert(0, str(Path(__file__).parent))

from s7comm_exploit import (
    S7ProtocolID,
    S7FunctionCode,
    S7Area,
    S7Protection,
    S7Packet,
    S7Symbol
)
from mock_plc_server import MockS7Server


class TestS7ProtocolID:
    """Test S7 protocol ID enumeration"""
    
    def test_protocol_ids(self):
        """Test protocol ID values"""
        assert S7ProtocolID.S7COMM == 0x32
        assert S7ProtocolID.S7COMM_PLUS == 0x72


class TestS7FunctionCode:
    """Test S7 function code enumeration"""
    
    def test_function_codes(self):
        """Test function code values"""
        assert S7FunctionCode.SETUP_COMMUNICATION == 0xF0
        assert S7FunctionCode.READ_VAR == 0x04
        assert S7FunctionCode.WRITE_VAR == 0x05
        assert S7FunctionCode.REQUEST_DOWNLOAD == 0x1A
        assert S7FunctionCode.DOWNLOAD_BLOCK == 0x1B
        assert S7FunctionCode.DOWNLOAD_ENDED == 0x1C
        assert S7FunctionCode.START_UPLOAD == 0x1D
        assert S7FunctionCode.UPLOAD == 0x1E
        assert S7FunctionCode.END_UPLOAD == 0x1F
        assert S7FunctionCode.PLC_CONTROL == 0x28
        assert S7FunctionCode.PLC_STOP == 0x29


class TestS7Area:
    """Test S7 memory area enumeration"""
    
    def test_area_codes(self):
        """Test area code values"""
        assert S7Area.SYSINFO == 0x03
        assert S7Area.SYSTEM_FLAGS == 0x05
        assert S7Area.ANALOG_INPUTS == 0x06
        assert S7Area.ANALOG_OUTPUTS == 0x07
        assert S7Area.COUNTER == 0x1C
        assert S7Area.TIMER == 0x1D
        assert S7Area.INPUTS == 0x81
        assert S7Area.OUTPUTS == 0x82
        assert S7Area.FLAGS == 0x83
        assert S7Area.DB == 0x84
        assert S7Area.DI == 0x85


class TestS7Protection:
    """Test S7 protection level enumeration"""
    
    def test_protection_levels(self):
        """Test protection level values"""
        assert S7Protection.NO_PROTECTION == 0
        assert S7Protection.WRITE_PROTECTION == 1
        assert S7Protection.READ_WRITE_PROTECTION == 2
        assert S7Protection.FULL_PROTECTION == 3


class TestS7PacketStructure:
    """Test S7 packet structure and validation"""
    
    def test_packet_creation_minimal(self):
        """Test minimal S7 packet creation"""
        packet = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x0001,
            parameter_length=0,
            data_length=0
        )
        
        assert packet.tpkt_version == 3
        assert packet.protocol_id == S7ProtocolID.S7COMM
        assert packet.message_type == 0x01
        
    def test_packet_to_bytes(self):
        """Test S7 packet serialization"""
        parameters = b'\x00\x01\x02\x03'
        data = b'\x04\x05\x06\x07\x08\x09'
        
        packet = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x1234,
            parameter_length=len(parameters),
            data_length=len(data),
            parameters=parameters,
            data=data
        )
        
        packet_bytes = packet.to_bytes()
        
        assert len(packet_bytes) == 4 + 3 + 10 + len(parameters) + len(data)
        
        assert packet_bytes[0] == 3
        
        tpkt_length = struct.unpack('>H', packet_bytes[2:4])[0]
        assert tpkt_length == len(packet_bytes)
        
        protocol_id = packet_bytes[7]
        assert protocol_id == S7ProtocolID.S7COMM
        
    def test_packet_from_bytes(self):
        """Test S7 packet deserialization"""
        parameters = b'\x00\x01\x02\x03'
        data = b'\x04\x05\x06\x07\x08\x09'
        
        original_packet = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x5678,
            parameter_length=len(parameters),
            data_length=len(data),
            parameters=parameters,
            data=data
        )
        
        packet_bytes = original_packet.to_bytes()
        
        parsed_packet = S7Packet.from_bytes(packet_bytes)
        
        assert parsed_packet.tpkt_version == 3
        assert parsed_packet.protocol_id == S7ProtocolID.S7COMM
        assert parsed_packet.message_type == 0x01
        assert parsed_packet.pdu_reference == 0x5678
        assert parsed_packet.parameters == parameters
        assert parsed_packet.data == data
        
    def test_packet_validation_valid(self):
        """Test valid packet validation"""
        packet = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x0001,
            parameter_length=4,
            data_length=6,
            parameters=b'\x00\x01\x02\x03',
            data=b'\x04\x05\x06\x07\x08\x09'
        )
        
        is_valid, message = packet.validate()
        
        assert is_valid is True
        assert message == "Valid"
        
    def test_packet_validation_invalid_version(self):
        """Test packet validation with invalid TPKT version"""
        packet = S7Packet(
            tpkt_version=2,
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x0001
        )
        
        is_valid, message = packet.validate()
        
        assert is_valid is False
        assert "version" in message.lower()
        
    def test_packet_validation_invalid_protocol(self):
        """Test packet validation with invalid protocol ID"""
        packet = S7Packet(
            protocol_id=0x99,
            message_type=0x01,
            pdu_reference=0x0001
        )
        
        is_valid, message = packet.validate()
        
        assert is_valid is False
        assert "protocol id" in message.lower()
        
    def test_packet_validation_parameter_length_mismatch(self):
        """Test packet validation with parameter length mismatch"""
        packet = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x0001,
            parameter_length=10,
            parameters=b'\x00\x01\x02\x03'
        )
        
        is_valid, message = packet.validate()
        
        assert is_valid is False
        assert "parameter length" in message.lower()
        
    def test_packet_validation_data_length_mismatch(self):
        """Test packet validation with data length mismatch"""
        packet = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x0001,
            parameter_length=0,
            data_length=10,
            data=b'\x00\x01'
        )
        
        is_valid, message = packet.validate()
        
        assert is_valid is False
        assert "data length" in message.lower()
        
    def test_packet_from_bytes_too_short(self):
        """Test packet deserialization with too short data"""
        short_data = b'\x03\x00\x00\x10'
        
        with pytest.raises(ValueError) as exc_info:
            S7Packet.from_bytes(short_data)
        
        assert "too short" in str(exc_info.value).lower()
        
    def test_packet_from_bytes_invalid_version(self):
        """Test packet deserialization with invalid TPKT version"""
        invalid_packet = b'\x02\x00\x00\x16\x11\xe0\x00'
        invalid_packet += b'\x32\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        
        with pytest.raises(ValueError) as exc_info:
            S7Packet.from_bytes(invalid_packet)
        
        assert "version" in str(exc_info.value).lower()
        
    def test_packet_from_bytes_invalid_protocol_id(self):
        """Test packet deserialization with invalid protocol ID"""
        invalid_packet = b'\x03\x00\x00\x16\x11\xe0\x00'
        invalid_packet += b'\x99\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        
        with pytest.raises(ValueError) as exc_info:
            S7Packet.from_bytes(invalid_packet)
        
        assert "protocol id" in str(exc_info.value).lower()
        
    def test_s7commplus_packet(self):
        """Test S7CommPlus packet creation"""
        packet = S7Packet(
            protocol_id=S7ProtocolID.S7COMM_PLUS,
            message_type=0x01,
            pdu_reference=0x0001
        )
        
        assert packet.protocol_id == S7ProtocolID.S7COMM_PLUS
        
        is_valid, _ = packet.validate()
        assert is_valid is True


class TestS7Symbol:
    """Test S7 symbol table structure"""
    
    def test_symbol_creation(self):
        """Test symbol creation"""
        symbol = S7Symbol(
            name="MotorSpeed",
            area=S7Area.DB,
            db_number=100,
            start_offset=10,
            bit_offset=0,
            data_type="INT",
            length=2,
            comment="Motor RPM"
        )
        
        assert symbol.name == "MotorSpeed"
        assert symbol.area == S7Area.DB
        assert symbol.db_number == 100
        assert symbol.start_offset == 10
        assert symbol.data_type == "INT"
        assert symbol.length == 2
        
    def test_symbol_to_dict(self):
        """Test symbol serialization to dict"""
        symbol = S7Symbol(
            name="Valve1Status",
            area=S7Area.DB,
            db_number=50,
            start_offset=20,
            bit_offset=3,
            data_type="BOOL",
            length=1,
            comment="Valve status bit"
        )
        
        symbol_dict = symbol.to_dict()
        
        assert isinstance(symbol_dict, dict)
        assert symbol_dict["name"] == "Valve1Status"
        assert symbol_dict["area"] == "DB"
        assert symbol_dict["db_number"] == 50
        assert "DB50.DBX20.3" in symbol_dict["address"]
        assert symbol_dict["data_type"] == "BOOL"
        assert symbol_dict["length"] == 1
        assert symbol_dict["comment"] == "Valve status bit"
        
    def test_symbol_without_db(self):
        """Test symbol without data block"""
        symbol = S7Symbol(
            name="GlobalFlag",
            area=S7Area.FLAGS,
            db_number=0,
            start_offset=5,
            bit_offset=2,
            data_type="BOOL",
            length=1
        )
        
        symbol_dict = symbol.to_dict()
        
        assert symbol_dict["db_number"] == 0
        assert "5.2" in symbol_dict["address"]
        assert "DB" not in symbol_dict["address"]


@pytest.fixture(scope="module")
def mock_s7_server():
    """Fixture to start/stop mock S7 server"""
    server = MockS7Server(host="127.0.0.1", port=1020)
    server.start()
    time.sleep(1)
    
    yield server
    
    server.stop()


class TestS7ServerInteraction:
    """Test interactions with mock S7 server"""
    
    def test_connection(self, mock_s7_server):
        """Test connection to mock S7 server"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 1020))
            
            cotp_conn_request = bytes([
                0x03, 0x00, 0x00, 0x16,
                0x11, 0xE0, 0x00, 0x00,
                0x00, 0x01, 0x00, 0xC0,
                0x01, 0x0A, 0xC1, 0x02,
                0x01, 0x02, 0xC2, 0x02,
                0x01, 0x00
            ])
            
            sock.send(cotp_conn_request)
            response = sock.recv(1024)
            
            assert len(response) > 0
            assert response[0] == 0x03
            
        finally:
            sock.close()
            
    def test_cotp_connection_confirm(self, mock_s7_server):
        """Test COTP connection confirmation"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 1020))
            
            cotp_conn_request = bytes([
                0x03, 0x00, 0x00, 0x16,
                0x11, 0xE0, 0x00, 0x00,
                0x00, 0x01, 0x00, 0xC0,
                0x01, 0x0A, 0xC1, 0x02,
                0x01, 0x02, 0xC2, 0x02,
                0x01, 0x00
            ])
            
            sock.send(cotp_conn_request)
            response = sock.recv(1024)
            
            assert len(response) >= 7
            assert response[5] == 0xF0
            
        finally:
            sock.close()


class TestS7PacketRoundtrip:
    """Test packet serialization/deserialization roundtrip"""
    
    def test_roundtrip_no_data(self):
        """Test roundtrip with no parameters or data"""
        original = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x1234
        )
        
        serialized = original.to_bytes()
        deserialized = S7Packet.from_bytes(serialized)
        
        assert deserialized.protocol_id == original.protocol_id
        assert deserialized.message_type == original.message_type
        assert deserialized.pdu_reference == original.pdu_reference
        
    def test_roundtrip_with_parameters(self):
        """Test roundtrip with parameters"""
        params = b'\x32\x01\x00\x00\x05\x00\x00'
        
        original = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0xABCD,
            parameter_length=len(params),
            parameters=params
        )
        
        serialized = original.to_bytes()
        deserialized = S7Packet.from_bytes(serialized)
        
        assert deserialized.parameters == original.parameters
        assert deserialized.parameter_length == original.parameter_length
        
    def test_roundtrip_with_data(self):
        """Test roundtrip with data"""
        data = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        
        original = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0xEF01,
            data_length=len(data),
            data=data
        )
        
        serialized = original.to_bytes()
        deserialized = S7Packet.from_bytes(serialized)
        
        assert deserialized.data == original.data
        assert deserialized.data_length == original.data_length
        
    def test_roundtrip_full_packet(self):
        """Test roundtrip with parameters and data"""
        params = b'\x32\x01\x00\x00\x0E\x00\x00\x04\x01'
        data = b'\xFF\x04\x00\x80\x00\x00\x00\x00\x00\x00'
        
        original = S7Packet(
            protocol_id=S7ProtocolID.S7COMM,
            message_type=0x01,
            pdu_reference=0x9999,
            parameter_length=len(params),
            data_length=len(data),
            parameters=params,
            data=data
        )
        
        serialized = original.to_bytes()
        deserialized = S7Packet.from_bytes(serialized)
        
        assert deserialized.protocol_id == original.protocol_id
        assert deserialized.message_type == original.message_type
        assert deserialized.pdu_reference == original.pdu_reference
        assert deserialized.parameters == original.parameters
        assert deserialized.data == original.data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
