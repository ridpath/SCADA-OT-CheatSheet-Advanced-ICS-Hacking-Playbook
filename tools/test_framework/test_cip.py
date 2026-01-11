#!/usr/bin/env python3
"""
test_cip.py
Unit tests for CIP/EtherNet/IP Security Assessment Toolkit
Author: Ridpath
Version: 1.0

Tests cover:
- CIP packet structure validation
- EtherNet/IP header encoding
- Service code enumeration
- Safety packet CRC calculation
- Packet serialization/deserialization
- Mock server interactions
"""

import pytest
import struct
import sys
import time
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent / "cip_security_assessment"))
sys.path.insert(0, str(Path(__file__).parent))

from cip_exploiter import (
    CIPServiceCode,
    CIPClassCode,
    CIPStatusCode,
    EtherNetIPCommand,
    SecurityLevel,
    EtherNetIPHeader,
    CIPPacket,
    SafetyPacket,
    SecurityAssessment
)
from mock_plc_server import MockCIPServer


class TestCIPServiceCode:
    """Test CIP service code enumeration"""
    
    def test_common_services(self):
        """Test common service codes"""
        assert CIPServiceCode.GET_ATTRIBUTES_ALL == 0x01
        assert CIPServiceCode.SET_ATTRIBUTES_ALL == 0x02
        assert CIPServiceCode.GET_ATTRIBUTE_SINGLE == 0x0E
        assert CIPServiceCode.SET_ATTRIBUTE_SINGLE == 0x10
        assert CIPServiceCode.RESET == 0x05
        assert CIPServiceCode.START == 0x06
        assert CIPServiceCode.STOP == 0x07
        
    def test_tag_services(self):
        """Test tag read/write service codes"""
        assert CIPServiceCode.READ_TAG == 0x4C
        assert CIPServiceCode.WRITE_TAG == 0x4D
        assert CIPServiceCode.READ_TAG_FRAGMENTED == 0x52
        assert CIPServiceCode.WRITE_TAG_FRAGMENTED == 0x53
        assert CIPServiceCode.READ_MODIFY_WRITE_TAG == 0x4E


class TestCIPClassCode:
    """Test CIP class code enumeration"""
    
    def test_class_codes(self):
        """Test class code values"""
        assert CIPClassCode.IDENTITY == 0x01
        assert CIPClassCode.MESSAGE_ROUTER == 0x02
        assert CIPClassCode.ASSEMBLY == 0x04
        assert CIPClassCode.CONNECTION == 0x05
        assert CIPClassCode.CONNECTION_MANAGER == 0x06
        assert CIPClassCode.SAFETY_SUPERVISOR == 0x39
        assert CIPClassCode.SAFETY_VALIDATOR == 0x3A
        assert CIPClassCode.CIP_SECURITY == 0x5D
        assert CIPClassCode.TCP_IP_INTERFACE == 0x75
        assert CIPClassCode.ETHERNET_LINK == 0x76


class TestCIPStatusCode:
    """Test CIP status code enumeration"""
    
    def test_status_codes(self):
        """Test status code values"""
        assert CIPStatusCode.SUCCESS == 0x00
        assert CIPStatusCode.CONNECTION_FAILURE == 0x01
        assert CIPStatusCode.RESOURCE_UNAVAILABLE == 0x02
        assert CIPStatusCode.INVALID_PARAMETER_VALUE == 0x03
        assert CIPStatusCode.SERVICE_NOT_SUPPORTED == 0x08
        assert CIPStatusCode.PRIVILEGE_VIOLATION == 0x0F
        assert CIPStatusCode.OBJECT_DOES_NOT_EXIST == 0x16


class TestEtherNetIPCommand:
    """Test EtherNet/IP command enumeration"""
    
    def test_commands(self):
        """Test command code values"""
        assert EtherNetIPCommand.NOP == 0x0000
        assert EtherNetIPCommand.LIST_SERVICES == 0x0004
        assert EtherNetIPCommand.LIST_IDENTITY == 0x0063
        assert EtherNetIPCommand.LIST_INTERFACES == 0x0064
        assert EtherNetIPCommand.REGISTER_SESSION == 0x0065
        assert EtherNetIPCommand.UNREGISTER_SESSION == 0x0066
        assert EtherNetIPCommand.SEND_RR_DATA == 0x006F
        assert EtherNetIPCommand.SEND_UNIT_DATA == 0x0070


class TestEtherNetIPHeader:
    """Test EtherNet/IP header structure"""
    
    def test_header_creation(self):
        """Test header creation"""
        header = EtherNetIPHeader(
            command=EtherNetIPCommand.LIST_IDENTITY,
            length=0,
            session_handle=0x12345678,
            status=0
        )
        
        assert header.command == EtherNetIPCommand.LIST_IDENTITY
        assert header.session_handle == 0x12345678
        assert header.length == 0
        assert header.status == 0
        
    def test_header_to_bytes(self):
        """Test header serialization"""
        header = EtherNetIPHeader(
            command=EtherNetIPCommand.REGISTER_SESSION,
            length=4,
            session_handle=0xABCDEF01,
            status=0,
            sender_context=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            options=0
        )
        
        header_bytes = header.to_bytes()
        
        assert len(header_bytes) == 24
        
        command = struct.unpack('<H', header_bytes[0:2])[0]
        assert command == EtherNetIPCommand.REGISTER_SESSION
        
        length = struct.unpack('<H', header_bytes[2:4])[0]
        assert length == 4
        
        session = struct.unpack('<I', header_bytes[4:8])[0]
        assert session == 0xABCDEF01
        
    def test_header_from_bytes(self):
        """Test header deserialization"""
        header_bytes = struct.pack('<HHIIQH',
            EtherNetIPCommand.LIST_SERVICES,
            0,
            0,
            0,
            0x0102030405060708,
            0
        )
        
        header = EtherNetIPHeader.from_bytes(header_bytes)
        
        assert header.command == EtherNetIPCommand.LIST_SERVICES
        assert header.length == 0
        assert header.session_handle == 0
        assert header.status == 0
        
    def test_header_from_bytes_too_short(self):
        """Test header deserialization with too short data"""
        short_data = b'\x00\x01\x02\x03'
        
        with pytest.raises(ValueError) as exc_info:
            EtherNetIPHeader.from_bytes(short_data)
        
        assert "too short" in str(exc_info.value).lower()
        
    def test_header_roundtrip(self):
        """Test header serialization/deserialization roundtrip"""
        original = EtherNetIPHeader(
            command=EtherNetIPCommand.SEND_RR_DATA,
            length=20,
            session_handle=0x11223344,
            status=0,
            sender_context=b'\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11',
            options=0
        )
        
        serialized = original.to_bytes()
        deserialized = EtherNetIPHeader.from_bytes(serialized)
        
        assert deserialized.command == original.command
        assert deserialized.length == original.length
        assert deserialized.session_handle == original.session_handle
        assert deserialized.status == original.status


class TestCIPPacket:
    """Test CIP packet structure"""
    
    def test_packet_creation(self):
        """Test CIP packet creation"""
        request_path = b'\x20\x01\x24\x01'
        request_data = b'\x00\x00\x00\x00'
        
        packet = CIPPacket(
            service=CIPServiceCode.GET_ATTRIBUTES_ALL,
            request_path=request_path,
            request_data=request_data
        )
        
        assert packet.service == CIPServiceCode.GET_ATTRIBUTES_ALL
        assert packet.request_path == request_path
        assert packet.request_data == request_data
        
    def test_packet_to_bytes(self):
        """Test CIP packet serialization"""
        request_path = b'\x20\x01\x24\x01'
        request_data = b'\x01\x02\x03\x04'
        
        packet = CIPPacket(
            service=CIPServiceCode.READ_TAG,
            request_path=request_path,
            request_data=request_data
        )
        
        packet_bytes = packet.to_bytes()
        
        assert packet_bytes[0] == CIPServiceCode.READ_TAG
        assert packet_bytes[1] == len(request_path) // 2
        assert packet_bytes[2:2+len(request_path)] == request_path
        assert packet_bytes[2+len(request_path):] == request_data
        
    def test_packet_from_bytes(self):
        """Test CIP packet deserialization"""
        request_path = b'\x20\x06\x24\x01'
        request_data = b'\xAA\xBB\xCC\xDD'
        
        original = CIPPacket(
            service=CIPServiceCode.WRITE_TAG,
            request_path=request_path,
            request_data=request_data
        )
        
        packet_bytes = original.to_bytes()
        parsed = CIPPacket.from_bytes(packet_bytes)
        
        assert parsed.service == original.service
        assert parsed.request_path == original.request_path
        assert parsed.request_data == original.request_data
        
    def test_packet_from_bytes_too_short(self):
        """Test CIP packet deserialization with too short data"""
        short_data = b'\x01'
        
        with pytest.raises(ValueError) as exc_info:
            CIPPacket.from_bytes(short_data)
        
        assert "too short" in str(exc_info.value).lower()
        
    def test_packet_validation_valid(self):
        """Test valid packet validation"""
        packet = CIPPacket(
            service=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
            request_path=b'\x20\x01\x24\x01'
        )
        
        is_valid, error = packet.validate()
        
        assert is_valid is True
        assert error is None
        
    def test_packet_validation_odd_path_length(self):
        """Test packet validation with odd path length"""
        packet = CIPPacket(
            service=CIPServiceCode.GET_ATTRIBUTES_ALL,
            request_path=b'\x20\x01\x24'
        )
        
        is_valid, error = packet.validate()
        
        assert is_valid is False
        assert "even number" in error.lower()
        
    def test_packet_roundtrip(self):
        """Test packet serialization/deserialization roundtrip"""
        original = CIPPacket(
            service=CIPServiceCode.SET_ATTRIBUTE_SINGLE,
            request_path=b'\x20\x02\x24\x01\x30\x03',
            request_data=b'\x00\x01\x02\x03\x04\x05'
        )
        
        serialized = original.to_bytes()
        deserialized = CIPPacket.from_bytes(serialized)
        
        assert deserialized.service == original.service
        assert deserialized.request_path == original.request_path
        assert deserialized.request_data == original.request_data


class TestSafetyPacket:
    """Test CIP Safety packet structure"""
    
    def test_safety_packet_creation(self):
        """Test safety packet creation"""
        safety_data = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        
        packet = SafetyPacket(
            safety_data=safety_data,
            timestamp=1234,
            sequence=56
        )
        
        assert packet.safety_data == safety_data
        assert packet.timestamp == 1234
        assert packet.sequence == 56
        
    def test_safety_packet_crc_calculation(self):
        """Test safety packet CRC-16 calculation"""
        safety_data = b'\xAA\xBB\xCC\xDD'
        
        packet = SafetyPacket(safety_data=safety_data)
        crc = packet.compute_crc()
        
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF
        
    def test_safety_packet_crc_consistency(self):
        """Test CRC calculation consistency"""
        safety_data = b'\x11\x22\x33\x44\x55\x66'
        
        packet1 = SafetyPacket(safety_data=safety_data)
        crc1 = packet1.compute_crc()
        
        packet2 = SafetyPacket(safety_data=safety_data)
        crc2 = packet2.compute_crc()
        
        assert crc1 == crc2
        
    def test_safety_packet_crc_difference(self):
        """Test different data produces different CRC"""
        packet1 = SafetyPacket(safety_data=b'\x01\x02\x03\x04')
        crc1 = packet1.compute_crc()
        
        packet2 = SafetyPacket(safety_data=b'\x01\x02\x03\x05')
        crc2 = packet2.compute_crc()
        
        assert crc1 != crc2
        
    def test_safety_packet_to_bytes(self):
        """Test safety packet serialization"""
        safety_data = b'\x10\x20\x30\x40'
        
        packet = SafetyPacket(
            safety_data=safety_data,
            timestamp=5678,
            sequence=90
        )
        
        packet_bytes = packet.to_bytes()
        
        assert len(packet_bytes) == 6 + len(safety_data)
        
        crc, timestamp, sequence = struct.unpack('<HHH', packet_bytes[:6])
        assert timestamp == 5678
        assert sequence == 90
        assert packet_bytes[6:] == safety_data
        
    def test_safety_packet_from_bytes(self):
        """Test safety packet deserialization"""
        original = SafetyPacket(
            safety_data=b'\xFF\xEE\xDD\xCC\xBB\xAA',
            timestamp=9999,
            sequence=123
        )
        
        packet_bytes = original.to_bytes()
        parsed = SafetyPacket.from_bytes(packet_bytes)
        
        assert parsed.safety_data == original.safety_data
        assert parsed.timestamp == original.timestamp
        assert parsed.sequence == original.sequence
        
    def test_safety_packet_from_bytes_too_short(self):
        """Test safety packet deserialization with too short data"""
        short_data = b'\x01\x02\x03'
        
        with pytest.raises(ValueError) as exc_info:
            SafetyPacket.from_bytes(short_data)
        
        assert "too short" in str(exc_info.value).lower()


class TestSecurityAssessment:
    """Test security assessment structure"""
    
    def test_assessment_creation(self):
        """Test security assessment creation"""
        assessment = SecurityAssessment(
            level=SecurityLevel.HIGH,
            vulnerabilities=["Unencrypted communications", "No authentication"],
            recommendations=["Enable encryption", "Implement authentication"]
        )
        
        assert assessment.level == SecurityLevel.HIGH
        assert len(assessment.vulnerabilities) == 2
        assert len(assessment.recommendations) == 2
        
    def test_assessment_to_dict(self):
        """Test security assessment serialization"""
        assessment = SecurityAssessment(
            level=SecurityLevel.MEDIUM,
            vulnerabilities=["Weak passwords"],
            recommendations=["Use strong passwords"]
        )
        
        assessment_dict = assessment.to_dict()
        
        assert isinstance(assessment_dict, dict)
        assert assessment_dict["level"] == "MEDIUM"
        assert assessment_dict["vulnerabilities"] == ["Weak passwords"]
        assert assessment_dict["recommendations"] == ["Use strong passwords"]


class TestSecurityLevel:
    """Test security level enumeration"""
    
    def test_security_levels(self):
        """Test security level values"""
        assert SecurityLevel.LOW.value == 1
        assert SecurityLevel.MEDIUM.value == 2
        assert SecurityLevel.HIGH.value == 3


@pytest.fixture(scope="module")
def mock_cip_server():
    """Fixture to start/stop mock CIP server"""
    server = MockCIPServer(host="127.0.0.1", port=44818)
    server.start()
    time.sleep(1)
    
    yield server
    
    server.stop()


class TestCIPServerInteraction:
    """Test interactions with mock CIP server"""
    
    def test_connection(self, mock_cip_server):
        """Test connection to mock CIP server"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 44818))
            assert True
        finally:
            sock.close()
            
    def test_list_identity_request(self, mock_cip_server):
        """Test ListIdentity request"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect(("127.0.0.1", 44818))
            
            header = EtherNetIPHeader(
                command=EtherNetIPCommand.LIST_IDENTITY,
                length=0,
                session_handle=0,
                status=0
            )
            
            sock.send(header.to_bytes())
            response = sock.recv(1024)
            
            assert len(response) >= 24
            
            response_header = EtherNetIPHeader.from_bytes(response[:24])
            assert response_header.command == EtherNetIPCommand.LIST_IDENTITY
            
        finally:
            sock.close()


class TestCIPPacketEdgeCases:
    """Test CIP packet edge cases"""
    
    def test_empty_request_path(self):
        """Test packet with empty request path"""
        packet = CIPPacket(
            service=CIPServiceCode.NOP,
            request_path=b'',
            request_data=b''
        )
        
        is_valid, error = packet.validate()
        assert is_valid is True
        
        packet_bytes = packet.to_bytes()
        parsed = CIPPacket.from_bytes(packet_bytes)
        
        assert parsed.service == packet.service
        assert parsed.request_path == packet.request_path
        
    def test_large_request_data(self):
        """Test packet with large request data"""
        large_data = b'\xAA' * 1000
        
        packet = CIPPacket(
            service=CIPServiceCode.WRITE_TAG,
            request_path=b'\x20\x01',
            request_data=large_data
        )
        
        packet_bytes = packet.to_bytes()
        parsed = CIPPacket.from_bytes(packet_bytes)
        
        assert parsed.request_data == large_data
        
    def test_max_path_size(self):
        """Test packet with maximum path size"""
        max_path = b'\x20\x01' * 127
        
        packet = CIPPacket(
            service=CIPServiceCode.GET_ATTRIBUTES_ALL,
            request_path=max_path
        )
        
        packet_bytes = packet.to_bytes()
        assert packet_bytes[1] == 127


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
