#!/usr/bin/env python3
"""
test_opcua.py
Unit tests for OPC-UA Security Framework
Author: Ridpath
Version: 1.0

Tests cover:
- Security policy enumeration
- Message security mode validation
- Node class enumeration
- Endpoint structure
- Node information structure
- Security event logging
"""

import pytest
import sys
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent / "opcua_security_framework"))

from opcua_exploit import (
    OPCUASecurityPolicy,
    OPCUAMessageSecurityMode,
    OPCUANodeClass,
    OPCUAServiceType,
    MITRETechnique,
    OPCUAEndpoint,
    OPCUANodeInfo,
    SecurityEvent
)


class TestOPCUASecurityPolicy:
    """Test OPC-UA security policy enumeration"""
    
    def test_security_policies(self):
        """Test security policy values"""
        assert OPCUASecurityPolicy.NONE.value == "None"
        assert OPCUASecurityPolicy.BASIC128RSA15.value == "Basic128Rsa15"
        assert OPCUASecurityPolicy.BASIC256.value == "Basic256"
        assert OPCUASecurityPolicy.BASIC256SHA256.value == "Basic256Sha256"
        assert OPCUASecurityPolicy.AES128_SHA256_RSAOAEP.value == "Aes128_Sha256_RsaOaep"
        assert OPCUASecurityPolicy.AES256_SHA256_RSAPSS.value == "Aes256_Sha256_RsaPss"


class TestOPCUAMessageSecurityMode:
    """Test OPC-UA message security mode enumeration"""
    
    def test_security_modes(self):
        """Test security mode values"""
        assert OPCUAMessageSecurityMode.INVALID == 0
        assert OPCUAMessageSecurityMode.NONE == 1
        assert OPCUAMessageSecurityMode.SIGN == 2
        assert OPCUAMessageSecurityMode.SIGNANDENCRYPT == 3


class TestOPCUANodeClass:
    """Test OPC-UA node class enumeration"""
    
    def test_node_classes(self):
        """Test node class values"""
        assert OPCUANodeClass.UNSPECIFIED == 0
        assert OPCUANodeClass.OBJECT == 1
        assert OPCUANodeClass.VARIABLE == 2
        assert OPCUANodeClass.METHOD == 4
        assert OPCUANodeClass.OBJECTTYPE == 8
        assert OPCUANodeClass.VARIABLETYPE == 16
        assert OPCUANodeClass.REFERENCETYPE == 32
        assert OPCUANodeClass.DATATYPE == 64
        assert OPCUANodeClass.VIEW == 128


class TestOPCUAServiceType:
    """Test OPC-UA service type enumeration"""
    
    def test_service_types(self):
        """Test service type values"""
        assert OPCUAServiceType.READ.value == "Read"
        assert OPCUAServiceType.WRITE.value == "Write"
        assert OPCUAServiceType.BROWSE.value == "Browse"
        assert OPCUAServiceType.CALL.value == "Call"
        assert OPCUAServiceType.CREATE_SUBSCRIPTION.value == "CreateSubscription"
        assert OPCUAServiceType.CREATE_MONITORED_ITEMS.value == "CreateMonitoredItems"


class TestMITRETechnique:
    """Test MITRE ATT&CK technique enumeration"""
    
    def test_techniques(self):
        """Test MITRE technique IDs"""
        assert MITRETechnique.T0801_MONITOR_PROCESS_STATE.value == "T0801"
        assert MITRETechnique.T0819_EXPLOIT_PUBLIC_FACING_APPLICATION.value == "T0819"
        assert MITRETechnique.T0855_UNAUTHORIZED_COMMAND_MESSAGE.value == "T0855"
        assert MITRETechnique.T0861_POINT_AND_TAG_IDENTIFICATION.value == "T0861"
        assert MITRETechnique.T0868_DETECT_OPERATING_MODE.value == "T0868"
        assert MITRETechnique.T0877_I_O_MODULE_DISCOVERY.value == "T0877"
        assert MITRETechnique.T0888_REMOTE_SYSTEM_INFORMATION_DISCOVERY.value == "T0888"


class TestOPCUAEndpoint:
    """Test OPC-UA endpoint structure"""
    
    def test_endpoint_creation_minimal(self):
        """Test minimal endpoint creation"""
        endpoint = OPCUAEndpoint(
            url="opc.tcp://192.168.1.100:4840"
        )
        
        assert endpoint.url == "opc.tcp://192.168.1.100:4840"
        assert endpoint.security_mode == OPCUAMessageSecurityMode.NONE
        assert endpoint.security_policy == OPCUASecurityPolicy.NONE.value
        assert len(endpoint.user_identity_tokens) == 0
        assert endpoint.server_certificate is None
        
    def test_endpoint_creation_full(self):
        """Test full endpoint creation"""
        cert = b'\x30\x82\x03\x00'
        
        endpoint = OPCUAEndpoint(
            url="opc.tcp://10.0.0.1:4840/server",
            security_mode=OPCUAMessageSecurityMode.SIGNANDENCRYPT,
            security_policy=OPCUASecurityPolicy.BASIC256SHA256.value,
            user_identity_tokens=["Anonymous", "UserName"],
            server_certificate=cert
        )
        
        assert endpoint.url == "opc.tcp://10.0.0.1:4840/server"
        assert endpoint.security_mode == OPCUAMessageSecurityMode.SIGNANDENCRYPT
        assert endpoint.security_policy == OPCUASecurityPolicy.BASIC256SHA256.value
        assert len(endpoint.user_identity_tokens) == 2
        assert endpoint.server_certificate == cert
        
    def test_endpoint_to_dict(self):
        """Test endpoint serialization to dict"""
        endpoint = OPCUAEndpoint(
            url="opc.tcp://localhost:4840",
            security_mode=OPCUAMessageSecurityMode.SIGN,
            security_policy=OPCUASecurityPolicy.BASIC256.value,
            user_identity_tokens=["UserName", "Certificate"],
            server_certificate=b'\x00\x01\x02\x03'
        )
        
        endpoint_dict = endpoint.to_dict()
        
        assert isinstance(endpoint_dict, dict)
        assert endpoint_dict["url"] == "opc.tcp://localhost:4840"
        assert endpoint_dict["security_mode"] == "SIGN"
        assert endpoint_dict["security_policy"] == "Basic256"
        assert endpoint_dict["user_identity_tokens"] == ["UserName", "Certificate"]
        assert endpoint_dict["has_certificate"] is True
        
    def test_endpoint_without_certificate(self):
        """Test endpoint without certificate"""
        endpoint = OPCUAEndpoint(
            url="opc.tcp://server:4840"
        )
        
        endpoint_dict = endpoint.to_dict()
        assert endpoint_dict["has_certificate"] is False


class TestOPCUANodeInfo:
    """Test OPC-UA node information structure"""
    
    def test_node_info_creation_minimal(self):
        """Test minimal node info creation"""
        node = OPCUANodeInfo(
            node_id="ns=2;i=1000",
            browse_name="MotorSpeed",
            display_name="Motor Speed",
            node_class=OPCUANodeClass.VARIABLE
        )
        
        assert node.node_id == "ns=2;i=1000"
        assert node.browse_name == "MotorSpeed"
        assert node.display_name == "Motor Speed"
        assert node.node_class == OPCUANodeClass.VARIABLE
        assert node.data_type is None
        assert node.value is None
        assert node.writable is False
        
    def test_node_info_creation_full(self):
        """Test full node info creation"""
        node = OPCUANodeInfo(
            node_id="ns=3;s=Temperature",
            browse_name="TempSensor1",
            display_name="Temperature Sensor 1",
            node_class=OPCUANodeClass.VARIABLE,
            data_type="Double",
            value=23.5,
            access_level=3,
            user_access_level=3,
            writable=True
        )
        
        assert node.node_id == "ns=3;s=Temperature"
        assert node.data_type == "Double"
        assert node.value == 23.5
        assert node.access_level == 3
        assert node.user_access_level == 3
        assert node.writable is True
        
    def test_node_info_to_dict(self):
        """Test node info serialization to dict"""
        node = OPCUANodeInfo(
            node_id="ns=4;i=5000",
            browse_name="PressureValve",
            display_name="Pressure Valve Control",
            node_class=OPCUANodeClass.VARIABLE,
            data_type="Boolean",
            value=True,
            access_level=3,
            user_access_level=1,
            writable=True
        )
        
        node_dict = node.to_dict()
        
        assert isinstance(node_dict, dict)
        assert node_dict["node_id"] == "ns=4;i=5000"
        assert node_dict["browse_name"] == "PressureValve"
        assert node_dict["display_name"] == "Pressure Valve Control"
        assert node_dict["node_class"] == "VARIABLE"
        assert node_dict["data_type"] == "Boolean"
        assert node_dict["value"] == "True"
        assert node_dict["access_level"] == 3
        assert node_dict["user_access_level"] == 1
        assert node_dict["writable"] is True
        
    def test_node_info_object_type(self):
        """Test object-type node info"""
        node = OPCUANodeInfo(
            node_id="ns=0;i=58",
            browse_name="BaseObjectType",
            display_name="BaseObjectType",
            node_class=OPCUANodeClass.OBJECTTYPE
        )
        
        assert node.node_class == OPCUANodeClass.OBJECTTYPE
        
        node_dict = node.to_dict()
        assert node_dict["node_class"] == "OBJECTTYPE"
        
    def test_node_info_method_type(self):
        """Test method-type node info"""
        node = OPCUANodeInfo(
            node_id="ns=2;s=StartMotor",
            browse_name="StartMotor",
            display_name="Start Motor Method",
            node_class=OPCUANodeClass.METHOD
        )
        
        assert node.node_class == OPCUANodeClass.METHOD
        
        node_dict = node.to_dict()
        assert node_dict["node_class"] == "METHOD"


class TestSecurityEvent:
    """Test security event structure"""
    
    def test_security_event_creation(self):
        """Test security event creation"""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            technique="Node Enumeration",
            mitre_id="T0861",
            target="opc.tcp://192.168.1.100:4840",
            success=True,
            details={"nodes_discovered": 150},
            severity="HIGH"
        )
        
        assert event.technique == "Node Enumeration"
        assert event.mitre_id == "T0861"
        assert event.target == "opc.tcp://192.168.1.100:4840"
        assert event.success is True
        assert event.details["nodes_discovered"] == 150
        assert event.severity == "HIGH"
        
    def test_security_event_to_dict(self):
        """Test security event serialization to dict"""
        timestamp = "2024-01-01T12:00:00"
        
        event = SecurityEvent(
            timestamp=timestamp,
            technique="Certificate Bypass",
            mitre_id="T0819",
            target="opc.tcp://10.0.0.1:4840",
            success=False,
            details={"error": "Connection refused"},
            severity="CRITICAL"
        )
        
        event_dict = event.to_dict()
        
        assert isinstance(event_dict, dict)
        assert event_dict["timestamp"] == timestamp
        assert event_dict["technique"] == "Certificate Bypass"
        assert event_dict["mitre_id"] == "T0819"
        assert event_dict["target"] == "opc.tcp://10.0.0.1:4840"
        assert event_dict["success"] is False
        assert event_dict["details"]["error"] == "Connection refused"
        assert event_dict["severity"] == "CRITICAL"
        
    def test_security_event_to_json(self):
        """Test security event serialization to JSON"""
        import json
        
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00",
            technique="Subscription Manipulation",
            mitre_id="T0801",
            target="opc.tcp://server:4840",
            success=True,
            details={"subscriptions_created": 5},
            severity="MEDIUM"
        )
        
        json_str = event.to_json()
        
        assert isinstance(json_str, str)
        
        parsed = json.loads(json_str)
        assert parsed["technique"] == "Subscription Manipulation"
        assert parsed["mitre_id"] == "T0801"
        assert parsed["success"] is True
        
    def test_security_event_default_severity(self):
        """Test security event with default severity"""
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00",
            technique="Test",
            mitre_id="T0000",
            target="test",
            success=True,
            details={}
        )
        
        assert event.severity == "MEDIUM"


class TestOPCUADataTypes:
    """Test OPC-UA data type handling"""
    
    def test_node_with_numeric_value(self):
        """Test node with numeric value"""
        node = OPCUANodeInfo(
            node_id="ns=2;i=1001",
            browse_name="Counter",
            display_name="Counter",
            node_class=OPCUANodeClass.VARIABLE,
            data_type="Int32",
            value=12345
        )
        
        node_dict = node.to_dict()
        assert node_dict["value"] == "12345"
        
    def test_node_with_string_value(self):
        """Test node with string value"""
        node = OPCUANodeInfo(
            node_id="ns=2;i=1002",
            browse_name="Status",
            display_name="Status",
            node_class=OPCUANodeClass.VARIABLE,
            data_type="String",
            value="Running"
        )
        
        node_dict = node.to_dict()
        assert node_dict["value"] == "Running"
        
    def test_node_with_boolean_value(self):
        """Test node with boolean value"""
        node = OPCUANodeInfo(
            node_id="ns=2;i=1003",
            browse_name="AlarmActive",
            display_name="Alarm Active",
            node_class=OPCUANodeClass.VARIABLE,
            data_type="Boolean",
            value=False
        )
        
        node_dict = node.to_dict()
        assert node_dict["value"] == "False"
        
    def test_node_with_none_value(self):
        """Test node with None value"""
        node = OPCUANodeInfo(
            node_id="ns=2;i=1004",
            browse_name="NotAvailable",
            display_name="Not Available",
            node_class=OPCUANodeClass.VARIABLE,
            data_type="Int32",
            value=None
        )
        
        node_dict = node.to_dict()
        assert node_dict["value"] is None


class TestOPCUAAccessLevels:
    """Test OPC-UA access level handling"""
    
    def test_read_only_access(self):
        """Test read-only access level"""
        node = OPCUANodeInfo(
            node_id="ns=2;i=2000",
            browse_name="ReadOnly",
            display_name="Read Only Variable",
            node_class=OPCUANodeClass.VARIABLE,
            access_level=1,
            user_access_level=1,
            writable=False
        )
        
        assert node.access_level == 1
        assert node.writable is False
        
    def test_read_write_access(self):
        """Test read/write access level"""
        node = OPCUANodeInfo(
            node_id="ns=2;i=2001",
            browse_name="ReadWrite",
            display_name="Read Write Variable",
            node_class=OPCUANodeClass.VARIABLE,
            access_level=3,
            user_access_level=3,
            writable=True
        )
        
        assert node.access_level == 3
        assert node.writable is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
