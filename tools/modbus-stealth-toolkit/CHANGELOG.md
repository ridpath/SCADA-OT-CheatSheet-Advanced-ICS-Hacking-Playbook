# Changelog - Modbus Stealth Attack Toolkit

## Version 3.0 - 2026-01-11

### Major Enhancements

#### Protocol Support
- **Modbus TCP**: Full implementation with MBAP header validation
- **Modbus RTU**: Complete RTU support with CRC-16 validation and serial communication
- **Modbus ASCII**: ASCII mode with LRC checksum calculation

#### Function Code Coverage
Added complete function code support per Modbus Application Protocol v1.1b3:

**Basic Functions (0x01-0x10):**
- 0x01: Read Coils
- 0x02: Read Discrete Inputs
- 0x03: Read Holding Registers
- 0x04: Read Input Registers
- 0x05: Write Single Coil
- 0x06: Write Single Register
- 0x07: Read Exception Status
- 0x08: Diagnostics
- 0x0B: Get Comm Event Counter
- 0x0C: Get Comm Event Log
- 0x0F: Write Multiple Coils
- 0x10: Write Multiple Registers

**Advanced Functions (0x11-0x18):**
- 0x11: Report Server ID
- **0x14: Read File Record** [NEW]
- **0x15: Write File Record** [NEW]
- **0x16: Mask Write Register** [NEW]
- **0x17: Read/Write Multiple Registers** [NEW]
- 0x18: Read FIFO Queue
- 0x2B: Encapsulated Interface Transport

#### New Classes and Data Structures

**ModbusPacket Class:**
```python
@dataclass
class ModbusPacket:
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int
    function_code: int
    data: bytes
    
    # Methods:
    - to_tcp_bytes() -> bytes
    - to_rtu_bytes() -> bytes
    - to_ascii_bytes() -> bytes
    - validate_tcp_packet(data) -> Tuple[bool, Optional[str]]
    - validate_rtu_packet(data) -> Tuple[bool, Optional[str]]
```

**Enumerations:**
- `ModbusFunctionCode`: All standard Modbus function codes
- `ModbusExceptionCode`: Exception response codes (0x01-0x0B)
- `ModbusTransportMode`: TCP, RTU, ASCII modes
- `ProtocolType`: Extended with MODBUS_RTU and MODBUS_ASCII

#### New Methods

**File Operations (Function Codes 0x14-0x17):**

1. **read_file_record(file_number, record_number, record_length)**
   - MITRE ATT&CK: T0801 (Monitor Process State), T0861 (Point & Tag Identification)
   - Reads data from PLC file memory
   - Supports sub-requests with reference type 0x06

2. **write_file_record(file_number, record_number, data)**
   - MITRE ATT&CK: T0836 (Modify Parameter), T0873 (Project File Infection)
   - Writes data to PLC file memory
   - Validates word-aligned data (even byte length)
   - Maximum 245 bytes per request

3. **mask_write_register(address, and_mask, or_mask)**
   - MITRE ATT&CK: T0836 (Modify Parameter)
   - Atomic bit manipulation using AND/OR masks
   - Result = (CurrentValue AND and_mask) OR (or_mask AND (NOT and_mask))

4. **read_write_multiple_registers(read_address, read_count, write_address, write_values)**
   - MITRE ATT&CK: T0855 (Unauthorized Command Message)
   - Atomic read and write in single transaction
   - Maximum 125 read registers, 121 write registers

#### Serial Communication Support

```python
IndustrialProtocolAttacker(
    transport_mode=ModbusTransportMode.RTU,
    serial_port='/dev/ttyUSB0',  # or 'COM3' on Windows
    serial_config={
        'baudrate': 9600,
        'bytesize': 8,
        'parity': 'N',
        'stopbits': 1,
        'timeout': 1.0
    }
)
```

**Features:**
- Automatic CRC-16 calculation for RTU frames
- Automatic LRC calculation for ASCII frames
- Proper frame validation on receive
- Serial port lifecycle management

#### Packet Validation

**TCP Validation:**
- MBAP header structure verification
- Protocol ID validation (must be 0x0000)
- Length field consistency check
- Function code range validation

**RTU Validation:**
- CRC-16 checksum verification
- Minimum frame length check
- Proper error reporting

**ASCII Validation:**
- LRC checksum calculation
- Colon prefix and CRLF suffix validation
- Hex string parsing

#### MITRE ATT&CK Mapping

Enhanced SecurityEvent class with comprehensive MITRE mapping:

| Technique | Tactic | Description |
|-----------|--------|-------------|
| T0801 | Discovery | Monitor Process State |
| T0836 | Impair Process Control | Modify Parameter |
| T0855 | Execution | Unauthorized Command Message |
| T0861 | Collection | Point & Tag Identification |
| T0873 | Lateral Movement | Project File Infection |

#### Type Safety

Added complete type hints throughout:
- Function signatures with `->` return type annotations
- Optional[] for nullable values
- List[], Dict[], Tuple[] for collections
- Union[] for multiple valid types

#### Documentation

- Comprehensive docstrings for all new methods
- Parameter descriptions with valid ranges
- Return value documentation
- MITRE ATT&CK references in method docstrings
- Example usage in TESTING.md

### Testing

Created comprehensive testing guide (TESTING.md) covering:
- Packet structure validation tests
- Function code coverage tests (all 0x01-0x18)
- Transport mode tests (TCP/RTU/ASCII)
- MITRE mapping verification
- Wireshark packet capture validation
- Error handling tests
- Performance benchmarks
- Security testing (dry-run, event logging)

### Performance Improvements

- Batch register scanning with configurable batch size
- Optimized serial communication with proper timeouts
- Efficient packet construction using struct.pack
- Connection reuse in async methods

### Breaking Changes

None - all existing functionality maintained, only additions.

### Dependencies

**New:**
- `pyserial` - for RTU/ASCII serial communication
- `struct` - for binary packet construction

**Updated:**
- `pymodbus >= 3.0` - recommended for full compatibility

### Files Modified

- `tools/modbus-stealth-toolkit/modbus_stealth_attack.py` - Enhanced to v3.0
  - Added ~500 lines of new code
  - Added 4 new major methods
  - Added 3 new classes/enums
  - Complete type annotations
  - Enhanced error handling

### Files Added

- `tools/modbus-stealth-toolkit/TESTING.md` - Comprehensive testing guide
- `tools/modbus-stealth-toolkit/CHANGELOG.md` - This file

### Migration Guide

Existing code remains fully compatible. To use new features:

**RTU Mode:**
```python
attacker = IndustrialProtocolAttacker(
    transport_mode=ModbusTransportMode.RTU,
    serial_port='/dev/ttyUSB0',
    serial_config={'baudrate': 9600}
)
```

**File Operations:**
```python
# Read PLC file
data = await attacker.read_file_record(file_number=1, record_number=0, record_length=10)

# Write PLC file
await attacker.write_file_record(file_number=1, record_number=0, data=b'\x12\x34\x56\x78')
```

**Mask Write:**
```python
# Set bits 0-3, clear bits 4-7
await attacker.mask_write_register(address=0, and_mask=0xFF0F, or_mask=0x000F)
```

### References

- Modbus Application Protocol Specification v1.1b3
- MITRE ATT&CK for ICS Framework
- CRC-16 (MODBUS) algorithm
- PyModbus 3.x Documentation

### Contributors

- Security audit and enhancements: 2026-01-11

## Version 2.1 - Previous

[Previous version documentation]
