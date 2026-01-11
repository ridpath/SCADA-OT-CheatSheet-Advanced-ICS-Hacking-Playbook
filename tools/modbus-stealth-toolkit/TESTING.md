# Modbus Protocol Implementation Testing Guide

## Overview
This document provides comprehensive testing procedures for the enhanced Modbus implementation in `modbus_stealth_attack.py` v3.0.

## Test Environment Setup

### Required Tools
- **modbus-simulator**: Open-source Modbus TCP/RTU simulator
- **Wireshark**: Network protocol analyzer for packet validation
- **pymodbus**: Python Modbus library (v3.0+)
- **Virtual serial ports**: For RTU/ASCII testing (e.g., `com0com` on Windows, `socat` on Linux)

### Installation

```bash
# Install dependencies
pip install pymodbus>=3.0 scapy pyserial

# Install modbus-simulator (Ubuntu/Debian)
sudo apt-get install modbus-simulator

# Or use Docker
docker run -d -p 502:502 oitc/modbus-server
```

## Test Categories

### 1. Packet Structure Validation Tests

#### Test 1.1: Modbus TCP Packet Validation
```python
from modbus_stealth_attack import ModbusPacket

# Valid TCP packet
packet = ModbusPacket(
    transaction_id=1,
    protocol_id=0,
    length=6,
    unit_id=1,
    function_code=0x03,
    data=b'\x00\x00\x00\x0A'
)

tcp_bytes = packet.to_tcp_bytes()
is_valid, error = ModbusPacket.validate_tcp_packet(tcp_bytes)
assert is_valid, f"Validation failed: {error}"

# Expected packet structure:
# [00 01] - Transaction ID (0x0001)
# [00 00] - Protocol ID (0x0000)
# [00 06] - Length (6 bytes following)
# [01] - Unit ID (0x01)
# [03] - Function Code (Read Holding Registers)
# [00 00 00 0A] - Data (start address 0, count 10)
```

#### Test 1.2: Modbus RTU CRC Validation
```python
# Valid RTU packet
packet = ModbusPacket(
    unit_id=1,
    function_code=0x03,
    data=b'\x00\x00\x00\x0A'
)

rtu_bytes = packet.to_rtu_bytes()
is_valid, error = ModbusPacket.validate_rtu_packet(rtu_bytes)
assert is_valid, f"CRC validation failed: {error}"

# Expected packet structure:
# [01] - Unit ID
# [03] - Function Code
# [00 00 00 0A] - Data
# [XX XX] - CRC-16 (calculated)
```

#### Test 1.3: Modbus ASCII LRC Validation
```python
# Valid ASCII packet
packet = ModbusPacket(
    unit_id=1,
    function_code=0x03,
    data=b'\x00\x00\x00\x0A'
)

ascii_bytes = packet.to_ascii_bytes()
# Expected format: :010300000A[LRC]\r\n
assert ascii_bytes.startswith(b':'), "ASCII packet must start with ':'"
assert ascii_bytes.endswith(b'\r\n'), "ASCII packet must end with CRLF"
```

### 2. Function Code Coverage Tests

#### Test 2.1: Read Coils (0x01)
```bash
# Start modbus-simulator
modbus-simulator --port 502 --unit-id 1

# Run test
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    coils = await attacker.read_coils(0, 10)
    print(f'Read coils: {coils}')
    assert len(coils) == 10, 'Should read 10 coils'

asyncio.run(test())
"
```

#### Test 2.2: Read Holding Registers (0x03)
```bash
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    registers = await attacker.read_holding_registers(0, 10)
    print(f'Read registers: {registers}')
    assert len(registers) == 10, 'Should read 10 registers'

asyncio.run(test())
"
```

#### Test 2.3: Write Single Coil (0x05)
```bash
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    result = await attacker.stealth_coil_write(0, True)
    assert result, 'Coil write should succeed'

asyncio.run(test())
"
```

#### Test 2.4: Write Single Register (0x06)
```bash
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    result = await attacker.stealth_register_write(0, 1234)
    assert result, 'Register write should succeed'

asyncio.run(test())
"
```

#### Test 2.5: Read File Record (0x14)
```bash
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    data = await attacker.read_file_record(
        file_number=1,
        record_number=0,
        record_length=10
    )
    print(f'Read file data: {data.hex() if data else None}')

asyncio.run(test())
"
```

#### Test 2.6: Write File Record (0x15)
```bash
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    # Data must be even length (word-aligned)
    test_data = b'\\x12\\x34\\x56\\x78\\xAB\\xCD\\xEF\\x00'
    result = await attacker.write_file_record(
        file_number=1,
        record_number=0,
        data=test_data
    )
    assert result, 'File write should succeed'

asyncio.run(test())
"
```

#### Test 2.7: Mask Write Register (0x16)
```bash
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    # Set bits 0-3, clear bits 4-7, leave others unchanged
    result = await attacker.mask_write_register(
        address=0,
        and_mask=0xFF0F,  # Keep all bits except 4-7
        or_mask=0x000F    # Set bits 0-3
    )
    assert result, 'Mask write should succeed'

asyncio.run(test())
"
```

#### Test 2.8: Read/Write Multiple Registers (0x17)
```bash
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    registers = await attacker.read_write_multiple_registers(
        read_address=0,
        read_count=10,
        write_address=50,
        write_values=[100, 200, 300, 400, 500]
    )
    print(f'Read registers: {registers}')
    assert len(registers) == 10, 'Should read 10 registers'

asyncio.run(test())
"
```

### 3. Transport Mode Tests

#### Test 3.1: Modbus TCP Transport
```python
from modbus_stealth_attack import IndustrialProtocolAttacker, ModbusTransportMode

async def test_tcp():
    attacker = IndustrialProtocolAttacker(
        target_ip='127.0.0.1',
        port=502,
        transport_mode=ModbusTransportMode.TCP
    )
    registers = await attacker.read_holding_registers(0, 5)
    print(f"TCP mode: {registers}")

asyncio.run(test_tcp())
```

#### Test 3.2: Modbus RTU Transport
```python
# Requires serial port setup
from modbus_stealth_attack import IndustrialProtocolAttacker, ModbusTransportMode, ProtocolType

async def test_rtu():
    attacker = IndustrialProtocolAttacker(
        target_ip=None,
        protocol=ProtocolType.MODBUS_RTU,
        transport_mode=ModbusTransportMode.RTU,
        serial_port='/dev/ttyUSB0',  # Linux
        # serial_port='COM3',  # Windows
        serial_config={
            'baudrate': 9600,
            'bytesize': 8,
            'parity': 'N',
            'stopbits': 1,
            'timeout': 1.0
        }
    )
    registers = await attacker.read_holding_registers(0, 5)
    print(f"RTU mode: {registers}")
    attacker.close_serial_connection()

asyncio.run(test_rtu())
```

### 4. MITRE ATT&CK Mapping Verification

| Function Code | Method | MITRE Technique | Tactic | Verified |
|--------------|--------|-----------------|---------|----------|
| 0x01 | read_coils | T0801 | Discovery | ✓ |
| 0x02 | read_discrete_inputs | T0801 | Discovery | ✓ |
| 0x03 | read_holding_registers | T0801 | Discovery | ✓ |
| 0x04 | read_input_registers | T0801 | Discovery | ✓ |
| 0x05 | stealth_coil_write | T0836 | Impact | ✓ |
| 0x06 | stealth_register_write | T0836 | Impair Process Control | ✓ |
| 0x0F | write_multiple_coils | T0836 | Impair Process Control | ✓ |
| 0x10 | write_multiple_registers | T0836 | Impair Process Control | ✓ |
| 0x14 | read_file_record | T0801, T0861 | Collection | ✓ |
| 0x15 | write_file_record | T0836, T0873 | Impair Process Control | ✓ |
| 0x16 | mask_write_register | T0836 | Impair Process Control | ✓ |
| 0x17 | read_write_multiple_registers | T0855 | Execution | ✓ |

**MITRE Technique Definitions:**
- **T0801**: Monitor Process State - Adversary monitors industrial process state/values
- **T0836**: Modify Parameter - Adversary modifies parameters to cause disruption
- **T0855**: Unauthorized Command Message - Adversary issues unauthorized commands
- **T0861**: Point & Tag Identification - Adversary identifies process measurement points
- **T0873**: Project File Infection - Adversary modifies PLC project files

### 5. Wireshark Packet Capture Validation

#### Capture Modbus TCP Traffic
```bash
# Start Wireshark capture on loopback
wireshark -i lo -f "tcp port 502" &

# Generate test traffic
python -c "
import asyncio
from modbus_stealth_attack import IndustrialProtocolAttacker

async def test():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    await attacker.read_holding_registers(0, 10)
    await attacker.stealth_register_write(0, 1234)

asyncio.run(test())
"
```

#### Expected Wireshark Filters
- `modbus` - All Modbus traffic
- `modbus.func_code == 3` - Read Holding Registers
- `modbus.func_code == 6` - Write Single Register
- `modbus.func_code == 20` - Read File Record (0x14)
- `modbus.func_code == 21` - Write File Record (0x15)

### 6. Error Handling Tests

#### Test 6.1: Invalid Address
```python
async def test_invalid_address():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    registers = await attacker.read_holding_registers(65535, 10)
    # Should handle gracefully, return empty list or log error
    assert isinstance(registers, list)

asyncio.run(test_invalid_address())
```

#### Test 6.2: Connection Timeout
```python
async def test_timeout():
    # Non-existent IP
    attacker = IndustrialProtocolAttacker('192.0.2.1', 502)
    registers = await attacker.read_holding_registers(0, 10)
    # Should timeout gracefully and return empty list
    assert registers == []

asyncio.run(test_timeout())
```

#### Test 6.3: Invalid Function Code Response
```python
async def test_invalid_function():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    # Try to write to read-only address (should get exception response)
    result = await attacker.stealth_register_write(30001, 1234, holding=False)
    # Should handle exception response gracefully
    assert isinstance(result, bool)

asyncio.run(test_invalid_function())
```

### 7. Performance Tests

#### Test 7.1: Batch Operations
```python
import time

async def test_batch_performance():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    
    start = time.time()
    for i in range(100):
        await attacker.read_holding_registers(i, 10)
    duration = time.time() - start
    
    print(f"100 reads took {duration:.2f}s ({100/duration:.2f} req/s)")
    assert duration < 10, "Should complete 100 reads in under 10 seconds"

asyncio.run(test_batch_performance())
```

### 8. Security Testing

#### Test 8.1: Dry Run Mode
```python
async def test_dry_run():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    attacker.dry_run = True
    
    # Should not send actual packets
    result = await attacker.stealth_coil_write(0, True)
    assert result == True, "Dry run should succeed without sending packets"

asyncio.run(test_dry_run())
```

#### Test 8.2: Event Logging
```python
async def test_event_logging():
    attacker = IndustrialProtocolAttacker('127.0.0.1', 502)
    attacker.json_log_file = "test_events.jsonl"
    
    await attacker.read_holding_registers(0, 10)
    
    # Verify log file created
    import os
    assert os.path.exists("test_events.jsonl")
    
    # Verify log format
    import base64, json
    with open("test_events.jsonl") as f:
        line = f.readline().strip()
        decoded = base64.b64decode(line)
        event = json.loads(decoded)
        assert event['mitre_technique'] == 'T0801'

asyncio.run(test_event_logging())
```

## Test Execution Checklist

- [ ] All function codes (0x01-0x18) tested
- [ ] TCP transport mode validated
- [ ] RTU transport mode validated with serial ports
- [ ] ASCII transport mode validated
- [ ] Packet structure validation confirmed
- [ ] CRC-16 calculation correct for RTU
- [ ] LRC calculation correct for ASCII
- [ ] MITRE ATT&CK mappings verified
- [ ] Wireshark captures analyzed
- [ ] Error handling tested for all edge cases
- [ ] Performance benchmarks meet requirements
- [ ] Security features (dry-run, logging) validated
- [ ] Type hints verified with mypy
- [ ] Documentation complete and accurate

## Test Results Template

```markdown
## Test Session: [Date]
**Tester**: [Name]
**Environment**: [OS, Python version, dependencies]

### Results
- Total tests: X
- Passed: Y
- Failed: Z
- Skipped: W

### Failed Tests
1. [Test name]: [Reason]
2. [Test name]: [Reason]

### Notes
[Additional observations]
```

## References
- Modbus Application Protocol Specification v1.1b3: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
- MITRE ATT&CK for ICS: https://attack.mitre.org/techniques/ics/
- PyModbus Documentation: https://pymodbus.readthedocs.io/
