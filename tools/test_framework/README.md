# ICS Security Toolkit Testing Framework

Comprehensive unit testing framework for ICS security assessment tools.

## Overview

This testing framework provides:
- Unit tests for all protocol implementations (Modbus, S7Comm, CIP, OPC-UA)
- Mock PLC servers for integration testing
- Coverage reporting (target: >70%)
- Continuous testing capabilities

## Installation

Install testing dependencies:

```bash
pip install -r requirements-test.txt
```

## Running Tests

### Run All Tests

```bash
pytest
```

### Run Specific Test File

```bash
pytest test_modbus.py
pytest test_s7comm.py
pytest test_cip.py
pytest test_opcua.py
```

### Run With Coverage Report

```bash
pytest --cov=. --cov-report=html
```

Coverage report will be generated in `htmlcov/index.html`

### Run Specific Test Class or Method

```bash
pytest test_modbus.py::TestModbusPacketStructure
pytest test_modbus.py::TestModbusPacketStructure::test_tcp_packet_creation
```

### Run Tests with Markers

```bash
pytest -m unit
pytest -m integration
pytest -m "not slow"
```

## Test Structure

### test_modbus.py
- Modbus packet structure validation (TCP/RTU/ASCII)
- Function code enumeration
- CRC/LRC calculation
- Mock server interactions
- Exception handling

### test_s7comm.py
- S7 packet structure (TPKT/COTP headers)
- Function code enumeration
- Packet serialization/deserialization
- Symbol table structure
- Mock server interactions

### test_cip.py
- CIP packet structure
- EtherNet/IP header encoding
- Service code enumeration
- Safety packet CRC calculation
- Mock server interactions

### test_opcua.py
- Security policy enumeration
- Message security modes
- Node class enumeration
- Endpoint and node structures
- Security event logging

## Mock Servers

### mock_plc_server.py

Multi-protocol mock PLC server for testing:
- **Modbus TCP**: Port 5020
- **S7Comm**: Port 1020
- **CIP/EtherNet/IP**: Port 44818
- **OPC-UA**: Port 4841 (requires asyncua)

### Running Mock Servers Standalone

```bash
python mock_plc_server.py --modbus-port 5020 --s7-port 1020 --cip-port 44818
```

## Coverage Requirements

Minimum coverage target: **70%**

Current coverage by module:
- Modbus: Protocol packet structures, function codes, server interactions
- S7Comm: Packet validation, serialization, COTP handling
- CIP: Packet structures, headers, safety packets
- OPC-UA: Security policies, node structures, events

## Writing New Tests

Follow pytest conventions:
1. Test files: `test_*.py`
2. Test classes: `Test*`
3. Test functions: `test_*`

Example:

```python
class TestNewFeature:
    def test_feature_creation(self):
        feature = NewFeature()
        assert feature is not None
        
    def test_feature_validation(self):
        feature = NewFeature(param=123)
        is_valid, error = feature.validate()
        assert is_valid is True
```

## Fixtures

Common fixtures available:
- `mock_modbus_server`: Modbus TCP mock server
- `mock_s7_server`: S7Comm mock server
- `mock_cip_server`: CIP/EtherNet/IP mock server

Usage:

```python
def test_with_mock_server(mock_modbus_server):
    # Server is automatically started/stopped
    # Connect and test
    pass
```

## Continuous Integration

Tests are designed to run in CI/CD pipelines:
- No external dependencies required
- Mock servers for all protocols
- Configurable timeouts
- Deterministic results

## Troubleshooting

### Tests Timeout
- Increase timeout in pytest.ini
- Check mock servers are starting correctly
- Verify no port conflicts

### Import Errors
- Ensure all dependencies installed: `pip install -r requirements-test.txt`
- Check Python path configuration
- Verify tool implementations are in correct directories

### Coverage Below Target
- Run: `pytest --cov=. --cov-report=term-missing`
- Identify uncovered lines
- Add tests for missing coverage

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Mock External Dependencies**: Use mock servers, not real PLCs
3. **Fast Execution**: Target <1 second per test
4. **Clear Assertions**: Use descriptive assertion messages
5. **Edge Cases**: Test boundary conditions and error handling

## References

- pytest documentation: https://docs.pytest.org/
- Coverage.py: https://coverage.readthedocs.io/
- Protocol specifications in `docs/protocol_quick_reference/`
