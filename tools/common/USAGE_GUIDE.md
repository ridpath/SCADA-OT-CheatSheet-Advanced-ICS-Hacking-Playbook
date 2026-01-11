# ICS Security Tools - Standardized Interface Usage Guide

Complete guide for using the standardized interface across all ICS security assessment tools.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Configuration Management](#configuration-management)
4. [Dry-Run Mode](#dry-run-mode)
5. [Safety Validation](#safety-validation)
6. [Result Export](#result-export)
7. [Protocol-Specific Usage](#protocol-specific-usage)
8. [Advanced Features](#advanced-features)
9. [Best Practices](#best-practices)

---

## Overview

The standardized interface provides:

- **Unified API**: Common interface across all protocols (Modbus, S7Comm, CIP, OPC-UA, PROFINET, BACnet)
- **Configuration Files**: YAML/JSON configuration support
- **Dry-Run Mode**: Test operations without execution
- **Safety Checks**: Built-in validation to prevent accidents
- **Multi-Format Export**: JSON, XML, CSV, HTML, TXT reports
- **Event Tracking**: Automatic MITRE ATT&CK mapping
- **Standardized Logging**: Consistent logging across tools

---

## Quick Start

### Installation

Ensure Python dependencies are installed:

```bash
pip install pyyaml pymodbus scapy opcua
```

### Basic Usage

#### Unified CLI

```bash
# Modbus assessment
python tools/common/ics_tool_cli.py modbus --target 192.168.1.100 --operation enumerate

# S7Comm assessment with dry-run
python tools/common/ics_tool_cli.py s7comm --target 192.168.1.101 --dry-run

# OPC-UA with export
python tools/common/ics_tool_cli.py opcua --endpoint opc.tcp://192.168.1.102:4840 --export report.json
```

#### Programmatic Usage

```python
from tools.common.tool_adapters import ModbusToolAdapter

# Initialize tool
tool = ModbusToolAdapter(
    target_ip="192.168.1.100",
    port=502,
    dry_run=True
)

# Run assessment
tool.run_assessment(operation='enumerate')

# Export results
tool.export_results("report.json", format="json")
```

---

## Configuration Management

### Configuration Files

Create `my_assessment.yaml`:

```yaml
# Global settings
dry_run: false
timeout: 5
max_retries: 3
log_level: INFO

# Safety checks
safety_checks:
  rate_limit: true
  validate_targets: true
  confirm_destructive: true

# Target configuration
targets:
  - ip: "192.168.1.100"
    port: 502
    protocol: "modbus"
  
  - ip: "192.168.1.101"
    port: 102
    protocol: "s7comm"

# Assessment scope
scope:
  enumerate: true
  exploit: false
  fuzz: false

# Export settings
export:
  enabled: true
  format: "json"
  output_dir: "./reports"

# Rate limiting
rate_limits:
  default: 10
  enumerate: 5
  fuzz: 1
```

### Loading Configuration

#### Via CLI

```bash
python ics_tool_cli.py modbus --target 192.168.1.100 --config my_assessment.yaml
```

#### Via API

```python
tool = ModbusToolAdapter(
    target_ip="192.168.1.100",
    config_file="my_assessment.yaml"
)
```

### JSON Configuration

Alternatively, use JSON format:

```json
{
  "dry_run": false,
  "timeout": 5,
  "safety_checks": {
    "rate_limit": true,
    "validate_targets": true
  }
}
```

---

## Dry-Run Mode

Dry-run mode simulates operations without executing them. Perfect for:
- Testing configuration
- Training exercises
- Demonstration purposes

### Enable Dry-Run

#### Via CLI

```bash
python ics_tool_cli.py modbus --target 192.168.1.100 --dry-run
```

#### Via API

```python
tool = ModbusToolAdapter(
    target_ip="192.168.1.100",
    dry_run=True
)
```

#### Via Configuration

```yaml
dry_run: true
```

### Dry-Run Behavior

```python
tool = ModbusToolAdapter(target_ip="192.168.1.100", dry_run=True)

# This will log the operation but NOT execute it
tool.run_assessment(operation='write_register', address=100, value=1234)
# Output: "DRY-RUN: Would write 1234 to register 100"
```

---

## Safety Validation

Built-in safety checks prevent accidental damage.

### Safety Check Types

1. **Target Validation**: Validates IP addresses/hostnames
2. **Rate Limiting**: Prevents DoS scenarios
3. **Destructive Operation Confirmation**: Prompts before dangerous operations

### Using Safety Checks

```python
tool = CIPToolAdapter(target_ip="192.168.1.102")

# Automatic validation before operations
if tool.validate_safety("target_validation", target="192.168.1.102"):
    # Proceed with operation
    pass

# Rate limit check
if tool.validate_safety("network_request", rate=15):
    # Within limits
    pass

# Destructive operation (prompts user)
if tool.validate_safety("destructive", description="Factory reset"):
    # User confirmed
    pass
```

### Configuring Safety Checks

```yaml
safety_checks:
  rate_limit: true          # Enable rate limiting
  validate_targets: true    # Validate targets
  confirm_destructive: true # Confirm dangerous ops
```

Disable for automated testing:

```yaml
safety_checks:
  confirm_destructive: false  # No prompts
```

---

## Result Export

Export assessment results in multiple formats.

### Supported Formats

- **JSON**: Structured data for automation
- **XML**: Enterprise integration
- **CSV**: Spreadsheet analysis
- **HTML**: Human-readable reports
- **TXT**: Plain text logs

### Export Examples

#### JSON Export

```bash
python ics_tool_cli.py modbus --target 192.168.1.100 \
  --export report.json --format json
```

```python
tool.export_results("report.json", format="json")
```

Example output:

```json
{
  "tool": "Modbus Stealth Attack Toolkit",
  "version": "3.0",
  "protocol": "Modbus",
  "timestamp": "2024-01-15T10:30:00Z",
  "dry_run": false,
  "events": [
    {
      "timestamp": "2024-01-15T10:30:05Z",
      "event_type": "enumeration",
      "severity": "INFO",
      "description": "Device enumeration",
      "target": "192.168.1.100:502",
      "protocol": "Modbus",
      "technique_id": "T0888"
    }
  ],
  "summary": {
    "total_events": 1,
    "by_severity": {"INFO": 1},
    "by_type": {"enumeration": 1}
  }
}
```

#### HTML Report

```bash
python ics_tool_cli.py s7comm --target 192.168.1.101 \
  --export report.html --format html
```

Generates professional HTML report with:
- Metadata table
- Event timeline
- Color-coded severity
- MITRE technique links

#### CSV Export

```bash
python ics_tool_cli.py cip --target 192.168.1.102 \
  --export report.csv --format csv
```

Suitable for Excel/spreadsheet analysis.

#### Multiple Formats

```python
tool = OPCUAToolAdapter(endpoint_url="opc.tcp://192.168.1.103:4840")
tool.run_assessment(operation='enumerate_nodes')

# Export in all formats
tool.export_results("report.json", format="json")
tool.export_results("report.xml", format="xml")
tool.export_results("report.csv", format="csv")
tool.export_results("report.html", format="html")
tool.export_results("report.txt", format="txt")
```

---

## Protocol-Specific Usage

### Modbus

```bash
# Enumerate device
python ics_tool_cli.py modbus --target 192.168.1.100 --operation enumerate

# Read registers
python ics_tool_cli.py modbus --target 192.168.1.100 \
  --operation read_registers --start-address 0 --count 10

# Write register (requires confirmation)
python ics_tool_cli.py modbus --target 192.168.1.100 \
  --operation write_register --address 100 --value 1234
```

Programmatic:

```python
from tools.common.tool_adapters import ModbusToolAdapter

tool = ModbusToolAdapter(target_ip="192.168.1.100", port=502)
tool.run_assessment(operation='read_registers', start_address=0, count=10)
tool.export_results("modbus_report.json")
```

### S7Comm

```bash
# Enumerate PLC
python ics_tool_cli.py s7comm --target 192.168.1.101 --operation enumerate

# Extract symbols
python ics_tool_cli.py s7comm --target 192.168.1.101 \
  --rack 0 --slot 2 --operation extract_symbols
```

Programmatic:

```python
from tools.common.tool_adapters import S7CommToolAdapter

tool = S7CommToolAdapter(
    target_ip="192.168.1.101",
    port=102,
    rack=0,
    slot=2
)
tool.run_assessment(operation='extract_symbols')
tool.export_results("s7comm_report.json")
```

### CIP/EtherNet/IP

```bash
# Enumerate objects
python ics_tool_cli.py cip --target 192.168.1.102 \
  --operation enumerate_objects

# Assess CIP Security
python ics_tool_cli.py cip --target 192.168.1.102 \
  --operation cip_security_assess
```

Programmatic:

```python
from tools.common.tool_adapters import CIPToolAdapter

tool = CIPToolAdapter(target_ip="192.168.1.102", port=44818)
tool.run_assessment(operation='enumerate_objects')
tool.export_results("cip_report.json")
```

### OPC-UA

```bash
# Discover endpoints
python ics_tool_cli.py opcua \
  --endpoint opc.tcp://192.168.1.103:4840 \
  --operation discover_endpoints

# Enumerate nodes
python ics_tool_cli.py opcua \
  --endpoint opc.tcp://192.168.1.103:4840 \
  --operation enumerate_nodes
```

Programmatic:

```python
from tools.common.tool_adapters import OPCUAToolAdapter

tool = OPCUAToolAdapter(endpoint_url="opc.tcp://192.168.1.103:4840")
tool.run_assessment(operation='enumerate_nodes')
tool.export_results("opcua_report.json")
```

### PROFINET

```bash
# Discover devices
python ics_tool_cli.py profinet --interface eth0 --operation discover

# Monitor RT traffic
python ics_tool_cli.py profinet --interface eth0 --operation monitor_rt
```

Programmatic:

```python
from tools.common.tool_adapters import PROFINETToolAdapter

tool = PROFINETToolAdapter(interface="eth0")
tool.run_assessment(operation='discover')
tool.export_results("profinet_report.json")
```

### BACnet

```bash
# Discover devices
python ics_tool_cli.py bacnet --operation discover

# Enumerate objects on specific device
python ics_tool_cli.py bacnet --target 192.168.1.105 --operation enumerate
```

Programmatic:

```python
from tools.common.tool_adapters import BACnetToolAdapter

tool = BACnetToolAdapter(target_ip="192.168.1.105", port=47808)
tool.run_assessment(operation='enumerate')
tool.export_results("bacnet_report.json")
```

---

## Advanced Features

### Event Logging with MITRE Mapping

```python
tool.log_event(
    event_type="write_operation",
    severity="HIGH",
    description="Unauthorized write to register 100",
    target="192.168.1.100:502",
    technique_id="T0855",  # Unauthorized Command Message
    source="attacker.local",
    register=100,
    value=1234
)
```

### Custom Safety Checks

```python
from tools.common.ics_security_tool import SafetyCheck

tool = ModbusToolAdapter(target_ip="192.168.1.100")

# Add custom safety check
custom_check = SafetyCheck(
    name="business_hours",
    description="Only allow operations during business hours",
    enabled=True,
    action="block"
)
tool.safety_checks.append(custom_check)
```

### Assessment Summary

```python
tool = S7CommToolAdapter(target_ip="192.168.1.101")
tool.run_assessment(operation='enumerate')

summary = tool.get_summary()
print(f"Total events: {summary['total_events']}")
print(f"By severity: {summary['by_severity']}")
print(f"By type: {summary['by_type']}")
```

---

## Best Practices

### 1. Always Use Dry-Run First

```bash
# Test with dry-run
python ics_tool_cli.py modbus --target 192.168.1.100 --dry-run

# Then run actual assessment
python ics_tool_cli.py modbus --target 192.168.1.100
```

### 2. Use Configuration Files

Store settings in config files instead of command-line arguments:

```yaml
# production_assessment.yaml
dry_run: false
safety_checks:
  confirm_destructive: true
rate_limits:
  default: 5
```

### 3. Enable All Safety Checks

```yaml
safety_checks:
  rate_limit: true
  validate_targets: true
  confirm_destructive: true
```

### 4. Export Results for Audit

```python
# Always export for documentation
tool.export_results(f"assessment_{timestamp}.json")
```

### 5. Use Appropriate Log Levels

```python
# Development
tool = ModbusToolAdapter(target_ip="...", log_level="DEBUG")

# Production
tool = ModbusToolAdapter(target_ip="...", log_level="INFO")
```

### 6. Validate Configuration

```python
# Test configuration loading first
tool = ModbusToolAdapter(
    target_ip="192.168.1.100",
    config_file="my_config.yaml",
    dry_run=True
)

# Check loaded config
print(tool.config)
```

### 7. Handle Errors Gracefully

```python
try:
    tool = ModbusToolAdapter(target_ip="192.168.1.100")
    tool.run_assessment(operation='enumerate')
    tool.export_results("report.json")
except Exception as e:
    print(f"Assessment failed: {e}")
    # Handle error
```

---

## Testing

Run the test suite to verify functionality:

```bash
cd tools/common
python test_standardized_interface.py
```

Tests include:
- Configuration loading (YAML/JSON)
- Dry-run mode
- Safety validation
- Event logging
- Result export (all formats)
- All protocol adapters
- Complete workflow

---

## Troubleshooting

### Issue: Configuration file not loading

**Solution**: Check file path and format

```python
import os
print(os.path.exists("my_config.yaml"))  # Should be True
```

### Issue: Safety validation blocking operations

**Solution**: Disable specific checks or use dry-run

```yaml
safety_checks:
  confirm_destructive: false  # For automated testing
```

### Issue: Export fails

**Solution**: Check write permissions and directory exists

```python
from pathlib import Path
Path("./reports").mkdir(exist_ok=True)
tool.export_results("./reports/report.json")
```

---

## Reference

### Available Operations by Protocol

| Protocol | Operations |
|----------|-----------|
| **Modbus** | enumerate, read_registers, write_register, write_coil, read_file_record, write_file_record, fuzz |
| **S7Comm** | enumerate, read_db, write_db, extract_symbols, export_all_dbs, test_protection, s7plus_probe |
| **CIP** | enumerate_objects, cip_security_assess, fuzz_class, safety_io_exploit, implicit_msg, reset_plc |
| **OPC-UA** | discover_endpoints, enumerate_nodes, test_certificate_bypass, create_subscription, fuzz_node_write |
| **PROFINET** | discover, set_name, set_ip, factory_reset, inject_rt, spoof_alarm, monitor_rt, firmware_mode, fuzz_dcp |
| **BACnet** | discover, enumerate, write_property, priority_array, comm_control, reinitialize, subscribe_cov |

### Severity Levels

- `CRITICAL`: Critical security event requiring immediate attention
- `HIGH`: High severity event with significant impact
- `MEDIUM`: Medium severity event
- `LOW`: Low severity informational event
- `INFO`: Informational event

### MITRE ATT&CK Techniques

Events are automatically mapped to relevant techniques:

- **T0801**: Monitor Process State
- **T0855**: Unauthorized Command Message
- **T0836**: Modify Parameter
- **T0819**: Exploit Public-Facing Application
- **T0861**: Point & Tag Identification
- **T0888**: Remote System Discovery

---

## Support

For issues or questions:

1. Check this usage guide
2. Review example configurations in `tools/common/`
3. Run test suite: `python test_standardized_interface.py`
4. Check protocol-specific documentation in `tools/*/TESTING.md`

---

## Security Notice

**FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.**

Use only on systems you own or have explicit written permission to test.

Unauthorized access to industrial control systems is illegal and dangerous.
