# ICS Security Tool Base Class

Standardized base class for all ICS security assessment tools providing common functionality including configuration management, dry-run mode, result export, and safety validation.

## Features

- **Configuration Management**: Load settings from YAML or JSON files
- **Dry-Run Mode**: Test tool behavior without executing operations
- **Result Export**: Export assessment results in multiple formats (JSON, XML, CSV, HTML, TXT)
- **Safety Validation**: Built-in safety checks to prevent accidental damage
- **Standardized Logging**: Consistent logging across all tools
- **Event Tracking**: Automatic tracking and categorization of security events

## Usage

### Creating a New Tool

Inherit from `ICSSecurityTool` and implement required abstract methods:

```python
from tools.common import ICSSecurityTool

class MyProtocolTool(ICSSecurityTool):
    def __init__(self, target: str, port: int, **kwargs):
        super().__init__(
            name="MyProtocol Security Tool",
            version="1.0",
            protocol="MyProtocol",
            **kwargs
        )
        self.target = target
        self.port = port
    
    def run_assessment(self, **kwargs) -> None:
        """Run security assessment"""
        self.logger.info(f"Starting assessment on {self.target}:{self.port}")
        
        # Validate safety before operation
        if not self.validate_safety("target_validation", target=self.target):
            return
        
        # Log security event
        self.log_event(
            event_type="enumeration",
            severity="INFO",
            description="Device discovery",
            target=self.target,
            technique_id="T0801"
        )
        
        # Perform assessment operations
        if not self.dry_run:
            # Actual network operations
            pass
        else:
            self.logger.info("DRY-RUN: Would perform enumeration")
    
    def get_available_operations(self) -> List[str]:
        """Get available operations"""
        return ["enumerate", "exploit", "fuzz"]
```

### Using Configuration Files

Create a YAML or JSON configuration file:

```yaml
# my_config.yaml
dry_run: false
timeout: 5
log_level: INFO

safety_checks:
  rate_limit: true
  validate_targets: true
  confirm_destructive: true

targets:
  - ip: "192.168.1.100"
    port: 502
```

Load configuration:

```python
tool = MyProtocolTool(
    target="192.168.1.100",
    port=502,
    config_file="my_config.yaml"
)
```

### Dry-Run Mode

Enable dry-run mode to test without executing operations:

```python
tool = MyProtocolTool(
    target="192.168.1.100",
    port=502,
    dry_run=True
)
tool.run_assessment()
```

Or via configuration:

```yaml
dry_run: true
```

### Logging Events

Use the standardized event logging:

```python
self.log_event(
    event_type="write_operation",
    severity="HIGH",
    description="Unauthorized write to register 100",
    target="192.168.1.100",
    technique_id="T0855",
    source="attacker.local",
    register=100,
    value=1234
)
```

Severity levels:
- `CRITICAL`: Critical security event
- `HIGH`: High severity event
- `MEDIUM`: Medium severity event
- `LOW`: Low severity event
- `INFO`: Informational event

### Exporting Results

Export assessment results in multiple formats:

```python
# JSON export
tool.export_results("report.json", format="json")

# XML export
tool.export_results("report.xml", format="xml")

# CSV export
tool.export_results("report.csv", format="csv")

# HTML report
tool.export_results("report.html", format="html")

# Plain text
tool.export_results("report.txt", format="txt")
```

### Safety Validation

Built-in safety checks prevent accidental damage:

```python
# Validate before network operation
if self.validate_safety("network_request", rate=15):
    # Proceed with operation
    pass

# Validate target
if self.validate_safety("target_validation", target=self.target):
    # Proceed with targeting
    pass

# Confirm destructive operation
if self.validate_safety("destructive", description="Factory reset"):
    # User will be prompted for confirmation
    pass
```

Safety checks can be configured:

```yaml
safety_checks:
  rate_limit: true  # Limit request rate
  validate_targets: true  # Validate target IPs
  confirm_destructive: true  # Confirm destructive ops
```

### Getting Summary

Get assessment summary statistics:

```python
summary = tool.get_summary()
print(f"Total events: {summary['total_events']}")
print(f"By severity: {summary['by_severity']}")
print(f"By type: {summary['by_type']}")
```

## Configuration Reference

### Global Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `dry_run` | boolean | false | Enable dry-run mode |
| `timeout` | integer | 5 | Network timeout (seconds) |
| `max_retries` | integer | 3 | Maximum retry attempts |
| `log_level` | string | INFO | Logging level |

### Safety Checks

| Check | Type | Default | Description |
|-------|------|---------|-------------|
| `rate_limit` | boolean | true | Limit request rate |
| `validate_targets` | boolean | true | Validate target IPs |
| `confirm_destructive` | boolean | true | Confirm destructive ops |

### Export Settings

| Setting | Type | Description |
|---------|------|-------------|
| `format` | string | Export format: json, xml, csv, html, txt |
| `output_dir` | string | Output directory path |
| `filename_template` | string | Filename template with variables |

## Examples

See `example_config.yaml` and `example_config.json` for complete configuration examples.

## Integration with Existing Tools

All tools in this repository inherit from `ICSSecurityTool`:

- `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`
- `tools/s7comm_security_framework/s7comm_exploit.py`
- `tools/cip_security_assessment/cip_exploiter.py`
- `tools/opcua_security_framework/opcua_exploit.py`
- `tools/profinet_exploitation/profinet_exploit.py`
- `tools/bacnet_security_assessment/bacnet_assessment.py`

## API Reference

### ICSSecurityTool

Base class for ICS security tools.

#### Methods

##### `__init__(name, version, protocol, config_file=None, dry_run=False, log_level="INFO")`

Initialize the tool.

##### `load_config(config_file)`

Load configuration from YAML or JSON file.

##### `validate_safety(operation, **kwargs)`

Validate safety for an operation. Returns `True` if safe.

##### `log_event(event_type, severity, description, target, technique_id=None, source=None, **metadata)`

Log a security event.

##### `export_results(output_file, format="json")`

Export results to file in specified format.

##### `get_summary()`

Get assessment summary statistics.

##### `run_assessment(**kwargs)` (abstract)

Run security assessment. Must be implemented by subclass.

##### `get_available_operations()` (abstract)

Get list of available operations. Must be implemented by subclass.

## License

This base class is part of the ICS Security Assessment Toolkit and follows the same license terms.

## Security Notice

**FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.**

Use only on systems you own or have explicit written permission to test.
