# OPC-UA Security Assessment Framework

Comprehensive security assessment toolkit for OPC Unified Architecture (OPC-UA) implementations in industrial control systems.

## Features

- **Endpoint Discovery**: Enumerate available OPC-UA endpoints and security configurations
- **Node Enumeration**: Recursively discover server address space and identify writable variables
- **Certificate Bypass Testing**: Test certificate validation bypass techniques
- **Subscription Manipulation**: Create and manipulate subscriptions with aggressive parameters
- **Session Hijacking**: Test session token reuse and hijacking vulnerabilities
- **Protocol Fuzzing**: Fuzz node write operations with malformed data
- **Security Assessment**: Evaluate server security posture and configuration
- **MITRE ATT&CK Mapping**: All techniques mapped to ICS-specific tactics

## Installation

```bash
cd tools/opcua_security_framework
pip install -r requirements.txt
```

## Dependencies

- `asyncua>=1.0.0` - Async OPC-UA client library
- `cryptography>=41.0.0` - Certificate generation and cryptographic operations
- `tqdm>=4.65.0` - Progress bars (optional)

## Usage

### Basic Endpoint Discovery

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 --discover-endpoints
```

### Node Enumeration

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 --enumerate-nodes --max-nodes 5000
```

### Certificate Bypass Testing

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 --test-cert-bypass
```

### Authenticated Assessment

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 \
  -u admin -p password123 \
  --enumerate-nodes \
  --assess-security
```

### Full Security Assessment

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 \
  --full-assessment \
  -o assessment_results.json \
  -v
```

### Subscription Creation

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 \
  -u admin -p password \
  --create-subscription "ns=2;i=1" "ns=2;i=2" "ns=2;i=3"
```

### Node Fuzzing

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 \
  -u admin -p password \
  --fuzz-node "ns=2;i=1" \
  --fuzz-iterations 1000
```

### Session Hijacking Test

```bash
python opcua_exploit.py -t opc.tcp://192.168.1.100:4840 \
  -u admin -p password \
  --test-session-hijack
```

## MITRE ATT&CK for ICS Mapping

| Technique ID | Technique Name | Implementation |
|--------------|----------------|----------------|
| T0801 | Monitor Process State | Subscription creation, node enumeration |
| T0819 | Exploit Public-Facing Application | Certificate bypass, session hijacking |
| T0855 | Unauthorized Command Message | Node write fuzzing, subscription manipulation |
| T0861 | Point & Tag Identification | Node enumeration, address space discovery |
| T0868 | Detect Operating Mode | Server information discovery |
| T0877 | I/O Module Discovery | Node class enumeration |
| T0888 | Remote System Information Discovery | Endpoint discovery, security assessment |

## Security Techniques Implemented

### 1. Endpoint Discovery (T0888)
- Enumerate all available endpoints
- Identify security policies and modes
- Extract user authentication token types
- Retrieve server certificates

### 2. Node Enumeration (T0801, T0861)
- Recursive address space browsing
- Variable data type identification
- Access level assessment
- Writable node identification

### 3. Certificate Validation Bypass (T0819)
- Self-signed certificate acceptance testing
- No certificate connection attempts
- Expired certificate testing
- Invalid CN bypass attempts

### 4. Subscription Manipulation (T0801, T0855)
- Aggressive publishing intervals
- Mass monitored item creation
- Subscription resource exhaustion
- Data change monitoring

### 5. Session Hijacking (T0819)
- Authentication token extraction
- Token reuse testing
- Session state analysis
- Unauthorized access attempts

### 6. Protocol Fuzzing (T0855)
- Malformed data injection
- Type confusion attacks
- Boundary value testing
- Error handling analysis

## Output Format

Results are exported in JSON format containing:

```json
{
  "target": "opc.tcp://192.168.1.100:4840",
  "assessment_time": "2024-01-15T10:30:00",
  "endpoints": [...],
  "nodes_discovered": [...],
  "events": [
    {
      "timestamp": "2024-01-15T10:30:05",
      "technique": "OPC-UA Node Enumeration",
      "mitre_id": "T0861",
      "success": true,
      "severity": "MEDIUM",
      "details": {...}
    }
  ]
}
```

## Testing Targets

Recommended OPC-UA servers for testing:

- **FreeOpcUa Python Server**: `pip install freeopcua`
- **Prosys OPC-UA Simulation Server**: https://www.prosysopc.com/products/opc-ua-simulation-server/
- **Unified Automation UaExpert**: https://www.unified-automation.com/products/development-tools/uaexpert.html
- **Open62541**: https://www.open62541.org/

## Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for legitimate security research and authorized penetration testing of OPC-UA implementations. Usage requires explicit written permission from system owners. Unauthorized access to industrial control systems is illegal and may result in criminal prosecution.

## References

- OPC Unified Architecture Specification: https://opcfoundation.org/developer-tools/specifications-unified-architecture
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- ICS-CERT: https://www.cisa.gov/ics

## Author

Ridpath - Industrial Control Systems Security Research

## Version

1.0 - Initial release with comprehensive OPC-UA assessment capabilities
