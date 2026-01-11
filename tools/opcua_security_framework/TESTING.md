# OPC-UA Security Framework Testing Guide

Comprehensive testing procedures for validating the OPC-UA Security Assessment Framework.

## Table of Contents

1. [Test Environment Setup](#test-environment-setup)
2. [Functional Testing](#functional-testing)
3. [Security Testing](#security-testing)
4. [Integration Testing](#integration-testing)
5. [Performance Testing](#performance-testing)
6. [Validation Checklist](#validation-checklist)

---

## Test Environment Setup

### Method 1: FreeOpcUa Python Server (Recommended for Quick Testing)

```bash
pip install freeopcua

cat > test_opcua_server.py << 'EOF'
from opcua import Server
import time

server = Server()
server.set_endpoint("opc.tcp://0.0.0.0:4840/freeopcua/server/")
server.set_server_name("Test OPC-UA Server")

uri = "http://test.opcua.server"
idx = server.register_namespace(uri)

objects = server.get_objects_node()

test_object = objects.add_object(idx, "TestObject")
test_var = test_object.add_variable(idx, "TestVariable", 0)
test_var.set_writable()

counter = test_object.add_variable(idx, "Counter", 0)
counter.set_writable()

temp = test_object.add_variable(idx, "Temperature", 25.5)
temp.set_writable()

pressure = test_object.add_variable(idx, "Pressure", 101.3)
pressure.set_writable()

server.start()
print("OPC-UA Server started at opc.tcp://0.0.0.0:4840/freeopcua/server/")

try:
    count = 0
    while True:
        time.sleep(1)
        count += 1
        counter.set_value(count)
except KeyboardInterrupt:
    server.stop()
EOF

python test_opcua_server.py
```

### Method 2: Prosys OPC-UA Simulation Server (Recommended for Full Testing)

1. Download from: https://www.prosysopc.com/products/opc-ua-simulation-server/
2. Install and launch
3. Configure endpoint: `opc.tcp://localhost:53530/OPCUA/SimulationServer`
4. Enable anonymous access for testing
5. Configure security policies (None, Basic256Sha256, etc.)

### Method 3: Open62541 Demo Server (Docker)

```bash
docker run -d --name opcua-server -p 4840:4840 open62541/open62541:latest

OPCUA_SERVER_URL="opc.tcp://localhost:4840"
```

### Method 4: Custom Test Server with Security Features

```python
from opcua import Server
from opcua.ua import SecurityPolicy, MessageSecurityMode
import os

server = Server()
server.set_endpoint("opc.tcp://0.0.0.0:4840/testserver/")

server.load_certificate("server_cert.pem")
server.load_private_key("server_key.pem")

server.set_security_policy([
    SecurityPolicy.Basic256Sha256,
    SecurityPolicy.Basic256,
    SecurityPolicy.NoSecurity
])

server.set_security_IDs(["Username", "Anonymous"])

uri = "http://secure.test.server"
idx = server.register_namespace(uri)

objects = server.get_objects_node()

secure_folder = objects.add_folder(idx, "SecureFolder")
sensitive_var = secure_folder.add_variable(idx, "SensitiveData", "SECRET")
sensitive_var.set_writable()

server.start()
print("Secure OPC-UA server started")
```

---

## Functional Testing

### Test Case 1: Endpoint Discovery

**Objective**: Verify endpoint enumeration functionality

**Command**:
```bash
python opcua_exploit.py -t opc.tcp://localhost:4840 --discover-endpoints -v
```

**Expected Results**:
- ✓ Discovers all available endpoints
- ✓ Identifies security policies (None, Basic256Sha256, etc.)
- ✓ Lists user identity token types
- ✓ Extracts server certificates (if available)
- ✓ Logs MITRE T0888 event

**Validation**:
```bash
grep "T0888" assessment_results.json
jq '.endpoints[] | {url, security_policy, security_mode}' results.json
```

**Pass Criteria**:
- At least 1 endpoint discovered
- Security policy correctly identified
- No exceptions raised

---

### Test Case 2: Node Enumeration

**Objective**: Validate recursive address space discovery

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --enumerate-nodes \
  --max-depth 10 \
  --max-nodes 5000 \
  -o nodes.json \
  -v
```

**Expected Results**:
- ✓ Discovers Objects, Variables, Methods, ObjectTypes
- ✓ Identifies writable variables
- ✓ Extracts data types and access levels
- ✓ Logs MITRE T0801 and T0861 events
- ✓ Respects max-depth and max-nodes limits

**Validation**:
```bash
jq '.nodes_discovered | length' nodes.json
jq '[.nodes_discovered[] | select(.writable == true)] | length' nodes.json
jq '[.nodes_discovered[] | select(.node_class == "VARIABLE")] | length' nodes.json
```

**Pass Criteria**:
- Minimum 10 nodes discovered
- Correct node class identification
- Writable variables accurately identified
- No infinite recursion

---

### Test Case 3: Certificate Bypass Testing

**Objective**: Test certificate validation weaknesses

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --test-cert-bypass \
  -v
```

**Expected Results**:
- ✓ Tests self-signed certificate acceptance
- ✓ Tests no-certificate connection
- ✓ Tests expired certificate (if applicable)
- ✓ Logs MITRE T0819 event with results
- ✓ Reports bypass success/failure for each test

**Validation**:
```bash
grep "self_signed_accepted" results.json
grep "no_cert_accepted" results.json
```

**Pass Criteria**:
- All bypass tests execute without crashes
- Results accurately reflect server behavior
- Event logged with severity HIGH

---

### Test Case 4: Subscription Creation

**Objective**: Validate subscription manipulation capabilities

**Setup**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840/freeopcua/server/ \
  --enumerate-nodes \
  -o nodes.json

WRITABLE_NODE=$(jq -r '.nodes_discovered[] | select(.writable == true) | .node_id' nodes.json | head -1)
```

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840/freeopcua/server/ \
  --create-subscription "$WRITABLE_NODE" \
  -v
```

**Expected Results**:
- ✓ Subscription created successfully
- ✓ Monitored items registered
- ✓ Publishing interval applied
- ✓ Logs MITRE T0801 event
- ✓ Subscription deleted cleanly

**Validation**:
```bash
grep "subscription_created.*true" results.json
grep "monitored_items" results.json
```

**Pass Criteria**:
- Subscription ID returned
- Monitored items count > 0
- No connection leaks

---

### Test Case 5: Node Write Fuzzing

**Objective**: Validate fuzzing capabilities and error handling

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840/freeopcua/server/ \
  --fuzz-node "ns=2;i=2" \
  --fuzz-iterations 500 \
  -v
```

**Expected Results**:
- ✓ Fuzzes with malformed data (None, overflow, NaN, etc.)
- ✓ Tracks successful vs. failed writes
- ✓ Captures exception types
- ✓ Logs MITRE T0855 event
- ✓ Does not crash on unexpected responses

**Validation**:
```bash
jq '.events[] | select(.technique == "OPC-UA Node Write Fuzzing")' results.json
jq '.events[] | select(.mitre_id == "T0855") | .details.successful_writes' results.json
```

**Pass Criteria**:
- Completes all iterations
- Error types captured
- Success rate calculated
- No unhandled exceptions

---

### Test Case 6: Session Hijacking Test

**Objective**: Verify session token extraction and reuse testing

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  -u admin -p password \
  --test-session-hijack \
  -v
```

**Expected Results**:
- ✓ Authentication token extracted
- ✓ Token reuse attempted
- ✓ Logs success/failure of reuse
- ✓ Logs MITRE T0819 event with CRITICAL severity
- ✓ Cleans up temporary connections

**Validation**:
```bash
jq '.events[] | select(.technique == "OPC-UA Session Hijacking Test")' results.json
jq '.events[] | select(.severity == "CRITICAL")' results.json
```

**Pass Criteria**:
- Token extraction succeeds (if authenticated)
- Reuse test completes
- Event severity marked CRITICAL
- No connection leaks

---

### Test Case 7: Security Configuration Assessment

**Objective**: Validate security posture evaluation

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --assess-security \
  -o security_assessment.json \
  -v
```

**Expected Results**:
- ✓ Identifies anonymous login availability
- ✓ Detects encryption requirements
- ✓ Lists weak security policies
- ✓ Lists strong security policies
- ✓ Enumerates user token types
- ✓ Logs MITRE T0888 event

**Validation**:
```bash
jq '.events[] | select(.technique == "OPC-UA Security Configuration Assessment")' security_assessment.json
jq '.events[].details.anonymous_login_enabled' security_assessment.json
jq '.events[].details.weak_policies_available' security_assessment.json
```

**Pass Criteria**:
- All security attributes evaluated
- Accurate weak vs. strong policy classification
- User token types enumerated

---

### Test Case 8: Full Assessment

**Objective**: Validate end-to-end assessment workflow

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --full-assessment \
  --max-nodes 2000 \
  --max-depth 8 \
  -o full_assessment.json \
  -v
```

**Expected Results**:
- ✓ Executes all assessment modules
- ✓ Endpoint discovery
- ✓ Security configuration assessment
- ✓ Certificate bypass testing
- ✓ Node enumeration
- ✓ Session hijacking test
- ✓ Comprehensive event logging
- ✓ JSON export with all results

**Validation**:
```bash
jq '.events | length' full_assessment.json
jq '[.events[] | .mitre_id] | unique' full_assessment.json
jq '.nodes_discovered | length' full_assessment.json
jq '.endpoints | length' full_assessment.json
```

**Pass Criteria**:
- Minimum 5 events logged
- All MITRE techniques represented
- Nodes and endpoints discovered
- Valid JSON output

---

## Security Testing

### Test Case 9: Anonymous Access Detection

**Objective**: Verify detection of anonymous access configurations

**Setup** (on test server):
```python
server.set_security_IDs(["Anonymous"])
```

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --assess-security \
  -v
```

**Expected Results**:
- ✓ Detects anonymous login enabled
- ✓ Reports in security assessment
- ✓ Flags as potential vulnerability

**Validation**:
```bash
jq '.events[].details.anonymous_login_enabled' results.json | grep true
```

---

### Test Case 10: Encrypted Connection Testing

**Objective**: Test secure channel establishment

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --security-policy Basic256Sha256 \
  --cert client_cert.pem \
  --key client_key.pem \
  --enumerate-nodes \
  -v
```

**Expected Results**:
- ✓ Secure channel established
- ✓ Certificate exchange successful
- ✓ Encrypted communication
- ✓ Node enumeration via encrypted channel

**Validation**:
```bash
grep "Security.*Basic256Sha256" results.json
```

---

## Integration Testing

### Test Case 11: Integration with Prosys Simulation Server

**Target**: Prosys OPC-UA Simulation Server

**Command**:
```bash
python opcua_exploit.py \
  -t opc.tcp://localhost:53530/OPCUA/SimulationServer \
  --full-assessment \
  -o prosys_test.json
```

**Expected Results**:
- ✓ Connects to Prosys server
- ✓ Enumerates simulation objects
- ✓ Identifies Counter, Sawtooth, Sinusoid variables
- ✓ Tests write operations on writable variables

**Validation**:
```bash
jq '.nodes_discovered[] | select(.browse_name | contains("Counter"))' prosys_test.json
jq '.nodes_discovered[] | select(.browse_name | contains("Sawtooth"))' prosys_test.json
```

---

### Test Case 12: Multi-Protocol Testing (OPC-UA + Modbus)

**Objective**: Validate coexistence with other ICS protocol testing

**Setup**:
```bash
python test_opcua_server.py &
OPCUA_PID=$!

python -m pymodbus.server.simulator --host 0.0.0.0 --port 5020 &
MODBUS_PID=$!
```

**Commands**:
```bash
python opcua_exploit.py -t opc.tcp://localhost:4840 --enumerate-nodes -o opcua_results.json
cd ../modbus-stealth-toolkit
python modbus_stealth_attack.py scan 127.0.0.1 -o modbus_results.json
```

**Expected Results**:
- ✓ Both tools run independently
- ✓ No port conflicts
- ✓ Results export correctly

**Cleanup**:
```bash
kill $OPCUA_PID $MODBUS_PID
```

---

## Performance Testing

### Test Case 13: Large Address Space Enumeration

**Objective**: Test performance with large node counts

**Setup**: Configure server with 10,000+ nodes

**Command**:
```bash
time python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --enumerate-nodes \
  --max-nodes 10000 \
  --max-depth 15 \
  -v
```

**Expected Results**:
- ✓ Completes within reasonable time (<5 minutes for 10k nodes)
- ✓ Memory usage remains stable
- ✓ Progress indication (if tqdm available)
- ✓ Respects max-nodes limit

**Validation**:
```bash
jq '.nodes_discovered | length' results.json
```

---

### Test Case 14: Fuzzing Performance

**Objective**: Validate fuzzing throughput

**Command**:
```bash
time python opcua_exploit.py \
  -t opc.tcp://localhost:4840 \
  --fuzz-node "ns=2;i=2" \
  --fuzz-iterations 5000 \
  -v
```

**Expected Results**:
- ✓ Completes 5000 iterations
- ✓ Throughput > 50 iterations/second
- ✓ No memory leaks
- ✓ Proper cleanup

**Validation**:
```bash
grep "successful_writes" results.json
```

---

## Validation Checklist

### Code Quality
- [ ] No syntax errors (`python -m py_compile opcua_exploit.py`)
- [ ] Type hints present for all functions
- [ ] Docstrings present for all classes and methods
- [ ] Follows PEP 8 style guidelines
- [ ] No hardcoded credentials
- [ ] Proper exception handling throughout

### Functionality
- [ ] Endpoint discovery works
- [ ] Node enumeration completes
- [ ] Certificate bypass tests execute
- [ ] Subscription creation succeeds
- [ ] Fuzzing completes iterations
- [ ] Session hijacking test runs
- [ ] Security assessment generates report
- [ ] Full assessment executes all modules

### Security
- [ ] All MITRE techniques mapped correctly
- [ ] Events logged with proper severity
- [ ] Results exported in valid JSON
- [ ] No credential leakage in logs
- [ ] Proper cleanup on errors

### Integration
- [ ] Works with FreeOpcUa server
- [ ] Works with Prosys Simulation Server
- [ ] Works with Open62541 server
- [ ] CLI arguments parsed correctly
- [ ] Output files created successfully

### Documentation
- [ ] README.md accurate and complete
- [ ] TESTING.md covers all test cases
- [ ] Usage examples work as documented
- [ ] MITRE mappings documented
- [ ] Installation instructions verified

---

## Troubleshooting

### Issue: "asyncua not available"
**Solution**:
```bash
pip install asyncua cryptography
```

### Issue: "Connection refused"
**Solution**: Verify OPC-UA server is running
```bash
netstat -an | grep 4840
```

### Issue: "Certificate validation failed"
**Solution**: Use `--security-policy None` for testing or provide valid certificates

### Issue: "Access denied"
**Solution**: Provide credentials with `-u username -p password`

### Issue: "Timeout during node enumeration"
**Solution**: Reduce `--max-nodes` or `--max-depth`, increase `--timeout`

---

## Continuous Integration

### Automated Testing Script

```bash
#!/bin/bash

echo "[*] Starting OPC-UA framework testing..."

pip install -r requirements.txt

python test_opcua_server.py &
SERVER_PID=$!
sleep 3

python opcua_exploit.py -t opc.tcp://localhost:4840 --discover-endpoints -o test1.json
TEST1=$?

python opcua_exploit.py -t opc.tcp://localhost:4840 --enumerate-nodes -o test2.json
TEST2=$?

python opcua_exploit.py -t opc.tcp://localhost:4840 --assess-security -o test3.json
TEST3=$?

kill $SERVER_PID

if [ $TEST1 -eq 0 ] && [ $TEST2 -eq 0 ] && [ $TEST3 -eq 0 ]; then
    echo "[+] All tests passed"
    exit 0
else
    echo "[-] Tests failed"
    exit 1
fi
```

---

## Test Result Summary Template

```
OPC-UA Security Framework Testing Report
=========================================

Test Date: [DATE]
Tester: [NAME]
Framework Version: 1.0

Test Environment:
- OPC-UA Server: [SERVER NAME/VERSION]
- Server URL: [URL]
- Python Version: [VERSION]

Test Results:
[✓] Endpoint Discovery
[✓] Node Enumeration
[✓] Certificate Bypass Testing
[✓] Subscription Creation
[✓] Node Write Fuzzing
[✓] Session Hijacking Test
[✓] Security Assessment
[✓] Full Assessment

Performance Metrics:
- Nodes enumerated: [COUNT]
- Enumeration time: [TIME]
- Fuzzing throughput: [ITERATIONS/SEC]

MITRE Techniques Validated:
[✓] T0801 - Monitor Process State
[✓] T0819 - Exploit Public-Facing Application
[✓] T0855 - Unauthorized Command Message
[✓] T0861 - Point & Tag Identification
[✓] T0888 - Remote System Information Discovery

Issues Found: [COUNT]
Critical: [COUNT]
High: [COUNT]
Medium: [COUNT]
Low: [COUNT]

Recommendations:
1. [RECOMMENDATION]
2. [RECOMMENDATION]

Overall Assessment: [PASS/FAIL]
```

---

## References

- OPC Foundation Compliance Testing: https://opcfoundation.org/certification/
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- ICS-CERT Testing Guidelines: https://www.cisa.gov/ics
