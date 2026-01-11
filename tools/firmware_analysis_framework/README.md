# ICS Firmware Analysis & Exploitation Framework

Automated firmware analysis and manipulation toolkit for industrial control system devices.

## Overview

Comprehensive framework for reverse engineering, vulnerability analysis, and exploitation of ICS firmware images from PLCs, RTUs, HMIs, and other industrial devices.

## Capabilities

### Static Analysis
- File type and architecture detection
- String extraction and analysis
- Binary signature scanning
- Metadata extraction

### Security Assessment
- Hardcoded credential discovery
- Backdoor detection
- Vulnerability scanning
- Cryptographic weakness identification

### Offensive Operations
- Backdoor injection
- Bootloader manipulation
- Persistent implant insertion
- Configuration tampering

## Installation

```bash
cd tools/firmware_analysis_framework
pip install -r requirements.txt
```

**Optional dependencies** for enhanced analysis:
```bash
pip install binwalk python-magic
```

## Usage Examples

### Full Analysis

```bash
python firmware_analyzer.py -f plc_firmware.bin --analyze -v
```

### Credential Extraction

```bash
python firmware_analyzer.py -f firmware.bin --find-creds
```

### Backdoor Detection

```bash
python firmware_analyzer.py -f firmware.bin --detect-backdoors
```

### Vulnerability Scanning

```bash
python firmware_analyzer.py -f firmware.bin --scan-vulns
```

### Backdoor Injection

```bash
python firmware_analyzer.py -f firmware.bin --inject-backdoor \
    --code "909090909090EB0C48656C6C6F20576F726C64" \
    --offset 0x8000
```

### Bootloader Extraction

```bash
python firmware_analyzer.py -f firmware.bin --extract-bootloader
```

### Generate Report

```bash
python firmware_analyzer.py -f firmware.bin --analyze --report analysis.json
```

## MITRE ATT&CK ICS Mapping

- **T0839**: Module Firmware
- **T0857**: System Firmware
- **T0866**: Exploitation of Remote Services
- **T0873**: Project File Infection
- **T0891**: Hardcoded Credentials

## Technical Details

### Supported Architectures

- ARM/ARM64
- MIPS
- x86/x86-64
- PowerPC
- M68K
- AVR

### File Type Detection

**Magic byte signatures**:
- ELF (0x7F 'E' 'L' 'F')
- PE/DOS (0x4D 'M' 'Z')
- Compressed (GZIP, BZIP2, XZ)
- Filesystem images (SquashFS, JFFS2)
- Archives (ZIP, TAR)

### Credential Detection Patterns

**Common patterns searched**:
- username/password pairs
- user/pass combinations
- login/pwd patterns
- Default credentials (admin/admin, root/root, etc.)

**Hash detection**:
- MD5 hashes
- SHA-1/SHA-256 hashes
- DES/3DES encrypted passwords
- Base64-encoded credentials

### Backdoor Indicators

**Detected backdoor types**:
- **Telnet backdoors**: Unauthorized telnet daemons
- **SSH backdoors**: Hidden SSH keys, modified dropbear
- **Debug interfaces**: JTAG, UART, debug shells
- **Hidden accounts**: Undocumented user accounts
- **Command injection**: Unsafe system() calls
- **Hardcoded keys**: Embedded private keys

### Vulnerability Classes

**Scanned vulnerabilities**:
- Buffer overflows (strcpy, sprintf, gets)
- Format string bugs (printf with user input)
- Command injection (system, exec, popen)
- Path traversal (../, ..\\)
- Weak cryptography (DES, RC4, MD5)

## Analysis Output

### Directory Structure

```
firmware_analysis/
├── strings.txt                 # Extracted strings
├── bootloader.bin             # Extracted bootloader
├── bootloader_modified.bin    # Modified bootloader
├── firmware_backdoored.bin    # Backdoored firmware
└── analysis_report.json       # Comprehensive report
```

### Report Format

```json
{
  "firmware_info": {
    "filename": "plc_firmware.bin",
    "size": 16777216,
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "file_type": "ELF",
    "architecture": "arm"
  },
  "credentials": [...],
  "backdoors": [...],
  "vulnerabilities": [...],
  "statistics": {...}
}
```

## Attack Scenarios

### Scenario 1: Credential Recovery

```bash
# Extract and analyze firmware
python firmware_analyzer.py -f siemens_s7_1200.bin --find-creds

# Discovered: engineering:siemens123
# Use credential to access PLC
```

### Scenario 2: Backdoor Implantation

```bash
# Analyze original firmware
python firmware_analyzer.py -f original.bin --analyze

# Inject persistent backdoor
python firmware_analyzer.py -f original.bin --inject-backdoor \
    --code "$(cat shellcode.hex)" --offset 0xA000

# Flash backdoored firmware to device
```

### Scenario 3: Bootloader Manipulation

```bash
# Extract bootloader
python firmware_analyzer.py -f firmware.bin --extract-bootloader

# Modify boot parameters (disable signature verification)
python firmware_analyzer.py -f firmware.bin --modify-bootloader

# Flash modified bootloader for persistent access
```

## Vendor-Specific Techniques

### Siemens S7

**Firmware structure**: TIA Portal project files (.zap16)  
**Encryption**: Proprietary obfuscation  
**Extraction**: Use Siemens-specific tools or custom parsers

### Allen-Bradley CompactLogix

**Firmware format**: .FW files  
**Bootloader**: U-Boot based  
**Common credentials**: admin/admin, user/user

### Schneider Electric

**Firmware packaging**: Unity Pro (.stu files)  
**Encryption**: AES-128 (weak key derivation)  
**Backdoors**: Historical telnet backdoors

### Honeywell

**Platform**: VxWorks RTOS  
**Bootloader**: Custom Honeywell bootloader  
**Debug ports**: Often UART on J3 header

## Countermeasures

1. **Firmware Signing**: Cryptographically sign all firmware
2. **Secure Boot**: Verify bootloader and firmware integrity
3. **Credential Management**: Eliminate hardcoded credentials
4. **Code Review**: Audit for backdoors and vulnerabilities
5. **Encryption**: Encrypt firmware images
6. **Access Control**: Restrict firmware download/upload
7. **Integrity Monitoring**: Detect unauthorized modifications

## Legal and Ethical Considerations

Firmware analysis and modification can violate:
- **DMCA Section 1201**: Circumvention of access controls
- **CFAA**: Unauthorized access to computer systems
- **License agreements**: Reverse engineering prohibitions

**Legal uses**:
- Authorized penetration testing
- Security research with permission
- Incident response and forensics
- Vulnerability disclosure programs

## Legal Notice

FOR AUTHORIZED SECURITY TESTING ONLY. Unauthorized firmware modification can cause device malfunction, safety hazards, and legal liability.

## References

- NIST SP 800-193: Platform Firmware Resiliency Guidelines
- ICS-CERT Firmware Analysis Best Practices
- Binwalk Documentation
- Ghidra/IDA Pro for Firmware RE
