#!/usr/bin/env python3
"""
firmware_analyzer.py
ICS Firmware Analysis & Exploitation Framework
Author: Ridpath
Version: 1.0

DISCLAIMER:
FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
Use only on firmware you own or have explicit written permission to analyze.

Purpose:
Comprehensive firmware analysis framework for industrial control system devices.
Automated extraction, analysis, vulnerability detection, and backdoor injection.

Features:
- Firmware extraction and unpacking
- Binary analysis and reverse engineering automation
- Hardcoded credential discovery
- Backdoor detection
- Vulnerability scanning
- Persistent implant injection
- Boot loader manipulation
- MITRE ATT&CK ICS mapping
"""

import os
import sys
import argparse
import logging
import hashlib
import struct
import re
import json
import subprocess
import binascii
from typing import List, Optional, Dict, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
from collections import defaultdict


class FirmwareType(Enum):
    """Firmware types"""
    PLC = "plc"
    RTU = "rtu"
    HMI = "hmi"
    IED = "ied"
    DCS = "dcs"
    SCADA = "scada"
    ROUTER = "router"
    FIREWALL = "firewall"


class Architecture(Enum):
    """CPU architectures"""
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    X86 = "x86"
    X86_64 = "x86_64"
    PPC = "powerpc"
    M68K = "m68k"
    AVR = "avr"


@dataclass
class FirmwareMetadata:
    """Firmware metadata"""
    filename: str
    size: int
    md5: str
    sha256: str
    file_type: str = ""
    architecture: Optional[Architecture] = None
    vendor: str = ""
    model: str = ""
    version: str = ""


@dataclass
class HardcodedCredential:
    """Discovered credential"""
    username: str
    password: str
    hash_type: str = ""
    location: str = ""
    confidence: float = 0.0


@dataclass
class Backdoor:
    """Detected backdoor"""
    type: str
    description: str
    location: str
    severity: str
    indicators: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    """Detected vulnerability"""
    cve_id: str = ""
    description: str = ""
    severity: str = ""
    affected_component: str = ""
    location: str = ""


class FirmwareAnalyzer:
    """Main firmware analysis framework"""
    
    def __init__(self, firmware_path: str, output_dir: str = "firmware_analysis",
                 verbose: bool = False):
        self.firmware_path = Path(firmware_path)
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        self.logger = self._setup_logging()
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata: Optional[FirmwareMetadata] = None
        self.credentials: List[HardcodedCredential] = []
        self.backdoors: List[Backdoor] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.strings: List[str] = []
        
        self.attack_log: List[Dict[str, Any]] = []
        self.mitre_mapping: Dict[str, List[str]] = defaultdict(list)
    
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("FirmwareAnalyzer")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def analyze(self) -> Dict[str, Any]:
        """
        Full firmware analysis pipeline
        
        MITRE ATT&CK ICS: T0873 - Project File Infection
        """
        self.logger.info(f"Starting firmware analysis: {self.firmware_path}")
        
        self.metadata = self._extract_metadata()
        
        self._extract_strings()
        
        self._detect_architecture()
        
        self._find_credentials()
        
        self._detect_backdoors()
        
        self._scan_vulnerabilities()
        
        self._log_attack("FIRMWARE_ANALYSIS", {
            "firmware": str(self.firmware_path),
            "size": self.metadata.size if self.metadata else 0
        }, ["T0873"])
        
        return self.generate_report()
    
    def _extract_metadata(self) -> FirmwareMetadata:
        """Extract firmware metadata"""
        self.logger.info("Extracting metadata")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        
        file_type = self._detect_file_type(data)
        
        metadata = FirmwareMetadata(
            filename=self.firmware_path.name,
            size=len(data),
            md5=md5,
            sha256=sha256,
            file_type=file_type
        )
        
        self.logger.info(f"MD5: {md5}")
        self.logger.info(f"SHA256: {sha256}")
        self.logger.info(f"File type: {file_type}")
        
        return metadata
    
    def _detect_file_type(self, data: bytes) -> str:
        """Detect firmware file type by magic bytes"""
        magic_signatures = {
            b'\x7fELF': 'ELF',
            b'MZ': 'PE/DOS',
            b'\x1f\x8b': 'GZIP',
            b'BZh': 'BZIP2',
            b'\xfd7zXZ': 'XZ',
            b'hsqs': 'SquashFS',
            b'ustar': 'TAR',
            b'PK\x03\x04': 'ZIP',
            b'\xd0\xcf\x11\xe0': 'OLE2',
        }
        
        for magic, ftype in magic_signatures.items():
            if data.startswith(magic):
                return ftype
        
        return 'Unknown'
    
    def _detect_architecture(self):
        """Detect CPU architecture"""
        self.logger.info("Detecting architecture")
        
        with open(self.firmware_path, 'rb') as f:
            header = f.read(64)
        
        if header.startswith(b'\x7fELF'):
            arch_byte = header[18:19]
            arch_map = {
                b'\x28': Architecture.ARM,
                b'\x08': Architecture.MIPS,
                b'\x03': Architecture.X86,
                b'\x3e': Architecture.X86_64,
                b'\x14': Architecture.PPC,
                b'\x04': Architecture.M68K,
                b'\xb7': Architecture.ARM64,
            }
            
            arch = arch_map.get(arch_byte)
            if arch and self.metadata:
                self.metadata.architecture = arch
                self.logger.info(f"Architecture: {arch.value}")
    
    def _extract_strings(self):
        """Extract printable strings from firmware"""
        self.logger.info("Extracting strings")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        pattern = rb'[\x20-\x7E]{6,}'
        matches = re.findall(pattern, data)
        
        self.strings = [s.decode('ascii', errors='ignore') for s in matches]
        
        self.logger.info(f"Extracted {len(self.strings)} strings")
        
        strings_file = self.output_dir / 'strings.txt'
        with open(strings_file, 'w') as f:
            f.write('\n'.join(self.strings))
    
    def _find_credentials(self):
        """
        Find hardcoded credentials
        
        MITRE ATT&CK ICS: T0891 - Hardcoded Credentials
        """
        self.logger.info("Searching for hardcoded credentials")
        
        credential_patterns = [
            (r'username["\s:=]+([a-zA-Z0-9_]+)', r'password["\s:=]+([a-zA-Z0-9!@#$%^&*()_+\-=]+)'),
            (r'user["\s:=]+([a-zA-Z0-9_]+)', r'pass["\s:=]+([a-zA-Z0-9!@#$%^&*()_+\-=]+)'),
            (r'login["\s:=]+([a-zA-Z0-9_]+)', r'pwd["\s:=]+([a-zA-Z0-9!@#$%^&*()_+\-=]+)'),
        ]
        
        full_text = '\n'.join(self.strings)
        
        for user_pattern, pass_pattern in credential_patterns:
            usernames = re.findall(user_pattern, full_text, re.IGNORECASE)
            passwords = re.findall(pass_pattern, full_text, re.IGNORECASE)
            
            for username in set(usernames):
                for password in set(passwords):
                    if len(username) >= 3 and len(password) >= 4:
                        cred = HardcodedCredential(
                            username=username,
                            password=password,
                            location="strings",
                            confidence=0.7
                        )
                        self.credentials.append(cred)
                        self.logger.warning(f"Found credential: {username}:{password}")
        
        common_defaults = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '12345'),
            ('root', 'root'),
            ('root', 'password'),
            ('operator', 'operator'),
            ('engineer', 'engineer'),
            ('service', 'service'),
        ]
        
        for username, password in common_defaults:
            if username in full_text.lower() and password in full_text.lower():
                cred = HardcodedCredential(
                    username=username,
                    password=password,
                    location="common_defaults",
                    confidence=0.5
                )
                self.credentials.append(cred)
                self.logger.warning(f"Found default credential: {username}:{password}")
        
        self._log_attack("CREDENTIAL_EXTRACTION", {
            "credentials_found": len(self.credentials)
        }, ["T0891"])
    
    def _detect_backdoors(self):
        """
        Detect potential backdoors
        
        MITRE ATT&CK ICS: T0839 - Module Firmware, T0873 - Project File Infection
        """
        self.logger.info("Detecting backdoors")
        
        backdoor_indicators = {
            'telnet_backdoor': [b'telnetd', b'telnet_enable', b'TELNET_PORT'],
            'ssh_backdoor': [b'dropbear', b'authorized_keys', b'ssh_enable'],
            'debug_interface': [b'debug_enable', b'JTAG_ENABLE', b'DEBUG_MODE'],
            'hidden_account': [b'backdoor', b'hidden_user', b'secret_admin'],
            'command_injection': [b'system(', b'exec(', b'popen(', b'shell_exec'],
            'hardcoded_key': [b'-----BEGIN RSA PRIVATE KEY-----', b'-----BEGIN PRIVATE KEY-----'],
        }
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        for backdoor_type, indicators in backdoor_indicators.items():
            found_indicators = []
            for indicator in indicators:
                if indicator in data:
                    found_indicators.append(indicator.decode('ascii', errors='ignore'))
                    offset = data.find(indicator)
                    self.logger.warning(f"Backdoor indicator at offset 0x{offset:08x}: {indicator}")
            
            if found_indicators:
                backdoor = Backdoor(
                    type=backdoor_type,
                    description=f"Potential {backdoor_type.replace('_', ' ')}",
                    location="firmware_binary",
                    severity="HIGH",
                    indicators=found_indicators
                )
                self.backdoors.append(backdoor)
        
        self._log_attack("BACKDOOR_DETECTION", {
            "backdoors_found": len(self.backdoors)
        }, ["T0839", "T0873"])
    
    def _scan_vulnerabilities(self):
        """
        Scan for known vulnerabilities
        
        MITRE ATT&CK ICS: T0866 - Exploitation of Remote Services
        """
        self.logger.info("Scanning for vulnerabilities")
        
        vuln_patterns = {
            'buffer_overflow': [b'strcpy', b'sprintf', b'gets', b'strcat'],
            'format_string': [b'printf(user', b'sprintf(buf,user', b'fprintf('],
            'command_injection': [b'system(', b'popen(', b'exec('],
            'path_traversal': [b'../', b'..\\', b'%2e%2e'],
            'weak_crypto': [b'DES_', b'MD5_', b'RC4_'],
        }
        
        full_text = '\n'.join(self.strings)
        
        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                if pattern in full_text.encode():
                    vuln = Vulnerability(
                        description=f"Potential {vuln_type.replace('_', ' ')}",
                        severity="MEDIUM",
                        affected_component="Unknown",
                        location="firmware_binary"
                    )
                    self.vulnerabilities.append(vuln)
                    self.logger.warning(f"Vulnerability: {vuln_type}")
        
        self._log_attack("VULNERABILITY_SCAN", {
            "vulnerabilities_found": len(self.vulnerabilities)
        }, ["T0866"])
    
    def inject_backdoor(self, backdoor_code: bytes, offset: int) -> bool:
        """
        Inject backdoor into firmware
        
        MITRE ATT&CK ICS: T0839 - Module Firmware, T0873 - Project File Infection
        """
        self.logger.warning(f"Injecting backdoor at offset 0x{offset:08x}")
        
        with open(self.firmware_path, 'rb') as f:
            data = bytearray(f.read())
        
        if offset + len(backdoor_code) > len(data):
            self.logger.error("Backdoor too large for offset")
            return False
        
        data[offset:offset+len(backdoor_code)] = backdoor_code
        
        backdoored_firmware = self.output_dir / f"{self.firmware_path.stem}_backdoored{self.firmware_path.suffix}"
        
        with open(backdoored_firmware, 'wb') as f:
            f.write(data)
        
        self.logger.info(f"Backdoored firmware: {backdoored_firmware}")
        
        self._log_attack("BACKDOOR_INJECTION", {
            "offset": offset,
            "size": len(backdoor_code),
            "output": str(backdoored_firmware)
        }, ["T0839", "T0873"])
        
        return True
    
    def extract_bootloader(self) -> Optional[bytes]:
        """
        Extract bootloader from firmware
        
        MITRE ATT&CK ICS: T0857 - System Firmware
        """
        self.logger.info("Extracting bootloader")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read(0x10000)
        
        bootloader_signatures = [
            b'U-Boot',
            b'Bootloader',
            b'RedBoot',
            b'CFE',
        ]
        
        for sig in bootloader_signatures:
            if sig in data:
                offset = data.find(sig)
                self.logger.info(f"Found {sig.decode()} at offset 0x{offset:08x}")
                
                bootloader_file = self.output_dir / 'bootloader.bin'
                with open(bootloader_file, 'wb') as f:
                    f.write(data[:0x10000])
                
                self._log_attack("BOOTLOADER_EXTRACTION", {
                    "signature": sig.decode('ascii', errors='ignore'),
                    "offset": offset
                }, ["T0857"])
                
                return data[:0x10000]
        
        return None
    
    def modify_bootloader(self, modifications: Dict[int, bytes]) -> bool:
        """
        Modify bootloader configuration
        
        MITRE ATT&CK ICS: T0857 - System Firmware
        """
        self.logger.warning("Modifying bootloader")
        
        bootloader = self.extract_bootloader()
        if not bootloader:
            self.logger.error("Bootloader not found")
            return False
        
        modified_bootloader = bytearray(bootloader)
        
        for offset, patch in modifications.items():
            if offset + len(patch) <= len(modified_bootloader):
                modified_bootloader[offset:offset+len(patch)] = patch
        
        modified_file = self.output_dir / 'bootloader_modified.bin'
        with open(modified_file, 'wb') as f:
            f.write(modified_bootloader)
        
        self.logger.info(f"Modified bootloader: {modified_file}")
        
        self._log_attack("BOOTLOADER_MODIFICATION", {
            "patches_applied": len(modifications)
        }, ["T0857"])
        
        return True
    
    def _log_attack(self, attack_type: str, params: Dict[str, Any],
                   mitre_tactics: List[str]):
        """Log attack with MITRE ATT&CK mapping"""
        attack_record = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "parameters": params,
            "mitre_tactics": mitre_tactics
        }
        self.attack_log.append(attack_record)
        
        for tactic in mitre_tactics:
            self.mitre_mapping[tactic].append(attack_type)
    
    def generate_report(self, output_file: str = None) -> Dict[str, Any]:
        """Generate analysis report"""
        if output_file is None:
            output_file = str(self.output_dir / 'analysis_report.json')
        
        report = {
            "firmware_info": {
                "filename": self.metadata.filename if self.metadata else "",
                "size": self.metadata.size if self.metadata else 0,
                "md5": self.metadata.md5 if self.metadata else "",
                "sha256": self.metadata.sha256 if self.metadata else "",
                "file_type": self.metadata.file_type if self.metadata else "",
                "architecture": self.metadata.architecture.value if self.metadata and self.metadata.architecture else "unknown"
            },
            "credentials": [
                {
                    "username": c.username,
                    "password": c.password,
                    "location": c.location,
                    "confidence": c.confidence
                }
                for c in self.credentials
            ],
            "backdoors": [
                {
                    "type": b.type,
                    "description": b.description,
                    "severity": b.severity,
                    "indicators": b.indicators
                }
                for b in self.backdoors
            ],
            "vulnerabilities": [
                {
                    "description": v.description,
                    "severity": v.severity,
                    "location": v.location
                }
                for v in self.vulnerabilities
            ],
            "attack_log": self.attack_log,
            "mitre_mapping": dict(self.mitre_mapping),
            "statistics": {
                "strings_extracted": len(self.strings),
                "credentials_found": len(self.credentials),
                "backdoors_detected": len(self.backdoors),
                "vulnerabilities_found": len(self.vulnerabilities)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report saved to {output_file}")
        return report


def main():
    parser = argparse.ArgumentParser(
        description="ICS Firmware Analysis & Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full analysis:
    python firmware_analyzer.py -f firmware.bin --analyze

  Credential extraction:
    python firmware_analyzer.py -f firmware.bin --find-creds

  Backdoor detection:
    python firmware_analyzer.py -f firmware.bin --detect-backdoors

  Backdoor injection:
    python firmware_analyzer.py -f firmware.bin --inject-backdoor --code "DEADBEEF" --offset 0x1000

  Bootloader extraction:
    python firmware_analyzer.py -f firmware.bin --extract-bootloader

MITRE ATT&CK ICS Coverage:
  T0839 - Module Firmware
  T0857 - System Firmware
  T0866 - Exploitation of Remote Services
  T0873 - Project File Infection
  T0891 - Hardcoded Credentials
        """
    )
    
    parser.add_argument('-f', '--firmware', required=True, help='Firmware file path')
    parser.add_argument('-o', '--output', default='firmware_analysis', help='Output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    parser.add_argument('--analyze', action='store_true', help='Full analysis')
    parser.add_argument('--find-creds', action='store_true', help='Find credentials')
    parser.add_argument('--detect-backdoors', action='store_true', help='Detect backdoors')
    parser.add_argument('--scan-vulns', action='store_true', help='Scan vulnerabilities')
    
    parser.add_argument('--inject-backdoor', action='store_true', help='Inject backdoor')
    parser.add_argument('--code', help='Backdoor code (hex string)')
    parser.add_argument('--offset', type=lambda x: int(x, 0), help='Injection offset')
    
    parser.add_argument('--extract-bootloader', action='store_true', help='Extract bootloader')
    parser.add_argument('--modify-bootloader', action='store_true', help='Modify bootloader')
    
    parser.add_argument('--report', help='Output report file')
    
    args = parser.parse_args()
    
    analyzer = FirmwareAnalyzer(
        firmware_path=args.firmware,
        output_dir=args.output,
        verbose=args.verbose
    )
    
    if args.analyze:
        report = analyzer.analyze()
        print(f"\n[+] Analysis complete")
        print(f"  Credentials: {len(analyzer.credentials)}")
        print(f"  Backdoors: {len(analyzer.backdoors)}")
        print(f"  Vulnerabilities: {len(analyzer.vulnerabilities)}")
    
    if args.find_creds:
        analyzer._extract_metadata()
        analyzer._extract_strings()
        analyzer._find_credentials()
        print(f"\n[+] Found {len(analyzer.credentials)} credentials")
        for cred in analyzer.credentials:
            print(f"  {cred.username}:{cred.password}")
    
    if args.detect_backdoors:
        analyzer._extract_metadata()
        analyzer._detect_backdoors()
        print(f"\n[+] Detected {len(analyzer.backdoors)} potential backdoors")
    
    if args.scan_vulns:
        analyzer._extract_metadata()
        analyzer._extract_strings()
        analyzer._scan_vulnerabilities()
        print(f"\n[+] Found {len(analyzer.vulnerabilities)} vulnerabilities")
    
    if args.inject_backdoor:
        if not args.code or args.offset is None:
            print("[-] --code and --offset required")
            sys.exit(1)
        backdoor_bytes = bytes.fromhex(args.code)
        analyzer.inject_backdoor(backdoor_bytes, args.offset)
    
    if args.extract_bootloader:
        bootloader = analyzer.extract_bootloader()
        if bootloader:
            print(f"\n[+] Bootloader extracted: {len(bootloader)} bytes")
    
    if args.modify_bootloader:
        analyzer.modify_bootloader({})
    
    if args.report or args.analyze:
        report_file = args.report if args.report else str(Path(args.output) / 'analysis_report.json')
        analyzer.generate_report(report_file)
        print(f"\n[+] Report: {report_file}")


if __name__ == "__main__":
    main()
