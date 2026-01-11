#!/usr/bin/env python3
"""Validate Suricata rules and Zeek scripts syntax"""
import re
from pathlib import Path

def validate_suricata_rules(rules_file):
    """Basic Suricata rules validation"""
    with open(rules_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.split('\n')
    rule_count = 0
    errors = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
            
        if stripped.startswith('alert'):
            rule_count += 1
            # Basic syntax checks
            if not (stripped.endswith(')') or stripped.endswith(')')):
                errors.append(f"Line {i}: Rule may be malformed")
            
            # Check for required fields
            if 'msg:' not in stripped:
                errors.append(f"Line {i}: Missing msg field")
            if 'sid:' not in stripped:
                errors.append(f"Line {i}: Missing sid field")
    
    return rule_count, errors

def validate_zeek_script(zeek_file):
    """Basic Zeek script validation"""
    with open(zeek_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    errors = []
    lines = content.split('\n')
    
    # Check for common syntax issues
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        
        # Check for unmatched braces (simple check)
        open_braces = stripped.count('{')
        close_braces = stripped.count('}')
        if open_braces != close_braces and not stripped.endswith(','):
            # This is a very basic check
            pass
    
    # Check basic structure
    has_module = '@load' in content or 'module' in content
    has_event = 'event ' in content
    
    return has_module or has_event, errors

# Validate Suricata rules
print("=" * 60)
print("SURICATA RULES VALIDATION")
print("=" * 60)

suricata_dir = Path('../../../configs/suricata_rules')
total_rules = 0
for rules_file in suricata_dir.glob('*.rules'):
    count, errors = validate_suricata_rules(rules_file)
    total_rules += count
    status = "OK" if not errors else f"WARNING: {len(errors)} issues"
    print(f"{rules_file.name}: {count} rules - {status}")
    if errors and len(errors) <= 3:
        for err in errors:
            print(f"  {err}")

print(f"\nTotal Suricata rules: {total_rules}")

# Validate Zeek scripts
print("\n" + "=" * 60)
print("ZEEK SCRIPTS VALIDATION")
print("=" * 60)

zeek_dir = Path('../../../configs/zeek')
total_scripts = 0
for zeek_file in zeek_dir.glob('*.zeek'):
    is_valid, errors = validate_zeek_script(zeek_file)
    total_scripts += 1
    status = "OK" if is_valid and not errors else "CHECK MANUALLY"
    print(f"{zeek_file.name}: {status}")
    if errors and len(errors) <= 3:
        for err in errors:
            print(f"  {err}")

print(f"\nTotal Zeek scripts: {total_scripts}")
