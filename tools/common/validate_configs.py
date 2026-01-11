#!/usr/bin/env python3
"""Validate configuration files"""

import yaml
import json
import sys

def validate_yaml():
    """Validate YAML configuration"""
    try:
        with open('tools/common/example_config.yaml', 'r') as f:
            yaml.safe_load(f)
        print("✓ YAML configuration valid")
        return True
    except Exception as e:
        print(f"✗ YAML validation failed: {e}")
        return False

def validate_json():
    """Validate JSON configuration"""
    try:
        with open('tools/common/example_config.json', 'r') as f:
            json.load(f)
        print("✓ JSON configuration valid")
        return True
    except Exception as e:
        print(f"✗ JSON validation failed: {e}")
        return False

if __name__ == '__main__':
    yaml_ok = validate_yaml()
    json_ok = validate_json()
    
    if yaml_ok and json_ok:
        print("\n✓ All configuration files valid")
        sys.exit(0)
    else:
        print("\n✗ Configuration validation failed")
        sys.exit(1)
