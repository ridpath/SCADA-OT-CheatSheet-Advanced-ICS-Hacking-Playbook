#!/usr/bin/env python3
"""
ics_security_tool.py
Base class for all ICS security assessment tools

Provides standardized interface including:
- Configuration management (YAML/JSON)
- Dry-run mode
- Result export (JSON, XML, CSV, HTML)
- Safety validation
- Logging
- Error handling
"""

import json
import yaml
import csv
import logging
import sys
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum
import xml.etree.ElementTree as ET
import xml.dom.minidom


class ExportFormat(Enum):
    """Supported export formats"""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    HTML = "html"
    TXT = "txt"


class Severity(Enum):
    """Event severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityEvent:
    """Standardized security event"""
    timestamp: str
    event_type: str
    severity: str
    description: str
    target: str
    protocol: str
    technique_id: Optional[str] = None
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class SafetyCheck:
    """Safety validation check"""
    name: str
    description: str
    enabled: bool = True
    threshold: Optional[float] = None
    action: str = "warn"


class ICSSecurityTool(ABC):
    """
    Abstract base class for all ICS security assessment tools
    
    Provides common functionality:
    - Configuration loading from YAML/JSON
    - Dry-run mode for testing without execution
    - Result export in multiple formats
    - Safety validation checks
    - Logging and error handling
    """

    def __init__(
        self,
        name: str,
        version: str,
        protocol: str,
        config_file: Optional[str] = None,
        dry_run: bool = False,
        log_level: str = "INFO"
    ):
        """
        Initialize ICS security tool
        
        Args:
            name: Tool name
            version: Tool version
            protocol: Protocol name (e.g., "Modbus", "S7Comm")
            config_file: Path to configuration file (YAML or JSON)
            dry_run: Enable dry-run mode (no actual network operations)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.name = name
        self.version = version
        self.protocol = protocol
        self.dry_run = dry_run
        self.config: Dict[str, Any] = {}
        self.events: List[SecurityEvent] = []
        self.safety_checks: List[SafetyCheck] = []
        
        self._setup_logging(log_level)
        
        if config_file:
            self.load_config(config_file)
        else:
            self._load_default_config()
        
        self._initialize_safety_checks()
        
        self.logger.info(f"{self.name} v{self.version} initialized")
        if self.dry_run:
            self.logger.warning("DRY-RUN MODE: No actual operations will be performed")

    def _setup_logging(self, log_level: str) -> None:
        """Configure logging"""
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def load_config(self, config_file: str) -> None:
        """
        Load configuration from YAML or JSON file
        
        Args:
            config_file: Path to configuration file
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            self.logger.error(f"Configuration file not found: {config_file}")
            return
        
        try:
            with open(config_path, 'r') as f:
                if config_path.suffix in ['.yaml', '.yml']:
                    self.config = yaml.safe_load(f)
                elif config_path.suffix == '.json':
                    self.config = json.load(f)
                else:
                    self.logger.error(f"Unsupported config format: {config_path.suffix}")
                    return
            
            self.logger.info(f"Configuration loaded from {config_file}")
            
            if 'dry_run' in self.config:
                self.dry_run = self.config['dry_run']
            
            if 'safety_checks' in self.config:
                self._load_safety_checks_from_config()
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")

    def _load_default_config(self) -> None:
        """Load default configuration"""
        self.config = {
            'dry_run': False,
            'timeout': 5,
            'max_retries': 3,
            'safety_checks': {
                'rate_limit': True,
                'validate_targets': True,
                'confirm_destructive': True
            }
        }

    def _initialize_safety_checks(self) -> None:
        """Initialize safety validation checks"""
        self.safety_checks = [
            SafetyCheck(
                name="rate_limit",
                description="Limit request rate to avoid DoS",
                enabled=True,
                threshold=10.0,
                action="block"
            ),
            SafetyCheck(
                name="validate_targets",
                description="Validate target IP addresses",
                enabled=True,
                action="block"
            ),
            SafetyCheck(
                name="confirm_destructive",
                description="Confirm before destructive operations",
                enabled=True,
                action="prompt"
            )
        ]

    def _load_safety_checks_from_config(self) -> None:
        """Load safety checks from configuration"""
        config_checks = self.config.get('safety_checks', {})
        for check in self.safety_checks:
            if check.name in config_checks:
                check.enabled = config_checks[check.name]

    def validate_safety(self, operation: str, **kwargs) -> bool:
        """
        Validate safety for an operation
        
        Args:
            operation: Operation name
            **kwargs: Operation-specific parameters
            
        Returns:
            True if operation is safe, False otherwise
        """
        for check in self.safety_checks:
            if not check.enabled:
                continue
            
            if check.name == "rate_limit" and operation == "network_request":
                rate = kwargs.get('rate', 0)
                if check.threshold and rate > check.threshold:
                    self.logger.warning(f"Rate limit exceeded: {rate} > {check.threshold}")
                    if check.action == "block":
                        return False
            
            elif check.name == "validate_targets" and operation == "target_validation":
                target = kwargs.get('target')
                if not self._validate_target(target):
                    self.logger.error(f"Invalid target: {target}")
                    if check.action == "block":
                        return False
            
            elif check.name == "confirm_destructive" and operation == "destructive":
                if check.action == "prompt" and not self.dry_run:
                    response = input(f"Confirm destructive operation '{kwargs.get('description', 'unknown')}' [yes/no]: ")
                    if response.lower() != 'yes':
                        self.logger.info("Operation cancelled by user")
                        return False
        
        return True

    def _validate_target(self, target: str) -> bool:
        """Validate target IP address or hostname"""
        if not target:
            return False
        
        try:
            import ipaddress
            ipaddress.ip_address(target)
            return True
        except ValueError:
            if '.' in target and len(target) > 0:
                return True
            return False

    def log_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        target: str,
        technique_id: Optional[str] = None,
        source: Optional[str] = None,
        **metadata
    ) -> None:
        """
        Log security event
        
        Args:
            event_type: Event type
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            description: Event description
            target: Target system
            technique_id: MITRE ATT&CK technique ID
            source: Source system
            **metadata: Additional metadata
        """
        event = SecurityEvent(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            event_type=event_type,
            severity=severity,
            description=description,
            target=target,
            protocol=self.protocol,
            technique_id=technique_id,
            source=source,
            metadata=metadata
        )
        
        self.events.append(event)
        
        log_msg = f"[{severity}] {event_type}: {description} (Target: {target})"
        if technique_id:
            log_msg += f" [MITRE: {technique_id}]"
        
        if severity == "CRITICAL":
            self.logger.critical(log_msg)
        elif severity == "HIGH":
            self.logger.error(log_msg)
        elif severity == "MEDIUM":
            self.logger.warning(log_msg)
        elif severity == "LOW":
            self.logger.info(log_msg)
        else:
            self.logger.debug(log_msg)

    def export_results(
        self,
        output_file: str,
        format: Union[str, ExportFormat] = ExportFormat.JSON
    ) -> None:
        """
        Export results to file in specified format
        
        Args:
            output_file: Output file path
            format: Export format (json, xml, csv, html, txt)
        """
        if isinstance(format, str):
            format = ExportFormat(format.lower())
        
        self.logger.info(f"Exporting {len(self.events)} events to {output_file} ({format.value})")
        
        try:
            if format == ExportFormat.JSON:
                self._export_json(output_file)
            elif format == ExportFormat.XML:
                self._export_xml(output_file)
            elif format == ExportFormat.CSV:
                self._export_csv(output_file)
            elif format == ExportFormat.HTML:
                self._export_html(output_file)
            elif format == ExportFormat.TXT:
                self._export_txt(output_file)
            else:
                self.logger.error(f"Unsupported export format: {format}")
                return
            
            self.logger.info(f"Results exported to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")

    def _export_json(self, output_file: str) -> None:
        """Export results as JSON"""
        data = {
            'tool': self.name,
            'version': self.version,
            'protocol': self.protocol,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'dry_run': self.dry_run,
            'events': [event.to_dict() for event in self.events],
            'summary': {
                'total_events': len(self.events),
                'by_severity': self._count_by_severity(),
                'by_type': self._count_by_type()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _export_xml(self, output_file: str) -> None:
        """Export results as XML"""
        root = ET.Element('report')
        
        metadata = ET.SubElement(root, 'metadata')
        ET.SubElement(metadata, 'tool').text = self.name
        ET.SubElement(metadata, 'version').text = self.version
        ET.SubElement(metadata, 'protocol').text = self.protocol
        ET.SubElement(metadata, 'timestamp').text = datetime.utcnow().isoformat() + 'Z'
        ET.SubElement(metadata, 'dry_run').text = str(self.dry_run)
        
        events_elem = ET.SubElement(root, 'events')
        for event in self.events:
            event_elem = ET.SubElement(events_elem, 'event')
            for key, value in event.to_dict().items():
                if isinstance(value, dict):
                    meta_elem = ET.SubElement(event_elem, key)
                    for k, v in value.items():
                        ET.SubElement(meta_elem, k).text = str(v)
                else:
                    ET.SubElement(event_elem, key).text = str(value) if value else ''
        
        summary = ET.SubElement(root, 'summary')
        ET.SubElement(summary, 'total_events').text = str(len(self.events))
        
        xml_str = ET.tostring(root, encoding='unicode')
        dom = xml.dom.minidom.parseString(xml_str)
        
        with open(output_file, 'w') as f:
            f.write(dom.toprettyxml(indent='  '))

    def _export_csv(self, output_file: str) -> None:
        """Export results as CSV"""
        if not self.events:
            return
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['timestamp', 'event_type', 'severity', 'description', 
                         'target', 'protocol', 'technique_id', 'source']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for event in self.events:
                row = event.to_dict()
                row.pop('metadata', None)
                writer.writerow(row)

    def _export_html(self, output_file: str) -> None:
        """Export results as HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{self.name} v{self.version} - Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .metadata {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .CRITICAL {{ color: #d32f2f; font-weight: bold; }}
        .HIGH {{ color: #f57c00; font-weight: bold; }}
        .MEDIUM {{ color: #fbc02d; }}
        .LOW {{ color: #388e3c; }}
        .INFO {{ color: #1976d2; }}
    </style>
</head>
<body>
    <h1>{self.name} v{self.version}</h1>
    <div class="metadata">
        <p><strong>Protocol:</strong> {self.protocol}</p>
        <p><strong>Timestamp:</strong> {datetime.utcnow().isoformat()}Z</p>
        <p><strong>Dry Run:</strong> {self.dry_run}</p>
        <p><strong>Total Events:</strong> {len(self.events)}</p>
    </div>
    <h2>Events</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Severity</th>
            <th>Event Type</th>
            <th>Description</th>
            <th>Target</th>
            <th>MITRE Technique</th>
        </tr>
"""
        
        for event in self.events:
            html += f"""        <tr>
            <td>{event.timestamp}</td>
            <td class="{event.severity}">{event.severity}</td>
            <td>{event.event_type}</td>
            <td>{event.description}</td>
            <td>{event.target}</td>
            <td>{event.technique_id or 'N/A'}</td>
        </tr>
"""
        
        html += """    </table>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html)

    def _export_txt(self, output_file: str) -> None:
        """Export results as plain text"""
        with open(output_file, 'w') as f:
            f.write(f"{self.name} v{self.version}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Protocol: {self.protocol}\n")
            f.write(f"Timestamp: {datetime.utcnow().isoformat()}Z\n")
            f.write(f"Dry Run: {self.dry_run}\n")
            f.write(f"Total Events: {len(self.events)}\n\n")
            
            f.write("Events:\n")
            f.write("-" * 80 + "\n")
            
            for event in self.events:
                f.write(f"\n[{event.timestamp}] [{event.severity}] {event.event_type}\n")
                f.write(f"  Target: {event.target}\n")
                f.write(f"  Description: {event.description}\n")
                if event.technique_id:
                    f.write(f"  MITRE Technique: {event.technique_id}\n")
                if event.metadata:
                    f.write(f"  Metadata: {event.metadata}\n")

    def _count_by_severity(self) -> Dict[str, int]:
        """Count events by severity"""
        counts = {}
        for event in self.events:
            counts[event.severity] = counts.get(event.severity, 0) + 1
        return counts

    def _count_by_type(self) -> Dict[str, int]:
        """Count events by type"""
        counts = {}
        for event in self.events:
            counts[event.event_type] = counts.get(event.event_type, 0) + 1
        return counts

    def get_summary(self) -> Dict[str, Any]:
        """
        Get assessment summary
        
        Returns:
            Dictionary with summary statistics
        """
        return {
            'tool': self.name,
            'version': self.version,
            'protocol': self.protocol,
            'total_events': len(self.events),
            'by_severity': self._count_by_severity(),
            'by_type': self._count_by_type(),
            'dry_run': self.dry_run
        }

    @abstractmethod
    def run_assessment(self, **kwargs) -> None:
        """
        Run security assessment (must be implemented by subclasses)
        
        Args:
            **kwargs: Assessment-specific parameters
        """
        pass

    @abstractmethod
    def get_available_operations(self) -> List[str]:
        """
        Get list of available operations (must be implemented by subclasses)
        
        Returns:
            List of operation names
        """
        pass
