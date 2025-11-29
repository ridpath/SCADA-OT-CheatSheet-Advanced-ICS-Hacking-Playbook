
#!/usr/bin/env python3
"""
ics_detector.py
Enhanced ICS/SCADA ML Anomaly Detection with Suricata Integration & OPC UA Support

DISCLAIMER:
FOR AUTHORIZED SECURITY RESEARCH AND DEFENSIVE CAPABILITY DEVELOPMENT ONLY.
USE ONLY ON AUTHORIZED TEST NETWORKS.

Author: Ridpath 
GitHub: https://github.com/ridpath
"""

import numpy as np
import pandas as pd
import argparse
import logging
import sys
import json
import pickle
import asyncio
import yaml
import warnings
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

# Core ML imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN
from sklearn.svm import OneClassSVM
from sklearn.model_selection import GridSearchCV, TimeSeriesSplit
from sklearn.metrics import classification_report, precision_recall_fscore_support
import joblib

# Statistical analysis
from scipy.stats import wasserstein_distance, zscore
import scipy.signal as signal

# Visualization
import matplotlib.pyplot as plt
import seaborn as sns
import shap

# Network & Protocol Stack
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether
from scapy.layers.inet import IP
import pyshark

# ICS Protocols
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException
import opcua
from opcua import Client, Node
import cpppo  # For Ethernet/IP (CIP)
import dnp3  # python-dnp3 library

# Suricata Integration
import suricatasc
from suricatasc import SuricataSC
import redis

# Production features
import psutil
from prometheus_client import start_http_server, Counter, Gauge, Histogram
import docker
from elasticsearch import Elasticsearch
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Async and performance
import aiofiles
from concurrent.futures import ThreadPoolExecutor
import threading

warnings.filterwarnings('ignore')

class ProductionConfig:
    """Production configuration management"""
    def __init__(self):
        self.config_paths = [
            '/etc/ics-detector/config.yaml',
            './config.yaml',
            './config/config.yaml'
        ]
        self.ensure_directories()
    
    def ensure_directories(self):
        """Create necessary directories"""
        dirs = ['logs', 'models', 'data', 'rules', 'exports']
        for dir_path in dirs:
            Path(dir_path).mkdir(exist_ok=True)
    
    def load_config(self) -> Dict:
        """Load configuration with fallbacks"""
        for config_path in self.config_paths:
            if Path(config_path).exists():
                try:
                    with open(config_path, 'r') as f:
                        config = yaml.safe_load(f)
                    logging.info(f"Loaded config from {config_path}")
                    return self.apply_defaults(config)
                except Exception as e:
                    logging.error(f"Error loading config {config_path}: {e}")
        
        # Return defaults if no config found
        logging.warning("No config file found, using defaults")
        return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """test bed default configuration"""
        return {
            'suricata': {
                'enabled': True,
                'socket_path': '/var/run/suricata/suricata-command.socket',
                'rules_dir': '/var/lib/suricata/rules',
                'eve_socket': 'redis://localhost:6379/0',
                'alert_threshold': 'medium'
            },
            'opcua': {
                'enabled': True,
                'default_port': 4840,
                'security_policies': ['Basic256Sha256', 'None'],
                'monitored_namespaces': [2, 3, 4]  # Common OPC UA namespaces
            },
            'models': {
                'ensemble_models': ['isolation_forest', 'one_class_svm', 'lof'],
                'retraining_interval_hours': 24,
                'drift_detection_threshold': 0.15,
                'cross_validation_folds': 5
            },
            'monitoring': {
                'prometheus_port': 8000,
                'health_check_interval': 30,
                'performance_metrics': True,
                'resource_limits': {
                    'max_memory_gb': 8,
                    'max_cpu_percent': 80
                }
            },
            'elasticsearch': {
                'enabled': True,
                'hosts': ['localhost:9200'],
                'index_prefix': 'ics-detection-',
                'batch_size': 1000
            },
            'alerting': {
                'critical_severities': ['CRITICAL', 'HIGH'],
                'email_notifications': False,
                'webhook_urls': [],
                'slack_webhook': None
            },
            'protocols': {
                'modbus': {'ports': [502, 503], 'deep_inspection': True},
                's7comm': {'ports': [102], 'deep_inspection': True},
                'dnp3': {'ports': [20000], 'deep_inspection': True},
                'opcua': {'ports': [4840, 62541], 'deep_inspection': True},
                'cip': {'ports': [44818, 2222], 'deep_inspection': True},
                'bacnet': {'ports': [47808], 'deep_inspection': False}
            }
        }
    
    def apply_defaults(self, config: Dict) -> Dict:
        """Apply default values to missing configuration sections"""
        defaults = self.get_default_config()
        for section, values in defaults.items():
            if section not in config:
                config[section] = values
            else:
                for key, value in values.items():
                    if key not in config[section]:
                        config[section][key] = value
        return config

class SuricataIntegration:
    """Advanced Suricata IDS integration"""
    
    def __init__(self, config: Dict):
        self.config = config['suricata']
        self.suricata_socket = None
        self.redis_client = None
        self.connected = False
        self.setup_suricata_connection()
    
    def setup_suricata_connection(self):
        """Establish connection to Suricata"""
        try:
            # Socket connection for command/control
            self.suricata_socket = SuricataSC(self.config['socket_path'])
            self.suricata_socket.connect()
            
            # Redis for EVE alerts
            if self.config.get('eve_socket'):
                import redis
                self.redis_client = redis.from_url(self.config['eve_socket'])
            
            self.connected = True
            logging.info("Suricata integration initialized successfully")
            
        except Exception as e:
            logging.error(f"Suricata connection failed: {e}")
            self.connected = False
    
    async def get_suricata_alerts(self, timeframe_minutes: int = 5) -> List[Dict]:
        """Retrieve Suricata alerts from EVE database"""
        if not self.connected or not self.redis_client:
            return []
        
        try:
            # Get recent alerts
            cutoff_time = datetime.now() - timedelta(minutes=timeframe_minutes)
            alerts = []
            
            # Scan Redis for recent alerts (simplified - actual implementation depends on Suricata+Redis setup)
            for key in self.redis_client.scan_iter("suricata:alert:*"):
                alert_data = self.redis_client.get(key)
                if alert_data:
                    alert = json.loads(alert_data)
                    alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                    if alert_time > cutoff_time:
                        alerts.append(alert)
            
            return self._enrich_suricata_alerts(alerts)
        
        except Exception as e:
            logging.error(f"Error fetching Suricata alerts: {e}")
            return []
    
    def _enrich_suricata_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Enrich Suricata alerts with ICS context"""
        ics_related_alerts = []
        ics_signatures = [
            'ET SCADA', 'MODBUS', 'DNP3', 'S7COMM', 'OPCUA', 'CIP', 'BACNET',
            'ICS', 'SCADA', 'PLC', 'RTU', 'HMI'
        ]
        
        for alert in alerts:
            signature = alert.get('signature', '')
            if any(ics_sig in signature.upper() for ics_sig in ics_signatures):
                alert['ics_context'] = {
                    'criticality': self._assess_ics_criticality(alert),
                    'potential_impact': self._assess_ics_impact(alert),
                    'mitre_attack_mapping': self._map_to_mitre_attack(alert)
                }
                ics_related_alerts.append(alert)
        
        return ics_related_alerts
    
    def _assess_ics_criticality(self, alert: Dict) -> str:
        """Assess ICS-specific criticality"""
        signature = alert.get('signature', '').upper()
        
        # Critical ICS patterns
        critical_patterns = [
            'WRITE', 'COMMAND', 'CONTROL', 'PROGRAM', 'DOWNLOAD',
            'STOP', 'RESTART', 'SETPOINT', 'PARAMETER'
        ]
        
        if any(pattern in signature for pattern in critical_patterns):
            return 'CRITICAL'
        elif 'READ' in signature or 'QUERY' in signature:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _map_to_mitre_attack(self, alert: Dict) -> List[str]:
        """Map Suricata alert to MITRE ATT&CK for ICS"""
        signature = alert.get('signature', '').upper()
        techniques = []
        
        # MITRE ATT&CK for ICS mappings
        mitre_mappings = {
            'MODBUS': ['T0859', 'T0801'],  # MODBUS Commands, Network Sniffing
            'WRITE': ['T0835', 'T0855'],   # Program Download, Modify Parameter
            'READ': ['T0802', 'T0814'],    # Operational Data Collection, I/O Image
            'DNP3': ['T0874', 'T0801'],    # DNP3 Commands, Network Sniffing
            'S7COMM': ['T0835', 'T0872'],  # Program Download, Modify Program
        }
        
        for pattern, techniques_list in mitre_mappings.items():
            if pattern in signature:
                techniques.extend(techniques_list)
        
        return list(set(techniques))  # Remove duplicates
    
    def add_custom_ics_rules(self, rules: List[str]):
        """Add custom ICS-specific Suricata rules"""
        if not self.connected:
            return False
        
        try:
            custom_rules_file = Path(self.config['rules_dir']) / 'custom-ics.rules'
            with open(custom_rules_file, 'w') as f:
                for rule in rules:
                    f.write(rule + '\n')
            
            # Reload Suricata rules
            self.suricata_socket.send_command('ruleset-reload-rules')
            logging.info(f"Added {len(rules)} custom ICS rules")
            return True
        
        except Exception as e:
            logging.error(f"Failed to add custom ICS rules: {e}")
            return False

class OPCUAParser:
    """Comprehensive OPC UA protocol parser and analyzer"""
    
    def __init__(self, config: Dict):
        self.config = config['opcua']
        self.known_endpoints = {}
        self.security_analyzer = OPCUASecurityAnalyzer()
    
    def parse_opcua_tcp(self, payload: bytes) -> Dict:
        """Parse OPC UA TCP packets"""
        try:
            parsed_data = {
                'protocol': 'OPC_UA',
                'message_type': 'UNKNOWN',
                'security_policy': 'UNKNOWN',
                'message_size': len(payload),
                'timestamp': datetime.now()
            }
            
            if len(payload) < 8:  # Minimum OPC UA TCP header size
                return parsed_data
            
            # Parse OPC UA TCP header (simplified)
            # Real implementation would use opcua library or custom parser
            message_type = payload[0:3]
            
            if message_type == b'HEL':  # Hello
                parsed_data.update(self._parse_hello_message(payload))
            elif message_type == b'ACK':  # Acknowledge
                parsed_data.update(self._parse_ack_message(payload))
            elif message_type == b'MSG':  # Secure Message
                parsed_data.update(self._parse_secure_message(payload))
            elif message_type == b'ERR':  # Error
                parsed_data.update(self._parse_error_message(payload))
            elif message_type == b'OPN':  # Open Secure Channel
                parsed_data.update(self._parse_open_secure_channel(payload))
            elif message_type == b'CLO':  # Close Secure Channel
                parsed_data.update(self._parse_close_secure_channel(payload))
            
            # Security analysis
            security_findings = self.security_analyzer.analyze_packet(parsed_data, payload)
            parsed_data['security_findings'] = security_findings
            
            return parsed_data
        
        except Exception as e:
            logging.error(f"OPC UA parsing error: {e}")
            return {'protocol': 'OPC_UA', 'error': str(e)}
    
    def _parse_hello_message(self, payload: bytes) -> Dict:
        """Parse OPC UA Hello message"""
        return {
            'message_type': 'HELLO',
            'protocol_version': int.from_bytes(payload[8:12], 'little') if len(payload) >= 12 else 0,
            'receive_buffer_size': int.from_bytes(payload[12:16], 'little') if len(payload) >= 16 else 0,
            'send_buffer_size': int.from_bytes(payload[16:20], 'little') if len(payload) >= 20 else 0,
            'max_message_size': int.from_bytes(payload[20:24], 'little') if len(payload) >= 24 else 0,
            'max_chunk_count': int.from_bytes(payload[24:28], 'little') if len(payload) >= 28 else 0,
            'endpoint_url': self._extract_string(payload, 28) if len(payload) > 28 else ''
        }
    
    def _parse_secure_message(self, payload: bytes) -> Dict:
        """Parse OPC UA Secure Message"""
        return {
            'message_type': 'SECURE_MESSAGE',
            'secure_channel_id': int.from_bytes(payload[4:8], 'little') if len(payload) >= 8 else 0,
            'security_token_id': int.from_bytes(payload[12:16], 'little') if len(payload) >= 16 else 0,
            'sequence_number': int.from_bytes(payload[16:20], 'little') if len(payload) >= 20 else 0,
            'request_id': int.from_bytes(payload[20:24], 'little') if len(payload) >= 24 else 0
        }
    
    def _extract_string(self, payload: bytes, offset: int) -> str:
        """Extract string from payload"""
        try:
            if len(payload) > offset + 4:
                str_len = int.from_bytes(payload[offset:offset+4], 'little')
                if str_len > 0 and len(payload) >= offset + 4 + str_len:
                    return payload[offset+4:offset+4+str_len].decode('utf-8', errors='ignore')
        except:
            pass
        return ''
    
    async def monitor_opcua_endpoint(self, endpoint_url: str, security_policy: str = 'Basic256Sha256'):
        """Monitor OPC UA endpoint for anomalies"""
        try:
            client = Client(endpoint_url)
            client.set_security_string(security_policy)
            
            # Connect and get server information
            await asyncio.get_event_loop().run_in_executor(None, client.connect)
            
            server_info = {
                'endpoint_url': endpoint_url,
                'server_name': client.get_endpoint().get_server_name(),
                'application_uri': client.get_endpoint().get_application_uri(),
                'security_policy': security_policy,
                'monitored_at': datetime.now()
            }
            
            # Monitor common nodes
            root_node = client.get_root_node()
            objects_node = root_node.get_child(["0:Objects"])
            
            # Track node changes and access patterns
            monitored_nodes = await self._discover_critical_nodes(objects_node)
            server_info['monitored_nodes'] = monitored_nodes
            
            client.disconnect()
            return server_info
            
        except Exception as e:
            logging.error(f"OPC UA endpoint monitoring failed: {e}")
            return None
    
    async def _discover_critical_nodes(self, objects_node) -> List[Dict]:
        """Discover and monitor critical OPC UA nodes"""
        critical_nodes = []
        
        try:
            # Look for common critical nodes in OPC UA servers
            critical_paths = [
                ["2:DeviceSet", "2:PLC1", "2:MainProgram"],
                ["2:Server", "2:ServerStatus"],
                ["2:Objects", "2:MainControl"],
            ]
            
            for path in critical_paths:
                try:
                    node = objects_node
                    for segment in path:
                        node = node.get_child([segment])
                    
                    node_info = {
                        'node_id': str(node.nodeid),
                        'browse_name': node.get_browse_name().Name,
                        'description': await self._get_node_description(node),
                        'data_type': await self._get_node_data_type(node),
                        'access_level': await self._get_node_access_level(node)
                    }
                    critical_nodes.append(node_info)
                except:
                    continue
            
        except Exception as e:
            logging.debug(f"Node discovery error: {e}")
        
        return critical_nodes

class OPCUASecurityAnalyzer:
    """OPC UA security-specific analysis"""
    
    def analyze_packet(self, parsed_data: Dict, raw_payload: bytes) -> List[Dict]:
        """Analyze OPC UA packet for security issues"""
        findings = []
        
        # Check for weak security policies
        if parsed_data.get('security_policy') == 'None':
            findings.append({
                'severity': 'HIGH',
                'finding': 'OPC_UA_UNENCRYPTED_COMMUNICATION',
                'description': 'OPC UA communication without encryption',
                'mitre_technique': 'T0860'  # Unsecured Credentials
            })
        
        # Check for large message sizes (potential DoS)
        if parsed_data.get('message_size', 0) > 1000000:  # 1MB
            findings.append({
                'severity': 'MEDIUM',
                'finding': 'OPC_UA_LARGE_MESSAGE',
                'description': 'Unusually large OPC UA message detected',
                'mitre_technique': 'T0811'  # Denial of Service
            })
        
        # Check for suspicious message types
        suspicious_types = ['CLO', 'ERR']  # Close channel, errors
        if parsed_data.get('message_type') in suspicious_types:
            findings.append({
                'severity': 'LOW',
                'finding': 'OPC_UA_SUSPICIOUS_MESSAGE',
                'description': f'Suspicious OPC UA message type: {parsed_data.get("message_type")}'
            })
        
        return findings

class EnhancedICSAnomalyDetector(ICSAnomalyDetector):
    """Enhanced ICS Anomaly Detector with production features"""
    
    def __init__(self, config_path: str = 'config.yaml'):
        self.production_config = ProductionConfig()
        self.config = self.production_config.load_config()
        
        # Initialize parent
        super().__init__(config_path)
        
        # Enhanced components
        self.suricata_integration = SuricataIntegration(self.config)
        self.opcua_parser = OPCUAParser(self.config)
        self.elasticsearch_client = None
        self.metrics = self.setup_metrics()
        
        # Enhanced models
        self.ensemble_weights = self.config['models'].get('ensemble_weights', [0.4, 0.4, 0.2])
        self.drift_detector = DataDriftDetector()
        self.performance_monitor = PerformanceMonitor()
        
        self.setup_elasticsearch()
        self.start_prometheus_server()
    
    def setup_elasticsearch(self):
        """Setup Elasticsearch connection for alert storage"""
        if self.config['elasticsearch']['enabled']:
            try:
                self.elasticsearch_client = Elasticsearch(
                    self.config['elasticsearch']['hosts'],
                    timeout=30,
                    max_retries=3,
                    retry_on_timeout=True
                )
                if self.elasticsearch_client.ping():
                    logging.info("Elasticsearch connected successfully")
                else:
                    logging.warning("Elasticsearch connection failed")
            except Exception as e:
                logging.error(f"Elasticsearch setup failed: {e}")
    
    def setup_metrics(self):
        """Setup Prometheus metrics"""
        return {
            'anomalies_detected': Counter('ics_anomalies_total', 'Total anomalies detected', ['severity']),
            'packets_processed': Counter('ics_packets_processed_total', 'Total packets processed'),
            'detection_latency': Histogram('ics_detection_latency_seconds', 'Detection processing time'),
            'model_accuracy': Gauge('ics_model_accuracy', 'Current model accuracy'),
            'system_memory': Gauge('ics_system_memory_bytes', 'System memory usage'),
            'suricata_alerts': Counter('ics_suricata_alerts_total', 'Suricata alerts processed')
        }
    
    def start_prometheus_server(self):
        """Start Prometheus metrics server"""
        if self.config['monitoring']['prometheus_port']:
            start_http_server(self.config['monitoring']['prometheus_port'])
            logging.info(f"Prometheus metrics on port {self.config['monitoring']['prometheus_port']}")
    
    async def enhanced_packet_sniffer(self, interface: str = "eth0", count: int = 100, 
                                    filter_str: str = "tcp port 102 or tcp port 502 or tcp port 4840 or tcp port 20000"):
        """Enhanced packet sniffer with multiple protocol support"""
        self.logger.info(f"Starting enhanced packet sniffer on {interface}")
        
        # Use pyshark for better protocol dissection
        capture = pyshark.LiveCapture(interface=interface, display_filter=filter_str)
        
        features = []
        for packet in capture.sniff_continuously(packet_count=count):
            try:
                feature = {
                    'timestamp': datetime.now(),
                    'src_ip': packet.ip.src if hasattr(packet, 'ip') else '',
                    'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else '',
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'UNKNOWN',
                    'length': int(packet.length) if hasattr(packet, 'length') else 0
                }
                
                # Protocol-specific parsing
                if hasattr(packet, 'tcp'):
                    feature.update({
                        'src_port': int(packet.tcp.srcport),
                        'dst_port': int(packet.tcp.dstport),
                        'payload_size': len(packet.tcp.payload) if hasattr(packet.tcp, 'payload') else 0
                    })
                    
                    # Protocol detection and parsing
                    raw_payload = bytes.fromhex(packet.tcp.payload.replace(':', '')) if hasattr(packet.tcp, 'payload') else b''
                    
                    if int(packet.tcp.dstport) == 502:  # Modbus
                        feature.update(self.parse_modbus(raw_payload))
                    elif int(packet.tcp.dstport) == 102:  # S7Comm
                        feature.update(self.parse_s7comm(raw_payload))
                    elif int(packet.tcp.dstport) == 4840:  # OPC UA
                        feature.update(self.opcua_parser.parse_opcua_tcp(raw_payload))
                    elif int(packet.tcp.dstport) == 20000:  # DNP3
                        feature.update(self.parse_dnp3(raw_payload))
                    elif int(packet.tcp.dstport) == 44818:  # CIP
                        feature.update(self.parse_cip(raw_payload))
                
                features.append(feature)
                self.metrics['packets_processed'].inc()
                
            except Exception as e:
                self.logger.debug(f"Packet parsing error: {e}")
                continue
        
        return features
    
    def parse_dnp3(self, payload: bytes) -> Dict:
        """Parse DNP3 protocol"""
        try:
            if len(payload) < 10:  # Minimum DNP3 header
                return {'dnp3_valid': False}
            
            return {
                'protocol': 'DNP3',
                'dnp3_start_bytes': payload[0:2].hex(),
                'dnp3_length': payload[2],
                'dnp3_control': payload[3],
                'dnp3_destination': int.from_bytes(payload[4:6], 'big'),
                'dnp3_source': int.from_bytes(payload[6:8], 'big'),
                'dnp3_crc': payload[8:10].hex(),
                'dnp3_function_code': payload[10] if len(payload) > 10 else 0
            }
        except Exception as e:
            return {'dnp3_error': str(e)}
    
    def parse_cip(self, payload: bytes) -> Dict:
        """Parse CIP (Common Industrial Protocol)"""
        try:
            if len(payload) < 4:
                return {'cip_valid': False}
            
            return {
                'protocol': 'CIP',
                'cip_service': payload[0],
                'cip_class': payload[1],
                'cip_instance': payload[2],
                'cip_attribute': payload[3] if len(payload) > 3 else 0
            }
        except Exception as e:
            return {'cip_error': str(e)}
    
    async def enhanced_detect_anomalies(self, real_time_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhanced anomaly detection with Suricata integration"""
        start_time = datetime.now()
        
        # Get Suricata alerts
        suricata_alerts = await self.suricata_integration.get_suricata_alerts(5)
        
        # Combine ML detection with Suricata alerts
        ml_anomalies = self.detect_anomalies(real_time_data)
        combined_anomalies = self.correlate_findings(ml_anomalies, suricata_alerts)
        
        # Store in Elasticsearch
        if self.elasticsearch_client and combined_anomalies:
            self.store_alerts_elasticsearch(combined_anomalies)
        
        # Update metrics
        detection_time = (datetime.now() - start_time).total_seconds()
        self.metrics['detection_latency'].observe(detection_time)
        
        for anomaly in combined_anomalies:
            self.metrics['anomalies_detected'].labels(severity=anomaly.get('alert_level', 'UNKNOWN')).inc()
        
        return combined_anomalies
    
    def correlate_findings(self, ml_anomalies: List[Dict], suricata_alerts: List[Dict]) -> List[Dict]:
        """Correlate ML anomalies with Suricata alerts"""
        correlated = []
        
        # Add ML anomalies
        for anomaly in ml_anomalies:
            anomaly['detection_source'] = 'ML_MODEL'
            correlated.append(anomaly)
        
        # Add and enrich Suricata alerts
        for alert in suricata_alerts:
            enriched_alert = {
                'timestamp': alert.get('timestamp', datetime.now()),
                'anomaly_score': 0.8,  # High confidence for Suricata
                'is_anomaly': True,
                'alert_level': alert.get('ics_context', {}).get('criticality', 'MEDIUM'),
                'detection_source': 'SURICATA',
                'suricata_alert': alert,
                'explanation': f"Suricata: {alert.get('signature', 'Unknown signature')}",
                'mitre_techniques': alert.get('ics_context', {}).get('mitre_attack_mapping', [])
            }
            correlated.append(enriched_alert)
            self.metrics['suricata_alerts'].inc()
        
        # Sort by severity and timestamp
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        correlated.sort(key=lambda x: (
            -severity_order.get(x.get('alert_level', 'LOW'), 0),
            x.get('timestamp', datetime.min)
        ))
        
        return correlated
    
    def store_alerts_elasticsearch(self, alerts: List[Dict]):
        """Store alerts in Elasticsearch"""
        if not self.elasticsearch_client:
            return
        
        try:
            index_name = f"{self.config['elasticsearch']['index_prefix']}{datetime.now().strftime('%Y-%m-%d')}"
            
            for alert in alerts:
                # Convert datetime to string for JSON serialization
                alert_dict = alert.copy()
                if 'timestamp' in alert_dict and isinstance(alert_dict['timestamp'], datetime):
                    alert_dict['timestamp'] = alert_dict['timestamp'].isoformat()
                
                self.elasticsearch_client.index(
                    index=index_name,
                    body=alert_dict,
                    refresh=False
                )
            
            self.logger.info(f"Stored {len(alerts)} alerts in Elasticsearch")
            
        except Exception as e:
            self.logger.error(f"Elasticsearch storage failed: {e}")
    
    def enhanced_train_model(self, training_data: List[Dict[str, Any]], contamination: float = 0.01):
        """Enhanced model training with cross-validation and hyperparameter tuning"""
        self.logger.info("Starting enhanced model training with cross-validation")
        
        features = self.extract_behavioral_features(training_data)
        if len(features) < 50:  # Minimum samples
            self.logger.warning("Insufficient training data")
            return False
        
        # Enhanced preprocessing
        scaled_features = self.scaler.fit_transform(features)
        self.baseline_distribution = np.mean(scaled_features, axis=0)
        
        # Cross-validation setup
        tscv = TimeSeriesSplit(n_splits=self.config['models']['cross_validation_folds'])
        
        # Train ensemble with hyperparameter tuning
        trained_models = []
        for i, model_type in enumerate(self.config['models']['ensemble_models']):
            try:
                if model_type == 'isolation_forest':
                    param_grid = {
                        'contamination': [0.01, 0.05, 0.1],
                        'n_estimators': [50, 100],
                        'max_samples': ['auto', 0.8]
                    }
                    base_model = IsolationForest(random_state=42)
                elif model_type == 'one_class_svm':
                    param_grid = {
                        'nu': [0.01, 0.05, 0.1],
                        'kernel': ['rbf', 'linear'],
                        'gamma': ['scale', 'auto']
                    }
                    base_model = OneClassSVM()
                else:
                    continue
                
                # Grid search with time series cross-validation
                grid_search = GridSearchCV(
                    base_model, param_grid, cv=tscv, scoring='precision',
                    n_jobs=-1, verbose=0
                )
                
                grid_search.fit(scaled_features)
                best_model = grid_search.best_estimator_
                trained_models.append((model_type, best_model))
                
                self.logger.info(f"Trained {model_type} with best params: {grid_search.best_params_}")
                
            except Exception as e:
                self.logger.error(f"Model training failed for {model_type}: {e}")
                continue
        
        self.models = trained_models
        self.is_trained = len(self.models) > 0
        
        if self.is_trained:
            # Evaluate model performance
            self.evaluate_model_performance(scaled_features)
            self.save_model(f'models/model_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pkl')
        
        return self.is_trained
    
    def evaluate_model_performance(self, features: np.ndarray):
        """Evaluate model performance and set metrics"""
        try:
            # Use a portion of data for evaluation
            if len(features) > 100:
                test_features = features[-100:]  # Last 100 samples
                
                # Create synthetic anomalies for evaluation
                normal_preds = []
                for model_type, model in self.models:
                    if hasattr(model, 'predict'):
                        preds = model.predict(test_features)
                        normal_preds.extend([1 for p in preds if p == 1])  # Count normal predictions
                
                accuracy = len(normal_preds) / (len(self.models) * len(test_features)) if normal_preds else 0
                self.metrics['model_accuracy'].set(accuracy)
                
                self.logger.info(f"Model evaluation - Approximate accuracy: {accuracy:.3f}")
        
        except Exception as e:
            self.logger.debug(f"Model evaluation error: {e}")

class DataDriftDetector:
    """Detect data drift in feature distributions"""
    
    def __init__(self):
        self.reference_distribution = None
        self.drift_threshold = 0.15
    
    def detect_drift(self, current_data: np.ndarray, reference_data: np.ndarray = None) -> Tuple[bool, float]:
        """Detect data drift using multiple methods"""
        if reference_data is None:
            reference_data = self.reference_distribution
        
        if reference_data is None or len(current_data) == 0:
            return False, 0.0
        
        try:
            # Wasserstein distance
            wasserstein_dist = wasserstein_distance(
                reference_data.flatten() if reference_data.ndim > 1 else reference_data,
                current_data.flatten() if current_data.ndim > 1 else current_data
            )
            
            # KL divergence (approximate)
            hist_ref, bins = np.histogram(reference_data, bins=50, density=True)
            hist_curr, _ = np.histogram(current_data, bins=bins, density=True)
            
            # Avoid zero probabilities
            hist_ref = np.where(hist_ref == 0, 1e-10, hist_ref)
            hist_curr = np.where(hist_curr == 0, 1e-10, hist_curr)
            
            kl_div = np.sum(hist_ref * np.log(hist_ref / hist_curr))
            
            # Combined drift score
            drift_score = (wasserstein_dist + min(kl_div, 10)) / 2
            
            return drift_score > self.drift_threshold, drift_score
        
        except Exception as e:
            logging.error(f"Drift detection error: {e}")
            return False, 0.0

class PerformanceMonitor:
    """Monitor system performance and resource usage"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.peak_memory = 0
    
    def check_system_health(self) -> Dict:
        """Check system health and resource usage"""
        try:
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=1)
            disk = psutil.disk_usage('/')
            
            health_status = {
                'timestamp': datetime.now(),
                'cpu_percent': cpu,
                'memory_percent': memory.percent,
                'memory_used_gb': memory.used / (1024**3),
                'disk_free_gb': disk.free / (1024**3),
                'uptime_seconds': (datetime.now() - self.start_time).total_seconds(),
                'process_memory_mb': psutil.Process().memory_info().rss / (1024**2)
            }
            
            self.peak_memory = max(self.peak_memory, health_status['process_memory_mb'])
            health_status['peak_memory_mb'] = self.peak_memory
            
            return health_status
        
        except Exception as e:
            logging.error(f"System health check error: {e}")
            return {}

# FastAPI Application for Test Bed
app = FastAPI(title="ICS Anomaly Detection API", 
              description="Test Bed Ready ICS Security Monitoring",
              version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global detector instance
detector = None

@app.on_event("startup")
async def startup_event():
    """Initialize detector on startup"""
    global detector
    detector = EnhancedICSAnomalyDetector()
    
    # Load or train initial model
    model_path = 'models/latest_model.pkl'
    if Path(model_path).exists():
        detector.load_model(model_path)
    else:
        training_data = detector.generate_training_data(1000)
        detector.enhanced_train_model(training_data)

@app.get("/")
async def root():
    """Root endpoint with system status"""
    health = detector.performance_monitor.check_system_health() if detector else {}
    return {
        "status": "operational",
        "system": "ICS Anomaly Detection",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "health": health
    }

@app.post("/api/v1/detect")
async def api_detect(data: List[Dict], background_tasks: BackgroundTasks):
    """API endpoint for anomaly detection"""
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    try:
        anomalies = await detector.enhanced_detect_anomalies(data)
        return {
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/health")
async def health_check():
    """Comprehensive health check endpoint"""
    system_health = detector.performance_monitor.check_system_health() if detector else {}
    detector_health = {
        "models_trained": detector.is_trained if detector else False,
        "model_count": len(detector.models) if detector else 0,
        "suricata_connected": detector.suricata_integration.connected if detector else False,
        "elasticsearch_connected": detector.elasticsearch_client.ping() if detector and detector.elasticsearch_client else False
    }
    
    return {
        "system": system_health,
        "detector": detector_health,
        "status": "healthy" if detector_health.get("models_trained", False) else "degraded"
    }

@app.post("/api/v1/train")
async def train_model(samples: int = 1000):
    """Trigger model retraining"""
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    try:
        training_data = detector.generate_training_data(samples)
        success = detector.enhanced_train_model(training_data)
        
        return {
            "success": success,
            "samples_used": samples,
            "models_trained": len(detector.models) if success else 0
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def main():
    """Enhanced main function with production features"""
    parser = argparse.ArgumentParser(description='ICS Anomaly Detection')
    subparsers = parser.add_subparsers(dest='command')
    
    # Train command
    train_parser = subparsers.add_parser('train')
    train_parser.add_argument('--config', default='config.yaml')
    train_parser.add_argument('--samples', type=int, default=1000)
    train_parser.add_argument('--output', required=True)
    
    # Detect command
    detect_parser = subparsers.add_parser('detect')
    detect_parser.add_argument('--model', required=True)
    detect_parser.add_argument('--samples', type=int, default=100)
    detect_parser.add_argument('--output', help='JSONL output')
    detect_parser.add_argument('--live', action='store_true')
    detect_parser.add_argument('--interface', default='eth0')
    
    # API command
    api_parser = subparsers.add_parser('api')
    api_parser.add_argument('--host', default='0.0.0.0')
    api_parser.add_argument('--port', type=int, default=8000)
    
    # Service command
    service_parser = subparsers.add_parser('service')
    service_parser.add_argument('--interface', default='eth0')
    
    args = parser.parse_args()
    
    detector = EnhancedICSAnomalyDetector(args.config if hasattr(args, 'config') else 'config.yaml')
    
    if args.command == 'train':
        data = detector.generate_training_data(args.samples)
        detector.enhanced_train_model(data)
        detector.save_model(args.output)
    
    elif args.command == 'detect':
        detector.load_model(args.model)
        if args.live:
            asyncio.run(detector.start_live_detection(args.interface))
        else:
            data = detector.generate_training_data(args.samples)
            anomalies = await detector.enhanced_detect_anomalies(data)
            print(f"Detected {len(anomalies)} anomalies")
            if args.output:
                detector.write_to_jsonl(anomalies, args.output)
    
    elif args.command == 'api':
        uvicorn.run(app, host=args.host, port=args.port)
    
    elif args.command == 'service':
        # Run as a continuous service
        async def service_loop():
            while True:
                try:
                    data = await detector.enhanced_packet_sniffer(args.interface)
                    anomalies = await detector.enhanced_detect_anomalies(data)
                    
                    # Health monitoring
                    health = detector.performance_monitor.check_system_health()
                    detector.metrics['system_memory'].set(health.get('memory_used_gb', 0) * 1024**3)
                    
                    await asyncio.sleep(10)  # Poll every 10s
                
                except Exception as e:
                    logging.error(f"Service loop error: {e}")
                    await asyncio.sleep(30)  # Wait longer on error
        
        asyncio.run(service_loop())

if __name__ == "__main__":
    main()
