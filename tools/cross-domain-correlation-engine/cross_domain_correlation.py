#!/usr/bin/env python3
"""
cross_domain_correlation.py
Cross-Domain Correlation Engine for IT/OT Security
Author: Ridpath
GitHub: https://github.com/ridpath

DISCLAIMER:
FOR AUTHORIZED SECURITY RESEARCH AND DEFENSIVE CAPABILITY DEVELOPMENT ONLY.

Purpose:
Advanced correlation engine that detects multi-stage attacks across IT and OT
boundaries by correlating events from multiple sources and protocols.

"""

import time
import json
import argparse
import logging
import sys
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import threading
from collections import defaultdict, deque
from elasticsearch import Elasticsearch
import yaml
from flask import Flask, request, jsonify
import requests
from sklearn.ensemble import IsolationForest
import numpy as np
import geoip2.database
import geoip2.errors

@dataclass
class SecurityEvent:
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    event_type: str
    severity: str
    details: Dict[str, Any]
    source_domain: str
    geo_country: Optional[str] = None
    geo_org: Optional[str] = None
    asset_type: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)

class CrossDomainCorrelator:
    def __init__(self, correlation_rules_file: str = None, es_host: str = None, 
                 email_config: Dict[str, str] = None, geoip_db: str = 'GeoLite2-City.mmdb'):
        self.correlation_rules = self.load_correlation_rules(correlation_rules_file)
        self.event_buffer = deque(maxlen=10000)
        self.historical_buffer = deque(maxlen=100000)
        self.correlation_window = 300
        self.active_correlations = {}
        self.es = Elasticsearch(es_host) if es_host else None
        self.email_config = email_config
        self.geoip_reader = geoip2.database.Reader(geoip_db) if os.path.exists(geoip_db) else None
        
        self.asset_database = self.load_asset_database()
        self.anomaly_model = IsolationForest(contamination=0.1, random_state=42)
        self.ip_behavior_history = defaultdict(list)
        self.setup_logging()
        
        self.running = True
        self.correlation_thread = threading.Thread(target=self.continuous_correlation)
        self.correlation_thread.daemon = True
        self.correlation_thread.start()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - CROSS_DOMAIN_CORRELATOR - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cross_domain_correlation.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('CrossDomainCorrelator')
    
    def load_asset_database(self) -> Dict[str, Dict]:
        asset_db = {
            '192.168.2.50': {'type': 'PLC', 'vulnerabilities': ['CVE-2023-1234']},
            '192.168.2.100': {'type': 'HMI', 'vulnerabilities': ['CVE-2022-5678']},
        }
        try:
            if os.path.exists('assets.yaml'):
                with open('assets.yaml', 'r') as f:
                    loaded_assets = yaml.safe_load(f)
                    asset_db.update(loaded_assets)
        except Exception as e:
            self.logger.error(f"Failed to load asset database: {e}")
        return asset_db
    
    def load_correlation_rules(self, rules_file: str = None) -> List[Dict[str, Any]]:
        if rules_file and os.path.exists(rules_file):
            try:
                if rules_file.endswith(('.yaml', '.yml')):
                    with open(rules_file, 'r') as f:
                        return yaml.safe_load(f)
                else:
                    with open(rules_file, 'r') as f:
                        return json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load rules file: {e}")
        
        default_rules = [
            {
                'name': 'IT_to_OT_Lateral_Movement',
                'description': 'Detect lateral movement from IT to OT networks',
                'conditions': [
                    {'field': 'source_ip', 'operator': 'in', 'value': ['192.168.1.0/24']},
                    {'field': 'destination_ip', 'operator': 'in', 'value': ['192.168.2.0/24']},
                    {'field': 'protocol', 'operator': 'equals', 'value': 'RDP'}
                ],
                'time_window': 300,
                'threshold': 1,
                'confidence': 0.85,
                'action': 'Isolate source IP and alert SOC',
                'severity': 'HIGH'
            },
            {
                'name': 'Multiple_Protocol_Reconnaissance',
                'description': 'Detect reconnaissance across multiple ICS protocols',
                'conditions': [
                    {'field': 'source_ip', 'operator': 'equals', 'value': 'current_event_source'},
                    {'field': 'protocol', 'operator': 'in', 'value': ['S7COMM', 'CIP', 'OPCUA']}
                ],
                'time_window': 300,
                'threshold': 3,
                'confidence': 0.90,
                'action': 'Block source IP and initiate forensic analysis',
                'severity': 'HIGH'
            },
            {
                'name': 'Vendor_Tool_Abuse',
                'description': 'Detect abnormal use of engineering tools',
                'conditions': [
                    {'field': 'event_type', 'operator': 'equals', 'value': 'Engineering_Software_Execution'},
                    {'field': 'timestamp', 'operator': 'outside_hours', 'value': {'start': '08:00', 'end': '17:00'}},
                    {'field': 'source_ip', 'operator': 'not_in', 'value': ['192.168.1.50', '192.168.1.51']}
                ],
                'time_window': 3600,
                'threshold': 1,
                'confidence': 0.75,
                'action': 'Investigate user activity and verify authorization',
                'severity': 'MEDIUM'
            },
            {
                'name': 'Safety_System_Anomaly',
                'description': 'Detect safety system manipulation',
                'conditions': [
                    {'field': 'protocol', 'operator': 'equals', 'value': 'TRITON'},
                    {'field': 'event_type', 'operator': 'equals', 'value': 'Safety_Program_Modification'}
                ],
                'time_window': 60,
                'threshold': 1,
                'confidence': 0.95,
                'action': 'Immediate safety system validation and operator alert',
                'severity': 'CRITICAL'
            },
            {
                'name': 'PLC_Stop_Command_From_IT',
                'description': 'Detect PLC stop commands originating from IT network',
                'conditions': [
                    {'field': 'source_domain', 'operator': 'equals', 'value': 'IT'},
                    {'field': 'event_type', 'operator': 'equals', 'value': 'PLC_Stop_Command'}
                ],
                'time_window': 60,
                'threshold': 1,
                'confidence': 0.80,
                'action': 'Block command and investigate source',
                'severity': 'HIGH'
            }
        ]
        
        self.logger.info("Loaded correlation rules")
        return default_rules
    
    def enrich_event(self, event: SecurityEvent):
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(event.source_ip)
                event.geo_country = response.country.name
                event.geo_org = response.traits.organization
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass
        
        asset = self.asset_database.get(event.destination_ip)
        if asset:
            event.asset_type = asset['type']
            event.vulnerabilities = asset.get('vulnerabilities', [])
    
    def add_event(self, event: SecurityEvent):
        self.enrich_event(event)
        self.event_buffer.append(event)
        self.historical_buffer.append(event)
        self.logger.debug(f"Added event: {event.source_ip} -> {event.destination_ip} [{event.protocol}]")
        
        if event.severity in ['HIGH', 'CRITICAL']:
            self.correlate_events_immediate(event)
    
    def correlate_events_immediate(self, trigger_event: SecurityEvent):
        correlations = []
        
        for rule in self.correlation_rules:
            if 'depends_on' in rule:
                if rule['depends_on'] not in self.active_correlations:
                    continue
            
            if self.rule_matches(rule, trigger_event):
                correlated_events = self.find_correlated_events(rule, trigger_event)
                if correlated_events and len(correlated_events) >= rule.get('threshold', 1):
                    correlation = self.create_correlation_alert(rule, trigger_event, correlated_events)
                    correlations.append(correlation)
                    
                    self.logger.warning(
                        f"Correlation detected: {rule['name']} - "
                        f"Source: {trigger_event.source_ip} - "
                        f"Confidence: {rule['confidence']}"
                    )
        
        return correlations
    
    def continuous_correlation(self):
        last_status_time = time.time()
        while self.running:
            try:
                self.perform_periodic_correlation()
                current_time = time.time()
                if current_time - last_status_time >= 30:
                    self.print_status()
                    last_status_time = current_time
                time.sleep(30)
            except Exception as e:
                self.logger.error(f"Continuous correlation error: {e}")
                time.sleep(60)
    
    def perform_periodic_correlation(self):
        current_time = time.time()
        
        while (self.event_buffer and 
               current_time - self.event_buffer[0].timestamp > self.correlation_window):
            self.event_buffer.popleft()
        
        events_by_ip = defaultdict(list)
        for event in self.event_buffer:
            events_by_ip[event.source_ip].append(event)
        
        for source_ip, events in events_by_ip.items():
            self.analyze_ip_behavior(source_ip, events)
    
    def analyze_ip_behavior(self, source_ip: str, events: List[SecurityEvent]):
        protocol_counts = defaultdict(int)
        domain_access = defaultdict(int)
        event_types = defaultdict(int)
        
        for event in events:
            protocol_counts[event.protocol] += 1
            domain_access[event.source_domain] += 1
            event_types[event.event_type] += 1
        
        if len(protocol_counts) >= 3:
            self.logger.warning(
                f"Multi-protocol activity detected from {source_ip}: "
                f"{dict(protocol_counts)}"
            )
        
        if 'IT' in domain_access and 'OT' in domain_access:
            self.logger.warning(
                f"Cross-domain movement detected from {source_ip}: "
                f"IT events: {domain_access['IT']}, OT events: {domain_access['OT']}"
            )
        
        suspicious_events = ['PLC_Stop_Command', 'Safety_Modification', 'Logic_Download']
        for event_type in suspicious_events:
            if event_type in event_types:
                self.logger.warning(
                    f"Suspicious event type from {source_ip}: "
                    f"{event_type} count: {event_types[event_type]}"
                )
        
        self.update_anomaly_model(source_ip, len(protocol_counts), len(events), len(domain_access) > 1)
    
    def update_anomaly_model(self, source_ip: str, protocol_count: int, event_volume: int, cross_domain: bool):
        features = [protocol_count, event_volume, 1 if cross_domain else 0]
        self.ip_behavior_history[source_ip].append(features)
        
        if len(self.ip_behavior_history[source_ip]) > 10:
            data = np.array(self.ip_behavior_history[source_ip])
            self.anomaly_model.fit(data)
            score = self.anomaly_model.decision_function([features])[0]
            if score < 0:
                self.logger.warning(f"Anomaly detected for {source_ip}: score={score}, features={features}")
    
    def rule_matches(self, rule: Dict[str, Any], event: SecurityEvent) -> bool:
        for condition in rule.get('conditions', []):
            field = condition['field']
            operator = condition['operator']
            value = condition['value']
            
            if value == 'current_event_source':
                value = event.source_ip
            
            if hasattr(event, field):
                field_value = getattr(event, field)
            elif field in event.details:
                field_value = event.details[field]
            else:
                return False
            
            if operator == 'equals' and field_value != value:
                return False
            elif operator == 'not_equals' and field_value == value:
                return False
            elif operator == 'in' and field_value not in value:
                return False
            elif operator == 'not_in' and field_value in value:
                return False
            elif operator == 'contains' and value not in str(field_value):
                return False
            elif operator == 'greater_than' and field_value <= value:
                return False
            elif operator == 'less_than' and field_value >= value:
                return False
            elif operator == 'outside_hours' and self.is_within_hours(field_value, value):
                return False
        
        return True
    
    def is_within_hours(self, timestamp: float, hours_config: Dict[str, str]) -> bool:
        try:
            event_time = datetime.fromtimestamp(timestamp)
            start_time = datetime.strptime(hours_config['start'], '%H:%M').time()
            end_time = datetime.strptime(hours_config['end'], '%H:%M').time()
            
            event_time_only = event_time.time()
            
            if start_time <= end_time:
                return start_time <= event_time_only <= end_time
            else:
                return event_time_only >= start_time or event_time_only <= end_time
                
        except Exception as e:
            self.logger.error(f"Error checking hours: {e}")
            return True
    
    def find_correlated_events(self, rule: Dict[str, Any], trigger_event: SecurityEvent) -> List[SecurityEvent]:
        correlated_events = []
        time_window = rule.get('time_window', 300)
        
        for event in self.event_buffer:
            if abs(event.timestamp - trigger_event.timestamp) > time_window:
                continue
            
            if event != trigger_event and self.rule_matches(rule, event):
                correlated_events.append(event)
        
        return correlated_events
    
    def create_correlation_alert(self, rule: Dict[str, Any], trigger_event: SecurityEvent, 
                               correlated_events: List[SecurityEvent]) -> Dict[str, Any]:
        alert = {
            'timestamp': time.time(),
            'rule_name': rule['name'],
            'rule_description': rule['description'],
            'trigger_event': {
                'source_ip': trigger_event.source_ip,
                'destination_ip': trigger_event.destination_ip,
                'protocol': trigger_event.protocol,
                'event_type': trigger_event.event_type,
                'timestamp': trigger_event.timestamp
            },
            'correlated_events_count': len(correlated_events),
            'correlated_events': [
                {
                    'source_ip': event.source_ip,
                    'protocol': event.protocol,
                    'event_type': event.event_type,
                    'timestamp': event.timestamp
                } for event in correlated_events[:10]
            ],
            'confidence_score': rule['confidence'],
            'severity': rule.get('severity', 'MEDIUM'),
            'recommended_action': rule['action'],
            'time_window': rule.get('time_window', 300)
        }
        
        self.active_correlations[rule['name']] = time.time()
        
        if self.es:
            self.log_to_elasticsearch(alert)
        
        if self.email_config:
            self.notify_email(alert)
        
        return alert
    
    def log_to_elasticsearch(self, alert: Dict[str, Any]):
        try:
            self.es.index(index='cross-domain-alerts', document=alert)
            self.logger.info("Alert indexed in Elasticsearch")
        except Exception as e:
            self.logger.error(f"Failed to log to Elasticsearch: {e}")
    
    def notify_email(self, alert: Dict[str, Any]):
        if not self.email_config:
            return
            
        try:
            message = MIMEMultipart()
            message['From'] = self.email_config['from_addr']
            message['To'] = ', '.join(self.email_config['to_addrs'])
            message['Subject'] = f"SECURITY ALERT: {alert['rule_name']} - {alert['severity']}"
            
            body = f"""
Cross-Domain Security Correlation Alert

Rule: {alert['rule_name']}
Description: {alert['rule_description']}
Severity: {alert['severity']}
Confidence: {alert['confidence_score']}
Timestamp: {datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}

Trigger Event:
- Source IP: {alert['trigger_event']['source_ip']}
- Destination IP: {alert['trigger_event']['destination_ip']}
- Protocol: {alert['trigger_event']['protocol']}
- Event Type: {alert['trigger_event']['event_type']}

Correlated Events: {alert['correlated_events_count']}
Recommended Action: {alert['recommended_action']}

This is an automated alert from the Cross-Domain Correlation Engine.
"""
            
            message.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                if self.email_config.get('use_tls'):
                    server.starttls()
                if self.email_config.get('username'):
                    server.login(self.email_config['username'], self.email_config['password'])
                server.send_message(message)
            
            self.logger.info("Alert sent via email")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def print_status(self):
        self.logger.info(f"Events in buffer: {len(self.event_buffer)}")
        self.logger.info(f"Active correlations: {len(self.active_correlations)}")
    
    def stop(self):
        self.running = False
        if self.correlation_thread.is_alive():
            self.correlation_thread.join(timeout=5)
        if self.geoip_reader:
            self.geoip_reader.close()
        self.logger.info("Correlation engine stopped")

def create_flask_app(correlator: CrossDomainCorrelator):
    app = Flask(__name__)

    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'healthy',
            'events_in_buffer': len(correlator.event_buffer),
            'active_correlations': len(correlator.active_correlations)
        })

    @app.route('/event', methods=['POST'])
    def receive_event():
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            required_fields = ['timestamp', 'source_ip', 'destination_ip', 'protocol', 
                             'event_type', 'severity', 'details', 'source_domain']
            
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            event = SecurityEvent(**data)
            correlator.add_event(event)
            return jsonify({'status': 'Event received'}), 200
            
        except Exception as e:
            correlator.logger.error(f"Error processing event: {e}")
            return jsonify({'error': str(e)}), 400

    @app.route('/alerts', methods=['GET'])
    def get_recent_alerts():
        try:
            hours = request.args.get('hours', 24, type=int)
            since_time = time.time() - (hours * 3600)
            
            recent_alerts = []
            for rule_name, alert_time in correlator.active_correlations.items():
                if alert_time >= since_time:
                    recent_alerts.append({
                        'rule_name': rule_name,
                        'trigger_time': alert_time
                    })
            
            return jsonify({'recent_alerts': recent_alerts})
            
        except Exception as e:
            correlator.logger.error(f"Error retrieving alerts: {e}")
            return jsonify({'error': str(e)}), 500

    return app

def main():
    parser = argparse.ArgumentParser(
        description='Cross-Domain Correlation Engine for IT/OT Security'
    )
    
    parser.add_argument('--rules-file', help='JSON or YAML file containing correlation rules')
    parser.add_argument('--es-host', default=os.getenv('ES_HOST'), help='Elasticsearch host')
    parser.add_argument('--geoip-db', default='GeoLite2-City.mmdb', help='Path to GeoIP database')
    parser.add_argument('--mode', choices=['service', 'api'], default='service', help='Run mode: service or api')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind API server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind API server to')
    
    args = parser.parse_args()
    
    email_config = None
    if all(os.getenv(var) for var in ['SMTP_SERVER', 'SMTP_PORT', 'EMAIL_FROM', 'EMAIL_TO']):
        email_config = {
            'smtp_server': os.getenv('SMTP_SERVER'),
            'smtp_port': int(os.getenv('SMTP_PORT')),
            'from_addr': os.getenv('EMAIL_FROM'),
            'to_addrs': os.getenv('EMAIL_TO').split(','),
            'use_tls': os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
        }
        
        if os.getenv('SMTP_USERNAME'):
            email_config.update({
                'username': os.getenv('SMTP_USERNAME'),
                'password': os.getenv('SMTP_PASSWORD', '')
            })
    
    correlator = CrossDomainCorrelator(
        args.rules_file, 
        args.es_host,
        email_config,
        args.geoip_db
    )
    
    logger = logging.getLogger('CrossDomainCorrelator')
    logger.info("Cross-Domain Correlation Engine Started")
    
    if args.mode == 'api':
        app = create_flask_app(correlator)
        logger.info(f"Starting API server on {args.host}:{args.port}")
        app.run(host=args.host, port=args.port, threaded=True)
    else:
        try:
            logger.info("Correlation engine running in service mode. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
        finally:
            correlator.stop()

if __name__ == "__main__":
    main()
