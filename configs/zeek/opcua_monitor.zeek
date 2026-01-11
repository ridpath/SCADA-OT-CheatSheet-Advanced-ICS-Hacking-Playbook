# OPC-UA Security Monitoring Script for Zeek
# Enhanced Detection Coverage:
# - Endpoint discovery and enumeration
# - Insecure session creation (SecurityMode=None)
# - Unauthorized write operations
# - Subscription manipulation
# - Method calls and remote execution
# - Certificate validation bypass
# - Session hijacking attempts
# - Historical data access patterns
#
# Aligned with attack tool:
# - tools/opcua_security_framework/opcua_exploit.py
#
# Load in local.zeek:
# @load configs/zeek/opcua_monitor

@load base/frameworks/notice
@load base/frameworks/sumstats

module OPCUA_DETECTION;

export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type += { OPCUA_Anomaly };

    type Info: record {
        ts: time &log;
        uid: string &log &optional;
        id: conn_id &log &optional;
        source_ip: addr &log;
        destination_ip: addr &log &optional;
        service_type: string &log &optional;
        event_type: string &log;
        severity: string &log;
        details: string &log;
    };

    const authorized_opcua_clients: set[addr] = {
        192.168.1.50, 192.168.1.51
    } &redef;

    const opcua_ports: set[port] = { 4840/tcp, 4841/tcp, 4843/tcp } &redef;
    const endpoint_discovery_threshold: count = 3 &redef;
    const browse_threshold: count = 20 &redef;
    const write_threshold: count = 5 &redef;
    const subscription_threshold: count = 5 &redef;
    const historical_read_threshold: count = 10 &redef;
    const sumstats_epoch_interval: interval = 5min &redef;

    global opcua_anomaly_detected: event(
        source_ip: addr,
        destination_ip: addr &default=0.0.0.0,
        service_type: string,
        event_type: string,
        details: string,
        c: connection &default=[$id=[$orig_h=0.0.0.0, $orig_p=0/tcp, $resp_h=0.0.0.0, $resp_p=0/tcp], $uid="", $start_time=0sec]
    );
}

global opcua_endpoint_discovery: table[addr] of count &create_expire=5min &default=0;
global opcua_browse_operations: table[addr] of count &create_expire=1min &default=0;
global opcua_write_operations: table[addr] of count &create_expire=5min &default=0;
global opcua_subscriptions: table[addr] of count &create_expire=5min &default=0;
global opcua_historical_reads: table[addr] of count &create_expire=10min &default=0;
global opcua_sessions: table[addr] of set[string] &create_expire=1hr;
global opcua_insecure_sessions: set[addr] &create_expire=1hr;
global opcua_method_calls: table[addr] of count &create_expire=5min &default=0;

event zeek_init() &priority=5 {
    Log::create_stream(OPCUA_DETECTION::LOG, [$columns=Info, $path="opcua_detection"]);
}

event connection_established(c: connection) {
    if (c$id$resp_p !in opcua_ports) return;
    
    local source_ip = c$id$orig_h;
    if (source_ip !in opcua_sessions)
        opcua_sessions[source_ip] = set();
}

event opcua_binary_protocol(c: connection, is_orig: bool) {
    if (!is_orig) return;
    
    local source_ip = c$id$orig_h;
    local destination_ip = c$id$resp_h;
}

# Detect OPC-UA GetEndpoints service (endpoint discovery)
# Service Type: 0x01AE (430 decimal)
# Aligned with: opcua_exploit.py:discover_endpoints()
# MITRE: T0888
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
    if (!is_orig) return;
    if (c$id$resp_p !in opcua_ports) return;
    if (len < 20) return;
    
    local source_ip = c$id$orig_h;
    
    # OPC-UA Binary Protocol Header: "OPN" + "F" (0x4F 0x50 0x4E 0x46)
    if (|payload| < 24) return;
    
    # Check for GetEndpoints service (Service ID: 0x01AE)
    if (/OPN/ in payload && /\x01\xae/ in payload) {
        ++opcua_endpoint_discovery[source_ip];
        if (opcua_endpoint_discovery[source_ip] >= endpoint_discovery_threshold) {
            local details = fmt("OPC-UA endpoint discovery from %s - %d requests in 5min", source_ip, opcua_endpoint_discovery[source_ip]);
            event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "GetEndpoints", "Endpoint_Discovery", details, c);
        }
    }
    
    # Check for CreateSession with SecurityMode=None (0x01 0x00 0x00 0x00)
    # Service ID: 0x01CD (461 decimal)
    if (/OPN/ in payload && /\xcd\x01/ in payload && /\x01\x00\x00\x00/ in payload) {
        add opcua_insecure_sessions[source_ip];
        local details = fmt("OPC-UA insecure session creation from %s (SecurityMode=None)", source_ip);
        event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "CreateSession", "Insecure_Session", details, c);
    }
    
    # Check for Browse service (0x020F - 527 decimal)
    # Aligned with: opcua_exploit.py:enumerate_nodes()
    if (/OPN/ in payload && /\x0f\x02/ in payload) {
        ++opcua_browse_operations[source_ip];
        if (opcua_browse_operations[source_ip] >= browse_threshold) {
            local details = fmt("OPC-UA recursive node enumeration from %s - %d browse operations in 1min", source_ip, opcua_browse_operations[source_ip]);
            event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "Browse", "Node_Enumeration", details, c);
        }
    }
    
    # Check for Write service (0x02A9 - 681 decimal)
    # Aligned with: opcua_exploit.py:fuzz_node_write()
    if (/OPN/ in payload && /\xa9\x02/ in payload) {
        if (source_ip !in authorized_opcua_clients) {
            ++opcua_write_operations[source_ip];
            local details = fmt("OPC-UA unauthorized write from %s - %d write operations", source_ip, opcua_write_operations[source_ip]);
            event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "Write", "Unauthorized_Write", details, c);
        }
    }
    
    # Check for CreateSubscription service (0x0333 - 819 decimal)
    # Aligned with: opcua_exploit.py:create_malicious_subscription()
    if (/OPN/ in payload && /\x33\x03/ in payload) {
        ++opcua_subscriptions[source_ip];
        if (opcua_subscriptions[source_ip] >= subscription_threshold) {
            local details = fmt("OPC-UA high-rate subscription creation from %s - %d subscriptions in 5min", source_ip, opcua_subscriptions[source_ip]);
            event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "CreateSubscription", "Subscription_Manipulation", details, c);
        }
    }
    
    # Check for Call service (Method call - 0x02B2 - 690 decimal)
    if (/OPN/ in payload && /\xb2\x02/ in payload) {
        ++opcua_method_calls[source_ip];
        local details = fmt("OPC-UA method call from %s - potential remote execution", source_ip);
        event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "Call", "Method_Call", details, c);
    }
    
    # Check for HistoryRead service (0x02A4 - 676 decimal)
    if (/OPN/ in payload && /\xa4\x02/ in payload) {
        ++opcua_historical_reads[source_ip];
        if (opcua_historical_reads[source_ip] >= historical_read_threshold) {
            local details = fmt("OPC-UA historical data access from %s - %d reads in 10min", source_ip, opcua_historical_reads[source_ip]);
            event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "HistoryRead", "Historical_Data_Access", details, c);
        }
    }
    
    # Check for certificate validation errors (BadCertificateInvalid - 0x80420000)
    if (|payload| > 50 && /\x80\x42\x00\x00/ in payload) {
        local details = fmt("OPC-UA certificate validation error from %s - potential bypass attempt", source_ip);
        event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "CertificateError", "Certificate_Bypass", details, c);
    }
}

event OPCUA_DETECTION::opcua_anomaly_detected(source_ip: addr, destination_ip: addr, service_type: string, event_type: string, details: string, c: connection) {
    local severity = "MEDIUM";
    
    if ( /Write|Method_Call|Certificate_Bypass|Insecure_Session/ in event_type )
        severity = "HIGH";
    else if ( /Discovery|Enumeration|Historical|Subscription/ in event_type )
        severity = "LOW";
    
    if ( /Unauthorized_Write|Method_Call/ in event_type )
        severity = "CRITICAL";

    local info: Info = [
        $ts=network_time(),
        $source_ip=source_ip,
        $service_type=service_type,
        $event_type=event_type,
        $severity=severity,
        $details=details
    ];

    if (c$uid != "") {
        info$uid = c$uid;
        info$id = c$id;
        info$destination_ip = c$id$resp_h;
    } else {
        info$destination_ip = destination_ip;
    }

    Log::write(LOG, info);

    NOTICE([$note=OPCUA_Anomaly, $src=source_ip, $dst=info$destination_ip,
            $msg=fmt("OPC-UA %s: %s", event_type, details),
            $identifier=cat(source_ip, event_type)]);
}

event connection_state_remove(c: connection) {
    if (c$id$resp_p !in opcua_ports) return;
    
    local source_ip = c$id$orig_h;
    
    # Check for session hijacking (multiple connections with same session)
    if (source_ip in opcua_insecure_sessions) {
        local session_count = |opcua_sessions[source_ip]|;
        if (session_count > 1) {
            local details = fmt("OPC-UA potential session hijacking from %s - %d concurrent sessions", source_ip, session_count);
            event OPCUA_DETECTION::opcua_anomaly_detected(source_ip, c$id$resp_h, "Session", "Session_Hijacking", details, c);
        }
    }
}
