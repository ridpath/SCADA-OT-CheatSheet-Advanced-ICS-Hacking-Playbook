# BACnet Security Monitoring Script for Zeek
# Enhanced Detection Coverage:
# - Who-Is device discovery
# - Unauthorized WriteProperty operations
# - Priority array manipulation
# - DeviceCommunicationControl attacks
# - ReinitializeDevice (cold/warm restart)
# - COV subscription monitoring
# - AtomicWriteFile (project infection)
# - AtomicReadFile (data exfiltration)
# - MS/TP token manipulation
# - Service fuzzing detection
#
# Aligned with attack tool:
# - tools/bacnet_security_assessment/bacnet_assessment.py
#
# Load in local.zeek:
# @load configs/zeek/bacnet_monitor

@load base/frameworks/notice
@load base/frameworks/sumstats

module BACNET_DETECTION;

export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type += { BACNET_Anomaly };

    type Info: record {
        ts: time &log;
        uid: string &log &optional;
        id: conn_id &log &optional;
        source_ip: addr &log;
        destination_ip: addr &log &optional;
        service: string &log &optional;
        event_type: string &log;
        severity: string &log;
        details: string &log;
    };

    const authorized_bacnet_clients: set[addr] = {
        192.168.1.50, 192.168.1.51
    } &redef;

    const bacnet_port: port = 47808/udp &redef;
    const whois_threshold: count = 10 &redef;
    const read_property_threshold: count = 20 &redef;
    const cov_subscription_threshold: count = 10 &redef;
    const atomic_read_threshold: count = 5 &redef;
    const sumstats_epoch_interval: interval = 1min &redef;

    global bacnet_anomaly_detected: event(
        source_ip: addr,
        destination_ip: addr &default=0.0.0.0,
        service: string,
        event_type: string,
        details: string,
        c: connection &default=[$id=[$orig_h=0.0.0.0, $orig_p=0/udp, $resp_h=0.0.0.0, $resp_p=0/udp], $uid="", $start_time=0sec]
    );
}

global bacnet_whois_count: table[addr] of count &create_expire=1min &default=0;
global bacnet_read_property_count: table[addr] of count &create_expire=1min &default=0;
global bacnet_write_property_count: table[addr] of count &create_expire=5min &default=0;
global bacnet_cov_subscription_count: table[addr] of count &create_expire=1min &default=0;
global bacnet_atomic_read_count: table[addr] of count &create_expire=5min &default=0;
global bacnet_cold_restart_seen: set[addr] &create_expire=1hr;
global bacnet_warm_restart_seen: set[addr] &create_expire=1hr;
global bacnet_comm_control_seen: set[addr] &create_expire=1hr;

event zeek_init() &priority=5 {
    Log::create_stream(BACNET_DETECTION::LOG, [$columns=Info, $path="bacnet_detection"]);
}

# BACnet/IP BVLC Type: 0x81 (BACnet/IP)
# PDU Types:
#   0x00 - Confirmed Request
#   0x10 - Unconfirmed Request
# Services:
#   Confirmed: 0x05 (SubscribeCOV), 0x06 (AtomicReadFile), 0x07 (AtomicWriteFile)
#              0x0C (ReadProperty), 0x0F (WriteProperty), 0x10 (WritePropertyMultiple)
#              0x11 (DeviceCommunicationControl), 0x14 (ReinitializeDevice)
#   Unconfirmed: 0x08 (I-Am), 0x0A (Who-Is)

event udp_contents(c: connection, is_orig: bool, contents: string) {
    if (!is_orig) return;
    if (c$id$resp_p != bacnet_port) return;
    if (|contents| < 4) return;
    
    local source_ip = c$id$orig_h;
    local destination_ip = c$id$resp_h;
    
    # Check for BACnet/IP BVLC header (0x81)
    if (bytestring_to_count(sub_bytes(contents, 0, 1)) != 0x81) return;
    
    if (|contents| < 5) return;
    
    # Extract PDU type (byte 4)
    local pdu_type = bytestring_to_count(sub_bytes(contents, 4, 1));
    
    # Unconfirmed Request (0x10)
    if (pdu_type == 0x10 && |contents| >= 6) {
        local unconfirmed_service = bytestring_to_count(sub_bytes(contents, 5, 1));
        
        # Who-Is service (0x08)
        # Aligned with: bacnet_assessment.py:discover_devices()
        if (unconfirmed_service == 0x08) {
            ++bacnet_whois_count[source_ip];
            if (bacnet_whois_count[source_ip] >= whois_threshold) {
                local details = fmt("BACnet Who-Is broadcast storm from %s - %d requests in 1min", source_ip, bacnet_whois_count[source_ip]);
                event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "Who-Is", "Device_Discovery_Storm", details, c);
            }
        }
    }
    
    # Confirmed Request (0x00)
    if (pdu_type == 0x00 && |contents| >= 6) {
        local confirmed_service = bytestring_to_count(sub_bytes(contents, 5, 1));
        
        # ReadProperty service (0x0C)
        # Aligned with: bacnet_assessment.py:enumerate_objects()
        if (confirmed_service == 0x0C) {
            ++bacnet_read_property_count[source_ip];
            if (bacnet_read_property_count[source_ip] >= read_property_threshold) {
                local details = fmt("BACnet property enumeration from %s - %d reads in 1min", source_ip, bacnet_read_property_count[source_ip]);
                event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "ReadProperty", "Property_Enumeration", details, c);
            }
        }
        
        # WriteProperty service (0x0F)
        # Aligned with: bacnet_assessment.py:write_property()
        if (confirmed_service == 0x0F) {
            if (source_ip !in authorized_bacnet_clients) {
                ++bacnet_write_property_count[source_ip];
                local details = fmt("BACnet unauthorized WriteProperty from %s", source_ip);
                event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "WriteProperty", "Unauthorized_Write", details, c);
                
                # Check for priority array manipulation (Property ID: 0x57 - 87 decimal)
                # Aligned with: bacnet_assessment.py:manipulate_priority_array()
                if (/\x57/ in contents) {
                    local details = fmt("BACnet priority array manipulation from %s - control override", source_ip);
                    event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "WriteProperty", "Priority_Array_Override", details, c);
                }
            }
        }
        
        # WritePropertyMultiple service (0x10)
        if (confirmed_service == 0x10 && |contents| > 300) {
            local details = fmt("BACnet WritePropertyMultiple from %s - bulk modification (%d bytes)", source_ip, |contents|);
            event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "WritePropertyMultiple", "Bulk_Modification", details, c);
        }
        
        # DeviceCommunicationControl service (0x11)
        # Aligned with: bacnet_assessment.py:device_communication_control()
        if (confirmed_service == 0x11) {
            add bacnet_comm_control_seen[source_ip];
            local details = fmt("BACnet DeviceCommunicationControl from %s - communication disruption", source_ip);
            event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "DeviceCommunicationControl", "Comm_Control", details, c);
        }
        
        # ReinitializeDevice service (0x14)
        # Aligned with: bacnet_assessment.py:reinitialize_device()
        if (confirmed_service == 0x14 && |contents| >= 7) {
            local reinit_state = bytestring_to_count(sub_bytes(contents, 6, 1));
            
            # Cold restart (0x00)
            if (reinit_state == 0x00) {
                add bacnet_cold_restart_seen[source_ip];
                local details = fmt("BACnet ReinitializeDevice (COLD_START) from %s - service disruption", source_ip);
                event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "ReinitializeDevice", "Cold_Restart", details, c);
            }
            
            # Warm restart (0x01)
            if (reinit_state == 0x01) {
                add bacnet_warm_restart_seen[source_ip];
                local details = fmt("BACnet ReinitializeDevice (WARM_START) from %s", source_ip);
                event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "ReinitializeDevice", "Warm_Restart", details, c);
            }
        }
        
        # SubscribeCOV service (0x05)
        # Aligned with: bacnet_assessment.py:subscribe_cov()
        if (confirmed_service == 0x05) {
            ++bacnet_cov_subscription_count[source_ip];
            if (bacnet_cov_subscription_count[source_ip] >= cov_subscription_threshold) {
                local details = fmt("BACnet COV subscription storm from %s - %d subscriptions in 1min", source_ip, bacnet_cov_subscription_count[source_ip]);
                event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "SubscribeCOV", "COV_Subscription_Storm", details, c);
            }
        }
        
        # AtomicWriteFile service (0x07)
        # Aligned with: bacnet_assessment.py:atomic_write_file()
        if (confirmed_service == 0x07 && |contents| > 200) {
            local details = fmt("BACnet AtomicWriteFile from %s - project file infection (%d bytes)", source_ip, |contents|);
            event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "AtomicWriteFile", "Project_File_Infection", details, c);
        }
        
        # AtomicReadFile service (0x06)
        if (confirmed_service == 0x06) {
            ++bacnet_atomic_read_count[source_ip];
            if (bacnet_atomic_read_count[source_ip] >= atomic_read_threshold) {
                local details = fmt("BACnet AtomicReadFile from %s - %d reads in 5min - potential data exfiltration", source_ip, bacnet_atomic_read_count[source_ip]);
                event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "AtomicReadFile", "Data_Exfiltration", details, c);
            }
        }
        
        # CreateObject service (0x0A)
        if (confirmed_service == 0x0A) {
            local details = fmt("BACnet CreateObject from %s - unauthorized object creation", source_ip);
            event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "CreateObject", "Unauthorized_Create", details, c);
        }
        
        # DeleteObject service (0x0B)
        if (confirmed_service == 0x0B) {
            local details = fmt("BACnet DeleteObject from %s - data destruction", source_ip);
            event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "DeleteObject", "Data_Destruction", details, c);
        }
    }
    
    # Detect fuzzing (abnormally large packets)
    # Aligned with: bacnet_assessment.py:fuzz_service()
    if (|contents| > 1000) {
        local details = fmt("BACnet service fuzzing from %s - malformed packet (%d bytes)", source_ip, |contents|);
        event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, destination_ip, "Fuzzing", "Service_Fuzzing", details, c);
    }
}

# Detect MS/TP token manipulation (via TCP gateway)
# Aligned with: bacnet_assessment.py:mstp_token_manipulation()
event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string) {
    if (!is_orig) return;
    if (|contents| < 10) return;
    
    local source_ip = c$id$orig_h;
    
    # Check for MS/TP frame marker (0x55 0xFF)
    if (/MS\/TP/ in contents || /\x55\xFF/ in contents) {
        local details = fmt("BACnet MS/TP token manipulation from %s - network disruption", source_ip);
        event BACNET_DETECTION::bacnet_anomaly_detected(source_ip, c$id$resp_h, "MS/TP", "Token_Manipulation", details, c);
    }
}

event BACNET_DETECTION::bacnet_anomaly_detected(source_ip: addr, destination_ip: addr, service: string, event_type: string, details: string, c: connection) {
    local severity = "MEDIUM";
    
    if ( /Write|Restart|Comm_Control|Infection|Destruction/ in event_type )
        severity = "HIGH";
    else if ( /Discovery|Enumeration|COV|Exfiltration/ in event_type )
        severity = "LOW";
    
    if ( /Cold_Restart|Priority_Array|Project_File|Data_Destruction|Comm_Control/ in event_type )
        severity = "CRITICAL";

    local info: Info = [
        $ts=network_time(),
        $source_ip=source_ip,
        $service=service,
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

    NOTICE([$note=BACNET_Anomaly, $src=source_ip, $dst=info$destination_ip,
            $msg=fmt("BACnet %s: %s", event_type, details),
            $identifier=cat(source_ip, event_type)]);
}
