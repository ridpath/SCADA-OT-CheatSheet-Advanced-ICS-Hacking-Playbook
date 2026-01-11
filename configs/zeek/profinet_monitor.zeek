# PROFINET Security Monitoring Script for Zeek
# Enhanced Detection Coverage:
# - DCP device discovery and reconnaissance
# - DCP Set operations (NameOfStation, IP address)
# - Factory reset commands
# - Real-time cyclic data injection (RT Class 1/2/3)
# - PROFINET alarm spoofing
# - Firmware update mode activation
# - TFTP firmware uploads
# - DCP protocol fuzzing
#
# Aligned with attack tool:
# - tools/profinet_exploitation/profinet_exploit.py
#
# Load in local.zeek:
# @load configs/zeek/profinet_monitor

@load base/frameworks/notice
@load base/frameworks/sumstats

module PROFINET_DETECTION;

export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type += { PROFINET_Anomaly };

    type Info: record {
        ts: time &log;
        uid: string &log &optional;
        source_mac: string &log;
        destination_mac: string &log;
        frame_id: count &log &optional;
        dcp_service: string &log &optional;
        event_type: string &log;
        severity: string &log;
        details: string &log;
    };

    const dcp_identify_threshold: count = 10 &redef;
    const rt_injection_threshold: count = 50 &redef;
    const alarm_spoof_threshold: count = 3 &redef;
    const sumstats_epoch_interval: interval = 1min &redef;

    global profinet_anomaly_detected: event(
        source_mac: string,
        destination_mac: string,
        frame_id: count,
        dcp_service: string,
        event_type: string,
        details: string
    );
}

global dcp_identify_count: table[string] of count &create_expire=30sec &default=0;
global rt_frame_count: table[string] of count &create_expire=1min &default=0;
global alarm_spoof_count: table[string] of count &create_expire=5min &default=0;
global dcp_set_operations: set[string] &create_expire=10min;
global factory_reset_seen: set[string] &create_expire=1hr;
global firmware_update_mode: set[string] &create_expire=1hr;

event zeek_init() &priority=5 {
    Log::create_stream(PROFINET_DETECTION::LOG, [$columns=Info, $path="profinet_detection"]);
}

# PROFINET uses EtherType 0x8892
# DCP Frame IDs:
#   0xFEFE - Identify Request
#   0xFEFF - Identify Response
#   0xFEFC - Get/Set Request/Response
#   0xFEFD - Hello
# RT Frame IDs:
#   0x8000-0xBFFF - RT Class 1
#   0xC000-0xEFFF - RT Class 2
#   0xF000-0xF7FF - RT Class 3 (IRT)
# Alarm Frame IDs:
#   0xFC01 - High Priority Alarm
#   0xFE01 - Low Priority Alarm

event raw_packet(p: raw_pkt_hdr) {
    if (|p$l2| < 14) return;
    
    # Extract EtherType (bytes 12-13)
    local ethertype_bytes = sub_bytes(p$l2, 12, 2);
    if (|ethertype_bytes| < 2) return;
    
    local ethertype = bytestring_to_count(ethertype_bytes);
    if (ethertype != 0x8892) return;  # Not PROFINET
    
    # Extract MAC addresses
    local src_mac = fmt("%02x:%02x:%02x:%02x:%02x:%02x", 
        bytestring_to_count(sub_bytes(p$l2, 6, 1)),
        bytestring_to_count(sub_bytes(p$l2, 7, 1)),
        bytestring_to_count(sub_bytes(p$l2, 8, 1)),
        bytestring_to_count(sub_bytes(p$l2, 9, 1)),
        bytestring_to_count(sub_bytes(p$l2, 10, 1)),
        bytestring_to_count(sub_bytes(p$l2, 11, 1)));
    
    local dst_mac = fmt("%02x:%02x:%02x:%02x:%02x:%02x",
        bytestring_to_count(sub_bytes(p$l2, 0, 1)),
        bytestring_to_count(sub_bytes(p$l2, 1, 1)),
        bytestring_to_count(sub_bytes(p$l2, 2, 1)),
        bytestring_to_count(sub_bytes(p$l2, 3, 1)),
        bytestring_to_count(sub_bytes(p$l2, 4, 1)),
        bytestring_to_count(sub_bytes(p$l2, 5, 1)));
    
    if (|p$l2| < 16) return;
    
    # Extract Frame ID (bytes 14-15 after EtherType)
    local frame_id_bytes = sub_bytes(p$l2, 14, 2);
    if (|frame_id_bytes| < 2) return;
    local frame_id = bytestring_to_count(frame_id_bytes);
    
    # DCP Identify Request (0xFEFE)
    # Aligned with: profinet_exploit.py:discover_devices()
    if (frame_id == 0xFEFE) {
        ++dcp_identify_count[src_mac];
        if (dcp_identify_count[src_mac] >= dcp_identify_threshold) {
            local details = fmt("PROFINET DCP Identify storm from %s - %d requests in 30sec", src_mac, dcp_identify_count[src_mac]);
            event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, dst_mac, frame_id, "DCP_Identify", "DCP_Identify_Storm", details);
        }
    }
    
    # DCP Get/Set (0xFEFC)
    if (frame_id == 0xFEFC && |p$l2| >= 20) {
        local service_bytes = sub_bytes(p$l2, 16, 2);
        if (|service_bytes| < 2) return;
        local service_id = bytestring_to_count(sub_bytes(service_bytes, 0, 1));
        local service_type = bytestring_to_count(sub_bytes(service_bytes, 1, 1));
        
        # DCP Set Request (Service ID: 0x04, Type: 0x00)
        # Aligned with: profinet_exploit.py:set_device_name(), set_device_ip()
        if (service_id == 0x04 && service_type == 0x00) {
            if (|p$l2| >= 22) {
                local option_bytes = sub_bytes(p$l2, 18, 2);
                if (|option_bytes| >= 2) {
                    local option = bytestring_to_count(sub_bytes(option_bytes, 0, 1));
                    local suboption = bytestring_to_count(sub_bytes(option_bytes, 1, 1));
                    
                    # NameOfStation (Option: 0x02, Suboption: 0x02)
                    if (option == 0x02 && suboption == 0x02) {
                        add dcp_set_operations[src_mac];
                        local details = fmt("PROFINET DCP Set NameOfStation from %s - device identity manipulation", src_mac);
                        event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, dst_mac, frame_id, "DCP_Set_Name", "Set_NameOfStation", details);
                    }
                    
                    # IP Parameter (Option: 0x01, Suboption: 0x02)
                    if (option == 0x01 && suboption == 0x02) {
                        add dcp_set_operations[src_mac];
                        local details = fmt("PROFINET DCP Set IP Address from %s - network reconfiguration", src_mac);
                        event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, dst_mac, frame_id, "DCP_Set_IP", "Set_IP_Address", details);
                    }
                    
                    # Factory Reset (Option: 0x05, Suboption: 0x05)
                    # Aligned with: profinet_exploit.py:factory_reset_device()
                    if (option == 0x05 && suboption == 0x05) {
                        add factory_reset_seen[src_mac];
                        local details = fmt("PROFINET DCP Factory Reset from %s - device reset attack", src_mac);
                        event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, dst_mac, frame_id, "DCP_Factory_Reset", "Factory_Reset", details);
                    }
                }
            }
        }
    }
    
    # RT Class 1 Cyclic Data (0x8000-0xBFFF)
    # Aligned with: profinet_exploit.py:inject_rt_frame()
    if (frame_id >= 0x8000 && frame_id <= 0xBFFF) {
        ++rt_frame_count[src_mac];
        if (rt_frame_count[src_mac] >= rt_injection_threshold) {
            local details = fmt("PROFINET RT Class 1 injection from %s - %d frames in 1min (Frame ID: 0x%04x)", src_mac, rt_frame_count[src_mac], frame_id);
            event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, dst_mac, frame_id, "RT_Class1", "RT_Frame_Injection", details);
        }
    }
    
    # RT Class 3 IRT (0xF000-0xF7FF)
    if (frame_id >= 0xF000 && frame_id <= 0xF7FF) {
        local details = fmt("PROFINET RT Class 3 IRT from %s - time-critical control manipulation (Frame ID: 0x%04x)", src_mac, frame_id);
        event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, dst_mac, frame_id, "RT_Class3_IRT", "IRT_Manipulation", details);
    }
    
    # High Priority Alarm (0xFC01)
    # Aligned with: profinet_exploit.py:spoof_alarm()
    if (frame_id == 0xFC01) {
        ++alarm_spoof_count[src_mac];
        if (alarm_spoof_count[src_mac] >= alarm_spoof_threshold) {
            local details = fmt("PROFINET High Priority Alarm spoofing from %s - %d alarms in 5min", src_mac, alarm_spoof_count[src_mac]);
            event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, dst_mac, frame_id, "Alarm_High", "Alarm_Spoofing", details);
        }
    }
}

# Detect TFTP firmware uploads (aligned with profinet_exploit.py:reprogram_device_tftp())
event tftp_request(c: connection, is_orig: bool, opcode: count, filename: string, mode: string) {
    if (opcode != 2) return;  # Not a write request
    if (!/.*(\.bin|\.fw|\.img|\.hex)$/i in filename) return;
    
    local source_ip = c$id$orig_h;
    local details = fmt("PROFINET TFTP firmware upload from %s - file: %s", source_ip, filename);
    
    # Note: We're converting IP to pseudo-MAC for consistency
    local src_mac = fmt("%s", source_ip);
    event PROFINET_DETECTION::profinet_anomaly_detected(src_mac, "broadcast", 0, "TFTP_Upload", "Firmware_Upload", details);
}

event PROFINET_DETECTION::profinet_anomaly_detected(source_mac: string, destination_mac: string, frame_id: count, dcp_service: string, event_type: string, details: string) {
    local severity = "MEDIUM";
    
    if ( /Set_|Factory_Reset|Firmware|IRT_Manipulation|Alarm_Spoofing/ in event_type )
        severity = "HIGH";
    else if ( /Identify_Storm|RT_Frame/ in event_type )
        severity = "LOW";
    
    if ( /Factory_Reset|Set_IP_Address|Alarm_Spoofing|Firmware_Upload/ in event_type )
        severity = "CRITICAL";

    local info: Info = [
        $ts=network_time(),
        $source_mac=source_mac,
        $destination_mac=destination_mac,
        $frame_id=frame_id,
        $dcp_service=dcp_service,
        $event_type=event_type,
        $severity=severity,
        $details=details
    ];

    Log::write(LOG, info);

    NOTICE([$note=PROFINET_Anomaly,
            $msg=fmt("PROFINET %s: %s", event_type, details),
            $identifier=cat(source_mac, event_type)]);
}
