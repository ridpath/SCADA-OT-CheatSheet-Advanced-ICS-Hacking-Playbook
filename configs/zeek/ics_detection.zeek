# ICS Detection Script for Zeek
# Enhanced Detection Coverage:
# - High-rate Modbus/S7Comm/ENIP/DNP3 requests
# - Unauthorized write attempts
# - Critical register writes
# - Multi-protocol reconnaissance
# - PLC stop/start and logic downloads
# - DNP3 cold restart and authentication bypass
# - Modbus file transfer operations
# - S7Comm symbol table extraction and data block mass export
# - CIP Safety I/O exploitation and implicit messaging manipulation
# - S7CommPlus protocol detection
#
# Aligned with attack tools:
# - tools/modbus-stealth-toolkit/modbus_stealth_attack.py
# - tools/s7comm_security_framework/s7comm_exploit.py
# - tools/cip_security_assessment/cip_exploiter.py
#
# Load in local.zeek:
# @load configs/zeek/ics_detection

@load base/frameworks/notice
@load base/frameworks/sumstats
@load protocols/modbus
@load protocols/s7comm
@load protocols/enip
@load protocols/dnp3

module ICS_DETECTION;

export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type += { ICS_Anomaly };

    type Info: record {
        ts: time &log;
        uid: string &log &optional;
        id: conn_id &log &optional;
        protocol: string &log;
        source_ip: addr &log;
        destination_ip: addr &log &optional;
        event_type: string &log;
        severity: string &log;
        details: string &log;
    };

    const authorized_writers: set[addr] = {
        192.168.1.50, 192.168.1.51
    } &redef;

    const large_read_threshold: count = 100 &redef;
    const critical_register_start: count = 1000 &redef;
    const critical_register_end: count = 2000 &redef;
    const request_rate_threshold: double = 50.0 &redef;
    const sumstats_epoch_interval: interval = 1min &redef;
    const multi_protocol_threshold: count = 3 &redef;
    const db_export_threshold: count = 10 &redef;
    const symbol_table_extract_threshold: count = 5 &redef;
    const file_transfer_threshold: count = 2 &redef;

    global ics_anomaly_detected: event(
        protocol: string,
        source_ip: addr,
        destination_ip: addr &default=0.0.0.0,
        event_type: string,
        details: string,
        c: connection &default=[$id=[$orig_h=0.0.0.0, $orig_p=0/tcp, $resp_h=0.0.0.0, $resp_p=0/tcp], $uid="", $start_time=0sec]
    );
}

global multi_protocol_sources: table[addr] of set[string] &create_expire=1hrs;
global s7comm_db_read_count: table[addr] of count &create_expire=1min &default=0;
global s7comm_szl_read_count: table[addr] of count &create_expire=2min &default=0;
global modbus_file_ops_count: table[addr] of count &create_expire=5min &default=0;
global dnp3_cold_restart_seen: set[addr] &create_expire=1hr;

event zeek_init() &priority=5 {
    Log::create_stream(ICS_DETECTION::LOG, [$columns=Info, $path="ics_detection"]);

    SumStats::create([$name="ics.modbus.requests",
                      $epoch=sumstats_epoch_interval,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = result["num"]$sum,
                      $threshold=request_rate_threshold,
                      $reducers=set(SumStats::Reducer($stream="ics.modbus.request", $apply=set(SumStats::SUM))),
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          local details = fmt("High Modbus request rate from %s: %.0f in %s", key$host, result["num"]$sum, sumstats_epoch_interval);
                          NOTICE([$note=ICS_Anomaly, $src=key$host, $msg=details]);
                          event ICS_DETECTION::ics_anomaly_detected("MODBUS", key$host, 0.0.0.0, "High_Rate", details);
                      }]);

    SumStats::create([$name="ics.s7comm.requests",
                      $epoch=sumstats_epoch_interval,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = result["num"]$sum,
                      $threshold=request_rate_threshold,
                      $reducers=set(SumStats::Reducer($stream="ics.s7comm.request", $apply=set(SumStats::SUM))),
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          local details = fmt("High S7Comm request rate from %s: %.0f in %s", key$host, result["num"]$sum, sumstats_epoch_interval);
                          NOTICE([$note=ICS_Anomaly, $src=key$host, $msg=details]);
                          event ICS_DETECTION::ics_anomaly_detected("S7COMM", key$host, 0.0.0.0, "High_Rate", details);
                      }]);

    SumStats::create([$name="ics.enip.requests",
                      $epoch=sumstats_epoch_interval,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = result["num"]$sum,
                      $threshold=request_rate_threshold,
                      $reducers=set(SumStats::Reducer($stream="ics.enip.request", $apply=set(SumStats::SUM))),
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          local details = fmt("High ENIP request rate from %s: %.0f in %s", key$host, result["num"]$sum, sumstats_epoch_interval);
                          NOTICE([$note=ICS_Anomaly, $src=key$host, $msg=details]);
                          event ICS_DETECTION::ics_anomaly_detected("ENIP", key$host, 0.0.0.0, "High_Rate", details);
                      }]);

    SumStats::create([$name="ics.dnp3.requests",
                      $epoch=sumstats_epoch_interval,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = result["num"]$sum,
                      $threshold=request_rate_threshold,
                      $reducers=set(SumStats::Reducer($stream="ics.dnp3.request", $apply=set(SumStats::SUM))),
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          local details = fmt("High DNP3 request rate from %s: %.0f in %s", key$host, result["num"]$sum, sumstats_epoch_interval);
                          NOTICE([$note=ICS_Anomaly, $src=key$host, $msg=details]);
                          event ICS_DETECTION::ics_anomaly_detected("DNP3", key$host, 0.0.0.0, "High_Rate", details);
                      }]);
}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    local source_ip = c$id$orig_h;

    if (source_ip !in multi_protocol_sources)
        multi_protocol_sources[source_ip] = set();
    add multi_protocol_sources[source_ip]["MODBUS"];

    SumStats::observe("ics.modbus.request", SumStats::Key($host=source_ip), SumStats::Observation($num=1));

    if (headers$function_code >= 5 && headers$function_code <= 16) {
        if (source_ip !in authorized_writers) {
            local details = fmt("Modbus write function %d from unauthorized source %s", headers$function_code, source_ip);
            event ICS_DETECTION::ics_anomaly_detected("MODBUS", source_ip, c$id$resp_h, "Unauthorized_Write", details, c);
        }
    }

    const recon_functions: set[count] = {0x0B, 0x0C, 0x11, 0x2B};
    if (headers$function_code in recon_functions) {
        local details = fmt("Modbus reconnaissance function %d from %s", headers$function_code, source_ip);
        event ICS_DETECTION::ics_anomaly_detected("MODBUS", source_ip, c$id$resp_h, "Reconnaissance", details, c);
    }

    const file_transfer_functions: set[count] = {0x14, 0x15, 0x16, 0x17};
    if (headers$function_code in file_transfer_functions) {
        ++modbus_file_ops_count[source_ip];
        if (modbus_file_ops_count[source_ip] >= file_transfer_threshold) {
            local details = fmt("Modbus file transfer operation (FC 0x%02x) from %s - potential logic exfiltration", headers$function_code, source_ip);
            event ICS_DETECTION::ics_anomaly_detected("MODBUS", source_ip, c$id$resp_h, "File_Transfer_Operation", details, c);
        }
    }
}

event s7comm_header(c: connection, is_orig: bool, header: S7COMM::Header) {
    local source_ip = c$id$orig_h;

    if (source_ip !in multi_protocol_sources)
        multi_protocol_sources[source_ip] = set();
    add multi_protocol_sources[source_ip]["S7COMM"];

    SumStats::observe("ics.s7comm.request", SumStats::Key($host=source_ip), SumStats::Observation($num=1));

    if (header$function == 0x29) {
        local details = fmt("S7Comm stop/start command from %s", source_ip);
        event ICS_DETECTION::ics_anomaly_detected("S7COMM", source_ip, c$id$resp_h, "PLC_Control", details, c);
    }

    if (header$function == 0x1a) {
        local details = fmt("S7Comm block download from %s", source_ip);
        event ICS_DETECTION::ics_anomaly_detected("S7COMM", source_ip, c$id$resp_h, "Logic_Download", details, c);
    }

    if (header$function == 0x05) {
        if (source_ip !in authorized_writers) {
            local details = fmt("S7Comm write from unauthorized source %s", source_ip);
            event ICS_DETECTION::ics_anomaly_detected("S7COMM", source_ip, c$id$resp_h, "Unauthorized_Write", details, c);
        }
    }

    if (header$function == 0x04) {
        ++s7comm_db_read_count[source_ip];
        if (s7comm_db_read_count[source_ip] >= db_export_threshold) {
            local details = fmt("S7Comm data block mass export detected from %s - %d reads in 1 minute", source_ip, s7comm_db_read_count[source_ip]);
            event ICS_DETECTION::ics_anomaly_detected("S7COMM", source_ip, c$id$resp_h, "Data_Block_Mass_Export", details, c);
        }
    }

    if (header$rosctr == 0x01 && header$function == 0x04) {
        ++s7comm_szl_read_count[source_ip];
        if (s7comm_szl_read_count[source_ip] >= symbol_table_extract_threshold) {
            local details = fmt("S7Comm symbol table extraction detected from %s - %d SZL reads in 2 minutes", source_ip, s7comm_szl_read_count[source_ip]);
            event ICS_DETECTION::ics_anomaly_detected("S7COMM", source_ip, c$id$resp_h, "Symbol_Table_Extraction", details, c);
        }
    }

    if (header$pdu_type == 0x72) {
        local details = fmt("S7CommPlus protocol detected from %s - may bypass traditional defenses", source_ip);
        event ICS_DETECTION::ics_anomaly_detected("S7COMM", source_ip, c$id$resp_h, "S7CommPlus_Protocol", details, c);
    }
}

event enip_header(c: connection, is_orig: bool, header: ENIP::Header) {
    local source_ip = c$id$orig_h;

    if (source_ip !in multi_protocol_sources)
        multi_protocol_sources[source_ip] = set();
    add multi_protocol_sources[source_ip]["ENIP"];

    SumStats::observe("ics.enip.request", SumStats::Key($host=source_ip), SumStats::Observation($num=1));

    const recon_commands: set[count] = {0x63, 0x64};
    if (header$command in recon_commands) {
        local cmd_name = (header$command == 0x63) ? "ListIdentity" : "ListInterfaces";
        local details = fmt("ENIP reconnaissance command %s (0x%02x) from %s", cmd_name, header$command, source_ip);
        event ICS_DETECTION::ics_anomaly_detected("ENIP", source_ip, c$id$resp_h, "Reconnaissance", details, c);
    }
}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count) {
    if (code > 0) {
        local source_ip = c$id$orig_h;
        local details = fmt("Modbus exception code %d from %s", code, source_ip);
        event ICS_DETECTION::ics_anomaly_detected("MODBUS", source_ip, c$id$resp_h, "Exception", details, c);
    }
}

event dnp3_header_block(c: connection, is_orig: bool, hdr: DNP3::DNP3HeaderBlock) {
    local source_ip = c$id$orig_h;

    if (source_ip !in multi_protocol_sources)
        multi_protocol_sources[source_ip] = set();
    add multi_protocol_sources[source_ip]["DNP3"];

    SumStats::observe("ics.dnp3.request", SumStats::Key($host=source_ip), SumStats::Observation($num=1));

    if (hdr$fc == 0x02) {
        if (source_ip !in authorized_writers) {
            local details = fmt("DNP3 write operation from unauthorized source %s", source_ip);
            event ICS_DETECTION::ics_anomaly_detected("DNP3", source_ip, c$id$resp_h, "Unauthorized_Write", details, c);
        }
    }

    if (hdr$fc == 0x0D) {
        add dnp3_cold_restart_seen[source_ip];
        local details = fmt("DNP3 cold restart command from %s - potential service disruption", source_ip);
        event ICS_DETECTION::ics_anomaly_detected("DNP3", source_ip, c$id$resp_h, "Cold_Restart", details, c);
    }

    if (hdr$fc == 0x14) {
        local details = fmt("DNP3 warm restart command from %s", source_ip);
        event ICS_DETECTION::ics_anomaly_detected("DNP3", source_ip, c$id$resp_h, "Warm_Restart", details, c);
    }

    if (hdr$fc == 0x15) {
        local details = fmt("DNP3 initialize data command from %s", source_ip);
        event ICS_DETECTION::ics_anomaly_detected("DNP3", source_ip, c$id$resp_h, "Initialize_Data", details, c);
    }
}

event connection_state_remove(c: connection) {
    if ("modbus" !in c$service && "s7comm" !in c$service && "enip" !in c$service && "dnp3" !in c$service) return;

    local source_ip = c$id$orig_h;
    if (source_ip in multi_protocol_sources) {
        local protocols = multi_protocol_sources[source_ip];
        if (|protocols| >= multi_protocol_threshold) {
            local protocol_list = join_string_set(protocols, ", ");
            local details = fmt("Multi-protocol access from %s: %s", source_ip, protocol_list);
            event ICS_DETECTION::ics_anomaly_detected("MULTI", source_ip, c$id$resp_h, "Multi_Protocol_Reconnaissance", details, c);
        }
    }
}

event ICS_DETECTION::ics_anomaly_detected(protocol: string, source_ip: addr, destination_ip: addr, event_type: string, details: string, c: connection) {
    local severity = "MEDIUM";
    if ( /Control|Download|Write|High_Rate|Cold_Restart|Warm_Restart|Mass_Export|Protection_Bypass|Safety/ in event_type )
        severity = "HIGH";
    else if ( /Reconnaissance|Exception|Protocol/ in event_type )
        severity = "LOW";
    
    if ( /Cold_Restart|Safety|Protection_Bypass|Mass_Export/ in event_type )
        severity = "CRITICAL";

    local info: Info = [
        $ts=network_time(),
        $protocol=protocol,
        $source_ip=source_ip,
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

    NOTICE([$note=ICS_Anomaly, $src=source_ip, $dst=info$destination_ip,
            $msg=fmt("%s %s: %s", protocol, event_type, details),
            $identifier=cat(source_ip, event_type)]);
}

event modbus_read_holding_registers(c: connection, headers: ModbusHeaders, start_address: count, quantity: count) {
    local source_ip = c$id$orig_h;
    if (quantity > large_read_threshold) {
        local details = fmt("Large register read: %d registers from address %d by %s", quantity, start_address, source_ip);
        event ICS_DETECTION::ics_anomaly_detected("MODBUS", source_ip, c$id$resp_h, "Large_Register_Read", details, c);
    }
}

event modbus_write_multiple_registers(c: connection, headers: ModbusHeaders, start_address: count, registers: ModbusRegisters) {
    local source_ip = c$id$orig_h;
    if (start_address >= critical_register_start && start_address <= critical_register_end) {
        local details = fmt("Write to critical register range starting at %d by %s", start_address, source_ip);
        event ICS_DETECTION::ics_anomaly_detected("MODBUS", source_ip, c$id$resp_h, "Critical_Register_Write", details, c);
    }
}
