# ICS Detection Script for Zeek
# Detects:
# - High-rate Modbus/S7Comm/ENIP requests
# - Unauthorized write attempts
# - Critical register writes
# - Multi-protocol reconnaissance
# - PLC stop/start and logic downloads
#
# Load in local.zeek:
# @load configs/zeek/ics_detection

@load base/frameworks/notice
@load base/frameworks/sumstats
@load protocols/modbus
@load protocols/s7comm
@load protocols/enip

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

event connection_state_remove(c: connection) {
    if ("modbus" !in c$service && "s7comm" !in c$service && "enip" !in c$service) return;

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
    if ( /Control|Download|Write|High_Rate/ in event_type )
        severity = "HIGH";
    else if ( /Reconnaissance|Exception/ in event_type )
        severity = "LOW";

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
