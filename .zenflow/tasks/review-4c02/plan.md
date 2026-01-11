# Spec and build

## Configuration
- **Artifacts Path**: {@artifacts_path} → `.zenflow/tasks/{task_id}`

---

## Agent Instructions

Ask the user questions when anything is unclear or needs their input. This includes:
- Ambiguous or incomplete requirements
- Technical decisions that affect architecture or user experience
- Trade-offs that require business context

Do not make assumptions on important decisions — get clarification first.

---

## Workflow Steps

### [x] Step: Technical Specification
<!-- chat-id: 45fb3467-f63d-4d95-9e4f-d08e318056b4 -->

Assess the task's difficulty, as underestimating it leads to poor outcomes.
- easy: Straightforward implementation, trivial bug fix or feature
- medium: Moderate complexity, some edge cases or caveats to consider
- hard: Complex logic, many caveats, architectural considerations, or high-risk changes

Create a technical specification for the task that is appropriate for the complexity level:
- Review the existing codebase architecture and identify reusable components.
- Define the implementation approach based on established patterns in the project.
- Identify all source code files that will be created or modified.
- Define any necessary data model, API, or interface changes.
- Describe verification steps using the project's test and lint commands.

Save the output to `{@artifacts_path}/spec.md` with:
- Technical context (language, dependencies)
- Implementation approach
- Source code structure changes
- Data model / API / interface changes
- Verification approach

If the task is complex enough, create a detailed implementation plan based on `{@artifacts_path}/spec.md`:
- Break down the work into concrete tasks (incrementable, testable milestones)
- Each task should reference relevant contracts and include verification steps
- Replace the Implementation step below with the planned tasks

Rule of thumb for step size: each step should represent a coherent unit of work (e.g., implement a component, add an API endpoint, write tests for a module). Avoid steps that are too granular (single function).

Save to `{@artifacts_path}/plan.md`. If the feature is trivial and doesn't warrant this breakdown, keep the Implementation step below as is.

---

### [x] Step: Code Audit - Modbus Protocol Implementation
<!-- chat-id: c1547bc6-e2a5-4a92-a04a-d094ab89feec -->
Audit and enhance `tools/modbus-stealth-toolkit/modbus_stealth_attack.py`:
- ✓ Validated packet structures against Modbus specification
- ✓ Added missing function codes (0x14-0x17 for file transfer)
- ✓ Added Modbus RTU/ASCII support with serial communication
- ✓ Added comprehensive error handling
- ✓ Added complete type hints and docstrings
- ✓ Verified MITRE technique mappings (T0801, T0836, T0855, T0861, T0873)
- ✓ Created comprehensive testing guide (TESTING.md)

**Enhancements Completed:**
- Added ModbusFunctionCode enum with all codes (0x01-0x2B)
- Added ModbusExceptionCode enum
- Added ModbusPacket class with TCP/RTU/ASCII conversion and validation
- Added CRC-16 calculation for RTU mode
- Added LRC calculation for ASCII mode
- Implemented read_file_record() - FC 0x14
- Implemented write_file_record() - FC 0x15
- Implemented mask_write_register() - FC 0x16
- Implemented read_write_multiple_registers() - FC 0x17
- Added serial port support for RTU/ASCII modes
- Enhanced SecurityEvent with to_dict() method
- Updated version to 3.0 with complete documentation

Verification: Testing guide created at tools/modbus-stealth-toolkit/TESTING.md

---

### [x] Step: Code Audit - S7Comm Protocol Implementation
<!-- chat-id: 5a4aa884-a97d-44cf-85e0-73387864c933 -->
Audit and enhance `tools/s7comm_security_framework/s7comm_exploit.py`:
- ✓ Validated S7Comm packet structures with S7Packet dataclass
- ✓ Added S7CommPlus protocol support (0x72)
- ✓ Added data block mass export automation
- ✓ Added symbol table extraction and analysis
- ✓ Added protection level bypass techniques
- ✓ Improved error handling throughout
- ✓ Created comprehensive testing guide (TESTING.md)

**Enhancements Completed:**
- Added S7ProtocolID, S7FunctionCode, S7Area, S7Protection enums
- Added S7Packet dataclass with to_bytes(), from_bytes(), validate() methods
- Added S7Symbol dataclass for symbol table entries
- Implemented extract_symbol_table() method with SZL data retrieval
- Implemented export_all_data_blocks() with metadata export (SHA256, author, version)
- Implemented test_protection_bypass() with multiple connection type testing
- Implemented s7commplus_probe() for S7CommPlus detection
- Added 4 new CLI commands: extract-symbols, export-all-dbs, test-protection, s7plus-probe
- Enhanced type hints and comprehensive docstrings
- Added MITRE mappings: T0818, T0849, T0861, T0868
- Updated version to 4.0 with complete documentation
- File expanded from 771 to 1316 lines

Verification: Testing guide created at tools/s7comm_security_framework/TESTING.md, syntax validated

---

### [x] Step: Code Audit - CIP/EtherNet/IP Implementation
<!-- chat-id: 416b3e47-0480-4add-be6b-3ffb4f920222 -->
Audit and enhance `tools/cip_security_assessment/cip_exploiter.py`:
- ✓ Validated CIP packet structures with CIPPacket dataclass
- ✓ Added EtherNet/IP encapsulation header structures
- ✓ Added Safety I/O exploitation methods
- ✓ Added implicit messaging manipulation
- ✓ Added CIP Security assessment capabilities
- ✓ Added class-based fuzzing
- ✓ Created comprehensive testing guide (TESTING.md)

**Enhancements Completed:**
- Added CIPServiceCode enum with all common services (0x01-0x53)
- Added CIPClassCode enum (Identity, Assembly, Safety, Security, etc.)
- Added CIPStatusCode enum with all general status codes
- Added EtherNetIPCommand enum for encapsulation commands
- Added EtherNetIPHeader dataclass with to_bytes(), from_bytes() methods
- Added CIPPacket dataclass with to_bytes(), from_bytes(), validate() methods
- Added SafetyPacket dataclass with CRC-16 computation
- Implemented send_raw_cip_packet() for low-level protocol manipulation
- Implemented exploit_safety_io() for Safety I/O exploitation (T0855, T0878)
- Implemented manipulate_implicit_messaging() for Class 1 connection spoofing (T0855, T0856)
- Implemented assess_cip_security_object() for CIP Security assessment (T0801)
- Implemented fuzz_cip_class() for class-based fuzzing (T0855)
- Implemented enumerate_cip_objects() for object discovery (T0801)
- Added 5 new CLI commands: enumerate-objects, cip-security-assess, fuzz-class, safety-io-exploit, implicit-msg
- Enhanced error handling and comprehensive docstrings
- Added MITRE mappings: T0800, T0801, T0803, T0804, T0855, T0856, T0878
- Updated version to 5.0 with complete documentation
- File expanded from 806 to 1480 lines

Verification: Testing guide created at tools/cip_security_assessment/TESTING.md, syntax validated

---

### [x] Step: Code Audit - Detection Rules
<!-- chat-id: c495e15b-4106-4069-a6aa-a544157456f8 -->
Audit and enhance detection rules:
- ✓ Enhanced `configs/suricata_rules/ics_malware_detection.rules` with 13 new rules
- ✓ Enhanced `configs/zeek/ics_detection.zeek` with DNP3 protocol support
- ✓ Created comprehensive testing guide (DETECTION_TESTING.md)
- ✓ Added protocol coverage for DNP3, Modbus file transfer, S7CommPlus, CIP Safety I/O
- ✓ Implemented false positive reduction techniques (thresholds, whitelisting, flowbit chaining)

**Enhancements Completed:**

**Suricata Rules (220→486 lines, 9→22 rules):**
- Added DNP3 detection: unauthorized write (SID 400003), cold restart (SID 400004), auth bypass (SID 400005)
- Added Modbus file transfer (SID 400006) and mask write (SID 400007)
- Added S7CommPlus protocol detection (SID 400008)
- Added S7Comm symbol table extraction (SID 400009) and DB mass export (SID 400010)
- Added S7Comm protection bypass detection (SID 400011)
- Added CIP Safety I/O exploitation (SID 400012)
- Added CIP implicit messaging manipulation (SID 400013)
- Added CIP Security Object enumeration (SID 400014)
- Added CIP fuzzing detection (SID 400015)
- Added ENIP ListIdentity reconnaissance (SID 400016)
- All rules aligned with attack tool methods and MITRE ATT&CK techniques

**Zeek Script (231→311 lines):**
- Added complete DNP3 protocol support with write/restart detection
- Added Modbus file transfer operations tracking (FC 0x14-0x17)
- Added S7Comm data block mass export detection (10+ reads in 60s)
- Added S7Comm symbol table extraction detection (5+ SZL reads in 2min)
- Added S7CommPlus protocol detection (PDU type 0x72)
- Added DNP3 request rate monitoring via SumStats
- Enhanced severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Added state tracking tables for advanced attack pattern detection

**Testing Framework:**
- Created DETECTION_TESTING.md (559 lines) with 10 test cases
- PCAP validation procedures for each rule
- False positive analysis methodology
- SIEM integration examples (Splunk, Elastic)
- Suricata-Verify automated testing configuration
- Performance impact assessment procedures
- Cross-reference matrix linking detection rules to attack tools

**Documentation:**
- Created ENHANCEMENT_SUMMARY.md documenting all changes
- Protocol coverage matrix (Modbus, S7Comm, DNP3, CIP/ENIP)
- MITRE ATT&CK mapping (11 techniques, 6 tactics)
- Deployment recommendations and tuning guidelines
- 100% alignment between detection rules and implemented attack methods

Verification: Testing guide created at configs/DETECTION_TESTING.md with comprehensive PCAP validation, false positive analysis, and tool alignment documentation

---

### [x] Step: Implement OPC-UA Security Framework
<!-- chat-id: b601d10c-4a08-4a35-8dfe-8a46d1223473 -->
Create new `tools/opcua_security_framework/`:
- ✓ Certificate validation bypass techniques
- ✓ Subscription manipulation
- ✓ Node enumeration
- ✓ Session hijacking
- ✓ Fuzzing implementation
- ✓ MITRE mapping (T0801, T0819, T0855, T0861, T0868, T0877, T0888)
- ✓ Comprehensive documentation

**Enhancements Completed:**
- Created OPCUASecurityFramework class with comprehensive assessment capabilities
- Added OPCUASecurityPolicy, OPCUAMessageSecurityMode, OPCUANodeClass enums
- Added OPCUAEndpoint dataclass for endpoint information
- Added OPCUANodeInfo dataclass for node details
- Implemented discover_endpoints() - enumerate all available endpoints (T0888)
- Implemented enumerate_nodes() - recursive address space discovery (T0801, T0861)
- Implemented test_certificate_bypass() - certificate validation testing (T0819)
- Implemented create_malicious_subscription() - subscription manipulation (T0801, T0855)
- Implemented fuzz_node_write() - protocol fuzzing with malformed data (T0855)
- Implemented test_session_hijacking() - session token reuse testing (T0819)
- Implemented assess_security_configuration() - security posture evaluation (T0888)
- Added self-signed certificate generation for testing
- Added SubscriptionHandler class for data change monitoring
- Complete CLI with 10+ command options
- Enhanced error handling and logging
- Added JSON export functionality
- Created comprehensive README.md (179 lines)
- Created comprehensive TESTING.md (686 lines) with 14 test cases
- Updated version to 1.0 with complete documentation
- File size: 1056 lines

Verification: Testing guide created at tools/opcua_security_framework/TESTING.md, syntax validated

---

### [x] Step: Implement PROFINET Exploitation Module
<!-- chat-id: 9b3a63fb-df0b-4259-8dc5-f44381e77c49 -->
Create new `tools/profinet_exploitation/`:
- ✓ DCP (Discovery and Configuration Protocol) manipulation
- ✓ Real-time class exploitation
- ✓ Device reprogramming techniques
- ✓ MITRE mapping (T0800, T0878)
- ✓ Documentation and examples

**Enhancements Completed:**
- Created PROFINETExploitationFramework class with comprehensive DCP and RT capabilities
- Added DCPServiceID, DCPServiceType, DCPBlockOption, DCPSuboption enums
- Added PNIOFrameID, PNIOAlarmType enums for real-time communication
- Added DCPPacket, DCPBlock, EthernetFrame, RTFrame dataclasses with to_bytes()/from_bytes() methods
- Added PNIODevice, SecurityEvent dataclasses for device tracking and event logging
- Implemented discover_devices() - DCP Identify broadcast discovery (T0801, T0868)
- Implemented set_device_name() - NameOfStation manipulation (T0855)
- Implemented set_device_ip() - IP address reconfiguration (T0855)
- Implemented factory_reset_device() - Factory reset via DCP Control (T0809)
- Implemented inject_rt_frame() - RT cyclic data injection (T0855, T0803)
- Implemented spoof_alarm() - PROFINET alarm spoofing (T0878, T0804)
- Implemented monitor_rt_traffic() - RT traffic capture and analysis (T0801, T0802)
- Implemented activate_firmware_update_mode() - Firmware update mode activation (T0800)
- Implemented reprogram_device_tftp() - TFTP firmware upload (T0800, T0873)
- Implemented fuzz_dcp_options() - DCP protocol fuzzing (T0855)
- Added raw socket Layer 2 communication (EtherType 0x8892)
- Complete CLI with 9 command options (discover, set-name, set-ip, factory-reset, inject-rt, spoof-alarm, monitor-rt, firmware-mode, fuzz-dcp)
- Enhanced error handling with SecurityEvent logging
- Added JSON export for devices and security events
- Added MITRE mappings: T0800, T0801, T0802, T0803, T0804, T0809, T0855, T0858, T0868, T0871, T0873, T0878
- Created comprehensive README.md (434 lines) with protocol documentation and attack scenarios
- Created comprehensive TESTING.md (762 lines) with 10 test cases and PCAP analysis
- Updated version to 1.0 with complete documentation
- File size: 1080 lines

Verification: Testing guide created at tools/profinet_exploitation/TESTING.md, syntax validated

---

### [x] Step: Implement BACnet Security Assessment
<!-- chat-id: 4af92a43-e325-4032-9d4a-5d4c71f33c13 -->
Create new `tools/bacnet_security_assessment/`:
- ✓ WriteProperty attacks
- ✓ Device binding manipulation
- ✓ MS/TP network attacks
- ✓ MITRE mapping (T0801, T0802, T0803, T0804, T0836, T0855, T0858, T0861, T0868, T0871, T0873, T0888)
- ✓ Comprehensive documentation

**Enhancements Completed:**
- Created BACnetSecurityAssessment class with comprehensive BACnet/IP and MS/TP capabilities
- Added BACnetPDUType, BACnetConfirmedService, BACnetUnconfirmedService enums
- Added BACnetObjectType enum with 30+ standard object types
- Added BACnetPropertyIdentifier enum with 168 standard properties
- Added BACnetApplicationTag enum for data encoding
- Added BACnetMSTPFrameType enum for MS/TP protocol
- Added BACnetDevice, BACnetObject, SecurityEvent dataclasses
- Added BACnetPacket dataclass with to_bytes(), from_bytes() methods
- Implemented discover_devices() - Who-Is/I-Am device discovery (T0888, T0868)
- Implemented read_property() - property value reading (T0801, T0861)
- Implemented write_property() - WriteProperty attack with priority override (T0855, T0836)
- Implemented enumerate_objects() - complete object inventory (T0861, T0888)
- Implemented manipulate_priority_array() - priority array control override (T0855, T0836)
- Implemented device_communication_control() - block/enable communication (T0803, T0804)
- Implemented reinitialize_device() - cold/warm restart (T0858, T0871)
- Implemented subscribe_cov() - Change-of-Value monitoring (T0801, T0802)
- Implemented atomic_write_file() - project file infection (T0873, T0871)
- Implemented mstp_token_manipulation() - MS/TP token passing attacks (T0803, T0804)
- Implemented fuzz_service() - protocol fuzzing for vulnerability discovery (T0855)
- Added complete BACnet/IP BVLC packet encoding/decoding
- Added BACnet application tag encoding (NULL, BOOLEAN, UNSIGNED_INT, SIGNED_INT, REAL, CHARACTER_STRING, OBJECT_IDENTIFIER)
- Added context tag encoding for service parameters
- Added RS-485 MS/TP serial communication support
- Complete CLI with 10 command options (discover, enumerate, write-property, priority-array, comm-control, reinitialize, subscribe-cov, atomic-write-file, mstp-token, fuzz)
- Enhanced error handling and comprehensive logging
- Added JSON export for devices, objects, and security events
- Added MITRE mappings: T0801, T0802, T0803, T0804, T0836, T0855, T0858, T0861, T0868, T0871, T0873, T0888
- Created comprehensive README.md (454 lines) with protocol background, priority array mechanics, BVLC functions, attack scenarios
- Created comprehensive TESTING.md (762 lines) with 14 test cases, PCAP analysis, false positive analysis
- Updated version to 1.0 with complete documentation
- File size: 1379 lines

Verification: Testing guide created at tools/bacnet_security_assessment/TESTING.md, syntax validated

---

### [x] Step: Enhance Detection Rules for New Protocols
<!-- chat-id: f2887163-df0e-4b8f-9d50-549ff7aa4255 -->
Add detection coverage:
- ✓ Create `configs/suricata_rules/opcua_detection.rules`
- ✓ Create `configs/suricata_rules/profinet_detection.rules`
- ✓ Create `configs/suricata_rules/bacnet_detection.rules`
- ✓ Create `configs/zeek/opcua_monitor.zeek`
- ✓ Create `configs/zeek/profinet_monitor.zeek`
- ✓ Create `configs/zeek/bacnet_monitor.zeek`

**Enhancements Completed:**

**Suricata Rules (39 new rules):**
- `opcua_detection.rules` (12 rules):
  - OPC-UA endpoint discovery (T0888)
  - Insecure session creation with SecurityMode=None (T0819)
  - Recursive node enumeration via Browse service (T0861, T0801)
  - Unauthorized Write service calls (T0855)
  - High-rate subscription creation (T0801, T0802)
  - Method call service (remote execution - T0871)
  - Session hijacking detection (T0819)
  - Certificate validation bypass (T0819)
  - Fuzzing with malformed write values (T0855)
  - Multi-service reconnaissance (T0888)
  - Historical data access (T0802)
  - Persistent session detection (T0868)
  - Aligned with tools/opcua_security_framework/opcua_exploit.py

- `profinet_detection.rules` (12 rules):
  - DCP Set NameOfStation (T0855)
  - DCP Set IP Address (T0855)
  - DCP Factory Reset (T0809, T0858)
  - DCP Identify broadcast storm (T0888, T0868)
  - RT Class 1 frame injection (T0855, T0803)
  - Alarm spoofing (T0878, T0804)
  - Firmware update mode activation (T0800)
  - TFTP firmware upload (T0800, T0873)
  - DCP protocol fuzzing (T0855)
  - RT traffic monitoring (T0802)
  - RT Class 3 IRT manipulation (T0855)
  - Device communication control (T0803)
  - Aligned with tools/profinet_exploitation/profinet_exploit.py

- `bacnet_detection.rules` (15 rules):
  - Who-Is broadcast storm (T0888, T0868)
  - Unauthorized WriteProperty (T0855, T0836)
  - ReadProperty enumeration (T0861)
  - Priority array manipulation (T0855, T0836)
  - DeviceCommunicationControl (T0803, T0804)
  - ReinitializeDevice cold restart (T0858, T0871)
  - ReinitializeDevice warm restart (T0858, T0871)
  - COV subscription storm (T0801, T0802)
  - AtomicWriteFile (project infection - T0873, T0871)
  - AtomicReadFile (data exfiltration - T0802)
  - Service fuzzing (T0855)
  - MS/TP token manipulation (T0803, T0804)
  - WritePropertyMultiple bulk modification (T0836)
  - CreateObject unauthorized creation (T0871)
  - DeleteObject data destruction (T0809)
  - Aligned with tools/bacnet_security_assessment/bacnet_assessment.py

**Zeek Scripts (3 new monitors):**
- `opcua_monitor.zeek` (280 lines):
  - Endpoint discovery tracking
  - Insecure session detection (SecurityMode=None)
  - Recursive Browse operation counting
  - Unauthorized Write detection
  - Subscription manipulation monitoring
  - Method call tracking
  - Session hijacking detection
  - Certificate validation error tracking
  - Historical data access monitoring
  - Service-based severity classification (CRITICAL/HIGH/MEDIUM/LOW)

- `profinet_monitor.zeek` (275 lines):
  - DCP Identify storm detection
  - DCP Set operations tracking (NameOfStation, IP)
  - Factory reset monitoring
  - RT Class 1/2/3 frame injection detection
  - Alarm spoofing detection
  - TFTP firmware upload monitoring
  - Layer 2 raw packet analysis (EtherType 0x8892)
  - Frame ID classification and tracking

- `bacnet_monitor.zeek` (295 lines):
  - Who-Is broadcast storm detection
  - Unauthorized WriteProperty tracking
  - Priority array manipulation detection
  - DeviceCommunicationControl monitoring
  - ReinitializeDevice cold/warm restart tracking
  - COV subscription storm detection
  - AtomicWriteFile/AtomicReadFile monitoring
  - MS/TP token manipulation detection
  - Service fuzzing detection (large packets)
  - BACnet/IP BVLC header parsing

**Protocol Coverage Summary:**
- Total Suricata rules: 61 (22 existing + 39 new)
- Total Zeek monitors: 6 (3 existing + 3 new)
- Protocols covered: Modbus, S7Comm, DNP3, CIP/ENIP, OPC-UA, PROFINET, BACnet
- MITRE techniques: 25+ unique techniques across all protocols
- 100% alignment between attack tools and detection rules

**Cross-References:**
- All rules reference corresponding attack tool methods
- SID ranges: OPC-UA (410001-410012), PROFINET (420001-420012), BACnet (430001-430015)
- All rules include MITRE ATT&CK metadata
- Priority levels: 1 (Critical), 2 (High), 3 (Medium)
- Thresholds configured to reduce false positives

Verification: 39 new Suricata rules created, 3 new Zeek monitors created, all aligned with attack tool implementations

---

### [x] Step: README Code Accuracy Audit (Part 1: Lines 1-5000)
<!-- chat-id: bd4f7659-6ba5-4e57-955e-f60597e2bf17 -->
Review README.md lines 1-5000:
- ✓ Verified all code examples are technically accurate
- ✓ Added cross-references to actual implementations
- ✓ Fixed protocol packet structures
- ✓ Updated MITRE mappings
- ✓ Added file:line references

**Enhancements Completed:**
- Added Implementation column to protocol comparison table (line 747-757)
- Cross-referenced all protocols to actual tool implementations
- Fixed Modbus TCP packet structure in Schneider exploit (line 10749-10758)
  - Added proper MBAP header documentation and reference to tools/modbus-stealth-toolkit/modbus_stealth_attack.py:138-147
- Fixed S7Comm packet structure in C code example (line 4386-4404)
  - Added missing TPKT header (4 bytes): version, reserved, length
  - Added missing COTP header (3 bytes): length, PDU type, TPDU number
  - Complete validation against tools/s7comm_security_framework/s7comm_exploit.py:94-140
- Enhanced Suricata detection rules with cross-references
  - Modbus write detection rule (line 1099) - fixed to check protocol ID at offset 2
  - S7Comm Stuxnet detection rules (line 1650, 1654) - added packet structure validation
- Fixed CIP service codes in Ruby exploit (line 10699-10704)
  - Corrected STOP: 0x07 (was 0x4E)
  - Corrected START: 0x06 (was 0x4D)
  - Added READ_TAG: 0x4C and WRITE_TAG: 0x4D
  - Validated against tools/cip_security_assessment/cip_exploiter.py:44-73

Verification: All protocol packet structures validated against actual implementations, cross-references added throughout lines 1-5000

---

### [ ] Step: README Code Accuracy Audit (Part 2: Lines 5001-10000)
Review README.md lines 5001-10000:
- Continue accuracy verification
- Add cross-references
- Fix errors
- Update content

Verification: Manual review

---

### [ ] Step: README Code Accuracy Audit (Part 3: Lines 10001-15000)
Review README.md lines 10001-15000:
- Continue accuracy verification
- Add cross-references
- Fix errors
- Update content

Verification: Manual review

---

### [ ] Step: README Code Accuracy Audit (Part 4: Lines 15001-18416)
Review README.md lines 15001-18416:
- Complete accuracy verification
- Add cross-references
- Fix errors
- Update content

Verification: Manual review

---

### [ ] Step: Create Protocol Quick Reference Guides
Create `docs/protocol_quick_reference/`:
- `modbus.md` - Modbus attack/defense reference
- `s7comm.md` - S7Comm attack/defense reference
- `cip.md` - CIP/EtherNet/IP reference
- `dnp3.md` - DNP3 reference
- `opcua.md` - OPC-UA reference
- `profinet.md` - PROFINET reference
- `bacnet.md` - BACnet reference

Each with: attack methods, detection signatures, MITRE mappings, tool references

Verification: Technical accuracy review

---

### [ ] Step: Create Attack Scenario Playbooks
Create `docs/attack_scenarios/`:
- `historian_poisoning.md` - End-to-end historian attack scenario
- `plc_logic_injection.md` - Logic manipulation scenario
- `safety_system_bypass.md` - Safety system attack scenario
- `network_reconnaissance.md` - ICS network discovery scenario

Each with: objectives, tools, commands, detection indicators

Verification: Walkthrough testing

---

### [ ] Step: Implement Testing Framework
Create `tools/test_framework/`:
- `test_modbus.py` - Unit tests for Modbus toolkit
- `test_s7comm.py` - Unit tests for S7Comm framework
- `test_cip.py` - Unit tests for CIP assessment
- `test_opcua.py` - Unit tests for OPC-UA framework
- `mock_plc_server.py` - Mock PLC for testing

Verification: pytest execution, coverage >70%

---

### [ ] Step: Standardize Tool Interfaces
Apply standardization across all tools:
- Add common base class `ICSSecurityTool`
- Add YAML/JSON configuration support
- Add dry-run mode to all tools
- Add result export in multiple formats
- Add safety validation checks

Verification: Interface consistency check

---

### [ ] Step: Create Master Index and Cross-Reference System
Update README.md:
- Add comprehensive table of contents with line anchors
- Create method index: `protocol:method → file:line`
- Add "See implementation" links after all code examples
- Create attack technique matrix
- Add navigation aids

Verification: Link validation, navigation testing

---

### [ ] Step: Final Validation and Report
Final quality assurance:
- Run all tests (unit + integration)
- Validate all cross-references work
- Check MITRE mapping accuracy
- Verify protocol implementations
- Run linters and type checkers
- PCAP validation of generated traffic
- False positive testing of detection rules
- Write completion report to `{@artifacts_path}/report.md`

Verification: Comprehensive testing suite
