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

### [ ] Step: Code Audit - Detection Rules
Audit and enhance detection rules:
- `configs/suricata_rules/ics_malware_detection.rules` - reduce false positives
- `configs/zeek/ics_detection.zeek` - add missing protocol coverage
- Test rules against known-good and known-bad traffic
- Add protocol coverage for gaps

Verification: PCAP replay testing, false positive analysis

---

### [ ] Step: Implement OPC-UA Security Framework
Create new `tools/opcua_security_framework/`:
- Certificate validation bypass techniques
- Subscription manipulation
- Node enumeration
- Session hijacking
- Fuzzing implementation
- MITRE mapping (T0801, T0819, T0855)
- Comprehensive documentation

Verification: Test against FreeOpcUa simulator

---

### [ ] Step: Implement PROFINET Exploitation Module
Create new `tools/profinet_exploitation/`:
- DCP (Discovery and Configuration Protocol) manipulation
- Real-time class exploitation
- Device reprogramming techniques
- MITRE mapping (T0800, T0878)
- Documentation and examples

Verification: Test against PROFINET simulator

---

### [ ] Step: Implement BACnet Security Assessment
Create new `tools/bacnet_security_assessment/`:
- WriteProperty attacks
- Device binding manipulation
- MS/TP network attacks
- MITRE mapping (T0855, T0836)
- Documentation

Verification: Test against BACnet simulator

---

### [ ] Step: Enhance Detection Rules for New Protocols
Add detection coverage:
- Create `configs/suricata_rules/opcua_detection.rules`
- Create `configs/suricata_rules/profinet_detection.rules`
- Create `configs/suricata_rules/bacnet_detection.rules`
- Create `configs/zeek/opcua_monitor.zeek`
- Create `configs/zeek/profinet_monitor.zeek`
- Create `configs/zeek/bacnet_monitor.zeek`

Verification: Rule validation, PCAP testing

---

### [ ] Step: README Code Accuracy Audit (Part 1: Lines 1-5000)
Review README.md lines 1-5000:
- Verify all code examples are technically accurate
- Add cross-references to actual implementations
- Mark theoretical code as such
- Fix protocol packet structures
- Update MITRE mappings
- Add file:line references

Verification: Manual review, cross-check with tools

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
