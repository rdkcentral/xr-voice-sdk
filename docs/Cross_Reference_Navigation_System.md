# XR Voice SDK Cross-Reference System

## Overview

This document provides a comprehensive cross-reference system for navigating between related concepts, components, APIs, and configurations throughout the XR Voice SDK documentation. Use this system to quickly find related information and understand component interactions.

## Component Cross-References

### XRAudio Component References

**Core Files:**
- **Header:** [`src/xr-audio/xraudio.h`](../src/xr-audio/xraudio.h)
- **Implementation:** [`src/xr-audio/xraudio.c`](../src/xr-audio/xraudio.c)
- **Configuration:** [`src/xr-audio/xraudio_config_default.json`](../src/xr-audio/xraudio_config_default.json)

**Related Documentation:**
- **[XRAudio Component Analysis](XRAudio_Component_Analysis.md)** - Primary component analysis
- **[XRAudio Real-Time Processing](XRAudio_Real_Time_Processing.md)** - Processing pipeline details  
- **[XRAudio Input Subsystem](XRAudio_Input_Subsystem.md)** - Input device management
- **[XRAudio Threading Model & Synchronization](XRAudio_Threading_Model_Synchronization.md)** - Threading implementation

**Dependencies:**
- **XR-Timer** → [XRAudio Utility Functions & Helpers](XRAudio_Utility_Functions_Helpers.md)
- **XR-Timestamp** → [XRAudio Real-Time Processing](XRAudio_Real_Time_Processing.md)  
- **XR-Logger** → [Error Handling Patterns](Error_Handling_Patterns_Return_Code_Conventions.md)
- **XR-MQ** → [XRSR Message Queue System](XRSR_Message_Queue_System.md)

**Configuration Cross-References:**
```json
xraudio_config_default.json
├── input.kwd → Keyword Detection → XRAudio_Component_Analysis.md#keyword-detection
├── input.eos → End-of-Speech → XRAudio_Real_Time_Processing.md#eos-detection  
├── input.dga → Gain Adjustment → XRAudio_Utility_Functions_Helpers.md#gain-control
├── input.sdf → Speech Detection → XRAudio_Component_Analysis.md#speech-framework
└── hal → Hardware Layer → XRAudio_Input_Subsystem.md#hal-integration
```

### XRSR Component References

**Core Files:**
- **Header:** [`src/xr-speech-router/xrsr.h`](../src/xr-speech-router/xrsr.h)
- **Implementation:** [`src/xr-speech-router/xrsr.c`](../src/xr-speech-router/xrsr.c)
- **Configuration:** [`src/xr-speech-router/xrsr_config_default.json`](../src/xr-speech-router/xrsr_config_default.json)

**Related Documentation:**
- **[XRSR Architecture & Protocol Analysis](XRSR_Architecture_Protocol_Analysis.md)** - Primary component analysis
- **[XRSR Session Lifecycle Management](XRSR_Session_Lifecycle_Management.md)** - Session management
- **[XRSR HTTP Protocol Implementation](XRSR_HTTP_Protocol_Implementation.md)** - HTTP protocol details
- **[XRSR WebSocket Protocol Implementation](XRSR_WebSocket_Protocol_Implementation.md)** - WebSocket protocol
- **[XRSR SDT Protocol Analysis](XRSR_SDT_Protocol_Analysis.md)** - SDT protocol implementation

**Protocol Cross-References:**
```
XRSR Protocol Matrix:
├── HTTP/HTTPS → XRSR_HTTP_Protocol_Implementation.md
├── WebSocket/WSS → XRSR_WebSocket_Protocol_Implementation.md  
├── SDT → XRSR_SDT_Protocol_Analysis.md
└── Protocol Selection Logic → XRSR_Architecture_Protocol_Analysis.md#protocol-selection
```

**Configuration Cross-References:**
```json
xrsr_config_default.json
├── http.debug → HTTP Protocol → XRSR_HTTP_Protocol_Implementation.md#debugging
├── ws.fpm → Full Power Mode → XRSR_Power_Mode_Integration.md#fpm-configuration
├── ws.lpm → Low Power Mode → XRSR_Power_Mode_Integration.md#lpm-configuration
└── xraudio → Audio Integration → Cross_Component_Integration_Analysis.md#xrsr-xraudio
```

### XRSV Component References

**Core Files:**
- **Header:** [`src/xr-speech-vrex/xrsv.h`](../src/xr-speech-vrex/xrsv.h)
- **HTTP Implementation:** [`src/xr-speech-vrex/xrsv_http/xrsv_http.h`](../src/xr-speech-vrex/xrsv_http/xrsv_http.h)
- **WebSocket Implementation:** [`src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h`](../src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h)

**Related Documentation:**
- **[XRSV Architecture Analysis](XRSV_Architecture_Analysis.md)** - Primary component analysis
- **[XRSV HTTP Voice Service Implementation](XRSV_HTTP_Voice_Service_Implementation.md)** - HTTP service details
- **[XRSV WebSocket NextGen Implementation](XRSV_WebSocket_NextGen_Implementation.md)** - WebSocket service details
- **[XRSV Configuration Management](XRSV_Configuration_Management.md)** - Configuration handling

## API Cross-Reference Matrix

### Core SDK API (`xr_voice_sdk.h`)

| Function | Parameters | Returns | Related Docs |
|----------|-----------|---------|--------------|
| `vsdk_init()` | `bool ansi_color, const char *filename, uint32_t file_size_max` | `int` | [API Interface Documentation](API_Interface_Documentation.md#core-sdk-api) |
| `vsdk_init_user_print()` | `xlog_print_t print, xlog_print_t print_safe, bool ansi_color, const char *filename, uint32_t file_size_max` | `int` | [API Interface Documentation](API_Interface_Documentation.md#initialization) |
| `vsdk_term()` | `void` | `void` | [Component Initialization](Component_Initialization_Startup_Documentation.md#shutdown) |
| `vsdk_version()` | `vsdk_version_info_t *version_info, uint32_t *qty` | `void` | [Versioning System](Versioning_System.md#api-interface) |
| `vsdk_log_level_get()` | `xlog_module_id_t id` | `xlog_level_t` | [Error Handling Patterns](Error_Handling_Patterns_Return_Code_Conventions.md#logging) |
| `vsdk_log_level_set()` | `xlog_module_id_t id, xlog_level_t level` | `void` | [Configuration Management](Runtime_Configuration_Update_Capabilities.md#log-levels) |

### XRAudio API References

| Data Type | Definition | Usage | Related Docs |
|-----------|------------|-------|--------------|
| `xraudio_result_t` | Error codes enumeration | All XRAudio functions | [XRAudio Component Analysis](XRAudio_Component_Analysis.md#error-handling) |
| `xraudio_input_record_from_t` | Recording start point | Recording functions | [XRAudio Input Subsystem](XRAudio_Input_Subsystem.md#recording-modes) |
| `audio_in_callback_event_t` | Input event types | Input callbacks | [XRAudio Real-Time Processing](XRAudio_Real_Time_Processing.md#event-handling) |
| `audio_out_callback_event_t` | Output event types | Output callbacks | [XRAudio Component Analysis](XRAudio_Component_Analysis.md#output-events) |

### XRSR API References

| Data Type | Definition | Usage | Related Docs |
|-----------|------------|-------|--------------|
| `xrsr_src_t` | Audio source types | Session creation | [XRSR Architecture](XRSR_Architecture_Protocol_Analysis.md#source-types) |
| `xrsr_protocol_t` | Protocol types | Protocol selection | [XRSR Architecture](XRSR_Architecture_Protocol_Analysis.md#protocol-support) |
| `xrsr_session_request_type_t` | Request types | Session requests | [XRSR Session Lifecycle](XRSR_Session_Lifecycle_Management.md#request-types) |
| `xrsr_result_t` | Result codes | All XRSR functions | [XRSR Error Handling](XRSR_Error_Handling_Recovery.md#result-codes) |

## Configuration Cross-Reference System

### Configuration File Hierarchy

```
Configuration Structure:
├── vsdk_config.json (Generated)
│   ├── xraudio → xraudio_config_default.json
│   └── xrsr → xrsr_config_default.json
├── rdkx_logger.json (Generated)  
│   ├── modules → rdkx_logger_modules.json
│   └── global → rdkx_logger_global.json
└── Individual Component Configs
    ├── xraudio_config_default.json
    └── xrsr_config_default.json
```

### Configuration Parameter Cross-References

| Parameter | Component | File Location | Documentation |
|-----------|-----------|---------------|---------------|
| `input.kwd.*` | XRAudio | `xraudio_config_default.json` | [XRAudio Configuration](XRAudio_Configuration_Management.md#keyword-detection) |
| `input.eos.*` | XRAudio | `xraudio_config_default.json` | [XRAudio Configuration](XRAudio_Configuration_Management.md#eos-detection) |
| `http.debug` | XRSR | `xrsr_config_default.json` | [XRSR HTTP Protocol](XRSR_HTTP_Protocol_Implementation.md#debug-configuration) |
| `ws.fpm.*` | XRSR | `xrsr_config_default.json` | [XRSR Power Modes](XRSR_Power_Mode_Integration.md#full-power-mode) |
| `ws.lpm.*` | XRSR | `xrsr_config_default.json` | [XRSR Power Modes](XRSR_Power_Mode_Integration.md#low-power-mode) |

## Build System Cross-References

### CMake Options and Dependencies

| CMake Option | Component | Related Files | Documentation |
|--------------|-----------|---------------|---------------|
| `HTTP_ENABLED` | XRSR | `xrsr_protocol_http.c` | [XRSR HTTP Protocol](XRSR_HTTP_Protocol_Implementation.md) |
| `WS_ENABLED` | XRSR | `xrsr_protocol_ws.c` | [XRSR WebSocket Protocol](XRSR_WebSocket_Protocol_Implementation.md) |
| `SDT_ENABLED` | XRSR | `xrsr_protocol_sdt.c` | [XRSR SDT Protocol](XRSR_SDT_Protocol_Analysis.md) |
| `RDK_VERSION_ENABLED` | Core | Version management | [Versioning System](Versioning_System.md#rdk-integration) |
| `VSDK_VENDOR_XLOG` | Logging | `xr-logger/` | [Build System Configuration](Build_System_Configuration.md#logging-options) |

### Library Dependencies

| Library | Usage | Components | Documentation |
|---------|-------|------------|---------------|
| `c, bsd, m` | Standard libraries | All components | [Build System Configuration](Build_System_Configuration.md#standard-libraries) |
| `pthread` | Threading | XRAudio, XRSR | [Threading Model](Threading_Model.md) |
| `uuid` | UUID generation | XRSR sessions | [XRSR Session Lifecycle](XRSR_Session_Lifecycle_Management.md#session-identification) |
| `jansson` | JSON parsing | Configuration | [Configuration Schema](Configuration_Schema_Documentation.md#json-processing) |
| `curl` | HTTP protocol | XRSR HTTP | [XRSR HTTP Protocol](XRSR_HTTP_Protocol_Implementation.md#curl-integration) |
| `nopoll` | WebSocket protocol | XRSR WebSocket | [XRSR WebSocket Protocol](XRSR_WebSocket_Protocol_Implementation.md#nopoll-library) |

## Integration Pattern Cross-References

### Component Interaction Patterns

| Interaction | Components | Data Flow | Documentation |
|-------------|------------|-----------|---------------|
| Audio Input → Speech Router | XRAudio → XRSR | Audio data via message queue | [Cross Component Integration](Cross_Component_Integration_Analysis.md#audio-speech-integration) |
| Speech Router → Voice Service | XRSR → XRSV | Protocol-specific data | [Cross Component Integration](Cross_Component_Integration_Analysis.md#speech-voice-integration) |
| Voice Service → Application | XRSV → App | Recognition results | [API Interface Documentation](API_Interface_Documentation.md#callback-patterns) |
| Timer → All Components | XR-Timer → All | Scheduled callbacks | [Threading Model](Threading_Model.md#timer-integration) |
| Logger → All Components | XR-Logger → All | Log messages | [Error Handling Patterns](Error_Handling_Patterns_Return_Code_Conventions.md#logging-integration) |

### Threading Interaction References

| Thread Type | Components | Synchronization | Documentation |
|-------------|------------|----------------|---------------|
| Main Thread | VSDK Core | API calls | [Threading Model](Threading_Model.md#main-thread) |
| Audio Processing | XRAudio | Atomic operations | [XRAudio Threading](XRAudio_Threading_Model_Synchronization.md) |
| Protocol Threads | XRSR | Message queues | [XRSR Message Queue](XRSR_Message_Queue_System.md) |
| Timer Threads | XR-Timer | Callback mechanisms | [Threading Model](Threading_Model.md#timer-threads) |
| Logging Threads | XR-Logger | Signal-safe operations | [Threading Model](Threading_Model.md#logging-threads) |

## Error Handling Cross-References

### Error Code Hierarchies

| Component | Error Type | Range | Documentation |
|-----------|------------|-------|---------------|
| Core VSDK | `int` return codes | `0` = success, `>0` = error | [API Interface Documentation](API_Interface_Documentation.md#error-handling) |
| XRAudio | `xraudio_result_t` | `XRAUDIO_RESULT_*` | [XRAudio Component Analysis](XRAudio_Component_Analysis.md#error-codes) |
| XRSR | `xrsr_result_t` | `XRSR_RESULT_*` | [XRSR Error Handling](XRSR_Error_Handling_Recovery.md#error-codes) |
| XRSV | `xrsv_result_t` | `XRSV_RESULT_*` | [XRSV Error Handling](XRSV_Error_Handling.md#error-codes) |

### Error Recovery Patterns

| Error Scenario | Recovery Action | Components | Documentation |
|----------------|----------------|------------|---------------|
| Audio Device Failure | Graceful degradation | XRAudio | [XRAudio Component Analysis](XRAudio_Component_Analysis.md#error-recovery) |
| Network Connection Loss | Protocol fallback | XRSR | [XRSR Error Handling](XRSR_Error_Handling_Recovery.md#network-recovery) |
| Authentication Failure | User notification | XRSV | [XRSV Authentication](XRSV_Authentication_Integration.md#error-handling) |
| Configuration Error | Default fallback | All | [Configuration Inheritance](Configuration_Inheritance_Override_Mechanisms.md#error-fallback) |

## Platform Integration Cross-References

### XR Platform References

| Platform | Integration Method | Components | Documentation |
|----------|-------------------|------------|---------------|
| Unity | C# P/Invoke wrapper | Core VSDK API | [XR Platform Integration](XR_Platform_Integration_Guide_for_Developers.md#unity-integration) |
| Unreal Engine | C++ Blueprint component | Core VSDK API | [XR Platform Integration](XR_Platform_Integration_Guide_for_Developers.md#unreal-integration) |
| Native OpenXR | Direct C API | Core VSDK API | [XR Platform Integration](XR_Platform_Integration_Guide_for_Developers.md#openxr-integration) |
| Mixed Language | C++ wrapper classes | All APIs | [CPP Compatibility](../openspec/specs/CPP_Compatibility_Mixed_Language_Support.md) |

## Quick Navigation Index

### By Component
- **Foundation:** [SDK Architecture](SDK_Architecture.md) → [Component Dependencies](Component_Dependencies.md)
- **XRAudio:** [Component Analysis](XRAudio_Component_Analysis.md) → [Real-Time Processing](XRAudio_Real_Time_Processing.md)
- **XRSR:** [Architecture & Protocol](XRSR_Architecture_Protocol_Analysis.md) → [Session Lifecycle](XRSR_Session_Lifecycle_Management.md)
- **XRSV:** [Architecture Analysis](XRSV_Architecture_Analysis.md) → [HTTP Implementation](XRSV_HTTP_Voice_Service_Implementation.md)

### By Use Case  
- **API Development:** [API Interface](API_Interface_Documentation.md) → [Error Handling](Error_Handling_Patterns_Return_Code_Conventions.md)
- **Platform Integration:** [XR Platform Guide](XR_Platform_Integration_Guide_for_Developers.md) → [C++ Compatibility](../openspec/specs/CPP_Compatibility_Mixed_Language_Support.md)
- **Configuration:** [Schema Documentation](Configuration_Schema_Documentation.md) → [Runtime Updates](Runtime_Configuration_Update_Capabilities.md)
- **Performance:** [Performance Analysis](Performance_Analysis_Framework.md) → [Threading Model](Threading_Model.md)

### By Development Stage
- **Getting Started:** [README](README.md) → [SDK Architecture](SDK_Architecture.md)
- **Implementation:** [API Interface](API_Interface_Documentation.md) → Component-specific docs
- **Integration:** [Cross Component Integration](Cross_Component_Integration_Analysis.md) → [XR Platform Guide](XR_Platform_Integration_Guide_for_Developers.md)
- **Validation:** [API Cross-Reference Validation](API_Cross_Reference_Validation_Report.md) → [Quality Assurance Summary](Validation_Quality_Assurance_Completion_Summary.md)