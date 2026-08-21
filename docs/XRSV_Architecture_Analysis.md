# XRSV Architecture Analysis

## Overview
The XRSV (XR Speech VREX) component is a voice service integration layer that provides high-level speech recognition and control services built on top of the XRSR (XR Speech Router) infrastructure. XRSV acts as a bridge between applications and voice recognition services, offering two primary implementations: HTTP-based voice services and WebSocket NextGen real-time voice interaction.

## Component Architecture

### Core Components
The XRSV architecture consists of four main components organized in a modular hierarchy:

```
xr-speech-vrex/
├── xrsv.h              # Core XRSV definitions and types
├── xrsv_utils.c/h      # Common utility functions
├── xrsv_http/          # HTTP voice service implementation
│   ├── xrsv_http.c
│   └── xrsv_http.h
└── xrsv_ws_nextgen/    # WebSocket NextGen implementation
    ├── xrsv_ws_nextgen.c
    ├── xrsv_ws_nextgen.h
    ├── xrsv_ws_nextgen_private.h
    ├── xrsv_ws_nextgen_msgtype.hash
    └── xrsv_ws_nextgen_tv_control.hash
```

### Design Philosophy

#### Abstraction Layer Purpose
XRSV serves as a **high-level abstraction layer** above XRSR, providing:
- **Simplified APIs**: Application-focused interfaces hiding XRSR complexity
- **Service-Specific Logic**: HTTP and WebSocket protocol-specific implementations
- **Callback Management**: Unified callback system for voice events
- **Configuration Management**: Service-specific parameter handling
- **Message Processing**: Protocol-aware message parsing and routing

#### Integration Architecture
```
Application Layer
       ↓
   XRSV Layer (HTTP/WebSocket)
       ↓
   XRSR Layer (Protocol Routing)
       ↓
   XRAudio Layer (Audio Processing)
       ↓
   Hardware Abstraction Layer
```

## Core Type System

### Base Result Types
```c
typedef enum {
   XRSV_RESULT_SUCCESS = 0, ///< Operation completed successfully
   XRSV_RESULT_ERROR   = 1, ///< Operation failed
   XRSV_RESULT_INVALID = 2, ///< Invalid parameters or state
} xrsv_result_t;
```

### VREX Stream Termination Results
```c
typedef enum {
   XRSV_STREAM_END_END_OF_SPEECH    = 0, ///< Natural end of speech detected
   XRSV_STREAM_END_END_OF_STREAM    = 1, ///< Stream completed normally
   XRSV_STREAM_END_TIMEOUT          = 2, ///< Session timeout occurred
   XRSV_STREAM_END_USER_INTERUPTED  = 3, ///< User interrupted the session
   XRSV_STREAM_END_MAX_LENGTH       = 4, ///< Maximum stream length reached
   XRSV_STREAM_END_INTERNAL_ERROR   = 5, ///< Internal processing error
   XRSV_STREAM_END_INVALID          = 6, ///< Unknown termination reason
} xrsv_vrex_result_t;
```

## XRSV HTTP Voice Service

### API Design
The XRSV HTTP component provides a traditional request-response voice recognition interface suitable for batch processing and simple voice queries.

#### Configuration Parameters

**Device Identification Parameters**:
```c
typedef struct {
   const char *device_id;        ///< Unique device identifier
   const char *receiver_id;      ///< Receiver hardware identifier
   const char *partner_id;       ///< Network partner identifier
   const char *experience;       ///< User experience identifier
   const char *app_id;           ///< Application identifier for HTTP requests
   const char *language;         ///< Device language setting
   bool        test_flag;        ///< Testing mode enablement
   bool        mask_pii;         ///< PII masking for privacy compliance
   void       *user_data;        ///< Application-specific user data
} xrsv_http_params_t;
```

**Key Configuration Features**:
- **Device Identity**: Complete device and partner identification
- **Application Context**: App-specific identification for service routing
- **Privacy Control**: Built-in PII masking capabilities
- **Testing Support**: Dedicated test mode for development/QA

#### Message Structure

**Voice Recognition Response**:
```c
typedef struct {
   long    ret_code;                                ///< Server response code
   char    message[XRSV_HTTP_SESSION_STR_LEN_MAX];       ///< Response message payload
   char    transcription[XRSV_HTTP_SESSION_STR_LEN_MAX]; ///< Speech transcription result
   char    session_id[XRSV_HTTP_SESSION_ID_LEN_MAX];     ///< Unique session identifier
} xrsv_http_recv_msg_t;
```

**Message Constraints**:
- **Session ID Length**: Maximum 64 characters including null termination
- **String Length**: Maximum 512 characters for messages and transcriptions
- **Structured Response**: Separate fields for status, content, and transcription

#### Callback System

**Session Lifecycle Callbacks**:
```c
typedef struct {
   xrsv_http_handler_session_begin_t     session_begin;     ///< Session initiation
   xrsv_http_handler_session_end_t       session_end;       ///< Session termination
   xrsv_http_handler_stream_begin_t      stream_begin;      ///< Audio stream start
   xrsv_http_handler_stream_end_t        stream_end;        ///< Audio stream end
   xrsv_http_handler_connected_t         connected;         ///< Connection established
   xrsv_http_handler_disconnected_t      disconnected;      ///< Connection terminated
   xrsv_http_handler_recv_msg_t          recv_msg;          ///< Message received
   xrsv_http_handler_source_error_t      source_error;      ///< Audio source error
} xrsv_http_handlers_t;
```

**Callback Design Features**:
- **UUID-Based Session Tracking**: Unique session identifiers for correlation
- **Timestamp Integration**: RDKX timestamp support for performance analysis
- **Statistics Integration**: Session and stream statistics provided
- **Error Isolation**: Source-specific error handling callbacks

#### API Functions

**Object Lifecycle Management**:
```c
// Object creation and destruction
xrsv_http_object_t xrsv_http_create(const xrsv_http_params_t *params);
void xrsv_http_destroy(xrsv_http_object_t object);

// Handler registration
bool xrsv_http_handlers(xrsv_http_object_t object, 
                       const xrsv_http_handlers_t *handlers_in, 
                       xrsr_handlers_t *handlers_out);
```

**Runtime Configuration Updates**:
```c
// Device identity updates
bool xrsv_http_update_device_id(xrsv_http_object_t object, const char *device_id);
bool xrsv_http_update_receiver_id(xrsv_http_object_t object, const char *receiver_id);
bool xrsv_http_update_partner_id(xrsv_http_object_t object, const char *partner_id);

// Application context updates
bool xrsv_http_update_experience(xrsv_http_object_t object, const char *experience);
bool xrsv_http_update_app_id(xrsv_http_object_t object, const char *app_id);
bool xrsv_http_update_language(xrsv_http_object_t object, const char *language);

// Privacy and testing controls
bool xrsv_http_update_mask_pii(xrsv_http_object_t object, bool enable);
bool xrsv_http_update_user_data(xrsv_http_object_t object, void *user_data);
```

## XRSV WebSocket NextGen

### Advanced Real-Time Voice Interface
The WebSocket NextGen component represents XRSV's most sophisticated implementation, providing real-time bidirectional voice interaction with advanced features including TV control integration, WUW (Wake-Up Word) verification, and streaming ASR (Automatic Speech Recognition).

#### Enhanced Configuration Parameters

**Comprehensive Device Profile**:
```c
typedef struct {
   const char *device_id;                 ///< Unique device identifier
   const char *account_id;                ///< User account identifier
   const char *partner_id;                ///< Network partner identifier
   const char *experience;                ///< User experience identifier
   const char *audio_profile;             ///< Device-specific audio profile
   const char *audio_model;               ///< Audio hardware model identifier
   const char *language;                  ///< Device language setting
   const char *device_mac;                ///< MAC address for device identification
   const char *rf_protocol;               ///< RF communication protocol
   bool        test_flag;                 ///< Testing mode enablement
   bool        bypass_wuw_verify_success; ///< WUW verification bypass (success)
   bool        bypass_wuw_verify_failure; ///< WUW verification bypass (failure)
   bool        mask_pii;                  ///< PII masking control
   void       *user_data;                 ///< Application user data
} xrsv_ws_nextgen_params_t;
```

**Advanced Configuration Features**:
- **Audio Hardware Profiling**: Audio profile and model identification for optimization
- **Network Hardware Details**: MAC address and RF protocol specification
- **Cloud WUW Control**: Wake-up word verification bypass for testing scenarios
- **Account Integration**: User account association for personalized services

#### Device Type Classification
```c
typedef enum {
   XRSV_WS_NEXTGEN_DEVICE_TYPE_STB     = 0, ///< Set-top box device
   XRSV_WS_NEXTGEN_DEVICE_TYPE_TV      = 1, ///< Television device
   XRSV_WS_NEXTGEN_DEVICE_TYPE_INVALID = 2  ///< Invalid device type
} xrsv_ws_nextgen_device_type_t;
```

#### Advanced Stream Parameters

**Comprehensive Audio Analysis Parameters**:
```c
typedef struct {
   uint32_t     keyword_sample_begin;               ///< Keyword start sample offset
   uint32_t     keyword_sample_end;                 ///< Keyword end sample offset
   uint16_t     keyword_doa;                        ///< Direction of arrival (0-359°)
   double       keyword_sensitivity;                ///< Sensitivity threshold
   uint16_t     keyword_sensitivity_triggered;      ///< Triggered sensitivity level
   double       keyword_sensitivity_high;           ///< High sensitivity threshold
   bool         keyword_sensitivity_high_support;   ///< High sensitivity mode support
   bool         keyword_sensitivity_high_triggered; ///< High sensitivity triggered
   double       keyword_gain;                       ///< Keyword detector input gain
   double       dynamic_gain;                       ///< Streamed audio dynamic gain
   double       signal_noise_ratio;                 ///< SNR measurement
   double       linear_confidence;                  ///< Linear confidence score
   int32_t      nonlinear_confidence;               ///< Nonlinear confidence score
   bool         push_to_talk;                       ///< Push-to-talk mode indicator
   const char * detector_name;                      ///< Keyword detector identifier
   const char * dsp_name;                           ///< DSP preprocessing identifier
   uint16_t     par_eos_timeout;                    ///< Press-and-release EOS timeout
} xrsv_ws_nextgen_stream_params_t;
```

**Advanced Audio Features**:
- **Precision Timing**: Sample-level keyword timing information
- **Spatial Audio**: Direction of arrival processing
- **Adaptive Processing**: Dynamic gain control and sensitivity adjustment
- **Confidence Analysis**: Multi-dimensional confidence scoring
- **Processing Chain Identification**: Detector and DSP component tracking

#### Comprehensive Callback System

**Core Voice Processing Callbacks**:
```c
// Session and stream lifecycle
xrsv_ws_nextgen_handler_session_begin_t     session_begin;     
xrsv_ws_nextgen_handler_session_end_t       session_end;       
xrsv_ws_nextgen_handler_stream_begin_t      stream_begin;      
xrsv_ws_nextgen_handler_stream_kwd_t        stream_kwd;        
xrsv_ws_nextgen_handler_stream_end_t        stream_end;        

// Connection management
xrsv_ws_nextgen_handler_connected_t         connected;         
xrsv_ws_nextgen_handler_disconnected_t      disconnected;      
xrsv_ws_nextgen_handler_sent_init_t         sent_init;         

// Voice recognition events
xrsv_ws_nextgen_handler_listening_t         listening;         
xrsv_ws_nextgen_handler_asr_t               asr;               
xrsv_ws_nextgen_handler_wuw_verification_t  wuw_verification;
```

**Advanced Integration Callbacks**:
```c
// Server communication
xrsv_ws_nextgen_handler_conn_close_t        conn_close;        
xrsv_ws_nextgen_handler_response_vrex_t     response_vrex;     
xrsv_ws_nextgen_handler_msg_t               msg;               

// TV control integration
xrsv_ws_nextgen_handler_tv_mute_t           tv_mute;           
xrsv_ws_nextgen_handler_tv_power_t          tv_power;          
xrsv_ws_nextgen_handler_tv_volume_t         tv_volume;         

// Error handling
xrsv_ws_nextgen_handler_source_error_t      source_error;      
```

**Specialized Callback Features**:
- **Real-Time ASR**: Progressive speech recognition result callbacks
- **Cloud WUW Verification**: Server-side wake-up word validation
- **TV Control Integration**: Direct TV control command handling
- **Bidirectional Messaging**: Raw message exchange capabilities

#### Advanced API Functions

**Enhanced Configuration Management**:
```c
// Device profile updates
bool xrsv_ws_nextgen_update_device_id(xrsv_ws_nextgen_object_t object, const char *device_id);
bool xrsv_ws_nextgen_update_account_id(xrsv_ws_nextgen_object_t object, const char *account_id);
bool xrsv_ws_nextgen_update_device_type(xrsv_ws_nextgen_object_t object, xrsv_ws_nextgen_device_type_t device_type);
bool xrsv_ws_nextgen_update_partner_id(xrsv_ws_nextgen_object_t object, const char *partner_id);

// Audio system configuration
bool xrsv_ws_nextgen_update_audio_profile(xrsv_ws_nextgen_object_t object, const char *audio_profile);
bool xrsv_ws_nextgen_update_audio_model(xrsv_ws_nextgen_object_t object, const char *audio_model);
bool xrsv_ws_nextgen_update_audio_rf_protocol(xrsv_ws_nextgen_object_t object, const char *rf_protocol);

// Advanced messaging capabilities
bool xrsv_ws_nextgen_update_init_app(xrsv_ws_nextgen_object_t object, const char *blob);
bool xrsv_ws_nextgen_send_msg(xrsv_ws_nextgen_object_t object, const char *msg);
```

## Internal Architecture

### WebSocket NextGen Internal Structure

#### Core Object Architecture
```c
typedef struct {
   uint32_t                    identifier;           ///< Object instance identifier
   xrsv_ws_nextgen_handlers_t  handlers;            ///< Callback handler collection
   xrsr_handler_send_t         send;                ///< XRSR send function pointer
   void *                      param;               ///< XRSR handler parameter
   
   // JSON message templates
   json_t *                    obj_init;            ///< Initialization message template
   json_t *                    obj_init_payload;    ///< Init payload structure
   json_t *                    obj_init_stb;        ///< STB-specific init data
   json_t *                    obj_init_stb_id;     ///< STB identification data
   json_t *                    obj_init_stb_id_account;    ///< Account information
   json_t *                    obj_init_stb_id_device_id;  ///< Device identification
   json_t *                    obj_init_stb_audio;         ///< Audio configuration
   json_t *                    obj_init_app;               ///< Application data
   json_t *                    obj_init_elements;          ///< Additional elements
   json_t *                    obj_stream_begin;           ///< Stream begin message
   json_t *                    obj_stream_end;             ///< Stream end message
   json_t *                    obj_stream_end_payload;     ///< Stream end payload
   
   // Query parameters
   char                        query_element_trx[41];      ///< Transaction ID
   char                        query_element_device_id[64]; ///< Device identifier
   char                        query_element_version[12];   ///< Protocol version
   
   // Runtime state
   bool                        mask_pii;            ///< PII masking flag
   void *                      user_data;           ///< Application user data
   bool                        user_initiated;      ///< User initiation flag
   bool                        first_audio_stream;  ///< First stream indicator
   xrsr_recv_event_t           recv_event;          ///< XRSR receive event
   xrsr_session_config_update_t *session_config_update; ///< Session configuration updates
   uuid_t                      uuid;                ///< Session UUID
} xrsv_ws_nextgen_obj_t;
```

#### Message Processing Architecture

**JSON Message Handler System**:
- **Hash-Based Dispatch**: Perfect hash tables for message type resolution
- **Type-Safe Handlers**: Function pointer-based message processing
- **Structured Processing**: Dedicated handlers for each message type

**Message Type Handlers**:
```c
// Core message processing functions
bool xrsv_ws_nextgen_msgtype_conn_close(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_response_vrex(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_wuw_verification(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_asr(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_listening(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_tv_control(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_server_stream_end(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
```

**TV Control Command Handlers**:
```c
// TV control command processing
void xrsv_ws_nextgen_tv_control_power_on(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_power_on_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_power_off(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_power_off_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_volume_up(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_volume_down(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_volume_mute_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
```

#### Perfect Hash Implementation
The WebSocket NextGen implementation uses **perfect hash tables** for efficient message dispatching:

**Hash File Structure**:
- **xrsv_ws_nextgen_msgtype.hash**: Message type to handler mapping
- **xrsv_ws_nextgen_tv_control.hash**: TV control command to handler mapping

**Hash Table Benefits**:
- **O(1) Message Lookup**: Constant-time message type resolution
- **Collision-Free**: Perfect hash guarantees no collisions
- **Memory Efficient**: Minimal memory overhead for dispatch tables
- **Compile-Time Generation**: Hash tables generated during build process

## Utility Functions

### Result String Conversion
The XRSV utility system provides string conversion for debugging and logging:

```c
const char *xrsv_result_str(xrsv_result_t type);

// Implementation provides:
// XRSV_RESULT_SUCCESS -> "SUCCESS"
// XRSV_RESULT_ERROR   -> "ERROR"  
// XRSV_RESULT_INVALID -> "INVALID"
// Unknown values      -> "INVALID(value)"
```

**Utility Design Features**:
- **Thread-Safe**: Static buffer management for concurrent access
- **Robust Error Handling**: Unknown values handled gracefully
- **Debug-Friendly**: Clear string representations for logging

## Integration with XRSR

### Handler Bridge Architecture
XRSV components implement a **handler bridge pattern** that translates between XRSR low-level callbacks and application-friendly XRSV callbacks:

```c
// XRSV provides XRSR handlers for integration
bool xrsv_http_handlers(xrsv_http_object_t object, 
                       const xrsv_http_handlers_t *handlers_in, 
                       xrsr_handlers_t *handlers_out);
```

**Bridge Features**:
- **Protocol Abstraction**: Hide XRSR protocol complexity from applications
- **Event Translation**: Convert XRSR events to service-specific events
- **State Management**: Maintain service-specific state across XRSR interactions
- **Error Propagation**: Translate XRSR errors to application-meaningful errors

### Session Lifecycle Integration
XRSV manages the complete session lifecycle through XRSR integration:

**Session Flow**:
1. **Initialization**: XRSV creates XRSR session with service-specific configuration
2. **Connection**: XRSR establishes protocol connection (HTTP/WebSocket)
3. **Audio Streaming**: XRSR manages audio pipeline through XRAudio
4. **Message Processing**: XRSV processes service responses through message handlers
5. **Termination**: XRSV coordinates graceful session cleanup

**State Synchronization**:
- **UUID Correlation**: Session UUIDs propagated through all layers
- **Statistics Collection**: XRSR statistics exposed through XRSV callbacks
- **Error Coordination**: Multi-layer error handling with appropriate escalation

## Dependencies and External Integration

### Required Libraries
**JSON Processing**: Jansson library for JSON message parsing and generation
**Logging**: RDKX Logger integration for comprehensive logging
**Timestamps**: RDKX Timestamp utilities for performance measurement
**String Handling**: BSD string functions for secure string operations

### XRSR Integration Points
**Protocol Routing**: Direct integration with XRSR protocol dispatch
**Audio Pipeline**: Transparent integration with XRAudio processing
**Message Queue**: Utilizes XRSR message queue infrastructure for async communication
**Configuration**: Extends XRSR configuration with service-specific parameters

### Platform Integration
**Privacy Compliance**: Built-in PII masking for regulatory compliance
**Testing Infrastructure**: Dedicated test modes and bypass mechanisms
**Device Integration**: Hardware identification and capability reporting
**Network Adaptation**: Partner and service provider configuration support

## Architectural Benefits

### Separation of Concerns
- **Protocol Independence**: Applications don't need to understand network protocols
- **Service Abstraction**: HTTP vs WebSocket differences hidden from applications
- **Configuration Simplification**: Service-specific configuration abstracts XRSR complexity
- **Error Encapsulation**: Service-specific error handling isolates protocol errors

### Extensibility
- **New Service Support**: Framework supports additional voice service implementations
- **Custom Message Types**: WebSocket hash tables enable easy message type extension
- **Callback Extension**: Handler system supports new event types
- **Configuration Growth**: Parameter structures designed for extension

### Performance Optimization
- **Perfect Hash Dispatch**: O(1) message processing for real-time performance
- **JSON Template Reuse**: Pre-built JSON templates minimize serialization overhead
- **Memory Management**: Efficient object lifecycle management
- **Event-Driven Architecture**: Asynchronous processing prevents blocking

### Developer Experience
- **Simplified APIs**: High-level interfaces reduce integration complexity
- **Comprehensive Callbacks**: Rich callback system provides application visibility
- **Runtime Configuration**: Dynamic parameter updates without restart
- **Debug Support**: Built-in logging and PII masking for development

The XRSV architecture successfully abstracts the complexities of voice service integration while providing the flexibility and performance required for production XR voice-enabled applications. The modular design enables both simple voice interactions through HTTP and sophisticated real-time voice control through WebSocket NextGen, all built on the solid foundation of the XRSR routing infrastructure.