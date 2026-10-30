# XRSV WebSocket NextGen Voice Service Implementation

## Overview

The XRSV WebSocket NextGen implementation provides a sophisticated, real-time voice interaction service built on top of the XRSR WebSocket protocol infrastructure. Unlike the simpler HTTP request-response model, this implementation offers advanced features including real-time streaming, TV control integration, wake-up word (WUW) verification, comprehensive audio profiling, and complex JSON message templating.

## Architecture

### Component Location
- **Source**: [`src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.c`](src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.c)
- **Header**: [`src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h`](src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h)

### Core Design Principles
- **Real-time Interaction**: Persistent WebSocket connection for continuous voice sessions
- **Template-based JSON Messaging**: Pre-configured JSON objects for consistent protocol communication
- **TV Control Integration**: Native support for TV power, volume, and mute operations
- **Advanced Audio Processing**: Comprehensive audio profiling and dynamic gain control
- **Extensible Handler Architecture**: Event-driven callback system for application integration

## JSON Message System

### Template Architecture
The implementation uses an extensive JSON template system with 70+ predefined constants for protocol communication:

```c
// Protocol structure constants
#define XRSV_WS_NEXTGEN_JSON_KEY_TRX                    "trx"
#define XRSV_WS_NEXTGEN_JSON_KEY_MSGTYPE                "msgType"
#define XRSV_WS_NEXTGEN_JSON_KEY_CREATED                "created"
#define XRSV_WS_NEXTGEN_JSON_KEY_PAYLOAD                "payload"
#define XRSV_WS_NEXTGEN_JSON_KEY_DEVICE                 "device"
#define XRSV_WS_NEXTGEN_JSON_KEY_STB                    "stb"

// Protocol version and values
#define XRSV_WS_NEXTGEN_JSON_VALUE_API_VERSION          "2.0.0p0"
#define XRSV_WS_NEXTGEN_JSON_VALUE_DEVICE_TYPE_STB      "STB"
#define XRSV_WS_NEXTGEN_JSON_VALUE_DEVICE_TYPE_TV       "TV"
```

### Message Object Lifecycle
The implementation pre-creates JSON objects during initialization to optimize real-time performance:

1. **obj_init**: Primary initialization message template
2. **obj_init_payload**: Payload wrapper for init message
3. **obj_init_stb**: Device-specific STB configuration
4. **obj_init_stb_audio**: Comprehensive audio profiling data
5. **obj_stream_begin**: Start-of-stream message template
6. **obj_stream_end**: End-of-stream message template

### Audio Profiling System
Comprehensive audio capability description:

```c
// Audio profiling constants
"profiles": [
    {
        "codecType": "ADPCM",
        "container": "NONE",
        "sampleRate": 16000,
        "channels": 1,
        "bitWidth": 16
    },
    {
        "codecType": "OPUS",
        "container": "NONE", 
        "sampleRate": 16000,
        "channels": 1,
        "bitWidth": 16
    }
]
```

## Real-time Voice Processing

### Session Management
The implementation provides comprehensive session lifecycle management:

#### Session Begin Flow
```c
void xrsv_ws_nextgen_handler_ws_session_begin(...) {
    // Extract keyword detection parameters
    if(detector_result != NULL) {
        stream_params.keyword_sample_begin = detector_result->offset_kwd_begin;
        stream_params.keyword_sample_end = detector_result->offset_kwd_end;
        stream_params.keyword_doa = detector_result->doa;
        stream_params.keyword_sensitivity = detector_result->sensitivity;
        stream_params.linear_confidence = detector_result->score;
        // ... additional audio parameters
    }
    
    // Update JSON objects with session UUID
    uuid_unparse_lower(uuid, uuid_str);
    json_object_set_new_nocheck(obj->obj_init, "trx", json_string(uuid_str));
}
```

#### Stream Processing
Real-time audio stream management with automatic message generation:

```c
void xrsv_ws_nextgen_handler_ws_stream_begin(...) {
    if(!obj->first_audio_stream && obj->send != NULL) {
        // Generate start-of-stream message
        uint8_t *buffer = NULL;
        uint32_t length = 0;
        xrsv_ws_nextgen_msg_stream_begin(obj, &buffer, &length);
        
        // Send real-time stream begin message
        xrsr_result_t result = (*obj->send)(obj->param, buffer, length);
        free(buffer);
    }
}
```

### Dynamic Configuration Updates
Support for real-time parameter updates during active sessions:

```c
void xrsv_ws_nextgen_msg_init(xrsv_ws_nextgen_obj_t *obj, ...) {
    // Update dynamic gain if session config requires update
    if((obj->session_config_update != NULL) && 
       (obj->session_config_update->update_required == true)) {
        
        json_object_set_new_nocheck(obj->obj_init_stb_audio, 
                                   "dynamicGain", 
                                   json_real(obj->session_config_update->dynamic_gain));
    }
}
```

## TV Control Integration

### Control Capabilities
Native support for comprehensive TV control operations:

#### Power Management
```c
void xrsv_ws_nextgen_tv_control_power_on(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
    if(obj->handlers.tv_power != NULL) {
        (*obj->handlers.tv_power)(true, false, obj->user_data);
    }
}

void xrsv_ws_nextgen_tv_control_power_on_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
    if(obj->handlers.tv_power != NULL) {
        (*obj->handlers.tv_power)(true, true, obj->user_data);
    }
}
```

#### Volume Control
```c
void xrsv_ws_nextgen_tv_control_volume_up(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
    uint32_t ir_repeat_count = 1;
    if(obj->handlers.tv_volume != NULL) {
        (*obj->handlers.tv_volume)(true, ir_repeat_count, obj->user_data);
    }
}

void xrsv_ws_nextgen_tv_control_volume_mute_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
    if(obj->handlers.tv_mute != NULL) {
        (*obj->handlers.tv_mute)(true, obj->user_data);
    }
}
```

### Message Routing System
Perfect hash-based message dispatch for TV control actions:

```c
bool xrsv_ws_nextgen_msgtype_tv_control(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
    json_t *obj_msg_type = json_object_get(obj_json, "action");
    const char *str_msg_type = json_string_value(obj_msg_type);
    
    // Perfect hash lookup for handler
    xrsv_ws_nextgen_tv_control_handler_t *handler = 
        xrsv_ws_nextgen_tv_control_handler_get(str_msg_type, strlen(str_msg_type));
    
    if(handler != NULL) {
        (*handler->func)(obj, obj_json);
    }
}
```

## WUW Verification System

### Cloud-based Verification
Advanced wake-up word verification with bypass capabilities for testing:

```c
typedef struct {
    bool bypass_wuw_verify_success; // Force success for testing
    bool bypass_wuw_verify_failure; // Force failure for testing
    // ... other parameters
} xrsv_ws_nextgen_params_t;
```

### Verification Processing
```c
bool xrsv_ws_nextgen_msgtype_wuw_verification(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
    // Extract verification results
    bool passed = true;
    json_t *obj_passed = json_object_get(obj_json, "passed");
    if(obj_passed && json_is_boolean(obj_passed)) {
        passed = json_is_true(obj_passed);
    }
    
    // Extract confidence score
    int confidence = 0;
    json_t *obj_confidence = json_object_get(obj_json, "confidence");
    if(obj_confidence && json_is_integer(obj_confidence)) {
        confidence = json_integer_value(obj_confidence);
    }
    
    // Notify application
    if(obj->handlers.wuw_verification != NULL) {
        obj->handlers.wuw_verification(obj->uuid, passed, confidence, obj->user_data);
    }
}
```

## Message Processing Architecture

### Incoming Message Handling
Comprehensive message routing with JSON parsing and validation:

```c
bool xrsv_ws_nextgen_handler_ws_recv_msg(void *data, xrsr_recv_msg_t type, 
                                        const uint8_t *buffer, uint32_t length, 
                                        xrsr_recv_event_t *recv_event) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    // Parse JSON message
    json_error_t error;
    json_t *obj_json = json_loads((const char *)buffer, JSON_REJECT_DUPLICATES, &error);
    
    if(obj_json != NULL && json_is_object(obj_json)) {
        // Process message through routing system
        bool retval = xrsv_ws_nextgen_msg_decode(obj, obj_json);
        json_decref(obj_json);
        
        // Update receive event for XRSR layer
        *recv_event = obj->recv_event;
        obj->recv_event = XRSR_RECV_EVENT_NONE;
        
        return retval;
    }
    
    return false;
}
```

### Connection Management
WebSocket connection lifecycle with proper initialization:

```c
bool xrsv_ws_nextgen_handler_ws_connected(void *data, const uuid_t uuid, 
                                        xrsr_handler_send_t send, void *param, 
                                        rdkx_timestamp_t *timestamp, 
                                        xrsr_session_config_update_t *session_config_update) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    // Store connection parameters
    obj->send = send;
    obj->param = param;
    obj->session_config_update = session_config_update;
    
    // Generate and send initialization message
    uint8_t *buffer = NULL;
    uint32_t length = 0;
    xrsv_ws_nextgen_msg_init(obj, &buffer, &length);
    
    // Send init message immediately upon connection
    xrsr_result_t result = (*send)(param, buffer, length);
    free(buffer);
    
    // Notify application of successful initialization
    if(obj->handlers.sent_init != NULL) {
        rdkx_timestamp_t ts_sent_init;
        rdkx_timestamp_get_realtime(&ts_sent_init);
        (*obj->handlers.sent_init)(uuid, &ts_sent_init, obj->user_data);
    }
    
    return (result == XRSR_RESULT_SUCCESS);
}
```

## Handler Interface System

### Comprehensive Callback Architecture
The implementation provides extensive event handling capabilities:

```c
typedef struct {
    xrsv_ws_nextgen_handler_session_begin_t     session_begin;
    xrsv_ws_nextgen_handler_session_end_t       session_end;
    xrsv_ws_nextgen_handler_stream_begin_t      stream_begin;
    xrsv_ws_nextgen_handler_stream_kwd_t        stream_kwd;
    xrsv_ws_nextgen_handler_stream_end_t        stream_end;
    xrsv_ws_nextgen_handler_connected_t         connected;
    xrsv_ws_nextgen_handler_disconnected_t      disconnected;
    xrsv_ws_nextgen_handler_sent_init_t         sent_init;
    xrsv_ws_nextgen_handler_listening_t         listening;
    xrsv_ws_nextgen_handler_asr_t               asr;
    xrsv_ws_nextgen_handler_conn_close_t        conn_close;
    xrsv_ws_nextgen_handler_response_vrex_t     response_vrex;
    xrsv_ws_nextgen_handler_wuw_verification_t  wuw_verification;
    xrsv_ws_nextgen_handler_msg_t               msg;
    xrsv_ws_nextgen_handler_source_error_t      source_error;
    xrsv_ws_nextgen_handler_tv_mute_t           tv_mute;
    xrsv_ws_nextgen_handler_tv_power_t          tv_power;
    xrsv_ws_nextgen_handler_tv_volume_t         tv_volume;
} xrsv_ws_nextgen_handlers_t;
```

### Stream Parameter Structure
Detailed audio stream metadata:

```c
typedef struct {
    uint32_t     keyword_sample_begin;               // Keyword start offset
    uint32_t     keyword_sample_end;                 // Keyword end offset
    uint16_t     keyword_doa;                        // Direction of arrival (0-359°)
    double       keyword_sensitivity;                // Detection sensitivity
    uint16_t     keyword_sensitivity_triggered;      // Sensitivity trigger status
    double       keyword_sensitivity_high;           // High sensitivity threshold
    bool         keyword_sensitivity_high_support;   // High sensitivity support
    bool         keyword_sensitivity_high_triggered; // High sensitivity trigger
    double       keyword_gain;                       // Keyword detector gain
    double       dynamic_gain;                       // Streaming audio gain
    double       signal_noise_ratio;                 // SNR measurement
    double       linear_confidence;                  // Linear confidence score
    int32_t      nonlinear_confidence;               // Nonlinear confidence
    bool         push_to_talk;                       // PTT activation status
    const char * detector_name;                      // Detector identifier
    const char * dsp_name;                           // DSP processor name
    uint16_t     par_eos_timeout;                    // Press-and-release timeout
} xrsv_ws_nextgen_stream_params_t;
```

## Configuration Management

### Runtime Parameter Updates
Support for dynamic configuration changes without session restart:

```c
bool xrsv_ws_nextgen_update_device_id(xrsv_ws_nextgen_object_t object, const char *device_id);
bool xrsv_ws_nextgen_update_account_id(xrsv_ws_nextgen_object_t object, const char *account_id);
bool xrsv_ws_nextgen_update_device_type(xrsv_ws_nextgen_object_t object, xrsv_ws_nextgen_device_type_t device_type);
bool xrsv_ws_nextgen_update_partner_id(xrsv_ws_nextgen_object_t object, const char *partner_id);
bool xrsv_ws_nextgen_update_experience(xrsv_ws_nextgen_object_t object, const char *experience);
bool xrsv_ws_nextgen_update_audio_profile(xrsv_ws_nextgen_object_t object, const char *audio_profile);
bool xrsv_ws_nextgen_update_language(xrsv_ws_nextgen_object_t object, const char *language);
bool xrsv_ws_nextgen_update_mask_pii(xrsv_ws_nextgen_object_t object, bool enable);
```

### Device Type Support
Multi-device compatibility with STB and TV profiles:

```c
typedef enum {
   XRSV_WS_NEXTGEN_DEVICE_TYPE_STB     = 0,
   XRSV_WS_NEXTGEN_DEVICE_TYPE_TV      = 1,
   XRSV_WS_NEXTGEN_DEVICE_TYPE_INVALID = 2
} xrsv_ws_nextgen_device_type_t;
```

## Memory Management

### Object Lifecycle
Proper resource management with reference counting:

```c
void xrsv_ws_nextgen_destroy_object(xrsv_ws_nextgen_obj_t *obj) {
    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        return;
    }
    
    // Clean up JSON objects with proper reference management
    if(obj->obj_init != NULL) {
        json_decref(obj->obj_init);
        obj->obj_init = NULL;
    }
    if(obj->obj_stream_begin != NULL) {
        json_decref(obj->obj_stream_begin);
        obj->obj_stream_begin = NULL;
    }
    if(obj->obj_stream_end != NULL) {
        json_decref(obj->obj_stream_end);
        obj->obj_stream_end = NULL;
    }
    
    // Clear query elements
    obj->query_element_device_id[0] = '\0';
    obj->query_element_trx[0] = '\0';
    obj->query_element_version[0] = '\0';
    obj->identifier = 0;
    
    free(obj);
}
```

## Performance Optimization

### Template Pre-creation
JSON objects are pre-created during initialization to minimize real-time overhead:

1. **Initialization Phase**: Complex JSON structures built once
2. **Runtime Phase**: Only dynamic values updated (timestamps, UUIDs, parameters)
3. **Message Generation**: Simple serialization of pre-built templates

### Perfect Hash Dispatch
Efficient message type routing using perfect hash functions for TV control and other message types, enabling O(1) handler lookup.

## Security Features

### PII Masking
Built-in support for personally identifiable information protection:

```c
typedef struct {
    // ... other fields
    bool mask_pii;  // Enable PII masking in logs
    // ... 
} xrsv_ws_nextgen_params_t;
```

### Connection Validation
Comprehensive connection and object validation:

```c
bool xrsv_ws_nextgen_object_is_valid(xrsv_ws_nextgen_obj_t *obj) {
    return (obj != NULL && obj->identifier == XRSV_WS_NEXTGEN_IDENTIFIER);
}
```

## Integration Points

### XRSR Protocol Bridge
The WebSocket NextGen implementation seamlessly integrates with XRSR protocol layer:

1. **Handler Registration**: Provides XRSR-compatible handlers for protocol events
2. **Message Routing**: Bridges XRSR WebSocket events to application callbacks
3. **Session Management**: Coordinates with XRSR session lifecycle
4. **Error Handling**: Translates XRSR errors into application-friendly events

### Application Interface
Clean separation between protocol implementation and application logic:

1. **Event-Driven Architecture**: Applications register handlers for relevant events
2. **Parameter Updates**: Runtime configuration changes without restart
3. **Session Control**: Application-initiated and server-initiated sessions
4. **TV Control**: Hardware abstraction for TV operations

## Comparison with HTTP Implementation

| Feature | HTTP Implementation | WebSocket NextGen | 
|---------|-------------------|------------------|
| **Connection Model** | Request-Response | Persistent Connection |
| **Real-time Capability** | Limited | Full Support |
| **TV Control** | None | Native Support |
| **Message Complexity** | Simple JSON | Complex Templates |
| **WUW Verification** | Basic | Advanced with Bypass |
| **Audio Profiling** | Limited | Comprehensive |
| **Session Management** | Simple | Advanced Lifecycle |
| **Performance** | Good for Simple | Optimized for Real-time |

The WebSocket NextGen implementation represents a significant advancement over the HTTP implementation, providing the foundation for sophisticated real-time voice interaction applications with comprehensive TV integration and advanced audio processing capabilities.