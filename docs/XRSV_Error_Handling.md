# XRSV Error Handling

## Overview

The XRSV (VREX Speech Request) component implements a comprehensive error handling system that manages failures at multiple levels: voice service logic errors, protocol-level failures propagated from XRSR, network connectivity issues, message processing errors, and session lifecycle problems. The error handling architecture focuses on graceful degradation, automatic recovery where possible, and clear error propagation to applications for appropriate user-level responses.

## Architecture

### Error Handling Layers
```
Application Layer (Error Response & User Notification)
       ↑ (Error Handlers)
XRSV Voice Service Layer (Error Classification & Recovery)
       ↑ (Error Propagation)
XRSR Protocol Layer (Network & Protocol Errors)
       ↑ (System Errors)
Network & System Layer (Connection & Transport Errors)
```

### Component Responsibilities

#### XRSV Layer (Error Consumer & Recovery)
- **Error Classification**: Categorizes errors by type and severity
- **Recovery Mechanisms**: Implements automatic retry and reconnection logic
- **State Management**: Maintains consistent state during error conditions
- **Error Propagation**: Forwards errors to applications with contextual information

#### XRSR Layer (Error Producer)
- **Protocol Errors**: Network failures, authentication errors, timeout conditions
- **Transport Errors**: Connection drops, SSL/TLS failures, message transport issues
- **Configuration Errors**: Invalid parameters, certificate problems, endpoint issues

## Error Categories and Types

### Voice Service Result Types
```c
typedef enum {
   XRSV_RESULT_SUCCESS = 0, ///< Operation completed successfully
   XRSV_RESULT_ERROR   = 1, ///< Operation did not complete successfully
   XRSV_RESULT_INVALID = 2, ///< Invalid return code
} xrsv_result_t;
```

### Stream Termination Error Classification
```c
typedef enum {
   XRSV_STREAM_END_END_OF_SPEECH    = 0, ///< Normal completion - end of speech detected
   XRSV_STREAM_END_END_OF_STREAM    = 1, ///< Normal completion - end of stream
   XRSV_STREAM_END_TIMEOUT          = 2, ///< Error - stream timeout occurred
   XRSV_STREAM_END_USER_INTERUPTED  = 3, ///< User initiated - user cancelled
   XRSV_STREAM_END_MAX_LENGTH       = 4, ///< Limit reached - maximum stream length
   XRSV_STREAM_END_INTERNAL_ERROR   = 5, ///< Error - VREX internal processing error
   XRSV_STREAM_END_INVALID          = 6, ///< Error - unknown/invalid termination reason
} xrsv_vrex_result_t;
```

### Error Source Classification
- **Audio Input Errors**: Microphone failures, audio processing issues
- **Network Errors**: Connection failures, timeouts, protocol errors
- **Authentication Errors**: Invalid credentials, token expiration, certificate issues
- **Protocol Errors**: Message format errors, unsupported operations, version mismatches
- **Service Errors**: Voice service processing failures, internal errors

## Object Validation and Safety

### Object Integrity Validation
```c
// HTTP implementation object validation
bool xrsv_http_object_is_valid(xrsv_http_obj_t *obj) {
    if(obj != NULL && obj->identifier == XRSV_HTTP_IDENTIFIER) {
        return(true);
    }
    return(false);
}

// WebSocket NextGen implementation object validation
bool xrsv_ws_nextgen_object_is_valid(xrsv_ws_nextgen_obj_t *obj) {
    if(obj != NULL && obj->identifier == XRSV_WS_NEXTGEN_IDENTIFIER) {
        return(true);
    }
    return(false);
}
```

### Safety Patterns
All XRSV API functions implement consistent safety validation:
```c
// Standard error checking pattern used throughout XRSV
bool xrsv_ws_nextgen_update_device_id(xrsv_ws_nextgen_object_t object, const char *device_id) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
    
    // Object validation
    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    // Parameter validation and processing
    // ... implementation
}
```

**Safety Features**:
- **Null Pointer Protection**: All functions validate object pointers before use
- **Magic Number Validation**: Object identifier verification prevents use-after-free
- **Early Error Return**: Fast failure path for invalid objects
- **Consistent Error Reporting**: Standardized error logging for debugging

## Error Propagation Handlers

### Source Error Handling

#### HTTP Implementation
```c
void xrsv_http_handler_source_error(xrsv_http_object_t object, xrsr_src_t src) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return;
    }
    
    // Forward error to application if handler registered
    if(obj->handlers.source_error != NULL) {
        (*obj->handlers.source_error)(src, obj->user_data);
    }
}
```

#### WebSocket NextGen Implementation  
```c
void xrsv_ws_nextgen_handler_ws_source_error(void *data, xrsr_src_t src) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return;
    }

    // Forward error to application if handler registered
    if(obj->handlers.source_error != NULL) {
        (*obj->handlers.source_error)(src, obj->user_data);
    }
}
```

#### Application Error Handler Interface
```c
// HTTP source error handler signature
typedef void (*xrsv_http_handler_source_error_t)(xrsr_src_t src, void *user_data);

// WebSocket NextGen source error handler signature  
typedef void (*xrsv_ws_nextgen_handler_source_error_t)(xrsr_src_t src, void *user_data);
```

### Connection Error Handling

#### HTTP Disconnection Handler
```c
void xrsv_http_handler_disconnected(xrsv_http_object_t object, 
                                   const uuid_t uuid, 
                                   xrsr_session_end_reason_t reason, 
                                   bool retry, 
                                   bool *detect_resume, 
                                   rdkx_timestamp_t *timestamp) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return;
    }
    
    XLOGD_INFO("");
    
    // Signal that detection should resume after disconnection
    if(detect_resume != NULL) {
        *detect_resume = true;
    }
    
    // Notify application of disconnection
    if(obj->handlers.disconnected != NULL) {
        (*obj->handlers.disconnected)(uuid, timestamp, obj->user_data);
    }
}
```

#### WebSocket NextGen Disconnection Handler
```c
void xrsv_ws_nextgen_handler_ws_disconnected(void *data, 
                                            const uuid_t uuid, 
                                            xrsr_session_end_reason_t reason, 
                                            bool retry, 
                                            bool *detect_resume, 
                                            rdkx_timestamp_t *timestamp) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return;
    }
    
    // Clean up connection state
    obj->send = NULL;
    obj->param = NULL;
    
    // Signal that detection should resume after disconnection
    if(detect_resume != NULL) {
        *detect_resume = true;
    }
    
    // Notify application with retry information
    if(obj->handlers.disconnected != NULL) {
        (*obj->handlers.disconnected)(uuid, retry, timestamp, obj->user_data);
    }
}
```

**Key Features**:
- **State Cleanup**: Connection parameters cleared on disconnection
- **Resume Control**: Applications can control detection resume behavior
- **Retry Information**: WebSocket NextGen provides retry recommendation to applications
- **Session Context**: UUID provided for multi-session management

## Message Processing Error Handling

### JSON Message Validation (WebSocket NextGen)
```c
bool xrsv_ws_nextgen_handler_ws_recv_msg(void *data, 
                                        xrsr_recv_msg_t type, 
                                        const uint8_t *buffer, 
                                        uint32_t length, 
                                        xrsr_recv_event_t *recv_event) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    // Object validation
    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    XLOGD_INFO("type <%s> length <%u>", xrsr_recv_msg_str(type), length);
    
    // Forward raw message to application if handler registered
    if(type == XRSR_RECV_MSG_TEXT && obj->handlers.msg) {
        obj->handlers.msg((const char *)buffer, length, obj->user_data);
    }

    // JSON parsing with error handling
    json_error_t error;
    json_t *obj_json = json_loads((const char *)buffer, JSON_REJECT_DUPLICATES, &error);
    
    if(obj_json == NULL) {
        XLOGD_ERROR("invalid json");
        return(false);
    } else if(!json_is_object(obj_json)) {
        XLOGD_ERROR("json object not found");
        json_decref(obj_json);
        return(false);
    }
    
    // Process message with error handling
    bool retval = xrsv_ws_nextgen_msg_decode(obj, obj_json);
    json_decref(obj_json);

    // Validate output parameters
    if(recv_event == NULL) {
        XLOGD_ERROR("null event pointer");
        retval = false;
    } else {
        *recv_event = obj->recv_event;
    }
    
    obj->recv_event = XRSR_RECV_EVENT_NONE;
    return(retval);
}
```

### Message Processing Error Patterns
1. **Input Validation**: Buffer and length validation before processing
2. **JSON Parsing**: Comprehensive JSON validation with error reporting
3. **Schema Validation**: Object type and structure validation  
4. **Parameter Validation**: Output parameter validation
5. **Resource Cleanup**: Proper JSON object reference management
6. **Error Propagation**: Clear return value indicating success/failure

## Stream End Error Handling

### Server-Initiated Stream Termination
```c
bool xrsv_ws_nextgen_msgtype_server_stream_end(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
    int reason = -1;
    json_t *obj_reason = NULL;

    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }

    // Extract termination reason from server message
    obj_reason = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_REASON);
    if(obj_reason == NULL || !json_is_integer(obj_reason)) {
        XLOGD_ERROR("failed to get stream end reason");
        return false;
    }

    reason = json_integer_value(obj_reason);
    
    // Map stream end reason to receive event
    obj->recv_event = (reason == XRSV_STREAM_END_END_OF_SPEECH ? 
                      XRSR_RECV_EVENT_EOS_SERVER : 
                      XRSR_RECV_EVENT_DISCONNECT_REMOTE);

    // Return disconnect indication for non-EOS reasons
    if(reason == XRSV_STREAM_END_END_OF_SPEECH) {
        return(false);  // Normal completion
    } else {
        return(true);   // Error condition requiring disconnection
    }
}
```

### Stream End Reason Processing
- **XRSV_STREAM_END_END_OF_SPEECH**: Normal completion, continue session
- **XRSV_STREAM_END_TIMEOUT**: Timeout occurred, may retry
- **XRSV_STREAM_END_INTERNAL_ERROR**: Server error, may need retry with backoff
- **XRSV_STREAM_END_USER_INTERUPTED**: User cancelled, clean termination
- **XRSV_STREAM_END_MAX_LENGTH**: Limit reached, normal completion
- **XRSV_STREAM_END_INVALID**: Unknown error, requires investigation

## Connection Failure and Recovery

### Connection Establishment Error Handling
```c
bool xrsv_ws_nextgen_handler_ws_connected(void *data, 
                                        const uuid_t uuid, 
                                        xrsr_handler_send_t send, 
                                        void *param, 
                                        rdkx_timestamp_t *timestamp, 
                                        xrsr_session_config_update_t *session_config_update) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return false;
    }

    // Notify application of successful connection
    if(obj->handlers.connected != NULL) {
        (*obj->handlers.connected)(uuid, timestamp, obj->user_data);
    }

    // Store connection parameters
    obj->send = send;
    obj->param = param;
    obj->session_config_update = session_config_update;

    // Generate and send initialization message
    uint8_t *buffer = NULL;
    uint32_t length = 0;
    xrsv_ws_nextgen_msg_init(obj, &buffer, &length);
    
    if(buffer == NULL || length == 0) {
        XLOGD_ERROR("invalid message");
        return false;
    }
    
    XLOGD_AUTOMATION_INFO("msg init <%s>", obj->mask_pii ? "***" : (char *)buffer);
    
    // Send initialization message with error handling
    xrsr_result_t result = (*send)(param, buffer, length);
    free(buffer);

    if(result != XRSR_RESULT_SUCCESS) {
        XLOGD_ERROR("result <%s>", xrsr_result_str(result));
    }
    
    // Notify application of initialization message sent
    if(obj->handlers.sent_init != NULL) {
        rdkx_timestamp_t ts_sent_init;
        rdkx_timestamp_get_realtime(&ts_sent_init);
        (*obj->handlers.sent_init)(uuid, &ts_sent_init, obj->user_data);
    }
    
    return (result == XRSR_RESULT_SUCCESS);
}
```

### Recovery Mechanisms
1. **Connection State Management**: Send function and parameters cleared on disconnect
2. **Resume Detection**: Applications can control whether voice detection resumes  
3. **Retry Logic**: XRSR layer provides retry recommendations to XRSV handlers
4. **Initialization Retry**: Failed initialization messages can trigger reconnection
5. **State Synchronization**: Session configuration maintained across reconnections

## Timeout Handling

### Configurable Timeout Support
```c
// WebSocket NextGen stream parameters with timeout configuration
typedef struct {
    // ... other parameters
    uint16_t par_eos_timeout; ///< Press-and-release end-of-speech timeout
    // ... other parameters
} xrsv_ws_nextgen_stream_params_t;

// Timeout configuration in session setup
void xrsv_ws_nextgen_handler_ws_session_config(void *data, 
                                              const uuid_t uuid, 
                                              xrsr_session_config_in_t *config_in) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    int rc = 0;

    if(config_in == NULL || config_in->ws.app_config == NULL) {
        XLOGD_ERROR("invalid stream params <%p>", config_in);
        return;
    }

    xrsv_ws_nextgen_stream_params_t *stream_params = 
        (xrsv_ws_nextgen_stream_params_t *)config_in->ws.app_config;

    // Configure timeout if specified
    if(stream_params->par_eos_timeout > 0) {
        rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, 
                                        XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TIMEOUT, 
                                        json_integer(stream_params->par_eos_timeout));
    } else {
        // Remove timeout configuration if not specified
        json_object_del(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TIMEOUT);
    }
    
    // ... other configuration processing
}
```

### Timeout Error Types
- **Connection Timeout**: Network connection establishment timeout
- **Response Timeout**: Server response timeout for voice requests
- **EOS Timeout**: End-of-speech detection timeout
- **Session Timeout**: Overall session duration timeout
- **Authentication Timeout**: Authentication token or certificate timeout

## Error Reporting and Logging

### Result String Conversion
```c
const char *xrsv_result_str(xrsv_result_t type) {
    switch(type) {
        case XRSV_RESULT_SUCCESS: return("SUCCESS");
        case XRSV_RESULT_ERROR:   return("ERROR");
        case XRSV_RESULT_INVALID: return("INVALID");
    }
    return(xrsv_invalid_return(type));
}

// Fallback for unknown result codes
static const char *xrsv_invalid_return(int value) {
    snprintf(xrsv_invalid_str, XRSV_INVALID_STR_LEN, "INVALID(%d)", value);
    xrsv_invalid_str[XRSV_INVALID_STR_LEN - 1] = '\0';
    return(xrsv_invalid_str);
}
```

### Logging Integration Patterns
```c
// Error logging with context
XLOGD_ERROR("result <%s>", xrsr_result_str(result));
XLOGD_ERROR("invalid json");
XLOGD_ERROR("failed to get stream end reason");
XLOGD_ERROR("invalid object");
XLOGD_ERROR("invalid message");

// Informational logging
XLOGD_INFO("type <%s> length <%u>", xrsr_recv_msg_str(type), length);
XLOGD_INFO("Updating dynamic_gain to <%f>", obj->session_config_update->dynamic_gain);

// Warning logging
XLOGD_WARN("truncated device id <%d>", rc);
```

## Application Error Handling Integration

### Comprehensive Error Handler Registration
```c
// HTTP error handlers
typedef struct {
    xrsv_http_handler_source_error_t      source_error;      ///< Source error events
    xrsv_http_handler_disconnected_t      disconnected;      ///< Disconnection events
    // ... other handlers
} xrsv_http_handlers_t;

// WebSocket NextGen error handlers  
typedef struct {
    xrsv_ws_nextgen_handler_source_error_t      source_error;      ///< Source error events
    xrsv_ws_nextgen_handler_disconnected_t      disconnected;      ///< Disconnection events
    // ... other handlers
} xrsv_ws_nextgen_handlers_t;
```

### Error Response Patterns
```c
// Application error handling example
void application_source_error_handler(xrsr_src_t src, void *user_data) {
    switch(src) {
        case XRSR_SRC_MICROPHONE:
            // Audio input error - check microphone, restart audio
            handle_microphone_error();
            break;
        case XRSR_SRC_HTTP_STREAM:
        case XRSR_SRC_WS_STREAM:
            // Network/protocol error - implement retry with backoff
            schedule_connection_retry();
            break;
        default:
            // Unknown source - log and investigate
            log_unknown_error_source(src);
            break;
    }
}

void application_disconnected_handler(const uuid_t uuid, 
                                     bool retry, 
                                     rdkx_timestamp_t *timestamp, 
                                     void *user_data) {
    if(retry) {
        // Retry recommended - attempt reconnection
        schedule_reconnection_with_backoff();
    } else {
        // Retry not recommended - may need user intervention
        notify_user_connection_problem();
        request_user_authentication_refresh();
    }
}
```

## Error Recovery Strategies

### Connection Recovery
1. **Automatic Retry**: XRSR layer provides retry recommendations  
2. **Exponential Backoff**: Applications should implement increasing delays
3. **Circuit Breaker**: Temporary suspension of retry attempts after repeated failures
4. **State Restoration**: Session configuration maintained across reconnections
5. **Graceful Degradation**: Fallback to offline mode or cached responses

### Session Recovery  
1. **Detection Resume**: Voice detection can resume after temporary failures
2. **Session Persistence**: Session state maintained during brief disconnections
3. **Parameter Restoration**: Configuration parameters restored on reconnection
4. **Context Maintenance**: User interaction context preserved where possible

### Audio Recovery
1. **Buffer Management**: Audio buffers handled gracefully during interruptions
2. **Stream Restart**: Audio streaming can restart after microphone errors
3. **Codec Switching**: Fallback to alternative codecs on compatibility issues
4. **Quality Adaptation**: Dynamic quality adjustment based on connection quality

## Performance and Resource Management

### Error Handling Performance
- **Fast Path Validation**: Object validation optimized for success case
- **Minimal Allocation**: Error paths avoid dynamic memory allocation
- **Efficient Logging**: Conditional logging to minimize overhead  
- **Resource Cleanup**: Automatic cleanup on error conditions

### Memory Management During Errors
```c
// JSON error handling with proper cleanup
json_t *obj_json = json_loads((const char *)buffer, JSON_REJECT_DUPLICATES, &error);
if(obj_json == NULL) {
    XLOGD_ERROR("invalid json");
    return(false);  // No cleanup needed - json_loads failed
} else if(!json_is_object(obj_json)) {
    XLOGD_ERROR("json object not found");
    json_decref(obj_json);  // Cleanup allocated JSON object  
    return(false);
}

// Process message
bool retval = xrsv_ws_nextgen_msg_decode(obj, obj_json);
json_decref(obj_json);  // Always cleanup JSON object

return retval;
```

## Best Practices for Error Handling

### Design Guidelines
1. **Early Validation**: Validate inputs at function entry points
2. **Consistent Patterns**: Use standard error checking across all functions
3. **Clear Error Messages**: Provide specific, actionable error information
4. **Resource Safety**: Ensure cleanup of resources in all error paths
5. **State Consistency**: Maintain consistent object state during failures

### Implementation Patterns  
```c
// Standard XRSV error handling pattern
bool xrsv_function(xrsv_object_t object, parameters...) {
    xrsv_obj_t *obj = (xrsv_obj_t *)object;
    
    // 1. Object validation
    if(!xrsv_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return false;
    }
    
    // 2. Parameter validation
    if(required_param == NULL) {
        XLOGD_ERROR("invalid parameter");
        return false;
    }
    
    // 3. Operation with error handling
    if(operation_fails()) {
        XLOGD_ERROR("operation failed");
        cleanup_resources();
        return false;
    }
    
    // 4. Success path
    return true;
}
```

### Application Integration Guidelines
1. **Handler Registration**: Always register error handlers for production systems
2. **Retry Logic**: Implement exponential backoff for network errors
3. **User Notification**: Provide clear user feedback for irrecoverable errors  
4. **Logging Integration**: Log errors with sufficient context for debugging
5. **Graceful Degradation**: Implement fallback mechanisms for service failures

### Debugging and Diagnostics  
1. **Error Context**: Include session UUID, timestamps, and operation context in error logs
2. **State Dumping**: Capture object state during unexpected errors
3. **Performance Monitoring**: Track error rates and patterns
4. **Network Diagnostics**: Log network conditions during connection failures
5. **Resource Monitoring**: Monitor memory and connection resource usage

The XRSV error handling system provides robust, comprehensive error management that ensures voice services can handle failures gracefully while providing applications with the information needed for appropriate user-level responses and recovery actions. The layered approach separates concerns effectively while maintaining consistency across HTTP and WebSocket NextGen implementations.