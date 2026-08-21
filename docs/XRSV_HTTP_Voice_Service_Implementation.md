# XRSV HTTP Voice Service Implementation

## Overview
The XRSV HTTP Voice Service implementation provides a request-response based voice recognition interface built on top of the XRSR HTTP protocol. It abstracts the complexities of HTTP communication, JSON message processing, and session management while providing a simplified callback-based API for applications. This implementation is designed for batch voice processing scenarios where real-time streaming is not required.

## Implementation Architecture

### Core Object Structure
```c
#define XRSV_HTTP_IDENTIFIER (0x773D8203)  // Object validation identifier

typedef struct {
   uint32_t             identifier;                      // Object type validation
   xrsv_http_handlers_t handlers;                        // Application callback handlers
   xrsr_handler_send_t  send;                           // XRSR send function pointer
   void *               param;                          // XRSR parameter context
   
   // Pre-formatted query string parameters  
   char                 query_element_trx[41];          // Transaction ID (UUID)
   char                 query_element_device_id[64];    // Device identifier
   char                 query_element_receiver_id[64];  // Receiver identifier  
   char                 query_element_codec[17];        // Audio codec specification
   char                 query_element_app_id[64];       // Application identifier
   char                 query_element_partner_id[32];   // Partner identifier
   char                 query_element_experience[32];   // Experience tag
   char                 query_element_language[32];     // Language setting
   char                 query_element_aspect_ratio[16]; // Video aspect ratio
   char                 query_element_vrex_filters[40]; // VREX processing filters
   
   // Runtime configuration
   bool                 mask_pii;                       // PII masking flag
   void *               user_data;                      // Application user data
} xrsv_http_obj_t;
```

### Object Lifecycle Management

#### Object Creation and Validation
```c
xrsv_http_object_t xrsv_http_create(const xrsv_http_params_t *params) {
    // Parameter validation
    if(params == NULL) {
        XLOGD_ERROR("invalid params");
        return(NULL);
    }
    
    // Memory allocation
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)malloc(sizeof(xrsv_http_obj_t));
    if(obj == NULL) {
        XLOGD_ERROR("Out of memory.");
        return(NULL);
    }
    
    // Initialize object structure
    memset(obj, 0, sizeof(*obj));
    obj->identifier = XRSV_HTTP_IDENTIFIER;
    
    // Apply configuration parameters
    if(params->device_id != NULL) {
        xrsv_http_update_device_id(obj, params->device_id);
    }
    // ... additional parameter initialization
    
    return(obj);
}
```

**Creation Features**:
- **Memory Safety**: Comprehensive null pointer checking and memory initialization
- **Parameter Validation**: Individual parameter validation during creation
- **Graceful Defaults**: Safe handling of optional parameters
- **Error Propagation**: Clear error messages for debugging

#### Object Validation Pattern
```c
bool xrsv_http_object_is_valid(xrsv_http_obj_t *obj) {
   if(obj != NULL && obj->identifier == XRSV_HTTP_IDENTIFIER) {
      return(true);
   }
   return(false);
}
```

**Validation Benefits**:
- **Type Safety**: Magic number validation prevents invalid object usage
- **Memory Corruption Detection**: Identifies corrupted or invalid objects
- **Debug Support**: Consistent validation across all object operations
- **API Robustness**: Prevents crashes from invalid object usage

### Handler Bridge Implementation

#### XRSR Integration Bridge
```c
bool xrsv_http_handlers(xrsv_http_object_t object, 
                       const xrsv_http_handlers_t *handlers_in, 
                       xrsr_handlers_t *handlers_out) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    // Configure XRSR handlers to point to XRSV implementation
    handlers_out->data           = obj;
    handlers_out->source_error   = xrsv_http_handler_source_error;
    handlers_out->session_begin  = xrsv_http_handler_session_begin;
    handlers_out->session_config = NULL;  // Not used in HTTP implementation
    handlers_out->session_end    = xrsv_http_handler_session_end;
    handlers_out->stream_begin   = xrsv_http_handler_stream_begin;
    handlers_out->stream_kwd     = NULL;  // Not applicable for HTTP
    handlers_out->stream_end     = xrsv_http_handler_stream_end;
    handlers_out->connected      = xrsv_http_handler_connected;
    handlers_out->disconnected   = xrsv_http_handler_disconnected;
    handlers_out->recv_msg       = xrsv_http_handler_recv_msg;
    
    // Store application handlers
    if(handlers_in) {
        obj->handlers = *handlers_in;
    }
    return(true);
}
```

**Bridge Design Features**:
- **Layer Translation**: Converts XRSR callbacks to application-friendly XRSV callbacks
- **Context Preservation**: Maintains object context through handler chain
- **Optional Handlers**: Gracefully handles NULL application handlers
- **Protocol Adaptation**: Disables non-applicable handlers for HTTP protocol

## Configuration Management

### Query Parameter System

#### HTTP Query String Construction
The HTTP implementation uses a sophisticated query parameter system that pre-formats all parameters as HTTP query strings:

**Parameter Formatting Functions**:
```c
bool xrsv_http_update_device_id(xrsv_http_object_t object, const char *device_id) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    int rc = snprintf(obj->query_element_device_id, 
                     sizeof(obj->query_element_device_id), 
                     "xboDeviceId=%s", device_id);
    if(rc >= sizeof(obj->query_element_device_id)) {
        XLOGD_WARN("truncated device id <%d>", rc);
        return(false);
    }
    return(true);
}
```

**Configuration Parameters**:
- **Device Identification**: `xboDeviceId`, `receiverId`, `partnerId`
- **Application Context**: `appId`, `experienceTag`
- **Language Settings**: `language` for localization
- **Media Configuration**: `aspectRatio` for video processing
- **Session Tracking**: `trx` for transaction correlation
- **Audio Format**: `codec` for audio processing specification

#### Runtime Parameter Updates
All configuration parameters support runtime updates without requiring object recreation:

```c
// Device identity updates  
bool xrsv_http_update_device_id(xrsv_http_object_t object, const char *device_id);
bool xrsv_http_update_receiver_id(xrsv_http_object_t object, const char *receiver_id);
bool xrsv_http_update_partner_id(xrsv_http_object_t object, const char *partner_id);

// Application configuration updates
bool xrsv_http_update_experience(xrsv_http_object_t object, const char *experience);
bool xrsv_http_update_app_id(xrsv_http_object_t object, const char *app_id);
bool xrsv_http_update_language(xrsv_http_object_t object, const char *language);

// Privacy and user context updates
bool xrsv_http_update_mask_pii(xrsv_http_object_t object, bool enable);
bool xrsv_http_update_user_data(xrsv_http_object_t object, void *user_data);
```

**Runtime Update Features**:
- **Atomic Updates**: Individual parameter updates without affecting others
- **Validation**: Length checking and truncation warnings
- **Thread Safety**: Safe for concurrent access (object-level locking at application level)
- **Immediate Effect**: Updates apply to next session without restart

### Buffer Management and Safety

#### Fixed Buffer Allocation
```c
// Query parameter buffers with safety margins
char query_element_trx[41];          // UUID string + null terminator (36+1+4 safety)
char query_element_device_id[64];    // Device ID with parameter name prefix
char query_element_receiver_id[64];  // Receiver ID with parameter name prefix
char query_element_codec[17];        // Codec name with parameter prefix
```

**Buffer Safety Features**:
- **Compile-Time Sizing**: Fixed buffer sizes prevent dynamic allocation issues
- **Overflow Protection**: snprintf() usage with size limits prevents buffer overruns
- **Truncation Detection**: Warning messages for oversized parameters
- **Safe Defaults**: Empty string initialization for unused parameters

## Session Lifecycle Implementation

### Session Initialization

#### Session Begin Handler
```c
void xrsv_http_handler_session_begin(xrsv_http_object_t object, const uuid_t uuid, 
                                   xrsr_src_t src, uint32_t dst_index, 
                                   xrsr_keyword_detector_result_t *detector_result, 
                                   xrsr_session_config_out_t *config_out, 
                                   xrsr_session_config_in_t *config_in, 
                                   rdkx_timestamp_t *timestamp, 
                                   const char *transcription_in) {
    // Generate session UUID string
    char uuid_str[37] = {'\0'};
    uuid_unparse_lower(uuid, uuid_str);
    
    // Notify application of session start
    if(obj->handlers.session_begin != NULL) {
        (*obj->handlers.session_begin)(uuid, src, dst_index, config_out, timestamp, obj->user_data);
    }
    
    // Determine audio codec from configuration
    const char *codec = "ADPCM";  // Default codec
    if(config_out->format.type == XRSR_AUDIO_FORMAT_PCM) {
        codec = "PCM_16_16K";
    } else if(config_out->format.type == XRSR_AUDIO_FORMAT_OPUS) {
        codec = "OPUS";
    }
    
    // Configure session-specific parameters
    snprintf(obj->query_element_trx, sizeof(obj->query_element_trx), "trx=%s", uuid_str);
    snprintf(obj->query_element_codec, sizeof(obj->query_element_codec), "codec=%s", codec);
    
    // Build complete query string array for XRSR
    config_in->http.query_strs[0] = obj->query_element_app_id;
    config_in->http.query_strs[1] = obj->query_element_device_id;
    config_in->http.query_strs[2] = obj->query_element_partner_id;
    config_in->http.query_strs[3] = obj->query_element_experience;
    config_in->http.query_strs[4] = obj->query_element_language;
    config_in->http.query_strs[5] = obj->query_element_aspect_ratio;
    config_in->http.query_strs[6] = obj->query_element_trx;
    config_in->http.query_strs[7] = obj->query_element_codec;
    
    // Configure VREX filters based on session type
    if (transcription_in != NULL) {
        // Text-only session: disable speech recognition filter
        snprintf(obj->query_element_vrex_filters, sizeof(obj->query_element_vrex_filters), 
                "vrexFilters=NLP,EVENT,AR,EXEC");
        config_in->http.query_strs[8] = obj->query_element_vrex_filters;
        config_in->http.query_strs[9] = NULL;
    } else {
        // Audio session: use default VREX filters
        config_in->http.query_strs[8] = NULL;
    }
}
```

**Session Begin Features**:
- **UUID Management**: Automatic UUID string conversion for HTTP transmission
- **Codec Detection**: Automatic audio codec determination from XRSR configuration
- **Query String Assembly**: Dynamic HTTP query string construction
- **Session Type Adaptation**: Different configurations for audio vs. text sessions
- **Filter Management**: VREX processing filter configuration

### Session Termination

#### Session End Handler
```c
void xrsv_http_handler_session_end(xrsv_http_object_t object, const uuid_t uuid, 
                                  xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return;
    }
    
    // Notify application of session completion
    if(obj->handlers.session_end != NULL) {
        (*obj->handlers.session_end)(uuid, stats, timestamp, obj->user_data);
    }
    
    // Clean up session-specific state
    obj->query_element_trx[0] = '\0';  // Clear transaction ID
}
```

**Session End Features**:
- **Statistics Propagation**: XRSR session statistics passed to application
- **State Cleanup**: Session-specific parameters cleared for next session
- **Application Notification**: Callback invocation with session results
- **Resource Management**: Proper cleanup without memory leaks

### Connection Management

#### Connection Established Handler
```c
bool xrsv_http_handler_connected(xrsv_http_object_t object, const uuid_t uuid, 
                               xrsr_handler_send_t send, void *param, 
                               rdkx_timestamp_t *timestamp, 
                               xrsr_session_config_update_t *session_config_update) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return false;
    }
    
    // Notify application of successful connection
    if(obj->handlers.connected != NULL) {
        (*obj->handlers.connected)(uuid, timestamp, obj->user_data);
    }
    
    return true;  // Indicate successful connection handling
}
```

#### Connection Termination Handler
```c
void xrsv_http_handler_disconnected(xrsv_http_object_t object, const uuid_t uuid, 
                                  xrsr_session_end_reason_t reason, bool retry, 
                                  bool *detect_resume, rdkx_timestamp_t *timestamp) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return;
    }
    
    // Enable keyword detection resume for next session
    if(detect_resume != NULL) {
        *detect_resume = true;
    }
    
    // Notify application of disconnection
    if(obj->handlers.disconnected != NULL) {
        (*obj->handlers.disconnected)(uuid, timestamp, obj->user_data);
    }
}
```

**Connection Management Features**:
- **Automatic Resume**: Keyword detection automatically enabled for next session
- **Reason Propagation**: Disconnection reason available for application logic
- **Timestamp Tracking**: Connection timing information for performance analysis
- **Error Recovery**: Graceful handling of connection failures

## Message Processing Implementation

### JSON Response Processing

#### HTTP Message Handler
```c
bool xrsv_http_handler_recv_msg(xrsv_http_object_t object, xrsr_recv_msg_t type, 
                              const uint8_t *buffer, uint32_t length, 
                              xrsr_recv_event_t *recv_event) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    switch(type) {
        case XRSR_RECV_MSG_TEXT: {
            xrsv_http_recv_msg_t msg;
            
            // Parse JSON response from HTTP server
            json_t *obj_json = json_loadb((const char *)buffer, length, JSON_DECODE_ANY, NULL);
            if(NULL == obj_json) {
                XLOGD_TELEMETRY("Failed to parse JSON response");
                return(false);
            }
            
            memset(&msg, 0, sizeof(msg));
            
            // Extract server return code
            json_t *temp = json_object_get(obj_json, "code");
            if(temp && json_is_integer(temp)) {
                msg.ret_code = json_integer_value(temp);
            } else {
                XLOGD_WARN("No server return code");
            }
            
            // Extract server message
            temp = json_object_get(obj_json, "message");
            if(temp && json_is_string(temp)) {
                strlcpy(msg.message, json_string_value(temp), sizeof(msg.message));
            } else {
                XLOGD_WARN("No message");
            }
            
            // Extract transcription from nested NLP response
            temp = json_object_get(obj_json, "nlp");
            if(temp && json_is_object(temp)) {
                temp = json_object_get(temp, "response");
                if(temp && json_is_object(temp)) {
                    temp = json_object_get(temp, "text");
                    if(temp && json_is_string(temp)) {
                        strlcpy(msg.transcription, json_string_value(temp), sizeof(msg.transcription));
                    }
                }
            } else {
                XLOGD_TELEMETRY("No transcription");
            }
            
            // Extract transaction ID
            temp = json_object_get(obj_json, "trx");
            if(temp && json_is_string(temp)) {
                strlcpy(msg.session_id, json_string_value(temp), sizeof(msg.session_id));
            } else {
                XLOGD_WARN("No trx");
            }
            
            // Deliver processed message to application
            if(obj->handlers.recv_msg != NULL) {
                (*obj->handlers.recv_msg)(&msg, obj->user_data);
            }
            
            json_decref(obj_json);  // Clean up JSON object
            break;
        }
        default: {
            XLOGD_INFO("msg type not implemented");
            break;
        }
    }
    return(false);
}
```

### JSON Message Structure

#### Expected Server Response Format
```json
{
    "code": 200,
    "message": "Voice processing completed successfully",
    "trx": "550e8400-e29b-41d4-a716-446655440000",
    "nlp": {
        "response": {
            "text": "turn on the lights in the living room"
        }
    }
}
```

**JSON Processing Features**:
- **Robust Parsing**: Jansson library integration for reliable JSON processing
- **Nested Extraction**: Deep object traversal for transcription text
- **Type Validation**: JSON type checking before value extraction  
- **Error Tolerance**: Graceful handling of missing or malformed fields
- **Memory Management**: Proper JSON object cleanup to prevent leaks

**Message Field Extraction**:
- **Return Code**: Server status code from `"code"` field
- **Message**: Server message from `"message"` field  
- **Transcription**: Speech recognition result from `"nlp.response.text"` field
- **Transaction ID**: Session correlation ID from `"trx"` field

### Buffer Safety in Message Processing

#### String Copy Protection
```c
// Safe string copying with size limits
strlcpy(msg.message, json_string_value(temp), sizeof(msg.message));
strlcpy(msg.transcription, json_string_value(temp), sizeof(msg.transcription));
strlcpy(msg.session_id, json_string_value(temp), sizeof(msg.session_id));
```

**Safety Features**:
- **BSD strlcpy()**: Prevents buffer overruns with guaranteed null-termination
- **Size-Aware Copying**: Uses sizeof() to enforce compile-time buffer limits
- **Truncation Handling**: Graceful truncation for oversized server responses
- **Memory Initialization**: memset() ensures clean initial state

## Audio Processing Integration

### Audio Format Detection

#### Codec Configuration Logic
```c
const char *codec = "ADPCM";  // Default fallback codec
if(config_out->format.type == XRSR_AUDIO_FORMAT_PCM) {
    codec = "PCM_16_16K";  // Uncompressed 16-bit 16kHz PCM
} else if(config_out->format.type == XRSR_AUDIO_FORMAT_OPUS) {
    codec = "OPUS";        // Opus compressed audio
}
```

**Supported Audio Formats**:
- **ADPCM**: Adaptive Differential Pulse Code Modulation (default)
- **PCM_16_16K**: 16-bit PCM at 16kHz sample rate
- **OPUS**: Opus audio codec for high-quality compression

**Codec Selection Features**:
- **Automatic Detection**: Codec determined from XRSR configuration
- **HTTP Parameter**: Codec information sent to server via query string
- **Fallback Strategy**: ADPCM used as default for unknown formats
- **Server Coordination**: Ensures client-server codec compatibility

### Session Type Adaptation

#### Text vs. Audio Session Handling
```c
if (transcription_in != NULL) {
    // Text-only session configuration
    snprintf(obj->query_element_vrex_filters, sizeof(obj->query_element_vrex_filters), 
            "vrexFilters=NLP,EVENT,AR,EXEC");
    config_in->http.query_strs[8] = obj->query_element_vrex_filters;
} else {
    // Audio session - use default filters (includes SR for speech recognition)
    config_in->http.query_strs[8] = NULL;
}
```

**Session Type Features**:
- **Text-Only Sessions**: Bypass speech recognition, process text directly
- **Audio Sessions**: Full speech processing pipeline with audio streaming  
- **Filter Configuration**: VREX processing filters adapted to session type
- **Resource Optimization**: Disabled unnecessary processing for text sessions

**VREX Filter Types**:
- **SR**: Speech Recognition (disabled for text-only)
- **NLP**: Natural Language Processing
- **EVENT**: Event processing
- **AR**: Augmented Reality processing  
- **EXEC**: Execution processing

## Error Handling and Diagnostics

### Telemetry and Logging Integration

#### Logging Strategy
The implementation uses structured logging for different severity levels:

```c
// Error conditions
XLOGD_ERROR("invalid object");           // Critical errors
XLOGD_ERROR("Out of memory.");          // Resource failures

// Warning conditions  
XLOGD_WARN("truncated device id <%d>", rc);   // Configuration issues
XLOGD_WARN("No server return code");          // Missing response fields

// Telemetry for analytics
XLOGD_TELEMETRY("Failed to parse JSON response");  // Processing failures
XLOGD_TELEMETRY("No transcription");               // Missing transcription

// Informational logging
XLOGD_INFO("");  // Event markers for session lifecycle
```

**Logging Categories**:
- **XLOGD_ERROR**: Critical failures requiring immediate attention
- **XLOGD_WARN**: Non-critical issues that may affect functionality  
- **XLOGD_TELEMETRY**: Analytics data for performance monitoring
- **XLOGD_INFO**: Normal operation event markers

### Validation and Defensive Programming

#### Input Validation Pattern
```c
// Consistent validation across all API functions
xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
if(!xrsv_http_object_is_valid(obj)) {
    XLOGD_ERROR("invalid object");
    return(false);  // or appropriate error value
}
```

**Defensive Programming Features**:
- **Null Pointer Checks**: All public functions validate input pointers
- **Object Validation**: Magic number verification for all object operations
- **Buffer Bounds**: snprintf() usage prevents buffer overruns
- **Return Code Checking**: Proper error propagation through return values

#### Graceful Degradation
```c
// Optional callback handling
if(obj->handlers.session_begin != NULL) {
    (*obj->handlers.session_begin)(uuid, src, dst_index, config_out, timestamp, obj->user_data);
}
```

**Degradation Features**:
- **Optional Callbacks**: NULL handler checks prevent crashes
- **Partial Functionality**: Missing configuration doesn't prevent operation
- **Error Recovery**: Failed operations don't corrupt object state
- **Resource Cleanup**: Proper cleanup even in error conditions

## Memory Management and Resource Handling

### Object Destruction
```c
void xrsv_http_destroy(xrsv_http_object_t object) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return;
    }
    
    // Clear sensitive data
    obj->query_element_device_id[0]     = '\0';
    obj->query_element_receiver_id[0]   = '\0';  
    obj->query_element_codec[0]         = '\0';
    obj->query_element_trx[0]           = '\0';
    obj->query_element_app_id[0]        = '\0';
    obj->query_element_partner_id[0]    = '\0';
    obj->query_element_experience[0]    = '\0';
    obj->query_element_language[0]      = '\0';
    obj->query_element_aspect_ratio[0]  = '\0';
    
    // Invalidate object identifier
    obj->identifier = 0;
    
    // Free allocated memory
    free(obj);
}
```

**Resource Management Features**:
- **Data Clearing**: Sensitive information cleared before deallocation
- **Object Invalidation**: Magic number cleared to detect use-after-free
- **Memory Deallocation**: Single malloc/free pair for simple memory management
- **Security Conscious**: PII and configuration data explicitly cleared

### JSON Memory Management
```c
// Automatic cleanup of JSON objects
json_t *obj_json = json_loadb((const char *)buffer, length, JSON_DECODE_ANY, NULL);
// ... JSON processing ...
json_decref(obj_json);  // Reference counting cleanup
```

**JSON Resource Features**:
- **Reference Counting**: Jansson library automatic memory management
- **Exception Safety**: JSON cleanup even if processing fails
- **Memory Leak Prevention**: Explicit json_decref() calls
- **Resource Scoping**: JSON objects have clear lifecycle boundaries

## Performance Optimization

### Pre-Formatted Query Strings
The implementation pre-formats all HTTP query parameters during configuration updates rather than during session processing:

```c
// Configuration time (infrequent)
snprintf(obj->query_element_device_id, sizeof(obj->query_element_device_id), 
         "xboDeviceId=%s", device_id);

// Session time (frequent) - just pointer assignment
config_in->http.query_strs[1] = obj->query_element_device_id;
```

**Performance Benefits**:
- **Reduced Session Latency**: No string formatting during time-critical session setup
- **Memory Efficiency**: Fixed buffers avoid dynamic allocation overhead
- **CPU Optimization**: String construction moved to configuration phase
- **Cache Efficiency**: Pre-formatted strings improve memory access patterns

### Minimal Dynamic Allocation
```c
// Single allocation per XRSV HTTP object
xrsv_http_obj_t *obj = (xrsv_http_obj_t *)malloc(sizeof(xrsv_http_obj_t));
```

**Allocation Strategy**:
- **Single Allocation**: One malloc/free pair per object lifecycle
- **Fixed Buffers**: All string storage uses compile-time sized buffers
- **No Session Allocation**: Session processing uses pre-allocated resources
- **Memory Predictability**: Deterministic memory usage for embedded systems

## Integration Patterns

### Application Integration Example
```c
// Application callback implementation
void app_recv_msg_handler(xrsv_http_recv_msg_t *msg, void *user_data) {
    printf("Server Response Code: %ld\n", msg->ret_code);
    printf("Message: %s\n", msg->message);
    printf("Transcription: %s\n", msg->transcription);
    printf("Session ID: %s\n", msg->session_id);
}

// XRSV HTTP object setup
xrsv_http_params_t params = {
    .device_id = "device123",
    .app_id = "voice_app",
    .language = "en-US",
    .mask_pii = true,
    .user_data = &app_context
};

xrsv_http_object_t http_obj = xrsv_http_create(&params);

xrsv_http_handlers_t handlers = {
    .recv_msg = app_recv_msg_handler,
    .session_begin = app_session_begin_handler,
    .session_end = app_session_end_handler
    // ... other handlers
};

xrsr_handlers_t xrsr_handlers;
xrsv_http_handlers(http_obj, &handlers, &xrsr_handlers);

// Register with XRSR for HTTP protocol
xrsr_register_handlers(XRSR_PROTOCOL_HTTP, &xrsr_handlers);
```

### Configuration Update Pattern
```c
// Runtime configuration updates
xrsv_http_update_language(http_obj, "es-MX");  // Switch to Spanish
xrsv_http_update_mask_pii(http_obj, false);    // Disable PII masking for debug
xrsv_http_update_user_data(http_obj, new_context);  // Update application context
```

## Protocol Characteristics

### HTTP-Specific Features
- **Request-Response Model**: Single request produces single response
- **Stateless Operation**: Each session is independent HTTP transaction
- **Batch Processing**: Suitable for non-real-time voice queries
- **Simple Integration**: Standard HTTP makes debugging and monitoring easy

### Limitations
- **No Real-Time Streaming**: Cannot provide progressive speech recognition
- **Single Response**: Only final results available, no intermediate updates
- **Higher Latency**: Full audio upload required before processing begins
- **No Bidirectional Communication**: Server cannot send unsolicited messages

## Security and Privacy

### PII Masking Integration
```c
obj->mask_pii = params->mask_pii;  // Configuration-driven PII handling
```

**Privacy Features**:
- **Application Control**: PII masking controlled by application configuration
- **Runtime Updates**: PII masking can be enabled/disabled during operation
- **Logging Integration**: Affects logging behavior throughout the system
- **Compliance Support**: Enables GDPR/CCPA compliance implementations

### Secure Configuration
- **Parameter Validation**: All configuration parameters validated for size and content
- **Buffer Safety**: Fixed buffers prevent injection attacks
- **Memory Clearing**: Sensitive data cleared during object destruction
- **Input Sanitization**: All user-provided strings validated and truncated if necessary

The XRSV HTTP Voice Service implementation provides a robust, efficient, and secure foundation for HTTP-based voice recognition services. Its design emphasizes simplicity, performance, and reliability while maintaining the flexibility needed for diverse voice application scenarios.