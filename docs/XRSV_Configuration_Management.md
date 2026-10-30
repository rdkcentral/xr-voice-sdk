# XRSV Configuration Management

## Overview

The XRSV (VREX Speech Request) component implements a comprehensive configuration management system that supports both static initialization parameters and dynamic runtime configuration updates. The system is designed to handle voice service configurations for both HTTP and WebSocket NextGen implementations, providing flexible parameter management while maintaining protocol-specific optimizations.

## Architecture

### Component Location
- **HTTP Configuration**: [`src/xr-speech-vrex/xrsv_http/xrsv_http.h`](src/xr-speech-vrex/xrsv_http/xrsv_http.h) and [`src/xr-speech-vrex/xrsv_http/xrsv_http.c`](src/xr-speech-vrex/xrsv_http/xrsv_http.c)
- **WebSocket Configuration**: [`src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h`](src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h) and [`src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.c`](src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.c)

### Design Principles
- **Protocol-Specific Configuration**: Different parameter sets for HTTP vs WebSocket implementations
- **Runtime Updateability**: Dynamic configuration changes without service restart
- **Validation and Safety**: Parameter validation with bounds checking and error handling
- **JSON Integration**: Native JSON object management for WebSocket protocols
- **Query Parameter Management**: URL query parameter formatting for HTTP protocols

## HTTP Configuration Management

### Parameter Structure
```c
typedef struct {
   const char *device_id;        ///< The client device's unique identifier
   const char *receiver_id;      ///< The client device's receiver identifier
   const char *partner_id;       ///< The network's partner identifier
   const char *experience;       ///< User experience identifier
   const char *app_id;           ///< The application identifier for HTTP requests
   const char *language;         ///< The device's language
   bool        test_flag;        ///< True if the device is used for testing only
   bool        mask_pii;         ///< True if the PII must be masked from the log
   void       *user_data;        ///< User data that is passed in to all callbacks
} xrsv_http_params_t;
```

### Initialization Pattern
```c
xrsv_http_object_t xrsv_http_create(const xrsv_http_params_t *params) {
    xrsv_http_obj_t *obj = calloc(1, sizeof(xrsv_http_obj_t));
    
    if(params == NULL) {
        XLOGD_ERROR("invalid params");
        return NULL;
    }
    
    // Initialize configuration fields
    if(params->device_id != NULL) {
        xrsv_http_update_device_id(obj, params->device_id);
    }
    if(params->receiver_id != NULL) {
        xrsv_http_update_receiver_id(obj, params->receiver_id);  
    }
    if(params->partner_id != NULL) {
        xrsv_http_update_partner_id(obj, params->partner_id);
    }
    if(params->experience != NULL) {
        xrsv_http_update_experience(obj, params->experience);
    }
    if(params->language != NULL) {
        xrsv_http_update_language(obj, params->language);
    }
    
    obj->user_data = params->user_data;
    return obj;
}
```

### Runtime Update Functions

#### Device Configuration Updates
```c
bool xrsv_http_update_device_id(xrsv_http_object_t object, const char *device_id) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    bool rv = false;
    int rc = snprintf(obj->query_element_device_id, 
                     sizeof(obj->query_element_device_id), 
                     "xboDeviceId=%s", device_id);
    
    if(rc >= sizeof(obj->query_element_device_id)) {
        XLOGD_WARN("truncated device id <%d>", rc);
    } else {
        rv = true;
    }
    return rv;
}
```

#### Network Configuration Updates
```c
bool xrsv_http_update_partner_id(xrsv_http_object_t object, const char *partner_id) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    bool rv = false;
    int rc = snprintf(obj->query_element_partner_id, 
                     sizeof(obj->query_element_partner_id), 
                     "partnerId=%s", partner_id);
                     
    if(rc >= sizeof(obj->query_element_partner_id)) {
        XLOGD_WARN("truncated partner id <%d>", rc);
    } else {
        rv = true;
    }
    return rv;
}
```

#### Experience Configuration Updates
```c
bool xrsv_http_update_experience(xrsv_http_object_t object, const char *experience) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object"); 
        return(false);
    }
    
    bool rv = false;
    int rc = snprintf(obj->query_element_experience, 
                     sizeof(obj->query_element_experience), 
                     "experienceTag=%s", experience);
                     
    if(rc >= sizeof(obj->query_element_experience)) {
        XLOGD_WARN("truncated experience id <%d>", rc);
    } else {
        rv = true;
    }
    return rv;
}
```

### Query Parameter Management
HTTP implementation uses formatted query parameters for REST API integration:

**Query Parameter Format**:
- Device ID: `xboDeviceId=<device_id>`
- Receiver ID: `receiverId=<receiver_id>`
- Partner ID: `partnerId=<partner_id>`
- Experience: `experienceTag=<experience>`

**Buffer Management**:
- Fixed-size buffers with overflow detection
- Truncation warnings for oversized parameters
- Null-terminated string guarantees

## WebSocket NextGen Configuration Management

### Parameter Structure
```c
typedef struct {
   const char *device_id;                 ///< The client device's unique identifier
   const char *account_id;                ///< The user's account identifier
   const char *partner_id;                ///< The network's partner identifier
   const char *experience;                ///< User experience identifier
   const char *audio_profile;             ///< Device audio profile
   const char *audio_model;               ///< Device audio model
   const char *language;                  ///< The device's language
   const char *device_mac;                ///< The device's MAC address
   const char *rf_protocol;               ///< The device's RF protocol
   bool        test_flag;                 ///< True if the device is used for testing only
   bool        bypass_wuw_verify_success; ///< True if server WUW verification is bypassed (success)
   bool        bypass_wuw_verify_failure; ///< True if server WUW verification is bypassed (failure)
   bool        mask_pii;                  ///< True if the PII must be masked from the log
   void       *user_data;                 ///< User data that is passed in to all callbacks
} xrsv_ws_nextgen_params_t;
```

### Device Type Configuration  
```c
typedef enum {
   XRSV_WS_NEXTGEN_DEVICE_TYPE_STB     = 0,
   XRSV_WS_NEXTGEN_DEVICE_TYPE_TV      = 1, 
   XRSV_WS_NEXTGEN_DEVICE_TYPE_INVALID = 2
} xrsv_ws_nextgen_device_type_t;
```

### JSON Configuration Management

#### Generic JSON Update Utilities
```c
bool xrsv_ws_nextgen_update_json(json_t *obj, const char *key, json_t *value) {
    if(obj == NULL || key == NULL || value == NULL) {
        XLOGD_ERROR("invalid params");
        return(false);
    }
    
    // Update the value
    int rc = json_object_set_new_nocheck(obj, key, value);
    
    if(rc != 0) {
        XLOGD_ERROR("object set failed");
        return(false);
    }
    return(true);
}

bool xrsv_ws_nextgen_update_json_str(json_t *obj, const char *key, const char *value) {
    return(xrsv_ws_nextgen_update_json(obj, key, json_string(value)));
}
```

#### Device ID Configuration
```c
bool xrsv_ws_nextgen_update_device_id(xrsv_ws_nextgen_object_t object, const char *device_id) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
    if(!xrsv_ws_nextgen_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    bool rv = true;
    if(obj->obj_init_stb_id_device_id) {
        // Update existing device ID object
        rv = xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_id_device_id, 
                                           XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, 
                                           device_id);
    } else {
        // Create new device ID object
        int rc = 0;
        json_t *obj_values = json_object_get(obj->obj_init_stb_id, 
                                           XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES);
        if(obj_values == NULL) {
            obj_values = json_array();
            rc |= json_object_set_new_nocheck(obj->obj_init_stb_id, 
                                            XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES, 
                                            obj_values);
        }
        
        if((obj->obj_init_stb_id_device_id = json_object()) == NULL) {
            rv = false;
        } else {
            rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_device_id, 
                                            XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, 
                                            json_string(XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE_DEVICE_ID));
            rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_device_id, 
                                            XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, 
                                            json_string(device_id));
            rc |= json_array_append_new(obj_values, obj->obj_init_stb_id_device_id);
            
            if(rc != 0) {
                XLOGD_ERROR("object set error");
                rv = false;
            }
        }
    }
    
    // Update query parameter format
    if(rv) {
        int rc = snprintf(obj->query_element_device_id, 
                         sizeof(obj->query_element_device_id), 
                         "id=%s", device_id);
        if(rc >= sizeof(obj->query_element_device_id)) {
            XLOGD_WARN("truncated device id <%d>", rc);
        }
    }
    return rv;
}
```

### Advanced Configuration Features

#### Audio Profile Management
```c
bool xrsv_ws_nextgen_update_audio_profile(xrsv_ws_nextgen_object_t object, 
                                         const char *audio_profile);
bool xrsv_ws_nextgen_update_audio_model(xrsv_ws_nextgen_object_t object, 
                                       const char *audio_model);
bool xrsv_ws_nextgen_update_audio_rf_protocol(xrsv_ws_nextgen_object_t object, 
                                             const char *rf_protocol);
```

#### WUW Verification Control
```c
// Configuration supports bypass options for testing:
typedef struct {
    // ... other fields
    bool bypass_wuw_verify_success; // Force WUW verification success
    bool bypass_wuw_verify_failure; // Force WUW verification failure
    // ... other fields
} xrsv_ws_nextgen_params_t;
```

#### Application Blob Updates
```c
bool xrsv_ws_nextgen_update_init_app(xrsv_ws_nextgen_object_t object, const char *blob);
```
**Purpose**: Allows runtime injection of application-specific JSON configuration into WebSocket initialization messages.

## Session-Level Dynamic Configuration

### Configuration Update Mechanism
```c
typedef struct {
    bool update_required;    ///< Flag indicating if update is needed
    double dynamic_gain;     ///< Updated dynamic gain value
    // ... other dynamic parameters
} xrsr_session_config_update_t;
```

### Runtime Configuration Application
```c
void xrsv_ws_nextgen_msg_init(xrsv_ws_nextgen_obj_t *obj, uint8_t **buffer, uint32_t *length) {
    json_t *obj_init = obj->obj_init;
    int rc;
    
    // Update timestamp
    rc = json_object_set_new_nocheck(obj_init, XRSV_WS_NEXTGEN_JSON_KEY_CREATED, 
                                    json_integer(xrsv_ws_nextgen_time_get()));
    
    // Apply dynamic configuration updates if required
    if((obj->session_config_update != NULL) && 
       (obj->session_config_update->update_required == true)) {
        
        XLOGD_INFO("Updating dynamic_gain to <%f>", obj->session_config_update->dynamic_gain);
        rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, 
                                        XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_DYNAMIC_GAIN, 
                                        json_real(obj->session_config_update->dynamic_gain));
    }
    
    if(rc != 0) {
        XLOGD_ERROR("object set failed");
    }
    
    *buffer = (uint8_t *)json_dumps(obj_init, JSON_COMPACT);
    *length = (*buffer != NULL) ? strlen((const char *)(*buffer)) : 0;
}
```

### Session Configuration Integration
```c
bool xrsv_ws_nextgen_handler_ws_connected(void *data, const uuid_t uuid, 
                                        xrsr_handler_send_t send, void *param, 
                                        rdkx_timestamp_t *timestamp, 
                                        xrsr_session_config_update_t *session_config_update) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    // Store session configuration update mechanism
    obj->send = send;
    obj->param = param;
    obj->session_config_update = session_config_update;
    
    // Generate initialization message with current configuration
    uint8_t *buffer = NULL;
    uint32_t length = 0;
    xrsv_ws_nextgen_msg_init(obj, &buffer, &length);
    
    // Send configuration message
    xrsr_result_t result = (*send)(param, buffer, length);
    free(buffer);
    
    return (result == XRSR_RESULT_SUCCESS);
}
```

## Configuration Validation and Error Handling

### Object Validation
```c
bool xrsv_http_object_is_valid(xrsv_http_obj_t *obj) {
    return (obj != NULL && obj->identifier == XRSV_HTTP_IDENTIFIER);
}

bool xrsv_ws_nextgen_object_is_valid(xrsv_ws_nextgen_obj_t *obj) {
    return (obj != NULL && obj->identifier == XRSV_WS_NEXTGEN_IDENTIFIER);
}
```

### Parameter Validation Patterns
```c
// HTTP Update Pattern
bool xrsv_http_update_device_id(xrsv_http_object_t object, const char *device_id) {
    xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
    
    // Object validation
    if(!xrsv_http_object_is_valid(obj)) {
        XLOGD_ERROR("invalid object");
        return(false);
    }
    
    // Parameter bounds checking
    int rc = snprintf(obj->query_element_device_id, 
                     sizeof(obj->query_element_device_id), 
                     "xboDeviceId=%s", device_id);
    
    // Overflow detection
    if(rc >= sizeof(obj->query_element_device_id)) {
        XLOGD_WARN("truncated device id <%d>", rc);
        return(false);
    }
    
    return(true);
}
```

### JSON Configuration Validation
```c
// WebSocket JSON Update Pattern
bool xrsv_ws_nextgen_update_json(json_t *obj, const char *key, json_t *value) {
    // Null parameter checking
    if(obj == NULL || key == NULL || value == NULL) {
        XLOGD_ERROR("invalid params");
        return(false);
    }
    
    // JSON operation validation
    int rc = json_object_set_new_nocheck(obj, key, value);
    if(rc != 0) {
        XLOGD_ERROR("object set failed");
        return(false);
    }
    
    return(true);
}
```

## Configuration Lifecycle Management

### Initialization Phase
1. **Parameter Structure Setup**: Application provides initial configuration
2. **Object Creation**: XRSV objects created with configuration validation
3. **JSON Template Generation**: WebSocket implementations build JSON templates
4. **Query Parameter Formatting**: HTTP implementations format URL parameters

### Runtime Phase
1. **Dynamic Updates**: Configuration parameters updated via update functions
2. **Session Configuration**: Per-session dynamic configuration via XRSR integration
3. **JSON Template Updates**: WebSocket JSON objects updated in-place
4. **Query Parameter Regeneration**: HTTP query strings rebuilt as needed

### Cleanup Phase
1. **JSON Object Cleanup**: Reference counting for JSON objects
2. **Buffer Management**: Static buffers automatically released
3. **Session State Cleanup**: Dynamic configuration state reset between sessions

## Security and Privacy Features

### PII Masking Configuration
```c
typedef struct {
    // ... other fields
    bool mask_pii;  ///< Controls PII masking in logs and debug output
    // ... other fields  
} xrsv_http_params_t, xrsv_ws_nextgen_params_t;
```

**Implementation**: 
```c
// Debug output with conditional PII masking
XLOGD_DEBUG("obj \n<%s>", (str == NULL) ? "NULL" : obj->mask_pii ? "***" : str);
```

### Test Configuration Support
```c
typedef struct {
    // ... other fields
    bool test_flag;  ///< Indicates testing environment
    // ... other fields
} xrsv_http_params_t, xrsv_ws_nextgen_params_t;
```

### WUW Verification Bypass (WebSocket NextGen)
```c
typedef struct {
    // ... other fields
    bool bypass_wuw_verify_success; ///< Force WUW verification success for testing
    bool bypass_wuw_verify_failure; ///< Force WUW verification failure for testing  
    // ... other fields
} xrsv_ws_nextgen_params_t;
```

## Memory Management Patterns

### Static Buffer Management
```c
// HTTP Implementation - Fixed Size Query Buffers
typedef struct {
    char query_element_device_id[64];
    char query_element_receiver_id[64];
    char query_element_partner_id[64];
    char query_element_experience[64];
    // ... other buffers
} xrsv_http_obj_t;
```

### Dynamic JSON Management
```c
// WebSocket Implementation - Reference Counted JSON Objects
typedef struct {
    json_t *obj_init;                // Main initialization object
    json_t *obj_init_payload;        // Payload wrapper
    json_t *obj_init_stb;            // STB-specific configuration
    json_t *obj_init_stb_audio;      // Audio configuration
    // ... other JSON objects with automatic reference management
} xrsv_ws_nextgen_obj_t;
```

### Resource Cleanup
```c
void xrsv_ws_nextgen_destroy_object(xrsv_ws_nextgen_obj_t *obj) {
    // JSON object cleanup with reference counting
    if(obj->obj_init != NULL) {
        json_decref(obj->obj_init);
        obj->obj_init = NULL;
    }
    // ... cleanup other JSON objects
    
    // Clear string buffers
    obj->query_element_device_id[0] = '\0';
    obj->query_element_trx[0] = '\0';
    
    free(obj);
}
```

## Performance Characteristics

### Configuration Update Performance

#### HTTP Implementation
- **Query Parameter Updates**: O(1) string formatting with fixed buffers
- **Memory Overhead**: Minimal - fixed-size character arrays
- **Thread Safety**: Object-level validation provides thread awareness

#### WebSocket NextGen Implementation  
- **JSON Updates**: O(1) hash table operations for JSON object updates
- **Template Efficiency**: Pre-built JSON templates minimize runtime overhead
- **Memory Overhead**: Higher due to JSON object trees, offset by reference counting

### Session Configuration Performance
- **Dynamic Updates**: Lazy evaluation - only applied when session messages generated
- **Validation Overhead**: Minimal - simple boolean and numeric checks
- **Integration Cost**: Single function call for configuration application

## Integration with XRSR Layer

### Configuration Bridge
XRSV configuration integrates with XRSR through:

1. **Session Config Structures**: XRSR provides session-level configuration updates
2. **Handler Registration**: XRSV handlers receive configuration through XRSR callbacks
3. **Protocol Abstraction**: XRSV translates generic configuration to protocol-specific formats

### Configuration Flow
```
Application Layer
       ↓ (Initial Configuration)
XRSV Configuration Management
       ↓ (Protocol-Specific Configuration)
XRSR Protocol Layer
       ↓ (Session Configuration Updates)
XRSV Dynamic Configuration
       ↓ (Protocol Messages)
Voice Service Endpoint
```

## Best Practices and Usage Guidelines

### Configuration Design Patterns

#### Initialization Best Practices
```c
// Recommended initialization pattern
xrsv_ws_nextgen_params_t params = {
    .device_id = device_identifier,
    .account_id = user_account,
    .partner_id = network_partner,
    .experience = "voice-remote-1.0",
    .audio_profile = "near-field",
    .language = "en-US",
    .test_flag = false,
    .mask_pii = true,  // Enable PII protection
    .user_data = application_context
};

xrsv_ws_nextgen_object_t voice_service = xrsv_ws_nextgen_create(&params);
```

#### Runtime Update Patterns
```c
// Safe configuration updates
if(xrsv_ws_nextgen_update_language(voice_service, "es-ES")) {
    XLOGD_INFO("Language updated successfully");
} else {
    XLOGD_ERROR("Language update failed");
}

// Batch updates for efficiency
xrsv_ws_nextgen_update_device_id(voice_service, new_device_id);
xrsv_ws_nextgen_update_account_id(voice_service, new_account_id);
xrsv_ws_nextgen_update_partner_id(voice_service, new_partner_id);
```

### Error Handling Guidelines
1. **Always Check Return Values**: Configuration update functions return success/failure
2. **Validate Objects**: Use object validation before configuration operations
3. **Handle Truncation**: Monitor warnings for oversized configuration parameters
4. **Graceful Degradation**: Provide fallback configurations for failed updates

### Security Considerations  
1. **Enable PII Masking**: Set `mask_pii = true` in production environments
2. **Validate External Input**: Sanitize configuration parameters from external sources
3. **Limit Test Features**: Disable test flags and bypass options in production
4. **Buffer Bounds**: Monitor buffer usage for potential overflow conditions

### Performance Optimization
1. **Batch Updates**: Group configuration changes to minimize JSON regeneration
2. **Static Configuration**: Use initialization parameters for unchanging values
3. **Session Optimization**: Leverage dynamic configuration for per-session changes
4. **Memory Efficiency**: Prefer HTTP implementation for simple use cases

The XRSV configuration management system provides a robust, flexible foundation for voice service configuration across protocol implementations while maintaining performance, security, and ease of use for applications integrating with the XR Voice SDK.