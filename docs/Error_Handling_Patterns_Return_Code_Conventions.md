# Error Handling Patterns and Return Code Conventions

## Overview

This document provides comprehensive documentation of error handling patterns and return code conventions used throughout the XR Voice SDK. The SDK implements a consistent, multi-layered error handling architecture that enables robust error detection, propagation, and recovery across all components and APIs.

## Error Handling Architecture

### Hierarchical Error Model

The XR Voice SDK employs a hierarchical error handling model where errors are classified, propagated, and handled at multiple levels:

```
┌─ Application Layer Error Handling ────────────────────────┐
│  • High-level error recovery and user notification        │
│  • Application-specific error handling policies           │
│  • Error logging and analytics integration               │
└─────────────────┬──────────────────────────────────────────┘
                  │
┌─ SDK Layer Error Handling ─────────────────────────────────┐
│  • Component error coordination and recovery              │
│  • Cross-component error propagation                     │
│  • Resource cleanup and state restoration                │
└─────────────────┬──────────────────────────────────────────┘
                  │
┌─ Component Layer Error Handling ──────────────────────────┐
│  • Component-specific error detection and handling       │
│  • Internal error recovery mechanisms                    │
│  • Error state management and cleanup                    │
└─────────────────┬──────────────────────────────────────────┘
                  │
┌─ System Layer Error Handling ─────────────────────────────┐
│  • Operating system error handling                       │
│  • Hardware error detection and recovery                 │
│  • Low-level resource error management                   │
└────────────────────────────────────────────────────────────┘
```

## Return Code Conventions

### Primary SDK Return Code System

#### VSDK Return Codes
Located in [`xr_voice_sdk.h`](../src/xr_voice_sdk.h):

```c
typedef enum {
    VSDK_RESULT_OK                    = 0,   // Success
    VSDK_RESULT_ERROR_PARAMS          = 1,   // Invalid parameters
    VSDK_RESULT_ERROR_INVALID_STATE   = 2,   // Invalid state for operation
    VSDK_RESULT_ERROR_MEMORY          = 3,   // Memory allocation failure
    VSDK_RESULT_ERROR_TIMEOUT         = 4,   // Operation timeout
    VSDK_RESULT_ERROR_NOT_SUPPORTED   = 5,   // Operation not supported
    VSDK_RESULT_ERROR_BUSY            = 6,   // Resource busy
    VSDK_RESULT_ERROR_OPEN            = 7,   // Open/initialization failure
    VSDK_RESULT_ERROR_CLOSE           = 8,   // Close/cleanup failure
    VSDK_RESULT_ERROR_SESSION         = 9,   // Session management error
    VSDK_RESULT_ERROR_AUDIO           = 10,  // Audio system error
    VSDK_RESULT_ERROR_NETWORK         = 11,  // Network communication error
    VSDK_RESULT_ERROR_SECURITY        = 12,  // Security/authentication error
    VSDK_RESULT_ERROR_CONFIG          = 13,  // Configuration error
    VSDK_RESULT_ERROR_INTERNAL        = 14   // Internal system error
} vsdk_result_t;
```

**Return Code Categories**:
- **Success (0)**: Operation completed successfully
- **Parameter Errors (1-2)**: Input validation and state errors
- **Resource Errors (3,6)**: Memory and resource availability errors
- **Operational Errors (4,5,7-8)**: Timeout, support, and lifecycle errors
- **Domain-Specific Errors (9-13)**: Component-specific error conditions
- **System Errors (14)**: Internal and unexpected error conditions

#### XRAudio Return Codes  
Located in [`xraudio.h`](../src/xr-audio/xraudio.h):

```c
typedef enum {
    XRAUDIO_RESULT_OK                     = 0,   // Success
    XRAUDIO_RESULT_ERROR_PARAMS           = 1,   // Invalid parameters
    XRAUDIO_RESULT_ERROR_INVALID_STATE    = 2,   // Invalid state for operation
    XRAUDIO_RESULT_ERROR_MEMORY           = 3,   // Memory allocation failure
    XRAUDIO_RESULT_ERROR_TIMEOUT          = 4,   // Operation timeout
    XRAUDIO_RESULT_ERROR_NOT_SUPPORTED    = 5,   // Operation not supported
    XRAUDIO_RESULT_ERROR_BUSY             = 6,   // Resource busy
    XRAUDIO_RESULT_ERROR_OPEN             = 7,   // Device/resource open failure
    XRAUDIO_RESULT_ERROR_CLOSE            = 8,   // Device/resource close failure
    XRAUDIO_RESULT_ERROR_DEVICE           = 9,   // Audio device error
    XRAUDIO_RESULT_ERROR_FORMAT           = 10,  // Audio format error
    XRAUDIO_RESULT_ERROR_STREAM           = 11,  // Audio stream error
    XRAUDIO_RESULT_ERROR_HAL              = 12,  // Hardware abstraction error
    XRAUDIO_RESULT_ERROR_CODEC            = 13,  // Audio codec error
    XRAUDIO_RESULT_ERROR_PROCESSING       = 14,  // Audio processing error
    XRAUDIO_RESULT_ERROR_INTERNAL         = 15   // Internal system error
} xraudio_result_t;
```

#### XRSR Return Codes
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h):

```c
typedef enum {
    XRSR_RESULT_OK                        = 0,   // Success
    XRSR_RESULT_ERROR_PARAMS              = 1,   // Invalid parameters
    XRSR_RESULT_ERROR_INVALID_STATE       = 2,   // Invalid state for operation
    XRSR_RESULT_ERROR_MEMORY              = 3,   // Memory allocation failure
    XRSR_RESULT_ERROR_TIMEOUT             = 4,   // Operation timeout
    XRSR_RESULT_ERROR_NOT_SUPPORTED       = 5,   // Operation not supported
    XRSR_RESULT_ERROR_BUSY                = 6,   // Resource busy
    XRSR_RESULT_ERROR_OPEN                = 7,   // Component open failure
    XRSR_RESULT_ERROR_CLOSE               = 8,   // Component close failure
    XRSR_RESULT_ERROR_SESSION             = 9,   // Session management error
    XRSR_RESULT_ERROR_PROTOCOL            = 10,  // Protocol error
    XRSR_RESULT_ERROR_NETWORK             = 11,  // Network communication error
    XRSR_RESULT_ERROR_AUTHENTICATION      = 12,  // Authentication error
    XRSR_RESULT_ERROR_SSL                 = 13,  // SSL/TLS error
    XRSR_RESULT_ERROR_CONNECTION          = 14,  // Connection error
    XRSR_RESULT_ERROR_RESPONSE            = 15,  // Server response error
    XRSR_RESULT_ERROR_INTERNAL            = 16   // Internal system error
} xrsr_result_t;
```

#### XRSV Return Codes
Located in [`xrsv.h`](../src/xr-speech-vrex/xrsv.h):

```c
typedef enum {
    XRSV_RESULT_OK                        = 0,   // Success  
    XRSV_RESULT_ERROR_PARAMS              = 1,   // Invalid parameters
    XRSV_RESULT_ERROR_INVALID_STATE       = 2,   // Invalid state for operation
    XRSV_RESULT_ERROR_MEMORY              = 3,   // Memory allocation failure
    XRSV_RESULT_ERROR_TIMEOUT             = 4,   // Operation timeout
    XRSV_RESULT_ERROR_NOT_SUPPORTED       = 5,   // Operation not supported
    XRSV_RESULT_ERROR_BUSY                = 6,   // Resource busy
    XRSV_RESULT_ERROR_OPEN                = 7,   // Service open failure
    XRSV_RESULT_ERROR_CLOSE               = 8,   // Service close failure
    XRSV_RESULT_ERROR_SESSION             = 9,   // Voice session error
    XRSV_RESULT_ERROR_REQUEST             = 10,  // Voice request error
    XRSV_RESULT_ERROR_RESPONSE            = 11,  // Voice response error
    XRSV_RESULT_ERROR_SERVICE             = 12,  // Voice service error
    XRSV_RESULT_ERROR_INTERNAL            = 13   // Internal system error
} xrsv_result_t;
```

### Return Code Consistency Principles

#### Common Error Code Alignment
All SDK components follow consistent numbering for common error types:

```c
// Consistent error code mapping across components
#define SDK_ERROR_OK                0    // Universal success code
#define SDK_ERROR_PARAMS            1    // Parameter validation errors
#define SDK_ERROR_INVALID_STATE     2    // State management errors
#define SDK_ERROR_MEMORY            3    // Memory allocation errors  
#define SDK_ERROR_TIMEOUT           4    // Timeout conditions
#define SDK_ERROR_NOT_SUPPORTED     5    // Unsupported operations
#define SDK_ERROR_BUSY              6    // Resource busy conditions
#define SDK_ERROR_OPEN              7    // Initialization/open errors
#define SDK_ERROR_CLOSE             8    // Cleanup/close errors
```

**Component-Specific Error Ranges**:
- **Common Errors (0-8)**: Shared across all components
- **Component Errors (9-15)**: Component-specific error conditions
- **Extended Errors (16+)**: Component-specific extended error codes

## Error Detection Patterns

### Parameter Validation

#### Standard Parameter Validation Pattern
All SDK APIs follow a consistent parameter validation pattern:

```c
// Standard parameter validation implementation
xraudio_result_t xraudio_stream_open(xraudio_obj_t obj,
                                    xraudio_devices_input_t device,
                                    const xraudio_input_format_t *format,
                                    xraudio_resource_id_input_t resource_id) {
    // Step 1: Null pointer validation
    if(obj == NULL) {
        XLOGD_ERROR("XRAUDIO", "Invalid object parameter");
        return XRAUDIO_RESULT_ERROR_PARAMS;
    }
    
    if(format == NULL) {
        XLOGD_ERROR("XRAUDIO", "Invalid format parameter");
        return XRAUDIO_RESULT_ERROR_PARAMS;
    }
    
    // Step 2: Range validation
    if(device >= XRAUDIO_DEVICE_INPUT_COUNT) {
        XLOGD_ERROR("XRAUDIO", "Invalid device parameter: %d", device);
        return XRAUDIO_RESULT_ERROR_PARAMS;
    }
    
    if(resource_id >= XRAUDIO_RESOURCE_ID_INPUT_COUNT) {
        XLOGD_ERROR("XRAUDIO", "Invalid resource_id parameter: %d", resource_id);
        return XRAUDIO_RESULT_ERROR_PARAMS;
    }
    
    // Step 3: Format validation
    if(!xraudio_format_validate(format)) {
        XLOGD_ERROR("XRAUDIO", "Invalid audio format parameters");
        return XRAUDIO_RESULT_ERROR_PARAMS;
    }
    
    // Step 4: State validation
    xraudio_main_t *main = (xraudio_main_t *)obj;
    if(main->state != XRAUDIO_STATE_READY) {
        XLOGD_ERROR("XRAUDIO", "Invalid state for stream open: %s", 
                   xraudio_state_str(main->state));
        return XRAUDIO_RESULT_ERROR_INVALID_STATE;
    }
    
    // Continue with operation...
    return xraudio_stream_open_internal(main, device, format, resource_id);
}
```

#### Object Identifier Validation Pattern
```c
// Object identifier validation for type safety
bool xrsr_obj_validate(xrsr_obj_t obj) {
    if(obj == NULL) {
        return false;
    }
    
    xrsr_main_t *main = (xrsr_main_t *)obj;
    
    // Check object identifier for corruption detection
    if(main->identifier != XRSR_IDENTIFIER) {
        XLOGD_ERROR("XRSR", "Object identifier mismatch: expected 0x%08X, got 0x%08X",
                   XRSR_IDENTIFIER, main->identifier);
        return false;
    }
    
    return true;
}

// Usage in API functions  
xrsr_result_t xrsr_session_begin(xrsr_obj_t obj, const xrsr_session_config_t *config) {
    if(!xrsr_obj_validate(obj)) {
        return XRSR_RESULT_ERROR_PARAMS;
    }
    
    // Continue with validated object...
}
```

### State Validation Patterns

#### Component State Machine Validation
```c
// State transition validation
typedef struct {
    xraudio_state_t from_state;
    xraudio_state_t to_state;
    bool allowed;
    const char *operation;
} xraudio_state_transition_t;

static const xraudio_state_transition_t g_valid_transitions[] = {
    {XRAUDIO_STATE_IDLE,      XRAUDIO_STATE_READY,     true,  "initialize"},
    {XRAUDIO_STATE_READY,     XRAUDIO_STATE_STREAMING, true,  "start_stream"},
    {XRAUDIO_STATE_STREAMING, XRAUDIO_STATE_READY,     true,  "stop_stream"},
    {XRAUDIO_STATE_READY,     XRAUDIO_STATE_IDLE,      true,  "shutdown"},
    {XRAUDIO_STATE_ERROR,     XRAUDIO_STATE_IDLE,      true,  "reset"},
    // Invalid transitions return false by default
};

bool xraudio_state_transition_validate(xraudio_state_t current_state,
                                      xraudio_state_t target_state,
                                      const char **error_message) {
    for(int i = 0; i < ARRAY_SIZE(g_valid_transitions); i++) {
        if(g_valid_transitions[i].from_state == current_state &&
           g_valid_transitions[i].to_state == target_state) {
            return g_valid_transitions[i].allowed;
        }
    }
    
    *error_message = "Invalid state transition";
    return false;
}
```

### Resource Availability Validation

#### Resource Lock and Availability Checking
```c
// Resource availability validation pattern
xraudio_result_t xraudio_resource_acquire(xraudio_obj_t obj,
                                         xraudio_resource_id_input_t resource_id) {
    xraudio_main_t *main = (xraudio_main_t *)obj;
    
    // Check resource availability
    if(!xraudio_resource_is_available(main, resource_id)) {
        XLOGD_ERROR("XRAUDIO", "Resource %d is not available", resource_id);
        return XRAUDIO_RESULT_ERROR_BUSY;
    }
    
    // Attempt resource acquisition with timeout
    if(!xraudio_resource_lock_acquire(main, resource_id, XRAUDIO_RESOURCE_TIMEOUT_MS)) {
        XLOGD_ERROR("XRAUDIO", "Failed to acquire resource %d within timeout", resource_id);
        return XRAUDIO_RESULT_ERROR_TIMEOUT;
    }
    
    // Verify resource is properly acquired
    if(!xraudio_resource_verify_acquired(main, resource_id)) {
        XLOGD_ERROR("XRAUDIO", "Resource %d acquisition verification failed", resource_id);
        xraudio_resource_lock_release(main, resource_id);
        return XRAUDIO_RESULT_ERROR_INTERNAL;
    }
    
    return XRAUDIO_RESULT_OK;
}
```

## Error Propagation Mechanisms

### Component-to-Component Error Propagation

#### Error Event Propagation System
```c
// Error event structure for cross-component propagation
typedef struct {
    uint32_t            event_id;           // Unique error event identifier
    vsdk_component_t    source_component;   // Component that detected the error
    vsdk_error_level_t  error_level;       // Error severity level
    uint32_t            error_code;         // Component-specific error code
    char                error_message[256]; // Human-readable error description
    uint64_t            timestamp;          // Error occurrence timestamp
    void                *context_data;      // Additional error context
} vsdk_error_event_t;

// Error event callback registration
typedef void (*vsdk_error_callback_t)(const vsdk_error_event_t *error_event,
                                      void *user_data);

// Register for error event notifications
vsdk_result_t vsdk_error_callbacks_register(vsdk_obj_t obj,
                                           vsdk_error_callback_t callback,
                                           void *user_data) {
    vsdk_main_t *main = (vsdk_main_t *)obj;
    
    if(callback == NULL) {
        return VSDK_RESULT_ERROR_PARAMS;
    }
    
    // Add callback to notification list
    main->error_callbacks[main->error_callback_count].callback = callback;
    main->error_callbacks[main->error_callback_count].user_data = user_data;
    main->error_callback_count++;
    
    return VSDK_RESULT_OK;
}
```

#### Cross-Component Error Notification
```c
// Propagate error events to registered callbacks
void vsdk_error_event_notify(vsdk_main_t *main, const vsdk_error_event_t *error_event) {
    // Log error event
    XLOGD_ERROR("VSDK", "Error event from %s: [%d] %s",
               vsdk_component_name(error_event->source_component),
               error_event->error_code,
               error_event->error_message);
    
    // Notify registered callbacks
    for(int i = 0; i < main->error_callback_count; i++) {
        if(main->error_callbacks[i].callback != NULL) {
            main->error_callbacks[i].callback(error_event, 
                                             main->error_callbacks[i].user_data);
        }
    }
    
    // Apply automatic error recovery if enabled
    if(main->auto_recovery_enabled) {
        vsdk_error_recovery_attempt(main, error_event);
    }
}
```

### Error Context Preservation

#### Error Context Stack Implementation
```c
// Error context tracking for debugging
typedef struct {
    const char *function_name;
    const char *file_name;
    int line_number;
    uint32_t error_code;
    const char *error_description;
} vsdk_error_context_t;

typedef struct {
    vsdk_error_context_t contexts[VSDK_ERROR_CONTEXT_STACK_SIZE];
    int context_count;
    pthread_mutex_t mutex;
} vsdk_error_context_stack_t;

// Thread-local error context stacks
static __thread vsdk_error_context_stack_t g_error_context_stack;

// Push error context onto stack
void vsdk_error_context_push(const char *function, const char *file, int line,
                            uint32_t error_code, const char *description) {
    pthread_mutex_lock(&g_error_context_stack.mutex);
    
    if(g_error_context_stack.context_count < VSDK_ERROR_CONTEXT_STACK_SIZE) {
        vsdk_error_context_t *ctx = &g_error_context_stack.contexts[g_error_context_stack.context_count];
        ctx->function_name = function;
        ctx->file_name = file;
        ctx->line_number = line;
        ctx->error_code = error_code;
        ctx->error_description = description;
        g_error_context_stack.context_count++;
    }
    
    pthread_mutex_unlock(&g_error_context_stack.mutex);
}

// Error context macros for automatic context tracking
#define VSDK_ERROR_CONTEXT_PUSH(code, desc) \
    vsdk_error_context_push(__FUNCTION__, __FILE__, __LINE__, code, desc)

#define VSDK_RETURN_ERROR(result, desc) do { \
    VSDK_ERROR_CONTEXT_PUSH(result, desc); \
    return result; \
} while(0)
```

## Error Recovery Mechanisms

### Automatic Error Recovery

#### Error Recovery Strategy Framework
```c
// Error recovery strategy definition
typedef struct {
    vsdk_component_t component;           // Target component for recovery
    uint32_t error_code;                 // Error code to handle
    int max_retry_attempts;              // Maximum retry attempts
    uint32_t retry_delay_ms;             // Delay between retries
    bool (*recovery_function)(vsdk_main_t *main, const vsdk_error_event_t *error);
} vsdk_error_recovery_strategy_t;

// Predefined error recovery strategies
static const vsdk_error_recovery_strategy_t g_recovery_strategies[] = {
    // XRAudio device error recovery
    {
        .component = VSDK_COMPONENT_XRAUDIO,
        .error_code = XRAUDIO_RESULT_ERROR_DEVICE,
        .max_retry_attempts = 3,
        .retry_delay_ms = 1000,
        .recovery_function = vsdk_xraudio_device_recovery
    },
    
    // XRSR connection error recovery
    {
        .component = VSDK_COMPONENT_XRSR,
        .error_code = XRSR_RESULT_ERROR_CONNECTION,
        .max_retry_attempts = 5,
        .retry_delay_ms = 2000,
        .recovery_function = vsdk_xrsr_connection_recovery
    },
    
    // Memory allocation error recovery
    {
        .component = VSDK_COMPONENT_ALL,
        .error_code = VSDK_RESULT_ERROR_MEMORY,
        .max_retry_attempts = 2,
        .retry_delay_ms = 500,
        .recovery_function = vsdk_memory_recovery
    }
};

// Automatic error recovery execution
bool vsdk_error_recovery_attempt(vsdk_main_t *main, const vsdk_error_event_t *error_event) {
    for(int i = 0; i < ARRAY_SIZE(g_recovery_strategies); i++) {
        const vsdk_error_recovery_strategy_t *strategy = &g_recovery_strategies[i];
        
        // Check if strategy applies to this error
        if((strategy->component == error_event->source_component || 
            strategy->component == VSDK_COMPONENT_ALL) &&
           strategy->error_code == error_event->error_code) {
            
            XLOGD_INFO("VSDK", "Attempting automatic recovery for error %d from %s",
                      error_event->error_code,
                      vsdk_component_name(error_event->source_component));
            
            // Execute recovery strategy
            for(int retry = 0; retry < strategy->max_retry_attempts; retry++) {
                if(strategy->recovery_function(main, error_event)) {
                    XLOGD_INFO("VSDK", "Automatic recovery successful after %d attempts", 
                              retry + 1);
                    return true;
                }
                
                // Wait before retry
                if(retry < strategy->max_retry_attempts - 1) {
                    usleep(strategy->retry_delay_ms * 1000);
                }
            }
            
            XLOGD_WARN("VSDK", "Automatic recovery failed after %d attempts", 
                      strategy->max_retry_attempts);
            return false;
        }
    }
    
    XLOGD_DEBUG("VSDK", "No recovery strategy found for error %d from %s",
               error_event->error_code,
               vsdk_component_name(error_event->source_component));
    return false;
}
```

### Component-Specific Recovery Functions

#### XRAudio Device Recovery
```c
// XRAudio device error recovery implementation
bool vsdk_xraudio_device_recovery(vsdk_main_t *main, const vsdk_error_event_t *error_event) {
    XLOGD_INFO("VSDK", "Attempting XRAudio device recovery");
    
    // Step 1: Stop any active audio operations
    xraudio_result_t result = xraudio_stop_all(main->xraudio_obj);
    if(result != XRAUDIO_RESULT_OK) {
        XLOGD_WARN("VSDK", "Failed to stop audio operations during recovery");
    }
    
    // Step 2: Reset audio device
    result = xraudio_device_reset(main->xraudio_obj);
    if(result != XRAUDIO_RESULT_OK) {
        XLOGD_ERROR("VSDK", "Audio device reset failed during recovery");
        return false;
    }
    
    // Step 3: Reinitialize with current configuration
    result = xraudio_reinitialize(main->xraudio_obj, &main->config.xraudio);
    if(result != XRAUDIO_RESULT_OK) {
        XLOGD_ERROR("VSDK", "Audio reinitialization failed during recovery");
        return false;
    }
    
    // Step 4: Verify device functionality
    if(!xraudio_health_check(main->xraudio_obj)) {
        XLOGD_ERROR("VSDK", "Audio health check failed after recovery");
        return false;
    }
    
    XLOGD_INFO("VSDK", "XRAudio device recovery completed successfully");
    return true;
}
```

#### XRSR Connection Recovery
```c
// XRSR connection error recovery implementation
bool vsdk_xrsr_connection_recovery(vsdk_main_t *main, const vsdk_error_event_t *error_event) {
    XLOGD_INFO("VSDK", "Attempting XRSR connection recovery");
    
    // Step 1: Terminate failed connections
    xrsr_result_t result = xrsr_connections_terminate_all(main->xrsr_obj);
    if(result != XRSR_RESULT_OK) {
        XLOGD_WARN("VSDK", "Failed to terminate connections during recovery");
    }
    
    // Step 2: Clear connection state
    result = xrsr_connection_state_reset(main->xrsr_obj);
    if(result != XRSR_RESULT_OK) {
        XLOGD_ERROR("VSDK", "Connection state reset failed during recovery");
        return false;
    }
    
    // Step 3: Test network connectivity
    if(!vsdk_network_connectivity_test(main)) {
        XLOGD_ERROR("VSDK", "Network connectivity test failed during recovery");
        return false;
    }
    
    // Step 4: Reinitialize protocols with backoff
    result = xrsr_protocols_reinitialize_with_backoff(main->xrsr_obj);
    if(result != XRSR_RESULT_OK) {
        XLOGD_ERROR("VSDK", "Protocol reinitialization failed during recovery");
        return false;
    }
    
    XLOGD_INFO("VSDK", "XRSR connection recovery completed successfully");
    return true;
}
```

## Error Logging and Diagnostics

### Structured Error Logging

#### Error Log Entry Format
```c
// Structured error log entry
typedef struct {
    uint64_t timestamp_us;                // Microsecond timestamp
    vsdk_component_t component;           // Component that logged the error
    vsdk_error_level_t level;            // Error severity level
    uint32_t error_code;                 // Component-specific error code
    uint32_t thread_id;                  // Thread ID where error occurred
    char function_name[64];              // Function name where error occurred
    char file_name[128];                 // Source file name
    int line_number;                     // Source line number
    char error_message[512];             // Detailed error description
    char context_data[256];              // Additional context information
} vsdk_error_log_entry_t;

// Error logging with context
void vsdk_error_log_structured(vsdk_component_t component,
                              vsdk_error_level_t level,
                              uint32_t error_code,
                              const char *function,
                              const char *file,
                              int line,
                              const char *format, ...) {
    vsdk_error_log_entry_t entry;
    
    // Fill basic entry information
    entry.timestamp_us = xr_timestamp_get_us();
    entry.component = component;
    entry.level = level;
    entry.error_code = error_code;
    entry.thread_id = pthread_self();
    strncpy(entry.function_name, function, sizeof(entry.function_name) - 1);
    strncpy(entry.file_name, file, sizeof(entry.file_name) - 1);
    entry.line_number = line;
    
    // Format error message
    va_list args;
    va_start(args, format);
    vsnprintf(entry.error_message, sizeof(entry.error_message), format, args);
    va_end(args);
    
    // Add error context from context stack
    vsdk_error_context_format(entry.context_data, sizeof(entry.context_data));
    
    // Write to error log
    vsdk_error_log_write(&entry);
    
    // Trigger error event notification
    vsdk_error_event_t error_event = {
        .event_id = vsdk_error_event_id_generate(),
        .source_component = component,
        .error_level = level,
        .error_code = error_code,
        .timestamp = entry.timestamp_us
    };
    strncpy(error_event.error_message, entry.error_message, 
           sizeof(error_event.error_message) - 1);
    
    vsdk_error_event_notify_async(&error_event);
}
```

#### Error Logging Macros
```c
// Convenient error logging macros
#define VSDK_LOG_ERROR(component, code, ...) \
    vsdk_error_log_structured(component, VSDK_ERROR_LEVEL_ERROR, code, \
                            __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define VSDK_LOG_WARN(component, code, ...) \
    vsdk_error_log_structured(component, VSDK_ERROR_LEVEL_WARN, code, \
                            __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define XRAUDIO_LOG_ERROR(code, ...) \
    VSDK_LOG_ERROR(VSDK_COMPONENT_XRAUDIO, code, __VA_ARGS__)

#define XRSR_LOG_ERROR(code, ...) \
    VSDK_LOG_ERROR(VSDK_COMPONENT_XRSR, code, __VA_ARGS__)
```

### Error Analysis and Diagnostics

#### Error Pattern Detection
```c
// Error pattern analysis for proactive error detection
typedef struct {
    uint32_t error_code;
    uint32_t occurrence_count;
    uint64_t first_occurrence;
    uint64_t last_occurrence;
    uint32_t frequency_threshold;      // Errors per time window
    uint32_t time_window_ms;          // Time window for frequency analysis
    bool pattern_detected;
} vsdk_error_pattern_t;

// Error pattern tracking and analysis
void vsdk_error_pattern_analyze(uint32_t error_code, uint64_t timestamp) {
    static vsdk_error_pattern_t patterns[VSDK_MAX_ERROR_PATTERNS];
    static int pattern_count = 0;
    
    // Find existing pattern entry
    vsdk_error_pattern_t *pattern = NULL;
    for(int i = 0; i < pattern_count; i++) {
        if(patterns[i].error_code == error_code) {
            pattern = &patterns[i];
            break;
        }
    }
    
    // Create new pattern entry if needed
    if(pattern == NULL && pattern_count < VSDK_MAX_ERROR_PATTERNS) {
        pattern = &patterns[pattern_count++];
        pattern->error_code = error_code;
        pattern->occurrence_count = 0;
        pattern->first_occurrence = timestamp;
        pattern->frequency_threshold = 5;  // Default threshold
        pattern->time_window_ms = 60000;   // 1 minute window
        pattern->pattern_detected = false;
    }
    
    if(pattern != NULL) {
        pattern->occurrence_count++;
        pattern->last_occurrence = timestamp;
        
        // Check for error pattern (frequency analysis)
        uint64_t time_window_start = timestamp - (pattern->time_window_ms * 1000);
        if(pattern->first_occurrence > time_window_start &&
           pattern->occurrence_count >= pattern->frequency_threshold) {
            
            if(!pattern->pattern_detected) {
                XLOGD_WARN("VSDK", "Error pattern detected: code %d occurred %d times in %d ms",
                          error_code, pattern->occurrence_count, pattern->time_window_ms);
                pattern->pattern_detected = true;
                
                // Trigger pattern-based recovery or escalation
                vsdk_error_pattern_response(pattern);
            }
        }
    }
}
```

## Error Handling Best Practices

### 1. **Consistent Return Code Usage**
```c
// Always check return codes and handle errors appropriately
xraudio_result_t result = xraudio_stream_open(audio_obj, device, &format, resource_id);
if(result != XRAUDIO_RESULT_OK) {
    XRAUDIO_LOG_ERROR(result, "Failed to open audio stream: device=%d, resource=%d", 
                     device, resource_id);
    return vsdk_result_from_xraudio_result(result);
}
```

### 2. **Resource Cleanup in Error Paths**
```c
// Always clean up resources in error handling paths
xrsr_result_t xrsr_session_create_with_cleanup(xrsr_obj_t obj, 
                                              const xrsr_session_config_t *config,
                                              xrsr_session_t **session) {
    // Allocate session object
    *session = calloc(1, sizeof(xrsr_session_t));
    if(*session == NULL) {
        return XRSR_RESULT_ERROR_MEMORY;
    }
    
    // Initialize session components
    xrsr_result_t result = xrsr_session_msgq_create(*session);
    if(result != XRSR_RESULT_OK) {
        goto error_cleanup_session;
    }
    
    result = xrsr_session_protocols_init(*session, config);
    if(result != XRSR_RESULT_OK) {
        goto error_cleanup_msgq;
    }
    
    return XRSR_RESULT_OK;
    
    // Error cleanup in reverse order
error_cleanup_msgq:
    xrsr_session_msgq_destroy(*session);
error_cleanup_session:
    free(*session);
    *session = NULL;
    return result;
}
```

### 3. **Error Context Preservation**
```c
// Preserve error context through call chains
xrsr_result_t xrsr_high_level_operation(xrsr_obj_t obj) {
    xrsr_result_t result = xrsr_mid_level_operation(obj);
    if(result != XRSR_RESULT_OK) {
        VSDK_ERROR_CONTEXT_PUSH(result, "High-level operation failed");
        return result;
    }
    return XRSR_RESULT_OK;
}

xrsr_result_t xrsr_mid_level_operation(xrsr_obj_t obj) {
    xrsr_result_t result = xrsr_low_level_operation(obj);
    if(result != XRSR_RESULT_OK) {
        VSDK_ERROR_CONTEXT_PUSH(result, "Mid-level operation failed");
        return result;
    }
    return XRSR_RESULT_OK;
}
```

### 4. **Graceful Degradation**
```c
// Implement graceful degradation for non-critical errors
vsdk_result_t vsdk_initialize_with_degradation(vsdk_obj_t *obj, 
                                              const vsdk_config_t *config) {
    // Critical components must succeed
    vsdk_result_t result = vsdk_core_components_init();
    if(result != VSDK_RESULT_OK) {
        return result;  // Cannot continue without core components
    }
    
    // Optional components can fail gracefully
    result = vsdk_optional_components_init();
    if(result != VSDK_RESULT_OK) {
        XLOGD_WARN("VSDK", "Optional components initialization failed, continuing with reduced functionality");
        // Continue with reduced functionality
    }
    
    return VSDK_RESULT_OK;
}
```

### 5. **Error Event Handling**
```c
// Register for error events to implement application-specific error handling
void application_error_callback(const vsdk_error_event_t *error_event, void *user_data) {
    application_context_t *app_ctx = (application_context_t *)user_data;
    
    switch(error_event->error_level) {
        case VSDK_ERROR_LEVEL_FATAL:
            // Initiate application shutdown
            application_shutdown_graceful(app_ctx);
            break;
            
        case VSDK_ERROR_LEVEL_ERROR:
            // Attempt application-level recovery
            application_error_recovery(app_ctx, error_event);
            break;
            
        case VSDK_ERROR_LEVEL_WARN:
            // Log warning and continue
            application_log_warning(app_ctx, error_event);
            break;
    }
}

// Register callback during application initialization
vsdk_error_callbacks_register(sdk_obj, application_error_callback, app_context);
```

## Conclusion

The XR Voice SDK implements a comprehensive error handling architecture that provides:

- **Consistent Return Codes** across all components with aligned error numbering
- **Structured Error Detection** with parameter, state, and resource validation
- **Cross-Component Error Propagation** through event-based notification systems
- **Automatic Error Recovery** with configurable recovery strategies  
- **Comprehensive Error Logging** with structured logging and context preservation
- **Error Pattern Analysis** for proactive error detection and response
- **Best Practice Guidelines** for robust error handling in applications

This architecture enables applications to implement sophisticated error handling strategies while the SDK provides automatic recovery capabilities for common error scenarios, resulting in more robust and reliable voice interaction systems.