# XR Voice SDK - Comprehensive API Interface Documentation

## Overview

The XR Voice SDK provides a comprehensive C API for voice interaction in XR applications. The public interface consists of three main API modules:

1. **Core SDK API** (`xr_voice_sdk.h`) - SDK lifecycle, logging, and system management
2. **Speech Router API** (`xrsr.h`) - Multi-protocol speech routing and session management  
3. **Voice Recognition API** (`xrsv.h`) - Voice recognition results and processing

## Core SDK API (xr_voice_sdk.h)

### Include Dependencies
```c
#include <xr_voice_sdk.h>  // Core SDK interface
#include <xrsr.h>          // Speech router (automatically included) 
#include <xrsv.h>          // Voice recognition (automatically included)
#include <rdkx_logger.h>   // Logging system (automatically included)
```

### Constants and Definitions

#### Version Management
```c
#define VSDK_VERSION_QTY_MAX (2)  ///< Maximum version info structures
```

### Data Structures

#### Version Information Structure
```c
typedef struct {
   const char *name;      ///< Component name (e.g., "xr-voice-sdk")
   const char *version;   ///< Version string (e.g., "1.0.0")
   const char *branch;    ///< Git branch name
   const char *commit_id; ///< Git commit identifier
} vsdk_version_info_t;
```

**Usage Guidelines:**
- Used with `vsdk_version()` to retrieve component version information
- Applications should allocate array of `VSDK_VERSION_QTY_MAX` structures
- Contains both compile-time and runtime version details

#### Thread Poll Callback
```c
typedef void (*vsdk_thread_poll_func_t)(void *data);
```

**Callback Contract:**
- Called when all SDK threads are confirmed responsive
- `data` parameter passes application context through `vsdk_thread_poll()`
- Should return quickly to avoid blocking thread monitoring

### Core Functions

#### SDK Lifecycle Management

##### vsdk_init()
```c
int vsdk_init(bool ansi_color, const char *filename, uint32_t file_size_max);
```

**Purpose:** Initialize the XR Voice SDK with file-based logging

**Parameters:**
- `ansi_color` - Enable ANSI color codes in log output for terminal display
- `filename` - Log file path (NULL for stdout only)
- `file_size_max` - Maximum log file size in bytes (0 for unlimited)

**Return Values:**
- `0` - Success, SDK initialized and ready for use
- Non-zero - Initialization failure, SDK not operational

**Usage Notes:**
- Must be called before any other SDK functions
- Creates logging infrastructure and initializes all components
- Loads plugins and establishes component communication
- Safe to call multiple times (subsequent calls ignored)

##### vsdk_init_user_print()
```c
int vsdk_init_user_print(xlog_print_t print, xlog_print_t print_safe, 
                         bool ansi_color, const char *filename, 
                         uint32_t file_size_max);
```

**Purpose:** Initialize SDK with custom logging functions

**Parameters:**
- `print` - Custom print function for normal logging
- `print_safe` - Signal-safe print function for interrupt contexts
- `ansi_color` - Enable ANSI color codes in log output
- `filename` - Log file path (NULL for custom handlers only)
- `file_size_max` - Maximum log file size in bytes

**Return Values:**
- `0` - Success
- Non-zero - Initialization failure

**Integration Pattern:**
```c
// Custom logging integration example
void my_log_handler(const char *msg) {
    // Forward to application logging system
    app_logger_write(LOG_INFO, msg);
}

void my_safe_log_handler(const char *msg) {
    // Signal-safe logging (no malloc, minimal system calls)
    write(STDERR_FILENO, msg, strlen(msg));
}

int result = vsdk_init_user_print(my_log_handler, my_safe_log_handler, 
                                  false, NULL, 0);
```

##### vsdk_term()
```c
void vsdk_term(void);
```

**Purpose:** Terminate SDK and release all resources

**Behavior:**
- Stops all background threads gracefully
- Closes network connections and audio devices
- Frees allocated memory and system resources
- Unloads plugins and cleans up component state
- Safe to call multiple times or without prior initialization

#### Version Information

##### vsdk_version()
```c
void vsdk_version(vsdk_version_info_t *version_info, uint32_t *qty);
```

**Purpose:** Retrieve detailed version information for SDK components

**Parameters:**
- `version_info` - Pre-allocated array of version structures
- `qty` - [IN] Array size, [OUT] number of entries populated

**Usage Pattern:**
```c
vsdk_version_info_t versions[VSDK_VERSION_QTY_MAX];
uint32_t count = VSDK_VERSION_QTY_MAX;

vsdk_version(versions, &count);

for(uint32_t i = 0; i < count; i++) {
    printf("Component: %s, Version: %s, Branch: %s, Commit: %s\n",
           versions[i].name, versions[i].version, 
           versions[i].branch, versions[i].commit_id);
}
```

#### Logging Control

##### vsdk_log_level_get()
```c
xlog_level_t vsdk_log_level_get(xlog_module_id_t id);
```

**Purpose:** Retrieve current log level for specific module

**Parameters:**
- `id` - Module identifier (see `xlog_module_id_t` enum)

**Return Values:**
- Current log level for specified module
- `XLOG_LEVEL_ERROR`, `XLOG_LEVEL_WARN`, `XLOG_LEVEL_INFO`, `XLOG_LEVEL_DEBUG`

##### vsdk_log_level_set()
```c
void vsdk_log_level_set(xlog_module_id_t id, xlog_level_t level);
```

**Purpose:** Set log level for specific module

**Parameters:**
- `id` - Module identifier
- `level` - Desired log level

**Module Examples:**
- `XLOG_MODULE_ID_VSDK` - Core SDK logging
- `XLOG_MODULE_ID_XRSR` - Speech router logging
- `XLOG_MODULE_ID_XRAUDIO` - Audio processing logging

##### vsdk_log_level_set_all()
```c
void vsdk_log_level_set_all(xlog_level_t level);
```

**Purpose:** Set uniform log level across all SDK modules

**Parameters:**
- `level` - Log level to apply to all components

**Usage Example:**
```c
// Enable debug logging for all components
vsdk_log_level_set_all(XLOG_LEVEL_DEBUG);

// Production: only show errors and warnings  
vsdk_log_level_set_all(XLOG_LEVEL_WARN);

// Fine-tune specific component logging
vsdk_log_level_set(XLOG_MODULE_ID_XRAUDIO, XLOG_LEVEL_DEBUG);
```

#### System Monitoring

##### vsdk_thread_poll()
```c
void vsdk_thread_poll(vsdk_thread_poll_func_t func, void *data);
```

**Purpose:** Monitor SDK thread health and responsiveness

**Parameters:**
- `func` - Callback function invoked when threads are responsive
- `data` - Application context passed to callback

**Monitoring Pattern:**
```c
void thread_health_callback(void *data) {
    AppContext *context = (AppContext*)data;
    context->sdk_health_ok = true;
    log_info("SDK threads healthy");
}

// Start periodic health monitoring
vsdk_thread_poll(thread_health_callback, &app_context);
```

## Speech Router API (xrsr.h)

### Key Constants
```c
#define XRSR_SAT_TOKEN_LEN_MAX             (5120)  ///< Max SAT token length
#define XRSR_USER_AGENT_LEN_MAX            (256)   ///< Max user agent string
#define XRSR_SESSION_IP_LEN_MAX            (48)    ///< Max IP address string
#define XRSR_DST_QTY_MAX                   (1)     ///< Max destinations per source
#define XRSR_SESSION_BY_TEXT_MAX_LENGTH    (128)   ///< Max text session length
#define XRSR_SESSION_AUDIO_FILE_MAX_LENGTH (256)   ///< Max audio file path length
#define XRSR_QUERY_STRING_QTY_MAX          (24)    ///< Max query strings supported
```

### Speech Source Types
```c
typedef enum {
   XRSR_SRC_RCU_PTT         = 0, ///< Push-to-talk remote control
   XRSR_SRC_RCU_FF          = 1, ///< Far-field remote control  
   XRSR_SRC_MICROPHONE      = 2, ///< Local microphone
   XRSR_SRC_MICROPHONE_TAP  = 3, ///< Local microphone tap
   XRSR_SRC_INVALID         = 4  ///< Invalid source type
} xrsr_src_t;
```

### Result Codes
```c
typedef enum {
   XRSR_RESULT_SUCCESS = 0, ///< Operation successful
   XRSR_RESULT_ERROR   = 1, ///< Operation failed
   XRSR_RESULT_INVALID = 2, ///< Invalid return code
} xrsr_result_t;
```

### Session Request Types
```c
typedef enum {
   XRSR_SESSION_REQUEST_TYPE_TEXT        = 0, ///< Text-only session
   XRSR_SESSION_REQUEST_TYPE_AUDIO_FILE  = 1, ///< Audio file input
   XRSR_SESSION_REQUEST_TYPE_AUDIO_FD    = 2, ///< Audio file descriptor
   XRSR_SESSION_REQUEST_TYPE_AUDIO_MIC   = 3, ///< Microphone input
   XRSR_SESSION_REQUEST_TYPE_INVALID     = 4, ///< Invalid type
} xrsr_session_request_type_t;
```

### Session End Reasons
```c
typedef enum {
   XRSR_SESSION_END_REASON_EOS                = 0,  ///< End of speech detected
   XRSR_SESSION_END_REASON_EOT                = 1,  ///< End of text session
   XRSR_SESSION_END_REASON_DISCONNECT_REMOTE  = 2,  ///< Server ended session
   // ... additional end reasons
} xrsr_session_end_reason_t;
```

## Voice Recognition API (xrsv.h)

### Result Types
```c
typedef enum {
   XRSV_RESULT_SUCCESS = 0, ///< Operation completed successfully
   XRSV_RESULT_ERROR   = 1, ///< Operation failed
   XRSV_RESULT_INVALID = 2, ///< Invalid return code
} xrsv_result_t;
```

### Stream End Results
```c
typedef enum {
   XRSV_STREAM_END_END_OF_SPEECH    = 0, ///< End of speech detected
   XRSV_STREAM_END_END_OF_STREAM    = 1, ///< End of audio stream
   XRSV_STREAM_END_TIMEOUT          = 2, ///< Stream timeout occurred
   XRSV_STREAM_END_USER_INTERUPTED  = 3, ///< User interrupted session
   XRSV_STREAM_END_MAX_LENGTH       = 4, ///< Maximum stream length reached
   XRSV_STREAM_END_INTERNAL_ERROR   = 5, ///< Internal processing error
   XRSV_STREAM_END_INVALID          = 6, ///< Unknown result
} xrsv_vrex_result_t;
```

## Integration Patterns

### Basic SDK Initialization
```c
#include <xr_voice_sdk.h>

int initialize_voice_sdk() {
    // Initialize with file logging
    int result = vsdk_init(true,           // ANSI colors enabled
                          "/var/log/voice.log", // Log file  
                          1024 * 1024);    // 1MB max file size
    
    if(result != 0) {
        fprintf(stderr, "Failed to initialize Voice SDK: %d\n", result);
        return -1;
    }
    
    // Set appropriate log levels for production
    vsdk_log_level_set_all(XLOG_LEVEL_WARN);
    vsdk_log_level_set(XLOG_MODULE_ID_XRAUDIO, XLOG_LEVEL_INFO);
    
    return 0;
}
```

### Custom Logging Integration
```c
// Application logging adapter
void app_voice_logger(const char *msg) {
    // Integrate with application logging framework
    app_log(APP_LOG_VOICE, "%s", msg);
}

void app_voice_logger_safe(const char *msg) {
    // Signal-safe logging for critical situations
    syslog(LOG_WARNING, "VSDK: %s", msg);
}

int init_with_custom_logging() {
    return vsdk_init_user_print(app_voice_logger,
                               app_voice_logger_safe,
                               false,  // No ANSI colors for structured logging
                               NULL,   // No file logging
                               0);     // No file size limit
}
```

### Version Verification
```c
bool verify_sdk_version(const char *required_version) {
    vsdk_version_info_t versions[VSDK_VERSION_QTY_MAX];
    uint32_t count = VSDK_VERSION_QTY_MAX;
    
    vsdk_version(versions, &count);
    
    for(uint32_t i = 0; i < count; i++) {
        if(strcmp(versions[i].name, "xr-voice-sdk") == 0) {
            return strcmp(versions[i].version, required_version) >= 0;
        }
    }
    return false;
}
```

### Health Monitoring Setup
```c
typedef struct {
    bool sdk_responsive;
    time_t last_health_check;
} health_monitor_t;

void sdk_health_callback(void *data) {
    health_monitor_t *monitor = (health_monitor_t*)data;
    monitor->sdk_responsive = true;
    monitor->last_health_check = time(NULL);
}

void setup_health_monitoring(health_monitor_t *monitor) {
    monitor->sdk_responsive = false;
    vsdk_thread_poll(sdk_health_callback, monitor);
}
```

## Error Handling Guidelines

### Return Code Checking
```c
// Always check initialization return codes
int result = vsdk_init(true, "/tmp/voice.log", 1024*1024);
if(result != 0) {
    // Handle initialization failure
    log_error("SDK initialization failed with code: %d", result);
    return INIT_FAILED;
}
```

### Resource Cleanup
```c
// Proper cleanup in error conditions
void cleanup_voice_sdk() {
    // Safe to call multiple times
    vsdk_term();
}

// Register cleanup handler
atexit(cleanup_voice_sdk);
```

## Thread Safety Considerations

### Thread-Safe Functions
- `vsdk_log_level_get()` - Safe from any thread
- `vsdk_log_level_set()` - Safe from any thread  
- `vsdk_thread_poll()` - Safe from any thread

### Single-Threaded Functions  
- `vsdk_init()` / `vsdk_init_user_print()` - Call from main thread only
- `vsdk_term()` - Call from main thread only
- `vsdk_version()` - Safe after initialization

### Callback Context
- Thread poll callbacks execute in SDK thread context
- Keep callback processing minimal and fast
- Avoid blocking operations in callbacks

## Platform-Specific Notes

### Linux
- Requires POSIX threading (`pthread`)
- Audio device access may require elevated privileges
- Network protocols require appropriate firewall configuration

### Embedded Systems
- Monitor memory usage with constrained resources
- Consider log file rotation in limited storage environments
- Audio device names may be platform-specific

### Cross-Platform Compatibility
- All APIs use standard C types (`bool`, `uint32_t`, etc.)
- File paths use forward slashes on all platforms
- Network addressing follows standard conventions

## Best Practices

### Initialization
1. Always check return codes from initialization functions
2. Set appropriate log levels for your deployment environment
3. Consider custom logging integration for production systems
4. Verify SDK version compatibility during startup

### Resource Management
1. Call `vsdk_term()` in application cleanup handlers
2. Monitor SDK thread health in long-running applications
3. Consider log file rotation for persistent applications
4. Handle initialization failures gracefully

### Performance
1. Use appropriate log levels to minimize I/O overhead
2. Keep thread poll callbacks lightweight and fast
3. Consider signal-safe logging for critical error paths
4. Monitor memory usage in resource-constrained environments

### Security
1. Validate log file permissions and paths
2. Consider log content sensitivity in production
3. Use secure protocols for network communication
4. Implement proper error handling to prevent information leakage