# XR Voice SDK Configuration Schema Documentation

## Overview

This document provides comprehensive schema documentation for all JSON configuration files used throughout the XR Voice SDK. The SDK uses a hierarchical configuration system with component-specific configuration files that define operational parameters, debugging settings, and runtime behavior controls.

## Configuration Architecture

### Configuration File Hierarchy

```
XR Voice SDK Configuration
├── Audio Processing (xraudio_config_default.json)
├── Speech Router (xrsr_config_default.json)  
├── Logger Global (rdkx_logger_global.json)
└── Logger Modules (rdkx_logger_modules.json)
```

### Configuration Loading Model

The SDK employs a multi-stage configuration loading process:

1. **Default Configuration Loading**: Built-in default values from JSON files
2. **Runtime Override**: Application-specific configuration updates
3. **Environment-Specific**: Debug vs. production configuration variants
4. **Component Isolation**: Each component maintains independent configuration scope

## Audio Processing Configuration

### File: `xraudio_config_default.json`
**Location**: [`src/xr-audio/xraudio_config_default.json`](../src/xr-audio/xraudio_config_default.json)

#### Schema Structure

```json
{
   "input": {
      "kwd": {},      // Keyword Detection Configuration
      "eos": {},      // End-of-Speech Detection Configuration
      "dga": {},      // Digital Gain Adjustment Configuration
      "sdf": {},      // Speech Detection Framework Configuration
      "ppr": {}       // Pre-Processing/Post-Processing Configuration
   },
   "output": {
      "eos": {},      // End-of-Speech Output Configuration
      "ovc": {}       // Output Voice Control Configuration
   },
   "hal": {}          // Hardware Abstraction Layer Configuration
}
```

#### Configuration Domains

##### Input Processing Configuration
- **`input.kwd`**: Keyword Detection Parameters
  - **Purpose**: Controls wake word detection sensitivity and algorithms
  - **Scope**: Real-time keyword detection engine
  - **Extensibility**: Plugin-specific keyword configurations

- **`input.eos`**: End-of-Speech Detection Parameters
  - **Purpose**: Configures speech endpoint detection algorithms
  - **Scope**: Voice activity detection and speech boundary identification
  - **Integration**: Works with VAD (Voice Activity Detection) systems

- **`input.dga`**: Digital Gain Adjustment Parameters
  - **Purpose**: Automatic gain control and signal normalization
  - **Scope**: Audio signal pre-processing pipeline
  - **Real-time**: Dynamic gain adjustments during recording

- **`input.sdf`**: Speech Detection Framework Parameters
  - **Purpose**: Advanced speech detection and classification
  - **Scope**: Machine learning-based speech analysis
  - **Performance**: CPU and memory optimization settings

- **`input.ppr`**: Pre/Post-Processing Parameters
  - **Purpose**: Audio enhancement and filtering operations
  - **Scope**: Noise reduction, echo cancellation, signal conditioning
  - **Quality**: Audio quality vs. performance trade-offs

##### Output Processing Configuration
- **`output.eos`**: End-of-Speech Output Parameters
  - **Purpose**: Controls output generation upon speech completion
  - **Scope**: Response generation and output formatting
  - **Timing**: Output timing and synchronization controls

- **`output.ovc`**: Output Voice Control Parameters
  - **Purpose**: Voice synthesis and output control parameters
  - **Scope**: Text-to-speech and voice response generation
  - **Quality**: Voice quality and speaker characteristics

##### Hardware Abstraction Configuration
- **`hal`**: Hardware Abstraction Layer Parameters
  - **Purpose**: Platform-specific hardware configuration
  - **Scope**: Audio device configuration and hardware optimization
  - **Portability**: Cross-platform hardware abstraction

#### Configuration Extension Model

The XRAudio configuration uses a plugin-based extension model where each processing component can define additional configuration parameters:

```json
{
   "input": {
      "kwd": {
         "sensitivity": 0.8,
         "timeout_ms": 5000,
         "models": ["wake_word_v2.bin"]
      },
      "ppr": {
         "noise_reduction": true,
         "echo_cancellation": {
            "enabled": true,
            "aggressiveness": "medium"
         }
      }
   }
}
```

### Configuration Usage Patterns

#### Runtime Configuration Access
Located in [`xraudio.c`](../src/xr-audio/xraudio.c):

```c
// Configuration loading and parsing
xraudio_result_t xraudio_config_load(const char *config_file_path) {
    // Load JSON configuration from file
    // Parse configuration sections
    // Apply component-specific configurations
    // Validate configuration parameters
}
```

#### Dynamic Configuration Updates
```c
// Runtime configuration updates
xraudio_result_t xraudio_config_update_input_kwd(xraudio_obj_t obj, 
                                                  xraudio_kwd_config_t *config);
```

## Speech Router Configuration

### File: `xrsr_config_default.json`
**Location**: [`src/xr-speech-router/xrsr_config_default.json`](../src/xr-speech-router/xrsr_config_default.json)

#### Schema Structure

```json
{
   "http": {
      "debug": false              // HTTP protocol debugging
   },
   "ws": {
      "debug": true,              // WebSocket protocol debugging
      "fpm": {                    // Full Power Mode Configuration
         "connect_check_interval": 50,    // Connection health check interval (ms)
         "timeout_connect": 2000,         // Connection establishment timeout (ms)
         "timeout_inactivity": 10000,     // Inactivity timeout (ms)
         "timeout_session": 5000,         // Session timeout (ms)
         "ipv4_fallback": true,           // Enable IPv4 fallback
         "backoff_delay": 50              // Retry backoff delay (ms)
      },
      "lpm": {                    // Low Power Mode Configuration
         "connect_check_interval": 50,    // Connection health check interval (ms)
         "timeout_connect": 10000,        // Connection establishment timeout (ms)
         "timeout_inactivity": 10000,     // Inactivity timeout (ms)
         "timeout_session": 10000,        // Session timeout (ms)
         "ipv4_fallback": true,           // Enable IPv4 fallback
         "backoff_delay": 100             // Retry backoff delay (ms)
      }
   },
   "xraudio": {}                  // XRAudio integration configuration
}
```

#### Configuration Domains

##### HTTP Protocol Configuration
- **`http.debug`**: HTTP Protocol Debugging
  - **Type**: Boolean
  - **Purpose**: Enable detailed HTTP request/response logging
  - **Impact**: Performance overhead in debug mode
  - **Default**: `false` (optimized for production)

##### WebSocket Protocol Configuration
- **`ws.debug`**: WebSocket Protocol Debugging
  - **Type**: Boolean
  - **Purpose**: Enable WebSocket frame-level debugging
  - **Impact**: Verbose logging of WebSocket communications
  - **Default**: `true` (development-friendly default)

##### Power Mode Configurations

###### Full Power Mode (FPM) Configuration
Optimized for low-latency, high-performance operation:

- **`fpm.connect_check_interval`**: Connection Health Check Frequency
  - **Type**: Integer (milliseconds)
  - **Range**: 10-1000ms 
  - **Purpose**: Frequency of connection health verification
  - **Default**: 50ms (20Hz monitoring)

- **`fpm.timeout_connect`**: Connection Establishment Timeout
  - **Type**: Integer (milliseconds)
  - **Range**: 500-10000ms
  - **Purpose**: Maximum time allowed for initial connection
  - **Default**: 2000ms (aggressive connection timing)

- **`fpm.timeout_inactivity`**: Inactivity Timeout
  - **Type**: Integer (milliseconds)
  - **Range**: 1000-60000ms
  - **Purpose**: Timeout for inactive connections
  - **Default**: 10000ms (10-second inactivity tolerance)

- **`fpm.timeout_session`**: Session Timeout
  - **Type**: Integer (milliseconds)
  - **Range**: 1000-30000ms
  - **Purpose**: Maximum session duration
  - **Default**: 5000ms (rapid session cycling)

- **`fpm.ipv4_fallback`**: IPv4 Fallback Enable
  - **Type**: Boolean
  - **Purpose**: Automatic fallback to IPv4 if IPv6 fails
  - **Default**: `true` (maximum connectivity reliability)

- **`fpm.backoff_delay`**: Retry Backoff Delay
  - **Type**: Integer (milliseconds)
  - **Range**: 10-1000ms
  - **Purpose**: Delay between connection retry attempts
  - **Default**: 50ms (aggressive retry strategy)

###### Low Power Mode (LPM) Configuration
Optimized for battery conservation and reduced resource usage:

- **`lpm.connect_check_interval`**: Connection Health Check Frequency
  - **Default**: 50ms (same as FPM for consistency)

- **`lpm.timeout_connect`**: Connection Establishment Timeout
  - **Default**: 10000ms (5x longer than FPM for power savings)

- **`lpm.timeout_inactivity`**: Inactivity Timeout
  - **Default**: 10000ms (same as FPM)

- **`lpm.timeout_session`**: Session Timeout  
  - **Default**: 10000ms (2x longer than FPM)

- **`lpm.ipv4_fallback`**: IPv4 Fallback Enable
  - **Default**: `true` (maintain connectivity reliability)

- **`lpm.backoff_delay`**: Retry Backoff Delay
  - **Default**: 100ms (2x longer than FPM to reduce power consumption)

##### XRAudio Integration Configuration
- **`xraudio`**: XRAudio Component Integration
  - **Purpose**: Configuration parameters for XRAudio integration
  - **Scope**: Cross-component communication settings
  - **Extensibility**: Supports component-specific parameters

### Power Mode Configuration Strategy

The dual power mode configuration enables the SDK to optimize behavior based on system power state:

#### Full Power Mode (FPM) Characteristics
- **Low Latency**: Aggressive timeouts for responsive interaction
- **High Frequency**: Frequent health checks and fast retries
- **Resource Intensive**: Higher CPU and network usage
- **Use Cases**: Active voice interaction, real-time communication

#### Low Power Mode (LPM) Characteristics  
- **Extended Timeouts**: Longer timeouts to reduce active processing
- **Reduced Frequency**: Less frequent background operations
- **Resource Conservative**: Lower CPU and battery usage
- **Use Cases**: Background monitoring, standby operation

### Configuration Usage in Code

#### Configuration Loading
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c):

```c
// Power mode configuration selection
if(power_mode == XRSR_POWER_MODE_FULL) {
    timeout_connect = config->ws.fpm.timeout_connect;
    timeout_inactivity = config->ws.fpm.timeout_inactivity;
    backoff_delay = config->ws.fpm.backoff_delay;
} else { // XRSR_POWER_MODE_LOW
    timeout_connect = config->ws.lpm.timeout_connect;
    timeout_inactivity = config->ws.lpm.timeout_inactivity;  
    backoff_delay = config->ws.lpm.backoff_delay;
}
```

## Logger Configuration System

### File: `rdkx_logger_global.json`
**Location**: [`src/xr-logger/rdkv/rdkx_logger_global.json`](../src/xr-logger/rdkv/rdkx_logger_global.json)

#### Schema Structure

```json
{
   "ANSI_COLOR": true           // ANSI color codes in log output
}
```

#### Global Logger Configuration
- **`ANSI_COLOR`**: ANSI Color Code Support
  - **Type**: Boolean
  - **Purpose**: Enable colored log output using ANSI escape codes
  - **Impact**: Improved log readability in compatible terminals
  - **Compatibility**: Disabled automatically for non-compatible output destinations
  - **Default**: `true` (enhanced developer experience)

### File: `rdkx_logger_modules.json`
**Location**: [`src/xr-logger/rdkv/rdkx_logger_modules.json`](../src/xr-logger/rdkv/rdkx_logger_modules.json)

#### Schema Structure

```json
{
   "RDKX": "XLOG_LEVEL_INFO",     // RDK Extension logging
   "VMIC": "XLOG_LEVEL_INFO",     // Voice Microphone Interface
   "VSDK": "XLOG_LEVEL_INFO",     // Voice SDK Core
   "XLOG": "XLOG_LEVEL_INFO",     // Logger Framework
   "XRAUDIO": "XLOG_LEVEL_INFO",  // XR Audio Component
   "XRBT": "XLOG_LEVEL_INFO",     // XR Bluetooth Component
   "XRFDC": "XLOG_LEVEL_INFO",    // XR FDC (Fault Detection/Correction)
   "XRMQ": "XLOG_LEVEL_INFO",     // XR Message Queue
   "XRSR": "XLOG_LEVEL_INFO",     // XR Speech Router
   "XRSTAMP": "XLOG_LEVEL_INFO",  // XR Timestamp Utility
   "XRSV": "XLOG_LEVEL_INFO",     // XR Speech VREX
   "XRTA": "XLOG_LEVEL_INFO",     // XR Timer/Alarm
   "XRTIMER": "XLOG_LEVEL_INFO",  // XR Timer Component
   "CTRLM": "XLOG_LEVEL_INFO",    // Control Manager
   "XRSM": "XLOG_LEVEL_INFO",     // XR State Machine Engine
   "BLE": "XLOG_LEVEL_INFO"       // Bluetooth Low Energy
}
```

#### Module-Specific Logging Configuration

Each module entry defines the minimum logging level for that component:

##### Core SDK Modules
- **`VSDK`**: Voice SDK Core
  - **Component**: Main SDK framework and APIs
  - **Typical Usage**: High-level SDK operations and lifecycle events

- **`XRAUDIO`**: XR Audio Processing
  - **Component**: Audio input/output, processing pipeline
  - **Typical Usage**: Audio device operations, codec operations, real-time processing

- **`XRSR`**: XR Speech Router  
  - **Component**: Protocol handling, speech routing
  - **Typical Usage**: Network communication, protocol state machines

- **`XRSV`**: XR Speech VREX
  - **Component**: Voice recognition and speech services
  - **Typical Usage**: Speech recognition results, service integration

##### Infrastructure Modules
- **`XLOG`**: Logger Framework
  - **Component**: Logging infrastructure itself
  - **Self-Reference**: Logs about logging operations

- **`XRMQ`**: XR Message Queue
  - **Component**: Inter-component message passing
  - **Typical Usage**: Message queue operations, IPC events

- **`XRTIMER`**: XR Timer Component
  - **Component**: Timer and timeout management
  - **Typical Usage**: Timer events, timeout notifications

- **`XRSTAMP`**: XR Timestamp Utility
  - **Component**: High-precision timestamps
  - **Typical Usage**: Performance measurement, event timing

##### Platform Integration Modules
- **`RDKX`**: RDK Extension Framework
  - **Component**: RDK (Reference Design Kit) integration
  - **Platform**: Set-top box and embedded device integration

- **`CTRLM`**: Control Manager
  - **Component**: Remote control and input management
  - **Integration**: Hardware control interface

- **`BLE`**: Bluetooth Low Energy
  - **Component**: Bluetooth audio and control interfaces
  - **Wireless**: Wireless communication protocols

##### Specialized Components
- **`VMIC`**: Voice Microphone Interface
  - **Component**: Hardware microphone abstraction
  - **Hardware**: Low-level audio hardware integration

- **`XRBT`**: XR Bluetooth Component
  - **Component**: Bluetooth audio processing
  - **Audio**: Wireless audio streaming and control

- **`XRFDC`**: XR Fault Detection/Correction
  - **Component**: Error detection and recovery systems
  - **Reliability**: System health monitoring

- **`XRSM`**: XR State Machine Engine
  - **Component**: Generic state machine framework
  - **Architecture**: State management across components

#### Logging Level Hierarchy

The SDK supports the following logging levels (in increasing verbosity):

```c
typedef enum {
    XLOG_LEVEL_FATAL   = 0,    // Critical errors causing termination
    XLOG_LEVEL_ERROR   = 1,    // Non-fatal error conditions
    XLOG_LEVEL_WARN    = 2,    // Warning conditions
    XLOG_LEVEL_INFO    = 3,    // Informational messages (default)
    XLOG_LEVEL_DEBUG   = 4,    // Debug-level messages
    XLOG_LEVEL_TRACE   = 5     // Detailed execution traces
} xlog_level_t;
```

#### Configuration Usage Patterns

##### Runtime Log Level Updates
```c
// Update specific module log level at runtime
xlog_level_set("XRAUDIO", XLOG_LEVEL_DEBUG);

// Query current log level for module
xlog_level_t level = xlog_level_get("XRSR");
```

##### Module-Specific Logging
```c
// Component-specific logging with module identification
XLOGD_INFO("XRAUDIO", "Audio device initialized: %s", device_name);
XLOGD_DEBUG("XRSR", "WebSocket connection established to %s", host);
XLOGD_ERROR("XRSV", "Speech recognition failed: %s", error_msg);
```

## Configuration Inheritance and Override Mechanisms

### Configuration Precedence

The SDK employs a hierarchical configuration precedence system:

1. **Hard-coded Defaults**: Compiled-in minimal configuration
2. **JSON Configuration Files**: Component-specific default configurations
3. **Environment Variables**: System-level configuration overrides
4. **Runtime API Calls**: Application-specific configuration updates
5. **Debug/Development Overrides**: Debug-specific configuration modifications

### Override Patterns

#### Environment Variable Overrides
```bash
# Override WebSocket debug setting
export XRSR_WS_DEBUG=false

# Override XRAudio logging level
export XRAUDIO_LOG_LEVEL=XLOG_LEVEL_DEBUG

# Override power mode timeouts
export XRSR_FPM_TIMEOUT_CONNECT=1500
```

#### Runtime Configuration Updates
```c
// Update XRSR configuration at runtime
xrsr_config_t updated_config;
updated_config.ws.fpm.timeout_connect = 1500;
xrsr_config_update(&updated_config);

// Update logging configuration
xlog_config_t log_config;
log_config.modules["XRAUDIO"] = XLOG_LEVEL_TRACE;
xlog_config_update(&log_config);
```

### Configuration Validation

#### JSON Schema Validation
Each configuration file undergoes validation during loading:

```c
// Configuration validation patterns
typedef struct {
    int min_value;
    int max_value;
    int default_value;
} config_range_t;

// Timeout validation ranges
config_range_t timeout_ranges = {
    .min_value = 100,      // Minimum 100ms
    .max_value = 60000,    // Maximum 60 seconds
    .default_value = 5000  // Default 5 seconds
};
```

#### Runtime Configuration Checks
```c
// Validate configuration parameters at runtime
bool xrsr_config_validate_timeouts(xrsr_config_t *config) {
    if(config->ws.fpm.timeout_connect < 500 || 
       config->ws.fpm.timeout_connect > 10000) {
        XLOGD_ERROR("XRSR", "Invalid FPM connect timeout: %d", 
                   config->ws.fpm.timeout_connect);
        return false;
    }
    return true;
}
```

## Configuration Best Practices

### Development Configuration
```json
{
   "http": { "debug": true },
   "ws": { "debug": true },
   "logging": {
      "XRAUDIO": "XLOG_LEVEL_DEBUG",
      "XRSR": "XLOG_LEVEL_DEBUG"
   }
}
```

### Production Configuration
```json
{
   "http": { "debug": false },
   "ws": { "debug": false },
   "logging": {
      "XRAUDIO": "XLOG_LEVEL_INFO",
      "XRSR": "XLOG_LEVEL_WARN"
   }
}
```

### Power-Optimized Configuration
```json
{
   "ws": {
      "lpm": {
         "timeout_connect": 15000,
         "backoff_delay": 200,
         "connect_check_interval": 100
      }
   }
}
```

## Configuration Schema Extensions

### Plugin Configuration Support

The configuration system supports plugin-specific extensions:

```json
{
   "plugins": {
      "keyword_detection": {
         "model_file": "/opt/models/wake_word.bin",
         "sensitivity": 0.7,
         "cpu_threads": 2
      },
      "noise_reduction": {
         "algorithm": "spectral_subtraction",
         "aggressiveness": "medium"
      }
   }
}
```

### Custom Configuration Validators

```c
// Register custom configuration validator
typedef bool (*config_validator_t)(const char *key, const char *value);

void xrsr_register_config_validator(const char *section, 
                                   const char *key,
                                   config_validator_t validator);
```

## Conclusion

The XR Voice SDK configuration system provides a comprehensive and flexible approach to component configuration management. The JSON-based configuration files enable:

- **Modular Configuration**: Component-specific configuration isolation
- **Power Management**: Dual-mode power optimization configurations  
- **Debugging Support**: Granular debug control and logging configuration
- **Runtime Flexibility**: Dynamic configuration updates and validation
- **Cross-Platform Support**: Platform-agnostic configuration management

The hierarchical configuration model with clear override mechanisms ensures that the SDK can be effectively configured for diverse deployment scenarios while maintaining operational reliability and developer productivity.