# XR Voice SDK - Complete System Architecture Documentation

## Executive Summary

The XR Voice SDK is a comprehensive, modular C-based voice interaction system designed for XR (Extended Reality) devices. It implements a three-layer architecture with rich plugin extensibility, supporting multiple communication protocols, audio codecs, and real-time processing capabilities.

## System Architecture Overview

### High-Level Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  XR Platform    │  │   Voice Apps    │  │ Integrators  │ │
│  │   Integration   │  │                 │  │              │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                          Public API
                              │
┌─────────────────────────────────────────────────────────────┐
│                      SDK CORE LAYER                         │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │                Core Integration                         │ │
│ │  vsdk_init()  vsdk_term()  vsdk_version()             │ │
│ └─────────────────────────────────────────────────────────┘ │
│                              │                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │              Component Layer                            │ │
│ │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ │ │
│ │  │xr-audio  │ │xr-speech-│ │xr-speech-│ │xr-logger    │ │ │
│ │  │          │ │ router   │ │  vrex    │ │             │ │ │
│ │  └──────────┘ └──────────┘ └──────────┘ └─────────────┘ │ │
│ │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ │ │
│ │  │ xr-mq    │ │xr-timer  │ │xr-fdc    │ │xr-sm-engine │ │ │
│ │  │          │ │          │ │          │ │             │ │ │
│ │  └──────────┘ └──────────┘ └──────────┘ └─────────────┘ │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                       Hardware Abstraction
                              │
┌─────────────────────────────────────────────────────────────┐
│                  HARDWARE INTERFACE LAYER                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │                Plugin Architecture                      │ │
│ │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌───────┐ │ │
│ │  │  HAL   │ │  KWD   │ │  ALG   │ │  SDF   │ │  OVC  │ │ │
│ │  │Plugin  │ │Plugin  │ │Plugin  │ │Plugin  │ │Plugin │ │ │
│ │  └────────┘ └────────┘ └────────┘ └────────┘ └───────┘ │ │
│ └─────────────────────────────────────────────────────────┘ │
│              ┌─────────────────────────────────┐             │
│              │      Hardware Interfaces        │             │
│              │   Audio, Network, Storage       │             │
│              └─────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

## Core Component Architecture

### 1. Audio Processing Subsystem (xr-audio)

**Primary Functions:**
- Multi-channel audio input/output management
- Real-time audio processing pipeline
- Audio codec support (ADPCM, Opus)
- Thread-safe atomic operations

**Key Components:**
- `xraudio.c` - Core audio management
- `xraudio_input.c`/`xraudio_output.c` - I/O handling  
- `xraudio_thread.c` - Threading model
- `xraudio_atomic.c` - Atomic operations
- `xraudio_utils.c` - Utility functions

**Threading Model:**
- High-priority audio threads with real-time scheduling
- Lock-free atomic operations for critical paths
- Separate threads for input capture and output playback

### 2. Speech Routing Subsystem (xr-speech-router)

**Primary Functions:**
- Multi-protocol speech communication (HTTP, WebSocket, SDT)
- State machine-driven connection management
- Message queue integration
- Audio pipeline integration

**Protocol Support:**
- **HTTP Protocol** (`xrsr_protocol_http.c`) - RESTful speech services
- **WebSocket Protocol** (`xrsr_protocol_ws.c`) - Real-time bidirectional communication
- **SDT Protocol** (`xrsr_protocol_sdt.c`) - Secure data transfer

**State Machine Architecture:**
- Protocol-specific state machines (`xrsr_protocol_*_sm.h`)
- Connection lifecycle management
- Error recovery and retry logic

### 3. Voice Recognition Subsystem (xr-speech-vrex)

**Primary Functions:**
- Speech-to-text processing
- Result processing and confidence scoring
- Multi-protocol recognition support

**Components:**
- **HTTP Recognition** (`xrsv_http/`) - Traditional HTTP-based recognition
- **WebSocket NextGen** (`xrsv_ws_nextgen/`) - Advanced real-time recognition
- **Utility Functions** (`xrsv_utils.c`) - Common processing functions

### 4. Logging Framework (xr-logger)

**Primary Functions:**
- Modular, hierarchical logging system
- Multi-destination output (file, console, custom handlers)
- Thread-safe operations with signal-safe support
- Runtime configuration management

**Architecture:**
- Module-based log level control (`rdkx_logger_modules.json`)
- Configurable output formatters with ANSI color support
- Automatic log rotation and size management

### 5. Message Queue Subsystem (xr-mq)

**Primary Functions:**
- Inter-component asynchronous communication
- Priority-based message ordering
- High-performance, low-latency message delivery
- Reliable delivery with acknowledgments

### 6. State Management Engine (xr-sm-engine)

**Primary Functions:**
- Centralized SDK state coordination
- State transition validation and safety
- Component synchronization
- Event notification system

### 7. Utility Services

**Timer Services (xr-timer):**
- High-precision timer management
- Periodic and one-shot timer operations
- Callback-based timer execution

**Timestamp Services (xr-timestamp):**
- Synchronized timestamp generation
- Cross-component timing correlation
- Audio processing synchronization

**Fault Detection & Correction (xr-fdc):**
- Component health monitoring
- Automatic error recovery
- System stability management

## Plugin Architecture

### Plugin Framework Design

The SDK implements a comprehensive plugin system enabling runtime extension of core functionality:

```c
// Plugin API Structure (from vsdk_private.h)
typedef struct {
    xraudio_hal_plugin_api_t *hal_plugin;   // Hardware Abstraction Layer
    xraudio_kwd_plugin_api_t *kwd_plugin;   // Keyword Detection
    xraudio_eos_plugin_api_t *eos_plugin;   // End of Speech
    xraudio_dga_plugin_api_t *dga_plugin;   // Dynamic Gain Adjustment
    xraudio_sdf_plugin_api_t *sdf_plugin;   // Speech Data Format
    xraudio_ovc_plugin_api_t *ovc_plugin;   // Output Volume Control
    xraudio_ppr_plugin_api_t *ppr_plugin;   // Post-Processing
} vsdk_plugin_apis_t;
```

### Plugin Types

1. **HAL Plugin** - Hardware abstraction for audio devices
2. **KWD Plugin** - Keyword detection and wake-word processing
3. **ALG Plugin** - Audio processing algorithms
4. **SDF Plugin** - Speech data format handling
5. **OVC Plugin** - Output volume control
6. **PPR Plugin** - Post-processing routines

## Data Flow Architecture

### Audio Processing Pipeline

```
[Microphone Array] 
        ↓
[HAL Plugin Interface]
        ↓
[Audio Input (xraudio_input.c)]
        ↓
[Atomic Buffer Management]
        ↓
[Real-time Processing Pipeline]
    ┌─────────────────────────┐
    │ • Noise Reduction       │
    │ • Echo Cancellation     │
    │ • Gain Control          │  
    │ • Format Conversion     │
    └─────────────────────────┘
        ↓
[Codec Processing (ADPCM/Opus)]
        ↓
[Speech Router (xrsr)]
    ┌─────────────────────────┐
    │ • Protocol Selection    │
    │ • State Management      │
    │ • Message Queue         │
    └─────────────────────────┘
        ↓
[Network Transmission]
    ┌─────────────────────────┐
    │ • HTTP Protocol         │
    │ • WebSocket Protocol    │
    │ • SDT Protocol          │
    └─────────────────────────┘
        ↓
[Voice Recognition Service]
        ↓
[Recognition Results]
        ↓
[Application Callbacks]
```

## Component Interdependencies

### Initialization Sequence

1. **vsdk_init()** - Master initialization
2. **xlog_init()** - Logging system initialization
3. **Plugin Loading** - Dynamic plugin discovery and loading
4. **Component Initialization:**
   - xr-audio subsystem
   - xr-speech-router protocols
   - xr-speech-vrex recognition
   - xr-mq message queues
   - xr-sm-engine state management
   - Utility services (timer, timestamp, fdc)

### Cross-Component Communication

**Message Flow Patterns:**
- **Audio → Speech Router**: Audio data via message queues
- **Speech Router → Voice Recognition**: Protocol-specific data transmission
- **State Engine → All Components**: State change notifications
- **Fault Detection → State Engine**: Health status updates
- **Timer Services → All Components**: Scheduled operation triggers

## Threading Architecture

### Thread Hierarchy

1. **Main Application Thread** - SDK API calls and initialization
2. **Audio Processing Threads** - High-priority real-time audio handling
3. **Network Protocol Threads** - HTTP/WebSocket/SDT communication
4. **Message Queue Threads** - Inter-component message processing
5. **Timer Service Threads** - Scheduled operation execution
6. **Logging Threads** - Asynchronous log processing

### Synchronization Mechanisms

- **Atomic Operations** (`xraudio_atomic.h`) - Lock-free audio buffer access
- **Message Queues** - Thread-safe inter-component communication
- **State Machines** - Synchronized state transitions
- **Callback Systems** - Event-driven component coordination

## Configuration Management

### Configuration Architecture

The SDK supports hierarchical configuration through JSON files:

**Core Configuration Files:**
- `vsdk_config.json` - Main SDK configuration
- `xraudio_config_default.json` - Audio processing parameters
- `xrsr_config_default.json` - Speech routing configuration
- `rdkx_logger_modules.json` - Logging module configuration

**Configuration Inheritance:**
1. Default embedded configurations
2. System-wide configuration files (`/etc/`)
3. Runtime configuration updates
4. Application-specific overrides

### Runtime Configuration Updates

Components support dynamic configuration updates for:
- Audio processing parameters
- Network protocol settings
- Logging levels and outputs
- State machine parameters

## Cross-Platform Support

### Build System Architecture (CMake)

**Platform Support:**
- Linux (x86_64, ARM, embedded)
- Windows (cross-compilation support)
- macOS (development/testing)
- Custom embedded platforms

**Configurable Features:**
```cmake
option(HTTP_ENABLED,     "HTTP protocol support")
option(WS_ENABLED,       "WebSocket protocol support") 
option(SDT_ENABLED,      "SDT protocol support")
option(RDK_VERSION_ENABLED, "RDK versioning support")
```

### Hardware Abstraction

**Abstraction Layers:**
- Audio device abstraction (HAL plugins)
- Network interface abstraction
- File system abstraction
- Threading abstraction (POSIX)

## Security and Resource Management

### Security Architecture

- **Plugin Isolation** - Sandboxed plugin execution
- **Memory Protection** - Buffer overflow prevention
- **Secure Protocols** - SDT encrypted communication
- **Input Validation** - Comprehensive parameter checking

### Resource Management

- **Memory Management** - Automatic resource cleanup and leak prevention
- **Thread Management** - Proper thread lifecycle management
- **Network Resources** - Connection pooling and cleanup
- **Audio Resources** - Device handle management and exclusive access

## Performance Characteristics

### Real-Time Constraints

- **Audio Latency** - Sub-10ms processing latency
- **Network Latency** - Protocol-optimized for responsiveness  
- **Memory Footprint** - Optimized for embedded deployments
- **CPU Utilization** - Multi-core aware processing

### Scalability Features

- **Concurrent Processing** - Multi-threaded architecture
- **Load Balancing** - Protocol selection based on load
- **Resource Monitoring** - Adaptive resource allocation
- **Graceful Degradation** - Fallback modes for resource constraints

## Integration Patterns

### Application Integration

**Public API Surface:**
```c
// Core SDK functions
int  vsdk_init(bool ansi_color, const char *filename, uint32_t file_size_max);
void vsdk_term(void);
void vsdk_version(vsdk_version_info_t *version_info, uint32_t *qty);

// Logging control
xlog_level_t vsdk_log_level_get(xlog_module_id_t id);
void         vsdk_log_level_set(xlog_module_id_t id, xlog_level_t level);

// Thread monitoring
void vsdk_thread_poll(vsdk_thread_poll_func_t func, void *data);
```

### Callback Patterns

- **Event-Driven Architecture** - Non-blocking callback mechanisms
- **Error Handling** - Comprehensive error reporting through callbacks
- **Status Monitoring** - Real-time status updates via callbacks

## Extensibility Framework

### Plugin Development

**Plugin Interface Standards:**
- Standardized plugin API structures
- Version compatibility checking
- Dynamic loading and unloading
- Error handling and recovery

### Custom Processing Stages

- **DSP Pipeline Extension** - Custom audio processing modules
- **Protocol Extensions** - Additional communication protocols
- **Recognition Engine Integration** - Third-party recognition services
- **Custom Logging Handlers** - Application-specific logging backends

## Summary

The XR Voice SDK implements a sophisticated, modular architecture designed for high-performance voice interaction in XR environments. Its three-layer design with comprehensive plugin support, real-time processing capabilities, and extensive configuration options make it suitable for diverse deployment scenarios while maintaining performance and reliability requirements.