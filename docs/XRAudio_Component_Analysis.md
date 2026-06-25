# XR Audio Component - Architecture Analysis

## Component Overview

The XR Audio component serves as the core audio processing engine within the XR Voice SDK, providing comprehensive audio input/output management, real-time processing pipelines, and hardware abstraction. This component orchestrates all audio-related functionality including device management, streaming, recording, playback, and plugin-based algorithm processing.

## Architecture Design Principles

### 1. Layered Architecture
- **Public API Layer**: Clean C interface for SDK integration (`xraudio.h`)
- **Core Management Layer**: Object lifecycle and resource coordination (`xraudio.c`)  
- **Processing Layer**: Input/output handling and stream management (`xraudio_input.c/h`, `xraudio_output.c/h`)
- **Platform Abstraction Layer**: Hardware and algorithm plugin interfaces
- **Utility Layer**: Atomic operations, threading, resource management

### 2. Asynchronous Processing Model
- **Multi-threaded Design**: Main processing thread with separate resource management
- **Message Queue Communication**: Thread-safe command dispatch via `xr_mq_t`
- **Callback-Driven Events**: Asynchronous notification system for audio events
- **Real-time Processing**: Frame-based audio processing with timing constraints

### 3. Plugin-Based Extensibility
- **Hardware Abstraction**: HAL plugins for platform-specific device access
- **Algorithm Plugins**: KWD, EOS, PPR, DGA, SDF, OVC plugins for audio processing
- **Dynamic Loading**: Runtime plugin discovery and loading with graceful fallbacks
- **Standardized Interfaces**: Common API patterns across all plugin types

### 4. Resource Management
- **Shared Memory Architecture**: Multi-process resource coordination
- **Priority-Based Allocation**: High/medium/low priority resource requests
- **Capability Negotiation**: Dynamic feature enablement based on hardware capabilities
- **Graceful Degradation**: Fallback behavior when resources are unavailable

## Core Object Structure

### Main Audio Object
```c
// Primary xraudio object (xraudio_obj_t) from xraudio.c
typedef struct {
   uint32_t                          identifier;           // Object validation (0x92834512)
   
   // Resource Management
   xraudio_resource_id_input_t       resource_id_record;   // Allocated input resources
   xraudio_resource_id_output_t      resource_id_playback; // Allocated output resources
   uint16_t                          capabilities_record;   // Input capabilities
   uint16_t                          capabilities_playback; // Output capabilities
   
   // Device Configuration
   xraudio_devices_input_t           devices_input;        // Input device configuration
   xraudio_devices_output_t          devices_output;       // Output device configuration
   xraudio_input_format_t            input_format;         // Audio input format
   
   // Threading Infrastructure
   xraudio_thread_t                  main_thread;          // Main processing thread
   xraudio_thread_t                  rsrc_thread;          // Resource management thread
   sem_t                             mutex_api;            // API call synchronization
   
   // Message Queue System
   xr_mq_t                           msgq_main;            // Main thread message queue
   xr_mq_t                           msgq_resource;        // Resource thread message queue
   int                               fifo_resource;        // Resource notification FIFO
   
   // Object State
   bool                              resources_requested;  // Resource request status
   bool                              opened;               // Device open status
   uint8_t                           user_id;             // Process/user identifier
   
   // Sub-component Objects
   xraudio_input_object_t            obj_input;           // Input processing object
   xraudio_output_object_t           obj_output;          // Output processing object
   
   // Configuration Objects
   json_t*                           json_obj_input;      // Input configuration
   json_t*                           json_obj_output;     // Output configuration  
   json_t*                           json_obj_hal;        // HAL configuration
   
   // Plugin Interface Pointers
   xraudio_hal_plugin_api_t *        hal_plugin;          // Hardware abstraction
   xraudio_dga_plugin_api_t *        dga_plugin;          // Dynamic gain adjustment
   xraudio_kwd_plugin_api_t *        kwd_plugin;          // Keyword detection
   
   // Feature Flags
   bool                              eos_enabled;         // End-of-speech detection
   bool                              ppr_enabled;         // Post-processing
   bool                              out_enabled;         // Audio output
   bool                              production_build;    // Build configuration
   bool                              curtail_enabled;     // Capture curtailment
   
   // Internal Capture Configuration
   xraudio_internal_capture_params_t internal_capture_params;
   
   // Shared Memory (Multi-process)
   xraudio_shared_mem_t *            shared_mem;          // Shared resource state
   int                               shared_mem_fd;       // Shared memory descriptor
} xraudio_obj_t;
```

### Process-Global State
```c
// Global process state (xraudio_process_t)
typedef struct {
   // Multi-process Resource Management
   int                      shm;                    // Shared memory descriptor
   xraudio_shared_mem_t    *shared_mem;            // Shared state pointer
   uint8_t                  user_cnt;              // Active user count
   
   // Hardware Abstraction Layer
   xraudio_hal_obj_t        hal_obj;               // HAL object handle
   uint8_t                  hal_user_cnt;          // HAL user count
   xraudio_hal_dsp_config_t dsp_config;           // DSP configuration
   
   // System State
   xraudio_power_mode_t     power_mode;           // Current power mode
   bool                     privacy_mode;          // Privacy mode status
} xraudio_process_t;
```

## Audio Input Architecture

### Input Processing Pipeline
The input processing system handles all audio capture, streaming, and recording operations:

#### Input Object Structure
- **Session Management**: Default and mic-tap session groups
- **State Machine**: Created → Idling → Recording/Streaming/Detecting states
- **Multi-source Support**: Far-field, push-to-talk, microphone inputs
- **Format Handling**: PCM 16-bit/32-bit, mono/multi-channel support

#### Core Input APIs
```c
// Primary input operations from xraudio_input.h
xraudio_input_object_t  xraudio_input_object_create(/* HAL integration */);
xraudio_result_t        xraudio_input_open(/* device configuration */);
xraudio_result_t        xraudio_input_record_to_file/memory(/* capture modes */);
xraudio_result_t        xraudio_input_stream_to_fifo/pipe/user(/* streaming modes */);
xraudio_result_t        xraudio_input_keyword_detect(/* voice activation */);
```

#### Advanced Input Features
- **Keyword Detection**: Wake-word processing with sensitivity control
- **End-of-Speech Detection**: Voice activity detection and session termination
- **Sound Intensity Monitoring**: Audio level analysis and reporting
- **Signal Direction Finding**: Beamforming and spatial audio processing
- **Dynamic Gain Adjustment**: Automatic gain control and level management
- **Post-Processing**: Noise reduction, echo cancellation, enhancement

### Input Session Types
```c
typedef enum {
   XRAUDIO_INPUT_SESSION_GROUP_DEFAULT = 0,  // Regular voice sessions (PTT, FFV)
   XRAUDIO_INPUT_SESSION_GROUP_MIC_TAP = 1,  // Microphone tap sessions
   XRAUDIO_INPUT_SESSION_GROUP_QTY     = 2
} xraudio_input_session_group_t;
```

## Audio Output Architecture  

### Output Processing Pipeline
The output system manages audio playback, volume control, and speaker management:

#### Output Operations
- **File Playback**: WAV, MP3, and other container format support
- **Memory Playback**: Direct buffer playback with format specification
- **Pipe/FIFO Playback**: Stream-based playbook from external sources  
- **User Callback Playback**: Custom audio source integration
- **Volume Control**: Absolute and relative volume with ramping
- **Pause/Resume**: Session control with state management

#### Output Configuration
- **Sample Rate Range**: 16kHz - 48kHz support
- **Channel Support**: Mono and stereo output
- **Bit Depth**: 16-bit PCM processing
- **Volume Control**: Hardware and software volume management
- **Format Negotiation**: Dynamic format selection based on capabilities

## Threading Model and Message Processing

### Thread Architecture
```c
typedef struct {
   const char *   name;        // Thread identification
   pthread_t      id;          // Thread handle  
   bool           running;     // Execution status
} xraudio_thread_t;
```

#### Main Processing Thread
- **Audio Frame Processing**: 20ms frame groups with real-time constraints
- **Plugin Coordination**: Algorithm execution and data flow management
- **State Machine Management**: Input/output session lifecycle
- **Event Callback Dispatch**: Asynchronous event notification

#### Resource Management Thread  
- **Multi-process Coordination**: Shared resource allocation across processes
- **Priority-based Scheduling**: High/medium/low priority request handling
- **Resource Grant/Revoke**: Dynamic resource management with notifications
- **Capability Negotiation**: Hardware and software feature enablement

### Message Queue System

#### Message Types
```c
typedef enum {
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_START       = 2,   // Start recording session
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_START         = 7,   // Start playback session
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT             = 11,  // Keyword detection
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_POWER_MODE         = 20,  // Power mode changes
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE       = 21,  // Privacy mode control
   // ... additional message types for all operations
} xraudio_main_queue_msg_type_t;
```

#### Synchronous vs Asynchronous Operations
- **Synchronous Mode**: Direct API calls with immediate completion (callback = NULL)
- **Asynchronous Mode**: Message queue dispatch with callback notification
- **Hybrid Operations**: Some APIs support both modes based on callback parameter

## Plugin Integration Architecture

### Plugin Framework Integration
The XR Audio component serves as the primary integration point for all audio plugins:

#### Hardware Abstraction Layer (HAL) Integration
```c
// HAL plugin integration from main object
typedef struct {
   xraudio_hal_plugin_api_t *        hal_plugin;          // Plugin API pointer
   xraudio_hal_obj_t                 hal_obj;             // HAL object instance
   xraudio_hal_input_obj_t           hal_input_obj;       // Input device object
   xraudio_hal_dsp_config_t          dsp_config;          // DSP configuration
} /* HAL context within xraudio_main_thread_params_t */;
```

#### Algorithm Plugin Integration
- **Keyword Detection (KWD)**: Wake-word detection with sensitivity control
- **End-of-Speech (EOS)**: Voice activity detection and session termination  
- **Dynamic Gain Adjustment (DGA)**: Automatic gain control and level management
- **Post-Processing (PPR)**: Audio enhancement algorithms (noise reduction, echo cancellation)
- **Signal Direction Finding (SDF)**: Beamforming and spatial processing
- **Output Volume Control (OVC)**: Advanced volume management

#### Plugin Loading and Management
- **Dynamic Discovery**: Plugin loading from multiple search paths
- **Graceful Fallbacks**: Operation continues with missing optional plugins
- **Version Compatibility**: Plugin interface version checking and negotiation
- **Error Isolation**: Plugin failures don't compromise core functionality

## Audio Format and Codec Support

### Supported Audio Formats
```c
// Input format constraints from xraudio.h
#define XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE      (16000)    // 16kHz default
#define XRAUDIO_INPUT_MIN_SAMPLE_RATE          (16000)    // 16kHz minimum  
#define XRAUDIO_INPUT_MAX_SAMPLE_RATE          (16000)    // 16kHz maximum
#define XRAUDIO_INPUT_MIN_SAMPLE_SIZE          (2)        // 16-bit minimum
#define XRAUDIO_INPUT_MAX_SAMPLE_SIZE          (4)        // 32-bit maximum
#define XRAUDIO_INPUT_MIN_CHANNEL_QTY          (1)        // Mono minimum
#define XRAUDIO_INPUT_MAX_CHANNEL_QTY          (4)        // 4-channel maximum

// Output format constraints  
#define XRAUDIO_OUTPUT_MIN_SAMPLE_RATE         (16000)    // 16kHz minimum
#define XRAUDIO_OUTPUT_MAX_SAMPLE_RATE         (48000)    // 48kHz maximum
#define XRAUDIO_OUTPUT_MIN_SAMPLE_SIZE         (2)        // 16-bit only
#define XRAUDIO_OUTPUT_MAX_SAMPLE_SIZE         (2)        // 16-bit only
#define XRAUDIO_OUTPUT_MIN_CHANNEL_QTY         (1)        // Mono minimum
#define XRAUDIO_OUTPUT_MAX_CHANNEL_QTY         (2)        // Stereo maximum
```

### Codec Implementation
- **ADPCM Codec**: Adaptive Differential PCM encoding/decoding (`adpcm/`)
- **Opus Codec**: Modern, low-latency audio codec (`opus/`)  
- **PCM Processing**: Native 16-bit and 32-bit linear PCM support
- **Container Formats**: WAV file generation and parsing utilities

### Format Negotiation
- **Capability Detection**: Dynamic format support based on hardware
- **Automatic Conversion**: Format translation between input and output
- **Quality Optimization**: Format selection based on quality requirements
- **Bandwidth Adaptation**: Codec selection based on network constraints

## Resource Management System

### Multi-Process Resource Coordination
```c
typedef struct {
   // Resource State
   bool                      resource_playback[XRAUDIO_RESOURCE_ID_OUTPUT_INVALID];
   bool                      resource_record[XRAUDIO_RESOURCE_ID_INPUT_INVALID];
   
   // Request Queue Management
   uint32_t                  resource_list_offset_head;   // Linked list head
   xraudio_resource_entry_t  resource_list[XRAUDIO_RESOURCE_LIST_QTY_MAX];
   
   // Hardware Capabilities  
   xraudio_hal_capabilities  capabilities;
   
   // Process Tracking
   uint32_t                  user_count;
   pid_t                     user_ids[XRAUDIO_USER_ID_MAX];
} xraudio_shared_mem_t;
```

#### Resource Request Lifecycle
1. **Resource Request**: Client requests input/output devices with priority
2. **Capability Check**: Verify hardware support for requested features
3. **Priority Queue**: Queue request based on priority and arrival order
4. **Resource Allocation**: Grant resources when available  
5. **Usage Monitoring**: Track resource usage and handle conflicts
6. **Resource Revocation**: Revoke resources for higher priority requests
7. **Resource Release**: Clean up when client no longer needs resources

#### Priority Management
```c
typedef enum {
   XRAUDIO_RESOURCE_PRIORITY_LOW     = 0,  // Background tasks
   XRAUDIO_RESOURCE_PRIORITY_MEDIUM  = 1,  // Normal operations
   XRAUDIO_RESOURCE_PRIORITY_HIGH    = 2,  // Critical operations (emergency calls)
   XRAUDIO_RESOURCE_PRIORITY_INVALID = 3,
} xraudio_resource_priority_t;
```

## Configuration and Initialization

### JSON Configuration System
- **Input Configuration**: Device parameters, format preferences, algorithm settings
- **Output Configuration**: Playback parameters, volume control, device selection
- **HAL Configuration**: Platform-specific hardware abstraction settings
- **Runtime Reconfiguration**: Dynamic parameter updates without restart

### Default Configuration
```json
// Example from xraudio_config_default.json
{
  "input": {
    "sample_rate": 16000,
    "sample_size": 2,  
    "channels": 1,
    "frame_group_qty": 1
  },
  "algorithms": {
    "keyword_detection": {
      "sensitivity": 0.0,
      "enabled": true
    },
    "end_of_speech": {
      "enabled": true,
      "timeout_initial": 5000,
      "timeout_end": 2000
    }
  }
}
```

### Initialization Sequence
1. **Object Creation**: Allocate main xraudio object and validate configuration
2. **Plugin Loading**: Discover and load available HAL and algorithm plugins  
3. **Thread Creation**: Launch main processing and resource management threads
4. **Shared Memory**: Initialize multi-process resource coordination
5. **HAL Initialization**: Initialize hardware abstraction layer
6. **Capability Detection**: Query and cache hardware capabilities
7. **Resource Management**: Enable resource request/grant system

## Error Handling And Diagnostics

### Result Code System
```c
typedef enum {
   XRAUDIO_RESULT_OK                   = 0,   // Success
   XRAUDIO_RESULT_ERROR_OBJECT         = 1,   // Invalid object
   XRAUDIO_RESULT_ERROR_INTERNAL       = 2,   // Internal error
   XRAUDIO_RESULT_ERROR_INPUT          = 4,   // Microphone error
   XRAUDIO_RESULT_ERROR_OUTPUT         = 3,   // Speaker error
   XRAUDIO_RESULT_ERROR_RESOURCE       = 17,  // Resource unavailable
   XRAUDIO_RESULT_ERROR_DISABLED       = 20,  // Feature disabled
   XRAUDIO_RESULT_ERROR_IN_USE         = 21,  // Resource busy
} xraudio_result_t;
```

### Diagnostic Capabilities
- **Internal Capture**: Raw audio capture for debugging and analysis
- **Statistics Collection**: Performance metrics and usage statistics
- **Audio File Analysis**: Capture and analyze audio streams to files
- **Plugin Monitoring**: Track plugin performance and error conditions
- **Resource Usage Tracking**: Monitor resource allocation and conflicts

### Error Recovery Mechanisms
- **Graceful Degradation**: Continue operation with reduced functionality
- **Automatic Retry**: Retry failed operations with exponential backoff
- **Plugin Fallbacks**: Use alternative plugins when primary plugins fail
- **Resource Cleanup**: Prevent resource leaks during error conditions
- **State Recovery**: Restore consistent state after error conditions

## Performance Characteristics

### Real-time Processing Constraints
- **Frame Period**: 20ms processing frames for real-time constraints
- **Latency Requirements**: Low-latency processing for interactive applications
- **CPU Utilization**: Configurable CPU utilization modes
- **Memory Management**: Pre-allocated buffers to minimize dynamic allocation
- **Thread Priority**: Real-time scheduling for audio processing threads

### Optimization Features
- **Atomic Operations**: Lock-free data structures for high-performance access
- **Frame Grouping**: Process multiple frames together to reduce overhead
- **Plugin Bypass**: Skip optional processing when not needed
- **Format Optimization**: Use most efficient format for hardware capabilities
- **Cache-Friendly Design**: Data structures optimized for cache locality

### Scalability
- **Multi-device Support**: Up to 3 input devices and 1 output device
- **Multi-channel**: Up to 4 input channels and 2 output channels  
- **Multi-process**: Shared resource management across processes
- **Plugin Architecture**: Extensible without core component changes

## Integration Patterns

### SDK Integration
The XR Audio component integrates with other SDK components through:
- **Speech Router Integration**: Audio stream routing to speech recognition
- **Voice VREX Integration**: Voice recognition and processing pipeline
- **Logger Integration**: Comprehensive logging and debugging support
- **Timestamp Integration**: Precise timing and synchronization
- **Message Queue Integration**: Inter-component communication

### Application Integration Patterns
```c
// Typical application integration sequence
xraudio_object_t audio_obj = xraudio_object_create(config);
xraudio_resource_request(audio_obj, input_device, output_device, priority, callback, param);
// Wait for resource grant notification
xraudio_open(audio_obj, power_mode, privacy_mode, input_device, output_device, &format);
xraudio_detect_keyword(audio_obj, keyword_callback, param);  // Start keyword detection
// Handle keyword detection events
xraudio_stream_to_pipe(audio_obj, source, pipes, &format, false, stream_callback, param);
// Process streaming audio data
xraudio_close(audio_obj);
xraudio_resource_release(audio_obj);
xraudio_object_destroy(audio_obj);
```

## Summary

The XR Audio component provides:

- **Comprehensive Audio Management**: Complete input/output processing with advanced features
- **Plugin-Based Architecture**: Extensible design supporting diverse hardware and algorithms
- **Multi-Process Resource Management**: Robust resource coordination across applications
- **Real-Time Processing**: Frame-based processing with performance optimization
- **Hardware Abstraction**: Clean separation between algorithm and platform code  
- **Asynchronous Operations**: Non-blocking APIs with callback-based event notification
- **Format Flexibility**: Support for multiple audio formats and codecs
- **Robust Error Handling**: Comprehensive error detection and recovery mechanisms
- **Diagnostic Capabilities**: Built-in debugging and analysis tools
- **SDK Integration**: Clean interfaces for integration with other voice SDK components

This component serves as the foundation for all audio processing within the XR Voice SDK, providing reliable, extensible, and high-performance audio functionality across diverse platforms and use cases.