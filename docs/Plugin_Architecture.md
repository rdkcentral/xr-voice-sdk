# XR Voice SDK - Plugin Architecture and Extension Points

## Overview

The XR Voice SDK implements a sophisticated plugin architecture that enables runtime extension of core functionality through dynamically loaded modules. This plugin system provides hardware abstraction, algorithm customization, and processing pipeline extension capabilities while maintaining performance and reliability.

## Plugin Architecture Principles

### Design Philosophy
1. **Hardware Abstraction** - Platform-specific implementations through standardized interfaces
2. **Algorithm Extensibility** - Pluggable audio processing and recognition algorithms
3. **Runtime Loading** - Dynamic plugin discovery and loading without SDK recompilation  
4. **Type Safety** - Strongly-typed plugin interfaces with version compatibility
5. **Performance Isolation** - Plugin boundaries minimize performance impact
6. **Graceful Degradation** - Optional plugins with fallback behavior

### Extension Point Strategy
- **Standardized Interfaces** - Common API patterns across plugin types
- **Version Management** - Plugin compatibility checking and version negotiation
- **Lifecycle Management** - Proper plugin initialization, operation, and cleanup
- **Error Isolation** - Plugin failures don't compromise SDK stability

## Core Plugin Framework

### Plugin Loading Architecture

#### Dynamic Library Loading
```c
#include <dlfcn.h>

// Plugin loading pattern used throughout SDK
void *vsdk_load_plugin_ffv_kwd(void) {
    void *handle = NULL;
    
    // Try video display version first
    handle = dlopen(so_path_vd, RTLD_NOW);
    if(handle == NULL) {
        // Fall back to middleware version
        handle = dlopen(so_path_mw, RTLD_NOW);
    }
    
    if(handle != NULL) {
        // Get plugin API entry point
        xraudio_kwd_plugin_api_get_t plugin_api_get = 
            (xraudio_kwd_plugin_api_get_t)dlsym(handle, "xraudio_kwd_plugin_api_get");
        
        if(plugin_api_get != NULL) {
            g_vsdk.kwd_plugin = (*plugin_api_get)();
        }
    }
    return handle;
}
```

#### Plugin Interface Pattern
```c
// Standard plugin API structure pattern
typedef struct {
    // Object lifecycle functions
    create_func_t        object_create;
    destroy_func_t       object_destroy;
    
    // Core functionality functions  
    process_func_t       process;
    configure_func_t     configure;
    
    // Utility and monitoring functions
    statistics_func_t    statistics_get;
    status_func_t        status_get;
} plugin_api_t;

// Plugin entry point function signature
typedef plugin_api_t *(*plugin_api_get_t)(void);
```

### Plugin Management System

#### Global Plugin Registry
```c
// From vsdk_private.h - SDK plugin interfaces
typedef struct {
    bool                      initialized;
    vsdk_ffv_plugin_handles_t ffv_plugins;        // Plugin handles
    
    // Plugin API pointers
    xraudio_hal_plugin_api_t *hal_plugin;         // Hardware abstraction
    xraudio_kwd_plugin_api_t *kwd_plugin;         // Keyword detection
    xraudio_eos_plugin_api_t *eos_plugin;         // End of speech
    xraudio_dga_plugin_api_t *dga_plugin;         // Dynamic gain adjustment
    xraudio_sdf_plugin_api_t *sdf_plugin;         // Signal direction finding
    xraudio_ovc_plugin_api_t *ovc_plugin;         // Output volume control
    xraudio_ppr_plugin_api_t *ppr_plugin;         // Post-processing
} vsdk_global_t;
```

#### Plugin Handle Management
```c
typedef struct {
    void *handle_ffv_hal;     // Hardware abstraction layer
    void *handle_ffv_kwd;     // Keyword detection
    void *handle_ffv_alg;     // Algorithm processing
    void *handle_ffv_sdf;     // Signal direction finding
    void *handle_ffv_ovc;     // Output volume control
    void *handle_ffv_ppr;     // Post-processing
} vsdk_ffv_plugin_handles_t;
```

## Plugin Types and Interfaces

### 1. Hardware Abstraction Layer (HAL) Plugin

#### Plugin Purpose
Provides platform-specific audio device integration and hardware abstraction.

#### Plugin Interface
```c
// From xraudio_hal.h
typedef struct {
    // Device management
    xraudio_hal_func_open_t                  open;
    xraudio_hal_func_close_t                 close;
    
    // Format negotiation  
    xraudio_hal_func_capabilities_t          capabilities;
    xraudio_hal_func_input_formats_t         input_formats;
    xraudio_hal_func_output_formats_t        output_formats;
    
    // Stream management
    xraudio_hal_func_input_open_t            input_open;
    xraudio_hal_func_input_close_t           input_close;
    xraudio_hal_func_output_open_t           output_open;
    xraudio_hal_func_output_close_t          output_close;
    
    // Audio processing
    xraudio_hal_func_input_read_t            input_read;
    xraudio_hal_func_output_write_t          output_write;
    
    // Control and monitoring
    xraudio_hal_func_input_mute_t            input_mute;
    xraudio_hal_func_output_volume_t         output_volume;
    xraudio_hal_func_thread_poll_t           thread_poll;
    
    // Status reporting
    xraudio_hal_func_status_t                status;
} xraudio_hal_plugin_api_t;
```

#### Capabilities System
```c
// HAL capability flags
#define XRAUDIO_CAPS_INPUT_NONE             (0x0000)
#define XRAUDIO_CAPS_INPUT_LOCAL            (0x0001)  // Local microphone support
#define XRAUDIO_CAPS_INPUT_SELECT           (0x0008)  // File descriptor selection
#define XRAUDIO_CAPS_INPUT_LOCAL_32_BIT     (0x0010)  // 32-bit PCM support
#define XRAUDIO_CAPS_INPUT_EOS_DETECTION    (0x0020)  // End-of-speech detection

#define XRAUDIO_CAPS_OUTPUT_NONE                (0x0000)
#define XRAUDIO_CAPS_OUTPUT_HAL_VOLUME_CONTROL  (0x0001)  // Hardware volume control  
#define XRAUDIO_CAPS_OUTPUT_OFFLOAD             (0x0002)  // Hardware offload support
#define XRAUDIO_CAPS_OUTPUT_DIRECT_PCM          (0x0004)  // Direct PCM processing
```

### 2. Keyword Detection (KWD) Plugin

#### Plugin Purpose
Implements keyword detection and wake-word processing algorithms.

#### Plugin Interface
```c
typedef struct {
    // Object lifecycle
    xraudio_kwd_func_object_create_t         object_create;
    xraudio_kwd_func_object_destroy_t        object_destroy;
    
    // Detection processing
    xraudio_kwd_func_detection_process_t     detection_process;
    xraudio_kwd_func_detection_reset_t       detection_reset;
    
    // Configuration management
    xraudio_kwd_func_sensitivity_set_t       sensitivity_set;
    xraudio_kwd_func_sensitivity_get_t       sensitivity_get;
    
    // Status and statistics
    xraudio_kwd_func_status_t                status;
    xraudio_kwd_func_statistics_t            statistics;
} xraudio_kwd_plugin_api_t;
```

### 3. Signal Direction Finding (SDF) Plugin

#### Plugin Purpose
Implements beamforming and signal direction analysis for microphone arrays.

#### Plugin Interface
```c
typedef struct {
    // Object management
    xraudio_sdf_func_object_create_t        object_create;
    xraudio_sdf_func_object_destroy_t       object_destroy;
    
    // Direction processing
    xraudio_sdf_func_focus_set_t            focus_set;
    xraudio_sdf_func_focus_update_t         focus_update;
    xraudio_sdf_func_signal_direction_get_t signal_direction_get;
    
    // Analytics
    xraudio_sdf_func_statistics_clear_t     statistics_clear;
    xraudio_sdf_func_statistics_print_t     statistics_print;
} xraudio_sdf_plugin_api_t;
```

#### SDF Processing Modes
```c
typedef enum {
    XRAUDIO_SDF_MODE_NONE              = 0,  // No direction finding
    XRAUDIO_SDF_MODE_KEYWORD_DETECTION = 1,  // Direction during keyword detection
    XRAUDIO_SDF_MODE_STRONGEST_SECTOR  = 2,  // Track strongest signal sector
    XRAUDIO_SDF_MODE_INVALID           = 3,
} xraudio_sdf_mode_t;
```

### 4. Output Volume Control (OVC) Plugin  

#### Plugin Purpose
Provides advanced audio output volume control and processing.

#### Plugin Interface
```c
typedef struct {
    // Volume control
    xraudio_ovc_func_volume_set_t           volume_set;
    xraudio_ovc_func_volume_get_t           volume_get;
    
    // Mute control
    xraudio_ovc_func_mute_set_t             mute_set;
    xraudio_ovc_func_mute_get_t             mute_get;
    
    // Advanced processing
    xraudio_ovc_func_process_t              process;
    xraudio_ovc_func_configure_t            configure;
    
    // Status monitoring
    xraudio_ovc_func_status_t               status;
} xraudio_ovc_plugin_api_t;
```

### 5. Post-Processing (PPR) Plugin

#### Plugin Purpose
Implements audio post-processing algorithms including echo cancellation, noise reduction, and enhancement.

#### Plugin Interface  
```c
typedef struct {
    // Processing pipeline
    xraudio_ppr_func_process_t              process;
    xraudio_ppr_func_configure_t            configure;
    
    // Algorithm control
    xraudio_ppr_func_algorithm_enable_t     algorithm_enable;
    xraudio_ppr_func_algorithm_disable_t    algorithm_disable;
    
    // Parameter tuning
    xraudio_ppr_func_parameter_set_t        parameter_set;
    xraudio_ppr_func_parameter_get_t        parameter_get;
    
    // Analytics and debugging
    xraudio_ppr_func_statistics_t           statistics;
    xraudio_ppr_func_debug_t                debug;
} xraudio_ppr_plugin_api_t;
```

### 6. End-of-Speech (EOS) Plugin

#### Plugin Purpose  
Detects end-of-speech conditions for voice activity detection and session management.

#### Plugin Interface
```c
typedef struct {
    // Detection processing
    xraudio_eos_func_process_t              process;
    xraudio_eos_func_reset_t                reset;
    
    // Configuration
    xraudio_eos_func_sensitivity_set_t      sensitivity_set;
    xraudio_eos_func_timeout_set_t          timeout_set;
    
    // Status reporting
    xraudio_eos_func_status_t               status;
    xraudio_eos_func_statistics_t           statistics;
} xraudio_eos_plugin_api_t;
```

### 7. Dynamic Gain Adjustment (DGA) Plugin

#### Plugin Purpose
Provides automatic gain control and dynamic range processing for audio inputs.

#### Plugin Interface
```c  
typedef struct {
    // Gain processing
    xraudio_dga_func_process_t              process;
    xraudio_dga_func_configure_t            configure;
    
    // Gain control
    xraudio_dga_func_gain_set_t             gain_set;
    xraudio_dga_func_gain_get_t             gain_get;
    
    // AGC functionality
    xraudio_dga_func_agc_enable_t           agc_enable;
    xraudio_dga_func_agc_configure_t        agc_configure;
    
    // Monitoring
    xraudio_dga_func_level_get_t            level_get;
    xraudio_dga_func_statistics_t           statistics;
} xraudio_dga_plugin_api_t;
```

## Plugin Loading and Discovery

### Plugin Search Strategy
```c
bool vsdk_load_plugin_ffv(vsdk_ffv_plugin_handles_t *handles) {
    bool hal_in_enabled = false;
    
    // Load plugins in dependency order
    handles->handle_ffv_hal = vsdk_load_plugin_ffv_hal(&g_vsdk.hal_out_enabled);
    if(handles->handle_ffv_hal != NULL) {
        hal_in_enabled = true;
        
        // Load dependent plugins only if HAL loaded successfully
        handles->handle_ffv_kwd = vsdk_load_plugin_ffv_kwd();
        handles->handle_ffv_alg = vsdk_load_plugin_ffv_alg(&handles->handle_ffv_ppr);
        handles->handle_ffv_sdf = vsdk_load_plugin_ffv_sdf();
        handles->handle_ffv_ovc = vsdk_load_plugin_ffv_ovc();
    }
    
    return hal_in_enabled;
}
```

### Plugin Path Resolution
The SDK searches for plugins in multiple locations with version-specific fallbacks:

1. **Video Display (VD) Version**: Platform-specific optimized plugins
2. **Middleware (MW) Version**: Generic fallback implementations  
3. **System Libraries**: Standard system plugin locations

### Plugin Dependency Management
- **Core Dependencies**: HAL plugin required for basic functionality
- **Optional Enhancements**: Algorithm plugins provide enhanced capabilities
- **Graceful Fallbacks**: Missing plugins don't prevent SDK operation

## Plugin Development Guidelines

### 1. Plugin Implementation Structure

#### Plugin Entry Point
```c
// Standard plugin entry point implementation
xraudio_example_plugin_api_t *xraudio_example_plugin_api_get(void) {
    static xraudio_example_plugin_api_t api = {
        .object_create    = example_object_create,
        .object_destroy   = example_object_destroy,
        .process         = example_process,
        .configure       = example_configure,
        .status          = example_status
    };
    
    return &api;
}
```

#### Plugin Object Pattern
```c
// Standard plugin object structure
typedef struct {
    uint32_t            identifier;     // Object validation
    plugin_state_t      state;          // Current state
    plugin_config_t     config;         // Configuration
    plugin_statistics_t stats;          // Runtime statistics
    // Plugin-specific data...
} plugin_object_t;

// Object lifecycle implementation
plugin_object_t *example_object_create(const plugin_config_t *config) {
    plugin_object_t *obj = malloc(sizeof(plugin_object_t));
    if(obj != NULL) {
        obj->identifier = PLUGIN_IDENTIFIER;
        obj->state = PLUGIN_STATE_INITIALIZED;
        memcpy(&obj->config, config, sizeof(plugin_config_t));
    }
    return obj;
}
```

### 2. Error Handling Patterns

#### Return Code Conventions
```c
typedef enum {
    PLUGIN_RESULT_SUCCESS = 0,      // Operation successful
    PLUGIN_RESULT_ERROR   = 1,      // Generic error
    PLUGIN_RESULT_INVALID = 2,      // Invalid parameters
    PLUGIN_RESULT_BUSY    = 3,      // Resource busy
    PLUGIN_RESULT_TIMEOUT = 4,      // Operation timeout
} plugin_result_t;
```

#### Error Recovery
- **Graceful Degradation**: Plugin failures don't crash SDK
- **Status Reporting**: Detailed error information through status APIs  
- **Recovery Actions**: Plugin restart or fallback mode activation
- **Logging Integration**: Plugin errors logged through SDK logging system

### 3. Performance Considerations

#### Real-Time Processing
```c
// Plugin processing constraints
#define PLUGIN_FRAME_PERIOD_MS     (20)    // 20ms processing frames
#define PLUGIN_MAX_LATENCY_MS      (5)     // Maximum processing latency
#define PLUGIN_BUFFER_SIZE_FRAMES  (4)     // Buffering for timing variations

// Real-time processing pattern
plugin_result_t plugin_process(plugin_object_t *obj, 
                              const int16_t *input, 
                              int16_t *output, 
                              uint32_t frame_size) {
    // Process audio frame within timing constraints
    // Return immediately on errors
    // Use lock-free algorithms where possible
    return PLUGIN_RESULT_SUCCESS;
}
```

#### Memory Management
- **Static Allocation**: Prefer static allocation for real-time paths
- **Buffer Reuse**: Minimize dynamic memory allocation during processing
- **Cache Efficiency**: Optimize data structures for cache locality
- **Resource Limits**: Respect memory constraints of target platforms

## Plugin Integration Patterns

### 1. Hardware Abstraction Integration

#### Audio Device Abstraction
```c
// HAL plugin integration example
xraudio_hal_plugin_api_t *hal = vsdk_hal_plugin_get();

if(hal != NULL && hal->input_open != NULL) {
    // Open audio input through HAL plugin
    xraudio_hal_input_obj_t input = hal->input_open(device_config);
    
    if(input != NULL) {
        // Use HAL for audio input operations
        hal->input_read(input, buffer, frame_size);
    }
}
```

#### Capability Negotiation
```c
// Check HAL capabilities before using features
uint32_t caps = hal->capabilities(device_id);

if(caps & XRAUDIO_CAPS_INPUT_LOCAL_32_BIT) {
    // Use 32-bit processing path
    configure_32bit_processing();
} else if(caps & XRAUDIO_CAPS_INPUT_LOCAL) {
    // Fall back to 16-bit processing  
    configure_16bit_processing();
}
```

### 2. Algorithm Pipeline Integration

#### Processing Chain Setup
```c
// Set up plugin processing chain
void setup_audio_processing_chain() {
    // Initialize plugins in processing order
    if(g_vsdk.dga_plugin) {
        dga_config_t dga_config = get_dga_configuration();
        dga_obj = g_vsdk.dga_plugin->object_create(&dga_config);
    }
    
    if(g_vsdk.ppr_plugin) {
        ppr_config_t ppr_config = get_ppr_configuration();
        ppr_obj = g_vsdk.ppr_plugin->object_create(&ppr_config);
    }
    
    if(g_vsdk.kwd_plugin) {
        kwd_config_t kwd_config = get_kwd_configuration();
        kwd_obj = g_vsdk.kwd_plugin->object_create(&kwd_config);
    }
}
```

#### Data Flow Processing
```c
// Process audio through plugin chain
void process_audio_frame(int16_t *audio_frame, uint32_t frame_size) {
    // Dynamic gain adjustment
    if(dga_obj && g_vsdk.dga_plugin->process) {
        g_vsdk.dga_plugin->process(dga_obj, audio_frame, frame_size);
    }
    
    // Post-processing (noise reduction, echo cancellation)
    if(ppr_obj && g_vsdk.ppr_plugin->process) {
        g_vsdk.ppr_plugin->process(ppr_obj, audio_frame, frame_size);
    }
    
    // Keyword detection
    if(kwd_obj && g_vsdk.kwd_plugin->detection_process) {
        kwd_result_t result = g_vsdk.kwd_plugin->detection_process(kwd_obj, 
                                                                  audio_frame, 
                                                                  frame_size);
        if(result.detected) {
            handle_keyword_detected(&result);
        }
    }
}
```

## Extension Point Framework

### 1. Custom Algorithm Integration

#### Algorithm Plugin Template
```c
// Custom algorithm plugin implementation
#include "xraudio_custom.h"

typedef struct {
    uint32_t identifier;
    // Custom algorithm state
} custom_algorithm_t;

custom_algorithm_t *custom_create(const custom_config_t *config) {
    // Initialize custom algorithm
}

plugin_result_t custom_process(custom_algorithm_t *obj,
                              const int16_t *input,
                              int16_t *output,
                              uint32_t samples) {
    // Implement custom processing
    return PLUGIN_RESULT_SUCCESS;
}

// Plugin API implementation
xraudio_custom_plugin_api_t *xraudio_custom_plugin_api_get(void) {
    static xraudio_custom_plugin_api_t api = {
        .object_create = custom_create,
        .object_destroy = custom_destroy,
        .process = custom_process,
        .configure = custom_configure
    };
    return &api;
}
```

### 2. Hardware Platform Integration

#### Platform-Specific HAL Implementation
```c
// Platform-specific HAL plugin
xraudio_hal_input_obj_t platform_input_open(const xraudio_hal_input_config_t *config) {
    platform_input_t *input = malloc(sizeof(platform_input_t));
    
    // Platform-specific device initialization
    input->device_fd = platform_audio_open(config->device_name);
    input->sample_rate = config->sample_rate;
    input->channels = config->channels;
    
    return input;
}

int32_t platform_input_read(xraudio_hal_input_obj_t obj, 
                           int16_t *buffer, 
                           uint32_t frame_size) {
    platform_input_t *input = (platform_input_t*)obj;
    
    // Platform-specific audio read implementation
    return platform_device_read(input->device_fd, buffer, frame_size);
}
```

### 3. Processing Pipeline Extensions

#### Custom Processing Stage
```c
// Custom processing stage plugin
typedef struct {
    uint32_t identifier;
    processing_config_t config;
    processing_state_t state;
} custom_processor_t;

plugin_result_t custom_audio_process(custom_processor_t *processor,
                                   const audio_frame_t *input,
                                   audio_frame_t *output) {
    // Implement custom audio processing algorithm
    // Examples: custom EQ, spatial audio, voice enhancement
    
    apply_custom_algorithm(input->data, output->data, 
                          input->sample_count, &processor->config);
    
    return PLUGIN_RESULT_SUCCESS;
}
```

## Plugin Debugging and Development Tools

### 1. Plugin Validation

#### Interface Validation
```c
// Plugin interface validation
bool validate_plugin_interface(const plugin_api_t *api) {
    if(api == NULL) return false;
    
    // Check required function pointers
    if(api->object_create == NULL) return false;
    if(api->object_destroy == NULL) return false;
    if(api->process == NULL) return false;
    
    // Validate optional function pointers
    return true;
}
```

#### Runtime Testing
```c
// Plugin runtime validation
plugin_result_t test_plugin_functionality(plugin_api_t *api) {
    // Create test object
    plugin_object_t *obj = api->object_create(&test_config);
    if(obj == NULL) return PLUGIN_RESULT_ERROR;
    
    // Test processing with known input
    int16_t test_input[TEST_FRAME_SIZE];
    int16_t test_output[TEST_FRAME_SIZE];
    
    generate_test_audio(test_input, TEST_FRAME_SIZE);
    plugin_result_t result = api->process(obj, test_input, test_output, TEST_FRAME_SIZE);
    
    // Validate output
    if(validate_output(test_output, TEST_FRAME_SIZE)) {
        result = PLUGIN_RESULT_SUCCESS;
    }
    
    api->object_destroy(obj);
    return result;
}
```

### 2. Performance Profiling

#### Plugin Performance Monitoring
```c
// Plugin performance measurement
typedef struct {
    uint64_t total_calls;
    uint64_t total_time_us;
    uint64_t min_time_us;
    uint64_t max_time_us;
} plugin_perf_stats_t;

void profile_plugin_call(plugin_api_t *api, plugin_object_t *obj,
                        const int16_t *input, int16_t *output, 
                        uint32_t samples, plugin_perf_stats_t *stats) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    api->process(obj, input, output, samples);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 + 
                         (end.tv_nsec - start.tv_nsec) / 1000;
    
    // Update statistics
    stats->total_calls++;
    stats->total_time_us += elapsed_us;
    if(elapsed_us < stats->min_time_us) stats->min_time_us = elapsed_us;
    if(elapsed_us > stats->max_time_us) stats->max_time_us = elapsed_us;
}
```

## Summary

The XR Voice SDK plugin architecture provides:

- **Comprehensive Extensibility**: Seven distinct plugin types covering all major SDK functions
- **Hardware Abstraction**: Clean separation between algorithm and platform-specific code
- **Runtime Flexibility**: Dynamic plugin loading with graceful fallback behavior
- **Performance Optimization**: Plugin interfaces designed for real-time processing requirements
- **Development Support**: Clear patterns and guidelines for plugin implementation
- **Robust Integration**: Thread-safe plugin interfaces with comprehensive error handling
- **Platform Portability**: Standardized interfaces supporting diverse hardware platforms

This plugin system enables the SDK to adapt to diverse deployment scenarios while maintaining performance, reliability, and maintainability across different hardware platforms and algorithmic requirements.