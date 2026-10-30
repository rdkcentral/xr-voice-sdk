# XR Audio Configuration Management and JSON Parsing Documentation

## Overview
The XR Audio component implements a comprehensive configuration management system using JSON-based configuration files and the Jansson JSON parsing library. The system provides hierarchical configuration organization, plugin-specific settings, and runtime configuration validation with fallback defaults.

## Configuration Architecture

### Hierarchical Configuration Structure
The configuration system follows a three-tier hierarchy:

```json
{
   "input": {
      "kwd": { /* Keyword Detection Configuration */ },
      "eos": { /* End-of-Speech Detection Configuration */ },
      "dga": { /* Dynamic Gain Adjustment Configuration */ },
      "sdf": { /* Spatial/Directional Filtering Configuration */ },
      "ppr": { /* Pre/Post Processing Configuration */ }
   },
   "output": {
      "eos": { /* Output EOS Configuration */ },
      "ovc": { /* Output Volume Control Configuration */ }
   },
   "hal": { /* Hardware Abstraction Layer Configuration */ }
}
```

### Default Configuration File
Located at [`xraudio_config_default.json`](../src/xr-audio/xraudio_config_default.json):

```json
{
   "input" : {
      "kwd" : {},
      "eos" : {},
      "dga" : {},
      "sdf" : {},
      "ppr" : {}
   },
   "output" : {
      "eos" : {},
      "ovc" : {}
   },
   "hal" : {}
}
```

## JSON Parsing Infrastructure

### Jansson Library Integration
The system uses the Jansson JSON library for parsing and manipulation:

```c
#include <jansson.h>

// Core JSON object structure embedded in xraudio objects
typedef struct {
    // ... other fields ...
    json_t *json_obj_input;   // Input configuration object
    json_t *json_obj_output;  // Output configuration object  
    json_t *json_obj_hal;     // HAL configuration object
    // ... other fields ...
} xraudio_obj_t;
```

### Configuration Object Creation and Management
Configuration objects are parsed and stored during XR Audio object creation:

```c
xraudio_object_t xraudio_object_create(const json_t *json_obj_xraudio_config) {
    xraudio_obj_t *obj = (xraudio_obj_t *)malloc(sizeof(xraudio_obj_t));
    
    if(NULL == json_obj_xraudio_config) {
        XLOGD_INFO("json_obj_xraudio_config is null, using defaults");
    } else {
        // Parse input configuration section
        obj->json_obj_input = json_object_get(json_obj_xraudio_config, JSON_OBJ_NAME_INPUT);
        if(NULL == obj->json_obj_input || !json_is_object(obj->json_obj_input)) {
            XLOGD_INFO("input object not found, using defaults");
            obj->json_obj_input = NULL;
        } else {
            json_incref(obj->json_obj_input);  // Increment reference count
        }

        // Parse output configuration section (if output enabled)
        if(obj->out_enabled) {
            obj->json_obj_output = json_object_get(json_obj_xraudio_config, JSON_OBJ_NAME_OUTPUT);
            if(NULL == obj->json_obj_output || !json_is_object(obj->json_obj_output)) {
                XLOGD_INFO("output object not found, using defaults");
                obj->json_obj_output = NULL;
            } else {
                json_incref(obj->json_obj_output);
            }
        }

        // Parse HAL configuration section
        obj->json_obj_hal = json_object_get(json_obj_xraudio_config, JSON_OBJ_NAME_HAL);
        if(NULL == obj->json_obj_hal || !json_is_object(obj->json_obj_hal)) {
            XLOGD_INFO("hal object not found, using defaults");
            obj->json_obj_hal = NULL;
        } else {
            json_incref(obj->json_obj_hal);
        }
    }
    
    return (xraudio_object_t)obj;
}
```

### Memory Management for JSON Objects
Proper reference counting ensures memory safety:

```c
void xraudio_object_destroy(xraudio_object_t object) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    // Decrement JSON object reference counts
    if(obj->json_obj_input != NULL) {
        json_decref(obj->json_obj_input);
        obj->json_obj_input = NULL;
    }
    if(obj->out_enabled && obj->json_obj_output != NULL) {
        json_decref(obj->json_obj_output);
        obj->json_obj_output = NULL;
    }
    if(obj->json_obj_hal != NULL) {
        json_decref(obj->json_obj_hal);
        obj->json_obj_hal = NULL;
    }
    
    free(obj);
}
```

## Plugin Configuration System

### Input Plugin Configuration Parsing
Each input plugin receives its specific configuration section:

```c
// EOS (End-of-Speech) Plugin Configuration
xraudio_input_object_t xraudio_input_object_create(/* ... */, json_t *json_obj_input) {
    json_t *jeos_config = NULL;
    
    if(NULL == json_obj_input) {
        XLOGD_INFO("json_obj_input is null, using defaults");
    } else {
        if(obj->eos_plugin != NULL) {
            jeos_config = json_object_get(json_obj_input, JSON_OBJ_NAME_INPUT_EOS);
            if(NULL == jeos_config) {
                XLOGD_INFO("EOS config not found, using defaults");
            } else if(!json_is_object(jeos_config)) {
                XLOGD_INFO("jeos_config is not object, using defaults");
                jeos_config = NULL;
            }
        }
        
        // PPR (Pre/Post Processing) Plugin Configuration
        if(obj->ppr_plugin != NULL) {
            jppr_config = json_object_get(json_obj_input, JSON_OBJ_NAME_INPUT_PPR);
            if(NULL == jppr_config) {
                XLOGD_INFO("PPR config not found, using defaults");
            } else if(!json_is_object(jppr_config)) {
                XLOGD_INFO("jppr_config is not object, using defaults");
                jppr_config = NULL;
            }
        }
    }
    
    // Create plugin objects with their specific configurations
    if(obj->eos_plugin != NULL) {
        obj->obj_eos = obj->eos_plugin->object_create(false, jeos_config);
    }
    if(obj->ppr_plugin != NULL) {
        obj->obj_ppr = obj->ppr_plugin->object_create(jeos_config, jppr_config);
    }
}
```

### Keyword Detection (KWD) Plugin Configuration
```c
// KWD Plugin initialization in main thread
void xraudio_msg_detect(xraudio_thread_state_t *state, void *msg) {
    json_t *jkwd_config = NULL;
    
    if(state->params.json_obj_input != NULL) {
        jkwd_config = json_object_get(state->params.json_obj_input, JSON_OBJ_NAME_INPUT_KWD);
        if(jkwd_config != NULL) {
            if(!json_is_object(jkwd_config)) {
                XLOGD_WARN("jkwd_config is not an object, using defaults");
                jkwd_config = NULL;
            }
        }
    }
    
    // Initialize KWD with configuration
    if(state->params.kwd_plugin != NULL) {
        state->kwd.obj = state->params.kwd_plugin->object_create(state->params.hal_obj, 
                                                                 jkwd_config, 
                                                                 &state->kwd.config);
    }
}
```

### DGA (Dynamic Gain Adjustment) Plugin Configuration
```c
// DGA Plugin configuration parsing
void configure_dga_plugin(xraudio_thread_state_t *state) {
    json_t *jdga_config = NULL;
    
    if(state->params.json_obj_input != NULL) {
        jdga_config = json_object_get(state->params.json_obj_input, JSON_OBJ_NAME_INPUT_DGA);
        if(jdga_config != NULL) {
            if(!json_is_object(jdga_config)) {
                XLOGD_WARN("jdga_config is not an object, using defaults");
                jdga_config = NULL;
            }
        }
    }
    
    // Initialize DGA with configuration
    if(state->params.dga_plugin != NULL) {
        state->dga.obj = state->params.dga_plugin->object_create(jdga_config);
    }
}
```

## HAL Configuration Management

### HAL Plugin Initialization with Configuration
```c
// HAL plugin receives configuration during initialization
xraudio_hal_plugin_api_t *hal_plugin = vsdk_hal_plugin_get();
if(hal_plugin != NULL) {
    // Initialize HAL with JSON configuration
    hal_plugin->init(obj->json_obj_hal);
    
    // Retrieve DSP configuration after initialization
    hal_plugin->dsp_config_get(&g_xraudio_process.dsp_config);
}
```

### DSP Configuration Structure
The HAL provides DSP configuration information:

```c
typedef struct {
    bool    ppr_enabled;                    // Pre/Post Processing enabled
    bool    dga_enabled;                    // Dynamic Gain Adjustment enabled  
    bool    eos_enabled;                    // End-of-Speech detection enabled
    uint8_t input_asr_max_channel_qty;      // Max ASR input channels
    uint8_t input_kwd_max_channel_qty;      // Max KWD input channels
    float   aop_adjust;                     // Acoustic Overload Point adjustment
    bool    dsp_output_override_enable;     // DSP output override flag
} xraudio_hal_dsp_config_t;

// Global process DSP configuration
static xraudio_process_t g_xraudio_process = {
    .dsp_config = {
        .ppr_enabled = false,
        .dga_enabled = false,
        .eos_enabled = false,
        .input_kwd_max_channel_qty = 0,
        .input_asr_max_channel_qty = 0
    },
    // ... other fields ...
};
```

### Device Configuration Structure
Hardware-specific configuration for input devices:

```c
typedef struct {
    uint32_t                       fifo_size;           // Input FIFO buffer size
    xraudio_power_mode_t          power_mode;          // Power management mode
    xraudio_stream_latency_mode_t latency_mode;        // Latency optimization mode
    bool                          privacy_mode;        // Privacy mode enabled
    bool                          eos_detection_enable;  // EOS detection enable
    bool                          dga_enable;          // DGA enable
    float                         aop_adjust;          // AOP adjustment value
    uint32_t                      stream_time_minimum; // Minimum stream time
    uint32_t                      timeout_input_active;// Input timeout
    uint32_t                      timeout_input_connect;// Connection timeout
} xraudio_device_input_configuration_t;
```

## Configuration Validation and Error Handling

### Input Validation Pattern
```c
// Standard configuration validation sequence
json_t *parse_and_validate_config(json_t *parent_config, const char *section_name) {
    json_t *section_config = NULL;
    
    if(parent_config != NULL) {
        section_config = json_object_get(parent_config, section_name);
        if(section_config != NULL) {
            if(!json_is_object(section_config)) {
                XLOGD_WARN("Configuration section '%s' is not an object, using defaults", section_name);
                return NULL;  // Use defaults
            }
            return section_config;  // Valid configuration
        } else {
            XLOGD_INFO("Configuration section '%s' not found, using defaults", section_name);
        }
    }
    
    return NULL;  // Use defaults
}
```

### Graceful Degradation with Defaults
The system provides robust fallback behavior:

1. **Missing Configuration File**: Uses compiled-in defaults
2. **Invalid JSON Syntax**: Logs error and uses defaults
3. **Missing Configuration Sections**: Uses per-plugin defaults
4. **Invalid Configuration Types**: Validates and falls back to defaults
5. **Plugin Unavailable**: Disables feature gracefully

### Error Logging and Diagnostics
```c
// Comprehensive error reporting
void log_configuration_status(xraudio_obj_t *obj) {
    XLOGD_INFO("Configuration Status:");
    XLOGD_INFO("  Input Config: %s", (obj->json_obj_input != NULL) ? "Loaded" : "Using Defaults");
    XLOGD_INFO("  Output Config: %s", (obj->json_obj_output != NULL) ? "Loaded" : "Using Defaults");
    XLOGD_INFO("  HAL Config: %s", (obj->json_obj_hal != NULL) ? "Loaded" : "Using Defaults");
    
    if(obj->json_obj_input != NULL) {
        XLOGD_DEBUG("Input configuration object size: %zu", json_object_size(obj->json_obj_input));
    }
}
```

## Runtime Configuration Updates

### Dynamic Parameter Updates
Some configuration parameters can be updated at runtime:

```c
// Runtime capture parameter updates
xraudio_result_t xraudio_internal_capture_params_set(xraudio_object_t object, 
                                                      xraudio_internal_capture_params_t *params) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    // Validate new parameters
    if(!params->enable) {
        XLOGD_INFO("Internal capture disabled");
    } else {
        if(params->file_qty_max == 0 || params->file_size_max < 4096) {
            XLOGD_ERROR("Invalid params - file qty max <%u> file size max <%u>", 
                        params->file_qty_max, params->file_size_max);
            return XRAUDIO_RESULT_ERROR_PARAMS;
        }
        
        // Validate directory path
        struct stat stats;
        if(stat(params->dir_path, &stats) < 0 || !S_ISDIR(stats.st_mode)) {
            XLOGD_ERROR("Invalid directory path <%s>", params->dir_path);
            return XRAUDIO_RESULT_ERROR_PARAMS;
        }
    }
    
    // Update configuration
    obj->internal_capture_params = *params;
    
    // Send update to main thread if system is running
    if(obj->opened) {
        xraudio_main_queue_msg_capture_params_set_t msg;
        msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_PARAMS_SET;
        msg.capture_params = obj->internal_capture_params;
        msg.curtail_enabled = obj->curtail_enabled;
        
        queue_msg_push(obj->msgq_main, (const char*)&msg, sizeof(msg));
    }
    
    return XRAUDIO_RESULT_OK;
}
```

## Configuration Integration Points

### Plugin Interface Configuration
Each plugin type has a standardized configuration interface:

```c
// Generic plugin configuration pattern
typedef plugin_object_t (*plugin_func_object_create_t)(const json_t *config);

// EOS Plugin Configuration Interface
typedef xraudio_eos_object_t (*xraudio_eos_func_object_create_t)(bool signal_level_only, 
                                                                  const json_t *config);

// HAL Plugin Configuration Interface  
typedef bool (*xraudio_hal_func_init_t)(json_t *obj_config);
```

### Configuration Inheritance and Overrides
1. **System Defaults**: Compiled-in baseline configuration
2. **Default JSON File**: File-based default overrides
3. **Runtime Configuration**: Application-provided JSON configuration
4. **Dynamic Updates**: Runtime parameter modifications

### Multi-Process Configuration Sharing
Configuration objects can be shared across processes through:
- **Shared Memory**: Configuration data in process-shared memory segments
- **Message Passing**: Configuration updates via message queues
- **File Synchronization**: Configuration file monitoring and reloading

## Performance and Memory Considerations

### Configuration Loading Overhead
- **Parse Time**: JSON parsing occurs once during object creation
- **Memory Usage**: Configuration objects maintained throughout object lifetime
- **Reference Counting**: Jansson handles memory management automatically
- **Validation Cost**: O(1) configuration section lookups during initialization

### Memory Optimization Strategies
```c
// Efficient configuration reference management
void optimize_configuration_memory(xraudio_obj_t *obj) {
    // Only maintain references to actively used configuration sections
    if(obj->eos_plugin == NULL && obj->json_obj_input != NULL) {
        json_t *eos_config = json_object_get(obj->json_obj_input, JSON_OBJ_NAME_INPUT_EOS);
        if(eos_config != NULL) {
            json_object_del(obj->json_obj_input, JSON_OBJ_NAME_INPUT_EOS);
        }
    }
}
```

This configuration management system provides flexible, robust, and extensible configuration handling while maintaining backward compatibility and graceful error recovery.