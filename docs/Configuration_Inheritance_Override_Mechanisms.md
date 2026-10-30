# Configuration Inheritance and Override Mechanisms

## Overview

The XR Voice SDK implements a sophisticated multi-layered configuration system that enables flexible configuration management across all components. This document details the configuration inheritance hierarchy, override mechanisms, and cross-component configuration propagation patterns used throughout the SDK.

## Configuration Architecture Overview

### Hierarchical Configuration Model

```
┌─ Application Configuration Layer ────────────────────────┐
│  • Runtime API configuration updates                    │
│  • Application-specific overrides                       │
│  • Dynamic configuration modifications                   │
└─────────────────┬────────────────────────────────────────┘
                  │ (Highest Priority)
┌─ Environment Configuration Layer ────────────────────────┐
│  • Environment variable overrides                       │
│  • System-level configuration                           │
│  • Deployment-specific settings                         │  
└─────────────────┬────────────────────────────────────────┘
                  │
┌─ Component Configuration Layer ───────────────────────────┐
│  • Component-specific JSON files                        │
│  • Default operational parameters                       │
│  • Protocol and feature configurations                  │
└─────────────────┬────────────────────────────────────────┘
                  │
┌─ Built-in Default Layer ─────────────────────────────────┐
│  • Compiled-in minimal configuration                    │
│  • Fallback values for critical parameters              │
│  • Emergency operational defaults                       │
└──────────────────────────────────────────────────────────┘
                  (Lowest Priority)
```

## Configuration Loading and Inheritance Process

### 1. System Initialization Configuration Loading

The SDK follows a systematic configuration loading process during system initialization:

#### Stage 1: Built-in Defaults Establishment
Located in component initialization code:

```c
// XRAudio component default initialization
static xraudio_config_t g_xraudio_config_default = {
    .input = {
        .sample_rate = 16000,
        .channels = 1,
        .bit_depth = 16,
        .buffer_size = 320  // 20ms at 16kHz
    },
    .output = {
        .sample_rate = 16000,
        .channels = 1,
        .bit_depth = 16
    },
    .processing = {
        .frame_size = 320,
        .privacy_mode = false,
        .debug_enabled = false
    }
};
```

#### Stage 2: JSON Configuration File Loading
Each component loads its default JSON configuration:

```c
// Configuration file loading with inheritance
bool xrsr_config_load_defaults(xrsr_config_t *config) {
    // Load base configuration from JSON
    if(!json_config_load("xrsr_config_default.json", &base_config)) {
        // Fall back to compiled defaults
        memcpy(config, &g_xrsr_config_default, sizeof(xrsr_config_t));
    }
    
    // Apply configuration inheritance rules
    xrsr_config_apply_inheritance(config, &base_config);
    
    return true;
}
```

#### Stage 3: Environment Variable Override Application
Environment variables override JSON configuration values:

```c
// Environment variable override processing
void xrsr_config_apply_env_overrides(xrsr_config_t *config) {
    char *env_value;
    
    // WebSocket debug mode override
    if((env_value = getenv("XRSR_WS_DEBUG")) != NULL) {
        config->ws.debug = (strcasecmp(env_value, "true") == 0);
    }
    
    // Timeout configuration overrides
    if((env_value = getenv("XRSR_FPM_TIMEOUT_CONNECT")) != NULL) {
        config->ws.fpm.timeout_connect = atoi(env_value);
    }
    
    // Power mode configuration overrides
    if((env_value = getenv("XRSR_POWER_MODE")) != NULL) {
        if(strcmp(env_value, "low") == 0) {
            // Apply low power mode configuration template
            xrsr_config_apply_lpm_defaults(config);
        }
    }
}
```

#### Stage 4: Runtime API Configuration Updates
Applications can override configuration through API calls:

```c
// Runtime configuration update API
xrsr_result_t xrsr_config_update(xrsr_obj_t obj, const xrsr_config_t *config) {
    xrsr_main_t *main = (xrsr_main_t *)obj;
    
    // Validate configuration parameters
    if(!xrsr_config_validate(config)) {
        return XRSR_RESULT_ERROR_INVALID_PARAMS;
    }
    
    // Apply configuration updates with inheritance
    xrsr_config_merge(&main->config, config);
    
    // Propagate configuration changes to active sessions
    xrsr_config_propagate_updates(main, config);
    
    return XRSR_RESULT_OK;
}
```

## Cross-Component Configuration Propagation

### Configuration Message Passing

The SDK uses a message-based system for propagating configuration changes across components:

#### Configuration Update Messages
Located in [`xrsr_private.h`](../src/xr-speech-router/xrsr_private.h):

```c
// Configuration update message types
typedef enum {
    xrsr_msg_config_update,           // General configuration update
    xrsr_msg_power_mode_update,       // Power mode configuration change
    xrsr_msg_debug_config_update,     // Debug configuration change
    xrsr_msg_timeout_config_update,   // Timeout parameter updates
    xrsr_msg_privacy_mode_update      // Privacy mode configuration
} xrsr_msg_type_t;

// Configuration update message structure
typedef struct {
    xrsr_msg_type_t  type;
    uint32_t         component_mask;   // Target components for update
    union {
        xrsr_config_t            general_config;
        xrsr_power_mode_config_t power_config;
        xrsr_debug_config_t      debug_config;
        xrsr_timeout_config_t    timeout_config;
        xrsr_privacy_config_t    privacy_config;
    } config;
} xrsr_config_msg_t;
```

#### Configuration Propagation Implementation
```c
// Propagate configuration changes to all active components
void xrsr_config_propagate_updates(xrsr_main_t *main, const xrsr_config_t *config) {
    xrsr_config_msg_t msg;
    
    // Propagate to XRAudio component
    if(config->xraudio_updated) {
        msg.type = xrsr_msg_config_update;
        msg.component_mask = XRSR_COMPONENT_XRAUDIO;
        msg.config.general_config = config->xraudio;
        
        xr_mq_push(main->msgq_xraudio, (const char *)&msg, sizeof(msg));
    }
    
    // Propagate to protocol handlers
    if(config->protocol_updated) {
        xrsr_protocol_config_update(main->protocol_http, &config->http);
        xrsr_protocol_config_update(main->protocol_ws, &config->ws);
        xrsr_protocol_config_update(main->protocol_sdt, &config->sdt);
    }
}
```

### Component Configuration Interfaces

#### XRAudio Configuration Integration
Located in [`xraudio.c`](../src/xr-audio/xraudio.c):

```c
// XRAudio configuration update reception
void xraudio_config_update_handler(xraudio_obj_t obj, 
                                   const xraudio_config_t *config,
                                   xraudio_config_mask_t update_mask) {
    xraudio_main_t *main = (xraudio_main_t *)obj;
    
    // Apply configuration updates with validation
    if(update_mask & XRAUDIO_CONFIG_INPUT) {
        xraudio_input_config_update(&main->input, &config->input);
    }
    
    if(update_mask & XRAUDIO_CONFIG_OUTPUT) {
        xraudio_output_config_update(&main->output, &config->output);
    }
    
    if(update_mask & XRAUDIO_CONFIG_PRIVACY) {
        xraudio_privacy_mode_update(main, config->privacy_mode);
    }
}
```

#### XRSR Protocol Configuration Integration
```c
// Protocol-specific configuration updates
void xrsr_ws_config_update(xrsr_state_ws_t *ws, 
                          const xrsr_ws_config_t *config) {
    // Update timeout configurations
    ws->timeout_connect = config->timeout_connect;
    ws->timeout_inactivity = config->timeout_inactivity;
    ws->timeout_session = config->timeout_session;
    
    // Update connection parameters
    ws->ipv4_fallback = config->ipv4_fallback;
    ws->backoff_delay = config->backoff_delay;
    
    // Apply changes to active connections
    if(ws->obj_conn != NULL) {
        nopoll_conn_set_timeout(ws->obj_conn, ws->timeout_connect);
    }
}
```

## Configuration Override Mechanisms

### 1. Environment Variable Override System

#### Supported Environment Variables

##### Global SDK Configuration
```bash
# SDK-wide configuration
export VSDK_DEBUG=true              # Enable SDK-wide debugging
export VSDK_LOG_LEVEL=DEBUG         # Set global log level
export VSDK_CONFIG_FILE=/path/config.json  # Override config file path
```

##### XRAudio Configuration Overrides
```bash
# Audio processing configuration
export XRAUDIO_SAMPLE_RATE=48000    # Override sample rate
export XRAUDIO_CHANNELS=2           # Override channel count
export XRAUDIO_PRIVACY_MODE=true    # Enable privacy mode
export XRAUDIO_DEBUG=true           # Enable XRAudio debugging
export XRAUDIO_HAL_DEBUG=true       # Enable HAL debugging
```

##### XRSR Configuration Overrides
```bash
# Speech router configuration
export XRSR_HTTP_DEBUG=false        # Disable HTTP debugging
export XRSR_WS_DEBUG=true           # Enable WebSocket debugging
export XRSR_POWER_MODE=low          # Set power mode
export XRSR_TIMEOUT_CONNECT=5000    # Override connection timeout
export XRSR_BACKOFF_DELAY=100       # Override retry delay
```

##### Logger Configuration Overrides
```bash
# Logging configuration
export RDKX_LOGGER_ANSI_COLOR=false # Disable ANSI colors
export XLOG_LEVEL_XRAUDIO=TRACE     # Set XRAudio log level
export XLOG_LEVEL_XRSR=DEBUG        # Set XRSR log level
export XLOG_OUTPUT_FILE=/var/log/vsdk.log  # Set log output file
```

#### Environment Variable Processing
```c
// Environment variable override implementation
static const struct {
    const char *env_var;
    size_t config_offset;
    config_type_t type;
    config_validator_t validator;
} g_env_var_mappings[] = {
    {"XRSR_WS_DEBUG",           offsetof(xrsr_config_t, ws.debug),           
     CONFIG_TYPE_BOOL,          xrsr_validate_bool},
    {"XRSR_FPM_TIMEOUT_CONNECT", offsetof(xrsr_config_t, ws.fpm.timeout_connect), 
     CONFIG_TYPE_INT,           xrsr_validate_timeout},
    {"XRSR_LPM_TIMEOUT_CONNECT", offsetof(xrsr_config_t, ws.lpm.timeout_connect), 
     CONFIG_TYPE_INT,           xrsr_validate_timeout},
    // ... additional mappings
};

void xrsr_config_apply_env_overrides(xrsr_config_t *config) {
    for(int i = 0; i < ARRAY_SIZE(g_env_var_mappings); i++) {
        const char *env_value = getenv(g_env_var_mappings[i].env_var);
        if(env_value != NULL) {
            if(g_env_var_mappings[i].validator(env_value)) {
                void *config_field = ((char*)config) + g_env_var_mappings[i].config_offset;
                config_set_value(config_field, g_env_var_mappings[i].type, env_value);
            }
        }
    }
}
```

### 2. Runtime Configuration Override System

#### Configuration Update APIs

##### SDK-Level Configuration Updates
```c
// High-level SDK configuration update
vsdk_result_t vsdk_config_update(vsdk_obj_t obj, 
                                 const vsdk_config_t *config,
                                 vsdk_config_mask_t update_mask) {
    vsdk_main_t *main = (vsdk_main_t *)obj;
    
    // Validate configuration parameters
    if(!vsdk_config_validate(config, update_mask)) {
        return VSDK_RESULT_INVALID_PARAMS;
    }
    
    // Apply updates to individual components
    if(update_mask & VSDK_CONFIG_AUDIO) {
        xraudio_config_update(main->xraudio_obj, &config->xraudio, 
                             XRAUDIO_CONFIG_ALL);
    }
    
    if(update_mask & VSDK_CONFIG_SPEECH_ROUTER) {
        xrsr_config_update(main->xrsr_obj, &config->xrsr);
    }
    
    // Propagate cross-component configuration dependencies
    vsdk_config_propagate_cross_dependencies(main, config, update_mask);
    
    return VSDK_RESULT_OK;
}
```

##### Component-Specific Configuration Updates
```c
// XRAudio configuration update
xraudio_result_t xraudio_config_update_privacy_mode(xraudio_obj_t obj, 
                                                    bool privacy_mode) {
    xraudio_main_t *main = (xraudio_main_t *)obj;
    
    // Update configuration
    main->config.privacy_mode = privacy_mode;
    
    // Propagate to hardware abstraction layer
    if(main->hal.privacy_mode != NULL) {
        main->hal.privacy_mode(main->hal_obj, privacy_mode);
    }
    
    // Notify other components
    xraudio_notify_privacy_mode_change(main, privacy_mode);
    
    return XRAUDIO_RESULT_OK;
}
```

#### Session-Specific Configuration Overrides
```c
// Session-specific configuration (per voice interaction session)
xrsr_result_t xrsr_session_config_override(xrsr_obj_t obj,
                                          const xrsr_session_config_t *session_config) {
    // Create session with specific configuration overrides
    xrsr_session_t *session = xrsr_session_create(obj);
    
    // Apply session-specific configurations
    session->timeout_connect = session_config->timeout_connect;
    session->retry_policy = session_config->retry_policy;
    session->protocol_preference = session_config->protocol_preference;
    
    // Override inherits from global configuration for unspecified parameters
    xrsr_session_apply_config_inheritance(session, obj->global_config);
    
    return XRSR_RESULT_OK;
}
```

## Configuration Validation and Error Handling

### Configuration Validation Framework

#### Parameter Validation Rules
```c
// Configuration parameter validation
typedef struct {
    const char *parameter_name;
    config_value_type_t type;
    union {
        struct { int min, max; } int_range;
        struct { float min, max; } float_range;
        struct { const char **valid_values; } enum_values;
        struct { bool (*validator)(const char *); } custom_func;
    } validation;
} config_validation_rule_t;

// Validation rules for XRSR configuration
static const config_validation_rule_t g_xrsr_validation_rules[] = {
    {
        .parameter_name = "ws.fpm.timeout_connect",
        .type = CONFIG_TYPE_INT,
        .validation.int_range = { .min = 500, .max = 10000 }
    },
    {
        .parameter_name = "ws.debug",
        .type = CONFIG_TYPE_BOOL,
        .validation.custom_func = { xrsr_validate_debug_bool }
    },
    // ... additional validation rules
};
```

#### Configuration Error Recovery
```c
// Configuration error recovery mechanisms
bool xrsr_config_validate_and_repair(xrsr_config_t *config) {
    bool repair_needed = false;
    
    // Validate timeout parameters
    if(config->ws.fmp.timeout_connect < 500) {
        XLOGD_WARN("XRSR", "Invalid timeout_connect %d, using default 2000", 
                  config->ws.fmp.timeout_connect);
        config->ws.fmp.timeout_connect = 2000;
        repair_needed = true;
    }
    
    // Validate power mode consistency
    if(config->ws.lpm.timeout_connect < config->ws.fpm.timeout_connect) {
        XLOGD_WARN("XRSR", "LPM timeout shorter than FPM, adjusting");
        config->ws.lpm.timeout_connect = config->ws.fpm.timeout_connect * 2;
        repair_needed = true;
    }
    
    return repair_needed;
}
```

### Configuration Change Notification System

#### Configuration Change Events
```c
// Configuration change notification callbacks
typedef struct {
    void (*on_config_changed)(void *user_data, 
                             const char *component,
                             const char *parameter,
                             const void *old_value,
                             const void *new_value);
    void (*on_config_validation_failed)(void *user_data,
                                       const char *component,
                                       const char *parameter,
                                       const char *error_message);
} xrsr_config_callbacks_t;

// Register for configuration change notifications
void xrsr_config_register_callbacks(xrsr_obj_t obj, 
                                   const xrsr_config_callbacks_t *callbacks,
                                   void *user_data) {
    xrsr_main_t *main = (xrsr_main_t *)obj;
    main->config_callbacks = *callbacks;
    main->config_callback_user_data = user_data;
}
```

## Configuration Templates and Profiles

### Predefined Configuration Profiles

#### Development Configuration Profile
```c
// Development configuration template
static const xrsr_config_t g_dev_config_template = {
    .http = {
        .debug = true,
        .timeout_connect = 2000,
        .retry_count = 3
    },
    .ws = {
        .debug = true,
        .fpm = {
            .timeout_connect = 2000,
            .timeout_inactivity = 5000,
            .backoff_delay = 50
        }
    },
    .logging = {
        .level = XLOG_LEVEL_DEBUG,
        .ansi_color = true
    }
};
```

#### Production Configuration Profile  
```c
// Production configuration template
static const xrsr_config_t g_prod_config_template = {
    .http = {
        .debug = false,
        .timeout_connect = 5000,
        .retry_count = 5
    },
    .ws = {
        .debug = false,
        .fpm = {
            .timeout_connect = 5000,
            .timeout_inactivity = 15000,
            .backoff_delay = 100
        }
    },
    .logging = {
        .level = XLOG_LEVEL_INFO,
        .ansi_color = false
    }
};
```

#### Low Power Configuration Profile
```c
// Low power configuration template  
static const xrsr_config_t g_low_power_config_template = {
    .ws = {
        .lpm = {
            .timeout_connect = 15000,
            .timeout_inactivity = 30000,
            .timeout_session = 20000,
            .connect_check_interval = 200,
            .backoff_delay = 500
        }
    },
    .xraudio = {
        .low_power_mode = true,
        .reduced_processing = true
    }
};
```

### Configuration Profile Application
```c
// Apply configuration profile
xrsr_result_t xrsr_config_apply_profile(xrsr_obj_t obj, 
                                       xrsr_config_profile_t profile) {
    xrsr_main_t *main = (xrsr_main_t *)obj;
    const xrsr_config_t *template_config;
    
    switch(profile) {
        case XRSR_CONFIG_PROFILE_DEVELOPMENT:
            template_config = &g_dev_config_template;
            break;
        case XRSR_CONFIG_PROFILE_PRODUCTION:
            template_config = &g_prod_config_template;
            break;
        case XRSR_CONFIG_PROFILE_LOW_POWER:
            template_config = &g_low_power_config_template;
            break;
        default:
            return XRSR_RESULT_ERROR_INVALID_PARAMS;
    }
    
    // Merge template with existing configuration
    xrsr_config_merge(&main->config, template_config);
    
    // Propagate changes to active components
    xrsr_config_propagate_updates(main, &main->config);
    
    return XRSR_RESULT_OK;
}
```

## Configuration Persistence and State Management

### Configuration State Persistence

#### Configuration Backup and Restore
```c
// Save current configuration for persistence
xrsr_result_t xrsr_config_save_state(xrsr_obj_t obj, const char *state_file) {
    xrsr_main_t *main = (xrsr_main_t *)obj;
    
    // Serialize current configuration to JSON
    json_t *config_json = xrsr_config_serialize(&main->config);
    
    // Write to persistent storage
    if(json_dump_file(config_json, state_file, JSON_INDENT(2)) != 0) {
        json_decref(config_json);
        return XRSR_RESULT_ERROR_FILE_WRITE;
    }
    
    json_decref(config_json);
    return XRSR_RESULT_OK;
}

// Restore configuration from persistent state
xrsr_result_t xrsr_config_restore_state(xrsr_obj_t obj, const char *state_file) {
    // Load configuration from file
    json_t *config_json = json_load_file(state_file, 0, NULL);
    if(config_json == NULL) {
        return XRSR_RESULT_ERROR_FILE_READ;
    }
    
    // Deserialize and apply configuration
    xrsr_config_t restored_config;
    if(xrsr_config_deserialize(config_json, &restored_config)) {
        xrsr_config_update(obj, &restored_config);
    }
    
    json_decref(config_json);
    return XRSR_RESULT_OK;
}
```

## Best Practices for Configuration Management

### 1. Configuration Layering Strategy
- **Use built-in defaults** for critical operational parameters
- **Provide sensible JSON defaults** for common deployment scenarios  
- **Reserve environment variables** for deployment-specific overrides
- **Implement runtime APIs** for application-specific customization

### 2. Configuration Validation Approach
- **Validate early** during configuration loading
- **Provide automatic repair** for recoverable configuration errors
- **Log configuration changes** for debugging and audit purposes
- **Implement config change notifications** for dependent components

### 3. Cross-Component Configuration Coordination
- **Use message queues** for asynchronous configuration propagation
- **Implement atomic updates** for related configuration parameters
- **Provide rollback mechanisms** for failed configuration changes
- **Coordinate power mode changes** across all components simultaneously

### 4. Configuration Performance Optimization
- **Cache frequently accessed** configuration values
- **Minimize configuration validation** overhead in performance-critical paths
- **Use configuration change events** rather than polling for updates
- **Implement lazy configuration propagation** for non-critical updates

## Conclusion

The XR Voice SDK's configuration inheritance and override system provides a robust and flexible foundation for managing complex multi-component configurations. The hierarchical approach ensures that:

- **Default configurations** provide reliable operational baselines
- **Environment variables** enable deployment-specific customization
- **Runtime APIs** support application-driven configuration management
- **Cross-component coordination** maintains system coherence
- **Validation and error recovery** ensure system stability
- **Configuration profiles** simplify common deployment scenarios

This architecture enables the SDK to be easily configured for diverse deployment environments while maintaining operational reliability and providing developers with the flexibility needed for sophisticated voice interaction applications.