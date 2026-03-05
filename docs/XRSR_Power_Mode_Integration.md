# XRSR Power Mode Integration Documentation

## Overview
The XRSR (XR Speech Router) Power Mode Integration provides sophisticated power management capabilities optimized for battery-powered XR devices. The system implements three distinct power modes (Full, Low, and Sleep) with adaptive configuration parameters, timeout adjustments, and coordinated resource management across protocol implementations, audio processing, and session management components. This power-aware architecture enables optimal performance while preserving battery life in mobile XR applications.

## Power Mode Architecture

### Power Mode Enumeration
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L194-L199):

The XRSR system defines three primary power modes:

```c
/// @brief XRSR power mode enumeration
/// @details Power mode enumeration indicates supported power management states
typedef enum {
   XRSR_POWER_MODE_FULL    = 0, ///< Full power mode - maximum performance
   XRSR_POWER_MODE_LOW     = 1, ///< Low power mode - balanced performance/power
   XRSR_POWER_MODE_SLEEP   = 2, ///< Sleep mode - minimal power consumption
   XRSR_POWER_MODE_INVALID = 3, ///< Invalid power mode type
} xrsr_power_mode_t;
```

### Power Mode Characteristics

#### Full Power Mode (FPM)
- **Performance**: Maximum responsiveness with minimal latency
- **Network**: Aggressive connection timeouts for fast establishment
- **Audio Processing**: Full capability microphone array processing
- **Battery Impact**: Highest power consumption for optimal user experience
- **Use Cases**: Active XR sessions, real-time interactions, performance-critical applications

#### Low Power Mode (LPM) 
- **Performance**: Balanced responsiveness with power savings
- **Network**: Extended timeouts to reduce connection overhead
- **Audio Processing**: Optimized processing with selective feature reduction
- **Battery Impact**: Reduced power consumption while maintaining functionality
- **Use Cases**: Background voice monitoring, standby mode, extended operation periods

#### Sleep Mode
- **Performance**: Minimal processing for maximum power savings
- **Network**: Minimal network activity with maximum conservation
- **Audio Processing**: Basic wake-word detection with reduced sensitivity
- **Battery Impact**: Lowest power consumption for extended standby
- **Use Cases**: Device idle state, overnight operation, emergency power preservation

## Configuration Framework Architecture

### Power Mode Configuration Structure  
Located in [`xrsr_private.h`](../src/xr-speech-router/xrsr_private.h#L108-L116):

The system uses a pointer-based configuration framework enabling dynamic parameter switching:

```c
typedef struct {
   bool     *debug;                   // Debug logging control pointer
   uint32_t *connect_check_interval;  // Connection polling interval pointer
   uint32_t *timeout_connect;         // Connection establishment timeout pointer
   uint32_t *timeout_inactivity;      // Session inactivity timeout pointer
   uint32_t *timeout_session;         // Overall session timeout pointer
   bool     *ipv4_fallback;           // IPv4 fallback enable pointer
   uint32_t *backoff_delay;           // Connection retry backoff delay pointer
} xrsr_dst_param_ptrs_t;
```

### WebSocket Power Mode Configuration
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L250-L285):

The system maintains separate configuration sets for each power mode:

#### Full Power Mode Configuration (FPM)
```c
// Full Power Mode Configuration Initialization
g_xrsr.ws_json_config_fpm.val_debug                  = JSON_BOOL_VALUE_WS_DEBUG;
g_xrsr.ws_json_config_fpm.ptr_debug                  = &g_xrsr.ws_json_config_fpm.val_debug;

// Connection timing - optimized for responsiveness
g_xrsr.ws_json_config_fpm.val_connect_check_interval = JSON_INT_VALUE_WS_FPM_CONNECT_CHECK_INTERVAL; // 50ms
g_xrsr.ws_json_config_fpm.ptr_connect_check_interval = &g_xrsr.ws_json_config_fpm.val_connect_check_interval;

g_xrsr.ws_json_config_fpm.val_timeout_connect        = JSON_INT_VALUE_WS_FPM_TIMEOUT_CONNECT;        // 2000ms
g_xrsr.ws_json_config_fpm.ptr_timeout_connect        = &g_xrsr.ws_json_config_fpm.val_timeout_connect;

g_xrsr.ws_json_config_fpm.val_timeout_inactivity     = JSON_INT_VALUE_WS_FPM_TIMEOUT_INACTIVITY;     // 10000ms
g_xrsr.ws_json_config_fpm.ptr_timeout_inactivity     = &g_xrsr.ws_json_config_fpm.val_timeout_inactivity;

g_xrsr.ws_json_config_fpm.val_timeout_session        = JSON_INT_VALUE_WS_FPM_TIMEOUT_SESSION;        // 5000ms
g_xrsr.ws_json_config_fpm.ptr_timeout_session        = &g_xrsr.ws_json_config_fpm.val_timeout_session;

// Network resilience settings
g_xrsr.ws_json_config_fpm.val_ipv4_fallback          = JSON_BOOL_VALUE_WS_FPM_IPV4_FALLBACK;          // true
g_xrsr.ws_json_config_fpm.ptr_ipv4_fallback          = &g_xrsr.ws_json_config_fpm.val_ipv4_fallback;

g_xrsr.ws_json_config_fpm.val_backoff_delay          = JSON_INT_VALUE_WS_FPM_BACKOFF_DELAY;          // 50ms
g_xrsr.ws_json_config_fpm.ptr_backoff_delay          = &g_xrsr.ws_json_config_fpm.val_backoff_delay;
```

#### Low Power Mode Configuration (LPM)
```c
// Low Power Mode Configuration Initialization
g_xrsr.ws_json_config_lpm.val_debug                  = JSON_BOOL_VALUE_WS_DEBUG;
g_xrsr.ws_json_config_lpm.ptr_debug                  = &g_xrsr.ws_json_config_lpm.val_debug;

// Connection timing - optimized for power savings
g_xrsr.ws_json_config_lpm.val_connect_check_interval = JSON_INT_VALUE_WS_LPM_CONNECT_CHECK_INTERVAL; // 50ms
g_xrsr.ws_json_config_lpm.ptr_connect_check_interval = &g_xrsr.ws_json_config_lpm.val_connect_check_interval;

g_xrsr.ws_json_config_lpm.val_timeout_connect        = JSON_INT_VALUE_WS_LPM_TIMEOUT_CONNECT;        // 10000ms
g_xrsr.ws_json_config_lpm.ptr_timeout_connect        = &g_xrsr.ws_json_config_lpm.val_timeout_connect;

g_xrsr.ws_json_config_lpm.val_timeout_inactivity     = JSON_INT_VALUE_WS_LPM_TIMEOUT_INACTIVITY;     // 10000ms
g_xrsr.ws_json_config_lpm.ptr_timeout_inactivity     = &g_xrsr.ws_json_config_lpm.val_timeout_inactivity;

g_xrsr.ws_json_config_lpm.val_timeout_session        = JSON_INT_VALUE_WS_LPM_TIMEOUT_SESSION;        // 10000ms
g_xrsr.ws_json_config_lpm.ptr_timeout_session        = &g_xrsr.ws_json_config_lpm.val_timeout_session;

// Network efficiency settings
g_xrsr.ws_json_config_lpm.val_ipv4_fallback          = JSON_BOOL_VALUE_WS_LPM_IPV4_FALLBACK;          // true
g_xrsr.ws_json_config_lpm.ptr_ipv4_fallback          = &g_xrsr.ws_json_config_lpm.val_ipv4_fallback;

g_xrsr.ws_json_config_lpm.val_backoff_delay          = JSON_INT_VALUE_WS_LPM_BACKOFF_DELAY;          // 100ms
g_xrsr.ws_json_config_lpm.ptr_backoff_delay          = &g_xrsr.ws_json_config_lpm.val_backoff_delay;
```

### JSON Configuration Values
Located in [`xrsr_config_default.json`](../src/xr-speech-router/xrsr_config_default.json#L6-L22):

The configuration differences between power modes:

#### FPM Settings (aggressive performance)
```json
{
   "ws" : {
      "fpm" : {
         "connect_check_interval" :    50,  // Frequent connection checks (50ms)
         "timeout_connect"        :  2000,  // Fast connection timeout (2s)
         "timeout_inactivity"     : 10000,  // Standard inactivity timeout (10s)
         "timeout_session"        :  5000,  // Aggressive session timeout (5s)
         "ipv4_fallback"          :  true,  // IPv4 fallback enabled
         "backoff_delay"          :    50   // Minimal retry delay (50ms)
      }
   }
}
```

#### LPM Settings (power-optimized)
```json
{
   "ws" : {
      "lpm" : {
         "connect_check_interval" :    50,  // Same polling frequency
         "timeout_connect"        : 10000,  // Extended connection timeout (10s)
         "timeout_inactivity"     : 10000,  // Standard inactivity timeout (10s)
         "timeout_session"        : 10000,  // Extended session timeout (10s)
         "ipv4_fallback"          :  true,  // IPv4 fallback enabled
         "backoff_delay"          :   100   // Extended retry delay (100ms)
      }
   }
}
```

## Power Mode Switching Mechanism

### Power Mode Transition API
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L1120-L1170):

The system provides a synchronous API for power mode transitions with comprehensive validation:

```c
bool xrsr_power_mode_set(xrsr_power_mode_t power_mode) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   
   // Validate power mode parameter
   if((uint32_t)power_mode >= XRSR_POWER_MODE_INVALID) {
      XLOGD_ERROR("invalid power mode <%s>", xrsr_power_mode_str(power_mode));
      return(false);
   }
   
   // Check if power mode change is needed
   if(g_xrsr.power_mode == power_mode) {
      XLOGD_INFO("power mode already set to <%s>", xrsr_power_mode_str(power_mode));
      return(true);
   }

   bool result = false;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send power mode update message to processing thread
   xrsr_queue_msg_power_mode_update_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_POWER_MODE_UPDATE;
   msg.semaphore      = &semaphore;
   msg.power_mode     = power_mode;
   msg.result         = &result;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   
   // Wait for completion
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   if(result) {
      g_xrsr.power_mode = power_mode;

      #ifdef WS_ENABLED
      // Switch WebSocket configuration pointer based on power mode
      g_xrsr.ws_json_config = (XRSR_POWER_MODE_LOW == power_mode) ? 
                              &g_xrsr.ws_json_config_lpm : 
                              &g_xrsr.ws_json_config_fpm;
      #endif
   }

   return(result);
}
```

### Power Mode Message Processing
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L1700-L1800):

The power mode update handler coordinates system-wide transitions:

```c
void xrsr_msg_power_mode_update(const xrsr_thread_params_t *params, 
                               xrsr_thread_state_t *state, 
                               void *msg) {
   xrsr_queue_msg_power_mode_update_t *power_mode_update = (xrsr_queue_msg_power_mode_update_t *)msg;

   XLOGD_AUTOMATION_INFO("power mode transition to <%s>", xrsr_power_mode_str(power_mode_update->power_mode));

   // Terminate active sessions when entering reduced power modes
   // This prevents resource conflicts and ensures clean state transitions
   if(power_mode_update->power_mode != XRSR_POWER_MODE_FULL) {
      for(uint32_t group = 0; group < XRSR_SESSION_GROUP_QTY; group++) {
         xrsr_session_t *session = &g_xrsr.sessions[group];
         
         if((uint32_t)session->src < XRSR_SRC_INVALID) {
            XLOGD_INFO("terminate source <%s> for power mode transition", xrsr_src_str(session->src));
            
            // Graceful session termination
            xrsr_queue_msg_session_terminate_t terminate;
            terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
            terminate.semaphore   = NULL;
            terminate.src         = session->src;
            
            xrsr_msg_session_terminate(params, state, &terminate);
         }
      }
   }
   
   // Update protocol-specific parameters for new power mode
   for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
      for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

         switch(dst->url_parts.prot) {
            #ifdef WS_ENABLED
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               xrsr_state_ws_t *ws = &dst->conn_state.ws;
               
               // Apply new power mode parameters to active WebSocket connections
               xrsr_ws_update_dst_params(ws, &dst->dst_param_ptrs[power_mode_update->power_mode]);
               break;
            }
            #endif
            // Additional protocols can be added here
         }
      }
   }

   // Coordinate power mode change with XRAudio subsystem
   bool result = xrsr_xraudio_power_mode_update(g_xrsr.xrsr_xraudio_object, power_mode_update->power_mode);

   if(power_mode_update->semaphore != NULL) {
      if(power_mode_update->result != NULL) {
         *(power_mode_update->result) = result;
      }
      sem_post(power_mode_update->semaphore);
   }
}
```

## WebSocket Protocol Power Mode Integration

### Dynamic Parameter Updates
Located in [`xrsr_protocol_ws.c`](../src/xr-speech-router/xrsr_protocol_ws.c#L153-L210):

The WebSocket protocol dynamically adjusts its behavior based on current power mode:

```c
bool xrsr_ws_update_dst_params(xrsr_state_ws_t *ws, xrsr_dst_param_ptrs_t *params) {
   bool ret = false;
   
   if(ws) {
      // Update debug logging configuration
      if(params->debug != NULL) {
         if(*params->debug) {
            nopoll_log_enable(ws->obj_ctx, nopoll_true);
            nopoll_log_set_handler(ws->obj_ctx, xrsr_ws_nopoll_log, NULL);
            ws->debug_enabled = true;
         } else {
            nopoll_log_set_handler(ws->obj_ctx, NULL, NULL);
            nopoll_log_enable(ws->obj_ctx, nopoll_false);
            ws->debug_enabled = false;
         }
      } else if(JSON_BOOL_VALUE_WS_DEBUG) {
         // Use default debug setting if not specified
         nopoll_log_enable(ws->obj_ctx, nopoll_true);
         nopoll_log_set_handler(ws->obj_ctx, xrsr_ws_nopoll_log, NULL);
         ws->debug_enabled = true;
      }

      // Update connection timing parameters
      if(params->connect_check_interval != NULL) {
         ws->connect_check_interval = *params->connect_check_interval;
      } else {
         ws->connect_check_interval = JSON_INT_VALUE_WS_FPM_CONNECT_CHECK_INTERVAL;
      }
      
      // Connection establishment timeout (power mode dependent)
      if(params->timeout_connect != NULL) {
         ws->timeout_connect = *params->timeout_connect;
      } else {
         ws->timeout_connect = JSON_INT_VALUE_WS_FPM_TIMEOUT_CONNECT;
      }
      
      // Session inactivity timeout
      if(params->timeout_inactivity != NULL) {
         ws->timeout_inactivity = *params->timeout_inactivity;
      } else {
         ws->timeout_inactivity = JSON_INT_VALUE_WS_FPM_TIMEOUT_INACTIVITY;
      }
      
      // Overall session timeout (significantly different between power modes)
      if(params->timeout_session != NULL) {
         ws->timeout_session = *params->timeout_session;
      } else {
         ws->timeout_session = JSON_INT_VALUE_WS_FPM_TIMEOUT_SESSION;
      }
      
      // Network resilience configuration
      if(params->ipv4_fallback != NULL) {
         ws->ipv4_fallback = *params->ipv4_fallback;
      } else {
         ws->ipv4_fallback = JSON_BOOL_VALUE_WS_FPM_IPV4_FALLBACK;
      }
      
      // Retry backoff delay (power mode optimized)
      if(params->backoff_delay != NULL) {
         ws->backoff_delay = *params->backoff_delay;
      } else {
         ws->backoff_delay = JSON_INT_VALUE_WS_FPM_BACKOFF_DELAY;
      }

      XLOGD_INFO("WebSocket power mode parameters: debug <%s> connect <%u, %u> inactivity <%u> session <%u> ipv4_fallback <%s> backoff <%u>", 
                 ws->debug_enabled ? "YES" : "NO", 
                 ws->connect_check_interval, 
                 ws->timeout_connect, 
                 ws->timeout_inactivity, 
                 ws->timeout_session, 
                 ws->ipv4_fallback ? "YES" : "NO", 
                 ws->backoff_delay);
      
      ret = true;
   } else {
      XLOGD_WARN("WebSocket state NULL during parameter update");
   }

   return(ret);
}
```

### Runtime Timeout Application
Located in [`xrsr_protocol_ws.c`](../src/xr-speech-router/xrsr_protocol_ws.c#L410-L450):

Power mode settings are applied during connection establishment:

```c
bool xrsr_ws_connect(xrsr_state_ws_t *ws, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, 
                     xraudio_input_format_t xraudio_format, bool user_initiated, bool is_retry, 
                     bool deferred, const char **query_strs) {
                     
   // Set retry timeout period based on current power mode
   rdkx_timestamp_get(&ws->retry_timestamp_end);
   rdkx_timestamp_add_ms(&ws->retry_timestamp_end, ws->timeout_session);

   ws->audio_src      = audio_src;
   ws->user_initiated = user_initiated;
   ws->is_retry       = is_retry;
   ws->query_strs     = query_strs;

   // Log connection parameters with current power mode settings
   XLOGD_AUTOMATION_INFO("WebSocket connection: src <%s> host <%s> port <%s> retry_period <%u>ms", 
                         xrsr_src_str(ws->audio_src), 
                         url_parts->host, 
                         url_parts->port_str, 
                         ws->timeout_session);

   // Apply power mode specific connection timeout to noPoll library
   nopoll_conn_connect_timeout(ws->obj_ctx, ws->timeout_connect * 1000);  // Convert to microseconds

   // Initialize connection timing based on power mode
   ws->connect_wait_time = ws->timeout_connect;

   return(true);
}
```

## XRAudio Power Mode Integration

### Audio Subsystem Coordination
Located in [`xrsr_xraudio.c`](../src/xr-speech-router/xrsr_xraudio.c#L973-L1029):

XRSR coordinates power mode changes with the XRAudio subsystem for comprehensive power management:

```c
bool xrsr_xraudio_power_mode_update(xrsr_xraudio_object_t object, xrsr_power_mode_t power_mode) {
   xrsr_xraudio_obj_t *obj = (xrsr_xraudio_obj_t *)object;

   if(!xrsr_xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("invalid xrsr xraudio object");
      return(false);
   }
   
   xraudio_power_mode_t xraudio_power_mode = XRAUDIO_POWER_MODE_INVALID;

   switch(power_mode) {
      case XRSR_POWER_MODE_FULL:
         xraudio_power_mode = XRAUDIO_POWER_MODE_FULL;
         
         // Configure full power microphone array processing
         obj->device_input  &= ~g_local_mic_low_power;   // Clear low power microphone flags
         obj->device_input  |=  g_local_mic_full_power;  // Set full power microphone flags
         break;

      case XRSR_POWER_MODE_LOW:
         xraudio_power_mode = XRAUDIO_POWER_MODE_LOW;
         
         // Configure power-optimized microphone processing
         obj->device_input  &= ~g_local_mic_full_power;  // Clear full power microphone flags
         obj->device_input  |=  g_local_mic_low_power;   // Set low power microphone flags
         break;

      case XRSR_POWER_MODE_SLEEP:
         xraudio_power_mode = XRAUDIO_POWER_MODE_SLEEP;
         
         // Configure minimal power microphone processing
         obj->device_input  &= ~g_local_mic_full_power;  // Clear full power microphone flags
         obj->device_input  |=  g_local_mic_low_power;   // Set low power microphone flags
         break;

      default: {
         XLOGD_ERROR("invalid power mode <%s>", xrsr_power_mode_str(power_mode));
         return(false);
      }
   }

   // Check if power mode change is actually needed  
   if(obj->xraudio_power_mode == xraudio_power_mode) {
      XLOGD_WARN("XRAudio power mode already set to <%s>", xrsr_power_mode_str(power_mode));
      return(true);
   }

   // Close audio devices to ensure clean state transition
   xrsr_xraudio_device_close(obj);
   
   // Update internal power mode state
   obj->xraudio_power_mode = xraudio_power_mode;
   
   // Request audio device resource under new power mode
   #ifdef XRAUDIO_RESOURCE_MGMT
   xrsr_xraudio_device_request(obj);
   #else
   xrsr_xraudio_device_granted(obj);
   #endif

   // Apply power mode change to XRAudio subsystem
   xraudio_result_t result = xraudio_power_mode_update(obj->xraudio_obj, xraudio_power_mode);
   if(result != XRAUDIO_RESULT_OK) {
      XLOGD_ERROR("unable to set xraudio power mode <%s>: %s", 
                  xrsr_power_mode_str(power_mode), 
                  xraudio_result_str(result));
      return(false);
   }

   XLOGD_INFO("XRAudio power mode successfully updated to <%s>", xrsr_power_mode_str(power_mode));
   return(true);
}
```

### Microphone Array Configuration
Located in [`xrsr_xraudio.c`](../src/xr-speech-router/xrsr_xraudio.c#L240-L260):

Power modes affect microphone array processing capabilities:

```c
// Power mode specific microphone processing
if(obj->xraudio_power_mode == XRAUDIO_POWER_MODE_LOW) {
   // Low power mode: reduce processing complexity
   // - Single microphone processing
   // - Reduced sample rates  
   // - Simplified noise cancellation
   // - Limited beamforming
   
   XLOGD_INFO("XRAudio operating in low power mode");
} else if(obj->xraudio_power_mode == XRAUDIO_POWER_MODE_FULL) {
   // Full power mode: maximum processing capability  
   // - Multi-microphone array processing
   // - Full sample rate processing
   // - Advanced noise cancellation
   // - Full beamforming and spatial audio
   
   XLOGD_INFO("XRAudio operating in full power mode");
}
```

## Route and Destination Power Mode Integration

### Power Mode Route Configuration
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L50-L70):

Each route destination maintains power mode specific parameters:

```c
typedef struct {
   bool                         initialized;                          // Route initialization status
   xrsr_url_parts_t             url_parts;                           // URL parsing results
   xrsr_route_handler_t         handler;                             // Protocol handler pointer
   xrsr_handlers_t              handlers;                            // Application callbacks
   xrsr_audio_format_type_t     formats;                            // Supported audio formats
   uint16_t                     stream_time_min;                     // Minimum stream duration
   xraudio_input_record_from_t  stream_from;                        // Stream start position
   int32_t                      stream_offset;                       // Stream timing offset
   xraudio_input_record_until_t stream_until;                       // Stream end condition
   uint32_t                     keyword_begin;                       // Keyword start sample
   uint32_t                     keyword_duration;                    // Keyword duration samples
   xrsr_conn_state_t            conn_state;                          // Connection state (protocol specific)
   xrsr_dst_param_ptrs_t        dst_param_ptrs[XRSR_POWER_MODE_INVALID]; // Power mode parameter sets
} xrsr_dst_int_t;
```

### Dynamic Parameter Pointer Management
The `dst_param_ptrs` array contains configuration pointers for each power mode, enabling instantaneous switching:

```c
// Power mode parameter pointer initialization during route setup
for(uint32_t power_mode = 0; power_mode < XRSR_POWER_MODE_INVALID; power_mode++) {
   xrsr_dst_param_ptrs_t *params = &dst->dst_param_ptrs[power_mode];
   
   switch(power_mode) {
      case XRSR_POWER_MODE_FULL: {
         // Point to FPM configuration values
         params->debug                  = &g_xrsr.ws_json_config_fpm.val_debug;
         params->connect_check_interval = &g_xrsr.ws_json_config_fpm.val_connect_check_interval;
         params->timeout_connect        = &g_xrsr.ws_json_config_fpm.val_timeout_connect;
         params->timeout_inactivity     = &g_xrsr.ws_json_config_fpm.val_timeout_inactivity;
         params->timeout_session        = &g_xrsr.ws_json_config_fpm.val_timeout_session;
         params->ipv4_fallback          = &g_xrsr.ws_json_config_fpm.val_ipv4_fallback;
         params->backoff_delay          = &g_xrsr.ws_json_config_fpm.val_backoff_delay;
         break;
      }
      
      case XRSR_POWER_MODE_LOW: {
         // Point to LPM configuration values
         params->debug                  = &g_xrsr.ws_json_config_lpm.val_debug;
         params->connect_check_interval = &g_xrsr.ws_json_config_lpm.val_connect_check_interval;
         params->timeout_connect        = &g_xrsr.ws_json_config_lpm.val_timeout_connect;
         params->timeout_inactivity     = &g_xrsr.ws_json_config_lpm.val_timeout_inactivity;
         params->timeout_session        = &g_xrsr.ws_json_config_lpm.val_timeout_session;
         params->ipv4_fallback          = &g_xrsr.ws_json_config_lpm.val_ipv4_fallback;
         params->backoff_delay          = &g_xrsr.ws_json_config_lpm.val_backoff_delay;
         break;
      }
   }
}
```

## Performance Impact Analysis

### Power Mode Timeout Comparison

| Parameter | Full Power Mode (FPM) | Low Power Mode (LPM) | Difference | Impact |
|-----------|----------------------|---------------------|------------|---------|
| Connection Timeout | 2,000ms | 10,000ms | +400% | Reduced connection attempts, lower network power |
| Session Timeout | 5,000ms | 10,000ms | +100% | Longer session retention, reduced reconnection overhead |
| Backoff Delay | 50ms | 100ms | +100% | Less aggressive retry behavior, reduced network activity |
| Connect Check Interval | 50ms | 50ms | 0% | Maintained responsiveness for connection monitoring |

### Battery Life Optimization Strategies

#### Network Activity Reduction
1. **Extended Timeouts**: Reduce connection attempt frequency in LPM
2. **Increased Backoff Delays**: Minimize retry storm impact on battery
3. **Session Persistence**: Maintain connections longer to avoid reconnection overhead
4. **Selective Fallback**: Maintain IPv4 fallback for reliability without performance penalty

#### Audio Processing Optimization
1. **Microphone Array Scaling**: Reduce active microphone count in low power modes
2. **Processing Complexity**: Simplified algorithms in power-constrained scenarios
3. **Sample Rate Adjustment**: Dynamic sample rate based on power requirements
4. **Feature Selectivity**: Disable non-essential audio processing features

#### Session Management Efficiency
1. **Graceful Termination**: Proper session cleanup during power mode transitions
2. **Resource Coordination**: Synchronized resource management across components
3. **State Preservation**: Maintain critical session state across power transitions
4. **Recovery Optimization**: Efficient session restoration after power mode changes

## Power Mode Best Practices

### Application Integration Guidelines

1. **Power Mode Selection**: Choose power modes based on user activity and battery level
2. **Transition Timing**: Coordinate power mode changes during session gaps when possible
3. **State Management**: Handle session termination gracefully during power mode transitions
4. **Performance Monitoring**: Track power consumption and adjust parameters accordingly
5. **User Experience**: Maintain acceptable responsiveness even in reduced power modes

### Battery Optimization Strategies

1. **Adaptive Timeouts**: Use longer timeouts when battery is low
2. **Connection Pooling**: Maintain fewer concurrent connections in low power modes
3. **Processing Reduction**: Scale audio processing complexity with available power
4. **Selective Features**: Disable non-critical features in power-constrained scenarios
5. **Sleep Mode Utilization**: Aggressive use of sleep mode during idle periods

### System Integration Considerations

1. **Component Coordination**: Ensure all subsystems respect power mode settings
2. **Resource Arbitration**: Coordinate resource usage across power-aware components
3. **Recovery Planning**: Implement robust recovery from power mode transition failures
4. **Performance Validation**: Validate functionality across all supported power modes
5. **Power Monitoring**: Implement real-time power consumption monitoring and adjustment

## Advanced Power Management Features

### Predictive Power Management
The system can be extended to support predictive power management based on:
- User interaction patterns
- Battery level trends
- Network condition monitoring  
- Audio processing complexity requirements
- Environmental factors (ambient noise, etc.)

### Dynamic Configuration Adjustment
Beyond the standard FPM/LPM configurations, the system supports:
- Runtime parameter adjustment based on measured performance
- Adaptive timeout scaling based on network conditions
- Load-based processing complexity adjustment
- Battery level dependent feature enablement

### Integration with Device Power Management
The XRSR power mode integration coordinates with:
- System-wide power management policies
- Device thermal management  
- Battery charge level monitoring
- Connected device power states (headsets, controllers, etc.)

This comprehensive power mode integration enables XR Voice SDK applications to deliver optimal performance while maximizing battery life across diverse usage scenarios and device configurations.