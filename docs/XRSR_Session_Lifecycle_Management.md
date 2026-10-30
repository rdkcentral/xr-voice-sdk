# XRSR Session Lifecycle Management Documentation

## Overview
The XRSR (XR Speech Router) Session Lifecycle Management provides comprehensive coordination of speech recognition sessions from initiation through termination. The system manages concurrent sessions across multiple audio sources, protocols, and destinations while ensuring proper resource allocation, state tracking, and cleanup operations. The lifecycle management operates through an asynchronous message queue architecture that coordinates all session operations within dedicated processing threads.

## Session Lifecycle Architecture

### Session State Management Framework
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L107-L130):

The XRSR session management is built around several key architectural components:

#### Session Management Structures
```c
typedef struct {
   xrsr_src_t                    src;                      // Audio source identifier
   xraudio_devices_input_t       xraudio_device_input;     // XRAudio device configuration
   int                           pipe_fds_rd[XRSR_DST_QTY_MAX]; // Read pipe file descriptors
   int                           pipe_size[XRSR_DST_QTY_MAX];   // Pipe buffer sizes
   bool                          requested_more_audio;     // Additional audio request flag
   uint16_t                      stream_id;               // Unique stream identifier
   xrsr_session_config_update_t  session_config_update;   // Dynamic configuration updates
} xrsr_session_t;
```

#### Global Session Context
```c
typedef struct {
   bool                          opened;                  // XRSR system state
   xrsr_power_mode_t             power_mode;             // Current power management mode
   bool                          privacy_mode;           // Privacy protection state
   bool                          mask_pii;               // PII masking configuration
   xrsr_thread_info_t            threads[XRSR_THREAD_QTY]; // Processing threads
   xrsr_route_int_t              routes[XRSR_SRC_INVALID]; // Audio source routing
   xrsr_xraudio_object_t         xrsr_xraudio_object;    // XRAudio interface object
   char *                        capture_dir_path;       // Audio capture directory
   xrsr_session_t                sessions[XRSR_SESSION_GROUP_QTY]; // Active sessions
   bool                          networked_standby;      // Network availability state
   bool                          local_mic;              // Local microphone availability
   bool                          local_mic_tap;          // Microphone monitoring capability
} xrsr_global_t;
```

## Message Queue Session Management

### Session Message Types
Located in [`xrsr_private.h`](../src/xr-speech-router/xrsr_private.h#L51-L53):

The session lifecycle is managed through a comprehensive message queue system:

```c
typedef enum {
   XRSR_QUEUE_MSG_TYPE_SESSION_BEGIN                       = 14, // Session initiation
   XRSR_QUEUE_MSG_TYPE_SESSION_CONFIG_IN                   = 15, // Session configuration
   XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE                   = 16, // Session termination
   XRSR_QUEUE_MSG_TYPE_SESSION_AUDIO_STREAM_START          = 17, // Audio streaming start
   XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_START               = 18, // Audio capture start
   XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_STOP                = 19, // Audio capture stop
} xrsr_queue_msg_type_t;
```

### Message Structures for Session Control
Located in [`xrsr_private.h`](../src/xr-speech-router/xrsr_private.h#L189-L226):

#### Session Begin Message
```c
typedef struct {
   xrsr_queue_msg_header_t     header;                 // Message header
   xrsr_src_t                  src;                    // Audio source
   bool                        user_initiated;         // User action flag
   xraudio_input_format_t      xraudio_format;         // Audio input format
   xraudio_keyword_detector_result_t detector_result;  // Keyword detection results
   bool                        has_result;             // Detection result validity
   xrsr_session_request_t      input_format;          // Session input configuration
   uuid_t                      uuid;                   // Session unique identifier
   bool                        low_latency;            // Latency optimization
   bool                        low_cpu_util;           // CPU optimization
   bool                        retry;                  // Retry attempt flag
   char                        transcription_in[XRSR_SESSION_TEXT_MAX]; // Text input
   char                        audio_file_in[XRSR_SESSION_FILE_PATH_MAX]; // Audio file path
} xrsr_queue_msg_session_begin_t;
```

#### Session Configuration Message
```c
typedef struct {
   xrsr_queue_msg_header_t     header;           // Message header
   uuid_t                      uuid;             // Session identifier
   xrsr_src_t                  src;              // Audio source
   uint32_t                    dst_index;        // Destination route index
   const char **               query_strs;       // Query string parameters
   uint32_t                    keyword_begin;    // Keyword start sample
   uint32_t                    keyword_duration; // Keyword duration samples
   void *                      app_config;       // Application-specific config
} xrsr_queue_msg_session_config_in_t;
```

#### Session Termination Message
```c
typedef struct {
   xrsr_queue_msg_header_t     header;      // Message header
   sem_t *                     semaphore;   // Synchronization semaphore
   xrsr_src_t                  src;         // Audio source to terminate
} xrsr_queue_msg_session_terminate_t;
```

## Session Lifecycle Flow

### Session Initiation Process
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L1904-L2200):

The session begin process coordinates multiple aspects of session setup:

#### 1. Session Validation and Conflict Resolution
```c
void xrsr_msg_session_begin(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_begin_t *begin = (xrsr_queue_msg_session_begin_t *)msg;

   if(begin->src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(begin->src));
      return;
   }
   
   // Handle session conflicts
   if(xrsr_is_source_active(begin->src) && !begin->retry) {
      #ifdef XRSR_SESSION_RETRIGGER_ABORT
      // Abort current session and start new one
      XLOGD_INFO("aborting current session in progress on source <%s>", xrsr_src_str(begin->src));
      xrsr_queue_msg_session_terminate_t terminate;
      terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
      terminate.semaphore   = NULL;
      terminate.src         = begin->src;
      xrsr_msg_session_terminate(params, state, &terminate);
      #else
      // Ignore new session and restart keyword detector
      XLOGD_INFO("ignoring due to current session in progress on source <%s>", xrsr_src_str(begin->src));
      if(xrsr_has_keyword_detector(begin->src)) {
         xrsr_xraudio_keyword_detect_restart(g_xrsr.xrsr_xraudio_object);
      }
      #endif
      return;
   }
```

#### 2. Session Context Setup
```c
   uint32_t group = xrsr_source_to_group(begin->src);
   xrsr_session_t *session = &g_xrsr.sessions[group];

   if(xrsr_is_group_active(group) && !begin->retry) {
      XLOGD_ERROR("session in progress on source <%s>", xrsr_src_str(session->src));
      return;
   }
   
   session->src = begin->src;
```

#### 3. Keyword Detection Result Processing
```c
   xrsr_keyword_detector_result_t *detector_result_ptr = NULL;
   xrsr_keyword_detector_result_t  detector_result;
   
   if(begin->has_result) {
      if(begin->detector_result.chan_selected >= XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
         XLOGD_ERROR("invalid selected channel <%u>", begin->detector_result.chan_selected);
      } else {
         // Extract keyword detection results for selected channel
         detector_result.score                = begin->detector_result.channels[begin->detector_result.chan_selected].score;
         detector_result.snr                  = begin->detector_result.channels[begin->detector_result.chan_selected].snr;
         detector_result.doa                  = begin->detector_result.channels[begin->detector_result.chan_selected].doa;
         detector_result.offset_buf_begin     = begin->detector_result.endpoints.pre;
         detector_result.offset_kwd_begin     = begin->detector_result.endpoints.begin;
         detector_result.offset_kwd_end       = begin->detector_result.endpoints.end;
         detector_result.kwd_gain             = begin->detector_result.endpoints.kwd_gain;
         detector_result.detector_name        = begin->detector_result.detector_name;
         detector_result.dsp_name             = begin->detector_result.dsp_name;
         detector_result.dynamic_gain         = begin->detector_result.channels[begin->detector_result.chan_selected].dynamic_gain;
         detector_result.dynamic_gain_update  = begin->detector_result.dynamic_gain_update;
         detector_result.sensitivity          = begin->detector_result.sensitivity;

         detector_result_ptr = &detector_result;
      }
   }
```

### Protocol-Specific Session Initialization

#### HTTP/HTTPS Session Setup
```c
#ifdef HTTP_ENABLED
case XRSR_PROTOCOL_HTTP:
case XRSR_PROTOCOL_HTTPS: {
   xrsr_state_http_t *http = &dst->conn_state.http;
   http->is_session_by_text = (transcription_in != NULL);
   http->is_session_by_file = (audio_file_in    != NULL);
   
   if(!xrsr_http_is_disconnected(http)) {
      XLOGD_ERROR("invalid state");
      break;
   }

   xrsr_session_config_out_t *session_config = &http->session_config_out;
   memset(&http->session_config_out, 0, sizeof(http->session_config_out));
   
   // Initialize session configuration
   session_config->user_initiated = begin->user_initiated;
   session_config->formats        = dst->formats;
   session_config->stream_time_min = dst->stream_time_min;
   // ... additional HTTP-specific initialization
}
#endif
```

#### WebSocket Session Setup
```c
#ifdef WS_ENABLED
case XRSR_PROTOCOL_WS:
case XRSR_PROTOCOL_WSS: {
   xrsr_state_ws_t *ws = &dst->conn_state.ws;
   ws->is_session_by_text = (transcription_in != NULL);
   ws->is_session_by_file = (audio_file_in    != NULL);
   
   if(!xrsr_ws_is_disconnected(ws)) {
      XLOGD_ERROR("invalid state");
      break;
   }

   // Initialize WebSocket-specific session parameters
   ws->dst_index      = dst_index;
   ws->input_format   = begin->input_format;
   ws->xraudio_format = xrsr_audio_format_get(dst->formats, begin->xraudio_format);
   ws->low_latency    = begin->low_latency;
   ws->low_cpu_util   = begin->low_cpu_util;
   // ... additional WebSocket configuration
}
#endif
```

### Session Configuration Management
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L2264-L2450):

The session configuration process allows dynamic parameter updates during session establishment:

#### Configuration Input Processing
```c
void xrsr_msg_session_config_in(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_config_in_t *config_in = (xrsr_queue_msg_session_config_in_t *)msg;
   
   bool found_session = false;
   
   // Locate active session matching the configuration request
   for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
      for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];
         
         if(dst->handler == NULL) {
            continue;
         }
         
         switch(dst->url_parts.prot) {
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               xrsr_state_ws_t *ws = &dst->conn_state.ws;
               
               if(uuid_compare(ws->uuid, config_in->uuid) == 0) {
                  found_session = true;
                  
                  // Apply configuration updates
                  xrsr_session_config_in_ws_t *session_config_in_ws = &ws->session_config_in.ws;
                  
                  dst->keyword_begin    = config_in->keyword_begin;
                  dst->keyword_duration = config_in->keyword_duration;
                  ws->audio_src         = config_in->src;
                  
                  // Process query string parameters
                  uint32_t i = 0;
                  const char **query_strs = session_config_in_ws->query_strs;
                  
                  // Append application query strings
                  const char **query_strs_app = config_in->query_strs;
                  while(*query_strs_app != NULL) {
                     if(i >= XRSR_QUERY_STRING_QTY_MAX) {
                        XLOGD_WARN("maximum query string elements reached");
                        break;
                     }
                     *query_strs = *query_strs_app;
                     query_strs++;
                     query_strs_app++;
                     i++;
                  }
                  *query_strs = NULL;
                  
                  // Call session configuration handler
                  if(ws->handlers.session_config != NULL) {
                     (*ws->handlers.session_config)(ws->handlers.data, ws->uuid, &ws->session_config_in);
                  }
               }
               break;
            }
         }
      }
   }
}
```

### Session Termination Process
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L2565-L2640):

Session termination provides coordinated cleanup across all protocol connections:

#### Multi-Protocol Termination Coordination
```c
void xrsr_msg_session_terminate(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_terminate_t *terminate = (xrsr_queue_msg_session_terminate_t *)msg;
   
   xrsr_src_t src = terminate->src;
   
   if((uint32_t)src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("source is invalid <%s>", xrsr_src_str(src));
      if(terminate->semaphore != NULL) {
         sem_post(terminate->semaphore);
      }
      return;
   }

   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("source is not active <%s>", xrsr_src_str(src));
      if(terminate->semaphore != NULL) {
         sem_post(terminate->semaphore);
      }
      return;
   }

   // Terminate all active protocol connections for this source
   uint32_t index_src = src;
   for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

      switch(dst->url_parts.prot) {
         #ifdef HTTP_ENABLED
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            xrsr_state_http_t *http = &dst->conn_state.http;
            if(!xrsr_http_is_disconnected(http)) {
               xrsr_http_terminate(http);
            }
            break;
         }
         #endif
         #ifdef WS_ENABLED
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            if(!xrsr_ws_is_disconnected(ws)) {
               xrsr_ws_terminate(ws);
            }
            break;
         }
         #endif
         #ifdef SDT_ENABLED
         case XRSR_PROTOCOL_SDT: {
            xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
            if(!xrsr_sdt_is_disconnected(sdt)) {
               xrsr_sdt_terminate(sdt);
            }
            break;
         }
         #endif
      }
   }
```

### Session Completion and Cleanup
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L2452-L2520):

Session end handling ensures proper resource cleanup and callback execution:

#### Session End Callback Processing
```c
void xrsr_session_end(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index, xrsr_session_stats_t *stats) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   XLOGD_INFO("uuid <%s> src <%s> dst index <%u>", uuid_str, xrsr_src_str(src), dst_index);

   if(((uint32_t) src) >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }

   xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(src)];
   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("source <%s> is not active source <%s>", xrsr_src_str(src), xrsr_src_str(session->src));
      return;
   }

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Execute session end callback
   if(dst->handlers.session_end != NULL) {
      (*dst->handlers.session_end)(dst->handlers.data, uuid, stats, &timestamp);
   }

   // Check if overall session is complete
   bool session_in_progress = false;
   for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[session->src].dsts[index];
      
      if(dst->handler == NULL) {
         continue;
      }
      
      // Check each protocol for active connections
      switch(dst->url_parts.prot) {
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            xrsr_state_http_t *http = &dst->conn_state.http;
            if(!xrsr_http_is_disconnected(http)) {
               session_in_progress = true;
            }
            break;
         }
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            if(!xrsr_ws_is_disconnected(ws)) {
               session_in_progress = true;
            }
            break;
         }
      }
   }

   // Complete session cleanup when all protocols disconnected
   if(!session_in_progress) {
      session->src                  = XRSR_SRC_INVALID;
      session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_NONE;
      session->requested_more_audio = false;
      session->stream_id            = 0;
   }
}
```

## Audio Streaming Lifecycle

### Audio Stream Initiation
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L2642-L2720):

Audio streaming management coordinates real-time audio delivery during sessions:

#### Multi-Protocol Stream Management
```c
void xrsr_msg_session_audio_stream_start(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_audio_stream_start_t *audio_stream_start = (xrsr_queue_msg_session_audio_stream_start_t *)msg;

   xrsr_src_t src = audio_stream_start->src;

   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("source is not active <%s>", xrsr_src_str(src));
      return;
   }

   uint32_t index_src = src;
   bool create_stream = true;
   
   for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

      switch(dst->url_parts.prot) {
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            if(!xrsr_ws_is_disconnected(ws)) {
               if(src != XRSR_SRC_RCU_PTT) {
                  // Far-field microphone: start streaming immediately
                  if(!xrsr_ws_audio_stream(ws, src, create_stream, true)) {
                     XLOGD_ERROR("ws audio stream - src <%s>", xrsr_src_str(src));
                  }
                  create_stream = false;
               } else {
                  // Push-to-talk: require explicit audio request
                  xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(src)];

                  if(!session->requested_more_audio) {
                     session->requested_more_audio = true;
                  } else {
                     if(!xrsr_ws_audio_stream(ws, src, create_stream, true)) {
                        XLOGD_ERROR("ws audio stream - src <%s>", xrsr_src_str(src));
                     }
                     create_stream = false;
                  }
               }
            }
            break;
         }
      }
   }
}
```

### Stream Event Callbacks
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L2720-L2820):

Stream lifecycle events provide detailed progression tracking:

#### Stream Begin Notification
```c
void xrsr_session_stream_begin(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   XLOGD_INFO("uuid <%s> src <%s> dst index <%u>", uuid_str, xrsr_src_str(src), dst_index);

   if(((uint32_t) src) >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Execute stream begin callback
   if(dst->handlers.stream_begin != NULL) {
      (*dst->handlers.stream_begin)(dst->handlers.data, uuid, src, &timestamp);
   }
}
```

#### Keyword Stream Notification
```c
void xrsr_session_stream_kwd(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Execute keyword stream callback
   if(dst->handlers.stream_kwd != NULL) {
      (*dst->handlers.stream_kwd)(dst->handlers.data, uuid, &timestamp);
   }
}
```

#### Stream End Notification
```c
void xrsr_session_stream_end(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index, xrsr_stream_stats_t *stats) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Execute stream end callback with performance statistics
   if(dst->handlers.stream_end != NULL) {
      (*dst->handlers.stream_end)(dst->handlers.data, uuid, stats, &timestamp);
   }
}
```

## Session State Tracking

### Session Activity Management
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L3000-L3100):

The system provides comprehensive session state tracking across all sources and groups:

#### Source Activity Detection
```c
static bool xrsr_is_source_active(xrsr_src_t src) {
   if((uint32_t)src >= XRSR_SRC_INVALID) {
      return(false);
   }
   
   uint32_t group = xrsr_source_to_group(src);
   xrsr_session_t *session = &g_xrsr.sessions[group];
   
   return(session->src == src);
}

static bool xrsr_is_group_active(uint32_t group) {
   if(group >= XRSR_SESSION_GROUP_QTY) {
      return(false);
   }
   
   xrsr_session_t *session = &g_xrsr.sessions[group];
   return((uint32_t)session->src < XRSR_SRC_INVALID);
}

static uint32_t xrsr_source_to_group(xrsr_src_t src) {
   switch(src) {
      case XRSR_SRC_RCU_PTT:         return(0);
      case XRSR_SRC_RCU_FF:          return(1);
      case XRSR_SRC_MICROPHONE:      return(2);
      case XRSR_SRC_MICROPHONE_TAP:  return(2); // Share group with microphone
      default:                       return(XRSR_SESSION_GROUP_QTY);
   }
}
```

### Power Mode Integration
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L1700-L1800):

Session lifecycle management integrates with system power management:

#### Power Mode Session Coordination
```c
void xrsr_msg_power_mode_update(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_power_mode_update_t *power_mode_update = (xrsr_queue_msg_power_mode_update_t *)msg;

   XLOGD_AUTOMATION_INFO("power mode <%s>", xrsr_power_mode_str(power_mode_update->power_mode));

   // Terminate active sessions when entering low power mode
   if(power_mode_update->power_mode != XRSR_POWER_MODE_FULL) {
      for(uint32_t group = 0; group < XRSR_SESSION_GROUP_QTY; group++) {
         xrsr_session_t *session = &g_xrsr.sessions[group];
         if((uint32_t)session->src < XRSR_SRC_INVALID) {
            XLOGD_INFO("terminate source <%s>", xrsr_src_str(session->src));
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
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               xrsr_state_ws_t *ws = &dst->conn_state.ws;
               xrsr_ws_update_dst_params(ws, &dst->dst_param_ptrs[power_mode_update->power_mode]);
               break;
            }
         }
      }
   }

   bool result = xrsr_xraudio_power_mode_update(g_xrsr.xrsr_xraudio_object, power_mode_update->power_mode);
}
```

## Session Conflict Resolution

### Concurrent Session Management
The XRSR implements sophisticated conflict resolution for overlapping session requests:

#### Session Retrigger Handling
```c
#ifdef XRSR_SESSION_RETRIGGER_ABORT
// Configuration: Abort current session and start new one
if(xrsr_is_source_active(begin->src) && !begin->retry) {
   XLOGD_INFO("aborting current session in progress on source <%s>", xrsr_src_str(begin->src));
   xrsr_queue_msg_session_terminate_t terminate;
   terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
   terminate.semaphore   = NULL;
   terminate.src         = begin->src;
   xrsr_msg_session_terminate(params, state, &terminate);
   // TODO: Set flag to restart new session after current termination
}
#else
// Configuration: Ignore new session and restart keyword detector
XLOGD_INFO("ignoring due to current session in progress on source <%s>", xrsr_src_str(begin->src));
if(xrsr_has_keyword_detector(begin->src)) {
   xrsr_xraudio_keyword_detect_restart(g_xrsr.xrsr_xraudio_object);
}
#endif
```

#### Group-Based Session Isolation
Sessions are organized into groups to prevent conflicts between related sources:

- **Group 0**: RCU Push-to-Talk (XRSR_SRC_RCU_PTT)
- **Group 1**: RCU Far-Field (XRSR_SRC_RCU_FF)
- **Group 2**: Local Microphones (XRSR_SRC_MICROPHONE, XRSR_SRC_MICROPHONE_TAP)

This grouping ensures that related audio sources share session context while maintaining isolation between independent input channels.

## Session Performance Monitoring

### Session Statistics Collection
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L373-L403):

The lifecycle management includes comprehensive performance tracking:

#### Session Quality Metrics
```c
typedef struct {
   xrsr_session_end_reason_t reason;                             // Session termination reason
   xrsr_ret_code_internal_t  ret_code_internal;                  // Internal return code
   long                      ret_code_protocol;                  // Protocol-specific response
   long                      ret_code_library;                   // Library return code
   char                      server_ip[XRSR_SESSION_IP_LEN_MAX]; // Connected server IP
   double                    time_connect;                       // Connection establishment time
   double                    time_dns;                           // DNS lookup time
} xrsr_session_stats_t;

typedef struct {
   bool               result;        // Stream operation success
   xrsr_protocol_t    prot;         // Protocol used for stream
   xrsr_audio_stats_t audio_stats;  // Detailed audio statistics
} xrsr_stream_stats_t;
```

### Error Handling and Recovery
Session lifecycle management includes comprehensive error handling:

#### Session Termination Reasons
```c
typedef enum {
   XRSR_SESSION_END_REASON_EOS                     = 0,  // Natural end-of-speech
   XRSR_SESSION_END_REASON_EOT                     = 1,  // End-of-text completion
   XRSR_SESSION_END_REASON_DISCONNECT_REMOTE       = 2,  // Server-initiated disconnect
   XRSR_SESSION_END_REASON_TERMINATE               = 3,  // User termination request
   XRSR_SESSION_END_REASON_ERROR_INTERNAL          = 4,  // Internal system error
   XRSR_SESSION_END_REASON_ERROR_WS_SEND           = 5,  // WebSocket transmission error
   XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN       = 6,  // Audio initialization failure
   XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION    = 7,  // Insufficient audio duration
   XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE   = 8,  // Connection establishment failure
   XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT   = 9,  // Connection timeout
   XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT   = 10, // Session operation timeout
   XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE = 11, // Unexpected server disconnect
} xrsr_session_end_reason_t;
```

## Session Lifecycle Best Practices

### Application Integration Guidelines

1. **Session UUID Tracking**: Always use UUIDs to correlate session events across callbacks
2. **State Validation**: Verify session states before performing operations
3. **Resource Management**: Properly handle session cleanup in error conditions
4. **Concurrent Session Awareness**: Design applications to handle multiple concurrent sessions
5. **Power Mode Coordination**: Account for session termination during power mode changes

### Performance Optimization

1. **Message Queue Efficiency**: Minimize message queue operations during high-frequency events
2. **Session Reuse**: Where possible, reuse session configurations for similar operations
3. **Protocol Selection**: Choose appropriate protocols based on session requirements and network conditions
4. **Stream Management**: Optimize audio streaming parameters for available bandwidth and latency requirements

### Error Recovery Strategies

1. **Automatic Retry Logic**: Implement retry mechanisms with exponential backoff for transient failures
2. **Graceful Degradation**: Provide fallback functionality when session establishment fails
3. **State Recovery**: Restore consistent state after error conditions
4. **Resource Cleanup**: Ensure complete resource cleanup on session termination or failure

This comprehensive session lifecycle management enables robust, scalable speech recognition operations suitable for production XR applications across diverse deployment scenarios and network conditions.