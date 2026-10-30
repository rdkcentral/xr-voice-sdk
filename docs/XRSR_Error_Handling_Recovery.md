# XRSR Error Handling and Recovery Documentation

## Overview
The XRSR (XR Speech Router) Error Handling and Recovery system provides comprehensive fault tolerance and resilience mechanisms across all protocol implementations, session management, and audio processing components. The system implements sophisticated timeout management, retry logic, error classification, and recovery strategies to ensure robust operation in production environments with varying network conditions and service reliability.

## Error Classification Architecture

### Session End Reason Taxonomy
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L88-L105):

The XRSR system provides comprehensive error classification for precise error handling and recovery:

```c
typedef enum {
   XRSR_SESSION_END_REASON_EOS                     = 0,  // Natural end-of-speech detection
   XRSR_SESSION_END_REASON_EOT                     = 1,  // End-of-text processing completion
   XRSR_SESSION_END_REASON_DISCONNECT_REMOTE       = 2,  // Server-initiated disconnection
   XRSR_SESSION_END_REASON_TERMINATE               = 3,  // User termination request
   XRSR_SESSION_END_REASON_ERROR_INTERNAL          = 4,  // Internal system error
   XRSR_SESSION_END_REASON_ERROR_WS_SEND           = 5,  // WebSocket transmission failure
   XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN       = 6,  // Audio initialization failure
   XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION    = 7,  // Insufficient audio duration
   XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE   = 8,  // Connection establishment failure
   XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT   = 9,  // Connection timeout expiration
   XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT   = 10, // Session operation timeout
   XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE = 11, // Unexpected server disconnect
   XRSR_SESSION_END_REASON_INVALID                 = 12, // Invalid reason code
} xrsr_session_end_reason_t;
```

### Stream End Reason Classification
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L290-L300):

```c
typedef enum {
   XRSR_STREAM_END_REASON_DID_NOT_BEGIN        = 0,  // Stream never started
   XRSR_STREAM_END_REASON_AUDIO_EOF            = 1,  // Audio end-of-file reached
   XRSR_STREAM_END_REASON_DISCONNECT_REMOTE    = 2,  // Remote disconnection
   XRSR_STREAM_END_REASON_TERMINATE            = 3,  // User termination
   XRSR_STREAM_END_REASON_INVALID              = 4   // Invalid reason
} xrsr_stream_end_reason_t;
```

### Internal Return Code System
Located in [`xrsr_private.h`](../src/xr-speech-router/xrsr_private.h#L300-L320):

```c
typedef enum {
   XRSR_RET_CODE_INTERNAL_SUCCESS              = 0,  // Successful operation
   XRSR_RET_CODE_INTERNAL_ERROR_SESSION        = 1,  // Session-level error
   XRSR_RET_CODE_INTERNAL_ERROR_CONNECT        = 2,  // Connection error
   XRSR_RET_CODE_INTERNAL_ERROR_TIMEOUT        = 3,  // Timeout error
   XRSR_RET_CODE_INTERNAL_ERROR_AUDIO          = 4,  // Audio processing error
   XRSR_RET_CODE_INTERNAL_ERROR_PROTOCOL       = 5,  // Protocol-specific error
   XRSR_RET_CODE_INTERNAL_ERROR_INVALID        = 6   // Invalid error code
} xrsr_ret_code_internal_t;
```

## Timeout Management System

### Configuration-Based Timeout Framework
Located in [`xrsr_config_default.json`](../src/xr-speech-router/xrsr_config_default.json#L6-L22):

The system implements power-mode aware timeout configuration:

#### Full Power Mode (FPM) Timeouts
```json
{
   "ws" : {
      "fpm" : {
         "connect_check_interval" :    50,  // Connection polling interval (ms)
         "timeout_connect"        :  2000,  // Connection establishment timeout (ms)
         "timeout_inactivity"     : 10000,  // Inactivity timeout (ms)
         "timeout_session"        :  5000,  // Session timeout (ms)
         "ipv4_fallback"          :  true,  // IPv4 fallback on IPv6 failure
         "backoff_delay"          :    50   // Retry backoff delay (ms)
      }
   }
}
```

#### Low Power Mode (LPM) Timeouts
```json
{
   "ws" : {
      "lpm" : {
         "connect_check_interval" :    50,  // Connection polling interval (ms)
         "timeout_connect"        : 10000,  // Extended connection timeout (ms)
         "timeout_inactivity"     : 10000,  // Extended inactivity timeout (ms)
         "timeout_session"        : 10000,  // Extended session timeout (ms)
         "ipv4_fallback"          :  true,  // IPv4 fallback on IPv6 failure
         "backoff_delay"          :   100   // Extended retry backoff delay (ms)
      }
   }
}
```

### WebSocket Timeout Configuration Structure
Located in [`xrsr_private.h`](../src/xr-speech-router/xrsr_private.h#L110-L120):

```c
typedef struct {
   bool *    ptr_debug;                    // Debug mode pointer
   bool      val_debug;                    // Debug mode value
   uint32_t *ptr_connect_check_interval;   // Connection check interval pointer
   uint32_t  val_connect_check_interval;   // Connection check interval value
   uint32_t *ptr_timeout_connect;          // Connection timeout pointer
   uint32_t  val_timeout_connect;          // Connection timeout value
   uint32_t *ptr_timeout_inactivity;       // Inactivity timeout pointer
   uint32_t  val_timeout_inactivity;       // Inactivity timeout value
   uint32_t *ptr_timeout_session;          // Session timeout pointer
   uint32_t  val_timeout_session;          // Session timeout value
   bool *    ptr_ipv4_fallback;            // IPv4 fallback pointer
   bool      val_ipv4_fallback;            // IPv4 fallback value
   uint32_t *ptr_backoff_delay;            // Backoff delay pointer
   uint32_t  val_backoff_delay;            // Backoff delay value
} xrsr_ws_json_config_t;
```

## Connection Error Handling

### WebSocket Connection State Machine
Located in [`xrsr_protocol_ws_sm.h`](../src/xr-speech-router/xrsr_protocol_ws_sm.h#L25-L45):

The WebSocket implementation uses a sophisticated state machine for error handling:

#### Error Event Definitions
```c
#define SM_EVENT_SESSION_BEGIN            (0)   // Session initiation
#define SM_EVENT_SESSION_BEGIN_STM        (1)   // Session begin with stream-to-mic
#define SM_EVENT_DISCONNECTED             (2)   // Disconnection event
#define SM_EVENT_STM                      (3)   // Stream-to-mic event
#define SM_EVENT_SOS                      (4)   // Start-of-speech
#define SM_EVENT_EOS                      (5)   // End-of-speech
#define SM_EVENT_TERMINATE                (6)   // Termination request
#define SM_EVENT_XRSR_ERROR               (7)   // XRSR internal error
#define SM_EVENT_TIMEOUT                  (8)   // Timeout expiration
#define SM_EVENT_CONNECTED                (9)   // Connection establishment
#define SM_EVENT_RETRY                    (10)  // Retry attempt
#define SM_EVENT_ESTABLISHED              (11)  // Connection established
#define SM_EVENT_WS_CLOSE                 (12)  // WebSocket close
#define SM_EVENT_CONNECT_TIMEOUT          (13)  // Connection timeout
#define SM_EVENT_MSG_RECV                 (14)  // Message reception
#define SM_EVENT_APP_CLOSE                (15)  // Application close
#define SM_EVENT_EOS_PIPE                 (16)  // End-of-speech pipe
#define SM_EVENT_WS_ERROR                 (17)  // WebSocket error
#define SM_EVENT_AUDIO_ERROR              (18)  // Audio processing error
#define SM_EVENT_ESTABLISH_TIMEOUT        (19)  // Establishment timeout
#define SM_EVENT_TEXT_SESSION_SUCCESS     (20)  // Text session success
```

#### State Transition Error Handling
```c
// Connecting State Error Transitions
tStateGuard St_Ws_Connecting_NextStates[] = 
{
    { SM_EVENT_CONNECT_TIMEOUT, &St_Ws_Disconnected_Info },   // Connection timeout -> Disconnect
    { SM_EVENT_TERMINATE,       &St_Ws_Disconnected_Info },   // Termination -> Disconnect
    { SM_EVENT_XRSR_ERROR,      &St_Ws_Disconnected_Info },   // Internal error -> Disconnect
    { SM_EVENT_TIMEOUT,         &St_Ws_Connecting_Info },     // Retry timeout -> Continue connecting
    { SM_EVENT_RETRY,           &St_Ws_Connection_Retry_Info }, // Retry -> Connection retry state
    { SM_EVENT_CONNECTED,       &St_Ws_Connected_Info }       // Success -> Connected state
};

// Connected State Error Transitions  
tStateGuard St_Ws_Connected_NextStates[] = 
{
    { SM_EVENT_ESTABLISH_TIMEOUT, &St_Ws_Disconnecting_Info }, // Establish timeout -> Disconnect
    { SM_EVENT_TERMINATE,         &St_Ws_Disconnecting_Info }, // Termination -> Disconnect
    { SM_EVENT_WS_CLOSE,          &St_Ws_Disconnected_Info },  // WebSocket close -> Disconnect
    { SM_EVENT_TIMEOUT,           &St_Ws_Connected_Info },     // Keep alive timeout -> Continue
    { SM_EVENT_ESTABLISHED,       &St_Ws_Streaming_Info }     // Establishment complete -> Streaming
};
```

### Connection Timeout Handler Implementation
Located in [`xrsr_protocol_ws.c`](../src/xr-speech-router/xrsr_protocol_ws.c#L1030-L1090):

#### Connecting State Timeout Management
```c
void St_Ws_Connecting(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   
   switch(eAction) {
      case ACT_ENTER: {
         if(!xrsr_ws_connect_new(ws)) {
            rdkx_timestamp_t timestamp;
            rdkx_timestamp_get(&timestamp);
            
            // Check if overall retry period has expired
            if(rdkx_timestamp_cmp(timestamp, ws->retry_timestamp_end) >= 0) {
               xrsr_ws_event(ws, SM_EVENT_CONNECT_TIMEOUT, true);
            } else {
               xrsr_ws_event(ws, SM_EVENT_RETRY, true);
            }
         } else {
            // Set up connection check timer
            rdkx_timestamp_t timeout;
            rdkx_timestamp_get(&timeout);
            rdkx_timestamp_add_ms(&timeout, ws->connect_check_interval);
            ws->timer_id = rdkx_timer_insert(ws->timer_obj, timeout, xrsr_ws_process_timeout, ws);
         }
         break;
      }
      
      case ACT_INTERNAL: {
         switch(pEvent->mID) {
            case SM_EVENT_TIMEOUT: {
               if(!nopoll_conn_is_ok(ws->obj_conn)) {
                  if(ws->connect_wait_time <= 0) {
                     // Connection timeout reached
                     rdkx_timestamp_t timestamp;
                     rdkx_timestamp_get(&timestamp);
                     
                     if(rdkx_timestamp_cmp(timestamp, ws->retry_timestamp_end) >= 0) {
                        xrsr_ws_event(ws, SM_EVENT_CONNECT_TIMEOUT, true);
                     } else {
                        xrsr_ws_event(ws, SM_EVENT_RETRY, true);
                     }
                  } else {
                     // Update timeout for next check
                     rdkx_timestamp_t timeout;
                     rdkx_timestamp_get(&timeout);
                     rdkx_timestamp_add_ms(&timeout, ws->connect_check_interval);
                     ws->connect_wait_time -= ws->connect_check_interval;

                     if(ws->timer_obj && ws->timer_id >= 0) {
                        if(!rdkx_timer_update(ws->timer_obj, ws->timer_id, timeout)) {
                           XLOGD_ERROR("src <%s> timer update", xrsr_src_str(ws->audio_src));
                        }
                     }
                  }
               } else {
                  // Connection successful
                  xrsr_ws_event(ws, SM_EVENT_CONNECTED, true);
               }
               break;
            }
         }
         break;
      }
      
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_CONNECT_TIMEOUT: {
               // Connection failure after timeout
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            case SM_EVENT_TERMINATE: {
               // User termination during connection
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
         }
         
         // Clean up timer resources
         if(ws->timer_obj != NULL && ws->timer_id >= 0) {
            if(!rdkx_timer_remove(ws->timer_obj, ws->timer_id)) {
               XLOGD_ERROR("src <%s> timer remove", xrsr_src_str(ws->audio_src));
            }
            ws->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
   }
}
```

## Retry Logic and Backoff Strategies

### WebSocket Connection Retry Framework
Located in [`xrsr_protocol_ws.c`](../src/xr-speech-router/xrsr_protocol_ws.c#L400-L450):

#### Retry Session Management
```c
bool xrsr_ws_connect(xrsr_state_ws_t *ws, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, 
                     xraudio_input_format_t xraudio_format, bool user_initiated, bool is_retry, 
                     bool deferred, const char **query_strs) {
                     
   // Set retry timeout period  
   rdkx_timestamp_get(&ws->retry_timestamp_end);
   rdkx_timestamp_add_ms(&ws->retry_timestamp_end, ws->timeout_session);

   ws->audio_src       = audio_src;
   ws->user_initiated  = user_initiated;
   ws->is_retry        = is_retry;
   ws->query_strs      = query_strs;
   
   // Log retry information with PII masking
   XLOGD_AUTOMATION_INFO("src <%s> local host <%s> remote host <%s> port <%s> url <%s> deferred <%s> family <%s> retry period <%u> ms", 
                        xrsr_src_str(ws->audio_src), 
                        ws->local_host_name, 
                        url_parts->host, 
                        url_parts->port_str, 
                        xrsr_mask_pii() ? "***" : ws->url, 
                        (deferred) ? "YES" : "NO", 
                        xrsr_address_family_str(url_parts->family), 
                        ws->timeout_session);

   // Initialize retry attempt counter
   ws->retry_cnt = 1;
   XLOGD_INFO("src <%s> attempt <%u>", xrsr_src_str(ws->audio_src), ws->retry_cnt);

   return(true);
}
```

#### Connection Retry State Implementation
```c
void St_Ws_Connection_Retry(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   
   switch(eAction) {
      case ACT_ENTER: {
         // Increment retry counter
         ws->retry_cnt++;
         XLOGD_INFO("src <%s> retry attempt <%u>", xrsr_src_str(ws->audio_src), ws->retry_cnt);
         
         // Apply backoff delay
         rdkx_timestamp_t timeout;
         rdkx_timestamp_get(&timeout);
         uint32_t backoff_delay = ws->backoff_delay * ws->retry_cnt; // Linear backoff
         rdkx_timestamp_add_ms(&timeout, backoff_delay);
         
         ws->timer_id = rdkx_timer_insert(ws->timer_obj, timeout, xrsr_ws_process_timeout, ws);
         break;
      }
      
      case ACT_INTERNAL: {
         switch(pEvent->mID) {
            case SM_EVENT_TIMEOUT: {
               // Backoff period complete, retry connection
               xrsr_ws_event(ws, SM_EVENT_SESSION_BEGIN, false);
               break;
            }
         }
         break;
      }
      
      case ACT_EXIT: {
         // Clean up retry timer
         if(ws->timer_obj != NULL && ws->timer_id >= 0) {
            if(!rdkx_timer_remove(ws->timer_obj, ws->timer_id)) {
               XLOGD_ERROR("src <%s> retry timer remove", xrsr_src_str(ws->audio_src));
            }
            ws->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
   }
}
```

### Write Operation Retry Logic
Located in [`xrsr_protocol_ws.c`](../src/xr-speech-router/xrsr_protocol_ws.c#L300-L320):

```c
#define XRSR_WS_WRITE_PENDING_RETRY_MAX  3  // Maximum write retry attempts

// Write operation with retry handling
if(ws->write_pending_retries > XRSR_WS_WRITE_PENDING_RETRY_MAX) {
   XLOGD_ERROR("src <%s> maximum write retries exceeded <%u>", 
               xrsr_src_str(ws->audio_src), 
               ws->write_pending_retries);
   
   ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
   ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_WS_SEND;
   xrsr_ws_terminate(ws);
} else {
   // Increment retry counter and attempt write again
   ws->write_pending_retries++;
   XLOGD_WARN("src <%s> write retry attempt <%u>", 
              xrsr_src_str(ws->audio_src), 
              ws->write_pending_retries);
}
```

## HTTP Protocol Error Handling

### HTTP Session Timeout Management
Located in [`xrsr_protocol_http.c`](../src/xr-speech-router/xrsr_protocol_http.c#L850-L950):

#### Connection Failure Handling
```c
switch(http->state) {
   case XRSR_STATE_HTTP_CONNECTED: {
      if(curl_code != CURLE_OK || response_code != 200) {
         if(curl_code == CURLE_OPERATION_TIMEDOUT) {
            XLOGD_ERROR("src <%s> HTTP request timed out", xrsr_src_str(http->audio_src));
            http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT;
         } else {
            XLOGD_ERROR("src <%s> HTTP connection failed: curl_code <%d> response_code <%ld>", 
                        xrsr_src_str(http->audio_src), curl_code, response_code);
            http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE;
         }
         
         // Record error details in session statistics
         http->session_stats.ret_code_protocol = response_code;
         http->session_stats.ret_code_library  = curl_code;
         
         xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, 
                               XRSR_STREAM_END_REASON_DISCONNECT_REMOTE, 
                               http->detect_resume, &http->audio_stats);
      }
      break;
   }
   
   case XRSR_STATE_HTTP_TERMINATED: {
      if(terminate_reason == XRSR_SESSION_END_REASON_TERMINATE) {
         XLOGD_INFO("src <%s> terminated by user", xrsr_src_str(http->audio_src));
         http->session_stats.reason = XRSR_SESSION_END_REASON_TERMINATE;
      } else {
         XLOGD_ERROR("src <%s> session terminated due to audio duration", xrsr_src_str(http->audio_src));
         http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION;
      }
      break;
   }
}
```

### Audio Duration Error Handling
```c
if(http->audio_bytes_rxd < XRSR_HTTP_MIN_AUDIO_DURATION_BYTES) {
   XLOGD_ERROR("src <%s> insufficient audio duration: received <%u> bytes, minimum required <%u> bytes", 
               xrsr_src_str(http->audio_src), 
               http->audio_bytes_rxd, 
               XRSR_HTTP_MIN_AUDIO_DURATION_BYTES);
               
   http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION;
   xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, 
                         XRSR_STREAM_END_REASON_DID_NOT_BEGIN, 
                         http->detect_resume, &http->audio_stats);
}
```

## Audio Processing Error Handling

### XRAudio Integration Error Management
Located in [`xrsr_xraudio.c`](../src/xr-speech-router/xrsr_xraudio.c#L200-L250):

#### Keyword Detection Error Handling
```c
void xrsr_xraudio_keyword_callback(xraudio_devices_input_t source, 
                                  xraudio_keyword_callback_event_t event, 
                                  void *data, 
                                  unsigned long size, 
                                  void *user_data) {
                                  
   if(event == KEYWORD_CALLBACK_EVENT_ERROR || event == KEYWORD_CALLBACK_EVENT_ERROR_FD) {
      XLOGD_ERROR("keyword callback error: source <%s> event <%s>", 
                  xrsr_src_str(source), 
                  xraudio_keyword_callback_event_str(event));
      
      // Send keyword detection error message
      xrsr_queue_msg_keyword_detected_t msg;
      msg.header.type = XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECT_ERROR;
      msg.source      = source;
      
      xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
      return;
   }
   
   // Handle successful keyword detection
   xrsr_keyword_detector_result_t *detector_result = (xrsr_keyword_detector_result_t *)data;
   
   if(detector_result == NULL || size != sizeof(xrsr_keyword_detector_result_t)) {
      XLOGD_ERROR("invalid keyword detection result: size <%lu> expected <%zu>", 
                  size, sizeof(xrsr_keyword_detector_result_t));
      return;
   }
}
```

#### Audio Stream Error Handling
```c
void xrsr_xraudio_stream_callback(xraudio_devices_input_t source, 
                                 xraudio_input_callback_event_t event, 
                                 void *data, 
                                 unsigned long size, 
                                 void *user_data) {
                                 
   switch(event) {
      case AUDIO_IN_CALLBACK_EVENT_ERROR: {
         XLOGD_ERROR("audio stream error: source <%s>", xrsr_src_str(source));
         
         // Send audio stream error event
         xrsr_queue_msg_xraudio_in_event_t msg;
         msg.header.type = XRSR_QUEUE_MSG_TYPE_XRAUDIO_EVENT;
         msg.event.src   = source;
         msg.event.event = XRSR_EVENT_STREAM_ERROR;
         
         xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
         break;
      }
      
      case AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_INITIAL:
      case AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_END: {
         XLOGD_INFO("audio EOS timeout: source <%s> event <%s>", 
                    xrsr_src_str(source), 
                    xraudio_input_callback_event_str(event));
         
         // Handle end-of-speech timeout
         xrsr_queue_msg_xraudio_in_event_t msg;
         msg.header.type = XRSR_QUEUE_MSG_TYPE_XRAUDIO_EVENT;
         msg.event.src   = source;
         msg.event.event = XRSR_EVENT_EOS_TIMEOUT;
         
         xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
         break;
      }
   }
}
```

### Microphone Error Recovery
```c
bool xrsr_xraudio_device_open(xrsr_xraudio_object_t object, 
                              xraudio_devices_input_t device, 
                              xraudio_input_format_t format) {
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   
   // Attempt to open audio device
   result = xraudio_input_open(object->obj_input, device, format, 
                              xrsr_xraudio_stream_callback, object);
   
   if(result != XRAUDIO_RESULT_OK) {
      if(XRAUDIO_RESULT_ERROR_MIC_OPEN == result) {
         XLOGD_ERROR("microphone open failed: device <%s> format <%s>", 
                     xraudio_devices_input_str(device), 
                     xraudio_input_format_str(format));
      } else {
         XLOGD_ERROR("audio device open failed: result <%s> device <%s> format <%s>", 
                     xraudio_result_str(result), 
                     xraudio_devices_input_str(device), 
                     xraudio_input_format_str(format));
      }
      
      // Attempt recovery by requesting resource management
      #ifdef XRAUDIO_RESOURCE_MGMT
      xrsr_xraudio_device_request(object);
      #endif
      
      return(false);
   }
   
   return(true);
}
```

## Session Error Recovery Strategies

### Power Mode Error Coordination
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L1700-L1750):

#### Low Power Mode Session Termination
```c
void xrsr_msg_power_mode_update(const xrsr_thread_params_t *params, 
                               xrsr_thread_state_t *state, 
                               void *msg) {
   xrsr_queue_msg_power_mode_update_t *power_mode_update = (xrsr_queue_msg_power_mode_update_t *)msg;

   XLOGD_AUTOMATION_INFO("power mode <%s>", xrsr_power_mode_str(power_mode_update->power_mode));

   // Terminate active sessions when entering low power mode to avoid resource conflicts
   if(power_mode_update->power_mode != XRSR_POWER_MODE_FULL) {
      for(uint32_t group = 0; group < XRSR_SESSION_GROUP_QTY; group++) {
         xrsr_session_t *session = &g_xrsr.sessions[group];
         
         if((uint32_t)session->src < XRSR_SRC_INVALID) {
            XLOGD_INFO("terminate source <%s> for power mode transition", xrsr_src_str(session->src));
            
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
               
               // Update timeout parameters for new power mode
               xrsr_ws_update_dst_params(ws, &dst->dst_param_ptrs[power_mode_update->power_mode]);
               break;
            }
         }
      }
   }
}
```

### Audio Error Recovery Handling
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L1850-L1900):

```c
void xrsr_msg_xraudio_event(const xrsr_thread_params_t *params, 
                           xrsr_thread_state_t *state, 
                           void *msg) {
   xrsr_queue_msg_xraudio_in_event_t *event = (xrsr_queue_msg_xraudio_in_event_t *)msg;

   if(event == NULL) {
      XLOGD_ERROR("invalid event");
      return;
   }

   xrsr_src_t src = event->event.src;

   if((uint32_t)src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }

   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("inactive source <%s>", xrsr_src_str(src));
      return;
   }

   // Handle audio stream errors with resource recovery
   if(event->event.event == XRSR_EVENT_STREAM_ERROR) {
      XLOGD_ERROR("audio stream error on source <%s>", xrsr_src_str(src));
      
      // Close audio device and terminate active session
      xrsr_xraudio_device_close(g_xrsr.xrsr_xraudio_object);
      
      if(xrsr_is_source_active(src)) {
         XLOGD_INFO("terminate source <%s> due to stream error", xrsr_src_str(src));
         
         xrsr_queue_msg_session_terminate_t terminate;
         terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
         terminate.semaphore   = NULL;
         terminate.src         = src;
         
         xrsr_msg_session_terminate(params, state, &terminate);
      }
      
      // Request audio device resource for recovery
      #ifdef XRAUDIO_RESOURCE_MGMT
      xrsr_xraudio_device_request(g_xrsr.xrsr_xraudio_object);
      #else
      xrsr_xraudio_device_granted(g_xrsr.xrsr_xraudio_object);
      #endif
      
      return;
   }

   // Forward event to protocol handlers for processing
   uint32_t index_src = src;
   for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

      switch(dst->url_parts.prot) {
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            xrsr_state_http_t *http = &dst->conn_state.http;
            xrsr_http_handle_speech_event(http, &event->event);
            break;
         }
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            xrsr_ws_handle_speech_event(ws, &event->event);
            break;
         }
      }
   }
}
```

## Keyword Detection Error Recovery

### Multi-Source Error Coordination
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L1950-L2000):

```c
void xrsr_msg_keyword_detect_error(const xrsr_thread_params_t *params, 
                                  xrsr_thread_state_t *state, 
                                  void *msg) {
   xrsr_queue_msg_keyword_detected_t *keyword_detected = (xrsr_queue_msg_keyword_detected_t *)msg;

   XLOGD_ERROR("keyword detection error: source <%s>", xrsr_src_str(keyword_detected->source));
   
   // Handle keyword detection error
   xrsr_xraudio_keyword_detect_error(g_xrsr.xrsr_xraudio_object, keyword_detected->source);

   // Terminate active session on error source
   if(xrsr_is_source_active(keyword_detected->source)) {
      XLOGD_INFO("terminate source <%s> due to keyword detection error", xrsr_src_str(keyword_detected->source));
      
      xrsr_queue_msg_session_terminate_t terminate;
      terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
      terminate.semaphore   = NULL;
      terminate.src         = keyword_detected->source;
      
      xrsr_msg_session_terminate(params, state, &terminate);
   }

   // Handle microphone tap error coordination
   if(keyword_detected->source == XRSR_SRC_MICROPHONE && 
      xrsr_is_source_active(XRSR_SRC_MICROPHONE_TAP)) {
      XLOGD_INFO("terminate microphone tap source due to main microphone error");
      
      xrsr_queue_msg_session_terminate_t terminate;
      terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
      terminate.semaphore   = NULL;
      terminate.src         = XRSR_SRC_MICROPHONE_TAP;
      
      xrsr_msg_session_terminate(params, state, &terminate);
   }
}
```

## Error Statistics and Performance Monitoring

### Comprehensive Session Statistics
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L373-L403):

#### Session Performance Metrics
```c
typedef struct {
   xrsr_session_end_reason_t reason;                             // Session termination reason
   xrsr_ret_code_internal_t  ret_code_internal;                  // Internal return code
   long                      ret_code_protocol;                  // Protocol HTTP/WebSocket code
   long                      ret_code_library;                   // Library-specific return code
   char                      server_ip[XRSR_SESSION_IP_LEN_MAX]; // Connected server IP address
   double                    time_connect;                       // Connection establishment time
   double                    time_dns;                           // DNS resolution time
} xrsr_session_stats_t;

typedef struct {
   bool     valid;                // Statistics validity flag
   uint32_t packets_processed;    // Total audio packets processed
   uint32_t packets_lost;         // Audio packets lost during transmission
   uint32_t samples_processed;    // Total audio samples processed
   uint32_t samples_lost;         // Audio samples lost during transmission
   uint32_t decoder_failures;     // Audio decoder failure count
   uint32_t samples_buffered_max; // Maximum buffered sample count
} xrsr_audio_stats_t;

typedef struct {
   bool               result;        // Stream operation success indicator
   xrsr_protocol_t    prot;         // Protocol used for stream
   xrsr_audio_stats_t audio_stats;  // Detailed audio processing statistics
} xrsr_stream_stats_t;
```

### Error Reporting and Callback Integration
Session end statistics are automatically provided to applications through the session end callback:

```c
void session_end_handler(void *data, 
                        const uuid_t uuid, 
                        xrsr_session_stats_t *stats, 
                        rdkx_timestamp_t *timestamp) {
   // Analyze error conditions
   switch(stats->reason) {
      case XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE: {
         XLOGD_ERROR("Connection failed: protocol_code <%ld> library_code <%ld> server_ip <%s>", 
                     stats->ret_code_protocol, 
                     stats->ret_code_library, 
                     stats->server_ip);
         
         // Implement application-specific error recovery
         schedule_retry_with_backoff();
         break;
      }
      
      case XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT: {
         XLOGD_ERROR("Session timeout: connect_time <%.3f> dns_time <%.3f>", 
                     stats->time_connect, 
                     stats->time_dns);
         
         // Consider network condition adjustment
         adjust_timeout_parameters();
         break;
      }
      
      case XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION: {
         XLOGD_ERROR("Insufficient audio duration");
         
         // Adjust audio capture parameters
         increase_min_audio_duration();
         break;
      }
   }
}
```

## Error Handling Best Practices

### Application Integration Guidelines

1. **Comprehensive Error Monitoring**: Implement handlers for all error callback types
2. **Adaptive Timeout Management**: Adjust timeout parameters based on network conditions
3. **Graceful Degradation**: Provide fallback functionality for critical error scenarios
4. **Resource Recovery**: Properly handle resource cleanup and reinitialization
5. **Error Classification**: Distinguish between recoverable and non-recoverable errors

### Network Resilience Strategies

1. **IPv4/IPv6 Fallback**: Enable automatic fallback for connection failures
2. **Exponential Backoff**: Implement increasing retry delays to avoid server overload
3. **Circuit Breaker Pattern**: Temporarily disable failing endpoints to prevent cascading failures
4. **Connection Pooling**: Reuse established connections when possible
5. **Health Monitoring**: Continuously monitor connection health and proactively handle degradation

### Audio Processing Error Recovery

1. **Device Recovery**: Implement automatic audio device reinitialization on hardware errors
2. **Format Negotiation**: Provide fallback audio formats for compatibility issues
3. **Buffer Management**: Handle audio buffer overruns and underruns gracefully
4. **Multi-Source Coordination**: Coordinate error handling across multiple audio sources
5. **Quality Monitoring**: Monitor audio quality metrics and adjust parameters dynamically

This comprehensive error handling and recovery system ensures robust operation of the XR Voice SDK across diverse deployment scenarios, network conditions, and hardware configurations, providing production-ready reliability for voice-enabled XR applications.