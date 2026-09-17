# XRSR SDT (Service Discovery and Transport) Protocol Analysis Documentation

## Overview
The XRSR SDT (Service Discovery and Transport) protocol represents a framework stub for implementing custom service discovery and transport mechanisms within the XRSR speech routing architecture. Unlike the fully-implemented HTTP and WebSocket protocols, SDT serves as a minimal template and testing framework that demonstrates the protocol abstraction capabilities of XRSR while providing hooks for future custom protocol implementations.

## Architectural Overview

### Design Intent and Purpose
The SDT protocol was designed as a proof-of-concept and extensibility framework that allows developers to:

1. **Prototype Custom Protocols**: Rapidly develop and test new speech recognition transport protocols
2. **Service Discovery Integration**: Provide hooks for dynamic service discovery mechanisms
3. **Protocol Abstraction Testing**: Validate the XRSR protocol abstraction layer
4. **Development and Debugging**: Offer simplified protocol behavior for testing scenarios

### Current Implementation Status
The SDT protocol is currently implemented as a **minimal stub** with the following characteristics:

- **No Network Communication**: Does not establish actual network connections
- **Simulated State Transitions**: Provides complete state machine behavior without real protocol logic
- **Framework Completeness**: Implements all required XRSR protocol interfaces
- **Audio Pipeline Integration**: Fully integrates with XRSR audio streaming capabilities
- **Event Handling**: Complete speech event processing and callback management

## Core Data Structures

### SDT Protocol State Management
Located in [`xrsr_protocol_sdt.h`](../src/xr-speech-router/xrsr_protocol_sdt.h#L30-L90):

```c
typedef struct {
    xrsr_protocol_t               prot;                    // Protocol identifier (SDT)
    xrsr_handlers_t               handlers;                // Callback function set
    uuid_t                        uuid;                    // Session unique identifier
    xrsr_session_config_out_t     session_config_out;      // Outgoing configuration
    
    /* Timer and Session Management */
    rdkx_timer_object_t           timer_obj;               // Timer management object
    rdkx_timer_id_t               timer_id;                // Active timer identifier
    uint32_t                      retry_cnt;               // Connection retry counter
    rdkx_timestamp_t              retry_timestamp_end;     // Retry timeout timestamp
    int32_t                       connect_wait_time;       // Connection establishment timeout
    bool                          stream_time_min_rxd;     // Minimum stream time received
    
    /* URL and Connection Details (Stub) */
    xrsr_url_parts_t *            url_parts;               // URL components (unused)
    char                          url[XRSR_SDT_URL_SIZE_MAX]; // URL string (unused)
    const char *                  sat_token;               // Security token (unused)
    
    /* Audio Session Parameters */
    xrsr_src_t                    audio_src;               // Audio source type
    uint32_t                      dst_index;               // Destination index
    xrsr_session_request_t        input_format;            // Input format specification
    xraudio_input_format_t        xraudio_format;          // XRAudio format details
    bool                          user_initiated;          // User-initiated session flag
    bool                          low_latency;             // Low latency mode
    bool                          low_cpu_util;            // CPU optimization mode
    
    /* Audio Data Handling */
    int                           audio_pipe_fd_read;      // Audio input pipe descriptor
    bool                          write_pending_bytes;     // Write flow control flag
    uint8_t                       write_pending_retries;   // Write retry counter
    char                          local_host_name[XRSR_SDT_HOST_NAME_LEN_MAX]; // Local hostname
    uint8_t                       buffer[4096];            // Audio data buffer
    
    /* Session Statistics */
    xrsr_session_stats_t          stats;                   // Session performance metrics
    xrsr_audio_stats_t            audio_stats;             // Audio processing statistics
    bool                          on_close;                // Connection close flag
    
    /* Message Queue Management */
    sem_t                         msg_out_semaphore;       // Message queue synchronization
    uint8_t                       msg_out_count;           // Queued message count
    char *                        msg_out[XRSR_SDT_MSG_OUT_MAX]; // Outgoing message queue
    
    /* Audio Keyword Detection */
    bool                          audio_kwd_notified;      // Keyword notification sent
    uint32_t                      audio_kwd_bytes;         // Keyword audio bytes count
    uint32_t                      audio_txd_bytes;         // Total transmitted bytes
    
    /* Configuration Parameters */
    uint32_t                      connect_check_interval;  // Connection health check interval
    uint32_t                      timeout_connect;         // Connection establishment timeout
    uint32_t                      timeout_inactivity;      // Inactivity timeout
    uint32_t                      timeout_session;         // Session timeout
    bool                          ipv4_fallback;           // IPv4 fallback enabled (unused)
    uint32_t                      backoff_delay;           // Retry backoff delay
    
    /* State Machine Management */
    tSmInstance                   state_machine;           // State machine instance
    tStateEvent                   state_machine_events_active[XRSR_SDT_SM_EVENTS_MAX]; // Event queue
    xrsr_stream_end_reason_t      stream_end_reason;       // Stream termination reason
    xrsr_session_end_reason_t     session_end_reason;      // Session termination reason
    bool                          detect_resume;           // Detection resume flag
    xrsr_session_config_update_t *session_config_update;   // Configuration updates
} xrsr_state_sdt_t;
```

### SDT Parameters Structure
```c
typedef struct {
    xrsr_protocol_t     prot;                    // Protocol type (SDT)
    const char *        host_name;               // Local hostname identifier
    rdkx_timer_object_t timer_obj;              // Timer management object
    bool *              debug;                   // Debug logging enabled pointer
    uint32_t *          connect_check_interval;  // Connection check interval pointer
    uint32_t *          timeout_connect;         // Connection timeout pointer
    uint32_t *          timeout_inactivity;      // Inactivity timeout pointer
    uint32_t *          timeout_session;         // Session timeout pointer
    bool *              ipv4_fallback;          // IPv4 fallback pointer (unused)
    uint32_t *          backoff_delay;          // Backoff delay pointer
} xrsr_sdt_params_t;
```

## SDT State Machine Architecture

### State Machine Events
Located in [`xrsr_protocol_sdt_sm.h`](../src/xr-speech-router/xrsr_protocol_sdt_sm.h#L20-L35):

The SDT state machine uses a simplified set of events compared to WebSocket:

```c
#define SM_EVENT_SESSION_BEGIN            (0)   // Session initiation
#define SM_EVENT_SESSION_BEGIN_STM        (1)   // Session begin with stream-time minimum
#define SM_EVENT_DISCONNECTED             (2)   // Connection lost (simulated)
#define SM_EVENT_STM                      (3)   // Stream-time minimum reached
#define SM_EVENT_EOS                      (4)   // End-of-speech detected
#define SM_EVENT_TERMINATE                (5)   // Session termination requested
#define SM_EVENT_XRSR_ERROR               (6)   // XRSR internal error
#define SM_EVENT_TIMEOUT                  (7)   // Timeout occurred
#define SM_EVENT_CONNECTED                (8)   // Connection established (simulated)
#define SM_EVENT_RETRY                    (9)   // Connection retry initiated
#define SM_EVENT_ESTABLISHED              (10)  // Protocol established (simulated)
#define SM_EVENT_WS_CLOSE                 (11)  // Connection closed (simulated)
#define SM_EVENT_CONNECT_TIMEOUT          (12)  // Connection establishment timeout
#define SM_EVENT_MSG_RECV                 (13)  // Message received (simulated)
#define SM_EVENT_APP_CLOSE                (14)  // Application-initiated close
#define SM_EVENT_EOS_PIPE                 (15)  // Audio pipe end-of-stream
#define SM_EVENT_WS_ERROR                 (16)  // Protocol error (simulated)
#define SM_EVENT_AUDIO_ERROR              (17)  // Audio system error
#define SM_EVENT_ESTABLISH_TIMEOUT        (18)  // Protocol establishment timeout
```

### State Definitions and Behavior

#### State Transition Matrix

| Current State | Key Events | Next States | Implementation Status |
|---------------|------------|-------------|----------------------|
| **St_Sdt_Disconnected** | SESSION_BEGIN | St_Sdt_Connecting | ✓ Complete - Initiates session |
| **St_Sdt_Disconnected** | SESSION_BEGIN_STM | St_Sdt_Buffering | ✓ Complete - Buffered session start |
| **St_Sdt_Disconnecting** | DISCONNECTED | St_Sdt_Disconnected | ✓ Complete - Clean disconnection |
| **St_Sdt_Buffering** | EOS | St_Sdt_Disconnected | ✓ Complete - Early termination |
| **St_Sdt_Buffering** | TERMINATE | St_Sdt_Disconnected | ✓ Complete - User termination |
| **St_Sdt_Buffering** | STM | St_Sdt_Connecting | ✓ Complete - Minimum stream time |
| **St_Sdt_Connecting** | CONNECT_TIMEOUT | St_Sdt_Disconnected | ⚠️ Stub - Always succeeds immediately |
| **St_Sdt_Connecting** | CONNECTED | St_Sdt_Connected | ⚠️ Stub - Automatic transition |
| **St_Sdt_Connected** | ESTABLISHED | St_Sdt_Streaming | ⚠️ Stub - Immediate establishment |
| **St_Sdt_Established** | MSG_RECV | St_Sdt_Established | ⚠️ Stub - No real message processing |
| **St_Sdt_Streaming** | EOS_PIPE | St_Sdt_Established | ✓ Complete - Audio stream end |

## Stub Implementation Analysis

### Simulated Connection Logic
Located in [`xrsr_protocol_sdt.c`](../src/xr-speech-router/xrsr_protocol_sdt.c#L200-L250):

```c
bool xrsr_sdt_connect_new(xrsr_state_sdt_t *sdt) {
    xrsr_url_parts_t *url_parts = sdt->url_parts;
    
    // Create origin string (unused but maintained for compatibility)
    const char *origin_fmt = "http://%s:%s";
    uint32_t origin_size = strlen(url_parts->host) + strlen(url_parts->port_str) + strlen(origin_fmt) - 3;
    char origin[origin_size];
    snprintf(origin, sizeof(origin), origin_fmt, url_parts->host, url_parts->port_str);
    
    XLOGD_INFO("attempt <%u>", sdt->retry_cnt);
    
    // STUB: Always return success - no actual connection attempted
    return(true);
}

bool xrsr_sdt_conn_is_ready(xrsr_state_sdt_t *sdt) {
    if(sdt == NULL) {
        XLOGD_ERROR("NULL xrsr_state_sdt_t");
        return(false);
    }
    
    // STUB: Always report connection as ready
    return(true);
}
```

### Simulated Data Transmission
```c
int xrsr_sdt_send_binary(xrsr_state_sdt_t *sdt, const uint8_t *buffer, uint32_t length) {
    if(sdt == NULL) {
        XLOGD_ERROR("NULL xrsr_state_sdt_t");
        return(-1);
    } else if(!xrsr_sdt_is_established(sdt)) {
        XLOGD_ERROR("invalid state");
        return(-1);
    }
    
    XLOGD_INFO("length <%u>", length);
    
    // STUB: Pretend data was transmitted successfully
    return length;
}

int xrsr_sdt_send_text(xrsr_state_sdt_t *sdt, const uint8_t *buffer, uint32_t length) {
    if(sdt == NULL) {
        XLOGD_ERROR("NULL xrsr_state_sdt_t");
        return(-1);
    } else if(!xrsr_sdt_is_established(sdt)) {
        XLOGD_ERROR("invalid state");
        return(-1);
    }
    
    XLOGD_DEBUG("length <%u>", length);
    
    // STUB: Queue message (but never actually send)
    bool ret = xrsr_sdt_queue_msg_out(sdt, (const char *)buffer, length);
    return (ret ? 1 : 0);
}
```

### Audio Processing Integration
The SDT protocol does integrate fully with the XRSR audio pipeline, demonstrating proper audio handling:

```c
void xrsr_sdt_handle_fds(xrsr_state_sdt_t *sdt, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    // Process audio data from input pipeline
    if(sdt->audio_pipe_fd_read >= 0 && FD_ISSET(sdt->audio_pipe_fd_read, readfds)) {
        int rc = read(sdt->audio_pipe_fd_read, sdt->buffer, sizeof(sdt->buffer));
        
        if(rc < 0) {
            int errsv = errno;
            if(errsv == EAGAIN || errsv == EWOULDBLOCK) {
                XLOGD_INFO("read would block");
                xrsr_sdt_event(sdt, SM_EVENT_AUDIO_ERROR, false);
            } else {
                XLOGD_ERROR("pipe read error <%s>", strerror(errsv));
                xrsr_sdt_event(sdt, SM_EVENT_AUDIO_ERROR, false);
            }
        } else if(rc == 0) { // EOF
            XLOGD_INFO("pipe read EOF");
            xrsr_sdt_event(sdt, SM_EVENT_EOS_PIPE, false);
        } else {
            XLOGD_INFO("pipe read <%d>", rc);
            uint32_t bytes_read = (uint32_t)rc;
            
            // Forward audio data to stream handler (if available)
            if(sdt->handlers.stream_audio == NULL) {
                XLOGD_INFO("stream data handler not available");
            } else {
                (*sdt->handlers.stream_audio)(sdt->buffer, bytes_read);
            }
            
            // Handle keyword detection notification
            if(!sdt->audio_kwd_notified && (sdt->audio_txd_bytes >= sdt->audio_kwd_bytes)) {
                if(!xrsr_speech_stream_kwd(sdt->uuid, sdt->audio_src, sdt->dst_index)) {
                    XLOGD_ERROR("xrsr_speech_stream_kwd failed");
                }
                sdt->audio_kwd_notified = true;
            }
        }
    }
}
```

## State Machine Implementation Details

### Connection State Handling
```c
void St_Sdt_Connecting(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
    
    switch(eAction) {
        case ACT_ENTER: {
            // STUB: Simulate connection attempt
            if(!xrsr_sdt_connect_new(sdt)) {
                // Connection failed (but this never happens in stub)
                rdkx_timestamp_t timestamp;
                rdkx_timestamp_get(&timestamp);
                xrsr_sdt_event(sdt, SM_EVENT_CONNECTED, true);
            } else {
                // Connection succeeded (always in stub)
                rdkx_timestamp_t timeout;
                rdkx_timestamp_get(&timeout);
                rdkx_timestamp_add_ms(&timeout, sdt->connect_check_interval);
                xrsr_sdt_event(sdt, SM_EVENT_CONNECTED, true);
            }
            break;
        }
        // ... error handling cases ...
    }
}
```

### Session Streaming State
```c
void St_Sdt_Streaming(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
    
    switch(eAction) {
        case ACT_ENTER: {
            // Notify XRSR framework that connection is established
            if(sdt->handlers.connected == NULL) {
                XLOGD_INFO("connected handler not available");
            } else {
                rdkx_timestamp_t timestamp;
                rdkx_timestamp_get_realtime(&timestamp);
                (*sdt->handlers.connected)(sdt->handlers.data, sdt->uuid, xrsr_conn_send, 
                                         (void *)sdt, &timestamp, sdt->session_config_update);
            }
            
            // Begin session stream reporting
            char uuid_str[37] = {'\0'};
            uuid_unparse_lower(sdt->uuid, uuid_str);
            xrsr_session_stream_begin(sdt->uuid, uuid_str, sdt->audio_src, sdt->dst_index);
            break;
        }
        // ... exit handling for various stream end scenarios ...
    }
}
```

## Message Queue Implementation

### Thread-Safe Message Management
```c
bool xrsr_sdt_queue_msg_out(xrsr_state_sdt_t *sdt, const char *msg, uint32_t length) {
    bool ret = false;
    sem_wait(&sdt->msg_out_semaphore);
    
    if(sdt->msg_out_count < XRSR_SDT_MSG_OUT_MAX) {
        uint32_t buf_len = length + 1;
        sdt->msg_out[sdt->msg_out_count] = (char *)malloc(sizeof(char) * buf_len);
        
        if(sdt->msg_out[sdt->msg_out_count] == NULL) {
            XLOGD_ERROR("failed to allocate msg_out buffer");
        } else {
            snprintf(sdt->msg_out[sdt->msg_out_count], buf_len, "%s", msg);
            sdt->msg_out_count++;
            ret = true;
        }
    }
    
    sem_post(&sdt->msg_out_semaphore);
    return(ret);
}

void xrsr_sdt_clear_msg_out(xrsr_state_sdt_t *sdt) {
    uint8_t i = 0;
    sem_wait(&sdt->msg_out_semaphore);
    
    for(i = 0; i < XRSR_SDT_MSG_OUT_MAX; i++) {
        if(sdt->msg_out[i] != NULL) {
            free(sdt->msg_out[i]);
            sdt->msg_out[i] = NULL;
        }
    }
    sdt->msg_out_count = 0;
    
    sem_post(&sdt->msg_out_semaphore);
}
```

## Configuration and Parameters

### Default Configuration Values
Located in [`xrsr_protocol_sdt.c`](../src/xr-speech-router/xrsr_protocol_sdt.c#L80-L95):

```c
bool xrsr_sdt_init(xrsr_state_sdt_t *sdt, xrsr_sdt_params_t *params) {
    // Initialize default configuration values
    sdt->on_close           = false;
    sdt->detect_resume      = true;
    sdt->write_pending_bytes = false;
    
    // Connection and timeout configuration
    sdt->connect_check_interval = 20;     // 20ms connection health checks
    sdt->timeout_connect        = 2000;   // 2 second connection timeout
    sdt->timeout_inactivity     = 2000;   // 2 second inactivity timeout
    sdt->backoff_delay          = 10;     // 10ms base backoff delay
    
    // Initialize message queue
    sem_init(&sdt->msg_out_semaphore, 0, 1);
    sdt->msg_out_count = 0;
    memset(sdt->msg_out, 0, sizeof(sdt->msg_out));
    
    return(true);
}
```

### Resource Limits and Constraints
```c
#define XRSR_SDT_HOST_NAME_LEN_MAX       (64)    // Maximum hostname length
#define XRSR_SDT_URL_SIZE_MAX            (2048)  // Maximum URL length (unused)
#define XRSR_SDT_SM_EVENTS_MAX           (5)     // State machine event queue depth
#define XRSR_SDT_MSG_OUT_MAX             (5)     // Outgoing message queue depth
#define XRSR_SDT_WRITE_PENDING_RETRY_MAX (5)     // Maximum write retry attempts (unused)
```

## Integration with XRSR Framework

### Callback Integration
```c
void xrsr_sdt_handle_speech_event(xrsr_state_sdt_t *sdt, xrsr_speech_event_t *event) {
    switch(event->event) {
        case XRSR_EVENT_EOS: {
            xrsr_sdt_event(sdt, SM_EVENT_EOS, false);
            break;
        }
        case XRSR_EVENT_STREAM_KWD_INFO: {
            sdt->audio_kwd_notified = false;
            sdt->audio_kwd_bytes    = event->data.byte_qty;
            break;
        }
        case XRSR_EVENT_STREAM_TIME_MINIMUM: {
            sdt->stream_time_min_rxd = true;
            xrsr_sdt_event(sdt, SM_EVENT_STM, false);
            break;
        }
        default: {
            XLOGD_WARN("unhandled speech event <%s>", xrsr_event_str(event->event));
            break;
        }
    }
}
```

### Session Lifecycle Management
- **UUID Tracking**: Full session correlation with unique identifiers
- **Audio Format Integration**: Proper XRAudio pipeline integration
- **Statistics Collection**: Complete session metrics and performance tracking
- **Error Handling**: Comprehensive error classification and reporting
- **State Synchronization**: Full state machine integration with XRSR framework

## Use Cases and Applications

### Development and Testing
1. **Protocol Development**: Template for implementing custom speech recognition protocols
2. **XRSR Testing**: Validation of protocol abstraction layer without network dependencies
3. **Audio Pipeline Testing**: Testing audio processing without network complexity
4. **State Machine Validation**: Testing state transitions and error handling

### Future Enhancement Opportunities
1. **Service Discovery**: Implement actual service discovery mechanisms (mDNS, DNS-SD, etc.)
2. **Custom Transport**: Add proprietary transport protocols for specialized deployments
3. **P2P Communication**: Direct peer-to-peer speech recognition protocols
4. **Edge Computing**: Local speech recognition service routing

## Comparison with Other XRSR Protocols

| Feature | HTTP | WebSocket | SDT |
|---------|------|-----------|-----|
| **Network Implementation** | ✓ Complete (libcurl) | ✓ Complete (noPoll) | ⚠️ Stub Only |
| **Connection Management** | ✓ Request-Response | ✓ Persistent | ⚠️ Simulated |
| **Security/TLS** | ✓ Full Support | ✓ Full Support | ✗ Not Implemented |
| **Authentication** | ✓ Bearer Tokens | ✓ Bearer Tokens | ✗ Not Implemented |
| **State Machine** | ✓ Complete | ✓ Complete | ✓ Complete |
| **Audio Streaming** | ✓ Chunked Upload | ✓ Real-time Binary | ✓ Pipeline Only |
| **Error Handling** | ✓ Comprehensive | ✓ Comprehensive | ✓ Framework Only |
| **Message Processing** | ✓ HTTP Responses | ✓ Bidirectional | ⚠️ Queue Only |
| **Production Ready** | ✓ Yes | ✓ Yes | ✗ Development Only |

## Conclusion

The SDT protocol demonstrates the extensibility and abstraction capabilities of the XRSR framework by providing a complete protocol template without actual network implementation. While not suitable for production speech recognition scenarios, SDT serves valuable purposes in development, testing, and as a foundation for custom protocol implementations.

The SDT implementation showcases how new protocols can be integrated into XRSR with full state machine behavior, audio pipeline integration, and framework callback support, making it an excellent starting point for developers looking to extend XRSR with custom transport mechanisms or service discovery capabilities.