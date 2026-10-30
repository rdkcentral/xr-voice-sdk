# XRSR HTTP Protocol Implementation Analysis Documentation

## Overview
The XRSR HTTP protocol implementation provides a comprehensive HTTP/HTTPS client for speech recognition services. Built on libcurl, it supports both secure and non-secure connections, multiple authentication methods, flexible certificate management, and sophisticated error handling. The HTTP protocol is designed for request-response speech recognition scenarios where audio data is transmitted via HTTP POST requests.

## Architectural Overview

### Core Design Philosophy
The HTTP protocol implementation follows a non-persistent connection model optimized for single-request speech recognition sessions. Unlike WebSocket implementations that maintain persistent connections, HTTP establishes connections per session, transmits audio data via chunked encoding or file uploads, and processes responses immediately.

### High-Level Architecture
```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Audio Pipeline    │    │   HTTP Protocol     │    │   Speech Service    │
│                     │    │     Manager         │    │                     │
│ • Live Microphone   │────┤                     ├────│ • HTTP/HTTPS       │
│ • Audio Files       │    │ • CURL Multi        │    │ • REST API          │
│ • File Descriptors  │    │ • State Machine     │    │ • Cloud ASR         │
│ • Text Input        │    │ • Certificate Mgmt  │    │ • On-Premise ASR    │
│                     │    │ • Error Handling    │    │                     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## Core Data Structures

### HTTP State Management
Located in [`xrsr_protocol_http.h`](../src/xr-speech-router/xrsr_protocol_http.h#L30-L70):

```c
typedef struct {
    xrsr_protocol_t               prot;                    // Protocol identifier
    xrsr_handlers_t               handlers;                // Callback function set
    rdkx_timer_object_t           timer_obj;               // Timer management object
    
    /* Session Management */
    int                           audio_pipe_fd_read;      // Audio input pipe descriptor
    xrsr_src_t                    audio_src;               // Audio source type
    uint32_t                      dst_index;               // Destination index
    xrsr_session_request_t        input_format;            // Input format specification
    xraudio_input_format_t        xraudio_format;          // XRAudio format details
    bool                          low_latency;             // Low latency mode flag
    bool                          low_cpu_util;            // CPU optimization flag
    uuid_t                        uuid;                    // Session UUID
    
    /* Configuration Structures */
    xrsr_session_config_out_t     session_config_out;      // Outgoing configuration
    xrsr_session_config_in_t      session_config_in;       // Incoming configuration
    const char *                  sat_token;               // Security access token
    const char *                  user_agent;              // HTTP User-Agent string
    
    /* Session Content */
    char                          transcription_in[XRSR_SESSION_BY_TEXT_MAX_LENGTH]; // Text input
    char *                        transcription_ptr;       // Text buffer pointer
    char                          audio_file_in[XRSR_SESSION_AUDIO_FILE_MAX_LENGTH]; // Audio file path
    
    /* CURL Library Integration */
    CURL *                        easy_handle;             // CURL easy handle
    struct curl_slist *           chunk;                   // HTTP headers list
    bool                          debug;                   // Debug logging enabled
    bool                          log_filter_enabled;     // Selective logging enabled
    
    /* Response Management */
    char                          write_buffer[XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX]; // Response buffer
    uint32_t                      write_buffer_index;      // Buffer read position
    rdkx_timer_id_t               timer_id_rsp;            // Response timeout timer
    
    /* Statistics and Session Tracking */
    xrsr_audio_stats_t            audio_stats;             // Audio processing statistics
    xrsr_session_stats_t          session_stats;           // Session performance metrics
    
    /* Session Type Flags */
    bool                          is_session_by_text;      // Text-only session flag
    bool                          is_session_by_file;      // File-based session flag
    
    /* State Machine Engine */
    tSmInstance                   state_machine;           // State machine instance
    tStateEvent                   state_machine_events_active[XRSR_WS_SM_EVENTS_MAX]; // Event queue
    bool                          detect_resume;           // Detection resume flag
    xrsr_session_config_update_t *session_config_update;   // Configuration update
} xrsr_state_http_t;
```

### Global HTTP Management
```c
typedef struct {
    unsigned int        ref;                    // Reference count for multi-session support
    unsigned int        easy_handle_cnt;        // Active CURL handles count
    CURLM              *multi_handle;           // CURL multi-handle for async operations
    int                 running;                // Active transfers count
    rdkx_timer_object_t timer_obj;             // Global timer object
    rdkx_timer_id_t     timer_id_multi;        // Multi-handle timer ID
    int                 readfds[XRSR_HTTP_CURL_FD_MAX];   // Read file descriptors
    int                 writefds[XRSR_HTTP_CURL_FD_MAX];  // Write file descriptors
} xrsr_state_http_global_t;
```

## HTTP State Machine Architecture

### State Definitions and Transitions
Located in [`xrsr_protocol_http_sm.h`](../src/xr-speech-router/xrsr_protocol_http_sm.h):

#### State Machine Events
```c
#define SM_EVENT_SESSION_BEGIN            (0)   // Session initiation
#define SM_EVENT_SESSION_BEGIN_STM        (1)   // Session begin with stream-time minimum
#define SM_EVENT_DISCONNECTED             (2)   // Connection lost/failed
#define SM_EVENT_STM                      (3)   // Stream-time minimum reached
#define SM_EVENT_EOS                      (4)   // End-of-speech detected
#define SM_EVENT_TERMINATE                (5)   // Session termination requested
#define SM_EVENT_TIMEOUT                  (6)   // Timeout occurred
#define SM_EVENT_CONNECTED                (7)   // Connection established
#define SM_EVENT_MSG_RECV                 (8)   // Response message received
#define SM_EVENT_PIPE_EOS                 (9)   // Audio pipe end-of-stream
#define SM_EVENT_TEXT_SESSION_SUCCESS     (10)  // Text session completed successfully
```

#### State Transition Matrix

| Current State | Event | Next State | Description |
|---------------|-------|------------|-------------|
| **St_Http_Disconnected** | SESSION_BEGIN | St_Http_Connecting | Direct connection initiation |
| **St_Http_Disconnected** | SESSION_BEGIN_STM | St_Http_Buffering | Buffered connection with STM |
| **St_Http_Buffering** | EOS | St_Http_Disconnected | Early end-of-speech termination |
| **St_Http_Buffering** | TERMINATE | St_Http_Disconnected | User-initiated termination |
| **St_Http_Buffering** | STM | St_Http_Connecting | Minimum stream time reached |
| **St_Http_Connecting** | DISCONNECTED | St_Http_Disconnected | Connection failure |
| **St_Http_Connecting** | CONNECTED | St_Http_Streaming | Connection established successfully |
| **St_Http_Connected** | MSG_RECV | St_Http_Disconnected | Response received and processed |
| **St_Http_Connected** | TERMINATE | St_Http_Disconnected | Session termination |
| **St_Http_Connected** | TIMEOUT | St_Http_Disconnected | Response timeout |
| **St_Http_Streaming** | PIPE_EOS | St_Http_Connected | Audio streaming completed |
| **St_Http_Streaming** | TERMINATE | St_Http_Disconnected | Session termination during stream |
| **St_Http_Streaming** | MSG_RECV | St_Http_Disconnected | Early response during stream |
| **St_Http_Streaming** | TEXT_SESSION_SUCCESS | St_Http_TextOnlySession | Text session completed |
| **St_Http_TextOnlySession** | PIPE_EOS | St_Http_Connected | Text session finalized |
| **St_Http_TextOnlySession** | TERMINATE | St_Http_Disconnected | Text session termination |
| **St_Http_TextOnlySession** | MSG_RECV | St_Http_Disconnected | Text session response |

## CURL Integration Architecture

### Multi-Handle Management System
The HTTP implementation uses CURL's multi-handle interface for efficient asynchronous operations:

```c
// Global multi-handle initialization
g_http.multi_handle = curl_multi_init();
curl_multi_setopt(g_http.multi_handle, CURLMOPT_SOCKETFUNCTION, _xrsr_http_socket_function);
curl_multi_setopt(g_http.multi_handle, CURLMOPT_SOCKETDATA,     NULL);
curl_multi_setopt(g_http.multi_handle, CURLMOPT_TIMERFUNCTION,  _xrsr_http_timer_function);
curl_multi_setopt(g_http.multi_handle, CURLMOPT_TIMERDATA,      NULL);
```

### Socket Event Management
The HTTP module integrates with the main event loop through file descriptor monitoring:

```c
int _xrsr_http_socket_function(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp) {
    switch(what) {
        case CURL_POLL_IN:    // Monitor for read readiness
        case CURL_POLL_OUT:   // Monitor for write readiness
        case CURL_POLL_INOUT: // Monitor for read/write readiness
        case CURL_POLL_REMOVE:// Remove from monitoring
    }
}
```

### Timer Integration
```c
int _xrsr_http_timer_function(CURLM *multi, long timeout_ms, void *userp) {
    // Manages connection timeouts, response timeouts, and keepalive intervals
    // Integrates with XRSR's timer system for coordinated timeout handling
}
```

### Performance Optimization Features
- **Connection Pooling**: Efficient reuse of HTTP connections where possible
- **Pipelined Operations**: Multiple requests can be processed simultaneously
- **Asynchronous I/O**: Non-blocking operations prevent thread stalls
- **Selective Logging**: Filtered debug output reduces overhead in production

## HTTP Request Configuration

### Header Management System
Located in [`xrsr_protocol_http.c`](../src/xr-speech-router/xrsr_protocol_http.c#L350-L380):

```c
// Content type configuration based on session type
if (transcription_in != NULL) {
    http->chunk = curl_slist_append(http->chunk, "Content-Type:text/plain");
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_COPYPOSTFIELDS, transcription_payload);
} else {
    http->chunk = curl_slist_append(http->chunk, "Transfer-Encoding: chunked");
    http->chunk = curl_slist_append(http->chunk, "Content-Type:application/octet-stream");
}

// Authorization header with SAT token
if(http->session_config_in.http.sat_token != NULL) {
    snprintf(sat_token_str, sizeof(sat_token_str), "Authorization: Bearer %s", 
             http->session_config_in.http.sat_token);
    http->chunk = curl_slist_append(http->chunk, sat_token_str);
}

// Disable HTTP/1.1 100-continue expectation
http->chunk = curl_slist_append(http->chunk, "Expect:");
```

### CURL Configuration Parameters
```c
// Core transfer settings
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_WRITEFUNCTION, _xrsr_http_write_function);
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_WRITEDATA, (void *)http);
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_READFUNCTION, _xrsr_http_read_function);
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_READDATA, (void *)http);

// Timeout and connection settings
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_CONNECTTIMEOUT, 5L);
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_FORBID_REUSE, 1);
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_FOLLOWLOCATION, 1L);
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_NOSIGNAL, 1L);

// HTTP method configuration
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_POST, 1L);
CURL_EASY_SETOPT(http->easy_handle, CURLOPT_HTTPHEADER, http->chunk);
```

## Security and Certificate Management

### Certificate Type Support Matrix

| Certificate Type | File Format | Key Management | Use Case |
|------------------|-------------|----------------|----------|
| **PKCS#12** | .p12, .pfx | Embedded private key | Enterprise deployments |
| **PEM** | .pem, .key, .crt | Separate key files | Development and testing |
| **X.509** | In-memory objects | Runtime certificate loading | Dynamic certificate management |

### PKCS#12 Certificate Configuration
```c
if(config_in->client_cert.type == XRSR_CERT_TYPE_P12) {
    xrsr_cert_p12_t *cert_p12 = &config_in->client_cert.cert.p12;
    
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERTTYPE, "P12");
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERT, cert_p12->filename);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_KEYPASSWD, cert_p12->passphrase);
    
    // OCSP stapling verification (optional)
    if(config_in->ocsp_verify_stapling) {
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYSTATUS, 1L);
    }
}
```

### PEM Certificate Chain Configuration
```c
if(config_in->client_cert.type == XRSR_CERT_TYPE_PEM) {
    xrsr_cert_pem_t *cert_pem = &config_in->client_cert.cert.pem;
    
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERTTYPE, "PEM");
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERT,   cert_pem->filename_cert);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLKEY,    cert_pem->filename_pkey);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_KEYPASSWD, cert_pem->passphrase);
    
    // Certificate chain verification
    if(cert_pem->filename_chain != NULL) {
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_CAINFO, cert_pem->filename_chain);
    }
}
```

### Security Features
- **TLS/SSL Support**: Full HTTPS with configurable cipher suites
- **Certificate Validation**: Hostname and certificate chain verification
- **OCSP Stapling**: Online Certificate Status Protocol validation
- **Client Authentication**: Mutual TLS with client certificates
- **Token-Based Auth**: Bearer token support for API authentication

## Audio Data Handling

### Streaming Data Transfer Model

#### Chunked Transfer Encoding
For live microphone input, audio data is transmitted using HTTP chunked encoding:

```c
size_t _xrsr_http_read_function(char *ptr, size_t size, size_t nmemb, void *userdata) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)userdata;
    
    if(http->audio_pipe_fd_read >= 0) {
        int rc = read(http->audio_pipe_fd_read, ptr, size * nmemb);
        
        if(rc < 0) {
            // Handle non-blocking read scenarios
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                return CURL_READFUNC_PAUSE; // Pause transfer temporarily
            }
            // Signal end-of-stream on error
            xrsr_http_event(http, SM_EVENT_PIPE_EOS, false);
        } else if(rc == 0) {
            // EOF reached - complete the transfer
            xrsr_http_event(http, SM_EVENT_PIPE_EOS, false);
        }
        
        return rc; // Return bytes read
    }
    return 0; // No data available
}
```

#### File-Based Data Transfer
For pre-recorded audio files, data is loaded and transmitted as a single POST body:

```c
// Configure file-based upload
if(input_format.type == XRSR_SESSION_REQUEST_TYPE_AUDIO_FILE) {
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_READDATA, audio_file_handle);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_INFILESIZE, file_size);
}
```

#### Text-Only Session Handling
```c
// Text session configuration
if(transcription_in != NULL) {
    snprintf(transcription_payload, sizeof(transcription_payload), "%s", transcription_in);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_COPYPOSTFIELDS, transcription_payload);
    http->chunk = curl_slist_append(http->chunk, "Content-Type:text/plain");
}
```

## Response Processing Architecture

### Response Buffer Management
```c
size_t _xrsr_http_write_function(char *ptr, size_t size, size_t nmemb, void *userdata) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)userdata;
    size_t len = strnlen(http->write_buffer, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX);
    
    if(len + (size * nmemb) > XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX) {
        XLOGD_ERROR("response buffer overflow");
        // Truncate response to prevent buffer overflow
        strncpy(&http->write_buffer[len], ptr, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX - len);
    } else {
        // Append new data to response buffer
        strncpy(&http->write_buffer[len], ptr, size * nmemb);
    }
    
    return size * nmemb; // Always return requested size to continue transfer
}
```

### Response Processing Pipeline
```c
// Response completion handling in xrsr_http_handle_fds()
if(CURLMSG_DONE == status->msg) {
    if(status->data.result == CURLE_OK) {
        // Extract session statistics
        curl_easy_getinfo(temp->easy_handle, CURLINFO_HTTP_CODE, &temp->session_stats.ret_code_protocol);
        curl_easy_getinfo(temp->easy_handle, CURLINFO_PRIMARY_IP, &primary_ip);
        curl_easy_getinfo(temp->easy_handle, CURLINFO_CONNECT_TIME, &temp->session_stats.time_connect);
        curl_easy_getinfo(temp->easy_handle, CURLINFO_NAMELOOKUP_TIME, &temp->session_stats.time_dns);
        
        // Forward response to message handler
        (*temp->handlers.recv_msg)(temp->handlers.data, XRSR_RECV_MSG_TEXT, 
                                 (uint8_t *)temp->write_buffer, 
                                 strnlen(temp->write_buffer, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX), 
                                 NULL);
        
        // Update session statistics
        temp->session_stats.ret_code_internal = XRSR_RET_CODE_INTERNAL_SUCCESS;
        temp->session_stats.ret_code_library = status->data.result;
        
        // Trigger state machine transition
        xrsr_http_event(temp, SM_EVENT_MSG_RECV, false);
    }
}
```

## Error Handling and Recovery

### Connection Error Management
```c
typedef enum {
    XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE   = 8,   // Connection establishment failure
    XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT   = 9,   // Connection timeout
    XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT   = 10,  // Session processing timeout
    XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE = 11,  // Unexpected server disconnect
} xrsr_session_end_reason_t;
```

### CURL Error Code Mapping
The HTTP implementation provides comprehensive error classification:

| CURL Error | Internal Mapping | Recovery Action |
|------------|------------------|------------------|
| CURLE_COULDNT_CONNECT | CONNECT_FAILURE | Retry with exponential backoff |
| CURLE_OPERATION_TIMEDOUT | CONNECT_TIMEOUT | Increase timeout, retry |
| CURLE_SSL_CONNECT_ERROR | SSL_FAILURE | Check certificates, retry |
| CURLE_HTTP_RETURNED_ERROR | HTTP_ERROR | Parse HTTP status, handle accordingly |
| CURLE_WRITE_ERROR | INTERNAL_ERROR | Check buffer capacity, retry |

### Timeout Management Strategy
```c
// Response timeout configuration
rdkx_timestamp_t timeout;
rdkx_timestamp_get(&timeout);
rdkx_timestamp_add_ms(&timeout, XRSR_HTTP_MSG_TIMEOUT);

http->timer_id_rsp = rdkx_timer_insert(http->timer_obj, timeout, 
                                       xrsr_http_timeout_response, http);
```

## Logging and Debugging Support

### Filtered Logging System
Located in [`xrsr_protocol_http_log_filter.h`](../src/xr-speech-router/xrsr_protocol_http_log_filter.h):

The HTTP implementation includes a sophisticated logging filter that selectively logs CURL debug information based on content analysis:

```c
int _xrsr_http_debug_function(CURL *handle, curl_infotype type, char *data, size_t size, void *userdata) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)userdata;
    
    switch(type) {
        case CURLINFO_TEXT: {
            // Apply log filtering to reduce noise
            if(xrsr_http_log_filter_handler_get(data, size) && 
               (http->debug || http->log_filter_enabled)) {
                XLOGD_TELEMETRY("%.*s", (int)size, data);
            } else if (http->debug) {
                XLOGD_NO_LF(XLOG_LEVEL_INFO, "%.*s", (int)size, data);
            }
            break;
        }
        case CURLINFO_HEADER_IN:
        case CURLINFO_HEADER_OUT:
        case CURLINFO_DATA_IN:
        case CURLINFO_DATA_OUT:
            // Log protocol-level data for debugging
            XLOGD_DEBUG("%.*s\n", (int)size, data);
            break;
    }
}
```

### Debug Configuration Options
- **Full Debug Mode**: Comprehensive CURL verbose output
- **Filtered Debug Mode**: Selective logging based on content filters  
- **Telemetry Mode**: Performance and error metrics only
- **Production Mode**: Error logging only

## Performance Characteristics and Optimization

### Latency Profile
- **Connection Establishment**: 100-2000ms (depending on network and SSL)
- **SSL Handshake**: 50-500ms additional for HTTPS connections
- **Audio Upload**: Near real-time for chunked encoding, dependent on audio duration
- **Response Processing**: <50ms for typical transcription responses
- **Session Teardown**: <100ms for connection cleanup

### Memory Usage Optimization
```c
#define XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX (102400)  // 100KB response buffer
#define XRSR_PROTOCOL_HTTP_URL_SIZE_MAX    (2048)    // 2KB URL limit
#define XRSR_HTTP_CURL_FD_MAX              (5)       // Maximum concurrent FDs
```

### Throughput Characteristics
- **Maximum Concurrent Sessions**: Limited by available file descriptors
- **Audio Streaming Rate**: Matches input sample rate (typically 16kHz)
- **Response Buffer Capacity**: 100KB for large transcription responses
- **Connection Reuse**: Disabled by default for session isolation

### CPU and Resource Optimization
- **Asynchronous I/O**: Non-blocking operations prevent thread stalls
- **Timer Coalescing**: Efficient timeout management across sessions  
- **Buffer Reuse**: Response buffers cleared and reused between sessions
- **Connection Pooling**: CURL handles managed efficiently across sessions

## Integration with XRSR Framework

### Callback Integration Points
```c
// Session lifecycle callbacks
http->handlers.session_begin = xrsr_http_session_begin_callback;
http->handlers.session_config_in = xrsr_http_session_config_callback; 
http->handlers.recv_msg = xrsr_http_recv_msg_callback;
http->handlers.session_end = xrsr_http_session_end_callback;

// Speech event integration  
void xrsr_http_handle_speech_event(xrsr_state_http_t *http, xrsr_speech_event_t *event) {
    switch(event->event) {
        case XRSR_EVENT_EOS:                  // End-of-speech detection
        case XRSR_EVENT_STREAM_TIME_MINIMUM:  // Minimum stream time reached
        case XRSR_EVENT_STREAM_KWD_INFO:      // Keyword timing information
    }
}
```

### Session Management Integration
- **UUID Tracking**: Each HTTP session assigned unique identifier for correlation
- **Audio Format Coordination**: HTTP format requirements coordinated with XRAudio
- **Power Mode Adaptation**: Connection timeouts adjusted based on system power state
- **Statistics Reporting**: Comprehensive session metrics provided to XRSR framework

This HTTP protocol implementation provides robust, secure, and efficient speech recognition capabilities with comprehensive error handling, security features, and performance optimization suitable for production XR voice interaction systems.