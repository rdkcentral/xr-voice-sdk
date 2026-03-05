# XRSR WebSocket Protocol Implementation Analysis Documentation

## Overview
The XRSR WebSocket protocol implementation provides a sophisticated real-time communication framework for speech recognition services. Built on the noPoll WebSocket library, it supports both secure (WSS) and non-secure (WS) connections, comprehensive SSL/TLS certificate management, bidirectional messaging, and advanced connection resilience features. The WebSocket protocol is optimized for persistent, low-latency speech recognition sessions with real-time audio streaming capabilities.

## Architectural Overview

### Core Design Philosophy
The WebSocket implementation follows a persistent connection model designed for real-time, bidirectional communication with speech recognition services. Unlike HTTP's request-response pattern, WebSocket maintains continuous connections that enable streaming audio input, real-time transcription responses, and interactive voice processing scenarios.

### High-Level Architecture
```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Audio Pipeline    │    │   WebSocket         │    │   Speech Service    │
│                     │    │   Protocol Manager  │    │                     │
│ • Live Microphone   │────┤                     ├────│ • WebSocket/WSS     │
│ • Audio Files       │    │ • noPoll Library    │    │ • Real-time ASR     │
│ • File Descriptors  │    │ • State Machine     │    │ • Streaming API     │
│ • Text Input        │    │ • SSL/TLS Manager   │    │ • Interactive Voice │
│                     │    │ • Message Queue     │    │                     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## Core Data Structures

### WebSocket State Management
Located in [`xrsr_protocol_ws.h`](../src/xr-speech-router/xrsr_protocol_ws.h#L32-L100):

```c
typedef struct {
    xrsr_protocol_t               prot;                    // Protocol identifier (WS/WSS)
    xrsr_handlers_t               handlers;                // Callback function set
    bool                          debug_enabled;           // Debug logging enabled
    uuid_t                        uuid;                    // Session unique identifier
    
    /* Session Configuration Structures */
    xrsr_session_config_out_t     session_config_out;      // Outgoing configuration
    xrsr_session_config_in_t      session_config_in;       // Incoming configuration
    
    /* Timer and Synchronization Management */
    rdkx_timer_object_t           timer_obj;               // Timer management object
    rdkx_timer_id_t               timer_id;                // Active timer identifier
    uint32_t                      retry_cnt;               // Connection retry counter
    rdkx_timestamp_t              retry_timestamp_end;     // Retry timeout timestamp
    int32_t                       connect_wait_time;       // Connection establishment timeout
    bool                          stream_time_min_rxd;     // Minimum stream time received
    
    /* URL and Connection Details */
    xrsr_url_parts_t *            url_parts;               // Parsed URL components
    char                          url[XRSR_WS_URL_SIZE_MAX]; // Complete WebSocket URL
    const char *                  sat_token;               // Security Access Token
    
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
    bool                          write_pending_bytes;     // Partial write pending flag
    uint8_t                       write_pending_retries;   // Write retry counter
    char                          local_host_name[XRSR_WS_HOST_NAME_LEN_MAX]; // Local hostname
    uint8_t                       buffer[4096];            // Audio data buffer
    
    /* Session Statistics and Tracking */
    xrsr_session_stats_t          stats;                   // Session performance metrics
    xrsr_audio_stats_t            audio_stats;             // Audio processing statistics
    bool                          on_close;                // Connection close flag
    int                           close_status;            // WebSocket close status
    bool                          requested_more_audio;    // Additional audio requested
    
    /* Outgoing Message Queue Management */
    sem_t                         msg_out_semaphore;       // Message queue semaphore
    uint8_t                       msg_out_count;           // Queued message count
    char *                        msg_out[XRSR_WS_MSG_OUT_MAX]; // Outgoing message queue
    
    /* Audio Keyword Detection and Streaming */
    bool                          audio_kwd_notified;      // Keyword notification sent
    uint32_t                      audio_kwd_bytes;         // Keyword audio bytes count
    uint32_t                      audio_txd_bytes;         // Total transmitted bytes
    
    /* Power Mode Configuration Parameters */
    uint32_t                      connect_check_interval;  // Connection health check interval
    uint32_t                      timeout_connect;         // Connection establishment timeout
    uint32_t                      timeout_inactivity;      // Inactivity timeout
    uint32_t                      timeout_session;         // Session timeout
    bool                          ipv4_fallback;           // IPv4 fallback enabled
    uint32_t                      backoff_delay;           // Retry backoff delay
    
    /* Session Type Flags */
    bool                          is_session_by_text;      // Text-only session
    bool                          is_session_by_file;      // File-based session
    char                          audio_file_in[XRSR_SESSION_AUDIO_FILE_MAX_LENGTH]; // Audio file path
    
    /* noPoll WebSocket Library Integration */
    noPollCtx *                   obj_ctx;                 // noPoll context object
    noPollConn *                  obj_conn;                // noPoll connection object
    NOPOLL_SOCKET                 socket;                  // WebSocket file descriptor
    noPollMsg *                   pending_msg;             // Pending incoming message
    
    /* State Machine Engine */
    tSmInstance                   state_machine;           // State machine instance
    tStateEvent                   state_machine_events_active[XRSR_WS_SM_EVENTS_MAX]; // Event queue
    xrsr_stream_end_reason_t      stream_end_reason;       // Stream termination reason
    xrsr_session_end_reason_t     session_end_reason;      // Session termination reason
    bool                          detect_resume;           // Detection resume flag
    xrsr_session_config_update_t *session_config_update;   // Configuration updates
} xrsr_state_ws_t;
```

### WebSocket Parameters Structure
```c
typedef struct {
    xrsr_protocol_t        prot;                 // Protocol type (WS/WSS)
    const char *           host_name;            // Local hostname identifier
    rdkx_timer_object_t    timer_obj;           // Timer management object
    xrsr_dst_param_ptrs_t *dst_params;          // Destination parameter pointers
} xrsr_ws_params_t;
```

## WebSocket State Machine Architecture

### State Machine Events
Located in [`xrsr_protocol_ws_sm.h`](../src/xr-speech-router/xrsr_protocol_ws_sm.h#L20-L45):

```c
#define SM_EVENT_SESSION_BEGIN            (0)   // Session initiation
#define SM_EVENT_SESSION_BEGIN_STM        (1)   // Session begin with stream-time minimum
#define SM_EVENT_DISCONNECTED             (2)   // Connection lost/failed
#define SM_EVENT_STM                      (3)   // Stream-time minimum reached
#define SM_EVENT_SOS                      (4)   // Start-of-speech detected
#define SM_EVENT_EOS                      (5)   // End-of-speech detected
#define SM_EVENT_TERMINATE                (6)   // Session termination requested
#define SM_EVENT_XRSR_ERROR               (7)   // XRSR internal error
#define SM_EVENT_TIMEOUT                  (8)   // Timeout occurred
#define SM_EVENT_CONNECTED                (9)   // TCP connection established
#define SM_EVENT_RETRY                    (10)  // Connection retry initiated
#define SM_EVENT_ESTABLISHED              (11)  // WebSocket handshake completed
#define SM_EVENT_WS_CLOSE                 (12)  // WebSocket connection closed
#define SM_EVENT_CONNECT_TIMEOUT          (13)  // Connection establishment timeout
#define SM_EVENT_MSG_RECV                 (14)  // Message received from server
#define SM_EVENT_APP_CLOSE                (15)  // Application-initiated close
#define SM_EVENT_EOS_PIPE                 (16)  // Audio pipe end-of-stream
#define SM_EVENT_WS_ERROR                 (17)  // WebSocket protocol error
#define SM_EVENT_AUDIO_ERROR              (18)  // Audio system error
#define SM_EVENT_ESTABLISH_TIMEOUT        (19)  // WebSocket establishment timeout
#define SM_EVENT_TEXT_SESSION_SUCCESS     (20)  // Text session completed successfully
```

### State Definitions and Transition Matrix

| Current State | Key Events | Next States | Description |
|---------------|------------|-------------|-------------|
| **St_Ws_Disconnected** | SESSION_BEGIN | St_Ws_Connecting | Direct connection initiation |
| **St_Ws_Disconnected** | SESSION_BEGIN_STM | St_Ws_Buffering | Buffered connection with stream-time minimum |
| **St_Ws_Disconnected** | TERMINATE | St_Ws_Disconnected | No-op termination in disconnected state |
| **St_Ws_Disconnecting** | DISCONNECTED | St_Ws_Disconnected | Clean disconnection completion |
| **St_Ws_Disconnecting** | TERMINATE | St_Ws_Disconnected | Force termination during disconnect |
| **St_Ws_Buffering** | EOS | St_Ws_Disconnected | Early end-of-speech termination |
| **St_Ws_Buffering** | TERMINATE | St_Ws_Disconnected | User-initiated termination |
| **St_Ws_Buffering** | STM | St_Ws_Connecting | Minimum stream time reached |
| **St_Ws_Connecting** | CONNECT_TIMEOUT | St_Ws_Disconnected | Connection establishment failure |
| **St_Ws_Connecting** | TERMINATE | St_Ws_Disconnected | Termination during connection |
| **St_Ws_Connecting** | XRSR_ERROR | St_Ws_Disconnected | Internal system error |
| **St_Ws_Connecting** | TIMEOUT | St_Ws_Connecting | Connection retry timeout |
| **St_Ws_Connecting** | RETRY | St_Ws_Connection_Retry | Initiate connection retry |
| **St_Ws_Connecting** | CONNECTED | St_Ws_Connected | TCP connection established |
| **St_Ws_Connected** | ESTABLISH_TIMEOUT | St_Ws_Disconnecting | WebSocket handshake timeout |
| **St_Ws_Connected** | TERMINATE | St_Ws_Disconnecting | Termination after TCP connect |
| **St_Ws_Connected** | WS_CLOSE | St_Ws_Disconnected | Connection closed during handshake |
| **St_Ws_Connected** | TIMEOUT | St_Ws_Connected | Keep-alive timeout |
| **St_Ws_Connected** | ESTABLISHED | St_Ws_Streaming | WebSocket handshake completed |
| **St_Ws_Established** | APP_CLOSE | St_Ws_Disconnecting | Application-initiated closure |
| **St_Ws_Established** | TERMINATE | St_Ws_Disconnecting | Session termination |
| **St_Ws_Established** | TIMEOUT | St_Ws_Disconnecting | Inactivity timeout |
| **St_Ws_Established** | MSG_RECV | St_Ws_Established | Message processing |
| **St_Ws_Established** | EOS | St_Ws_Established | End-of-speech handling |
| **St_Ws_Established** | EOS_PIPE | St_Ws_Established | Audio pipe completion |
| **St_Ws_Established** | SOS | St_Ws_Streaming | Start-of-speech transition |
| **St_Ws_Established** | WS_CLOSE | St_Ws_Disconnected | Unexpected server closure |
| **St_Ws_Streaming** | MSG_RECV | St_Ws_Streaming | Real-time message processing |
| **St_Ws_Streaming** | EOS | St_Ws_Streaming | End-of-speech during stream |
| **St_Ws_Streaming** | EOS_PIPE | St_Ws_Established | Audio stream completion |
| **St_Ws_Streaming** | TERMINATE | St_Ws_Disconnecting | Termination during streaming |
| **St_Ws_Streaming** | WS_ERROR | St_Ws_Disconnecting | WebSocket error during stream |
| **St_Ws_Streaming** | WS_CLOSE | St_Ws_Disconnected | Connection lost during stream |
| **St_Ws_Streaming** | AUDIO_ERROR | St_Ws_Established | Audio error recovery |
| **St_Ws_Streaming** | TEXT_SESSION_SUCCESS | St_Ws_TextOnlySession | Text session completion |
| **St_Ws_TextOnlySession** | EOS_PIPE | St_Ws_Established | Text session finalized |
| **St_Ws_TextOnlySession** | TERMINATE | St_Ws_Disconnecting | Text session termination |
| **St_Ws_TextOnlySession** | WS_ERROR | St_Ws_Disconnecting | Error in text session |
| **St_Ws_TextOnlySession** | WS_CLOSE | St_Ws_Disconnected | Connection closed |
| **St_Ws_Connection_Retry** | TERMINATE | St_Ws_Disconnected | Termination during retry |
| **St_Ws_Connection_Retry** | TIMEOUT | St_Ws_Connecting | Retry timeout elapsed |

## noPoll WebSocket Library Integration

### Library Configuration and Initialization
Located in [`xrsr_protocol_ws.c`](../src/xr-speech-router/xrsr_protocol_ws.c#L100-L150):

```c
bool xrsr_ws_init(xrsr_state_ws_t *ws, xrsr_ws_params_t *params) {
    // Initialize noPoll context
    ws->obj_ctx = nopoll_ctx_new();
    if(ws->obj_ctx == NULL) {
        XLOGD_ERROR("unable to create context");
        return(false);
    }
    
    // Configure logging based on debug settings
    if(debug_enabled) {
        nopoll_log_enable(ws->obj_ctx, nopoll_true);
        nopoll_log_set_handler(ws->obj_ctx, xrsr_ws_nopoll_log, NULL);
    } else {
        nopoll_log_enable(ws->obj_ctx, nopoll_false);
    }
    
    // Initialize message queue semaphore
    sem_init(&ws->msg_out_semaphore, 0, 1);
    ws->msg_out_count = 0;
    
    // Configure connection timeouts
    nopoll_conn_connect_timeout(ws->obj_ctx, ws->timeout_connect * 1000);
    
    return(true);
}
```

### Connection Establishment Process
```c
bool xrsr_ws_connect_new(xrsr_state_ws_t *ws) {
    xrsr_url_parts_t *url_parts = ws->url_parts;
    noPollConnOpts *nopoll_opts = xrsr_conn_opts_get(ws, config_in->sat_token);
    
    // Prepare Origin header for WebSocket handshake
    char origin[origin_size];
    snprintf(origin, sizeof(origin), "http://%s:%s", url_parts->host, url_parts->port_str);
    
    // Establish connection based on protocol (WS vs WSS)
    if(ws->prot == XRSR_PROTOCOL_WSS) {
        // Configure SSL/TLS context for WSS connections
        if(config_in->client_cert.type != XRSR_CERT_TYPE_NONE) {
            nopoll_ctx_set_ssl_context_creator(ws->obj_ctx, xrsr_ws_ssl_ctx_creator, ws);
            nopoll_ctx_set_post_ssl_check(ws->obj_ctx, xrsr_ws_ssl_post_check_cb, ws);
        }
        
        const char *ptr_path = strchrnul(&ws->url[6], '/'); // Skip wss://
        ws->obj_conn = NOPOLL_CONN_TLS_NEW(ws->obj_ctx, nopoll_opts, 
                                          url_parts->host, url_parts->port_str, 
                                          NULL, ptr_path, NULL, origin);
    } else {
        const char *ptr_path = strchrnul(&ws->url[5], '/'); // Skip ws://
        ws->obj_conn = NOPOLL_CONN_NEW(ws->obj_ctx, nopoll_opts, 
                                      url_parts->host, url_parts->port_str, 
                                      NULL, ptr_path, NULL, origin);
    }
    
    // Configure connection as non-blocking
    if (!nopoll_conn_set_sock_block(nopoll_conn_socket(ws->obj_conn), nopoll_false)) {
        XLOGD_ERROR("failed to configure connection as non-blocking");
        return(false);
    }
    
    // Set connection event handlers
    nopoll_conn_set_on_close(ws->obj_conn, xrsr_ws_on_close, ws);
    
    return(true);
}
```

## SSL/TLS Security Implementation

### Certificate Management Architecture
The WebSocket implementation supports comprehensive certificate management with multiple certificate formats and advanced security features.

#### SSL Context Creation
```c
static noPollPtr xrsr_ws_ssl_ctx_creator(noPollCtx * ctx, noPollConn * conn, 
                                         noPollConnOpts * opts, nopoll_bool is_client, 
                                         noPollPtr user_data) {
    xrsr_state_ws_t *ws = (xrsr_state_ws_t *)user_data;
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    
    if(ssl_ctx == NULL) {
        XLOGD_ERROR("Failed to create SSL context");
        return NULL;
    }
    
    // Configure cipher list for strong security
    if(!SSL_CTX_set_cipher_list(ssl_ctx, XRSR_WS_CIPHER_LIST)) {
        XLOGD_ERROR("Failed to set cipher list");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    
    // Configure certificate verification
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, xrsr_ws_ssl_ctx_certificate_cb);
    
    // Configure client certificate based on type
    xrsr_session_config_in_ws_t *config_in = &ws->session_config_in.ws;
    
    switch(config_in->client_cert.type) {
        case XRSR_CERT_TYPE_P12: {
            xrsr_cert_p12_t *cert_p12 = &config_in->client_cert.cert.p12;
            // Load PKCS#12 certificate bundle
            FILE *fp = fopen(cert_p12->filename, "rb");
            if(fp != NULL) {
                PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
                fclose(fp);
                
                if(p12 != NULL) {
                    EVP_PKEY *pkey;
                    X509 *cert;
                    STACK_OF(X509) *ca_certs;
                    
                    if(PKCS12_parse(p12, cert_p12->passphrase, &pkey, &cert, &ca_certs)) {
                        xrsr_ws_ssl_cert_set(ssl_ctx, cert, pkey, ca_certs);
                        
                        // Clean up
                        if(pkey) EVP_PKEY_free(pkey);
                        if(cert) X509_free(cert);
                        if(ca_certs) sk_X509_pop_free(ca_certs, X509_free);
                    }
                    PKCS12_free(p12);
                }
            }
            break;
        }
        
        case XRSR_CERT_TYPE_PEM: {
            xrsr_cert_pem_t *cert_pem = &config_in->client_cert.cert.pem;
            
            // Load PEM certificate file
            if(!SSL_CTX_use_certificate_file(ssl_ctx, cert_pem->filename_cert, SSL_FILETYPE_PEM)) {
                XLOGD_ERROR("Failed to load certificate file");
            }
            
            // Load PEM private key file
            if(!SSL_CTX_use_PrivateKey_file(ssl_ctx, cert_pem->filename_pkey, SSL_FILETYPE_PEM)) {
                XLOGD_ERROR("Failed to load private key file");
            }
            
            // Load certificate chain if provided
            if(cert_pem->filename_chain != NULL) {
                if(!SSL_CTX_load_verify_locations(ssl_ctx, cert_pem->filename_chain, NULL)) {
                    XLOGD_ERROR("Failed to load certificate chain");
                }
            }
            break;
        }
        
        case XRSR_CERT_TYPE_X509: {
            xrsr_cert_x509_t *cert_x509 = &config_in->client_cert.cert.x509;
            xrsr_ws_ssl_cert_set(ssl_ctx, cert_x509->x509, cert_x509->pkey, cert_x509->chain);
            break;
        }
    }
    
    return ssl_ctx;
}
```

#### OCSP Certificate Validation
Online Certificate Status Protocol (OCSP) validation provides real-time certificate revocation checking:

```c
static bool xrsr_ws_ocsp_verify(SSL *ssl, bool allow_expired, bool allow_revoked, bool query_ca_server) {
    OCSP_RESPONSE *ocsp_response = NULL;
    bool result = false;
    
    // Attempt to get OCSP response from SSL handshake (stapling)
    const unsigned char *ocsp_data = NULL;
    long ocsp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_data);
    
    if(ocsp_len > 0 && ocsp_data != NULL) {
        // Parse stapled OCSP response
        ocsp_response = d2i_OCSP_RESPONSE(NULL, &ocsp_data, ocsp_len);
    } else if(query_ca_server) {
        // Query OCSP server directly
        if(!xrsr_ws_ocsp_server_query(ssl, &ocsp_response)) {
            XLOGD_WARN("Failed to query OCSP server");
        }
    }
    
    if(ocsp_response != NULL) {
        result = xrsr_ws_ocsp_response_check(ssl, ocsp_response, allow_expired, allow_revoked);
        OCSP_RESPONSE_free(ocsp_response);
    } else {
        XLOGD_WARN("No OCSP response available for verification");
        result = true; // Allow connection without OCSP if not available
    }
    
    return result;
}
```

### Hostname Verification
```c
static nopoll_bool xrsr_ws_ssl_post_check_cb(noPollCtx *ctx, noPollConn *conn, 
                                             noPollPtr SSL_CTX, noPollPtr SSL, 
                                             noPollPtr user_data) {
    xrsr_state_ws_t *ws = (xrsr_state_ws_t *)user_data;
    
    // Perform hostname verification
    if(ws->session_config_in.ws.host_verify) {
        X509 *peer_cert = SSL_get_peer_certificate((SSL*)SSL);
        if(peer_cert == NULL) {
            XLOGD_ERROR("No peer certificate received");
            return nopoll_false;
        }
        
        // Check Subject Alternative Names (SAN) and Common Name (CN)
        if(!xrsr_ws_hostname_verify(peer_cert, ws->url_parts->host)) {
            XLOGD_ERROR("Hostname verification failed for %s", ws->url_parts->host);
            X509_free(peer_cert);
            return nopoll_false;
        }
        
        X509_free(peer_cert);
    }
    
    // Perform OCSP verification if configured
    if(ws->session_config_in.ws.ocsp_verify) {
        if(!xrsr_ws_ocsp_verify((SSL*)SSL, false, false, true)) {
            XLOGD_ERROR("OCSP verification failed");
            return nopoll_false;
        }
    }
    
    return nopoll_true;
}
```

## Real-Time Message Processing Architecture

### File Descriptor Management and Event Loop Integration
Located in [`xrsr_protocol_ws.c`](../src/xr-speech-router/xrsr_protocol_ws.c#L290-L380):

```c
void xrsr_ws_fd_set(xrsr_state_ws_t *ws, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    if(xrsr_ws_is_established(ws) && ws->socket >= 0) {
        // Always monitor for incoming WebSocket messages
        FD_SET(ws->socket, readfds);
        if(ws->socket >= *nfds) {
            *nfds = ws->socket + 1;
        }
        
        // Monitor for write readiness if we have pending data or messages
        if(ws->write_pending_bytes || xrsr_ws_is_msg_out(ws)) {
            FD_SET(ws->socket, writefds);
        }
        
        // Monitor audio pipe only if we can write to WebSocket
        if(ws->audio_pipe_fd_read >= 0 && !ws->write_pending_bytes) {
            FD_SET(ws->audio_pipe_fd_read, readfds);
            if(ws->audio_pipe_fd_read >= *nfds) {
                *nfds = ws->audio_pipe_fd_read + 1;
            }
        }
    }
}
```

### Bidirectional Data Flow Management
```c
void xrsr_ws_handle_fds(xrsr_state_ws_t *ws, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    // Step 1: Process incoming WebSocket messages
    if(ws->socket >= 0 && FD_ISSET(ws->socket, readfds)) {
        xrsr_ws_read_pending(ws);
    }
    
    // Step 2: Send outgoing messages and handle write flow control
    if(ws->socket >= 0 && FD_ISSET(ws->socket, writefds)) {
        // Handle write flow control for pending bytes
        if(ws->write_pending_bytes) {
            int pending_bytes = nopoll_conn_pending_write_bytes(ws->obj_conn);
            int completed_bytes = nopoll_conn_complete_pending_write(ws->obj_conn);
            
            if(pending_bytes != completed_bytes) {
                ws->write_pending_retries++;
                if(ws->write_pending_retries > XRSR_WS_WRITE_PENDING_RETRY_MAX) {
                    xrsr_ws_event(ws, SM_EVENT_WS_ERROR, false);
                }
                return; // Cannot proceed until pending write completes
            }
            
            ws->write_pending_bytes = false;
            ws->write_pending_retries = 0;
        }
        
        // Send queued outgoing messages
        if(xrsr_ws_is_msg_out(ws)) {
            char *msg_buffer = NULL;
            uint32_t msg_length = 0;
            
            if(xrsr_ws_get_msg_out(ws, &msg_buffer, &msg_length)) {
                int bytes_sent = nopoll_conn_send_text(ws->obj_conn, msg_buffer, msg_length);
                free(msg_buffer); // noPoll has copied the data
                
                if(bytes_sent <= 0 || bytes_sent != msg_length) {
                    if(bytes_sent == -2) { // NOPOLL_EWOULDBLOCK
                        ws->write_pending_bytes = true;
                    } else {
                        xrsr_ws_event(ws, SM_EVENT_WS_ERROR, false);
                    }
                }
            }
        }
    }
    
    // Step 3: Process audio data from input pipeline
    if(ws->audio_pipe_fd_read >= 0 && FD_ISSET(ws->audio_pipe_fd_read, readfds)) {
        int bytes_read = read(ws->audio_pipe_fd_read, ws->buffer, sizeof(ws->buffer));
        
        if(bytes_read < 0) {
            if(errno != EAGAIN && errno != EWOULDBLOCK) {
                xrsr_ws_event(ws, SM_EVENT_AUDIO_ERROR, false);
            }
        } else if(bytes_read == 0) {
            // End of audio stream
            xrsr_ws_event(ws, SM_EVENT_EOS_PIPE, false);
        } else {
            // Send audio data as binary WebSocket message
            int result = nopoll_conn_send_binary(ws->obj_conn, (const char *)ws->buffer, bytes_read);
            
            if(result == -2) { // Would block
                ws->write_pending_bytes = true;
            } else if(result <= 0) {
                xrsr_ws_event(ws, SM_EVENT_WS_ERROR, false);
            } else if(result != bytes_read) {
                ws->write_pending_bytes = true; // Partial send
            }
            
            ws->audio_txd_bytes += (result > 0) ? result : 0;
            
            // Notify keyword detection if threshold reached
            if(!ws->audio_kwd_notified && (ws->audio_txd_bytes >= ws->audio_kwd_bytes)) {
                xrsr_speech_stream_kwd(ws->uuid, ws->audio_src, ws->dst_index);
                ws->audio_kwd_notified = true;
            }
        }
    }
}
```

### Message Queue Management System
```c
// Thread-safe outgoing message queue
static bool xrsr_ws_queue_msg_out(xrsr_state_ws_t *ws, const char *msg, uint32_t length) {
    if(sem_wait(&ws->msg_out_semaphore) != 0) {
        return false;
    }
    
    if(ws->msg_out_count >= XRSR_WS_MSG_OUT_MAX) {
        sem_post(&ws->msg_out_semaphore);
        return false; // Queue full
    }
    
    // Allocate and copy message
    ws->msg_out[ws->msg_out_count] = malloc(length + 1);
    if(ws->msg_out[ws->msg_out_count] != NULL) {
        memcpy(ws->msg_out[ws->msg_out_count], msg, length);
        ws->msg_out[ws->msg_out_count][length] = '\0';
        ws->msg_out_count++;
    }
    
    sem_post(&ws->msg_out_semaphore);
    return true;
}

static bool xrsr_ws_get_msg_out(xrsr_state_ws_t *ws, char **msg, uint32_t *length) {
    if(sem_wait(&ws->msg_out_semaphore) != 0) {
        return false;
    }
    
    if(ws->msg_out_count == 0) {
        sem_post(&ws->msg_out_semaphore);
        return false;
    }
    
    // Dequeue first message (FIFO)
    *msg = ws->msg_out[0];
    *length = strlen(*msg);
    
    // Shift remaining messages
    for(int i = 1; i < ws->msg_out_count; i++) {
        ws->msg_out[i-1] = ws->msg_out[i];
    }
    ws->msg_out_count--;
    ws->msg_out[ws->msg_out_count] = NULL;
    
    sem_post(&ws->msg_out_semaphore);
    return true;
}
```

## Connection Resilience and Error Recovery

### Retry Strategy Implementation
```c
// Exponential backoff with jitter
void xrsr_ws_connection_retry(xrsr_state_ws_t *ws) {
    ws->retry_cnt++;
    
    // Calculate exponential backoff with maximum limit
    uint32_t backoff_ms = ws->backoff_delay * (1 << MIN(ws->retry_cnt - 1, 8));
    backoff_ms = MIN(backoff_ms, 30000); // Cap at 30 seconds
    
    // Add random jitter (±25%)
    uint32_t jitter = (rand() % (backoff_ms / 2)) - (backoff_ms / 4);
    backoff_ms += jitter;
    
    XLOGD_INFO("Retry %u in %u ms", ws->retry_cnt, backoff_ms);
    
    // Set retry timer
    rdkx_timestamp_t retry_time;
    rdkx_timestamp_get(&retry_time);
    rdkx_timestamp_add_ms(&retry_time, backoff_ms);
    
    ws->timer_id = rdkx_timer_insert(ws->timer_obj, retry_time, 
                                     xrsr_ws_connection_retry_timeout, ws);
}
```

### Timeout Management Configuration
Power mode-aware timeout configuration provides optimal balance between responsiveness and power consumption:

```c
bool xrsr_ws_update_dst_params(xrsr_state_ws_t *ws, xrsr_dst_param_ptrs_t *params) {
    // Configure timeouts based on power mode
    if(params->timeout_connect != NULL) {
        ws->timeout_connect = *params->timeout_connect;
    } else {
        ws->timeout_connect = (power_mode == FULL_POWER) ? 2000 : 10000;
    }
    
    if(params->timeout_inactivity != NULL) {
        ws->timeout_inactivity = *params->timeout_inactivity;
    } else {
        ws->timeout_inactivity = (power_mode == FULL_POWER) ? 10000 : 30000;
    }
    
    if(params->timeout_session != NULL) {
        ws->timeout_session = *params->timeout_session;
    } else {
        ws->timeout_session = (power_mode == FULL_POWER) ? 5000 : 15000;
    }
    
    // Connection health check frequency
    if(params->connect_check_interval != NULL) {
        ws->connect_check_interval = *params->connect_check_interval;
    } else {
        ws->connect_check_interval = 50; // 50ms for all power modes
    }
}
```

## Authentication and Authorization

### Bearer Token Integration
```c
noPollConnOpts *xrsr_conn_opts_get(xrsr_state_ws_t *ws, const char *sat_token) {
    noPollConnOpts *nopoll_opts = nopoll_conn_opts_new();
    
    if(sat_token != NULL) {
        char sat_token_str[24 + XRSR_SAT_TOKEN_LEN_MAX] = {'\0'};
        // Format: "\r\nheader:value\r\nheader2:value2" (no trailing \r\n)
        snprintf(sat_token_str, sizeof(sat_token_str), 
                "\r\nAuthorization: Bearer %s", sat_token);
        nopoll_conn_opts_set_extra_headers(nopoll_opts, sat_token_str);
    }
    
    return nopoll_opts;
}
```

### WebSocket Protocol Negotiation
```c
// WebSocket subprotocol and extension negotiation
void xrsr_ws_configure_protocols(noPollConnOpts *opts) {
    // Configure supported WebSocket subprotocols
    nopoll_conn_opts_set_protocol(opts, "speech-recognition-v1");
    
    // Configure WebSocket extensions
    nopoll_conn_opts_set_extra_headers(opts, 
        "\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits");
}
```

## Performance Optimization and Resource Management

### Memory Management Strategy
```c
#define XRSR_WS_URL_SIZE_MAX            (2048)    // Maximum URL length
#define XRSR_WS_MSG_OUT_MAX             (5)       // Outgoing message queue depth
#define XRSR_WS_WRITE_PENDING_RETRY_MAX (5)       // Maximum write retry attempts
#define XRSR_WS_HOST_NAME_LEN_MAX       (64)      // Local hostname buffer size
```

### Latency Optimization Features
- **Non-blocking Operations**: All socket operations configured as non-blocking
- **Zero-Copy Audio Path**: Direct pipe-to-socket data transfer where possible
- **Message Queue Batching**: Efficient outgoing message aggregation
- **Write Flow Control**: Prevents buffer overflow and memory pressure

### CPU Usage Optimization
- **Selective Logging**: Debug output filtered to reduce overhead
- **Timer Coalescing**: Multiple timeouts managed efficiently
- **Buffer Reuse**: Audio buffers recycled between sessions
- **State Machine Efficiency**: Minimal state transition overhead

### Network Efficiency Features
```c
// TCP socket optimization
void xrsr_ws_optimize_socket(NOPOLL_SOCKET socket) {
    // Disable Nagle's algorithm for low latency
    int tcp_nodelay = 1;
    setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));
    
    // Configure keep-alive parameters
    int keepalive = 1;
    setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    
    // Set send/receive buffer sizes
    int buffer_size = 32768; // 32KB buffers
    setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
    setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
}
```

## Integration with XRSR Framework

### Callback Integration Architecture
```c
// WebSocket-specific callbacks for XRSR integration
void xrsr_ws_register_callbacks(xrsr_state_ws_t *ws) {
    ws->handlers.session_begin = xrsr_ws_session_begin_callback;
    ws->handlers.session_config_in = xrsr_ws_session_config_callback;
    ws->handlers.recv_msg = xrsr_ws_recv_msg_callback;
    ws->handlers.session_end = xrsr_ws_session_end_callback;
    ws->handlers.stream_begin = xrsr_ws_stream_begin_callback;
    ws->handlers.stream_kwd = xrsr_ws_stream_kwd_callback;
    ws->handlers.stream_end = xrsr_ws_stream_end_callback;
}

// Speech event handler integration
void xrsr_ws_handle_speech_event(xrsr_state_ws_t *ws, xrsr_speech_event_t *event) {
    switch(event->event) {
        case XRSR_EVENT_EOS:
            xrsr_ws_event(ws, SM_EVENT_EOS, false);
            break;
        case XRSR_EVENT_STREAM_TIME_MINIMUM:
            xrsr_ws_event(ws, SM_EVENT_STM, false);
            break;
        case XRSR_EVENT_STREAM_KWD_INFO:
            ws->audio_kwd_bytes = event->data.stream_kwd.kwd_bytes;
            ws->audio_kwd_notified = false;
            break;
    }
}
```

### Session Lifecycle Management
- **UUID Correlation**: Each WebSocket session tracked with unique identifier
- **Audio Format Coordination**: WebSocket requirements integrated with XRAudio pipeline
- **Power State Synchronization**: Connection parameters adjusted based on system power mode
- **Error Propagation**: WebSocket errors translated to XRSR error codes
- **Statistics Collection**: Comprehensive session metrics provided to framework

This WebSocket protocol implementation delivers enterprise-grade real-time speech recognition capabilities with robust security, advanced error recovery, and optimal performance characteristics suitable for production XR voice interaction systems.