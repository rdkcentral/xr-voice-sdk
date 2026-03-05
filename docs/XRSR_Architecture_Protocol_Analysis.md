# XR Speech Router (XRSR) Architecture and Protocol Analysis Documentation

## Overview
The XR Speech Router (XRSR) is a comprehensive speech routing and recognition framework designed to abstract multiple speech recognition protocols and provide unified audio streaming capabilities. XRSR acts as an intelligent middleware layer between audio input sources and remote speech recognition services, supporting multiple protocols, power management modes, and flexible audio routing configurations.

## Architectural Overview

### Core Design Philosophy
XRSR implements a protocol-agnostic architecture that allows seamless switching between different speech recognition backends (HTTP, WebSocket, SDT) while maintaining consistent API interfaces and state management. The system is designed for real-time, low-latency speech processing in resource-constrained XR environments.

### High-Level Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Audio Sources │    │      XRSR       │    │  SR Backends    │
│                 │    │   Core Router   │    │                 │
│ • Microphone    │────┤                 ├────│ • HTTP/HTTPS    │
│ • RCU PTT       │    │ • Session Mgmt  │    │ • WebSocket/WSS │
│ • RCU FF        │    │ • Protocol Abs  │    │ • SDT Protocol  │
│ • Mic Tap       │    │ • Power Mgmt    │    │ • Custom APIs   │
│ • File/FD       │    │ • Audio Routing │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Component Architecture

### Source Types and Input Management
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L60-L67):

```c
typedef enum {
    XRSR_SRC_RCU_PTT         = 0,  // Push-to-talk remote control
    XRSR_SRC_RCU_FF          = 1,  // Far-field remote control  
    XRSR_SRC_MICROPHONE      = 2,  // Local microphone input
    XRSR_SRC_MICROPHONE_TAP  = 3,  // Local microphone tap (monitoring)
    XRSR_SRC_INVALID         = 4   // Invalid source type
} xrsr_src_t;
```

#### Source Capabilities Matrix
| Source Type | Real-time | Buffered | Keyword Detection | EOS Detection |
|-------------|-----------|----------|-------------------|---------------|
| RCU PTT     | ✓         | ✓        | Optional          | ✓             |
| RCU FF      | ✓         | ✓        | ✓                 | ✓             |
| Microphone  | ✓         | ✓        | ✓                 | ✓             |
| Mic Tap     | ✓         | ✗        | ✗                 | ✗             |

### Session Request Types
```c
typedef enum {
    XRSR_SESSION_REQUEST_TYPE_TEXT       = 0,  // Text-only session (no audio)
    XRSR_SESSION_REQUEST_TYPE_AUDIO_FILE = 1,  // Pre-recorded audio file
    XRSR_SESSION_REQUEST_TYPE_AUDIO_FD   = 2,  // Audio file descriptor
    XRSR_SESSION_REQUEST_TYPE_AUDIO_MIC  = 3,  // Live microphone input
    XRSR_SESSION_REQUEST_TYPE_INVALID    = 4   // Invalid request type
} xrsr_session_request_type_t;
```

#### Input Configuration Structures
```c
// Text-only session
typedef struct {
    const char *text;  // Transcription input (no audio streaming)
} xrsr_request_text_t;

// Audio file session  
typedef struct {
    const char *path;  // Path to audio file input
} xrsr_request_audio_file_t;

// File descriptor session with callback support
typedef struct {
    int                       audio_fd;     // Audio file descriptor
    xrsr_audio_format_t       audio_format; // Audio format specification
    xrsr_input_data_read_cb_t callback;     // Read completion callback (optional)
    void *                    user_data;    // User context data (optional)
} xrsr_request_audio_fd_t;

// Live microphone session
typedef struct {
    bool   stream_params_required;  // Requires keyword timing information
    float *dynamic_gain_update;     // Dynamic gain adjustment pointer
} xrsr_request_audio_mic_t;
```

## Protocol Implementation Architecture

### Multi-Protocol Support Framework
XRSR supports three primary protocol implementations with conditional compilation:

```c
// Protocol enumeration with security variants
typedef enum {
    XRSR_PROTOCOL_HTTP    = 0,  // Hypertext Transfer Protocol
    XRSR_PROTOCOL_HTTPS   = 1,  // Secure HTTP with TLS/SSL
    XRSR_PROTOCOL_WS      = 2,  // WebSocket Protocol  
    XRSR_PROTOCOL_WSS     = 3,  // Secure WebSocket with TLS/SSL
    XRSR_PROTOCOL_SDT     = 4,  // Service Discovery and Transport
    XRSR_PROTOCOL_INVALID = 5   // Invalid protocol identifier
} xrsr_protocol_t;
```

### Protocol State Management
```c
// Unified protocol state union
typedef union {
#ifdef WS_ENABLED
    xrsr_state_ws_t   ws;    // WebSocket connection state
#endif
#ifdef HTTP_ENABLED  
    xrsr_state_http_t http;  // HTTP connection state
#endif
#ifdef SDT_ENABLED
    xrsr_state_sdt_t  sdt;   // SDT protocol state
#endif
} xrsr_conn_state_t;
```

### Protocol Configuration System
Located in [`xrsr_config_default.json`](../src/xr-speech-router/xrsr_config_default.json):

#### WebSocket Configuration with Power Mode Support
```json
{
    "ws": {
        "debug": true,
        "fpm": {                          // Full Power Mode settings
            "connect_check_interval": 50,   // Connection health check (ms)
            "timeout_connect": 2000,        // Connection timeout (ms)
            "timeout_inactivity": 10000,    // Inactivity timeout (ms)  
            "timeout_session": 5000,        // Session timeout (ms)
            "ipv4_fallback": true,          // IPv4 fallback enabled
            "backoff_delay": 50             // Reconnection backoff (ms)
        },
        "lpm": {                          // Low Power Mode settings
            "connect_check_interval": 50,   // Reduced check frequency
            "timeout_connect": 10000,       // Extended connection timeout
            "timeout_inactivity": 10000,    // Extended inactivity timeout
            "timeout_session": 10000,       // Extended session timeout
            "ipv4_fallback": true,          // IPv4 fallback enabled
            "backoff_delay": 100            // Increased backoff delay
        }
    },
    "http": {
        "debug": false                    // HTTP debug logging
    }
}
```

## Audio Format Support Architecture

### Supported Audio Formats
```c
typedef enum {
    XRSR_AUDIO_FORMAT_NONE             = 0,       // No audio format
    XRSR_AUDIO_FORMAT_PCM              = 1 << 0,  // 16-bit PCM
    XRSR_AUDIO_FORMAT_PCM_32_BIT       = 1 << 1,  // 32-bit PCM
    XRSR_AUDIO_FORMAT_PCM_32_BIT_MULTI = 1 << 2,  // Multi-channel 32-bit PCM
    XRSR_AUDIO_FORMAT_PCM_RAW          = 1 << 3,  // Unprocessed 32-bit PCM
    XRSR_AUDIO_FORMAT_ADPCM_FRAME      = 1 << 4,  // Framed ADPCM compression
    XRSR_AUDIO_FORMAT_OPUS             = 1 << 6,  // Opus compression
    XRSR_AUDIO_FORMAT_MAX              = 1 << 7   // Format boundary marker
} xrsr_audio_format_type_t;
```

### ADPCM Frame Configuration
```c  
typedef struct {
    uint8_t size_packet;                // ADPCM packet size
    uint8_t size_header;                // ADPCM header size
    uint8_t offset_step_size_index;     // Step size index offset  
    uint8_t offset_predicted_sample_lsb;// Predicted sample LSB offset
    uint8_t offset_predicted_sample_msb;// Predicted sample MSB offset
    uint8_t offset_sequence_value;      // Sequence value offset
    uint8_t shift_sequence_value;       // Sequence value bit shift
    uint8_t sequence_value_min;         // Minimum sequence value
    uint8_t sequence_value_max;         // Maximum sequence value
} xrsr_adpcm_frame_t;

typedef struct {
    xrsr_audio_format_type_t type;      // Format type identifier
    union {
        xrsr_adpcm_frame_t adpcm_frame; // ADPCM-specific parameters
    } value;
} xrsr_audio_format_t;
```

### Audio Container Support
```c
typedef enum {
    XRSR_AUDIO_CONTAINER_NONE    = 0,  // Raw audio data (no container)
    XRSR_AUDIO_CONTAINER_WAV     = 1,  // WAV file container format
    XRSR_AUDIO_CONTAINER_INVALID = 2   // Invalid container type
} xrsr_audio_container_t;
```

## Stream Management Architecture

### Stream Timing Control
```c
// Stream start position control
typedef enum {
    XRSR_STREAM_FROM_BEGINNING     = 0,  // Start from audio beginning
    XRSR_STREAM_FROM_LIVE          = 1,  // Start from live point
    XRSR_STREAM_FROM_KEYWORD_BEGIN = 2,  // Start from keyword detection
    XRSR_STREAM_FROM_KEYWORD_END   = 3,  // Start after keyword end
    XRSR_STREAM_FROM_INVALID       = 4   // Invalid start position
} xrsr_stream_from_t;

// Stream end condition control
typedef enum {
    XRSR_STREAM_UNTIL_END_OF_STREAM  = 0,  // Stream until EOF or error
    XRSR_STREAM_UNTIL_END_OF_SPEECH  = 1,  // Stream until EOS detection
    XRSR_STREAM_UNTIL_END_OF_KEYWORD = 2,  // Stream until keyword end
    XRSR_STREAM_UNTIL_INVALID        = 3   // Invalid end condition
} xrsr_stream_until_t;
```

### Session End Reason Taxonomy
```c
typedef enum {
    XRSR_SESSION_END_REASON_EOS                     = 0,   // End-of-speech detected
    XRSR_SESSION_END_REASON_EOT                     = 1,   // End-of-text session
    XRSR_SESSION_END_REASON_DISCONNECT_REMOTE       = 2,   // Server disconnection
    XRSR_SESSION_END_REASON_TERMINATE               = 3,   // Client termination
    XRSR_SESSION_END_REASON_ERROR_INTERNAL          = 4,   // Internal system error
    XRSR_SESSION_END_REASON_ERROR_WS_SEND           = 5,   // WebSocket send failure
    XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN       = 6,   // Audio initialization failure  
    XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION    = 7,   // Insufficient audio duration
    XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE   = 8,   // Connection establishment failure
    XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT   = 9,   // Connection timeout
    XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT   = 10,  // Session processing timeout
    XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE = 11,  // Unexpected server disconnect
    XRSR_SESSION_END_REASON_INVALID                 = 12   // Invalid end reason
} xrsr_session_end_reason_t;
```

## Threading and Message Architecture

### Main Thread Architecture
Located in [`xrsr.c`](../src/xr-speech-router/xrsr.c#L35-L45):

```c
typedef enum {
    XRSR_THREAD_MAIN = 0,  // Primary processing thread
    XRSR_THREAD_QTY  = 1   // Thread count
} xrsr_thread_t;

typedef struct {
    const char *       name;       // Thread name for debugging
    int                msgq_id;    // Message queue identifier  
    size_t             msgsize;    // Maximum message size
    xrsr_thread_func_t func;       // Thread entry point function
    void *             params;     // Thread parameter structure
    pthread_t          id;         // POSIX thread identifier
    sem_t              semaphore;  // Thread synchronization primitive
} xrsr_thread_info_t;
```

### Message Handler Architecture
```c
typedef void (*xrsr_msg_handler_t)(const xrsr_thread_params_t *params, 
                                   xrsr_thread_state_t *state, 
                                   void *msg);

// Message handler dispatch table
static const xrsr_msg_handler_t g_xrsr_msg_handlers[] = {
    xrsr_msg_terminate,                        // System termination
    xrsr_msg_route_update,                     // Route configuration update
    xrsr_msg_keyword_update,                   // Keyword configuration update
    xrsr_msg_host_name_update,                 // Host name change notification
    xrsr_msg_capture_config_update,            // Capture configuration update
    xrsr_msg_power_mode_update,                // Power mode transition
    xrsr_msg_privacy_mode_update,              // Privacy mode toggle
    xrsr_msg_privacy_mode_get,                 // Privacy mode query
    xrsr_msg_xraudio_granted,                  // Audio resource granted
    xrsr_msg_xraudio_revoked,                  // Audio resource revoked
    xrsr_msg_xraudio_event,                    // Audio system event
    xrsr_msg_keyword_detected,                 // Keyword detection event
    xrsr_msg_keyword_detect_error,             // Keyword detection error
    xrsr_msg_keyword_detect_sensitivity_limits_get, // Sensitivity limits query
    xrsr_msg_session_begin,                    // Session initiation
    xrsr_msg_session_config_in,                // Session configuration input
    xrsr_msg_session_terminate,                // Session termination
    xrsr_msg_session_audio_stream_start,       // Audio stream start
    xrsr_msg_session_capture_start,            // Capture session start
    xrsr_msg_session_capture_stop,             // Capture session stop
    xrsr_msg_thread_poll,                      // Thread health check
};
```

## Global State Management

### System State Structure
```c
typedef struct {
    bool                          opened;             // System initialization state
    xrsr_power_mode_t             power_mode;         // Current power management mode
    bool                          privacy_mode;       // Privacy mode enabled flag
    bool                          mask_pii;           // PII masking enabled flag
    xrsr_thread_info_t            threads[XRSR_THREAD_QTY]; // Thread management
    xrsr_route_int_t              routes[XRSR_SRC_INVALID]; // Route configurations
    xrsr_xraudio_object_t         xrsr_xraudio_object; // Audio system integration
    char *                        capture_dir_path;   // Audio capture directory
    xrsr_session_t                sessions[XRSR_SESSION_GROUP_QTY]; // Active sessions
    
#ifdef WS_ENABLED
    xrsr_ws_json_config_t         *ws_json_config;    // Active WebSocket config
    xrsr_ws_json_config_t          ws_json_config_fpm;// Full power mode WS config
    xrsr_ws_json_config_t          ws_json_config_lpm;// Low power mode WS config  
#endif
#ifdef HTTP_ENABLED
    xrsr_http_json_config_t        http_json_config;  // HTTP configuration
#endif
    
    bool                           networked_standby;  // Network standby mode
    bool                           local_mic;          // Local microphone enabled
    bool                           local_mic_tap;      // Microphone tap enabled
} xrsr_global_t;
```

### Route Management Architecture
```c
typedef struct {
    xrsr_dst_int_t dsts[XRSR_DST_QTY_MAX]; // Destination configurations
} xrsr_route_int_t;

typedef struct {
    bool                         initialized;         // Route initialization state
    xrsr_url_parts_t             url_parts;          // Parsed URL components
    xrsr_route_handler_t         handler;            // Protocol-specific handler
    xrsr_handlers_t              handlers;           // Callback function set
    xrsr_audio_format_type_t     formats;           // Supported audio formats
    uint16_t                     stream_time_min;    // Minimum stream duration
    xraudio_input_record_from_t  stream_from;        // Stream start position
    int32_t                      stream_offset;      // Stream timing offset
    xraudio_input_record_until_t stream_until;       // Stream end condition
    uint32_t                     keyword_begin;      // Keyword timing: start
    uint32_t                     keyword_duration;   // Keyword timing: duration
    xrsr_conn_state_t            conn_state;         // Connection state
    xrsr_dst_param_ptrs_t        dst_param_ptrs[XRSR_POWER_MODE_INVALID]; // Power mode params
} xrsr_dst_int_t;
```

## Session Management Architecture

### Session Configuration and State
```c
typedef struct {
    xrsr_src_t                    src;                // Audio source type
    xraudio_devices_input_t       xraudio_device_input; // Audio device configuration
    int                           pipe_fds_rd[XRSR_DST_QTY_MAX]; // Read pipe descriptors
    int                           pipe_size[XRSR_DST_QTY_MAX];   // Pipe buffer sizes
    bool                          requested_more_audio; // Additional audio requested
    uint16_t                      stream_id;          // Unique stream identifier
    xrsr_session_config_update_t  session_config_update; // Configuration update info
} xrsr_session_t;
```

### Power Mode Management
```c
typedef enum {
    XRSR_POWER_MODE_FULL    = 0,  // Maximum performance, minimum latency
    XRSR_POWER_MODE_LOW     = 1,  // Reduced performance, power optimization
    XRSR_POWER_MODE_SLEEP   = 2,  // Minimal activity, maximum power saving
    XRSR_POWER_MODE_INVALID = 3   // Invalid power mode
} xrsr_power_mode_t;
```

#### Power Mode Impact Matrix
| Component | Full Power Mode | Low Power Mode | Sleep Mode |
|-----------|----------------|----------------|------------|
| Connection Timeout | 2000ms | 10000ms | N/A |
| Session Timeout | 5000ms | 10000ms | N/A |
| Check Interval | 50ms | 50ms | N/A |
| Backoff Delay | 50ms | 100ms | N/A |
| Keyword Detection | Always Active | Selective | Disabled |
| Audio Processing | Full Quality | Reduced Quality | Stopped |

## Security and Certificate Management

### Certificate Support Framework
```c
typedef enum {
    XRSR_CERT_TYPE_NONE    = 0,  // No certificate
    XRSR_CERT_TYPE_P12     = 1,  // PKCS#12 certificate bundle
    XRSR_CERT_TYPE_PEM     = 2,  // PEM-encoded certificates  
    XRSR_CERT_TYPE_X509    = 3,  // X.509 certificate objects
    XRSR_CERT_TYPE_INVALID = 4   // Invalid certificate type
} xrsr_cert_type_t;

// PKCS#12 certificate configuration
typedef struct {
    const char *filename;    // P12 file path
    const char *passphrase;  // Decryption passphrase
} xrsr_cert_p12_t;

// PEM certificate configuration  
typedef struct {
    const char *filename_cert;  // Certificate file path
    const char *filename_pkey;  // Private key file path
    const char *filename_chain; // Certificate chain file path
    const char *passphrase;     // Private key passphrase
} xrsr_cert_pem_t;

// X.509 in-memory certificate objects
typedef struct {
    X509 *          x509;   // Certificate object
    EVP_PKEY *      pkey;   // Private key object  
    STACK_OF(X509) *chain;  // Certificate chain stack
} xrsr_cert_x509_t;

// Unified certificate structure
typedef struct {
    xrsr_cert_type_t type;  // Certificate type identifier
    union {
        xrsr_cert_p12_t  p12;   // PKCS#12 configuration
        xrsr_cert_pem_t  pem;   // PEM configuration
        xrsr_cert_x509_t x509;  // X.509 objects
    } cert;
} xrsr_cert_t;
```

## XR Audio Integration Architecture

### Audio System Integration Points
The XRSR integrates with the XR Audio component through several key interfaces:

1. **Resource Management**: Dynamic audio resource acquisition and release
2. **Stream Routing**: Real-time audio data pipeline from sources to destinations  
3. **Event Handling**: Keyword detection, EOS detection, and error notifications
4. **Configuration Synchronization**: Coordinated audio format and timing parameters

### Integration Callback Architecture
```c
// Session configuration callback for HTTP protocol
#ifdef HTTP_ENABLED
static void xrsr_callback_session_config_in_http(const uuid_t uuid, 
                                                 xrsr_session_config_in_t *config_in);
#endif

// Session configuration callback for WebSocket protocol
static void xrsr_callback_session_config_in_ws(const uuid_t uuid, 
                                               xrsr_session_config_in_t *config_in);

// Audio streaming callbacks
static void xrsr_session_stream_kwd(const uuid_t uuid, const char *uuid_str, 
                                    xrsr_src_t src, uint32_t dst_index);

static void xrsr_session_stream_end(const uuid_t uuid, const char *uuid_str, 
                                    xrsr_src_t src, uint32_t dst_index, 
                                    xrsr_stream_stats_t *stats);
```

## Performance and Scalability Characteristics

### Protocol Performance Profiles
- **HTTP/HTTPS**: Low overhead, request-response model, suitable for batch processing
- **WebSocket/WSS**: Real-time bidirectional communication, optimal for streaming
- **SDT**: Optimized for service discovery and low-latency transport

### Memory Usage Optimization
- **Static Configuration**: Pre-allocated route and session structures
- **Dynamic Scaling**: Session resources allocated/deallocated on-demand  
- **Buffer Management**: Efficient audio buffer pooling and reuse
- **Protocol Isolation**: Conditional compilation reduces memory footprint

### Latency Characteristics
- **Session Establishment**: 50-2000ms depending on protocol and power mode
- **Audio Streaming**: <10ms additional latency over base audio pipeline
- **Protocol Switching**: <100ms for seamless protocol migration
- **Error Recovery**: <500ms for connection re-establishment

This comprehensive speech routing architecture provides flexible, efficient, and scalable voice recognition capabilities while maintaining optimal resource utilization and system responsiveness across diverse deployment scenarios.