# XRSR Speech Recognition Integration Analysis Documentation

## Overview
The XRSR (XR Speech Router) speech recognition integration provides a comprehensive framework for connecting audio input sources with remote speech recognition services through multiple protocol backends. The integration architecture handles the complete speech recognition lifecycle from session initiation, through audio streaming, to transcription response processing, with sophisticated callback mechanisms for application control and event handling.

## Architectural Overview

### Speech Recognition Integration Philosophy
XRSR's speech recognition integration is built on several key architectural principles:

1. **Protocol Agnostic Interface**: Applications interact with a unified API regardless of underlying transport protocols
2. **Event-Driven Architecture**: Asynchronous callbacks provide real-time notification of session events
3. **Bidirectional Communication**: Support for both streaming audio to services and receiving real-time responses
4. **Session State Management**: Complete lifecycle tracking with comprehensive error handling
5. **Multi-Source Support**: Simultaneous handling of different audio input sources with independent sessions

### High-Level Integration Architecture
```
┌─────────────────────────┐    ┌─────────────────────────┐    ┌─────────────────────────┐
│   Application Layer     │    │   XRSR Integration      │    │  Speech Recognition     │
│                         │    │                         │    │       Services          │
│ • Session Management    │────┤ • Callback Framework    ├────│ • Cloud ASR APIs        │
│ • Event Handling        │    │ • Message Processing    │    │ • Real-time STT         │
│ • Transcription Proc    │    │ • Protocol Abstraction │    │ • Voice Analytics       │
│ • Audio Control         │    │ • Session Lifecycle     │    │ • Response Generation   │
│                         │    │ • Error Management      │    │                         │
└─────────────────────────┘    └─────────────────────────┘    └─────────────────────────┘
```

## Session Lifecycle Management

### Speech Recognition Session Flow
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L75-L150):

The XRSR speech recognition integration manages sessions through a well-defined lifecycle:

#### Session Types and Input Modes
```c
typedef enum {
   XRSR_SESSION_REQUEST_TYPE_TEXT        = 0, // Text-only transcription processing
   XRSR_SESSION_REQUEST_TYPE_AUDIO_FILE  = 1, // Pre-recorded audio file input
   XRSR_SESSION_REQUEST_TYPE_AUDIO_FD    = 2, // Audio file descriptor streaming
   XRSR_SESSION_REQUEST_TYPE_AUDIO_MIC   = 3, // Live microphone input
   XRSR_SESSION_REQUEST_TYPE_INVALID     = 4, // Invalid session type
} xrsr_session_request_type_t;
```

#### Session Request Structure
```c
typedef struct {
   xrsr_session_request_type_t type;
   union {
      xrsr_request_text_t       text;       // Text input for NLU processing
      xrsr_request_audio_file_t audio_file; // File path for audio input
      xrsr_request_audio_fd_t   audio_fd;   // File descriptor with callbacks
      xrsr_request_audio_mic_t  audio_mic;  // Live microphone configuration
   } value;
} xrsr_session_request_t;
```

### Session Configuration Architecture

#### Input Configuration Types
```c
// Text-only session configuration
typedef struct {
   const char *text; // Transcription input for NLU processing
} xrsr_request_text_t;

// Audio file input configuration
typedef struct {
   const char *path; // Path to audio file for recognition
} xrsr_request_audio_file_t;

// File descriptor input with callback support
typedef struct {
   int                       audio_fd;     // Audio file descriptor
   xrsr_audio_format_t       audio_format; // Audio format specification
   xrsr_input_data_read_cb_t callback;     // Read completion callback
   void *                    user_data;    // User context data
} xrsr_request_audio_fd_t;

// Live microphone configuration
typedef struct {
   bool   stream_params_required; // Requires keyword timing information
   float *dynamic_gain_update;    // Dynamic gain adjustment pointer
} xrsr_request_audio_mic_t;
```

#### Protocol-Specific Session Configuration
The integration provides protocol-specific configuration for advanced features:

```c
// HTTP/HTTPS session configuration
typedef struct {
   const char *        sat_token;                                 // Security Access Token
   const char *        user_agent;                                // HTTP User-Agent header
   const char *        query_strs[XRSR_QUERY_STRING_QTY_MAX + 1]; // Query string parameters
   uint32_t            keyword_begin;                             // Keyword start sample
   uint32_t            keyword_duration;                          // Keyword duration samples
   xrsr_cert_t         client_cert;                               // Client certificate
   bool                host_verify;                               // Hostname verification
   bool                ocsp_verify_stapling;                      // OCSP stapling verification
   bool                ocsp_verify_ca;                            // OCSP CA verification
} xrsr_session_config_in_http_t;

// WebSocket session configuration
typedef struct {
   const char *        sat_token;                                   // Security Access Token
   const char *        query_strs[XRSR_QUERY_STRING_QTY_MAX + 1];   // Query parameters
   uint32_t            keyword_begin;                               // Keyword start sample
   uint32_t            keyword_duration;                            // Keyword duration samples
   xrsr_cert_t         client_cert;                                 // Client certificate
   bool                host_verify;                                 // Hostname verification
   bool                ocsp_verify_stapling;                        // OCSP stapling verification
   bool                ocsp_verify_ca;                              // OCSP CA verification
   bool                cert_expired_allow;                          // Allow expired certificates
   bool                cert_revoked_allow;                          // Allow revoked certificates
   bool                ocsp_expired_allow;                          // Allow expired OCSP responses
   void *              app_config;                                  // Application-specific config
} xrsr_session_config_in_ws_t;
```

## Callback Framework Architecture

### Core Callback Interface
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L420-L520):

The XRSR integration provides a comprehensive callback framework for application integration:

```c
typedef struct {
   void *                        data;           // User context pointer
   xrsr_handler_session_begin_t  session_begin;  // Session initiation callback
   xrsr_handler_session_config_t session_config; // Session configuration callback
   xrsr_handler_session_end_t    session_end;    // Session completion callback
   xrsr_handler_stream_begin_t   stream_begin;   // Audio streaming start callback
   xrsr_handler_stream_kwd_t     stream_kwd;     // Keyword detection callback
   xrsr_handler_stream_audio_t   stream_audio;   // Audio data streaming callback
   xrsr_handler_stream_end_t     stream_end;     // Audio streaming end callback
   xrsr_handler_source_error_t   source_error;   // Audio source error callback
   xrsr_handler_connected_t      connected;      // Protocol connection callback
   xrsr_handler_disconnected_t   disconnected;   // Protocol disconnection callback
   xrsr_handler_recv_msg_t       recv_msg;       // Message reception callback
} xrsr_handlers_t;
```

### Session Lifecycle Callbacks

#### Session Begin Handler
```c
typedef void (*xrsr_handler_session_begin_t)(
   void *data,                            // User context data
   const uuid_t uuid,                     // Session unique identifier
   xrsr_src_t src,                        // Audio source type
   uint32_t dst_index,                    // Destination route index
   xrsr_keyword_detector_result_t *detector_result, // Keyword detection results
   xrsr_session_config_out_t *config_out, // Output configuration
   xrsr_session_config_in_t *config_in,   // Input configuration
   rdkx_timestamp_t *timestamp,           // Session start timestamp
   const char *transcription_in           // Text input for text-only sessions
);
```

**Purpose**: Notifies the application when a new speech recognition session begins, allowing configuration of session-specific parameters including authentication tokens, protocol settings, and audio format requirements.

#### Session End Handler
```c
typedef void (*xrsr_handler_session_end_t)(
   void *data,                    // User context data
   const uuid_t uuid,            // Session unique identifier
   xrsr_session_stats_t *stats,  // Session performance statistics
   rdkx_timestamp_t *timestamp   // Session end timestamp
);
```

**Purpose**: Provides session completion notification with comprehensive performance metrics including connection times, protocol response codes, and error conditions.

### Audio Streaming Callbacks

#### Stream Begin Handler
```c
typedef void (*xrsr_handler_stream_begin_t)(
   void *data,                  // User context data
   const uuid_t uuid,          // Session unique identifier
   xrsr_src_t src,             // Audio source type
   rdkx_timestamp_t *timestamp // Stream start timestamp
);
```

**Purpose**: Indicates when audio streaming begins within a session, enabling applications to track audio pipeline activation and prepare for real-time audio processing.

#### Stream Keyword Handler
```c
typedef void (*xrsr_handler_stream_kwd_t)(
   void *data,                  // User context data
   const uuid_t uuid,          // Session unique identifier
   rdkx_timestamp_t *timestamp // Keyword detection timestamp
);
```

**Purpose**: Notifies when keyword audio has been transmitted to the speech service, allowing applications to provide user feedback and track voice interaction progression.

#### Stream End Handler
```c
typedef void (*xrsr_handler_stream_end_t)(
   void *data,                    // User context data
   const uuid_t uuid,            // Session unique identifier
   xrsr_stream_stats_t *stats,   // Stream performance statistics
   rdkx_timestamp_t *timestamp   // Stream end timestamp
);
```

**Purpose**: Provides audio streaming completion notification with detailed statistics about audio processing, packet transmission, and stream quality metrics.

### Protocol Connection Callbacks

#### Connected Handler
```c
typedef bool (*xrsr_handler_connected_t)(
   void *data,                              // User context data
   const uuid_t uuid,                       // Session unique identifier
   xrsr_handler_send_t send,                // Data transmission function
   void *param,                             // Send function parameter
   rdkx_timestamp_t *timestamp,             // Connection timestamp
   xrsr_session_config_update_t *session_config_update // Configuration update
);
```

**Purpose**: Notification of successful protocol connection establishment, providing the application with a send function for bidirectional communication and allowing dynamic session configuration updates.

#### Disconnected Handler
```c
typedef void (*xrsr_handler_disconnected_t)(
   void *data,                      // User context data
   const uuid_t uuid,              // Session unique identifier
   xrsr_session_end_reason_t reason, // Disconnection reason
   bool retry,                      // Indicates if retry will occur
   bool *detect_resume,             // Resume detection flag pointer
   rdkx_timestamp_t *timestamp      // Disconnection timestamp
);
```

**Purpose**: Handles protocol disconnection events with detailed reason codes, retry indicators, and control over whether keyword detection should resume after disconnection.

### Message Processing Callbacks

#### Receive Message Handler
```c
typedef bool (*xrsr_handler_recv_msg_t)(
   void *data,                  // User context data
   xrsr_recv_msg_t type,       // Message type (text/binary)
   const uint8_t *buffer,      // Message data buffer
   uint32_t length,            // Message length
   xrsr_recv_event_t *event    // Associated event information
);
```

**Purpose**: Processes incoming messages from speech recognition services, including transcription results, intermediate responses, and service-specific data.

#### Message Types and Event Handling
```c
typedef enum {
   XRSR_RECV_MSG_TEXT    = 0, // Text-based message (JSON, XML, etc.)
   XRSR_RECV_MSG_BINARY  = 1, // Binary message data
   XRSR_RECV_MSG_INVALID = 2, // Invalid message type
} xrsr_recv_msg_t;

typedef enum {
   XRSR_RECV_EVENT_EOS_SERVER        = 0, // Server-detected end of speech
   XRSR_RECV_EVENT_DISCONNECT_REMOTE = 1, // Server initiated disconnection
   XRSR_RECV_EVENT_NONE              = 2, // No associated event
   XRSR_RECV_EVENT_INVALID           = 3, // Invalid event type
} xrsr_recv_event_t;
```

## Keyword Detection Integration

### Keyword Detector Results Structure
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L404-L420):

```c
typedef struct {
   float        score;                // Confidence score (0-100%)
   float        snr;                  // Signal-to-noise ratio (-100 to +100 dB)
   uint16_t     doa;                  // Direction of arrival (0-359 degrees)
   int32_t      offset_buf_begin;     // Negative offset to buffer beginning
   int32_t      offset_kwd_begin;     // Negative offset to keyword start
   int32_t      offset_kwd_end;       // Negative offset to keyword end
   float        kwd_gain;             // Fixed gain applied to keyword detector
   const char * detector_name;        // Keyword detector identifier
   const char * dsp_name;             // DSP preprocessing identifier
   float        dynamic_gain;         // Calculated dynamic gain value
   float        sensitivity;          // Keyword detector sensitivity
   float *      dynamic_gain_update;  // Recalculated dynamic gain pointer
} xrsr_keyword_detector_result_t;
```

### Keyword Detection Integration Points

1. **Session Initiation**: Keyword detection results automatically trigger session begin callbacks
2. **Audio Timing**: Precise keyword timing information enables accurate audio streaming alignment
3. **Adaptive Processing**: Dynamic gain calculations optimize audio quality for speech recognition
4. **Multi-Detector Support**: Multiple keyword detectors can operate simultaneously with unique identifiers

## Session Statistics and Performance Monitoring

### Comprehensive Performance Metrics
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L373-L403):

#### Audio Stream Statistics
```c
typedef struct {
   bool     valid;                // Statistics validity flag
   uint32_t packets_processed;    // Total audio packets processed
   uint32_t packets_lost;         // Audio packets lost during transmission
   uint32_t samples_processed;    // Total audio samples processed
   uint32_t samples_lost;         // Audio samples lost during transmission
   uint32_t decoder_failures;     // Audio decoder failure count
   uint32_t samples_buffered_max; // Maximum buffered sample count
} xrsr_audio_stats_t;
```

#### Session Performance Statistics
```c
typedef struct {
   xrsr_session_end_reason_t reason;                             // Session end reason
   xrsr_ret_code_internal_t  ret_code_internal;                  // Internal return code
   long                      ret_code_protocol;                  // Protocol response code
   long                      ret_code_library;                   // Library-specific code
   char                      server_ip[XRSR_SESSION_IP_LEN_MAX]; // Server IP address
   double                    time_connect;                       // Connection time (seconds)
   double                    time_dns;                           // DNS lookup time (seconds)
} xrsr_session_stats_t;
```

#### Stream Quality Statistics
```c
typedef struct {
   bool               result;        // Stream success indicator
   xrsr_protocol_t    prot;         // Protocol used for stream
   xrsr_audio_stats_t audio_stats;  // Detailed audio statistics
} xrsr_stream_stats_t;
```

## Error Handling and Recovery Architecture

### Session End Reason Classification
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L88-L105):

```c
typedef enum {
   XRSR_SESSION_END_REASON_EOS                     = 0,  // Natural end of speech
   XRSR_SESSION_END_REASON_EOT                     = 1,  // End of text session
   XRSR_SESSION_END_REASON_DISCONNECT_REMOTE       = 2,  // Server disconnection
   XRSR_SESSION_END_REASON_TERMINATE               = 3,  // User termination
   XRSR_SESSION_END_REASON_ERROR_INTERNAL          = 4,  // Internal system error
   XRSR_SESSION_END_REASON_ERROR_WS_SEND           = 5,  // WebSocket send failure
   XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN       = 6,  // Audio initialization failure
   XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION    = 7,  // Insufficient audio duration
   XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE   = 8,  // Connection failure
   XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT   = 9,  // Connection timeout
   XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT   = 10, // Session timeout
   XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE = 11, // Unexpected server disconnect
   XRSR_SESSION_END_REASON_INVALID                 = 12, // Invalid reason code
} xrsr_session_end_reason_t;
```

### Error Recovery Mechanisms

1. **Automatic Retry**: Configurable retry logic with exponential backoff for transient failures
2. **Graceful Degradation**: Fallback to alternative protocols or reduced functionality
3. **Session Isolation**: Errors in one session do not affect concurrent sessions
4. **Resource Cleanup**: Automatic cleanup of resources on session termination or failure

## Multi-Source Audio Management

### Audio Source Types and Capabilities
Located in [`xrsr.h`](../src/xr-speech-router/xrsr.h#L60-L67):

```c
typedef enum {
   XRSR_SRC_RCU_PTT         = 0, // Remote Control Unit Push-to-Talk
   XRSR_SRC_RCU_FF          = 1, // Remote Control Unit Far-Field
   XRSR_SRC_MICROPHONE      = 2, // Local Microphone Input
   XRSR_SRC_MICROPHONE_TAP  = 3, // Local Microphone Tap (monitoring)
   XRSR_SRC_INVALID         = 4  // Invalid source type
} xrsr_src_t;
```

### Concurrent Session Management

The XRSR integration supports multiple concurrent speech recognition sessions:

- **Source Isolation**: Each audio source operates independently with separate session contexts
- **Resource Arbitration**: Intelligent management of shared resources (network, CPU, memory)
- **Priority Handling**: Configurable priority levels for different source types
- **Session Queuing**: Orderly handling of overlapping session requests

## Protocol Integration Architecture

### Protocol-Agnostic Session API
The XRSR integration abstracts protocol differences through a unified session management interface:

```c
// Session initiation (protocol-independent)
bool xrsr_session_request(
   xrsr_src_t src,                    // Audio source type
   xrsr_audio_format_t output_format, // Desired audio format
   xrsr_session_request_t input_format, // Input configuration
   const uuid_t *uuid,               // Optional session UUID
   bool low_latency,                 // Low latency mode
   bool low_cpu_util                 // CPU optimization mode
);

// Session termination (protocol-independent)
void xrsr_session_terminate(xrsr_src_t src);

// Dynamic audio streaming control
void xrsr_session_audio_stream_start(xrsr_src_t src);
```

### Data Transmission Interface
Bidirectional communication is handled through a unified send interface:

```c
typedef xrsr_result_t (*xrsr_handler_send_t)(
   void *param,                // Protocol-specific parameter
   const uint8_t *buffer,      // Data buffer to transmit
   uint32_t length             // Buffer length in bytes
);
```

This interface allows applications to send data through any supported protocol without protocol-specific knowledge.

## Real-Time Communication Features

### Bidirectional Streaming Support
The integration supports both audio streaming to services and real-time response processing:

1. **Audio Upload Streaming**: Continuous audio transmission during recognition sessions
2. **Intermediate Results**: Real-time partial transcription results during audio processing  
3. **Final Results**: Complete transcription and analysis results upon session completion
4. **Service Messages**: Protocol-specific messages and service status updates

### Audio Format Negotiation
Dynamic audio format selection based on service capabilities and network conditions:

```c
typedef enum {
   XRSR_AUDIO_FORMAT_PCM              = 1 << 0, // 16-bit PCM
   XRSR_AUDIO_FORMAT_PCM_32_BIT       = 1 << 1, // 32-bit PCM
   XRSR_AUDIO_FORMAT_PCM_32_BIT_MULTI = 1 << 2, // Multi-channel 32-bit PCM
   XRSR_AUDIO_FORMAT_PCM_RAW          = 1 << 3, // Raw unprocessed PCM
   XRSR_AUDIO_FORMAT_ADPCM_FRAME      = 1 << 4, // Framed ADPCM compression
   XRSR_AUDIO_FORMAT_OPUS             = 1 << 6, // Opus compression
} xrsr_audio_format_type_t;
```

## Integration Best Practices

### Application Integration Guidelines

1. **Callback Registration**: Always register all relevant callbacks before opening XRSR
2. **UUID Management**: Use UUIDs to correlate session events across callbacks
3. **Resource Management**: Properly handle resources in callback functions
4. **Error Handling**: Implement comprehensive error handling for all callback scenarios
5. **Thread Safety**: Ensure callback implementations are thread-safe if needed

### Performance Optimization

1. **Callback Efficiency**: Keep callback functions lightweight to avoid blocking XRSR processing
2. **Memory Management**: Minimize memory allocations in callback contexts
3. **Network Optimization**: Use appropriate audio formats for available bandwidth
4. **Session Reuse**: Where possible, reuse configured routes for multiple sessions

### Security Considerations

1. **Certificate Management**: Properly validate and manage SSL/TLS certificates
2. **Token Security**: Securely handle SAT tokens and authentication credentials
3. **Data Privacy**: Implement appropriate data handling for voice recordings
4. **Network Security**: Use encrypted protocols (HTTPS/WSS) for production deployments

## Configuration and Customization

### Route Configuration
Applications configure speech recognition routes with comprehensive parameter control:

```c
typedef struct {
   const char *        url;                             // Service endpoint URL
   xrsr_handlers_t     handlers;                        // Callback function set
   uint32_t            formats;                         // Supported audio format bitmap
   uint16_t            stream_time_min;                 // Minimum stream duration (ms)
   xrsr_stream_from_t  stream_from;                     // Stream start position
   int32_t             stream_offset;                   // Stream timing offset
   xrsr_stream_until_t stream_until;                    // Stream end condition
   xrsr_dst_params_t * params[XRSR_POWER_MODE_INVALID]; // Power mode parameters
} xrsr_dst_t;
```

### Power Mode Integration
XRSR provides power-aware operation with configurable parameters for different power states:

- **Full Power Mode**: Maximum performance and minimum latency
- **Low Power Mode**: Balanced performance and power consumption
- **Sleep Mode**: Minimal power consumption with reduced functionality

This comprehensive speech recognition integration architecture enables robust, scalable, and efficient voice interaction capabilities suitable for production XR applications across diverse deployment scenarios.