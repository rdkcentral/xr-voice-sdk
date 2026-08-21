# XRSR Advanced Features Analysis

## Overview
The XRSR (XR Speech Router) component implements numerous advanced features that extend beyond basic protocol routing and speech recognition. These features provide performance optimization, comprehensive monitoring, dynamic configuration capabilities, robust error recovery, and quality of service management for production deployment in XR voice-enabled devices.

## Performance Optimization Features

### Low-Latency Mode
All XRSR protocols support **low-latency** operation for time-critical voice applications:

```c
// Protocol handler signature with low_latency parameter
void xrsr_protocol_handler_http(xrsr_src_t src, bool retry, bool user_initiated, 
                               xraudio_input_format_t xraudio_format, 
                               xraudio_keyword_detector_result_t *detector_result, 
                               xrsr_session_request_t input_format, const uuid_t *uuid, 
                               bool low_latency, bool low_cpu_util);
```

**Low-Latency Features**:
- **Reduced Buffer Sizes**: Minimizes audio buffering for faster response
- **Optimized Processing**: Streamlined audio pipeline processing
- **Priority Scheduling**: Higher priority for time-sensitive operations
- **Fast Connection Setup**: Reduced handshake and negotiation overhead

### Low CPU Utilization Mode
Complementary **low_cpu_util** mode for resource-constrained environments:

**CPU Optimization Features**:
- **Reduced Processing Load**: Less intensive audio processing algorithms
- **Optimized Memory Usage**: Minimal memory allocation and copying
- **Efficient Codec Selection**: Preference for low-complexity audio codecs
- **Background Processing**: Non-critical operations moved to background threads

### Buffer Management Optimization
**HTTP Protocol Buffer Configuration**:
```c
#define XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX (102400)  // 100KB maximum buffer

typedef struct {
    char write_buffer[XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX];
    // Other HTTP state...
} xrsr_state_http_t;
```

**Buffer Optimization Features**:
- **Large Write Buffers**: 100KB buffers for efficient HTTP transmission
- **Circular Audio Buffers**: Efficient audio data management in WebSocket/SDT
- **Zero-Copy Operations**: Minimize memory copying in audio pipeline
- **Adaptive Buffer Sizing**: Dynamic adjustment based on network conditions

## Comprehensive Statistics and Monitoring

### Audio Statistics Tracking
Detailed **xrsr_audio_stats_t** structure provides comprehensive audio pipeline monitoring:

```c
typedef struct {
   bool     valid;                ///< Stats validity flag
   uint32_t packets_processed;    ///< Total audio packets processed
   uint32_t packets_lost;         ///< Packets lost during transmission
   uint32_t samples_processed;    ///< Total audio samples processed
   uint32_t samples_lost;         ///< Samples lost during transmission
   uint32_t decoder_failures;     ///< Audio decoder failure count
   uint32_t samples_buffered_max; ///< Peak buffer utilization
} xrsr_audio_stats_t;
```

**Audio Monitoring Capabilities**:
- **Packet Loss Detection**: Real-time packet loss monitoring
- **Sample-Level Tracking**: Precise audio sample accounting
- **Decoder Health Monitoring**: Codec failure detection and reporting
- **Buffer Utilization Analysis**: Peak memory usage tracking

### Session Statistics Monitoring
Comprehensive **xrsr_session_stats_t** for session lifecycle analysis:

```c
typedef struct {
   xrsr_session_end_reason_t reason;           ///< Session termination reason
   xrsr_ret_code_internal_t  ret_code_internal; ///< Internal error codes
   long                      ret_code_protocol; ///< Protocol-specific errors
   long                      ret_code_library;  ///< Library error codes (curl, nopoll)
   char                      server_ip[XRSR_SESSION_IP_LEN_MAX]; ///< Server IP address
   double                    time_connect;      ///< Connection establishment time
   double                    time_dns;          ///< DNS resolution time
} xrsr_session_stats_t;
```

**Session Monitoring Features**:
- **Performance Metrics**: Connection and DNS timing analysis
- **Error Classification**: Multi-layer error code tracking
- **Server Identification**: IP address logging for troubleshooting
- **Termination Analysis**: Detailed session end reason tracking

### Real-Time Statistics Logging
Integrated statistics reporting throughout the system:

```c
// XRAudio statistics integration
XLOGD_DEBUG("xraudio stats - packets processed <%u> lost <%u> samples processed <%u> lost <%u> decoder failures <%u>", 
            stream->audio_stats.packets_processed, 
            stream->audio_stats.packets_lost, 
            stream->audio_stats.samples_processed, 
            stream->audio_stats.samples_lost, 
            stream->audio_stats.decoder_failures);
```

## Dynamic Configuration Management

### Route Update System
Runtime routing configuration through **XRSR_QUEUE_MSG_TYPE_ROUTE_UPDATE** messages:

```c
typedef struct {
   xrsr_queue_msg_header_t header;
   // Route update parameters
   xrsr_src_t              src;
   uint32_t                dst_qty;
   // Dynamic routing configuration...
} xrsr_queue_msg_route_update_t;
```

**Dynamic Routing Features**:
- **Runtime Route Changes**: Modify routing without restart
- **Multi-Destination Support**: Configure multiple target destinations
- **Priority-Based Routing**: Route selection based on configured priorities
- **A/B Testing Support**: Dynamic switching between different speech services

### Session Configuration Updates
Real-time session parameter adjustment via **xrsr_session_config_update_t**:

```c
typedef struct {
   bool  update_required;  ///< Flag indicating update necessity
   float dynamic_gain;     ///< Real-time audio gain adjustment
} xrsr_session_config_update_t;
```

**Session Configuration Features**:
- **Dynamic Audio Gain**: Real-time microphone sensitivity adjustment
- **Mid-Session Updates**: Parameter changes during active sessions
- **Callback Integration**: Configuration updates through connected() callback
- **Automatic Validation**: Built-in parameter validation and sanitization

### Capture Configuration Updates
Audio capture parameter adjustment through **XRSR_QUEUE_MSG_TYPE_CAPTURE_CONFIG_UPDATE**:

**Capture Configuration Capabilities**:
- **Real-Time Format Changes**: Modify audio format during capture
- **Microphone Parameter Updates**: Adjust capture device settings
- **Quality Setting Adjustments**: Change audio quality parameters dynamically
- **Source Selection**: Runtime switching between input sources

## Advanced Debugging and Development Features

### Protocol-Specific Debug Modes
Each protocol implementation supports comprehensive debugging:

**HTTP Debug Configuration**:
```c
typedef struct {
   bool debug;  ///< HTTP-specific debug flag
   // Other HTTP protocol state...
} xrsr_state_http_t;
```

**WebSocket Debug Configuration**:
```c
typedef struct {
   bool debug_enabled;  ///< WebSocket debug enablement
   // noPoll library debug integration
} xrsr_state_ws_t;
```

**SDT Debug Configuration**:
```c
typedef struct {
   bool *debug;  ///< SDT protocol debug pointer
   // SDT-specific debugging features
} xrsr_protocol_params_sdt_t;
```

### Advanced Logging Integration
**Message Queue Debug Logging**:
```c
XLOGD_DEBUG("msgq %d size %d msg %p", msgq, msg_len, msg);
```

**Debug Configuration Options**:
- **Per-Protocol Debug Control**: Independent debug settings for each protocol
- **Runtime Debug Toggle**: Enable/disable debugging without restart
- **Detailed Message Tracing**: Comprehensive message queue activity logging
- **Performance Impact Minimal**: Efficient debug logging with low overhead

### Development Configuration
**JSON Configuration for Debug Features**:
```json
{
   "http": {
      "debug": false
   },
   "ws": {
      "debug": true,
      // Protocol-specific debug settings
   }
}
```

## Retry and Failover Mechanisms

### Advanced Retry Logic
All protocols implement sophisticated retry mechanisms:

**SDT Retry Configuration**:
```c
#define XRSR_SDT_WRITE_PENDING_RETRY_MAX (5)  // Maximum retry attempts

typedef struct {
   uint32_t         retry_cnt;           ///< Current retry count
   rdkx_timestamp_t retry_timestamp_end; ///< Retry timeout timestamp
} xrsr_state_sdt_t;
```

**Retry Features**:
- **Configurable Retry Limits**: Adjustable maximum retry attempts
- **Exponential Backoff**: Progressive delay between retry attempts
- **Timeout-Based Retry**: Time-bounded retry logic with timestamps
- **Context-Aware Retry**: Different retry strategies per protocol

### IPv4 Fallback Mechanism
Automatic IPv6-to-IPv4 fallback for improved connectivity:

```c
typedef struct {
   bool ipv4_fallback;  ///< Enable IPv4 fallback
} xrsr_protocol_params_sdt_t;
```

**Fallback Configuration (JSON)**:
```json
{
   "ws": {
      "fpm": {
         "ipv4_fallback": true,
         "backoff_delay": 50
      },
      "lpm": {
         "ipv4_fallback": true,
         "backoff_delay": 100
      }
   }
}
```

**Fallback Features**:
- **Automatic Detection**: IPv6 connection failure triggers IPv4 attempt
- **Power Mode Aware**: Different fallback strategies for FPM/LPM modes
- **Configurable Delays**: Adjustable backoff delays between attempts
- **Transparent Operation**: Fallback hidden from application layer

### Connection Recovery
**Multi-Layer Error Recovery**:
- **Protocol-Level Recovery**: HTTP/WebSocket/SDT specific recovery
- **Library-Level Recovery**: curl/noPoll library error handling
- **Network-Level Recovery**: TCP connection recovery and reconnection
- **Application-Level Recovery**: Session-aware recovery mechanisms

## Power Mode Adaptive Configuration

### FPM (Full Power Mode) Configuration
Optimized settings for maximum performance:

```json
"fpm": {
   "connect_check_interval": 50,    // 50ms connection monitoring
   "timeout_connect": 2000,         // 2-second connection timeout
   "timeout_inactivity": 10000,     // 10-second inactivity timeout
   "timeout_session": 5000,         // 5-second session timeout
   "ipv4_fallback": true,
   "backoff_delay": 50
}
```

### LPM (Low Power Mode) Configuration
Power-optimized settings with extended timeouts:

```json
"lpm": {
   "connect_check_interval": 50,    // Maintained monitoring frequency
   "timeout_connect": 10000,        // Extended 10-second connection timeout
   "timeout_inactivity": 10000,     // Maintained inactivity timeout
   "timeout_session": 10000,        // Extended 10-second session timeout
   "ipv4_fallback": true,
   "backoff_delay": 100             // Slower backoff for power conservation
}
```

**Power Mode Features**:
- **Adaptive Timeouts**: Different timeout strategies per power mode
- **Connection Strategy**: Balanced performance vs. power consumption
- **Monitoring Frequency**: Consistent monitoring with adaptive response
- **Recovery Timing**: Power-aware error recovery timing

## Security and Authentication Features

### SAT Token Authentication
Comprehensive security token support across all protocols:

```c
#define XRSR_SAT_TOKEN_LEN_MAX (5120)  // Maximum SAT token length

// Protocol configuration with SAT token
typedef struct {
   const char *sat_token;  ///< Security Authentication Token
} xrsr_session_config_http_t;
```

**Authentication Features**:
- **Large Token Support**: Up to 5KB authentication tokens
- **Multi-Protocol Support**: SAT tokens supported across HTTP/WS/SDT
- **Runtime Token Updates**: Dynamic token refresh capabilities
- **Secure Token Handling**: PII masking in logs for security

### HTTP User Agent Configuration
Customizable user agent strings for HTTP protocol:

```c
#define XRSR_USER_AGENT_LEN_MAX (256)  // Maximum user agent length

typedef struct {
   const char *user_agent;  ///< Custom user agent string
} xrsr_session_config_http_t;
```

**User Agent Features**:
- **Custom Identification**: Configurable client identification
- **Protocol Compliance**: Standard HTTP user agent handling
- **Device Fingerprinting**: Device-specific user agent configuration
- **Service Differentiation**: Different user agents per service endpoint

### PII (Personally Identifiable Information) Protection
Built-in privacy protection mechanisms:

```c
// PII masking in debug logs
XLOGD_INFO("url <%s>", xrsr_mask_pii() ? "***" : sdt->url);
```

**Privacy Features**:
- **Automatic PII Masking**: URLs and sensitive data masked in logs
- **Configurable Privacy**: Runtime control of PII logging
- **Security Compliance**: Built-in privacy protection mechanisms
- **Debug vs. Production**: Different privacy levels for different builds

## Quality of Service (QoS) Features

### Timeout Management
Comprehensive timeout configuration for different scenarios:

**Connection Timeouts**:
- **timeout_connect**: Network connection establishment timeout
- **timeout_inactivity**: Idle connection timeout
- **timeout_session**: Maximum session duration timeout

**Adaptive Timeout Strategy**:
```c
typedef struct {
   uint32_t timeout_connect;     ///< Connection timeout (milliseconds)
   uint32_t timeout_inactivity; ///< Inactivity timeout (milliseconds)  
   uint32_t timeout_session;    ///< Session timeout (milliseconds)
} xrsr_protocol_params_sdt_t;
```

### Connection Management
**Multi-Connection Support**:
- **Connection Pooling**: Efficient connection reuse
- **Concurrent Sessions**: Multiple simultaneous voice sessions
- **Load Distribution**: Balanced load across multiple connections
- **Resource Arbitration**: Fair resource allocation between sessions

### Resource Priority Management
Integration with XRAudio resource management:

```c
// XRAudio resource request with priority
xraudio_result_t result = xraudio_resource_request(obj->xraudio_obj, 
                                                  obj->device_input, 
                                                  obj->device_output, 
                                                  XRAUDIO_RESOURCE_PRIORITY_LOW, 
                                                  xrsr_xraudio_resource_notification, 
                                                  NULL);
```

**Priority Features**:
- **Resource Priority Levels**: Low/Medium/High priority resource requests
- **Dynamic Priority Adjustment**: Runtime priority modification
- **Resource Arbitration**: Fair resource allocation between components
- **Preemption Support**: Higher priority sessions can preempt lower priority

## Advanced Protocol Extensions

### HTTP Protocol Extensions
**Advanced HTTP Features**:
- **Custom Headers**: Configurable HTTP headers for service integration
- **Query String Parameters**: Dynamic URL parameter configuration
- **Chunked Transfer**: Efficient streaming data transfer
- **libcurl Integration**: Full libcurl feature set availability

### WebSocket Protocol Extensions
**Advanced WebSocket Features**:
- **noPoll Library Integration**: Full WebSocket protocol support
- **SSL/TLS Support**: Secure WebSocket connections (WSS)
- **Custom Headers**: WebSocket handshake header customization
- **Connection Options**: Advanced noPoll connection configuration

### SDT Protocol Framework
**Extensible SDT Protocol**:
- **Plugin Architecture**: Extensible protocol implementation
- **Stub Framework**: Ready for custom protocol implementations
- **State Machine Integration**: Full protocol state management
- **Custom Message Types**: Extensible message type system

## Performance Monitoring and Profiling

### Connection Performance Metrics
**Timing Analysis**:
- **DNS Resolution Time**: `time_dns` field in session statistics
- **Connection Establishment Time**: `time_connect` field tracking
- **End-to-End Latency**: Complete session performance measurement
- **Throughput Analysis**: Data transfer rate monitoring

### Audio Pipeline Performance
**Real-Time Audio Metrics**:
- **Sample Processing Rate**: Samples processed per second
- **Buffer Utilization**: Peak and average buffer usage
- **Codec Performance**: Encoder/decoder performance metrics
- **Latency Tracking**: Audio pipeline latency measurement

### System Resource Monitoring
**Resource Usage Tracking**:
- **Memory Utilization**: Dynamic memory allocation tracking
- **CPU Usage**: Processing load monitoring
- **Network Utilization**: Bandwidth usage analysis
- **Thread Performance**: Threading efficiency metrics

## Production Deployment Features

### Configuration Flexibility
**Runtime Configuration Management**:
- **JSON Configuration**: Human-readable configuration files
- **Environment-Specific Settings**: Development vs. production configurations
- **Hot Configuration Reload**: Runtime configuration updates
- **Validation and Sanitization**: Built-in configuration validation

### Error Recovery and Resilience
**Production-Ready Error Handling**:
- **Graceful Degradation**: Continued operation with reduced functionality
- **Automatic Recovery**: Self-healing capabilities for transient errors
- **Circuit Breaker Pattern**: Protection against cascading failures
- **Health Check Integration**: System health monitoring capabilities

### Logging and Diagnostics
**Production Logging Features**:
- **Structured Logging**: Machine-readable log formats
- **Log Level Control**: Runtime log level adjustment
- **Performance Logging**: Minimal overhead production logging
- **Error Correlation**: Unique session IDs for error tracking

The advanced features of XRSR provide a comprehensive foundation for deploying voice recognition capabilities in production XR environments, with sophisticated performance optimization, monitoring, security, and reliability features that ensure robust operation across diverse network conditions and device capabilities.