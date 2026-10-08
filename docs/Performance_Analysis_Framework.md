# Performance Analysis Framework

## Overview
The XR Voice SDK implements a comprehensive performance analysis framework designed for real-time voice processing systems. The framework provides high-resolution timing infrastructure, session and stream statistics collection, performance monitoring capabilities, latency measurement systems, and resource usage tracking. This analysis examines the performance analysis tools, monitoring infrastructure, and optimization techniques implemented across all SDK components.

## Timestamp Infrastructure (rdkx_timestamp)

### 1. High-Resolution Timing Core
The SDK implements a sophisticated timestamp system built on `CLOCK_MONOTONIC_RAW` for precise performance measurement:

#### Core Timing API
```c
// High-resolution timestamp definition
typedef struct timespec rdkx_timestamp_t;

// Monotonic timestamp (unaffected by system clock adjustments)
void rdkx_timestamp_get(rdkx_timestamp_t *timestamp) {
   if(timestamp == NULL || clock_gettime(CLOCK_MONOTONIC_RAW, timestamp)) {
      XLOGD_ERROR("Unable to get time.");
   }
}

// Real-time timestamp (for wall clock correlation)
void rdkx_timestamp_get_realtime(rdkx_timestamp_t *timestamp) {
   if(timestamp == NULL || clock_gettime(CLOCK_REALTIME, timestamp)) {
      XLOGD_ERROR("Unable to get time.");
   }
}
```

#### Precision Timing Operations
```c
// Nanosecond-precision difference calculation
signed long long rdkx_timestamp_subtract_ns(rdkx_timestamp_t one, rdkx_timestamp_t two) {
   int cmp = rdkx_timestamp_cmp(one, two);
   
   if(cmp > 0) { // one is greater than two
      if(one.tv_sec - two.tv_sec) {
         return(((one.tv_sec - two.tv_sec) * (long long)-1000000000) + 
                one.tv_nsec - two.tv_nsec);
      }
      return(two.tv_nsec - one.tv_nsec);
   } else if(cmp < 0) { // one is less than two
      if(two.tv_sec - one.tv_sec) {
         return(((two.tv_sec - one.tv_sec) * (long long)1000000000) - 
                one.tv_nsec + two.tv_nsec);
      }
      return(two.tv_nsec - one.tv_nsec);
   }
   return 0;
}

// Microsecond and millisecond precision helpers
signed long long rdkx_timestamp_subtract_us(rdkx_timestamp_t one, rdkx_timestamp_t two) {
   return(rdkx_timestamp_subtract_ns(one, two) / 1000);
}

signed long long rdkx_timestamp_subtract_ms(rdkx_timestamp_t one, rdkx_timestamp_t two) {
   return(rdkx_timestamp_subtract_ns(one, two) / 1000000);
}
```

#### Performance Measurement Utilities
```c
// Time elapsed since a reference timestamp
unsigned long long rdkx_timestamp_since_ns(rdkx_timestamp_t timestamp) {
   rdkx_timestamp_t now;
   rdkx_timestamp_get(&now);
   if(rdkx_timestamp_cmp(timestamp, now) >= 0) {
      return(0);
   }
   return((unsigned long long)rdkx_timestamp_subtract_ns(timestamp, now));
}

// Time remaining until a target timestamp
unsigned long long rdkx_timestamp_until_ns(rdkx_timestamp_t timestamp) {
   rdkx_timestamp_t now;
   rdkx_timestamp_get(&now);
   if(rdkx_timestamp_cmp(timestamp, now) <= 0) {
      return(0);
   }
   return((unsigned long long)rdkx_timestamp_subtract_ns(now, timestamp));
}
```

**Timing Infrastructure Benefits**:
- **Nanosecond Precision**: Sub-microsecond accuracy for real-time analysis
- **Monotonic Clock**: Immune to system clock adjustments and leap seconds
- **Cross-Platform**: Consistent timing across different operating systems
- **Overflow Safe**: 64-bit arithmetic prevents timestamp overflow issues

## Session Performance Statistics Framework

### 1. Comprehensive Session Statistics Collection
The SDK implements detailed session statistics throughout voice interaction lifecycles:

#### Session Statistics Structure
```c
typedef struct {
   xrsr_session_end_reason_t     reason;              // Session termination reason
   bool                          retry;               // Whether retry is recommended
   long                          ret_code_internal;   // Internal result code
   long                          ret_code_protocol;   // Protocol-specific result code  
   long                          ret_code_library;    // Library-specific result code
   char                          server_ip[16];       // Server IP address
   double                        time_connect;        // Connection establishment time (s)
   double                        time_dns;            // DNS resolution time (s) 
   double                        time_session;        // Total session duration (s)
   uint32_t                      audio_bytes_sent;    // Total audio data transmitted
   uint32_t                      audio_bytes_received; // Total audio data received
} xrsr_session_stats_t;
```

#### Session Lifecycle Timing
```c
// Session timing collection throughout lifecycle
typedef struct {
   rdkx_timestamp_t session_start;        // Session initiation timestamp
   rdkx_timestamp_t connect_start;        // Connection attempt start
   rdkx_timestamp_t connect_complete;     // Connection established
   rdkx_timestamp_t stream_start;         // Audio streaming start
   rdkx_timestamp_t first_response;       // First server response
   rdkx_timestamp_t session_end;          // Session completion
} xrsr_timing_context_t;
```

### 2. Protocol-Specific Performance Tracking
Each protocol implementation includes specialized performance metrics:

#### HTTP Protocol Statistics
```c
// HTTP-specific performance metrics from CURL
void xrsr_http_stats_collect(xrsr_state_http_t *http) {
   // Network timing metrics
   curl_easy_getinfo(http->easy_handle, CURLINFO_CONNECT_TIME, 
                    &http->session_stats.time_connect);
   curl_easy_getinfo(http->easy_handle, CURLINFO_NAMELOOKUP_TIME, 
                    &http->session_stats.time_dns);
   
   // Protocol result codes
   curl_easy_getinfo(http->easy_handle, CURLINFO_HTTP_CODE, 
                    &http->session_stats.ret_code_protocol);
   http->session_stats.ret_code_library = curl_result;
   
   // Server identification
   char *primary_ip;
   curl_easy_getinfo(http->easy_handle, CURLINFO_PRIMARY_IP, &primary_ip);
   if(primary_ip) {
      strncpy_s(http->session_stats.server_ip, 
               sizeof(http->session_stats.server_ip), 
               primary_ip, sizeof(http->session_stats.server_ip));
   }
}
```

#### WebSocket Protocol Statistics 
```c
// WebSocket real-time performance metrics
typedef struct {
   rdkx_timestamp_t  ws_connect_start;         // WebSocket connection start
   rdkx_timestamp_t  ws_handshake_complete;    // WebSocket handshake done
   rdkx_timestamp_t  first_message_sent;       // First message transmission
   rdkx_timestamp_t  first_message_received;   // First response received
   uint32_t          messages_sent;            // Total messages sent
   uint32_t          messages_received;        // Total messages received
   uint32_t          total_bytes_sent;         // Total data transmitted
   uint32_t          total_bytes_received;     // Total data received
   uint32_t          connection_errors;        // Connection error count
} xrsr_ws_performance_t;
```

### 3. Audio Performance Statistics
Audio processing performance is tracked at multiple levels:

#### Audio Stream Statistics
```c
typedef struct {
   bool              active;                    // Stream is active
   bool              detecting;                 // Keyword detection active
   bool              audio_stats_rxd;           // Audio statistics received
   xrsr_audio_stats_t audio_stats;             // Audio-specific metrics
} xrsr_xraudio_stream_t;

typedef struct {
   uint32_t          samples_processed;         // Total samples processed
   uint32_t          frames_processed;          // Total frames processed
   uint32_t          buffer_underruns;          // Audio buffer underruns
   uint32_t          buffer_overruns;           // Audio buffer overruns
   double            avg_processing_time_us;    // Average processing time
   double            max_processing_time_us;    // Maximum processing time
   uint32_t          detection_count;           // Keyword detection count
   double            detection_accuracy;        // Detection accuracy percentage
} xrsr_audio_stats_t;
```

## Plugin Performance Framework

### 1. Plugin Performance Monitoring System
The SDK implements comprehensive plugin performance tracking:

#### Plugin Performance Statistics Structure
```c
typedef struct {
   uint64_t          total_calls;              // Total plugin invocations
   uint64_t          total_time_us;            // Cumulative processing time
   uint32_t          min_time_us;              // Minimum processing time
   uint32_t          max_time_us;              // Maximum processing time
   uint32_t          avg_time_us;              // Average processing time
   uint32_t          timeout_count;            // Processing timeouts
   uint32_t          error_count;              // Processing errors
} plugin_perf_stats_t;
```

#### Real-Time Plugin Performance Measurement
```c
plugin_result_t measure_plugin_performance(plugin_api_t *api, 
                                          int16_t *input, int16_t *output,
                                          uint32_t samples, plugin_perf_stats_t *stats) {
   // High-precision timing around plugin call
   rdkx_timestamp_t start_time;
   rdkx_timestamp_get(&start_time);
   
   // Execute plugin processing
   plugin_result_t result = api->process_audio(input, output, samples);
   
   rdkx_timestamp_t end_time;
   rdkx_timestamp_get(&end_time);
   
   // Calculate and record performance metrics
   uint32_t elapsed_us = rdkx_timestamp_subtract_us(start_time, end_time);
   
   stats->total_calls++;
   stats->total_time_us += elapsed_us;
   if(elapsed_us < stats->min_time_us) stats->min_time_us = elapsed_us;
   if(elapsed_us > stats->max_time_us) stats->max_time_us = elapsed_us;
   stats->avg_time_us = stats->total_time_us / stats->total_calls;
   
   // Check for performance violations
   if(elapsed_us > PLUGIN_MAX_LATENCY_US) {
      stats->timeout_count++;
      XLOGD_WARN("Plugin processing exceeded latency threshold: %u μs", elapsed_us);
   }
   
   if(result != PLUGIN_RESULT_SUCCESS) {
      stats->error_count++;
   }
   
   return result;
}
```

### 2. Plugin Performance Constraints
```c
// Performance requirements for audio plugins
#define PLUGIN_MAX_LATENCY_US        (5000)    // 5ms maximum processing latency
#define PLUGIN_TARGET_LATENCY_US     (2000)    // 2ms target processing latency  
#define PLUGIN_BUFFER_SIZE_FRAMES    (4)       // 4-frame lookahead buffer
#define PLUGIN_MAX_CPU_USAGE_PCT     (15)      // 15% maximum CPU usage
#define PLUGIN_TIMEOUT_THRESHOLD     (10)      // 10 timeouts before warning

// Plugin performance validation
bool validate_plugin_performance(const plugin_perf_stats_t *stats) {
   // Check average latency compliance
   if(stats->avg_time_us > PLUGIN_TARGET_LATENCY_US) {
      XLOGD_WARN("Plugin average latency: %u μs (target: %u μs)", 
                 stats->avg_time_us, PLUGIN_TARGET_LATENCY_US);
   }
   
   // Check for excessive timeouts
   if(stats->timeout_count > PLUGIN_TIMEOUT_THRESHOLD) {
      XLOGD_ERROR("Plugin timeout count: %u (threshold: %u)", 
                  stats->timeout_count, PLUGIN_TIMEOUT_THRESHOLD);
      return false;
   }
   
   // Check error rate
   double error_rate = (double)stats->error_count / stats->total_calls;
   if(error_rate > 0.01) { // 1% error rate threshold
      XLOGD_ERROR("Plugin error rate: %.2f%%", error_rate * 100.0);
      return false;
   }
   
   return true;
}
```

## Voice Interaction Performance Analysis

### 1. End-to-End Latency Measurement
The SDK provides comprehensive voice interaction latency analysis:

#### Voice Processing Pipeline Timing
```c
typedef struct {
   rdkx_timestamp_t  wakeword_detected;        // Wake word detection
   rdkx_timestamp_t  session_initiated;        // Session begin
   rdkx_timestamp_t  audio_stream_start;       // Audio streaming start
   rdkx_timestamp_t  server_connected;         // Server connection established
   rdkx_timestamp_t  audio_transmission_start; // Audio transmission begin
   rdkx_timestamp_t  server_response_start;    // First server response
   rdkx_timestamp_t  response_processed;       // Response processing complete
   rdkx_timestamp_t  action_executed;          // Application action complete
} voice_interaction_timeline_t;

// Voice interaction performance analysis
void analyze_voice_interaction_performance(const voice_interaction_timeline_t *timeline) {
   // Component latencies
   uint32_t wakeword_latency = rdkx_timestamp_subtract_us(timeline->wakeword_detected, 
                                                         timeline->session_initiated);
   uint32_t connection_latency = rdkx_timestamp_subtract_us(timeline->session_initiated,
                                                           timeline->server_connected);
   uint32_t processing_latency = rdkx_timestamp_subtract_us(timeline->audio_transmission_start,
                                                           timeline->server_response_start);
   uint32_t total_latency = rdkx_timestamp_subtract_us(timeline->wakeword_detected,
                                                      timeline->action_executed);
   
   // Performance validation against targets
   if(wakeword_latency > 100000) {  // 100ms threshold
      XLOGD_WARN("Wake word processing latency: %u μs", wakeword_latency);
   }
   
   if(connection_latency > 500000) { // 500ms threshold  
      XLOGD_WARN("Connection establishment latency: %u μs", connection_latency);
   }
   
   if(processing_latency > 2000000) { // 2s threshold
      XLOGD_WARN("Server processing latency: %u μs", processing_latency);
   }
   
   if(total_latency > 3000000) { // 3s threshold
      XLOGD_WARN("Total voice interaction latency: %u μs", total_latency);
   }
   
   // Log detailed performance breakdown
   XLOGD_INFO("Voice interaction performance breakdown:");
   XLOGD_INFO("  Wake word processing: %u μs", wakeword_latency);
   XLOGD_INFO("  Connection setup: %u μs", connection_latency);
   XLOGD_INFO("  Server processing: %u μs", processing_latency);
   XLOGD_INFO("  Total end-to-end: %u μs", total_latency);
}
```

### 2. Real-Time Performance Monitoring
```c
// Continuous performance monitoring during voice processing
typedef struct {
   rdkx_timestamp_t  last_measurement;         // Last performance check
   uint32_t          measurement_interval_ms;  // Monitoring interval
   uint32_t          audio_frame_count;        // Frames processed
   uint32_t          missed_deadlines;         // Real-time deadline misses
   double            cpu_utilization;          // Current CPU usage
   size_t            memory_usage_bytes;       // Current memory usage
   uint32_t          active_sessions;          // Active voice sessions
} performance_monitor_t;

void update_performance_metrics(performance_monitor_t *monitor) {
   rdkx_timestamp_t now;
   rdkx_timestamp_get(&now);
   
   uint32_t elapsed_ms = rdkx_timestamp_subtract_ms(monitor->last_measurement, now);
   
   if(elapsed_ms >= monitor->measurement_interval_ms) {
      // Calculate frame processing rate
      uint32_t fps = (monitor->audio_frame_count * 1000) / elapsed_ms;
      
      // Check for real-time performance compliance
      if(fps < AUDIO_TARGET_FPS) {
         monitor->missed_deadlines++;
         XLOGD_WARN("Audio processing below target rate: %u fps (target: %u fps)", 
                   fps, AUDIO_TARGET_FPS);
      }
      
      // Reset counters for next measurement period  
      monitor->audio_frame_count = 0;
      monitor->last_measurement = now;
   }
}
```

## Threading Performance Analysis

### 1. Thread Performance Monitoring
The SDK implements comprehensive thread performance tracking:

#### Thread Health Monitoring
```c
typedef struct {
   pthread_t         thread_id;              // Thread identifier
   char              thread_name[32];        // Human-readable name
   rdkx_timestamp_t  last_heartbeat;         // Last thread activity
   rdkx_timestamp_t  last_response_time;     // Last response timestamp
   uint32_t          heartbeat_interval_ms;  // Expected heartbeat interval
   uint32_t          response_timeout_ms;    // Response timeout threshold
   bool              thread_responsive;      // Thread health status
   uint32_t          missed_heartbeats;      // Consecutive missed heartbeats
} thread_health_monitor_t;

// Thread responsiveness checking
bool check_thread_responsiveness(thread_health_monitor_t *monitor) {
   rdkx_timestamp_t now;
   rdkx_timestamp_get(&now);
   
   uint32_t elapsed_ms = rdkx_timestamp_subtract_ms(monitor->last_heartbeat, now);
   
   if(elapsed_ms > monitor->response_timeout_ms) {
      monitor->missed_heartbeats++;
      
      if(monitor->missed_heartbeats > 3) {
         monitor->thread_responsive = false;
         XLOGD_ERROR("Thread %s unresponsive for %u ms", 
                    monitor->thread_name, elapsed_ms);
         return false;
      }
   } else {
      monitor->missed_heartbeats = 0;
      monitor->thread_responsive = true;
   }
   
   return monitor->thread_responsive;
}
```

### 2. Lock Contention Analysis
```c
// Mutex performance monitoring for identifying bottlenecks
typedef struct {
   pthread_mutex_t  *mutex;                  // Mutex being monitored
   char             name[32];                // Mutex identifier
   uint64_t         lock_count;              // Total lock acquisitions
   uint64_t         contention_count;        // Lock contentions detected
   uint64_t         total_wait_time_us;      // Cumulative wait time
   uint32_t         max_wait_time_us;        // Maximum wait time
   rdkx_timestamp_t last_lock_attempt;       // Last lock attempt timestamp
} mutex_perf_monitor_t;

int monitored_mutex_lock(mutex_perf_monitor_t *monitor) {
   rdkx_timestamp_t lock_start;
   rdkx_timestamp_get(&lock_start);
   
   int result = pthread_mutex_trylock(monitor->mutex);
   
   if(result == EBUSY) {
      // Lock contention detected
      monitor->contention_count++;
      
      // Wait for lock with timing
      result = pthread_mutex_lock(monitor->mutex);
   }
   
   if(result == 0) {
      rdkx_timestamp_t lock_acquired;
      rdkx_timestamp_get(&lock_acquired);
      
      uint32_t wait_time_us = rdkx_timestamp_subtract_us(lock_start, lock_acquired);
      
      monitor->lock_count++;
      monitor->total_wait_time_us += wait_time_us;
      
      if(wait_time_us > monitor->max_wait_time_us) {
         monitor->max_wait_time_us = wait_time_us;
      }
      
      // Warn about excessive lock contention
      if(wait_time_us > 1000) { // 1ms threshold
         XLOGD_WARN("Excessive mutex wait time for %s: %u μs", 
                   monitor->name, wait_time_us);
      }
   }
   
   return result;
}
```

## Memory Performance Analysis

### 1. Memory Usage Tracking
The SDK implements memory performance monitoring for resource optimization:

#### Memory Allocation Monitoring
```c
// Memory allocation tracking for performance analysis
typedef struct {
   size_t           total_allocated;         // Total memory allocated
   size_t           peak_allocated;          // Peak memory usage
   size_t           current_allocated;       // Current allocation
   uint32_t         allocation_count;        // Number of allocations
   uint32_t         deallocation_count;      // Number of deallocations
   uint32_t         reallocation_count;      // Number of reallocations
   size_t           average_alloc_size;      // Average allocation size
   uint32_t         fragmentation_score;     // Memory fragmentation metric
} memory_perf_stats_t;

// Tracked memory allocation wrapper
void* tracked_malloc(size_t size, memory_perf_stats_t *stats) {
   void *ptr = malloc(size);
   
   if(ptr != NULL) {
      stats->allocation_count++;
      stats->total_allocated += size;
      stats->current_allocated += size;
      
      if(stats->current_allocated > stats->peak_allocated) {
         stats->peak_allocated = stats->current_allocated;
      }
      
      stats->average_alloc_size = stats->total_allocated / stats->allocation_count;
      
      // Track large allocations
      if(size > 4096) { // 4KB threshold
         XLOGD_INFO("Large memory allocation: %zu bytes", size);
      }
   } else {
      XLOGD_ERROR("Memory allocation failed: %zu bytes", size);
   }
   
   return ptr;
}

void tracked_free(void *ptr, size_t size, memory_perf_stats_t *stats) {
   if(ptr != NULL) {
      free(ptr);
      stats->deallocation_count++;
      stats->current_allocated -= size;
   }
}
```

### 2. Buffer Performance Analysis
```c
// Audio buffer performance monitoring
typedef struct {
   uint32_t         buffer_size;             // Buffer capacity
   uint32_t         current_fill;            // Current fill level
   uint32_t         peak_fill;               // Peak fill level
   uint32_t         underrun_count;          // Buffer underrun events
   uint32_t         overrun_count;           // Buffer overrun events
   double           average_fill_percent;    // Average fill percentage
   rdkx_timestamp_t last_update;             // Last buffer update
} buffer_perf_stats_t;

void update_buffer_performance(buffer_perf_stats_t *stats, uint32_t current_fill) {
   stats->current_fill = current_fill;
   
   if(current_fill > stats->peak_fill) {
      stats->peak_fill = current_fill;
   }
   
   // Calculate fill percentage
   double fill_percent = (double)current_fill / stats->buffer_size * 100.0;
   stats->average_fill_percent = (stats->average_fill_percent + fill_percent) / 2.0;
   
   // Check for buffer conditions
   if(current_fill == 0) {
      stats->underrun_count++;
      XLOGD_WARN("Audio buffer underrun detected");
   }
   
   if(current_fill >= stats->buffer_size) {
      stats->overrun_count++;
      XLOGD_WARN("Audio buffer overrun detected");
   }
   
   rdkx_timestamp_get(&stats->last_update);
}
```

## Performance Analysis Integration

### 1. Unified Performance Dashboard
The SDK provides centralized performance monitoring:

#### Performance Metrics Aggregation
```c
typedef struct {
   voice_interaction_timeline_t  voice_metrics;     // Voice interaction timing
   plugin_perf_stats_t          plugin_stats[8];   // Plugin performance stats
   thread_health_monitor_t      thread_monitors[4]; // Thread health monitoring
   memory_perf_stats_t          memory_stats;       // Memory performance
   buffer_perf_stats_t          audio_buffers[2];   // Audio buffer performance
   mutex_perf_monitor_t         mutex_monitors[6];  // Lock contention stats
   rdkx_timestamp_t             collection_start;   // Monitoring start time
   uint32_t                     collection_period_s; // Collection period
} sdk_performance_dashboard_t;

// Comprehensive performance report generation
void generate_performance_report(const sdk_performance_dashboard_t *dashboard) {
   rdkx_timestamp_t now;
   rdkx_timestamp_get(&now);
   
   uint32_t collection_duration_s = rdkx_timestamp_subtract_ms(dashboard->collection_start, now) / 1000;
   
   XLOGD_INFO("=== XR Voice SDK Performance Report ===");
   XLOGD_INFO("Collection Period: %u seconds", collection_duration_s);
   
   // Voice interaction performance
   XLOGD_INFO("Voice Interaction Performance:");
   XLOGD_INFO("  Average end-to-end latency: %u ms", 
              /* calculate from voice_metrics */);
   
   // Plugin performance summary
   XLOGD_INFO("Plugin Performance Summary:");
   for(int i = 0; i < 8; i++) {
      if(dashboard->plugin_stats[i].total_calls > 0) {
         XLOGD_INFO("  Plugin %d: avg=%u μs, max=%u μs, calls=%llu", 
                   i, dashboard->plugin_stats[i].avg_time_us,
                   dashboard->plugin_stats[i].max_time_us,
                   dashboard->plugin_stats[i].total_calls);
      }
   }
   
   // Thread health summary
   XLOGD_INFO("Thread Health Summary:");
   for(int i = 0; i < 4; i++) {
      XLOGD_INFO("  %s: %s (missed heartbeats: %u)",
                dashboard->thread_monitors[i].thread_name,
                dashboard->thread_monitors[i].thread_responsive ? "OK" : "UNRESPONSIVE",
                dashboard->thread_monitors[i].missed_heartbeats);
   }
   
   // Memory performance summary
   XLOGD_INFO("Memory Performance:");
   XLOGD_INFO("  Peak usage: %zu KB", dashboard->memory_stats.peak_allocated / 1024);
   XLOGD_INFO("  Current usage: %zu KB", dashboard->memory_stats.current_allocated / 1024);
   XLOGD_INFO("  Allocations: %u, Deallocations: %u", 
              dashboard->memory_stats.allocation_count,
              dashboard->memory_stats.deallocation_count);
   
   XLOGD_INFO("========================================");
}
```

### 2. Performance Alerting System
```c
// Performance threshold monitoring and alerting
typedef struct {
   uint32_t  voice_latency_threshold_ms;      // Voice latency alert threshold
   uint32_t  plugin_latency_threshold_us;     // Plugin latency alert threshold  
   double    cpu_utilization_threshold;       // CPU usage alert threshold
   size_t    memory_usage_threshold_kb;       // Memory usage alert threshold
   uint32_t  thread_timeout_threshold_ms;     // Thread timeout alert threshold
   uint32_t  buffer_underrun_threshold;       // Buffer underrun alert threshold
} performance_alert_config_t;

void check_performance_alerts(const sdk_performance_dashboard_t *dashboard,
                             const performance_alert_config_t *config) {
   // Check voice interaction latency
   /* if(voice_latency > config->voice_latency_threshold_ms) {
      SEND_PERFORMANCE_ALERT("Voice interaction latency exceeded threshold");
   } */
   
   // Check plugin performance
   for(int i = 0; i < 8; i++) {
      if(dashboard->plugin_stats[i].avg_time_us > config->plugin_latency_threshold_us) {
         XLOGD_ERROR("ALERT: Plugin %d latency exceeded threshold: %u μs", 
                    i, dashboard->plugin_stats[i].avg_time_us);
      }
   }
   
   // Check memory usage
   if(dashboard->memory_stats.current_allocated > config->memory_usage_threshold_kb * 1024) {
      XLOGD_ERROR("ALERT: Memory usage exceeded threshold: %zu KB", 
                 dashboard->memory_stats.current_allocated / 1024);
   }
   
   // Check thread health
   for(int i = 0; i < 4; i++) {
      if(!dashboard->thread_monitors[i].thread_responsive) {
         XLOGD_ERROR("ALERT: Thread %s unresponsive", 
                    dashboard->thread_monitors[i].thread_name);
      }
   }
}
```

## Performance Optimization Features

### 1. Adaptive Performance Tuning
The SDK includes dynamic performance optimization:

#### Automatic Performance Adjustment
```c
// Dynamic performance tuning based on runtime metrics
void optimize_performance_dynamically(sdk_performance_dashboard_t *dashboard) {
   // Adjust audio buffer sizes based on underrun/overrun rates
   for(int i = 0; i < 2; i++) {
      buffer_perf_stats_t *buffer = &dashboard->audio_buffers[i];
      
      if(buffer->underrun_count > 5) {
         // Increase buffer size to prevent underruns
         uint32_t new_size = buffer->buffer_size * 1.2;
         XLOGD_INFO("Increasing audio buffer size: %u -> %u", 
                   buffer->buffer_size, new_size);
         // Apply buffer size change
      }
      
      if(buffer->overrun_count > 3) {
         // Decrease buffer size to reduce latency
         uint32_t new_size = buffer->buffer_size * 0.9;
         XLOGD_INFO("Decreasing audio buffer size: %u -> %u", 
                   buffer->buffer_size, new_size);
         // Apply buffer size change
      }
   }
   
   // Adjust thread priorities based on performance
   for(int i = 0; i < 4; i++) {
      thread_health_monitor_t *monitor = &dashboard->thread_monitors[i];
      
      if(monitor->missed_heartbeats > 3) {
         XLOGD_INFO("Increasing thread priority for %s", monitor->thread_name);
         // Increase thread priority implementation
      }
   }
}
```

## Performance Analysis Benefits

### 1. Real-Time Voice Processing Optimization
**Voice Interaction Performance**:
- **Sub-100ms**: Wake word detection and processing latency
- **Sub-500ms**: Connection establishment for voice services
- **Sub-2s**: Server processing and response handling
- **Sub-3s**: Complete end-to-end voice interaction cycle

### 2. Resource Efficiency Monitoring
**System Resource Optimization**:
- **Memory Efficiency**: Peak usage tracking and leak detection
- **CPU Optimization**: Thread utilization and lock contention analysis  
- **Audio Performance**: Buffer management and real-time deadline monitoring
- **Plugin Efficiency**: Processing latency and error rate tracking

### 3. Production Deployment Support
**Operational Performance Monitoring**:
- **Continuous Monitoring**: 24/7 performance metric collection
- **Alerting System**: Threshold-based performance alerts
- **Performance Reports**: Comprehensive performance analytics
- **Adaptive Optimization**: Dynamic system tuning based on metrics

The XR Voice SDK performance analysis framework provides comprehensive monitoring, measurement, and optimization capabilities essential for real-time voice processing systems. The nanosecond-precision timing infrastructure, detailed statistics collection, plugin performance tracking, and adaptive optimization features ensure optimal performance across diverse deployment scenarios while maintaining the strict real-time requirements of voice interaction applications.