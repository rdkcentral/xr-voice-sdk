# XR Voice SDK - Threading Model and Synchronization Mechanisms

## Overview

The XR Voice SDK implements a sophisticated multi-threaded architecture designed for real-time audio processing and voice interaction. The threading model emphasizes performance, reliability, and thread-safety while maintaining low-latency processing requirements critical for voice applications.

## Threading Architecture Principles

### Design Philosophy
1. **Real-Time Performance** - High-priority threads for audio processing with minimal latency
2. **Component Isolation** - Thread boundaries align with component boundaries  
3. **Lock-Free Optimization** - Atomic operations for critical paths to avoid blocking
4. **Health Monitoring** - Thread responsiveness monitoring and deadlock detection
5. **Resource Management** - Clean thread lifecycle management with proper cleanup

### Thread Safety Strategy
- **Atomic Operations** - Hardware-assisted atomic operations for critical data structures
- **Message Passing** - Inter-component communication through message queues
- **Thread Polling** - Health monitoring system for thread responsiveness
- **Synchronization Primitives** - Semaphores, mutexes for coordination where needed

## Core Threading Components

### 1. Atomic Operations Framework (xraudio_atomic)

#### Hardware Atomic Support
```c
// Modern compiler atomic operations (GCC 4.9+)
#ifdef USE_ATOMIC
#include <stdatomic.h>
typedef atomic_int xraudio_atomic_int_t;

int xraudio_atomic_int_get(xraudio_atomic_int_t *atomic) {
    return atomic_load(atomic);
}

void xraudio_atomic_int_set(xraudio_atomic_int_t *atomic, int new_val) {
    return atomic_store(atomic, new_val);
}

bool xraudio_atomic_compare_and_set(xraudio_atomic_int_t *atomic, 
                                   int old_val, int new_val) {
    return atomic_compare_exchange_strong(atomic, &old_val, new_val);
}
#endif
```

#### Fallback pthread Implementation
```c
// Fallback for systems without atomic support
#ifndef USE_ATOMIC
typedef volatile int xraudio_atomic_int_t;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

int xraudio_atomic_int_get(xraudio_atomic_int_t *atomic) {
    int ret;
    pthread_mutex_lock(&g_mutex);
    ret = *atomic;
    pthread_mutex_unlock(&g_mutex);
    return ret;
}

// Similar pattern for set and compare_and_set operations
#endif
```

**Architecture Benefits:**
- **Performance**: Lock-free operations on supported hardware
- **Portability**: Graceful fallback to mutex-based implementation
- **Consistency**: Uniform interface regardless of underlying mechanism

### 2. Thread Health Monitoring System

#### SDK-Level Thread Polling
```c
typedef void (*vsdk_thread_poll_func_t)(void *data);

void vsdk_thread_poll(vsdk_thread_poll_func_t func, void *data) {
    g_vsdk.func = func;
    g_vsdk.data = data;
    
    // Check speech router thread
    xrsr_thread_poll(vsdk_thread_response);
}

void vsdk_thread_response(void) {
    // Audio system thread polling
    if(g_vsdk.hal_plugin && g_vsdk.hal_plugin->thread_poll) {
        g_vsdk.hal_plugin->thread_poll();
    }
    
    // Invoke callback if all threads responsive
    if(g_vsdk.func != NULL) {
        (*g_vsdk.func)(g_vsdk.data);
    }
}
```

#### Component Thread Polling
```c
// Speech router thread health checking
typedef void (*xrsr_thread_poll_func_t)(void);

void xrsr_thread_poll(xrsr_thread_poll_func_t func) {
    // Send thread poll message to speech router thread
    // Callback executed in speech router thread context
}
```

**Monitoring Capabilities:**
- **Thread Responsiveness**: Detect hung or blocked threads
- **Deadlock Detection**: Identify threading issues early
- **Health Callbacks**: Application notification of thread health status
- **Component Coordination**: Cross-component thread health verification

## Component-Specific Threading Models

### 1. Audio Processing Threading (xr-audio)

#### Audio Thread Architecture
The audio subsystem implements dedicated high-priority threads for real-time processing:

**Input Processing Thread:**
- **Priority**: Real-time scheduling for low-latency capture
- **Responsibilities**: Audio input capture, format conversion, buffer management
- **Synchronization**: Atomic operations for buffer pointers and state

**Output Processing Thread:**  
- **Priority**: Real-time scheduling for audio playback  
- **Responsibilities**: Audio output rendering, codec decoding, volume control
- **Synchronization**: Lock-free buffer management with atomic operations

#### Audio Buffer Management
```c
// Lock-free audio buffer operations using atomics
#define XRAUDIO_INPUT_FRAME_SAMPLE_QTY_MAX  (samples * channels)
#define XRAUDIO_INPUT_FRAME_SIZE_MAX        (XRAUDIO_INPUT_FRAME_SAMPLE_QTY_MAX * size)

// Atomic buffer pointer management
xraudio_atomic_int_t buffer_read_index;
xraudio_atomic_int_t buffer_write_index;

// Thread-safe buffer access patterns
int read_pos = xraudio_atomic_int_get(&buffer_read_index);
int write_pos = xraudio_atomic_int_get(&buffer_write_index);

// Atomic update of buffer positions
xraudio_atomic_compare_and_set(&buffer_read_index, old_pos, new_pos);
```

#### Real-Time Constraints
- **Frame Period**: 20ms audio frames (XRAUDIO_INPUT_FRAME_PERIOD)
- **Buffer Management**: Multiple buffering to prevent underruns
- **Priority Scheduling**: Real-time thread priorities for audio threads
- **Interrupt Handling**: Minimal processing in interrupt context

### 2. Speech Router Threading (xr-speech-router)

#### Message Queue Threading
```c
// Thread communication via message queues
typedef enum {
    XRSR_QUEUE_MSG_TYPE_THREAD_POLL = 20,
    // Other message types...
} xrsr_queue_msg_type_t;

typedef struct {
    xrsr_thread_poll_func_t func;
} xrsr_queue_msg_thread_poll_t;
```

#### Protocol-Specific Threading
- **HTTP Protocol**: Dedicated thread for HTTP request/response handling  
- **WebSocket Protocol**: Event-driven thread for WebSocket communication
- **SDT Protocol**: Secure data transfer thread with encryption/decryption

#### State Machine Synchronization
- **Thread-Safe State Transitions**: Atomic state updates across protocol threads
- **Message Serialization**: Sequential message processing within protocol threads  
- **Cross-Protocol Coordination**: Message queues for protocol switching

### 3. Timer Services Threading (xr-timer)

#### Timer Thread Management
```c
typedef struct {
    uint32_t       identifier;
    uint32_t       qty_max;
    bool           single_thread;      // Single-threaded vs multi-threaded mode
    bool           thread_id_check;    // Thread ID validation in debug mode
    pthread_t      thread_id;          // Owning thread ID
    sem_t          semaphore;          // Multi-thread synchronization
    // Timer list management...
} rdkx_timer_obj_t;
```

#### Synchronization Patterns
```c
// Conditional synchronization based on threading mode
#define RDKX_TIMER_MUTEX_WAIT() \
    if(!obj->single_thread) { \
        sem_wait(&obj->semaphore); \
    } else if(obj->thread_id_check) { \
        assert(pthread_equal(obj->thread_id, pthread_self())); \
    }

#define RDKX_TIMER_MUTEX_POST() \
    if(!obj->single_thread) { \
        sem_post(&obj->semaphore); \
    }
```

**Timer Threading Modes:**
- **Single-Threaded**: All timer operations from one thread (assertion-checked)
- **Multi-Threaded**: Semaphore-protected shared timer lists
- **Thread Validation**: Debug-mode thread ID checking

## Threading Patterns and Best Practices

### 1. Lock-Free Programming Patterns

#### Atomic State Management
```c
// Example: Component state using atomic operations
typedef enum {
    COMPONENT_STATE_INACTIVE = 0,
    COMPONENT_STATE_ACTIVE   = 1,
    COMPONENT_STATE_ERROR    = 2
} component_state_t;

xraudio_atomic_int_t component_state;

// Thread-safe state transitions
bool activate_component() {
    return xraudio_atomic_compare_and_set(&component_state, 
                                         COMPONENT_STATE_INACTIVE,
                                         COMPONENT_STATE_ACTIVE);
}
```

#### Producer-Consumer Patterns
```c 
// Lock-free ring buffer using atomic indices
struct audio_ring_buffer {
    volatile int32_t *buffer;
    xraudio_atomic_int_t write_index;
    xraudio_atomic_int_t read_index;
    uint32_t size;
};

// Producer (audio input thread)
void produce_audio_frame(struct audio_ring_buffer *ring, int32_t *frame) {
    int write_pos = xraudio_atomic_int_get(&ring->write_index);
    int next_write = (write_pos + 1) % ring->size;
    
    // Check for buffer overflow
    if(next_write != xraudio_atomic_int_get(&ring->read_index)) {
        memcpy(&ring->buffer[write_pos * FRAME_SIZE], frame, FRAME_SIZE);
        xraudio_atomic_int_set(&ring->write_index, next_write);
    }
}

// Consumer (audio processing thread)  
bool consume_audio_frame(struct audio_ring_buffer *ring, int32_t *frame) {
    int read_pos = xraudio_atomic_int_get(&ring->read_index);
    
    if(read_pos != xraudio_atomic_int_get(&ring->write_index)) {
        memcpy(frame, &ring->buffer[read_pos * FRAME_SIZE], FRAME_SIZE);
        xraudio_atomic_int_set(&ring->read_index, (read_pos + 1) % ring->size);
        return true;
    }
    return false; // Buffer empty
}
```

### 2. Message-Based Communication

#### Inter-Component Messaging
- **Asynchronous Communication**: Components communicate via message queues
- **Thread Boundaries**: Messages cross thread boundaries safely
- **Priority Handling**: Critical messages prioritized over regular traffic
- **Flow Control**: Back-pressure mechanisms prevent queue overflow

#### Message Processing Patterns
```c  
// Typical message processing loop
void component_thread_main(void *data) {
    component_context_t *ctx = (component_context_t*)data;
    
    while(ctx->running) {
        message_t msg;
        if(queue_receive(ctx->message_queue, &msg, TIMEOUT_MS)) {
            switch(msg.type) {
                case MSG_THREAD_POLL:
                    handle_thread_poll(&msg);
                    break;
                case MSG_AUDIO_DATA:
                    process_audio_data(&msg);
                    break;
                // Handle other message types...
            }
        }
    }
}
```

### 3. Thread Health Monitoring

#### Health Check Implementation
```c
// Component thread health monitoring
typedef struct {
    bool thread_responsive;
    rdkx_timestamp_t last_response_time;
    uint32_t missed_polls;
} thread_health_t;

void monitor_thread_health(thread_health_t *health) {
    rdkx_timestamp_t now = rdkx_timestamp_get();
    rdkx_timestamp_t elapsed = now - health->last_response_time;
    
    if(elapsed > THREAD_RESPONSE_TIMEOUT_MS) {
        health->missed_polls++;
        if(health->missed_polls > MAX_MISSED_POLLS) {
            // Thread appears hung - take recovery action
            log_error("Thread appears unresponsive - initiating recovery");
            initiate_thread_recovery();
        }
    }
}
```

## Performance Characteristics and Constraints

### Real-Time Processing Requirements

#### Audio Processing Latency
- **Target Latency**: < 10ms total processing latency
- **Frame Processing**: 20ms frames processed in < 5ms
- **Buffer Depth**: 3-4 frame buffers to prevent underruns
- **Thread Priority**: SCHED_FIFO with elevated priority for audio threads

#### Memory and CPU Constraints
```c
// Optimized for embedded systems
#define XRAUDIO_INPUT_FRAME_PERIOD          (20)    // 20ms frames
#define XRAUDIO_INPUT_MAX_SAMPLE_RATE       (48000) // Max sample rate
#define XRAUDIO_INPUT_MAX_CHANNEL_QTY       (8)     // Max audio channels

// Memory footprint calculations
#define AUDIO_BUFFER_MEMORY_KB (FRAME_SIZE * BUFFER_COUNT * CHANNEL_COUNT / 1024)
```

### Threading Performance Optimizations

#### Cache-Friendly Data Structures
- **Data Locality**: Thread-local data structures minimize cache misses
- **Memory Alignment**: Audio buffers aligned for SIMD operations  
- **Lock-Free Algorithms**: Reduce memory barriers and cache line bouncing

#### Context Switching Minimization
- **Thread Affinity**: Critical threads pinned to specific CPU cores
- **Priority Inversion Avoidance**: Careful priority assignment
- **Busy Waiting**: Short busy waits for low-latency operations

## Error Handling and Recovery

### Thread Failure Detection
1. **Watchdog Timers**: Periodic health checks with timeouts
2. **Heartbeat Monitoring**: Regular thread activity verification
3. **Deadlock Detection**: Cross-component dependency monitoring
4. **Resource Leak Monitoring**: Memory and handle usage tracking

### Recovery Mechanisms
```c
// Thread recovery procedures
typedef enum {
    RECOVERY_ACTION_RESTART_THREAD = 1,
    RECOVERY_ACTION_RESET_COMPONENT = 2,
    RECOVERY_ACTION_SYSTEM_RESTART = 3
} recovery_action_t;

void handle_thread_failure(thread_id_t failed_thread, recovery_action_t action) {
    switch(action) {
        case RECOVERY_ACTION_RESTART_THREAD:
            stop_thread(failed_thread);
            cleanup_thread_resources(failed_thread);
            restart_thread(failed_thread);
            break;
            
        case RECOVERY_ACTION_RESET_COMPONENT:
            reset_component(get_component_for_thread(failed_thread));
            break;
            
        case RECOVERY_ACTION_SYSTEM_RESTART:
            initiate_controlled_restart();
            break;
    }
}
```

## Integration Guidelines

### Application Thread Safety
```c
// Thread-safe SDK initialization
void app_main() {
    // SDK initialization (main thread only)
    if(vsdk_init(true, "/var/log/voice.log", 1024*1024) != 0) {
        exit(1);
    }
    
    // Set up health monitoring (any thread)
    vsdk_thread_poll(health_monitor_callback, &app_context);
    
    // Runtime operations (any thread)
    vsdk_log_level_set(XLOG_MODULE_ID_XRAUDIO, XLOG_LEVEL_DEBUG);
}
```

### Custom Thread Integration
```c
// Application thread coordination with SDK
void app_audio_thread_main() {
    // Set real-time scheduling
    struct sched_param param;
    param.sched_priority = AUDIO_THREAD_PRIORITY;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    
    // Main processing loop
    while(app_running) {
        // Process audio with SDK
        // Use atomic operations for shared state
        // Respect SDK threading model
    }
}
```

## Platform-Specific Threading Considerations

### Linux Threading
- **POSIX Threads**: Standard pthread library for thread management
- **Real-Time Scheduling**: SCHED_FIFO scheduling for audio threads  
- **Thread Priorities**: Elevated priorities for real-time processing
- **CPU Affinity**: Thread-to-core binding for predictable performance

### Embedded System Adaptations
- **Memory Constraints**: Reduced thread stack sizes for embedded systems
- **Priority Levels**: Careful priority assignment for resource-constrained systems
- **Power Management**: Thread suspension during low-power modes
- **Deterministic Behavior**: Predictable timing for real-time embedded applications

## Summary

The XR Voice SDK threading model provides:

- **High Performance**: Lock-free algorithms and atomic operations minimize overhead
- **Real-Time Capability**: Dedicated high-priority threads for audio processing
- **Reliability**: Comprehensive health monitoring and recovery mechanisms  
- **Scalability**: Message-based communication enables component isolation
- **Portability**: Graceful fallbacks for platforms with limited atomic support
- **Maintainability**: Clear thread boundaries aligned with component architecture
- **Safety**: Thread-safe APIs and robust synchronization primitives

This threading architecture ensures the SDK meets the demanding requirements of real-time voice processing while maintaining system stability and performance across diverse deployment scenarios.