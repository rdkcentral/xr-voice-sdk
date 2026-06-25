# XR Audio Threading Model and Synchronization Documentation

## Overview
The XR Audio component implements a sophisticated multi-threaded architecture designed for real-time audio processing with deterministic latency guarantees. The threading model combines dedicated processing threads, message-based communication, and multiple synchronization primitives to ensure thread-safe operation while meeting strict timing requirements.

## Threading Architecture

### Primary Thread Design
The system employs a multi-threaded architecture with specialized thread roles:

1. **Main Processing Thread**: Core audio processing and state management
2. **Resource Management Thread**: Multi-process resource arbitration  
3. **First Read/Write Threads**: Latency masking for initial audio operations
4. **Application Threads**: Client application interaction via API

## Thread Structure Definition

### Core Thread Type
```c
typedef struct {
    const char *name;      // Human-readable thread name
    pthread_t   id;        // POSIX thread identifier
    bool        running;   // Thread lifecycle state
} xraudio_thread_t;
```

### Thread Creation Infrastructure
```c
bool xraudio_thread_create(xraudio_thread_t *thread, 
                           const char *name, 
                           void *(*start_routine)(void *), 
                           void *arg) {
    pthread_attr_t attr;
    pthread_attr_t *attr_param = NULL;

    // Initialize thread attributes
    if(pthread_attr_init(&attr) != 0) {
        XLOGD_WARN("pthread_attr_init failed");
    } else {
        attr_param = &attr;
    }

    // Create POSIX thread
    if(pthread_create(&thread->id, attr_param, start_routine, arg) != 0) {
        XLOGD_ERROR("unable to launch thread");
        return false;
    }

    // Set descriptive thread name for debugging
    if(name != NULL) {
        char name_max[16];
        snprintf(name_max, sizeof(name_max), "%s", name);
        if(pthread_setname_np(thread->id, name_max) != 0) {
            XLOGD_WARN("pthread_setname_np failed");
        }
    }

    thread->running = true;
    return true;
}
```

### Thread Lifecycle Management
```c
bool xraudio_thread_join(xraudio_thread_t *thread) {
    if(!thread->running) {
        return false;
    }
    
    // Wait for thread completion
    if(pthread_join(thread->id, NULL) != 0) {
        XLOGD_ERROR("pthread_join failed");
        return false;
    }
    
    thread->running = false;
    return true;
}
```

## Main Processing Thread

### Thread Launch and Synchronization
Located in [`main_thread_launch()`](../src/xr-audio/xraudio.c#L1149-L1200):

```c
xraudio_result_t main_thread_launch(xraudio_obj_t *obj) {
    if(obj->main_thread.running) {
        return XRAUDIO_RESULT_ERROR_INTERNAL;
    }

    // Synchronization semaphore for startup coordination
    sem_t semaphore;
    sem_init(&semaphore, 0, 0);

    // Thread parameter structure
    xraudio_main_thread_params_t params;
    params.msgq           = obj->msgq_main;
    params.semaphore      = &semaphore;
    params.obj_input      = obj->obj_input;
    params.eos_enabled    = obj->eos_enabled;
    params.ppr_enabled    = obj->ppr_enabled;
    params.out_enabled    = obj->out_enabled;
    params.hal_plugin     = obj->hal_plugin;
    params.kwd_plugin     = obj->kwd_plugin;
    params.dga_plugin     = obj->dga_plugin;
    
    // Launch main processing thread
    if(!xraudio_thread_create(&obj->main_thread, "xraudio_main", 
                              xraudio_main_thread, &params)) {
        return XRAUDIO_RESULT_ERROR_INTERNAL;
    }

    // Block until thread initialization completes
    sem_wait(&semaphore);
    sem_destroy(&semaphore);
    
    return XRAUDIO_RESULT_OK;
}
```

### Main Thread Function Pattern
The main processing thread follows a standardized initialization pattern:

```c
void *xraudio_main_thread(void *param) {
    // Allocate thread-local state
    xraudio_thread_state_t *state = malloc(sizeof(xraudio_thread_state_t));
    memset(state, 0, sizeof(*state));
    
    // Copy initialization parameters
    state->params = *((xraudio_main_thread_params_t *)param);
    
    // Initialize voice session global state
    if(!g_voice_session.init) {
        g_voice_session = (xraudio_session_voice_t) {
            .init              = true,
            .msgq              = state->params.msgq,
            .detecting         = 0,
            .sources_supported = XRAUDIO_DEVICE_INPUT_NONE,
            .source            = { XRAUDIO_DEVICE_INPUT_INVALID }
        };
    }
    
    // Signal parent thread that initialization is complete
    sem_post(state->params.semaphore);
    
    // Enter main event processing loop
    while(state->running) {
        // select()-based event loop with message queue monitoring
        // Process audio frames, handle control messages, manage timers
    }
    
    free(state);
    return NULL;
}
```

## Resource Management Thread

### Multi-Process Resource Arbitration
The resource management thread coordinates audio resource allocation across processes:

```c
void *xraudio_resource_thread(void *param) {
    xraudio_resource_thread_params_t thread_params = 
        *((xraudio_resource_thread_params_t *)param);
    
    xraudio_resource_params_t params;
    params.object     = thread_params.object;
    params.msgq       = thread_params.msgq;
    params.fifo       = thread_params.fifo;
    params.user_id    = thread_params.user_id;
    params.shared_mem = thread_params.shared_mem;
    
    // Signal parent thread completion
    sem_post(thread_params.semaphore);
    
    // Process resource requests and notifications
    while(params.running) {
        // Monitor message queue and FIFO for resource events
        // Arbitrate resource conflicts between processes
        // Send grant/revoke notifications
    }
    
    return NULL;
}
```

### Resource Thread Launch
```c
xraudio_result_t rsrc_thread_launch(xraudio_obj_t *obj) {
    sem_t semaphore;
    sem_init(&semaphore, 0, 0);

    xraudio_resource_thread_params_t params;
    params.object     = (xraudio_object_t)obj;
    params.msgq       = obj->msgq_resource;
    params.fifo       = obj->fifo_resource;
    params.user_id    = obj->user_id;
    params.shared_mem = obj->shared_mem;
    params.semaphore  = &semaphore;

    if(!xraudio_thread_create(&obj->rsrc_thread, "xraudio_rsrc", 
                              xraudio_resource_thread, &params)) {
        return XRAUDIO_RESULT_ERROR_INTERNAL;
    }

    // Wait for resource thread initialization
    sem_wait(&semaphore);
    sem_destroy(&semaphore);
    
    return XRAUDIO_RESULT_OK;
}
```

## First Read/Write Threads

### Latency Masking Architecture
To minimize perceived latency during audio operations, the system uses dedicated threads for the first read/write operations:

#### First Write Thread (Output Latency Masking)
```c
#ifdef MASK_FIRST_WRITE_DELAY
void *xraudio_thread_first_write(void *param) {
    xraudio_thread_first_write_params_t params = 
        *((xraudio_thread_first_write_params_t *)param);

    // Perform initial silence write to prime output buffers
    xraudio_out_write_silence(params.params, params.session, 
                              params.session->frame_size);

    // Signal completion
    params.session->first_write_pending = false;
    return NULL;
}
#endif
```

#### First Read Thread (Input Latency Masking)
```c
#ifdef MASK_FIRST_READ_DELAY
void *xraudio_thread_first_read(void *param) {
    xraudio_thread_first_read_params_t params = 
        *((xraudio_thread_first_read_params_t *)param);

    // Calculate frame size based on channel configuration
    xraudio_devices_input_t device_input_local = 
        XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input);
    xraudio_devices_input_t device_input_ecref = 
        XRAUDIO_DEVICE_INPUT_EC_REF_GET(session->devices_input);

    uint8_t chan_qty_mic = (device_input_local == XRAUDIO_DEVICE_INPUT_QUAD) ? 4 : 
                           (device_input_local == XRAUDIO_DEVICE_INPUT_TRI) ? 3 : 1;
    uint8_t chan_qty_ecref = (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_5_1) ? 6 : 
                             (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_STEREO) ? 2 : 
                             (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_MONO) ? 1 : 0;

    uint32_t mic_frame_size = (chan_qty_mic + chan_qty_ecref) * 
                              params.session->frame_size_in;

    // Perform first HAL read to prime input pipeline
    uint8_t mic_frame_data[XRAUDIO_INPUT_FRAME_SIZE_MAX];
    xraudio_hal_input_read(params.params->hal_input_obj, mic_frame_data, 
                           mic_frame_size, NULL);

    // Signal completion
    params.session->first_read_pending = false;
    return NULL;
}
#endif
```

## Synchronization Primitives

### Semaphore-Based Synchronization
The system uses POSIX semaphores for thread coordination:

#### Thread Startup Synchronization
```c
// Pattern used throughout thread creation
sem_t startup_semaphore;
sem_init(&startup_semaphore, 0, 0);  // Initialize to 0 (blocked)

// Parent thread blocks until child signals completion
sem_wait(&startup_semaphore);

// Child thread signals completion in thread function
sem_post(startup_semaphore);
```

#### API Synchronization
```c
// Per-object API mutex for thread-safe API access
typedef struct {
    sem_t mutex_api;  // API-level synchronization
    // ... other fields ...
} xraudio_obj_t;

#define XRAUDIO_API_MUTEX_LOCK()    sem_wait(&obj->mutex_api)
#define XRAUDIO_API_MUTEX_UNLOCK()  sem_post(&obj->mutex_api)

// Usage pattern in API functions
xraudio_result_t xraudio_api_function(xraudio_object_t object) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    XRAUDIO_API_MUTEX_LOCK();
    
    // Critical section - thread-safe API operation
    
    XRAUDIO_API_MUTEX_UNLOCK();
    return result;
}
```

### Message Queue Communication
Thread-safe inter-thread communication via message queues:

```c
// Thread-safe message dispatch
void queue_msg_push(xr_mq_t msgq, const char *msg, xr_mq_msg_size_t msg_len) {
    // XR message queue provides internal synchronization
    xr_mq_push(msgq, msg, msg_len);
}

// Main thread message processing loop
void process_message_queue(xraudio_thread_state_t *state) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(state->params.msgq, &rfds);
    
    // Block until message arrives or timeout
    int activity = select(nfds, &rfds, NULL, NULL, &timeout);
    
    if(FD_ISSET(state->params.msgq, &rfds)) {
        // Process messages atomically from queue
        while(message_available) {
            dispatch_message_handler(state, message);
        }
    }
}
```

### Atomic Operations for Session State
Lock-free session management using atomic compare-and-swap:

```c
// Voice session state with atomic source tracking
typedef struct {
    bool                    init;
    int                     msgq;
    int                     detecting;
    xraudio_devices_input_t sources_supported;
    xraudio_atomic_int_t    source[XRAUDIO_INPUT_SESSION_GROUP_QTY];  // Atomic session sources
} xraudio_session_voice_t;

// Lock-free session acquisition
bool xraudio_in_session_group_semaphore_lock(xraudio_devices_input_t source) {
    uint32_t group = xraudio_input_source_to_group(source);
    
    // Atomic attempt to claim session
    return xraudio_atomic_compare_and_set(&g_voice_session.source[group], 
                                          XRAUDIO_DEVICE_INPUT_NONE, source);
}

// Lock-free session release  
void xraudio_in_session_group_semaphore_unlock(xraudio_devices_input_t source) {
    uint32_t group = xraudio_input_source_to_group(source);
    xraudio_atomic_int_set(&g_voice_session.source[group], XRAUDIO_DEVICE_INPUT_NONE);
}
```

## Thread Communication Patterns

### Request-Response with Synchronous Blocking
```c
// Synchronous API call with thread coordination
xraudio_result_t xraudio_synchronous_operation(xraudio_object_t object, 
                                               operation_params_t *params) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    xraudio_result_t result = XRAUDIO_RESULT_OK;
    
    // Create synchronization semaphore
    sem_t response_semaphore;
    sem_init(&response_semaphore, 0, 0);
    
    // Prepare message for main thread
    xraudio_queue_msg_operation_t msg;
    msg.header.type = XRAUDIO_QUEUE_MSG_TYPE_OPERATION;
    msg.params      = *params;
    msg.semaphore   = &response_semaphore;
    msg.result      = &result;
    
    // Send message to main thread
    queue_msg_push(obj->msgq_main, (const char *)&msg, sizeof(msg));
    
    // Block until operation completes
    sem_wait(&response_semaphore);
    sem_destroy(&response_semaphore);
    
    return result;
}
```

### Asynchronous Event Notification
```c
// Asynchronous event notification from main thread to application
void notify_application_event(xraudio_thread_state_t *state, 
                              application_event_t event) {
    if(state->event_callback != NULL) {
        // Call application callback from main thread context
        state->event_callback(event, state->callback_param);
    }
    
    // May also send event via message queue for thread decoupling
    if(state->async_notification_enabled) {
        queue_async_event_notification(state->application_msgq, event);
    }
}
```

## Thread Priority and Affinity

### Real-Time Thread Configuration
```c
// Configure thread for real-time audio processing
void configure_realtime_thread(pthread_t thread_id) {
    // Set real-time scheduling policy
    struct sched_param param;
    param.sched_priority = XRAUDIO_REALTIME_PRIORITY;
    
    if(pthread_setschedparam(thread_id, SCHED_FIFO, &param) != 0) {
        XLOGD_WARN("Failed to set real-time priority");
    }
    
    // Set CPU affinity for consistent performance
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(XRAUDIO_PREFERRED_CPU_CORE, &cpuset);
    
    if(pthread_setaffinity_np(thread_id, sizeof(cpuset), &cpuset) != 0) {
        XLOGD_WARN("Failed to set CPU affinity");
    }
}
```

### Thread Monitoring and Health
```c
// Thread health monitoring
void xraudio_thread_poll(xraudio_object_t object, 
                         xraudio_thread_poll_func_t func) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    // Send poll message to main thread
    xraudio_main_queue_msg_thread_poll_t msg;
    msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_THREAD_POLL;
    msg.func        = func;
    
    queue_msg_push(obj->msgq_main, (const char *)&msg, sizeof(msg));
}

// Thread responsiveness check in main thread
void xraudio_msg_thread_poll(xraudio_thread_state_t *state, void *msg) {
    xraudio_main_queue_msg_thread_poll_t *poll = 
        (xraudio_main_queue_msg_thread_poll_t *)msg;
    
    // Verify HAL responsiveness
    if(state->params.kwd_plugin != NULL || state->params.out_enabled) {
        if(!state->params.hal_plugin->thread_poll()) {
            XLOGD_ERROR("xraudio HAL is NOT responsive");
            return;
        }
    }
    
    // Call application poll function
    if(poll->func != NULL) {
        poll->func();
    }
}
```

## Error Handling and Recovery

### Thread Failure Recovery
```c
// Thread failure detection and recovery
void handle_thread_failure(xraudio_thread_t *failed_thread, 
                          thread_type_t type) {
    XLOGD_ERROR("Thread failure detected: %s", failed_thread->name);
    
    // Attempt graceful shutdown
    if(failed_thread->running) {
        pthread_cancel(failed_thread->id);
        pthread_join(failed_thread->id, NULL);
        failed_thread->running = false;
    }
    
    // Restart critical threads
    if(type == THREAD_TYPE_MAIN_PROCESSING) {
        // Main thread failure requires full restart
        restart_audio_system();
    } else if(type == THREAD_TYPE_RESOURCE_MANAGER) {
        // Resource thread can be restarted independently
        restart_resource_thread();
    }
}
```

### Deadlock Prevention and Detection
```c
// Lock ordering discipline to prevent deadlock
void acquire_multiple_locks_safely(xraudio_obj_t *obj) {
    // Always acquire locks in consistent order:
    // 1. API mutex
    // 2. Shared memory lock  
    // 3. Session-specific locks
    
    XRAUDIO_API_MUTEX_LOCK();
    XRAUDIO_SHARED_MEM_LOCK(obj);
    
    // Critical section
    
    // Release in reverse order
    XRAUDIO_SHARED_MEM_UNLOCK(obj);
    XRAUDIO_API_MUTEX_UNLOCK();
}
```

## Performance Characteristics

### Threading Overhead
- **Thread Creation**: ~1-2ms per thread (including name setup)
- **Context Switching**: ~5-50μs depending on system load
- **Message Queue Latency**: ~10-100μs for message dispatch
- **Semaphore Operations**: ~1-5μs for signal/wait operations

### Memory Footprint
- **Thread Stack Size**: 8MB default per thread (configurable)
- **Thread Control Blocks**: ~1KB per thread
- **Synchronization Objects**: 24-48 bytes per semaphore/mutex
- **Message Queue Buffers**: Configurable, typically 1-16KB per queue

### Scalability Properties
- **Maximum Threads**: Typically limited to 4-8 audio processing threads
- **Thread Pool**: Not used; threads are long-lived and specialized  
- **CPU Cores**: Designed for 2-8 core systems with affinity optimization
- **Memory Scaling**: Linear with number of concurrent audio sessions

This threading architecture ensures reliable, low-latency audio processing while maintaining system responsiveness and providing robust error recovery mechanisms.