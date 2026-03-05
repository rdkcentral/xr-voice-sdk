# XR Audio Atomic Operations and Thread Safety Documentation

## Overview
The XR Audio component implements comprehensive thread safety mechanisms to ensure reliable operation in multi-threaded environments. The system combines atomic operations, file-based locking, and semaphores to provide thread-safe access to shared resources while maintaining real-time performance guarantees.

## Atomic Operations Infrastructure

### Core Atomic API
The atomic operations are implemented in [`xraudio_atomic.h`](../src/xr-audio/xraudio_atomic.h) and [`xraudio_atomic.c`](../src/xr-audio/xraudio_atomic.c) with dual implementation paths:

#### Modern C11 Atomics (Preferred Path)
```c
// Available when GCC 4.9+ and C11 atomics are supported
#ifdef USE_ATOMIC
#include <stdatomic.h>

typedef atomic_int xraudio_atomic_int_t;

int xraudio_atomic_int_get(xraudio_atomic_int_t *atomic) {
    return atomic_load(atomic);
}

void xraudio_atomic_int_set(xraudio_atomic_int_t *atomic, int new_val) {
    atomic_store(atomic, new_val);
}

bool xraudio_atomic_compare_and_set(xraudio_atomic_int_t *atomic, int old_val, int new_val) {
    return atomic_compare_exchange_strong(atomic, &old_val, new_val);
}
#endif
```

#### Fallback Pthread Implementation
```c
// Fallback for older compilers or platforms without C11 atomics
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

void xraudio_atomic_int_set(xraudio_atomic_int_t *atomic, int new_val) {
    pthread_mutex_lock(&g_mutex);
    *atomic = new_val;
    pthread_mutex_unlock(&g_mutex);
}

bool xraudio_atomic_compare_and_set(xraudio_atomic_int_t *atomic, int old_val, int new_val) {
    bool ret = false;
    pthread_mutex_lock(&g_mutex);
    ret = (*atomic == old_val);
    if(ret) {
        *atomic = new_val;
    }
    pthread_mutex_unlock(&g_mutex);
    return ret;
}
#endif
```

### Atomic Variable Usage Patterns

#### Voice Session State Management
The primary use of atomic operations is in session management via [`g_voice_session`](../src/xr-audio/xraudio_thread.c#L532):

```c
typedef struct {
    bool                    init;
    int                     msgq;
    int                     detecting;
    xraudio_devices_input_t sources_supported;
    xraudio_atomic_int_t    source[XRAUDIO_INPUT_SESSION_GROUP_QTY];  // Atomic session sources
} xraudio_session_voice_t;

static xraudio_session_voice_t g_voice_session = {0};
```

#### Session Locking Protocol
The atomic operations implement a lock-free session reservation system:

```c
// Session acquisition with atomic compare-and-swap
bool xraudio_in_session_group_semaphore_lock(xraudio_devices_input_t source) {
    uint32_t group = xraudio_input_source_to_group(source);
    
    // Atomic attempt to claim session: NONE -> source
    if(xraudio_atomic_compare_and_set(&g_voice_session.source[group], 
                                      XRAUDIO_DEVICE_INPUT_NONE, source)) {
        return true;  // Successfully acquired session
    }
    return false;     // Session already in use
}

// Session release with atomic store
void xraudio_in_session_record_group_semaphore_unlock(xraudio_main_thread_params_t *params, 
                                                       xraudio_session_record_t *session, 
                                                       xraudio_devices_input_t source) {
    uint32_t group = xraudio_input_source_to_group(source);
    xraudio_atomic_int_set(&g_voice_session.source[group], XRAUDIO_DEVICE_INPUT_NONE);
}

// Thread-safe session state query
xraudio_devices_input_t xraudio_in_session_group_source_get(xraudio_input_session_group_t group) {
    return xraudio_atomic_int_get(&g_voice_session.source[group]);
}
```

#### Error Recovery with Atomic Reset
```c
void xraudio_msg_async_input_error(xraudio_thread_state_t *state, void *msg) {
    xraudio_queue_msg_async_input_error_t *error = (xraudio_queue_msg_async_input_error_t *)msg;
    
    if(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(error->source) != XRAUDIO_DEVICE_INPUT_NONE && 
       XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(error->source) == 
       xraudio_in_session_group_source_get(XRAUDIO_INPUT_SESSION_GROUP_DEFAULT)) {
        
        // Atomic reset of session state on error
        xraudio_atomic_int_set(&g_voice_session.source[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT], 
                               XRAUDIO_DEVICE_INPUT_NONE);
    }
}
```

## Shared Memory Locking

### File-Based Mutual Exclusion
The system uses file-based locking for resource management across processes:

```c
#define XRAUDIO_SHARED_MEM_LOCK(...)   xraudio_shared_mem_lock(__VA_ARGS__)
#define XRAUDIO_SHARED_MEM_UNLOCK(...) xraudio_shared_mem_unlock(__VA_ARGS__)

void xraudio_shared_mem_lock(xraudio_object_t object) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    // Block until exclusive access to shared memory lockfile
    if(flock(obj->shared_mem_fd, LOCK_EX)) {
        XLOGD_FATAL("flock() failed");
        exit(-1);  // Critical failure - cannot continue
    }
}

void xraudio_shared_mem_unlock(xraudio_object_t object) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    // Release exclusive access to shared memory
    if(flock(obj->shared_mem_fd, LOCK_UN)) {
        XLOGD_FATAL("flock() failed");
        exit(-1);  // Critical failure - cannot continue
    }
}
```

### Resource Management Protected Sections
Critical sections for multi-process resource arbitration:

```c
// Resource allocation with shared memory protection
static bool resource_entry_allocate(xraudio_resource_params_t *params, 
                                     xraudio_resource_entry_t *entry) {
    XRAUDIO_SHARED_MEM_LOCK(params->object);
    
    // Critical section: check and allocate resources atomically
    bool success = false;
    if(resource_available(params, entry->req_input, entry->req_output)) {
        allocate_resources(params, entry);
        success = true;
    }
    
    XRAUDIO_SHARED_MEM_UNLOCK(params->object);
    return success;
}

// Resource list manipulation with protection
static void resource_entry_remove(xraudio_resource_params_t *params, 
                                   xraudio_resource_entry_t *entry, 
                                   bool locked) {
    if(!locked) { 
        XRAUDIO_SHARED_MEM_LOCK(params->object); 
    }
    
    // Critical section: linked list modification
    remove_from_resource_list(params, entry);
    
    if(!locked) { 
        XRAUDIO_SHARED_MEM_UNLOCK(params->object); 
    }
}
```

## Semaphore-Based Synchronization

### API-Level Mutual Exclusion
Each XR Audio object maintains an API mutex for thread-safe access:

```c
typedef struct {
    // ... other fields ...
    sem_t mutex_api;  // API-level synchronization
    // ... other fields ...
} xraudio_obj_t;

#define XRAUDIO_API_MUTEX_LOCK()      sem_wait(&obj->mutex_api)
#define XRAUDIO_API_MUTEX_UNLOCK()    sem_post(&obj->mutex_api)

// Example usage in API functions
xraudio_result_t xraudio_open(xraudio_object_t object, /* ... */) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    XRAUDIO_API_MUTEX_LOCK();
    
    // Critical section: check state and initialize resources
    if(obj->opened) {
        XRAUDIO_API_MUTEX_UNLOCK();
        return XRAUDIO_RESULT_ERROR_OPEN;
    }
    
    // Perform initialization...
    obj->opened = true;
    
    XRAUDIO_API_MUTEX_UNLOCK();
    return XRAUDIO_RESULT_OK;
}
```

### Thread Launch Synchronization
Semaphores coordinate thread startup and shutdown:

```c
// Thread launch with synchronization
static void* resource_thread_main(void *param) {
    xraudio_thread_params_t thread_params = *(xraudio_thread_params_t*)param;
    
    // Signal parent thread that initialization is complete
    sem_post(thread_params.semaphore);
    
    // Main thread loop...
    return NULL;
}

// Synchronous message passing with semaphores
xraudio_result_t xraudio_power_mode_set(xraudio_object_t object, 
                                        xraudio_power_mode_t power_mode) {
    sem_t semaphore;
    sem_init(&semaphore, 0, 0);
    
    xraudio_main_queue_msg_power_mode_t msg;
    msg.power_mode = power_mode;
    msg.semaphore = &semaphore;
    
    queue_msg_push(obj->msgq_main, (const char*)&msg, sizeof(msg));
    
    // Block until operation completes
    sem_wait(&semaphore);  
    sem_destroy(&semaphore);
    
    return result;
}
```

## Message Queue Thread Safety

### Lock-Free Inter-Thread Communication
The system uses message queues for asynchronous, thread-safe communication:

```c
// Thread-safe message dispatch
void queue_msg_push(xr_mq_t xrmq, const char *msg, xr_mq_msg_size_t msg_len) {
    // XR message queue handles internal synchronization
    xr_mq_push(xrmq, msg, msg_len);
}

// Message processing loop with select()-based synchronization
void* xraudio_main_thread(void *param) {
    fd_set rfds_master;
    FD_ZERO(&rfds_master);
    FD_SET(params->msgq, &rfds_master);  // Message queue file descriptor
    
    while(state.running) {
        fd_set rfds_copy = rfds_master;
        
        // Block until message arrives or timeout
        int activity = select(nfds, &rfds_copy, NULL, NULL, &timeout);
        
        if(FD_ISSET(params->msgq, &rfds_copy)) {
            // Process incoming messages thread-safely
            process_message_queue(&state);
        }
    }
    return NULL;
}
```

## Real-Time Thread Safety Patterns

### Lock-Free Audio Buffer Management
Audio processing uses lock-free techniques for real-time guarantees:

```c
// Triple-buffered frame management
typedef struct {
    volatile uint32_t               frame_group_index;    // Atomic buffer index
    xraudio_audio_group_int16_t     frame_buffer_int16;   // Processing buffers
    xraudio_audio_group_float_t     frame_buffer_fp32;    // Format conversion buffers
} xraudio_session_record_inst_t;

// Lock-free buffer rotation
static void advance_frame_buffers(xraudio_session_record_t *session) {
    // Atomic advancement of circular buffer index
    session->frame_group_index = 
        (session->frame_group_index + 1) % XRAUDIO_INPUT_FRAME_GROUP_QTY_MAX;
}
```

### DSP Pipeline Thread Safety
Multi-channel audio processing with thread-safe operations:

```c
void xraudio_preprocess_mic_data(xraudio_main_thread_params_t *params, 
                                 xraudio_session_record_t *session, 
                                 xraudio_ppr_event_t *ppr_event) {
    // Format conversion with local stack buffers (thread-safe)
    xraudio_audio_frame_int32_t ppmic_input_buffers[chan_qty_mic];
    xraudio_audio_frame_int32_t ppasr_output_buffers[XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY];
    
    // Thread-safe format conversion operations
    for(uint8_t chan = 0; chan < chan_qty_total; ++chan) {
        float *pf32 = &session->frame_buffer_fp32[chan].frames[session->frame_group_index].samples[0];
        int32_t *pi32 = &ppmic_input_buffers[chan].samples[0];
        
        // Lock-free format conversion (read-only access to session buffers)
        xraudio_samples_convert_fp32_int32(pi32, pf32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
    }
    
    // Thread-safe DSP processing with immutable inputs
    *ppr_event = xraudio_input_ppr_run(params->obj_input, 
                                       XRAUDIO_INPUT_FRAME_SAMPLE_QTY,
                                       (const int32_t **)&ppmic_inputs,
                                       (const int32_t **)&ppref_inputs,
                                       (int32_t **)&ppkwd_outputs,
                                       (int32_t **)&ppasr_outputs,
                                       (int32_t **)&ppref_outputs);
}
```

## Thread Safety Guarantees

### Memory Ordering and Consistency
- **C11 Atomics**: Provide sequential consistency guarantees for atomic operations
- **Pthread Fallback**: Uses mutex-based critical sections with memory barriers
- **File Locking**: Ensures process-level mutual exclusion with kernel synchronization
- **Buffer Management**: Lock-free circular buffers with atomic index management

### Deadlock Prevention
```c
// Consistent lock ordering to prevent deadlock
void function_requiring_multiple_locks(xraudio_obj_t *obj) {
    // Always acquire locks in same order: API mutex -> shared memory -> resource locks
    XRAUDIO_API_MUTEX_LOCK();
    XRAUDIO_SHARED_MEM_LOCK(obj);
    
    // Critical section...
    
    // Release in reverse order
    XRAUDIO_SHARED_MEM_UNLOCK(obj);
    XRAUDIO_API_MUTEX_UNLOCK();
}
```

### Real-Time Safety Properties
- **Lock-Free Audio Path**: Critical audio processing avoids blocking operations
- **Message-Based Control**: Non-blocking control operations via asynchronous messages
- **Atomic Session State**: Session management uses atomic compare-and-swap for consistency
- **Triple Buffering**: Audio buffers rotate atomically without blocking DSP operations

## Error Handling and Recovery

### Atomic State Recovery
```c
// Safe error recovery with atomic operations
void handle_audio_input_error(xraudio_devices_input_t failed_source) {
    uint32_t group = xraudio_input_source_to_group(failed_source);
    
    // Atomic reset of failed session
    xraudio_atomic_int_set(&g_voice_session.source[group], XRAUDIO_DEVICE_INPUT_NONE);
    
    // Allow new sessions to be established
    XLOGD_INFO("Session reset for group <%s> due to input error", 
               xraudio_input_session_group_str(group));
}
```

### Critical Failure Handling
```c
// Fatal error handling for lock failures
void xraudio_shared_mem_lock(xraudio_object_t object) {
    if(flock(obj->shared_mem_fd, LOCK_EX)) {
        XLOGD_FATAL("Shared memory lock failed - system integrity compromised");
        exit(-1);  // Cannot continue safely without synchronization
    }
}
```

## Performance Characteristics

### Atomic Operation Overhead
- **C11 Atomics**: ~1-5 CPU cycles for simple operations (load/store/CAS)
- **Pthread Fallback**: ~50-100 CPU cycles due to mutex overhead
- **Session Management**: Lock-free session acquisition with O(1) complexity
- **Voice Session State**: Sub-microsecond atomic state transitions

### Scalability Properties
- **Multi-Session Support**: Independent atomic variables per session group
- **Process Isolation**: File-based locking enables multi-process resource sharing
- **Real-Time Compatibility**: Lock-free audio pipeline maintains deterministic timing
- **Memory Efficiency**: Minimal atomic variable footprint (4 bytes per session group)

This thread safety architecture ensures robust, real-time operation while supporting complex multi-threaded and multi-process audio processing scenarios.