# Message Queue System Analysis

## Overview
The XR Voice SDK implements a sophisticated message queue system that enables asynchronous inter-thread communication between the main XRSR thread and various components. The system is built on two layers: the XR-MQ infrastructure providing generic message queue functionality, and the XRSR message queue wrapper providing speech router-specific message handling.

## Core Architecture

### XR-MQ Infrastructure (xr_mq.c/h)

#### Message Queue Structure
```c
typedef struct {
    uint8_t          max_msg;
    xr_mq_msg_size_t max_msg_size;
} xr_mq_attr_t;

typedef int xr_mq_t;  // File descriptor for eventfd
typedef size_t xr_mq_msg_size_t;
```

#### Default Configuration
- **Maximum Messages**: 10 messages per queue (XR_MQ_DEFAULT_MAX_MSG)
- **Maximum Message Size**: 128 + sizeof(xr_mq_msg_size_t) bytes (XR_MQ_DEFAULT_MAX_MSG_SIZE)
- **Invalid Queue ID**: -1 (XR_MQ_INVALID) 

#### Core Implementation
The XR-MQ system uses **eventfd** for efficient event notification combined with **pthread mutex** for thread-safe access:

**Data Structure**:
```c
typedef struct xr_mq_node {
    struct xr_mq_node *next;
    xr_mq_t           eventfd;
    pthread_mutex_t   mutex;
    // Circular buffer management
    uint8_t           *buffer;
    uint32_t          in;       // Write position
    uint32_t          out;      // Read position
    uint32_t          mask;     // Buffer mask for efficient modulo
    uint8_t           max_msg;
    xr_mq_msg_size_t  max_msg_size;
} xr_mq_node_t;
```

**Key Features**:
- **Thread-Safe Operations**: All operations protected by pthread mutex
- **Event-Driven Notification**: Uses eventfd for select() integration  
- **Circular Buffer**: Efficient memory usage with power-of-2 sizing
- **Linked List Management**: Multiple queues managed through linked list

#### API Functions

**Queue Creation**:
```c
xr_mq_t xr_mq_create(xr_mq_attr_t *attr);
```
- Creates eventfd with EFD_CLOEXEC flag
- Initializes pthread mutex with PTHREAD_MUTEX_RECURSIVE
- Allocates circular buffer (power of 2 sizing)
- Returns eventfd file descriptor or XR_MQ_INVALID on failure

**Message Push**:
```c
bool xr_mq_push(xr_mq_t mq, const void *msg, xr_mq_msg_size_t msg_size);
```
- Validates queue, message size, and buffer capacity
- Thread-safe message insertion into circular buffer
- Increments eventfd counter to notify waiting threads
- Returns false if queue full or message too large

**Message Pop**:
```c
xr_mq_msg_size_t xr_mq_pop(xr_mq_t mq, void *msg, xr_mq_msg_size_t msg_size);
```
- Thread-safe message retrieval from circular buffer
- Decrements eventfd counter to maintain consistency
- Returns actual message size or -1 on error

**Queue Destruction**:
```c
void xr_mq_destroy(xr_mq_t mq);
```
- Closes eventfd file descriptor
- Destroys pthread mutex
- Frees allocated memory

#### Error Handling
Comprehensive error checking with detailed logging:
- Memory allocation failures
- eventfd creation failures
- Mutex initialization failures
- Queue overflow conditions
- Message size validation
- Buffer underflow protection

### XRSR Message Queue Wrapper (xrsr_msgq.c)

#### Wrapper Functions
```c
bool xrsr_msgq_push(xr_mq_t msgq_id, void *msg)
{
    return(xr_mq_push(msgq_id, msg, XRSR_MSG_QUEUE_MSG_SIZE_MAX));
}
```

**Key Features**:
- **Fixed Message Size**: XRSR_MSG_QUEUE_MSG_SIZE_MAX (sizeof(xrsr_queue_msg_union_t))
- **Simplified API**: Removes size parameter for speech router messages
- **Type Safety**: Enforces consistent message sizing across XRSR

## Message Type System

### Message Type Enumeration (xrsr_private.h)
The XRSR system defines 21 distinct message types for comprehensive inter-thread communication:

#### Control Messages
- **TERMINATE**: Shutdown signal for clean thread termination
- **TERMINATE_COMPLETE**: Confirmation of termination completion
- **POWER_MODE_UPDATE**: Power state transitions (FPM/LPM/Sleep modes)

#### Configuration Messages  
- **ROUTE_UPDATE**: Dynamic routing configuration changes
- **KEYWORD_UPDATE**: Keyword detection parameter updates
- **ROUTE_DELETE**: Route removal operations

#### Session Management Messages
- **SESSION_BEGIN**: Voice session initialization
- **SESSION_CONFIG**: Session configuration parameters  
- **SESSION_TERMINATE**: Session cleanup and termination
- **SESSION_TERMINATE_COMPLETE**: Termination acknowledgment

#### Audio Processing Messages
- **AUDIO_DATA**: Real-time audio frame delivery
- **AUDIO_STREAM_BEGIN**: Audio streaming initialization
- **AUDIO_STREAM_END**: Audio streaming completion
- **AUDIO_FOCUS**: Audio focus arbitration

#### Speech Recognition Messages
- **SPEECH_STATUS**: Recognition pipeline status updates
- **TEXT**: Transcription results delivery
- **EVENT**: Speech recognition events

#### State Management Messages
- **CONNECTED**: Protocol connection establishment
- **DISCONNECTED**: Protocol connection termination
- **SENT**: Message transmission confirmation

#### Statistics & Monitoring
- **STATS**: Performance and operational metrics

### Message Structure Design

#### Header Structure
```c
typedef struct {
    xrsr_queue_msg_type_t type;
    // Type-specific payload follows
} xrsr_queue_msg_header_t;
```

#### Union-Based Message System
All messages use a union structure to ensure consistent sizing:
```c
typedef union {
    xrsr_queue_msg_terminate_t         terminate;
    xrsr_queue_msg_route_update_t      route_update;
    xrsr_queue_msg_keyword_update_t    keyword_update;
    xrsr_queue_msg_session_begin_t     session_begin;
    xrsr_queue_msg_audio_data_t        audio_data;
    xrsr_queue_msg_speech_status_t     speech_status;
    xrsr_queue_msg_text_t              text;
    // ... additional message types
} xrsr_queue_msg_union_t;

#define XRSR_MSG_QUEUE_MSG_SIZE_MAX (sizeof(xrsr_queue_msg_union_t))
```

## Message Processing Framework

### Main Thread Processing Loop (xrsr.c)

#### Select-Based Event Loop
The XRSR main thread implements a sophisticated event loop using **select()** to monitor multiple file descriptors:

```c
int nfds = params.msgq_id + 1;
fd_set rfds, wfds;
FD_ZERO(&rfds);
FD_ZERO(&wfds);

// Always monitor message queue
FD_SET(params.msgq_id, &rfds);

// Add protocol-specific file descriptors
for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
    for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
        // HTTP, WebSocket, SDT protocol file descriptors
        xrsr_http_fd_set(http, 1, &nfds, &rfds, &wfds, NULL);
        xrsr_ws_fd_set(ws, &nfds, &rfds, &wfds, NULL);
        xrsr_sdt_fd_set(sdt, &nfds, &rfds, &wfds, NULL);
    }
}
```

#### Message Queue Processing
When select() indicates message queue activity:
```c
if(FD_ISSET(params.msgq_id, &rfds)) {
    ssize_t bytes_read = xr_mq_pop(params.msgq_id, msg, sizeof(msg));
    if(bytes_read > 0) {
        xrsr_queue_msg_header_t *header = (xrsr_queue_msg_header_t *)msg;
        
        // Type validation
        if(header->type < XRSR_QUEUE_MSG_TYPE_INVALID) {
            // Dispatch to appropriate handler
            (*g_xrsr_msg_handlers[header->type])(&params, &state, msg);
        }
    }
}
```

#### Handler Dispatch System
Static handler array provides O(1) message dispatch:
```c
static void (*g_xrsr_msg_handlers[XRSR_QUEUE_MSG_TYPE_INVALID])(
    xrsr_thread_params_t *params, 
    xrsr_thread_state_t *state, 
    void *msg
) = {
    xrsr_queue_msg_terminate,
    xrsr_queue_msg_route_update,
    xrsr_queue_msg_keyword_update,
    xrsr_queue_msg_session_begin,
    // ... handler for each message type
};
```

### Timer Integration
The message processing loop integrates with RDKX timer system:
- **Timer Events**: Handled synchronously when timeouts expire
- **Select Timeout**: Dynamic timeout based on next scheduled timer
- **Timer Priority**: Timer events processed before socket/queue events

### Protocol Integration
Each protocol (HTTP/WebSocket/SDT) integrates with the event loop:
- **File Descriptor Management**: Protocol handlers register/unregister FDs
- **Read/Write Events**: select() monitors both read and write readiness
- **State Synchronization**: Protocol state managed through message queue

## Inter-Thread Communication Patterns

### Asynchronous Messaging
- **Producer Threads**: Audio input, timer handlers, callback contexts
- **Consumer Thread**: Main XRSR thread processes all messages
- **Non-Blocking**: Message push operations never block producers
- **Event Notification**: eventfd provides efficient wake-up mechanism

### Synchronous Operations
Some operations require synchronous completion:
- **Termination**: TERMINATE + TERMINATE_COMPLETE pattern
- **Session Management**: BEGIN + CONFIG + TERMINATE sequences
- **Status Updates**: Immediate processing of critical state changes

### Message Queue Benefits

#### Performance
- **Zero-Copy**: Messages copied only during queue operations
- **Event-Driven**: No polling overhead, select() provides efficient blocking
- **Minimal Latency**: eventfd wake-up mechanism minimizes response time

#### Reliability
- **Thread Safety**: Comprehensive mutex protection
- **Message Ordering**: FIFO queue ensures message sequence integrity
- **Error Recovery**: Robust error handling with detailed logging

#### Scalability  
- **Multiple Queues**: Linked list allows unlimited queue instances
- **Configurable Sizing**: Queue depth and message size customizable per queue
- **Protocol Agnostic**: Queue system independent of speech router protocols

## Configuration and Deployment

### Queue Configuration
```c
xr_mq_attr_t attr = {
    .max_msg = XR_MQ_DEFAULT_MAX_MSG,           // 10 messages
    .max_msg_size = XR_MQ_DEFAULT_MAX_MSG_SIZE  // 128 + size_t bytes
};
```

### XRSR-Specific Configuration
- **Message Size**: XRSR_MSG_QUEUE_MSG_SIZE_MAX ensures all message types fit
- **Queue Depth**: Default 10 messages suitable for typical speech processing loads
- **File Descriptor**: Message queue integrated into main select() loop

### Integration Points
- **Thread Creation**: Message queue created during XRSR thread initialization
- **Component Registration**: All XRSR components receive queue handle for message sending
- **Shutdown**: Message queue destroyed during clean thread termination

## Error Scenarios and Recovery

### Queue Overflow
- **Detection**: xr_mq_push() returns false when queue full
- **Recovery**: Producers should implement backoff or drop non-critical messages
- **Monitoring**: Error logging provides visibility into queue saturation

### Message Corruption
- **Prevention**: Union-based sizing prevents buffer overruns
- **Detection**: Type validation catches corrupted message headers  
- **Recovery**: Invalid messages logged and discarded

### Thread Synchronization Issues
- **Prevention**: Comprehensive mutex protection in XR-MQ layer
- **Detection**: Error codes from pthread operations
- **Recovery**: System-level error handling for threading failures

The message queue system provides the foundational communication infrastructure that enables the XRSR's modular architecture, real-time audio processing, and multi-protocol speech routing capabilities.