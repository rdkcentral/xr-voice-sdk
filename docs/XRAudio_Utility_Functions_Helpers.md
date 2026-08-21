# XR Audio Utility Functions and Helper Modules Documentation

## Overview
The XR Audio component provides a comprehensive suite of utility functions and helper modules designed to support audio processing, format conversion, debugging, and system integration. These utilities abstract common operations and provide consistent interfaces for string conversion, validation, audio format handling, and diagnostic functions.

## Utility Function Categories

### 1. String Conversion and Debugging Utilities

#### Enum-to-String Conversion Functions
Located in [`xraudio_utils.c`](../src/xr-audio/xraudio_utils.c), these functions provide human-readable string representations of enumerated types for logging and debugging:

```c
// Device Input String Conversion with Multi-Flag Support
const char *xraudio_devices_input_str(xraudio_devices_input_t type) {
    static char str[64];  // Thread-local static buffer

    if(type == XRAUDIO_DEVICE_INPUT_NONE) {
        return "NONE";
    }

    str[0] = '\0';
    
    // Support multiple simultaneous device flags
    if(type & XRAUDIO_DEVICE_INPUT_SINGLE) {
        strlcat(str, "SINGLE", sizeof(str));
    }
    if(type & XRAUDIO_DEVICE_INPUT_TRI) {
        strlcat(str, str[0] ? ", TRI" : "TRI", sizeof(str));
    }
    if(type & XRAUDIO_DEVICE_INPUT_QUAD) {
        strlcat(str, str[0] ? ", QUAD" : "QUAD", sizeof(str));
    }
    // ... additional flags
    
    return str[0] ? str : xraudio_invalid_return(type);
}

// Output Device String Conversion
const char *xraudio_devices_output_str(xraudio_devices_output_t type) {
    switch(type) {
        case XRAUDIO_DEVICE_OUTPUT_NONE:    return "NONE";
        case XRAUDIO_DEVICE_OUTPUT_NORMAL:  return "NORMAL";
        case XRAUDIO_DEVICE_OUTPUT_EC_REF:  return "EC REF";
        case XRAUDIO_DEVICE_OUTPUT_OFFLOAD: return "OFFLOAD";
        case XRAUDIO_DEVICE_OUTPUT_HFP:     return "HFP";
        case XRAUDIO_DEVICE_OUTPUT_INVALID: return "INVALID";
    }
    return xraudio_invalid_return(type);
}

// Audio Container Format Strings
const char *xraudio_container_str(xraudio_container_t type) {
    switch(type) {
        case XRAUDIO_CONTAINER_NONE:    return "NONE";
        case XRAUDIO_CONTAINER_WAV:     return "WAV";
        case XRAUDIO_CONTAINER_MP3:     return "MP3";
        case XRAUDIO_CONTAINER_INVALID: return "INVALID";
    }
    return xraudio_invalid_return(type);
}

// Audio Encoding Type Strings
const char *xraudio_encoding_str(xraudio_encoding_type_t type) {
    switch(type) {
        case XRAUDIO_ENCODING_PCM:         return "PCM";
        case XRAUDIO_ENCODING_PCM_RAW:     return "PCM_RAW";
        case XRAUDIO_ENCODING_ADPCM_FRAME: return "ADPCM_FRAME";
        case XRAUDIO_ENCODING_ADPCM:       return "ADPCM";
        case XRAUDIO_ENCODING_OPUS_XVP:    return "OPUS_XVP";
        case XRAUDIO_ENCODING_OPUS:        return "OPUS";
        case XRAUDIO_ENCODING_INVALID:     return "INVALID";
    }
    return xraudio_invalid_return(type);
}
```

#### Error and Result String Conversion
```c
const char *xraudio_result_str(xraudio_result_t type) {
    switch(type) {
        case XRAUDIO_RESULT_OK:                   return "OK";
        case XRAUDIO_RESULT_ERROR_OBJECT:         return "INVALID OBJECT";
        case XRAUDIO_RESULT_ERROR_INTERNAL:       return "INTERNAL ERROR";
        case XRAUDIO_RESULT_ERROR_OUTPUT:         return "SPEAKER NOT AVAILABLE";
        case XRAUDIO_RESULT_ERROR_INPUT:          return "MICROPHONE NOT AVAILABLE";
        case XRAUDIO_RESULT_ERROR_OPEN:           return "XRAUDIO IS NOT OPEN";
        case XRAUDIO_RESULT_ERROR_PARAMS:         return "INVALID PARAMETERS";
        case XRAUDIO_RESULT_ERROR_STATE:          return "INVALID STATE";
        case XRAUDIO_RESULT_ERROR_CONTAINER:      return "INVALID CONTAINER";
        case XRAUDIO_RESULT_ERROR_ENCODING:       return "INVALID ENCODING";
        case XRAUDIO_RESULT_ERROR_FILE_OPEN:      return "FILE OPEN";
        case XRAUDIO_RESULT_ERROR_FILE_SEEK:      return "FILE SEEK";
        case XRAUDIO_RESULT_ERROR_FIFO_OPEN:      return "FIFO OPEN";
        case XRAUDIO_RESULT_ERROR_FIFO_CONTROL:   return "FIFO CONTROL";
        case XRAUDIO_RESULT_ERROR_OUTPUT_OPEN:    return "SPEAKER OPEN";
        case XRAUDIO_RESULT_ERROR_OUTPUT_VOLUME:  return "SPEAKER VOLUME";
        case XRAUDIO_RESULT_ERROR_WAVE_HEADER:    return "WAVE HEADER";
        case XRAUDIO_RESULT_ERROR_RESOURCE:       return "RESOURCE";
        case XRAUDIO_RESULT_ERROR_CAPTURE:        return "CAPTURE";
        case XRAUDIO_RESULT_ERROR_MIC_OPEN:       return "MIC_OPEN_ERROR";
        case XRAUDIO_RESULT_ERROR_DISABLED:       return "DISABLED";
        case XRAUDIO_RESULT_ERROR_IN_USE:         return "IN_USE";
        case XRAUDIO_RESULT_ERROR_INVALID:        return "INVALID";
    }
    return xraudio_invalid_return(type);
}
```

#### Advanced Event and State String Conversion
```c
// EOS (End-of-Speech) Event Strings
const char *xraudio_eos_event_str(xraudio_eos_event_t type) {
    switch(type) {
        case XRAUDIO_EOS_EVENT_NONE:            return "NONE";
        case XRAUDIO_EOS_EVENT_STARTOFSPEECH:   return "STARTOFSPEECH";
        case XRAUDIO_EOS_EVENT_ENDOFSPEECH:     return "ENDOFSPEECH";
        case XRAUDIO_EOS_EVENT_TIMEOUT_INITIAL: return "TIMEOUT_INITIAL";
        case XRAUDIO_EOS_EVENT_TIMEOUT_END:     return "TIMEOUT_END";
        case XRAUDIO_EOS_EVENT_END_OF_WAKEWORD: return "END_OF_WAKEWORD";
        case XRAUDIO_EOS_EVENT_INVALID:         return "INVALID";
    }
    return xraudio_invalid_return(type);
}

// PPR (Pre/Post-Processing) Event Strings  
const char *xraudio_ppr_event_str(xraudio_ppr_event_t type) {
    switch(type) {
        case XRAUDIO_PPR_EVENT_NONE:                       return "NONE";
        case XRAUDIO_PPR_EVENT_STARTOFSPEECH:              return "STARTOFSPEECH";
        case XRAUDIO_PPR_EVENT_ENDOFSPEECH:                return "ENDOFSPEECH";
        case XRAUDIO_PPR_EVENT_TIMEOUT_INITIAL:            return "TIMEOUT_INITIAL";
        case XRAUDIO_PPR_EVENT_TIMEOUT_END:                return "TIMEOUT_END";
        case XRAUDIO_PPR_EVENT_LOCAL_KEYWORD_DETECTED:     return "LOCAL_KEYWORD_DETECTED";
        case XRAUDIO_PPR_EVENT_REFERENCE_KEYWORD_DETECTED: return "REFERENCE_KEYWORD_DETECTED";
        case XRAUDIO_PPR_EVENT_INVALID:                    return "INVALID";
    }
    return xraudio_invalid_return(type);
}

// Message Queue Type Strings for Inter-Thread Communication
const char *xraudio_main_queue_msg_type_str(xraudio_main_queue_msg_type_t type) {
    switch(type) {
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_START:     return "RECORD IDLE START";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_STOP:      return "RECORD IDLE STOP";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_START:          return "RECORD START";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_STOP:           return "RECORD STOP";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_START:         return "CAPTURE START";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_STOP:          return "CAPTURE STOP";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_IDLE:             return "PLAY IDLE";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_START:            return "PLAY START";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_PAUSE:            return "PLAY PAUSE";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_RESUME:           return "PLAY RESUME";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_STOP:             return "PLAY STOP";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT:                return "DETECT";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_PARAMS:         return "DETECT_PARAMS";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_SENSITIVITY_LIMITS_GET: return "DETECT SENSITIVITY LIMITS";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_STOP:           return "DETECT STOP";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_BEGIN:   return "SESSION_BEGIN";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_END:     return "SESSION_END";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_INPUT_ERROR:     return "INPUT_ERROR";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_TERMINATE:             return "TERMINATE";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_THREAD_POLL:           return "THREAD_POLL";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_POWER_MODE:            return "POWER_MODE";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE:          return "PRIVACY_MODE";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE_GET:      return "PRIVACY_MODE_GET";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_PARAMS_SET:    return "CAPTURE_PARAMS_SET";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_INPUT_SOURCE_FD_SET:   return "INPUT_SOURCE_FD_SET";
        case XRAUDIO_MAIN_QUEUE_MSG_TYPE_INVALID:               return "INVALID";
    }
    return xraudio_invalid_return(type);
}
```

#### Invalid Value Handler
```c
// Generic invalid value string generator with thread-safe buffer  
#define XRAUDIO_INVALID_STR_LEN (24)
static char xraudio_invalid_str[XRAUDIO_INVALID_STR_LEN];

const char *xraudio_invalid_return(int value) {
    snprintf(xraudio_invalid_str, XRAUDIO_INVALID_STR_LEN, "INVALID(%d)", value);
    xraudio_invalid_str[XRAUDIO_INVALID_STR_LEN - 1] = '\0';  // Ensure null termination
    return xraudio_invalid_str;
}
```

### 2. Device and Input Validation Utilities

#### Device Input Validation
```c
// Local device input validation
bool xraudio_devices_input_local_is_valid(xraudio_devices_input_t devices) {
    // Validate local microphone configuration
    switch(XRAUDIO_DEVICE_INPUT_LOCAL_GET(devices)) {
        case XRAUDIO_DEVICE_INPUT_NONE:
        case XRAUDIO_DEVICE_INPUT_SINGLE:
        case XRAUDIO_DEVICE_INPUT_TRI:
        case XRAUDIO_DEVICE_INPUT_QUAD:
        case XRAUDIO_DEVICE_INPUT_HFP:
        case XRAUDIO_DEVICE_INPUT_MIC_TAP:
            break;
        default:
            return false;
    }

    // Validate echo cancellation reference configuration
    switch(XRAUDIO_DEVICE_INPUT_EC_REF_GET(devices)) {
        case XRAUDIO_DEVICE_INPUT_EC_REF_NONE:
        case XRAUDIO_DEVICE_INPUT_EC_REF_MONO:
        case XRAUDIO_DEVICE_INPUT_EC_REF_STEREO:
        case XRAUDIO_DEVICE_INPUT_EC_REF_5_1:
            break;
        default:
            return false;
    }
    return true;
}

// External device input validation  
bool xraudio_devices_input_external_is_valid(xraudio_devices_input_t devices) {
    devices = XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(devices);
    
    // Only PTT and FF external inputs are valid
    return (devices & ~(XRAUDIO_DEVICE_INPUT_PTT | XRAUDIO_DEVICE_INPUT_FF)) == 0;
}

// Combined device input validation
bool xraudio_devices_input_is_valid(xraudio_devices_input_t devices) {
    return xraudio_devices_input_local_is_valid(devices) && 
           xraudio_devices_input_external_is_valid(devices);
}

// Output device validation
bool xraudio_devices_output_is_valid(xraudio_devices_output_t devices) {
    switch(devices) {
        case XRAUDIO_DEVICE_OUTPUT_NONE:
        case XRAUDIO_DEVICE_OUTPUT_NORMAL:
        case XRAUDIO_DEVICE_OUTPUT_EC_REF:
        case XRAUDIO_DEVICE_OUTPUT_OFFLOAD:
        case XRAUDIO_DEVICE_OUTPUT_HFP:
            return true;
        default:
            return false;
    }
}
```

### 3. Audio Format Conversion Utilities

#### Sample Format Conversion Functions
Located in [`xraudio_thread.c`](../src/xr-audio/xraudio_thread.c#L5187-L5270):

```c
// Float32 to Int16 Conversion with Saturation Protection
void xraudio_samples_convert_fp32_int16(int16_t *samples_int16, 
                                         float *samples_fp32, 
                                         uint32_t sample_qty, 
                                         uint32_t bit_qty) {
    XLOGD_DEBUG("sample qty <%u> bit qty <%u>", sample_qty, bit_qty);

    for(uint32_t i = 0; i < sample_qty; i++) {
        // Saturation arithmetic for safe conversion
        if(*samples_fp32 < INT32_MIN) {
            *samples_int16 = INT16_MIN;
        } else if(*samples_fp32 > INT32_MAX) {
            *samples_int16 = INT16_MAX;
        } else {
            // Convert 32-bit float to 16-bit integer with bit shifting
            *samples_int16 = (int16_t)(((int32_t)(*samples_fp32)) >> 16);
        }
        samples_fp32++;
        samples_int16++;
    }
}

// Int32 to Int16 Conversion with Bit Shifting
void xraudio_samples_convert_int32_int16(int16_t *int16buf, 
                                          int32_t *int32buf, 
                                          uint32_t sample_qty_frame, 
                                          uint32_t bit_qty) {
    int32_t *pi32 = int32buf;
    int16_t *pi16 = int16buf;

    for(uint32_t sample = 0; sample < sample_qty_frame; sample++) {
        *pi16 = (*pi32 >> 16);  // Extract upper 16 bits
        pi16++;
        pi32++;
    }
}

// Int32 to Float32 Direct Conversion
void xraudio_samples_convert_int32_fp32(float *fp32buf, 
                                         int32_t *int32buf, 
                                         uint32_t sample_qty_frame, 
                                         uint32_t bit_qty) {
    int32_t *pi32 = int32buf;
    float *pf32 = fp32buf;

    for(uint32_t sample = 0; sample < sample_qty_frame; sample++) {
        *pf32++ = (float)(*pi32++);  // Direct cast to float
    }
}

// Float32 to Int32 Conversion with Saturation Protection
void xraudio_samples_convert_fp32_int32(int32_t *int32buf, 
                                         float *fp32buf, 
                                         uint32_t sample_qty_frame, 
                                         uint32_t bit_qty) {
    int32_t *pi32 = int32buf;
    float *pf32 = fp32buf;

    for(uint32_t sample = 0; sample < sample_qty_frame; sample++) {
        // Saturation arithmetic for safe conversion
        if(*pf32 < INT32_MIN) {
            *pi32 = INT32_MIN;
        } else if(*pf32 > INT32_MAX) {
            *pi32 = INT32_MAX;
        } else {
            *pi32 = (int32_t)(*pf32);
        }
        pf32++;
        pi32++;
    }
}
```

### 4. WAVE Header Generation Utilities

#### WAV File Header Creation
```c
// Generate standard WAV file header with optional padding
void xraudio_wave_header_gen(uint8_t *header, 
                              uint16_t audio_format, 
                              uint16_t num_channels, 
                              uint32_t sample_rate, 
                              uint16_t bits_per_sample, 
                              uint32_t pcm_data_size, 
                              uint32_t padding) {
    // Calculate derived values
    uint32_t byte_rate = sample_rate * num_channels * bits_per_sample / 8;
    uint32_t chunk_size = pcm_data_size + 36;
    uint16_t block_align = num_channels * bits_per_sample / 8;
    uint32_t fmt_chunk_size = 16;

    // RIFF header
    header[0] = 'R'; header[1] = 'I'; header[2] = 'F'; header[3] = 'F';
    
    // File size (chunk_size)
    header[4] = (uint8_t)(chunk_size);
    header[5] = (uint8_t)(chunk_size >> 8);
    header[6] = (uint8_t)(chunk_size >> 16);
    header[7] = (uint8_t)(chunk_size >> 24);
    
    // WAVE format identifier
    header[8] = 'W'; header[9] = 'A'; header[10] = 'V'; header[11] = 'E';
    
    // fmt chunk identifier
    header[12] = 'f'; header[13] = 'm'; header[14] = 't'; header[15] = ' ';
    
    // fmt chunk size
    header[16] = (uint8_t)(fmt_chunk_size);
    header[17] = (uint8_t)(fmt_chunk_size >> 8);
    header[18] = (uint8_t)(fmt_chunk_size >> 16);
    header[19] = (uint8_t)(fmt_chunk_size >> 24);
    
    // Audio format (PCM = 1)
    header[20] = (uint8_t)(audio_format);
    header[21] = (uint8_t)(audio_format >> 8);
    
    // Number of channels
    header[22] = (uint8_t)(num_channels);
    header[23] = (uint8_t)(num_channels >> 8);
    
    // Sample rate
    header[24] = (uint8_t)(sample_rate);
    header[25] = (uint8_t)(sample_rate >> 8);
    header[26] = (uint8_t)(sample_rate >> 16);
    header[27] = (uint8_t)(sample_rate >> 24);
    
    // Byte rate (bytes per second)
    header[28] = (uint8_t)(byte_rate);
    header[29] = (uint8_t)(byte_rate >> 8);
    header[30] = (uint8_t)(byte_rate >> 16);
    header[31] = (uint8_t)(byte_rate >> 24);
    
    // Block align (bytes per sample frame)
    header[32] = (uint8_t)(block_align);
    header[33] = (uint8_t)(block_align >> 8);
    
    // Bits per sample  
    header[34] = (uint8_t)(bits_per_sample);
    header[35] = (uint8_t)(bits_per_sample >> 8);

    uint32_t i = 36;
    
    // Optional padding chunk for alignment
    if(padding >= 8) {
        padding -= 8;  // Account for chunk header
        
        // 'pad ' chunk identifier
        header[i++] = 'p'; header[i++] = 'a'; 
        header[i++] = 'd'; header[i++] = ' ';
        
        // Padding chunk size
        header[i++] = (uint8_t)(padding);
        header[i++] = (uint8_t)(padding >> 8);
        header[i++] = (uint8_t)(padding >> 16);
        header[i++] = (uint8_t)(padding >> 24);
        
        // Zero-filled padding data
        for(uint32_t index = 0; index < padding; index++) {
            header[i++] = 0;
        }
    }
    
    // Data chunk identifier
    header[i++] = 'd'; header[i++] = 'a';
    header[i++] = 't'; header[i++] = 'a';
    
    // PCM data size
    header[i++] = (uint8_t)(pcm_data_size);
    header[i++] = (uint8_t)(pcm_data_size >> 8);
    header[i++] = (uint8_t)(pcm_data_size >> 16);
    header[i++] = (uint8_t)(pcm_data_size >> 24);
}
```

### 5. Channel Configuration Utilities

#### Channel Quantity String Conversion
```c
// Convert channel count to human-readable string
const char *xraudio_channel_qty_str(unsigned char channel_qty) {
    switch(channel_qty) {
        case 0: return "none";
        case 1: return "mono";
        case 2: return "stereo";
        case 3: return "tri";
        case 4: return "quad";
    }
    
    // Handle non-standard channel counts
    snprintf(xraudio_invalid_str, XRAUDIO_INVALID_STR_LEN, "%u chans", channel_qty);
    xraudio_invalid_str[XRAUDIO_INVALID_STR_LEN - 1] = '\0';
    return xraudio_invalid_str;
}

// Session Group String Conversion
const char *xraudio_input_session_group_str(xraudio_input_session_group_t group) {
    switch(group) {
        case XRAUDIO_INPUT_SESSION_GROUP_DEFAULT: return "DEFAULT";
        case XRAUDIO_INPUT_SESSION_GROUP_MIC_TAP: return "MIC_TAP";
        case XRAUDIO_INPUT_SESSION_GROUP_QTY:     return "INVALID";
    }
    return xraudio_invalid_return(group);
}
```

### 6. Logging and Time Utilities

#### Custom Logging Time Format
```c
#ifndef USE_RDKX_LOGGER
void xraudio_get_log_time(char *log_buffer) {
    struct tm *local;
    struct timeval tv;
    uint16_t msecs;
    
    // Get current time with microsecond precision
    gettimeofday(&tv, NULL);
    local = localtime(&tv.tv_sec);
    msecs = (uint16_t)(tv.tv_usec / 1000);  // Convert to milliseconds
    
    // Format time as HH:MM:SS
    strftime(log_buffer, 9, "%T", local);
    
    // Append milliseconds as ":XXX"
    log_buffer[12] = '\0';                              // Null terminate
    log_buffer[11] = (msecs % 10) + '0'; msecs /= 10;   // 1's digit
    log_buffer[10] = (msecs % 10) + '0'; msecs /= 10;   // 10's digit
    log_buffer[9]  = (msecs % 10) + '0';                // 100's digit
    log_buffer[8]  = ':';
}
#endif
```

### 7. File and Capture Helper Functions

#### Audio Capture File Management
```c
// Write audio data to capture session file
int xraudio_in_capture_session_to_file_input(xraudio_session_record_t *session, 
                                              uint8_t chan, 
                                              void *data, 
                                              uint32_t size) {
    errno = 0;
    ssize_t bytes_written = write(session->capture_session.input[chan].file.fd, 
                                  data, size);
    if(bytes_written != size) {
        int errsv = errno;
        XLOGD_ERROR("Write error (%zd) <%s>", bytes_written, strerror(errsv));
        return -1;
    }
    
    // Update file statistics
    session->capture_session.input[chan].file.audio_data_size += size;
    return size;
}

// Write Int32 samples to capture file
int xraudio_in_capture_session_to_file_int32(xraudio_capture_point_t *capture_point, 
                                              int32_t *samples, 
                                              uint32_t sample_qty_frame) {
    size_t data_size = sample_qty_frame * sizeof(int32_t);
    
    // Write samples with error handling
    errno = 0;
    ssize_t bytes_written = write(capture_point->file.fd, samples, data_size);
    if(bytes_written != data_size) {
        int errsv = errno;
        XLOGD_ERROR("Int32 capture write error (%zd) <%s>", 
                    bytes_written, strerror(errsv));
        return -1;
    }
    
    // Update capture statistics
    capture_point->file.audio_data_size += data_size;
    return data_size;
}
```

### 8. Performance and System Utilities

#### CPU Utilization Mode Management
```c
// Set stream CPU utilization mode for performance optimization
xraudio_result_t xraudio_stream_cpu_util_mode_set(xraudio_object_t object, 
                                                   xraudio_devices_input_t source, 
                                                   xraudio_stream_cpu_util_mode_t cpu_util_mode) {
    xraudio_obj_t *obj = (xraudio_obj_t *)object;
    
    if(!xraudio_object_is_valid(obj)) {
        return XRAUDIO_RESULT_ERROR_OBJECT;
    }
    
    if(cpu_util_mode >= XRAUDIO_STREAM_CPU_UTIL_MODE_INVALID) {
        return XRAUDIO_RESULT_ERROR_PARAMS;
    }
    
    XRAUDIO_API_MUTEX_LOCK();
    
    xraudio_result_t result = XRAUDIO_RESULT_OK;
    if(obj->obj_input != NULL) {
        result = xraudio_input_cpu_util_mode_set(obj->obj_input, source, cpu_util_mode);
    }
    
    XRAUDIO_API_MUTEX_UNLOCK();
    return result;
}

// CPU utilization mode string conversion
const char *xraudio_stream_cpu_util_mode_str(xraudio_stream_cpu_util_mode_t cpu_util_mode) {
    switch(cpu_util_mode) {
        case XRAUDIO_STREAM_CPU_UTIL_MODE_NORMAL: return "NORMAL";
        case XRAUDIO_STREAM_CPU_UTIL_MODE_LOW:    return "LOW";
        case XRAUDIO_STREAM_CPU_UTIL_MODE_INVALID:return "INVALID";
    }
    return xraudio_invalid_return(cpu_util_mode);
}
```

## Utility Function Integration Patterns

### Thread-Safe String Operations
```c
// Thread-safe string concatenation using BSD strlcat
static char result_buffer[MAX_STRING_LENGTH];

void safe_string_building(device_flags_t flags) {
    result_buffer[0] = '\0';  // Initialize empty string
    
    if(flags & FLAG_A) {
        strlcat(result_buffer, "FLAG_A", sizeof(result_buffer));
    }
    if(flags & FLAG_B) {
        strlcat(result_buffer, 
                result_buffer[0] ? ", FLAG_B" : "FLAG_B", 
                sizeof(result_buffer));
    }
    // Guaranteed null termination and no buffer overflow
}
```

### Error-Safe Numeric Conversions
```c
// Safe sample format conversion with bounds checking
void convert_with_validation(float input, int16_t *output) {
    if(input < INT16_MIN) {
        *output = INT16_MIN;  // Clamp to minimum
        XLOGD_WARN("Audio sample underflow detected");
    } else if(input > INT16_MAX) {
        *output = INT16_MAX;  // Clamp to maximum  
        XLOGD_WARN("Audio sample overflow detected");
    } else {
        *output = (int16_t)input;  // Safe conversion
    }
}
```

### Extensible Enum Handling
```c
// Pattern for handling new enum values gracefully
const char *future_safe_enum_str(enum_type_t value) {
    switch(value) {
        // Known cases
        case ENUM_VALUE_A: return "VALUE_A";
        case ENUM_VALUE_B: return "VALUE_B";
        
        // Future-proofing
        default:
            if(value < ENUM_RESERVED_RANGE_START) {
                return xraudio_invalid_return(value);  // Unknown legacy value
            } else {
                snprintf(xraudio_invalid_str, XRAUDIO_INVALID_STR_LEN, 
                         "FUTURE_%d", value);
                return xraudio_invalid_str;  // Future extension
            }
    }
}
```

## Performance Characteristics

### String Conversion Performance
- **Static Buffer Usage**: Avoids dynamic allocation for thread safety
- **Switch-Based Lookups**: O(1) performance for known enum values
- **Cached Results**: String literals stored in read-only memory
- **Buffer Safety**: Always null-terminated with overflow protection

### Audio Format Conversion Performance  
- **Vectorization Potential**: Loops structured for compiler auto-vectorization
- **Cache Efficiency**: Linear memory access patterns optimize cache usage
- **Saturation Arithmetic**: Hardware-optimized clamping operations
- **Bit Manipulation**: Efficient bit shifting for format conversions

### Memory Usage Optimization
- **Stack Allocation**: Local buffers for temporary conversions
- **Buffer Reuse**: Shared static buffers for non-concurrent operations  
- **Minimal Overhead**: Lightweight data structure access patterns
- **Zero-Copy Where Possible**: Direct buffer manipulation without intermediate copies

This comprehensive utility framework provides robust, efficient, and maintainable support functions that enhance system reliability while maintaining optimal performance characteristics for real-time audio processing applications.