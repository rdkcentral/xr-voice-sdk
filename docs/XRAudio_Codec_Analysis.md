# XR Audio Codec Implementation Analysis - ADPCM and Opus

## Overview

The XR Audio component includes two distinct codec implementations: ADPCM (Adaptive Differential Pulse Code Modulation) for low-bitrate compression and Opus for high-quality, low-latency audio processing. Both codecs are designed for real-time voice communication with specific focus on XR (Extended Reality) applications requiring efficient bandwidth usage and minimal processing latency.

## ADPCM Codec Implementation

### Architecture Overview

The ADPCM codec provides 4:1 compression ratio for audio data, converting 16-bit PCM samples to 4-bit ADPCM codes. This implementation follows the IMA/DVI ADPCM standard with optimizations for real-time processing and frame-based operation.

#### Core ADPCM Object Structure
```c
// Primary ADPCM decoder object (adpcm_dec_t) from adpcm_internal.h
struct adpcm_dec_t {
    uint8_t              magic_number;            // Object validation (46)
    uint8_t              expected_sequence_value; // Packet sequence tracking
    int8_t               step_size_index;         // ADPCM step size index (0-88)
    int16_t              predicted_sample;        // Last predicted sample value
    adpcm_decode_stats_t stats;                   // Decode statistics
};

// ADPCM statistics tracking
typedef struct {
    uint32_t samples_decoded;            // Total samples decoded
    uint32_t failed_decodes;             // Number of decode failures
    uint32_t frames_processed;           // Total frames processed
    uint32_t frames_lost;                // Lost frames count
    uint32_t step_size_mismatch;         // Step size validation errors
    uint32_t predicted_sample_mismatch;  // Prediction errors
} adpcm_decode_stats_t;
```

### ADPCM Algorithm Implementation

#### Step Size Table and Index Mapping
```c
// ADPCM step size quantization table (89 values)
uint16_t table_step_size[] = {
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31,
    34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
    130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371,
    408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166,
    1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024,
    3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845,
    8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500,
    20350, 22385, 24623, 27086, 29794, 32767
};

// Index adjustment table for step size adaptation
int8_t table_index[] = {-1, -1, -1, -1, 2, 4, 6, 8, 
                       -1, -1, -1, -1, 2, 4, 6, 8};
```

#### Core Decoding Algorithm
```c
static pcm_t adpcm_decode_single(adpcm_dec_t *decoder, adpcm_t halfbyte) {
    int32_t difference = 0;
    pcm_t new_sample = decoder->predicted_sample;
    int8_t step_size_index = decoder->step_size_index;
    uint16_t step_size = table_step_size[step_size_index];

    // Calculate difference from 4-bit ADPCM code
    if(halfbyte & 4) difference += step_size;        // Bit 2: +step_size
    if(halfbyte & 2) difference += step_size >> 1;   // Bit 1: +step_size/2
    if(halfbyte & 1) difference += step_size >> 2;   // Bit 0: +step_size/4
    difference += step_size >> 3;                    // Always: +step_size/8

    // Apply sign bit
    if(halfbyte & 8) difference = -difference;       // Bit 3: sign

    // Calculate new sample with saturation
    if((new_sample + difference) > INT16_MAX) {
        new_sample = INT16_MAX;
    } else if((new_sample + difference) < INT16_MIN) {
        new_sample = INT16_MIN;
    } else {
        new_sample += difference;
    }

    // Update step size index with bounds checking
    if((step_size_index + table_index[halfbyte]) < 0) {
        step_size_index = 0;
    } else if((step_size_index + table_index[halfbyte]) > 88) {
        step_size_index = 88;
    } else {
        step_size_index += table_index[halfbyte];
    }

    // Update decoder state
    decoder->predicted_sample = new_sample;
    decoder->step_size_index = step_size_index;
    decoder->stats.samples_decoded++;

    return new_sample;
}
```

### ADPCM Data Format and Framing

#### Byte Packing Format
```c
// Sample extraction from packed bytes
#define ADPCM_ODD_SAMPLE_GET(x)   (x & 0xF)  // First sample (lower 4 bits)
#define ADPCM_EVEN_SAMPLE_GET(x)  (x >> 4)   // Second sample (upper 4 bits)

// Big-endian sample order: {2nd sample, 1st sample}, {4th sample, 3rd sample}
// Little-endian sample order: {1st sample, 2nd sample}, {3rd sample, 4th sample}
```

#### Frame Processing and Analysis
```c
// Frame deframing with validation
int32_t adpcm_deframe(adpcm_dec_t *decoder, uint8_t *inbuf, uint32_t inlen, 
                     xraudio_adpcm_frame_t *adpcm_frame) {
    
    // Parameter validation
    if(!decoder || !inbuf || !adpcm_frame) return -1;
    if(decoder->magic_number != ADPCM_DECODE_MAGIC_NUMBER) return -1;
    
    // Analyze packet for integrity
    if(!adpcm_analyze(decoder, inbuf, inlen, adpcm_frame)) {
        return -1; // Packet analysis failed
    }
    
    // Remove header and return payload size
    uint8_t *payload = &inbuf[adpcm_frame->size_header];
    for(uint32_t i = adpcm_frame->size_header; i < inlen; i++) {
        *inbuf = *payload;  // Shift data to remove header
        inbuf++;
        payload++;
    }
    
    return inlen - adpcm_frame->size_header;
}

// Packet integrity analysis
bool adpcm_analyze(adpcm_dec_t *decoder, uint8_t *inbuf, uint32_t inlen, 
                  xraudio_adpcm_frame_t *adpcm_frame) {
    
    // Sequence number validation for packet loss detection
    uint8_t received_sequence = extract_sequence_number(inbuf);
    
    if(received_sequence != decoder->expected_sequence_value) {
        // Handle packet loss or out-of-order delivery
        uint8_t lost_packets = sequence_value_diff(
            decoder->expected_sequence_value, 
            received_sequence,
            SEQUENCE_MIN, SEQUENCE_MAX
        );
        
        decoder->stats.frames_lost += lost_packets;
        decoder->expected_sequence_value = received_sequence;
    }
    
    // Update expected sequence for next packet
    decoder->expected_sequence_value = sequence_value_next(
        received_sequence, SEQUENCE_MIN, SEQUENCE_MAX
    );
    
    decoder->stats.frames_processed++;
    return true;
}
```

### ADPCM API Interface
```c
// Object lifecycle management
adpcm_dec_t *adpcm_decode_create(void);              // Create decoder
void         adpcm_decode_destroy(adpcm_dec_t *decoder); // Destroy decoder
bool         adpcm_decode_reset(adpcm_dec_t *decoder);   // Reset decoder state

// Decoding operations
int32_t adpcm_deframe(adpcm_dec_t *decoder,             // Remove framing
                     uint8_t *inbuf, uint32_t inlen,
                     xraudio_adpcm_frame_t *adpcm_frame);

bool    adpcm_analyze(adpcm_dec_t *decoder,             // Analyze packet
                     uint8_t *inbuf, uint32_t inlen,
                     xraudio_adpcm_frame_t *adpcm_frame);

int32_t adpcm_decode(adpcm_dec_t *decoder,              // Decode ADPCM data
                    adpcm_t *inbuf, uint32_t inlen,
                    pcm_t *outbuf, uint32_t outlen,
                    xraudio_adpcm_frame_t *adpcm_frame,
                    bool is_big_endian);

// Statistics and diagnostics
bool    adpcm_decode_stats(adpcm_dec_t *decoder,        // Get statistics
                         adpcm_decode_stats_t *stats);
```

### ADPCM Performance Characteristics
- **Compression Ratio**: 4:1 (16-bit PCM to 4-bit ADPCM)
- **Latency**: Ultra-low latency, single-sample processing
- **Quality**: Good for voice, moderate for music
- **CPU Usage**: Very low computational requirements
- **Memory Usage**: Minimal state (< 16 bytes per decoder)
- **Packet Loss Resilience**: Built-in sequence tracking and loss detection

## Opus Codec Implementation

### Architecture Overview

The Opus codec implementation provides high-quality, low-latency audio compression using the open-source Opus library. This implementation supports mono audio at 16kHz sample rate with configurable bitrates and frame sizes optimized for voice communication in XR environments.

#### Core Opus Object Structure
```c
// Opus decoder object (xraudio_opus_obj_t) from xraudio_opus.c
typedef struct {
   uint32_t     identifier;    // Object validation (0x378D6F5A)
   OpusDecoder *decoder;       // Opus library decoder instance
   uint8_t      cmd_id_next;   // Expected command ID for framing
} xraudio_opus_obj_t;

// Opus statistics tracking
typedef struct {
   uint16_t packet_total;    // Total packets processed
   uint16_t packet_lost;     // Lost packets count
   uint8_t  err_discont;     // Discontinuity errors
   uint8_t  err_repeat;      // Repeat packet errors
   uint8_t  err_cmd_id;      // Command ID errors
   uint8_t  err_cmd_len;     // Length validation errors
} xraudio_opus_stats_t;
```

### Opus Configuration and Initialization
```c
xraudio_opus_object_t xraudio_opus_create(void) {
    // Allocate decoder object with embedded Opus decoder
    size_t opus_size = opus_decoder_get_size(1);  // Mono channel
    xraudio_opus_obj_t *obj = malloc(sizeof(xraudio_opus_obj_t) + opus_size);
    
    if(obj == NULL) return NULL;
    
    // Initialize object
    obj->identifier = XRAUDIO_OPUS_IDENTIFIER;
    obj->decoder = (OpusDecoder *)&obj[1];  // Embedded after struct
    obj->cmd_id_next = XRAUDIO_OPUS_CMD_ID_BEGIN;
    
    // Initialize Opus decoder for 16kHz mono
    int rc = opus_decoder_init(obj->decoder, 16000, 1);
    if(rc != OPUS_OK) {
        XLOGD_ERROR("Failed to initialize Opus decoder: %s", opus_error_str(rc));
        free(obj);
        return NULL;
    }
    
    return obj;
}
```

### Opus Frame Processing

#### Command ID Sequence Management
```c
// Command ID range and sequencing
#define XRAUDIO_OPUS_CMD_ID_BEGIN  (0x20)  // Start of valid range
#define XRAUDIO_OPUS_CMD_ID_END    (0x3F)  // End of valid range

static void xraudio_opus_cmd_id_inc(uint8_t *cmd_id) {
    (*cmd_id)++;
    if(*cmd_id > XRAUDIO_OPUS_CMD_ID_END) {
        *cmd_id = XRAUDIO_OPUS_CMD_ID_BEGIN;  // Wrap around
    }
}

// Frame integrity checking
bool validate_opus_frame(xraudio_opus_obj_t *obj, uint8_t cmd_id) {
    if(cmd_id < XRAUDIO_OPUS_CMD_ID_BEGIN || cmd_id > XRAUDIO_OPUS_CMD_ID_END) {
        XLOGD_ERROR("Invalid command ID: 0x%02X", cmd_id);
        return false;
    }
    
    if(cmd_id != obj->cmd_id_next) {
        XLOGD_ERROR("Discontinuity: got 0x%02X, expected 0x%02X", 
                   cmd_id, obj->cmd_id_next);
        obj->cmd_id_next = cmd_id;  // Resync
    }
    
    xraudio_opus_cmd_id_inc(&obj->cmd_id_next);
    return true;
}
```

#### Frame Deframing and Decoding
```c
// Remove RF4CE framing from Opus packets
int32_t xraudio_opus_deframe(xraudio_opus_object_t object, 
                             uint8_t *inbuf, uint32_t inlen) {
    xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)object;
    
    if(!xraudio_opus_obj_is_valid(obj) || !inbuf) return -1;
    if(inlen < XRAUDIO_OPUS_HEADER_LENGTH + 1) return -1;
    
    // Extract and validate command ID
    uint8_t cmd_id = inbuf[0];
    if(!validate_opus_frame(obj, cmd_id)) return -1;
    
    // Remove header by shifting payload data
    uint8_t *payload = &inbuf[XRAUDIO_OPUS_HEADER_LENGTH];
    for(uint32_t i = XRAUDIO_OPUS_HEADER_LENGTH; i < inlen; i++) {
        *inbuf++ = *payload++;
    }
    
    return inlen - XRAUDIO_OPUS_HEADER_LENGTH;
}

// Decode Opus audio data
int32_t xraudio_opus_decode(xraudio_opus_object_t object, uint8_t framed,
                           uint8_t *inbuf, uint32_t inlen,
                           pcm_t *outbuf, uint32_t outlen) {
    xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)object;
    uint8_t buf_index = 0;
    uint8_t buf_len = inlen;
    
    if(!xraudio_opus_obj_is_valid(obj) || !inbuf || !outbuf) return -1;
    
    // Handle framed input (RF4CE protocol)
    if(framed) {
        if(inlen < XRAUDIO_OPUS_HEADER_LENGTH + 1) return -1;
        
        uint8_t cmd_id = inbuf[0];
        if(!validate_opus_frame(obj, cmd_id)) return -1;
        
        buf_index = XRAUDIO_OPUS_HEADER_LENGTH;
        buf_len = inlen - XRAUDIO_OPUS_HEADER_LENGTH;
    }
    
    // Decode using Opus library
    int samples = opus_decode(obj->decoder, 
                             &inbuf[buf_index], buf_len,
                             outbuf, outlen, 0);
    
    if(samples < 0) {
        XLOGD_ERROR("Opus decode failed: %s", opus_error_str(samples));
        return samples;
    }
    
    return samples * sizeof(pcm_t);  // Return bytes decoded
}
```

### Opus API Interface
```c
// Object lifecycle management
xraudio_opus_object_t xraudio_opus_create(void);         // Create decoder
void                  xraudio_opus_destroy(xraudio_opus_object_t object); // Destroy decoder  
bool                  xraudio_opus_reset(xraudio_opus_object_t object);   // Reset decoder state

// Decoding operations
int32_t xraudio_opus_deframe(xraudio_opus_object_t object,   // Remove framing
                            uint8_t *inbuf, uint32_t inlen);

int32_t xraudio_opus_decode(xraudio_opus_object_t object,    // Decode audio
                           uint8_t framed, 
                           uint8_t *inbuf, uint32_t inlen,
                           pcm_t *outbuf, uint32_t outlen);

// Statistics and diagnostics  
bool    xraudio_opus_stats(xraudio_opus_object_t object,     // Get statistics
                          xraudio_opus_stats_t *stats);
```

### Opus Performance Characteristics
- **Compression Ratio**: Variable (typically 8:1 to 16:1 for voice)
- **Latency**: 20ms frames (configurable down to 2.5ms)
- **Quality**: Excellent voice quality, good music quality
- **CPU Usage**: Moderate computational requirements
- **Memory Usage**: Moderate state (~8KB per decoder)
- **Bitrate Range**: 6 kbps to 510 kbps (voice typically 8-64 kbps)
- **Error Resilience**: Built-in error correction and concealment

## Codec Integration Architecture

### XR Audio Integration Points

#### Common Type Definitions
```c
typedef uint8_t  adpcm_t;     // ADPCM 4-bit samples (packed in bytes)
typedef int16_t  pcm_t;       // 16-bit signed PCM samples (both codecs)

// Common frame structure for both codecs
typedef struct {
    uint8_t  cmd_id;          // Command/sequence identifier
    uint8_t  length;          // Payload length
    uint32_t timestamp;       // Frame timestamp
    uint8_t  payload[];       // Codec-specific data
} xraudio_codec_frame_t;
```

#### Codec Selection and Switching
```c
typedef enum {
    XRAUDIO_CODEC_PCM    = 0,  // Uncompressed PCM
    XRAUDIO_CODEC_ADPCM  = 1,  // ADPCM compression
    XRAUDIO_CODEC_OPUS   = 2,  // Opus compression
    XRAUDIO_CODEC_INVALID = 3
} xraudio_codec_type_t;

// Codec selection based on requirements
xraudio_codec_type_t select_codec(uint32_t bandwidth_kbps, 
                                 uint32_t latency_ms,
                                 xraudio_quality_t quality) {
    if(latency_ms < 5) {
        return XRAUDIO_CODEC_ADPCM;  // Ultra-low latency
    } else if(bandwidth_kbps < 32) {
        return XRAUDIO_CODEC_ADPCM;  // Low bandwidth
    } else if(quality == XRAUDIO_QUALITY_HIGH) {
        return XRAUDIO_CODEC_OPUS;   // High quality
    } else {
        return XRAUDIO_CODEC_PCM;    // No compression needed
    }
}
```

### Error Handling and Recovery

#### ADPCM Error Recovery
```c
// ADPCM packet loss handling 
void handle_adpcm_packet_loss(adpcm_dec_t *decoder, uint32_t lost_count) {
    // ADPCM is relatively resilient to packet loss
    // The predictor will adapt quickly to new data
    decoder->stats.frames_lost += lost_count;
    
    // Optional: reset predictor for large losses
    if(lost_count > 10) {
        decoder->predicted_sample = 0;
        decoder->step_size_index = 0;
    }
}

// ADPCM decoder state validation
bool validate_adpcm_state(adpcm_dec_t *decoder) {
    if(decoder->step_size_index < 0 || decoder->step_size_index > 88) {
        XLOGD_ERROR("Invalid step size index: %d", decoder->step_size_index);
        decoder->step_size_index = 0;  // Reset to safe value
        return false;
    }
    return true;
}
```

#### Opus Error Recovery  
```c
// Opus packet loss concealment
int32_t handle_opus_packet_loss(xraudio_opus_obj_t *obj, 
                               pcm_t *outbuf, uint32_t outlen) {
    // Use Opus built-in packet loss concealment
    int samples = opus_decode(obj->decoder, 
                             NULL, 0,          // NULL input indicates loss
                             outbuf, outlen, 0);
    
    if(samples < 0) {
        XLOGD_ERROR("Opus PLC failed: %s", opus_error_str(samples)); 
        // Fill with silence as fallback
        memset(outbuf, 0, outlen * sizeof(pcm_t));
        return outlen;
    }
    
    return samples * sizeof(pcm_t);
}

// Opus decoder state recovery
bool recover_opus_decoder(xraudio_opus_obj_t *obj) {
    int rc = opus_decoder_ctl(obj->decoder, OPUS_RESET_STATE);
    if(rc != OPUS_OK) {
        XLOGD_ERROR("Failed to reset Opus state: %s", opus_error_str(rc));
        return false;
    }
    
    obj->cmd_id_next = XRAUDIO_OPUS_CMD_ID_BEGIN;
    return true;
}
```

## Performance Comparison and Use Cases

### Codec Characteristics Matrix

| Feature              | ADPCM    | Opus     | PCM      |
|---------------------|----------|----------|----------|
| Compression Ratio   | 4:1      | 8:1-16:1 | 1:1      |
| Latency (typical)   | <1ms     | 20ms     | <1ms     |
| CPU Usage           | Very Low | Moderate | None     |
| Memory Usage        | <16B     | ~8KB     | None     |
| Quality (voice)     | Good     | Excellent| Perfect  |
| Quality (music)     | Poor     | Good     | Perfect  |
| Bandwidth (voice)   | 32 kbps  | 8-64kbps | 256kbps  |
| Error Resilience    | Good     | Excellent| Poor     |
| Complexity          | Low      | High     | None     |

### Use Case Recommendations

#### ADPCM Optimal Scenarios
- **Ultra-low Latency**: Real-time voice interaction with <5ms latency requirements
- **Limited Bandwidth**: Network conditions with <32 kbps available
- **Low CPU Environments**: Resource-constrained embedded systems  
- **Simple Integration**: Applications requiring minimal codec complexity
- **Voice-Only**: Speech communication without music quality requirements

#### Opus Optimal Scenarios
- **High Quality Voice**: Premium voice communication applications
- **Mixed Content**: Voice with background music or sound effects
- **Network Resilience**: Unreliable network conditions requiring error correction
- **Adaptive Quality**: Applications needing dynamic bitrate adjustment
- **Standards Compliance**: Integration with WebRTC or other Opus-based systems

#### Integration Patterns
```c
// Adaptive codec selection based on runtime conditions
typedef struct {
    xraudio_codec_type_t primary_codec;
    xraudio_codec_type_t fallback_codec;
    uint32_t switch_threshold_ms;
    uint32_t switch_threshold_kbps;
} xraudio_codec_policy_t;

// Runtime codec switching
void adapt_codec_selection(xraudio_codec_policy_t *policy,
                          uint32_t current_latency_ms,
                          uint32_t current_bandwidth_kbps) {
    
    if(current_latency_ms > policy->switch_threshold_ms ||
       current_bandwidth_kbps < policy->switch_threshold_kbps) {
        // Switch to more efficient codec
        if(policy->primary_codec == XRAUDIO_CODEC_OPUS) {
            switch_to_adpcm_codec();
            XLOGD_INFO("Switched to ADPCM due to constraints");
        }
    } else {
        // Return to preferred codec when conditions improve
        if(policy->primary_codec == XRAUDIO_CODEC_OPUS) {
            switch_to_opus_codec();
            XLOGD_INFO("Switched to Opus with improved conditions");
        }
    }
}
```

## Debugging and Diagnostics

### ADPCM Diagnostics
```c
// Comprehensive ADPCM diagnostics
void print_adpcm_diagnostics(adpcm_dec_t *decoder) {
    adpcm_decode_stats_t stats;
    if(!adpcm_decode_stats(decoder, &stats)) return;
    
    printf("ADPCM Decoder Statistics:\n");
    printf("  Samples decoded: %u\n", stats.samples_decoded);
    printf("  Frames processed: %u\n", stats.frames_processed);
    printf("  Frames lost: %u (%.2f%%)\n", stats.frames_lost,
           100.0 * stats.frames_lost / stats.frames_processed);
    printf("  Failed decodes: %u\n", stats.failed_decodes);
    printf("  Step size mismatches: %u\n", stats.step_size_mismatch);
    printf("  Predicted sample mismatches: %u\n", stats.predicted_sample_mismatch);
    printf("  Current state: step_index=%d, predicted=%d\n",
           decoder->step_size_index, decoder->predicted_sample);
}
```

### Opus Diagnostics  
```c
// Comprehensive Opus diagnostics
void print_opus_diagnostics(xraudio_opus_obj_t *obj) {
    xraudio_opus_stats_t stats;
    if(!xraudio_opus_stats(obj, &stats)) return;
    
    printf("Opus Decoder Statistics:\n");
    printf("  Packets total: %u\n", stats.packet_total);
    printf("  Packets lost: %u (%.2f%%)\n", stats.packet_lost,
           100.0 * stats.packet_lost / stats.packet_total);
    printf("  Discontinuity errors: %u\n", stats.err_discont);
    printf("  Repeat errors: %u\n", stats.err_repeat);
    printf("  Command ID errors: %u\n", stats.err_cmd_id);
    printf("  Length errors: %u\n", stats.err_cmd_len);
    printf("  Next expected cmd_id: 0x%02X\n", obj->cmd_id_next);
    
    // Query Opus decoder internal state
    opus_int32 lookahead, sample_rate, gain;
    opus_decoder_ctl(obj->decoder, OPUS_GET_LOOKAHEAD(&lookahead));
    opus_decoder_ctl(obj->decoder, OPUS_GET_SAMPLE_RATE(&sample_rate));
    opus_decoder_ctl(obj->decoder, OPUS_GET_GAIN(&gain));
    
    printf("  Opus lookahead: %d samples\n", lookahead);
    printf("  Sample rate: %d Hz\n", sample_rate);
    printf("  Decoder gain: %d\n", gain);
}
```

## Summary

The XR Audio codec implementations provide:

### ADPCM Codec Features:
- **Ultra-Low Latency**: Sub-millisecond processing for real-time interaction
- **Efficient Compression**: 4:1 compression with minimal quality loss for voice
- **Robust Implementation**: Comprehensive error detection and packet loss handling
- **Low Resource Usage**: Minimal CPU and memory requirements
- **Standards Compliance**: IMA/DVI ADPCM compatibility with XR optimizations

### Opus Codec Features:  
- **High Quality Audio**: Excellent voice quality with good music handling
- **Adaptive Compression**: Variable bitrate with network condition adaptation
- **Advanced Error Recovery**: Built-in packet loss concealment and error correction
- **Standards Integration**: Full compatibility with Opus standard and WebRTC
- **Flexible Configuration**: Configurable frame sizes and quality settings

### Integrated Architecture:
- **Codec Abstraction**: Common interfaces enabling runtime codec switching
- **Performance Optimization**: Specialized use case optimization for XR applications
- **Robust Error Handling**: Comprehensive error detection, recovery, and diagnostics
- **Real-time Processing**: Frame-based processing optimized for voice interaction
- **Resource Efficiency**: Optimized implementations for diverse platform requirements

Both codecs serve complementary roles in the XR Voice SDK, with ADPCM providing ultra-low latency for real-time interaction scenarios and Opus delivering high-quality audio for premium voice communication applications.