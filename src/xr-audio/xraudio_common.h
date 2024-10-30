/*
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
*/
#ifndef _XRAUDIO_COMMON_H_
#define _XRAUDIO_COMMON_H_

/// @file xraudio_common.h
///
/// @defgroup XRAUDIO XRAUDIO - COMMON
/// @{
///
/// @defgroup XRAUDIO_DEFINITIONS Constants
/// @defgroup XRAUDIO_ENUMS       Enumerations
/// @defgroup XRAUDIO_STRUCTS     Structures
/// @defgroup XRAUDIO_FUNCTIONS   Functions

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <jansson.h>

#include "xraudio_platform.h"

/// @addtogroup XRAUDIO_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The xraudio library provides macros for some parameters which may change in the future.

#define XRAUDIO_INPUT_FRAME_PERIOD             (20)                                ///< input frame period, milliseconds
#define XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE      (16000)                             ///< input sample rate per channel, Hz
#define XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE      (2)                                 ///< Default input sample size, bytes
#define XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY      (1)                                 ///< Input channel quantity
#define XRAUDIO_INPUT_MAX_CHANNEL_QTY          (4)                                 ///< Maximum input channel quantity
#define XRAUDIO_INPUT_MAX_CHANNEL_QTY_EC_REF   (6)                                 ///< Maximum echo canceller reference channel quantity

#define XRAUDIO_OUTPUT_FRAME_PERIOD            (20)                                ///< Output frame period in milliseconds

#define XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY      (1)                                 ///< Input channel quantity audio to ASR/cloud

#define XRAUDIO_INPUT_KWD_MAX_CHANNEL_QTY      (XRAUDIO_INPUT_MAX_CHANNEL_QTY)     ///< Input channel quantity audio to keyword detector

#define XRAUDIO_INPUT_ADPCM_FRAME_SAMPLE_QTY       (272)
#define XRAUDIO_INPUT_ADPCM_BUFFER_SIZE            (140)

#define XRAUDIO_INPUT_OPUS_FRAME_SAMPLE_QTY        (320)
#define XRAUDIO_INPUT_OPUS_BUFFER_SIZE              (95)

/// @}

/// @addtogroup XRAUDIO_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio library provides enumerated types for logical groups of values.

/// @brief xraudio input devices
/// @details The input devices enumeration indicates all the input devices which may be supported by xraudio.
typedef uint32_t xraudio_devices_input_t;
#define XRAUDIO_DEVICE_INPUT_NONE              (0x0000)
#define XRAUDIO_DEVICE_INPUT_SINGLE            (0x0001)
#define XRAUDIO_DEVICE_INPUT_TRI               (0x0002)
#define XRAUDIO_DEVICE_INPUT_QUAD              (0x0004)
#define XRAUDIO_DEVICE_INPUT_HFP               (0x0008)
#define XRAUDIO_DEVICE_INPUT_MIC_TAP           (0x0010)

#define XRAUDIO_DEVICE_INPUT_EC_REF_NONE       (0x0000)
#define XRAUDIO_DEVICE_INPUT_EC_REF_MONO       (0x0020)
#define XRAUDIO_DEVICE_INPUT_EC_REF_STEREO     (0x0040)
#define XRAUDIO_DEVICE_INPUT_EC_REF_5_1        (0x0080)

#define XRAUDIO_DEVICE_INPUT_PTT               (0x0100)
#define XRAUDIO_DEVICE_INPUT_FF                (0x0200)
#define XRAUDIO_DEVICE_INPUT_INVALID           (0xFFFF)

#define XRAUDIO_DEVICE_INPUT_LOCAL_GET(x)      (x & 0x001F)
#define XRAUDIO_DEVICE_INPUT_EC_REF_GET(x)     (x & 0x00E0)
#define XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(x)   (x & 0xFF00)
#define XRAUDIO_DEVICE_INPUT_CONTAINS(x, y)    (x & y)

/// @brief xraudio output devices
/// @details The output devices enumeration indicates all the speaker devices which may be supported by xraudio.
typedef uint32_t xraudio_devices_output_t;
#define XRAUDIO_DEVICE_OUTPUT_NONE             (0x0000)
#define XRAUDIO_DEVICE_OUTPUT_NORMAL           (0x0001)
#define XRAUDIO_DEVICE_OUTPUT_EC_REF           (0x0002)
#define XRAUDIO_DEVICE_OUTPUT_OFFLOAD          (0x0004)
#define XRAUDIO_DEVICE_OUTPUT_HFP              (0x0008)
#define XRAUDIO_DEVICE_OUTPUT_INVALID          (0xFFFF)

#define XRAUDIO_STATISTICS_INVALID                    (0x00000000)                   ///< Invalid statistics entry
#define XRAUDIO_STATISTICS_INPUT_GENERAL              (0x00000001)                   ///< General microphone statistics
#define XRAUDIO_STATISTICS_INPUT_TIMING               (0x00000002)                   ///< Microphone timing statistics
#define XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_REGULAR  (0x00000004)                   ///< Microphone regular sound focus statistics
#define XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_BLOCKING (0x00000008)                   ///< Microphone blocking sound focus statistics
#define XRAUDIO_STATISTICS_OUTPUT_GENERAL             (0x00010000)                   ///< General speaker statistics
#define XRAUDIO_STATISTICS_OUTPUT_TIMING              (0x00020000)                   ///< Speaker timing statistics
#define XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_ALL      (XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_REGULAR | XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_BLOCKING)                                                                  ///< All sound focus statistics
#define XRAUDIO_STATISTICS_INPUT_ALL                  (XRAUDIO_STATISTICS_INPUT_GENERAL | XRAUDIO_STATISTICS_INPUT_TIMING | XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_REGULAR | XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_BLOCKING) ///< All microphone statistics
#define XRAUDIO_STATISTICS_OUTPUT_ALL                 (XRAUDIO_STATISTICS_OUTPUT_GENERAL | XRAUDIO_STATISTICS_OUTPUT_TIMING)                                                                                          ///< All speaker statistics
#define XRAUDIO_STATISTICS_ALL                        (XRAUDIO_STATISTICS_INPUT_ALL | XRAUDIO_STATISTICS_OUTPUT_ALL)                                                                                                  ///< All statistics

/// @brief Audio Container Types
/// @details The container enumeration indicates all the valid audio container types which may be supported by xraudio.
typedef enum {
   XRAUDIO_CONTAINER_NONE    = 0, ///< No container is present (raw audio data)
   XRAUDIO_CONTAINER_WAV     = 1, ///< Wave container is present
   XRAUDIO_CONTAINER_MP3     = 2, ///< MP3 container is present
   XRAUDIO_CONTAINER_INVALID = 3, ///< Invalid container
} xraudio_container_t;

/// @brief Audio Encoding Types
/// @details The encoding enumeration indicates all the valid audio encoding types which may be supported by xraudio.
typedef enum {
   XRAUDIO_ENCODING_PCM         = 0, ///< PCM encoding (16-bit integer little endian)
   XRAUDIO_ENCODING_PCM_RAW     = 1, ///< Raw unprocessed PCM encoding (32-bit integer little endian)
   XRAUDIO_ENCODING_ADPCM_FRAME = 2, ///< ADPCM encoding (with framing)
   XRAUDIO_ENCODING_ADPCM       = 3, ///< ADPCM encoding (standard)
   XRAUDIO_ENCODING_OPUS_XVP    = 4, ///< OPUS encoding (with XVP framing)
   XRAUDIO_ENCODING_OPUS        = 5, ///< OPUS encoding (standard)
   XRAUDIO_ENCODING_INVALID     = 6, ///< Invalid encoding
} xraudio_encoding_type_t;

/// @brief Audio stream latency mode Types
/// @details The audio stream latency enumeration indicates all the latency modes supported by xraudio.
typedef enum {
   XRAUDIO_STREAM_LATENCY_NORMAL      = 0, ///< Default stream processing with normal latency
   XRAUDIO_STREAM_LATENCY_LOW         = 1, ///< Stream processing optimized for low latency
   XRAUDIO_STREAM_LATENCY_INVALID     = 2, ///< Invalid stream latency type
} xraudio_stream_latency_mode_t;

/// @brief Audio stream CPU utilization mode Types
/// @details The audio stream cpu utilization mode enumeration indicates all the cpu utilization modes supported by xraudio.
typedef enum {
   XRAUDIO_STREAM_CPU_UTIL_NORMAL      = 0, ///< Default stream processing with normal cpu utilization
   XRAUDIO_STREAM_CPU_UTIL_LOW         = 1, ///< Stream processing optimized for low cpu utilization
   XRAUDIO_STREAM_CPU_UTIL_INVALID     = 2, ///< Invalid cpu utilization type
} xraudio_stream_cpu_util_mode_t;

/// @brief xraudio interval type
/// @details The interval type used with xraudio for time synchronization.
typedef struct timeval  xraudio_interval_t;

/// @brief xraudio_volume_step_t
/// @details The xraudio volume control step type. Each step of a variable of this type changes the volume one pre-configured dB step size.
typedef int8_t          xraudio_volume_step_t;

/// @brief xraudio_volume_step_size_t
/// @details The xraudio volume control step size in dB per step increment.
typedef float           xraudio_volume_step_size_t;

/// @}

/// @addtogroup XRAUDIO_STRUCTS
/// @{
/// @brief Structure definitions
/// @details The xraudio client api provides structures that are used in function calls.

typedef struct {
   uint8_t size_packet;
   uint8_t size_header;
   uint8_t offset_step_size_index;
   uint8_t offset_predicted_sample_lsb;
   uint8_t offset_predicted_sample_msb;
   uint8_t offset_sequence_value;
   uint8_t sequence_value_min;
   uint8_t sequence_value_max;
} xraudio_adpcm_frame_t;

typedef struct {
   xraudio_encoding_type_t type;
   union {
      xraudio_adpcm_frame_t adpcm_frame;
   } value;
} xraudio_encoding_t;

/// @brief xraudio input format structure
/// @details The input format for incoming audio data.
typedef struct {
   xraudio_container_t container;   ///< audio container type
   xraudio_encoding_t  encoding;    ///< audio encoding type
   uint32_t            sample_rate; ///< sample rate (in Hertz)
   uint8_t             sample_size; ///< sample size (in bytes)
   uint8_t             channel_qty; ///< channel quantity (1=mono, 2=stereo, etc)
} xraudio_input_format_t;

/// @brief xraudio output format structure
/// @details The output format for outgoing audio data.
typedef struct {
   xraudio_container_t container;   ///< audio container type
   xraudio_encoding_t  encoding;    ///< audio encoding type
   uint32_t            sample_rate; ///< sample rate (in Hertz)
   uint8_t             sample_size; ///< sample size (in bytes)
   uint8_t             channel_qty; ///< channel quantity (1=mono, 2=stereo, etc)
} xraudio_output_format_t;

/// @brief Power Mode Types
/// @details The power mode enumeration indicates the power modes which may be supported.
typedef enum {
   XRAUDIO_POWER_MODE_FULL    = 0, ///< Full power mode
   XRAUDIO_POWER_MODE_LOW     = 1, ///< Low power mode
   XRAUDIO_POWER_MODE_SLEEP   = 2, ///< Lower power mode
   XRAUDIO_POWER_MODE_INVALID = 3, ///< Invalid power mode type
} xraudio_power_mode_t;

/// @brief Single Channel Mode Types
/// @details Modifier used to specify single channel processing mode requested
typedef enum {
   XRAUDIO_SINGLE_CHANNEL_ONLY      = 0,  ///< Process only specified channel
   XRAUDIO_SINGLE_CHANNEL_SKIP      = 1,  ///< Process all channels except specified channel
   XRAUDIO_SINGLE_CHANNEL_INVALID   = 2,  ///< Invalid single channel processing modifier
} xraudio_single_chan_mode_t;

/// @}

/// @addtogroup XRAUDIO_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio library provides functions to be called directly by the user application.

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Convert the input device type to a string
const char *     xraudio_devices_input_str(xraudio_devices_input_t type);
/// @brief Convert the output device type to a string
const char *     xraudio_devices_output_str(xraudio_devices_output_t type);
/// @brief Convert the channel quantity to a string
const char *     xraudio_channel_qty_str(unsigned char channel_qty);
/// @brief Convert the container type to a string
const char *     xraudio_container_str(xraudio_container_t type);
/// @brief Convert the encoding type to a string
const char *     xraudio_encoding_str(xraudio_encoding_type_t type);
/// @brief Convert the xraudio_power_mode_t type to a string
const char *     xraudio_power_mode_str(xraudio_power_mode_t type);

#ifdef __cplusplus
}
#endif
/// @}
/// @}

#endif
