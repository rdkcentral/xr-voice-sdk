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
#ifndef _XRAUDIO_PPR_H_
#define _XRAUDIO_PPR_H_

#include <stdint.h>
#include <stdbool.h>
#include <xraudio_version.h>

/// @file xraudio_ppr.h
///
/// @defgroup XRAUDIO_PPR COMPONENT - DSP Preprocessing Function Block for XRAUDIO
/// @{
///
/// @defgroup XRAUDIO_PPR_DEFINITIONS Constants
/// @defgroup XRAUDIO_PPR_TYPEDEFS    Typedefs
/// @defgroup XRAUDIO_PPR_ENUMS       Enumerations
/// @defgroup XRAUDIO_PPR_STRUCTS     Structures
/// @defgroup XRAUDIO_PPR_FUNCTIONS   Functions
///

/// @addtogroup XRAUDIO_PPR_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The xraudio preprocessor provides macros for some parameters which may change in the future.  Clients should use
/// these names to allow the client code to function correctly if the values change.

#define XRAUDIO_PPR_MAX_MICS 8
#define XRAUDIO_PPR_MAX_REFS 7

/// @}

/// @addtogroup XRAUDIO_PPR_TYPEDEFS
/// @{
/// @brief Type Definitions
/// @details The xraudio preprocess api provides structures for grouping of values.

typedef void* xraudio_ppr_object_t;           ///< An opaque type for the xraudio_ppr object.

/// @}

/// @addtogroup XRAUDIO_PPR_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio preprocess api provides enumerated types for logical groups of values.

/// @brief xraudio preprocess configure sources
/// @details The configure sources enumeration indicates data sources available for configuring xraudio_ppr
typedef enum {
   XRAUDIO_PPR_CONFIG_SOURCE_FILE     = 0,
   XRAUDIO_PPR_CONFIG_SOURCE_TUNING   = 1,
   XRAUDIO_PPR_CONFIG_SOURCE_JSON     = 2,
   XRAUDIO_PPR_CONFIG_SOURCE_INVALID  = 3,
} xraudio_ppr_config_source_t;

/// @brief xraudio preprocess commands
/// @details The commands enumeration indicates all commands available to execute by xraudio_ppr
typedef enum {
   XRAUDIO_PPR_COMMAND_KEYWORD_DETECT        = 0,  ///< Keyword was detected, session beginning
   XRAUDIO_PPR_COMMAND_PUSH_TO_TALK          = 1,  ///< User pressed push-to-talk
   XRAUDIO_PPR_PRIVACY                       = 2,  ///< Privacy is enabled
   XRAUDIO_PPR_END_PRIVACY                   = 3,  ///< Privacy is disabled
   XRAUDIO_PPR_COMMAND_END_OF_SESSION        = 4,  ///< Streaming session has ended
   XRAUDIO_PPR_COMMAND_TUNING_INTERFACE_ON   = 5,  ///< Tuning interface is enabled
   XRAUDIO_PPR_COMMAND_TUNING_INTERFACE_OFF  = 6,  ///< Tuning interface is disabled
   XRAUDIO_PPR_COMMAND_INVALID               = 7
} xraudio_ppr_command_t;

/// @brief xraudio preprocess events
/// @details Events that can be returned by xraudio_ppr_run()
///
typedef enum {
   XRAUDIO_PPR_EVENT_NONE                       = 0,  ///< No event
   XRAUDIO_PPR_EVENT_STARTOFSPEECH              = 1,  ///< Start of speech was just detected
   XRAUDIO_PPR_EVENT_ENDOFSPEECH                = 2,  ///< End of speech was detected
   XRAUDIO_PPR_EVENT_TIMEOUT_INITIAL            = 3,  ///< No speech detected within timeout period
   XRAUDIO_PPR_EVENT_TIMEOUT_END                = 4,  ///< No end of speech detected within timeout period
   XRAUDIO_PPR_EVENT_LOCAL_KEYWORD_DETECTED     = 5,  ///< Keyword has been detected on local mic input/stream
   XRAUDIO_PPR_EVENT_REFERENCE_KEYWORD_DETECTED = 6,  ///< Keyword has been detected in reference stream (TV audio)
   XRAUDIO_PPR_EVENT_INVALID                    = 7
} xraudio_ppr_event_t;

/// @brief xraudio preprocess stream types
/// @details The stream types enumeration supported by xraudio ppr
typedef enum {
   XRAUDIO_PPR_STREAM_TYPE_KEYWORD  = 0,
   XRAUDIO_PPR_STREAM_TYPE_ASR      = 1,
   XRAUDIO_PPR_STREAM_TYPE_REF      = 2,
   XRAUDIO_PPR_STREAM_TYPE_INVALID  = 3
} xraudio_ppr_stream_t;

/// @brief xraudio preprocess stream lookback buffer offset
/// @details The stream lookback buffer offset options supported by xraudio ppr
typedef enum {
   XRAUDIO_PPR_STREAM_OFFSET_NOW             = 0,  ///< Lookback request is with respect to current sample time
   XRAUDIO_PPR_STREAM_OFFSET_KEYWORD_START   = 1,  ///< Lookback request is with respect to keyword start time
   XRAUDIO_PPR_STREAM_OFFSET_KEYWORD_END     = 2,  ///< Lookback request is with respect to keyword end time
   XRAUDIO_PPR_STREAM_OFFSET_INVALID         = 3
} xraudio_ppr_stream_offset_t;

/// @brief xraudio preprocess PCM formats
/// @details The PCM format types supported by xraudio ppr
typedef enum {
   XRAUDIO_PPR_FORMAT_PCM16      = 0,  ///< 16 bit PCM
   XRAUDIO_PPR_FORMAT_PCM24LJ    = 1,  ///< 24 bit PCM, left justified in a 32-bit number
   XRAUDIO_PPR_FORMAT_PCM24RJ    = 2,  ///< 24-bit PCM, right justified and sign extended in a 32-bit number
   XRAUDIO_PPR_FORMAT_PCM32      = 3,  ///< 32-bit PCM
   XRAUDIO_PPR_FORMAT_PCMFLOAT   = 4,  ///< 32-bit floating point
   XRAUDIO_PPR_FORMAT_INVALID    = 5
} xraudio_ppr_pcm_format_t;

/// @}

/// @addtogroup XRAUDIO_PPR_STRUCTS
/// @{
/// @brief Preprocess structure definitions
/// @details The xraudio preprocess api provides structures for grouping of values.

/// @brief xraudio preprocess status
/// @details Status information returned by xraudio_dspblock_get_status()
typedef struct {
    float  snr;
    float  mic_levels_dbfs[XRAUDIO_PPR_MAX_MICS];   ///< Mic levels, specified in dBFS
    float  ref_levels_dbfs[XRAUDIO_PPR_MAX_REFS];   ///< Reference input levels, specified in dBFS
    float  erledb[XRAUDIO_PPR_MAX_MICS];            ///< AEC Echo Return Loss Enhancement (ERLE) values, specified in dB
    float  erldB[XRAUDIO_PPR_MAX_MICS];             ///< Echo Return Loss (ERL) values measured in dB
    char * dsp_name;                                 ///< Name of DSP preprocessing in use
} xraudio_ppr_status_t;

/// @}

/// @addtogroup XRAUDIO_PPR_FUNCTIONS
/// @{
/// @brief Preprocess function definitions
/// @details The xraudio preprocess api provides functions to be called directly by xraudio.

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Retrieve the preprocess version
/// @details Retrieves the detailed version information for the xraudio_ppr component.
/// @param[in] version_info Pointer to an array of version information structures
/// @param[inout] qty       Quantity of entries in the version_info array (in), qty of entries populated (out).
/// @return The function has no return value.  It returns the version info for each component.
void                 xraudio_ppr_version(xraudio_version_info_t *version_info, uint32_t *qty);

/// @brief Create preprocess object
/// @details Create an xraudio preprocess component object and initializes it with parameters provided
/// @param[in] params   Reference to a JSON config parameters object.
/// @return The function returns a reference to the object or NULL if an error occurred.
xraudio_ppr_object_t xraudio_ppr_object_create(const json_t *params);

/// @brief Preprocess initialization
/// @details Initializes or reinitializes a preprocess instance
/// @param[in] object   Reference to a preprocess object.
/// @return The function returns true for success and false for failure.
bool    xraudio_ppr_init(xraudio_ppr_object_t object);

/// @brief Destroy preprocess object
/// @details Destroy an xraudio preprocess object. If resources have been allocated, they will be released.
/// @param[in] object   Reference to an xraudio preprocess object.
/// @return The function has no return value.
void    xraudio_ppr_object_destroy(xraudio_ppr_object_t object);

/// @brief Run preprocess
/// @details The xraudio preprocess run function inputs the mic and reference streams and outputs the keyword,
/// asr, and reference output streams. Each input and output buffer is specified by a pointer (pp_xxx) to a
/// pointer of buffer arrays. The number of arrays per ppxxx paramter depends upon how many channels each
/// stream has been configured for at init time. The number of samples per buffer is specified by frame_size_in_samples.
/// To be clear, the pp_xxx pointers and the arrays buffers that they point to are all "owned" by the calling function (xraudio)
/// As an example, if we have 4 microphones, we have
///   ppmic_input_buffers[0] -> MicBuffer0[frame_size_in_samples]
///   ppmic_input_buffers[1] -> MicBuffer1[frame_size_in_samples]
///   ppmic_input_buffers[2] -> MicBuffer2[frame_size_in_samples]
///   ppmic_input_buffers[3] -> MicBuffer3[frame_size_in_samples]
/// @param[in]    object                  Reference to an xraudio preprocess object.
/// @param[in]    frame_size_in_samples   Number of samples in a frame
/// @param[in]    ppmic_input_buffers,    pointer to array of mic input buffer pointers
/// @param[in]    ppref_input_buffers,    pointer to array of reference input buffer pointers
/// @param[out]   ppkwd_output_buffers,   pointer to array of keyword stream output buffers
/// @param[out]   ppasr_output_buffers,   pointer to array of asr stream output buffers
/// @param[out]   ppref_output_buffers    pointer to array of reference output buffers
/// @return The function returns an event value
xraudio_ppr_event_t xraudio_ppr_run(
            xraudio_ppr_object_t object,
            uint16_t frame_size_in_samples,
            const int32_t** ppmic_input_buffers,   ///< pointer to array of mic input buffer pointers
            const int32_t** ppref_input_buffers,   ///< pointer to array of reference input buffer pointers
            int32_t** ppkwd_output_buffers,        ///< pointer to array of keyword stream output buffers
            int32_t** ppasr_output_buffers,        ///< pointer to array of asr stream output buffers
            int32_t** ppref_output_buffers         ///< pointer to array of reference output buffers
            );

/// @brief Preprocess command
/// @details Used by xraudio to issue a command to the preprocess
/// @param[in]    object      Reference to an xraudio preprocess object.
/// @param[in]    command     Command value to issue to preprocess
/// @return The function has no return value.
void    xraudio_ppr_command(xraudio_ppr_object_t object, xraudio_ppr_command_t command);

/// @brief Preprocess status
/// @details Used by xraudio to retrieve status information from the preprocess
/// @param[in]    object      Reference to an xraudio preprocess object.
/// @param[out]   status      Reference to status data structure
/// @return The function has no return value.
void    xraudio_ppr_get_status(xraudio_ppr_object_t object, xraudio_ppr_status_t *status);

/// @brief Preprocess lookback buffer data
/// @details Used by xraudio to retrieve past samples of a specified channel within a specified stream
/// @param[in]    object                  Reference to an xraudio preprocess object.
/// @param[in]    stream                  Type of stream to retrieve lookback (keyword or reference)
/// @param[in]    channel                 Channel number in the stream or -1 for composite of all channels in stream
/// @param[in]    offset_type             Event from which offset_in_samples is referenced
/// @param[in]    offset_in_samples       Offset into lookback buffer to retrieve first sample
/// @param[in]    num_requested_samples   Number of requested number of samples to return
/// @param[in]    format                  Format of PCM samples to return
/// @param[out]   psamples                Pointer to destination buffer of selected lookback samples. psamples must have enough space to hold number of requested samples.
/// @param[out]   n_samples_returned      actual number of samples returned
/// @return The function has no return value.
void    xraudio_ppr_get_lookback_pcm(
            xraudio_ppr_object_t object,
            xraudio_ppr_stream_t stream,              ///< which stream's lookback to pull from (keyword or reference)
            uint8_t channel,                          ///< which channel in the stream. -1 for composite of all channels in stream
            xraudio_ppr_stream_offset_t offset_type,  ///< event from which offset_in_samples is referenced
            int32_t offset_in_samples,                ///< first sample to retrieve in lookback buffer
            uint32_t num_requested_samples,           ///< requested number of samples to return
            xraudio_ppr_pcm_format_t format,          ///< Format of samples to return
            void *psamples,                           ///< pointer to destination of selected lookback samples.
                                                      ///< psamples must contain sufficient space to hold up to num_requested_samples samples.
            uint32_t *n_samples_returned              ///< actual number of samples returned
            );

#ifdef __cplusplus
}
#endif

/// @}

/// @}

#endif //_XRAUDIO_PPR_H_
