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
#ifndef _XRAUDIO_MFV_H_
#define _XRAUDIO_MFV_H_

/// @file xraudio_mfv.h
///
/// @defgroup XRAUDIO_MFV XRAUDIO - MID-FIELD VOICE
/// @{
///
/// @defgroup XRAUDIO_MFV_DEFINES     Defines
/// @defgroup XRAUDIO_MFV_TYPEDEFS    Type Definitions
/// @defgroup XRAUDIO_MFV_ENUMS       Enumerations
/// @defgroup XRAUDIO_MFV_STRUCTS     Structures
/// @defgroup XRAUDIO_MFV_FUNCTIONS   Functions
///

#include <stdbool.h>
#include <stdint.h>
#include <jansson.h>

/// @addtogroup XRAUDIO_MFV_DEFINES
/// @{
/// @brief Defines
/// @details The xraudio MFV api provides defines for the plugin API version and capability flags.

#ifndef XRAUDIO_MFV_API_VERSION
/// @brief MFV plugin API version
#define XRAUDIO_MFV_API_VERSION 1
#endif

/// @brief No capabilities supported
#define XRAUDIO_MFV_CAPS_NONE               (0x0000)
/// @brief Supports audio gain adjustment on the input audio stream
#define XRAUDIO_MFV_CAPS_AUDIO_GAIN         (0x0001)
/// @brief Supports keyword validation
#define XRAUDIO_MFV_CAPS_KWD_VALIDATION     (0x0002)
/// @brief Supports end-of-speech detection
#define XRAUDIO_MFV_CAPS_EOS_DETECTION      (0x0004)
/// @brief Supports reference audio stream (e.g. keyword detection in reference audio)
#define XRAUDIO_MFV_CAPS_REFERENCE_AUDIO    (0x0008)

/// @}

/// @addtogroup XRAUDIO_MFV_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio MFV api provides enumerated types for logical groups of values.

/// @brief MFV result codes
/// @details The xraudio_mfv_result_t enumeration indicates the result of an MFV api operation.
typedef enum {
   XRAUDIO_MFV_RESULT_SUCCESS        = 0, ///< Operation completed successfully
   XRAUDIO_MFV_RESULT_ERROR_PARAMS   = 1, ///< Operation failed due to invalid parameters
   XRAUDIO_MFV_RESULT_ERROR_INTERNAL = 2, ///< Operation failed due to an internal error
   XRAUDIO_MFV_RESULT_INVALID        = 3, ///< Invalid result code (sentinel)
} xraudio_mfv_result_t;

/// @brief MFV end-of-speech result codes
/// @details The xraudio_mfv_eos_result_t enumeration indicates the outcome of end-of-speech detection for a session.
typedef enum {
   XRAUDIO_MFV_EOS_RESULT_UNAVAILABLE     = 0, ///< EOS detection result is unavailable
   XRAUDIO_MFV_EOS_RESULT_SUCCESS         = 1, ///< End of speech was successfully detected
   XRAUDIO_MFV_EOS_RESULT_TIMEOUT_INITIAL = 2, ///< Timed out waiting for initial speech to begin
   XRAUDIO_MFV_EOS_RESULT_TIMEOUT_FINAL   = 3, ///< Timed out waiting for end of speech
   XRAUDIO_MFV_EOS_RESULT_INVALID         = 4, ///< Invalid EOS result code (sentinel)
} xraudio_mfv_eos_result_t;

/// @brief MFV detection types
/// @details The xraudio_mfv_detection_t enumeration indicates the detection type for a session.
typedef enum {
   XRAUDIO_MFV_DETECTION_ACTIVE = 0, ///< Keyword detected while microphone is active (e.g. not asleep)
   XRAUDIO_MFV_DETECTION_ASLEEP = 1, ///< Keyword detected while microphone is asleep
} xraudio_mfv_detection_t;

/// @brief MFV message types
/// @details The xraudio_mfv_msg_type_t enumeration identifies the type of an asynchronous MFV event message.
typedef enum {
   XRAUDIO_MFV_MSG_TYPE_KEYWORD_DETECTED = 0, ///< A keyword detection event has occurred
   XRAUDIO_MFV_MSG_TYPE_ERROR            = 1, ///< An error event has occurred
   XRAUDIO_MFV_MSG_TYPE_INVALID          = 2  ///< Invalid message type (sentinel)
} xraudio_mfv_msg_type_t;

/// @brief MFV error codes
/// @details The xraudio_mfv_error_t enumeration indicates the specific type of error that occurred during processing.
typedef enum {
   XRAUDIO_MFV_ERROR_AUDIO_REFERENCE_READ = 0, ///< Error reading from the reference audio stream
   XRAUDIO_MFV_ERROR_AUDIO_OUTPUT_WRITE   = 1, ///< Error writing to the audio output stream
   XRAUDIO_MFV_ERROR_INTERNAL             = 2, ///< Internal plugin error
   XRAUDIO_MFV_ERROR_INVALID              = 3  ///< Invalid error code (sentinel)
} xraudio_mfv_error_t;

/// @}

/// @addtogroup XRAUDIO_MFV_STRUCTS
/// @{
/// @brief Structures
/// @details The xraudio MFV api provides structures for passing data to and from the plugin interface.

/// @brief MFV message header
/// @details Common header embedded at the start of every MFV event message structure.
typedef struct {
   xraudio_mfv_msg_type_t  type; ///< The type of the message
} xraudio_mfv_msg_header_t;

/// @brief MFV keyword detected message
/// @details Message payload delivered via callback when a keyword is detected in the audio stream.
typedef struct {
   xraudio_mfv_msg_header_t header;     ///< Message header (type == XRAUDIO_MFV_MSG_TYPE_KEYWORD_DETECTED)
   float                    confidence; ///< Keyword detection confidence score
} xraudio_mfv_msg_keyword_detected_t;

/// @brief MFV error message
/// @details Message payload delivered via callback when an error event occurs.
typedef struct {
   xraudio_mfv_msg_header_t  header; ///< Message header (type == XRAUDIO_MFV_MSG_TYPE_ERROR)
   xraudio_mfv_error_t       error;  ///< The specific error that occurred
} xraudio_mfv_msg_error_t;

/// @brief MFV session configuration
/// @details Specifies which optional processing features should be enabled for an MFV session.
typedef struct {
   bool apply_gain;           ///< true if gain should be applied to the input audio stream, false otherwise
   bool validate_keyword;     ///< true if keyword should be validated, false otherwise
   bool detect_end_of_speech; ///< true if end of speech should be detected, false otherwise
} xraudio_mfv_session_info_t;

/// @brief MFV keyword detection information
/// @details Provides details about a keyword found in the audio stream.
typedef struct {
   xraudio_mfv_detection_t detection;      ///< detection type indicating whether the keyword was detected while microphone is active or asleep
   int32_t                 keyword_start;  ///< sample offset to start of keyword in audio stream (negative value indicates keyword start is unknown)
   int32_t                 keyword_end;    ///< sample offset to end of keyword in audio stream (negative value indicates keyword end is unknown)
   float                   confidence;     ///< keyword detection confidence
} xraudio_mfv_keyword_info_t;

/// @brief MFV audio processing result
/// @details Returned by xraudio_mfv_func_session_process_audio_t to report per-call keyword and EOS status.
typedef struct {
   bool is_keyword_invalid; ///< true if the keyword has been declared invalid and should be ignored, false otherwise
   bool is_end_of_speech;   ///< true if the end of speech has been declared in the input audio stream, false otherwise
} xraudio_mfv_process_result_t;

/// @brief MFV session statistics
/// @details Aggregated statistics collected over the lifetime of an MFV processing session.
typedef struct {
   uint32_t                 total_audio_samples;    ///< total number of audio samples processed in the session
   bool                     keyword_validated;      ///< true if the keyword has been validated, false otherwise
   float                    keyword_confidence;     ///< the confidence of the keyword detection/validation (value between 0.0 and 1.0, or a negative value if not applicable)
   xraudio_mfv_eos_result_t end_of_speech_result;   ///< result code for end of speech detection
   bool                     gain_applied;           ///< true if gain has been applied to the input audio stream, false otherwise
   float                    gain_value;             ///< the gain applied to the input audio stream in dB
} xraudio_mfv_session_stats_t;

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRAUDIO_MFV_TYPEDEFS
/// @{
/// @brief Type Definitions
/// @details The xraudio MFV api provides type definitions for opaque handles and callback function pointers.

/// @brief MFV object handle
/// @details An opaque handle representing an MFV plugin instance. Returned by xraudio_mfv_func_object_create_t and passed to all subsequent MFV api calls.
typedef void *xraudio_mfv_object_t;

/// @brief MFV message callback
/// @details Callback function invoked by the MFV plugin to deliver asynchronous event messages to the caller.
/// @param[in] msg  Pointer to the message structure; cast to the appropriate type based on the embedded header type field
/// @return true if the message was consumed successfully, false otherwise
typedef bool (*xraudio_mfv_msg_callback_t)(void *msg);

/// @}

/// @addtogroup XRAUDIO_MFV_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio MFV api provides function pointer types that form the plugin interface contract.

/// @brief Create an MFV plugin object
/// @details Allocates and initializes an MFV plugin instance using the provided JSON configuration.
/// @param[in] config  JSON object containing plugin-specific configuration parameters
/// @return An opaque MFV object handle on success, or NULL on failure
typedef xraudio_mfv_object_t (*xraudio_mfv_func_object_create_t)(const json_t *config);

/// @brief Destroy an MFV plugin object
/// @details Releases all resources associated with the MFV object. The handle must not be used after this call.
/// @param[in] object  The MFV object handle to destroy
typedef void                 (*xraudio_mfv_func_object_destroy_t)(xraudio_mfv_object_t object);

/// @brief Open an MFV processing session
/// @details Begins an MFV processing session with the specified configuration and callback.
/// @param[in]  object     The MFV object handle
/// @param[in]  info       Pointer to the session configuration specifying which features to enable
/// @param[out] output_fd  File descriptor for the processed audio output stream
/// @param[in]  callback   Callback function invoked to deliver asynchronous event messages
/// @return XRAUDIO_MFV_RESULT_SUCCESS on success, or an error code on failure
typedef xraudio_mfv_result_t (*xraudio_mfv_func_session_open_t)(xraudio_mfv_object_t object, const xraudio_mfv_session_info_t *info, int *output_fd, xraudio_mfv_msg_callback_t callback);

/// @brief Close an MFV processing session
/// @details Ends the current MFV processing session and optionally retrieves accumulated statistics.
/// @param[in]  object  The MFV object handle
/// @param[out] stats   Pointer to a structure to receive session statistics, or NULL to discard
typedef void                 (*xraudio_mfv_func_session_close_t)(xraudio_mfv_object_t object, xraudio_mfv_session_stats_t *stats);

/// @brief Provide additional information for the session
/// @details Provides information which is not available at the start of the active session.
/// @param[in]  object  The MFV object handle
/// @param[in]  info    Pointer to a structure with the keyword detection details
/// @return XRAUDIO_MFV_RESULT_SUCCESS on success, or an error code on failure
typedef xraudio_mfv_result_t (*xraudio_mfv_func_session_info_t)(xraudio_mfv_object_t object, const xraudio_mfv_keyword_info_t *info);

/// @brief Process a block of audio samples
/// @details Submits a buffer of PCM audio samples for MFV processing and returns per-call results.
/// @param[in]  object         The MFV object handle
/// @param[in]  sample_buffer  Pointer to the array of 16-bit PCM audio samples to process
/// @param[in]  sample_qty     Number of samples in sample_buffer
/// @param[out] result         Pointer to a structure to receive the processing result for this call
/// @return XRAUDIO_MFV_RESULT_SUCCESS on success, or an error code on failure
typedef xraudio_mfv_result_t (*xraudio_mfv_func_session_process_audio_t)(xraudio_mfv_object_t object, const int16_t *sample_buffer, uint32_t sample_qty, xraudio_mfv_process_result_t *result);

/// @brief Open the reference audio stream
/// @details Registers a reference audio file descriptor for use in reference-channel processing (e.g. AEC).
/// @param[in] object    The MFV object handle
/// @param[in] fd        File descriptor of the reference audio input stream
/// @param[in] callback  Callback function invoked to deliver events from the reference stream
/// @return XRAUDIO_MFV_RESULT_SUCCESS on success, or an error code on failure
typedef xraudio_mfv_result_t (*xraudio_mfv_func_reference_audio_open_t)(xraudio_mfv_object_t object, int fd, xraudio_mfv_msg_callback_t callback);

/// @brief Close the reference audio stream
/// @details Deregisters and releases the reference audio stream previously opened with xraudio_mfv_func_reference_audio_open_t.
/// @param[in] object  The MFV object handle
typedef void                 (*xraudio_mfv_func_reference_audio_close_t)(xraudio_mfv_object_t object);

/// @brief MFV plugin API interface
/// @details Structure containing the API version, capability flags, and all function pointers that constitute the MFV plugin interface. An MFV plugin shared library exports this structure via xraudio_mfv_plugin_api_get().
typedef struct {
   uint16_t                                       api_version;           ///< Plugin API version
   uint16_t                                       capabilities;          ///< Bitmask of supported capabilities (XRAUDIO_MFV_CAPS_* flags)
   xraudio_mfv_func_object_create_t               object_create;         ///< Create a new MFV plugin instance
   xraudio_mfv_func_object_destroy_t              object_destroy;        ///< Destroy an MFV plugin instance
   xraudio_mfv_func_session_open_t                session_open;          ///< Open a new MFV processing session
   xraudio_mfv_func_session_close_t               session_close;         ///< Close the current MFV processing session
   xraudio_mfv_func_session_info_t                session_info;          ///< Provide keyword detection information for the active session
   xraudio_mfv_func_session_process_audio_t       session_process_audio; ///< Process a block of PCM audio samples
   xraudio_mfv_func_reference_audio_open_t        reference_audio_open;  ///< Open the reference audio stream
   xraudio_mfv_func_reference_audio_close_t       reference_audio_close; ///< Close the reference audio stream
} xraudio_mfv_plugin_api_t;

/// @brief Function pointer type for the MFV plugin entry point
/// @details Type of the symbol exported by an MFV plugin shared library to expose its API.
typedef xraudio_mfv_plugin_api_t *(*xraudio_mfv_plugin_api_get_t)(void);

/// @brief Retrieve the MFV plugin API
/// @details Returns a pointer to the statically defined xraudio_mfv_plugin_api_t structure for the built-in MFV plugin implementation.
/// @return Pointer to the xraudio_mfv_plugin_api_t structure exposed by this plugin
xraudio_mfv_plugin_api_t *xraudio_mfv_plugin_api_get(void);

/// @}
/// @}

#ifdef __cplusplus
}
#endif
#endif
