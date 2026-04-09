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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <jansson.h>

#ifndef XRAUDIO_MFV_API_VERSION
#define XRAUDIO_MFV_API_VERSION 1
#endif

// Capabilities
#define XRAUDIO_MFV_CAPS_NONE               (0x0000)
#define XRAUDIO_MFV_CAPS_AUDIO_GAIN         (0x0001) // Supports audio gain adjustment on the input audio stream
#define XRAUDIO_MFV_CAPS_KWD_VALIDATION     (0x0002) // Supports keyword validation
#define XRAUDIO_MFV_CAPS_EOS_DETECTION      (0x0004) // Supports end-of-speech detection
#define XRAUDIO_MFV_CAPS_REFERENCE_AUDIO    (0x0008) // Supports reference audio stream (e.g. keyword detection in reference audio)

typedef enum {
   XRAUDIO_MFV_RESULT_SUCCESS        = 0,
   XRAUDIO_MFV_RESULT_ERROR_PARAMS   = 1,
   XRAUDIO_MFV_RESULT_ERROR_INTERNAL = 2,
   XRAUDIO_MFV_RESULT_INVALID        = 3,
} xraudio_mfv_result_t;

typedef enum {
   XRAUDIO_MFV_EOS_RESULT_UNAVAILABLE     = 0,
   XRAUDIO_MFV_EOS_RESULT_SUCCESS         = 1,
   XRAUDIO_MFV_EOS_RESULT_TIMEOUT_INITIAL = 2,
   XRAUDIO_MFV_EOS_RESULT_TIMEOUT_FINAL   = 3,
   XRAUDIO_MFV_EOS_RESULT_INVALID         = 4,
} xraudio_mfv_eos_result_t;

typedef enum {
   XRAUDIO_MFV_MSG_TYPE_KEYWORD_DETECTED = 0,
   XRAUDIO_MFV_MSG_TYPE_INPUT_ERROR      = 1,
   XRAUDIO_MFV_MSG_TYPE_INVALID          = 2
} xraudio_mfv_msg_type_t;

typedef enum {
   XRAUDIO_MFV_ERROR_AUDIO_REFERENCE_READ = 0,
   XRAUDIO_MFV_ERROR_AUDIO_OUTPUT_WRITE   = 1,
   XRAUDIO_MFV_ERROR_INTERNAL             = 2,
   XRAUDIO_MFV_ERROR_INVALID              = 3
} xraudio_mfv_error_t;

typedef struct {
   xraudio_mfv_msg_type_t  type;
} xraudio_mfv_msg_header_t;

typedef struct {
   xraudio_mfv_msg_header_t header;
   float                    confidence;
} xraudio_mfv_msg_keyword_detected_t;

typedef struct {
   xraudio_mfv_msg_header_t  header;
   xraudio_mfv_error_t       type;
} xraudio_mfv_msg_error_t;

typedef struct {
   bool apply_gain;           ///< true if gain should be applied to the input audio stream, false otherwise
   bool validate_keyword;     ///< true if keyword should be validated, false otherwise
   bool detect_end_of_speech; ///< true if end of speech should be detected, false otherwise
} xraudio_mfv_session_info_t;

typedef struct {
   uint8_t detection_type; ///< detection type (0 = detection while active, 1 = detection while asleep)
   int16_t keyword_start;  ///< sample offset to start of keyword in audio stream (negative value indicates keyword start is unknown)
   int16_t keyword_end;    ///< sample offset to end of keyword in audio stream (negative value indicates keyword end is unknown)
   int16_t confidence;     ///< keyword detection confidence
} xraudio_mfv_keyword_info_t;

typedef struct {
   bool is_keyword_invalid; ///< true if the keyword has been declared invalid and should be ignored, false otherwise
   bool is_end_of_speech;   ///< true if the end of speech has been declared in the input audio stream, false otherwise
} xraudio_mfv_process_result_t;

typedef struct {
   uint32_t                 total_audio_samples;    ///< total number of audio samples processed in the session
   bool                     keyword_validated;      ///< true if the keyword has been validated, false otherwise
   float                    keyword_confidence;     ///< the confidence of the keyword detection/validation (value between 0.0 and 1.0, or a negative value if not applicable)
   xraudio_mfv_eos_result_t end_of_speech_result;   ///< result code for end of speech detection
   bool                     gain_applied;           ///< true if gain has been applied to the input audio stream, false otherwise
   float                    gain_value;             ///< the gain applied to the input audio stream in dB
} xraudio_mfv_session_stats_t;

typedef void *xraudio_mfv_object_t;

typedef bool (*xraudio_mfv_msg_callback_t)(void *msg);

#ifdef __cplusplus
extern "C" {
#endif

typedef xraudio_mfv_object_t (*xraudio_mfv_func_object_create_t)(const json_t *config);

typedef void                 (*xraudio_mfv_func_object_destroy_t)(xraudio_mfv_object_t object);

typedef xraudio_mfv_result_t (*xraudio_mfv_func_session_open_t)(xraudio_mfv_object_t object, xraudio_mfv_session_info_t *info, int *output_fd, xraudio_mfv_msg_callback_t callback);

typedef void                 (*xraudio_mfv_func_session_close_t)(xraudio_mfv_object_t object, xraudio_mfv_session_stats_t *stats);

typedef xraudio_mfv_result_t (*xraudio_mfv_func_session_info_t)(xraudio_mfv_object_t object, xraudio_mfv_keyword_info_t *info);

typedef xraudio_mfv_result_t (*xraudio_mfv_func_session_process_audio_t)(xraudio_mfv_object_t object, const int16_t *sample_buffer, uint32_t sample_qty, xraudio_mfv_process_result_t *result);

typedef xraudio_mfv_result_t (*xraudio_mfv_func_reference_audio_open_t)(xraudio_mfv_object_t object, int fd, xraudio_mfv_msg_callback_t callback);

typedef void                 (*xraudio_mfv_func_reference_audio_close_t)(xraudio_mfv_object_t object);

typedef struct {
   uint16_t                                       api_version;
   uint16_t                                       capabilities;
   xraudio_mfv_func_object_create_t               object_create;
   xraudio_mfv_func_object_destroy_t              object_destroy;
   xraudio_mfv_func_session_open_t                session_open;
   xraudio_mfv_func_session_close_t               session_close;
   xraudio_mfv_func_session_info_t                session_info;
   xraudio_mfv_func_session_process_audio_t       session_process_audio;
   xraudio_mfv_func_reference_audio_open_t        reference_audio_open;
   xraudio_mfv_func_reference_audio_close_t       reference_audio_close;
} xraudio_mfv_plugin_api_t;

typedef xraudio_mfv_plugin_api_t *(*xraudio_mfv_plugin_api_get_t)(void);
xraudio_mfv_plugin_api_t *xraudio_mfv_plugin_api_get(void);

#ifdef __cplusplus
}
#endif
