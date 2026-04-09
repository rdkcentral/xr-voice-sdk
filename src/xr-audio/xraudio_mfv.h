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

typedef enum {
   XRAUDIO_MFV_MSG_TYPE_KEYWORD_DETECTED = 0,
   XRAUDIO_MFV_MSG_TYPE_INPUT_ERROR      = 1,
   XRAUDIO_MFV_MSG_TYPE_INVALID          = 2
} xraudio_mfv_msg_type_t;

typedef enum {
   XRAUDIO_MFV_INPUT_ERROR_READ     = 0,
   XRAUDIO_MFV_INPUT_ERROR_INTERNAL = 1,
   XRAUDIO_MFV_INPUT_ERROR_INVALID  = 2
} xraudio_mfv_input_error_t;

typedef struct {
   xraudio_mfv_msg_type_t  type;
} xraudio_mfv_msg_header_t;

typedef struct {
   xraudio_mfv_msg_header_t header;
   float                    confidence;
} xraudio_mfv_msg_keyword_detected_t;

typedef struct {
   xraudio_mfv_msg_header_t  header;
   xraudio_mfv_input_error_t type;
} xraudio_mfv_msg_input_error_t;

typedef struct {
   bool is_keyword_invalid; ///< true if the keyword has been declared invalid and should be ignored, false otherwise
   bool is_end_of_speech;   ///< true if the end of speech has been declared in the input audio stream, false otherwise
} xraudio_mfv_process_result_t;

typedef void *xraudio_mfv_object_t;

typedef bool (*xraudio_mfv_msg_callback_t)(void *msg);

#ifdef __cplusplus
extern "C" {
#endif

typedef xraudio_mfv_object_t (*xraudio_mfv_func_object_create_t)(const json_t *config);

typedef void                 (*xraudio_mfv_func_object_destroy_t)(xraudio_mfv_object_t object);

typedef bool                 (*xraudio_mfv_func_session_open_t)(xraudio_mfv_object_t object, int output_fd);

typedef void                 (*xraudio_mfv_func_session_close_t)(xraudio_mfv_object_t object);

typedef bool                 (*xraudio_mfv_func_session_process_audio_t)(xraudio_mfv_object_t object, const int16_t *sample_buffer, uint32_t sample_qty, xraudio_mfv_process_result_t *result);

typedef bool                 (*xraudio_mfv_func_output_audio_open_t)(xraudio_mfv_object_t object, int input_fd, xraudio_mfv_msg_callback_t callback);

typedef void                 (*xraudio_mfv_func_output_audio_close_t)(xraudio_mfv_object_t object);

typedef struct {
   uint32_t                                       api_version;
   xraudio_mfv_func_object_create_t               object_create;
   xraudio_mfv_func_object_destroy_t              object_destroy;
   xraudio_mfv_func_session_open_t                session_open;
   xraudio_mfv_func_session_close_t               session_close;
   xraudio_mfv_func_session_process_audio_t       session_process_audio;
   xraudio_mfv_func_output_audio_open_t           output_audio_open;
   xraudio_mfv_func_output_audio_close_t          output_audio_close;
} xraudio_mfv_plugin_api_t;

typedef xraudio_mfv_plugin_api_t *(*xraudio_mfv_plugin_api_get_t)(void);
xraudio_mfv_plugin_api_t *xraudio_mfv_plugin_api_get(void);

#ifdef __cplusplus
}
#endif
