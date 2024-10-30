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
#ifndef _XRAUDIO_INPUT_H_
#define _XRAUDIO_INPUT_H_

typedef enum {
   XRAUDIO_INPUT_SESSION_GROUP_DEFAULT = 0, // Session index for regular voice sessions (PTT, FFV)
   #ifdef MICROPHONE_TAP_ENABLED
   XRAUDIO_INPUT_SESSION_GROUP_MIC_TAP = 1, // Session index for microphone tap voice sessions
   XRAUDIO_INPUT_SESSION_GROUP_QTY     = 2
   #else
   XRAUDIO_INPUT_SESSION_GROUP_QTY     = 1
   #endif
} xraudio_input_session_group_t;

typedef enum {
   XRAUDIO_INPUT_STATE_CREATED   = 0,
   XRAUDIO_INPUT_STATE_IDLING    = 1,
   XRAUDIO_INPUT_STATE_RECORDING = 2,
   XRAUDIO_INPUT_STATE_STREAMING = 3,
   XRAUDIO_INPUT_STATE_DETECTING = 4,
   XRAUDIO_INPUT_STATE_INVALID   = 5,
} xraudio_input_state_t;

// Input object
typedef void * xraudio_input_object_t;

#ifdef __cplusplus
extern "C" {
#endif

xraudio_input_object_t  xraudio_input_object_create(xraudio_hal_obj_t hal_obj, uint8_t user_id, int msgq, uint16_t capabilities, xraudio_hal_dsp_config_t *dsp_config, json_t *json_obj_input);
void                    xraudio_input_object_destroy(xraudio_input_object_t object);
xraudio_hal_input_obj_t xraudio_input_hal_obj_get(xraudio_input_object_t object);
xraudio_result_t        xraudio_input_open(xraudio_input_object_t object, xraudio_devices_input_t device, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_resource_id_input_t resource_id, uint16_t capabilities, xraudio_input_format_t format);
void                    xraudio_input_close(xraudio_input_object_t object);
xraudio_result_t        xraudio_input_source_fd_set(xraudio_input_object_t object, xraudio_devices_input_t source, int fd, xraudio_input_format_t format, xraudio_input_data_read_cb_t callback, void *user_data);
xraudio_result_t        xraudio_input_sound_intensity_transfer(xraudio_input_object_t object, const char *fifo_name);
xraudio_result_t        xraudio_input_latency_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_latency_mode_t latency_mode);
xraudio_result_t        xraudio_input_cpu_util_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_cpu_util_mode_t cpu_util_mode);
xraudio_result_t        xraudio_input_frame_group_quantity_set(xraudio_object_t object, xraudio_devices_input_t source, uint8_t quantity);
xraudio_result_t        xraudio_input_stream_identifer_set(xraudio_object_t object, xraudio_devices_input_t source, const char *identifer);
xraudio_eos_event_t     xraudio_input_eos_run(xraudio_input_object_t object, uint8_t chan, float *input_samples, int32_t sample_qty, int16_t *scaled_eos_samples);
void                    xraudio_input_eos_state_set_speech_begin(xraudio_input_object_t object);
xraudio_ppr_event_t     xraudio_input_ppr_run(xraudio_input_object_t object, uint16_t frame_size_in_samples, const int32_t** ppmic_input_buffers, const int32_t** ppref_input_buffers, int32_t** ppkwd_output_buffers, int32_t** ppasr_output_buffers, int32_t** ppref_output_buffers);
void                    xraudio_input_ppr_state_set_speech_begin(xraudio_input_object_t object);
void                    xraudio_input_sound_focus_set(xraudio_input_object_t object, xraudio_sdf_mode_t mode);
void                    xraudio_input_sound_focus_update(xraudio_input_object_t object, uint32_t sample_qty);
xraudio_result_t        xraudio_input_record_to_file(xraudio_input_object_t object, xraudio_devices_input_t source, xraudio_container_t container, const char *audio_file_path, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param);      // Synchronous if callback is NULL
xraudio_result_t        xraudio_input_record_to_memory(xraudio_input_object_t object, xraudio_devices_input_t source, xraudio_sample_t *buf_samples, unsigned long sample_qty, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param); // Synchronous if callback is NULL
xraudio_result_t        xraudio_input_stream_time_minimum(xraudio_object_t object, xraudio_devices_input_t source, uint16_t ms);
xraudio_result_t        xraudio_input_stream_keyword_info(xraudio_object_t object, xraudio_devices_input_t source, uint32_t keyword_begin, uint32_t keyword_duration);
xraudio_result_t        xraudio_input_stream_keyword_info_get(xraudio_object_t object, xraudio_devices_input_t source, xraudio_keyword_detector_result_t *keyword_detector_result);
xraudio_result_t        xraudio_input_stream_to_fifo(xraudio_input_object_t object, xraudio_devices_input_t source, const char *fifo_name, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param); // Synchronous if callback is NULL
xraudio_result_t        xraudio_input_stream_to_pipe(xraudio_input_object_t object, xraudio_devices_input_t source, xraudio_dst_pipe_t dsts[], xraudio_input_format_t *format_decoded, bool subsequent, audio_in_callback_t callback, void *param); // Synchronous if callback is NULL
xraudio_result_t        xraudio_input_stream_to_user(xraudio_input_object_t object, xraudio_devices_input_t source, audio_in_data_callback_t data, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param); // Synchronous if callback is NULL
xraudio_result_t        xraudio_input_detect_stop(xraudio_input_object_t object, xraudio_devices_input_t source);
xraudio_result_t        xraudio_input_stop(xraudio_input_object_t object, xraudio_devices_input_t source, int32_t index);
xraudio_result_t        xraudio_input_keyword_params(xraudio_input_object_t object, xraudio_keyword_phrase_t keyword_phrase, xraudio_keyword_sensitivity_t keyword_sensitivity);
xraudio_result_t        xraudio_input_keyword_detect(xraudio_input_object_t object, keyword_callback_t callback, void *param, bool synchronous);
void                    xraudio_input_statistics_clear(xraudio_input_object_t object, uint32_t statistics);
void                    xraudio_input_statistics_print(xraudio_input_object_t object, uint32_t statistics);
// Should be private...
void                    xraudio_input_keyword_detected(xraudio_input_object_t object);
unsigned char           xraudio_input_signal_level_get(xraudio_input_object_t object, uint8_t chan);
uint16_t                xraudio_input_signal_direction_get(xraudio_input_object_t object);

xraudio_result_t        xraudio_input_capture_to_file_start(xraudio_input_object_t object, xraudio_capture_t capture, xraudio_container_t container, const char *audio_file_path, bool raw_mic_enable, audio_in_callback_t callback, void *param);
xraudio_result_t        xraudio_input_capture_stop(xraudio_input_object_t object);

void                    xraudio_input_stats_timestamp_frame_ready(xraudio_input_object_t object, rdkx_timestamp_t timestamp_next);
void                    xraudio_input_stats_timestamp_frame_read(xraudio_input_object_t object);
void                    xraudio_input_stats_timestamp_frame_eos(xraudio_input_object_t object);
void                    xraudio_input_stats_timestamp_frame_sound_focus(xraudio_input_object_t object);
void                    xraudio_input_stats_timestamp_frame_process(xraudio_input_object_t object);
void                    xraudio_input_stats_timestamp_frame_end(xraudio_input_object_t object);
void                    xraudio_input_stats_playback_status(xraudio_input_object_t object, bool is_active);
void                    xraudio_input_ppr_info_get(xraudio_input_object_t object, char **dsp_name);
xraudio_hal_input_obj_t xraudio_input_hal_obj_external_get(xraudio_hal_input_obj_t hal_obj_input, xraudio_devices_input_t device, xraudio_input_format_t format, xraudio_device_input_configuration_t *configuration);

const char *xraudio_input_state_str(xraudio_input_state_t type);
const char *xraudio_input_record_from_str(xraudio_input_record_from_t type);
const char *xraudio_input_record_until_str(xraudio_input_record_until_t type);

#ifdef __cplusplus
}
#endif

__inline uint32_t xraudio_input_source_to_group(xraudio_devices_input_t source) {
   #ifdef MICROPHONE_TAP_ENABLED
   uint32_t group = (source == XRAUDIO_DEVICE_INPUT_MIC_TAP) ? XRAUDIO_INPUT_SESSION_GROUP_MIC_TAP : XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; // Select the group based on source type
   return(group);
   #else
   return(XRAUDIO_INPUT_SESSION_GROUP_DEFAULT);
   #endif
}

#endif
