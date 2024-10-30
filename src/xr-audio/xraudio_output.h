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
#ifdef XRAUDIO_OUTPUT_ENABLED
#ifndef _XRAUDIO_OUTPUT_H_
#define _XRAUDIO_OUTPUT_H_

#include <jansson.h>

typedef enum {
   XRAUDIO_OUTPUT_STATE_CREATED = 0,
   XRAUDIO_OUTPUT_STATE_IDLING  = 1,
   XRAUDIO_OUTPUT_STATE_PLAYING = 2,
   XRAUDIO_OUTPUT_STATE_PAUSED  = 3,
   XRAUDIO_OUTPUT_STATE_INVALID = 4,
} xraudio_output_state_t;

// Speaker object
typedef void * xraudio_output_object_t;

#ifdef __cplusplus
extern "C" {
#endif

xraudio_output_object_t  xraudio_output_object_create(xraudio_hal_obj_t hal_obj, uint8_t user_id, int msgq, uint16_t capabilities, xraudio_hal_dsp_config_t *dsp_config, json_t* json_obj_output);
void                     xraudio_output_object_destroy(xraudio_output_object_t object);
void                     xraudio_output_open(xraudio_output_object_t object, xraudio_devices_output_t device, xraudio_power_mode_t power_mode, xraudio_resource_id_output_t resource_id, uint16_t capabilities);
void                     xraudio_output_close(xraudio_output_object_t object);
xraudio_hal_output_obj_t xraudio_output_hal_obj_get(xraudio_output_object_t object);
xraudio_result_t         xraudio_output_play_from_file(xraudio_output_object_t object, const char *audio_file_path, audio_out_callback_t callback, void *param);
xraudio_result_t         xraudio_output_play_from_memory(xraudio_output_object_t object, xraudio_output_format_t *format, const unsigned char *audio_buf, unsigned long size, audio_out_callback_t callback, void *param);
xraudio_result_t         xraudio_output_play_from_pipe(xraudio_output_object_t object, xraudio_output_format_t *format, int pipe, audio_out_callback_t callback, void *param);
xraudio_result_t         xraudio_output_play_from_user(xraudio_output_object_t object, xraudio_output_format_t *format, audio_out_data_callback_t data, audio_out_callback_t callback, void *param);
xraudio_result_t         xraudio_output_pause(xraudio_output_object_t object, audio_out_callback_t callback, void *param);
xraudio_result_t         xraudio_output_resume(xraudio_output_object_t object, audio_out_callback_t callback, void *param);
xraudio_result_t         xraudio_output_stop(xraudio_output_object_t object);
xraudio_result_t         xraudio_output_volume_set(xraudio_output_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right, int8_t ramp_en);
xraudio_result_t         xraudio_output_volume_get(xraudio_output_object_t object, xraudio_volume_step_t *left, xraudio_volume_step_t *right, int8_t *ramp_en);
xraudio_result_t         xraudio_output_volume_config_set(xraudio_output_object_t object, xraudio_volume_step_t max_volume, xraudio_volume_step_t min_volume, xraudio_volume_step_size_t volume_step_dB, int8_t use_ext_gain);
xraudio_result_t         xraudio_output_volume_config_get(xraudio_output_object_t object, xraudio_volume_step_t *max_volume, xraudio_volume_step_t *min_volume, xraudio_volume_step_size_t *volume_step_dB, int8_t *use_ext_gain);
xraudio_result_t         xraudio_output_sound_intensity_transfer(xraudio_output_object_t object, const char *fifo_name);
xraudio_eos_event_t      xraudio_output_eos_run(xraudio_output_object_t object, int16_t *input_samples, int32_t sample_qty);
void                     xraudio_output_statistics_clear(xraudio_output_object_t object, uint32_t statistics);
void                     xraudio_output_statistics_print(xraudio_output_object_t object, uint32_t statistics);
// Also private but needs to be public for access by playback thread
unsigned char            xraudio_output_signal_level_get(xraudio_output_object_t object);
xraudio_result_t         xraudio_output_volume_gain_apply(xraudio_output_object_t object, unsigned char *buffer, unsigned long bytes, int32_t chans);

xraudio_result_t         xraudio_output_hfp_start(xraudio_output_object_t object, uint32_t sample_rate);
xraudio_result_t         xraudio_output_hfp_stop(xraudio_output_object_t object);
xraudio_result_t         xraudio_output_hfp_mute(xraudio_output_object_t object, unsigned char enable);

const char *             xraudio_output_state_str(xraudio_output_state_t type);

#ifdef __cplusplus
}
#endif

#endif
#endif
