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
#ifndef _XRAUDIO_OVC_H_
#define _XRAUDIO_OVC_H_

#include <stdbool.h>

typedef void * xraudio_ovc_object_t;

#ifdef __cplusplus
extern "C" {
#endif

void                 xraudio_ovc_version(const char **name, const char **version, const char **branch, const char **commit_id);
xraudio_ovc_object_t xraudio_ovc_object_create(bool ramp_enable, bool use_external_gain);
void                 xraudio_ovc_object_destroy(xraudio_ovc_object_t object);

void  xraudio_ovc_config_get(xraudio_ovc_object_t object, xraudio_volume_step_t *max_volume, xraudio_volume_step_t *min_volume, xraudio_volume_step_size_t *volume_step_dB);
void  xraudio_ovc_config_set(xraudio_ovc_object_t object, xraudio_output_format_t format, xraudio_volume_step_t max_volume, xraudio_volume_step_t min_volume, xraudio_volume_step_size_t volume_step_dB, int8_t use_ext_gain, xraudio_volume_step_t *volume_step);
void  xraudio_ovc_set_gain(xraudio_ovc_object_t object, float gain);
void  xraudio_ovc_increase(xraudio_ovc_object_t object);
void  xraudio_ovc_decrease(xraudio_ovc_object_t object);
bool  xraudio_ovc_apply_gain_multichannel(xraudio_ovc_object_t object, int16_t *buffer_src, int16_t *buffer_dst, uint8_t chan_qty, uint32_t sample_qty);
float xraudio_ovc_get_scale(xraudio_ovc_object_t object);
bool  xraudio_ovc_is_ramp_active(xraudio_ovc_object_t object);

#ifdef __cplusplus
}
#endif

#endif



