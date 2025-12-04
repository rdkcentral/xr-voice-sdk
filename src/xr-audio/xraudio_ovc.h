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
#include "xraudio_common.h"

typedef void * xraudio_ovc_object_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef void                 (*xraudio_ovc_func_version_t)(const char **name, const char **version, const char **branch, const char **commit_id);
typedef xraudio_ovc_object_t (*xraudio_ovc_func_object_create_t)(bool ramp_enable, bool use_external_gain);
typedef void                 (*xraudio_ovc_func_object_destroy_t)(xraudio_ovc_object_t object);

typedef void  (*xraudio_ovc_func_config_get_t)(xraudio_ovc_object_t object, xraudio_volume_step_t *max_volume, xraudio_volume_step_t *min_volume, xraudio_volume_step_size_t *volume_step_dB);
typedef void  (*xraudio_ovc_func_config_set_t)(xraudio_ovc_object_t object, xraudio_output_format_t format, xraudio_volume_step_t max_volume, xraudio_volume_step_t min_volume, xraudio_volume_step_size_t volume_step_dB, int8_t use_ext_gain, xraudio_volume_step_t *volume_step);
typedef void  (*xraudio_ovc_func_set_gain_t)(xraudio_ovc_object_t object, float gain);
typedef void  (*xraudio_ovc_func_increase_t)(xraudio_ovc_object_t object);
typedef void  (*xraudio_ovc_func_decrease_t)(xraudio_ovc_object_t object);
typedef bool  (*xraudio_ovc_func_apply_gain_multichannel_t)(xraudio_ovc_object_t object, int16_t *buffer_src, int16_t *buffer_dst, uint8_t chan_qty, uint32_t sample_qty);
typedef float (*xraudio_ovc_func_get_scale_t)(xraudio_ovc_object_t object);
typedef bool  (*xraudio_ovc_func_is_ramp_active_t)(xraudio_ovc_object_t object);

typedef struct {
   xraudio_ovc_func_version_t                 version;
   xraudio_ovc_func_object_create_t           object_create;
   xraudio_ovc_func_object_destroy_t          object_destroy;
   xraudio_ovc_func_config_get_t              config_get;
   xraudio_ovc_func_config_set_t              config_set;
   xraudio_ovc_func_set_gain_t                set_gain;
   xraudio_ovc_func_increase_t                increase;
   xraudio_ovc_func_decrease_t                decrease;
   xraudio_ovc_func_apply_gain_multichannel_t apply_gain_multichannel;
   xraudio_ovc_func_get_scale_t               get_scale;
   xraudio_ovc_func_is_ramp_active_t          is_ramp_active;
} xraudio_ovc_plugin_api_t;

typedef xraudio_ovc_plugin_api_t *(*xraudio_ovc_plugin_api_get_t)(void);
xraudio_ovc_plugin_api_t *xraudio_ovc_plugin_api_get(void);

#ifdef __cplusplus
}
#endif

#endif



