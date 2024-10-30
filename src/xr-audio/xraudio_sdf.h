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
#ifndef _XRAUDIO_SOUND_FOCUS_H_
#define _XRAUDIO_SOUND_FOCUS_H_

#include <xraudio_hal.h>

// Sound Focus object
typedef void * xraudio_sdf_object_t;

xraudio_sdf_object_t xraudio_sdf_object_create(xraudio_hal_obj_t obj);
void                 xraudio_sdf_object_destroy(xraudio_sdf_object_t object);
void                 xraudio_sdf_focus_set(xraudio_sdf_object_t object, xraudio_sdf_mode_t mode);
void                 xraudio_sdf_focus_update(xraudio_sdf_object_t object, uint8_t *polar_data, int8_t snr, uint16_t doa);
uint16_t             xraudio_sdf_signal_direction_get(xraudio_sdf_object_t object);
void                 xraudio_sdf_statistics_clear(xraudio_sdf_object_t object, uint32_t statistics);
void                 xraudio_sdf_statistics_print(xraudio_sdf_object_t object, uint32_t statistics);
#endif
