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
#ifndef __VSDK_FFV_ADAPTER_H__
#define __VSDK_FFV_ADAPTER_H__

#ifndef USE_RDKV_HAL
#include "xraudio_hal.h"
#include "xr_ffv_hal_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

void vsdk_ffv_adapter_set_interface_plugin(xr_ffv_hal_plugin_func_t *plugin);
xraudio_hal_plugin_api_t *vsdk_ffv_adapter_api_get(void);

#ifdef __cplusplus
}
#endif
#endif

#endif
