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
#ifndef __VSDK_PRIVATE__
#define __VSDK_PRIVATE__

#include "xraudio_hal.h"
#include "xraudio_kwd.h"
#include "xraudio_dga.h"
#include "xraudio_sdf.h"
#include "xraudio_ovc.h"
#include "xraudio_ppr.h"

#ifdef __cplusplus
extern "C" {
#endif

bool vsdk_curtail_xraudio_enabled(void);
bool vsdk_xraudio_allow_input_failure(void);

bool vsdk_hal_in_enabled(void);
bool vsdk_hal_out_enabled(void);

xraudio_hal_plugin_api_t *vsdk_hal_plugin_get(void);
xraudio_kwd_plugin_api_t *vsdk_kwd_plugin_get(void);
xraudio_eos_plugin_api_t *vsdk_eos_plugin_get(void);
xraudio_dga_plugin_api_t *vsdk_dga_plugin_get(void);
xraudio_sdf_plugin_api_t *vsdk_sdf_plugin_get(void);
xraudio_ovc_plugin_api_t *vsdk_ovc_plugin_get(void);
xraudio_ppr_plugin_api_t *vsdk_ppr_plugin_get(void);

#ifdef __cplusplus
}
#endif

/// @}

#endif
