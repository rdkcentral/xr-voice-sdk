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
#ifndef _XRAUDIO_VERSION_H_
#define _XRAUDIO_VERSION_H_

#define XRAUDIO_VERSION_QTY_MAX (16)

typedef struct {
   const char *name;
   const char *version;
   const char *branch;
   const char *commit_id;
} xraudio_version_info_t;

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Gets xraudio version
/// @details Returns the version information for the xraudio component.
void xraudio_version(xraudio_version_info_t *version_info, uint32_t *qty);

#ifdef __cplusplus
}
#endif

#endif
