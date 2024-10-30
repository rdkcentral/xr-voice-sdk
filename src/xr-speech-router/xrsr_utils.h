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
#ifndef _XRSR_UTILS_H_
#define _XRSR_UTILS_H_

#ifdef __cplusplus
extern "C"
{
#endif

const char *xrsr_queue_msg_type_str(xrsr_queue_msg_type_t type);
const char *xrsr_xraudio_state_str(xrsr_xraudio_state_t type);
const char *xrsr_audio_format_str(xrsr_audio_format_type_t format);
const char *xrsr_audio_format_bitmask_str(xrsr_audio_format_type_t formats);
const char *xrsr_stream_from_str(xrsr_stream_from_t stream_from);
const char *xrsr_stream_until_str(xrsr_stream_until_t stream_until);
const char *xrsr_power_mode_str(xrsr_power_mode_t power_mode);
const char *xrsr_address_family_str(xrsr_address_family_t family);
const char *xrsr_event_str(xrsr_event_t event);
const char *xrsr_cert_type_str(xrsr_cert_type_t type);

#ifdef HTTP_ENABLED
const char *xrsr_curlmcode_str(CURLMcode code);
#endif

bool                  xrsr_url_parse(const char *url, xrsr_url_parts_t *url_parts);
void                  xrsr_url_free(xrsr_url_parts_t *url_parts);

#ifdef __cplusplus
}
#endif

#endif
