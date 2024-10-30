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
#ifndef __XRAUDIO_OPUS_H__
#define __XRAUDIO_OPUS_H__

#include <stdint.h>
#include <stdbool.h>

typedef void *  xraudio_opus_object_t;
typedef int16_t pcm_t;

typedef struct {
   uint16_t packet_total;
   uint16_t packet_lost;
   uint8_t  err_discont;
   uint8_t  err_repeat;
   uint8_t  err_cmd_id;
   uint8_t  err_cmd_len;
} xraudio_opus_stats_t;

#ifdef __cplusplus
extern "C"
{
#endif

xraudio_opus_object_t xraudio_opus_create(void);

int32_t xraudio_opus_deframe(xraudio_opus_object_t object, uint8_t *inbuf, uint32_t inlen);
int32_t xraudio_opus_decode(xraudio_opus_object_t object, uint8_t framed, uint8_t *inbuf, uint32_t inlen, pcm_t *outbuf, uint32_t outlen);
bool    xraudio_opus_stats(xraudio_opus_object_t object, xraudio_opus_stats_t *stats);
bool    xraudio_opus_reset(xraudio_opus_object_t object);
void    xraudio_opus_destroy(xraudio_opus_object_t object);

#ifdef __cplusplus
}
#endif

#endif
