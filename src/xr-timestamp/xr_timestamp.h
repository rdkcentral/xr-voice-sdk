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
#ifndef __XR_TIMESTAMP__
#define __XR_TIMESTAMP__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

typedef struct timespec rdkx_timestamp_t;

#ifdef __cplusplus
extern "C" {
#endif

void               rdkx_timestamp_get(rdkx_timestamp_t *timestamp);
void               rdkx_timestamp_get_realtime(rdkx_timestamp_t *timestamp);
int                rdkx_timestamp_cmp(rdkx_timestamp_t one, rdkx_timestamp_t two);
signed long long   rdkx_timestamp_subtract_ns(rdkx_timestamp_t one, rdkx_timestamp_t two);
signed long long   rdkx_timestamp_subtract_us(rdkx_timestamp_t one, rdkx_timestamp_t two);
signed long long   rdkx_timestamp_subtract_ms(rdkx_timestamp_t one, rdkx_timestamp_t two);
void               rdkx_timestamp_add_ns(rdkx_timestamp_t *timestamp, unsigned long long nanoseconds);
void               rdkx_timestamp_add_us(rdkx_timestamp_t *timestamp, unsigned long microseconds);
void               rdkx_timestamp_add_ms(rdkx_timestamp_t *timestamp, unsigned long milliseconds);
void               rdkx_timestamp_add_secs(rdkx_timestamp_t *timestamp, unsigned long seconds);
unsigned long long rdkx_timestamp_until_ns(rdkx_timestamp_t timestamp);
unsigned long long rdkx_timestamp_until_us(rdkx_timestamp_t timestamp);
unsigned long long rdkx_timestamp_until_ms(rdkx_timestamp_t timestamp);
unsigned long long rdkx_timestamp_since_ns(rdkx_timestamp_t timestamp);
unsigned long long rdkx_timestamp_since_us(rdkx_timestamp_t timestamp);
unsigned long long rdkx_timestamp_since_ms(rdkx_timestamp_t timestamp);

#ifdef __cplusplus
}
#endif

#endif
