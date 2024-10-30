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
#ifndef __XR_TIMER__
#define __XR_TIMER__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

#define RDXK_TIMER_OBJ_INVALID (NULL)
#define RDXK_TIMER_ID_INVALID  (-1)

typedef void *  rdkx_timer_object_t;
typedef int32_t rdkx_timer_id_t;

typedef void (*rdkx_timer_handler_t)(void *data);

#ifdef __cplusplus
extern "C" {
#endif

rdkx_timer_object_t rdkx_timer_create(uint32_t qty, bool single_thread, bool thread_id_check);
void                rdkx_timer_destroy(rdkx_timer_object_t object);
rdkx_timer_id_t     rdkx_timer_insert(rdkx_timer_object_t object, struct timespec timeout, const rdkx_timer_handler_t handler, const void *data);
bool                rdkx_timer_update(rdkx_timer_object_t object, rdkx_timer_id_t timer_id, struct timespec timeout);
bool                rdkx_timer_update_handler(rdkx_timer_object_t object, rdkx_timer_id_t timer_id, struct timespec timeout, const rdkx_timer_handler_t handler, const void *data);
bool                rdkx_timer_remove(rdkx_timer_object_t object, rdkx_timer_id_t timer_id);
rdkx_timer_id_t     rdkx_timer_next_get(rdkx_timer_object_t object, struct timeval *tv, rdkx_timer_handler_t *handler, void **data);
rdkx_timer_id_t     rdkx_timer_next_get_ts(rdkx_timer_object_t object, struct timespec *ts, rdkx_timer_handler_t *handler, void **data);

#ifdef __cplusplus
}
#endif

#endif
