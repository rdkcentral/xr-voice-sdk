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
#ifndef __XR_MQ_H__
#define __XR_MQ_H__
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define XR_MQ_DEFAULT_MAX_MSG      (10)
#define XR_MQ_DEFAULT_MAX_MSG_SIZE (128 + sizeof(xr_mq_msg_size_t))

#define XR_MQ_INVALID (-1)

typedef int    xr_mq_t;
typedef size_t xr_mq_msg_size_t;

typedef struct {
    uint8_t          max_msg;
    xr_mq_msg_size_t max_msg_size;
} xr_mq_attr_t;

#ifdef __cplusplus
extern "C" {
#endif

xr_mq_t          xr_mq_create(xr_mq_attr_t *attr);
bool             xr_mq_push(xr_mq_t mq, const void *msg, xr_mq_msg_size_t msg_size);
xr_mq_msg_size_t xr_mq_pop(xr_mq_t mq, void *msg, xr_mq_msg_size_t msg_size);
void             xr_mq_destroy(xr_mq_t mq);

#ifdef __cplusplus
}
#endif

#endif
