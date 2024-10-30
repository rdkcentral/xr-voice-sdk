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
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include "xr_mq.h"
#include "xrsr_private.h"

bool xrsr_message_queue_open(int *msgq, size_t msgsize) {
   xr_mq_attr_t attr = {.max_msg = 16, .max_msg_size = msgsize};

   *msgq = xr_mq_create(&attr);
   if(*msgq < 0) {
      return(false);
   }
   return(true);
}

void xrsr_message_queue_close(int *msgq) {
   if(*msgq >= 0) {
      xr_mq_destroy(*msgq);
   }
}
int xrsr_queue_msg_push(int msgq, const char *msg, size_t msg_len) {
   XLOGD_DEBUG("msgq %d size %d msg %p", msgq, msg_len, msg);
   if(msg_len > XRSR_MSG_QUEUE_MSG_SIZE_MAX) {
      XLOGD_ERROR("Message size is too big! size %d max %d", msg_len, XRSR_MSG_QUEUE_MSG_SIZE_MAX);
      return(-1);
   }
   if(msgq < 0) {
      XLOGD_WARN("program is terminating");
      return(-1);
   }

   if(!xr_mq_push(msgq, msg, msg_len)) {
      XLOGD_ERROR("failed to push msg");
      return(-1);
   }
   return(0);
}
