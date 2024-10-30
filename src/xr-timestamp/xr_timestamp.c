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
#include <xr_timestamp.h>
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRSTAMP
#include <rdkx_logger.h>

void rdkx_timestamp_get(rdkx_timestamp_t *timestamp) {
   if(timestamp == NULL || clock_gettime(CLOCK_MONOTONIC_RAW, timestamp)) {
      XLOGD_ERROR("Unable to get time.");
   }
}

void rdkx_timestamp_get_realtime(rdkx_timestamp_t *timestamp) {
   if(timestamp == NULL || clock_gettime(CLOCK_REALTIME, timestamp)) {
      XLOGD_ERROR("Unable to get time.");
   }
}

//  1 : one is greater than two
//  0 : one and two are equal
// -1 : one is less than two
int rdkx_timestamp_cmp(rdkx_timestamp_t one, rdkx_timestamp_t two) {
   if(one.tv_sec > two.tv_sec) {
      return(1);
   } else if(one.tv_sec < two.tv_sec) {
      return(-1);
   }
   if(one.tv_nsec > two.tv_nsec) {
      return(1);
   } else if(one.tv_nsec < two.tv_nsec) {
      return(-1);
   }
   return(0);
}

// Subtract timestamp one from two ... (two - one)
signed long long rdkx_timestamp_subtract_ns(rdkx_timestamp_t one, rdkx_timestamp_t two) {
   int cmp = rdkx_timestamp_cmp(one, two);

   if(cmp > 0) { // one is greater than two
      if(one.tv_sec - two.tv_sec) {
         return(((one.tv_sec - two.tv_sec)*(long long)-1000000000) + one.tv_nsec - two.tv_nsec);
      }
      return(two.tv_nsec - one.tv_nsec);
   } else if(cmp < 0) { // one is less than two
      if(two.tv_sec - one.tv_sec) {
         return(((two.tv_sec - one.tv_sec)*(long long)1000000000) - one.tv_nsec + two.tv_nsec);
      }
      return(two.tv_nsec - one.tv_nsec);
   }
   return 0;
}

signed long long rdkx_timestamp_subtract_us(rdkx_timestamp_t one, rdkx_timestamp_t two) {
   return(rdkx_timestamp_subtract_ns(one, two) / 1000);
}

signed long long rdkx_timestamp_subtract_ms(rdkx_timestamp_t one, rdkx_timestamp_t two) {
   return(rdkx_timestamp_subtract_ns(one, two) / 1000000);
}

void rdkx_timestamp_add_ns(rdkx_timestamp_t *timestamp, unsigned long long nanoseconds) {
   if(timestamp == NULL) {
      XLOGD_ERROR("Invalid timestamp");
      return;
   }
   unsigned long long nsecs = timestamp->tv_nsec + nanoseconds;

   timestamp->tv_nsec  = nsecs % 1000000000;
   timestamp->tv_sec  += nsecs / 1000000000;
}

void rdkx_timestamp_add_us(rdkx_timestamp_t *timestamp, unsigned long microseconds) {
   rdkx_timestamp_add_ns(timestamp, ((unsigned long long)microseconds) * 1000);
}

void rdkx_timestamp_add_ms(rdkx_timestamp_t *timestamp, unsigned long milliseconds) {
   rdkx_timestamp_add_ns(timestamp, ((unsigned long long)milliseconds) * 1000000);
}

void rdkx_timestamp_add_secs(rdkx_timestamp_t *timestamp, unsigned long seconds) {
   if(timestamp == NULL) {
      XLOGD_ERROR("Invalid timestamp");
      return;
   }
   timestamp->tv_sec += seconds;
}

unsigned long long rdkx_timestamp_until_ns(rdkx_timestamp_t timestamp) {
   rdkx_timestamp_t now;
   rdkx_timestamp_get(&now);
   if(rdkx_timestamp_cmp(timestamp, now) <= 0) {
      return(0);
   }

   return((unsigned long long)rdkx_timestamp_subtract_ns(now, timestamp));
}

unsigned long long rdkx_timestamp_until_us(rdkx_timestamp_t timestamp) {
   return(rdkx_timestamp_until_ns(timestamp) / 1000);
}

unsigned long long rdkx_timestamp_until_ms(rdkx_timestamp_t timestamp) {
   return(rdkx_timestamp_until_ns(timestamp) / 1000000);
}

unsigned long long rdkx_timestamp_since_ns(rdkx_timestamp_t timestamp) {
   rdkx_timestamp_t now;
   rdkx_timestamp_get(&now);
   if(rdkx_timestamp_cmp(timestamp, now) >= 0) {
      return(0);
   }

   return((unsigned long long)rdkx_timestamp_subtract_ns(timestamp, now));
}

unsigned long long rdkx_timestamp_since_us(rdkx_timestamp_t timestamp) {
   return(rdkx_timestamp_since_ns(timestamp) / 1000);
}

unsigned long long rdkx_timestamp_since_ms(rdkx_timestamp_t timestamp)  {
   return(rdkx_timestamp_since_ns(timestamp) / 1000000);
}
