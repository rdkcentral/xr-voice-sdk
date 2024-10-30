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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <xrsv.h>

#define XRSV_INVALID_STR_LEN (24)

static char xrsv_invalid_str[XRSV_INVALID_STR_LEN];

static const char *xrsv_invalid_return(int value);

const char *xrsv_invalid_return(int value) {
   snprintf(xrsv_invalid_str, XRSV_INVALID_STR_LEN, "INVALID(%d)", value);
   xrsv_invalid_str[XRSV_INVALID_STR_LEN - 1] = '\0';
   return(xrsv_invalid_str);
}

const char *xrsv_result_str(xrsv_result_t type) {
   switch(type) {
      case XRSV_RESULT_SUCCESS: return("SUCCESS");
      case XRSV_RESULT_ERROR:   return("ERROR");
      case XRSV_RESULT_INVALID: return("INVALID");
   }
   return(xrsv_invalid_return(type));
}
