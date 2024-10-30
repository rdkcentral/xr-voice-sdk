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
#ifndef __XR_SPEECH_VREX__
#define __XR_SPEECH_VREX__

#include <stdint.h>
#include <stdbool.h>

/// @file xrsv.h
///
/// @defgroup XRSV VREX SPEECH REQUEST HANDLER
/// @{
///
/// @defgroup XRSV_DEFINITIONS Definitions
/// @defgroup XRSV_ENUMS       Enumerations
/// @defgroup XRSV_STRUCTS     Structures
/// @defgroup XRSV_TYPEDEFS    Type Definitions
/// @defgroup XRSV_FUNCTIONS   Functions
///

/// @addtogroup XRSV_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The VREX speech request handler provides enumerated types for logical groups of values.

/// @brief XRSV result types
/// @details The result enumeration indicates all the possible return codes.
typedef enum {
   XRSV_RESULT_SUCCESS = 0, ///< Operation completed successfully
   XRSV_RESULT_ERROR   = 1, ///< Operation did not completed successfully
   XRSV_RESULT_INVALID = 2, ///< Invalid return code
} xrsv_result_t;

/// @brief VREX endOfStream results
/// @details The
typedef enum {
   XRSV_STREAM_END_END_OF_SPEECH    = 0, ///< VREX returned end of speech
   XRSV_STREAM_END_END_OF_STREAM    = 1, ///< VREX returned end of stream
   XRSV_STREAM_END_TIMEOUT          = 2, ///< VREX returned stream timeout
   XRSV_STREAM_END_USER_INTERUPTED  = 3, ///< VREX returned User Interrupted
   XRSV_STREAM_END_MAX_LENGTH       = 4, ///< VREX returned max stream length reached
   XRSV_STREAM_END_INTERNAL_ERROR   = 5, ///< VREX returned Internal Error
   XRSV_STREAM_END_INVALID          = 6, ///< VREX returned Unknown
} xrsv_vrex_result_t;

/// @}

#endif
