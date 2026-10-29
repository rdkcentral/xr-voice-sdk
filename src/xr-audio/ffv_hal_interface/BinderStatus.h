/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @brief
 *
 * BinderStatus.h
 *
 * Contains the definition of Binder Status used by Far Field Voice HAL.
 */

#pragma once

#include <stdint.h>

namespace hal
{

enum class BinderStatus : int32_t
{
  EX_NONE = 0,
  EX_SECURITY = -1,
  EX_BAD_PARCELABLE = -2,
  EX_ILLEGAL_ARGUMENT = -3,
  EX_NULL_POINTER = -4,
  EX_ILLEGAL_STATE = -5,
  EX_NETWORK_MAIN_THREAD = -6,
  EX_UNSUPPORTED_OPERATION = -7,
  EX_SERVICE_SPECIFIC = -8,
  EX_HAS_REPLY_HEADER = -128,
  EX_TRANSACTION_FAILED = -129,
};

}  // namespace hal
