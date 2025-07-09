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
 * HalFileDescriptor.h
 *
 * Contains the definition of Binder Status used by Far Field Voice HAL.
 */

#pragma once

#include <stdint.h>

namespace hal
{

class HalFileDescriptor
{
public:
	HalFileDescriptor();
	~HalFileDescriptor();

    /**
	 * Far Field Voice client pipe file read descriptor.
     */
	int m_clientFileDescriptor;
};  // class HalFileDescriptor

}  // namespace hal
