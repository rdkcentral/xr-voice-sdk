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
 * FarFieldVoiceControllerListener.h
 *
 * Contains the definition of the Far Field Voice HAL controller listener.
 */

#pragma once

#include <stdint.h>
#include "KeywordDetectData.h"

using namespace std;
using namespace hal;
using namespace farfieldvoice;

class FarFieldVoiceControllerListener
{
public:

    /**
	 * Callback when a keyword is detected on the Keyword channel.
     */
    virtual void onKeywordDetected(::farfieldvoice::KeywordDetectData keywordDetectData) = 0;

    /**
	 * Callback when a start of voice command is detected on the Keyword channel following the keyword.
     */
    virtual void onStartOfCommand(long sampleOffset) = 0;

    /**
	 * Callback when an End of voice command is detected on the Keyword channel following the keyword.
     */
    virtual void onEndOfCommand(long sampleOffset) = 0;

    /**
	 * Callback when a start of voice command is not detected on the Keyword channel following within a
     * time period.
     */
    virtual void onNoStartOfCommand(long sampleOffset) = 0;

    /**
	 * Callback when an end of voice command is not detected on the Keyword channel within a time period.
     */
    virtual void onNoEndOfCommand(long sampleOffset) = 0;
};  // class FarFieldVoiceControllerListener
