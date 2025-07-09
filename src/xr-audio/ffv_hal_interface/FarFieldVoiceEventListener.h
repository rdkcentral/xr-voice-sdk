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
 * FarFieldVoiceEventListener.h
 *
 * Contains the definition of the Far Field Voice HAL event listener.
 */

#pragma once

#include "HalState.h"
#include "FailureCode.h"

using namespace std;
using namespace hal;
using namespace farfieldvoice;

class FarFieldVoiceEventListener
{
public:

    /**
	 * Callback when Far Field Voice has transitioned to a new state.
     */
    virtual void onStateChanged(::hal::HalState oldState, ::hal::HalState newState) = 0;

    /**
	 * Callback when Far Field Voice has transitioned to Full Power mode.
     */
    virtual void onEnteredFullPowerMode() = 0;

    /**
	 * Callback when Far Field Voice has transitioned to Standby mode.
     */
    virtual void onEnteredStandbyMode() = 0;

    /**
	 * Callback when Far Field Voice has transitioned to Deep Sleep mode.
     */
    virtual void onEnteredDeepSleepMode() = 0;

    /**
	 * Callback when Far Field Voice has failed.
     */
    virtual void onHardwareFailed(::farfieldvoice::FailureCode failureCode) = 0;
};  // class FarFieldVoiceEventListener
