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
 * KeywordDetectData.h
 *
 * Contains the definition of the Far Field Voice HAL keyword detect data.
 */

#pragma once

#include <string>

namespace farfieldvoice
{

class KeywordDetectData
{
public:
    /**
     * Keyword channel sample offset to the beginning of the keyword.
     */
	int64_t beginSampleOffset = 0L;

    /**
     * Keyword channel sample offset to the end of the keyword.
     */
	int64_t endSampleOffset = 0L;

    /**
     * Keyword detect sensitivity (keyword detector vendor specific units).
     */
	float detectSensitivity = 0.0f;

    /**
     * Keyword detect low trigger level threshold (keyword detector vendor specific units).
     */
	float lowDetectThreshold = 0.0f;

    /**
     * Keyword detect high trigger level threshold (keyword detector vendor specific units).
     */
	float highDetectThreshold = 0.0f;

    /**
     * Keyword detect triggered by high level threshold (highDetectThreshold).
     */
	bool highThresholdTriggered = false;

    /**
     * Keyword detect confidence score (keyword detector vendor specific units).
     */
	float confidenceScore = 0.0f;

    /**
     * Signal to noise ratio during the keyword utterance (units of dB).
     */
	float keywordSnrDb = 0.0f;

    /**
     * Keyword direction of arrival (units of degrees).
     */
	int32_t directionOfArrivalDegrees = 0;

    /**
     * Dynamic gain applied to audio (units of dB).
     */
	float dynamicGainDb = 0.0f;

    /**
     * Name of keyword detector vendor.
     */
	std::string keywordDetectVendorName = "N/A";

    /**
     * Name of component where keyword was detected.
     */
	std::string keywordDetectComponentName = "N/A";
};  // class KeywordDetectData

}  // namespace farfieldvoice
