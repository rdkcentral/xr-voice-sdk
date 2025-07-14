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
 * Status.h
 *
 * Contains the definition of Far Field Voice HAL status.
 */

#pragma once

#include "PowerMode.h"
#include "KeywordDetectData.h"
#include <string>

namespace farfieldvoice
{

class Status
{
public:
    /**
     * Build version of this Far Field Voice code instance.
     *
     * This is for information only and useful to log when the Far Field
     * Voice service is opened.
     */
	std::string codeBuildVersion;

    /**
     * Current power mode.
     */
	farfieldvoice::PowerMode powerMode = farfieldvoice::PowerMode::DEEP_SLEEP;

    /**
     * Indicates if the Keyword channel has been opened.
     */
	bool keywordChannelOpen = false;

    /**
     * Indicates if the Continual channel has been opened.
     */
	bool continualChannelOpen = false;

    /**
     * Indicates if the Microphone channels has been opened.
     */
	bool microphoneChannelsOpen = false;

    /**
     * Indicates if a keyword was detected on the Keyword channel.
     */
	bool keywordDetected = false;

    /**
     * Keyword detect information (applicable only if keywordDetected is true).
     */
	farfieldvoice::KeywordDetectData keywordDetectData;

    /**
     * Indicates if privacy state is active.
     */
	bool privacyStateActive = false;

    /**
     * Total number of keyword channel samples lost due to buffer overflow.
     *
     * This is for information only and useful to log at the end of a session.
     * Non zero values may indicate inadequate CPU time or buffer space and
     * be a reason for poor voice quality and false negative keyword detects.
     */
	int64_t keywordChannelSamplesLost = 0L;

    /**
     * Total number of continual channel samples lost due to buffer overflow.
     *
     * This is for information only and useful to log at the end of a session.
     * Non zero values may indicate inadequate CPU time or buffer space and
     * be a reason for poor voice quality.
     */
	int64_t continualChannelSamplesLost = 0L;

    /**
     * Total number of microphone channels samples lost due to buffer overflow.
     *
     * This is for information only and useful to log at the end of a session.
     * Non zero values may indicate inadequate CPU time or buffer space and
     * be a reason for erroneous microphone data.
     */
	int64_t microphoneChannelsSamplesLost = 0L;

    /**
     * Vendor specific error code to indicate an error condition. A value of
     * zero indicates no error.
     *
     * This is for information only and useful to log if an error condition occurs.
     */
	int64_t vendorErrorCode = 0L;

    /**
     * Vendor specific error text to indicate an error condition.
     *
     * This is for information only and useful to log if an error condition occurs.
     */
	std::string vendorErrorText = "none";
};  // class Status

}  // namespace farfieldvoice
