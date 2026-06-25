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
 * FarFieldVoiceController.h
 *
 * Contains the definition of the FarFieldVoiceController class.
 */

#pragma once

#include "FarFieldVoice.h"
#include "FarFieldVoiceControllerListener.h"
#include "BinderStatus.h"
#include "FFVmsgQueue.h"
#include "HalFileDescriptor.h"

using namespace std;
using namespace hal;
using namespace farfieldvoice;

class FarFieldVoice;

class FarFieldVoiceController
{
public:

    /**
     * Open the Keyword channel.
     *
     * If successful, creates and returns a pipe for passing Keyword channel audio to the client and
     * the Keyword channel is in the open state.
     *
     * Keyword channel audio processing is initialized and keyword detection is started. Upon keyword
     * detection, audio samples are written to the Keyword channel's pipe.
     *
     * Audio data is signed 16 bits per sample at 16kHz sampling rate. The endian order of each sample
     * value is that of the host processor's native endian order.
     *
     * Once a keyword is detected, the Far Field Voice service begins writing audio samples to the Keyword
     * channel's pipe whenever audio samples are available. Initially, samples may be written to the pipe
     * faster than real time as audio buffered within the service is provided as fast as possible. Once all
     * buffered audio is written to the pipe, audio will be written at a rate based on 16kHz sampling rate
     * (real time).
     *
     * The following FarFieldVoiceControllerListener callbacks can occur after the Keyword channel is started.
     *   onKeywordDetected()
     *   onEndOfCommand()
     *
     * The sample offset values provided in 'onKeywordDetected' and 'onEndOfCommand', are the relative sample
     * number with respect to the audio samples written to the Keyword channel's pipe. A sample offset value
     * of zero corresponds to the first sample written after opening the Keyword channel.
     *
     * The Keyword channel can be opened only in Standby or Full Power modes.
     *
     * @returns hal::HalFileDescriptor or null if the Keyword channel is already open or pipe create fails.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	The Keyword channel is already open, or the
     *                                                  Microphones channel is open, or power state is not
     *													Standby or Full Power.
     * @exception hal::BinderStatus EX_NULL_POINTER		'fileDescriptor' is null or pipe create failed.
     *
     * @pre The Keyword channel must be in the closed state.
     * @pre The Microphones channel must be in the closed state.
     * @pre The power state must be Full Power or Standby.
     * 
     * @see closeKeywordChannel()
     */
	hal::BinderStatus openKeywordChannel(hal::HalFileDescriptor** fileDescriptor);

    /**
     * Close the Keyword channel.
     *
     * The Keyword channel is stopped, the channel's pipe is closed, and the Keyword channel is in the
     * closed state.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	The Keyword channel is not open.
     *
     * @pre The Keyword channel must be in the open state.
     * 
     * @see openKeywordChannel()
     */
	hal::BinderStatus closeKeywordChannel();

    /**
     * Open the Continual channel.
     *
     * If successful, creates and returns a pipe for passing Continual channel audio to the client
     * and the Continual channel is in the open state.
     *
     * Continual channel audio processing is initialized and audio samples are written to the Continual
     * channel's pipe at 16kHz sampling rate.
     *
     * Audio data is signed 16 bits per sample at 16kHz sampling rate. The endian order of each sample
     * value is that of the host processor's native endian order.
     *
     * The Continual channel can be opened only in Full Power mode.
     * 
     * @returns hal::HalFileDescriptor or null if the Continual channel is already open, the power mode
     *          is not Full Power, pipe create fails, or the Continual channel is not supported.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	    The Continual channel is already open, or the
     *                                                      Microphones channel is open, or power mode is
     *                                                      not Full Power.
     * @exception hal::BinderStatus EX_NULL_POINTER		    'fileDescriptor' is null or pipe create failed.
     * @exception hal::BinderStatus EX_ILLEGAL_ARGUMENT     The Continual channel is not supported.
     *
     * @pre The Continual channel must be in the closed state.
     * @pre The Microphones channel must be in the closed state.
     * @pre The power mode must be Full Power.
     * 
     * @see closeContinualChannel()
     */
	hal::BinderStatus openContinualChannel(hal::HalFileDescriptor** fileDescriptor);

    /**
     * Close the Continual channel.
     *
     * The Continual channel is stopped, the channel's pipe is closed, and the Continual channel is in
     * the closed state.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	The Continual channel is not open.
     *
     * @pre The Continual channel must be in the open state.
     * 
     * @see openContinualChannel()
     */
	hal::BinderStatus closeContinualChannel();

    /**
     * Open the Microphones channel.
     *
     * If successful, creates and returns a pipe for passing raw microphone data to the client and
     * the Microphones channel is in the open state.
     *
     * Audio data is signed 32 bits per sample at 16kHz sampling rate. The endian order of each sample
     * value is that of the host processor's native endian order. Multiple microphones are interleaved
     * by sample with the number of microphones being equal to the microphoneChannelCount field in the
     * Far Field Voice service's Capabilities.
     *
     * The Microphones channel can be opened only in Full Power mode.
     * 
     * @returns hal::HalFileDescriptor or null if the Microphones channel is already open, the power mode is not
     *          Full Power, or pipe create fails.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	The Microphones channel is already open, or Keyword or
     *                                                  Continual channels are open, or power mode is not Full Power.
     * @exception hal::BinderStatus EX_NULL_POINTER 	'fileDescriptor' is null or pipe create failed.
     *
     * @pre The Microphones channel must be in the closed state.
     * @pre The Keyword channel must be in the closed state.
     * @pre The Continual channel must be in the closed state.
     * @pre The power mode must be Full Power.
     * 
     * @see closeMicrophonesChannel()
     */
	hal::BinderStatus openMicrophonesChannel(hal::HalFileDescriptor** fileDescriptor);

    /**
     * Close the Microphones channel.
     *
     * The Microphones channel is stopped, the channel's pipe is closed, and the Microphones channel is in the
     * closed state.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	The Microphones channel is not open.
     *
     * @pre The Microphones channel must be in the open state.
     * 
     * @see openMicrophonesChannel()
     */
	hal::BinderStatus closeMicrophonesChannel();

    /**
     * Start (activate) privacy state.
     *
     * All audio input will be forced to silence when privacy state is active.
     */
	hal::BinderStatus startPrivacyState();

    /**
     * Stop (inactivate) privacy state.
     *
     * All audio input will use actual input when privacy state is inactive.
     */
	hal::BinderStatus stopPrivacyState();

    /**
     * Enter Full Power mode processing state.
     *
     * If successful, Full Power mode audio processing will be initialized.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	All audio channels must be in the closed state.
     *
     * @pre All audio channels must be in the closed state.
     *
     * @see FarFieldVoiceEventListener.onEnteredFullPowerMode(), FarFieldVoiceEventListener.onFullPowerModeFailed()
     */
	hal::BinderStatus enterFullPowerMode();

    /**
     * Enter Standby mode processing state.
     *
     * If successful, Standby (low power) mode audio processing will be initialized.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	All audio channels must be in the closed state.
     *
     * @pre All audio channels must be in the closed state.
     *
     * @see FarFieldVoiceEventListener.onEnteredStandbyMode(), FarFieldVoiceEventListener.onStandbyModeFailed()
     */
	hal::BinderStatus enterStandbyMode();

    /**
     * Enter Deep Sleep mode processing state.
     *
     * If successful, Deep Sleep (no power) mode will be initialized.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	All audio channels must be in the closed state.
     *
     * @pre All audio channels must be in the closed state.
     *
     * @see FarFieldVoiceEventListener.onEnteredDeepSleepMode()
     */
	hal::BinderStatus enterDeepSleepMode();

    /**
     * Start recording audio.
     *
     * Captures of audio will be written to wave files for test purposes. Each wave file name
     * will begin with the specified base path and file name and end with a vendor specific extension
     * correlating to the particular captured audio.
     *
     * @param[in] fileNamePrefix	File name prefix (path and base file name).
     * @param[in] audioSelect		Selected audio to capture (vendor specific code).
     *
     * @exception hal::BinderStatus EX_ILLEGAL_ARGUMENT     Unknown audio selection.
     * @exception hal::BinderStatus EX_NULL_POINTER	        File create failed.
     */
	hal::BinderStatus startAudioRecording(std::string fileNamePrefix, long audioSelect);

    /**
     * Stop recording audio.
     *
     * Captures of audio are stopped and capture files are closed.
     */
	hal::BinderStatus stopAudioRecording();

    /**
     * Perform a test command.
     *
     * Performs a vendor specific test command for test and debug purposes.
     *
     * @param[in] command		Test command.
     *
     * @returns string - Response to command.
     */
	hal::BinderStatus testCommand(std::string command, std::string* response);

private:
	friend class FarFieldVoice;
	FarFieldVoiceController(FarFieldVoice* parent, FarFieldVoiceControllerListener* controllerListener);
	~FarFieldVoiceController();
	bool m_createFailed;		// flag: create failed
	FarFieldVoice* m_parent;
	FarFieldVoiceControllerListener* m_controllerListener;
	FFVmsgQueue *m_toThreadMsgQue;
	FFVmsgQueue *m_fromThreadMsgQue;
	hal::HalFileDescriptor *m_keywordFileDescriptor;
	hal::HalFileDescriptor *m_continualFileDescriptor;
	hal::HalFileDescriptor *m_microphonesFileDescriptor;
	void FarFieldVoiceControllerThread();
	std::thread m_ffvControllerThread;
	bool m_ffvControllerThreadActive;
	void kwdCallbackThread();
	void eocCallbackThread();
	std::string testCommandResponse = "";
	int64_t m_sampleNum;		// Keyword channel audio sample number
	bool m_eocTimedOut;			// End of Command timed out
};  // class FarFieldVoiceController
