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
 * FarFieldVoiceWrapper.h
 *
 * Contains the definition of the C API wrapper for the Far Field Voice HAL.
 *
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "FFVplatformDependent.h"

#ifdef __cplusplus
#include "FarFieldVoice.h"
extern "C"
{
#endif

// Far Field Voice HAL handle.
typedef void* FFVhalHandle;

// Far Field Voice HAL Controller handle.
typedef void* FFVhalControlHandle;

// HAL API status equivalent to common RDK-E HAL Binder status (::android::binder::Status).
typedef enum
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
	EX_TRANSACTION_FAILED = -129
} FFVhalApiStatus_t;

// HAL state equivalent to common RDK-E HAL State (com::rdk::hal::State).
typedef enum
{
	UNKNOWN = 0,
	CLOSED = 1,
	OPENING = 2,
	READY = 3,
	STARTING = 4,
	STARTED = 5,
	FLUSHING = 6,
	STOPPING = 7,
	CLOSING = 8
} FFVhalState_t;

// Far Field Voice HAL capabilities (equivalent to com::rdk::hal::farfieldvoice::Capabilities).
typedef struct
{
	int32_t microphoneChannelCount;		// number of microphone inputs
    bool continualChannelSupported;		// flag: Continual channel is supported
} FFVhalCapabilities_t;

// Far Field Voice HAL power mode (equivalent to com::rdk::hal::farfieldvoice::PowerMode).
typedef enum
{
	NONE = 0,			// never set or power mode change in progress (not ready)
	FULL_POWER = 1,		// Full Power
	STANDBY = 2,		// Standby
	DEEP_SLEEP = 3		// Deep Sleep
} FFVhalPowerMode_t;

// Far Field Voice HAL channel type (equivalent to com::rdk::hal::farfieldvoice::ChannelType).
typedef enum
{
	KEYWORD = 0,		// Keyword
	CONTINUAL = 1,		// Continual
	MICROPHONES = 2		// Microphones
} FFVhalChannelType_t;

// Far Field Voice HAL failure code (equivalent to com::rdk::hal::farfieldvoice::FailureCode).
typedef enum
{
	SUB_COMPONENT_FAILURE = 0,	// failure to instantiate or communicate with a sub component
	IO_FAILURE = 1				// failure to perform I/O
} FFVhalFailureCode_t;

// Far Field Voice HAL keyword detect information (equivalent to com::rdk::hal::farfieldvoice::KeywordDetectInfo).
typedef struct
{
	int64_t beginSampleOffset;			// keyword channel sample offset to the beginning of the keyword
	int64_t endSampleOffset;			// keyword channel sample offset to the end of the keyword
	float detectSensitivity;			// keyword detect sensitivity (keyword detector vendor specific units)
	float lowDetectThreshold;			// keyword detect low trigger level threshold (keyword detector vendor specific units)
	float highDetectThreshold;			// keyword detect high trigger level threshold (keyword detector vendor specific units)
	bool highThresholdTriggered;		// keyword detect triggered by high level threshold (highDetectThreshold)
	float confidenceScore;				// keyword detect confidence score (keyword detector vendor specific units)
	float keywordSnrDb;					// signal to noise ratio during the keyword utterance (units of dB)
	int32_t directionOfArrivalDegrees;	// keyword direction of arrival (units of degrees)
	float dynamicGainDb;				// dynamic gain applied to audio (units of dB)
	const char *pKeywordDetectVendorName;		// pntr to name of keyword detector vendor string
	const char *pKeywordDetectComponentName;	// pntr to name of component where keyword was detected string
} FFVhalKwdInfo_t;

// Far Field Voice HAL status (equivalent to com::rdk::hal::farfieldvoice::Status).
typedef struct
{
	const char *pCodeBuildVersion;			// pntr to build version of this Far Field Voice HAL code instance string
	FFVhalPowerMode_t powerMode;			// current power mode
	bool keywordChannelOpen;				// indicates if the Keyword channel has been opened
	bool continualChannelOpen;				// indicates if the Continual channel has been opened
	bool microphonesChannelOpen;			// indicates if the Microphones channel has been opened
	bool keywordDetected;					// indicates if a keyword was detected on the Keyword channel
	FFVhalKwdInfo_t keywordDetectInfo;		// Keyword detect information (applicable only if keywordDetected is true)
	bool privacyStateActive;				// indicates if privacy state is active
	int64_t keywordChannelSamplesLost;		// total number of keyword channel samples lost due to buffer overflow
	int64_t continualChannelSamplesLost;	// total number of continual channel samples lost due to buffer overflow
	int64_t microphoneChannelsSamplesLost;	// total number of microphone channels samples lost due to buffer overflow 
	int64_t vendorErrorCode;				// vendor specific error code to indicate an error condition
} FFVhalStatus_t;

// Callback when Far Field Voice HAL has transitioned to a new state.
typedef void (*FFVhalOnStateChangedCb_t)(FFVhalState_t oldState, FFVhalState_t newState);

// Callback when Far Field Voice has transitioned to a new power mode.
typedef void (*FFVhalOnEnteredPowerModeCb_t)(FFVhalPowerMode_t powerMode);

// Callback when Far Field Voice has failed.
typedef void (*FFVhalOnHardwareFailedCb_t)(FFVhalFailureCode_t failureCode);

// Callback when Far Field Voice Controller has detected the keyword on the Keyword channel.
typedef void (*FFVhalOnKeywordDetectedCb_t)(FFVhalKwdInfo_t keywordDetectInfo);

// Callback when Far Field Voice Controller has detected end of voice command on the Keyword channel.
typedef void (*FFVhalOnEndOfCommand_t)(long sampleOffset, bool timedOut);

//
// Get a handle to the Far Field Voice HAL.
//
// Returns:
//	The Far Field Voice HAL handle or NULL if an error occurs.
//
FFVhalHandle FFVhal_getService(void);

//
// Release usage of the Far Field Voice HAL.
//
// Returns:
//  nothing (handle is invalid upon return)
//
// Note: All pointers to strings provided by the HAL become invalid after
//       calling FFVhal_destroy.
//
void FFVhal_destroy(
	FFVhalHandle handle			// Far Field Voice HAL handle
);

//
// Get the capabilities of the Far Field Voice HAL.
//
// Returns:
//	EX_NONE = Success (capabilities are stored in pCapabilities)
//	EX_NULL_POINTER = handle or pCapabilities is NULL, or HAL destroyed
//
FFVhalApiStatus_t FFVhal_GetCapabilities(
	FFVhalHandle handle,					// Far Field Voice HAL handle
	FFVhalCapabilities_t *pCapabilities		// pntr to variable to store capabilities
);

//
// Get the current state of the Far Field Voice HAL.
//
// Returns:
//	EX_NONE = Success (state is stored in pState)
//	EX_NULL_POINTER = handle or pState is NULL, or HAL destroyed
//
FFVhalApiStatus_t FFVhal_getState(
	FFVhalHandle handle,				// Far Field Voice HAL handle
	FFVhalState_t *pState				// pntr to variable to store state
);

//
// Get the current status of the Far Field Voice HAL.
//
// Returns:
//	EX_NONE = Success (status is stored in pStatus)
//	EX_NULL_POINTER = handle or pStatus is NULL, or HAL destroyed
//
// Note: All pointers to strings provided by the HAL become invalid after
//       calling FFVhal_destroy.
//
FFVhalApiStatus_t FFVhal_getStatus(
	FFVhalHandle handle,				// Far Field Voice HAL handle
	FFVhalStatus_t *pStatus				// pntr to variable to store status
);

//
// Register Far Field Voice event listeners.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = handle is NULL, or HAL destroyed
//
// Note: Any callback may be NULL if not needed.
//
FFVhalApiStatus_t FFVhal_registerEventListeners(
	FFVhalHandle handle,										// Far Field Voice HAL handle
	FFVhalOnStateChangedCb_t onStateChanged,					// on state changed callback
	FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode,			// on entered power mode callback
	FFVhalOnHardwareFailedCb_t onHardwareFailed					// on failure callback
);

//
// Unregister Far Field Voice event listeners.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = handle is NULL, or HAL destroyed
//
// Note: All callbacks must be the same as passed to FFVhal_registerEventListeners.
//
FFVhalApiStatus_t FFVhal_unregisterEventListeners(
	FFVhalHandle handle,										// Far Field Voice HAL handle
	FFVhalOnStateChangedCb_t onStateChanged,					// on state changed callback
	FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode,			// on entered power mode callback
	FFVhalOnHardwareFailedCb_t onHardwareFailed					// on failure callback
);

//
// Open the Far Field Voice HAL.
//
// If successful, the Far Field Voice HAL transitions to an `OPENING` state and then
// a `READY` state which is notified to any registered onStateChanged listener.
//
// The returned controller handle is used by the client to configure and control voice processing.
// There can only be one client in control of voice processing.
//
// Prerequisites:
//	HAL's current state must be CLOSED.
//
// Returns:
//	EX_NONE = Success (HAL controller handle stored in pControllerHandle)
//	EX_NULL_POINTER = handle or pControllerHandle is NULL, or HAL destroyed, or failed to create controller
//	EX_ILLEGAL_STATE = HAL's current state is not CLOSED
//
// Note: Any callback may be NULL if not needed.
//
FFVhalApiStatus_t FFVhal_open(
	FFVhalHandle handle,							// Far Field Voice HAL handle
	FFVhalOnKeywordDetectedCb_t onKeywordDetected,	// on keyword detected callback
	FFVhalOnEndOfCommand_t onEndOfCommand,			// on end of command detected callback
	FFVhalControlHandle *pControllerHandle			// pntr to Far Field Voice HAL Controller handle variable
);

//
// Close the Far Field Voice HAL.
//
// If successful, the Far Field Voice HAL transitions to a `CLOSING` state and then
// a `CLOSED` state which is notified to any registered onStateChanged listener.
//
// Prerequisites:
//	HAL's current state must be READY.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = handle is NULL, or HAL destroyed
//	EX_ILLEGAL_STATE = HAL's current state is not READY
//
FFVhalApiStatus_t FFVhal_close(
	FFVhalHandle handle					// Far Field Voice HAL handle
);

//
// Open an audio channel.
//
// If successful, creates and returns a pipe for passing the specified channel type audio to the
// client and the specified channel type is in the open state.
//
// If the channel type is Keyword:
//
// 	Keyword channel audio processing is initialized and keyword detection is started. Upon keyword
// 	detection, audio samples are written to the Keyword channel's pipe.
//
//  Audio data is signed 16 bits per sample at 16kHz sampling rate. The endian order of each sample
//  value is that of the host processor's native endian order.
//
//  Once a keyword is detected, the Far Field Voice HAL begins writing audio samples to the Keyword
//  channel's pipe whenever audio samples are available. Initially, samples may be written to the pipe
//  faster than real time as audio buffered within the HAL is provided as fast as possible. Once all
//  buffered audio is written to the pipe, audio will be written at a rate based on 16kHz sampling rate
//  (real time).
//
// 	The following controller callbacks can occur after the Keyword channel is opened.
//	 onKeywordDetected()
//	 onEndOfCommand()
//
//  The sample offset values provided in 'onKeywordDetected' and 'onEndOfCommand' are the relative
//  sample number with respect to the audio samples written to the Keyword channel's pipe. A sample
//  offset value of zero corresponds to the first sample written after opening the Keyword channel.
//
//  Prerequisites:
//	 The Keyword channel must be in the closed state.
//	 The Microphones channel must be in the closed state.
//	 The power mode must be Full Power or Standby.
//
//  Returns:
//   EX_ILLEGAL_ARGUMENT = Invalid channel type
//	 EX_ILLEGAL_STATE = Keyword channel is already open, Microphones channel is open, or power mode is not STANDBY or FULL_POWER
//
// If the channel type is Continual:
//
//  Continual channel audio processing is initialized and audio samples are written to the Continual
//  channel's pipe at 16kHz sampling rate. Audio data is signed 16 bits per sample. The endian order
//  of each sample value is that of the host processor's native endian order.
//
//  Prerequisites:
//	 The Continual channel must be in the closed state.
//	 The Microphones channel must be in the closed state.
//	 The power mode must be Full Power.
//
//  Returns:
//	 EX_ILLEGAL_ARGUMENT = Invalid channel type or the Continual channel is not supported 
//	 EX_ILLEGAL_STATE = Continual channel is already open, Microphones channel is open, or power mode is not FULL_POWER
//
// If the channel type is Microphones:
//
//  Raw microphone data is written to the Microphones channel's pipe at 16kHz sampling rate. Sample
//  values are signed 32 bits per sample. The endian order of each sample value is that of the host
//  processor's native endian order. Multiple microphones are interleaved by sample with the number
//  of microphones being equal to the microphoneChannelCount field in the FFVhalCapabilities_t structure
//  provided by FFVhal_GetCapabilities.
//
//  Prerequisites:
//	 The Microphones channel must be in the closed state.
//	 The Keyword channel must be in the closed state.
//	 The Continual channel must be in the closed state.
//	 The power mode must be Full Power.
//
//  Returns:
//   EX_ILLEGAL_ARGUMENT = Invalid channel type
//   EX_ILLEGAL_STATE = Microphones channel is already open, Keyword or Continual channel are open,
//                      or power mode is not FULL_POWER
//
// Common to all channel types:
//
//  Returns:
//	 EX_NONE = Success (the audio channel's pipe file descriptor is stored in pFileDescriptor)
//	 EX_NULL_POINTER = controllerHandle or pFileDescriptor is NULL, or failed to create pipe, or controller failed
//
FFVhalApiStatus_t FFVhal_openChannel(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	FFVhalChannelType_t channelType,		// Far Field Voice channel type
	FFVhalFileDescriptor *pFileDescriptor	// pntr to pipe read file descriptor variable
);

//
// Close an audio channel.
//
// The specified channel type audio processing is stopped, the channel's pipe is closed, and the channel
// is in the closed state.
//
// Prerequisites:
//	The specified channel type must be in the open state.
//
// Returns:
//	EX_NONE = Success
//  EX_ILLEGAL_ARGUMENT = Invalid channel type
//	EX_NULL_POINTER = controllerHandle is NULL or controller failed
//	EX_ILLEGAL_STATE = Channel type is not open
//
// Note: The channel's pipe file descriptor becomes invalid.
//
FFVhalApiStatus_t FFVhal_closeChannel(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	FFVhalChannelType_t channelType			// Far Field Voice channel type
);

//
// Set (activate or deactivate) privacy state.
//
// All audio input will be forced to silence when privacy state is active.
// All audio input will use actual input when privacy state is inactive.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = controllerHandle is NULL or controller failed
//
FFVhalApiStatus_t FFVhal_setPrivacyState(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	bool activate							// flag: true = activate privacy state
);

//
// Set power mode.
//
// If successful, the specified power mode is initialized.
//
// Prerequisites:
//	All audio channels must be in the closed state.
//
// Returns:
//	EX_NONE = Success
//  EX_ILLEGAL_ARGUMENT = Invalid power mode
//	EX_NULL_POINTER = controllerHandle is NULL or controller failed
//	EX_ILLEGAL_STATE = An audio channel is open
//
FFVhalApiStatus_t FFVhal_setPowerMode(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	FFVhalPowerMode_t powerMode				// target power mode
);

//
// Start audio recording.
//
// Captures of audio will be written to wave files for test purposes. Each wave file name
// will begin with the specified base path and file name and end with a vendor specific
// extension correlating to the particular captured audio.
//
// Prerequisites:
//	The power mode must be Full Power.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = controllerHandle or pFileNamePrefix is NULL, or controller failed
//	EX_ILLEGAL_STATE = Power mode is not FULL_POWER
//	EX_ILLEGAL_ARGUMENT = Invalid file name prefix or audio select
//
FFVhalApiStatus_t FFVhal_startAudioRecording(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	const char *pFileNamePrefix,			// pntr to file name prefix (path and base file name) string
	long audioSelect						// selected audio to capture (vendor specific code)
);

//
// Stop audio recording.
//
// Captures of audio are stopped and capture files are closed.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = controllerHandle is NULL or controller failed
//
FFVhalApiStatus_t FFVhal_stopAudioRecording(
	FFVhalControlHandle controllerHandle	// Far Field Voice HAL Controller handle
);

//
// Perform a test command.
//
// Performs a vendor specific test command for test and debug purposes.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = controllerHandle or pCommand is NULL, or controller failed
//
// Note: ppResponse may be NULL if a response isn't needed. The value stored in
//       ppResponse becomes invalid after calling FFVhal_destroy.
//
FFVhalApiStatus_t FFVhal_testCommand(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	const char *pCommand,					// pntr to test command string
	const char **ppResponse					// pntr to response string pointer variable
);

#ifdef __cplusplus
}
#endif
