/*
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2026 RDK Management
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

/** @brief
 *
 * xr_ffv_hal_plugin.h
 *
 * Contains the definition of the C API wrapper for the Far Field Voice HAL.
 *
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include "FarFieldVoice.h"
extern "C"
{
#endif

// Windows definitions.
#ifdef _WIN32
#include <windows.h> 
typedef HANDLE FFVhalFileDescriptor;	// file descriptor (Windows pipe handle)
// Linux definitions.
#else
typedef int FFVhalFileDescriptor;		// file descriptor
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

// HAL state equivalent to common RDK-E HAL State (com::rdk::hal::farfieldvoice::State).
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
#define MAX_FFV_CHAN_TYPES 2	// maximum FFV HAL channel types supported
typedef struct
{
	const char *channelTypes[MAX_FFV_CHAN_TYPES];	// array of channel types supported (null terminated string)
													// "KEYWORD" = Keyword channel
													// "MICROPHONES" = Raw microphones channel
													// NULL if not supported
	int32_t microphoneChannelCount;		// number of microphone inputs
} FFVhalCapabilities_t;

// Far Field Voice HAL power mode (equivalent to com::rdk::hal::farfieldvoice::PowerMode).
typedef enum
{
	NONE = 0,			// never set or power mode change in progress (not ready)
	FULL_POWER = 1,		// Full Power
	STANDBY = 2,		// Standby
	DEEP_SLEEP = 3		// Deep Sleep
} FFVhalPowerMode_t;

// Far Field Voice HAL failure code (equivalent to com::rdk::hal::farfieldvoice::FailureCode).
typedef enum
{
	SUB_COMPONENT_FAILURE = 0,	// failure to instantiate or communicate with a sub component
	IO_FAILURE = 1				// failure to perform I/O
} FFVhalFailureCode_t;

// Far Field Voice HAL status (equivalent to com::rdk::hal::farfieldvoice::Status).
typedef struct
{
	FFVhalPowerMode_t powerMode;			// current power mode
	bool keywordDetected;					// indicates if a keyword was detected on the "KEYWORD" channel
	bool privacyStateActive;				// indicates if privacy state is active
	int64_t vendorErrorCode;				// vendor specific error code to indicate an error condition
} FFVhalStatus_t;

// Far Field Voice HAL channel status (equivalent to com::rdk::hal::farfieldvoice::ChannelStatus).
typedef struct
{
	bool channelIsOpen;			// indicates if the channel has been opened
	int32_t samplesLost;		// total number of samples lost due to buffer overflow
} FFVhalChannelStatus_t;

// Callback when Far Field Voice HAL has transitioned to a new state.
typedef void (*FFVhalOnStateChangedCb_t)(FFVhalState_t oldState, FFVhalState_t newState);

// Callback when Far Field Voice has transitioned to a new power mode.
typedef void (*FFVhalOnEnteredPowerModeCb_t)(FFVhalPowerMode_t powerMode);

// Callback when Far Field Voice has failed.
typedef void (*FFVhalOnHardwareFailedCb_t)(FFVhalFailureCode_t failureCode);

// Callback when Far Field Voice Controller has detected the keyword on the "KEYWORD" channel.
typedef void (*FFVhalOnKeywordDetectedCb_t)(void);

// Callback when Far Field Voice Controller has detected end of voice command on the "KEYWORD" channel.
typedef void (*FFVhalOnEndOfCommand_t)(int32_t sampleOffset, bool timedOut);

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
FFVhalApiStatus_t FFVhal_getStatus(
	FFVhalHandle handle,				// Far Field Voice HAL handle
	FFVhalStatus_t *pStatus				// pntr to variable to store status
);

//
// Get the current status of a Far Field Voice channel.
//
// Returns:
//	EX_NONE = Success (channel status is stored in pChannelStatus)
//	EX_NULL_POINTER = handle or pChannelStatus is NULL, or HAL destroyed
//	EX_ILLEGAL_ARGUMENT = invalid channel type
//
FFVhalApiStatus_t FFVhal_getChannelStatus(
	FFVhalHandle handle,					// Far Field Voice HAL handle
	const char *pChannelType,				// pntr to channel type string
	FFVhalChannelStatus_t *pChannelStatus	// pntr to variable to store channel status
);

//
// Get keyword detect meta data.
//
// Returns:
//	EX_NONE = Success (pointer to meta data string is stored in ppMetaData)
//	EX_NULL_POINTER = handle or ppMetaData is NULL, or HAL destroyed
//	EX_ILLEGAL_STATE = the keyword was not detected
//
FFVhalApiStatus_t FFVhal_getKeywordMetaData(
	FFVhalHandle handle,		// Far Field Voice HAL handle
	unsigned char **ppMetaData	// pntr to meta data pointer variable
);

//
// Set vendor defined configuration.
//
// Returns:
//	EX_NONE = Success
//	EX_NULL_POINTER = handle or pConfiguration is NULL, or HAL destroyed
//	EX_ILLEGAL_ARGUMENT = invalid configuration
//
FFVhalApiStatus_t FFVhal_setConfiguration(
	FFVhalHandle handle,		// Far Field Voice HAL handle
	char *pConfiguration		// pntr to configuration string
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
	FFVhalHandle handle,								// Far Field Voice HAL handle
	FFVhalOnStateChangedCb_t onStateChanged,			// on state changed callback
	FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode,	// on entered power mode callback
	FFVhalOnHardwareFailedCb_t onHardwareFailed			// on failure callback
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
	FFVhalHandle handle,								// Far Field Voice HAL handle
	FFVhalOnStateChangedCb_t onStateChanged,			// on state changed callback
	FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode,	// on entered power mode callback
	FFVhalOnHardwareFailedCb_t onHardwareFailed			// on failure callback
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
// If the channel type is "KEYWORD":
//
// 	Keyword channel audio processing is initialized and keyword detection is started. Upon keyword
// 	detection, audio samples are written to the channel's pipe.
//
//  Audio data is signed 16 bits per sample at 16kHz sampling rate. The endian order of each sample
//  value is that of the host processor's native endian order.
//
//  Once a keyword is detected, the Far Field Voice HAL begins writing audio samples to the channel's
//  pipe whenever audio samples are available. Initially, samples may be written to the pipe faster
//  than real time as audio buffered within the HAL is provided as fast as possible. Once all buffered
//  audio is written to the pipe, audio will be written at a rate based on 16kHz sampling rate (real time).
//
// 	The following controller callbacks can occur after the Keyword channel is opened.
//	 onKeywordDetected()
//	 onEndOfCommand()
//
//  The sample offset values provided in 'onKeywordDetected' and 'onEndOfCommand' are the relative
//  sample number with respect to the audio samples written to the channel's pipe. A sample offset
//  value of zero corresponds to the first sample written after opening the channel.
//
//  Prerequisites:
//	 The "KEYWORD" channel must be in the closed state.
//	 The "MICROPHONES" channel must be in the closed state.
//	 The power mode must be FULL_POWER or STANDBY.
//
//  Returns:
//   EX_ILLEGAL_ARGUMENT = Invalid channel type
//	 EX_ILLEGAL_STATE = "KEYWORD" channel is already open, "MICROPHONES" channel is open,
//                      or power mode is not STANDBY or FULL_POWER
//
// If the channel type is "MICROPHONES":
//
//  Raw microphone data is written to the channel's pipe at 16kHz sampling rate. Sample values are signed
//  32 bits per sample. The endian order of each sample value is that of the host processor's native endian
//  order. Multiple microphones are interleaved by sample with the number of microphones being equal to the
//  microphoneChannelCount field in the FFVhalCapabilities_t structure provided by FFVhal_GetCapabilities.
//
//  Prerequisites:
//	 The "MICROPHONES" channel must be in the closed state.
//	 The "KEYWORD" channel must be in the closed state.
//	 The power mode must be FULL_POWER.
//
//  Returns:
//   EX_ILLEGAL_ARGUMENT = Invalid channel type
//   EX_ILLEGAL_STATE = "MICROPHONES" channel is already open, "KEYWORD" channel is open,
//                      or power mode is not FULL_POWER
//
// Common to all channel types:
//
//  Returns:
//	 EX_NONE = Success (the audio channel's pipe file descriptor is stored in pFileDescriptor)
//	 EX_NULL_POINTER = controllerHandle or pFileDescriptor is NULL, or failed to create pipe,
//                     or controller failed
//
FFVhalApiStatus_t FFVhal_openChannel(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	const char *pChannelType,				// pntr to channel type string
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
	const char *pChannelType				// pntr to channel type string
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
//	EX_NULL_POINTER = controllerHandle is NULL, or controller or initialization failed
//	EX_ILLEGAL_STATE = An audio channel is open
//
FFVhalApiStatus_t FFVhal_setPowerMode(
	FFVhalControlHandle controllerHandle,	// Far Field Voice HAL Controller handle
	FFVhalPowerMode_t powerMode				// target power mode
);

#ifdef __cplusplus
}
#endif
