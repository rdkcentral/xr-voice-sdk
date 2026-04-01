//
// MFVservice.h
//
// Contains the definition of Mid Field Voice service.
//

#pragma once

#include <stdint.h>
#include <stdbool.h>

// Windows definitions.
#ifdef _WIN32

#include <windows.h> 

typedef HANDLE MFVfileDescriptor;							// file descriptor (Windows pipe handle)
#define MFV_INVALID_FILE_DESCRIPTOR INVALID_HANDLE_VALUE	// invalid File Descriptor value

// Linux definitions.
#else

typedef int MFVfileDescriptor;			// file descriptor
#define MFV_INVALID_FILE_DESCRIPTOR -1	// invalid File Descriptor value

#endif

// Mid Field Voice service handle.
typedef void* MFVserviceHandle_t;

// Mid Field Voice service API status values.
typedef enum
{
	MFV_Success = 0,			// success
	MFV_Error = 1,				// error
	MFV_InvalidArgument = 2		// invalid argument
} MFVapiStatus_t;

// Mid Field Voice service session configuration.
typedef struct
{
	uint8_t detectionType;		// detection type (remote's Session Start value)
	int16_t sowSampleOffset;	// sample offset to start of wake word in remote audio stream
	int16_t eowSampleOffset;	// sample offset to end of wake word in remote audio stream
	int16_t kwdConfidence;		// keyword detect confidence level from remote
} MFVsessionConfig_t;

// Mid Field Voice service status.
typedef struct
{
	bool sessionActive;					// indicates a session is active (started)
	bool keywordDetected;				// indicates a keyword was detected in the remote audio stream
	bool commandDetected;				// indicates a command was detected in the remote audio stream
	bool tvAudioKwDetected;				// indicates a keyword was detected in the TV audio output
	int32_t sowSampleOffset;			// sample offset to start of keyword in audio stream
	int32_t eowSampleOffset;			// sample offset to end of keyword in audio stream
	int32_t eocSampleOffset;			// sample offset to end of command in audio stream
	float kwdSensitivity;				// keyword detect sensitivity
	float kwdThreshold;					// keyword detect trigger level threshold
	float confidenceScore;				// keyword detect confidence score
	float keywordSnrDb;					// signal to noise ratio during keyword utterance (units of dB)
	float dynamicGainDb;				// dynamic gain applied to audio (units of dB)
	char *pKeywordDetectVendorName;		// pntr to name of keyword detector vendor string
	char *pKeywordDetectComponentName;	// pntr to name of component where keyword was detected string
} MFVserviceStatus_t;

// Callback when Mid Field Voice service has verified the keyword in the remote audio stream.
typedef void (*MFVonKeywordVerifyCb_t)(bool detected);
// detected = false indicates the keyword was not found in the remote audio
// detected = true indicates the keyword was found in the remote audio

// Callback when Mid Field Voice service has detected end of voice command in the remote audio stream.
typedef void (*MFVonEndOfCommandCb_t)(int64_t sampleOffset, bool timedOut);
// sampleOffset = the relative sample offset from beginning of audio stream to end of command
// timedOut = false indicates timed out finding end of voice command in the remote audio
// timedOut = true indicates the end of voice command was found in the remote audio

//
// Open the Mid Field Voice service.
//
// The service begins keyword detection in the audio output to the speakers.
//
// Returns:
//  The Mid Field Voice service handle or NULL if an error occurs.
//
extern MFVserviceHandle_t MFVservice_Open(void);

//
// Close the Mid Field Voice service.
//
// Returns:
//  MFV_Success if service closed successfully (handle is invalid upon return)
//  MFV_InvalidArgument if handle is invalid
//
extern MFVapiStatus_t MFVservice_Close(
	MFVserviceHandle_t handle	// Mid Field Voice service handle
);

//
// Start Mid Field Voice service session.
//
// The service creates a pipe for passing audio from the remote control to the
// service. A file descriptor to be used by the client to write to the pipe is
// returned in *pRemoteAudioWriteFd. The pipe is created with the blocking
// mode specified via remoteAudioWritedNonBlock.
//
// The service optionally creates a pipe for passing processed audio from the
// service to the client. A file descriptor to be used by the client to read from
// the pipe is returned in *pAudioOutReadFd. If pAudioOutReadFd is NULL, the pipe
// is not created and the service does not provide processed audio. The pipe is
// created with the blocking mode specified via audioOutReadNonBlock.
//
// The service registers optional client callbacks for keyword verification and
// end of voice command notifications. The callbacks can be NULL if not used.
//
// pSessionConfig can not be NULL
// pRemoteAudioWriteFd can not be NULL
// pAudioOutReadFd can be NULL if not used
// onKeywordVerify and onEndOfCommand can be NULL if not used
//
// All audio is signed 16 bit PCM.
//
// If successful, the service begins keyword detection in the remote audio stream.
// Upon keyword detection or lack of detection, the service notifies the client via
// callback and updates the service status. If the keyword is detected, the service
// then begins detecting the end of a voice command. If a command is detected, the
// service notifies the client via callback and updates the service status.
//
// If a keyword is detected in the audio output to the speakers at the same time as
// the session, a keyword detect in the remote audio is ignored.
//
// Returns:
//  MFV_Success if session started successfully
//  MFV_InvalidArgument if handle is invalid, pSessionConfig or pRemoteAudioWriteFd is NULL
//  MFV_Error if allocation of a required resource fails
//
extern MFVapiStatus_t MFVservice_Start(
	MFVserviceHandle_t handle,				// Mid Field Voice service handle
	MFVsessionConfig_t *pSessionConfig,		// pntr to session configuration
	bool remoteAudioWritedNonBlock,			// flag: set remote audio pipe write to non blocking mode
	MFVfileDescriptor *pRemoteAudioWriteFd,	// pntr to remote audio pipe write file descriptor variable
	bool audioOutReadNonBlock,				// flag: set output audio pipe read to non blocking mode
	MFVfileDescriptor *pAudioOutReadFd,		// pntr to output audio pipe read file descriptor variable
	MFVonKeywordVerifyCb_t onKeywordVerify,	// on keyword verify callback
	MFVonEndOfCommandCb_t onEndOfCommand	// on end of command detected callback
);

//
// Stop Mid Field Voice service session.
//
// The service stops keyword detection and audio processing.
//
// Returns:
//  MFV_Success if session stopped successfully
//
extern MFVapiStatus_t MFVservice_Stop(
	MFVserviceHandle_t handle	// Mid Field Voice service handle
);

//
// Get the current status of the Mid Field Voice service.
//
// Returns:
//  MFV_Success if status returned successfully
//  MFV_InvalidArgument if handle is invalid or pStatus is NULL
//
extern MFVapiStatus_t MFVservice_GetStatus(
	MFVserviceHandle_t handle,		// Mid Field Voice service handle
	MFVserviceStatus_t *pStatus		// pntr to variable to store status
);
