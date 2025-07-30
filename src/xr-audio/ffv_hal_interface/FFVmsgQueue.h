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
 * FFVmsgQueue.h
 *
 * Contains the definition of a message queue used by the Far Field Voice HAL controller.
 */

#pragma once

#include <stdint.h>
#include <unistd.h>
#include <semaphore.h>
#include "FarFieldVoiceController.h"

#ifdef _WIN32
#include <windows.h> 
#endif

class FarFieldVoiceController;

using namespace farfieldvoice;

class FFVmsgQueue
{
private:
	friend class FarFieldVoiceController;
	FFVmsgQueue();
	~FFVmsgQueue();
	bool m_createFailed;		// flag: create failed
	bool sendMessage(uint8_t *pMessage, uint32_t messageLengthBytes);
	bool receiveMessage(uint8_t *pMessageBufr, uint32_t *pMessageLengthBytes, bool waitForever);

    /**
	 * Far Field Voice private message queue.
     */
#ifdef _WIN32	// Windows
	HANDLE m_pipeReadHandle;	// pipe read handle
	HANDLE m_pipeWriteHandle;	// pipe write handle
	HANDLE m_semaphoreHandle;	// semaphore handle
#else	// Linux
	int m_pipeReadFileDescriptor;	// pipe read file descriptor
	int m_pipeWriteFileDescriptor;	// pipe write file descriptor
	sem_t m_semaphore;				// semaphore
	int m_semStatus;				// semaphore init status
#endif
};  // class FFVmsgQueue

// Far Field Voice HAL Controller internal message type codes.
#define FFV_MSG_EXIT 1
#define FFV_MSG_OPEN_KEYWORD_CHANNEL 2
#define FFV_MSG_CLOSE_KEYWORD_CHANNEL 3
#define FFV_MSG_CLOSE_KEYWORD_CHANNEL_ACK 4
#define FFV_MSG_OPEN_CONTINUAL_CHANNEL 5
#define FFV_MSG_CLOSE_CONTINUAL_CHANNEL 6
#define FFV_MSG_CLOSE_CONTINUAL_CHANNEL_ACK 7
#define FFV_MSG_OPEN_MICROPHONES_CHANNEL 8
#define FFV_MSG_CLOSE_MICROPHONES_CHANNEL 9
#define FFV_MSG_CLOSE_MICROPHONES_CHANNEL_ACK 10
#define FFV_MSG_START_PRIVACY_STATE 11
#define FFV_MSG_STOP_PRIVACY_STATE 12
#define FFV_MSG_ENTER_FULLPOWER_MODE 13
#define FFV_MSG_ENTER_FULLPOWER_MODE_ACK 14
#define FFV_MSG_ENTER_STANDBY_MODE 15
#define FFV_MSG_ENTER_STANDBY_MODE_ACK 16
#define FFV_MSG_ENTER_DEEPSLEEP_MODE 17
#define FFV_MSG_ENTER_DEEPSLEEP_MODE_ACK 18
#define FFV_MSG_START_RECORDING 19
#define FFV_MSG_STOP_RECORDING 20
#define FFV_MSG_STOP_RECORDING_ACK 21
#define FFV_MSG_TEST_COMMAND 22
#define FFV_MSG_TEST_COMMAND_ACK 23
