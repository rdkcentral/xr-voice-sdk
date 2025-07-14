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
 * FarFieldVoice.h
 *
 * Contains the definition of the FarFieldVoice HAL class.
 */

/**
 *  The Far Field Voice HAL provides a stream of far field audio input to the client
 *  upon detection of a keyword in the audio stream. Following detection of the keyword,
 *  the HAL detects a voice command in the stream and reports it's occurrence to the client.
 *  This stream is referred to as the Keyword channel.
 *
 *  The Far Field Voice HAL may optionally provide a second stream of audio to the client
 *  that is continual in nature. There is no keyword or voice command detection. A typical
 *  use is for a VOIP application. This stream is referred to as the Continual channel.
 *
 *  The Far Field Voice HAL may optionally provide raw microphone data to the client.
 *  A typical use is for factory testing of the microphones. This stream is referred to as
 *  the Microphone channels.
 *
 *  Multiple clients may obtain information from the Far Field Voice HAL but only one client
 *  at a time may control the Far Field Voice HAL.
 */

#pragma once

#include <mutex>
#include <thread>
#include <vector>
#include "BinderStatus.h"
#include "HalState.h"
#include "Capabilities.h"
#include "Status.h"
#include "FarFieldVoiceEventListener.h"
#include "FarFieldVoiceControllerListener.h"
#include "FarFieldVoiceController.h"

using namespace std;
using namespace hal;
using namespace farfieldvoice;

class FarFieldVoice
{
private:
	FarFieldVoice();
	~FarFieldVoice();
	static FarFieldVoice* instancePtr;
	static int instanceCnt;
	static std::mutex mtx;
	void FarFieldVoiceHalThread();
	std::thread m_ffvHalThread;
	bool m_ffvHalThreadActive{false};
	farfieldvoice::Capabilities m_capabilities;
	hal::HalState m_halState;
	farfieldvoice::Status m_ffvStatus;
	std::vector<FarFieldVoiceEventListener*> m_eventListeners;
	FarFieldVoiceController* m_controller;
	void changeStateTo(hal::HalState newState);
	friend class FarFieldVoiceController;
public:
	FarFieldVoice(const FarFieldVoice& obj) = delete;  // delete  copy constructor to prevent copies

   /**
     * Get a pointer to the Far Field Voice HAL class. The class is a singleton and created if needed.
     *
     * @returns A pointer to the Far Field Voice HAL class.
     */
	static FarFieldVoice* getService()
	{
		std::lock_guard<std::mutex> lock(mtx);
		if (instancePtr == nullptr)
		{
			instancePtr = new FarFieldVoice();
			instanceCnt++;
		}
		return instancePtr;
	}

   /**
     * Destroy the Far Field Voice HAL class. The class is a singleton and destroyed if needed.
     *
     * @returns Capabilities parcelable.
     */
	static void destroy()
	{
		std::lock_guard<std::mutex> lock(mtx);
		if ((instancePtr != nullptr) && (instanceCnt > 0))
		{
			if (--instanceCnt == 0)
			{
				delete instancePtr;
				instancePtr = nullptr;
			}
		}
	}
    /**
     * Get the capabilities of the Far Field Voice HAL.
     *
     * @returns farfieldvoice::Capabilities.
     */
	hal::BinderStatus getCapabilities(farfieldvoice::Capabilities* capabilities);

	/**
	 * Gets the current state of the Far Field Voice service.
     *
     * @returns hal::HalState - Current state.
	 *
     * @see FarFieldVoiceEventListener.onStateChanged().
     */
	hal::BinderStatus getState(hal::HalState* halState);

    /**
     * Get the current status of the Far Field Voice HAL.
     *
     * @returns farfieldvoice::Status - Current status.
     */
	hal::BinderStatus getStatus(farfieldvoice::Status* ffvStatus);

    /**
     * Register a Far Field Voice event listener.
     * 
     * A `FarFieldVoiceEventListener` can only be registered once and will fail on subsequent
     * registration attempts.
     *
     * The listener is notified when a Far Field Voice event occurs.
     *
     * @param[in] listener	Listener object for callbacks.
     *
     * @return boolean
     * @retval true		The event listener was registered.
     * @retval false	The event listener is already registered.
     *
     * @see unregisterEventListener()
     */
	hal::BinderStatus registerEventListener(FarFieldVoiceEventListener* listener, bool* result);

    /**
     * Unregister a Far Field Voice event listener.
     *
     * @param[in] listener		Listener object for callbacks.
     *
     * @return boolean
     * @retval true		The event listener was unregistered.
     * @retval false	The event listener was not found registered.
     *
     * @see registerEventListener()
     */
	hal::BinderStatus unregisterEventListener(FarFieldVoiceEventListener* listener, bool* result);

    /**
	 * Open the Far Field Voice HAL.
     *
     * If successful, the Far Field Voice HAL transitions to an `OPENING`
     * state and then a `READY` state which is notified to any registered
     * `FarFieldVoiceEventListener` interface.
     *
     * Controller related callbacks are made through the `FarFieldVoiceControllerListener`
     * passed into the call.
     *
     * The returned `FarFieldVoiceController` interface is used by the client
     * to configure and control voice processing. There can only be one client
     * in control of voice processing.
     *
     * @param[in] controllerListener	Listener object for controller callbacks.
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE	The Far Field Voice HAL state is not HalState::CLOSED.
     * @exception hal::BinderStatus EX_NULL_POINTER 	'controller' is null or FarFieldVoiceController create failed.
     * 
     * @returns FarFieldVoiceController or null if not in the CLOSED state.
     * 
     * @pre Resource is in hal::HalState::CLOSED state.
     * 
     * @see IFarFieldVoiceController, close(), registerEventListener()
     */
	hal::BinderStatus open(FarFieldVoiceControllerListener* controllerListener, FarFieldVoiceController** controller);

    /**
     * Close the Far Field Voice HAL.
     *
     * The Far Field Voice HAL must be in a `READY` state before it can be closed.
     * If successful the Far Field Voice HAL transitions to a `CLOSING` state and then
     * a `CLOSED` state. `onStateChanged(CLOSING, CLOSED)` will be notified on any registered
     * listener interface.
     *
     * @param[in] controller	Instance of FarFieldVoiceController returned by open().
     *
     * @exception hal::BinderStatus EX_ILLEGAL_STATE		The Far Field Voice HAL state is not HalState::READY.
     * @exception hal::BinderStatus EX_ILLEGAL_ARGUMENT 	'controller' is not same as returned by open().
     *
     * @return boolean
     * @retval true		Successfully closed.
     * @retval false	Invalid state or unrecognised parameter.
     *
     * @pre Resource is in hal::HalState::READY state.
     *
     * @see open()
     */
	hal::BinderStatus close(FarFieldVoiceController* controller, bool* result);

};	// class FarFieldVoice
