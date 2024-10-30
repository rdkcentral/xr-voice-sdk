/*
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
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
#ifndef _XRAUDIO_EOS_H_
#define _XRAUDIO_EOS_H_

#include <stdbool.h>
#include <stdint.h>
#include <jansson.h>
#include <xraudio_version.h>

/// @file xraudio_eos.h
///
/// @defgroup XRAUDIO_EOS XRAUDIO - END OF SPEECH
/// @{
///
/// @defgroup XRAUDIO_EOS_ENUMS       Enumerations
/// @defgroup XRAUDIO_EOS_TYPEDEFS    Type Definitions
/// @defgroup XRAUDIO_EOS_FUNCTIONS   Functions
///

/// @addtogroup XRAUDIO_EOS_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio EOS api provides enumerated types for logical groups of values.

typedef enum {
   XRAUDIO_EOS_EVENT_NONE,            ///< No EOS event has occurred
   XRAUDIO_EOS_EVENT_STARTOFSPEECH,   ///< Start of speech was detected
   XRAUDIO_EOS_EVENT_ENDOFSPEECH,     ///< End of speech was detected
   XRAUDIO_EOS_EVENT_TIMEOUT_INITIAL, ///< No speech detected within a timeout period whose timer starts when speech begins
   XRAUDIO_EOS_EVENT_TIMEOUT_END,     ///< No end of speech detected within timeout period whose timer starts when speech begins
   XRAUDIO_EOS_EVENT_END_OF_WAKEWORD, ///< End of wakeword was detected
   XRAUDIO_EOS_EVENT_INVALID          ///< An invalid event
} xraudio_eos_event_t;

/// @}

/// @addtogroup XRAUDIO_EOS_TYPEDEFS
/// @{
/// @brief Type Definitions
/// @details The xraudio EOS api provides type definitions for renaming types.

typedef void * xraudio_eos_object_t; ///< An opaque type for the EOS object.

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRAUDIO_EOS_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio EOS api provides functions to be called directly by xraudio.

/// @brief Retreive the EOS version
/// @details Retrieves the detailed version information for the EOS component.
/// @param[in] version_info Pointer to an array of version information structures
/// @param[inout] qty       Quantity of entries in the version_info array (in), qty of entries populated (out).
/// @return The function has no return value.  It returns the version info for each component.
void                 xraudio_eos_version(xraudio_version_info_t *version_info, uint32_t *qty);

/// @brief Create an xraudio EOS object
/// @details Create an xraudio EOS object.
/// @param[in] signal_level_only If true, indicates that only signal level needs to be calculated.  Otherwise, both end of speech events and signal level need to be calculated.
/// @return The function returns a reference to the object or NULL if an error occurred.
xraudio_eos_object_t xraudio_eos_object_create(bool signal_level_only, const json_t *config);

/// @brief Initialize an xraudio EOS session
/// @details Initialize an xraudio EOS session with the provided parameters.
/// @param[in] object   Reference to an xraudio EOS object.
/// @param[in] chan_qty Deprecated.  Will be removed.
/// @param[in] params   Deprecated.  Will be removed.
/// @return The function returns true for success and false for failure.
bool                 xraudio_eos_init(xraudio_eos_object_t object, uint8_t chan_qty, void *params);

/// @brief Destroy an xraudio EOS object
/// @details Destroy an xraudio EOS object.  If resources have been allocated, they will be released.
/// @param[in] object Reference to an xraudio EOS object.
/// @return The function has no return value.
void                 xraudio_eos_object_destroy(xraudio_eos_object_t object);

/// @brief Run an xraudio EOS session
/// @details This function is called to execute the end of speech detector on the sample buffer of single precision floating point PCM samples.
/// @param[in]  object             Reference to an xraudio EOS object.
/// @param[in]  sample_buffer      Pointer to an array of single precision float PCM samples
/// @param[in]  sample_qty         Quantity of samples in the sample_buffer array
/// @param[out] scaled_eos_samples Pointer to an array of 16-bit samples returned by the component for capture purposes.  If NULL, the parameter is ignored.
/// @return The function returns the current EOS event based on the input audio.
xraudio_eos_event_t  xraudio_eos_run_float(xraudio_eos_object_t object, const float *sample_buffer, uint32_t sample_qty, int16_t *scaled_eos_samples);

/// @brief Run an xraudio EOS session
/// @details This function is called to execute the end of speech detector on the sample buffer of 16-bit signed PCM samples.
/// @param[in] object        Reference to an xraudio EOS object.
/// @param[in] sample_buffer Pointer to an array of 16-bit signed PCM samples
/// @param[in] sample_qty    Quantity of samples in the sample_buffer array
/// @return The function returns the current EOS event based on the input audio.
xraudio_eos_event_t  xraudio_eos_run_int16(xraudio_eos_object_t object, int16_t *sample_buffer, uint32_t sample_qty);

/// @brief Inform xraudio EOS session of speech begin
/// @details Informs the end of speech detector that speech detection has started.
/// @param[in] object Reference to an EOS object.
/// @return The function has no return value.
void                 xraudio_eos_state_set_speech_begin(xraudio_eos_object_t object);

/// @brief Inform xraudio EOS session of speech end
/// @details Informs the end of speech detector that speech detection has ended.
/// @param[in] object Reference to an EOS object.
/// @return The function has no return value.
void                 xraudio_eos_state_set_speech_end(xraudio_eos_object_t object);

/// @brief Retrieve an xraudio EOS session signal level
/// @details Retrieve the current signal level for this end of speech detector.
/// @param[in] object Reference to an xraudio EOS object.
/// @return The function returns the signal level in percent (0-100).
unsigned char        xraudio_eos_signal_level_get(xraudio_eos_object_t object);

/// @brief Retrieve an xraudio EOS session SNR
/// @details Retrieve the current signal to noise ratio for this end of speech detector.
/// @param[in] object Reference to an xraudio EOS object.
/// @return The function returns the current signal to noise ratio in DB.
float                xraudio_eos_signal_to_noise_ratio_get(xraudio_eos_object_t object);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif
