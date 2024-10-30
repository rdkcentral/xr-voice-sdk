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
#ifndef _XRAUDIO_DGA_H_
#define _XRAUDIO_DGA_H_

#include <stdbool.h>
#include <stdint.h>
#include <jansson.h>
#include <xraudio_version.h>

/// @file xraudio_dga.h
///
/// @defgroup XRAUDIO_DGA XRAUDIO - DYNAMIC GAIN ADJUSTMENT
/// @{
///
/// @defgroup XRAUDIO_DGA_TYPEDEFS    Typedefs
/// @defgroup XRAUDIO_DGA_FUNCTIONS   Functions
///

/// @addtogroup XRAUDIO_DGA_TYPEDEFS
/// @{
/// @brief Type Definitions
/// @details The xraudio DGA api provides structures for grouping of values.

typedef void * xraudio_dga_object_t; ///< An opaque type for the DGA object.

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRAUDIO_DGA_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio DGA api provides functions to be called directly by xraudio.

/// @brief Retreive the DGA version
/// @details Retrieves the detailed version information for the DGA component.
/// @param[in] version_info Pointer to an array of version information structures
/// @param[inout] qty       Quantity of entries in the version_info array (in), qty of entries populated (out).
/// @return The function has no return value.  It returns the version info for each component.
void                 xraudio_dga_version(xraudio_version_info_t *version_info, uint32_t *qty);

/// @brief Create an xraudio DGA object
/// @details Create an xraudio DGA object.
/// @return The function returns a reference to the object or NULL if an error occurred.
xraudio_dga_object_t xraudio_dga_object_create(const json_t *config);

/// @brief Destroy an xraudio DGA object
/// @details Destroy an xraudio DGA object.  If resources have been allocated, they will be released.
/// @param[in] object Reference to an xraudio DGA object.
/// @return The function has no return value.
void                 xraudio_dga_object_destroy(xraudio_dga_object_t object);

/// @brief Calculate gain based on an audio clip
/// @details Calculate a gain value based on a set of audio samples.
/// @param[in] object   Reference to an xraudio DGA object.
/// @param[in]
/// @param[in]
/// @param[in]
/// @param[in]
/// @param[out]   gain        Current dynamic gain value
/// @param[out]   input_level Calculated audio level of input signal in dBFS
void                 xraudio_dga_calculate(xraudio_dga_object_t object, uint8_t *pcm_bit_qty, uint32_t frame_qty, const float *samples[], uint32_t sample_qty[], float *gain, float *input_level);

/// @brief Update gain to apply to audio
/// @details Update gain to apply to audio from an externally provided peak power value
/// @param[in]    object   Reference to an xraudio DGA object.
/// @param[inout] pcm bit depth of audio samples to apply gain
/// @param[in]    peak external keyword detector power in dBFS
/// @param[out]   gain     Current dynamic gain value
void                 xraudio_dga_update(xraudio_dga_object_t object, uint8_t *pcm_bit_qty, int16_t peak_power, float *gain);

/// @brief Apply gain to audio
/// @details Apply gain to the audio provided.
/// @param[in]    object   Reference to an xraudio DGA object.
/// @param[inout] samples
/// @param[in]    sample_qty
void                 xraudio_dga_apply(xraudio_dga_object_t object, float *samples, uint32_t sample_qty);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif



