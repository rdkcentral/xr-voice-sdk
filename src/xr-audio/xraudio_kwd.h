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
#ifndef _XRAUDIO_KWD_H_
#define _XRAUDIO_KWD_H_

#include <stdbool.h>
#include <stdint.h>
#include <jansson.h>
#include <xraudio_version.h>

/// @file xraudio_kwd.h
///
/// @defgroup XRAUDIO_KWD XRAUDIO - KEYWORD DETECTOR
/// @{
///
/// @defgroup XRAUDIO_KWD_TYPEDEFS    Typedefs
/// @defgrouo XRAUDIO_KWD_ENUMS       Enumerations
/// @defgroup XRAUDIO_KWD_STRUCTS     Structures
/// @defgroup XRAUDIO_KWD_FUNCTIONS   Functions
///

/// @addtogroup XRAUDIO_KWD_TYPEDEFS
/// @{
/// @brief Type defintions
/// @details The xraudio KWD api provides type definitions for renaming types.

/// @brief xraudio KWD object
/// @details The xraudio KWD object type is returned by the xraudio_kwd_object_create api.  It is used in all subsequent calls to xraudio_kwd api's.
typedef void *xraudio_kwd_object_t;

/// @brief xraudio KWD score
/// @details The xraudio KWD score is used to store the confidence score for a given keyword detection.
typedef float xraudio_kwd_score_t;

/// @brief xraudio KWD SNR
/// @details The xraudio KWD SNR type is used to store the signal to noise ratio in DB.
typedef float xraudio_kwd_snr_t;

/// @brief xraudio KWD sensitivity
/// @details The xraudio KWD sensitivity type is used to store the sensitivity of the keyword detector
typedef float xraudio_keyword_sensitivity_t;

/// @}

/// @addtogroup XRAUDIO_KWD_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio KWD api provides enumerated types for logical groups of values.

/// @brief xraudio KWD criterion
/// @details The xraudio KWD criterion enumeration indicates all the criteria available for determining the active channel
typedef enum {
   XRAUDIO_KWD_CRITERION_SCORE      = 0,  ///< The xraudio KWD active channel criterion is best detection score
   XRAUDIO_KWD_CRITERION_SNR        = 1,  ///< The xraudio KWD active channel criterion is best detection snr
   XRAUDIO_KWD_CRITERION_INVALID    = 2,
} xraudio_kwd_criterion_t;

/// @}

/// @addtogroup XRAUDIO_KWD_STRUCTS
/// @{
/// @brief Structures
/// @details The xraudio kwd api provides structures for grouping of values.


/// @brief xraudio keyword endpoint structure
/// @details The keyword endpoint structure returned by keyword result function.
typedef struct {
   bool         valid;                    ///< true if the endpoint is valid, false otherwise
   int32_t      pre;                      ///< the negative offset in samples from current point to start of buffered audio data
   int32_t      begin;                    ///< the negative offset in samples from current point to the beginning of the keyword
   int32_t      end;                      ///< the negative/positive offset in samples from current point to the end of the keyword
   const char * detector_name;            ///< the name of the keyword detector in use
   bool         end_of_wuw_ext_enabled;   ///< true if the detector has enabled extended detection of the end of wakeup word, false if disabled.
   bool         talker_thresh_enabled;    ///< true if the detector has enabled talker level threshold test before reporting wakeup word detection.
   float        talker_threshold_dBSPL;   ///< the minimum talker level (in dBSPL) allowed below which wakeup words are ignored.
   float        kwd_gain;                 ///< the gain applied to audio at input of keyword detector
} xraudio_kwd_endpoints_t;

/// @brief xraudio keyword result structure
/// @details The keyword result structure returned by a keyword detector.
typedef struct {
   float    score;
   float    snr;
   uint16_t doa;
   float    dynamic_gain;
} xraudio_kwd_chan_result_t;

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRAUDIO_KWD_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio KWD api provides functions to be called directly by xraudio.

/// @brief Retreive the KWD version
/// @details Retrieves the detailed version information for the KWD component.
/// @param[in] version_info Pointer to an array of version information structures
/// @param[inout] qty       Quantity of entries in the version_info array (in), qty of entries populated (out).
/// @return The function has no return value.  It returns the version info for each component.
typedef void                 (*xraudio_kwd_func_version_t)(xraudio_version_info_t *version_info, uint32_t *qty);

/// @brief Create an xraudio KWD object
/// @details Create an xraudio KWD object.
/// @return The function returns a reference to the object or NULL if an error occurred.
typedef xraudio_kwd_object_t (*xraudio_kwd_func_object_create_t)(const json_t *config);

/// @brief Destroy an xraudio KWD object
/// @details Destroy an xraudio KWD object.  If resources have been allocated, they will be released.
/// @param[in] object Reference to an xraudio KWD object.
/// @return The function has no return value.
typedef void                 (*xraudio_kwd_func_object_destroy_t)(xraudio_kwd_object_t object);

/// @brief Initialize an xraudio KWD session
/// @details Initialize an xraudio KWD session with the provided parameters.  Returns true for success and false for failure.
/// @param[in] object   Reference to an xraudio KWD object.
/// @param[in]
/// @param[in]
typedef bool                 (*xraudio_kwd_func_init_t)(xraudio_kwd_object_t object, uint8_t chan_qty, xraudio_keyword_sensitivity_t *sensitivity, int *spot_delay, xraudio_kwd_criterion_t *criterion);

/// @brief Update xraudio KWD parameters
/// @details Update an xraudio KWD object with the provided parameters.  Returns true for success and false for failure.
/// @param[in] object   Reference to an xraudio KWD object.
/// @param[in]
typedef bool                 (*xraudio_kwd_func_update_t)(xraudio_kwd_object_t object, xraudio_keyword_sensitivity_t *sensitivity);

/// @brief Run an xraudio KWD
/// @details Run the keyword detector with the provided input parameters.  Returns true for success and false for failure.
/// @param[in] object   Reference to an xraudio KWD object.
/// @param[in]
/// @param[in]
/// @param[in]
/// @param[in]
/// @param[in]
typedef bool                 (*xraudio_kwd_func_run_t)(xraudio_kwd_object_t object, uint8_t chan, const float *sample_buffer, uint32_t sample_qty, bool *detected, int16_t *scaled_kwd_samples);

typedef bool                 (*xraudio_kwd_func_run_int16_t)(xraudio_kwd_object_t object, uint8_t chan, const int16_t *sample_buffer, uint32_t sample_qty, bool *detected);

/// @brief Post-process and retrieve an xraudio KWD detection results
/// @details Returns post-processed results after the most recent detection event if required by KWD library.  Returns true for success and false for failure.
/// @param[in] object   Reference to an xraudio KWD object.
/// @param[in]
/// @param[in]
/// @param[in]
/// @param[in]
typedef bool                 (*xraudio_kwd_func_postprocess_t)(xraudio_kwd_object_t object, uint8_t chan, int32_t *start_wuw, int32_t *end_wuw);

/// @brief Retrieve an xraudio KWD detection result
/// @details Returns the results for the most recent keyword detection event.  Returns true for success and false for failure.
/// @param[in] object   Reference to an xraudio KWD object.
/// @param[in]
/// @param[in]
/// @param[in]
/// @param[in]
typedef bool                 (*xraudio_kwd_func_result_t)(xraudio_kwd_object_t object, uint8_t chan, xraudio_kwd_score_t *score, xraudio_kwd_snr_t *snr, xraudio_kwd_endpoints_t *endpoints);

/// @brief Terminate an xraudio KWD session
/// @details Terminates an xraudio KWD session if it has been initialized.
/// @param[in] object   Reference to an xraudio KWD object.
typedef void                 (*xraudio_kwd_func_term_t)(xraudio_kwd_object_t object);

/// @brief Retrieves an xraudio KWD object's parameters
/// @details Retrieves an xraudio KWD object's sensitivity limits.
/// @param[in] object   Reference to an xraudio KWD object.
/// @param[in]
/// @param[in]
typedef bool                 (*xraudio_kwd_func_sensitivity_limits_get_t)(xraudio_kwd_object_t object, xraudio_keyword_sensitivity_t *min, xraudio_keyword_sensitivity_t *max);

/// @brief TBD
/// @details TBD
/// @param[in] object   Reference to an xraudio KWD object.
/// @param[in]
/// @param[in]
typedef bool                 (*xraudio_kwd_func_sensitivity_lut_check_t)(xraudio_kwd_object_t object, xraudio_keyword_sensitivity_t *sensitivity_lut, uint8_t sensitivity_lut_size);

typedef struct {
   xraudio_kwd_func_version_t                     version;
   xraudio_kwd_func_object_create_t               object_create;
   xraudio_kwd_func_object_destroy_t              object_destroy;
   xraudio_kwd_func_init_t                        init;
   xraudio_kwd_func_update_t                      update;
   xraudio_kwd_func_run_t                         run;
   xraudio_kwd_func_run_int16_t                   run_int16;
   xraudio_kwd_func_postprocess_t                 postprocess;
   xraudio_kwd_func_result_t                      result;
   xraudio_kwd_func_term_t                        term;
   xraudio_kwd_func_sensitivity_limits_get_t      sensitivity_limits_get;
   xraudio_kwd_func_sensitivity_lut_check_t       sensitivity_lut_check;
} xraudio_kwd_plugin_api_t;

typedef xraudio_kwd_plugin_api_t *(*xraudio_kwd_plugin_api_get_t)(void);
xraudio_kwd_plugin_api_t *xraudio_kwd_plugin_api_get(void);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif
