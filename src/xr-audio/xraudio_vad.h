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
#ifndef _XRAUDIO_VAD_H_
#define _XRAUDIO_VAD_H_

#include <stdint.h>
#include <stdbool.h>
#include <xraudio.h>
#include "xraudio_common.h"

/// @brief VAD processing object type
typedef void * xraudio_vad_object_t;

/// @brief VAD statistics structure  
/// @details Statistics and metrics collected during VAD processing
typedef struct {
   uint32_t frames_processed;        ///< Total number of audio frames processed
   uint32_t frames_voice;            ///< Number of frames detected as voice
   uint32_t frames_silence;          ///< Number of frames detected as silence  
   uint32_t state_transitions;       ///< Number of VAD state transitions
   float    average_energy;          ///< Average audio energy level (dB)
   float    average_confidence;      ///< Average VAD confidence level (0.0-1.0)
   uint64_t total_processing_time_us; ///< Total processing time in microseconds
   float    overall_vad_score;       ///< Overall VAD score for the session (0.0-1.0)
} xraudio_vad_stats_t;

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Create VAD processing object
/// @details Creates and initializes a VAD processing object with specified configuration
/// @param[in] config VAD configuration parameters
/// @param[in] sample_rate Audio sample rate in Hz
/// @return VAD object handle or NULL on error
xraudio_vad_object_t xraudio_vad_create(const xraudio_input_vad_config_t *config, uint32_t sample_rate);

/// @brief Destroy VAD processing object  
/// @details Destroys VAD object and releases associated resources
/// @param[in] object VAD object handle
void xraudio_vad_destroy(xraudio_vad_object_t object);

/// @brief Process audio frame through VAD
/// @details Processes a single audio frame and returns VAD state information
/// @param[in] object VAD object handle
/// @param[in] audio_frame Audio frame data (16-bit PCM samples)
/// @param[in] frame_size Number of samples in the frame
/// @param[out] vad_data VAD event data with state, confidence, energy, etc.
/// @return XRAUDIO_RESULT_OK on success, error code otherwise
xraudio_result_t xraudio_vad_process_frame(xraudio_vad_object_t object, 
                                          const xraudio_sample_t *audio_frame,
                                          uint32_t frame_size,
                                          xraudio_vad_event_data_t *vad_data);

/// @brief Update VAD configuration
/// @details Updates VAD processing parameters at runtime
/// @param[in] object VAD object handle
/// @param[in] config New VAD configuration parameters
/// @return XRAUDIO_RESULT_OK on success, error code otherwise  
xraudio_result_t xraudio_vad_config_update(xraudio_vad_object_t object, 
                                           const xraudio_input_vad_config_t *config);

/// @brief Reset VAD processing state
/// @details Resets VAD internal state for new audio stream processing
/// @param[in] object VAD object handle
/// @return XRAUDIO_RESULT_OK on success, error code otherwise
xraudio_result_t xraudio_vad_reset(xraudio_vad_object_t object);

/// @brief Get VAD processing statistics
/// @details Retrieves accumulated VAD processing statistics and metrics
/// @param[in] object VAD object handle
/// @param[out] stats VAD statistics structure
/// @return XRAUDIO_RESULT_OK on success, error code otherwise
xraudio_result_t xraudio_vad_get_stats(xraudio_vad_object_t object, 
                                       xraudio_vad_stats_t *stats);

/// @brief Finalize VAD processing session
/// @details Finalizes VAD session and calculates overall score for telemetry
/// @param[in] object VAD object handle
/// @param[out] vad_data Final VAD event data with overall score
/// @return XRAUDIO_RESULT_OK on success, error code otherwise
xraudio_result_t xraudio_vad_finalize(xraudio_vad_object_t object, 
                                      xraudio_vad_event_data_t *vad_data);

#ifdef __cplusplus
}
#endif

#endif // _XRAUDIO_VAD_H_