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
#include "xraudio_vad.h"
#include "xraudio_private.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>

// WebRTC includes
#define WEBRTC_POSIX
#define WEBRTC_AUDIO_PROCESSING_ONLY_BUILD
#include "webrtc/modules/audio_processing/include/audio_processing.h"
#include "webrtc/modules/interface/module_common_types.h"
#include "webrtc/common_types.h"

/// @brief VAD object internal structure
typedef struct {
   xraudio_vad_config_t           config;                 ///< VAD configuration parameters
   webrtc::AudioProcessing*       audio_processing;       ///< WebRTC AudioProcessing instance
   xraudio_vad_state_t            current_state;          ///< Current VAD state
   xraudio_vad_state_t            previous_state;         ///< Previous VAD state for hysteresis
   uint64_t                       state_change_time_us;   ///< Time of last state change
   uint64_t                       session_start_time_us;  ///< Session start timestamp
   uint32_t                       hysteresis_counter;     ///< Hysteresis counter in frames
   uint32_t                       hysteresis_threshold;   ///< Hysteresis threshold in frames
   xraudio_vad_stats_t            stats;                  ///< VAD processing statistics
   float                          energy_sum;             ///< Sum of energy levels for averaging
   float                          confidence_sum;         ///< Sum of confidence levels for averaging
   uint64_t                       processing_time_sum_us; ///< Sum of processing times
} xraudio_vad_obj_t;

// Internal helper functions
static uint64_t xraudio_vad_timestamp_get(void);
static float xraudio_vad_calculate_energy(const xraudio_sample_t *audio_frame, uint32_t frame_size);
static xraudio_vad_state_t xraudio_vad_apply_hysteresis(xraudio_vad_obj_t *obj, float voice_probability);
static float xraudio_vad_calculate_overall_score(xraudio_vad_obj_t *obj);

xraudio_vad_object_t xraudio_vad_create(const xraudio_vad_config_t *config) {
   if (config == NULL) {
      XLOGD_ERROR("invalid config parameter");
      return NULL;
   }
   
   // Validate configuration parameters
   if (config->sample_rate > 32000) {
      XLOGD_ERROR("unsupported sample rate: %u (max 32kHz)", config->sample_rate);
      return NULL;
   }
   
   if (config->sensitivity < XRAUDIO_VAD_MIN_SENSITIVITY || 
       config->sensitivity > XRAUDIO_VAD_MAX_SENSITIVITY) {
      XLOGD_ERROR("invalid VAD sensitivity: %f", config->sensitivity);
      return NULL;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)calloc(1, sizeof(xraudio_vad_obj_t));
   if (obj == NULL) {
      XLOGD_ERROR("unable to allocate VAD object");
      return NULL;
   }
   
   // Copy configuration
   memcpy(&obj->config, config, sizeof(xraudio_vad_config_t));
   
   // Create WebRTC AudioProcessing instance
   try {
      obj->audio_processing = webrtc::AudioProcessing::Create();
      if (obj->audio_processing == NULL) {
         XLOGD_ERROR("failed to create WebRTC AudioProcessing instance");
         free(obj);
         return NULL;
      }
      
      // Initialize AudioProcessing with the sample rate
      int result = obj->audio_processing->Initialize(config->sample_rate, config->sample_rate, config->sample_rate,
                                                    webrtc::AudioProcessing::kMono, webrtc::AudioProcessing::kMono, webrtc::AudioProcessing::kMono);
      if (result != webrtc::AudioProcessing::kNoError) {
         XLOGD_ERROR("failed to initialize AudioProcessing: %d", result);
         delete obj->audio_processing;
         free(obj);
         return NULL;
      }
      
      // Enable and configure voice detection
      obj->audio_processing->voice_detection()->Enable(true);
      obj->audio_processing->voice_detection()->set_likelihood(webrtc::VoiceDetection::kModerateLikelihood);
      obj->audio_processing->voice_detection()->set_frame_size_ms(20);
   } catch (const std::exception& e) {
      XLOGD_ERROR("failed to create WebRTC AudioProcessing instance: %s", e.what());
      free(obj);
      return NULL;
   }
   
   // Initialize state
   obj->current_state         = XRAUDIO_VAD_STATE_UNKNOWN;
   obj->previous_state        = XRAUDIO_VAD_STATE_UNKNOWN;
   obj->session_start_time_us = xraudio_vad_timestamp_get();
   
   // Calculate hysteresis threshold in frames (assuming 20ms frames)
   uint32_t frame_period_ms = 20;
   obj->hysteresis_threshold = obj->config.hysteresis_ms / frame_period_ms;
   
   XLOGD_INFO("created VAD object: sample_rate=%u, sensitivity=%f, hysteresis=%ums, mode=%u", 
              config->sample_rate, config->sensitivity, config->hysteresis_ms, config->mode);
   
   return (xraudio_vad_object_t)obj;
}

void xraudio_vad_destroy(xraudio_vad_object_t object) {
   if (object == NULL) {
      return;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   // Clean up WebRTC AudioProcessing instance
   if (obj->audio_processing != NULL) {
      delete obj->audio_processing;
   }
   
   XLOGD_INFO("destroyed VAD object");
   free(obj);
}

xraudio_result_t xraudio_vad_process_frame(xraudio_vad_object_t object, const xraudio_sample_t *audio_frame, uint32_t frame_size, xraudio_vad_event_data_t *vad_data) {
   if (object == NULL || audio_frame == NULL || vad_data == NULL) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   // Validate frame size for WebRTC VAD compatibility
   // WebRTC VAD expects frames of 10ms, 20ms, or 30ms duration
   uint32_t expected_10ms = obj->config.sample_rate / 100;       // 10ms frame size
   uint32_t expected_20ms = obj->config.sample_rate / 50;        // 20ms frame size  
   uint32_t expected_30ms = (obj->config.sample_rate * 3) / 100; // 30ms frame size
   
   if (frame_size != expected_10ms && frame_size != expected_20ms && frame_size != expected_30ms) {
      XLOGD_ERROR("Invalid frame size %u for sample rate %u (expected %u, %u, or %u)", 
                  frame_size, obj->config.sample_rate, expected_10ms, expected_20ms, expected_30ms);
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   uint64_t start_time = xraudio_vad_timestamp_get();
   
   // Create AudioFrame for processing
   webrtc::AudioFrame audio_frame_webrtc;
   audio_frame_webrtc.samples_per_channel_ = frame_size;
   audio_frame_webrtc.sample_rate_hz_ = obj->config.sample_rate;
   audio_frame_webrtc.num_channels_ = 1;
   
   // Copy audio data (ensure we don't exceed the buffer size)
   size_t copy_size = (frame_size < webrtc::AudioFrame::kMaxDataSizeSamples) ? frame_size : webrtc::AudioFrame::kMaxDataSizeSamples;
   memcpy(audio_frame_webrtc.data_, audio_frame, copy_size * sizeof(int16_t));
   
   // Process frame through WebRTC AudioProcessing
   int result = obj->audio_processing->ProcessStream(&audio_frame_webrtc);
   if (result != webrtc::AudioProcessing::kNoError) {
      XLOGD_ERROR("AudioProcessing::ProcessStream failed: %d", result);
      return XRAUDIO_RESULT_ERROR_INTERNAL;
   }
   
   // Get voice detection result from WebRTC VoiceDetection
   bool has_voice = obj->audio_processing->voice_detection()->stream_has_voice();
   float voice_probability = has_voice ? 0.9f : 0.1f;  // Convert boolean to probability estimate
   
   // Calculate audio energy level
   float energy_level = xraudio_vad_calculate_energy(audio_frame, frame_size);
   
   // Apply hysteresis to determine VAD state
   xraudio_vad_state_t new_state = xraudio_vad_apply_hysteresis(obj, voice_probability);
   
   // Check for state transition
   bool state_changed = (new_state != obj->current_state);
   if (state_changed) {
      obj->previous_state = obj->current_state;
      obj->current_state = new_state;
      obj->state_change_time_us = xraudio_vad_timestamp_get();
      obj->stats.state_transitions++;
   }
   
   // Update statistics
   obj->stats.frames_processed++;
   if (new_state == XRAUDIO_VAD_STATE_VOICE) {
      obj->stats.frames_voice++;
   } else if (new_state == XRAUDIO_VAD_STATE_SILENCE) {
      obj->stats.frames_silence++;
   }
   
   obj->energy_sum     += energy_level;
   obj->confidence_sum += voice_probability;

   obj->stats.average_energy     = obj->energy_sum     / obj->stats.frames_processed;
   obj->stats.average_confidence = obj->confidence_sum / obj->stats.frames_processed;
   
   uint64_t processing_time = xraudio_vad_timestamp_get() - start_time;
   obj->processing_time_sum_us += processing_time;
   obj->stats.total_processing_time_us = obj->processing_time_sum_us;
   
   // Fill VAD event data
   vad_data->state = new_state;
   vad_data->confidence = voice_probability;
   vad_data->energy_level = energy_level;
   vad_data->timestamp_us = xraudio_vad_timestamp_get() - obj->session_start_time_us;
   vad_data->overall_score = 0.0; // Only provided at finalization
   vad_data->is_final = false;
   
   return XRAUDIO_RESULT_OK;
}

xraudio_result_t xraudio_vad_config_update(xraudio_vad_object_t object, const xraudio_vad_config_t *config) {
   if (object == NULL || config == NULL) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   // Validate new configuration
   if (config->sensitivity < XRAUDIO_VAD_MIN_SENSITIVITY || 
       config->sensitivity > XRAUDIO_VAD_MAX_SENSITIVITY) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   // Update configuration
   memcpy(&obj->config, config, sizeof(xraudio_vad_config_t));
   
   // Recalculate hysteresis threshold
   uint32_t frame_period_ms = 20;
   obj->hysteresis_threshold = obj->config.hysteresis_ms / frame_period_ms;
   
   XLOGD_INFO("updated VAD sensitivity=%f, hysteresis=%ums, mode=%u", obj->config.sensitivity, obj->config.hysteresis_ms, obj->config.mode);
   
   return XRAUDIO_RESULT_OK;
}

xraudio_result_t xraudio_vad_reset(xraudio_vad_object_t object) {
   if (object == NULL) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   // Reset VAD state
   obj->current_state = XRAUDIO_VAD_STATE_UNKNOWN;
   obj->previous_state = XRAUDIO_VAD_STATE_UNKNOWN;
   obj->session_start_time_us = xraudio_vad_timestamp_get();
   obj->hysteresis_counter = 0;
   
   // Reset statistics
   memset(&obj->stats, 0, sizeof(xraudio_vad_stats_t));
   obj->energy_sum = 0.0;
   obj->confidence_sum = 0.0;
   obj->processing_time_sum_us = 0;
   
   XLOGD_INFO("reset VAD processing state");
   
   return XRAUDIO_RESULT_OK;
}

xraudio_result_t xraudio_vad_get_stats(xraudio_vad_object_t object, xraudio_vad_stats_t *stats) {
   if (object == NULL || stats == NULL) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   memcpy(stats, &obj->stats, sizeof(xraudio_vad_stats_t));
   
   return XRAUDIO_RESULT_OK;
}

xraudio_result_t xraudio_vad_finalize(xraudio_vad_object_t object, xraudio_vad_event_data_t *vad_data) {
   if (object == NULL || vad_data == NULL) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   // Calculate overall VAD score for telemetry
   float overall_score = xraudio_vad_calculate_overall_score(obj);
   obj->stats.overall_vad_score = overall_score;
   
   // Fill final VAD event data
   vad_data->state         = obj->current_state;
   vad_data->confidence    = obj->stats.average_confidence;
   vad_data->energy_level  = obj->stats.average_energy;
   vad_data->timestamp_us  = xraudio_vad_timestamp_get() - obj->session_start_time_us;
   vad_data->overall_score = overall_score;
   vad_data->is_final      = true;
   
   XLOGD_INFO("finalized VAD session: overall_score=%f, frames_processed=%u, voice_frames=%u", 
              overall_score, obj->stats.frames_processed, obj->stats.frames_voice);
   
   return XRAUDIO_RESULT_OK;
}

// Internal helper function implementations

static uint64_t xraudio_vad_timestamp_get(void) {
   struct timeval tv;
   gettimeofday(&tv, NULL);
   return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static float xraudio_vad_calculate_energy(const xraudio_sample_t *audio_frame, uint32_t frame_size) {
   if (audio_frame == NULL || frame_size == 0) {
      return 0.0;
   }
   
   double sum_squares = 0.0;
   for (uint32_t i = 0; i < frame_size; i++) {
      sum_squares += (double)audio_frame[i] * audio_frame[i];
   }
   
   double rms = sqrt(sum_squares / frame_size);
   
   // Convert to dB (with floor to avoid log(0))
   const double db_floor = -100.0;
   double db = (rms > 0.0) ? 20.0 * log10(rms / 32768.0) : db_floor;
   
   return (float)fmax(db, db_floor);
}

static xraudio_vad_state_t xraudio_vad_apply_hysteresis(xraudio_vad_obj_t *obj, float voice_probability) {
   // Determine target state based on probability and sensitivity threshold
   xraudio_vad_state_t target_state = (voice_probability >= obj->config.sensitivity) ? 
                                      XRAUDIO_VAD_STATE_VOICE : XRAUDIO_VAD_STATE_SILENCE;
   
   // If target state matches current state, reset counter
   if (target_state == obj->current_state) {
      obj->hysteresis_counter = 0;
      return obj->current_state;
   }
   
   // If target state is different, increment counter
   obj->hysteresis_counter++;
   
   // If counter exceeds threshold, change state
   if (obj->hysteresis_counter >= obj->hysteresis_threshold) {
      obj->hysteresis_counter = 0;
      return target_state;
   }
   
   // Otherwise maintain current state
   return obj->current_state;
}

static float xraudio_vad_calculate_overall_score(xraudio_vad_obj_t *obj) {
   if (obj->stats.frames_processed == 0) {
      return 0.0;
   }
   
   // Calculate overall score as weighted combination of:
   // - Voice frame ratio (70% weight)
   // - Average confidence (30% weight)
   float voice_ratio = (float)obj->stats.frames_voice / obj->stats.frames_processed;
   float weighted_score = (0.7f * voice_ratio) + (0.3f * obj->stats.average_confidence);
   
   return fmax(0.0, fmin(1.0, weighted_score));
}