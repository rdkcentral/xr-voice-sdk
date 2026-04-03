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
#include "xr_timestamp.h"
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

#define XRAUDIO_VAD_OBJECT_IDENTIFIER (0x5641446F) // 'VADo' in hex

/// @brief VAD object internal structure
typedef struct {
   uint32_t                       identifier;             ///< Unique identifier for validation
   xraudio_input_vad_config_t     config;                 ///< VAD configuration parameters
   uint32_t                       sample_rate;            ///< Audio sample rate in Hz
   webrtc::AudioProcessing*       audio_processing;       ///< WebRTC AudioProcessing instance
   xraudio_vad_state_t            current_state;          ///< Current VAD state
   xraudio_vad_stats_t            stats;                  ///< VAD processing statistics
   int64_t                        rms_level_sum;          ///< Sum of RMS levels for averaging
   float                          confidence_sum;         ///< Sum of confidence levels for averaging
   uint64_t                       processing_time_sum_us; ///< Sum of processing times
   xraudio_sample_t               sample_buffer[416];     ///< Buffer for caching samples (supports up to 26ms at 16kHz)
   uint32_t                       buffer_samples;         ///< Number of samples currently in buffer
   bool*                          voice_activity_history; ///< Circular buffer tracking voice activity for analysis window
   uint32_t                       analysis_window_size;   ///< Number of 10ms frames in analysis window
   uint32_t                       intro_window_size;      ///< Number of 10ms frames in intro window
   int32_t                        audio_rms_level_min;    ///< Minimum audio RMS level in dB for voice detection
   uint32_t                       history_index;          ///< Current index in voice activity history
   uint32_t                       history_count;          ///< Number of frames stored in history
   uint32_t                       voice_frame_count;      ///< Current count of voice frames in analysis window
} xraudio_vad_obj_t;

static xraudio_vad_state_t xraudio_vad_analyze_window(xraudio_vad_obj_t *obj, float *confidence_out);

xraudio_vad_object_t xraudio_vad_create(const xraudio_input_vad_config_t *config, uint32_t sample_rate) {
   if (config == NULL) {
      XLOGD_ERROR("invalid config parameter");
      return NULL;
   }
   
   // Validate configuration parameters
   if (sample_rate > 32000) {
      XLOGD_ERROR("unsupported sample rate: %u (max 32kHz)", sample_rate);
      return NULL;
   }
   
   if (config->sensitivity < XRAUDIO_VAD_MIN_SENSITIVITY || 
       config->sensitivity > XRAUDIO_VAD_MAX_SENSITIVITY) {
      XLOGD_ERROR("invalid VAD sensitivity: %f", config->sensitivity);
      return NULL;
   }

   if (config->analysis_window_ms < XRAUDIO_VAD_MIN_ANALYSIS_WINDOW_MS ||
       config->analysis_window_ms > XRAUDIO_VAD_MAX_ANALYSIS_WINDOW_MS) {
      XLOGD_ERROR("invalid VAD analysis window: %u ms", config->analysis_window_ms);
      return NULL;
   }

   if (config->audio_rms_level_min < XRAUDIO_VAD_MIN_AUDIO_RMS_LEVEL_MIN || 
       config->audio_rms_level_min > XRAUDIO_VAD_MAX_AUDIO_RMS_LEVEL_MIN) {
      XLOGD_ERROR("invalid VAD audio RMS level min: %f dB", config->audio_rms_level_min);
      return NULL;
   }

   if (config->intro_window_ms < XRAUDIO_VAD_MIN_INTRO_WINDOW_MS ||
       config->intro_window_ms > XRAUDIO_VAD_MAX_INTRO_WINDOW_MS) {
      XLOGD_ERROR("invalid VAD intro window: %u ms", config->intro_window_ms);
      return NULL;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)calloc(1, sizeof(xraudio_vad_obj_t));
   if (obj == NULL) {
      XLOGD_ERROR("unable to allocate VAD object");
      return NULL;
   }
   
   // Copy configuration and sample rate
   memcpy(&obj->config, config, sizeof(xraudio_input_vad_config_t));
   obj->sample_rate = sample_rate;
   
   // Calculate analysis window size in 10ms frames
   obj->analysis_window_size = config->analysis_window_ms / 10;
   if (obj->analysis_window_size == 0) {
      obj->analysis_window_size = 1; // Minimum 1 frame
   }
   
   // Calculate intro window size in 10ms frames
   obj->intro_window_size = config->intro_window_ms / 10;

   // Store minimum audio RMS level
   obj->audio_rms_level_min = config->audio_rms_level_min;
   
   // Allocate voice activity history buffer
   obj->voice_activity_history = (bool*)calloc(obj->analysis_window_size, sizeof(bool));
   if (obj->voice_activity_history == NULL) {
      XLOGD_ERROR("unable to allocate voice activity history buffer");
      free(obj);
      return NULL;
   }
   
   // Create WebRTC AudioProcessing instance
   try {
      obj->audio_processing = webrtc::AudioProcessing::Create();
      if (obj->audio_processing == NULL) {
         XLOGD_ERROR("failed to create WebRTC AudioProcessing instance");
         free(obj->voice_activity_history);
         free(obj);
         return NULL;
      }
      
      // Initialize AudioProcessing with the sample rate
      webrtc::ProcessingConfig processing_config;
      processing_config.input_stream().set_sample_rate_hz(sample_rate);
      processing_config.input_stream().set_num_channels(1);
      processing_config.output_stream().set_sample_rate_hz(sample_rate);
      processing_config.output_stream().set_num_channels(1);
      processing_config.reverse_input_stream().set_sample_rate_hz(sample_rate);
      processing_config.reverse_input_stream().set_num_channels(1);
      processing_config.reverse_output_stream().set_sample_rate_hz(sample_rate);
      processing_config.reverse_output_stream().set_num_channels(1);

      int result = obj->audio_processing->Initialize(processing_config);
      if (result != webrtc::AudioProcessing::kNoError) {
         XLOGD_ERROR("failed to initialize AudioProcessing: %d", result);
         delete obj->audio_processing;
         free(obj->voice_activity_history);
         free(obj);
         return NULL;
      }
      
      // Enable and configure voice detection
      obj->audio_processing->voice_detection()->Enable(true);
      obj->audio_processing->voice_detection()->set_likelihood(webrtc::VoiceDetection::kModerateLikelihood);  // kVeryLowLikelihood, kLowLikelihood, kModerateLikelihood, kHighLikelihood  
      obj->audio_processing->voice_detection()->set_frame_size_ms(10);  // Match our processing chunk size
      
      // Enable and configure noise suppression
      obj->audio_processing->noise_suppression()->Enable(true);
      obj->audio_processing->noise_suppression()->set_level(webrtc::NoiseSuppression::kModerate);  // kLow, kModerate, kHigh, kVeryHigh
      
      // Enable high pass filter
      obj->audio_processing->high_pass_filter()->Enable(true);
      
      // Enable level estimator 
      obj->audio_processing->level_estimator()->Enable(true);

   } catch (const std::exception& e) {
      XLOGD_ERROR("failed to create WebRTC AudioProcessing instance: %s", e.what());
      free(obj->voice_activity_history);
      free(obj);
      return NULL;
   }
   
   // Initialize state
   obj->identifier            = XRAUDIO_VAD_OBJECT_IDENTIFIER;
   obj->current_state         = XRAUDIO_VAD_STATE_UNKNOWN;
   obj->history_index         = 0;
   obj->history_count         = 0;
   obj->voice_frame_count     = 0;
   
   // Initialize sample buffer
   obj->buffer_samples = 0;
   memset(obj->sample_buffer, 0, sizeof(obj->sample_buffer));
   
   XLOGD_INFO("sample rate <%u Hz> sensitivity <%f>, analysis window <%u ms, %u frames> intro window <%u ms, %u frames> audio RMS level min <%d dB>", 
              sample_rate, config->sensitivity, config->analysis_window_ms, obj->analysis_window_size, config->intro_window_ms, obj->intro_window_size, obj->audio_rms_level_min);
   
   return (xraudio_vad_object_t)obj;
}

void xraudio_vad_destroy(xraudio_vad_object_t object) {
   if (object == NULL) {
      XLOGD_ERROR("invalid VAD object");
      return;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;

   if (obj->identifier != XRAUDIO_VAD_OBJECT_IDENTIFIER) {
      XLOGD_ERROR("invalid VAD object identifier");
      return;
   }
   
   // Clean up WebRTC AudioProcessing instance
   if (obj->audio_processing != NULL) {
      delete obj->audio_processing;
   }
   
   // Free voice activity history buffer
   if (obj->voice_activity_history != NULL) {
      free(obj->voice_activity_history);
   }
   obj->identifier = 0; // Invalidate identifier to prevent further use of this object 

   XLOGD_INFO("destroyed VAD object");
   free(obj);
}

static xraudio_result_t xraudio_vad_process_chunk(xraudio_vad_obj_t *obj, const xraudio_sample_t *audio_frame, uint32_t frame_size, xraudio_vad_event_data_t *vad_data) {
   rdkx_timestamp_t start_time;
   rdkx_timestamp_get(&start_time);

   // Create AudioFrame for processing
   webrtc::AudioFrame audio_frame_webrtc;
   audio_frame_webrtc.samples_per_channel_ = frame_size;
   audio_frame_webrtc.sample_rate_hz_      = obj->sample_rate;
   audio_frame_webrtc.num_channels_        = 1;
   
   // Copy audio data (ensure we don't exceed the buffer size)
   size_t copy_size = (frame_size < webrtc::AudioFrame::kMaxDataSizeSamples) ? frame_size : webrtc::AudioFrame::kMaxDataSizeSamples;
   memcpy(audio_frame_webrtc.data_, audio_frame, copy_size * sizeof(int16_t));
   
   // Process frame through WebRTC AudioProcessing
   int result;
   bool has_voice_webrtc;
   int rms_level;
   try {
      result = obj->audio_processing->ProcessStream(&audio_frame_webrtc);
      if(result != webrtc::AudioProcessing::kNoError) {
         XLOGD_ERROR("AudioProcessing::ProcessStream failed: %d", result);
         return XRAUDIO_RESULT_ERROR_INTERNAL;
      }

      // Get voice detection result from WebRTC VoiceDetection
      has_voice_webrtc = obj->audio_processing->voice_detection()->stream_has_voice();

      // Calculate audio RMS level
      rms_level = -obj->audio_processing->level_estimator()->RMS();
   } catch(const std::exception& e) {
      XLOGD_ERROR("exception during AudioProcessing: %s", e.what());
      return XRAUDIO_RESULT_ERROR_INTERNAL;
   }
   
   if(obj->stats.frames_processed <= obj->intro_window_size) {
      has_voice_webrtc = false;
   }
   // Apply minimum RMS level threshold
   bool has_voice = has_voice_webrtc && (rms_level >= obj->audio_rms_level_min);
   
   // Update sliding window with current frame's voice activity
   bool old_voice_activity = false;
   if(obj->history_count >= obj->analysis_window_size) {
      // Get the old value that will be overwritten
      old_voice_activity = obj->voice_activity_history[obj->history_index];
      if (old_voice_activity) {
         obj->voice_frame_count--;
      }
   } else {
      obj->history_count++;
   }
   
   // Store new voice activity and update count
   obj->voice_activity_history[obj->history_index] = has_voice;
   if(has_voice) {
      obj->voice_frame_count++;
   }
   
   // Advance circular buffer index
   obj->history_index = (obj->history_index + 1) % obj->analysis_window_size;
   
   // Determine VAD state based on analysis window
   float confidence = 0.0f;
   xraudio_vad_state_t new_state = xraudio_vad_analyze_window(obj, &confidence);
      
   // Check for state transition
   bool state_changed = (new_state != obj->current_state);
   if(state_changed) {
      obj->current_state = new_state;
      obj->stats.state_transitions++;
   }
   
   // Update statistics
   obj->stats.frames_processed++;
   if(has_voice) {
      obj->stats.frames_voice++;
   } else {
      obj->stats.frames_silence++;
   }
   
   obj->rms_level_sum  += rms_level;
   obj->confidence_sum += confidence;
   
   // Track peak values
   if(rms_level > obj->stats.rms_level_peak) {
      obj->stats.rms_level_peak = rms_level;
   }
   if(confidence > obj->stats.confidence_peak) {
      obj->stats.confidence_peak = confidence;
   }
   
   uint64_t processing_time = rdkx_timestamp_since_us(start_time);
   obj->processing_time_sum_us += processing_time;
   
      // Print debug information
   XLOGD_DEBUG("has_voice <%s><%s> rms_level <%d dB> voice_frames <%u/%u> confidence <%.2f> new_state <%s> frames <%u> rms level sum <%lld> obj %p",  has_voice_webrtc ? "YES" : "NO",
              has_voice ? "YES" : "NO", rms_level, obj->voice_frame_count, obj->history_count, confidence, xraudio_vad_state_str(new_state), obj->stats.frames_processed, obj->rms_level_sum, obj);

   // Fill VAD event data
   vad_data->state      = new_state;
   vad_data->confidence = confidence;
   vad_data->rms_level  = rms_level;
   vad_data->is_final   = false;
   
   return XRAUDIO_RESULT_OK;
}

xraudio_result_t xraudio_vad_process_frame(xraudio_vad_object_t object, const xraudio_sample_t *audio_frame, uint32_t frame_size, xraudio_vad_event_data_t *vad_data) {
   if (object == NULL || audio_frame == NULL || vad_data == NULL) {
      XLOGD_ERROR("invalid VAD object or parameters");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   if (obj->identifier != XRAUDIO_VAD_OBJECT_IDENTIFIER) {
      XLOGD_ERROR("invalid VAD object identifier");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }

   // Calculate 10ms frame size for current sample rate
   uint32_t chunk_size = obj->sample_rate / 100;  // 10ms frame size
   
   // Validate that we have room in sample buffer
   if (obj->buffer_samples + frame_size > sizeof(obj->sample_buffer) / sizeof(obj->sample_buffer[0])) {
      XLOGD_ERROR("Input frame too large: %u samples (buffer has %u, can accept %zu more)", 
                  frame_size, obj->buffer_samples, 
                  (sizeof(obj->sample_buffer) / sizeof(obj->sample_buffer[0])) - obj->buffer_samples);
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   // Copy incoming samples to buffer
   memcpy(&obj->sample_buffer[obj->buffer_samples], audio_frame, frame_size * sizeof(xraudio_sample_t));
   obj->buffer_samples += frame_size;
   
   xraudio_result_t result = XRAUDIO_RESULT_OK;
   
   // Process all complete 10ms chunks in buffer
   while (obj->buffer_samples >= chunk_size && result == XRAUDIO_RESULT_OK) {
      // Process 10ms chunk
      result = xraudio_vad_process_chunk(obj, obj->sample_buffer, chunk_size, vad_data);
      
      if (result != XRAUDIO_RESULT_OK) {
         break;
      }
      
      // Move remaining samples to beginning of buffer
      uint32_t remaining_samples = obj->buffer_samples - chunk_size;
      if (remaining_samples > 0) {
         memmove(obj->sample_buffer, &obj->sample_buffer[chunk_size], remaining_samples * sizeof(xraudio_sample_t));
      }
      obj->buffer_samples = remaining_samples;
   }
   
   return result;
}

xraudio_result_t xraudio_vad_config_update(xraudio_vad_object_t object, const xraudio_input_vad_config_t *config) {
   if (object == NULL || config == NULL) {
      XLOGD_ERROR("invalid VAD object or config parameter");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   if (obj->identifier != XRAUDIO_VAD_OBJECT_IDENTIFIER) {
      XLOGD_ERROR("invalid VAD object identifier");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }

   // Validate new configuration
   if (config->sensitivity < XRAUDIO_VAD_MIN_SENSITIVITY || 
       config->sensitivity > XRAUDIO_VAD_MAX_SENSITIVITY) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   if (config->analysis_window_ms < XRAUDIO_VAD_MIN_ANALYSIS_WINDOW_MS ||
       config->analysis_window_ms > XRAUDIO_VAD_MAX_ANALYSIS_WINDOW_MS) {
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   // Check if analysis window size is changing
   uint32_t new_window_size = config->analysis_window_ms / 10;
   if (new_window_size == 0) {
      new_window_size = 1;
   }
   
   if (new_window_size != obj->analysis_window_size) {
      // Reallocate voice activity history buffer if window size changed
      bool *new_history = (bool*)calloc(new_window_size, sizeof(bool));
      if (new_history == NULL) {
         return XRAUDIO_RESULT_ERROR_INTERNAL;
      }
      
      // Free old buffer and update to new one
      free(obj->voice_activity_history);
      obj->voice_activity_history = new_history;
      obj->analysis_window_size = new_window_size;
      obj->history_index = 0;
      obj->history_count = 0;
      obj->voice_frame_count = 0;
   }
   
   // Update configuration
   memcpy(&obj->config, config, sizeof(xraudio_input_vad_config_t));
   
   XLOGD_INFO("updated VAD sensitivity=%f, analysis_window=%ums (%u frames)", 
              obj->config.sensitivity, obj->config.analysis_window_ms, obj->analysis_window_size);
   
   return XRAUDIO_RESULT_OK;
}

xraudio_result_t xraudio_vad_reset(xraudio_vad_object_t object) {
   if (object == NULL) {
      XLOGD_ERROR("invalid VAD object");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;
   
   if (obj->identifier != XRAUDIO_VAD_OBJECT_IDENTIFIER) {
      XLOGD_ERROR("invalid VAD object identifier");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }

   // Reset WebRTC AudioProcessing instance
   if(obj->audio_processing != NULL) {
      try {
         webrtc::ProcessingConfig processing_config;
         processing_config.input_stream().set_sample_rate_hz(obj->sample_rate);
         processing_config.input_stream().set_num_channels(1);
         processing_config.output_stream().set_sample_rate_hz(obj->sample_rate);
         processing_config.output_stream().set_num_channels(1);
         processing_config.reverse_input_stream().set_sample_rate_hz(obj->sample_rate);
         processing_config.reverse_input_stream().set_num_channels(1);
         processing_config.reverse_output_stream().set_sample_rate_hz(obj->sample_rate);
         processing_config.reverse_output_stream().set_num_channels(1);

         int rc = obj->audio_processing->Initialize(processing_config);
         if(rc != webrtc::AudioProcessing::kNoError) {
            XLOGD_ERROR("failed to reinitialize AudioProcessing: %d", rc);
            return XRAUDIO_RESULT_ERROR_INTERNAL;
         }
      } catch(const std::exception& e) {
         XLOGD_ERROR("exception reinitializing AudioProcessing: %s", e.what());
         return XRAUDIO_RESULT_ERROR_INTERNAL;
      }
   }

   // Reset VAD state
   obj->current_state     = XRAUDIO_VAD_STATE_UNKNOWN;
   obj->history_index     = 0;
   obj->history_count     = 0;
   obj->voice_frame_count = 0;
   
   // Clear voice activity history
   if(obj->voice_activity_history != NULL) {
      memset(obj->voice_activity_history, 0, obj->analysis_window_size * sizeof(bool));
   }
   
   // Reset sample buffer
   obj->buffer_samples = 0;
   memset(obj->sample_buffer, 0, sizeof(obj->sample_buffer));
   
   // Reset statistics
   memset(&obj->stats, 0, sizeof(xraudio_vad_stats_t));
   obj->stats.rms_level_peak     = -100.0f; // Initialize to very low value
   obj->stats.confidence_peak    = 0.0f;    // Initialize to minimum
   obj->stats.rms_level_average  = 0.0f;
   obj->stats.confidence_average = 0.0f;
   obj->stats.cpu_utilization    = 0.0f;
   obj->rms_level_sum            = 0;
   obj->confidence_sum           = 0.0;
   obj->processing_time_sum_us   = 0;
   
   XLOGD_INFO("reset VAD processing state");
   
   return XRAUDIO_RESULT_OK;
}

xraudio_result_t xraudio_vad_get_stats(xraudio_vad_object_t object, xraudio_vad_stats_t *stats, bool finalize) {
   if(object == NULL || stats == NULL) {
      XLOGD_ERROR("invalid VAD object or stats parameter");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }
   
   xraudio_vad_obj_t *obj = (xraudio_vad_obj_t *)object;

   if (obj->identifier != XRAUDIO_VAD_OBJECT_IDENTIFIER) {
      XLOGD_ERROR("invalid VAD object identifier");
      return XRAUDIO_RESULT_ERROR_PARAMS;
   }

   *stats = obj->stats;

   if(finalize && obj->stats.frames_processed > 0) {
      // Finalize statistics
      stats->rms_level_average  = ((float)obj->rms_level_sum)  / (float)obj->stats.frames_processed;
      stats->confidence_average = ((float)obj->confidence_sum) / (float)obj->stats.frames_processed;
      stats->cpu_utilization    = 100 * ((float)obj->processing_time_sum_us) / (obj->stats.frames_processed * 10000.0f); // Convert to percentage (assuming 10ms frames)
   }
   
   return XRAUDIO_RESULT_OK;
}

static xraudio_vad_state_t xraudio_vad_analyze_window(xraudio_vad_obj_t *obj, float *confidence_out) {
   // If we don't have enough frames yet, return current state
   if(obj->history_count == 0) {
      return XRAUDIO_VAD_STATE_UNKNOWN;
   }
   
   // Calculate percentage of voice frames in the analysis window
   float voice_percentage = (float)obj->voice_frame_count / (float)obj->history_count;
   
   if(confidence_out != NULL) {
      *confidence_out = voice_percentage;
   }

   // Compare against sensitivity threshold
   if(voice_percentage >= obj->config.sensitivity) {
      return XRAUDIO_VAD_STATE_VOICE;
   } else {
      return XRAUDIO_VAD_STATE_SILENCE;
   }
}
