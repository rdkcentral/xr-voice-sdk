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
#include "xraudio_vad.h"
#include "xraudio_private.h"

#include <stdlib.h>
#include <string.h>

#define XRAUDIO_VAD_STUB_IDENTIFIER (0x56415342) /* 'VASB' */

typedef struct {
   uint32_t                   identifier;
   xraudio_input_vad_config_t config;
   xraudio_vad_stats_t        stats;
} xraudio_vad_stub_obj_t;

xraudio_vad_object_t xraudio_vad_create(const xraudio_input_vad_config_t *config, uint32_t sample_rate) {
   if(config == NULL) {
      XLOGD_ERROR("invalid config parameter");
      return(NULL);
   }

   (void)sample_rate; // VAD is disabled; stub ignores sample rate

   xraudio_vad_stub_obj_t *obj = (xraudio_vad_stub_obj_t *)calloc(1, sizeof(xraudio_vad_stub_obj_t));
   if(obj == NULL) {
      XLOGD_ERROR("unable to allocate VAD stub object");
      return(NULL);
   }

   obj->identifier = XRAUDIO_VAD_STUB_IDENTIFIER;
   obj->config = *config;
   obj->stats.rms_level_peak    = -100.0f;
   obj->stats.rms_level_average = -100.0f;

   static volatile int warned = 0;
   if(__sync_bool_compare_and_swap(&warned, 0, 1)) { XLOGD_WARN("VAD is disabled at build time, using stub implementation"); }
   return((xraudio_vad_object_t)obj);
}

void xraudio_vad_destroy(xraudio_vad_object_t object) {
   if(object == NULL) {
      return;
   }

   xraudio_vad_stub_obj_t *obj = (xraudio_vad_stub_obj_t *)object;
   if(obj->identifier != XRAUDIO_VAD_STUB_IDENTIFIER) {
      XLOGD_ERROR("invalid VAD stub object");
      return;
   }

   obj->identifier = 0;
   free(obj);
}

xraudio_result_t xraudio_vad_process_frame(xraudio_vad_object_t object, const xraudio_sample_t *audio_frame, uint32_t frame_size, xraudio_vad_event_data_t *vad_data) {
   if(object == NULL || audio_frame == NULL || vad_data == NULL || frame_size == 0) {
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   xraudio_vad_stub_obj_t *obj = (xraudio_vad_stub_obj_t *)object;
   if(obj->identifier != XRAUDIO_VAD_STUB_IDENTIFIER) {
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   obj->stats.frames_processed++;
   obj->stats.frames_silence++;

   vad_data->state = XRAUDIO_VAD_STATE_SILENCE;
   vad_data->confidence = 0.0f;
   vad_data->rms_level = obj->stats.rms_level_peak;
   vad_data->overall_score = 0.0f;
   vad_data->is_final = false;

   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_vad_config_update(xraudio_vad_object_t object, const xraudio_input_vad_config_t *config) {
   if(object == NULL || config == NULL) {
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   xraudio_vad_stub_obj_t *obj = (xraudio_vad_stub_obj_t *)object;
   if(obj->identifier != XRAUDIO_VAD_STUB_IDENTIFIER) {
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   obj->config = *config;
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_vad_reset(xraudio_vad_object_t object) {
   if(object == NULL) {
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   xraudio_vad_stub_obj_t *obj = (xraudio_vad_stub_obj_t *)object;
   if(obj->identifier != XRAUDIO_VAD_STUB_IDENTIFIER) {
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   memset(&obj->stats, 0, sizeof(obj->stats));
   obj->stats.rms_level_peak    = -100.0f;
   obj->stats.rms_level_average = -100.0f;
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_vad_get_stats(xraudio_vad_object_t object, xraudio_vad_stats_t *stats, bool finalize) {
   (void)finalize;

   if(object == NULL || stats == NULL) {
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   xraudio_vad_stub_obj_t *obj = (xraudio_vad_stub_obj_t *)object;
   if(obj->identifier != XRAUDIO_VAD_STUB_IDENTIFIER) {
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   *stats = obj->stats;
   return(XRAUDIO_RESULT_OK);
}
