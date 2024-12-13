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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <bsd/string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <limits.h>
#include <semaphore.h>
#include <jansson.h>
#include "xraudio.h"
#include "xraudio_private.h"

#define POLAR_ACTIVITY_PERIOD_IN_MSEC    (50)

#define XRAUDIO_INPUT_IDENTIFIER (0x928E461A)

#define XRAUDIO_RECORD_MUTEX_LOCK()   sem_wait(&obj->mutex_record)
#define XRAUDIO_RECORD_MUTEX_UNLOCK() sem_post(&obj->mutex_record)

//#define INPUT_TIMING_DATA
#ifdef INPUT_TIMING_DATA
#define INPUT_TIMING_SAMPLE_QTY (20 * 1000 / 20)
typedef struct {
   rdkx_timestamp_t optimal;      // Elapsed time at which the sample should be taken
   rdkx_timestamp_t actual;       // Actual time when the sample was taken
   rdkx_timestamp_t time_read;    // Amount of time to read the PCM data
   rdkx_timestamp_t time_eos;     // Amount of time to run end of speech algorithm
   rdkx_timestamp_t time_snd_foc; // Amount of time to run sound focus algorithm
   rdkx_timestamp_t time_process; // Amount of time to process the data
   rdkx_timestamp_t time_capture; // Amount of time to capture to file
   bool             playback;     // true if playback is active
} xraudio_input_timing_t;

typedef struct {
   rdkx_timestamp_t begin;
   rdkx_timestamp_t end;
} xraudio_timing_sample_t;

#endif

typedef struct {
   unsigned long frames_lost;
} xraudio_input_statistics_t;

typedef struct {
   bool                active;
   xraudio_capture_t   type;
   xraudio_container_t container;
   const char *        audio_file_path;
   bool                raw_mic_enable;
} xraudio_input_capture_t;

typedef struct {
   xraudio_keyword_sensitivity_t sensitivity;
} xraudio_input_detect_params_t;

typedef struct {
   xraudio_input_state_t          state;
   uint8_t                        frame_group_qty;
   char                           stream_identifer[XRAUDIO_STREAM_ID_SIZE_MAX];
   uint16_t                       stream_time_minimum;
   uint32_t                       stream_keyword_begin;
   uint32_t                       stream_keyword_duration;
   xraudio_stream_latency_mode_t  latency_mode;
   xraudio_stream_cpu_util_mode_t cpu_util_mode;
   xraudio_input_record_from_t    from[XRAUDIO_FIFO_QTY_MAX];
   int32_t                        offset[XRAUDIO_FIFO_QTY_MAX];
   xraudio_input_record_until_t   until[XRAUDIO_FIFO_QTY_MAX];
   xraudio_input_format_t         format_out;
   xraudio_sample_t *             audio_buf_samples;
   unsigned long                  audio_buf_sample_qty;
   int                            fifo_sound_intensity;
   #if defined(XRAUDIO_DGA_ENABLED) && defined(XRAUDIO_KWD_ENABLED)
   int16_t                        kwd_peak_power_dBFS;
   float *                        dynamic_gain_update;
   #endif

   // Only one of these can be set at a time
   int                           fifo_audio_data[XRAUDIO_FIFO_QTY_MAX];
   int                           fd;
   audio_in_data_callback_t      data_callback;

} xraudio_input_session_t;

typedef struct {
   uint32_t                      identifier;
   uint8_t                       user_id;
   xraudio_hal_obj_t             hal_obj;
   xraudio_hal_input_obj_t       hal_input_obj;
   xr_mq_t                       msgq;
   sem_t                         mutex_record;
   xraudio_input_session_t       sessions[XRAUDIO_INPUT_SESSION_GROUP_QTY];
   xraudio_devices_input_t       device;
   xraudio_resource_id_input_t   resource_id;
   uint16_t                      capabilities;
   uint8_t                       pcm_bit_qty;
   int                           fd;
   xraudio_input_format_t        format_in;

   char                          fifo_name[XRAUDIO_FIFO_NAME_LENGTH_MAX];
   xraudio_input_statistics_t    statistics;
   #ifdef XRAUDIO_EOS_ENABLED
   xraudio_eos_object_t          obj_eos[XRAUDIO_INPUT_MAX_CHANNEL_QTY];
   #endif
   #ifdef XRAUDIO_SDF_ENABLED
   xraudio_sdf_object_t          obj_sdf;
   uint32_t                      sound_focus_sample_count;
   #endif
   #ifdef XRAUDIO_PPR_ENABLED
   xraudio_ppr_object_t          obj_ppr;
   #endif
   xraudio_input_capture_t       capture;
   xraudio_input_detect_params_t detect_params;
   #ifdef INPUT_TIMING_DATA
   xraudio_input_timing_t *      timing_data_begin;
   xraudio_input_timing_t *      timing_data_end;
   xraudio_input_timing_t *      timing_data_current;
   xraudio_timing_sample_t       timing_data_input_close;
   xraudio_timing_sample_t       timing_data_input_open;
   #endif
   xraudio_hal_dsp_config_t      dsp_config;
   char *                        dsp_name;
} xraudio_input_obj_t;

static bool             xraudio_input_object_is_valid(xraudio_input_obj_t *obj);
static void             xraudio_input_queue_msg_push(xraudio_input_obj_t *obj, const char *msg, size_t msg_len);
static void             xraudio_input_dispatch_idle_start(xraudio_input_obj_t *obj);
static void             xraudio_input_dispatch_idle_stop(xraudio_input_obj_t *obj);
static xraudio_result_t xraudio_input_dispatch_record(xraudio_input_obj_t *obj, xraudio_devices_input_t source, xraudio_input_format_t *format_decoded, bool subsequent, audio_in_callback_t callback, void *param);
static xraudio_result_t xraudio_input_dispatch_detect(xraudio_input_obj_t *obj, keyword_callback_t callback, void *param, bool synchronous);
static xraudio_result_t xraudio_input_dispatch_detect_params(xraudio_input_obj_t *obj);
static xraudio_result_t xraudio_input_dispatch_detect_stop(xraudio_input_obj_t *obj, xraudio_devices_input_t source, audio_in_callback_t callback, void *param);
static xraudio_result_t xraudio_input_dispatch_stop(xraudio_input_obj_t *obj, xraudio_devices_input_t source, int32_t index, audio_in_callback_t callback, void *param);
static xraudio_result_t xraudio_input_dispatch_capture(xraudio_input_obj_t *obj, audio_in_callback_t callback, void *param);
static xraudio_result_t xraudio_input_dispatch_capture_stop(xraudio_input_obj_t *obj);
#ifdef XRAUDIO_KWD_ENABLED
static bool             xraudio_input_audio_hal_open(xraudio_input_obj_t *obj, xraudio_devices_input_t device, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_input_format_t format, uint8_t *pcm_bit_qty, int *fd);
static void             xraudio_input_audio_hal_close(xraudio_input_obj_t *obj);
#endif
static void             xraudio_input_sound_intensity_fifo_open(xraudio_input_obj_t *obj);
static void             xraudio_input_sound_intensity_fifo_close(xraudio_input_obj_t *obj);

static void             xraudio_input_stats_general_clear(xraudio_input_obj_t *obj);
static void             xraudio_input_stats_general_print(xraudio_input_obj_t *obj);
static void             xraudio_input_stats_timing_clear(xraudio_input_obj_t *obj);
static void             xraudio_input_stats_timing_print(xraudio_input_obj_t *obj);
static void             xraudio_input_stats_sound_focus_clear(xraudio_input_obj_t *obj, uint32_t statistics);
static void             xraudio_input_stats_sound_focus_print(xraudio_input_obj_t *obj, uint32_t statistics);

static void             xraudio_input_close_locked(xraudio_input_obj_t *obj);
static xraudio_result_t xraudio_input_stop_locked(xraudio_input_obj_t *obj, xraudio_devices_input_t source, int32_t index);
static xraudio_result_t xraudio_input_capture_stop_locked(xraudio_input_obj_t *obj);
static __inline xraudio_input_session_t *xraudio_input_source_to_session(xraudio_input_obj_t *obj, xraudio_devices_input_t source);

xraudio_input_object_t xraudio_input_object_create(xraudio_hal_obj_t hal_obj, uint8_t user_id, int msgq, uint16_t capabilities, xraudio_hal_dsp_config_t *dsp_config, json_t *json_obj_input) {
   #ifdef XRAUDIO_EOS_ENABLED
   json_t *jeos_config = NULL;
   #endif
   #ifdef XRAUDIO_PPR_ENABLED
   json_t *jppr_config = NULL;
   #endif
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)malloc(sizeof(xraudio_input_obj_t));

   if(obj == NULL) {
      XLOGD_ERROR("Out of memory.");
      return(NULL);
   }

   sem_init(&obj->mutex_record, 0, 1);
   obj->identifier               = XRAUDIO_INPUT_IDENTIFIER;
   obj->user_id                  = user_id;
   obj->hal_obj                  = hal_obj;
   obj->msgq                     = msgq;
   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_input_session_t *session = &obj->sessions[group];

      session->state                    = XRAUDIO_INPUT_STATE_CREATED;
      session->frame_group_qty          = XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY;
      session->latency_mode             = XRAUDIO_STREAM_LATENCY_NORMAL;
      session->cpu_util_mode            = XRAUDIO_STREAM_CPU_UTIL_NORMAL;
      session->stream_time_minimum      = 0;
      session->stream_keyword_begin     = 0;
      session->stream_keyword_duration  = 0;
      session->fifo_audio_data[0]       = -1;
      session->fd                       = -1;
      session->data_callback            = NULL;
      session->audio_buf_samples        = NULL;
      session->audio_buf_sample_qty     = 0;
      session->fifo_sound_intensity     = -1;
      #ifdef XRAUDIO_DGA_ENABLED
      session->kwd_peak_power_dBFS      = 0;
      #endif

      session->format_out                = (xraudio_input_format_t) { .container     = XRAUDIO_CONTAINER_INVALID,
                                                                      .encoding.type = XRAUDIO_ENCODING_INVALID,
                                                                      .sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                                      .sample_size   = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                                      .channel_qty   = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };

      memset(session->stream_identifer, 0, sizeof(session->stream_identifer));
   }
   obj->device                   = XRAUDIO_DEVICE_INPUT_INVALID;
   obj->resource_id              = XRAUDIO_RESOURCE_ID_INPUT_INVALID;
   obj->capabilities             = XRAUDIO_CAPS_INPUT_NONE;
   obj->pcm_bit_qty              = 16;
   obj->fd                       = -1;
   obj->format_in                = (xraudio_input_format_t) { .container     = XRAUDIO_CONTAINER_INVALID,
                                                              .encoding.type = XRAUDIO_ENCODING_INVALID,
                                                              .sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                              .sample_size   = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                              .channel_qty   = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };
   obj->hal_input_obj            = NULL;
   obj->statistics               = (xraudio_input_statistics_t) { .frames_lost = 0 };
   #ifdef XRAUDIO_KWD_ENABLED
   obj->dsp_config               = *dsp_config;
   #endif
   if(NULL == json_obj_input) {
      XLOGD_INFO("json_obj_input is null, using defaults");
   } else {
      #ifdef XRAUDIO_EOS_ENABLED
      jeos_config = json_object_get(json_obj_input, JSON_OBJ_NAME_INPUT_EOS);
      if(NULL == jeos_config) {
         XLOGD_INFO("EOS config not found, using defaults");
      } else if(!json_is_object(jeos_config)) {
         XLOGD_INFO("jeos_config is not object, using defaults");
         jeos_config = NULL;
      }
      #endif
      #ifdef XRAUDIO_PPR_ENABLED
      jppr_config = json_object_get(json_obj_input, JSON_OBJ_NAME_INPUT_PPR);
      if(NULL == jppr_config) {
         XLOGD_INFO("PPR config not found, using defaults");
      } else if(!json_is_object(jppr_config)) {
         XLOGD_INFO("jppr_config is not object, using defaults");
         jppr_config = NULL;
      }
      #endif
   }

   #ifdef XRAUDIO_EOS_ENABLED
   for (uint8_t i = 0; i < XRAUDIO_INPUT_MAX_CHANNEL_QTY; ++i) {
      obj->obj_eos[i] = xraudio_eos_object_create(false, jeos_config);
   }
   #endif
   #ifdef XRAUDIO_SDF_ENABLED
   obj->obj_sdf                  = xraudio_sdf_object_create(hal_obj);
   obj->sound_focus_sample_count = 0;
   #endif
   #ifdef XRAUDIO_PPR_ENABLED
   obj->obj_ppr                  = xraudio_ppr_object_create(jppr_config);

   if(!xraudio_ppr_init(obj->obj_ppr)) {
      XLOGD_ERROR("Preprocess init failed");
      if(obj->obj_ppr != NULL) {
         xraudio_ppr_object_destroy(obj->obj_ppr);
      }
      free(obj);
      return(NULL);
   }

   xraudio_ppr_status_t ppr_status;
   xraudio_ppr_get_status(obj->obj_ppr, &ppr_status);
   obj->dsp_name = ppr_status.dsp_name;
   #endif
   memset(obj->fifo_name, 0, sizeof(obj->fifo_name));

   obj->capture.active           = false;
   obj->capture.type             = XRAUDIO_CAPTURE_INPUT_MONO;
   obj->capture.container        = XRAUDIO_CONTAINER_INVALID;
   obj->capture.audio_file_path  = NULL;

   obj->detect_params.sensitivity = XRAUDIO_INPUT_DEFAULT_KEYWORD_SENSITIVITY;

   #ifdef INPUT_TIMING_DATA
   obj->timing_data_begin   = (xraudio_input_timing_t *)malloc(sizeof(xraudio_input_timing_t) * (INPUT_TIMING_SAMPLE_QTY + 1));
   if(obj->timing_data_begin == NULL) {
      XLOGD_ERROR("unable to allocate timing data buffer");
      obj->timing_data_end     = NULL;
      obj->timing_data_current = NULL;
   } else {
      obj->timing_data_end     = obj->timing_data_begin + INPUT_TIMING_SAMPLE_QTY;
      obj->timing_data_current = obj->timing_data_begin;
   }
   #endif

   return((xraudio_input_object_t)obj);
}

void xraudio_input_object_destroy(xraudio_input_object_t object) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(xraudio_input_object_is_valid(obj)) {
      XRAUDIO_RECORD_MUTEX_LOCK();
      xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];
      if(session->state != XRAUDIO_INPUT_STATE_CREATED) {
         // Close the microphone interface
         xraudio_input_close_locked(obj);
      }
      #ifdef XRAUDIO_EOS_ENABLED
      for (int i = 0; i < XRAUDIO_INPUT_MAX_CHANNEL_QTY; ++i) {
         if(obj->obj_eos[i] != NULL) {
            xraudio_eos_object_destroy(obj->obj_eos[i]);
            obj->obj_eos[i] = NULL;
         }
      }
      #endif
      #ifdef XRAUDIO_SDF_ENABLED
      if(obj->obj_sdf != NULL) {
         xraudio_sdf_object_destroy(obj->obj_sdf);
         obj->obj_sdf = NULL;
      }
      #endif
      #ifdef INPUT_TIMING_DATA
      if(obj->timing_data_begin) {
         free(obj->timing_data_begin);
         obj->timing_data_begin = NULL;
      }
      #endif
      #ifdef XRAUDIO_PPR_ENABLED
      if(obj->obj_ppr != NULL) {
         xraudio_ppr_object_destroy(obj->obj_ppr);
         obj->obj_ppr = NULL;
      }
      #endif
      obj->identifier = 0;
      for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
         xraudio_input_session_t *session = &obj->sessions[group];
         session->state = XRAUDIO_INPUT_STATE_INVALID;
      }
      XRAUDIO_RECORD_MUTEX_UNLOCK();

      free(obj);
   }
}

bool xraudio_input_object_is_valid(xraudio_input_obj_t *obj) {
   if(obj != NULL && obj->identifier == XRAUDIO_INPUT_IDENTIFIER) {
      return(true);
   }
   return(false);
}

xraudio_hal_input_obj_t xraudio_input_hal_obj_get(xraudio_input_object_t object) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(NULL);
   }
   return(obj->hal_input_obj);
}

void xraudio_input_queue_msg_push(xraudio_input_obj_t *obj, const char *msg, size_t msg_len) {
   if(msg_len > XRAUDIO_MSG_QUEUE_MSG_SIZE_MAX) {
      XLOGD_ERROR("Message size is too big! (%zd)", msg_len);
      return;
   }
   if(!xr_mq_push(obj->msgq, msg, msg_len)) {
      XLOGD_ERROR("Unable to send message!");
   }
}

xraudio_result_t xraudio_input_open(xraudio_input_object_t object, xraudio_devices_input_t device, xraudio_power_mode_t power_mode, bool privacy_mode,  xraudio_resource_id_input_t resource_id, uint16_t capabilities, xraudio_input_format_t format) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return XRAUDIO_RESULT_ERROR_OBJECT;
   }
   XRAUDIO_RECORD_MUTEX_LOCK();

   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   if(session->state != XRAUDIO_INPUT_STATE_CREATED) {
      XLOGD_ERROR("session in progress <%s>", xraudio_input_state_str(session->state));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return XRAUDIO_RESULT_ERROR_STATE;
   }

   xraudio_input_format_t format_in = format;
   if(capabilities & XRAUDIO_CAPS_INPUT_LOCAL_32_BIT) { // HAL suports 32-bit PCM input
      format_in.sample_size = 4;
   }

   uint8_t pcm_bit_qty = 16;
   int     fd          = -1;

   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_devices_input_t device_input_local = XRAUDIO_DEVICE_INPUT_LOCAL_GET(device);
   if(device_input_local != XRAUDIO_DEVICE_INPUT_NONE) {

      format_in.channel_qty = (device_input_local == XRAUDIO_DEVICE_INPUT_QUAD) ? 4 : (device_input_local == XRAUDIO_DEVICE_INPUT_TRI) ? 3 : 1;

      if(!xraudio_input_audio_hal_open(obj, XRAUDIO_DEVICE_INPUT_LOCAL_GET(device), power_mode, privacy_mode, format_in, &pcm_bit_qty, &fd)) {
         XLOGD_ERROR("Unable to open microphone interface");
         XRAUDIO_RECORD_MUTEX_UNLOCK();
         return XRAUDIO_RESULT_ERROR_MIC_OPEN;
      }
   }

   //HAL capabilities and dsp_config might change after open(). For example when Llama loads NSM DSP image
   #ifndef XRAUDIO_RESOURCE_MGMT
   xraudio_hal_capabilities caps;
   xraudio_hal_capabilities_get(&caps);
   for(uint8_t index = 0; index < caps.input_qty; index++) { // Find the local microphone
      if(caps.input_caps[index] & (XRAUDIO_CAPS_INPUT_LOCAL | XRAUDIO_CAPS_INPUT_LOCAL_32_BIT)) {
          capabilities = caps.input_caps[index];
      }
   }
   #endif
   xraudio_hal_dsp_config_get(&obj->dsp_config);
   #endif

   obj->device             = device;
   obj->resource_id        = resource_id;
   obj->capabilities       = capabilities;
   obj->format_in          = format_in;
   obj->pcm_bit_qty        = pcm_bit_qty;
   obj->fd                 = fd;

   xraudio_input_sound_intensity_fifo_open(obj);

   XLOGD_INFO("sample size <%u> %u-bit pcm using <%s>", obj->format_in.sample_size, obj->pcm_bit_qty, obj->fd >= 0 ? "fd" : "timing");

   xraudio_input_dispatch_idle_start(obj);

   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_input_session_t *session = &obj->sessions[group];
      session->state = XRAUDIO_INPUT_STATE_IDLING;
   }

   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return XRAUDIO_RESULT_OK;
}

void xraudio_input_close(xraudio_input_object_t object) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   XRAUDIO_RECORD_MUTEX_LOCK();
   xraudio_input_close_locked(obj);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
}

void xraudio_input_close_locked(xraudio_input_obj_t *obj) {
   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_input_session_t *session = &obj->sessions[group];
      if(session->state == XRAUDIO_INPUT_STATE_RECORDING || session->state == XRAUDIO_INPUT_STATE_STREAMING || session->state == XRAUDIO_INPUT_STATE_DETECTING) {
         // Stop the recording in process
         xraudio_input_stop_locked(obj, (group == XRAUDIO_INPUT_SESSION_GROUP_DEFAULT) ? obj->device : XRAUDIO_DEVICE_INPUT_MIC_TAP, -1);
      }
   }

   if(obj->capture.active) {
      xraudio_input_capture_stop_locked(obj);
   }

   xraudio_input_dispatch_idle_stop(obj);

   xraudio_input_sound_intensity_fifo_close(obj);

   #ifdef XRAUDIO_KWD_ENABLED
   // Close the microphone interface
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(obj->device) != XRAUDIO_DEVICE_INPUT_NONE) {
      xraudio_input_audio_hal_close(obj);
   }
   #endif

   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_input_session_t *session = &obj->sessions[group];
      session->state = XRAUDIO_INPUT_STATE_CREATED;
   }
}

xraudio_result_t xraudio_input_record_to_file(xraudio_input_object_t object, xraudio_devices_input_t source, xraudio_container_t container, const char *audio_file_path, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();

   // Check if object contains this source
   if(!XRAUDIO_DEVICE_INPUT_CONTAINS(obj->device, source)) {
      XLOGD_ERROR("invalid source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   // Close previous session if present
   if(session->state != XRAUDIO_INPUT_STATE_IDLING && session->state != XRAUDIO_INPUT_STATE_DETECTING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_input_state_str(session->state));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(container != XRAUDIO_CONTAINER_WAV) {
      XLOGD_ERROR("unsupported container <%s>", xraudio_container_str(container));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_CONTAINER);
   }
   if((uint32_t)from >= XRAUDIO_INPUT_RECORD_FROM_INVALID || (uint32_t)until >= XRAUDIO_INPUT_RECORD_UNTIL_INVALID) {
      XLOGD_ERROR("invalid from/until param");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN && !XRAUDIO_DEVICE_INPUT_LOCAL_GET(source)) {
      XLOGD_ERROR("invalid from keyword point on non-local source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_BEGINNING && offset < 0) {
      XLOGD_ERROR("invalid negative offset from beginning");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   errno = 0;
   session->fd = open(audio_file_path, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
   if(session->fd < 0) {
      int errsv = errno;
      XLOGD_ERROR("Unable to open file <%s> <%s>", audio_file_path, strerror(errsv));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_FILE_OPEN);
   }

   if(container == XRAUDIO_CONTAINER_WAV) { // Write space for the wave header (need to know pcm data size so generate at the end of recording)
      uint8_t header[WAVE_HEADER_SIZE_MIN];
      memset(header, 0, WAVE_HEADER_SIZE_MIN);

      errno = 0;
      ssize_t bytes_written = write(session->fd, header, sizeof(header));
      if(bytes_written != sizeof(header)) {
         int errsv = errno;
         XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
      }
   }

   xraudio_input_sound_intensity_fifo_open(obj);

   #ifdef XRAUDIO_STSF_TEST
   xraudio_input_sound_focus_set(obj, XRAUDIO_SDF_MODE_STRONGEST_SECTOR);
   #endif

   session->format_out.container     = container;
   session->format_out.encoding.type = XRAUDIO_ENCODING_PCM;

   session->from[0]   = from;
   session->offset[0] = offset;
   session->until[0]  = until;

   XLOGD_INFO("file <%s> container <%s> from <%s> offset <%d> until <%s> <%s>", audio_file_path, xraudio_container_str(container), xraudio_input_record_from_str(from), offset, xraudio_input_record_until_str(until), (callback == NULL) ? "sync" : "async");

   session->state = XRAUDIO_INPUT_STATE_RECORDING;

   xraudio_result_t result = xraudio_input_dispatch_record(obj, source, NULL, false, callback, param);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_input_record_to_memory(xraudio_input_object_t object, xraudio_devices_input_t source, xraudio_sample_t *buf_samples, unsigned long sample_qty, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();

    // Check if object contains this source
   if(!XRAUDIO_DEVICE_INPUT_CONTAINS(obj->device, source)) {
      XLOGD_ERROR("invalid source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   // Close previous session if present
   if(session->state != XRAUDIO_INPUT_STATE_IDLING && session->state != XRAUDIO_INPUT_STATE_DETECTING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_input_state_str(session->state));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(buf_samples == NULL || sample_qty == 0) {
      XLOGD_ERROR("invalid parameters - buf samples %p sample qty %lu", buf_samples, sample_qty);
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if((uint32_t)from >= XRAUDIO_INPUT_RECORD_FROM_INVALID || (uint32_t)until >= XRAUDIO_INPUT_RECORD_UNTIL_INVALID) {
      XLOGD_ERROR("invalid from/until param");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN && !XRAUDIO_DEVICE_INPUT_LOCAL_GET(source)) {
      XLOGD_ERROR("invalid from keyword point on non-local source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_BEGINNING && offset < 0) {
      XLOGD_ERROR("invalid negative offset from beginning");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   session->audio_buf_samples     = buf_samples;
   session->audio_buf_sample_qty  = sample_qty;

   xraudio_input_sound_intensity_fifo_open(obj);

   session->format_out.container     = XRAUDIO_CONTAINER_NONE;
   session->format_out.encoding.type = XRAUDIO_ENCODING_PCM;

   session->from[0]   = from;
   session->offset[0] = offset;
   session->until[0]  = until;

   XLOGD_INFO("buffer %p size %lu from <%s> offset <%d> until <%s> <%s>", session->audio_buf_samples, session->audio_buf_sample_qty, xraudio_input_record_from_str(from), offset, xraudio_input_record_until_str(until), (callback == NULL) ? "sync" : "async");

   session->state = XRAUDIO_INPUT_STATE_RECORDING;

   xraudio_result_t result = xraudio_input_dispatch_record(obj, source, NULL, false, callback, param);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_input_stream_time_minimum(xraudio_object_t object, xraudio_devices_input_t source, uint16_t ms) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   if(ms > XRAUDIO_STREAM_TIME_MINIMUM_MAX) {
      XLOGD_ERROR("Minimum audio threshold %u ms is greater than max %u ms (using max)", ms, XRAUDIO_STREAM_TIME_MINIMUM_MAX);
      session->stream_time_minimum = XRAUDIO_STREAM_TIME_MINIMUM_MAX;
   } else {
      XLOGD_INFO("Minimum Audio Threshold %u ms", ms);
      session->stream_time_minimum = ms;
   }
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_stream_keyword_info(xraudio_object_t object, xraudio_devices_input_t source, uint32_t keyword_begin, uint32_t keyword_duration) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   XLOGD_INFO("keyword begin <%u> duration <%u>", keyword_begin, keyword_duration);
   session->stream_keyword_begin    = keyword_begin;
   session->stream_keyword_duration = keyword_duration;

   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_stream_keyword_info_get(xraudio_object_t object, xraudio_devices_input_t source, xraudio_keyword_detector_result_t *keyword_detector_result) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_hal_stream_params_t stream_params;
   if(!xraudio_hal_input_stream_params_get(object, &stream_params)) {
      XLOGD_ERROR("Failed to read HAL keyword parameters");
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   if(!stream_params.valid) {
      XLOGD_ERROR("HAL reports invalid stream params");
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   #ifdef XRAUDIO_DGA_ENABLED
   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);
   session->kwd_peak_power_dBFS                    = stream_params.kwd_peak_power_dBFS;
   session->dynamic_gain_update                    = keyword_detector_result->dynamic_gain_update;
   #endif
   keyword_detector_result->endpoints.begin        = stream_params.kwd_begin;
   keyword_detector_result->endpoints.end          = stream_params.kwd_end;
   keyword_detector_result->endpoints.pre          = stream_params.kwd_pre;
   keyword_detector_result->dsp_name               = stream_params.dsp_name;
   keyword_detector_result->sensitivity            = stream_params.sensitivity;
   keyword_detector_result->detector_name          = stream_params.keyword_detector;
   keyword_detector_result->endpoints.kwd_gain     = stream_params.dsp_kwd_gain;
   #endif

   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_stream_to_fifo(xraudio_input_object_t object, xraudio_devices_input_t source, const char *fifo_name, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();

    // Check if object contains this source
   if(!XRAUDIO_DEVICE_INPUT_CONTAINS(obj->device, source)) {
      XLOGD_ERROR("invalid source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   // Close previous session if present
   if(session->state != XRAUDIO_INPUT_STATE_IDLING && session->state != XRAUDIO_INPUT_STATE_DETECTING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_input_state_str(session->state));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(fifo_name == NULL) {
      XLOGD_ERROR("invalid parameters");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if((uint32_t)from >= XRAUDIO_INPUT_RECORD_FROM_INVALID || (uint32_t)until >= XRAUDIO_INPUT_RECORD_UNTIL_INVALID) {
      XLOGD_ERROR("invalid from/until param");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN && !XRAUDIO_DEVICE_INPUT_LOCAL_GET(source)) {
      XLOGD_ERROR("invalid from keyword point on non-local source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_BEGINNING && offset < 0) {
      XLOGD_ERROR("invalid negative offset from beginning");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   // Open fifo
   errno = 0;
   int fd = open(fifo_name, O_RDWR | O_NONBLOCK);
   if(fd < 0) {
      int errsv = errno;
      XLOGD_ERROR("unable to open fifo %d <%s>", fd, strerror(errsv));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_FIFO_OPEN);
   }

   session->fifo_audio_data[0] = fd;

   xraudio_input_sound_intensity_fifo_open(obj);

   session->format_out.container     = XRAUDIO_CONTAINER_NONE;
   session->format_out.encoding.type = XRAUDIO_ENCODING_PCM;

   session->from[0]   = from;
   session->offset[0] = offset;
   session->until[0]  = until;

   XLOGD_INFO("pipe %d from <%s> offset <%d> until <%s> <%s>", session->fifo_audio_data[0], xraudio_input_record_from_str(from), offset, xraudio_input_record_until_str(until), (callback == NULL) ? "sync" : "async");

   session->state = XRAUDIO_INPUT_STATE_STREAMING;

   xraudio_result_t result = xraudio_input_dispatch_record(obj, source, format_decoded, false, callback, param);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_input_stream_to_pipe(xraudio_input_object_t object, xraudio_devices_input_t source, xraudio_dst_pipe_t dsts[], xraudio_input_format_t *format_decoded, bool subsequent, audio_in_callback_t callback, void *param) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();

   // Check if object contains this source (or SINGLE is requested when TRI or QUAD is available)
   if(!XRAUDIO_DEVICE_INPUT_CONTAINS(obj->device, source) && !((source == XRAUDIO_DEVICE_INPUT_SINGLE || source == XRAUDIO_DEVICE_INPUT_MIC_TAP) && (obj->device & (XRAUDIO_DEVICE_INPUT_TRI | XRAUDIO_DEVICE_INPUT_QUAD)))) {
      XLOGD_ERROR("invalid source <%s>", xraudio_devices_input_str(source));
      XLOGD_ERROR("valid sources  <%s>", xraudio_devices_input_str(obj->device));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   // Close previous session if present
   if(session->state != XRAUDIO_INPUT_STATE_IDLING && session->state != XRAUDIO_INPUT_STATE_DETECTING) {
      XLOGD_ERROR("src <%s> session in progress <%s>", xraudio_devices_input_str(source), xraudio_input_state_str(session->state));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(dsts[0].pipe < 0) {
      XLOGD_ERROR("src <%s> invalid parameters - pipe[0] <%d>", xraudio_devices_input_str(source), dsts[0].pipe);
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   bool found_end = false;
   for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
      int pipe = dsts[index].pipe;
      if(pipe < 0 || found_end) {
         found_end = true;
         session->fifo_audio_data[index] = -1;
         break;
      }

      xraudio_input_record_from_t  from   = dsts[index].from;
      int32_t                      offset = dsts[index].offset;
      xraudio_input_record_until_t until  = dsts[index].until;


      if((uint32_t)from >= XRAUDIO_INPUT_RECORD_FROM_INVALID || (uint32_t)until >= XRAUDIO_INPUT_RECORD_UNTIL_INVALID) {
         XLOGD_ERROR("src <%s> invalid from/until param", xraudio_devices_input_str(source));
         XRAUDIO_RECORD_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_PARAMS);
      }
      if(from == XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN && !XRAUDIO_DEVICE_INPUT_LOCAL_GET(source)) {
         XLOGD_ERROR("src <%s> invalid from keyword point on non-local source <%s>", xraudio_devices_input_str(source), xraudio_input_record_from_str(from));
         XRAUDIO_RECORD_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_PARAMS);
      }
      if(from == XRAUDIO_INPUT_RECORD_FROM_BEGINNING && offset < 0) {
         XLOGD_ERROR("src <%s> invalid negative offset from beginning", xraudio_devices_input_str(source));
         XRAUDIO_RECORD_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_PARAMS);
      }

      int flags = fcntl(pipe, F_GETFL);

      if((flags & O_NONBLOCK) == 0) {
         flags |= O_NONBLOCK;

         XLOGD_DEBUG("Setting pipe to non-blocking");

         if(fcntl(pipe, F_SETFL, flags) < 0) {
            XLOGD_ERROR("src <%s> unable to set pipe to non-blocking", xraudio_devices_input_str(source));
            XRAUDIO_RECORD_MUTEX_UNLOCK();
            return(XRAUDIO_RESULT_ERROR_FIFO_CONTROL);
         }
      }

      session->fifo_audio_data[index] = pipe;
      session->from[index]            = from;
      session->offset[index]          = offset;
      session->until[index]           = until;

      #ifdef XRAUDIO_KWD_ENABLED
      if((index == 0) && (from == XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN)) {
         XLOGD_INFO("src <%s> calling xraudio_hal_input_stream-start_set with offset %d", xraudio_devices_input_str(source), session->stream_keyword_begin);
         if(!xraudio_hal_input_stream_start_set(obj->hal_input_obj, session->stream_keyword_begin)) {
            XLOGD_ERROR("src <%s> failed to set stream start point", xraudio_devices_input_str(source));
            XRAUDIO_RECORD_MUTEX_UNLOCK();
            return(XRAUDIO_RESULT_ERROR_INPUT);
         }
      }
      #endif
      XLOGD_INFO("src <%s> index <%u> pipe <%d> from <%s> offset <%d> until <%s> <%s>", xraudio_devices_input_str(source), index, pipe, xraudio_input_record_from_str(from), offset, xraudio_input_record_until_str(until), (callback == NULL) ? "sync" : "async");
   }

   xraudio_input_sound_intensity_fifo_open(obj);

   session->format_out.container     = XRAUDIO_CONTAINER_NONE;
   session->format_out.encoding.type = XRAUDIO_ENCODING_PCM;
   session->format_out.sample_size   = (format_decoded != NULL) ? format_decoded->sample_size : XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE;

   if(source == XRAUDIO_DEVICE_INPUT_TRI) {
      session->format_out.channel_qty = 3;
   } else if(source == XRAUDIO_DEVICE_INPUT_QUAD) {
      session->format_out.channel_qty = 4;
   } else if(source == XRAUDIO_DEVICE_INPUT_MIC_TAP) { // Use max channel qty
     if(obj->device & XRAUDIO_DEVICE_INPUT_QUAD) {
        session->format_out.channel_qty = 4;
     } else if(obj->device & XRAUDIO_DEVICE_INPUT_TRI) {
        session->format_out.channel_qty = 3;
     } else {
        session->format_out.channel_qty = 1;
     }
   } else {
      session->format_out.channel_qty = 1;
   }

   // Correct channel qty since the caller doesn't know this.  may need to revisit later.
   if(format_decoded != NULL && format_decoded->channel_qty > session->format_out.channel_qty) {
      if(obj->device & XRAUDIO_DEVICE_INPUT_QUAD) {
         format_decoded->channel_qty = 4;
      } else if(obj->device & XRAUDIO_DEVICE_INPUT_TRI) {
         format_decoded->channel_qty = 3;
      } else {
         format_decoded->channel_qty = 1;
      }
   }

   session->state = XRAUDIO_INPUT_STATE_STREAMING;

   #ifdef XRAUDIO_EOS_ENABLED
   if(subsequent && obj->dsp_config.eos_enabled) {
      for (int i = 0; i < XRAUDIO_INPUT_MAX_CHANNEL_QTY; ++i) {
         xraudio_eos_state_set_speech_begin(obj->obj_eos[i]);
      }
   }
   #endif

   xraudio_result_t result = xraudio_input_dispatch_record(obj, source, format_decoded, subsequent, callback, param);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_input_stream_to_user(xraudio_input_object_t object, xraudio_devices_input_t source, audio_in_data_callback_t data, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();

    // Check if object contains this source
   if(!XRAUDIO_DEVICE_INPUT_CONTAINS(obj->device, source)) {
      XLOGD_ERROR("invalid source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   // Close previous session if present
   if(session->state != XRAUDIO_INPUT_STATE_IDLING && session->state != XRAUDIO_INPUT_STATE_DETECTING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_input_state_str(session->state));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(data == NULL) {
      XLOGD_ERROR("invalid parameters - data callback");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if((uint32_t)from >= XRAUDIO_INPUT_RECORD_FROM_INVALID || (uint32_t)until >= XRAUDIO_INPUT_RECORD_UNTIL_INVALID) {
      XLOGD_ERROR("invalid from/until param");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN && !XRAUDIO_DEVICE_INPUT_LOCAL_GET(source)) {
      XLOGD_ERROR("invalid from keyword point on non-local source");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(from == XRAUDIO_INPUT_RECORD_FROM_BEGINNING && offset < 0) {
      XLOGD_ERROR("invalid negative offset from beginning");
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   session->data_callback = data;

   xraudio_input_sound_intensity_fifo_open(obj);

   session->format_out.container     = XRAUDIO_CONTAINER_NONE;
   session->format_out.encoding.type = XRAUDIO_ENCODING_PCM;

   session->from[0]   = from;
   session->offset[0] = offset;
   session->until[0]  = until;

   XLOGD_INFO("from <%s> offset <%d> until <%s> <%s>", xraudio_input_record_from_str(from), offset, xraudio_input_record_until_str(until), (callback == NULL) ? "sync" : "async");

   session->state = XRAUDIO_INPUT_STATE_STREAMING;

   xraudio_result_t result = xraudio_input_dispatch_record(obj, source, format_decoded, false, callback, param);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

void xraudio_input_sound_intensity_fifo_open(xraudio_input_obj_t *obj) {
   if(obj->fifo_name[0] != 0) {
      // Open fifo
      errno = 0;
      int fd = open(obj->fifo_name, O_RDWR | O_NONBLOCK);
      if(fd < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to open fifo %d <%s>", fd, strerror(errsv));
      }
      xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

      session->fifo_sound_intensity = fd;
   }
}

void xraudio_input_sound_intensity_fifo_close(xraudio_input_obj_t *obj) {
   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];
   // Close previously opened fifo
   if(session->fifo_sound_intensity >= 0) {
      errno = 0;
      int rc = close(session->fifo_sound_intensity);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to close fifo %d <%s>", rc, strerror(errsv));
      }
      session->fifo_sound_intensity = -1;
   }
}

xraudio_result_t xraudio_input_source_fd_set(xraudio_input_object_t object, xraudio_devices_input_t source, int fd, xraudio_input_format_t format, xraudio_input_data_read_cb_t callback, void *user_data) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xraudio_main_queue_msg_input_source_fd_set_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_INPUT_SOURCE_FD_SET;
   msg.source      = source;
   msg.format      = format;
   msg.fd          = fd;
   msg.callback    = callback;
   msg.user_data   = user_data;
   msg.semaphore   = &semaphore;
   msg.result      = &result;

   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   if(result != XRAUDIO_RESULT_OK) {
      XLOGD_ERROR("unable to set input source fd");
   }
   return(result);
}

xraudio_result_t xraudio_input_sound_intensity_transfer(xraudio_input_object_t object, const char *fifo_name) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];
   // Close previously opened fifo
   if(session->fifo_sound_intensity >= 0) {
      errno = 0;
      int rc = close(session->fifo_sound_intensity);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to close fifo %d <%s>", rc, strerror(errsv));
      }
      session->fifo_sound_intensity = -1;
   }
   
   // Store fifo name
   if(fifo_name == NULL) {
      memset(obj->fifo_name, 0, sizeof(obj->fifo_name));
      return(XRAUDIO_RESULT_OK);
   }

   size_t len = strlen(fifo_name);

   if(len < XRAUDIO_FIFO_NAME_LENGTH_MIN || len > XRAUDIO_FIFO_NAME_LENGTH_MAX - 1) {
      XLOGD_ERROR("Fifo name out of range.");
      memset(obj->fifo_name, 0, sizeof(obj->fifo_name));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   strncpy(obj->fifo_name, fifo_name, XRAUDIO_FIFO_NAME_LENGTH_MAX);
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_latency_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_latency_mode_t latency_mode) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XLOGD_INFO("latency mode <%s>", xraudio_stream_latency_mode_str(latency_mode));

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   session->latency_mode = latency_mode;
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_cpu_util_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_cpu_util_mode_t cpu_util_mode) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XLOGD_INFO("cpu util mode <%s>", xraudio_stream_cpu_util_mode_str(cpu_util_mode));

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   session->cpu_util_mode = cpu_util_mode;
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_frame_group_quantity_set(xraudio_object_t object, xraudio_devices_input_t source, uint8_t quantity) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   if(quantity < XRAUDIO_INPUT_MIN_FRAME_GROUP_QTY || quantity > XRAUDIO_INPUT_MAX_FRAME_GROUP_QTY) {
      XLOGD_ERROR("Frame group quantity out of range. %u frames", quantity);
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   session->frame_group_qty = quantity;
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_stream_identifer_set(xraudio_object_t object, xraudio_devices_input_t source, const char *identifer) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   snprintf(session->stream_identifer, sizeof(session->stream_identifer), "%s", identifer ? identifer : "");
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_keyword_params(xraudio_input_object_t object, xraudio_keyword_phrase_t keyword_phrase, xraudio_keyword_sensitivity_t keyword_sensitivity) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(keyword_phrase >= XRAUDIO_KEYWORD_PHRASE_INVALID) {
      XLOGD_ERROR("Invalid parameters.");
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   XRAUDIO_RECORD_MUTEX_LOCK();

   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   switch(keyword_phrase) {
      default:
      case XRAUDIO_KEYWORD_PHRASE_HEY_XFINITY: {
         XLOGD_INFO("keyword sensitivity <%f> detecting <%s>", keyword_sensitivity, (session->state == XRAUDIO_INPUT_STATE_DETECTING) ? "YES" : "NO");
         if(obj->detect_params.sensitivity != keyword_sensitivity) {
            obj->detect_params.sensitivity = keyword_sensitivity;
            if(session->state == XRAUDIO_INPUT_STATE_DETECTING) {
               xraudio_input_dispatch_detect_params(obj);
            }
         }
         break;
      }
   }

   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_keyword_detect(xraudio_input_object_t object, keyword_callback_t callback, void *param, bool synchronous) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();

   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   // Ensure that the microphone is not already open
   if(session->state != XRAUDIO_INPUT_STATE_IDLING) {
      XLOGD_ERROR("invalid state <%s>.", xraudio_input_state_str(session->state));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(obj->format_in.sample_rate != XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE ||
      obj->format_in.channel_qty < XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY || obj->format_in.channel_qty > XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
      XLOGD_ERROR("unsupported format sample rate %u Hz %u-bit %s.", obj->format_in.sample_rate, obj->format_in.sample_size * 8, xraudio_channel_qty_str(obj->format_in.channel_qty));
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   
   session->state = XRAUDIO_INPUT_STATE_DETECTING;
   xraudio_result_t result = xraudio_input_dispatch_detect(obj, callback, param, synchronous);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

void xraudio_input_keyword_detected(xraudio_input_object_t object) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;

   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }

#if defined(XRAUDIO_EOS_ENABLED) || defined(XRAUDIO_PPR_ENABLED)
   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];
#endif

#ifdef XRAUDIO_EOS_ENABLED
   if(session->state == XRAUDIO_INPUT_STATE_DETECTING && obj->dsp_config.eos_enabled) {
      for (int i = 0; i < XRAUDIO_INPUT_MAX_CHANNEL_QTY; ++i) {
         xraudio_eos_state_set_speech_begin(obj->obj_eos[i]);
      }
   }
#endif
#ifdef XRAUDIO_PPR_ENABLED
   if(session->state == XRAUDIO_INPUT_STATE_DETECTING && obj->dsp_config.ppr_enabled) {
      xraudio_ppr_command(obj->obj_ppr, XRAUDIO_PPR_COMMAND_KEYWORD_DETECT);
   }
#endif
}

void xraudio_input_sound_focus_set(xraudio_input_object_t object, xraudio_sdf_mode_t mode) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   #ifdef XRAUDIO_SDF_ENABLED
   xraudio_sdf_focus_set(obj->obj_sdf, mode);
   #endif
}

unsigned char xraudio_input_signal_level_get(xraudio_input_object_t object, uint8_t chan) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(0);
   }
   if(chan >= XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
      XLOGD_ERROR("Bad channel (%hu).", (uint16_t)chan);
      return(0);
   }

#ifdef XRAUDIO_EOS_ENABLED
   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   if(obj->dsp_config.eos_enabled) {
      if(session->state == XRAUDIO_INPUT_STATE_DETECTING || session->state == XRAUDIO_INPUT_STATE_RECORDING || session->state == XRAUDIO_INPUT_STATE_STREAMING) {
         return(xraudio_eos_signal_level_get(obj->obj_eos[chan]));
      }
   }
#endif
   return(0);
}

uint16_t xraudio_input_signal_direction_get(xraudio_input_object_t object) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(0);
   }

   #ifdef XRAUDIO_SDF_ENABLED
   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   if(session->state == XRAUDIO_INPUT_STATE_DETECTING || session->state == XRAUDIO_INPUT_STATE_RECORDING || session->state == XRAUDIO_INPUT_STATE_STREAMING) {
      return(xraudio_sdf_signal_direction_get(obj->obj_sdf));
   }
   #endif
   return(0);
}

xraudio_eos_event_t xraudio_input_eos_run(xraudio_input_object_t object, uint8_t chan, float *input_samples, int32_t sample_qty, int16_t *scaled_eos_samples) {
#ifdef XRAUDIO_EOS_ENABLED
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_EOS_EVENT_NONE);
   }
   if(chan >= XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
      XLOGD_ERROR("Bad channel (%hu).", (uint16_t)chan);
      return(0);
   }
   return (obj->dsp_config.eos_enabled) ? xraudio_eos_run_float(obj->obj_eos[chan], input_samples, sample_qty, scaled_eos_samples) : XRAUDIO_EOS_EVENT_NONE;
#else
   return XRAUDIO_EOS_EVENT_NONE;
#endif
}

void xraudio_input_eos_state_set_speech_begin(xraudio_input_object_t object) {
#ifdef XRAUDIO_EOS_ENABLED
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(obj->dsp_config.eos_enabled) {
      XLOGD_DEBUG("Keyword detected. Force VADEOS to start.");
      for (int i = 0; i < XRAUDIO_INPUT_MAX_CHANNEL_QTY; ++i) {
         xraudio_eos_state_set_speech_begin(obj->obj_eos[i]);
      }
   }
#endif
}

xraudio_ppr_event_t xraudio_input_ppr_run(xraudio_input_object_t object, uint16_t frame_size_in_samples, const int32_t** ppmic_input_buffers, const int32_t** ppref_input_buffers, int32_t** ppkwd_output_buffers, int32_t** ppasr_output_buffers, int32_t** ppref_output_buffers) {
   xraudio_ppr_event_t event = XRAUDIO_PPR_EVENT_NONE;
#ifdef XRAUDIO_PPR_ENABLED
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_PPR_EVENT_NONE);
   }
   if(obj->dsp_config.ppr_enabled) {
      event = xraudio_ppr_run(
                  obj->obj_ppr,
                  frame_size_in_samples,
                  ppmic_input_buffers,
                  ppref_input_buffers,
                  ppkwd_output_buffers,
                  ppasr_output_buffers,
                  ppref_output_buffers
              );
   }
#endif
   return(event);
}

void xraudio_input_ppr_state_set_speech_begin(xraudio_input_object_t object) {
#if defined(XRAUDIO_PPR_ENABLED)
   // Tell ppr that keyword was detected and begin streaming speech and look for end of speech
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(obj->dsp_config.ppr_enabled && !obj->dsp_config.eos_enabled) {
      xraudio_ppr_command(obj->obj_ppr, XRAUDIO_PPR_COMMAND_KEYWORD_DETECT);
   }
#endif
}

void xraudio_input_sound_focus_update(xraudio_input_object_t object, uint32_t sample_qty) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   #ifdef XRAUDIO_SDF_ENABLED
   if(obj->device != XRAUDIO_DEVICE_INPUT_TRI && obj->device != XRAUDIO_DEVICE_INPUT_QUAD) {
      XLOGD_DEBUG("Sound focus not valid for single microphone");
      return;
   }

   obj->sound_focus_sample_count += sample_qty;

   unsigned long activity_period_in_samples = (POLAR_ACTIVITY_PERIOD_IN_MSEC * obj->format_in.sample_rate / 1000);
   if(obj->sound_focus_sample_count < activity_period_in_samples) {
      return;
   }

   /* TODO

   float SNR = xraudio_eos_signal_to_noise_ratio_get(obj->obj_eos);
   int8_t snr;
   if(SNR < 0) {
      snr = 0;
   } else if(SNR > 255) {
      snr = 255;
   } else {
      snr = (int8_t) SNR;
   }

   qahw_param_payload source_track_data;

   source_track_data.st_params.doa_speech = 180;
   qahw_get_param_data(obj->hal_obj, QAHW_PARAM_SOURCE_TRACK, &source_track_data);

   xraudio_sdf_focus_update(obj->obj_sdf, source_track_data.st_params.polar_activity, snr, source_track_data.st_params.doa_speech);
   */

   obj->sound_focus_sample_count -= activity_period_in_samples;
   #endif
}

xraudio_result_t xraudio_input_detect_stop(xraudio_input_object_t object, xraudio_devices_input_t source) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_RECORD_MUTEX_LOCK();
   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   if(session->state != XRAUDIO_INPUT_STATE_DETECTING) {
      XRAUDIO_RECORD_MUTEX_UNLOCK();
      XLOGD_ERROR("src <%s> invalid state <%s>", xraudio_devices_input_str(source), xraudio_input_state_str(session->state));
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   xraudio_result_t result = xraudio_input_dispatch_detect_stop(obj, source, NULL, NULL);

   session->state = XRAUDIO_INPUT_STATE_IDLING;
   
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_input_stop(xraudio_input_object_t object, xraudio_devices_input_t source, int32_t index) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();
   xraudio_result_t result = xraudio_input_stop_locked(obj, source, index);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_input_stop_locked(xraudio_input_obj_t *obj, xraudio_devices_input_t source, int32_t index) {
   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   //If the state is idling then a session was rejected so we're not streaming or recording but still need to restart keyword detection
   if(session->state != XRAUDIO_INPUT_STATE_RECORDING && session->state != XRAUDIO_INPUT_STATE_STREAMING && session->state != XRAUDIO_INPUT_STATE_IDLING) {
      XLOGD_ERROR("src <%s> invalid state <%s>", xraudio_devices_input_str(source), xraudio_input_state_str(session->state));
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   xraudio_input_dispatch_stop(obj, source, index, NULL, NULL);

   if(session->fd >= 0) {
      close(session->fd);
      session->fd = -1;
   }

   // default is to close all streams
   uint32_t index_begin = 0;
   uint32_t index_end   = XRAUDIO_FIFO_QTY_MAX;
   if(index >= 0 && index < XRAUDIO_FIFO_QTY_MAX) { // close a specific stream
      index_begin = index;
      index_end   = index + 1;
   }

   bool more_streams = false;
   for(uint32_t i = 0; i < XRAUDIO_FIFO_QTY_MAX; i++) {
      if(i >= index_begin && i < index_end && session->fifo_audio_data[i] >= 0) {
         // xraudio main thread is responsible for closing write side of the pipe
         session->fifo_audio_data[i] = -1;
      } else if(session->fifo_audio_data[i] >= 0) {
         more_streams = true;
      }
   }

   if(!more_streams) {
      session->audio_buf_samples       = NULL;
      session->audio_buf_sample_qty    = 0;
      session->data_callback           = NULL;
      session->stream_time_minimum     = 0;
      session->stream_keyword_begin    = 0;
      session->stream_keyword_duration = 0;

      for(uint32_t i = 0; i < XRAUDIO_FIFO_QTY_MAX; i++) {
         session->from[i]   = XRAUDIO_INPUT_RECORD_FROM_INVALID;
         session->offset[i] = 0;
         session->until[i]  = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
      }

      session->state = XRAUDIO_INPUT_STATE_IDLING;
   }
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_capture_to_file_start(xraudio_input_object_t object, xraudio_capture_t capture, xraudio_container_t container, const char *audio_file_path, bool raw_mic_enable, audio_in_callback_t callback, void *param) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   xraudio_input_session_t *session = &obj->sessions[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   // Ensure that microphone data is being received
   if(session->state == XRAUDIO_INPUT_STATE_CREATED || session->state >= XRAUDIO_INPUT_STATE_INVALID) {
      XLOGD_ERROR("invalid state <%s>", xraudio_input_state_str(session->state));
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   // Ensure that a capture is not in progress
   if(obj->capture.active) {
      XLOGD_ERROR("capture in progress");
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(container != XRAUDIO_CONTAINER_WAV && container != XRAUDIO_CONTAINER_NONE) {
      XLOGD_ERROR("unsupported container <%s>", xraudio_container_str(container));
      return(XRAUDIO_RESULT_ERROR_CONTAINER);
   }

   if(capture >= (XRAUDIO_CAPTURE_OUTPUT << 1)) {
      XLOGD_ERROR("unsupported capture <%s>", xraudio_capture_str(capture));
      return(XRAUDIO_RESULT_ERROR_CONTAINER);
   }

   XLOGD_INFO("file <%s> capture <%s> container <%s> raw_mic_enable <%d>", audio_file_path, xraudio_capture_str(capture), xraudio_container_str(container), raw_mic_enable);

   obj->capture.active          = true;
   obj->capture.type            = capture;
   obj->capture.container       = container;
   obj->capture.audio_file_path = audio_file_path;
   obj->capture.raw_mic_enable  = raw_mic_enable;

   return(xraudio_input_dispatch_capture(obj, callback, param));
}

xraudio_result_t xraudio_input_capture_stop(xraudio_input_object_t object) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_RECORD_MUTEX_LOCK();
   xraudio_result_t result = xraudio_input_capture_stop_locked(obj);
   XRAUDIO_RECORD_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_input_capture_stop_locked(xraudio_input_obj_t *obj) {
   if(!obj->capture.active) {
      XLOGD_ERROR("capture not in progress");
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   xraudio_input_dispatch_capture_stop(obj);

   obj->capture.active          = false;
   obj->capture.type            = XRAUDIO_CAPTURE_INPUT_MONO;
   obj->capture.container       = XRAUDIO_CONTAINER_INVALID;
   obj->capture.audio_file_path = NULL;
   obj->capture.raw_mic_enable  = false;

   return(XRAUDIO_RESULT_OK);
}

void xraudio_input_dispatch_idle_start(xraudio_input_obj_t *obj) {
   xraudio_queue_msg_idle_start_t msg;
   msg.header.type         = XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_START;
   msg.fd                  = obj->fd;
   msg.format              = obj->format_in;
   msg.pcm_bit_qty         = obj->pcm_bit_qty;
   msg.devices_input       = obj->device;
   msg.capabilities        = obj->capabilities;

   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
}

void xraudio_input_dispatch_idle_stop(xraudio_input_obj_t *obj) {
   xraudio_queue_msg_record_idle_stop_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_STOP;

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   msg.semaphore = &semaphore;
   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

   // Block until operation is complete
   sem_wait(&semaphore);
}

xraudio_result_t xraudio_input_dispatch_record(xraudio_input_obj_t *obj, xraudio_devices_input_t source, xraudio_input_format_t *format_decoded, bool subsequent, audio_in_callback_t callback, void *param) {
   bool synchronous = (callback == NULL) ? true : false;

   xraudio_input_session_t *session = xraudio_input_source_to_session(obj, source);

   xraudio_queue_msg_record_start_t msg;
   msg.header.type              = XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_START;
   msg.source                   =  source;
   msg.format_native            = session->format_out;
   msg.callback                 = callback;
   msg.param                    = param;
   msg.semaphore                = NULL;
   msg.frame_group_qty          = session->frame_group_qty;
   msg.fd                       = session->fd;
   msg.audio_buf_samples        = session->audio_buf_samples;
   msg.audio_buf_sample_qty     = session->audio_buf_sample_qty;
   msg.latency_mode             = session->latency_mode;
   #if defined(XRAUDIO_DGA_ENABLED) && defined(XRAUDIO_KWD_ENABLED)
   msg.kwd_peak_power_dBFS      = session->kwd_peak_power_dBFS;
   msg.dynamic_gain_update      = session->dynamic_gain_update;
   session->kwd_peak_power_dBFS = 0;
   #endif

   // Reset latency mode flag back to normal. Latency mode will persist until the end of the stream.
   session->latency_mode       = XRAUDIO_STREAM_LATENCY_NORMAL;

   msg.cpu_util_mode           = session->cpu_util_mode;

   // Reset cpu util mode flag back to normal. cpu util mode will persist until the end of the stream.
   session->cpu_util_mode      = XRAUDIO_STREAM_CPU_UTIL_NORMAL;

   for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
      msg.fifo_audio_data[index] = session->fifo_audio_data[index];

      msg.stream_from[index]         = session->from[index];
      msg.stream_begin_offset[index] = session->offset[index];
      msg.stream_until[index]        = session->until[index];
   }
   msg.data_callback           = session->data_callback;
   msg.fifo_sound_intensity    = session->fifo_sound_intensity;
   msg.stream_time_minimum     = session->stream_time_minimum;
   msg.stream_keyword_begin    = session->stream_keyword_begin;
   msg.stream_keyword_duration = session->stream_keyword_duration;
   msg.format_decoded          = (format_decoded != NULL) ? *format_decoded : (xraudio_input_format_t){ .container = XRAUDIO_CONTAINER_INVALID, .encoding.type = XRAUDIO_ENCODING_INVALID, .sample_rate = 0, .sample_size = 0, .channel_qty = 0 };
   snprintf(msg.identifier, sizeof(msg.identifier), "%s", session->stream_identifer);
   msg.subsequent              = subsequent;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      return(XRAUDIO_RESULT_OK);
   }

   // asynchronous
   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_dispatch_detect(xraudio_input_obj_t *obj, keyword_callback_t callback, void *param, bool synchronous) {
   xraudio_queue_msg_detect_t msg;

   msg.header.type            = XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT;
   msg.callback               = callback;
   msg.param                  = param;
   msg.chan_qty               = obj->format_in.channel_qty;
   msg.sensitivity            = obj->detect_params.sensitivity;
   msg.semaphore              = NULL;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      return(XRAUDIO_RESULT_OK);
   }

   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_dispatch_detect_params(xraudio_input_obj_t *obj) {
   xraudio_queue_msg_detect_params_t msg;
   msg.header.type            = XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_PARAMS;
   msg.sensitivity            = obj->detect_params.sensitivity;

   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_dispatch_detect_stop(xraudio_input_obj_t *obj, xraudio_devices_input_t source, audio_in_callback_t callback, void *param) {
   bool synchronous = (callback == NULL) ? true : false;
   xraudio_queue_msg_detect_stop_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_STOP;
   msg.source      = source;
   msg.synchronous = synchronous;
   msg.callback    = callback;
   msg.param       = param;
   msg.semaphore   = NULL;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      return(XRAUDIO_RESULT_OK);
   }

   // asynchronous
   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_dispatch_stop(xraudio_input_obj_t *obj, xraudio_devices_input_t source, int32_t index, audio_in_callback_t callback, void *param) {
   bool synchronous = (callback == NULL) ? true : false;
   xraudio_queue_msg_record_stop_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_STOP;
   msg.source      = source;
   msg.synchronous = synchronous;
   msg.index       = index;
   msg.callback    = callback;
   msg.param       = param;
   msg.semaphore   = NULL;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      return(XRAUDIO_RESULT_OK);
   }

   // asynchronous
   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_dispatch_capture(xraudio_input_obj_t *obj, audio_in_callback_t callback, void *param) {
   xraudio_queue_msg_capture_start_t msg;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   msg.header.type          = XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_START;
   msg.semaphore            = &semaphore;
   msg.callback             = callback;
   msg.param                = param;
   msg.capture_type         = obj->capture.type;
   msg.container            = obj->capture.container;
   msg.audio_file_path      = obj->capture.audio_file_path;
   msg.raw_mic_enable       = obj->capture.raw_mic_enable;

   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

   // Block until operation is complete
   sem_wait(&semaphore);
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_input_dispatch_capture_stop(xraudio_input_obj_t *obj) {
   xraudio_queue_msg_capture_stop_t msg;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_STOP;
   msg.semaphore   = &semaphore;

   xraudio_input_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

   // Block until operation is complete
   sem_wait(&semaphore);
   return(XRAUDIO_RESULT_OK);
}

#ifdef XRAUDIO_KWD_ENABLED
bool xraudio_input_audio_hal_open(xraudio_input_obj_t *obj, xraudio_devices_input_t device, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_input_format_t format, uint8_t *pcm_bit_qty, int *fd) {
   #ifdef INPUT_TIMING_DATA
   rdkx_timestamp_get(&obj->timing_data_input_open.begin);
   #endif

   xraudio_device_input_configuration_t configuration;
   configuration.fd               = -1;
   configuration.interval.tv_sec  = 0;
   configuration.interval.tv_usec = 0;
   configuration.pcm_bit_qty      = *pcm_bit_qty;
   configuration.power_mode       = power_mode;
   configuration.privacy_mode     = privacy_mode;

   obj->hal_input_obj = xraudio_hal_input_open(obj->hal_obj, device, format, &configuration);

   // Get the bit qty back from the hal object
   *pcm_bit_qty = configuration.pcm_bit_qty;
   *fd          = configuration.fd;
   
   #ifdef INPUT_TIMING_DATA
   rdkx_timestamp_get(&obj->timing_data_input_open.end);
   #endif

   return(obj->hal_input_obj != NULL);
}

void xraudio_input_audio_hal_close(xraudio_input_obj_t *obj) {
   if(obj->hal_input_obj == NULL) {
      return;
   }
   XLOGD_INFO("");

   #ifdef INPUT_TIMING_DATA
   rdkx_timestamp_get(&obj->timing_data_input_close.begin);
   #endif

   xraudio_hal_input_close(obj->hal_input_obj);
   obj->hal_input_obj = NULL;


   #ifdef INPUT_TIMING_DATA
   rdkx_timestamp_get(&obj->timing_data_input_close.end);
   #endif
}
#endif

void xraudio_input_statistics_clear(xraudio_input_object_t object, uint32_t statistics) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(statistics & XRAUDIO_STATISTICS_INPUT_GENERAL) {
      xraudio_input_stats_general_clear(obj);
   }
   if(statistics & XRAUDIO_STATISTICS_INPUT_TIMING) {
      xraudio_input_stats_timing_clear(obj);
   }
   if(statistics & XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_ALL) {
      xraudio_input_stats_sound_focus_clear(obj, statistics & XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_ALL);
   }
}

void xraudio_input_statistics_print(xraudio_input_object_t object, uint32_t statistics) {
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(statistics & XRAUDIO_STATISTICS_INPUT_GENERAL) {
      xraudio_input_stats_general_print(obj);
   }
   if(statistics & XRAUDIO_STATISTICS_INPUT_TIMING) {
      xraudio_input_stats_timing_print(obj);
   }
   if(statistics & XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_ALL) {
      xraudio_input_stats_sound_focus_print(obj, statistics & XRAUDIO_STATISTICS_INPUT_SOUND_FOCUS_ALL);
   }
}

static void xraudio_input_stats_general_clear(xraudio_input_obj_t *obj) {
   //if(obj->hal_input_obj != NULL) {
   //   qahw_in_get_input_frames_lost(obj->hal_input_obj);
   //}
   //obj->statistics.frames_lost = 0;
}

static void xraudio_input_stats_general_print(xraudio_input_obj_t *obj) {
   //if(obj->hal_input_obj != NULL) {
   //   obj->statistics.frames_lost += qahw_in_get_input_frames_lost(obj->hal_input_obj);
   //}
   //XLOGD_INFO("input frames lost %lu", obj->statistics.frames_lost);
}

static void xraudio_input_stats_timing_clear(xraudio_input_obj_t *obj) {
   #ifdef INPUT_TIMING_DATA
   if(obj->timing_data_begin != NULL) {
      memset(obj->timing_data_begin, 0, sizeof(xraudio_input_timing_t) * (INPUT_TIMING_SAMPLE_QTY + 1));
      obj->timing_data_current = obj->timing_data_begin;
   }
   //obj->timing_data_input_open.begin  = (rdkx_timestamp_t) { .tv_sec = 0, .tv_nsec = 0 };
   //obj->timing_data_input_open.end    = (rdkx_timestamp_t) { .tv_sec = 0, .tv_nsec = 0 };
   obj->timing_data_input_close.begin = (rdkx_timestamp_t) { .tv_sec = 0, .tv_nsec = 0 };
   obj->timing_data_input_close.end   = (rdkx_timestamp_t) { .tv_sec = 0, .tv_nsec = 0 };
   #endif
}

void xraudio_input_stats_timestamp_frame_ready(xraudio_input_object_t object, rdkx_timestamp_t timestamp_next) {
   #ifdef INPUT_TIMING_DATA
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   obj->timing_data_current->optimal = timestamp_next;
   rdkx_timestamp_get(&obj->timing_data_current->actual);
   #endif
}

void xraudio_input_stats_timestamp_frame_read(xraudio_input_object_t object) {
   #ifdef INPUT_TIMING_DATA
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   rdkx_timestamp_get(&obj->timing_data_current->time_read);
   #endif
}

void xraudio_input_stats_timestamp_frame_eos(xraudio_input_object_t object) {
   #ifdef INPUT_TIMING_DATA
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   rdkx_timestamp_get(&obj->timing_data_current->time_eos);
   #endif
}

void xraudio_input_stats_timestamp_frame_sound_focus(xraudio_input_object_t object) {
   #ifdef INPUT_TIMING_DATA
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   rdkx_timestamp_get(&obj->timing_data_current->time_snd_foc);
   #endif
}

void xraudio_input_stats_timestamp_frame_process(xraudio_input_object_t object) {
   #ifdef INPUT_TIMING_DATA
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   rdkx_timestamp_get(&obj->timing_data_current->time_process);
   #endif
}

void xraudio_input_stats_timestamp_frame_end(xraudio_input_object_t object) {
   #ifdef INPUT_TIMING_DATA
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   rdkx_timestamp_get(&obj->timing_data_current->time_capture);
   #endif
}

void xraudio_input_stats_playback_status(xraudio_input_object_t object, bool is_active) {
   #ifdef INPUT_TIMING_DATA
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   obj->timing_data_current->playback = is_active;
   if(obj->timing_data_current < obj->timing_data_end) {
      obj->timing_data_current++;
   }
   #endif
}

void xraudio_input_ppr_info_get(xraudio_input_object_t object, char **dsp_name) {
   #ifdef XRAUDIO_PPR_ENABLED
   xraudio_input_obj_t *obj = (xraudio_input_obj_t *)object;
   if(!xraudio_input_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   *dsp_name = obj->dsp_name;
   #endif
}

static void xraudio_input_stats_timing_print(xraudio_input_obj_t *obj) {
   #ifndef INPUT_TIMING_DATA
   XLOGD_INFO("timing data collection is disabled");
   #else
   printf("Microphone Open  %lld us %lld ns\n", rdkx_timestamp_subtract_us(obj->timing_data_input_open.begin,  obj->timing_data_input_open.end), rdkx_timestamp_subtract_ns(obj->timing_data_input_open.begin,  obj->timing_data_input_open.end));
   printf("Microphone Close %lld us %lld ns\n", rdkx_timestamp_subtract_us(obj->timing_data_input_close.begin, obj->timing_data_input_close.end), rdkx_timestamp_subtract_ns(obj->timing_data_input_close.begin, obj->timing_data_input_close.end));
   
   if(obj->timing_data_begin == NULL) {
      XLOGD_INFO("timing data buffer is NULL");
      return;
   }

   int64_t  sum_read =  0, sum_eos =  0, sum_snd_foc =  0, sum_process =  0, sum_capture =  0, sum_total =  0;
   int64_t  vio_read =  0, vio_eos =  0, vio_snd_foc =  0, vio_process =  0, vio_capture =  0, vio_total =  0;
   int64_t  max_read =  0, max_eos =  0, max_snd_foc =  0, max_process =  0, max_capture =  0, max_total =  0;
   int64_t  min_read = LLONG_MAX, min_eos = LLONG_MAX, min_snd_foc = LLONG_MAX, min_process = LLONG_MAX, min_capture = LLONG_MAX, min_total = LLONG_MAX;
   int64_t  avg_read, avg_eos, avg_snd_foc, avg_process, avg_capture, avg_total;
   uint32_t sample_qty = 0;

   
   printf("%12s %12s %12s   %12s %12s %12s %12s %12s %12s\n", "Optimal(ms)", "Actual(ms)", "Delta(us)", "Read(us)", "EOS(us)", "SND FOC(us)", "Process(us)", "Capture(us)", "Total(us)");
   for(uint32_t index = 0; index < INPUT_TIMING_SAMPLE_QTY - 1; index++) {
      if(obj->timing_data_begin[index + 1].optimal.tv_sec != 0) { // Ignore last entry which is invalid
         int64_t elapsed_optimal = rdkx_timestamp_subtract_ms(obj->timing_data_begin[0].actual,      obj->timing_data_begin[index].optimal);
         int64_t elapsed_actual  = rdkx_timestamp_subtract_ms(obj->timing_data_begin[0].actual,      obj->timing_data_begin[index].actual);
         int64_t elapsed_delta   = rdkx_timestamp_subtract_us(obj->timing_data_begin[index].optimal, obj->timing_data_begin[index].actual);
   
         int64_t elapsed_read    = rdkx_timestamp_subtract_us(obj->timing_data_begin[index].actual,       obj->timing_data_begin[index].time_read);
         int64_t elapsed_eos     = rdkx_timestamp_subtract_us(obj->timing_data_begin[index].time_read,    obj->timing_data_begin[index].time_eos);
         int64_t elapsed_snd_foc = rdkx_timestamp_subtract_us(obj->timing_data_begin[index].time_eos,     obj->timing_data_begin[index].time_snd_foc);
         int64_t elapsed_process = rdkx_timestamp_subtract_us(obj->timing_data_begin[index].time_snd_foc, obj->timing_data_begin[index].time_process);
         int64_t elapsed_capture = rdkx_timestamp_subtract_us(obj->timing_data_begin[index].time_process, obj->timing_data_begin[index].time_capture);
         int64_t elapsed_total   = rdkx_timestamp_subtract_us(obj->timing_data_begin[index].actual,       obj->timing_data_begin[index].time_capture);
   
         printf("%12lld %12lld %12lld %1s %12lld %12lld %12lld  %12lld %12lld %12lld\n", elapsed_optimal, elapsed_actual, elapsed_delta, obj->timing_data_begin[index].playback ? "P" : "", elapsed_read, elapsed_eos, elapsed_snd_foc, elapsed_process, elapsed_capture, elapsed_total);

         if(index == 0) { // Ignore first sample in calculations
            continue;
         }
         sample_qty++;
         if(elapsed_read    < min_read)    { min_read    = elapsed_read;    }
         if(elapsed_eos     < min_eos)     { min_eos     = elapsed_eos;     }
         if(elapsed_snd_foc < min_snd_foc) { min_snd_foc = elapsed_snd_foc; }
         if(elapsed_process < min_process) { min_process = elapsed_process; }
         if(elapsed_capture < min_capture) { min_capture = elapsed_capture; }
         if(elapsed_total   < min_total)   { min_total   = elapsed_total;   }
         if(elapsed_read    > max_read)    { max_read    = elapsed_read;    }
         if(elapsed_eos     > max_eos)     { max_eos     = elapsed_eos;     }
         if(elapsed_snd_foc > max_snd_foc) { max_snd_foc = elapsed_snd_foc; }
         if(elapsed_process > max_process) { max_process = elapsed_process; }
         if(elapsed_capture > max_capture) { max_capture = elapsed_capture; }
         if(elapsed_total   > max_total)   { max_total   = elapsed_total;   }
         sum_read    += elapsed_read;
         sum_eos     += elapsed_eos;
         sum_snd_foc += elapsed_snd_foc;
         sum_process += elapsed_process;
         sum_capture += elapsed_capture;
         sum_total   += elapsed_total;

         if(elapsed_read    >= XRAUDIO_INPUT_FRAME_PERIOD * 1000) { vio_read++;    }
         if(elapsed_eos     >= XRAUDIO_INPUT_FRAME_PERIOD * 1000) { vio_eos++;     }
         if(elapsed_snd_foc >= XRAUDIO_INPUT_FRAME_PERIOD * 1000) { vio_snd_foc++; }
         if(elapsed_process >= XRAUDIO_INPUT_FRAME_PERIOD * 1000) { vio_process++; }
         if(elapsed_capture >= XRAUDIO_INPUT_FRAME_PERIOD * 1000) { vio_capture++; }
         if(elapsed_total   >= XRAUDIO_INPUT_FRAME_PERIOD * 1000) { vio_total++;   }
      }
   }
   if(sample_qty == 0) {
      XLOGD_INFO("timing data not available");
      return;
   }
   
   avg_read    = sum_read    / sample_qty;
   avg_eos     = sum_eos     / sample_qty;
   avg_snd_foc = sum_snd_foc / sample_qty;
   avg_process = sum_process / sample_qty;
   avg_capture = sum_capture / sample_qty;
   avg_total   = sum_total   / sample_qty;

   // Print Avg, Max and Min for each step
   printf("        : %12s %12s %12s %12s\n", "Average", "Min", "Max", "Violation");
   printf("MIC READ: %12lld %12lld %12lld %12lld\n", avg_read,    min_read,    max_read,    vio_read);
   printf("EOS     : %12lld %12lld %12lld %12lld\n", avg_eos,     min_eos,     max_eos,     vio_eos);
   printf("SND FOC : %12lld %12lld %12lld %12lld\n", avg_snd_foc, min_snd_foc, max_snd_foc, vio_snd_foc);
   printf("PROCESS : %12lld %12lld %12lld %12lld\n", avg_process, min_process, max_process, vio_process);
   printf("CAPTURE : %12lld %12lld %12lld %12lld\n", avg_capture, min_capture, max_capture, vio_capture);
   printf("TOTAL   : %12lld %12lld %12lld %12lld\n", avg_total,   min_total,   max_total,   vio_total);
   #endif
}

static void xraudio_input_stats_sound_focus_clear(xraudio_input_obj_t *obj, uint32_t statistics) {
   #ifndef XRAUDIO_SDF_ENABLED
   XLOGD_INFO("sound focus is disabled");
   return;
   #else
   xraudio_sdf_statistics_clear(obj->obj_sdf, statistics);

   #endif
}

static void xraudio_input_stats_sound_focus_print(xraudio_input_obj_t *obj, uint32_t statistics) {
   #ifndef XRAUDIO_SDF_ENABLED
   XLOGD_INFO("sound focus is disabled");
   return;
   #else
   xraudio_sdf_statistics_print(obj->obj_sdf, statistics);
   #endif
}

#ifdef XRAUDIO_KWD_ENABLED
xraudio_hal_input_obj_t xraudio_input_hal_obj_external_get(xraudio_hal_input_obj_t hal_obj_input, xraudio_devices_input_t device, xraudio_input_format_t format, xraudio_device_input_configuration_t *configuration) {
   if(!xraudio_devices_input_external_is_valid(device)) {
      XLOGD_ERROR("not a valid external device");
      return NULL;
   }

   return xraudio_hal_input_open(hal_obj_input, device, format, configuration);
}
#endif

xraudio_input_session_t *xraudio_input_source_to_session(xraudio_input_obj_t *obj, xraudio_devices_input_t source) {
   return(&obj->sessions[xraudio_input_source_to_group(source)]);
}

