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
#include <string.h>
#include <bsd/string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <semaphore.h>
#include "xraudio.h"
#include "xraudio_private.h"

#define XRAUDIO_OUTPUT_IDENTIFIER (0x9C834920)

#define XRAUDIO_PLAY_MUTEX_LOCK()     sem_wait(&obj->mutex_play)
#define XRAUDIO_PLAY_MUTEX_UNLOCK()   sem_post(&obj->mutex_play)

typedef struct {
   uint32_t                       identifier;
   uint8_t                        user_id;
   xraudio_hal_obj_t              hal_obj;
   xraudio_hal_output_obj_t       hal_output_obj;
   int                            msgq;
   sem_t                          mutex_play;
   xraudio_output_state_t         state;
   xraudio_devices_output_t       device;
   xraudio_resource_id_output_t   resource_id;
   uint16_t                       capabilities;
   xraudio_output_format_t        format;
   int                            fd;
   const unsigned char *          audio_buf;
   unsigned long                  audio_buf_size;
   int                            pipe_audio_data;
   audio_out_data_callback_t      data_callback;
   char                           fifo_name[XRAUDIO_FIFO_NAME_LENGTH_MAX];
   int                            fifo_sound_intensity;
   xraudio_volume_step_t          volume_left;
   xraudio_volume_step_t          volume_right;
   xraudio_volume_step_t          volume_mono_cur;
   int8_t                         play_bumper;
   int8_t                         ramp_enable;
   int8_t                         use_external_gain; // set to 1 to use hal api for volume control or 0 to use volume control library
   #ifdef XRAUDIO_EOS_ENABLED
   xraudio_eos_object_t           obj_eos;
   #endif
   #ifdef XRAUDIO_OVC_ENABLED
   xraudio_ovc_object_t           obj_ovc;
   #endif
   xraudio_hal_dsp_config_t       dsp_config;
} xraudio_output_obj_t;

static bool             xraudio_output_object_is_valid(xraudio_output_obj_t *obj);
static long             xraudio_output_container_header_parse(xraudio_output_obj_t *obj, xraudio_container_t container, int fd, const unsigned char *header, unsigned long size, uint32_t *data_length);
static void             xraudio_output_queue_msg_push(xraudio_output_obj_t *obj, const char *msg, xr_mq_msg_size_t msg_size);
//static xraudio_result_t xraudio_output_dispatch_idle(xraudio_output_obj_t *obj);
static xraudio_result_t xraudio_output_dispatch_play(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param);
static xraudio_result_t xraudio_output_dispatch_pause(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param);
static xraudio_result_t xraudio_output_dispatch_resume(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param);
static xraudio_result_t xraudio_output_dispatch_stop(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param);
static bool             xraudio_output_audio_hal_open(xraudio_output_obj_t *obj);
static void             xraudio_output_audio_hal_close(xraudio_output_obj_t *obj);
static void             xraudio_output_sound_intensity_fifo_open(xraudio_output_obj_t *obj);
static void             xraudio_output_sound_intensity_fifo_close(xraudio_output_obj_t *obj);

static void             xraudio_output_stats_general_clear(xraudio_output_obj_t *obj);
static void             xraudio_output_stats_general_print(xraudio_output_obj_t *obj);
static void             xraudio_output_stats_timing_clear(xraudio_output_obj_t *obj);
static void             xraudio_output_stats_timing_print(xraudio_output_obj_t *obj);

static void             xraudio_output_close_locked(xraudio_output_obj_t *obj);
static xraudio_result_t xraudio_output_stop_locked(xraudio_output_obj_t *obj);

xraudio_output_object_t xraudio_output_object_create(xraudio_hal_obj_t hal_obj, uint8_t user_id, int msgq, uint16_t capabilities, xraudio_hal_dsp_config_t *dsp_config, json_t* json_obj_output) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)malloc(sizeof(xraudio_output_obj_t));
#ifdef XRAUDIO_EOS_ENABLED
   json_t *jeos_config = NULL;
#endif

   if(obj == NULL) {
      XLOGD_ERROR("Out of memory.");
      return(NULL);
   }

   sem_init(&obj->mutex_play, 0, 1);
   obj->identifier           = XRAUDIO_OUTPUT_IDENTIFIER;
   obj->user_id              = user_id;
   obj->hal_obj              = hal_obj;
   obj->msgq                 = msgq;
   obj->state                = XRAUDIO_OUTPUT_STATE_CREATED;
   obj->device               = XRAUDIO_DEVICE_OUTPUT_INVALID;
   obj->resource_id          = XRAUDIO_RESOURCE_ID_OUTPUT_INVALID;
   obj->capabilities         = XRAUDIO_CAPS_OUTPUT_NONE;
   obj->format               = (xraudio_output_format_t) { .container   = XRAUDIO_CONTAINER_INVALID,
                                                             .encoding    = XRAUDIO_ENCODING_INVALID,
                                                             .sample_rate = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                             .sample_size = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                             .channel_qty = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };
   obj->fd                   = -1;
   obj->audio_buf            = NULL;
   obj->audio_buf_size       = 0;
   obj->pipe_audio_data      = -1;
   obj->data_callback        = NULL;
   obj->hal_output_obj       = NULL;
   obj->fifo_sound_intensity = -1;
   obj->volume_left          = XRAUDIO_VOLUME_NOM;
   obj->volume_right         = XRAUDIO_VOLUME_NOM;
   obj->volume_mono_cur      = XRAUDIO_VOLUME_NOM;
   obj->play_bumper          = 0;
   obj->dsp_config           = *dsp_config;
   #ifdef XRAUDIO_EOS_ENABLED
   if(NULL == json_obj_output) {
      XLOGD_INFO("json_obj_output is null, using defaults");
   }
   else {
      jeos_config = json_object_get(json_obj_output, JSON_OBJ_NAME_OUTPUT_EOS);
      if(NULL == jeos_config) {
         XLOGD_INFO("EOS config not found, using defaults");
      }
      else {
         if(!json_is_object(jeos_config)) {
            XLOGD_INFO("jeos_config not object, using defaults");
            jeos_config = NULL;
         }
      }
   }

   obj->obj_eos              = xraudio_eos_object_create(true, jeos_config);
   #endif
   obj->use_external_gain    = (capabilities & XRAUDIO_CAPS_OUTPUT_HAL_VOLUME_CONTROL) ? 1 : 0;
   obj->ramp_enable          = 1;

   #ifdef XRAUDIO_OVC_ENABLED
   obj->obj_ovc = xraudio_ovc_object_create(obj->ramp_enable, obj->use_external_gain);
   if(obj->obj_ovc == NULL) {
       XLOGD_ERROR("Unable to allocate ovc memory");
       return(NULL);
   }
   #endif

   memset(obj->fifo_name, 0, sizeof(obj->fifo_name));

   return((xraudio_output_object_t)obj);
}

void xraudio_output_object_destroy(xraudio_output_object_t object) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(xraudio_output_object_is_valid(obj)) {
      XRAUDIO_PLAY_MUTEX_LOCK();
      if(obj->state != XRAUDIO_OUTPUT_STATE_CREATED) {
         // Close the speaker interface
         xraudio_output_close_locked(obj);
      }
      #ifdef XRAUDIO_EOS_ENABLED
      if(obj->obj_eos != NULL) {
         xraudio_eos_object_destroy(obj->obj_eos);
         obj->obj_eos = NULL;
      }
      #endif
      #ifdef XRAUDIO_OVC_ENABLED
      if(obj->obj_ovc != NULL) {
         xraudio_ovc_object_destroy(obj->obj_ovc);
         obj->obj_ovc = NULL;
      }
      #endif
      obj->identifier = 0;
      obj->state      = XRAUDIO_OUTPUT_STATE_INVALID;
      XRAUDIO_PLAY_MUTEX_UNLOCK();

      if (sem_destroy(&obj->mutex_play) < 0) {
         int errsv = errno;
         XLOGD_ERROR("sem_destroy(&obj->mutex_play) failed, errstr = %s", strerror(errsv) );
      }

      free(obj);
   }
}

bool xraudio_output_object_is_valid(xraudio_output_obj_t *obj) {
   if(obj != NULL && obj->identifier == XRAUDIO_OUTPUT_IDENTIFIER) {
      return(true);
   }
   return(false);
}

xraudio_hal_output_obj_t xraudio_output_hal_obj_get(xraudio_output_object_t object) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(NULL);
   }
   return(obj->hal_output_obj);
}

void xraudio_output_queue_msg_push(xraudio_output_obj_t *obj, const char *msg, xr_mq_msg_size_t msg_size) {
   if(msg_size > XRAUDIO_MSG_QUEUE_MSG_SIZE_MAX) {
      XLOGD_ERROR("Message size is too big! (%zd)", msg_size);
      return;
   }
   if(!xr_mq_push(obj->msgq, msg, msg_size)) {
      XLOGD_ERROR("Unable to send message!");
   }
}

void xraudio_output_open(xraudio_output_object_t object, xraudio_devices_output_t device, xraudio_power_mode_t power_mode, xraudio_resource_id_output_t resource_id, uint16_t capabilities) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state != XRAUDIO_OUTPUT_STATE_CREATED) {
      XLOGD_ERROR("session in progress <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return;
   }

   //xraudio_output_dispatch_idle();

   obj->device       = device;
   obj->resource_id  = resource_id;
   obj->capabilities = capabilities;
   obj->state        = XRAUDIO_OUTPUT_STATE_IDLING;
   XRAUDIO_PLAY_MUTEX_UNLOCK();
}

void xraudio_output_close(xraudio_output_object_t object) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   xraudio_output_close_locked(obj);
   XRAUDIO_PLAY_MUTEX_UNLOCK();
}

void xraudio_output_close_locked(xraudio_output_obj_t *obj) {
   if(obj->state > XRAUDIO_OUTPUT_STATE_IDLING && obj->state < XRAUDIO_OUTPUT_STATE_INVALID) {
      // Stop the playback in process
      xraudio_output_stop_locked(obj);
   }

   obj->state = XRAUDIO_OUTPUT_STATE_CREATED;
}

xraudio_result_t xraudio_output_play_from_file(xraudio_output_object_t object, const char *audio_file_path, audio_out_callback_t callback, void *param) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state != XRAUDIO_OUTPUT_STATE_IDLING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   size_t length = strlen(audio_file_path);
   if(length < 4) {
      XLOGD_ERROR("File name less than minimum <%s>", audio_file_path);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   
   if(strcmp(&audio_file_path[length - 4], ".wav") == 0) {
      obj->format.container = XRAUDIO_CONTAINER_WAV;
   } else {
      XLOGD_ERROR("Unsupported file extension <%s>", audio_file_path);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   // Open  input file
   errno = 0;
   obj->fd = open(audio_file_path, O_RDONLY);
   if(obj->fd < 0) {
      int errsv = errno;
      XLOGD_ERROR("Unable to open file <%s> <%s>", audio_file_path, strerror(errsv));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_FILE_OPEN);
   }
   uint32_t data_length = 0;
   long data_offset = xraudio_output_container_header_parse(obj, obj->format.container, obj->fd, NULL, 0, &data_length);
   if(data_offset < 0) {
      XLOGD_ERROR("Error parsing wave header");
      close(obj->fd);
      obj->fd = -1;
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_WAVE_HEADER);
   }
   errno = 0;
   if(lseek(obj->fd, data_offset, SEEK_SET) < 0) {
      int errsv = errno;
      XLOGD_ERROR("Unable to set file pointer to offset %ld <%s>", data_offset, strerror(errsv));
      close(obj->fd);
      obj->fd = -1;
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_FILE_SEEK);
   }
   
   if(!xraudio_output_audio_hal_open(obj)) {
      XLOGD_ERROR("Unable to open speaker interface");
      close(obj->fd);
      obj->fd = -1;
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OUTPUT_OPEN);
   }

   xraudio_output_sound_intensity_fifo_open(obj);

   XLOGD_INFO("Sample rate %u %u-bit %s <%s>", obj->format.sample_rate, obj->format.sample_size * 8, xraudio_channel_qty_str(obj->format.channel_qty), (callback == NULL) ? "sync" : "async");

   obj->state = XRAUDIO_OUTPUT_STATE_PLAYING;
   xraudio_result_t result = xraudio_output_dispatch_play(obj, callback, param);
   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_output_play_from_memory(xraudio_output_object_t object, xraudio_output_format_t *format, const unsigned char *audio_buf, unsigned long size, audio_out_callback_t callback, void *param) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state != XRAUDIO_OUTPUT_STATE_IDLING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   if(audio_buf == NULL || size == 0) {
      XLOGD_ERROR("Invalid audio buffer %p size (%lu)", audio_buf, size);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(format == NULL) {
      XLOGD_ERROR("no format specified");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(format->container == XRAUDIO_CONTAINER_NONE) {
      if(format->encoding != XRAUDIO_ENCODING_PCM) {
         XLOGD_ERROR("unsupported encoding <%s>", xraudio_encoding_str(format->encoding));
         XRAUDIO_PLAY_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_ENCODING);
      }
   } else if(format->container != XRAUDIO_CONTAINER_WAV) {
      XLOGD_ERROR("unsupported container <%s>", xraudio_container_str(format->container));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_CONTAINER);
   }
   uint32_t data_length = 0;
   long     data_offset = 0;
   if(format->container != XRAUDIO_CONTAINER_NONE) {
      data_offset = xraudio_output_container_header_parse(obj, format->container, -1, audio_buf, size, &data_length);
      if(data_offset < 0 || (unsigned long)data_offset >= size) {
         XLOGD_ERROR("Error parsing wave header");
         XRAUDIO_PLAY_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_WAVE_HEADER);
      }
      obj->format.container = format->container;
   } else {
      obj->format = *format;
   }

   if(obj->format.sample_rate < 16000 || obj->format.sample_rate > 48000 || obj->format.sample_size != 2 || obj->format.channel_qty == 0 || obj->format.channel_qty > 2) {
      XLOGD_ERROR("unsupported sample rate %u sample size %u channel qty %u", obj->format.sample_rate, obj->format.sample_size, obj->format.channel_qty);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   if(!xraudio_output_audio_hal_open(obj)) {
      XLOGD_ERROR("Unable to open speaker interface");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OUTPUT_OPEN);
   }

   xraudio_output_sound_intensity_fifo_open(obj);

   XLOGD_INFO("Sample rate %u %u-bit %s <%s>", obj->format.sample_rate, obj->format.sample_size * 8, xraudio_channel_qty_str(obj->format.channel_qty), (callback == NULL) ? "sync" : "async");

   obj->audio_buf      = &audio_buf[data_offset];;
   obj->audio_buf_size = size - data_offset;
   obj->state          = XRAUDIO_OUTPUT_STATE_PLAYING;
   xraudio_result_t result = xraudio_output_dispatch_play(obj, callback, param);
   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(result);

}

xraudio_result_t xraudio_output_play_from_pipe(xraudio_output_object_t object, xraudio_output_format_t *format, int pipe, audio_out_callback_t callback, void *param) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state != XRAUDIO_OUTPUT_STATE_IDLING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   if(pipe < 0) {
      XLOGD_ERROR("Invalid audio pipe %d", pipe);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(format == NULL) {
      XLOGD_ERROR("no format specified");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(format->container != XRAUDIO_CONTAINER_NONE || format->encoding != XRAUDIO_ENCODING_PCM) {
      XLOGD_ERROR("unsupported container <%s> encoding <%s>", xraudio_container_str(format->container), xraudio_encoding_str(format->encoding));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_CONTAINER);
   }
   if(format->sample_rate < 16000 || format->sample_rate > 48000 || format->sample_size != 2 || format->channel_qty == 0 || format->channel_qty > 2) {
      XLOGD_ERROR("unsupported sample rate %u sample size %u channel qty %u", format->sample_rate, format->sample_size, format->channel_qty);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   obj->format = *format;

   int flags = fcntl(pipe, F_GETFL);

   if((flags & O_NONBLOCK) == 0) {
      flags |= O_NONBLOCK;

      XLOGD_DEBUG("Setting pipe to non-blocking");

      if(fcntl(pipe, F_SETFL, flags) < 0) {
         XLOGD_ERROR("unable to set pipe to non-blocking");
         XRAUDIO_PLAY_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_FIFO_CONTROL);
      }
   }

   if(!xraudio_output_audio_hal_open(obj)) {
      XLOGD_ERROR("Unable to open speaker interface");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OUTPUT_OPEN);
   }

   xraudio_output_sound_intensity_fifo_open(obj);

   XLOGD_INFO("Sample rate %u %u-bit %s <%s>", obj->format.sample_rate, obj->format.sample_size * 8, xraudio_channel_qty_str(obj->format.channel_qty), (callback == NULL) ? "sync" : "async");

   obj->pipe_audio_data = pipe;
   obj->state           = XRAUDIO_OUTPUT_STATE_PLAYING;
   xraudio_result_t result = xraudio_output_dispatch_play(obj, callback, param);
   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_output_play_from_user(xraudio_output_object_t object, xraudio_output_format_t *format, audio_out_data_callback_t data, audio_out_callback_t callback, void *param) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state != XRAUDIO_OUTPUT_STATE_IDLING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }

   if(data == NULL) {
      XLOGD_ERROR("Invalid data callback");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(format == NULL) {
      XLOGD_ERROR("no format specified");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(format->container != XRAUDIO_CONTAINER_NONE || format->encoding != XRAUDIO_ENCODING_PCM) {
      XLOGD_ERROR("unsupported container <%s> encoding <%s>", xraudio_container_str(format->container), xraudio_encoding_str(format->encoding));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_CONTAINER);
   }
   if(format->sample_rate < 16000 || format->sample_rate > 48000 || format->sample_size != 2 || format->channel_qty == 0 || format->channel_qty > 2) {
      XLOGD_ERROR("unsupported sample rate %u sample size %u channel qty %u", format->sample_rate, format->sample_size, format->channel_qty);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   obj->format = *format;

   if(!xraudio_output_audio_hal_open(obj)) {
      XLOGD_ERROR("Unable to open speaker interface");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OUTPUT_OPEN);
   }

   xraudio_output_sound_intensity_fifo_open(obj);

   XLOGD_INFO("Sample rate %u %u-bit %s <%s>", obj->format.sample_rate, obj->format.sample_size * 8, xraudio_channel_qty_str(obj->format.channel_qty), (callback == NULL) ? "sync" : "async");

   obj->data_callback = data;
   obj->state         = XRAUDIO_OUTPUT_STATE_PLAYING;
   xraudio_result_t result = xraudio_output_dispatch_play(obj, callback, param);
   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_output_pause(xraudio_output_object_t object, audio_out_callback_t callback, void *param) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(obj->state != XRAUDIO_OUTPUT_STATE_PLAYING) {
      XLOGD_ERROR("invalid state <%s>", xraudio_output_state_str(obj->state));
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   
   obj->state = XRAUDIO_OUTPUT_STATE_PAUSED;
   return(xraudio_output_dispatch_pause(obj, callback, param));
}

xraudio_result_t xraudio_output_resume(xraudio_output_object_t object, audio_out_callback_t callback, void *param) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(obj->state != XRAUDIO_OUTPUT_STATE_PAUSED) {
      XLOGD_ERROR("invalid state <%s>", xraudio_output_state_str(obj->state));
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   
   obj->state = XRAUDIO_OUTPUT_STATE_PLAYING;
   return(xraudio_output_dispatch_resume(obj, callback, param));
}

xraudio_result_t xraudio_output_stop(xraudio_output_object_t object) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   xraudio_result_t result = xraudio_output_stop_locked(obj);
   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_output_stop_locked(xraudio_output_obj_t *obj) {
   if(obj->state == XRAUDIO_OUTPUT_STATE_CREATED || obj->state >= XRAUDIO_OUTPUT_STATE_INVALID) {
      XLOGD_ERROR("invalid state <%s>", xraudio_output_state_str(obj->state));
      return(XRAUDIO_RESULT_ERROR_STATE);
   } else if(obj->state == XRAUDIO_OUTPUT_STATE_IDLING) {
      return(XRAUDIO_RESULT_OK);
   }

   XLOGD_INFO("");

   xraudio_output_dispatch_stop(obj, NULL, NULL);

   if(obj->fd >= 0) {
      close(obj->fd);
      obj->fd = -1;
   }
   if(obj->pipe_audio_data >= 0) {
      close(obj->pipe_audio_data);
      obj->pipe_audio_data = -1;
   }
   obj->audio_buf       = NULL;
   obj->audio_buf_size  = 0;
   obj->data_callback   = NULL;

   xraudio_output_sound_intensity_fifo_close(obj);

   // Close the speaker interface
   xraudio_output_audio_hal_close(obj);

   obj->state = XRAUDIO_OUTPUT_STATE_IDLING;
   return(XRAUDIO_RESULT_OK);
}

//xraudio_result_t xraudio_output_dispatch_idle(xraudio_output_obj_t *obj) {
//   xraudio_queue_msg_detect_t msg;
//   msg.header.type          = XRAUDIO_QUEUE_MSG_TYPE_PLAY_IDLE;
//   xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
//   return(XRAUDIO_RESULT_OK);
//}

xraudio_result_t xraudio_output_dispatch_play(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param) {
   bool synchronous = (callback == NULL) ? true : false;
   xraudio_queue_msg_play_start_t msg;
   msg.header.type          = XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_START;
   msg.hal_output_obj       = obj->hal_output_obj;
   msg.format               = obj->format;
   msg.callback             = callback;
   msg.param                = param;
   msg.semaphore            = NULL;
   msg.fd                   = obj->fd;
   msg.audio_buf            = obj->audio_buf;
   msg.audio_buf_size       = obj->audio_buf_size;
   msg.pipe                 = obj->pipe_audio_data;
   msg.data_callback        = obj->data_callback;
   msg.fifo_sound_intensity = obj->fifo_sound_intensity;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      // call stop for synchronous playback as the playback is completed
      xraudio_output_stop_locked(obj);
      return(XRAUDIO_RESULT_OK);
   }

   // asynchronous
   xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);

}

xraudio_result_t xraudio_output_dispatch_pause(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param) {
   bool synchronous = (callback == NULL) ? true : false;
   xraudio_queue_msg_play_pause_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_PAUSE;
   msg.synchronous = synchronous;
   msg.callback    = callback;
   msg.param       = param;
   msg.semaphore   = NULL;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      return(XRAUDIO_RESULT_OK);
   }

   // asynchronous
   xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_output_dispatch_resume(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param) {
   bool synchronous = (callback == NULL) ? true : false;
   xraudio_queue_msg_play_resume_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_RESUME;
   msg.synchronous = synchronous;
   msg.callback    = callback;
   msg.param       = param;
   msg.semaphore   = NULL;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      return(XRAUDIO_RESULT_OK);
   }

   // asynchronous
   xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_output_dispatch_stop(xraudio_output_obj_t *obj, audio_out_callback_t callback, void *param) {
   bool synchronous = (callback == NULL) ? true : false;
   xraudio_queue_msg_play_stop_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_STOP;
   msg.synchronous = synchronous;
   msg.callback    = callback;
   msg.param       = param;
   msg.semaphore   = NULL;

   if(synchronous) { // synchronous
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      msg.semaphore = &semaphore;
      xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));

      // Block until operation is complete
      sem_wait(&semaphore);
      return(XRAUDIO_RESULT_OK);
   }

   // asynchronous
   xraudio_output_queue_msg_push(obj, (const char *)&msg, sizeof(msg));
   return(XRAUDIO_RESULT_OK);
}

bool xraudio_output_audio_hal_open(xraudio_output_obj_t *obj) {
   obj->hal_output_obj = xraudio_hal_output_open(obj->hal_obj, obj->device, obj->resource_id, obj->user_id, &obj->format, obj->volume_left, obj->volume_right);

   XLOGD_INFO("stream handle %p", obj->hal_output_obj);

   return(obj->hal_output_obj != NULL);
}

void xraudio_output_audio_hal_close(xraudio_output_obj_t *obj) {
   if(obj->hal_output_obj == NULL) {
      XLOGD_ERROR("invalid stream handle");
      return;
   }
   XLOGD_INFO("");
   xraudio_hal_output_close(obj->hal_output_obj, obj->device);
   obj->hal_output_obj = NULL;
}

xraudio_result_t xraudio_output_volume_set(xraudio_output_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right, int8_t ramp_en) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   obj->ramp_enable = ramp_en != 0 ? 1 : 0;

   if(right > XRAUDIO_VOLUME_MAX) {
      right = XRAUDIO_VOLUME_MAX;
      obj->play_bumper = 1;
   } else if(right < XRAUDIO_VOLUME_MIN) {
      right = XRAUDIO_VOLUME_MIN;
      obj->play_bumper = 1;
   }

   switch(obj->format.channel_qty) {
   case 1:
   case 2:  // volume control library currently does not support separate channel controls
      // increase or decrease volume if different from current volume
      if(obj->hal_output_obj != NULL && obj->capabilities & XRAUDIO_CAPS_OUTPUT_HAL_VOLUME_CONTROL) {
         xraudio_hal_output_volume_set_int(obj->hal_output_obj, obj->device, left, right);
      }

      obj->volume_right = right;
      obj->volume_left  = right;

      XLOGD_DEBUG("right <%d> left <%d> cur <%d>", obj->volume_right,  obj->volume_left, obj->volume_mono_cur);
      break;
   default:
      XLOGD_ERROR("channel quantity %d not supported by volume control.", obj->format.channel_qty);
      return(XRAUDIO_RESULT_ERROR_OUTPUT_VOLUME);
   }
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_output_volume_gain_apply(xraudio_output_object_t object, unsigned char *buffer, unsigned long bytes, int32_t chans) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   xraudio_result_t result = XRAUDIO_RESULT_OK;

   if(obj->volume_mono_cur != obj->volume_right) {
      xraudio_volume_step_t max_volume = 0, min_volume= 0;
      xraudio_volume_step_size_t vol_step_dB;

      xraudio_output_volume_config_get(object, &max_volume, &min_volume, &vol_step_dB, NULL);

      if(obj->ramp_enable == 0) {
         obj->volume_mono_cur = obj->volume_right;
         #ifdef XRAUDIO_OVC_ENABLED
         float gain = obj->volume_mono_cur * vol_step_dB;
         xraudio_ovc_set_gain(obj->obj_ovc, gain);
         #endif
         XLOGD_DEBUG("right <%d> left <%d> cur <%d> NO RAMP", obj->volume_right,  obj->volume_left,  obj->volume_mono_cur);
      } else {
         bool ramp_is_active = false;
         #ifdef XRAUDIO_OVC_ENABLED
         ramp_is_active = xraudio_ovc_is_ramp_active(obj->obj_ovc);
         #endif
         if(!ramp_is_active) {
            if(obj->volume_mono_cur < obj->volume_right) {
               obj->volume_mono_cur++;
               if(obj->volume_mono_cur > max_volume) {
                  obj->volume_mono_cur = max_volume;
               }
               #ifdef XRAUDIO_OVC_ENABLED
               xraudio_ovc_increase(obj->obj_ovc);
               #endif
            } else if(obj->volume_mono_cur > obj->volume_right) {
               obj->volume_mono_cur--;
               if(obj->volume_mono_cur < min_volume) {
                  obj->volume_mono_cur = min_volume;
               }
               #ifdef XRAUDIO_OVC_ENABLED
               xraudio_ovc_decrease(obj->obj_ovc);
               #endif
            }
            XLOGD_DEBUG("right <%d> left <%d> cur <%d> RAMP", obj->volume_right,  obj->volume_left, obj->volume_mono_cur);
         }
      }
   } else if(obj->play_bumper) {
      XLOGD_INFO("PLAY BUMPER");
      #ifdef XRAUDIO_OVC_ENABLED
      if(obj->volume_mono_cur == XRAUDIO_VOLUME_MAX) {
         xraudio_ovc_increase(obj->obj_ovc);
      } else if(obj->volume_mono_cur == XRAUDIO_VOLUME_MIN) {
         xraudio_ovc_decrease(obj->obj_ovc);
      }
      #endif
      obj->play_bumper = 0;
   }

   //XLOGD_DEBUG("right <%d> cur <%d> ramp <%d> ramp_act <%s>", obj->volume_right, obj->volume_mono_cur, obj->ramp_enable, ramp_is_active ? "YES" : "NO");
   #ifdef XRAUDIO_OVC_ENABLED
   uint32_t sample_qty = (bytes / sizeof(int16_t));
   if(!xraudio_ovc_apply_gain_multichannel(obj->obj_ovc, (int16_t *)buffer, (int16_t *)buffer, chans, sample_qty)) {
      XLOGD_ERROR("error applying gain");
      result = XRAUDIO_RESULT_ERROR_OUTPUT_VOLUME;
   }
   #endif
   if(obj->hal_output_obj != NULL && (obj->capabilities & XRAUDIO_CAPS_OUTPUT_HAL_VOLUME_CONTROL)) {
      float vol_left_scale  = 1.0;
      float vol_right_scale = 1.0;
      #ifdef XRAUDIO_OVC_ENABLED
      if(obj->use_external_gain != 0) {
         vol_left_scale  = xraudio_ovc_get_scale(obj->obj_ovc);
         vol_right_scale = xraudio_ovc_get_scale(obj->obj_ovc);
      }
      #endif

      if(!xraudio_hal_output_volume_set_float(obj->hal_output_obj, obj->device, vol_left_scale, vol_right_scale)) {
         XLOGD_ERROR("unable to set volume");
         result = XRAUDIO_RESULT_ERROR_OUTPUT_VOLUME;
      }
   }
   return(result);
}

xraudio_result_t xraudio_output_volume_get(xraudio_output_object_t object, xraudio_volume_step_t *left, xraudio_volume_step_t *right, int8_t *ramp_en) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(left != NULL) {*left = obj->volume_left;}
   if(right != NULL) {*right = obj->volume_right;}
   if(ramp_en != NULL) {*ramp_en = obj->ramp_enable;}
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_output_volume_config_set(xraudio_output_object_t object, xraudio_volume_step_t max_volume, xraudio_volume_step_t min_volume, xraudio_volume_step_size_t volume_step_dB, int8_t use_ext_gain) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   #ifdef XRAUDIO_OVC_ENABLED
   xraudio_volume_step_t volume_step;
   xraudio_ovc_config_set(obj->obj_ovc, obj->format, max_volume, min_volume, volume_step_dB, use_ext_gain, &volume_step);

   obj->volume_right = volume_step;
   obj->volume_left  = obj->volume_right;
   #endif

   obj->use_external_gain = (use_ext_gain > 0) ? 1 : 0;

   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_output_volume_config_get(xraudio_output_object_t object, xraudio_volume_step_t *max_volume, xraudio_volume_step_t *min_volume, xraudio_volume_step_size_t *volume_step_dB, int8_t *use_ext_gain) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   #ifdef XRAUDIO_OVC_ENABLED
   xraudio_ovc_config_get(obj, max_volume, min_volume, volume_step_dB);
   #endif

   if(use_ext_gain != NULL) {
      *use_ext_gain = obj->use_external_gain;
   }

   return(XRAUDIO_RESULT_OK);
}

void xraudio_output_sound_intensity_fifo_open(xraudio_output_obj_t *obj) {
   if(obj->fifo_name[0] != 0) {
      // Open fifo
      errno = 0;
      int fd = open(obj->fifo_name, O_RDWR);
      if(fd < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to open fifo %d <%s>", fd, strerror(errsv));
      }

      obj->fifo_sound_intensity = fd;
   }
}

void xraudio_output_sound_intensity_fifo_close(xraudio_output_obj_t *obj) {
   // Close previously opened fifo
   if(obj->fifo_sound_intensity >= 0) {
      errno = 0;
      int rc = close(obj->fifo_sound_intensity);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to close fifo %d <%s>", rc, strerror(errsv));
      }
      obj->fifo_sound_intensity = -1;
   }
}

xraudio_result_t xraudio_output_sound_intensity_transfer(xraudio_output_object_t object, const char *fifo_name) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   // Close previously opened fifo
   if(obj->fifo_sound_intensity >= 0) {
      errno = 0;
      int rc = close(obj->fifo_sound_intensity);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to close fifo %d <%s>", rc, strerror(errsv));
      }
      obj->fifo_sound_intensity = -1;
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

   strlcpy(obj->fifo_name, fifo_name, XRAUDIO_FIFO_NAME_LENGTH_MAX);
   return(XRAUDIO_RESULT_OK);
}

xraudio_eos_event_t xraudio_output_eos_run(xraudio_output_object_t object, int16_t *input_samples, int32_t sample_qty) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_EOS_EVENT_NONE);
   }
   #ifdef XRAUDIO_EOS_ENABLED
   return (obj->dsp_config.eos_enabled) ? xraudio_eos_run_int16(obj->obj_eos, input_samples, sample_qty) : XRAUDIO_EOS_EVENT_NONE;
   #else
   return(XRAUDIO_EOS_EVENT_NONE);
   #endif
}

unsigned char xraudio_output_signal_level_get(xraudio_output_object_t object) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(0);
   }
   #ifdef XRAUDIO_EOS_ENABLED
   if(obj->state == XRAUDIO_OUTPUT_STATE_PLAYING && obj->dsp_config.eos_enabled) {
      return(xraudio_eos_signal_level_get(obj->obj_eos));
   }
   #endif
   return(0);
}

long xraudio_output_container_header_parse(xraudio_output_obj_t *obj, xraudio_container_t container, int fd, const unsigned char *header, unsigned long size, uint32_t *data_length) {
   if(container != XRAUDIO_CONTAINER_WAV) {
      XLOGD_ERROR("Unsupported audio container <%s>", xraudio_container_str(container));
      return(-1);
   }

   return(xraudio_container_header_parse_wave(fd, header, size, &obj->format, data_length));
}

void xraudio_output_statistics_clear(xraudio_output_object_t object, uint32_t statistics) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(statistics & XRAUDIO_STATISTICS_OUTPUT_GENERAL) {
      xraudio_output_stats_general_clear(obj);
   }
   if(statistics & XRAUDIO_STATISTICS_OUTPUT_TIMING) {
      xraudio_output_stats_timing_clear(obj);
   }
}

void xraudio_output_statistics_print(xraudio_output_object_t object, uint32_t statistics) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(statistics & XRAUDIO_STATISTICS_OUTPUT_GENERAL) {
      xraudio_output_stats_general_print(obj);
   }
   if(statistics & XRAUDIO_STATISTICS_OUTPUT_TIMING) {
      xraudio_output_stats_timing_print(obj);
   }
}

static void xraudio_output_stats_general_clear(xraudio_output_obj_t *obj) {
   
}

static void xraudio_output_stats_general_print(xraudio_output_obj_t *obj) {
   if(obj->hal_output_obj != NULL) {
      XLOGD_INFO("output latency estimate %u ms", xraudio_hal_output_latency_get(obj->hal_output_obj));
   }
}

static void xraudio_output_stats_timing_clear(xraudio_output_obj_t *obj) {
   
}

static void xraudio_output_stats_timing_print(xraudio_output_obj_t *obj) {
   
}

xraudio_result_t xraudio_output_hfp_start(xraudio_output_object_t object, uint32_t sample_rate) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state != XRAUDIO_OUTPUT_STATE_IDLING) {
      XLOGD_ERROR("session in progress <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   }
   if(sample_rate != 16000 && sample_rate != 8000) {
      XLOGD_ERROR("unsupported sample rate %u", sample_rate);
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   obj->format.sample_rate = sample_rate;
   obj->format.sample_size = XRAUDIO_OUTPUT_MIN_SAMPLE_SIZE;
   obj->format.channel_qty = XRAUDIO_OUTPUT_MIN_CHANNEL_QTY;

   if(!xraudio_output_audio_hal_open(obj)) {
      XLOGD_ERROR("Unable to open speaker interface");
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OUTPUT_OPEN);
   }

   XLOGD_INFO("Sample rate %u %u-bit %s", obj->format.sample_rate, obj->format.sample_size * 8, xraudio_channel_qty_str(obj->format.channel_qty));

   obj->state           = XRAUDIO_OUTPUT_STATE_PLAYING;
   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_output_hfp_stop(xraudio_output_object_t object) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state == XRAUDIO_OUTPUT_STATE_CREATED || obj->state >= XRAUDIO_OUTPUT_STATE_INVALID) {
      XLOGD_ERROR("invalid state <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   } else if(obj->state == XRAUDIO_OUTPUT_STATE_IDLING) {
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_OK);
   }

   XLOGD_INFO("");

   // Close the speaker interface
   xraudio_output_audio_hal_close(obj);

   obj->state = XRAUDIO_OUTPUT_STATE_IDLING;
   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_output_hfp_mute(xraudio_output_object_t object, unsigned char enable) {
   xraudio_output_obj_t *obj = (xraudio_output_obj_t *)object;
   if(!xraudio_output_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   XRAUDIO_PLAY_MUTEX_LOCK();
   if(obj->state == XRAUDIO_OUTPUT_STATE_CREATED || obj->state >= XRAUDIO_OUTPUT_STATE_INVALID) {
      XLOGD_ERROR("invalid state <%s>", xraudio_output_state_str(obj->state));
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_STATE);
   } else if(obj->state == XRAUDIO_OUTPUT_STATE_IDLING) {
      XRAUDIO_PLAY_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_OK);
   }

   XLOGD_INFO("qahw_set_mic_mute <%s>", enable ? "TRUE" : "FALSE");

   if(!xraudio_hal_input_mute(NULL, XRAUDIO_DEVICE_INPUT_HFP, enable)) {
     XLOGD_ERROR("hal mic mute failed");
   }

   XRAUDIO_PLAY_MUTEX_UNLOCK();
   return(XRAUDIO_RESULT_OK);
}
