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
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef XRAUDIO_RESOURCE_MGMT
#include <sys/mman.h>
#endif
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <signal.h>
#include <semaphore.h>
#include <errno.h>
#include <jansson.h>
#include "rdkversion.h"
#include "xraudio.h"
#include "xraudio_private.h"
#ifdef XRAUDIO_DECODE_ADPCM
#include "adpcm.h"
#endif
#ifdef XRAUDIO_DECODE_OPUS
#include "xraudio_opus.h"
#endif

#define XRAUDIO_FIFO_NAME_RESOURCE "/tmp/xraudio_resource_"
#define XRAUDIO_SHARED_MEM_NAME    "/xraudio_shared_mem"
//#define XRAUDIO_SHARED_MEM_DEBUG

#define XRAUDIO_API_MUTEX_LOCK()      sem_wait(&obj->mutex_api)
#define XRAUDIO_API_MUTEX_UNLOCK()    sem_post(&obj->mutex_api)

#define XRAUDIO_IDENTIFIER (0x92834512)

typedef struct {
   uint32_t                          identifier;
   xraudio_resource_id_input_t       resource_id_record;
   uint16_t                          capabilities_record;
   xraudio_devices_input_t           devices_input;
   xraudio_input_format_t            input_format;
   uint8_t                           user_id;
   xraudio_thread_t                  main_thread;
   xraudio_thread_t                  rsrc_thread;
   sem_t                             mutex_api;
   xr_mq_t                           msgq_main;
   xr_mq_t                           msgq_resource;
   int                               fifo_resource;
   bool                              resources_requested;
   bool                              opened;
   #ifdef XRAUDIO_OUTPUT_ENABLED
   xraudio_output_object_t           obj_output;
   json_t*                           json_obj_output;
   xraudio_resource_id_output_t      resource_id_playback;
   uint16_t                          capabilities_playback;
   xraudio_devices_output_t          devices_output;
   #endif
   json_t*                           json_obj_input;
   xraudio_input_object_t            obj_input;
   json_t*                           json_obj_hal;
   #ifdef XRAUDIO_RESOURCE_MGMT
   xraudio_shared_mem_t *            shared_mem;
   int                               shared_mem_fd;
   #endif
   bool                              production_build;
   xraudio_internal_capture_params_t internal_capture_params;
} xraudio_obj_t;

typedef struct {
   #ifdef XRAUDIO_RESOURCE_MGMT
   int                      shm;
   xraudio_shared_mem_t    *shared_mem;
   uint8_t                  user_cnt;
   #endif
   xraudio_hal_obj_t        hal_obj;
   #ifdef XRAUDIO_KWD_ENABLED
   uint8_t                  hal_user_cnt;
   xraudio_hal_dsp_config_t dsp_config;
   #endif
   xraudio_power_mode_t     power_mode;
   bool                     privacy_mode;
} xraudio_process_t;

static xraudio_result_t main_thread_launch(xraudio_obj_t *obj);
static void             main_thread_terminate(xraudio_obj_t *obj);
#ifdef XRAUDIO_RESOURCE_MGMT
static xraudio_result_t rsrc_thread_launch(xraudio_obj_t *obj);
static void             rsrc_thread_terminate(xraudio_obj_t *obj);

static xraudio_result_t xraudio_shared_mem_open(xraudio_obj_t *obj);
static void             xraudio_shared_mem_close(xraudio_obj_t *obj);
#ifdef XRAUDIO_SHARED_MEM_DEBUG
static void             xraudio_shared_mem_print(xraudio_obj_t *obj);
#endif

static xraudio_result_t xraudio_message_queue_resource_open(xraudio_obj_t *obj);
static void             xraudio_message_queue_resource_close(xraudio_obj_t *obj);
static xraudio_result_t xraudio_fifo_open(const char *name, int *fifo);
static xraudio_result_t xraudio_fifo_resource_open(xraudio_obj_t *obj);
static void             xraudio_fifo_resource_close(xraudio_obj_t *obj);
#endif

static xraudio_result_t xraudio_message_queue_open(xr_mq_t *msgq);
static xraudio_result_t xraudio_message_queue_main_open(xraudio_obj_t *obj);
static void             xraudio_message_queue_main_close(xraudio_obj_t *obj);
static xraudio_result_t xraudio_audio_hal_open(xraudio_obj_t *obj);
static void             xraudio_audio_hal_close(xraudio_obj_t *obj);
static bool             xraudio_object_is_valid(xraudio_obj_t *obj);

// This variable contains data that is applicable to the entire process (ie. not per thread or object)
static xraudio_process_t g_xraudio_process = {
   #ifdef XRAUDIO_RESOURCE_MGMT
   .shm = -1, .shared_mem = NULL, .user_cnt = 0,
   #endif
   .hal_obj = NULL,
   #ifdef XRAUDIO_KWD_ENABLED
   .hal_user_cnt = 0,
   .dsp_config = { .ppr_enabled = false,
                   .dga_enabled = false,
                   .eos_enabled = false,
                   .input_kwd_max_channel_qty = 0,
                   .input_asr_max_channel_qty = 0 },
   #endif
   .power_mode = XRAUDIO_POWER_MODE_FULL, .privacy_mode = false,
};

void xraudio_version(xraudio_version_info_t *version_info, uint32_t *qty) {
   if(qty == NULL || *qty < XRAUDIO_VERSION_QTY_MAX || version_info == NULL) {
      return;
   }
   uint32_t qty_avail = *qty;

   #ifdef XRAUDIO_EOS_ENABLED
   uint32_t qty_eos = qty_avail;
   xraudio_eos_version(version_info, &qty_eos);

   version_info += qty_eos;
   qty_avail    -= qty_eos;
   #endif

   #ifdef XRAUDIO_KWD_ENABLED
   uint32_t qty_kwd = qty_avail;
   xraudio_kwd_version(version_info, &qty_kwd);

   version_info += qty_kwd;
   qty_avail    -= qty_kwd;
   #endif

   #ifdef XRAUDIO_PPR_ENABLED
   uint32_t qty_ppr = qty_avail;
   xraudio_ppr_version(version_info, &qty_ppr);

   version_info += qty_ppr;
   qty_avail    -= qty_ppr;
   #endif

   #ifdef XRAUDIO_DGA_ENABLED
   uint32_t qty_dga = qty_avail;
   xraudio_dga_version(version_info, &qty_dga);

   version_info += qty_dga;
   qty_avail    -= qty_dga;
   #endif

   #ifdef XRAUDIO_KWD_ENABLED
   uint32_t qty_hal = qty_avail;
   xraudio_hal_version(version_info, &qty_hal);

   version_info += qty_hal;
   qty_avail    -= qty_hal;
   #endif

   *qty -= qty_avail;
}

xraudio_object_t xraudio_object_create(const json_t *json_obj_xraudio_config) {
   xraudio_obj_t *obj = (xraudio_obj_t *)malloc(sizeof(xraudio_obj_t));

   if(obj == NULL) {
      XLOGD_ERROR("Out of memory.");
      return(NULL);
   }

   obj->identifier            = XRAUDIO_IDENTIFIER;
   obj->resource_id_record    = XRAUDIO_RESOURCE_ID_INPUT_INVALID;
   obj->capabilities_record   = XRAUDIO_CAPS_INPUT_NONE;
   obj->devices_input         = XRAUDIO_DEVICE_INPUT_NONE;
   #ifdef XRAUDIO_OUTPUT_ENABLED
   obj->resource_id_playback  = XRAUDIO_RESOURCE_ID_OUTPUT_INVALID;
   obj->capabilities_playback = XRAUDIO_CAPS_OUTPUT_NONE;
   obj->devices_output        = XRAUDIO_DEVICE_OUTPUT_NONE;
   obj->obj_output            = NULL;
   obj->json_obj_output       = NULL;
   #endif
   obj->input_format          = (xraudio_input_format_t) { .sample_rate = 0, .sample_size = 0, .channel_qty = 0 };
   obj->user_id               = XRAUDIO_USER_ID_MAX;
   obj->main_thread.id        = 0;
   obj->rsrc_thread.id        = 0;
   obj->main_thread.running   = false;
   obj->rsrc_thread.running   = false;
   obj->msgq_main             = XR_MQ_INVALID;
   obj->msgq_resource         = XR_MQ_INVALID;
   obj->fifo_resource         = -1;
   obj->resources_requested   = false;
   obj->opened                = false;
   obj->obj_input             = NULL;
   obj->json_obj_input        = NULL;
   obj->json_obj_hal          = NULL;
   #ifdef XRAUDIO_RESOURCE_MGMT
   obj->shared_mem            = NULL;
   obj->shared_mem_fd         = -1;
   #endif

   obj->internal_capture_params.enable        = false;
   obj->internal_capture_params.use_curtail   = false;
   obj->internal_capture_params.file_qty_max  = 0;
   obj->internal_capture_params.file_size_max = 0;
   obj->internal_capture_params.dir_path      = NULL;

   if(NULL == json_obj_xraudio_config) {
      XLOGD_INFO("json_obj_xraudio_config is null, using defaults");
   } else {
      obj->json_obj_input = json_object_get(json_obj_xraudio_config, JSON_OBJ_NAME_INPUT);
      if(NULL == obj->json_obj_input || !json_is_object(obj->json_obj_input)) {
         XLOGD_INFO("input object not found, using defaults");
         obj->json_obj_input = NULL;
      } else {
         json_incref(obj->json_obj_input);
      }

      #ifdef XRAUDIO_OUTPUT_ENABLED
      obj->json_obj_output = json_object_get(json_obj_xraudio_config, JSON_OBJ_NAME_OUTPUT);
      if(NULL == obj->json_obj_output || !json_is_object(obj->json_obj_output)) {
         XLOGD_INFO("output object not found, using defaults");
         obj->json_obj_output = NULL;
      } else {
         json_incref(obj->json_obj_output);
      }
      #endif

      obj->json_obj_hal = json_object_get(json_obj_xraudio_config, JSON_OBJ_NAME_HAL);
      if(NULL == obj->json_obj_hal || !json_is_object(obj->json_obj_hal)) {
         XLOGD_INFO("hal object not found, using defaults");
         obj->json_obj_hal = NULL;
      } else {
         json_incref(obj->json_obj_hal);
      }
   }
   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_hal_init(obj->json_obj_hal);
   xraudio_hal_dsp_config_get(&g_xraudio_process.dsp_config);
   #endif

   sem_init(&obj->mutex_api, 0, 1);

   rdk_version_info_t version_info;
   memset(&version_info, 0, sizeof(version_info));

   if(0 != rdk_version_parse_version(&version_info)) {
      XLOGD_WARN("unable to parse version");
      version_info.production_build = true;
   }

   obj->production_build = version_info.production_build;

   rdk_version_object_free(&version_info);

   return((xraudio_object_t)obj);
}

void xraudio_object_destroy(xraudio_object_t object) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(xraudio_object_is_valid(obj)) {
      xraudio_close(obj);
      #ifdef XRAUDIO_RESOURCE_MGMT
      xraudio_resource_release(obj);
      #endif
      obj->identifier = 0;

      if(obj->json_obj_input != NULL) {
         json_decref(obj->json_obj_input);
         obj->json_obj_input = NULL;
      }
      #ifdef XRAUDIO_OUTPUT_ENABLED
      if(obj->json_obj_output != NULL) {
         json_decref(obj->json_obj_output);
         obj->json_obj_output = NULL;
      }
      #endif
      if(obj->json_obj_hal != NULL) {
         json_decref(obj->json_obj_hal);
         obj->json_obj_hal = NULL;
      }

      if(sem_destroy(&obj->mutex_api) < 0) {
         int errsv = errno;
         XLOGD_ERROR("sem_destroy(&obj->mutex_api) failed, errstr = %s", strerror(errsv) );
      }
      free(obj);
   }
}

bool xraudio_object_is_valid(xraudio_obj_t *obj) {
   if(obj != NULL && obj->identifier == XRAUDIO_IDENTIFIER) {
      return(true);
   }
   return(false);
}

xraudio_result_t xraudio_available_devices_get(xraudio_object_t object, xraudio_devices_input_t *inputs, uint32_t input_qty_max, xraudio_devices_output_t *outputs, uint32_t output_qty_max) {
   xraudio_obj_t *obj = (xraudio_obj_t *) object;

   if (!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if ((input_qty_max < XRAUDIO_INPUT_MAX_DEVICE_QTY) || (output_qty_max < XRAUDIO_OUTPUT_MAX_DEVICE_QTY)) {
      XLOGD_ERROR("Not enough space allocated for available input <%d> or output <%d> devices", XRAUDIO_INPUT_MAX_DEVICE_QTY, XRAUDIO_OUTPUT_MAX_DEVICE_QTY);
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   #if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_OUTPUT_ENABLED)
   if (!xraudio_hal_available_devices_get(inputs, input_qty_max, outputs, output_qty_max)) {
      XLOGD_ERROR("Unable to get available xraudio hal devices");
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }
   #endif

   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_resource_request(xraudio_object_t object, xraudio_devices_input_t input, xraudio_devices_output_t output, xraudio_resource_priority_t priority, resource_notification_callback_t callback, void *param) {
   #ifndef XRAUDIO_RESOURCE_MGMT
   XLOGD_ERROR("resource management is disabled");
   return(XRAUDIO_RESULT_ERROR_OBJECT);
   #else
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;

   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   if(priority >= XRAUDIO_RESOURCE_PRIORITY_INVALID) {
      XLOGD_ERROR("Invalid priority <%s>", xraudio_resource_priority_str(priority));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   if(callback == NULL) {
      XLOGD_ERROR("NULL callback");
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   if((!xraudio_devices_output_is_valid(output)) || (!xraudio_devices_input_is_valid(input))) { // Only check local input
      XLOGD_ERROR("invalid devices parameter <%s> <%s>", xraudio_devices_input_str(input), xraudio_devices_output_str(output));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   if((output == XRAUDIO_DEVICE_OUTPUT_NONE) && (input == XRAUDIO_DEVICE_INPUT_NONE)) {
      XLOGD_ERROR("invalid devices parameter <%s> <%s>", xraudio_devices_input_str(input), xraudio_devices_output_str(output));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   XRAUDIO_API_MUTEX_LOCK();

   if(obj->opened) {
      XLOGD_ERROR("Already opened.");
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OPEN);
   }

   if(XRAUDIO_RESULT_OK != xraudio_shared_mem_open(obj)) {
      XLOGD_ERROR("Unable to open shared memory.");
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   if(XRAUDIO_RESULT_OK != xraudio_message_queue_resource_open(obj)) {
      XLOGD_ERROR("Unable to create resource message queue.");
      xraudio_shared_mem_close(obj);
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   if(XRAUDIO_RESULT_OK != xraudio_fifo_resource_open(obj)) {
      XLOGD_ERROR("Unable to create resource fifo.");
      xraudio_message_queue_resource_close(obj);
      xraudio_shared_mem_close(obj);
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   if(XRAUDIO_RESULT_OK != rsrc_thread_launch(obj)) {
      XLOGD_ERROR("Unable to launch resource thread.");
      xraudio_fifo_resource_close(obj);
      xraudio_message_queue_resource_close(obj);
      xraudio_shared_mem_close(obj);
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   // Dispatch the request to the resource manager thread
   xraudio_queue_msg_resource_request_t msg;
   msg.header.type = XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_REQUEST;
   msg.object      = object;
   msg.input       = input;
   msg.output      = output;
   msg.priority    = priority;
   msg.callback    = callback;
   msg.cb_param    = param;

   queue_msg_push(obj->msgq_resource, (const char *)&msg, sizeof(msg));

   obj->resources_requested = true;
   XLOGD_INFO("resources <%s> <%s>", xraudio_devices_input_str(input), xraudio_devices_output_str(output));

   XRAUDIO_API_MUTEX_UNLOCK();
   return(XRAUDIO_RESULT_OK);
   #endif
}

#ifdef XRAUDIO_RESOURCE_MGMT
void xraudio_resource_grant(xraudio_object_t object, xraudio_resource_id_input_t resource_id_record, xraudio_resource_id_output_t resource_id_playback, uint16_t capabilities_record, uint16_t capabilities_playback) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;

   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(!obj->resources_requested) {
      return;
   }

   XRAUDIO_API_MUTEX_LOCK();

   obj->resource_id_record    = resource_id_record;
   obj->resource_id_playback  = resource_id_playback;
   obj->capabilities_record   = capabilities_record;
   obj->capabilities_playback = capabilities_playback;

   XRAUDIO_API_MUTEX_UNLOCK();

   XLOGD_INFO("<%s, %s>", xraudio_resource_id_input_str(obj->resource_id_record), xraudio_resource_id_output_str(obj->resource_id_playback));
}
#endif

void xraudio_resource_release(xraudio_object_t object) {
   #ifndef XRAUDIO_RESOURCE_MGMT
   XLOGD_ERROR("resource management is disabled");
   #else
   xraudio_obj_t *obj = (xraudio_obj_t *)object;

   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(!obj->resources_requested) {
      return;
   }

   XLOGD_INFO("<%s, %s>", xraudio_resource_id_input_str(obj->resource_id_record), xraudio_resource_id_output_str(obj->resource_id_playback));
   xraudio_close(obj);

   XRAUDIO_API_MUTEX_LOCK();

   // Release the resources
   xraudio_rsrc_queue_msg_generic_t msg;
   msg.header.type = XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_RELEASE;

   queue_msg_push(obj->msgq_resource, (const char *)&msg, sizeof(msg));

   //TODO make this synchronous

   obj->resource_id_record    = XRAUDIO_RESOURCE_ID_INPUT_INVALID;
   obj->resource_id_playback  = XRAUDIO_RESOURCE_ID_OUTPUT_INVALID;
   obj->capabilities_record   = XRAUDIO_CAPS_INPUT_NONE;
   obj->capabilities_playback = XRAUDIO_CAPS_OUTPUT_NONE;
   rsrc_thread_terminate(obj);
   xraudio_message_queue_resource_close(obj);
   xraudio_fifo_resource_close(obj);
   xraudio_shared_mem_close(obj);
   obj->resources_requested = false;

   XRAUDIO_API_MUTEX_UNLOCK();
   #endif
}

xraudio_result_t xraudio_open(xraudio_object_t object, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_devices_input_t input, xraudio_devices_output_t output, xraudio_input_format_t *format) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_OK;

   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if((uint32_t)power_mode >= XRAUDIO_POWER_MODE_INVALID) {
      XLOGD_ERROR("Invalid power mode <%s>", xraudio_power_mode_str(power_mode));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   XRAUDIO_API_MUTEX_LOCK();

   if(obj->opened) {
      XLOGD_TELEMETRY("Already opened.");
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OPEN);
   }

   #if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_OUTPUT_ENABLED)
   #ifndef XRAUDIO_RESOURCE_MGMT
   xraudio_hal_capabilities caps;
   xraudio_hal_capabilities_get(&caps);
   // Allocate the first resource since resource management is disabled
   if(output != XRAUDIO_DEVICE_OUTPUT_NONE) {
      #ifdef XRAUDIO_OUTPUT_ENABLED
      obj->resource_id_playback  = XRAUDIO_RESOURCE_ID_OUTPUT_1;
      obj->capabilities_playback = caps.output_caps[0];
      #else
      XLOGD_ERROR("Invalid output <%s>", xraudio_devices_output_str(output));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
      #endif
   }
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(input) != XRAUDIO_DEVICE_INPUT_NONE) {
      for(uint8_t index = 0; index < caps.input_qty; index++) { // Find the local microphone
         if(caps.input_caps[index] & (XRAUDIO_CAPS_INPUT_LOCAL | XRAUDIO_CAPS_INPUT_LOCAL_32_BIT)) {
            obj->resource_id_record    = XRAUDIO_RESOURCE_ID_INPUT_1;
            obj->capabilities_record   = caps.input_caps[index];
         }
      }
   }
   #endif
   #endif

   if((!xraudio_devices_output_is_valid(output)) || (!xraudio_devices_input_is_valid(input))) {
      XLOGD_ERROR("invalid devices parameter <%s> <%s>", xraudio_devices_input_str(input), xraudio_devices_output_str(output));
      obj->devices_input  = XRAUDIO_DEVICE_INPUT_NONE;
      #ifdef XRAUDIO_OUTPUT_ENABLED
      obj->devices_output = XRAUDIO_DEVICE_OUTPUT_NONE;
      #endif
      result = XRAUDIO_RESULT_ERROR_PARAMS;
   } else if((output == XRAUDIO_DEVICE_OUTPUT_NONE) && (input == XRAUDIO_DEVICE_INPUT_NONE)) {
      XLOGD_ERROR("invalid devices parameter <%s> <%s>", xraudio_devices_input_str(input), xraudio_devices_output_str(output));
      obj->devices_input  = XRAUDIO_DEVICE_INPUT_NONE;
      #ifdef XRAUDIO_OUTPUT_ENABLED
      obj->devices_output = XRAUDIO_DEVICE_OUTPUT_NONE;
      #endif
      result = XRAUDIO_RESULT_ERROR_PARAMS;
   #ifdef XRAUDIO_OUTPUT_ENABLED
   } else if(((output                                != XRAUDIO_DEVICE_OUTPUT_NONE) && (obj->resource_id_playback >= XRAUDIO_RESOURCE_ID_OUTPUT_INVALID))) {
      XLOGD_ERROR("invalid output resource allocation.");
      result = XRAUDIO_RESULT_ERROR_RESOURCE;
   #endif
   } else if(((XRAUDIO_DEVICE_INPUT_LOCAL_GET(input) != XRAUDIO_DEVICE_INPUT_NONE)  && (obj->resource_id_record   >= XRAUDIO_RESOURCE_ID_INPUT_INVALID))) { // Only care about resources for local mic
      XLOGD_ERROR("invalid input resource allocation.");
      result = XRAUDIO_RESULT_ERROR_RESOURCE;
   } else {
      obj->devices_input  = input;
      XLOGD_INFO("input devices: <%s>, resources: <%s>", xraudio_devices_input_str(input), xraudio_resource_id_input_str(obj->resource_id_record));
      #ifdef XRAUDIO_OUTPUT_ENABLED
      obj->devices_output = output;
      XLOGD_INFO("output devices: <%s>, resources: <%s>", xraudio_devices_output_str(output), xraudio_resource_id_output_str(obj->resource_id_playback));
      #endif
   }

   if(result != XRAUDIO_RESULT_OK) {
      XRAUDIO_API_MUTEX_UNLOCK();
      return(result);
   }

   if(format != NULL) {
      if(format->sample_rate != 16000 && format->sample_rate != 22050 && format->sample_rate != 44100 && format->sample_rate != 48000) {
         XLOGD_ERROR("invalid sample rate %u Hz", format->sample_rate);
         result = XRAUDIO_RESULT_ERROR_PARAMS;
      } else if(format->sample_size != XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE) {
         XLOGD_ERROR("invalid sample size %u-bit", format->sample_size * 8);
         result = XRAUDIO_RESULT_ERROR_PARAMS;
      } else if(format->channel_qty < XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY || format->channel_qty > XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
         XLOGD_ERROR("invalid channel qty %u", format->channel_qty);
         result = XRAUDIO_RESULT_ERROR_PARAMS;
      } else {
         obj->input_format = *format;
      }
   } else { // Use default values
      obj->input_format.sample_rate = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE;
      obj->input_format.sample_size = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE;
      obj->input_format.channel_qty = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY;
   }

   if(result != XRAUDIO_RESULT_OK) {
      XRAUDIO_API_MUTEX_UNLOCK();
      return(result);
   }

   g_xraudio_process.privacy_mode = privacy_mode;

   if(XRAUDIO_RESULT_OK != xraudio_audio_hal_open(obj)) {
      result = XRAUDIO_RESULT_ERROR_INTERNAL;
   } else if(XRAUDIO_RESULT_OK != xraudio_message_queue_main_open(obj)) {
      result = XRAUDIO_RESULT_ERROR_INTERNAL;
      xraudio_audio_hal_close(obj);
   }

   xraudio_hal_dsp_config_t *dsp_config = NULL;
   #ifdef XRAUDIO_KWD_ENABLED
   dsp_config = &g_xraudio_process.dsp_config;
   #endif

   if(result == XRAUDIO_RESULT_OK) {
      XLOGD_INFO("input sample rate %u Hz %u-bit %s privacy <%s>", obj->input_format.sample_rate, obj->input_format.sample_size * 8, xraudio_channel_qty_str(obj->input_format.channel_qty), privacy_mode ? "YES" : "NO");

      if((obj->devices_input != XRAUDIO_DEVICE_INPUT_NONE) && (obj->devices_input != XRAUDIO_DEVICE_INPUT_HFP)) { // Create microphone object
         obj->obj_input = xraudio_input_object_create(g_xraudio_process.hal_obj, obj->user_id, obj->msgq_main, obj->capabilities_record, dsp_config, obj->json_obj_input);
         result = xraudio_input_open(obj->obj_input, obj->devices_input, power_mode, privacy_mode, obj->resource_id_record, obj->capabilities_record, obj->input_format);
      }

      if(result == XRAUDIO_RESULT_ERROR_MIC_OPEN) {
         XLOGD_TELEMETRY("failed to open microphone");
         xraudio_audio_hal_close(obj);
         xraudio_input_object_destroy(obj->obj_input);
         XRAUDIO_API_MUTEX_UNLOCK();
         return result;
      }

      #ifdef XRAUDIO_KWD_ENABLED
      xraudio_hal_dsp_config_get(&g_xraudio_process.dsp_config);
      #endif

      #ifdef XRAUDIO_OUTPUT_ENABLED
      if(obj->devices_output != XRAUDIO_DEVICE_OUTPUT_NONE) { // Create speaker object
         obj->obj_output = xraudio_output_object_create(g_xraudio_process.hal_obj, obj->user_id, obj->msgq_main, obj->capabilities_playback, dsp_config, obj->json_obj_output);
         xraudio_output_open(obj->obj_output, obj->devices_output, power_mode, obj->resource_id_playback, obj->capabilities_playback);
      }
      #endif

      // Launch main xraudio thread
      if(XRAUDIO_RESULT_OK != main_thread_launch(obj)) {
         result = XRAUDIO_RESULT_ERROR_INTERNAL;
         #ifdef XRAUDIO_OUTPUT_ENABLED
         if(obj->obj_output != NULL) {
            xraudio_output_close(obj->obj_output);
            xraudio_output_object_destroy(obj->obj_output);
            obj->obj_output = NULL;
         }
         #endif
         if(obj->obj_input != NULL) {
            xraudio_input_close(obj->obj_input);
            xraudio_input_object_destroy(obj->obj_input);
            obj->obj_input = NULL;
         }
         xraudio_message_queue_main_close(obj);
         xraudio_audio_hal_close(obj);
      } else {
         g_xraudio_process.power_mode   = power_mode;
         obj->opened                    = true;
      }
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

void xraudio_close(xraudio_object_t object) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(obj->opened) {
      #ifdef XRAUDIO_OUTPUT_ENABLED
      if(obj->obj_output != NULL) {
         xraudio_output_close(obj->obj_output);
      }
      #endif
      if(obj->obj_input != NULL) {
         xraudio_input_close(obj->obj_input);
      }

      // Terminate the main thread
      main_thread_terminate(obj);

      if(obj->obj_input != NULL) { // Destroy microphone object
         xraudio_input_object_destroy(obj->obj_input);
         obj->obj_input = NULL;
      }
      #ifdef XRAUDIO_OUTPUT_ENABLED
      if(obj->obj_output != NULL) { // Destroy speaker object
         xraudio_output_object_destroy(obj->obj_output);
         obj->obj_output = NULL;
      }
      #endif

      xraudio_message_queue_main_close(obj);

      xraudio_audio_hal_close(obj);

      obj->opened = false;
   }
   XRAUDIO_API_MUTEX_UNLOCK();
}

xraudio_result_t xraudio_internal_capture_params_set(xraudio_object_t object, xraudio_internal_capture_params_t *params) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(params == NULL) {
      XLOGD_ERROR("Null params");
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   XRAUDIO_API_MUTEX_LOCK();
   xraudio_result_t result = XRAUDIO_RESULT_OK;

   if(!params->enable) {
      XLOGD_INFO("disabled");
   } else { // Check other input params
      if(params->file_qty_max == 0 || params->file_size_max < 4096) {
         XLOGD_ERROR("invalid params - file qty max <%u> file size max <%u>", params->file_qty_max, params->file_size_max);
         XRAUDIO_API_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_PARAMS);
      }

      if(params->dir_path == NULL) {
         XLOGD_ERROR("Null dir path");
         XRAUDIO_API_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_PARAMS);
      }

      struct stat stats;

      errno = 0;
      int rc = stat(params->dir_path, &stats);

      if(rc < 0) {
         int errsv = errno;
         XLOGD_ERROR("invalid params - dir path <%s> stat error <%s>", params->dir_path, strerror(errsv));
         XRAUDIO_API_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_PARAMS);
      }
      if(!S_ISDIR(stats.st_mode)) { // dir doesn't exist or isn't writable
         XLOGD_ERROR("invalid params - dir path <%s>", params->dir_path);
         XRAUDIO_API_MUTEX_UNLOCK();
         return(XRAUDIO_RESULT_ERROR_PARAMS);
      }
      XLOGD_INFO("file qty max <%u> file size max <%u> dir path <%s>", params->file_qty_max, params->file_size_max, params->dir_path);
   }

   obj->internal_capture_params = *params;

   if(obj->opened) { // Need to send the new params to main thread
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      xraudio_main_queue_msg_capture_params_set_t msg;
      msg.header.type    = XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_PARAMS_SET;
      msg.capture_params = obj->internal_capture_params;
      msg.semaphore      = &semaphore;
      msg.result         = &result;

      queue_msg_push(obj->msgq_main, (const char*)&msg, sizeof(msg));

      sem_wait(&semaphore);
      sem_destroy(&semaphore);

      if(result != XRAUDIO_RESULT_OK) {
         XLOGD_ERROR("unable to set capture params");
      }
   }

   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_internal_capture_delete_files(xraudio_object_t object, const char *dir_path) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(dir_path == NULL) {
      XLOGD_ERROR("Null dir_path");
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(obj->opened) {
      XLOGD_ERROR("capture params must be set before calling open.");
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_OPEN);
   }

   struct stat stats;

   errno = 0;
   int rc = stat(dir_path, &stats);

   if(rc < 0) {
      int errsv = errno;
      XLOGD_ERROR("invalid params - dir path <%s> stat error <%s>", dir_path, strerror(errsv));
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(!S_ISDIR(stats.st_mode)) { // dir doesn't exist or isn't writable
      XLOGD_ERROR("invalid params - dir path <%s>", dir_path);
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   xraudio_result_t result = xraudio_capture_file_delete_all(dir_path);

   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_message_queue_open(xr_mq_t *msgq) {
   xr_mq_attr_t attr;
   attr.max_msg      = XRAUDIO_MSG_QUEUE_MSG_MAX;
   attr.max_msg_size = XRAUDIO_MSG_QUEUE_MSG_SIZE_MAX;

   *msgq = xr_mq_create(&attr);

   if(*msgq < 0) {
      XLOGD_ERROR("unable to create message queue");
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   return(XRAUDIO_RESULT_OK);
}

xraudio_result_t xraudio_message_queue_main_open(xraudio_obj_t *obj) {
   return xraudio_message_queue_open(&obj->msgq_main);
}

void xraudio_message_queue_main_close(xraudio_obj_t *obj) {
   if(obj->msgq_main != XR_MQ_INVALID) {
      xr_mq_destroy(obj->msgq_main);
      obj->msgq_main = XR_MQ_INVALID;
   }
}

#ifdef XRAUDIO_RESOURCE_MGMT
xraudio_result_t xraudio_message_queue_resource_open(xraudio_obj_t *obj) {
   return xraudio_message_queue_open(&obj->msgq_resource);
}

void xraudio_message_queue_resource_close(xraudio_obj_t *obj) {
   if(obj->msgq_resource != XR_MQ_INVALID) {
      xr_mq_destroy(obj->msgq_resource);
      obj->msgq_resource = XR_MQ_INVALID;
   }
}

void xraudio_resource_fifo_name_get(char *name, uint8_t user_id) {
   snprintf(name, XRAUDIO_FIFO_NAME_LENGTH_MAX, "%s%u", XRAUDIO_FIFO_NAME_RESOURCE, user_id);
}

xraudio_result_t xraudio_fifo_resource_open(xraudio_obj_t *obj) {
   char name[XRAUDIO_FIFO_NAME_LENGTH_MAX];

   xraudio_resource_fifo_name_get(name, obj->user_id);

   XLOGD_INFO("<%s>", name);

   return xraudio_fifo_open(name, &obj->fifo_resource);
}

xraudio_result_t xraudio_fifo_open(const char *name, int *fifo) {
   errno = 0;
   int rc = mkfifo(name, 0666);

   if(rc < 0) {
      int errsv = errno;
      if(errsv != EEXIST) {
         XLOGD_ERROR("unable to create fifo <%s> <%s>", name, strerror(errsv));
         return(XRAUDIO_RESULT_ERROR_INTERNAL);
      }
      XLOGD_INFO("unlink existing fifo <%s>", name);

      // Fifo already exists so unlink the current one and try to create again
      errno = 0;
      rc = unlink(name);
      if(rc < 0) {
         errsv = errno;
         XLOGD_ERROR("unable to unlink fifo <%s> <%s>", name, strerror(errsv));
         return(XRAUDIO_RESULT_ERROR_INTERNAL);
      }
      errno = 0;
      rc = mkfifo(name, 0666);
      if(rc < 0) {
         errsv = errno;
         XLOGD_ERROR("unable to create fifo <%s> <%s>", name, strerror(errsv));
         return(XRAUDIO_RESULT_ERROR_INTERNAL);
      }
   }

   XLOGD_INFO("opening fifo <%s>", name);

   errno = 0;
   *fifo = open(name, O_RDWR);
   if(*fifo < 0) {
      int errsv = errno;
      XLOGD_ERROR("unable to open fifo <%s> <%s>", name, strerror(errsv));
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   return(XRAUDIO_RESULT_OK);
}

void xraudio_fifo_resource_close(xraudio_obj_t *obj) {
   if(obj->fifo_resource >= 0) {
      close(obj->fifo_resource);
      obj->fifo_resource = -1;

      char name[XRAUDIO_FIFO_NAME_LENGTH_MAX];

      xraudio_resource_fifo_name_get(name, obj->user_id);

      int rc = unlink(name);
      if(rc < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to unlink fifo <%s> %d <%s>", name, rc, strerror(errsv));
      }
   }
}

xraudio_result_t xraudio_shared_mem_open(xraudio_obj_t *obj) {
   errno = 0;
   obj->shared_mem_fd = open("/tmp/.xraudio_lockfile", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
   if(obj->shared_mem_fd == -1) {
       int err = errno;
       XLOGD_FATAL("open() failed <%s>", strerror(err));
       exit(-1);
   }

   XRAUDIO_SHARED_MEM_LOCK(obj);
   bool created = false;

   if(g_xraudio_process.shm < 0) {
      errno = 0;
      g_xraudio_process.shm = shm_open(XRAUDIO_SHARED_MEM_NAME, O_CREAT | O_RDWR, 0666);

      if(g_xraudio_process.shm < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to open shared memory<%s>", strerror(errsv));
         XRAUDIO_SHARED_MEM_UNLOCK(obj);
         return(XRAUDIO_RESULT_ERROR_INTERNAL);
      }
   }

   struct stat buf;
   errno = 0;
   if(fstat(g_xraudio_process.shm, &buf) < 0) {
      int errsv = errno;
      XLOGD_ERROR("unable to stat shared memory %d <%s>", g_xraudio_process.shm, strerror(errsv));
      XRAUDIO_SHARED_MEM_UNLOCK(obj);
      xraudio_shared_mem_close(obj);
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   if(buf.st_size == 0) { // Shared memory region was created
      XLOGD_INFO("Created shared memory region");
      errno = 0;
      if(ftruncate(g_xraudio_process.shm, sizeof(xraudio_shared_mem_t)) < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to set shared memory size %d <%s>", g_xraudio_process.shm, strerror(errsv));
         XRAUDIO_SHARED_MEM_UNLOCK(obj);
         xraudio_shared_mem_close(obj);
         return(XRAUDIO_RESULT_ERROR_INTERNAL);
      }

      created = true;
   }

   if(g_xraudio_process.shared_mem == NULL) {
      errno = 0;
      g_xraudio_process.shared_mem = (xraudio_shared_mem_t *)mmap(NULL, sizeof(xraudio_shared_mem_t), (PROT_READ | PROT_WRITE), MAP_SHARED, g_xraudio_process.shm, 0);

      if(g_xraudio_process.shared_mem == NULL) {
         int errsv = errno;
         XLOGD_ERROR("unable to map shared memory %d <%s>", g_xraudio_process.shm, strerror(errsv));
         XRAUDIO_SHARED_MEM_UNLOCK(obj);
         xraudio_shared_mem_close(obj);
         return(XRAUDIO_RESULT_ERROR_INTERNAL);
      }
   }

   g_xraudio_process.user_cnt++;
   obj->shared_mem = g_xraudio_process.shared_mem;

   // Clean up user ids
   for(uint8_t index = 0; index < XRAUDIO_USER_ID_MAX; index++) {
      pid_t pid = obj->shared_mem->user_ids[index];

      if(pid != 0) {
         if(kill(pid, 0) < 0) { // Remove the stale entry and decrement the user count
            XLOGD_INFO("Removing stale entry at index %u with pid %u user count %u", index, pid, obj->shared_mem->user_count);
            obj->shared_mem->user_ids[index] = 0;
            if(obj->shared_mem->user_count) {
               obj->shared_mem->user_count--;
            }
         }
      }
   }

   if(created || (obj->shared_mem->user_count == 0)) {
      XLOGD_INFO("initialize resource list");
      xraudio_resource_list_init(obj->shared_mem);
   }

   // TODO Need to validate resource linked list

   obj->shared_mem->user_count++;
   obj->user_id = XRAUDIO_USER_ID_MAX;

   // Get next user id
   for(uint8_t index = 0; index < XRAUDIO_USER_ID_MAX; index++) {
      if(obj->shared_mem->user_ids[index] == 0) {
         obj->shared_mem->user_ids[index] = getpid();
         obj->user_id = index;
         break;
      }
   }
   #ifdef XRAUDIO_SHARED_MEM_DEBUG
   xraudio_shared_mem_print(obj);
   #endif
   XRAUDIO_SHARED_MEM_UNLOCK(obj);

   if(obj->user_id >= XRAUDIO_USER_ID_MAX) {
      XLOGD_ERROR("unable to allocate user id %u", obj->user_id);
      xraudio_shared_mem_close(obj);
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }
   XLOGD_INFO("user id %u", obj->user_id);
   return(XRAUDIO_RESULT_OK);
}

#ifdef XRAUDIO_SHARED_MEM_DEBUG
void xraudio_shared_mem_print(xraudio_obj_t *obj) {
   XLOGD_INFO("BEGIN");
   xraudio_shared_mem_t *shmem = obj->shared_mem;

   XLOGD_INFO("addr begin %p end 0x%08x size %u", shmem, ((uint32_t)shmem) + sizeof(xraudio_shared_mem_t), sizeof(xraudio_shared_mem_t));
   XLOGD_INFO("user count %u", shmem->user_count);
   for(uint8_t index = 0; index < XRAUDIO_USER_ID_MAX; index++) {
      XLOGD_INFO("User Id %u, pid %d", index, shmem->user_ids[index]);
   }
   for(uint8_t index = 0; index < XRAUDIO_RESOURCE_LIST_QTY_MAX; index++) {
      xraudio_resource_entry_t *entry = &shmem->resource_list[index];
      XLOGD_INFO("index %u %p Priority <%s> Pid %d msgq %d user id %u priority <%s> notified <%s> Req <%s, %s> Id <%s, %s>", index, entry, xraudio_resource_priority_str(entry->priority), entry->pid, entry->msgq, entry->user_id, xraudio_resource_priority_str(entry->priority), entry->notified ? "TRUE" : "FALSE",
               xraudio_devices_input_str(entry->req_input), xraudio_devices_output_str(entry->req_output), XRAUDIO_RESOURCE_ID_INPUT_str(entry->id_record), XRAUDIO_RESOURCE_ID_OUTPUT_str(entry->id_playback));
   }

   XLOGD_INFO("LIST HEAD offset 0x%08X", shmem->resource_list_offset_head);
   for(xraudio_resource_entry_t *entry = xraudio_resource_list_get_head(shmem); entry != NULL; entry = xraudio_resource_list_get_next(shmem, entry)) {
      XLOGD_INFO("%p Priority <%s> Pid %d msgq %d user id %u priority <%s> notified <%s> Req <%s, %s> Id <%s, %s>", entry, xraudio_resource_priority_str(entry->priority), entry->pid, entry->msgq, entry->user_id, xraudio_resource_priority_str(entry->priority), entry->notified ? "TRUE" : "FALSE",
               xraudio_devices_input_str(entry->req_input), xraudio_devices_output_str(entry->req_output), XRAUDIO_RESOURCE_ID_INPUT_str(entry->id_record), XRAUDIO_RESOURCE_ID_OUTPUT_str(entry->id_playback));
   }
   XLOGD_INFO("END");
}
#endif

void xraudio_shared_mem_close(xraudio_obj_t *obj) {
   uint32_t user_count_system  = 0;

   XRAUDIO_SHARED_MEM_LOCK(obj);

   if(obj->shared_mem != NULL) {
      g_xraudio_process.user_cnt--;
      obj->shared_mem->user_count--;
      if(obj->user_id < XRAUDIO_USER_ID_MAX) {
         obj->shared_mem->user_ids[obj->user_id] = 0;
      }

      user_count_system  = obj->shared_mem->user_count;

      obj->shared_mem = NULL;
   }

   if(g_xraudio_process.user_cnt == 0) { // Only unmap and close when nothing in this process needs shared mem
      if(g_xraudio_process.shared_mem != NULL) {
         errno = 0;
         if(munmap(g_xraudio_process.shared_mem, sizeof(xraudio_shared_mem_t)) < 0) {
            int errsv = errno;
            XLOGD_WARN("unable to unmap shared memory %d <%s>", g_xraudio_process.shm, strerror(errsv));
         }
         g_xraudio_process.shared_mem = NULL;
      }

      if(g_xraudio_process.shm >= 0) {
         errno = 0;
         if(close(g_xraudio_process.shm) < 0) {
            int errsv = errno;
            XLOGD_WARN("unable to close shared memory %d <%s>", g_xraudio_process.shm, strerror(errsv));
         }
         g_xraudio_process.shm = -1;
      }
   }

   if(user_count_system == 0) { // Only unlink when nothing in the system needs shared mem
      XLOGD_INFO("unlink shared memory");
      errno = 0;
      if(shm_unlink(XRAUDIO_SHARED_MEM_NAME) < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to unlink shared memory <%s>", strerror(errsv));
      }
   }
   XRAUDIO_SHARED_MEM_UNLOCK(obj);

   errno = 0;
   if(close(obj->shared_mem_fd) == -1) {
      int err = errno;
      XLOGD_FATAL("close() failed <%s>", strerror(err));
      exit(-1);
   }
}

void xraudio_shared_mem_lock(xraudio_object_t object) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }

   errno = 0;
   if(flock(obj->shared_mem_fd, LOCK_EX)) { // Block until has exclusive access to file
      int err = errno;
      XLOGD_FATAL("flock() failed <%s>", strerror(err));
      exit(-1);
   }
}

void xraudio_shared_mem_unlock(xraudio_object_t object) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   errno = 0;
   if(flock(obj->shared_mem_fd, LOCK_UN)) { // Release exclusive access to file
      int err = errno;
      XLOGD_FATAL("flock() failed <%s>", strerror(err));
      exit(-1);
   }
}
#endif

xraudio_result_t xraudio_audio_hal_open(xraudio_obj_t *obj) {
   #ifdef XRAUDIO_KWD_ENABLED
   XLOGD_INFO("hal obj %p user count %u", g_xraudio_process.hal_obj, g_xraudio_process.hal_user_cnt);

   // Get qahw handle from process global memory
   if(g_xraudio_process.hal_obj == NULL) {
      XLOGD_INFO("hal open obj");
      g_xraudio_process.hal_obj = xraudio_hal_open(false, g_xraudio_process.power_mode, g_xraudio_process.privacy_mode, xraudio_hal_msg_async_handler);
      if(g_xraudio_process.hal_obj == NULL) {
         XLOGD_ERROR("hal open failed.");
         return(XRAUDIO_RESULT_ERROR_INTERNAL);
      }
   }
   g_xraudio_process.hal_user_cnt++;
   XLOGD_INFO("hal obj %p", g_xraudio_process.hal_obj);
   #endif
   return(XRAUDIO_RESULT_OK);
}

void xraudio_audio_hal_close(xraudio_obj_t *obj) {
   #ifdef XRAUDIO_KWD_ENABLED
   XLOGD_INFO("hal obj %p user count %u", g_xraudio_process.hal_obj, g_xraudio_process.hal_user_cnt);
   g_xraudio_process.hal_user_cnt--;
   if((g_xraudio_process.hal_user_cnt == 0) && (g_xraudio_process.hal_obj != NULL)) {
      XLOGD_INFO("");
      xraudio_hal_close(g_xraudio_process.hal_obj);
      g_xraudio_process.hal_obj = NULL;
   }
   #endif
}

xraudio_result_t main_thread_launch(xraudio_obj_t *obj) {
   if(obj->main_thread.running) {
      XLOGD_ERROR("already running...");
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xraudio_main_thread_params_t params;
   params.msgq                           = obj->msgq_main;
   params.semaphore                      = &semaphore;
   params.obj_input                      = obj->obj_input;
   #ifdef XRAUDIO_OUTPUT_ENABLED
   params.obj_output                     = obj->obj_output;
   params.json_obj_output                = obj->json_obj_output;
   #endif
   #ifdef XRAUDIO_KWD_ENABLED
   params.hal_obj                        = g_xraudio_process.hal_obj;
   params.dsp_config                     = g_xraudio_process.dsp_config;
   params.hal_input_obj                  = obj->obj_input ? xraudio_input_hal_obj_get(obj->obj_input) : NULL;
   #endif
   params.internal_capture_params        = obj->internal_capture_params;
   params.json_obj_input                 = obj->json_obj_input;

   if(!xraudio_thread_create(&obj->main_thread, "xraudio_main", xraudio_main_thread, &params)) {
      XLOGD_ERROR("unable to launch thread");
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   // Block until initialization is complete or a timeout occurs
   XLOGD_DEBUG("Waiting for main thread initialization...");
   sem_wait(&semaphore);
   return(XRAUDIO_RESULT_OK);
}

void main_thread_terminate(xraudio_obj_t *obj) {
   if(!obj->main_thread.running) {
      return;
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xraudio_main_queue_msg_terminate_t msg;
   struct timespec end_time;

   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_TERMINATE;
   msg.semaphore   = &semaphore;

   queue_msg_push(obj->msgq_main, (const char *)&msg, sizeof(msg));

   // Block until termination is acknowledged or a timeout occurs
   XLOGD_INFO("Waiting for main thread termination...");
   int rc = -1;
   if(clock_gettime(CLOCK_REALTIME, &end_time) != 0) {
      XLOGD_ERROR("unable to get time");
   } else {
      end_time.tv_sec += 5;
      do {
         errno = 0;
         rc = sem_timedwait(&semaphore, &end_time);
         if(rc == -1 && errno == EINTR) {
            XLOGD_INFO("interrupted");
         } else {
            break;
         }
      } while(1);
   }

   if(rc != 0) { // no response received
      XLOGD_INFO("Do NOT wait for thread to exit");
   } else {
      // Wait for thread to exit
      XLOGD_INFO("Waiting for thread to exit");
      xraudio_thread_join(&obj->main_thread);
      XLOGD_INFO("thread exited.");
   }
}

#ifdef XRAUDIO_RESOURCE_MGMT
xraudio_result_t rsrc_thread_launch(xraudio_obj_t *obj) {
   if(obj->rsrc_thread.running) {
      XLOGD_INFO("already running...");
      return(XRAUDIO_RESULT_OK);
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xraudio_resource_thread_params_t params;
   params.msgq               = obj->msgq_resource;
   params.fifo               = obj->fifo_resource;
   params.user_id            = obj->user_id;
   params.shared_mem         = obj->shared_mem;
   params.semaphore          = &semaphore;

   if(!xraudio_thread_create(&obj->rsrc_thread, "xraudio_rsrc", xraudio_resource_thread, &params)) {
      XLOGD_ERROR("unable to launch thread");
      return(XRAUDIO_RESULT_ERROR_INTERNAL);
   }

   // Block until initialization is complete or a timeout occurs
   XLOGD_DEBUG("Waiting for resource thread initialization...");
   sem_wait(&semaphore);
   return(XRAUDIO_RESULT_OK);
}

void rsrc_thread_terminate(xraudio_obj_t *obj) {
   if(!obj->rsrc_thread.running) {
      return;
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xraudio_rsrc_queue_msg_terminate_t msg;
   struct timespec end_time;

   msg.header.type = XRAUDIO_RSRC_QUEUE_MSG_TYPE_TERMINATE;
   msg.semaphore   = &semaphore;

   queue_msg_push(obj->msgq_resource, (const char *)&msg, sizeof(msg));

   // Block until termination is acknowledged or a timeout occurs
   XLOGD_INFO("Waiting for resource thread termination...");
   int rc = -1;
   if(clock_gettime(CLOCK_REALTIME, &end_time) != 0) {
      XLOGD_ERROR("unable to get time");
   } else {
      end_time.tv_sec += 5;
      do {
         errno = 0;
         rc = sem_timedwait(&semaphore, &end_time);
         if(rc == -1 && errno == EINTR) {
            XLOGD_INFO("interrupted");
         } else {
            break;
         }
      } while(1);
   }

   if(rc != 0) { // no response received
      XLOGD_INFO("Do NOT wait for thread to exit");
   } else {
      // Wait for thread to exit
      XLOGD_INFO("Waiting for thread to exit");
      xraudio_thread_join(&obj->rsrc_thread);
      XLOGD_INFO("thread exited.");
   }
}
#endif

void queue_msg_push(xr_mq_t xrmq, const char *msg, xr_mq_msg_size_t msg_size) {
   if(msg_size > XRAUDIO_MSG_QUEUE_MSG_SIZE_MAX) {
      XLOGD_ERROR("Message size is too big! (%zd)", msg_size);
      return;
   }
   if(!xr_mq_push(xrmq, msg, msg_size)) {
      XLOGD_ERROR("Unable to send message!");
   }
}

xraudio_result_t xraudio_detect_params(xraudio_object_t object, xraudio_keyword_phrase_t keyword_phrase, xraudio_keyword_sensitivity_t keyword_sensitivity) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_keyword_params(obj->obj_input, keyword_phrase, keyword_sensitivity);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_detect_keyword(xraudio_object_t object, keyword_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_keyword_detect(obj->obj_input, callback, param, true);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_detect_stop(xraudio_object_t object) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_detect_stop(obj->obj_input, obj->devices_input);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_detect_sensitivity_limits_get(xraudio_object_t object, xraudio_keyword_sensitivity_t *keyword_sensitivity_min, xraudio_keyword_sensitivity_t *keyword_sensitivity_max) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return XRAUDIO_RESULT_ERROR_OBJECT;
   }
   if(keyword_sensitivity_min == NULL || keyword_sensitivity_max == NULL) {
      XLOGD_ERROR("Invalid params - keyword_sensitivity_min <%p> keyword_sensitivity_max <%p>", keyword_sensitivity_min, keyword_sensitivity_max);
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   XRAUDIO_API_MUTEX_LOCK();

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xraudio_main_queue_msg_detect_sensitivity_limits_get_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_SENSITIVITY_LIMITS_GET;
   msg.min         = keyword_sensitivity_min;
   msg.max         = keyword_sensitivity_max;
   msg.semaphore   = &semaphore;
   msg.result      = &result;

   queue_msg_push(obj->msgq_main, (const char*)&msg, sizeof(msg));

   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   if(result != XRAUDIO_RESULT_OK) {
      XLOGD_ERROR("unable to get keyword detector sensitivity limits");
   }

   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_source_fd_set(xraudio_object_t object, xraudio_devices_input_t source, int fd, xraudio_input_format_t format, xraudio_input_data_read_cb_t callback, void *user_data) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(source != XRAUDIO_DEVICE_INPUT_PTT && source != XRAUDIO_DEVICE_INPUT_FF) {
      XLOGD_ERROR("Invalid source <%s>", xraudio_devices_input_str(source));
      return(XRAUDIO_RESULT_ERROR_INPUT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_source_fd_set(obj->obj_input, source, fd, format, callback, user_data);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_record_sound_intensity_transfer(xraudio_object_t object, const char *fifo_name) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_sound_intensity_transfer(obj->obj_input, fifo_name);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_record_to_file(xraudio_object_t object, xraudio_devices_input_t source, xraudio_container_t container, const char *audio_file_path, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_input_record_to_file(obj->obj_input, source, container, audio_file_path, from, offset, until, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_record_to_memory(xraudio_object_t object, xraudio_devices_input_t source, xraudio_sample_t *buf_samples, uint32_t sample_qty, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_input_record_to_memory(obj->obj_input, source, buf_samples, sample_qty, from, offset, until, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_record_stop(xraudio_object_t object, xraudio_devices_input_t source) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("microphone object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_stop(obj->obj_input, source, -1);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_time_minimum(xraudio_object_t object, xraudio_devices_input_t source, uint16_t ms) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_stream_time_minimum(obj->obj_input, source, ms);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_keyword_info(xraudio_object_t object, xraudio_devices_input_t source, uint32_t keyword_begin, uint32_t keyword_duration) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_stream_keyword_info(obj->obj_input, source, keyword_begin, keyword_duration);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_keyword_info_get(xraudio_object_t object, xraudio_devices_input_t source, xraudio_keyword_detector_result_t *keyword_result) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_stream_keyword_info_get(obj->obj_input, source, keyword_result);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_sound_intensity_transfer(xraudio_object_t object, const char *fifo_name) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_sound_intensity_transfer(obj->obj_input, fifo_name);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_latency_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_latency_mode_t latency_mode) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(obj->devices_input) == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("microphone object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_latency_mode_set(obj->obj_input, source, latency_mode);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_cpu_util_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_cpu_util_mode_t cpu_util_mode) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(obj->devices_input) == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("microphone object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_cpu_util_mode_set(obj->obj_input, source, cpu_util_mode);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_frame_group_quantity_set(xraudio_object_t object, xraudio_devices_input_t source, uint8_t quantity) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_frame_group_quantity_set(obj->obj_input, source, quantity);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_identifier_set(xraudio_object_t object, xraudio_devices_input_t source, const char *identifier) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_stream_identifer_set(obj->obj_input, source, identifier);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_stream_to_fifo(xraudio_object_t object, xraudio_devices_input_t source, const char *fifo_name, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("microphone object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_input_stream_to_fifo(obj->obj_input, source, fifo_name, from, offset, until, format_decoded, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_stream_to_pipe(xraudio_object_t object, xraudio_devices_input_t source, xraudio_dst_pipe_t dsts[], xraudio_input_format_t *format_decoded, bool subsequent, audio_in_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_input_stream_to_pipe(obj->obj_input, source, dsts, format_decoded, subsequent, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_stream_to_user(xraudio_object_t object, xraudio_devices_input_t source, audio_in_data_callback_t data, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_input_stream_to_user(obj->obj_input, source, data, from, offset, until, format_decoded, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_stream_stop(xraudio_object_t object, xraudio_devices_input_t source, int32_t index) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("input not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("input object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_stop(obj->obj_input, source, index);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_capture_to_file_start(xraudio_object_t object, xraudio_capture_t capture, xraudio_container_t container, const char *audio_file_path, bool raw_mic_enable, audio_in_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(obj->production_build) { // Disabled in production build
      XLOGD_INFO("disabled");
      result = XRAUDIO_RESULT_ERROR_DISABLED;
   } else if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(obj->devices_input) == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("microphone object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_capture_to_file_start(obj->obj_input, capture, container, audio_file_path, raw_mic_enable, callback, param);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_capture_stop(xraudio_object_t object) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(obj->production_build) { // Disabled in production build
      XLOGD_INFO("disabled");
      result = XRAUDIO_RESULT_ERROR_DISABLED;
   } else if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(obj->devices_input) == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_input == NULL) {
      XLOGD_ERROR("microphone object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_input_capture_stop(obj->obj_input);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

#ifdef XRAUDIO_OUTPUT_ENABLED
xraudio_result_t xraudio_play_sound_intensity_transfer(xraudio_object_t object, const char *fifo_name) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      xraudio_output_sound_intensity_transfer(obj->obj_output, fifo_name);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_play_from_file(xraudio_object_t object, const char *audio_file_path, audio_out_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_output_play_from_file(obj->obj_output, audio_file_path, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_play_from_memory(xraudio_object_t object, xraudio_output_format_t *format, const uint8_t *audio_buf, uint32_t size, audio_out_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_output_play_from_memory(obj->obj_output, format, audio_buf, size, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_play_from_pipe(xraudio_object_t object, xraudio_output_format_t *format, int pipe, audio_out_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_output_play_from_pipe(obj->obj_output, format, pipe, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_play_from_user(xraudio_object_t object, xraudio_output_format_t *format, audio_out_data_callback_t data, audio_out_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   bool has_mutex = true;

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      if(callback == NULL) { // Synchronous
         XRAUDIO_API_MUTEX_UNLOCK();
         has_mutex = false;
      }
      result = xraudio_output_play_from_user(obj->obj_output, format, data, callback, param);
   }
   if(has_mutex) {
      XRAUDIO_API_MUTEX_UNLOCK();
   }
   return(result);
}

xraudio_result_t xraudio_play_pause(xraudio_object_t object, audio_out_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_pause(obj->obj_output, callback, param);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_play_resume(xraudio_object_t object, audio_out_callback_t callback, void *param) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_resume(obj->obj_output, callback, param);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_play_stop(xraudio_object_t object) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not available!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_stop(obj->obj_output);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_play_volume_set(xraudio_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_volume_set(obj->obj_output, left, right, 1);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_play_volume_ramp_set(xraudio_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right, int8_t ramp_en) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_volume_set(obj->obj_output, left, right, ramp_en);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_play_volume_get(xraudio_object_t object, xraudio_volume_step_t *left, xraudio_volume_step_t *right, int8_t *ramp_en) {
    xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
    xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
    if(!xraudio_object_is_valid(obj)) {
       XLOGD_ERROR("Invalid object.");
       return(XRAUDIO_RESULT_ERROR_OBJECT);
    }

    XRAUDIO_API_MUTEX_LOCK();
    if(!obj->opened) {
       XLOGD_ERROR("xraudio is not open!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
    } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
       XLOGD_ERROR("speaker not opened!");
       result = XRAUDIO_RESULT_ERROR_OUTPUT;
    } else if(obj->obj_output == NULL) {
       XLOGD_ERROR("speaker object is NULL!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
    } else {
       result = xraudio_output_volume_get(obj->obj_output, left, right, ramp_en);
    }
    XRAUDIO_API_MUTEX_UNLOCK();
    return(result);
}

xraudio_result_t xraudio_play_volume_set_rel(xraudio_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right, int8_t ramp_en) {
   xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   xraudio_volume_step_t left_current, right_current;
   if(!xraudio_object_is_valid(obj)) {
       XLOGD_ERROR("Invalid object.");
       return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
       XLOGD_ERROR("xraudio is not open!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
       XLOGD_ERROR("speaker not opened!");
       result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->obj_output == NULL) {
       XLOGD_ERROR("speaker object is NULL!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_volume_get(obj->obj_output, &left_current, &right_current, NULL);
      if (result == XRAUDIO_RESULT_OK) {
         // check for overflow or underflow
         xraudio_volume_step_t sum_left, sum_right;
         if (((int8_t)left > (INT8_MAX - (int8_t)left_current)) ||
             ((int8_t)left < (INT8_MIN - (int8_t)left_current))) {
            XLOGD_ERROR("speaker left volume overflow or underflow. No change applied.");
            sum_left = 0;
         } else {
            sum_left = left + left_current;
         }
         if (((int8_t)right > (INT8_MAX - (int8_t)right_current)) ||
             ((int8_t)right < (INT8_MIN - (int8_t)right_current))) {
            XLOGD_ERROR("speaker right volume overflow or underflow. No change applied.");
            sum_right = 0;
         } else {
            sum_right = right + right_current;
         }
         result = xraudio_output_volume_set(obj->obj_output, sum_left, sum_right, ramp_en);
      }
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_play_volume_config_set(xraudio_object_t object, xraudio_volume_step_t max_volume, xraudio_volume_step_t min_volume, xraudio_volume_step_size_t volume_step_dB, int8_t use_ext_gain) {
    xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
    xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
    if(!xraudio_object_is_valid(obj)) {
       XLOGD_ERROR("Invalid object.");
       return(XRAUDIO_RESULT_ERROR_OBJECT);
    }

    XRAUDIO_API_MUTEX_LOCK();
    if(!obj->opened) {
       XLOGD_ERROR("xraudio is not open!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
    } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
       XLOGD_ERROR("speaker not opened!");
       result = XRAUDIO_RESULT_ERROR_OUTPUT;
    } else if(obj->obj_output == NULL) {
       XLOGD_ERROR("speaker object is NULL!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
    } else {
       result = xraudio_output_volume_config_set(obj->obj_output, max_volume, min_volume, volume_step_dB, use_ext_gain);
    }
    XRAUDIO_API_MUTEX_UNLOCK();
    return(result);
}

xraudio_result_t xraudio_play_volume_config_get(xraudio_object_t object, xraudio_volume_step_t *max_volume, xraudio_volume_step_t *min_volume, xraudio_volume_step_size_t *volume_step_dB, int8_t *use_ext_gain) {
    xraudio_obj_t *  obj    = (xraudio_obj_t *)object;
    xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
    if(!xraudio_object_is_valid(obj)) {
       XLOGD_ERROR("Invalid object.");
       return(XRAUDIO_RESULT_ERROR_OBJECT);
    }

    XRAUDIO_API_MUTEX_LOCK();
    if(!obj->opened) {
       XLOGD_ERROR("xraudio is not open!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
    } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
       XLOGD_ERROR("speaker not opened!");
       result = XRAUDIO_RESULT_ERROR_OUTPUT;
    } else if(obj->obj_output == NULL) {
       XLOGD_ERROR("speaker object is NULL!");
       result = XRAUDIO_RESULT_ERROR_OPEN;
    } else {
       result = xraudio_output_volume_config_get(obj->obj_output, max_volume, min_volume, volume_step_dB, use_ext_gain);
    }
    XRAUDIO_API_MUTEX_UNLOCK();
    return(result);
}
#endif

void xraudio_statistics_clear(xraudio_object_t object, uint32_t statistics) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   
   XRAUDIO_API_MUTEX_LOCK();
   if((statistics & XRAUDIO_STATISTICS_INPUT_ALL) && obj->obj_input != NULL) {
      xraudio_input_statistics_clear(obj->obj_input, statistics & XRAUDIO_STATISTICS_INPUT_ALL);
   }
   #ifdef XRAUDIO_OUTPUT_ENABLED
   if((statistics & XRAUDIO_STATISTICS_OUTPUT_ALL) && obj->obj_output != NULL) {
      xraudio_output_statistics_clear(obj->obj_output, statistics & XRAUDIO_STATISTICS_OUTPUT_ALL);
   }
   #endif
   XRAUDIO_API_MUTEX_UNLOCK();
}

void xraudio_statistics_print(xraudio_object_t object, uint32_t statistics) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }

   XRAUDIO_API_MUTEX_LOCK();
   if((statistics & XRAUDIO_STATISTICS_INPUT_ALL) && obj->obj_input != NULL) {
      xraudio_input_statistics_print(obj->obj_input, statistics & XRAUDIO_STATISTICS_INPUT_ALL);
   }
   #ifdef XRAUDIO_OUTPUT_ENABLED
   if((statistics & XRAUDIO_STATISTICS_OUTPUT_ALL) && obj->obj_output != NULL) {
      xraudio_output_statistics_print(obj->obj_output, statistics & XRAUDIO_STATISTICS_OUTPUT_ALL);
   }
   #endif
   XRAUDIO_API_MUTEX_UNLOCK();
}

#ifdef XRAUDIO_OUTPUT_ENABLED
xraudio_result_t xraudio_bluetooth_hfp_start(xraudio_object_t object, xraudio_input_format_t *format) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output != XRAUDIO_DEVICE_OUTPUT_HFP) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->devices_input != XRAUDIO_DEVICE_INPUT_HFP) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   //} else if(obj->obj_input == NULL) {
   //   XLOGD_ERROR("microphone object is NULL!");
   //   result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(format == NULL) {
      XLOGD_ERROR("format is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } else if(format->sample_rate != 16000 && format->sample_rate != 8000) {
      XLOGD_ERROR("invalid sample rate %u Hz", format->sample_rate);
      result = XRAUDIO_RESULT_ERROR_PARAMS;
   } else if(format->sample_size != XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE) {
      XLOGD_ERROR("invalid sample size %u-bit", format->sample_size * 8);
      result = XRAUDIO_RESULT_ERROR_PARAMS;
   } else if(format->channel_qty != XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY) {
      XLOGD_ERROR("invalid channel qty %u", format->channel_qty);
      result = XRAUDIO_RESULT_ERROR_PARAMS;
   } else {
      result = xraudio_output_hfp_start(obj->obj_output, format->sample_rate);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_bluetooth_hfp_stop(xraudio_object_t object) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   //} else if(obj->obj_input == NULL) {
   //   XLOGD_ERROR("microphone object is NULL!");
   //   result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_hfp_stop(obj->obj_output);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_bluetooth_hfp_mute(xraudio_object_t object, unsigned char enable) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) {
      XLOGD_ERROR("xraudio is not open!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   } if(obj->devices_output == XRAUDIO_DEVICE_OUTPUT_NONE) {
      XLOGD_ERROR("speaker not opened!");
      result = XRAUDIO_RESULT_ERROR_OUTPUT;
   } else if(obj->devices_input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("microphone not opened!");
      result = XRAUDIO_RESULT_ERROR_INPUT;
   } else if(obj->obj_output == NULL) {
      XLOGD_ERROR("speaker object is NULL!");
      result = XRAUDIO_RESULT_ERROR_OPEN;
   //} else if(obj->obj_input == NULL) {
   //   XLOGD_ERROR("microphone object is NULL!");
   //   result = XRAUDIO_RESULT_ERROR_OPEN;
   } else {
      result = xraudio_output_hfp_mute(obj->obj_output, enable);
   }
   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}
#endif

void xraudio_thread_poll(xraudio_object_t object, xraudio_thread_poll_func_t func) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return;
   }
   if(func == NULL) {
      XLOGD_ERROR("Invalid param.");
      return;
   }

   XRAUDIO_API_MUTEX_LOCK();
   if(!obj->opened) { // call response directly
      (*func)();
   } else { // send to main thread
      xraudio_main_queue_msg_thread_poll_t msg;
      msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_THREAD_POLL;
      msg.func        = func;

      queue_msg_push(obj->msgq_main, (const char *)&msg, sizeof(msg));
      #ifdef XRAUDIO_RESOURCE_MGMT
      #error Need to add thread poll for resource management thread.
      #endif
   }
   XRAUDIO_API_MUTEX_UNLOCK();
}

xraudio_result_t xraudio_power_mode_update(xraudio_object_t object, xraudio_power_mode_t power_mode) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if((uint32_t)power_mode >= XRAUDIO_POWER_MODE_INVALID) {
      XLOGD_ERROR("Invalid power mode <%s>", xraudio_power_mode_str(power_mode));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   XRAUDIO_API_MUTEX_LOCK();
   if(g_xraudio_process.power_mode == power_mode) {
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_OK);
   }
   XLOGD_INFO("power mode <%s>", xraudio_power_mode_str(power_mode));

   if(!obj->opened) { // just store the mode
      g_xraudio_process.power_mode = power_mode;
      result = XRAUDIO_RESULT_OK;
   } else {
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      xraudio_main_queue_msg_power_mode_t msg;
      msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_POWER_MODE;
      msg.power_mode  = power_mode;
      msg.semaphore   = &semaphore;
      msg.result      = &result;

      queue_msg_push(obj->msgq_main, (const char *)&msg, sizeof(msg));

      sem_wait(&semaphore);
      sem_destroy(&semaphore);

      if(result != XRAUDIO_RESULT_OK) {
         XLOGD_ERROR("unable to set power mode <%s>", xraudio_power_mode_str(power_mode));
      } else {
         g_xraudio_process.power_mode = power_mode;
      }
   }

   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_privacy_mode_update(xraudio_object_t object, xraudio_devices_input_t input, bool enable) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return(XRAUDIO_RESULT_ERROR_OBJECT);
   }
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(input) == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("Invalid input device <%s>", xraudio_devices_input_str(input));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   XRAUDIO_API_MUTEX_LOCK();
   if((g_xraudio_process.privacy_mode && enable) || (!g_xraudio_process.privacy_mode && !enable)) {
      XRAUDIO_API_MUTEX_UNLOCK();
      return(XRAUDIO_RESULT_OK);
   }
   XLOGD_INFO("privacy mode <%s>", enable ? "ENABLE" : "DISABLE");

   if(!obj->opened) { // just store the mode
      g_xraudio_process.privacy_mode = enable;
      result = XRAUDIO_RESULT_OK;
   } else {
      sem_t semaphore;
      sem_init(&semaphore, 0, 0);

      xraudio_main_queue_msg_privacy_mode_t msg;
      msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE;
      msg.enable      = enable;
      msg.semaphore   = &semaphore;
      msg.result      = &result;

      queue_msg_push(obj->msgq_main, (const char *)&msg, sizeof(msg));

      sem_wait(&semaphore);
      sem_destroy(&semaphore);

      if(result != XRAUDIO_RESULT_OK) {
         XLOGD_ERROR("unable to set privacy mode");
      } else {
         g_xraudio_process.privacy_mode = enable;
      }
   }

   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

xraudio_result_t xraudio_privacy_mode_get(xraudio_object_t object, xraudio_devices_input_t input, bool *enabled) {
   xraudio_obj_t *obj = (xraudio_obj_t *)object;
   if(!xraudio_object_is_valid(obj)) {
      XLOGD_ERROR("Invalid object.");
      return XRAUDIO_RESULT_ERROR_OBJECT;
   }
   if(enabled == NULL || input == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("Invalid params - input <%s> enabled <%p>", xraudio_devices_input_str(input), enabled);
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(input) == XRAUDIO_DEVICE_INPUT_NONE) {
      *enabled = g_xraudio_process.privacy_mode;
      return(XRAUDIO_RESULT_OK);
   }

   xraudio_result_t result = XRAUDIO_RESULT_ERROR_INVALID;
   XRAUDIO_API_MUTEX_LOCK();

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xraudio_main_queue_msg_privacy_mode_get_t msg;
   msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE_GET;
   msg.enabled     = enabled;
   msg.semaphore   = &semaphore;
   msg.result      = &result;

   queue_msg_push(obj->msgq_main, (const char*)&msg, sizeof(msg));

   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   if(result != XRAUDIO_RESULT_OK) {
      XLOGD_ERROR("unable to get mute state");
   } else {
      g_xraudio_process.privacy_mode = *enabled;
   }

   XRAUDIO_API_MUTEX_UNLOCK();
   return(result);
}

int32_t xraudio_container_header_parse_wave(int fd, const uint8_t *header, uint32_t size, xraudio_output_format_t *format, uint32_t *data_length) {
   long data_offset = 0;
   *data_length = 0;
   uint8_t file_data[WAVE_HEADER_SIZE_MIN];

   if(format == NULL) {
      XLOGD_ERROR("Invalid format parameter");
      return(-1);
   }

   if(fd >= 0) {
      header = file_data;
      if(lseek(fd, 0, SEEK_CUR) < 0) {
         int errsv = errno;
         XLOGD_ERROR("Unable to seek <%s>", strerror(errsv));
         return(-1);
      }
      // Read the RIFF Header
      if(12 != read(fd, file_data, 12)) {
         int errsv = errno;
         XLOGD_ERROR("Unable to read header RIFF <%s>", strerror(errsv));
         return(-1);
      }
   }

   if(strncmp((const char *)header, "RIFF", 4) != 0) {
      XLOGD_ERROR("Invalid wave header - RIFF <%c%c%c%c>", header[0], header[1], header[2], header[3]);
      return(-1);
   }
   unsigned long riff_length = (header[7] << 24) | (header[6] << 16) | (header[5] << 8) | header[4];

   if(strncmp((const char *)&header[8], "WAVE", 4) != 0) {
      XLOGD_ERROR("Invalid wave header - WAVE <%c%c%c%c>", header[8], header[9], header[10], header[11]);
      return(-1);
   }
   riff_length -= 4;

   unsigned long subchunks_length = 0;
   bool has_fmt  = false;
   bool has_data = false;

   while(subchunks_length < riff_length - 1) {
      const uint8_t *subchunk_start;

      XLOGD_DEBUG("subchunks_length %lu riff length %lu", subchunks_length, riff_length);

      if(fd < 0) {
         subchunk_start = &header[subchunks_length + 12];
      } else {
         subchunk_start = file_data;
         // Read the subchunk Header
         if(8 != read(fd, file_data, 8)) {
            int errsv = errno;
            XLOGD_ERROR("Unable to read header <%s>", strerror(errsv));
            return(-1);
         }
      }
      // Get next chunk length
      uint32_t subchunk_length = (subchunk_start[7] << 24) | (subchunk_start[6] << 16) | (subchunk_start[5] << 8) | subchunk_start[4];
      if((strncmp((const char *)subchunk_start, "fmt ", 4) == 0)) { // Handle required fmt chunk
         has_fmt = true;
         if(fd >= 0) { // Read the subchunk body
            if(subchunk_length + 8 > sizeof(file_data)) {
               XLOGD_ERROR("Unable to read fmt subchunk body");
               return(-1);
            }
            if(subchunk_length != read(fd, &file_data[8], subchunk_length)) {
               int errsv = errno;
               XLOGD_ERROR("Unable to read fmt subchunk body <%s>", strerror(errsv));
               return(-1);
            }
         }

         uint16_t audio_format    = (subchunk_start[9] << 8)   | subchunk_start[8];
         uint16_t num_channels    = (subchunk_start[11] << 8)  | subchunk_start[10];
         uint32_t sample_rate     = (subchunk_start[15] << 24) | (subchunk_start[14] << 16) | (subchunk_start[13] << 8) | subchunk_start[12];
         uint16_t bits_per_sample = (subchunk_start[23] << 8)  | subchunk_start[22];
         if(audio_format != 1 || bits_per_sample != 16 || num_channels == 0 || num_channels > 2) {
            XLOGD_ERROR("Unsupported wave params - format <%d> channel qty <%u> bits per sample <%u>", audio_format, num_channels, bits_per_sample);
            return(-1);
         } else {
            format->channel_qty   = num_channels;
            format->sample_rate   = sample_rate;
            format->sample_size   = bits_per_sample / 8;
            format->encoding.type = XRAUDIO_ENCODING_PCM;
         }

      } else if((strncmp((const char *)subchunk_start, "INFO", 4) == 0)) { // Handle optional INFO chunk
         XLOGD_DEBUG("INFO Chunk length %u", subchunk_length);
         if(fd >= 0 && lseek(fd, subchunk_length, SEEK_CUR) < 0) {
            int errsv = errno;
            XLOGD_ERROR("Unable to seek <%s>", strerror(errsv));
            return(-1);
         }
      } else if((strncmp((const char *)subchunk_start, "data", 4) == 0)) { // Check for data chunk
         has_data = true;
         data_offset  = subchunks_length + 20;
         *data_length = subchunk_length;
         XLOGD_DEBUG("data Chunk length %lu offset %ld", subchunk_length, data_offset);
         if(fd >= 0 && lseek(fd, subchunk_length, SEEK_CUR) < 0) {
            int errsv = errno;
            XLOGD_ERROR("Unable to seek <%s>", strerror(errsv));
            return(-1);
         }
      } else { // Unhandled chunk
         XLOGD_DEBUG("%c%c%c%c Chunk length %u", subchunk_start[0], subchunk_start[1], subchunk_start[2], subchunk_start[3], subchunk_length);
         if(fd >= 0 && lseek(fd, subchunk_length, SEEK_CUR) < 0) {
            int errsv = errno;
            XLOGD_ERROR("Unable to seek <%s>", strerror(errsv));
            return(-1);
         }
      }
      subchunks_length += subchunk_length + 8;
   }

   if(!has_fmt || !has_data) {
      XLOGD_ERROR("Invalid wave file - missing fmt or data subchunk");
      return(-1);
   }

   XLOGD_INFO("encoding <%s> sample rate %u Hz size %u-bit %s", xraudio_encoding_str(format->encoding.type), format->sample_rate, format->sample_size * 8, xraudio_channel_qty_str(format->channel_qty));
   return(data_offset);
}

