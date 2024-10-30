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
#ifndef _XRAUDIO_PRIVATE_H_
#define _XRAUDIO_PRIVATE_H_

#include <semaphore.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <xr_mq.h>
#include <xr_timestamp.h>
#include <xr_timer.h>
#include <jansson.h>
#include "xraudio_hal.h"
#include "xraudio_config.h"
#ifdef XRAUDIO_EOS_ENABLED
#include "xraudio_eos.h"
#endif
#ifdef XRAUDIO_KWD_ENABLED
#include "xraudio_kwd.h"
#endif
#ifdef XRAUDIO_DGA_ENABLED
#include "xraudio_dga.h"
#endif
#ifdef XRAUDIO_SDF_ENABLED
#include "xraudio_sdf.h"
#endif
#ifdef XRAUDIO_OVC_ENABLED
#include "xraudio_ovc.h"
#endif
#ifdef XRAUDIO_PPR_ENABLED
#include "xraudio_ppr.h"
#endif
#ifdef XRAUDIO_OUTPUT_ENABLED
#include "xraudio_output.h"
#endif
#include "xraudio_input.h"

#define XLOG_MODULE_ID XLOG_MODULE_ID_XRAUDIO
#include "rdkx_logger.h"

#define WAVE_HEADER_SIZE_MIN              (44)
#define WAVE_HEADER_PADDING_MAX           (32) // 8 + 24-bit * 8 channels max
#define XRAUDIO_MSG_QUEUE_MSG_MAX         (10)
#define XRAUDIO_MSG_QUEUE_MSG_SIZE_MAX    (sizeof(xraudio_queue_msg_record_start_t))
#define XRAUDIO_FIFO_NAME_LENGTH_MAX      (64)
#define XRAUDIO_FIFO_NAME_LENGTH_MIN      (2)

#define XRAUDIO_FIFO_QTY_MAX              (1)

#define BLOCK_INTERFERER_DURING_VREX       (1)

#define XRAUDIO_RESOURCE_LIST_QTY_MAX (10)
#define XRAUDIO_USER_ID_MAX           (4)

#define XRAUDIO_SHARED_MEM_LOCK(...)   xraudio_shared_mem_lock(__VA_ARGS__)
#define XRAUDIO_SHARED_MEM_UNLOCK(...) xraudio_shared_mem_unlock(__VA_ARGS__)

//#define SINGLE_PROCESS_OWNER // Define when only a single process can hold the resources

#define XRAUDIO_OUTPUT_FRAME_PERIOD (20)    // in milliseconds

#define XRAUDIO_IN_AOP_ADJ_DB_TO_SHIFT(x)    ((int8_t)roundf((x) / 6.02)) // 6 dB per bit shift

#define XRAUDIO_CAPTURE_FILE_FLAGS (O_WRONLY | O_CREAT | O_TRUNC)
#define XRAUDIO_CAPTURE_FILE_MODE  (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

typedef enum {
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_START               = 0,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_STOP                = 1,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_START                    = 2,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_STOP                     = 3,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_START                   = 4,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_STOP                    = 5,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_IDLE                       = 6,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_START                      = 7,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_PAUSE                      = 8,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_RESUME                     = 9,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_STOP                       = 10,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT                          = 11,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_PARAMS                   = 12,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_SENSITIVITY_LIMITS_GET   = 13,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_STOP                     = 14,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_BEGIN             = 15,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_END               = 16,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_INPUT_ERROR               = 17,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_TERMINATE                       = 18,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_THREAD_POLL                     = 19,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_POWER_MODE                      = 20,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE                    = 21,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE_GET                = 22,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_PARAMS_SET              = 23,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_INPUT_SOURCE_FD_SET             = 24,
   XRAUDIO_MAIN_QUEUE_MSG_TYPE_INVALID                         = 25,
} xraudio_main_queue_msg_type_t;

#ifdef XRAUDIO_RESOURCE_MGMT
typedef enum {
   XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_REQUEST    = 0,
   XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_RELEASE    = 1,
   XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_GRANT      = 2,
   XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_REVOKE     = 3,
   XRAUDIO_RSRC_QUEUE_MSG_TYPE_TERMINATE           = 4,
   XRAUDIO_RSRC_QUEUE_MSG_TYPE_INVALID             = 5,
} xraudio_rsrc_queue_msg_type_t;

typedef struct xraudio_resource_entry_t {
   uint32_t                             offset_next;    // Linked list next entry (offset from base of shared mem because can't use pointers)
   pid_t                                pid;            // Requester's process id
   xr_mq_t                              msgq;           // msgq to notify requester (if in same process)
   uint8_t                              user_id;        // user id to open fifo (when in different process)
   xraudio_resource_priority_t          priority;       // Priority of the request
   bool                                 notified;       // Set to true when the requester has been notified of an event (grant/revoke)
   xraudio_devices_input_t              req_input; // Devices that have been requested
   xraudio_devices_output_t             req_output;
   xraudio_resource_id_input_t          id_record;      // Resources that have been allocated
   xraudio_resource_id_output_t         id_playback;
} xraudio_resource_entry_t;

typedef struct {
   uint32_t                  user_count;
   pid_t                     user_ids[XRAUDIO_USER_ID_MAX];

   bool                      resource_playback[XRAUDIO_RESOURCE_ID_OUTPUT_INVALID];
   bool                      resource_record[XRAUDIO_RESOURCE_ID_INPUT_INVALID];
   uint32_t                  resource_list_offset_head; // Can't use pointers in shared mem so this is actually offset from base of shared mem to the head entry or NULL is the list is empty
   xraudio_resource_entry_t  resource_list[XRAUDIO_RESOURCE_LIST_QTY_MAX];
   xraudio_hal_capabilities  capabilities;
} xraudio_shared_mem_t;
#endif

typedef struct {
   const char *   name;
   pthread_t      id;
   bool           running;
} xraudio_thread_t;

typedef struct {
   xr_mq_t                           msgq;
   sem_t *                           semaphore;
   xraudio_input_object_t            obj_input;
   #ifdef XRAUDIO_OUTPUT_ENABLED
   xraudio_output_object_t           obj_output;
   json_t*                           json_obj_output;
   #endif
   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_hal_obj_t                 hal_obj;
   xraudio_hal_input_obj_t           hal_input_obj;
   xraudio_hal_dsp_config_t          dsp_config;
   #endif
   xraudio_internal_capture_params_t internal_capture_params;
   json_t*                           json_obj_input;
} xraudio_main_thread_params_t;

#ifdef XRAUDIO_RESOURCE_MGMT
typedef struct {
   xr_mq_t               msgq;
   int                   fifo;
   uint8_t               user_id;
   xraudio_shared_mem_t *shared_mem;
   sem_t *               semaphore;
} xraudio_resource_thread_params_t;

typedef struct {
   xraudio_rsrc_queue_msg_type_t type;
} xraudio_rsrc_queue_msg_header_t;

typedef struct {
   xraudio_rsrc_queue_msg_header_t header;
} xraudio_rsrc_queue_msg_generic_t;

typedef struct {
   xraudio_rsrc_queue_msg_header_t header;
   sem_t *                         semaphore;
} xraudio_rsrc_queue_msg_terminate_t;

typedef struct {
   xraudio_rsrc_queue_msg_header_t  header;
   xraudio_object_t                 object;
   xraudio_devices_input_t          input;
   xraudio_devices_output_t         output;
   xraudio_resource_priority_t      priority;
   resource_notification_callback_t callback;
   void *                           cb_param;
} xraudio_queue_msg_resource_request_t;
#endif

typedef struct {
   xraudio_main_queue_msg_type_t type;
} xraudio_main_queue_msg_header_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
} xraudio_main_queue_msg_generic_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   sem_t *                         semaphore;
} xraudio_main_queue_msg_terminate_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   int                             fd;
   xraudio_input_format_t          format;
   uint8_t                         pcm_bit_qty;
   xraudio_devices_input_t         devices_input;
   uint16_t                        capabilities;
} xraudio_queue_msg_idle_start_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   sem_t *                         semaphore;
} xraudio_queue_msg_record_idle_stop_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_devices_input_t         source;
   xraudio_input_format_t          format_native;
   xraudio_input_format_t          format_decoded;
   audio_in_callback_t             callback;
   void *                          param;
   sem_t *                         semaphore;
   uint8_t                         frame_group_qty;
   int                             fd;
   xraudio_sample_t *              audio_buf_samples;
   unsigned long                   audio_buf_sample_qty;
   int                             fifo_audio_data[XRAUDIO_FIFO_QTY_MAX];
   xraudio_input_record_from_t     stream_from[XRAUDIO_FIFO_QTY_MAX];
   xraudio_input_record_until_t    stream_until[XRAUDIO_FIFO_QTY_MAX];
   int32_t                         stream_begin_offset[XRAUDIO_FIFO_QTY_MAX];
   audio_in_data_callback_t        data_callback;
   int                             fifo_sound_intensity;
   uint16_t                        stream_time_minimum;
   uint32_t                        stream_keyword_begin;
   uint32_t                        stream_keyword_duration;
   int16_t                         kwd_peak_power_dBFS;
   float *                         dynamic_gain_update;
   char                            identifier[XRAUDIO_STREAM_ID_SIZE_MAX];
   xraudio_stream_latency_mode_t   latency_mode;
   xraudio_stream_cpu_util_mode_t  cpu_util_mode;
   bool                            subsequent;
} xraudio_queue_msg_record_start_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   keyword_callback_t              callback;
   void *                          param;
   uint8_t                         chan_qty;
   xraudio_keyword_sensitivity_t   sensitivity;
   sem_t *                         semaphore;
} xraudio_queue_msg_detect_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_keyword_sensitivity_t   sensitivity;
} xraudio_queue_msg_detect_params_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_keyword_sensitivity_t * min;
   xraudio_keyword_sensitivity_t * max;
   sem_t *                         semaphore;
   xraudio_result_t *              result;
} xraudio_main_queue_msg_detect_sensitivity_limits_get_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_devices_input_t         source;
   bool                            synchronous;
   audio_in_callback_t             callback;
   void *                          param;
   sem_t *                         semaphore;
} xraudio_queue_msg_detect_stop_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_devices_input_t         source;
   bool                            synchronous;
   int32_t                         index;
   audio_in_callback_t             callback;
   void *                          param;
   sem_t *                         semaphore;
} xraudio_queue_msg_record_stop_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   sem_t *                         semaphore;
   audio_in_callback_t             callback;
   void *                          param;
   xraudio_capture_t               capture_type;
   xraudio_container_t             container;
   const char *                    audio_file_path;
   bool                            raw_mic_enable;
} xraudio_queue_msg_capture_start_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   sem_t *                         semaphore;
} xraudio_queue_msg_capture_stop_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_hal_output_obj_t        hal_output_obj;
   xraudio_output_format_t         format;
   audio_out_callback_t            callback;
   void *                          param;
   sem_t *                         semaphore;
   int                             fd;
   const unsigned char *           audio_buf;
   unsigned long                   audio_buf_size;
   int                             pipe;
   audio_out_data_callback_t       data_callback;
   int                             fifo_sound_intensity;
} xraudio_queue_msg_play_start_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   bool                            synchronous;
   audio_out_callback_t            callback;
   void *                          param;
   sem_t *                         semaphore;
} xraudio_queue_msg_play_pause_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   bool                            synchronous;
   audio_out_callback_t            callback;
   void *                          param;
   sem_t *                         semaphore;
} xraudio_queue_msg_play_resume_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   bool                            synchronous;
   audio_out_callback_t            callback;
   void *                          param;
   sem_t *                         semaphore;
} xraudio_queue_msg_play_stop_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_devices_input_t         source;
   xraudio_input_format_t          format;
   uuid_t                          uuid;
   //Optional field for DSP keyword detection
   xraudio_hal_stream_params_t     stream_params;
} xraudio_queue_msg_async_session_begin_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_devices_input_t         source;
} xraudio_queue_msg_async_session_end_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_devices_input_t         source;
} xraudio_queue_msg_async_input_error_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_thread_poll_func_t      func;
} xraudio_main_queue_msg_thread_poll_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   xraudio_power_mode_t            power_mode;
   sem_t *                         semaphore;
   xraudio_result_t *              result;
} xraudio_main_queue_msg_power_mode_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   bool                            enable;
   sem_t *                         semaphore;
   xraudio_result_t *              result;
} xraudio_main_queue_msg_privacy_mode_t;

typedef struct {
   xraudio_main_queue_msg_header_t header;
   bool *                          enabled;
   sem_t *                         semaphore;
   xraudio_result_t *              result;
} xraudio_main_queue_msg_privacy_mode_get_t;

typedef struct {
   xraudio_main_queue_msg_header_t   header;
   xraudio_internal_capture_params_t capture_params;
   sem_t *                           semaphore;
   xraudio_result_t *                result;
} xraudio_main_queue_msg_capture_params_set_t;

typedef struct {
   xraudio_main_queue_msg_header_t   header;
   xraudio_devices_input_t           source;
   xraudio_input_format_t            format;
   int                               fd;
   xraudio_input_data_read_cb_t      callback;
   void *                            user_data;
   sem_t *                           semaphore;
   xraudio_result_t *                result;
} xraudio_main_queue_msg_input_source_fd_set_t;

#ifdef __cplusplus
extern "C" {
#endif

void *xraudio_main_thread(void *param);
void *xraudio_resource_thread(void *param);

bool xraudio_thread_create(xraudio_thread_t *thread, const char *name, void *(*start_routine) (void *), void *arg);
bool xraudio_thread_join(xraudio_thread_t *thread);

const char *xraudio_main_queue_msg_type_str(xraudio_main_queue_msg_type_t type);
const char *xraudio_input_session_group_str(xraudio_input_session_group_t group);

void queue_msg_push(xr_mq_t xrmq, const char *msg, xr_mq_msg_size_t msg_len);

#ifdef XRAUDIO_RESOURCE_MGMT
const char *xraudio_rsrc_queue_msg_type_str(xraudio_rsrc_queue_msg_type_t type);

void                      xraudio_resource_list_init(xraudio_shared_mem_t *shared_mem);
xraudio_resource_entry_t *xraudio_resource_list_get_head(xraudio_shared_mem_t *shared_mem);
xraudio_resource_entry_t *xraudio_resource_list_get_next(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry);

void xraudio_resource_grant(xraudio_object_t object, xraudio_resource_id_input_t resource_id_record, xraudio_resource_id_output_t resource_id_playback, uint16_t capabilities_record, uint16_t capabilities_playback);
void xraudio_resource_fifo_name_get(char *name, uint8_t user_id);

void xraudio_shared_mem_lock(xraudio_object_t object);
void xraudio_shared_mem_unlock(xraudio_object_t object);
#endif

bool xraudio_devices_input_local_is_valid(xraudio_devices_input_t devices);
bool xraudio_devices_input_external_is_valid(xraudio_devices_input_t devices);
bool xraudio_devices_input_is_valid(xraudio_devices_input_t devices);
bool xraudio_devices_output_is_valid(xraudio_devices_output_t devices);

bool xraudio_hal_msg_async_handler(void *msg);

xraudio_result_t xraudio_capture_file_delete_all(const char *dir_path);

#ifdef __cplusplus
}
#endif

#endif
