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
#ifndef __XRSR_PRIVATE__
#define __XRSR_PRIVATE__

#include <semaphore.h>
#include <bsd/string.h>
#include <errno.h>
#include "safec_lib.h"
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRSR
#include <rdkx_logger.h>
#include <xr_timestamp.h>
#include <xr_timer.h>
#include <xraudio.h>
#include <xrsr.h>
#include <xrsr_config.h>

typedef enum {
   XRSR_QUEUE_MSG_TYPE_TERMINATE                               =  0,
   XRSR_QUEUE_MSG_TYPE_ROUTE_UPDATE                            =  1,
   XRSR_QUEUE_MSG_TYPE_KEYWORD_UPDATE                          =  2,
   XRSR_QUEUE_MSG_TYPE_HOST_NAME_UPDATE                        =  3,
   XRSR_QUEUE_MSG_TYPE_CAPTURE_CONFIG_UPDATE                   =  4,
   XRSR_QUEUE_MSG_TYPE_POWER_MODE_UPDATE                       =  5,
   XRSR_QUEUE_MSG_TYPE_PRIVACY_MODE_UPDATE                     =  6,
   XRSR_QUEUE_MSG_TYPE_PRIVACY_MODE_GET                        =  7,
   XRSR_QUEUE_MSG_TYPE_XRAUDIO_GRANTED                         =  8,
   XRSR_QUEUE_MSG_TYPE_XRAUDIO_REVOKED                         =  9,
   XRSR_QUEUE_MSG_TYPE_XRAUDIO_EVENT                           = 10,
   XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECTED                        = 11,
   XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECT_ERROR                    = 12,
   XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECT_SENSITIVITY_LIMITS_GET   = 13,
   XRSR_QUEUE_MSG_TYPE_SESSION_BEGIN                           = 14,
   XRSR_QUEUE_MSG_TYPE_SESSION_CONFIG_IN                       = 15,
   XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE                       = 16,
   XRSR_QUEUE_MSG_TYPE_SESSION_AUDIO_STREAM_START              = 17,
   XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_START                   = 18,
   XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_STOP                    = 19,
   XRSR_QUEUE_MSG_TYPE_THREAD_POLL                             = 20,
   XRSR_QUEUE_MSG_TYPE_INVALID                                 = 21,
} xrsr_queue_msg_type_t;

typedef enum {
   XRSR_XRAUDIO_STATE_CREATED   = 0,
   XRSR_XRAUDIO_STATE_REQUESTED = 1,
   XRSR_XRAUDIO_STATE_GRANTED   = 2,
   XRSR_XRAUDIO_STATE_OPENED    = 3,
} xrsr_xraudio_state_t;

typedef enum {
   XRSR_EVENT_EOS                 = 0,
   XRSR_EVENT_STREAM_TIME_MINIMUM = 1,
   XRSR_EVENT_STREAM_KWD_INFO     = 2,
   XRSR_EVENT_STREAM_ERROR        = 3,
   XRSR_EVENT_INVALID             = 4
} xrsr_event_t;

typedef enum {
   XRSR_ADDRESS_FAMILY_IPV4    = 0,
   XRSR_ADDRESS_FAMILY_IPV6    = 1,
   XRSR_ADDRESS_FAMILY_INVALID = 2
} xrsr_address_family_t;

typedef enum {
   XRSR_SESSION_GROUP_DEFAULT = 0, // Session index for regular voice sessions (PTT, FFV)
   #ifdef MICROPHONE_TAP_ENABLED
   XRSR_SESSION_GROUP_MIC_TAP = 1, // Session index for microphone tap voice sessions
   XRSR_SESSION_GROUP_QTY     = 2
   #else
   XRSR_SESSION_GROUP_QTY     = 1
   #endif
} xrsr_session_group_t;

typedef struct {
   int         msgq_id;
   sem_t *     semaphore;
   bool        is_prod;
} xrsr_thread_params_t;

typedef struct {
   char *                urle;
   xrsr_protocol_t       prot;
   char *                user;
   char *                host;
   char *                port_str;
   uint16_t              port_int;
   char *                path;
   xrsr_address_family_t family;
   bool                  has_query;
   bool                  has_param;
   bool                  has_fragment;
} xrsr_url_parts_t;

typedef struct {
   bool     *debug;
   uint32_t *connect_check_interval;
   uint32_t *timeout_connect;
   uint32_t *timeout_inactivity;
   uint32_t *timeout_session;
   bool     *ipv4_fallback;
   uint32_t *backoff_delay;
} xrsr_dst_param_ptrs_t;

typedef struct {
   xrsr_queue_msg_type_t type;
} xrsr_queue_msg_header_t;

typedef struct {
   xrsr_queue_msg_header_t header;
} xrsr_queue_msg_generic_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   sem_t *                 semaphore;
} xrsr_queue_msg_term_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   sem_t *                 semaphore;
   const char *            host_name;
   const xrsr_route_t *    routes;
} xrsr_queue_msg_route_update_t;

typedef struct {
   xrsr_queue_msg_header_t      header;
   sem_t *                      semaphore;
   const xrsr_keyword_config_t *keyword_config;
} xrsr_queue_msg_keyword_update_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   sem_t *                 semaphore;
   float *                 sensitivity_min;
   float *                 sensitivity_max;
   bool *                  result;
} xrsr_queue_msg_keyword_sensitivity_limits_get_t ;

typedef struct {
   xrsr_queue_msg_header_t      header;
   sem_t *                      semaphore;
   const char *                 host_name;
} xrsr_queue_msg_host_name_update_t;

typedef struct {
   xrsr_queue_msg_header_t      header;
   sem_t *                      semaphore;
   const xrsr_capture_config_t *capture_config;
} xrsr_queue_msg_capture_config_update_t;

typedef struct {
   xrsr_queue_msg_header_t      header;
   sem_t *                      semaphore;
   xrsr_power_mode_t            power_mode;
   bool *                       result;
} xrsr_queue_msg_power_mode_update_t;

typedef struct {
   xrsr_queue_msg_header_t      header;
   sem_t *                      semaphore;
   bool                         enable;
   bool *                       result;
} xrsr_queue_msg_privacy_mode_update_t;

typedef struct {
   xrsr_queue_msg_header_t           header;
   xraudio_devices_input_t           source;
   xraudio_input_format_t            xraudio_format;
   uuid_t                            uuid;
   bool                              has_result;
   xraudio_keyword_detector_result_t detector_result;
} xrsr_queue_msg_keyword_detected_t;

typedef struct {
   xrsr_queue_msg_header_t           header;
   xrsr_src_t                        src;
   bool                              retry;
   bool                              user_initiated;
   xrsr_session_request_t            input_format;
   xraudio_input_format_t            xraudio_format;
   bool                              low_latency;
   bool                              low_cpu_util;
   bool                              has_result;
   xraudio_keyword_detector_result_t detector_result;
   rdkx_timestamp_t                  timestamp;
   char                              transcription_in[XRSR_SESSION_BY_TEXT_MAX_LENGTH];
   char                              audio_file_in[XRSR_SESSION_AUDIO_FILE_MAX_LENGTH];
   uuid_t                            uuid;
} xrsr_queue_msg_session_begin_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   xrsr_src_t              src;
   xrsr_protocol_t         protocol;
   uuid_t                  uuid;
   const char *            sat_token;
   const char *            user_agent;
   const char *            query_strs[XRSR_QUERY_STRING_QTY_MAX];
   uint32_t                keyword_begin;
   uint32_t                keyword_duration;
   xrsr_cert_t             client_cert;
   bool                    host_verify;
   bool                    ocsp_verify_stapling;
   bool                    ocsp_verify_ca;
   void *                  app_config;
} xrsr_queue_msg_session_config_in_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   sem_t *                 semaphore;
   xrsr_src_t              src;
} xrsr_queue_msg_session_terminate_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   sem_t *                 semaphore;
   xrsr_src_t              src;
} xrsr_queue_msg_session_audio_stream_start_t;

typedef struct {
   xrsr_queue_msg_header_t      header;
   sem_t *                      semaphore;
   xrsr_audio_container_t       container;
   const char *                 file_path;
   bool                         raw_mic_enable;
} xrsr_queue_msg_session_capture_start_t;

typedef struct {
   xrsr_queue_msg_header_t      header;
   sem_t *                      semaphore;
} xrsr_queue_msg_session_capture_stop_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   sem_t *                 semaphore;
   bool *                  enabled;
   bool *                  result;
} xrsr_queue_msg_privacy_mode_get_t ;

typedef struct {
   xrsr_src_t   src;
   xrsr_event_t event;
   union {
      uint32_t  byte_qty;
   } data;
} xrsr_speech_event_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   xrsr_speech_event_t     event;
} xrsr_queue_msg_xraudio_in_event_t;

typedef struct {
   xrsr_queue_msg_header_t header;
   xrsr_thread_poll_func_t func;
} xrsr_queue_msg_thread_poll_t;

// Make sure all vrexm_queue_msg types are added to this union so
// that XRSR_MSG_QUEUE_MSG_SIZE_MAX can be set to the max message size
typedef union {
   xrsr_queue_msg_generic_t                        generic;
   xrsr_queue_msg_term_t                           term;
   xrsr_queue_msg_route_update_t                   route_update;
   xrsr_queue_msg_keyword_update_t                 keyword_update;
   xrsr_queue_msg_keyword_detected_t               keyword_detected;
   xrsr_queue_msg_keyword_sensitivity_limits_get_t keyword_sensitivity_limits_get;
   xrsr_queue_msg_session_begin_t                  session_begin;
   xrsr_queue_msg_session_config_in_t              session_config_in;
   xrsr_queue_msg_session_terminate_t              session_terminate;
   xrsr_queue_msg_xraudio_in_event_t               xraudio_in_event;
   xrsr_queue_msg_session_capture_start_t          session_capture_start;
   xrsr_queue_msg_session_capture_stop_t           session_capture_stop;
   xrsr_queue_msg_privacy_mode_get_t               privacy_mode_get;
   xrsr_queue_msg_thread_poll_t                    thread_poll;
} xrsr_queue_msg_union_t;

typedef void *xrsr_xraudio_object_t;

typedef void (*xrsr_route_handler_t)(xrsr_src_t src, bool retry, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util);
typedef void (*xrsr_timer_handler_t)(void *data);


#define XRSR_MSG_QUEUE_MSG_SIZE_MAX (sizeof(xrsr_queue_msg_union_t))

#ifdef WS_ENABLED
#include <xrsr_protocol_ws.h>
#endif

#ifdef HTTP_ENABLED
#include <xrsr_protocol_http.h>
#endif

#ifdef SDT_ENABLED
#include "xrsr_protocol_sdt.h"
#endif

#include <xrsr_utils.h>

bool xrsr_message_queue_open(int *msgq, size_t msgsize);
void xrsr_message_queue_close(int *msgq);
int  xrsr_queue_msg_push(int msgq, const char *msg, size_t msg_len);
int  xrsr_msgq_fd_get(void);
xrsr_result_t xrsr_conn_send(void *param, const uint8_t *buffer, uint32_t length);
bool xrsr_speech_stream_begin(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_session_request_t input_format, xraudio_input_format_t output_format, bool user_initiated, bool low_latency, bool low_cpu_util, bool create_stream, bool subsequent, const char *audio_file_in, int *pipe_fd_read);
bool xrsr_speech_stream_kwd(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index);
bool xrsr_speech_stream_end(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_stream_end_reason_t reason, bool detect_resume, xrsr_audio_stats_t *audio_stats);

void xrsr_session_stream_begin(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index);
void xrsr_session_end(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index, xrsr_session_stats_t *stats);

xrsr_xraudio_object_t xrsr_xraudio_create(xraudio_keyword_phrase_t keyword_phrase, xraudio_keyword_sensitivity_t keyword_sensitivity, xraudio_power_mode_t power_mode, bool privacy_mode, const json_t *json_obj_xraudio);
void xrsr_xraudio_destroy(xrsr_xraudio_object_t object);
void xrsr_xraudio_internal_capture_params_set(xrsr_xraudio_object_t object, xraudio_internal_capture_params_t *params);
void xrsr_xraudio_internal_capture_delete_files(xrsr_xraudio_object_t object, const char *dir_path);
void xrsr_xraudio_device_granted(xrsr_xraudio_object_t object);
void xrsr_xraudio_device_revoked(xrsr_xraudio_object_t object);
void xrsr_xraudio_device_request(xrsr_xraudio_object_t object);
void xrsr_xraudio_device_update(xrsr_xraudio_object_t object, xrsr_src_t srcs[]);
void xrsr_xraudio_device_close(xrsr_xraudio_object_t object);
void xrsr_xraudio_keyword_detect_params(xrsr_xraudio_object_t *obj, xraudio_keyword_phrase_t keyword_phrase, xraudio_keyword_sensitivity_t keyword_sensitivity);
void xrsr_xraudio_keyword_detect_restart(xrsr_xraudio_object_t object);
void xrsr_xraudio_keyword_detected(xrsr_xraudio_object_t object, xrsr_queue_msg_keyword_detected_t *msg, xrsr_src_t current_session_src, bool requested_more_audio, bool *audio_stream_start);
void xrsr_xraudio_keyword_detect_error(xrsr_xraudio_object_t object, xraudio_devices_input_t source);
bool xrsr_xraudio_stream_begin(xrsr_xraudio_object_t object, const char *stream_id, xraudio_devices_input_t source, bool user_initiated, xraudio_input_format_t *format_decoded, xraudio_dst_pipe_t dsts[], uint16_t stream_time_min, uint32_t keyword_begin, uint32_t keyword_duration, uint32_t frame_duration, bool low_latency, bool low_cpu_util, bool subsequent);
bool xrsr_xraudio_stream_end(xrsr_xraudio_object_t object, xraudio_devices_input_t source, uint32_t dst_index, bool more_streams, bool detect_resume, xrsr_audio_stats_t *audio_stats);
void xrsr_xraudio_stream_event_handler(xraudio_devices_input_t source, audio_in_callback_event_t event, xrsr_speech_event_t *speech_event);
bool xrsr_xraudio_session_request(xrsr_xraudio_object_t object, xrsr_src_t src, xraudio_input_format_t xraudio_format, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util);
bool xrsr_xraudio_input_source_fd_set(xrsr_xraudio_object_t object, xrsr_src_t src, int fd, xrsr_audio_format_t format, xraudio_input_data_read_cb_t callback, void *user_data);
void xrsr_xraudio_session_capture_start(xrsr_xraudio_object_t object, xrsr_audio_container_t container, const char *file_path, bool raw_mic_enable);
void xrsr_xraudio_session_capture_stop(xrsr_xraudio_object_t object);
void xrsr_xraudio_thread_poll(xrsr_xraudio_object_t object, xrsr_thread_poll_func_t func);
bool xrsr_xraudio_power_mode_update(xrsr_xraudio_object_t object, xrsr_power_mode_t power_mode);
bool xrsr_xraudio_privacy_mode_update(xrsr_xraudio_object_t object, bool enable);
bool xrsr_xraudio_privacy_mode_get(xrsr_xraudio_object_t object, bool *enabled);
bool xrsr_xraudio_keyword_detect_sensitivity_limits_get(xrsr_xraudio_object_t object, xraudio_keyword_sensitivity_t *keyword_sensitivity_min, xraudio_keyword_sensitivity_t *keyword_sensitivity_max);
xrsr_audio_format_t xrsr_xraudio_format_to_xrsr(xraudio_input_format_t format);
xraudio_input_format_t xrsr_xrsr_format_to_xraudio(xrsr_audio_format_t format);
xrsr_src_t xrsr_xraudio_src_to_xrsr(xraudio_devices_input_t src);
xraudio_devices_input_t xrsr_xrsr_src_to_xraudio(xrsr_src_t src);

void xrsr_session_begin(xrsr_src_t src, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util);
void xrsr_keyword_detect_error(xrsr_src_t src);
bool xrsr_mask_pii(void);

#endif
