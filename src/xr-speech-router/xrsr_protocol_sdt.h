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
#ifndef __XRSR_PROTOCOL_SDT_H__
#define __XRSR_PROTOCOL_SDT_H__

#include "xr_sm_engine.h"
#include <semaphore.h>

#define XRSR_SDT_HOST_NAME_LEN_MAX       (64)
#define XRSR_SDT_URL_SIZE_MAX            (2048)
#define XRSR_SDT_SM_EVENTS_MAX           (5)
#define XRSR_SDT_MSG_OUT_MAX             (5)
#define XRSR_SDT_WRITE_PENDING_RETRY_MAX (5)

typedef struct {
   xrsr_protocol_t     prot;
   const char *        host_name;
   rdkx_timer_object_t timer_obj;
   bool *              debug;
   uint32_t *          connect_check_interval;
   uint32_t *          timeout_connect;
   uint32_t *          timeout_inactivity;
   uint32_t *          timeout_session;
   bool *              ipv4_fallback;
   uint32_t *          backoff_delay;
} xrsr_sdt_params_t;

typedef struct {
   xrsr_protocol_t               prot;  // Used for identification
   xrsr_handlers_t               handlers;
   uuid_t                        uuid;
   xrsr_session_config_out_t     session_config_out;
   rdkx_timer_object_t           timer_obj;
   rdkx_timer_id_t               timer_id;
   uint32_t                      retry_cnt;
   rdkx_timestamp_t              retry_timestamp_end;
   int32_t                       connect_wait_time;
   bool                          stream_time_min_rxd;
   xrsr_url_parts_t *            url_parts;
   char                          url[XRSR_WS_URL_SIZE_MAX];
   const char *                  sat_token;
   xrsr_src_t                    audio_src;
   uint32_t                      dst_index;
   xrsr_session_request_t        input_format;
   xraudio_input_format_t        xraudio_format;
   bool                          user_initiated;
   bool                          low_latency;
   bool                          low_cpu_util;
   int                           audio_pipe_fd_read;
   bool                          write_pending_bytes;
   uint8_t                       write_pending_retries;
   char                          local_host_name[XRSR_SDT_HOST_NAME_LEN_MAX];
   uint8_t                       buffer[4096];
   xrsr_session_stats_t          stats;
   xrsr_audio_stats_t            audio_stats;
   bool                          on_close;

   sem_t                         msg_out_semaphore;
   uint8_t                       msg_out_count;
   char *                        msg_out[XRSR_WS_MSG_OUT_MAX];

   bool                          audio_kwd_notified;
   uint32_t                      audio_kwd_bytes;
   uint32_t                      audio_txd_bytes;

   uint32_t                      connect_check_interval;
   uint32_t                      timeout_connect;
   uint32_t                      timeout_inactivity;
   uint32_t                      timeout_session;
   bool                          ipv4_fallback;
   uint32_t                      backoff_delay;

   /* State Machine */
   tSmInstance                   state_machine;
   tStateEvent                   state_machine_events_active[XRSR_SDT_SM_EVENTS_MAX];
   xrsr_stream_end_reason_t      stream_end_reason;
   xrsr_session_end_reason_t     session_end_reason;
   bool                          detect_resume;
   xrsr_session_config_update_t *session_config_update;
} xrsr_state_sdt_t;

void xrsr_protocol_handler_sdt(xrsr_src_t src, bool retry, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util);
bool xrsr_sdt_init(xrsr_state_sdt_t *sdt, xrsr_sdt_params_t *params);
void xrsr_sdt_term(xrsr_state_sdt_t *sdt);
void xrsr_sdt_host_name_set(xrsr_state_sdt_t *sdt, const char *host_name);
void xrsr_sdt_fd_set(xrsr_state_sdt_t *sdt, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
void xrsr_sdt_handle_fds(xrsr_state_sdt_t *sdt, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
bool xrsr_sdt_connect(xrsr_state_sdt_t *sdt, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, xraudio_input_format_t xraudio_format, bool user_initiated, bool is_retry, bool deferred, const char *sat_token, const char **query_strs);
bool xrsr_sdt_conn_is_ready(xrsr_state_sdt_t *sdt);
void xrsr_sdt_terminate(xrsr_state_sdt_t *sdt);
bool xrsr_sdt_audio_stream(xrsr_state_sdt_t *sdt, xrsr_src_t src, const char *audio_file_in);
int  xrsr_sdt_send_binary(xrsr_state_sdt_t *sdt, const uint8_t *buffer, uint32_t length);
int  xrsr_sdt_send_text(xrsr_state_sdt_t *sdt, const uint8_t *buffer, uint32_t length);
int  xrsr_sdt_read_pending(xrsr_state_sdt_t *sdt);
void xrsr_sdt_speech_session_end(xrsr_state_sdt_t *sdt, xrsr_session_end_reason_t reason);
void xrsr_sdt_handle_speech_event(xrsr_state_sdt_t *sdt, xrsr_speech_event_t *event);

// State check functions
bool xrsr_sdt_is_established(xrsr_state_sdt_t *sdt);
bool xrsr_sdt_is_disconnected(xrsr_state_sdt_t *sdt);

#endif
