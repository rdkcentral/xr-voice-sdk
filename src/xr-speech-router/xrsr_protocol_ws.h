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
#ifndef __XRSR_PROTOCOL_WS_H__
#define __XRSR_PROTOCOL_WS_H__

#include <nopoll.h>
#include "nopoll_private.h"
#include "xr_sm_engine.h"
#include <semaphore.h>

#define XRSR_WS_HOST_NAME_LEN_MAX       (64)
#define XRSR_WS_URL_SIZE_MAX            (2048)
#define XRSR_WS_SM_EVENTS_MAX           (5)
#define XRSR_WS_MSG_OUT_MAX             (5)
#define XRSR_WS_WRITE_PENDING_RETRY_MAX (5)

typedef struct {
   xrsr_protocol_t        prot;
   const char *           host_name;
   rdkx_timer_object_t    timer_obj;
   xrsr_dst_param_ptrs_t *dst_params;
} xrsr_ws_params_t;

typedef struct {
   xrsr_protocol_t               prot;  // Used for identification
   xrsr_handlers_t               handlers;
   bool                          debug_enabled;
   uuid_t                        uuid;
   xrsr_session_config_out_t     session_config_out;
   xrsr_session_config_in_t      session_config_in;
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
   char                          local_host_name[XRSR_WS_HOST_NAME_LEN_MAX];
   uint8_t                       buffer[4096];
   xrsr_session_stats_t          stats;
   xrsr_audio_stats_t            audio_stats;
   bool                          on_close;
   int                           close_status;
   bool                          requested_more_audio;

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

   bool                          is_session_by_text;
   bool                          is_session_by_file;
   char                          audio_file_in[XRSR_SESSION_AUDIO_FILE_MAX_LENGTH];

   /* WS Library Specific attributes */
   noPollCtx *                   obj_ctx;
   noPollConn *                  obj_conn;
   NOPOLL_SOCKET                 socket;
   noPollMsg *                   pending_msg;

   /* State Machine */
   tSmInstance                   state_machine;
   tStateEvent                   state_machine_events_active[XRSR_WS_SM_EVENTS_MAX];
   xrsr_stream_end_reason_t      stream_end_reason;
   xrsr_session_end_reason_t     session_end_reason;
   bool                          detect_resume;
   xrsr_session_config_update_t *session_config_update;
} xrsr_state_ws_t;

void xrsr_protocol_handler_ws(xrsr_src_t src, bool retry, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util);
bool xrsr_ws_init(xrsr_state_ws_t *ws, xrsr_ws_params_t *params);
void xrsr_ws_term(xrsr_state_ws_t *ws);
bool xrsr_ws_update_dst_params(xrsr_state_ws_t *ws, xrsr_dst_param_ptrs_t *params);
void xrsr_ws_host_name_set(xrsr_state_ws_t *ws, const char *host_name);
void xrsr_ws_fd_set(xrsr_state_ws_t *ws, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
void xrsr_ws_handle_fds(xrsr_state_ws_t *ws, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
bool xrsr_ws_connect(xrsr_state_ws_t *ws, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, xraudio_input_format_t xraudio_format, bool user_initiated, bool is_retry, bool deferred, const char **query_strs);
bool xrsr_ws_conn_is_ready(xrsr_state_ws_t *ws);
void xrsr_ws_terminate(xrsr_state_ws_t *ws);
bool xrsr_ws_audio_stream(xrsr_state_ws_t *ws, xrsr_src_t src, bool create_stream, bool subsequent);
int  xrsr_ws_send_binary(xrsr_state_ws_t *ws, const uint8_t *buffer, uint32_t length);
int  xrsr_ws_send_text(xrsr_state_ws_t *ws, const uint8_t *buffer, uint32_t length);
int  xrsr_ws_read_pending(xrsr_state_ws_t *ws);
void xrsr_ws_speech_session_end(xrsr_state_ws_t *ws, xrsr_session_end_reason_t reason);
void xrsr_ws_handle_speech_event(xrsr_state_ws_t *ws, xrsr_speech_event_t *event);

// State check functions
bool xrsr_ws_is_established(xrsr_state_ws_t *ws);
bool xrsr_ws_is_disconnected(xrsr_state_ws_t *ws);

const char *xrsr_ws_opcode_str(noPollOpCode type);
#endif
