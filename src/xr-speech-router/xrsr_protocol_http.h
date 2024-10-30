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
#ifndef __XRSR_PROTOCOL_HTTP_H__
#define __XRSR_PROTOCOL_HTTP_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/select.h>
#include <xrsr_protocol_http_log_filter.h>

#define XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX (102400)
#define XRSR_PROTOCOL_HTTP_URL_SIZE_MAX    (2048)
#define XRSR_HTTP_SM_EVENTS_MAX            (5)

typedef struct {
   xrsr_protocol_t               prot;  // Used for identification
   xrsr_handlers_t               handlers;
   rdkx_timer_object_t           timer_obj;
   int                           audio_pipe_fd_read;
   xrsr_src_t                    audio_src;
   uint32_t                      dst_index;
   xrsr_session_request_t        input_format;
   xraudio_input_format_t        xraudio_format;
   bool                          low_latency;
   bool                          low_cpu_util;
   uuid_t                        uuid;
   xrsr_session_config_out_t     session_config_out;
   xrsr_session_config_in_t      session_config_in;
   const char *                  sat_token;
   const char *                  user_agent;
   char                          transcription_in[XRSR_SESSION_BY_TEXT_MAX_LENGTH];
   char                         *transcription_ptr;
   char                          audio_file_in[XRSR_SESSION_AUDIO_FILE_MAX_LENGTH];

   /* HTTP Library Specific attributes */
   CURL                         *easy_handle;
   struct curl_slist            *chunk;
   bool                          debug;
   bool                          log_filter_enabled;
   char                          write_buffer[XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX];
   uint32_t                      write_buffer_index;
   rdkx_timer_id_t               timer_id_rsp;
   xrsr_audio_stats_t            audio_stats;
   xrsr_session_stats_t          session_stats;

   bool                          is_session_by_text;
   bool                          is_session_by_file;

   /* State Machine */
   tSmInstance                   state_machine;
   tStateEvent                   state_machine_events_active[XRSR_WS_SM_EVENTS_MAX];
   bool                          detect_resume;
   xrsr_session_config_update_t *session_config_update;
} xrsr_state_http_t;

void xrsr_protocol_handler_http(xrsr_src_t src, bool retry, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util);
bool xrsr_http_init(xrsr_state_http_t *http, bool debug);
void xrsr_http_term(xrsr_state_http_t *http, bool closing);
void xrsr_http_terminate(xrsr_state_http_t *http);
void xrsr_http_fd_set(xrsr_state_http_t *http, int size, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
void xrsr_http_handle_fds(xrsr_state_http_t *http, int size, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
void xrsr_http_handle_speech_event(xrsr_state_http_t *http, xrsr_speech_event_t *event);
bool xrsr_http_connect(xrsr_state_http_t *http, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, xraudio_input_format_t xraudio_format, rdkx_timer_object_t object, bool delay, const char **query_strs, const char* transcription_in);
bool xrsr_http_conn_is_ready();
int  xrsr_http_send(xrsr_state_http_t *http, const uint8_t *buffer, uint32_t length);
int  xrsr_http_recv(xrsr_state_http_t *http, uint8_t *buffer, uint32_t length);
int  xrsr_http_recv_pending(xrsr_state_http_t *http);

// State check functions
bool xrsr_http_is_connected(xrsr_state_http_t *http);
bool xrsr_http_is_disconnected(xrsr_state_http_t *http);

#endif
