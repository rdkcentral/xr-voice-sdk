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
#include <mqueue.h>
#include "xrsr_private.h"
#include "xrsr_protocol_sdt_sm.h"

static void xrsr_sdt_event(xrsr_state_sdt_t *sdt, tStEventID id, bool from_state_handler);
static void xrsr_sdt_reset(xrsr_state_sdt_t *sdt);
static void xrsr_sdt_sm_init(xrsr_state_sdt_t *sdt);
static void xrsr_sdt_process_timeout(void *data);
static void xrsr_sdt_speech_stream_end(xrsr_state_sdt_t *sdt, xrsr_stream_end_reason_t reason, bool detect_resume);
static bool xrsr_sdt_connect_new(xrsr_state_sdt_t *sdt);
static bool xrsr_sdt_queue_msg_out(xrsr_state_sdt_t *sdt, const char *msg, uint32_t length);
static void xrsr_sdt_clear_msg_out(xrsr_state_sdt_t *sdt);

// This function kicks off the session
void xrsr_protocol_handler_sdt(xrsr_src_t src, bool retry, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util) {
   xrsr_queue_msg_session_begin_t msg;
   msg.header.type     = XRSR_QUEUE_MSG_TYPE_SESSION_BEGIN;
   msg.src             = src;
   msg.retry           = retry;
   msg.user_initiated  = user_initiated;
   msg.input_format    = input_format;
   msg.xraudio_format  = xraudio_format;
   msg.low_latency     = low_latency;
   msg.low_cpu_util    = low_cpu_util;
   if(detector_result == NULL) {
      msg.has_result = false;
      memset(&msg.detector_result, 0, sizeof(msg.detector_result));
   } else {
      msg.has_result      = true;
      msg.detector_result = *detector_result;
   }
   rdkx_timestamp_get_realtime(&msg.timestamp);

   if(input_format.type == XRSR_SESSION_REQUEST_TYPE_TEXT && input_format.value.text.text != NULL) {
      strncpy(msg.transcription_in, input_format.value.text.text, sizeof(msg.transcription_in)-1);
      msg.transcription_in[sizeof(msg.transcription_in)-1] = '\0';
   } else {
      msg.transcription_in[0] = '\0';
   }

   if(input_format.type == XRSR_SESSION_REQUEST_TYPE_AUDIO_FILE && input_format.value.audio_file.path != NULL) {
      strncpy(msg.audio_file_in, input_format.value.audio_file.path, sizeof(msg.audio_file_in)-1);
      msg.audio_file_in[sizeof(msg.audio_file_in)-1] = '\0';
   } else {
      msg.audio_file_in[0] = '\0';
   }

   if(uuid != NULL) {
      uuid_copy(msg.uuid, *uuid);
   } else {
      uuid_clear(msg.uuid);
   }

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
}

bool xrsr_sdt_init(xrsr_state_sdt_t *sdt, xrsr_sdt_params_t *params) {
   if(sdt == NULL || params == NULL) {
      XLOGD_ERROR("invalid params - ws <%p> params <%p>", sdt, params);
      return(false);
   }
   
   memset(sdt, 0, sizeof(*sdt));
   
   sem_init(&sdt->msg_out_semaphore, 0, 1);
   sdt->msg_out_count = 0;
   memset(sdt->msg_out, 0, sizeof(sdt->msg_out));
 

   sdt->timer_obj          = params->timer_obj;
   sdt->prot               = params->prot;
   sdt->audio_pipe_fd_read = -1;
   sdt->prot               = params->prot;
   sdt->on_close           = false;
   sdt->detect_resume         = true;
   sdt->write_pending_bytes   = false;
   sdt->connect_check_interval = 20;
   sdt->timeout_connect = 2000;
   sdt->timeout_inactivity = 2000;
   sdt->backoff_delay = 10;
   xrsr_sdt_clear_msg_out(sdt);

   xrsr_sdt_sm_init(sdt);

   return(true);
}

void xrsr_sdt_term(xrsr_state_sdt_t *sdt) {
   XLOGD_INFO("");
   if(sdt == NULL ) {
      XLOGD_ERROR("NULL context");
      return;
   }
}

void xrsr_sdt_fd_set(xrsr_state_sdt_t *sdt, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
   if(xrsr_sdt_is_established(sdt)) {
      // We don't want to wake up for the audio pipe if we can't write it to the pipe
      if(sdt->audio_pipe_fd_read >= 0 && !sdt->write_pending_bytes) {
         FD_SET(sdt->audio_pipe_fd_read, readfds);
         if(sdt->audio_pipe_fd_read >= *nfds) {
            *nfds = sdt->audio_pipe_fd_read + 1;
         }
      }
   }
}

void xrsr_sdt_handle_fds(xrsr_state_sdt_t *sdt, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {

   // Finally let's check if we have audio data available to send
   if(sdt->audio_pipe_fd_read >= 0 && FD_ISSET(sdt->audio_pipe_fd_read, readfds)) {
      // Read the audio data and write to websocket
      int rc = read(sdt->audio_pipe_fd_read, sdt->buffer, sizeof(sdt->buffer));
      if(rc < 0) {
         int errsv = errno;
         if(errsv == EAGAIN || errsv == EWOULDBLOCK) {
            XLOGD_INFO("read would block");
            xrsr_sdt_event(sdt, SM_EVENT_AUDIO_ERROR, false);
         } else {
            XLOGD_ERROR("pipe read error <%s>", strerror(errsv));
            xrsr_sdt_event(sdt, SM_EVENT_AUDIO_ERROR, false);
         }
      } else if(rc == 0) { // EOF
         XLOGD_INFO("pipe read EOF");
         xrsr_sdt_event(sdt, SM_EVENT_EOS_PIPE, false);
      } else {
         XLOGD_INFO("pipe read <%d>", rc);
         uint32_t bytes_read = (uint32_t)rc;
	 XLOGD_INFO("pipe bytes read <%d>", bytes_read);

         if(sdt->handlers.stream_audio == NULL) {
            XLOGD_INFO("stream data handler not available");
         } else {
            (*sdt->handlers.stream_audio)(sdt->buffer,bytes_read);
         }

         if(!sdt->audio_kwd_notified && (sdt->audio_txd_bytes >= sdt->audio_kwd_bytes)) {
            if(!xrsr_speech_stream_kwd(sdt->uuid,  sdt->audio_src, sdt->dst_index)) {
               XLOGD_ERROR("xrsr_speech_stream_kwd failed");
            }
            sdt->audio_kwd_notified = true;
         }
      }
   }
}

void xrsr_sdt_process_timeout(void *data) {
   XLOGD_INFO("");
   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)data;
   xrsr_sdt_event(sdt, SM_EVENT_TIMEOUT, false);
}

bool xrsr_sdt_connect(xrsr_state_sdt_t *sdt, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, xraudio_input_format_t xraudio_format, bool user_initiated, bool is_retry, bool deferred, const char *sat_token, const char **query_strs) {
   XLOGD_INFO("");
   if(sdt == NULL) {
      XLOGD_ERROR("NULL xrsr_state_sdt_t");
      return(false);
   } 

   rdkx_timestamp_get(&sdt->retry_timestamp_end);
   rdkx_timestamp_add_ms(&sdt->retry_timestamp_end, sdt->timeout_session);

   sdt->audio_src      = audio_src;
   sdt->xraudio_format = xraudio_format;

   strlcpy(sdt->url, url_parts->urle, sizeof(sdt->url)); // Copy main url

   XLOGD_INFO("local host <%s> remote host <%s> port <%s> url <%s> deferred <%s> sat <%s> family <%s> retry period <%u> ms", sdt->local_host_name, url_parts->host, url_parts->port_str, xrsr_mask_pii() ? "***" : sdt->url, (deferred) ? "YES" : "NO", (sat_token == NULL) ? "NO" : "YES", xrsr_address_family_str(url_parts->family), sdt->timeout_session);


   sdt->url_parts          = url_parts;
   sdt->user_initiated     = user_initiated;
   sdt->audio_kwd_notified = true; // if keyword is present in the stream, xraudio will inform
   sdt->audio_kwd_bytes    = 0;
   sdt->audio_txd_bytes    = 0;
   sdt->connect_wait_time  = sdt->timeout_connect;
   sdt->on_close           = false;
   memset(&sdt->stats, 0, sizeof(sdt->stats));
   memset(&sdt->audio_stats, 0, sizeof(sdt->audio_stats));

   if(!deferred) {
      xrsr_sdt_event(sdt, SM_EVENT_SESSION_BEGIN, false);
      return(true);
   }
   xrsr_sdt_event(sdt, SM_EVENT_SESSION_BEGIN_STM, false);
   return(true);
}

bool xrsr_sdt_connect_new(xrsr_state_sdt_t *sdt) {
   xrsr_url_parts_t *url_parts = sdt->url_parts;

   const char *origin_fmt = "http://%s:%s";
   uint32_t origin_size = strlen(url_parts->host) + strlen(url_parts->port_str) + strlen(origin_fmt) - 3;
   char origin[origin_size];

   snprintf(origin, sizeof(origin), origin_fmt, url_parts->host, url_parts->port_str);

   XLOGD_INFO("attempt <%u>",sdt->retry_cnt);

  return(true);
}


bool xrsr_sdt_conn_is_ready(xrsr_state_sdt_t *sdt) {
   if(sdt == NULL) {
      XLOGD_ERROR("NULL xrsr_state_sdt_t");
      return(false);
   }
   
   return(true);
}

void xrsr_sdt_terminate(xrsr_state_sdt_t *sdt) {
   XLOGD_INFO("");

   if(sdt == NULL) {
      XLOGD_ERROR("NULL xrsr_state_sdt_t");
      return;
   } 

   xrsr_sdt_event(sdt, SM_EVENT_TERMINATE, false);
}

// TODO, work on this function
bool xrsr_sdt_audio_stream(xrsr_state_sdt_t *sdt, xrsr_src_t src, const char *audio_file_in) {
   if(sdt == NULL) {
      XLOGD_ERROR("NULL xrsr_state_sdt_t");
      return(false);
   }

   sdt->audio_src = src;

   // Continue streaming audio to the websocket
   int pipe_fd_read   = -1;
   bool create_stream = false;
   bool subsequent    = false;

   if(!xrsr_speech_stream_begin(sdt->uuid, sdt->audio_src, sdt->dst_index, sdt->input_format, sdt->xraudio_format, sdt->user_initiated, sdt->low_latency, sdt->low_cpu_util, create_stream, subsequent, audio_file_in, &pipe_fd_read)) {
      XLOGD_ERROR("xrsr_speech_stream_begin failed");
      // perform clean up of the session
      xrsr_sdt_speech_session_end(sdt, XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN);
      return(false);
   }

   sdt->audio_pipe_fd_read = pipe_fd_read;

   char uuid_str[37] = {'\0'};
   uuid_unparse_lower(sdt->uuid, uuid_str);
   xrsr_session_stream_begin(sdt->uuid, uuid_str,sdt->audio_src, sdt->dst_index);

   return(true);
}

int xrsr_sdt_read_pending(xrsr_state_sdt_t *sdt) {
   if(sdt == NULL) {
      XLOGD_ERROR("NULL xrsr_state_sdt_t");
      return(-1);
   }

   return(0);
}

int xrsr_sdt_send_binary(xrsr_state_sdt_t *sdt, const uint8_t *buffer, uint32_t length) {
   if(sdt == NULL) {
      XLOGD_ERROR("NULL xrsr_state_sdt_t");
      return(-1);
   } else if(!xrsr_sdt_is_established(sdt)) {
      XLOGD_ERROR("invalid state");
      return(-1);
   }
   XLOGD_INFO("length <%u>", length);
   return length;
}

int xrsr_sdt_send_text(xrsr_state_sdt_t *sdt, const uint8_t *buffer, uint32_t length) {
   if(sdt == NULL) {
      XLOGD_ERROR("NULL xrsr_state_sdt_t");
      return(-1);
   } else if(!xrsr_sdt_is_established(sdt)) {
      XLOGD_ERROR("invalid state");
      return(-1);
   }
   XLOGD_DEBUG("length <%u>", length);
   errno = 0;
   bool ret = xrsr_sdt_queue_msg_out(sdt, (const char *)buffer, length);
   return (ret ? 1 : 0);
}

void xrsr_sdt_speech_stream_end(xrsr_state_sdt_t *sdt, xrsr_stream_end_reason_t reason, bool detect_resume) {
   XLOGD_INFO("fd <%d> reason <%s>", sdt->audio_pipe_fd_read, xrsr_stream_end_reason_str(reason));

   xrsr_speech_stream_end(sdt->uuid, sdt->audio_src, sdt->dst_index, reason, detect_resume, &sdt->audio_stats);

   if(sdt->audio_pipe_fd_read >= 0) {
      close(sdt->audio_pipe_fd_read);
      sdt->audio_pipe_fd_read = -1;
   }
}

void xrsr_sdt_speech_session_end(xrsr_state_sdt_t *sdt, xrsr_session_end_reason_t reason) {
   XLOGD_INFO("fd <%d> reason <%s>", sdt->audio_pipe_fd_read, xrsr_session_end_reason_str(reason));

   sdt->stats.reason = reason;

   char uuid_str[37] = {'\0'};
   uuid_unparse_lower(sdt->uuid, uuid_str);
   xrsr_session_end(sdt->uuid, uuid_str, sdt->audio_src, sdt->dst_index, &sdt->stats);
}

void xrsr_sdt_handle_speech_event(xrsr_state_sdt_t *sdt, xrsr_speech_event_t *event) {
   if(NULL == event) {
      XLOGD_ERROR("speech event is NULL");
      return;
   }

   switch(event->event) {
      case XRSR_EVENT_EOS: {
         xrsr_sdt_event(sdt, SM_EVENT_EOS, false);
         break;
      }
      case XRSR_EVENT_STREAM_KWD_INFO: {
         sdt->audio_kwd_notified = false;
         sdt->audio_kwd_bytes    = event->data.byte_qty;
         break;
      }
      case XRSR_EVENT_STREAM_TIME_MINIMUM: {
         sdt->stream_time_min_rxd = true;
         xrsr_sdt_event(sdt, SM_EVENT_STM, false);
         break;
      }
      default: {
         XLOGD_WARN("unhandled speech event <%s>", xrsr_event_str(event->event));
         break;
      }
   }
}

bool xrsr_sdt_queue_msg_out(xrsr_state_sdt_t *sdt, const char *msg, uint32_t length) {
   bool ret = false;
   sem_wait(&sdt->msg_out_semaphore);
   if(sdt->msg_out_count < XRSR_SDT_MSG_OUT_MAX) {
      uint32_t buf_len = length + 1;
      sdt->msg_out[sdt->msg_out_count] = (char *)malloc(sizeof(char) * buf_len);
      if(sdt->msg_out[sdt->msg_out_count] == NULL) {
         XLOGD_ERROR("failed to allocate msg_out buffer");
      } else {
         snprintf(sdt->msg_out[sdt->msg_out_count], buf_len, "%s", msg);
         sdt->msg_out_count++;
         ret = true;
      }
   }
   sem_post(&sdt->msg_out_semaphore);
   return(ret);
}

void xrsr_sdt_clear_msg_out(xrsr_state_sdt_t *sdt) {
   uint8_t i = 0;
   sem_wait(&sdt->msg_out_semaphore);
   for(i = 0; i < XRSR_SDT_MSG_OUT_MAX; i++) {
      if(sdt->msg_out[i] != NULL) {
         free(sdt->msg_out[i]);
         sdt->msg_out[i] = NULL;
      }
   }
   sdt->msg_out_count = 0;
   sem_post(&sdt->msg_out_semaphore);
}

void xrsr_sdt_reset(xrsr_state_sdt_t *sdt) {
   if(sdt) {
      sdt->timer_id              = RDXK_TIMER_ID_INVALID;
      sdt->audio_src             = XRSR_SRC_INVALID;
      sdt->write_pending_bytes   = false;
      sdt->write_pending_retries = 0;
      sdt->detect_resume         = true;
      sdt->on_close              = false;
      sdt->retry_cnt             = 1;
      if(sdt->audio_pipe_fd_read > -1) {
         close(sdt->audio_pipe_fd_read);
         sdt->audio_pipe_fd_read = -1;
      }
      xrsr_sdt_clear_msg_out(sdt);
   }
}

void xrsr_sdt_sm_init(xrsr_state_sdt_t *sdt) {
   if(sdt) {
      sdt->state_machine.mInstanceName = "sdtSM";
      sdt->state_machine.bInitFinished = false;

      sdt->state_machine.bInitFinished = FALSE; 
      sdt->state_machine.activeEvtQueue.mpQData = sdt->state_machine_events_active; 
      sdt->state_machine.activeEvtQueue.mQSize = XRSR_SDT_SM_EVENTS_MAX; 
      sdt->state_machine.deferredEvtQueue.mpQData = NULL; 
      sdt->state_machine.deferredEvtQueue.mQSize = 0;
    
      SmInit( &sdt->state_machine, &St_Sdt_Disconnected_Info );
   }
}

void xrsr_sdt_event(xrsr_state_sdt_t *sdt, tStEventID id, bool from_state_handler) {
   if(sdt) {
      SmEnqueueEvent(&sdt->state_machine, id, (void *)sdt);
      if(!from_state_handler) {
         SmProcessEvents(&sdt->state_machine);
      }
   }
}

void St_Sdt_Disconnected(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {

   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         rdkx_timestamp_t timestamp;
         rdkx_timestamp_get_realtime(&timestamp);
         if(sdt->handlers.disconnected == NULL) {
            XLOGD_INFO("disconnected handler not available");
         } else {
            (*sdt->handlers.disconnected)(sdt->handlers.data, sdt->uuid, sdt->session_end_reason, false, &sdt->detect_resume, &timestamp);
         }
         xrsr_sdt_speech_session_end(sdt, sdt->session_end_reason);
         xrsr_sdt_reset(sdt);
	 xrsr_sdt_terminate(sdt);
         break;
      }
      default: {
         break;
      }
   }
}

void St_Sdt_Disconnecting(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {

   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         xrsr_sdt_event(sdt, SM_EVENT_DISCONNECTED, true);
         break;
      }
      default: {
         break;
      }
   }
}

void St_Sdt_Buffering(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_EOS: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_AUDIO_EOF;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            case SM_EVENT_TERMINATE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            default: {
               break;
            }
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Sdt_Connecting(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {

   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         if(!xrsr_sdt_connect_new(sdt)) {
            rdkx_timestamp_t timestamp;
            rdkx_timestamp_get(&timestamp);
            xrsr_sdt_event(sdt, SM_EVENT_CONNECTED, true);

         } else {
            rdkx_timestamp_t timeout;
            rdkx_timestamp_get(&timeout);
            rdkx_timestamp_add_ms(&timeout, sdt->connect_check_interval);
            xrsr_sdt_event(sdt, SM_EVENT_CONNECTED, true);

         }
         break;
     }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_XRSR_ERROR: {
               //TODO
               break;
            }
            case SM_EVENT_CONNECT_TIMEOUT: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            case SM_EVENT_TERMINATE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            default: {
               break;
            }
         }
         if(sdt->timer_obj != NULL && sdt->timer_id >= 0) {
            if(!rdkx_timer_remove(sdt->timer_obj, sdt->timer_id)) {
               XLOGD_ERROR("timer remove");
            }
            sdt->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Sdt_Connected(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {

   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         rdkx_timestamp_t timeout;
         rdkx_timestamp_get(&timeout);
         rdkx_timestamp_add_ms(&timeout, sdt->connect_check_interval);

         xrsr_sdt_event(sdt, SM_EVENT_ESTABLISHED, true);

         break;
      }
      case ACT_INTERNAL: {
         switch(pEvent->mID) {
            case SM_EVENT_TIMEOUT: {
               if(!xrsr_sdt_conn_is_ready(sdt)) {
                  XLOGD_WARN("websocket is not ready");
                  if(sdt->connect_wait_time <= 0) {
                     XLOGD_ERROR("server hang on HTTP upgrade request");
                     xrsr_sdt_event(sdt, SM_EVENT_ESTABLISH_TIMEOUT, true);
                  } else {
                     rdkx_timestamp_t timeout;
                     rdkx_timestamp_get(&timeout);
                     rdkx_timestamp_add_ms(&timeout, sdt->connect_check_interval);
                     sdt->connect_wait_time -= sdt->connect_check_interval;

                     if(sdt->timer_obj && sdt->timer_id >= 0) {
                        if(!rdkx_timer_update(sdt->timer_obj, sdt->timer_id, timeout)) {
                           XLOGD_ERROR("timer update");
                        }
                     }
                  }
               } else {
                  xrsr_sdt_event(sdt, SM_EVENT_ESTABLISHED, true);
               }
               break;
            }
            default: {
               break;
            }
         }
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_WS_CLOSE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            case SM_EVENT_ESTABLISH_TIMEOUT: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            case SM_EVENT_TERMINATE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            default: {
               break;
            }
         }
         if(sdt->timer_obj != NULL && sdt->timer_id >= 0) {
            if(!rdkx_timer_remove(sdt->timer_obj, sdt->timer_id)) {
               XLOGD_ERROR("timer remove");
            }
            sdt->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Sdt_Established(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_INTERNAL: {
         switch(pEvent->mID) {
            case SM_EVENT_MSG_RECV: {
               rdkx_timestamp_t timeout;
               rdkx_timestamp_get(&timeout);
               rdkx_timestamp_add_ms(&timeout, sdt->timeout_inactivity);
               if(sdt->timer_obj && sdt->timer_id >= 0) {
                  if(!rdkx_timer_update(sdt->timer_obj, sdt->timer_id, timeout)) {
                     XLOGD_ERROR("timer update");
                  }
               }
               break;
            }
            default: {
               break;
            }
         }
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_APP_CLOSE: {
               sdt->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_TERMINATE: {
               sdt->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               break;
            }
            case SM_EVENT_TIMEOUT: {
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT;
               break;
            }
            case SM_EVENT_WS_CLOSE: {
               sdt->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            default: {
               break;
            }
         }
         if(sdt->timer_obj != NULL && sdt->timer_id >= 0) {
            if(!rdkx_timer_remove(sdt->timer_obj, sdt->timer_id)) {
               XLOGD_ERROR("timer remove");
            }
            sdt->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Sdt_Streaming(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         // Call connected handler
         if(sdt->handlers.connected == NULL) {
            XLOGD_INFO("connected handler not available");
         } else {
            rdkx_timestamp_t timestamp;
            rdkx_timestamp_get_realtime(&timestamp);
            (*sdt->handlers.connected)(sdt->handlers.data, sdt->uuid, xrsr_conn_send, (void *)sdt, &timestamp, sdt->session_config_update);
         }

         char uuid_str[37] = {'\0'};
         uuid_unparse_lower(sdt->uuid, uuid_str);
         xrsr_session_stream_begin(sdt->uuid, uuid_str, sdt->audio_src, sdt->dst_index);
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_EOS_PIPE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_AUDIO_EOF;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_TERMINATE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_LOCAL;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               break;
            }
            case SM_EVENT_ESTABLISH_TIMEOUT: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT;
               break;
            }
            case SM_EVENT_AUDIO_ERROR: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_ERROR_AUDIO_READ;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_WS_ERROR: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_WS_SEND;
               break;
            }
            case SM_EVENT_WS_CLOSE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_ERROR_WS_SEND;
               break;
            }
            default: {
               break;
            }
         }
         xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
         break;
      }
      default: {
         break;
      }
   }
}

void St_Sdt_Connection_Retry(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         sdt->retry_cnt++;
         // Calculate retry delay
         uint32_t slots = 1 << sdt->retry_cnt;
         uint32_t retry_delay_ms = sdt->backoff_delay * (rand() % slots);

         XLOGD_INFO("retry connection - delay <%u> ms", retry_delay_ms);

         rdkx_timestamp_t timeout;
         rdkx_timestamp_get(&timeout);
         rdkx_timestamp_add_ms(&timeout, retry_delay_ms);

         if(rdkx_timestamp_cmp(timeout, sdt->retry_timestamp_end) > 0) {
            timeout = sdt->retry_timestamp_end;
         }

         sdt->timer_id = rdkx_timer_insert(sdt->timer_obj, timeout, xrsr_sdt_process_timeout, sdt);
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_TERMINATE: {
               sdt->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_LOCAL;
               sdt->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_sdt_speech_stream_end(sdt, sdt->stream_end_reason, sdt->detect_resume);
               break;
            }
            default: {
               break;
            }
         }
         if(sdt->timer_obj != NULL && sdt->timer_id >= 0) {
            if(!rdkx_timer_remove(sdt->timer_obj, sdt->timer_id)) {
               XLOGD_ERROR("timer remove");
            }
            sdt->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

bool xrsr_sdt_is_established(xrsr_state_sdt_t *sdt) {
   bool ret = false;
   if(sdt) {
      if(SmInThisState(&sdt->state_machine, &St_Sdt_Established_Info) ||
         SmInThisState(&sdt->state_machine, &St_Sdt_Streaming_Info)) {
         ret = true;
      }
   }
   return(ret);
}

bool xrsr_sdt_is_disconnected(xrsr_state_sdt_t *sdt) {
   bool ret = false;
   if(sdt) {
      if(SmInThisState(&sdt->state_machine, &St_Sdt_Disconnected_Info)) {
         ret = true;
      }
   }
   return(ret);
}
