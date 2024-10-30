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
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/ocsp.h>
#include "xrsr_private.h"
#include "xrsr_protocol_ws_sm.h"

#define XRSR_WS_CIPHER_LIST "AES256-SHA256:AES128-GCM-SHA256:AES128-SHA256"

#define XRSR_HOSTNAME_VERIFY_POST_CHECK

#ifdef WS_NOPOLL_PATCHES
#define NOPOLL_CONN_SSL_HOST_VERIFY nopoll_conn_opts_ssl_host_verify
#define NOPOLL_CONN_TLS_NEW         nopoll_conn_tls_new_auto
#define NOPOLL_CONN_NEW             nopoll_conn_new_opts_auto
#else
#define NOPOLL_CONN_SSL_HOST_VERIFY nopoll_conn_opts_ssl_peer_verify
#define NOPOLL_CONN_TLS_NEW         nopoll_conn_tls_new6
#define NOPOLL_CONN_NEW             nopoll_conn_new_opts
#endif

static void xrsr_ws_event(xrsr_state_ws_t *ws, tStEventID id, bool from_state_handler);
static void xrsr_ws_reset(xrsr_state_ws_t *ws);
static void xrsr_ws_sm_init(xrsr_state_ws_t *ws);

static void xrsr_ws_on_msg(xrsr_state_ws_t *ws, noPollConn *conn, noPollMsg *msg);
static void xrsr_ws_on_close(noPollCtx *ctx,  noPollConn *conn, noPollPtr user_data);
static void xrsr_ws_nopoll_log(noPollCtx * ctx, noPollDebugLevel level, const char * log_msg, noPollPtr user_data);
static void xrsr_ws_process_timeout(void *data);
static void xrsr_ws_speech_stream_end(xrsr_state_ws_t *ws, xrsr_stream_end_reason_t reason, bool detect_resume);
static bool xrsr_ws_connect_new(xrsr_state_ws_t *ws);
static noPollConnOpts *xrsr_conn_opts_get(xrsr_state_ws_t *ws, const char *sat_token);

static bool xrsr_ws_queue_msg_out(xrsr_state_ws_t *ws, const char *msg, uint32_t length);
static bool xrsr_ws_is_msg_out(xrsr_state_ws_t *ws);
static bool xrsr_ws_get_msg_out(xrsr_state_ws_t *ws, char **msg, uint32_t *length);
static void xrsr_ws_clear_msg_out(xrsr_state_ws_t *ws);

static noPollPtr   xrsr_ws_ssl_ctx_creator(noPollCtx * ctx, noPollConn * conn, noPollConnOpts * opts, nopoll_bool is_client, noPollPtr user_data);
static nopoll_bool xrsr_ws_ssl_post_check_cb(noPollCtx *ctx, noPollConn *conn, noPollPtr SSL_CTX, noPollPtr SSL, noPollPtr user_data);
static int         xrsr_ws_ssl_ctx_certificate_cb(int preverify_ok, X509_STORE_CTX *ctx);
static bool        xrsr_ws_ssl_cert_set(SSL_CTX *ssl_ctx, X509 *x509_cert, EVP_PKEY *pkey, STACK_OF(X509) *additional_certs);
static bool        xrsr_ws_ocsp_verify(SSL *ssl, bool allow_expired, bool allow_revoked, bool query_ca_server);
static bool        xrsr_ws_ocsp_server_query(SSL *ssl, OCSP_RESPONSE **ocsp_response);
static bool        xrsr_ws_ocsp_request_prepare(SSL *ssl, OCSP_REQUEST **ocsp_request, char **ocsp_url);
static bool        xrsr_ws_ocsp_response_check(SSL *ssl, OCSP_RESPONSE *ocsp_response, bool allow_expired, bool allow_revoked);

// TODO.
// This a terrible idea, but we're painted in a corner here.  If we want this bulletproof, we will have to protect with a global semaphore and only allow one connection thru this check at a time.
static int g_xrsr_ws_ex_data_index;

// This function kicks off the session
void xrsr_protocol_handler_ws(xrsr_src_t src, bool retry, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util) {
   xrsr_queue_msg_session_begin_t msg;
   msg.header.type     = XRSR_QUEUE_MSG_TYPE_SESSION_BEGIN;
   msg.src             = src;
   msg.retry           = retry;
   msg.user_initiated  = user_initiated;
   msg.xraudio_format  = xraudio_format;
   msg.input_format    = input_format;
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

bool xrsr_ws_init(xrsr_state_ws_t *ws, xrsr_ws_params_t *params) {
   if(ws == NULL || params == NULL) {
      XLOGD_ERROR("invalid params - ws <%p> params <%p>", ws, params);
      return(false);
   }
   
   memset(ws, 0, sizeof(*ws));
   ws->obj_ctx = nopoll_ctx_new();
   
   if(ws->obj_ctx == NULL) {
      XLOGD_ERROR("unable to create context");
      return(false);
   }
   ws->pending_msg   = NULL;

   sem_init(&ws->msg_out_semaphore, 0, 1);
   ws->msg_out_count = 0;
   memset(ws->msg_out, 0, sizeof(ws->msg_out));

   xrsr_ws_update_dst_params(ws, params->dst_params);
   ws->timer_obj          = params->timer_obj;
   ws->prot               = params->prot;
   ws->audio_pipe_fd_read = -1;
   xrsr_ws_reset(ws);

   if(params->host_name != NULL) {
      xrsr_ws_host_name_set(ws, params->host_name);
      XLOGD_INFO("host name <%s>", params->host_name);
   }

   xrsr_ws_sm_init(ws);

   return(true);
}

bool xrsr_ws_update_dst_params(xrsr_state_ws_t *ws, xrsr_dst_param_ptrs_t *params) {
   bool ret = false;
   if(ws) {
      if(params->debug != NULL) { // debug parameter was specified
         if(*params->debug) {
            nopoll_log_enable(ws->obj_ctx, nopoll_true);
            nopoll_log_set_handler(ws->obj_ctx, xrsr_ws_nopoll_log, NULL);
            ws->debug_enabled = true;
         } else {
            nopoll_log_set_handler(ws->obj_ctx, NULL, NULL); // Remove log handler
            nopoll_log_enable(ws->obj_ctx, nopoll_false); // disable logging
            ws->debug_enabled = false;
         }
      } else if(JSON_BOOL_VALUE_WS_DEBUG) { // debug enabled by default
         nopoll_log_enable(ws->obj_ctx, nopoll_true);
         nopoll_log_set_handler(ws->obj_ctx, xrsr_ws_nopoll_log, NULL);
         ws->debug_enabled = true;
      } else {
         nopoll_log_set_handler(ws->obj_ctx, NULL, NULL); // Remove log handler
         nopoll_log_enable(ws->obj_ctx, nopoll_false); // disable logging
         ws->debug_enabled = false;
      }

      if(params->connect_check_interval != NULL) {
         ws->connect_check_interval = *params->connect_check_interval;
      } else {
         ws->connect_check_interval = JSON_INT_VALUE_WS_FPM_CONNECT_CHECK_INTERVAL;
      }
      if(params->timeout_connect != NULL) {
         ws->timeout_connect = *params->timeout_connect;
      } else {
         ws->timeout_connect = JSON_INT_VALUE_WS_FPM_TIMEOUT_CONNECT;
      }
      if(params->timeout_inactivity != NULL) {
         ws->timeout_inactivity = *params->timeout_inactivity;
      } else {
         ws->timeout_inactivity = JSON_INT_VALUE_WS_FPM_TIMEOUT_INACTIVITY;
      }
      if(params->timeout_session != NULL) {
         ws->timeout_session = *params->timeout_session;
      } else {
         ws->timeout_session = JSON_INT_VALUE_WS_FPM_TIMEOUT_SESSION;
      }
      if(params->ipv4_fallback != NULL) {
         ws->ipv4_fallback = *params->ipv4_fallback;
      } else {
         ws->ipv4_fallback = JSON_BOOL_VALUE_WS_FPM_IPV4_FALLBACK;
      }
      if(params->backoff_delay != NULL) {
         ws->backoff_delay = *params->backoff_delay;
      } else {
         ws->backoff_delay = JSON_INT_VALUE_WS_FPM_BACKOFF_DELAY;
      }

      XLOGD_INFO("debug <%s> connect <%u, %u> inactivity <%u> session <%u> ipv4 fallback <%s> backoff delay <%u>", ws->debug_enabled ? "YES" : "NO", ws->connect_check_interval, ws->timeout_connect, ws->timeout_inactivity, ws->timeout_session, ws->ipv4_fallback ? "YES" : "NO", ws->backoff_delay);
   } else {
      XLOGD_WARN("ws state NULL");
   }
   return(ret);
}

void xrsr_ws_nopoll_log(noPollCtx * ctx, noPollDebugLevel level, const char * log_msg, noPollPtr user_data) {
   xlog_args_t args;
   args.options  = XLOG_OPTS_DEFAULT;
   args.color    = XLOG_COLOR_NONE;
   args.function = XLOG_FUNCTION_NONE;
   args.line     = XLOG_LINE_NONE;
   args.id       = XLOG_MODULE_ID;
   args.size_max = XLOG_BUF_SIZE_DEFAULT;

   switch(level) {
      case NOPOLL_LEVEL_DEBUG:    { args.level = XLOG_LEVEL_DEBUG; break; }
      #ifdef NOPOLL_LEVEL_INFO
      case NOPOLL_LEVEL_INFO:     { args.level = XLOG_LEVEL_INFO;  break; }
      #endif
      case NOPOLL_LEVEL_WARNING:  { args.level = XLOG_LEVEL_WARN;  break; }
      case NOPOLL_LEVEL_CRITICAL: { args.level = XLOG_LEVEL_ERROR; break; }
      default:                    { args.level = XLOG_LEVEL_INFO;  break; }
   }
   int errsv = errno;
   xlog_printf(&args, "%s", log_msg);
   errno = errsv;
}

void xrsr_ws_term(xrsr_state_ws_t *ws) {
   XLOGD_INFO("");
   if(ws == NULL) {
      XLOGD_ERROR("invalid params");
      return;
   } else if(ws->obj_ctx == NULL) {
      XLOGD_ERROR("NULL context");
      return;
   }
   if(nopoll_ctx_ref_count(ws->obj_ctx) > 1) {
      XLOGD_WARN("ws context reference count <%d>", nopoll_ctx_ref_count(ws->obj_ctx));
   }
   
   xrsr_ws_event(ws, SM_EVENT_TERMINATE, false);
   sem_destroy(&ws->msg_out_semaphore);

   nopoll_ctx_unref(ws->obj_ctx);
   ws->obj_ctx = NULL;
}

void xrsr_ws_host_name_set(xrsr_state_ws_t *ws, const char *host_name) {
   int rc = snprintf(ws->local_host_name, sizeof(ws->local_host_name), "%s", host_name ? host_name : "");
   if(rc >= sizeof(ws->local_host_name)) {
      XLOGD_ERROR("host name truncated");
   }
}

void xrsr_ws_fd_set(xrsr_state_ws_t *ws, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
   if(xrsr_ws_is_established(ws) && ws->socket >= 0) {
      //XLOGD_INFO("src <%s> socket <%d> audio pipe <%d> write pending bytes <%d>", xrsr_src_str(ws->audio_src), ws->socket, ws->audio_pipe_fd_read, ws->write_pending_bytes);
      // Always check for incoming messages if ws is established
      FD_SET(ws->socket, readfds);
      if(ws->socket >= *nfds) {
         *nfds = ws->socket + 1;
      }

      // If we need to send an outgoing message or waiting on data to go out
      if(ws->write_pending_bytes || xrsr_ws_is_msg_out(ws)) {
         FD_SET(ws->socket, writefds);
      }

      // We don't want to wake up for the audio pipe if we can't write it to the pipe
      if(ws->audio_pipe_fd_read >= 0 && !ws->write_pending_bytes) {
         FD_SET(ws->audio_pipe_fd_read, readfds);
         if(ws->audio_pipe_fd_read >= *nfds) {
            *nfds = ws->audio_pipe_fd_read + 1;
         }
      }
   }
}

void xrsr_ws_handle_fds(xrsr_state_ws_t *ws, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
   // First, let's check if we have received a message over the websocket
   if(ws->socket >= 0 && FD_ISSET(ws->socket, readfds)) {
      XLOGD_INFO("src <%s> data available for read", xrsr_src_str(ws->audio_src));
      xrsr_ws_read_pending(ws);
   }

   // Now let's send any outgoing messages or pending data over the websocket
   if(ws->socket >= 0 && FD_ISSET(ws->socket, writefds)) {
      // First check if we are trying to send pending bytes
      if(ws->write_pending_bytes) {
         int bytes = nopoll_conn_pending_write_bytes(ws->obj_conn);
         if(bytes != (nopoll_conn_complete_pending_write(ws->obj_conn))) {
            XLOGD_WARN("src <%s> still waiting to write pending bytes...", xrsr_src_str(ws->audio_src));
            ws->write_pending_retries++;
            if(ws->write_pending_retries > XRSR_WS_WRITE_PENDING_RETRY_MAX) {
               xrsr_ws_event(ws, SM_EVENT_WS_ERROR, false);
            }
            // No point in continuing, as we haven't sent the pending data yet.
            return;
         }
         XLOGD_INFO("src <%s> pending bytes written successfully", xrsr_src_str(ws->audio_src));
         ws->write_pending_bytes   = false;
         ws->write_pending_retries = 0;
      }

      // Now lets see if we have a message to send out
      if(xrsr_ws_is_msg_out(ws)) {
         int bytes    = 0;
         char *buf    = NULL;
         uint32_t len = 0;

         if(xrsr_ws_get_msg_out(ws, &buf, &len)) {
            if(buf) {
               XLOGD_INFO("src <%s> sending outgoing message", xrsr_src_str(ws->audio_src));
               bytes = nopoll_conn_send_text(ws->obj_conn, (const char *)buf, (long)len);
               // NoPoll now has the data copied into an internal buffer
               free(buf);
               buf = NULL;
               if(bytes == 0 || bytes == -1) {
                  XLOGD_ERROR("src <%s> failed to write to websocket", xrsr_src_str(ws->audio_src));
                  xrsr_ws_event(ws, SM_EVENT_WS_ERROR, false);
               } else if(bytes == -2 || bytes != len) {
                  if(bytes == -2) {
                     XLOGD_WARN("src <%s> websocket would block sending outgoing message", xrsr_src_str(ws->audio_src));
                  } else {
                     XLOGD_WARN("src <%s> partial message sent", xrsr_src_str(ws->audio_src));
                  }
                  ws->write_pending_bytes = true;
                  // No point in continuing, as we haven't sent this message yet.
                  return;
               }
            }
         }
      }
   }

   // Finally let's check if we have audio data available to send
   if(ws->audio_pipe_fd_read >= 0 && FD_ISSET(ws->audio_pipe_fd_read, readfds)) {
      // Read the audio data and write to websocket
      int rc = read(ws->audio_pipe_fd_read, ws->buffer, sizeof(ws->buffer));
      if(rc < 0) {
         int errsv = errno;
         if(errsv == EAGAIN || errsv == EWOULDBLOCK) {
            XLOGD_INFO("src <%s> read would block", xrsr_src_str(ws->audio_src));
            xrsr_ws_event(ws, SM_EVENT_AUDIO_ERROR, false);
         } else {
            XLOGD_ERROR("src <%s> pipe read error <%s>", xrsr_src_str(ws->audio_src), strerror(errsv));
            xrsr_ws_event(ws, SM_EVENT_AUDIO_ERROR, false);
         }
      } else if(rc == 0) { // EOF
         XLOGD_INFO("src <%s> pipe read EOF", xrsr_src_str(ws->audio_src));
         xrsr_ws_event(ws, SM_EVENT_EOS_PIPE, false);
      } else {
         XLOGD_DEBUG("src <%s> pipe read <%d>", xrsr_src_str(ws->audio_src), rc);
         uint32_t bytes_read = (uint32_t)rc;

         rc = nopoll_conn_send_binary(ws->obj_conn, (const char *)ws->buffer, (long)bytes_read);
         if(rc == -2) { // NOPOLL_EWOULDBLOCK
            XLOGD_WARN("src <%s> websocket would block", xrsr_src_str(ws->audio_src));
            // Set flag to wait for socket write ready
            ws->write_pending_bytes = true;
         } else if(rc == 0) { // no bytes sent (see errno indication)
            int errsv = errno;
            XLOGD_ERROR("src <%s> websocket failure <%s>", xrsr_src_str(ws->audio_src), strerror(errsv));
            xrsr_ws_event(ws, SM_EVENT_WS_ERROR, false);
         } else if(rc < 0) { // failure found
            XLOGD_ERROR("src <%s> websocket failure <%d>", xrsr_src_str(ws->audio_src), rc);
            xrsr_ws_event(ws, SM_EVENT_WS_ERROR, false);
         } else if(rc != bytes_read) { // partial bytes sent
            XLOGD_WARN("src <%s> websocket size mismatch req <%u> sent <%d>", xrsr_src_str(ws->audio_src), bytes_read, rc);
            // Set flag to wait for socket write ready
            ws->write_pending_bytes = true;
            ws->audio_txd_bytes    += (uint32_t) rc;
         } else {
            ws->audio_txd_bytes += bytes_read;
         }
         if(!ws->audio_kwd_notified && (ws->audio_txd_bytes >= ws->audio_kwd_bytes)) {
            if(!xrsr_speech_stream_kwd(ws->uuid,  ws->audio_src, ws->dst_index)) {
               XLOGD_ERROR("src <%s> xrsr_speech_stream_kwd failed", xrsr_src_str(ws->audio_src));
            }
            ws->audio_kwd_notified = true;
         }
      }
   }
}

void xrsr_ws_process_timeout(void *data) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)data;
   XLOGD_INFO("src <%s>", xrsr_src_str(ws->audio_src));
   xrsr_ws_event(ws, SM_EVENT_TIMEOUT, false);
}

bool xrsr_ws_connect(xrsr_state_ws_t *ws, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, xraudio_input_format_t xraudio_format, bool user_initiated, bool is_retry, bool deferred, const char **query_strs) {
   XLOGD_INFO("");
   if(ws == NULL) {
      XLOGD_ERROR("NULL xrsr_state_ws_t");
      return(false);
   } else if(ws->obj_ctx == NULL) {
      XLOGD_ERROR("NULL param");
      return(false);
   } 

   rdkx_timestamp_get(&ws->retry_timestamp_end);
   rdkx_timestamp_add_ms(&ws->retry_timestamp_end, ws->timeout_session);

   ws->audio_src      = audio_src;
   ws->xraudio_format = xraudio_format;

   errno_t safe_rc = -1;
   safe_rc = strncpy_s(ws->url, sizeof(ws->url), url_parts->urle, XRSR_WS_URL_SIZE_MAX-1); // Copy main url
   ERR_CHK(safe_rc);

   if(query_strs != NULL && *query_strs != NULL) { // add attribute-value pairs to the query string
      if(url_parts->path[0] == '\0') { // Handle case where the "/" may also be omitted if neither <path> nor <searchpart> is present.
         strlcat(ws->url, "/", sizeof(ws->url));
      }

      bool delimit = true;
      if(!url_parts->has_query) {
         strlcat(ws->url, "?", sizeof(ws->url));
         delimit = false;
      }

      do {
         if(delimit) {
            strlcat(ws->url, "&", sizeof(ws->url));
         }
         strlcat(ws->url, *query_strs, sizeof(ws->url));
         delimit = true;
         query_strs++;
      } while(*query_strs != NULL);
   }

   XLOGD_INFO("src <%s> local host <%s> remote host <%s> port <%s> url <%s> deferred <%s> family <%s> retry period <%u> ms", xrsr_src_str(ws->audio_src), ws->local_host_name, url_parts->host, url_parts->port_str, xrsr_mask_pii() ? "***" : ws->url, (deferred) ? "YES" : "NO", xrsr_address_family_str(url_parts->family), ws->timeout_session);

   nopoll_conn_connect_timeout(ws->obj_ctx, ws->timeout_connect * 1000);  // wait no more than N milliseconds

   ws->url_parts          = url_parts;
   ws->user_initiated     = user_initiated;
   ws->audio_kwd_notified = true; // if keyword is present in the stream, xraudio will inform
   ws->audio_kwd_bytes    = 0;
   ws->audio_txd_bytes    = 0;
   ws->connect_wait_time  = ws->timeout_connect;
   ws->on_close           = false;
   ws->close_status       = -1;
   memset(&ws->stats, 0, sizeof(ws->stats));
   memset(&ws->audio_stats, 0, sizeof(ws->audio_stats));

   if(!deferred) {
      xrsr_ws_event(ws, SM_EVENT_SESSION_BEGIN, false);
      return(true);
   }
   xrsr_ws_event(ws, SM_EVENT_SESSION_BEGIN_STM, false);
   return(true);
}

bool xrsr_ws_connect_new(xrsr_state_ws_t *ws) {
   xrsr_url_parts_t *url_parts = ws->url_parts;
   xrsr_session_config_in_ws_t *config_in = &ws->session_config_in.ws;
   noPollConnOpts *nopoll_opts = xrsr_conn_opts_get(ws, config_in->sat_token);

   const char *origin_fmt = "http://%s:%s";
   uint32_t origin_size = strlen(url_parts->host) + strlen(url_parts->port_str) + strlen(origin_fmt) - 3;
   char origin[origin_size];

   snprintf(origin, sizeof(origin), origin_fmt, url_parts->host, url_parts->port_str);

   XLOGD_INFO("src <%s> attempt <%u>", xrsr_src_str(ws->audio_src), ws->retry_cnt);

   if(ws->prot == XRSR_PROTOCOL_WSS) {
      if(config_in->client_cert.type != XRSR_CERT_TYPE_NONE) {
         nopoll_ctx_set_ssl_context_creator(ws->obj_ctx, xrsr_ws_ssl_ctx_creator, ws);
         nopoll_ctx_set_post_ssl_check(ws->obj_ctx, xrsr_ws_ssl_post_check_cb, ws);
      }

      const char *ptr_path = strchrnul(&ws->url[6], '/'); // skip over wss:// and locate next /
      ws->obj_conn = NOPOLL_CONN_TLS_NEW(ws->obj_ctx, nopoll_opts, url_parts->host, url_parts->port_str, NULL, ptr_path, NULL, origin);
   } else {
      const char *ptr_path = strchrnul(&ws->url[5], '/'); // skip over ws:// and locate next /
      ws->obj_conn = NOPOLL_CONN_NEW(ws->obj_ctx, nopoll_opts, url_parts->host, url_parts->port_str, NULL, ptr_path, NULL, origin);
   }
   
   if(ws->obj_conn == NULL) {
      XLOGD_ERROR("src <%s> conn new", xrsr_src_str(ws->audio_src));
      return(false);
   }

   if (!nopoll_conn_set_sock_block (nopoll_conn_socket(ws->obj_conn), nopoll_false)) {
      XLOGD_ERROR("failed to configure connection as non-blocking");
      return(false);
   }

   nopoll_conn_set_on_close(ws->obj_conn, xrsr_ws_on_close, ws);
   return(true);
}

noPollConnOpts *xrsr_conn_opts_get(xrsr_state_ws_t *ws, const char *sat_token) {
   noPollConnOpts *nopoll_opts = NULL;

   if(sat_token || ws->prot == XRSR_PROTOCOL_WSS) {
      nopoll_opts = nopoll_conn_opts_new();
      if(nopoll_opts == NULL) {
         XLOGD_ERROR("NULL nopoll opts");
         return(nopoll_opts);
      }
   }
   // re-use options in case of retry?
   //nopoll_conn_opts_set_reuse(nopoll_opts, nopoll_true);

   if(sat_token != NULL) {
      char sat_token_str[24 + XRSR_SAT_TOKEN_LEN_MAX] = {'\0'};
      // String must match the format: "\r\nheader:value\r\nheader2:value2" with no trailing \r\n.
      snprintf(sat_token_str, sizeof(sat_token_str), "\r\nAuthorization: Bearer %s", sat_token);
      nopoll_conn_opts_set_extra_headers(nopoll_opts, sat_token_str);
   }

   if(ws->prot == XRSR_PROTOCOL_WSS) {
      if(!ws->session_config_in.ws.host_verify) {
         XLOGD_WARN("hostname verification disabled");
         NOPOLL_CONN_SSL_HOST_VERIFY(nopoll_opts, nopoll_false);
      } else {
         // Set host name verification option to validate that the certificate's Subject Alternative Name (SAN) or Subject CommonName (CN) matches the url's host name
         #ifdef XRSR_HOSTNAME_VERIFY_POST_CHECK
         NOPOLL_CONN_SSL_HOST_VERIFY(nopoll_opts, nopoll_false);
         #else
         NOPOLL_CONN_SSL_HOST_VERIFY(nopoll_opts, nopoll_true);
         #endif
      }
   }

   return(nopoll_opts);
}

bool xrsr_ws_conn_is_ready(xrsr_state_ws_t *ws) {
   if(ws == NULL) {
      XLOGD_ERROR("NULL xrsr_state_ws_t");
      return(false);
   } else if(ws->obj_conn == NULL) {
      XLOGD_ERROR("src <%s> NULL param", xrsr_src_str(ws->audio_src));
      return(false);
   }
   if(nopoll_true != nopoll_conn_is_ready(ws->obj_conn)) {
      return(false);
   }

   ws->socket          = nopoll_conn_socket(ws->obj_conn);
   
   if(nopoll_true != nopoll_conn_set_sock_block(ws->socket, nopoll_false)) {
      XLOGD_WARN("src <%s> unable to set non-blocking", xrsr_src_str(ws->audio_src));
   }
   return(true);
}

void xrsr_ws_terminate(xrsr_state_ws_t *ws) {
   XLOGD_INFO("");
   if(ws == NULL) {
      XLOGD_ERROR("NULL xrsr_state_ws_t");
      return;
   } else if(ws->obj_ctx == NULL) {
      XLOGD_ERROR("src <%s> NULL context", xrsr_src_str(ws->audio_src));
      return;
   } 

   xrsr_ws_event(ws, SM_EVENT_TERMINATE, false);
}

// TODO, work on this function
bool xrsr_ws_audio_stream(xrsr_state_ws_t *ws, xrsr_src_t src, bool create_stream, bool subsequent) {
   if(ws == NULL) {
      XLOGD_ERROR("NULL xrsr_state_ws_t");
      return(false);
   } else if(ws->obj_ctx == NULL) {
      XLOGD_ERROR("src <%s> NULL context", xrsr_src_str(ws->audio_src));
      return(false);
   }

   ws->audio_src = src;

   // Continue streaming audio to the websocket
   int pipe_fd_read = -1;
   const char *audio_file_in = (ws->is_session_by_file && !subsequent) ? ws->audio_file_in : NULL;

   if(!xrsr_speech_stream_begin(ws->uuid, ws->audio_src, ws->dst_index, ws->input_format, ws->xraudio_format, ws->user_initiated, ws->low_latency, ws->low_cpu_util, create_stream, subsequent, audio_file_in, &pipe_fd_read)) {
      XLOGD_ERROR("src <%s> xrsr_speech_stream_begin failed", xrsr_src_str(ws->audio_src));
      // perform clean up of the session
      xrsr_ws_speech_session_end(ws, XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN);
      return(false);
   }

   ws->audio_pipe_fd_read = pipe_fd_read;

   if(subsequent) { // Trigger start of stream event
      xrsr_ws_event(ws, SM_EVENT_SOS, false);
   } else {
      char uuid_str[37] = {'\0'};
      uuid_unparse_lower(ws->uuid, uuid_str);
      xrsr_session_stream_begin(ws->uuid, uuid_str, ws->audio_src, ws->dst_index);
   }

   return(true);
}

int xrsr_ws_read_pending(xrsr_state_ws_t *ws) {
   if(ws == NULL) {
      XLOGD_ERROR("NULL xrsr_state_ws_t");
      return(-1);
   }

   noPollMsg *msg = nopoll_conn_get_msg(ws->obj_conn);

   if(msg == NULL) {
      XLOGD_DEBUG("src <%s> nopoll_conn_get_msg returned NULL", xrsr_src_str(ws->audio_src));
   } else {
      xrsr_ws_on_msg(ws, ws->obj_conn, msg);
   }

   return(0);
}

int xrsr_ws_send_binary(xrsr_state_ws_t *ws, const uint8_t *buffer, uint32_t length) {
   if(ws == NULL) {
      XLOGD_ERROR("NULL xrsr_state_ws_t");
      return(-1);
   } else if(!xrsr_ws_is_established(ws)) {
      XLOGD_ERROR("src <%s> invalid state", xrsr_src_str(ws->audio_src));
      return(-1);
   }
   XLOGD_DEBUG("src <%s> length <%u>", xrsr_src_str(ws->audio_src), length);
   errno = 0;
   int rc = nopoll_conn_send_binary(ws->obj_conn, (const char *)buffer, (long)length);
   if(rc <= 0) { // failure found
      int errsv = errno;
      XLOGD_ERROR("src <%s> websocket failure <%d>, errno (%d) <%s>, setting ws->socket = -1;", xrsr_src_str(ws->audio_src), rc, errsv, strerror(errsv));
      ws->socket = -1;
   } else if(rc != length) { // partial bytes sent
      XLOGD_ERROR("src <%s> websocket size mismatch req <%u> sent <%d>", xrsr_src_str(ws->audio_src), length, rc);
   }
   return rc;
}

int xrsr_ws_send_text(xrsr_state_ws_t *ws, const uint8_t *buffer, uint32_t length) {
   if(ws == NULL) {
      XLOGD_ERROR("NULL xrsr_state_ws_t");
      return(-1);
   } else if(!xrsr_ws_is_established(ws)) {
      XLOGD_ERROR("src <%s> invalid state", xrsr_src_str(ws->audio_src));
      return(-1);
   }
   XLOGD_DEBUG("src <%s> length <%u>", xrsr_src_str(ws->audio_src), length);
   errno = 0;
   bool ret = xrsr_ws_queue_msg_out(ws, (const char *)buffer, length);
   return (ret ? 1 : 0);
}

void xrsr_ws_on_msg(xrsr_state_ws_t *ws, noPollConn *conn, noPollMsg *msg) {
   XLOGD_INFO("src <%s>", xrsr_src_str(ws->audio_src));
   xrsr_recv_msg_t msg_type      = XRSR_RECV_MSG_INVALID;
   xrsr_recv_event_t recv_event  = XRSR_RECV_EVENT_NONE;

   // Check if we are building up a message
   if(ws->pending_msg != NULL && nopoll_msg_is_final(msg) == nopoll_true) {
      XLOGD_INFO("src <%s> Final Fragment received", xrsr_src_str(ws->audio_src));
      ws->pending_msg = nopoll_msg_join(ws->pending_msg, msg);
      nopoll_msg_unref(msg);
      msg = ws->pending_msg;
      ws->pending_msg = NULL;
   } else if(nopoll_msg_is_fragment(msg) == nopoll_true) {
      XLOGD_INFO("src <%s> Fragment received", xrsr_src_str(ws->audio_src));
      ws->pending_msg = nopoll_msg_join(ws->pending_msg, msg);
      nopoll_msg_unref(msg);
      return;
   }

   noPollOpCode opcode = nopoll_msg_opcode(msg);
   switch(opcode) {
      case NOPOLL_TEXT_FRAME: {
         msg_type = XRSR_RECV_MSG_TEXT;
         break;
      }
      case NOPOLL_BINARY_FRAME: {
         msg_type = XRSR_RECV_MSG_BINARY;
         break;
      }
      default: {
         XLOGD_ERROR("src <%s> invalid opcode <%s>", xrsr_src_str(ws->audio_src), xrsr_ws_opcode_str(opcode));
         break;
      }
   }
   if(msg_type == XRSR_RECV_MSG_INVALID) {
      return;
   }
   const unsigned char *payload = nopoll_msg_get_payload(msg);
   int size = nopoll_msg_get_payload_size(msg);

   xrsr_ws_event(ws, SM_EVENT_MSG_RECV, false);

   // Call recv msg handler
   if(ws->handlers.recv_msg == NULL) {
      XLOGD_ERROR("src <%s> recv msg handler not available", xrsr_src_str(ws->audio_src));
   } else {
      if((*ws->handlers.recv_msg)(ws->handlers.data, msg_type, payload, size, &recv_event)) {
         XLOGD_WARN("src <%s> app close", xrsr_src_str(ws->audio_src));
         // Close the connection
         xrsr_ws_event(ws, SM_EVENT_APP_CLOSE, false);
      }
   }
   nopoll_msg_unref(msg);

  if((unsigned int)recv_event < XRSR_RECV_EVENT_NONE) {
     ws->stream_end_reason  = (recv_event == XRSR_RECV_EVENT_EOS_SERVER ? XRSR_STREAM_END_REASON_AUDIO_EOF : XRSR_STREAM_END_REASON_DISCONNECT_REMOTE);
     ws->session_end_reason = (recv_event == XRSR_RECV_EVENT_EOS_SERVER ? XRSR_SESSION_END_REASON_EOS      : XRSR_SESSION_END_REASON_ERROR_WS_SEND);
     XLOGD_INFO("src <%s> recv_event %s", xrsr_src_str(ws->audio_src), xrsr_recv_event_str(recv_event));
     xrsr_ws_event(ws, SM_EVENT_EOS_PIPE, true);
  }
}

void xrsr_ws_on_close(noPollCtx *ctx, noPollConn *conn, noPollPtr user_data) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)user_data;
   XLOGD_INFO("src <%s>", xrsr_src_str(ws->audio_src));

   ws->on_close = true;
   if(ws->pending_msg) { // This shouldn't ever happen, but for sanity.
      nopoll_msg_unref(ws->pending_msg);
      ws->pending_msg = NULL;
   }
   ws->close_status = nopoll_conn_get_close_status(conn);

   xrsr_ws_event(ws, SM_EVENT_WS_CLOSE, false);
}

void xrsr_ws_speech_stream_end(xrsr_state_ws_t *ws, xrsr_stream_end_reason_t reason, bool detect_resume) {
   XLOGD_INFO("src <%s> fd <%d> reason <%s>", xrsr_src_str(ws->audio_src), ws->audio_pipe_fd_read, xrsr_stream_end_reason_str(reason));

   xrsr_speech_stream_end(ws->uuid, ws->audio_src, ws->dst_index, reason, detect_resume, &ws->audio_stats);

   if(ws->audio_pipe_fd_read >= 0) {
      close(ws->audio_pipe_fd_read);
      ws->audio_pipe_fd_read = -1;
   }
}

void xrsr_ws_speech_session_end(xrsr_state_ws_t *ws, xrsr_session_end_reason_t reason) {
   XLOGD_INFO("src <%s> fd <%d> reason <%s> close code <%d>", xrsr_src_str(ws->audio_src), ws->audio_pipe_fd_read, xrsr_session_end_reason_str(reason), ws->close_status);

   ws->stats.reason = reason;

   char uuid_str[37] = {'\0'};
   uuid_unparse_lower(ws->uuid, uuid_str);
   xrsr_session_end(ws->uuid, uuid_str, ws->audio_src, ws->dst_index, &ws->stats);
}

const char *xrsr_ws_opcode_str(noPollOpCode type) {
   switch(type) {
      case NOPOLL_UNKNOWN_OP_CODE:    return("UNKNOWN_OP_CODE");
      case NOPOLL_CONTINUATION_FRAME: return("CONTINUATION_FRAME");
      case NOPOLL_TEXT_FRAME:         return("TEXT_FRAME");
      case NOPOLL_BINARY_FRAME:       return("BINARY_FRAME");
      case NOPOLL_CLOSE_FRAME:        return("CLOSE_FRAME");
      case NOPOLL_PING_FRAME:         return("PING_FRAME");
      case NOPOLL_PONG_FRAME:         return("PONG_FRAME");
   }
   return("INVALID");
}

void xrsr_ws_handle_speech_event(xrsr_state_ws_t *ws, xrsr_speech_event_t *event) {
   if(NULL == event) {
      XLOGD_ERROR("speech event is NULL");
      return;
   }

   switch(event->event) {
      case XRSR_EVENT_EOS: {
         xrsr_ws_event(ws, SM_EVENT_EOS, false);
         break;
      }
      case XRSR_EVENT_STREAM_KWD_INFO: {
         ws->audio_kwd_notified = false;
         ws->audio_kwd_bytes    = event->data.byte_qty;
         break;
      }
      case XRSR_EVENT_STREAM_TIME_MINIMUM: {
         ws->stream_time_min_rxd = true;
         xrsr_ws_event(ws, SM_EVENT_STM, false);
         break;
      }
      default: {
         XLOGD_WARN("src <%s> unhandled speech event <%s>", xrsr_src_str(ws->audio_src), xrsr_event_str(event->event));
         break;
      }
   }
}

bool xrsr_ws_queue_msg_out(xrsr_state_ws_t *ws, const char *msg, uint32_t length) {
   bool ret = false;
   sem_wait(&ws->msg_out_semaphore);
   if(ws->msg_out_count < XRSR_WS_MSG_OUT_MAX) {
      uint32_t buf_len = length + 1;
      ws->msg_out[ws->msg_out_count] = (char *)malloc(sizeof(char) * buf_len);
      if(ws->msg_out[ws->msg_out_count] == NULL) {
         XLOGD_ERROR("src <%s> failed to allocate msg_out buffer", xrsr_src_str(ws->audio_src));
      } else {
         snprintf(ws->msg_out[ws->msg_out_count], buf_len, "%s", msg);
         ws->msg_out_count++;
         ret = true;
      }
   }
   sem_post(&ws->msg_out_semaphore);
   return(ret);
}

bool xrsr_ws_is_msg_out(xrsr_state_ws_t *ws) {
   bool ret = false;
   sem_wait(&ws->msg_out_semaphore);
   ret = (ws->msg_out_count > 0);
   sem_post(&ws->msg_out_semaphore);
   return(ret);
}

bool xrsr_ws_get_msg_out(xrsr_state_ws_t *ws, char **msg, uint32_t *length) {
   bool ret = false;
   if(msg != NULL && length != NULL) {
      sem_wait(&ws->msg_out_semaphore);
      if(ws->msg_out_count > 0) {
         uint8_t i = 0;

         *msg    = ws->msg_out[0];
         *length = strlen(*msg);
         ret     = true;

         // Clean up
         ws->msg_out_count--;
         for(i = 0; i < ws->msg_out_count; i++) {
            ws->msg_out[i] = ws->msg_out[i+1];
         }
         ws->msg_out[i] = NULL;
      } else {
         XLOGD_WARN("src <%s> No outgoing messages available", xrsr_src_str(ws->audio_src));
      }
      sem_post(&ws->msg_out_semaphore);
   } else {
      XLOGD_ERROR("src <%s> NULL parameters", xrsr_src_str(ws->audio_src));
   }
   return(ret);
}

void xrsr_ws_clear_msg_out(xrsr_state_ws_t *ws) {
   uint8_t i = 0;
   sem_wait(&ws->msg_out_semaphore);
   for(i = 0; i < XRSR_WS_MSG_OUT_MAX; i++) {
      if(ws->msg_out[i] != NULL) {
         free(ws->msg_out[i]);
         ws->msg_out[i] = NULL;
      }
   }
   ws->msg_out_count = 0;
   sem_post(&ws->msg_out_semaphore);
}

void xrsr_ws_reset(xrsr_state_ws_t *ws) {
   if(ws) {
      ws->socket                = -1;
      ws->timer_id              = RDXK_TIMER_ID_INVALID;
      ws->audio_src             = XRSR_SRC_INVALID;
      ws->write_pending_bytes   = false;
      ws->write_pending_retries = 0;
      ws->detect_resume         = true;
      ws->on_close              = false;
      ws->retry_cnt             = 1;
      ws->is_session_by_text    = false;
      ws->is_session_by_file    = false;
      if(ws->audio_pipe_fd_read > -1) {
         close(ws->audio_pipe_fd_read);
         ws->audio_pipe_fd_read = -1;
      }
      xrsr_ws_clear_msg_out(ws);
   }
}

void xrsr_ws_sm_init(xrsr_state_ws_t *ws) {
   if(ws) {
      ws->state_machine.mInstanceName = "wsSM";
      ws->state_machine.bInitFinished = false;
      ws->state_machine.activeEvtQueue.mpQData = ws->state_machine_events_active; 
      ws->state_machine.activeEvtQueue.mQSize = XRSR_WS_SM_EVENTS_MAX; 
      ws->state_machine.deferredEvtQueue.mpQData = NULL; 
      ws->state_machine.deferredEvtQueue.mQSize = 0;
    
      SmInit( &ws->state_machine, &St_Ws_Disconnected_Info );
   }
}

void xrsr_ws_event(xrsr_state_ws_t *ws, tStEventID id, bool from_state_handler) {
   if(ws) {
      SmEnqueueEvent(&ws->state_machine, id, (void *)ws);
      if(!from_state_handler) {
         SmProcessEvents(&ws->state_machine);
      }
   }
}

void St_Ws_Disconnected(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
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
         if(ws->handlers.disconnected == NULL) {
            XLOGD_INFO("src <%s> disconnected handler not available", xrsr_src_str(ws->audio_src));
         } else {
            (*ws->handlers.disconnected)(ws->handlers.data, ws->uuid, ws->session_end_reason, false, &ws->detect_resume, &timestamp);
         }
         xrsr_ws_speech_session_end(ws, ws->session_end_reason);
         xrsr_ws_reset(ws);
         break;
      }
      default: {
         break;
      }
   }
}

void St_Ws_Disconnecting(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         if(ws->obj_conn != NULL) {
            // Remove on_close handler
            nopoll_conn_set_on_close(ws->obj_conn, NULL, NULL);

            // only call close if network is available
            XLOG_DEBUG("src <%s> nopoll ref count %d, should be 2...", xrsr_src_str(ws->audio_src), nopoll_conn_ref_count(ws->obj_conn));
            if(ws->on_close == false) {
               nopoll_conn_close(ws->obj_conn);
            } else {
               XLOG_DEBUG("src <%s> server closed the connection", xrsr_src_str(ws->audio_src));
            }
            ws->obj_conn = NULL;
         }
         xrsr_ws_event(ws, SM_EVENT_DISCONNECTED, true);
         break;
      }
      default: {
         break;
      }
   }
}

void St_Ws_Buffering(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
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
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_AUDIO_EOF;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            case SM_EVENT_TERMINATE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
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

void St_Ws_Connecting(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         if(!xrsr_ws_connect_new(ws)) {
            rdkx_timestamp_t timestamp;
            rdkx_timestamp_get(&timestamp);
            if(rdkx_timestamp_cmp(timestamp, ws->retry_timestamp_end) >= 0) {
               xrsr_ws_event(ws, SM_EVENT_CONNECT_TIMEOUT, true);
            } else {
               xrsr_ws_event(ws, SM_EVENT_RETRY, true);
            }
         } else {
            rdkx_timestamp_t timeout;
            rdkx_timestamp_get(&timeout);
            rdkx_timestamp_add_ms(&timeout, ws->connect_check_interval);

            ws->timer_id = rdkx_timer_insert(ws->timer_obj, timeout, xrsr_ws_process_timeout, ws);
         }
         break;
      }
      case ACT_INTERNAL: {
         switch(pEvent->mID) {
            case SM_EVENT_TIMEOUT: {
               if(!nopoll_conn_is_ok(ws->obj_conn)) {
                  if(ws->connect_wait_time <= 0) { // overall timeout reached
                     rdkx_timestamp_t timestamp;
                     rdkx_timestamp_get(&timestamp);
                     if(rdkx_timestamp_cmp(timestamp, ws->retry_timestamp_end) >= 0) {
                        xrsr_ws_event(ws, SM_EVENT_CONNECT_TIMEOUT, true);
                     } else {
                        xrsr_ws_event(ws, SM_EVENT_RETRY, true);
                     }
                  } else { // Set next timeout
                     rdkx_timestamp_t timeout;
                     rdkx_timestamp_get(&timeout);
                     rdkx_timestamp_add_ms(&timeout, ws->connect_check_interval);
                     ws->connect_wait_time -= ws->connect_check_interval;

                     if(ws->timer_obj && ws->timer_id >= 0) {
                        if(!rdkx_timer_update(ws->timer_obj, ws->timer_id, timeout)) {
                           XLOGD_ERROR("src <%s> timer update", xrsr_src_str(ws->audio_src));
                        }
                     }
                  }
               } else {
                  xrsr_ws_event(ws, SM_EVENT_CONNECTED, true);
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
            case SM_EVENT_XRSR_ERROR: {
               //TODO
               break;
            }
            case SM_EVENT_CONNECT_TIMEOUT: {
               // After attempting to connect until connect timeout, we failed. Consider this a failure.
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            case SM_EVENT_TERMINATE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            default: {
               break;
            }
         }
         if(ws->timer_obj != NULL && ws->timer_id >= 0) {
            if(!rdkx_timer_remove(ws->timer_obj, ws->timer_id)) {
               XLOGD_ERROR("src <%s> timer remove", xrsr_src_str(ws->audio_src));
            }
            ws->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Ws_Connected(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
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

         // Call connected handler
         if(ws->handlers.connected == NULL) {
            XLOGD_INFO("src <%s> connected handler not available", xrsr_src_str(ws->audio_src));
         } else {
            rdkx_timestamp_t timestamp;
            rdkx_timestamp_get_realtime(&timestamp);
            bool success = (*ws->handlers.connected)(ws->handlers.data, ws->uuid, xrsr_conn_send, (void *)ws, &timestamp, ws->session_config_update);

            if(!success) {
               XLOGD_ERROR("src <%s> connect handler failed", xrsr_src_str(ws->audio_src));
            }
         }

         rdkx_timestamp_add_ms(&timeout, ws->connect_check_interval);

         ws->timer_id = rdkx_timer_insert(ws->timer_obj, timeout, xrsr_ws_process_timeout, ws);
         ws->connect_wait_time = ws->timeout_connect;
         break;
      }
      case ACT_INTERNAL: {
         switch(pEvent->mID) {
            case SM_EVENT_TIMEOUT: {
               if(!xrsr_ws_conn_is_ready(ws)) {
                  XLOGD_WARN("src <%s> websocket is not ready", xrsr_src_str(ws->audio_src));
                  if(ws->connect_wait_time <= 0) {
                     XLOGD_ERROR("src <%s> server hang on HTTP upgrade request", xrsr_src_str(ws->audio_src));
                     xrsr_ws_event(ws, SM_EVENT_ESTABLISH_TIMEOUT, true);
                  } else {
                     rdkx_timestamp_t timeout;
                     rdkx_timestamp_get(&timeout);
                     rdkx_timestamp_add_ms(&timeout, ws->connect_check_interval);
                     ws->connect_wait_time -= ws->connect_check_interval;

                     if(ws->timer_obj && ws->timer_id >= 0) {
                        if(!rdkx_timer_update(ws->timer_obj, ws->timer_id, timeout)) {
                           XLOGD_ERROR("src <%s> timer update", xrsr_src_str(ws->audio_src));
                        }
                     }
                  }
               } else {
                  xrsr_ws_event(ws, SM_EVENT_ESTABLISHED, true);
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
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            case SM_EVENT_ESTABLISH_TIMEOUT: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            case SM_EVENT_TERMINATE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            default: {
               break;
            }
         }
         if(ws->timer_obj != NULL && ws->timer_id >= 0) {
            if(!rdkx_timer_remove(ws->timer_obj, ws->timer_id)) {
               XLOGD_ERROR("src <%s> timer remove", xrsr_src_str(ws->audio_src));
            }
            ws->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Ws_Established(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         // Update the timer for connection message monitoring
         rdkx_timestamp_t timeout;
         rdkx_timestamp_get(&timeout);
         rdkx_timestamp_add_ms(&timeout, ws->timeout_inactivity);

         ws->timer_id = rdkx_timer_insert(ws->timer_obj, timeout, xrsr_ws_process_timeout, ws);
         break;
      }
      case ACT_INTERNAL: {
         switch(pEvent->mID) {
            case SM_EVENT_MSG_RECV: {
               rdkx_timestamp_t timeout;
               rdkx_timestamp_get(&timeout);
               rdkx_timestamp_add_ms(&timeout, ws->timeout_inactivity);
               if(ws->timer_obj && ws->timer_id >= 0) {
                  if(!rdkx_timer_update(ws->timer_obj, ws->timer_id, timeout)) {
                     XLOGD_ERROR("src <%s> timer update", xrsr_src_str(ws->audio_src));
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
               ws->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_TERMINATE: {
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               break;
            }
            case SM_EVENT_TIMEOUT: {
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT;
               break;
            }
            case SM_EVENT_WS_CLOSE: {
               ws->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            default: {
               break;
            }
         }
         if(ws->timer_obj != NULL && ws->timer_id >= 0) {
            if(!rdkx_timer_remove(ws->timer_obj, ws->timer_id)) {
               XLOGD_ERROR("src <%s> timer remove", xrsr_src_str(ws->audio_src));
            }
            ws->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Ws_Streaming(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         char uuid_str[37] = {'\0'};
         uuid_unparse_lower(ws->uuid, uuid_str);
         xrsr_session_stream_begin(ws->uuid, uuid_str, ws->audio_src, ws->dst_index);

         if (ws->is_session_by_text) {
            xrsr_ws_event(ws, SM_EVENT_TEXT_SESSION_SUCCESS, true);
         }
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_EOS_PIPE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_AUDIO_EOF;
               ws->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_TERMINATE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_LOCAL;
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               break;
            }
            case SM_EVENT_ESTABLISH_TIMEOUT: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT;
               break;
            }
            case SM_EVENT_AUDIO_ERROR: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_ERROR_AUDIO_READ;
               ws->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_WS_ERROR: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_WS_SEND;
               break;
            }
            case SM_EVENT_WS_CLOSE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
               ws->session_end_reason = (ws->close_status != 1000) ? XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE : XRSR_SESSION_END_REASON_DISCONNECT_REMOTE;
               break;
            }
            case SM_EVENT_TEXT_SESSION_SUCCESS: {
               XLOGD_INFO("src <%s> SM_EVENT_TEXT_SESSION_SUCCESS - text-only session init message sent successfully.", xrsr_src_str(ws->audio_src));
               break;
            }
            default: {
               break;
            }
         }
         if (pEvent->mID != SM_EVENT_TEXT_SESSION_SUCCESS) {
            xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
         }
         break;
      }
      default: {
         break;
      }
   }
}

void St_Ws_TextOnlySession(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_EOS_PIPE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_AUDIO_EOF;
               ws->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_TERMINATE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_LOCAL;
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               break;
            }
            case SM_EVENT_ESTABLISH_TIMEOUT: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DID_NOT_BEGIN;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT;
               break;
            }
            case SM_EVENT_AUDIO_ERROR: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_ERROR_AUDIO_READ;
               ws->session_end_reason = XRSR_SESSION_END_REASON_EOS;
               break;
            }
            case SM_EVENT_WS_ERROR: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_REMOTE;
               ws->session_end_reason = XRSR_SESSION_END_REASON_ERROR_WS_SEND;
               break;
            }
            case SM_EVENT_WS_CLOSE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_INVALID;
               ws->session_end_reason = XRSR_SESSION_END_REASON_EOT;
               break;
            }
            default: {
               break;
            }
         }
         xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
         break;
      }
      default: {
         break;
      }
   }
}

void St_Ws_Connection_Retry(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)pEvent->mData;
   switch(eAction) {
      case ACT_GUARD: {
         if(bGuardResponse) {
            *bGuardResponse = true;
         }
         break;
      }
      case ACT_ENTER: {
         ws->retry_cnt++;
         // Calculate retry delay
         uint32_t slots = 1 << ws->retry_cnt;
         uint32_t retry_delay_ms = ws->backoff_delay * (rand() % slots);

         XLOGD_INFO("src <%s> retry connection - delay <%u> ms", xrsr_src_str(ws->audio_src), retry_delay_ms);

         rdkx_timestamp_t timeout;
         rdkx_timestamp_get(&timeout);
         rdkx_timestamp_add_ms(&timeout, retry_delay_ms);

         if(rdkx_timestamp_cmp(timeout, ws->retry_timestamp_end) > 0) {
            timeout = ws->retry_timestamp_end;
         }

         ws->timer_id = rdkx_timer_insert(ws->timer_obj, timeout, xrsr_ws_process_timeout, ws);
         break;
      }
      case ACT_EXIT: {
         switch(pEvent->mID) {
            case SM_EVENT_TERMINATE: {
               ws->stream_end_reason  = XRSR_STREAM_END_REASON_DISCONNECT_LOCAL;
               ws->session_end_reason = XRSR_SESSION_END_REASON_TERMINATE;
               xrsr_ws_speech_stream_end(ws, ws->stream_end_reason, ws->detect_resume);
               break;
            }
            default: {
               break;
            }
         }
         if(ws->timer_obj != NULL && ws->timer_id >= 0) {
            if(!rdkx_timer_remove(ws->timer_obj, ws->timer_id)) {
               XLOGD_ERROR("src <%s> timer remove", xrsr_src_str(ws->audio_src));
            }
            ws->timer_id = RDXK_TIMER_ID_INVALID;
         }
         break;
      }
      default: {
         break;
      }
   }
}

bool xrsr_ws_is_established(xrsr_state_ws_t *ws) {
   bool ret = false;
   if(ws) {
      if(SmInThisState(&ws->state_machine, &St_Ws_Connected_Info) ||
         SmInThisState(&ws->state_machine, &St_Ws_Established_Info) ||
         SmInThisState(&ws->state_machine, &St_Ws_Streaming_Info) || 
         SmInThisState(&ws->state_machine, &St_Ws_TextOnlySession_Info)) {
         ret = true;
      }
   }
   return(ret);
}

bool xrsr_ws_is_disconnected(xrsr_state_ws_t *ws) {
   bool ret = false;
   if(ws) {
      if(SmInThisState(&ws->state_machine, &St_Ws_Disconnected_Info)) {
         ret = true;
      }
   }
   return(ret);
}

// SSL Context Creator
// This function creates a new SSL_CTX for each connection with the correct options.
noPollPtr xrsr_ws_ssl_ctx_creator(noPollCtx * ctx, noPollConn * conn, noPollConnOpts * opts, nopoll_bool is_client, noPollPtr user_data) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)user_data;
   if(ws == NULL) {
      XLOGD_ERROR("ws is null");
      return(NULL);
   }
   if(!is_client) {
      XLOGD_ERROR("server not supported");
      return(NULL);
   }
   xrsr_session_config_in_ws_t *config_in = &ws->session_config_in.ws;
   #if (OPENSSL_VERSION_NUMBER >= 0x1010107fL)
   SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
   #else
   SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
   #endif

   if(ssl_ctx == NULL) {
      XLOGD_ERROR("SSL_CTX is null");
      return(NULL);
   }

   #if (OPENSSL_VERSION_NUMBER >= 0x1010107fL)
   SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
   SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
   #endif

   xrsr_cert_t *cert = &config_in->client_cert;

   if(cert->type == XRSR_CERT_TYPE_P12) {
      xrsr_cert_p12_t *cert_p12 = &cert->cert.p12;
      XLOGD_INFO("P12 filename <%s>", cert_p12->filename);

      bool cert_is_valid = false;
      PKCS12 *p12_cert   = NULL;
      EVP_PKEY *pkey     = NULL;
      X509 *x509_cert    = NULL;
      STACK_OF(X509) *additional_certs = NULL;
      do {
         FILE *fp = fopen(cert_p12->filename, "rb");
         if(fp == NULL) {
            XLOGD_ERROR("unable to open P12 certificate <%s>", cert_p12->filename);
            break;
         }

         d2i_PKCS12_fp(fp, &p12_cert);
         fclose(fp);
         fp = NULL;

         if(p12_cert == NULL) {
            XLOGD_ERROR("unable to read P12 certificate <%s>", cert_p12->filename);
            break;
         }

         if(1 != PKCS12_parse(p12_cert, cert_p12->passphrase, &pkey, &x509_cert, &additional_certs)) {
            XLOGD_ERROR("unable to parse P12 certificate <%s>", cert_p12->filename);
            break;
         }

         if(!xrsr_ws_ssl_cert_set(ssl_ctx, x509_cert, pkey, additional_certs)) {
            XLOGD_ERROR("Failed to set cert and key");
            break;
         }

         //X509_print_fp(XLOGD_OUTPUT, x509_cert);

         SSL_CTX_set_verify_depth(ssl_ctx, sk_X509_num(additional_certs));
         cert_is_valid = true;
      } while(0);

      if(p12_cert != NULL) {
         PKCS12_free(p12_cert);
      }
      if(pkey != NULL) {
         EVP_PKEY_free(pkey);
      }
      if(x509_cert != NULL) {
         X509_free(x509_cert);
      }
      if(additional_certs != NULL) {
         sk_X509_pop_free(additional_certs, X509_free);
      }

      if(!cert_is_valid) {
         SSL_CTX_free(ssl_ctx);
         return(NULL);
      }
   } else if(cert->type == XRSR_CERT_TYPE_X509) {
      xrsr_cert_x509_t *cert_x509 = &cert->cert.x509;
      XLOGD_INFO("X509 cert <%p> pkey <%p> chain <%p>", cert_x509->x509, cert_x509->pkey, cert_x509->chain);

      if(!xrsr_ws_ssl_cert_set(ssl_ctx, cert_x509->x509, cert_x509->pkey, cert_x509->chain)) {
         XLOGD_ERROR("Failed to set cert and key");
         SSL_CTX_free(ssl_ctx);
         return(NULL);
      }

      SSL_CTX_set_verify_depth(ssl_ctx, sk_X509_num(cert_x509->chain));
   } else if(cert->type != XRSR_CERT_TYPE_NONE) {
      XLOGD_ERROR("invalid cert type <%d>", cert->type);
      SSL_CTX_free(ssl_ctx);
      return(NULL);
   }

   SSL_CTX_set_default_verify_paths(ssl_ctx);
   SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, xrsr_ws_ssl_ctx_certificate_cb);
   SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);

   if(cert->type != XRSR_CERT_TYPE_NONE && 1 != SSL_CTX_check_private_key(ssl_ctx)) {
      XLOGD_ERROR("cert and key mismatch");
      SSL_CTX_free(ssl_ctx);
      return(NULL);
   }

   g_xrsr_ws_ex_data_index = SSL_CTX_get_ex_new_index(0, "ws state", NULL, NULL, NULL);
   if(g_xrsr_ws_ex_data_index < 0) {
      XLOGD_ERROR("unable to get new index");
      SSL_CTX_free(ssl_ctx);
      return(NULL);
   }

   if(1 != SSL_CTX_set_ex_data(ssl_ctx, g_xrsr_ws_ex_data_index, ws)) {
      XLOGD_ERROR("set ex data failed");
      SSL_CTX_free(ssl_ctx);
      return(NULL);
   }

   // Set cipher list
   if(SSL_CTX_set_cipher_list(ssl_ctx, XRSR_WS_CIPHER_LIST) == 0) {
      XLOGD_ERROR("Failed to set cipher list");
      SSL_CTX_free(ssl_ctx);
      return(NULL);
   }

   if(ws->session_config_in.ws.ocsp_verify_stapling) { // inform the server to attach OSCP confirmation in the response
      #if (OPENSSL_VERSION_NUMBER >= 0x1010107fL)
      long rc = SSL_CTX_set_tlsext_status_type(ssl_ctx, TLSEXT_STATUSTYPE_ocsp);
      #else
      long rc = SSL_set_tlsext_status_type(conn->ssl, TLSEXT_STATUSTYPE_ocsp);
      #endif
      if(rc < 0) {
         XLOGD_ERROR("Failed to request OCSP confirmation");
         SSL_CTX_free(ssl_ctx);
         return(NULL);
      }
   }

   return(ssl_ctx);
}

bool xrsr_ws_ssl_cert_set(SSL_CTX *ssl_ctx, X509 *x509_cert, EVP_PKEY *pkey, STACK_OF(X509) *additional_certs) {
   #if (OPENSSL_VERSION_NUMBER >= 0x1010107fL)
   if(1 != SSL_CTX_use_cert_and_key(ssl_ctx, x509_cert, pkey, additional_certs, 1)) {
      XLOGD_ERROR("Failed to set cert and key");
      return(false);
   }
   #else
   if(1 != SSL_CTX_use_certificate(ssl_ctx, x509_cert)) {
      XLOGD_ERROR("Failed to set cert");
      return(false);
   }
   if(1 != SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
      XLOGD_ERROR("Failed to set key");
      return(false);
   }
   if(additional_certs != NULL) {
      for(uint32_t index = 0; index < sk_X509_num(additional_certs); index++) {
         X509 *cert = sk_X509_value(additional_certs, index);

         if(!SSL_CTX_add_client_CA(ssl_ctx, cert)) {
            XLOGD_ERROR("Failed to add client CA");
            return(false);
         }
         if(!SSL_CTX_add_extra_chain_cert(ssl_ctx, cert)) {
            XLOGD_ERROR("Failed to add extra chain cert");
            return(false);
         }
      }
   }
   #endif
   return(true);
}

// The certificate chain is checked starting with the deepest nesting level (the root CA certificate) and worked upward to the peer's certificate.
// At each level signatures and issuer attributes are checked.
// precheck - whether the verification of the certificate in question was passed (preverify_ok=1) or not (preverify_ok=0)
int xrsr_ws_ssl_ctx_certificate_cb(int preverify_ok, X509_STORE_CTX *ctx) {
   SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
   if(ssl == NULL) {
      XLOGD_ERROR("unable to get SSL");
      return(0);
   }
   SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
   if(ssl == NULL) {
      XLOGD_ERROR("unable to get SSL CTX");
      return(0);
   }

   xrsr_state_ws_t *ws = SSL_CTX_get_ex_data(ssl_ctx, g_xrsr_ws_ex_data_index);
   if(ws == NULL) {
      XLOGD_ERROR("unable to get ws state");
      return(0);
   }

   if(!preverify_ok) {
      int err = X509_STORE_CTX_get_error(ctx);


      if(err == X509_V_ERR_CERT_HAS_EXPIRED && ws->session_config_in.ws.cert_expired_allow) {
         XLOGD_TELEMETRY("expired certificate - allow connection.");

         X509 *x509_cert = X509_STORE_CTX_get_current_cert(ctx);
         if(NULL != x509_cert) {
            X509_print_fp(XLOGD_OUTPUT, x509_cert);
         }
      } else if(err == X509_V_ERR_CERT_REVOKED && ws->session_config_in.ws.cert_revoked_allow) {
         XLOGD_WARN("revoked certificate - allow connection.");
         X509 *x509_cert = X509_STORE_CTX_get_current_cert(ctx);
         if(NULL != x509_cert) {
            X509_print_fp(XLOGD_OUTPUT, x509_cert);
         }
      } else {
         XLOGD_ERROR("preverify failed <%s>", X509_verify_cert_error_string(err));
         return(0);
      }
   } else {
      #if 0
      XLOGD_INFO("valid certificate - allow connection.");
      X509 *x509_cert = X509_STORE_CTX_get_current_cert(ctx);
      if(NULL != x509_cert) {
         X509_print_fp(XLOGD_OUTPUT, x509_cert);
      }
      #endif
   }

   return(1);
}

nopoll_bool xrsr_ws_ssl_post_check_cb(noPollCtx *ctx, noPollConn *conn, noPollPtr SSL_CTX, noPollPtr SSL, noPollPtr user_data) {
   xrsr_state_ws_t *ws = (xrsr_state_ws_t *)user_data;

   if(ws == NULL) {
      XLOGD_ERROR("invalid params");
      return(nopoll_false);
   }

   X509 *cert_client = SSL_CTX_get0_certificate(SSL_CTX);
   if(cert_client == NULL) {
      XLOGD_ERROR("unable to get client certificate");
      return(nopoll_false);
   }

   X509 *cert_server = SSL_get_peer_certificate(conn->ssl);
   if(cert_server == NULL) {
      XLOGD_ERROR("unable to get server certificate");
      return(nopoll_false);
   }

   bool local_host = false;
   if((0 == strcmp(conn->host_name, "localhost")) || (0 == strcmp(conn->host_name, "127.0.0.1"))) {
      XLOGD_INFO("local host - host name <%s>", conn->host_name); // Server is local host. Host verification and OCSP will be skipped.
      local_host = true;
   }

   #ifdef XRSR_HOSTNAME_VERIFY_POST_CHECK
   if(ws->session_config_in.ws.host_verify && !local_host) {
      // checks if the certificate Subject Alternative Name (SAN) or Subject CommonName (CN) matches the specified hostname
      int rc = X509_check_host(cert_server, conn->host_name, 0, 0, NULL);
      if(rc != 1) {
         XLOGD_TELEMETRY("host verify failed <%s> host name <%s>", (rc == 0) ? "FAILED MATCH" : "INTERNAL ERROR", conn->host_name); // Allow the connection to continue anyway.  This will show up in telemetry.
         X509_print_fp(XLOGD_OUTPUT, cert_server);
         X509_free(cert_server);
         return(nopoll_false);
      }
      XLOGD_INFO("host verify success - host name <%s>", conn->host_name);
   }
   #endif

   X509_free(cert_server);

   if(ws->session_config_in.ws.ocsp_verify_stapling && !local_host) {
      XLOGD_INFO("OCSP verification");
      if(!xrsr_ws_ocsp_verify(conn->ssl, ws->session_config_in.ws.ocsp_expired_allow, ws->session_config_in.ws.cert_revoked_allow, ws->session_config_in.ws.ocsp_verify_ca)) {
         XLOGD_ERROR("OCSP verification failed");
         return(nopoll_false);
      }
   }

   return(nopoll_true);
}

bool xrsr_ws_ocsp_verify(SSL *ssl, bool allow_expired, bool allow_revoked, bool query_ca_server) {
   unsigned char *response_data;
   OCSP_RESPONSE *ocsp_response = NULL;
   bool stapled_response_valid = false;

   // Check for an OCSP stapled response first
   long response_len = SSL_get_tlsext_status_ocsp_resp(ssl, &response_data);

   if(response_len > 0 && response_data != NULL) {
      // convert response to internal type
      ocsp_response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **)&response_data, response_len);

      if(ocsp_response == NULL) {
         XLOGD_ERROR("response conversion error");
      } else {
         stapled_response_valid = true;
      }
   }

   if(!stapled_response_valid) {
      XLOGD_TELEMETRY("stapled response not valid"); // Track this in telemetry to ensure the server's are stapling the responses.

      if(!query_ca_server) {
         XLOGD_TELEMETRY("OCSP server query disabled (soft fail)");
         return(true);
      }
      if(!xrsr_ws_ocsp_server_query(ssl, &ocsp_response)) {
         XLOGD_TELEMETRY("server response not received");
         return(false);
      }
   }
   return(xrsr_ws_ocsp_response_check(ssl, ocsp_response, allow_expired, allow_revoked));
}

bool xrsr_ws_ocsp_response_check(SSL *ssl, OCSP_RESPONSE *ocsp_response, bool allow_expired, bool allow_revoked) {
   // Validate OCSP response
   if(!ocsp_response) {
      XLOGD_ERROR("Invalid ocsp_response");
      return false;
   }
   OCSP_BASICRESP *ocsp_rsp_basic = NULL;
   OCSP_CERTID *   ocsp_cert_id   = NULL;

   X509_STORE     *cert_store = NULL;
   STACK_OF(X509) *peer_chain = NULL;
   X509 *          peer_cert  = NULL;

   bool result = false;

   do {
      int response_status = OCSP_response_status(ocsp_response);

      if(response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
         XLOGD_ERROR("response status error <%s>", OCSP_response_status_str(response_status));
         break;
      }

      ocsp_rsp_basic = OCSP_response_get1_basic(ocsp_response);
      if(ocsp_rsp_basic == NULL) {
         XLOGD_ERROR("response get1 basic error");
         break;
      }

      peer_chain = SSL_get_peer_cert_chain(ssl);

      if(peer_chain == NULL) {
         XLOGD_ERROR("unable to get peer cert chain");
         break;
      }

      SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);

      if(ssl_ctx == NULL) {
         XLOGD_ERROR("unable to get ssl ctx");
         break;
      }

      cert_store = SSL_CTX_get_cert_store(ssl_ctx);

      if(cert_store == NULL) {
         XLOGD_ERROR("unable to get cert store");
         break;
      }

      // confirm that the basic response message is correctly signed and that the signer certificate can be validated
      int rc = OCSP_basic_verify(ocsp_rsp_basic, peer_chain, cert_store, 0);
      if(rc != 1) {
         XLOGD_ERROR("basic verify <%s>", (rc == 0) ? "FAILURE" : "ERROR");
         break;
      }

      peer_cert = SSL_get_peer_certificate(ssl);
      if(peer_cert == NULL) {
         XLOGD_ERROR("unable to get peer certificate");
         break;
      }

      // Locate the issuer of the cert on the peer certificate chain
      for(uint32_t index = 0; index < sk_X509_num(peer_chain); index++) {
         X509 *issuer = sk_X509_value(peer_chain, index);
         if(X509_check_issued(issuer, peer_cert) == X509_V_OK) {
            ocsp_cert_id = OCSP_cert_to_id(EVP_sha1(), peer_cert, issuer);
            break;
         }
      }

      if(ocsp_cert_id == NULL) {
         XLOGD_ERROR("unable to get cert id");
         break;
      }


      // Now check the result
      ASN1_GENERALIZEDTIME *revtime = NULL;
      ASN1_GENERALIZEDTIME *thisupd = NULL;
      ASN1_GENERALIZEDTIME *nextupd = NULL;
      int status = 0;
      int reason = 0;

      if(1 != OCSP_resp_find_status(ocsp_rsp_basic, ocsp_cert_id, &status, &reason, &revtime, &thisupd, &nextupd)) {
         XLOGD_ERROR("resp find status failed");
         break;
      }

      long sec    = 300;
      long maxsec = -1;
      if(1 != OCSP_check_validity(thisupd, nextupd, sec, maxsec)) {
         XLOGD_TELEMETRY("response has expired - %s connection", allow_expired ? "allow" : "deny");
         if(!allow_expired) {
            break;
         }
      }

      if(status != V_OCSP_CERTSTATUS_GOOD) {
         if(status == V_OCSP_CERTSTATUS_REVOKED) {
            XLOGD_TELEMETRY("revoked cert - reason <%s> %s connection", OCSP_crl_reason_str(reason), allow_revoked ? "allow" : "deny"); // Allow the connection to continue anyway.  This will show up in telemetry.
            if(!allow_revoked) {
               break;
            }
         } else {
            XLOGD_ERROR("unknown cert status <%s>", OCSP_cert_status_str(status)); // Deny the connection.  This will show up in telemetry.
            break;
         }
      }

      result = true;

   } while(0);

   if(peer_cert != NULL) {
      X509_free(peer_cert);
   }
   if(ocsp_cert_id != NULL) {
      OCSP_CERTID_free(ocsp_cert_id);
   }
   if(ocsp_rsp_basic != NULL) {
      OCSP_BASICRESP_free(ocsp_rsp_basic);
   }
   if(ocsp_response != NULL) {
      OCSP_RESPONSE_free(ocsp_response);
   }
   return(result);
}

bool xrsr_ws_ocsp_server_query(SSL *ssl, OCSP_RESPONSE **ocsp_response) {
   OCSP_REQUEST *ocsp_request = NULL;
   char *        ocsp_url     = NULL;

   if(!xrsr_ws_ocsp_request_prepare(ssl, &ocsp_request, &ocsp_url)) {
      XLOGD_ERROR("unable to prepare OCSP request");
      return(false);
   }

   // Make the OCSP request to the server
   char *        host           = NULL;
   char *        port           = NULL;
   char *        path           = NULL;
   BIO  *        obj_bio        = NULL;
   SSL_CTX *     ctx            = NULL;
   OCSP_REQ_CTX *ocsp_req_ctx   = NULL;
   bool          response_valid = false;

   do {
      int secure = 0;

      if(!OCSP_parse_url(ocsp_url, &host, &port, &path, &secure)) {
         XLOGD_ERROR("unable to parse url <%s>", ocsp_url);
         break;
      }

      XLOGD_INFO("host <%s> port <%s> path <%s> ssl <%s>", host, port, path, secure ? "YES" : "NO");

      obj_bio = BIO_new_connect(host);

      if(obj_bio == NULL) {
         XLOGD_ERROR("unable to create bio object");
         break;
      }

      if(port != NULL) {
         BIO_set_conn_port(obj_bio, port);
      }
      if(secure != 0) {
         ctx = SSL_CTX_new(SSLv23_client_method());
         if(ctx == NULL) {
            XLOGD_ERROR("unable to create ssl context");
            break;
         }
         SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
         BIO *obj_bio_ssl = BIO_new_ssl(ctx, 1);
         if(obj_bio_ssl == NULL) {
            XLOGD_ERROR("unable to create bio ssl");
            break;
         }
         obj_bio = BIO_push(obj_bio_ssl, obj_bio);
      }

      OCSP_RESPONSE *response = NULL;

      // set the non-blocking io flag - 0 is blocking (default), 1 is non-blocking
      BIO_set_nbio(obj_bio, 1);

      int rc = BIO_do_connect(obj_bio);

      if((rc <= 0) && !BIO_should_retry(obj_bio)) {
         XLOGD_ERROR("unable to connect to host <%s>", host);
         break;
      }

      int fd = -1;
      if(BIO_get_fd(obj_bio, &fd) < 0) {
         XLOGD_ERROR("unable to get fd");
         break;
      }

      fd_set fds;
      FD_ZERO(&fds);

      struct timeval tval;
      tval.tv_usec = 0;
      tval.tv_sec  = 3;

      FD_SET(fd, &fds);

      rc = select(fd + 1, NULL, (void *)&fds, NULL, &tval);
      if(rc == 0) {
         XLOGD_ERROR("connect timeout");
         break;
      } else if(rc < 0) {
         XLOGD_ERROR("select error");
         break;
      }

      ocsp_req_ctx = OCSP_sendreq_new(obj_bio, path, NULL, -1);
      if(ocsp_req_ctx == NULL) {
         XLOGD_ERROR("unable to create req ctx");
         break;
      }

      if(!OCSP_REQ_CTX_add1_header(ocsp_req_ctx, "Host", host)) {
         XLOGD_ERROR("unable to add host header");
         break;
      }

      if(!OCSP_REQ_CTX_set1_req(ocsp_req_ctx, ocsp_request)) {
         XLOGD_ERROR("unable to set request");
         break;
      }

      do {
         // returns 1 if the operation was completed successfully, -1 if the operation should be retried, or 0 if an error occurred
         rc = OCSP_sendreq_nbio(&response, ocsp_req_ctx);
         if(rc == 1) {
            response_valid = true;
            break;
         }
         if(rc == 0) {
            XLOGD_ERROR("unable to send request");
            break;
         }
         // call select to determine when to retry
         FD_ZERO(&fds);
         FD_SET(fd, &fds);
         tval.tv_usec = 0;
         tval.tv_sec  = 3;
         if(BIO_should_read(obj_bio)) {
            errno = 0;
            rc = select(fd + 1, (void *)&fds, NULL, NULL, &tval);
         } else if(BIO_should_write(obj_bio)) {
            errno = 0;
            rc = select(fd + 1, NULL, (void *)&fds, NULL, &tval);
         } else {
            XLOGD_ERROR("request error");
            break;
         }
         if(rc == 0) {
            int errsv = errno;
            XLOGD_ERROR("send request timeout <%s>", strerror(errsv));
            break;
         }
         if(rc == -1) {
            int errsv = errno;
            XLOGD_ERROR("send request select error <%s>", strerror(errsv));
            break;
         }
      } while(1);

      if(response_valid) {
         *ocsp_response = response;
      }
   } while(0);

   if(ocsp_req_ctx) {
      OCSP_REQ_CTX_free(ocsp_req_ctx);
   }
   if(ctx != NULL) {
      SSL_CTX_free(ctx);
   }
   if(obj_bio != NULL) {
      BIO_free_all(obj_bio);
   }
   if(host != NULL) {
      free(host);
   }
   if(port != NULL) {
      free(port);
   }
   if(path != NULL) {
      free(path);
   }
   if(ocsp_request != NULL) {
      OCSP_REQUEST_free(ocsp_request);
   }
   if(ocsp_url != NULL) {
      free(ocsp_url);
   }

   return(response_valid);
}

bool xrsr_ws_ocsp_request_prepare(SSL *ssl, OCSP_REQUEST **ocsp_request, char **ocsp_url) {
   if(ssl == NULL || ocsp_request == NULL || ocsp_url == NULL) {
      XLOGD_ERROR("invalid params");
      return(false);
   }

   bool rc = false;
   X509 *peer_cert = NULL;
   STACK_OF(OPENSSL_STRING) *url_stack = NULL;
   OCSP_REQUEST *ocsp_request_local = NULL;
   char *ocsp_url_local = NULL;
   OCSP_CERTID *cert_id = NULL;

   do {
      peer_cert = SSL_get_peer_certificate(ssl);
      if(peer_cert == NULL) {
         XLOGD_ERROR("unable to get peer cert");
         break;
      }

      STACK_OF(X509) *peer_chain = SSL_get_peer_cert_chain(ssl);
      if(peer_chain == NULL) {
         XLOGD_ERROR("unable to get peer cert chain");
         break;
      }
      //XLOGD_WARN("peer cert");
      //X509_print_fp(XLOGD_OUTPUT, peer_cert);

      // To get ocsp url
      url_stack = X509_get1_ocsp(peer_cert);

      if(url_stack == NULL) {
         XLOGD_ERROR("unable to get OCSP url");
         break;
      }
      if(sk_OPENSSL_STRING_num(url_stack) < 1) {
         XLOGD_ERROR("url stack empty");
         break;
      }

      ocsp_url_local = strdup(sk_OPENSSL_STRING_value(url_stack, 0));
      if(ocsp_url_local == NULL) {
         XLOGD_ERROR("unable to dup url");
         break;
      }

      ocsp_request_local = OCSP_REQUEST_new();
      if(ocsp_request_local == NULL) {
         XLOGD_ERROR("unable to create OCSP request");
         break;
      }
      int peer_cert_qty = sk_X509_num(peer_chain);
      if(peer_cert_qty < 2) {
         XLOGD_ERROR("peer chain too small <%d>", peer_cert_qty);
         break;
      }

      X509_NAME *issuer_name = X509_get_issuer_name(peer_cert);
      X509 *issuer = NULL;

      for(int index = 0; index < peer_cert_qty; index++) {
         X509 *cert = sk_X509_value(peer_chain, index);
         if(0 == X509_NAME_cmp(X509_get_subject_name(cert), issuer_name)) {
            issuer = cert;
            break;
         }
         //XLOGD_WARN("chain cert <%d>", index);
         //X509_print_fp(XLOGD_OUTPUT, cert);
      }

      if(issuer == NULL) {
         XLOGD_ERROR("issuer not found");
         break;
      }

      cert_id = OCSP_cert_to_id(EVP_sha1(), peer_cert, issuer);
      if(cert_id == NULL) {
         XLOGD_ERROR("unable to get OCSP cert id");
         break;
      }
      if(0 == OCSP_request_add0_id(ocsp_request_local, cert_id)) {
         XLOGD_ERROR("unable to add OCSP cert id");
         OCSP_CERTID_free(cert_id);
         break;
      }

      XLOGD_INFO("ocsp_url <%s>", ocsp_url_local);

      *ocsp_request = ocsp_request_local;
      *ocsp_url     = ocsp_url_local;
      rc            = true;
   } while(0);

   if(url_stack != NULL) {
      X509_email_free(url_stack);
   }
   if(peer_cert != NULL) {
      X509_free(peer_cert);
   }
   if(!rc) {
      if(ocsp_request_local != NULL) {
         OCSP_REQUEST_free(ocsp_request_local);
      }
      if(ocsp_url_local != NULL) {
         free(ocsp_url_local);
      }
   }

   return(rc);
}
