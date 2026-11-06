/*
 * If not stated otherwise in this file or this component's license file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Drives one text-only HTTP session through xrsr + xrsv_http against a contract mock (Prism).
// Exit code 0 only if the mock returns the expected HTTP status (a contract violation yields 422).

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <xr_voice_sdk.h>
#include <xrsv_http.h>

#define HARNESS_REQUEST_RETRY_MAX (50)    // xraudio opens asynchronously after xrsr_open
#define HARNESS_SESSION_TIMEOUT_S (20)

typedef struct {
   pthread_mutex_t      mutex;
   pthread_cond_t       cond;
   bool                 session_ended;
   bool                 msg_received;
   long                 http_status;
   xrsv_http_recv_msg_t msg;
   const char *         sat_token;
} harness_state_t;

static harness_state_t g_state = {
   .mutex = PTHREAD_MUTEX_INITIALIZER,
   .cond  = PTHREAD_COND_INITIALIZER,
};

static void harness_session_begin(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_session_config_out_t *configuration, rdkx_timestamp_t *timestamp, void *user_data) {
   // Mirrors ctrlm_voice_endpoint_http_t::voice_session_begin_callback_http: the app must hand back session config
   static xrsr_session_config_in_t config_in;
   memset(&config_in, 0, sizeof(config_in));
   config_in.src                  = src;
   config_in.http.sat_token       = g_state.sat_token;
   config_in.http.user_agent      = "rmtType=contract-harness";
   config_in.http.host_verify     = false;
   config_in.http.query_strs[0]   = NULL;

   if(configuration->cb_session_config != NULL) {
      (*configuration->cb_session_config)(uuid, &config_in);
   } else {
      fprintf(stderr, "harness: no session config callback\n");
   }
}

static void harness_recv_msg(xrsv_http_recv_msg_t *msg, void *user_data) {
   pthread_mutex_lock(&g_state.mutex);
   g_state.msg          = *msg;
   g_state.msg_received = true;
   pthread_mutex_unlock(&g_state.mutex);
}

static void harness_session_end(const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp, void *user_data) {
   pthread_mutex_lock(&g_state.mutex);
   g_state.http_status   = (stats != NULL) ? stats->ret_code_protocol : -1;
   g_state.session_ended = true;
   pthread_cond_signal(&g_state.cond);
   pthread_mutex_unlock(&g_state.mutex);
}

static void usage(const char *name) {
   fprintf(stderr, "usage: %s --url <http://host:port/speech> [--sat <token>] [--text <transcription>] [--expect-status <code>]\n", name);
}

int main(int argc, char *argv[]) {
   const char *url             = NULL;
   const char *text            = "watch the news";
   long        expected_status = 200;

   static const struct option long_opts[] = {
      { "url",           required_argument, NULL, 'u' },
      { "sat",           required_argument, NULL, 's' },
      { "text",          required_argument, NULL, 't' },
      { "expect-status", required_argument, NULL, 'e' },
      { NULL, 0, NULL, 0 }
   };

   int opt;
   while((opt = getopt_long(argc, argv, "u:s:t:e:", long_opts, NULL)) != -1) {
      switch(opt) {
         case 'u': url             = optarg; break;
         case 's': g_state.sat_token = optarg; break;
         case 't': text            = optarg; break;
         case 'e': expected_status = strtol(optarg, NULL, 10); break;
         default:  usage(argv[0]); return(2);
      }
   }
   if(url == NULL) {
      usage(argv[0]);
      return(2);
   }

   if(vsdk_init(false, NULL, 0) != 0) {
      fprintf(stderr, "harness: vsdk_init failed\n");
      return(1);
   }

   xrsv_http_params_t params = {
      .device_id   = "contract-device-1",
      .receiver_id = "contract-receiver-1",
      .partner_id  = "contract-partner",
      .app_id      = "contract-app",
      .language    = "eng-USA",
      .test_flag   = true,
      .mask_pii    = false,
      .user_data   = NULL,
   };
   xrsv_http_object_t obj_http = xrsv_http_create(&params);
   if(obj_http == NULL) {
      fprintf(stderr, "harness: xrsv_http_create failed\n");
      vsdk_term();
      return(1);
   }

   xrsv_http_handlers_t handlers_in = {
      .session_begin = harness_session_begin,
      .session_end   = harness_session_end,
      .recv_msg      = harness_recv_msg,
   };

   // xrsr keeps a pointer to the routes, so they must outlive the session
   static xrsr_route_t routes[2];
   memset(routes, 0, sizeof(routes));
   routes[0].src                     = XRSR_SRC_RCU_PTT;
   routes[0].dst_qty                 = 1;
   routes[0].dsts[0].url             = url;
   routes[0].dsts[0].formats         = XRSR_AUDIO_FORMAT_PCM;
   routes[0].dsts[0].stream_time_min = 0;
   routes[0].dsts[0].stream_from     = XRSR_STREAM_FROM_BEGINNING;
   routes[0].dsts[0].stream_offset   = 0;
   routes[0].dsts[0].stream_until    = XRSR_STREAM_UNTIL_END_OF_STREAM;
   routes[1].src                     = XRSR_SRC_INVALID;

   if(!xrsv_http_handlers(obj_http, &handlers_in, &routes[0].dsts[0].handlers)) {
      fprintf(stderr, "harness: xrsv_http_handlers failed\n");
      xrsv_http_destroy(obj_http);
      vsdk_term();
      return(1);
   }

   if(!xrsr_open("contract-harness", routes, NULL, NULL, XRSR_POWER_MODE_FULL, false, false, NULL)) {
      fprintf(stderr, "harness: xrsr_open failed\n");
      xrsv_http_destroy(obj_http);
      vsdk_term();
      return(1);
   }

   xrsr_session_request_t request = { .type = XRSR_SESSION_REQUEST_TYPE_TEXT };
   request.value.text.text        = text;
   xrsr_audio_format_t    format  = { .type = XRSR_AUDIO_FORMAT_NONE };

   bool requested = false;
   for(int i = 0; i < HARNESS_REQUEST_RETRY_MAX && !requested; i++) {
      requested = xrsr_session_request(XRSR_SRC_RCU_PTT, 0, format, request, NULL, false, false);
      if(!requested) {
         usleep(100 * 1000);
      }
   }

   int rc = 1;
   if(!requested) {
      fprintf(stderr, "harness: xrsr_session_request failed\n");
   } else {
      struct timespec deadline;
      clock_gettime(CLOCK_REALTIME, &deadline);
      deadline.tv_sec += HARNESS_SESSION_TIMEOUT_S;

      pthread_mutex_lock(&g_state.mutex);
      int wait_rc = 0;
      while(!g_state.session_ended && wait_rc != ETIMEDOUT) {
         wait_rc = pthread_cond_timedwait(&g_state.cond, &g_state.mutex, &deadline);
      }
      bool ended          = g_state.session_ended;
      long status         = g_state.http_status;
      bool msg_received   = g_state.msg_received;
      xrsv_http_recv_msg_t msg = g_state.msg;
      pthread_mutex_unlock(&g_state.mutex);

      if(!ended) {
         fprintf(stderr, "harness: FAIL session did not end within %d s\n", HARNESS_SESSION_TIMEOUT_S);
      } else {
         printf("harness: http status <%ld> expected <%ld>\n", status, expected_status);
         if(msg_received) {
            printf("harness: parsed ret_code <%ld> message <%s> trx <%s> transcription <%s>\n", msg.ret_code, msg.message, msg.session_id, msg.transcription);
         }
         if(status != expected_status) {
            fprintf(stderr, "harness: FAIL unexpected http status (422 means the SDK request violated the contract)\n");
         } else if(expected_status == 200 && (!msg_received || msg.session_id[0] == '\0' || msg.transcription[0] == '\0')) {
            fprintf(stderr, "harness: FAIL SDK did not parse trx/transcription from the contract example\n");
         } else {
            printf("harness: PASS\n");
            rc = 0;
         }
      }
   }

   xrsr_close();
   xrsv_http_destroy(obj_http);
   vsdk_term();
   return(rc);
}
