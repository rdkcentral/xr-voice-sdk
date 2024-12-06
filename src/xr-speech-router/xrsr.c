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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <semaphore.h>
#include <xr_mq.h>
#include <pthread.h>
#include <xrsr_private.h>
#include <xraudio.h>
#include <opus/opus.h>

#define XRSR_KEYWORD_PHRASE (0)

typedef enum {
   XRSR_THREAD_MAIN = 0,
   XRSR_THREAD_QTY  = 1,
} xrsr_thread_t;

typedef void *(*xrsr_thread_func_t)(void *);

typedef union {
   #ifdef WS_ENABLED
   xrsr_state_ws_t     ws;
   #endif
   #ifdef HTTP_ENABLED
   xrsr_state_http_t   http;
   #endif
   #ifdef SDT_ENABLED
   xrsr_state_sdt_t  sdt;
   #endif
} xrsr_conn_state_t;

typedef struct {
   bool                         initialized;
   xrsr_url_parts_t             url_parts;
   xrsr_route_handler_t         handler;
   xrsr_handlers_t              handlers;
   xrsr_audio_format_type_t     formats;
   uint16_t                     stream_time_min;
   xraudio_input_record_from_t  stream_from;
   int32_t                      stream_offset;
   xraudio_input_record_until_t stream_until;
   uint32_t                     keyword_begin;
   uint32_t                     keyword_duration;
   xrsr_conn_state_t            conn_state;
   xrsr_dst_param_ptrs_t        dst_param_ptrs[XRSR_POWER_MODE_INVALID];
} xrsr_dst_int_t;

typedef struct {
   xrsr_dst_int_t dsts[XRSR_DST_QTY_MAX];
} xrsr_route_int_t;

typedef struct {
   const char *       name;
   int                msgq_id;
   size_t             msgsize;
   xrsr_thread_func_t func;
   void *             params;
   pthread_t          id;
   sem_t              semaphore;
} xrsr_thread_info_t;

typedef struct {
   bool                running;
   rdkx_timer_object_t timer_obj;
} xrsr_thread_state_t;

#ifdef WS_ENABLED
typedef struct {
   bool *    ptr_debug;
   bool      val_debug;
   uint32_t *ptr_connect_check_interval;
   uint32_t  val_connect_check_interval;
   uint32_t *ptr_timeout_connect;
   uint32_t  val_timeout_connect;
   uint32_t *ptr_timeout_inactivity;
   uint32_t  val_timeout_inactivity;
   uint32_t *ptr_timeout_session;
   uint32_t  val_timeout_session;
   bool *    ptr_ipv4_fallback;
   bool      val_ipv4_fallback;
   uint32_t *ptr_backoff_delay;
   uint32_t  val_backoff_delay;
} xrsr_ws_json_config_t;
#endif

#ifdef HTTP_ENABLED
typedef struct {
   bool      debug;
} xrsr_http_json_config_t;
#endif

typedef struct {
   xrsr_src_t                    src;
   xraudio_devices_input_t       xraudio_device_input;
   int                           pipe_fds_rd[XRSR_DST_QTY_MAX]; // cache the read side of the pipes since the stream requests
   int                           pipe_size[XRSR_DST_QTY_MAX];
   bool                          requested_more_audio;
   uint16_t                      stream_id;
   xrsr_session_config_update_t  session_config_update;
} xrsr_session_t;

typedef struct {
   bool                          opened;
   xrsr_power_mode_t             power_mode;
   bool                          privacy_mode;
   bool                          mask_pii;
   xrsr_thread_info_t            threads[XRSR_THREAD_QTY];
   xrsr_route_int_t              routes[XRSR_SRC_INVALID];
   xrsr_xraudio_object_t         xrsr_xraudio_object;
   char *                        capture_dir_path;
   xrsr_session_t                sessions[XRSR_SESSION_GROUP_QTY];
   #ifdef WS_ENABLED
   xrsr_ws_json_config_t         *ws_json_config;
   xrsr_ws_json_config_t          ws_json_config_fpm;
   xrsr_ws_json_config_t          ws_json_config_lpm;
   #endif
   #ifdef HTTP_ENABLED
   xrsr_http_json_config_t        http_json_config;
   #endif
} xrsr_global_t;

static void xrsr_session_stream_kwd(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index);
static void xrsr_session_stream_end(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index, xrsr_stream_stats_t *stats);

#ifdef HTTP_ENABLED
static void xrsr_callback_session_config_in_http(const uuid_t uuid, xrsr_session_config_in_t *config_in);
#endif

static void xrsr_callback_session_config_in_ws(const uuid_t uuid, xrsr_session_config_in_t *config_in);

typedef void (*xrsr_msg_handler_t)(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);

static void xrsr_msg_terminate                              (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_route_update                           (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_keyword_update                         (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_host_name_update                       (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_capture_config_update                  (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_power_mode_update                      (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_privacy_mode_update                    (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_privacy_mode_get                       (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_xraudio_granted                        (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_xraudio_revoked                        (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_xraudio_event                          (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_keyword_detected                       (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_keyword_detect_error                   (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_keyword_detect_sensitivity_limits_get  (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_session_begin                          (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_session_config_in                      (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_session_terminate                      (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_session_audio_stream_start             (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_session_capture_start                  (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_session_capture_stop                   (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);
static void xrsr_msg_thread_poll                            (const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg);

static bool     xrsr_is_source_active(xrsr_src_t src);
static bool     xrsr_is_group_active(uint32_t group);
static uint32_t xrsr_source_to_group(xrsr_src_t src);
static bool     xrsr_has_keyword_detector(xrsr_src_t src);
static bool     xrsr_capture_config_apply(const xrsr_capture_config_t *capture_config);

static const xrsr_msg_handler_t g_xrsr_msg_handlers[XRSR_QUEUE_MSG_TYPE_INVALID] = {
   xrsr_msg_terminate,
   xrsr_msg_route_update,
   xrsr_msg_keyword_update,
   xrsr_msg_host_name_update,
   xrsr_msg_capture_config_update,
   xrsr_msg_power_mode_update,
   xrsr_msg_privacy_mode_update,
   xrsr_msg_privacy_mode_get,
   xrsr_msg_xraudio_granted,
   xrsr_msg_xraudio_revoked,
   xrsr_msg_xraudio_event,
   xrsr_msg_keyword_detected,
   xrsr_msg_keyword_detect_error,
   xrsr_msg_keyword_detect_sensitivity_limits_get,
   xrsr_msg_session_begin,
   xrsr_msg_session_config_in,
   xrsr_msg_session_terminate,
   xrsr_msg_session_audio_stream_start,
   xrsr_msg_session_capture_start,
   xrsr_msg_session_capture_stop,
   xrsr_msg_thread_poll,
};

static xrsr_global_t g_xrsr;

static bool xrsr_threads_init(bool is_prod);
static void xrsr_threads_term(void);
static void *xrsr_thread_main(void *param);
static void xrsr_route_free_all(void);
static void xrsr_route_free(xrsr_src_t src, bool closing);
static void xrsr_route_update(const char *host_name, const xrsr_route_t *route, xrsr_thread_state_t *state);

static xrsr_audio_format_t xrsr_audio_format_get(uint32_t formats_supported_dst, xraudio_input_format_t format_src);

void xrsr_version(xrsr_version_info_t *version_info, uint32_t *qty) {
   if(qty == NULL || *qty < XRSR_VERSION_QTY_MAX || version_info == NULL) {
      return;
   }
   uint32_t qty_avail = *qty;

   xraudio_version_info_t xraudio_version_info[XRAUDIO_VERSION_QTY_MAX];
   memset(xraudio_version_info, 0, sizeof(xraudio_version_info));

   uint32_t qty_xraudio = qty_avail;
   xraudio_version(xraudio_version_info, &qty_xraudio);

   for(uint32_t index = 0; index < qty_xraudio; index++) {
      xraudio_version_info_t *entry = &xraudio_version_info[index];
      version_info->name      = entry->name;
      version_info->version   = entry->version;
      version_info->branch    = entry->branch;
      version_info->commit_id = entry->commit_id;
      version_info++;
      qty_avail--;
   }
   *qty -= qty_avail;
}

bool xrsr_open(const char *host_name, const xrsr_route_t routes[], const xrsr_keyword_config_t *keyword_config, const xrsr_capture_config_t *capture_config, xrsr_power_mode_t power_mode, bool privacy_mode, bool mask_pii, const json_t *json_obj_vsdk) {
   json_t *json_obj_xraudio = NULL;
   if(g_xrsr.opened) {
      XLOGD_ERROR("already open");
      return(false);
   }
   if(routes == NULL) {
      XLOGD_ERROR("invalid parameter");
      return(false);
   }
   if((uint32_t)power_mode >= XRSR_POWER_MODE_INVALID) {
      XLOGD_ERROR("invalid power mode <%s>", xrsr_power_mode_str(power_mode));
      return(false);
   }

   memset(g_xrsr.routes, 0, sizeof(g_xrsr.routes));

   uint32_t index = 0;
   do {
      if(routes[index].src >= XRSR_SRC_INVALID) {
         break;
      }
      XLOGD_INFO("%u: src <%s>", index, xrsr_src_str(routes[index].src));

      if(routes[index].dst_qty < 1 || routes[index].dst_qty > XRSR_DST_QTY_MAX) {
         XLOGD_ERROR("invalid dsts array");
         break;
      }

      for(uint32_t dst_index = 0; dst_index < routes[index].dst_qty; dst_index++) {
         const xrsr_dst_t *dst = &routes[index].dsts[dst_index];
         XLOGD_INFO("dst <%s>", dst->url);
      }
      index++;
   } while(1);

   // Create xraudio object
   xraudio_keyword_sensitivity_t sensitivity = (keyword_config == NULL) ? XRAUDIO_INPUT_DEFAULT_KEYWORD_SENSITIVITY : (xraudio_keyword_sensitivity_t)keyword_config->sensitivity;

   for(uint32_t group = 0; group < XRSR_SESSION_GROUP_QTY; group++) {
      xrsr_session_t *session = &g_xrsr.sessions[group];
      session->src                  = XRSR_SRC_INVALID;
      session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_NONE;
      session->requested_more_audio = false;
      session->stream_id            = 0;

      for(index = 0; index < XRSR_DST_QTY_MAX; index++) {
         session->pipe_fds_rd[index] = -1;
      }
   }

   if(NULL == json_obj_vsdk) {
      XLOGD_INFO("xraudio json object not found, using defaults");
   } else {
      json_obj_xraudio = json_object_get(json_obj_vsdk, JSON_OBJ_NAME_XRAUDIO);
      if(NULL == json_obj_xraudio) {
         XLOGD_INFO("xraudio json object not found, using defaults");
      } else {
         if(!json_is_object(json_obj_xraudio))  {
            XLOGD_WARN("json_obj_xraudio is not object, using defaults");
            json_obj_xraudio = NULL;
         }
      }
   }

   json_t *json_obj;
   #ifdef HTTP_ENABLED
   memset(&g_xrsr.http_json_config, 0, sizeof(xrsr_http_json_config_t));

   json_t *json_obj_http  = json_object_get(json_obj_vsdk, JSON_OBJ_NAME_HTTP);
   if(NULL == json_obj_http || !json_is_object(json_obj_http)) {
      XLOGD_INFO("http json object not found, using defaults");
   } else {
      json_obj = json_object_get(json_obj_http, JSON_BOOL_NAME_HTTP_DEBUG);
      if(json_obj != NULL && json_is_boolean(json_obj)) {
         g_xrsr.http_json_config.debug = json_is_true(json_obj) ? true : false;
         XLOGD_INFO("http json: debug <%s>", g_xrsr.http_json_config.debug ? "YES" : "NO");
      }
   }
   #endif

   #ifdef WS_ENABLED
   memset(&g_xrsr.ws_json_config_fpm, 0, sizeof(xrsr_ws_json_config_t));
   memset(&g_xrsr.ws_json_config_lpm, 0, sizeof(xrsr_ws_json_config_t));

   json_t *json_obj_ws     = json_object_get(json_obj_vsdk, JSON_OBJ_NAME_WS);
   if(NULL == json_obj_ws || !json_is_object(json_obj_ws)) {
      XLOGD_INFO("ws json object not found, using defaults");
   } else {
      //"debug" shared between full and low power configs
      json_obj = json_object_get(json_obj_ws, JSON_BOOL_NAME_WS_DEBUG);
      if(json_obj != NULL && json_is_boolean(json_obj)) {
         g_xrsr.ws_json_config_fpm.val_debug = json_is_true(json_obj) ? true : false;
         g_xrsr.ws_json_config_fpm.ptr_debug = &g_xrsr.ws_json_config_fpm.val_debug;
         g_xrsr.ws_json_config_lpm.val_debug = json_is_true(json_obj) ? true : false;
         g_xrsr.ws_json_config_lpm.ptr_debug = &g_xrsr.ws_json_config_lpm.val_debug;
         XLOGD_INFO("ws json: debug <%s>", g_xrsr.ws_json_config_fpm.val_debug ? "YES" : "NO");
      }

      json_t *json_obj_fpm = json_object_get(json_obj_ws, JSON_OBJ_NAME_WS_FPM);
      if(NULL == json_obj_fpm || !json_is_object(json_obj_fpm)) {
         XLOGD_INFO("fpm json object not found, using defaults");
      } else {
         json_obj = json_object_get(json_obj_fpm, JSON_INT_NAME_WS_FPM_CONNECT_CHECK_INTERVAL);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 1000) {
               g_xrsr.ws_json_config_fpm.val_connect_check_interval = value;
               g_xrsr.ws_json_config_fpm.ptr_connect_check_interval = &g_xrsr.ws_json_config_fpm.val_connect_check_interval;
               XLOGD_INFO("ws fpm json: connect check interval <%d> ms", g_xrsr.ws_json_config_fpm.val_connect_check_interval);
            }
         }
         json_obj = json_object_get(json_obj_fpm, JSON_INT_NAME_WS_FPM_TIMEOUT_CONNECT);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 60000) {
               g_xrsr.ws_json_config_fpm.val_timeout_connect = value;
               g_xrsr.ws_json_config_fpm.ptr_timeout_connect = &g_xrsr.ws_json_config_fpm.val_timeout_connect;
               XLOGD_INFO("ws fpm json: timeout connect <%d> ms", g_xrsr.ws_json_config_fpm.val_timeout_connect);
            }
         }
         json_obj = json_object_get(json_obj_fpm, JSON_INT_NAME_WS_FPM_TIMEOUT_INACTIVITY);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 60000) {
               g_xrsr.ws_json_config_fpm.val_timeout_inactivity = value;
               g_xrsr.ws_json_config_fpm.ptr_timeout_inactivity = &g_xrsr.ws_json_config_fpm.val_timeout_inactivity;
               XLOGD_INFO("ws fpm json: timeout inactivity <%d> ms", g_xrsr.ws_json_config_fpm.val_timeout_inactivity);
            }
         }
         json_obj = json_object_get(json_obj_fpm, JSON_INT_NAME_WS_FPM_TIMEOUT_SESSION);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 60000) {
               g_xrsr.ws_json_config_fpm.val_timeout_session = value;
               g_xrsr.ws_json_config_fpm.ptr_timeout_session = &g_xrsr.ws_json_config_fpm.val_timeout_session;
               XLOGD_INFO("ws fpm json: timeout session <%d> ms", g_xrsr.ws_json_config_fpm.val_timeout_session);
            }
         }
         json_obj = json_object_get(json_obj_fpm, JSON_BOOL_NAME_WS_FPM_IPV4_FALLBACK);
         if(json_obj != NULL && json_is_boolean(json_obj)) {
            g_xrsr.ws_json_config_fpm.val_ipv4_fallback = json_is_true(json_obj) ? true : false;
            g_xrsr.ws_json_config_fpm.ptr_ipv4_fallback = &g_xrsr.ws_json_config_fpm.val_ipv4_fallback;
            XLOGD_INFO("ws fpm json: ipv4 fallback <%s>", g_xrsr.ws_json_config_fpm.val_ipv4_fallback ? "YES" : "NO");
         }
         json_obj = json_object_get(json_obj_fpm, JSON_INT_NAME_WS_FPM_BACKOFF_DELAY);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 10000) {
               g_xrsr.ws_json_config_fpm.val_backoff_delay = value;
               g_xrsr.ws_json_config_fpm.ptr_backoff_delay = &g_xrsr.ws_json_config_fpm.val_backoff_delay;
               XLOGD_INFO("ws fpm json: backoff delay <%d> ms", g_xrsr.ws_json_config_fpm.val_backoff_delay);
            }
         }
      }

      json_t *json_obj_lpm = json_object_get(json_obj_ws, JSON_OBJ_NAME_WS_LPM);
      if(NULL == json_obj_lpm || !json_is_object(json_obj_lpm)) {
         XLOGD_INFO("lpm json object not found, using defaults");
      } else {
         json_obj = json_object_get(json_obj_lpm, JSON_INT_NAME_WS_LPM_CONNECT_CHECK_INTERVAL);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 1000) {
               g_xrsr.ws_json_config_lpm.val_connect_check_interval = value;
               g_xrsr.ws_json_config_lpm.ptr_connect_check_interval = &g_xrsr.ws_json_config_lpm.val_connect_check_interval;
               XLOGD_INFO("ws lpm json: connect check interval <%d> ms", g_xrsr.ws_json_config_lpm.val_connect_check_interval);
            }
         }
         json_obj = json_object_get(json_obj_lpm, JSON_INT_NAME_WS_LPM_TIMEOUT_CONNECT);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 60000) {
               g_xrsr.ws_json_config_lpm.val_timeout_connect = value;
               g_xrsr.ws_json_config_lpm.ptr_timeout_connect = &g_xrsr.ws_json_config_lpm.val_timeout_connect;
               XLOGD_INFO("ws lpm json: timeout connect <%d> ms", g_xrsr.ws_json_config_lpm.val_timeout_connect);
            }
         }
         json_obj = json_object_get(json_obj_lpm, JSON_INT_NAME_WS_LPM_TIMEOUT_INACTIVITY);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 60000) {
               g_xrsr.ws_json_config_lpm.val_timeout_inactivity = value;
               g_xrsr.ws_json_config_lpm.ptr_timeout_inactivity = &g_xrsr.ws_json_config_lpm.val_timeout_inactivity;
               XLOGD_INFO("ws lpm json: timeout inactivity <%d> ms", g_xrsr.ws_json_config_lpm.val_timeout_inactivity);
            }
         }
         json_obj = json_object_get(json_obj_lpm, JSON_INT_NAME_WS_LPM_TIMEOUT_SESSION);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 60000) {
               g_xrsr.ws_json_config_lpm.val_timeout_session = value;
               g_xrsr.ws_json_config_lpm.ptr_timeout_session = &g_xrsr.ws_json_config_lpm.val_timeout_session;
               XLOGD_INFO("ws lpm json: timeout session <%d> ms", g_xrsr.ws_json_config_lpm.val_timeout_session);
            }
         }
         json_obj = json_object_get(json_obj_lpm, JSON_BOOL_NAME_WS_LPM_IPV4_FALLBACK);
         if(json_obj != NULL && json_is_boolean(json_obj)) {
            g_xrsr.ws_json_config_lpm.val_ipv4_fallback = json_is_true(json_obj) ? true : false;
            g_xrsr.ws_json_config_lpm.ptr_ipv4_fallback = &g_xrsr.ws_json_config_lpm.val_ipv4_fallback;
            XLOGD_INFO("ws lpm json: ipv4 fallback <%s>", g_xrsr.ws_json_config_lpm.val_ipv4_fallback ? "YES" : "NO");
         }
         json_obj = json_object_get(json_obj_lpm, JSON_INT_NAME_WS_LPM_BACKOFF_DELAY);
         if(json_obj != NULL && json_is_integer(json_obj)) {
            json_int_t value = json_integer_value(json_obj);
            if(value >= 0 && value <= 10000) {
               g_xrsr.ws_json_config_lpm.val_backoff_delay = value;
               g_xrsr.ws_json_config_lpm.ptr_backoff_delay = &g_xrsr.ws_json_config_lpm.val_backoff_delay;
               XLOGD_INFO("ws lpm json: backoff delay <%d> ms", g_xrsr.ws_json_config_lpm.val_backoff_delay);
            }
         }
      }
      #endif
   }

   xraudio_power_mode_t xraudio_power_mode;

   switch(power_mode) {
      case XRSR_POWER_MODE_FULL:
         xraudio_power_mode = XRAUDIO_POWER_MODE_FULL;
         g_xrsr.ws_json_config = &g_xrsr.ws_json_config_fpm;
         break;
      case XRSR_POWER_MODE_LOW:
         xraudio_power_mode = XRAUDIO_POWER_MODE_LOW;
         g_xrsr.ws_json_config = &g_xrsr.ws_json_config_lpm;
         break;
      case XRSR_POWER_MODE_SLEEP:
         xraudio_power_mode = XRAUDIO_POWER_MODE_SLEEP;
         g_xrsr.ws_json_config = &g_xrsr.ws_json_config_lpm;
         break;
      default:
         XLOGD_ERROR("Invalid power mode");
         return(false);
   }

   g_xrsr.xrsr_xraudio_object = xrsr_xraudio_create(XRSR_KEYWORD_PHRASE, sensitivity, xraudio_power_mode, privacy_mode, json_obj_xraudio);

   if(capture_config != NULL) {
      if(!xrsr_capture_config_apply(capture_config)) {
         XLOGD_ERROR("unable to apply capture config");
      }
   }

   // TODO Get prod vs debug from rdkversion

   if(!xrsr_threads_init(false)) {
      XLOGD_ERROR("thread init failed");
      return(false);
   }

   // Send the route information
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);
   xrsr_queue_msg_route_update_t msg;
   msg.header.type = XRSR_QUEUE_MSG_TYPE_ROUTE_UPDATE;
   msg.semaphore   = &semaphore;
   msg.routes      = routes;
   msg.host_name   = host_name;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   g_xrsr.power_mode   = power_mode;
   g_xrsr.privacy_mode = privacy_mode;
   g_xrsr.mask_pii     = mask_pii;
   g_xrsr.opened       = true;
   return(true);
}

void xrsr_close(void) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return;
   }
   XLOGD_INFO("");

   xrsr_threads_term();

   xrsr_xraudio_destroy(g_xrsr.xrsr_xraudio_object);
   g_xrsr.xrsr_xraudio_object = NULL;

   xrsr_route_free_all();

   if(g_xrsr.capture_dir_path != NULL) {
      free(g_xrsr.capture_dir_path);
      g_xrsr.capture_dir_path = NULL;
   }

   g_xrsr.opened = false;
}

bool xrsr_threads_init(bool is_prod) {
   xrsr_thread_params_t params_main;

   // Launch threads
   xrsr_thread_info_t *info;
   info             = &g_xrsr.threads[XRSR_THREAD_MAIN];
   info->name       = "main";
   info->msgq_id    = -1;
   info->msgsize    = XRSR_MSG_QUEUE_MSG_SIZE_MAX;
   info->func       = xrsr_thread_main;
   info->params     = &params_main;
   params_main.semaphore = &info->semaphore;
   params_main.is_prod   = is_prod;
   sem_init(&info->semaphore, 0, 0);

   for(uint32_t index = 0; index < XRSR_THREAD_QTY; index++) {
      xrsr_thread_info_t *info = &g_xrsr.threads[index];

      // Create message queue
      if(!xrsr_message_queue_open(&info->msgq_id, info->msgsize)) {
         XLOGD_ERROR("unable to open msgq");
         return(false);
      }
      ((xrsr_thread_params_t *)info->params)->msgq_id = info->msgq_id;

      if(0 != pthread_create(&info->id, NULL, info->func, info->params)) {
         XLOGD_ERROR("unable to launch thread");
         return(false);
      }

      // Block until initialization is complete or a timeout occurs
      XLOGD_INFO("Waiting for %s thread initialization...", info->name);
      sem_wait(&info->semaphore);
   }
   sem_destroy(params_main.semaphore);
   return(true);
}

void xrsr_threads_term(void) {
   // Clean up the threads
   for(uint32_t index = 0; index < XRSR_THREAD_QTY; index++) {
      xrsr_thread_info_t *info = &g_xrsr.threads[index];

      if(info->msgq_id < 0) {
         continue;
      }

      sem_t semaphore;
      sem_init(&semaphore, 0, 0);
      xrsr_queue_msg_term_t msg;
      msg.header.type = XRSR_QUEUE_MSG_TYPE_TERMINATE;
      msg.semaphore   = &semaphore;

      struct timespec end_time;

      xrsr_queue_msg_push(info->msgq_id, (const char *)&msg, sizeof(msg));

      // Block until termination is acknowledged or a timeout occurs
      XLOGD_INFO("Waiting for %s thread termination...", info->name);
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
         sem_destroy(&semaphore);
         // Wait for thread to exit
         XLOGD_INFO("Waiting for thread to exit");
         void *retval = NULL;
         pthread_join(info->id, &retval);
         XLOGD_INFO("thread exited.");
      }

      // Close message queue
      xrsr_message_queue_close(&info->msgq_id);
   }
}

void xrsr_route_free_all(void) {
   for(uint32_t index = 0; index < XRSR_SRC_INVALID; index++) {
      xrsr_route_free(index, true);
   }
}

void xrsr_route_free(xrsr_src_t src, bool closing) {
   for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[index];

      if(dst->initialized) {
         switch(dst->url_parts.prot) {
            #ifdef HTTP_ENABLED
            case XRSR_PROTOCOL_HTTP:
            case XRSR_PROTOCOL_HTTPS: {
               xrsr_http_term(&dst->conn_state.http, closing);
               dst->initialized = false;
               break;
            }
            #endif
            #ifdef WS_ENABLED
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               if(!closing) {
                  xrsr_ws_term(&dst->conn_state.ws);
               }
               dst->initialized = false;
               break;
            }
            #endif
            #ifdef SDT_ENABLED
            case XRSR_PROTOCOL_SDT: {
               xrsr_sdt_term(&dst->conn_state.sdt);
               break;
            }
            #endif
            default: {
               break;
            }
         }
      }
      dst->handler  = NULL;
      xrsr_url_free(&dst->url_parts);
   }
}

void xrsr_route_update(const char *host_name, const xrsr_route_t *route, xrsr_thread_state_t *state) {
   xrsr_src_t src = route->src;

   if((uint32_t)src >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_WARN("invalid src <%s>", xrsr_src_str(src));
      return;
   }

   xrsr_route_free(src, false);

   if(route->dst_qty == 0) { // Just deleting the route
      return;
   }

   uint32_t index = 0;

   for(uint32_t dst_index = 0; dst_index < route->dst_qty; dst_index++) {
      const xrsr_dst_t *dst = &route->dsts[dst_index];
      const char *                 url             = dst->url;
      uint16_t                     stream_time_min = dst->stream_time_min;
      xraudio_input_record_from_t  stream_from     = XRAUDIO_INPUT_RECORD_FROM_BEGINNING;
      xraudio_input_record_until_t stream_until    = XRAUDIO_INPUT_RECORD_UNTIL_END_OF_STREAM;

      if(index >= XRSR_DST_QTY_MAX) {
         XLOGD_ERROR("maximum destinations exceeded <%u>", index);
         break;
      }

      if((uint32_t)dst->stream_from >= XRSR_STREAM_FROM_INVALID) {
         XLOGD_WARN("invalid stream from <%s>", xrsr_stream_from_str(dst->stream_from));
         return;
      }

      if((uint32_t)dst->stream_until >= XRSR_STREAM_UNTIL_INVALID) {
         XLOGD_WARN("invalid stream until <%s>", xrsr_stream_until_str(dst->stream_until));
         return;
      }

      if(dst->stream_from == XRSR_STREAM_FROM_LIVE) {
         stream_from = XRAUDIO_INPUT_RECORD_FROM_LIVE;
      } else if(dst->stream_from == XRSR_STREAM_FROM_KEYWORD_BEGIN) {
         stream_from = XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN;
      } else if(dst->stream_from == XRSR_STREAM_FROM_KEYWORD_END) {
         stream_from = XRAUDIO_INPUT_RECORD_FROM_KEYWORD_END;
      }

      if(dst->stream_until == XRSR_STREAM_UNTIL_END_OF_SPEECH) {
         stream_until = XRAUDIO_INPUT_RECORD_UNTIL_END_OF_SPEECH;
      } else if(dst->stream_until == XRSR_STREAM_UNTIL_END_OF_KEYWORD) {
         stream_until = XRAUDIO_INPUT_RECORD_UNTIL_END_OF_KEYWORD;
      }

      // Parse url
      xrsr_url_parts_t url_parts;
      if(!xrsr_url_parse(url, &url_parts)) {
         XLOGD_ERROR("invalid url <%s>", url);
         return;
      }

      XLOGD_DEBUG("src <%s> dst qty <%u> index <%u> url <%s> session begin <%p>", xrsr_src_str(route->src), route->dst_qty, dst_index, dst->url, dst->handlers.session_begin);

      xrsr_dst_int_t *dst_int = &g_xrsr.routes[src].dsts[index];

      switch(url_parts.prot) {
         #ifdef HTTP_ENABLED
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            dst_int->handler = xrsr_protocol_handler_http;

            if(!xrsr_http_init(&dst_int->conn_state.http, g_xrsr.http_json_config.debug)) {
               XLOGD_ERROR("http init");
               return;
            }
            dst_int->initialized = true;
            break;
         }
         #endif
         #ifdef WS_ENABLED
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            dst_int->handler = xrsr_protocol_handler_ws;

            // Set params from json config and allow override per url/powerstate
            for(int i = 0; i < XRSR_POWER_MODE_INVALID; i++) {
               if(dst->params[i] != NULL) {
                  dst_int->dst_param_ptrs[i].debug                  = &dst->params[i]->debug;
                  dst_int->dst_param_ptrs[i].connect_check_interval = &dst->params[i]->connect_check_interval;
                  dst_int->dst_param_ptrs[i].timeout_connect        = &dst->params[i]->timeout_connect;
                  dst_int->dst_param_ptrs[i].timeout_inactivity     = &dst->params[i]->timeout_inactivity;
                  dst_int->dst_param_ptrs[i].timeout_session        = &dst->params[i]->timeout_session;
                  dst_int->dst_param_ptrs[i].ipv4_fallback          = &dst->params[i]->ipv4_fallback;
                  dst_int->dst_param_ptrs[i].backoff_delay          = &dst->params[i]->backoff_delay;
               } else {
                  dst_int->dst_param_ptrs[i].debug                  = g_xrsr.ws_json_config->ptr_debug;
                  dst_int->dst_param_ptrs[i].connect_check_interval = g_xrsr.ws_json_config->ptr_connect_check_interval;
                  dst_int->dst_param_ptrs[i].timeout_connect        = g_xrsr.ws_json_config->ptr_timeout_connect;
                  dst_int->dst_param_ptrs[i].timeout_inactivity     = g_xrsr.ws_json_config->ptr_timeout_inactivity;
                  dst_int->dst_param_ptrs[i].timeout_session        = g_xrsr.ws_json_config->ptr_timeout_session;
                  dst_int->dst_param_ptrs[i].ipv4_fallback          = g_xrsr.ws_json_config->ptr_ipv4_fallback;
                  dst_int->dst_param_ptrs[i].backoff_delay          = g_xrsr.ws_json_config->ptr_backoff_delay;
               }
            }

            xrsr_ws_params_t params;
            params.prot               = url_parts.prot;
            params.host_name          = host_name;
            params.timer_obj          = state->timer_obj;
            params.dst_params         = &dst_int->dst_param_ptrs[g_xrsr.power_mode];

            if(!xrsr_ws_init(&dst_int->conn_state.ws, &params)) {
               XLOGD_ERROR("ws init");
               return;
            }
            dst_int->initialized = true;
            dst_int->conn_state.ws.session_config_update = &g_xrsr.sessions[xrsr_source_to_group(src)].session_config_update;
            break;
         }
         #endif
         #ifdef SDT_ENABLED
         case XRSR_PROTOCOL_SDT: {
           dst_int->handler = xrsr_protocol_handler_sdt;
           xrsr_sdt_params_t params;
           params.prot               = url_parts.prot;
           params.host_name          = host_name;
           params.timer_obj          = state->timer_obj;

            if(!xrsr_sdt_init(&dst_int->conn_state.sdt, &params)) {
               XLOGD_ERROR("xrsr sdt init failed");
               return;
            }
            break;
         }
         #endif
         default: {
            XLOGD_ERROR("invalid protocol <%s>", xrsr_protocol_str(url_parts.prot));
            xrsr_url_free(&url_parts);
            return;
         }
      }

      // Add new route
      dst_int->url_parts        = url_parts;
      dst_int->handlers         = dst->handlers;
      dst_int->formats          = dst->formats;
      dst_int->stream_time_min  = stream_time_min;
      dst_int->stream_from      = stream_from;
      dst_int->stream_offset    = dst->stream_offset;
      dst_int->stream_until     = stream_until;
      dst_int->keyword_begin    = 0;
      dst_int->keyword_duration = 0;

      index++;
   }
}

bool xrsr_route(const xrsr_route_t routes[]) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   if(routes == NULL) {
      XLOGD_ERROR("invalid parameter");
      return(false);
   }

   uint32_t index = 0;
   do {
      if(routes[index].src >= XRSR_SRC_INVALID) {
         break;
      }
      XLOGD_INFO("%u: src <%s>", index, xrsr_src_str(routes[index].src));

      if(routes[index].dst_qty < 1 || routes[index].dst_qty > XRSR_DST_QTY_MAX) {
         XLOGD_ERROR("invalid dsts array");
         break;
      }

      for(uint32_t dst_index = 0; dst_index < routes[index].dst_qty; dst_index++) {
         const xrsr_dst_t *dst = &routes[index].dsts[dst_index];
         XLOGD_INFO("dst <%s> audio format <%s>", dst->url, xrsr_audio_format_bitmask_str(dst->formats));
      }

      index++;
   } while(1);

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the route information
   xrsr_queue_msg_route_update_t msg;
   msg.header.type = XRSR_QUEUE_MSG_TYPE_ROUTE_UPDATE;
   msg.semaphore   = &semaphore;
   msg.routes      = routes;
   msg.host_name   = NULL;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   return(true);
}

bool xrsr_host_name_set(const char *host_name) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the keyword information
   xrsr_queue_msg_host_name_update_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_HOST_NAME_UPDATE;
   msg.semaphore      = &semaphore;
   msg.host_name      = host_name;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   return(true);
}

bool xrsr_keyword_config_set(const xrsr_keyword_config_t *keyword_config) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   if(keyword_config == NULL) {
      XLOGD_ERROR("invalid parameter");
      return(false);
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the keyword information
   xrsr_queue_msg_keyword_update_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_KEYWORD_UPDATE;
   msg.semaphore      = &semaphore;
   msg.keyword_config = keyword_config;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   return(true);
}

bool xrsr_keyword_sensitivity_limits_get(float *sensitivity_min, float *sensitivity_max) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   if(sensitivity_min == NULL || sensitivity_max == NULL) {
      XLOGD_ERROR("invalid parameters");
      return(false);
   }

   bool result = false;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Get the keyword detector sensitivity limits
   xrsr_queue_msg_keyword_sensitivity_limits_get_t msg;
   msg.header.type      = XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECT_SENSITIVITY_LIMITS_GET;
   msg.semaphore        = &semaphore;
   msg.sensitivity_min  = sensitivity_min;
   msg.sensitivity_max  = sensitivity_max;
   msg.result           = &result;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   return(result);
}

bool xrsr_capture_config_set(const xrsr_capture_config_t *capture_config) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   if(capture_config == NULL) {
      XLOGD_ERROR("invalid parameter");
      return(false);
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the capture configuration information
   xrsr_queue_msg_capture_config_update_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_CAPTURE_CONFIG_UPDATE;
   msg.semaphore      = &semaphore;
   msg.capture_config = capture_config;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   return(true);
}

bool xrsr_capture_config_apply(const xrsr_capture_config_t *capture_config) {
   if(capture_config->delete_files) {
      xrsr_xraudio_internal_capture_delete_files(g_xrsr.xrsr_xraudio_object, capture_config->dir_path);
   }
   if(capture_config->enable) {
      XLOGD_INFO("delete files <%s> enable <YES> curtail <%s> file qty max <%u> size max <%u>", capture_config->delete_files ? "YES" : "NO", capture_config->use_curtail ? "YES" : "NO", capture_config->file_qty_max, capture_config->file_size_max);
      xraudio_internal_capture_params_t capture_params;
      capture_params.enable        = capture_config->enable;
      capture_params.use_curtail   = capture_config->use_curtail;
      capture_params.file_qty_max  = capture_config->file_qty_max;
      capture_params.file_size_max = capture_config->file_size_max;

      if(capture_config->dir_path == NULL) {
         XLOGD_ERROR("dir path is NULL");
         return(false);
      } else {
         if(g_xrsr.capture_dir_path != NULL) {
            free(g_xrsr.capture_dir_path);
         }
         g_xrsr.capture_dir_path = strdup(capture_config->dir_path);

         if(g_xrsr.capture_dir_path == NULL) {
            XLOGD_ERROR("out of memory");
            return(false);
         } else {
            capture_params.dir_path = g_xrsr.capture_dir_path;
            xrsr_xraudio_internal_capture_params_set(g_xrsr.xrsr_xraudio_object, &capture_params);
         }
      }
   } else {
      XLOGD_INFO("delete files <%s> enable <NO>", capture_config->delete_files ? "YES" : "NO");
   }
   return(true);
}

bool xrsr_power_mode_set(xrsr_power_mode_t power_mode) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   if((uint32_t)power_mode >= XRSR_POWER_MODE_INVALID) {
      XLOGD_ERROR("invalid power mode <%s>", xrsr_power_mode_str(power_mode));
      return(false);
   }
   if(g_xrsr.power_mode == power_mode) {
      return(true);
   }

   bool result = false;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the power mode
   xrsr_queue_msg_power_mode_update_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_POWER_MODE_UPDATE;
   msg.semaphore      = &semaphore;
   msg.power_mode     = power_mode;
   msg.result         = &result;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   if(result) {
      g_xrsr.power_mode = power_mode;

      #ifdef WS_ENABLED
      g_xrsr.ws_json_config = (XRSR_POWER_MODE_LOW==power_mode) ? &g_xrsr.ws_json_config_lpm : &g_xrsr.ws_json_config_fpm;
      #endif
   }

   return(result);
}

bool xrsr_privacy_mode_set(bool enable) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   if(g_xrsr.privacy_mode == enable) {
      XLOGD_WARN("already %s", enable ? "enabled" : "disabled");
      return(true);
   }

   bool result = false;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the privacy mode
   xrsr_queue_msg_privacy_mode_update_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_PRIVACY_MODE_UPDATE;
   msg.semaphore      = &semaphore;
   msg.enable         = enable;
   msg.result         = &result;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   if(result) {
      g_xrsr.privacy_mode = enable;
   }

   return(result);
}

bool xrsr_privacy_mode_get(bool *enabled) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }

   bool result = false;
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Get the privacy mode
   xrsr_queue_msg_privacy_mode_get_t msg;
   msg.header.type = XRSR_QUEUE_MSG_TYPE_PRIVACY_MODE_GET;
   msg.semaphore   = &semaphore;
   msg.enabled     = enabled;
   msg.result      = &result;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   if(!result) {
      XLOGD_ERROR("failed to get privacy mode");
   } else {
      g_xrsr.privacy_mode = *enabled;
   }

   return(result);
}

bool xrsr_mask_pii_set(bool enable) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }
   if(g_xrsr.mask_pii == enable) {
      XLOGD_WARN("already %s", enable ? "enabled" : "disabled");
      return(true);
   }

   g_xrsr.mask_pii = enable;

   return(true);
}

bool xrsr_mask_pii(void) {
   return(g_xrsr.mask_pii);
}

void *xrsr_thread_main(void *param) {
   xrsr_thread_params_t params = *((xrsr_thread_params_t *)param);
   char msg[XRSR_MSG_QUEUE_MSG_SIZE_MAX];

   xrsr_thread_state_t state;
   state.running               = true;
   state.timer_obj             = rdkx_timer_create(16, true, !params.is_prod);

   if(state.timer_obj == NULL) {
      XLOGD_ERROR("timer create");
      return(NULL);
   }

   // Unblock the caller that launched this thread
   sem_post(params.semaphore);
   params.semaphore = NULL;

   XLOGD_INFO("Enter main loop");

   do {
      int src;
      int nfds = params.msgq_id + 1;

      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(params.msgq_id, &rfds);

      fd_set wfds;
      FD_ZERO(&wfds);

      // Add fd's for all open connections
      for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
         for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
            xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

            if(dst->handler == NULL) {
               continue;
            }
            switch(dst->url_parts.prot) {
               #ifdef HTTP_ENABLED
               case XRSR_PROTOCOL_HTTP:
               case XRSR_PROTOCOL_HTTPS: {
                  xrsr_state_http_t *http = &dst->conn_state.http;

                  if(xrsr_http_is_connected(http)) {
                     xrsr_http_fd_set(http, 1, &nfds, &rfds, &wfds, NULL);
                  }
                  break;
               }
               #endif
               #ifdef WS_ENABLED
               case XRSR_PROTOCOL_WS:
               case XRSR_PROTOCOL_WSS: {
                  xrsr_state_ws_t *ws = &dst->conn_state.ws;
                  if(xrsr_ws_is_established(ws)) {
                     xrsr_ws_fd_set(ws, &nfds, &rfds, &wfds, NULL);
                  }
                  break;
               }
               #endif
               #ifdef SDT_ENABLED
               case XRSR_PROTOCOL_SDT: {
                  xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
                  if(xrsr_sdt_is_established(sdt)) {
                     xrsr_sdt_fd_set(sdt, &nfds, &rfds, &wfds, NULL);
                  }
                  break;
               }
               #endif

               default: {
                  break;
               }
            }
         }
      }

      struct timeval tv;
      rdkx_timer_handler_t handler = NULL;
      void *data = NULL;
      rdkx_timer_id_t timer_id = rdkx_timer_next_get(state.timer_obj, &tv, &handler, &data);

      errno = 0;
      if(timer_id >= 0) {
         XLOGD_DEBUG("timer id <%d> timeout %d secs %d microsecs", timer_id, tv.tv_sec, tv.tv_usec);
         if(tv.tv_sec == 0 && tv.tv_usec == 0) { // Process the expired timer instead of calling select().
            src = 0;
         } else {
            src = select(nfds, &rfds, &wfds, NULL, &tv);
         }
      } else {
         XLOGD_DEBUG("no timeout set");
         src = select(nfds, &rfds, &wfds, NULL, NULL);
      }

      if(src < 0) { // error occurred
         int errsv = errno;
         XLOGD_ERROR("select failed, rc <%s>", strerror(errsv));
         break;
      } else if(src == 0) { // timeout occurred
         XLOGD_DEBUG("timeout occurred");
         if(handler == NULL) {
            XLOGD_ERROR("invalid timer - handler <%p> data <%p>", handler, data);
            if(!rdkx_timer_remove(state.timer_obj, timer_id)) {
               XLOGD_ERROR("timer remove");
            }
         } else {
            (*handler)(data);
         }
         
         continue;
      }
      if(FD_ISSET(params.msgq_id, &rfds)) {
         ssize_t bytes_read = xr_mq_pop(params.msgq_id, msg, sizeof(msg));
         if(bytes_read <= 0) {
            XLOGD_ERROR("mq_receive failed, rc <%d>", bytes_read);
         } else {
            xrsr_queue_msg_header_t *header = (xrsr_queue_msg_header_t *)msg;

            if((uint32_t)header->type >= XRSR_QUEUE_MSG_TYPE_INVALID) {
               XLOGD_ERROR("invalid msg type <%s>", xrsr_queue_msg_type_str(header->type));
            } else {
               XLOGD_DEBUG("msg type <%s>", xrsr_queue_msg_type_str(header->type));
               (*g_xrsr_msg_handlers[header->type])(&params, &state, msg);
            }
         }
      }

      // Check fd's for all open connections
      for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
         for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
            xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

            switch(dst->url_parts.prot) {
               #ifdef HTTP_ENABLED
               case XRSR_PROTOCOL_HTTP:
               case XRSR_PROTOCOL_HTTPS: {
                  xrsr_state_http_t *http = &dst->conn_state.http;
                  if(xrsr_http_is_connected(http)) {
                     xrsr_http_handle_fds(http, 1, &rfds, &wfds, NULL);
                  }
                  break;
               }
               #endif
               #ifdef WS_ENABLED
               case XRSR_PROTOCOL_WS:
               case XRSR_PROTOCOL_WSS: {
                  xrsr_state_ws_t *ws = &dst->conn_state.ws;
                  if(!xrsr_ws_is_disconnected(ws)) {
                     xrsr_ws_handle_fds(ws, &rfds, &wfds, NULL);
                  }
                  break;
               }
               #endif
               #ifdef SDT_ENABLED
               case XRSR_PROTOCOL_SDT: {
                  xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
                  if(!xrsr_sdt_is_disconnected(sdt)) {
                     xrsr_sdt_handle_fds(sdt, &rfds, &wfds, NULL);
                  }
                  break;
               }
               #endif

               default: {
                  break;
               }
            }
         }
      }
   } while(state.running);

   // Terminate all open connections
   for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
      for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

         switch(dst->url_parts.prot) {
            #ifdef HTTP_ENABLED
            case XRSR_PROTOCOL_HTTP:
            case XRSR_PROTOCOL_HTTPS: {
               //xrsr_state_http_t *http = &dst->conn_state.http;
               break;
            }
            #endif
            #ifdef WS_ENABLED
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               xrsr_state_ws_t *ws = &dst->conn_state.ws;
               xrsr_ws_term(ws);
               break;
            }
            #endif
            #ifdef SDT_ENABLED
            case XRSR_PROTOCOL_SDT: {
               xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
               xrsr_sdt_term(sdt);
               break;
            }
            #endif

            default: {
               break;
            }
         }
      }
   }

   rdkx_timer_destroy(state.timer_obj);

   return(NULL);
}

int xrsr_msgq_fd_get(void) {
   return(g_xrsr.threads[XRSR_THREAD_MAIN].msgq_id);
}

void xrsr_msg_terminate(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_term_t *term = (xrsr_queue_msg_term_t *)msg;
   if(term->semaphore != NULL) {
      sem_post(term->semaphore);
   }
   state->running = false;
}

void xrsr_msg_route_update(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_route_update_t *route_update = (xrsr_queue_msg_route_update_t *)msg;
   xrsr_src_t srcs[XRSR_SRC_INVALID+1];
   uint32_t index = 0;
   do {
      xrsr_src_t src = route_update->routes[index].src;
      if(src >= XRSR_SRC_INVALID) {
         break;
      }
      XLOGD_INFO("%u: src <%s>", index, xrsr_src_str(src));

      if(xrsr_is_source_active(src)) { // Terminate active session on this source since it is being altered
         XLOGD_INFO("terminate source <%s>", xrsr_src_str(src));
         xrsr_queue_msg_session_terminate_t terminate;
         terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
         terminate.semaphore   = NULL;
         terminate.src         = src;
         xrsr_msg_session_terminate(params, state, &terminate);
      }

      xrsr_route_update(route_update->host_name, &route_update->routes[index], state);
      srcs[index] = src;
      index++;
   } while(1);

   srcs[index] = XRSR_SRC_INVALID;

   if(index == 0) {
      XLOGD_INFO("removing all routes");
   }

   xrsr_xraudio_device_update(g_xrsr.xrsr_xraudio_object, srcs);

   if(route_update->semaphore != NULL) {
      sem_post(route_update->semaphore);
   }
}

bool xrsr_session_request(xrsr_src_t src, xrsr_audio_format_t output_format, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util) {
   if(input_format.type >= XRSR_SESSION_REQUEST_TYPE_INVALID) {
      XLOGD_INFO("unsupported input format <%s>", xrsr_session_request_type_str(input_format.type));
      return(false);
   }
   xrsr_audio_format_type_t output_format_type = output_format.type;
   xraudio_input_format_t xraudio_format;
   xraudio_format.container     = XRAUDIO_CONTAINER_NONE;
   xraudio_format.encoding.type = (output_format_type == XRSR_AUDIO_FORMAT_PCM_RAW) ? XRAUDIO_ENCODING_PCM_RAW : (output_format_type == XRSR_AUDIO_FORMAT_OPUS) ? XRAUDIO_ENCODING_OPUS : XRAUDIO_ENCODING_PCM;
   xraudio_format.sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE;
   xraudio_format.sample_size   = (output_format_type == XRSR_AUDIO_FORMAT_PCM_RAW || output_format_type == XRSR_AUDIO_FORMAT_PCM_32_BIT || output_format_type == XRSR_AUDIO_FORMAT_PCM_32_BIT_MULTI) ? XRAUDIO_INPUT_MAX_SAMPLE_SIZE : XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE;
   xraudio_format.channel_qty   = (output_format_type == XRSR_AUDIO_FORMAT_PCM_RAW || output_format_type == XRSR_AUDIO_FORMAT_PCM_32_BIT_MULTI) ? XRAUDIO_INPUT_MAX_CHANNEL_QTY : XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY;

   if(input_format.type == XRSR_SESSION_REQUEST_TYPE_AUDIO_MIC) {
      if(input_format.value.audio_mic.stream_params_required == true ) {
         xrsr_session_config_update_t *session_config_update = &g_xrsr.sessions[xrsr_source_to_group(src)].session_config_update;
         session_config_update->update_required = true;
         input_format.value.audio_mic.dynamic_gain_update = &session_config_update->dynamic_gain;
      }
   }

   return(xrsr_xraudio_session_request(g_xrsr.xrsr_xraudio_object, src, xraudio_format, input_format, uuid, low_latency, low_cpu_util));
}

bool xrsr_session_audio_fd_set(xrsr_src_t src, int fd, xrsr_audio_format_t audio_format, xrsr_input_data_read_cb_t callback, void *user_data) {
   if(src != XRSR_SRC_RCU_PTT && src != XRSR_SRC_RCU_FF) {
      XLOGD_ERROR("unsupported source <%s>", xrsr_src_str(src));
      return(false);
   }

   return(xrsr_xraudio_input_source_fd_set(g_xrsr.xrsr_xraudio_object, src, fd, audio_format, callback, user_data));
}

bool xrsr_session_keyword_info_set(xrsr_src_t src, uint32_t keyword_begin, uint32_t keyword_duration) {
   if(src != XRSR_SRC_RCU_FF) {
      XLOGD_INFO("unsupported source <%s>", xrsr_src_str(src));
      return(false);
   }
   for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
      g_xrsr.routes[src].dsts[index].keyword_begin    = keyword_begin;
      g_xrsr.routes[src].dsts[index].keyword_duration = keyword_duration;
   }
   return(true);
}

bool xrsr_session_capture_start(xrsr_audio_container_t container, const char *file_path, bool raw_mic_enable) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the keyword information
   xrsr_queue_msg_session_capture_start_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_START;
   msg.semaphore      = &semaphore;
   msg.container      = container;
   msg.file_path      = file_path;
   msg.raw_mic_enable = raw_mic_enable;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   return(true);
}

bool xrsr_session_capture_stop(void) {
   if(!g_xrsr.opened) {
      XLOGD_ERROR("not opened");
      return(false);
   }

   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   // Send the keyword information
   xrsr_queue_msg_session_capture_stop_t msg;
   msg.header.type    = XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_STOP;
   msg.semaphore      = &semaphore;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
   sem_wait(&semaphore);
   sem_destroy(&semaphore);

   return(true);
}

void xrsr_session_terminate(xrsr_src_t src) {
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xrsr_queue_msg_session_terminate_t terminate;
   terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
   terminate.semaphore   = &semaphore;
   terminate.src         = src;
   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&terminate, sizeof(terminate));

   sem_wait(&semaphore);
   sem_destroy(&semaphore);
}

void xrsr_session_audio_stream_start(xrsr_src_t src) {
   sem_t semaphore;
   sem_init(&semaphore, 0, 0);

   xrsr_queue_msg_session_audio_stream_start_t audio_stream_start;
   audio_stream_start.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_AUDIO_STREAM_START;
   audio_stream_start.semaphore   = &semaphore;
   audio_stream_start.src         = src;
   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&audio_stream_start, sizeof(audio_stream_start));

   sem_wait(&semaphore);
   sem_destroy(&semaphore);
}

void xrsr_msg_keyword_update(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_keyword_update_t *keyword_update = (xrsr_queue_msg_keyword_update_t *)msg;
   if(keyword_update->keyword_config == NULL) {
      XLOGD_ERROR("NULL keyword config");
   } else {
      xrsr_xraudio_keyword_detect_params(g_xrsr.xrsr_xraudio_object, XRSR_KEYWORD_PHRASE, (xraudio_keyword_sensitivity_t)keyword_update->keyword_config->sensitivity);
   }
   if(keyword_update->semaphore != NULL) {
      sem_post(keyword_update->semaphore);
   }
}

void xrsr_msg_host_name_update(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_host_name_update_t *host_name_update = (xrsr_queue_msg_host_name_update_t *)msg;

   for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
      for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

         switch(dst->url_parts.prot) {
            #ifdef HTTP_ENABLED
            case XRSR_PROTOCOL_HTTP:
            case XRSR_PROTOCOL_HTTPS: {
               //xrsr_state_http_t *http = &dst->conn_state.http;
               break;
            }
            #endif
            #ifdef WS_ENABLED
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               xrsr_state_ws_t *ws = &dst->conn_state.ws;
               xrsr_ws_host_name_set(ws, host_name_update->host_name);
               break;
            }
            #endif
            default: {
               break;
            }
         }
      }
   }

   if(host_name_update->semaphore != NULL) {
      sem_post(host_name_update->semaphore);
   }
}

void xrsr_msg_capture_config_update(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_capture_config_update_t *capture_config_update = (xrsr_queue_msg_capture_config_update_t *)msg;
   if(capture_config_update->capture_config == NULL) {
      XLOGD_ERROR("NULL capture config");
   } else {
      if(!xrsr_capture_config_apply(capture_config_update->capture_config)) {
         XLOGD_ERROR("unable to apply capture config");
      }
   }
   if(capture_config_update->semaphore != NULL) {
      sem_post(capture_config_update->semaphore);
   }
}

void xrsr_msg_power_mode_update(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_power_mode_update_t *power_mode_update = (xrsr_queue_msg_power_mode_update_t *)msg;

   XLOGD_INFO("power mode <%s>", xrsr_power_mode_str(power_mode_update->power_mode));

   if(power_mode_update->power_mode != XRSR_POWER_MODE_FULL) { // Terminate active sessions
      for(uint32_t group = 0; group < XRSR_SESSION_GROUP_QTY; group++) {
         xrsr_session_t *session = &g_xrsr.sessions[group];
         if((uint32_t)session->src < XRSR_SRC_INVALID) {
            XLOGD_INFO("terminate source <%s>", xrsr_src_str(session->src));
            xrsr_queue_msg_session_terminate_t terminate;
            terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
            terminate.semaphore   = NULL;
            terminate.src         = session->src;
            xrsr_msg_session_terminate(params, state, &terminate);
         }
      }
   }
   
   // Update the dst params for the new power mode
   for(uint32_t index_src = 0; index_src < XRSR_SRC_INVALID; index_src++) {
      for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

         switch(dst->url_parts.prot) {
            #ifdef WS_ENABLED
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               xrsr_state_ws_t *ws = &dst->conn_state.ws;
               xrsr_ws_update_dst_params(ws, &dst->dst_param_ptrs[power_mode_update->power_mode]);
               break;
            }
            #endif
            default: {
               break;
            }
         }
      }
   }

   bool result = xrsr_xraudio_power_mode_update(g_xrsr.xrsr_xraudio_object, power_mode_update->power_mode);

   if(power_mode_update->semaphore != NULL) {
      if(power_mode_update->result != NULL) {
         *(power_mode_update->result) = result;
      }
      sem_post(power_mode_update->semaphore);
   }
}

void xrsr_msg_privacy_mode_update(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_privacy_mode_update_t *privacy_mode_update = (xrsr_queue_msg_privacy_mode_update_t *)msg;

   XLOGD_INFO("privacy mode <%s>", privacy_mode_update->enable ? "ENABLE" : "DISABLE");

   bool result = xrsr_xraudio_privacy_mode_update(g_xrsr.xrsr_xraudio_object, privacy_mode_update->enable);

   if(privacy_mode_update->semaphore != NULL) {
      if(privacy_mode_update->result != NULL) {
         *(privacy_mode_update->result) = result;
      }
      sem_post(privacy_mode_update->semaphore);
   }
}

void xrsr_msg_xraudio_granted(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_xraudio_device_granted(g_xrsr.xrsr_xraudio_object);
}

void xrsr_msg_xraudio_revoked(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
#ifdef XRAUDIO_RESOURCE_MGMT
   xrsr_xraudio_device_revoked(g_xrsr.xrsr_xraudio_object);
#endif
}

void xrsr_msg_xraudio_event(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_xraudio_in_event_t *event = (xrsr_queue_msg_xraudio_in_event_t *)msg;

   if(event == NULL) {
      XLOGD_ERROR("invalid event");
      return;
   }

   xrsr_src_t src = event->event.src;

   if((uint32_t)src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }

   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("inactive source <%s>", xrsr_src_str(src));
      return;
   }

   if(event->event.event != XRSR_EVENT_INVALID) {
      if(event->event.event == XRSR_EVENT_STREAM_ERROR) {
         xrsr_xraudio_device_close(g_xrsr.xrsr_xraudio_object);
         if(xrsr_is_source_active(src)) { // Terminate active session on this source since an error occurred
            XLOGD_INFO("terminate source <%s>", xrsr_src_str(src));
            xrsr_queue_msg_session_terminate_t terminate;
            terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
            terminate.semaphore   = NULL;
            terminate.src         = src;
            xrsr_msg_session_terminate(params, state, &terminate);
         }
         #ifdef XRAUDIO_RESOURCE_MGMT
         xrsr_xraudio_device_request(g_xrsr.xrsr_xraudio_object);
         #else
         xrsr_xraudio_device_granted(g_xrsr.xrsr_xraudio_object);
         #endif
         return;
      }
      uint32_t index_src = src;
      for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

         switch(dst->url_parts.prot) {
            #ifdef HTTP_ENABLED
            case XRSR_PROTOCOL_HTTP:
            case XRSR_PROTOCOL_HTTPS: {
               xrsr_state_http_t *http = &dst->conn_state.http;
               xrsr_http_handle_speech_event(http, &event->event);
               break;
            }
            #endif
            #ifdef WS_ENABLED
            case XRSR_PROTOCOL_WS:
            case XRSR_PROTOCOL_WSS: {
               xrsr_state_ws_t *ws = &dst->conn_state.ws;
               xrsr_ws_handle_speech_event(ws, &event->event);
               break;
            }
            #endif
            #ifdef SDT_ENABLED
            case XRSR_PROTOCOL_SDT: {
               xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
               xrsr_sdt_handle_speech_event(sdt, &event->event);
               break;
            }
            #endif
            default: {
               break;
            }
         }
      }
   }
}

void xrsr_msg_keyword_detected(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_keyword_detected_t *keyword_detected = (xrsr_queue_msg_keyword_detected_t *)msg;

   xrsr_src_t src = xrsr_xraudio_src_to_xrsr(keyword_detected->source);

   xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(src)];

   bool audio_stream_start = false;

   xrsr_xraudio_keyword_detected(g_xrsr.xrsr_xraudio_object, keyword_detected, session->src, session->requested_more_audio, &audio_stream_start);

   if(audio_stream_start) {
      xrsr_queue_msg_session_audio_stream_start_t audio_stream_start;
      audio_stream_start.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_AUDIO_STREAM_START;
      audio_stream_start.semaphore   = NULL;
      audio_stream_start.src         = src;

      xrsr_msg_session_audio_stream_start(params, state, &audio_stream_start);
   }
}

void xrsr_msg_keyword_detect_error(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_keyword_detected_t *keyword_detected = (xrsr_queue_msg_keyword_detected_t *)msg;

   xrsr_xraudio_keyword_detect_error(g_xrsr.xrsr_xraudio_object, keyword_detected->source);

   if(xrsr_is_source_active(keyword_detected->source)) { // Terminate active session on this source since an error occurred
      XLOGD_INFO("terminate source <%s>", xrsr_src_str(keyword_detected->source));
      xrsr_queue_msg_session_terminate_t terminate;
      terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
      terminate.semaphore   = NULL;
      terminate.src         = keyword_detected->source;
      xrsr_msg_session_terminate(params, state, &terminate);
   }

   #ifdef MICROPHONE_TAP_ENABLED
   if(keyword_detected->source == XRSR_SRC_MICROPHONE && xrsr_is_source_active(XRSR_SRC_MICROPHONE_TAP)) { // Terminate active session on this source since an error occurred
      XLOGD_INFO("terminate source <%s>", xrsr_src_str(XRSR_SRC_MICROPHONE_TAP));
      xrsr_queue_msg_session_terminate_t terminate;
      terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
      terminate.semaphore   = NULL;
      terminate.src         = XRSR_SRC_MICROPHONE_TAP;
      xrsr_msg_session_terminate(params, state, &terminate);
   }
   #endif
}

void xrsr_msg_keyword_detect_sensitivity_limits_get(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_keyword_sensitivity_limits_get_t *keyword_sensitivity_limits_get = (xrsr_queue_msg_keyword_sensitivity_limits_get_t *)msg;

   bool result = xrsr_xraudio_keyword_detect_sensitivity_limits_get(g_xrsr.xrsr_xraudio_object, keyword_sensitivity_limits_get->sensitivity_min, keyword_sensitivity_limits_get->sensitivity_max);

   if(keyword_sensitivity_limits_get->semaphore != NULL) {
      if(keyword_sensitivity_limits_get->result != NULL) {
         *(keyword_sensitivity_limits_get->result) = result;
      }
      sem_post(keyword_sensitivity_limits_get->semaphore);
   }
}

void xrsr_msg_session_begin(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_begin_t *begin = (xrsr_queue_msg_session_begin_t *)msg;

   if(begin->src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(begin->src));
      return;
   }
   if(xrsr_is_source_active(begin->src) && !begin->retry) { // Keyword was triggered again from same source while previous session is in progress
      #ifdef XRSR_SESSION_RETRIGGER_ABORT
      // terminate current session and start a new one
      XLOGD_INFO("aborting current session in progress on source <%s>", xrsr_src_str(begin->src));
      xrsr_queue_msg_session_terminate_t terminate;
      terminate.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE;
      terminate.semaphore   = NULL;
      terminate.src         = begin->src;
      xrsr_msg_session_terminate(params, state, &terminate);

      // TODO Need to set a flag to restart a new session immediately after the current session terminates

      #else // ignore the keyword detection and restart the detector
      XLOGD_INFO("ignoring due to current session in progress on source <%s>", xrsr_src_str(begin->src));

      if(xrsr_has_keyword_detector(begin->src)) { // Need to restart the keyword detector again
         xrsr_xraudio_keyword_detect_restart(g_xrsr.xrsr_xraudio_object);
      }
      #endif
      return;
   }
   uint32_t group = xrsr_source_to_group(begin->src);
   xrsr_session_t *session = &g_xrsr.sessions[group];

   if(xrsr_is_group_active(group) && !begin->retry) {
      XLOGD_ERROR("session in progress on source <%s>", xrsr_src_str(session->src));
      return;
   }
   session->src                  = begin->src;

   xrsr_keyword_detector_result_t *detector_result_ptr = NULL;
   xrsr_keyword_detector_result_t  detector_result;
   if(begin->has_result) {
      if(begin->detector_result.chan_selected >= XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
         XLOGD_ERROR("invalid selected channel <%u>", begin->detector_result.chan_selected);
      } else {
         detector_result.score                = begin->detector_result.channels[begin->detector_result.chan_selected].score;
         detector_result.snr                  = begin->detector_result.channels[begin->detector_result.chan_selected].snr;
         detector_result.doa                  = begin->detector_result.channels[begin->detector_result.chan_selected].doa;
         detector_result.offset_buf_begin     = begin->detector_result.endpoints.pre;
         detector_result.offset_kwd_begin     = begin->detector_result.endpoints.begin;
         detector_result.offset_kwd_end       = begin->detector_result.endpoints.end;
         detector_result.kwd_gain             = begin->detector_result.endpoints.kwd_gain;
         detector_result.detector_name        = begin->detector_result.detector_name;
         detector_result.dsp_name             = begin->detector_result.dsp_name;
         detector_result.dynamic_gain         = begin->detector_result.channels[begin->detector_result.chan_selected].dynamic_gain;
         detector_result.dynamic_gain_update  = begin->detector_result.dynamic_gain_update;
         detector_result.sensitivity          = begin->detector_result.sensitivity;

         detector_result_ptr   = &detector_result;

         XLOGD_INFO("selected kwd channel <%u> gain <%f> buf begin <%d> kwd begin <%d> end <%d>", begin->detector_result.chan_selected, detector_result.kwd_gain, detector_result.offset_buf_begin, detector_result.offset_kwd_begin, detector_result.offset_kwd_end);
         for(uint32_t chan = 0; chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY; chan++) {
            xraudio_kwd_chan_result_t *chan_result = &begin->detector_result.channels[chan];
            if(chan_result->score >= 0.0) {
               XLOGD_INFO("chan <%u> score <%0.6f> snr <%0.4f> doa <%u> dynamic_gain <%f>", chan, chan_result->score, chan_result->snr, chan_result->doa, chan_result->dynamic_gain);
            }
         }
      }
   }

   const char *transcription_in = (begin->transcription_in[0] == '\0') ? NULL : begin->transcription_in;
   const char *audio_file_in    = (begin->audio_file_in[0]    == '\0') ? NULL : begin->audio_file_in;

   bool create_stream = true;
   for(uint32_t dst_index = 0; dst_index < XRSR_DST_QTY_MAX; dst_index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[session->src].dsts[dst_index];

      if((uint32_t)session->src >= XRSR_SRC_INVALID) { // Source can be released by index 0
         break;
      }
      if(dst->handler == NULL) {
         continue;
      }
      xrsr_protocol_t prot = dst->url_parts.prot;

      switch(prot) {
         #ifdef HTTP_ENABLED
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            xrsr_state_http_t *http = &dst->conn_state.http;
            http->is_session_by_text = (transcription_in != NULL);
            http->is_session_by_file = (audio_file_in    != NULL);
            if(!xrsr_http_is_disconnected(http)) {
               XLOGD_ERROR("invalid state");
               break;
            }

            xrsr_session_config_out_t *session_config = &http->session_config_out;
            memset(&http->session_config_out, 0, sizeof(http->session_config_out));

            if(uuid_is_null(begin->uuid)) {
               uuid_generate(http->uuid);
            } else {
               uuid_copy(http->uuid, begin->uuid);
            }
            char uuid_str[37] = {'\0'};
            uuid_unparse_lower(http->uuid, uuid_str);

            session_config->format            = xrsr_audio_format_get(dst->formats, begin->xraudio_format);
            session_config->user_initiated    = begin->user_initiated;
            session_config->cb_session_config = xrsr_callback_session_config_in_http;

            XLOGD_INFO("src <%s(%u)> prot <%s> uuid <%s> format <%s>", xrsr_src_str(session->src), dst_index, xrsr_protocol_str(prot), uuid_str, xrsr_audio_format_str(session_config->format.type));

            // Set the handlers based on source
            http->handlers       = dst->handlers;
            http->dst_index      = dst_index;
            http->input_format   = begin->input_format;
            http->xraudio_format = begin->xraudio_format;
            http->low_latency    = begin->low_latency;
            http->low_cpu_util   = begin->low_cpu_util;

            if(transcription_in == NULL) {
               http->transcription_ptr = NULL;
            } else {
               errno_t safec_rc = -1;
               safec_rc = strncpy_s(http->transcription_in, sizeof(http->transcription_in), transcription_in, sizeof(http->transcription_in) - 1);
               ERR_CHK(safec_rc);
               http->transcription_in[sizeof(http->transcription_in) - 1] = '\0';
               http->transcription_ptr = &http->transcription_in[0];
            }

            if(http->is_session_by_file) {
               errno_t safec_rc = -1;
               safec_rc = strncpy_s(http->audio_file_in, sizeof(http->audio_file_in), audio_file_in, sizeof(http->audio_file_in) - 1);
               ERR_CHK(safec_rc);
               http->audio_file_in[sizeof(http->audio_file_in) - 1] = '\0';
            }

            // Call session begin handler
            if(!begin->retry && http->handlers.session_begin != NULL) {
               http->session_config_in.http.query_strs[0] = NULL;
               (*http->handlers.session_begin)(http->handlers.data, http->uuid, session->src, dst_index, detector_result_ptr, &http->session_config_out, &http->session_config_in, &begin->timestamp, http->transcription_ptr);
            }

            // Defer until the application sets the session config via the callback.  This must be done asynchronously to avoid deadlock situations.

            if(begin->retry) { // connect again for retries
               bool deferred = ((dst->stream_time_min > 0) && !http->is_session_by_text && !http->is_session_by_file) ? true : false;

               if(!xrsr_http_connect(http, &dst->url_parts, session->src, http->xraudio_format, state->timer_obj, deferred, http->session_config_in.http.query_strs, transcription_in)) {
                  XLOGD_ERROR("http connect failed");
               }
            }
            break;
         }
         #endif
         #ifdef WS_ENABLED
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            ws->is_session_by_text = (transcription_in != NULL);
            ws->is_session_by_file = (audio_file_in    != NULL);
            if(xrsr_ws_is_disconnected(ws)) {
               xrsr_session_config_out_t *session_config = &ws->session_config_out;

               if(!begin->retry) { // Only generate new uuid if it's not a retry attempt
                  if(uuid_is_null(begin->uuid)) {
                     uuid_generate(ws->uuid);
                  } else {
                     uuid_copy(ws->uuid, begin->uuid);
                  }
                  ws->stream_time_min_rxd = false;
               }
               char uuid_str[37] = {'\0'};
               uuid_unparse_lower(ws->uuid, uuid_str);

               session_config->format            = xrsr_audio_format_get(dst->formats, begin->xraudio_format);
               session_config->user_initiated    = begin->user_initiated;
               session_config->cb_session_config = xrsr_callback_session_config_in_ws;

               XLOGD_INFO("src <%s(%u)> prot <%s> uuid <%s> format <%s>", xrsr_src_str(session->src), dst_index, xrsr_protocol_str(prot), uuid_str, xrsr_audio_format_str(session_config->format.type));

               // Set the handlers based on source
               ws->handlers       = dst->handlers;
               ws->dst_index      = dst_index;
               ws->input_format   = begin->input_format;
               ws->xraudio_format = begin->xraudio_format;
               ws->low_latency    = begin->low_latency;
               ws->low_cpu_util   = begin->low_cpu_util;

               if(ws->is_session_by_file) {
                  errno_t safec_rc = -1;
                  safec_rc = strncpy_s(ws->audio_file_in, sizeof(ws->audio_file_in), audio_file_in, sizeof(ws->audio_file_in) - 1);
                  ERR_CHK(safec_rc);
                  ws->audio_file_in[sizeof(ws->audio_file_in) - 1] = '\0';
               }

               if(!begin->retry && ws->handlers.session_begin != NULL) { // Call session begin handler
                  ws->session_config_in.ws.query_strs[0] = NULL;

                  (*ws->handlers.session_begin)(ws->handlers.data, ws->uuid, session->src, dst_index, detector_result_ptr, &ws->session_config_out, &ws->session_config_in, &begin->timestamp, transcription_in);
               }

               // Defer audio stream and connect until the application sets the session config via the callback.  This must be done asynchronously to avoid deadlock situations.

               if(begin->retry) { // connect again for retries
                  bool deferred = ((dst->stream_time_min == 0) || ws->is_session_by_text || ws->is_session_by_file) ? false : !ws->stream_time_min_rxd;

                  if(!xrsr_ws_connect(ws, &dst->url_parts, session->src, ws->xraudio_format, begin->user_initiated, begin->retry, deferred, ws->session_config_in.ws.query_strs)) {
                     XLOGD_ERROR("ws connect");
                  }
               }
            } else if(xrsr_ws_is_established(ws)) {
               XLOGD_INFO("ws session continue");
               if(!xrsr_ws_audio_stream(ws, session->src, create_stream, false)) {
                  XLOGD_ERROR("ws audio stream");
               }
               create_stream = false;
            } else {
               XLOGD_ERROR("invalid state");
            }
            break;
         }
         #endif

         #ifdef SDT_ENABLED
         case XRSR_PROTOCOL_SDT: {
            xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
            if(xrsr_sdt_is_disconnected(sdt)){
               xrsr_session_config_out_t *session_config = &sdt->session_config_out;

               if(uuid_is_null(begin->uuid)) {
                  uuid_generate(sdt->uuid);
               } else {
                  uuid_copy(sdt->uuid, begin->uuid);
               }
               sdt->stream_time_min_rxd = false;
               
               char uuid_str[37] = {'\0'};
               uuid_unparse_lower(sdt->uuid, uuid_str);

               session_config->format            = xrsr_audio_format_get(dst->formats, begin->xraudio_format);
               session_config->cb_session_config = NULL;

               XLOGD_INFO("src <%s(%u)> prot <%s> uuid <%s> format <%s>", xrsr_src_str(session->src), dst_index, xrsr_protocol_str(prot), uuid_str, xrsr_audio_format_str(session_config->format.type));

               // Set the handlers based on source
               sdt->handlers       = dst->handlers;
               sdt->dst_index      = dst_index;
               sdt->input_format   = begin->input_format;
               sdt->xraudio_format = begin->xraudio_format;
               sdt->low_latency    = begin->low_latency;
               sdt->low_cpu_util   = begin->low_cpu_util;

               // Call session begin handler
               session_config->user_initiated = begin->user_initiated;

               if(transcription_in == NULL) {
                  int pipe_fd_read = -1;

                  if(!xrsr_speech_stream_begin(sdt->uuid, session->src, sdt->dst_index, begin->input_format, begin->xraudio_format, begin->user_initiated, begin->low_latency, begin->low_cpu_util, create_stream, false, audio_file_in, &pipe_fd_read)) {
                     XLOGD_ERROR("xrsr_speech_stream_begin failed");
                     // perform clean up of the session
                     xrsr_sdt_speech_session_end(sdt, XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN);
                     break;
                  } else {
                     create_stream = false;
                     sdt->audio_pipe_fd_read = pipe_fd_read;
                  }
               }

               bool is_session_by_file = (audio_file_in != NULL);
               bool deferred = ((dst->stream_time_min == 0) || is_session_by_file) ? false : !sdt->stream_time_min_rxd;

               if(!xrsr_sdt_connect(sdt, &dst->url_parts, session->src, begin->xraudio_format, begin->user_initiated, begin->retry, deferred, NULL, NULL)) {
                  XLOGD_ERROR("sdt connect");
               }
            } else if(xrsr_sdt_is_established(sdt)) {
               XLOGD_INFO("sdt session continue");
               if(!xrsr_sdt_audio_stream(sdt, session->src, audio_file_in)) {
                  XLOGD_ERROR("sdt audio stream");
               }
            } else {
               XLOGD_ERROR("invalid state");
            }
           break;
         }
         #endif
         default: {
            XLOGD_ERROR("invalid protocol <%s>", xrsr_protocol_str(prot));
            return;
         }
      }
   }
}

#ifdef HTTP_ENABLED
void xrsr_callback_session_config_in_http(const uuid_t uuid, xrsr_session_config_in_t *config_in) {
   xrsr_queue_msg_session_config_in_t msg;

   msg.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_CONFIG_IN;
   msg.src         = config_in->src;
   msg.protocol    = XRSR_PROTOCOL_HTTP;
   uuid_copy(msg.uuid, uuid);

   uint32_t i = 0;
   const char **query_strs = config_in->http.query_strs;

   while(*query_strs != NULL) {
      if(i >= XRSR_QUERY_STRING_QTY_MAX - 1) {
         XLOGD_WARN("maximum query string elements reached");
         break;
      }
      msg.query_strs[i++] = *query_strs;
      query_strs++;
   }

   msg.query_strs[i] = NULL;

   msg.sat_token            = config_in->http.sat_token;
   msg.user_agent           = config_in->http.user_agent;
   msg.keyword_begin        = config_in->http.keyword_begin;
   msg.keyword_duration     = config_in->http.keyword_duration;
   msg.client_cert          = config_in->http.client_cert;
   msg.host_verify          = config_in->http.host_verify;
   msg.ocsp_verify_stapling = config_in->http.ocsp_verify_stapling;
   msg.ocsp_verify_ca       = config_in->http.ocsp_verify_ca;
   msg.app_config           = NULL;

   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
}
#endif

#ifdef WS_ENABLED
void xrsr_callback_session_config_in_ws(const uuid_t uuid, xrsr_session_config_in_t *config_in) {
   xrsr_queue_msg_session_config_in_t msg;

   msg.header.type = XRSR_QUEUE_MSG_TYPE_SESSION_CONFIG_IN;
   msg.src         = config_in->src;
   msg.protocol    = XRSR_PROTOCOL_WS;
   uuid_copy(msg.uuid, uuid);

   uint32_t i = 0;
   const char **query_strs = config_in->ws.query_strs;

   while(*query_strs != NULL) {
      if(i >= XRSR_QUERY_STRING_QTY_MAX - 1) {
         XLOGD_WARN("maximum query string elements reached");
         break;
      }
      msg.query_strs[i++] = *query_strs;
      query_strs++;
   }

   msg.query_strs[i] = NULL;

   msg.sat_token            = config_in->ws.sat_token;
   msg.user_agent           = NULL;
   msg.keyword_begin        = config_in->ws.keyword_begin;
   msg.keyword_duration     = config_in->ws.keyword_duration;
   msg.client_cert          = config_in->ws.client_cert;
   msg.host_verify          = config_in->ws.host_verify;
   msg.ocsp_verify_stapling = config_in->ws.ocsp_verify_stapling;
   msg.ocsp_verify_ca       = config_in->ws.ocsp_verify_ca;
   msg.app_config           = config_in->ws.app_config;

   if(0 != xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg))) {
      if(config_in->ws.app_config != NULL) {
         free(config_in->ws.app_config);
      }
   }
}
#endif

void xrsr_msg_session_config_in(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_config_in_t *config_in = (xrsr_queue_msg_session_config_in_t *)msg;

   if((uint32_t)config_in->src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(config_in->src));
      return;
   }

   xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(config_in->src)];

   bool found_session = false;
   bool create_stream = true;
   for(uint32_t dst_index = 0; dst_index < XRSR_DST_QTY_MAX; dst_index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[session->src].dsts[dst_index];

      if((uint32_t)session->src >= XRSR_SRC_INVALID) { // Source can be released by index 0
         break;
      }
      if(dst->handler == NULL) {
         continue;
      }
      xrsr_protocol_t prot = dst->url_parts.prot;

      switch(prot) {
         #ifdef HTTP_ENABLED
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            if(config_in->protocol != XRSR_PROTOCOL_HTTP) {
               break;
            }
            xrsr_state_http_t *http = &dst->conn_state.http;
            if(uuid_compare(http->uuid, config_in->uuid) == 0) {
               found_session = true;

               // Copy the session configuration input
               xrsr_session_config_in_http_t *session_config_in_http = &http->session_config_in.http;

               session_config_in_http->sat_token            = config_in->sat_token;
               session_config_in_http->user_agent           = config_in->user_agent;
               session_config_in_http->keyword_begin        = config_in->keyword_begin;
               session_config_in_http->keyword_duration     = config_in->keyword_duration;
               session_config_in_http->client_cert          = config_in->client_cert;
               session_config_in_http->host_verify          = config_in->host_verify;
               session_config_in_http->ocsp_verify_stapling = config_in->ocsp_verify_stapling;
               session_config_in_http->ocsp_verify_ca       = config_in->ocsp_verify_ca;

               http->audio_src = config_in->src;

               XLOGD_DEBUG("HTTP config sat token <%p> user agent <%p> keyword begin <%u> duration <%u> client cert <%s>", session_config_in_http->sat_token, session_config_in_http->user_agent, session_config_in_http->keyword_begin, session_config_in_http->keyword_duration, xrsr_cert_type_str(session_config_in_http->client_cert.type));
               uint32_t i = 0;
               const char **query_strs = session_config_in_http->query_strs;

               // Locate end of current query string list
               while(*query_strs != NULL) {
                  if(i >= XRSR_QUERY_STRING_QTY_MAX) {
                     XLOGD_WARN("maximum query string elements reached");
                     break;
                  }
                  query_strs++;
                  i++;
               }

               // Append query strings from app
               const char **query_strs_app = config_in->query_strs;
               while(*query_strs_app != NULL) {
                  if(i >= XRSR_QUERY_STRING_QTY_MAX) {
                     XLOGD_WARN("maximum query string elements reached");
                     break;
                  }

                  *query_strs = *query_strs_app;
                  query_strs++;
                  query_strs_app++;
                  i++;
               }

               *query_strs = NULL;

               // Call session config handler
               if(http->handlers.session_config != NULL) {
                  (*http->handlers.session_config)(http->handlers.data, http->uuid, &http->session_config_in);
               }

               bool deferred = ((dst->stream_time_min > 0) && !http->is_session_by_text && !http->is_session_by_file) ? true : false;

               int pipe_fd_read = -1;
               const char *audio_file_in = (http->is_session_by_file) ? http->audio_file_in : NULL;

               if(!http->is_session_by_text && !xrsr_speech_stream_begin(http->uuid, session->src, dst_index, http->input_format, http->xraudio_format, http->session_config_out.user_initiated, http->low_latency, http->low_cpu_util, create_stream, false, audio_file_in, &pipe_fd_read)) {
                  XLOGD_ERROR("xrsr_speech_stream_begin failed");
               } else if(!xrsr_http_connect(http, &dst->url_parts, session->src, http->xraudio_format, state->timer_obj, deferred, session_config_in_http->query_strs, http->transcription_ptr)) {
                  XLOGD_ERROR("http connect failed");
               } else {
                  create_stream = false;
                  http->audio_pipe_fd_read = pipe_fd_read;
               }

            }
            break;
         }
         #endif
         #ifdef WS_ENABLED
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            if(config_in->protocol != XRSR_PROTOCOL_WS) {
               break;
            }
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            if(uuid_compare(ws->uuid, config_in->uuid) == 0) {
               found_session = true;

               // Copy the session configuration input
               xrsr_session_config_in_ws_t *session_config_in_ws = &ws->session_config_in.ws;

               session_config_in_ws->sat_token            = config_in->sat_token;
               session_config_in_ws->keyword_begin        = config_in->keyword_begin;
               session_config_in_ws->keyword_duration     = config_in->keyword_duration;
               session_config_in_ws->app_config           = config_in->app_config;
               session_config_in_ws->client_cert          = config_in->client_cert;
               session_config_in_ws->host_verify          = config_in->host_verify;
               session_config_in_ws->ocsp_verify_stapling = config_in->ocsp_verify_stapling;
               session_config_in_ws->ocsp_verify_ca       = config_in->ocsp_verify_ca;

               dst->keyword_begin    = config_in->keyword_begin;
               dst->keyword_duration = config_in->keyword_duration;

               ws->audio_src = config_in->src;

               XLOGD_DEBUG("WS config sat token <%p> keyword begin <%u> duration <%u>", session_config_in_ws->sat_token, session_config_in_ws->keyword_begin, session_config_in_ws->keyword_duration);

               uint32_t i = 0;
               const char **query_strs = session_config_in_ws->query_strs;

               // Locate end of current query string list
               while(*query_strs != NULL) {
                  if(i >= XRSR_QUERY_STRING_QTY_MAX) {
                     XLOGD_WARN("maximum query string elements reached");
                     break;
                  }
                  query_strs++;
                  i++;
               }

               // Append query strings from app
               const char **query_strs_app = config_in->query_strs;
               while(*query_strs_app != NULL) {
                  if(i >= XRSR_QUERY_STRING_QTY_MAX) {
                     XLOGD_WARN("maximum query string elements reached");
                     break;
                  }

                  *query_strs = *query_strs_app;
                  query_strs++;
                  query_strs_app++;
                  i++;
               }

               *query_strs = NULL;

               // Call session config handler
               if(ws->handlers.session_config != NULL) {
                  (*ws->handlers.session_config)(ws->handlers.data, ws->uuid, &ws->session_config_in);
               }

               if(!ws->is_session_by_text) { // start streaming audio to the pipe
                  int pipe_fd_read = -1;
                  const char *audio_file_in = (ws->is_session_by_file) ? ws->audio_file_in : NULL;

                  if(!xrsr_speech_stream_begin(ws->uuid, session->src, ws->dst_index, ws->input_format, ws->xraudio_format, ws->session_config_out.user_initiated, ws->low_latency, ws->low_cpu_util, create_stream, false, audio_file_in, &pipe_fd_read)) {
                     XLOGD_ERROR("xrsr_speech_stream_begin failed");
                     // perform clean up of the session
                     xrsr_ws_speech_session_end(ws, XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN);
                     break;
                  } else {
                     create_stream = false;
                     ws->audio_pipe_fd_read = pipe_fd_read;
                  }
               }

               bool deferred = ((dst->stream_time_min == 0) || ws->is_session_by_text || ws->is_session_by_file) ? false : !ws->stream_time_min_rxd;

               if(!xrsr_ws_connect(ws, &dst->url_parts, session->src, ws->xraudio_format, ws->session_config_out.user_initiated, false, deferred, ws->session_config_in.ws.query_strs)) {
                  XLOGD_ERROR("ws connect");
               }
            }
            break;
         }
         #endif
         default: {
         }
      }
   }

   if(!found_session) {
      char uuid_str[37] = {'\0'};
      uuid_unparse_lower(config_in->uuid, uuid_str);
      XLOGD_WARN("session not found uuid <%s>", uuid_str);
      if(config_in->app_config != NULL) {
         free(config_in->app_config);
      }
   }
}

void xrsr_session_end(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index, xrsr_session_stats_t *stats) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   XLOGD_INFO("uuid <%s> src <%s> dst index <%u>", uuid_str, xrsr_src_str(src), dst_index);

   if(((uint32_t) src) >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }

   xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(src)];
   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("source <%s> is not active source <%s>", xrsr_src_str(src), xrsr_src_str(session->src));
      return;
   }
   if(dst_index >= XRSR_DST_QTY_MAX || g_xrsr.routes[src].dsts[dst_index].handler == NULL) {
      XLOGD_ERROR("source <%s> invalid dst index <%u>", xrsr_src_str(src), dst_index);
      return;
   }

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Call session end handler
   if(dst->handlers.session_end != NULL) {
      (*dst->handlers.session_end)(dst->handlers.data, uuid, stats, &timestamp);
   } else {
      XLOGD_DEBUG("no session end handler");
   }

   // check state of each dst to determine if session if overall session is completed
   bool session_in_progress = false;
   for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[session->src].dsts[index];
      if(dst->handler == NULL) {
         continue;
      }
      xrsr_protocol_t prot = dst->url_parts.prot;

      switch(prot) {
         #ifdef HTTP_ENABLED
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            xrsr_state_http_t *http = &dst->conn_state.http;
            if(!xrsr_http_is_disconnected(http)) {
               session_in_progress = true;
            }
            break;
         }
         #endif
         #ifdef WS_ENABLED
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            if(!xrsr_ws_is_disconnected(ws)) {
               session_in_progress = true;
            }
            break;
         }
         #endif
         #ifdef SDT_ENABLED
         case XRSR_PROTOCOL_SDT: {
            xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
            if(!xrsr_sdt_is_disconnected(sdt)) {
               session_in_progress = true;
            }
            break;
         }
         #endif
         default: {
         }
      }
   }

   if(!session_in_progress) {
      session->src                  = XRSR_SRC_INVALID;
      session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_NONE;
      session->requested_more_audio = false;
      session->stream_id            = 0;
   }
}

void xrsr_msg_session_terminate(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_terminate_t *terminate = (xrsr_queue_msg_session_terminate_t *)msg;

   xrsr_src_t src = terminate->src;

   if((uint32_t)src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("source is invalid <%s>", xrsr_src_str(src));
      if(terminate->semaphore != NULL) {
         sem_post(terminate->semaphore);
      }
      return;
   }

   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("source is not active <%s>", xrsr_src_str(src));
      if(terminate->semaphore != NULL) {
         sem_post(terminate->semaphore);
      }
      return;
   }

   uint32_t index_src = src;
   for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

      switch(dst->url_parts.prot) {
         #ifdef HTTP_ENABLED
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            xrsr_state_http_t *http = &dst->conn_state.http;
            XLOGD_INFO("http");
            if(!xrsr_http_is_disconnected(http)) {
               xrsr_http_terminate(http);
            }
            break;
         }
         #endif
         #ifdef WS_ENABLED
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            if(!xrsr_ws_is_disconnected(ws)) {
               xrsr_ws_terminate(ws);
            }
            break;
         }
         #endif
         #ifdef SDT_ENABLED
         case XRSR_PROTOCOL_SDT: {
            xrsr_state_sdt_t *sdt = &dst->conn_state.sdt;
            if(!xrsr_sdt_is_disconnected(sdt)) {
               xrsr_sdt_terminate(sdt);
            }
            break;
         }
         #endif
         default: {
            break;
         }
      }
   }

   if(terminate->semaphore != NULL) {
      sem_post(terminate->semaphore);
   }
}

void xrsr_msg_session_audio_stream_start(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_audio_stream_start_t *audio_stream_start = (xrsr_queue_msg_session_audio_stream_start_t *)msg;

   xrsr_src_t src = audio_stream_start->src;

   if((uint32_t)src >= XRSR_SRC_INVALID) {
      XLOGD_ERROR("source is invalid <%s>", xrsr_src_str(src));
      if(audio_stream_start->semaphore != NULL) {
         sem_post(audio_stream_start->semaphore);
      }
      return;
   }

   if(!xrsr_is_source_active(src)) {
      XLOGD_ERROR("source is not active <%s>", xrsr_src_str(src));
      if(audio_stream_start->semaphore != NULL) {
         sem_post(audio_stream_start->semaphore);
      }
      return;
   }

   uint32_t index_src = src;
   bool create_stream = true;
   for(uint32_t index_dst = 0; index_dst < XRSR_DST_QTY_MAX; index_dst++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[index_src].dsts[index_dst];

      switch(dst->url_parts.prot) {
         #ifdef HTTP_ENABLED
         case XRSR_PROTOCOL_HTTP:
         case XRSR_PROTOCOL_HTTPS: {
            if(index_dst == 0) {
               XLOGD_WARN("http protocol does not support multiple audio streams");
            }
            break;
         }
         #endif
         #ifdef WS_ENABLED
         case XRSR_PROTOCOL_WS:
         case XRSR_PROTOCOL_WSS: {
            xrsr_state_ws_t *ws = &dst->conn_state.ws;
            if(!xrsr_ws_is_disconnected(ws)) {
               if(src != XRSR_SRC_RCU_PTT) { // far field microphone, start streaming immediately
                  if(!xrsr_ws_audio_stream(ws, src, create_stream, true)) {
                     XLOGD_ERROR("ws audio stream - src <%s>", xrsr_src_str(src));
                  }
                  create_stream = false;
               } else { // PTT
                  xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(src)];

                  if(!session->requested_more_audio) { // First mark the session as having requested more audio
                     session->requested_more_audio = true;
                  } else { // Now start streaming the audio
                     if(!xrsr_ws_audio_stream(ws, src, create_stream, true)) {
                        XLOGD_ERROR("ws audio stream - src <%s>", xrsr_src_str(src));
                     }
                     create_stream = false;
                  }
               }
            }
            break;
         }
         #endif
         #ifdef SDT_ENABLED
         case XRSR_PROTOCOL_SDT: {
            if(index_dst == 0) {
               XLOGD_WARN("sdt protocol does not support multiple audio streams");
            }
            break;
         }
         #endif
         default: {
            break;
         }
      }
   }

   if(audio_stream_start->semaphore != NULL) {
      sem_post(audio_stream_start->semaphore);
   }
}
void xrsr_session_stream_begin(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   XLOGD_INFO("uuid <%s> src <%s> dst index <%u>", uuid_str, xrsr_src_str(src), dst_index);

   if(((uint32_t) src) >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }
   if(dst_index >= XRSR_DST_QTY_MAX || g_xrsr.routes[src].dsts[dst_index].handler == NULL) {
      XLOGD_ERROR("source <%s> invalid dst index <%u>", xrsr_src_str(src), dst_index);
      return;
   }

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Call session stream begin handler
   if(dst->handlers.stream_begin != NULL) {
      (*dst->handlers.stream_begin)(dst->handlers.data, uuid, src, &timestamp);
   } else {
      XLOGD_DEBUG("no stream begin handler");
   }
}

void xrsr_session_stream_kwd(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   XLOGD_INFO("uuid <%s> src <%s> dst index <%u>", uuid_str, xrsr_src_str(src), dst_index);

   if(((uint32_t) src) >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }
   if(dst_index >= XRSR_DST_QTY_MAX || g_xrsr.routes[src].dsts[dst_index].handler == NULL) {
      XLOGD_ERROR("source <%s> invalid dst index <%u>", xrsr_src_str(src), dst_index);
      return;
   }

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Call session stream kwd handler
   if(dst->handlers.stream_kwd != NULL) {
      (*dst->handlers.stream_kwd)(dst->handlers.data, uuid, &timestamp);
   } else {
      XLOGD_DEBUG("no stream keyword handler");
   }
}

void xrsr_session_stream_end(const uuid_t uuid, const char *uuid_str, xrsr_src_t src, uint32_t dst_index, xrsr_stream_stats_t *stats) {
   rdkx_timestamp_t timestamp;
   rdkx_timestamp_get_realtime(&timestamp);

   XLOGD_INFO("uuid <%s> src <%s>", uuid_str, xrsr_src_str(src));

   if(((uint32_t) src) >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }
   if(dst_index >= XRSR_DST_QTY_MAX || g_xrsr.routes[src].dsts[dst_index].handler == NULL) {
      XLOGD_ERROR("source <%s> invalid dst index <%u>", xrsr_src_str(src), dst_index);
      return;
   }

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   // Call session stream end handler
   if(dst->handlers.stream_end != NULL) {
      (*dst->handlers.stream_end)(dst->handlers.data, uuid, stats, &timestamp);
   } else {
      XLOGD_DEBUG("no stream end handler");
   }
}

void xrsr_msg_session_capture_start(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_capture_start_t *capture_start = (xrsr_queue_msg_session_capture_start_t *)msg;


   xrsr_xraudio_session_capture_start(g_xrsr.xrsr_xraudio_object, capture_start->container, capture_start->file_path, capture_start->raw_mic_enable);

   if(capture_start->semaphore != NULL) {
      sem_post(capture_start->semaphore);
   }
}

void xrsr_msg_session_capture_stop(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_session_capture_stop_t *capture_stop = (xrsr_queue_msg_session_capture_stop_t *)msg;


   xrsr_xraudio_session_capture_stop(g_xrsr.xrsr_xraudio_object);

   if(capture_stop->semaphore != NULL) {
      sem_post(capture_stop->semaphore);
   }
}

void xrsr_msg_privacy_mode_get(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_privacy_mode_get_t *privacy_mode_get = (xrsr_queue_msg_privacy_mode_get_t *)msg;

   bool result = xrsr_xraudio_privacy_mode_get(g_xrsr.xrsr_xraudio_object, privacy_mode_get->enabled);

   if(privacy_mode_get->semaphore != NULL) {
      if(privacy_mode_get->result != NULL) {
         *(privacy_mode_get->result) = result;
      }
      sem_post(privacy_mode_get->semaphore);
   }
}

void xrsr_send_stream_data(xrsr_src_t src, uint8_t *buffer, uint32_t size)
{
  if((uint32_t)src >= (uint32_t)XRSR_SRC_INVALID) {
     XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
     return;
   }

   for(uint32_t dst_index = 0; dst_index < XRSR_DST_QTY_MAX; dst_index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

      if(dst->handler == NULL) {
         if(dst_index == 0) {
            XLOGD_ERROR("no handler for source <%s>", xrsr_src_str(src));
         }
         return;
      }
      // Call source send audio handler
      if(dst->handlers.stream_audio != NULL) {
         (*dst->handlers.stream_audio)(buffer,size);
      }
   }
}

void xrsr_session_begin(xrsr_src_t src, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util) {
   if((uint32_t)src >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }

   // TODO Only the handler for dst index 0 is called.  Really this needs to be changed so that each protocol doesn't need to get called here.
   for(uint32_t dst_index = 0; dst_index < 1; dst_index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

      if(dst->handler == NULL) {
         XLOGD_ERROR("no handler for source <%s> dst index <%u>", xrsr_src_str(src), dst_index);
         return;
      }
      (*dst->handler)(src, false, user_initiated, xraudio_format, detector_result, input_format, uuid, low_latency, low_cpu_util);
   }
}

void xrsr_keyword_detect_error(xrsr_src_t src) {
   if((uint32_t)src >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return;
   }

   for(uint32_t dst_index = 0; dst_index < XRSR_DST_QTY_MAX; dst_index++) {
      xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

      if(dst->handler == NULL) {
         if(dst_index == 0) {
            XLOGD_ERROR("no handler for source <%s>", xrsr_src_str(src));
         }
         return;
      }

      // Call source error handler
      if(dst->handlers.source_error != NULL) {
         (*dst->handlers.source_error)(dst->handlers.data, src);
      }
   }
}

xrsr_result_t xrsr_conn_send(void *param, const uint8_t *buffer, uint32_t length) {
   xrsr_protocol_t *prot = (xrsr_protocol_t *)param;
   int ret = 0;
   switch(*prot) {
      #ifdef WS_ENABLED
      case XRSR_PROTOCOL_WS:
      case XRSR_PROTOCOL_WSS: {
         xrsr_state_ws_t *ws = (xrsr_state_ws_t *)param;
         ret = xrsr_ws_send_text(ws, buffer, length);
         break;
      }
      #endif
      #ifdef HTTP_ENABLED
      case XRSR_PROTOCOL_HTTP:
      case XRSR_PROTOCOL_HTTPS: {
         xrsr_state_http_t *http = (xrsr_state_http_t *)param;
         ret = xrsr_http_send(http, buffer, length);
         break;
      }
      #endif
      #ifdef SDT_ENABLED
      case XRSR_PROTOCOL_SDT: {
        xrsr_state_sdt_t *sdt = (xrsr_state_sdt_t *)param;
        ret = xrsr_sdt_send_text(sdt, buffer, length);
         break;
      }
      #endif
      default: {
         XLOGD_ERROR("protocol not supportted");
         break;
      }
   }
   return(ret == 1) ? XRSR_RESULT_SUCCESS : XRSR_RESULT_ERROR;
}

bool xrsr_speech_stream_begin(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_session_request_t input_format, xraudio_input_format_t output_format, bool user_initiated, bool low_latency, bool low_cpu_util, bool create_stream, bool subsequent, const char *audio_file_in, int *pipe_fd_read) {
   xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(src)];

   if(create_stream) { // New audio stream setup (create pipe, set initial state)
      xraudio_dst_pipe_t dsts[XRSR_DST_QTY_MAX];

      session->requested_more_audio = false;
      session->stream_id++;

      // create pipe for each destination
      for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[index];

         if(dst->handler == NULL) {
            session->pipe_size[index]   = -1;
            session->pipe_fds_rd[index] = -1;
            dsts[index].pipe            = -1;
            dsts[index].from            = XRAUDIO_INPUT_RECORD_FROM_INVALID;
            dsts[index].offset          = 0;
            dsts[index].until           = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
            break;
         }

         int pipe_fds[2];

         errno = 0;
         if(pipe(pipe_fds) == -1) {
            int errsv = errno;
            XLOGD_ERROR("unable to create pipe <%s>", strerror(errsv));
            return(false);
         }

         // Hold up to X milliseconds of audio in the pipe
         uint32_t duration = 10000;
         uint32_t size     = (XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE * XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE * XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY * duration) / 1000;

         int rc = fcntl(pipe_fds[1], F_SETPIPE_SZ, size);
         if(rc < size) { // emit a warning if the kernel returns a pipe size smaller than we requested
            XLOGD_WARN("set pipe size failed exp <%u> rxd <%d>", size, rc);
         } else {
            duration = (rc * 1000) / (XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE * XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE * XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY);
            XLOGD_INFO("src <%s> dst index <%u> pipe size %u ms (%u KB)", xrsr_src_str(src), index, duration, rc / 1024);
         }

         session->pipe_size[index]        = rc;
         session->pipe_fds_rd[index]      = pipe_fds[0];
         dsts[index].pipe                 = pipe_fds[1];

         if(subsequent) { // use parameter for subsequent streams
            dsts[index].from            = XRSR_STREAM_FROM_LIVE;
            dsts[index].offset          = 0;
            dsts[index].until           = dst->stream_until;
         } else {
            dsts[index].from            = dst->stream_from;
            dsts[index].offset          = dst->stream_offset;
            dsts[index].until           = dst->stream_until;
         }
      }

      // Start the audio stream
      switch(src) {
         case XRSR_SRC_RCU_PTT:        { session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_PTT;     break; }
         case XRSR_SRC_RCU_FF:         { session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_FF;      break; }
         case XRSR_SRC_MICROPHONE:     { session->xraudio_device_input = (output_format.encoding.type == XRAUDIO_ENCODING_PCM_RAW || output_format.channel_qty > 1) ? XRAUDIO_DEVICE_INPUT_TRI : XRAUDIO_DEVICE_INPUT_SINGLE; break; }
         case XRSR_SRC_MICROPHONE_TAP: { session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_MIC_TAP; break; }
         default: {
            XLOGD_ERROR("invalid src <%s>", xrsr_src_str(src));
            session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_NONE;
            return(false);
         }
      }

      bool stream_begin_failure = false;
      if(audio_file_in == NULL) {
         xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

         xraudio_input_format_t xraudio_format = output_format;

         xrsr_audio_format_t audio_format = xrsr_audio_format_get(dst->formats, xraudio_format);
         switch(audio_format.type) {
            case XRSR_AUDIO_FORMAT_PCM:              { xraudio_format.encoding.type = XRAUDIO_ENCODING_PCM;     xraudio_format.sample_size = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE; xraudio_format.channel_qty = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY; break; }
            case XRSR_AUDIO_FORMAT_PCM_32_BIT:       { xraudio_format.encoding.type = XRAUDIO_ENCODING_PCM;     xraudio_format.sample_size = XRAUDIO_INPUT_MAX_SAMPLE_SIZE;     xraudio_format.channel_qty = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY; break; }
            case XRSR_AUDIO_FORMAT_PCM_32_BIT_MULTI: { xraudio_format.encoding.type = XRAUDIO_ENCODING_PCM;     xraudio_format.sample_size = XRAUDIO_INPUT_MAX_SAMPLE_SIZE;     xraudio_format.channel_qty = XRAUDIO_INPUT_MAX_CHANNEL_QTY;     break; }
            case XRSR_AUDIO_FORMAT_PCM_RAW:          { xraudio_format.encoding.type = XRAUDIO_ENCODING_PCM_RAW; xraudio_format.sample_size = XRAUDIO_INPUT_MAX_SAMPLE_SIZE;     xraudio_format.channel_qty = XRAUDIO_INPUT_MAX_CHANNEL_QTY;     break; }
            case XRSR_AUDIO_FORMAT_ADPCM_FRAME:      { if(xraudio_format.encoding.type != XRAUDIO_ENCODING_ADPCM_FRAME) { xraudio_format.encoding.type = XRAUDIO_ENCODING_ADPCM; } break; }
            case XRSR_AUDIO_FORMAT_OPUS:             { if(xraudio_format.encoding.type != XRAUDIO_ENCODING_OPUS_XVP)  xraudio_format.encoding.type = XRAUDIO_ENCODING_OPUS;  break; }
            default: {
               xraudio_format.encoding.type = XRAUDIO_ENCODING_INVALID;
               break;
            }
         }

         char stream_id[40] = {'\0'};
         uuid_unparse_lower(uuid, stream_id);
  
         // append stream id
         stream_id[36] = '_';
         if(session->stream_id < 10) {
            stream_id[37] = '0';
            stream_id[38] = '0' + session->stream_id;
         } else if(session->stream_id < 100) {
            stream_id[37] = '0' + session->stream_id / 10;
            stream_id[38] = '0' + session->stream_id % 10;
         } else {
            stream_id[37] = 'X';
            stream_id[38] = 'X';
         }
         stream_id[39] = '\0';

         uint32_t frame_duration = 0;
         if(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(session->xraudio_device_input)) {
            if(input_format.type == XRSR_SESSION_REQUEST_TYPE_AUDIO_FD) {
               xrsr_request_audio_fd_t *audio_fd = &input_format.value.audio_fd;
               if(audio_fd->audio_format.type == XRSR_AUDIO_FORMAT_ADPCM_FRAME) {
                  xrsr_adpcm_frame_t *adpcm_frame = &audio_fd->audio_format.value.adpcm_frame;
                  frame_duration = 1000 * 1000 * 2 * (adpcm_frame->size_packet - adpcm_frame->size_header) / xraudio_format.sample_rate;
               } else if(audio_fd->audio_format.type == XRSR_AUDIO_FORMAT_PCM) {
                  frame_duration = XRAUDIO_INPUT_FRAME_PERIOD * 1000; // use default frame period
               } else if(audio_fd->audio_format.type == XRSR_AUDIO_FORMAT_OPUS) {
                  frame_duration = XRAUDIO_INPUT_FRAME_PERIOD * 1000; // use default frame period
               } else {
                  XLOGD_ERROR("invalid audio format <%s>", xrsr_audio_format_str(audio_fd->audio_format.type));
                  return(false);
               }
            } else {
               XLOGD_ERROR("invalid request type <%s>", xrsr_session_request_type_str(input_format.type));
               return(false);
            }
         } else {
            frame_duration = XRAUDIO_INPUT_FRAME_PERIOD * 1000;
         }

         uint32_t keyword_begin    = (user_initiated || subsequent) ? 0 : dst->keyword_begin;
         uint32_t keyword_duration = (user_initiated || subsequent) ? 0 : dst->keyword_duration;

         // Make a single call to start streaming to all destinations
         if(!xrsr_xraudio_stream_begin(g_xrsr.xrsr_xraudio_object, stream_id, session->xraudio_device_input, user_initiated, &xraudio_format, dsts, dst->stream_time_min, keyword_begin, keyword_duration, frame_duration, low_latency, low_cpu_util, subsequent)) {
            XLOGD_ERROR("xrsr_xraudio_stream_begin failed");
            stream_begin_failure = true;
         }
      } else {
         // open the audio input file
         errno = 0;
         int fd = open(audio_file_in, O_RDONLY);
         if(fd < 0) {
            int errsv = errno;
            XLOGD_ERROR("Unable to open file <%s> <%s>", audio_file_in, strerror(errsv));
            stream_begin_failure = true;
         } else {
            // verify the audio format
            uint32_t data_length = 0;
            bool encoding_opus = (output_format.encoding.type == XRAUDIO_ENCODING_OPUS);
            OpusDecoder *obj_opus = NULL;
            if(encoding_opus) {
               int opus_error = 0;
               obj_opus = opus_decoder_create(16000, 1, &opus_error);
               if(obj_opus == NULL || opus_error != OPUS_OK) {
                  XLOGD_ERROR("unable to create opus object");
                  stream_begin_failure = true;
               } else {
                  struct stat statbuf;
                  errno = 0;
                  if(0 != fstat(fd, &statbuf)) {
                     int errsv = errno;
                     XLOGD_ERROR("unable to stat file <%s>", strerror(errsv));
                     stream_begin_failure = true;
                  } else {
                     data_length = statbuf.st_size; // the full length of the file
                  }
               }
            } else {
               xraudio_output_format_t format;
               int32_t offset =  xraudio_container_header_parse_wave(fd, NULL, 0, &format, &data_length);
               if(offset < 0) {
                  XLOGD_ERROR("failed to parse wave header <%s>", audio_file_in);
                  stream_begin_failure = true;
               } else if(format.channel_qty != 1 || format.sample_rate != 16000 || format.sample_size != 2 || format.encoding.type != XRAUDIO_ENCODING_PCM) {
                  XLOGD_ERROR("unsupported wave file format - channel qty <%u> sample rate <%d> sample size <%u> encoding <%d>", format.channel_qty, format.sample_rate, format.sample_size, format.encoding);
                  stream_begin_failure = true;
               } else if(data_length == 0) {
                  XLOGD_ERROR("zero length audio data <%s>", audio_file_in);
                  stream_begin_failure = true;
               } else if(lseek(fd, offset, SEEK_SET) != offset) {
                  XLOGD_ERROR("unable to seek wave file <%s> offset <%d>", audio_file_in, offset);
                  stream_begin_failure = true;
               }
            }
            if(!stream_begin_failure) {
               // Ensure that the pipes are large enough to hold the entire audio data
               for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
                  xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[index];
                  if(dst->handler == NULL) {
                     continue;
                  }
                  if(data_length > session->pipe_size[index]) {
                     XLOGD_ERROR("audio file data larger than pipe capacity <%d> <%d>", data_length, session->pipe_size[index]);
                     stream_begin_failure = true;
                     break;
                  }
               }

               if(!stream_begin_failure) { // Read the audio file in chunks and write to the pipe
                  while(data_length) {
                     uint8_t buffer[4096];
                     size_t chunk_size = 0;

                     if(encoding_opus) { // Process one packet at a time
                        uint8_t length_bytes[2] = { '\0' };
                        errno = 0;
                        int rc = read(fd, &length_bytes[0], 1); // Read opus self-delimiting header first byte
                        if(rc != 1) {
                           int errsv = errno;
                           XLOGD_ERROR("failed to read opus header1 <%s> rxd <%d> <%s>", audio_file_in, rc, strerror(errsv));
                           stream_begin_failure = true;
                           break;
                        }
                        data_length--;
                        uint8_t  opus_packet_buf[1275];
                        uint16_t opus_packet_size = length_bytes[0];

                        if(opus_packet_size >= 252) { // Read second header byte
                           rc = read(fd, &length_bytes[1], 1); // Read opus self-delimiting header second byte
                           if(rc != 1) {
                              int errsv = errno;
                              XLOGD_ERROR("failed to read opus header2 <%s> rxd <%d> <%s>", audio_file_in, rc, strerror(errsv));
                              stream_begin_failure = true;
                              break;
                           }
                           opus_packet_size += (length_bytes[1] * 4);
                           data_length--;
                        }

                        if(opus_packet_size > 0) {
                           rc = read(fd, opus_packet_buf, opus_packet_size);
                           if(rc != opus_packet_size) {
                              int errsv = errno;
                              XLOGD_ERROR("failed to read opus data <%s> exp <%d> rxd <%d> <%s>", audio_file_in, opus_packet_size, rc, strerror(errsv));
                              stream_begin_failure = true;
                              break;
                           }
                           data_length -= opus_packet_size;
                        }
                        // Decode opus to pcm
                        int samples = opus_decode(obj_opus, opus_packet_buf, opus_packet_size, (opus_int16 *)buffer, sizeof(buffer), 0);
                        if(samples < 0) {
                           XLOGD_ERROR("failed to decode opus frame <%d>", samples);
                           stream_begin_failure = true;
                           break;
                        }
                        chunk_size = samples * sizeof(int16_t);

                     } else {
                        chunk_size = (data_length >= sizeof(buffer)) ? sizeof(buffer) : data_length;
                        errno = 0;
                        int rc = read(fd, buffer, chunk_size);
                        if(rc != chunk_size) {
                           int errsv = errno;
                           XLOGD_ERROR("failed to read wave data <%s> exp <%u> rxd <%d> <%s>", audio_file_in, chunk_size, rc, strerror(errsv));
                           stream_begin_failure = true;
                           break;
                        }

                        data_length -= chunk_size;
                     }

                     for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
                        xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[index];

                        if(dst->handler == NULL) {
                           continue;
                        }
                        errno = 0;
                        int rc = write(dsts[index].pipe, buffer, chunk_size);
                        if(rc != chunk_size) {
                           int errsv = errno;
                           XLOGD_ERROR("failed to write wave data - exp <%u> rxd <%d> <%s>", chunk_size, rc, strerror(errsv));
                           stream_begin_failure = true;
                           data_length = 0; // to exit the while loop
                           break;
                        }
                     }
                  }
               }

               // close the file handle and write side of the pipe
               for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
                  xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[index];

                  if(dst->handler == NULL) {
                     continue;
                  }
                  close(dsts[index].pipe);
                  dsts[index].pipe = -1;
               }
            }
            close(fd);
            if(obj_opus == NULL) {
               opus_decoder_destroy(obj_opus);
            }
         }
      }

      if(stream_begin_failure) {
         for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
            if(dsts[index].pipe >= 0) {
               close(dsts[index].pipe);
            }
            if(session->pipe_fds_rd[index] >= 0) {
               close(session->pipe_fds_rd[index]);
               session->pipe_fds_rd[index] = -1;
            }
         }
         session->xraudio_device_input = XRAUDIO_DEVICE_INPUT_NONE;
         if(xrsr_has_keyword_detector(src)) { // Need to restart the keyword detector again
            xrsr_xraudio_keyword_detect_restart(g_xrsr.xrsr_xraudio_object);
         }
         return(false);
      }
   }

   *pipe_fd_read = session->pipe_fds_rd[dst_index];

   return(true);
}

bool xrsr_speech_stream_kwd(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index) {
   char uuid_str[37] = {'\0'};
   uuid_unparse_lower(uuid, uuid_str);

   xrsr_session_stream_kwd(uuid, uuid_str, src, dst_index);

   return(true);
}

bool xrsr_speech_stream_end(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_stream_end_reason_t reason, bool detect_resume, xrsr_audio_stats_t *audio_stats) {
   bool result = true;

   XLOGD_INFO("src <%s> dst index <%u> reason <%s> detect resume <%s>", xrsr_src_str(src), dst_index, xrsr_stream_end_reason_str(reason), detect_resume ? "YES" : "NO");

   if(((uint32_t) src) >= (uint32_t)XRSR_SRC_INVALID) {
      XLOGD_ERROR("invalid source <%s>", xrsr_src_str(src));
      return(false);
   }
   if(dst_index >= XRSR_DST_QTY_MAX || g_xrsr.routes[src].dsts[dst_index].handler == NULL) {
      XLOGD_ERROR("source <%s> invalid dst index <%u>", xrsr_src_str(src), dst_index);
      return(false);
   }

   xrsr_session_t *session = &g_xrsr.sessions[xrsr_source_to_group(src)];

   // Need to know when all streams have ended to call xraudio stream end?
   session->pipe_fds_rd[dst_index] = -1;

   bool more_streams = false;
   for(uint32_t index = 0; index < XRSR_DST_QTY_MAX; index++) {
      if(session->pipe_fds_rd[index] >= 0) {
         more_streams = true;
      }
   }

   if(!xrsr_xraudio_stream_end(g_xrsr.xrsr_xraudio_object, session->xraudio_device_input, dst_index, more_streams, detect_resume, audio_stats)) {
      XLOGD_ERROR("xrsr_xraudio_stream_end failed");
      result = false;
   }

   xrsr_dst_int_t *dst = &g_xrsr.routes[src].dsts[dst_index];

   if(reason != XRSR_STREAM_END_REASON_DID_NOT_BEGIN) { // the stream was started
      char uuid_str[37] = {'\0'};
      uuid_unparse_lower(uuid, uuid_str);

      xrsr_stream_stats_t stats;
      memset(&stats, 0, sizeof(stats));

      stats.result = (reason == XRSR_STREAM_END_REASON_AUDIO_EOF) ? true : false;
      stats.prot   = dst->url_parts.prot;
      if(audio_stats) {
         stats.audio_stats = *audio_stats;
      }
      xrsr_session_stream_end(uuid, uuid_str, src, dst_index, &stats);
   }

   return(result);
}

void xrsr_thread_poll(xrsr_thread_poll_func_t func) {
   xrsr_queue_msg_thread_poll_t msg;
   msg.header.type  = XRSR_QUEUE_MSG_TYPE_THREAD_POLL;
   msg.func         = func;
   xrsr_queue_msg_push(xrsr_msgq_fd_get(), (const char *)&msg, sizeof(msg));
}

void xrsr_msg_thread_poll(const xrsr_thread_params_t *params, xrsr_thread_state_t *state, void *msg) {
   xrsr_queue_msg_thread_poll_t *thread_poll = (xrsr_queue_msg_thread_poll_t *)msg;

   if(thread_poll == NULL || thread_poll->func == NULL) {
      return;
   }

   if(g_xrsr.xrsr_xraudio_object == NULL) { // xraudio is not open.  call poll response directly.
      (*thread_poll->func)();
   } else { // send thread poll to xraudio
      xrsr_xraudio_thread_poll(g_xrsr.xrsr_xraudio_object, thread_poll->func);
   }
}

xrsr_audio_format_t xrsr_audio_format_get(uint32_t formats_supported_dst, xraudio_input_format_t format_src) {
   xrsr_audio_format_t ret = { .type = XRSR_AUDIO_FORMAT_NONE };
   xrsr_audio_format_t src = xrsr_xraudio_format_to_xrsr(format_src);
   if(src.type & formats_supported_dst) {
      ret = src;
   } else if(XRSR_AUDIO_FORMAT_PCM & formats_supported_dst) {
      ret.type = XRSR_AUDIO_FORMAT_PCM;
   }
   return(ret);
}

bool xrsr_is_source_active(xrsr_src_t src) {
   for(uint32_t group = 0; group < XRSR_SESSION_GROUP_QTY; group++) {
      xrsr_session_t *session = &g_xrsr.sessions[group];
      if(session->src == src) {
         return(true);
      }
   }
   return(false);
}

bool xrsr_is_group_active(uint32_t group) {
   xrsr_session_t *session = &g_xrsr.sessions[group];
   if((uint32_t)session->src < XRSR_SRC_INVALID) {
      return(true);
   }
   return(false);
}

uint32_t xrsr_source_to_group(xrsr_src_t src) {
   #ifdef MICROPHONE_TAP_ENABLED
   if(src == XRSR_SRC_MICROPHONE_TAP) {
      return(1);
   }
   #endif
   return(0);
}

bool xrsr_has_keyword_detector(xrsr_src_t src) {
   #ifdef MICROPHONE_TAP_ENABLED
   if(src == XRSR_SRC_MICROPHONE_TAP) {
      return(false);
   }
   #endif
   return(true);
}
