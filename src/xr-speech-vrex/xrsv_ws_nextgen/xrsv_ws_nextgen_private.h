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
#ifndef __XRSV_WS_NEXTGEN_PRIVATE__
#define __XRSV_WS_NEXTGEN_PRIVATE__

#include <stddef.h>
#include <bsd/string.h>
#include <errno.h>
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRSV
#include <rdkx_logger.h>
#include <jansson.h>
#include <xrsv_ws_nextgen.h>

typedef struct {
   uint32_t                    identifier;
   xrsv_ws_nextgen_handlers_t  handlers;
   xrsr_handler_send_t         send;
   void *                      param;
   json_t *                    obj_init;
   json_t *                    obj_init_payload;
   json_t *                    obj_init_stb;
   json_t *                    obj_init_stb_id;
   json_t *                    obj_init_stb_id_account;
   json_t *                    obj_init_stb_id_device_id;
   json_t *                    obj_init_stb_audio;
   json_t *                    obj_init_app;
   json_t *                    obj_init_elements;
   json_t *                    obj_stream_begin;
   json_t *                    obj_stream_end;
   json_t *                    obj_stream_end_payload;
   char                        query_element_trx[41];
   char                        query_element_device_id[64];
   char                        query_element_version[12];
   bool                        mask_pii;
   void *                      user_data;
   bool                        user_initiated;
   bool                        first_audio_stream;
   xrsr_recv_event_t           recv_event;
   xrsr_session_config_update_t *session_config_update;
   uuid_t                      uuid;
} xrsv_ws_nextgen_obj_t;

bool xrsv_ws_nextgen_msgtype_conn_close(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_response_vrex(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_wuw_verification(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_asr(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_listening(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_tv_control(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
bool xrsv_ws_nextgen_msgtype_server_stream_end(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);

void xrsv_ws_nextgen_tv_control_power_on(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_power_on_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_power_off(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_power_off_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_volume_up(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_volume_down(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
void xrsv_ws_nextgen_tv_control_volume_mute_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);



typedef bool (*xrsv_ws_nextgen_handler_bool_t)(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
typedef void (*xrsv_ws_nextgen_handler_void_t)(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);

typedef struct xrsv_ws_nextgen_msgtype_handler_s { char *name; xrsv_ws_nextgen_handler_bool_t func; } xrsv_ws_nextgen_msgtype_handler_t;
typedef struct xrsv_ws_nextgen_tv_control_handler_s { char *name; xrsv_ws_nextgen_handler_void_t func; } xrsv_ws_nextgen_tv_control_handler_t;

struct xrsv_ws_nextgen_msgtype_handler_s * xrsv_ws_nextgen_msgtype_handler_get(const char *str, size_t len);
struct xrsv_ws_nextgen_tv_control_handler_s * xrsv_ws_nextgen_tv_control_handler_get(const char *str, size_t len);

#endif
