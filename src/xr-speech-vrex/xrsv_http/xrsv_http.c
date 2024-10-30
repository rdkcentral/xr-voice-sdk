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
#include <time.h>
#include <errno.h>
#include <xrsv_http.h>
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRSV
#include <rdkx_logger.h>
#include <jansson.h>
#include <bsd/string.h>

#define XRSV_HTTP_IDENTIFIER (0x773D8203)

typedef struct {
   uint32_t             identifier;
   xrsv_http_handlers_t handlers;
   xrsr_handler_send_t  send;
   void *               param;
   char                 query_element_trx[41];
   char                 query_element_device_id[64];
   char                 query_element_receiver_id[64];
   char                 query_element_codec[17];
   char                 query_element_app_id[64];
   char                 query_element_partner_id[32];
   char                 query_element_experience[32];
   char                 query_element_language[32];
   char                 query_element_aspect_ratio[16];
   char                 query_element_vrex_filters[40];
   bool                 mask_pii;
   void *               user_data;
} xrsv_http_obj_t;

static void xrsv_http_handler_source_error(xrsv_http_object_t object, xrsr_src_t src);
static bool xrsv_http_handler_connected(xrsv_http_object_t object, const uuid_t uuid, xrsr_handler_send_t send, void *param, rdkx_timestamp_t *timestamp, xrsr_session_config_update_t *session_config_update);
static void xrsv_http_handler_disconnected(xrsv_http_object_t object, const uuid_t uuid, xrsr_session_end_reason_t reason, bool retry, bool *detect_resume, rdkx_timestamp_t *timestamp);
static void xrsv_http_handler_session_begin(xrsv_http_object_t object, const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_keyword_detector_result_t *detector_result, xrsr_session_config_out_t *config_out, xrsr_session_config_in_t *config_in, rdkx_timestamp_t *timestamp, const char *transcription_in);
static void xrsv_http_handler_session_end(xrsv_http_object_t object, const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp);
static void xrsv_http_handler_stream_begin(xrsv_http_object_t object, const uuid_t uuid, xrsr_src_t src, rdkx_timestamp_t *timestamp);
static void xrsv_http_handler_stream_end(xrsv_http_object_t object, const uuid_t uuid, xrsr_stream_stats_t *stats, rdkx_timestamp_t *timestamp);
static bool xrsv_http_handler_recv_msg(xrsv_http_object_t object, xrsr_recv_msg_t type, const uint8_t *buffer, uint32_t length, xrsr_recv_event_t *recv_event);

bool xrsv_http_object_is_valid(xrsv_http_obj_t *obj) {
   if(obj != NULL && obj->identifier == XRSV_HTTP_IDENTIFIER) {
      return(true);
   }
   return(false);
}

xrsv_http_object_t xrsv_http_create(const xrsv_http_params_t *params) {
   if(params == NULL) {
      XLOGD_ERROR("invalid params");
      return(NULL);
   }
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)malloc(sizeof(xrsv_http_obj_t));

   if(obj == NULL) {
      XLOGD_ERROR("Out of memory.");
      return(NULL);
   }

   memset(obj, 0, sizeof(*obj));

   obj->identifier = XRSV_HTTP_IDENTIFIER;

   int rc;
   
   if(params->device_id != NULL) {
      xrsv_http_update_device_id(obj, params->device_id);
   }
   if(params->receiver_id) {
      xrsv_http_update_receiver_id(obj, params->receiver_id);
   }
   if(params->app_id != NULL) {
      xrsv_http_update_app_id(obj, params->app_id);
   }
   if(params->partner_id != NULL) {
      xrsv_http_update_partner_id(obj, params->partner_id);
   }
   if(params->experience != NULL) {
      xrsv_http_update_experience(obj, params->experience);
   }
   if(params->language != NULL) {
      xrsv_http_update_language(obj, params->language);
   }
   rc = snprintf(obj->query_element_aspect_ratio, sizeof(obj->query_element_aspect_ratio), "aspectRatio=HD");
   if(rc >= sizeof(obj->query_element_aspect_ratio)) {
      XLOGD_WARN("truncated aspect ratio <%d>", rc);
   }

   obj->mask_pii  = params->mask_pii;
   obj->user_data = params->user_data;

   return(obj);
}

bool xrsv_http_handlers(xrsv_http_object_t object, const xrsv_http_handlers_t *handlers_in, xrsr_handlers_t *handlers_out) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool ret = true;
   handlers_out->data           = obj;
   handlers_out->source_error   = xrsv_http_handler_source_error;
   handlers_out->session_begin  = xrsv_http_handler_session_begin;
   handlers_out->session_config = NULL;
   handlers_out->session_end    = xrsv_http_handler_session_end;
   handlers_out->stream_begin   = xrsv_http_handler_stream_begin;
   handlers_out->stream_kwd     = NULL;
   handlers_out->stream_end     = xrsv_http_handler_stream_end;
   handlers_out->connected      = xrsv_http_handler_connected;
   handlers_out->disconnected   = xrsv_http_handler_disconnected;
   handlers_out->recv_msg       = xrsv_http_handler_recv_msg;

   if(handlers_in) {
      obj->handlers = *handlers_in;
   }
   return(ret);
}

bool xrsv_http_update_user_data(xrsv_http_object_t object, void *user_data) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   obj->user_data = user_data;
   return(true);
}

bool xrsv_http_update_device_id(xrsv_http_object_t object, const char *device_id) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = false;
   int rc = snprintf(obj->query_element_device_id, sizeof(obj->query_element_device_id), "xboDeviceId=%s", device_id);
   if(rc >= sizeof(obj->query_element_device_id)) {
      XLOGD_WARN("truncated device id <%d>", rc);
   } else {
      rv = true;
   }
   return(rv);
}

bool xrsv_http_update_receiver_id(xrsv_http_object_t object, const char *receiver_id) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = false;
   int rc = snprintf(obj->query_element_receiver_id, sizeof(obj->query_element_receiver_id), "receiverId=%s", receiver_id);
   if(rc >= sizeof(obj->query_element_receiver_id)) {
      XLOGD_WARN("truncated receiver id <%d>", rc);
   } else {
      rv = true;
   }
   return(rv);
}

bool xrsv_http_update_partner_id(xrsv_http_object_t object, const char *partner_id) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = false;
   int rc = snprintf(obj->query_element_partner_id, sizeof(obj->query_element_partner_id), "partnerId=%s", partner_id);
   if(rc >= sizeof(obj->query_element_partner_id)) {
      XLOGD_WARN("truncated partner id <%d>", rc);
   } else {
      rv = true;
   }
   return(rv);
}
 
bool xrsv_http_update_experience(xrsv_http_object_t object, const char *experience) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = false;
   int rc = snprintf(obj->query_element_experience, sizeof(obj->query_element_experience), "experienceTag=%s", experience);
   if(rc >= sizeof(obj->query_element_experience)) {
      XLOGD_WARN("truncated experience id <%d>", rc);
   } else {
      rv = true;
   }
   return(rv);
}

bool xrsv_http_update_app_id(xrsv_http_object_t object, const char *app_id) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = false;
   int rc = snprintf(obj->query_element_app_id, sizeof(obj->query_element_app_id), "appId=%s", app_id);
   if(rc >= sizeof(obj->query_element_app_id)) {
      XLOGD_WARN("truncated app id <%d>", rc);
   } else {
      rv = true;
   }
   return(rv);
}

bool xrsv_http_update_language(xrsv_http_object_t object, const char *language) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = false;
   int rc  = snprintf(obj->query_element_language, sizeof(obj->query_element_language), "language=%s", language);
   if(rc >= sizeof(obj->query_element_language)) {
      XLOGD_WARN("truncated language <%d>", rc);
   } else {
      rv = true;
   }
   return(rv);
}

bool xrsv_http_update_mask_pii(xrsv_http_object_t object, bool enable) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   obj->mask_pii = enable;
   return(true);
}

void xrsv_http_destroy(xrsv_http_object_t object) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   XLOGD_INFO("");

   obj->query_element_device_id[0]     = '\0';
   obj->query_element_receiver_id[0]   = '\0';
   obj->query_element_codec[0]         = '\0';
   obj->query_element_trx[0]           = '\0';
   obj->query_element_app_id[0]        = '\0';
   obj->query_element_partner_id[0]    = '\0';
   obj->query_element_experience[0]    = '\0';
   obj->query_element_language[0]      = '\0';
   obj->query_element_aspect_ratio[0]  = '\0';
   obj->identifier                     = 0;
   free(obj);
}

void xrsv_http_handler_source_error(xrsv_http_object_t object, xrsr_src_t src) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(obj->handlers.source_error != NULL) {
      (*obj->handlers.source_error)(src, obj->user_data);
   }
}

bool xrsv_http_handler_connected(xrsv_http_object_t object, const uuid_t uuid, xrsr_handler_send_t send, void *param, rdkx_timestamp_t *timestamp, xrsr_session_config_update_t *session_config_update) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return false;
   }
   if(obj->handlers.connected != NULL) {
      (*obj->handlers.connected)(uuid, timestamp, obj->user_data);
   }
   XLOGD_INFO("");
   return true;
}

void xrsv_http_handler_disconnected(xrsv_http_object_t object, const uuid_t uuid, xrsr_session_end_reason_t reason, bool retry, bool *detect_resume, rdkx_timestamp_t *timestamp) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   XLOGD_INFO("");
   if(detect_resume != NULL) {
      *detect_resume = true;
   }
   if(obj->handlers.disconnected != NULL) {
      (*obj->handlers.disconnected)(uuid, timestamp, obj->user_data);
   }
}

void xrsv_http_handler_session_begin(xrsv_http_object_t object, const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_keyword_detector_result_t *detector_result, xrsr_session_config_out_t *config_out, xrsr_session_config_in_t *config_in, rdkx_timestamp_t *timestamp, const char *transcription_in) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   char uuid_str[37] = {'\0'};
   uuid_unparse_lower(uuid, uuid_str);

   if(obj->handlers.session_begin != NULL) {
      (*obj->handlers.session_begin)(uuid, src, dst_index, config_out, timestamp, obj->user_data);
   }


   const char *codec = "ADPCM";

   if(config_out->format.type == XRSR_AUDIO_FORMAT_PCM) {
      codec = "PCM_16_16K";
   } else if(config_out->format.type == XRSR_AUDIO_FORMAT_OPUS) {
      codec = "OPUS";
   }

   // Add attribute-value pairs to query string
   snprintf(obj->query_element_trx,        sizeof(obj->query_element_trx),   "trx=%s", uuid_str);
   snprintf(obj->query_element_codec,      sizeof(obj->query_element_codec), "codec=%s", codec);


   config_in->http.query_strs[0] = obj->query_element_app_id;
   config_in->http.query_strs[1] = obj->query_element_device_id;
   config_in->http.query_strs[2] = obj->query_element_partner_id;
   config_in->http.query_strs[3] = obj->query_element_experience;
   config_in->http.query_strs[4] = obj->query_element_language;
   config_in->http.query_strs[5] = obj->query_element_aspect_ratio;
   config_in->http.query_strs[6] = obj->query_element_trx;
   config_in->http.query_strs[7] = obj->query_element_codec;

   if (transcription_in != NULL) {
      // For a text only session, remove SR (speech recognition) from the filter
      snprintf(obj->query_element_vrex_filters, sizeof(obj->query_element_vrex_filters), "vrexFilters=NLP,EVENT,AR,EXEC");
      config_in->http.query_strs[8] = obj->query_element_vrex_filters;
      config_in->http.query_strs[9] = NULL;
   } else {
      // Leave VREX filters at default
      obj->query_element_vrex_filters[0] = '\0';
      config_in->http.query_strs[8] = NULL;
   }

}

void xrsv_http_handler_session_end(xrsv_http_object_t object, const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(obj->handlers.session_end != NULL) {
      (*obj->handlers.session_end)(uuid, stats, timestamp, obj->user_data);
   }
   obj->query_element_trx[0] = '\0';
}

void xrsv_http_handler_stream_begin(xrsv_http_object_t object, const uuid_t uuid, xrsr_src_t src, rdkx_timestamp_t *timestamp) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(obj->handlers.stream_begin != NULL) {
      (*obj->handlers.stream_begin)(uuid, src, timestamp, obj->user_data);
   }
}

void xrsv_http_handler_stream_end(xrsv_http_object_t object, const uuid_t uuid, xrsr_stream_stats_t *stats, rdkx_timestamp_t *timestamp) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(obj->handlers.stream_end != NULL) {
      (*obj->handlers.stream_end)(uuid, stats, timestamp, obj->user_data);
   }
}

bool xrsv_http_handler_recv_msg(xrsv_http_object_t object, xrsr_recv_msg_t type, const uint8_t *buffer, uint32_t length, xrsr_recv_event_t *recv_event) {
   xrsv_http_obj_t *obj = (xrsv_http_obj_t *)object;
   if(!xrsv_http_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   switch(type) {
      case XRSR_RECV_MSG_TEXT: {
         xrsv_http_recv_msg_t msg;
         json_t *obj_json = json_loadb((const char *)buffer, length, JSON_DECODE_ANY, NULL);
         json_t *temp;
         if(NULL == obj_json) {
            XLOGD_TELEMETRY("Failed to parse JSON response");
            return(false);
         }

         memset(&msg, 0, sizeof(msg));

         // Server ret code
         temp = json_object_get(obj_json, "code");
         if(temp && json_is_integer(temp)) {
            msg.ret_code = json_integer_value(temp);
         } else {
            XLOGD_WARN("No server return code");
         }

         // Message
         temp = json_object_get(obj_json, "message");
         if(temp && json_is_string(temp)) {
            strlcpy(msg.message, json_string_value(temp), sizeof(msg.message));
         } else {
            XLOGD_WARN("No message");
         }
         
         // Transcription
         temp = json_object_get(obj_json, "nlp");
         if(temp && json_is_object(temp)) {
            temp = json_object_get(temp, "response");
            if(temp && json_is_object(temp)) {
               temp = json_object_get(temp, "text");
               if(temp && json_is_string(temp)) {
                  strlcpy(msg.transcription, json_string_value(temp), sizeof(msg.transcription));
               }
            }
         } else {
            XLOGD_TELEMETRY("No transcription");
         }

         // TRX
         temp = json_object_get(obj_json, "trx");
         if(temp && json_is_string(temp)) {
            strlcpy(msg.session_id, json_string_value(temp), sizeof(msg.session_id));
         } else {
            XLOGD_WARN("No trx");
         }

         if(obj->handlers.recv_msg != NULL) {
            (*obj->handlers.recv_msg)(&msg, obj->user_data);
         }
         json_decref(obj_json);
         break;
      }
      default: {
         XLOGD_INFO("msg type not implemented");
         break;
      }
   }
   return(false);
}
