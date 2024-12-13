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
#include <xrsv_ws_nextgen_private.h>

#define XRSV_WS_NEXTGEN_JSON_KEY_API_VERSION                            "apiVersion"
#define XRSV_WS_NEXTGEN_JSON_KEY_MSG_TYPE                               "msgType"
#define XRSV_WS_NEXTGEN_JSON_KEY_MSG_PAYLOAD                            "msgPayload"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENTS                               "elements"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ROLES                          "roles"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_DOWNSTREAM                     "downstreamProtocol"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_TRANSMISSION                   "transmissionProtocol"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID                             "id"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_PARTNER                     "partner"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE                        "type"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE_VALUE_STB              "stb"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE_VALUE_TV               "smartTv"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES                      "values"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE                       "value"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE_DEVICE_ID             "xboDeviceId"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE_ACCOUNT_ID            "xboAccountId"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_CAPABILITIES                   "capabilities"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO                          "audio"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_PROFILE                  "audioProfile"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_CODEC                    "envoyCodec"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TRIGGER                  "triggeredBy"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TRIGGER_TIME             "triggeredEpochTime"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_MODEL                    "audioModel"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_DYNAMIC_GAIN             "gain"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW                      "wuw"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_START                "sowuw"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_END                  "eowuw"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DSP_PREPROCESSING    "dspPreprocessing"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR             "detector"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_VENDOR      "vendor"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_SENSITIVITY "keywordSensitivity"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_SENS_TRIG   "keywordSensitivityTriggered"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_GAIN        "gain"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_SNR         "signalNoiseRatio"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_NONLINEAR   "keywordConfidenceNonLinear"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_LINEAR      "keywordConfidenceLinear"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_DEVICE_SW_VERSION        "deviceSwVersion"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_STB_SW_VERSION           "stbSwVersion"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TIMEOUT                  "timeout"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_RF_PROTOCOL              "rfProtocol"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_LANG                           "language"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_MAC                            "mac"
#define XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_EXPERIENCE                     "experience"
#define XRSV_WS_NEXTGEN_JSON_KEY_CREATED                                "created"
#define XRSV_WS_NEXTGEN_JSON_KEY_TRX                                    "trx"
#define XRSV_WS_NEXTGEN_JSON_KEY_REASON                                 "reason"
#define XRSV_WS_NEXTGEN_JSON_KEY_RETURN_CODE                            "returnCode"
#define XRSV_WS_NEXTGEN_JSON_KEY_CONTEXT                                "context"
#define XRSV_WS_NEXTGEN_JSON_KEY_LAST_COMMAND                           "lastCommand"
#define XRSV_WS_NEXTGEN_JSON_KEY_CONFIDENCE                             "confidence"
#define XRSV_WS_NEXTGEN_JSON_KEY_PASSED                                 "passed"
#define XRSV_WS_NEXTGEN_JSON_KEY_TEXT                                   "text"
#define XRSV_WS_NEXTGEN_JSON_KEY_FINAL                                  "isFinal"
#define XRSV_WS_NEXTGEN_JSON_KEY_ACTION                                 "action"

#define XRSV_WS_NEXTGEN_JSON_MSG_TYPE_INIT                              "init"
#define XRSV_WS_NEXTGEN_JSON_MSG_TYPE_EOS                               "endOfStream"
#define XRSV_WS_NEXTGEN_JSON_MSG_TYPE_SOS                               "startOfStream"
#define XRSV_WS_NEXTGEN_JSON_API_VERSION                                "2.0.0p0"
#define XRSV_WS_NEXTGEN_JSON_DOWNSTREAM_PROTOCOL                        "thisWebsocket"
#define XRSV_WS_NEXTGEN_JSON_ELEMENT_AUDIO_TRIGGER_PTT                  "ptt"
#define XRSV_WS_NEXTGEN_JSON_ELEMENT_AUDIO_TRIGGER_WUW                  "wuw"

#define XRSV_WS_NEXTGEN_JSON_ELEMENT_STB_INDEX                           (0)
#define XRSV_WS_NEXTGEN_JSON_ELEMENT_APP_INDEX                           (1)

#define XRSV_WS_NEXTGEN_IDENTIFIER (0xC11FB9C2)

static bool     xrsv_ws_nextgen_object_is_valid(xrsv_ws_nextgen_obj_t *obj);
static void     xrsv_ws_nextgen_msg_init(xrsv_ws_nextgen_obj_t *obj, uint8_t **buffer, uint32_t *length);
static void     xrsv_ws_nextgen_msg_stream_begin(xrsv_ws_nextgen_obj_t *obj, uint8_t **buffer, uint32_t *length);
static void     xrsv_ws_nextgen_msg_stream_end(xrsv_ws_nextgen_obj_t *obj, int32_t reason, uint8_t **buffer, uint32_t *length);
static bool     xrsv_ws_nextgen_msg_decode(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json);
static uint64_t xrsv_ws_nextgen_time_get(void);
static bool     xrsv_ws_nextgen_update_json(json_t *obj, const char *key, json_t *value);
static bool     xrsv_ws_nextgen_update_json_str(json_t *obj, const char *key, const char *value);

static void xrsv_ws_nextgen_handler_ws_source_error(void *data, xrsr_src_t src);
static void xrsv_ws_nextgen_handler_ws_session_begin(void *data, const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_keyword_detector_result_t *detector_result, xrsr_session_config_out_t *config_out, xrsr_session_config_in_t *config_in, rdkx_timestamp_t *timestamp, const char *transcription_in);
static void xrsv_ws_nextgen_handler_ws_session_config(void *data, const uuid_t uuid, xrsr_session_config_in_t *config_in);
static void xrsv_ws_nextgen_handler_ws_session_end(void *data, const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp);
static void xrsv_ws_nextgen_handler_ws_stream_begin(void *data, const uuid_t uuid, xrsr_src_t src, rdkx_timestamp_t *timestamp);
static void xrsv_ws_nextgen_handler_ws_stream_kwd(void *data, const uuid_t uuid, rdkx_timestamp_t *timestamp);
static void xrsv_ws_nextgen_handler_ws_stream_end(void *data, const uuid_t uuid, xrsr_stream_stats_t *stats, rdkx_timestamp_t *timestamp);
static bool xrsv_ws_nextgen_handler_ws_connected(void *data, const uuid_t uuid, xrsr_handler_send_t send, void *param, rdkx_timestamp_t *timestamp, xrsr_session_config_update_t *session_config_update);
static void xrsv_ws_nextgen_handler_ws_disconnected(void *data, const uuid_t uuid, xrsr_session_end_reason_t reason, bool retry, bool *detect_resume, rdkx_timestamp_t *timestamp);
static bool xrsv_ws_nextgen_handler_ws_recv_msg(void *data, xrsr_recv_msg_t type, const uint8_t *buffer, uint32_t length, xrsr_recv_event_t *recv_event);


bool xrsv_ws_nextgen_object_is_valid(xrsv_ws_nextgen_obj_t *obj) {
   if(obj != NULL && obj->identifier == XRSV_WS_NEXTGEN_IDENTIFIER) {
      return(true);
   }
   return(false);
}

xrsv_ws_nextgen_object_t xrsv_ws_nextgen_create(const xrsv_ws_nextgen_params_t *params) {
   if(params == NULL) {
      XLOGD_ERROR("invalid params");
      return(NULL);
   }
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)malloc(sizeof(xrsv_ws_nextgen_obj_t));

   if(obj == NULL) {
      XLOGD_ERROR("Out of memory.");
      return(NULL);
   }

   memset(obj, 0, sizeof(*obj));

   if((obj->obj_init = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      free(obj);
      return(NULL);
   } else if((obj->obj_init_stb_id = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   } else if((obj->obj_init_stb = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_init_stb_id);
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   } else if((obj->obj_init_stb_audio = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_init_stb);
      json_decref(obj->obj_init_stb_id);
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   } else if((obj->obj_init_elements = json_array()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_init_stb_audio);
      json_decref(obj->obj_init_stb);
      json_decref(obj->obj_init_stb_id);
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   } else if((obj->obj_init_payload = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_init_elements);
      json_decref(obj->obj_init_stb_audio);
      json_decref(obj->obj_init_stb);
      json_decref(obj->obj_init_stb_id);
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   }
   obj->obj_init_app              = NULL;
   obj->obj_init_stb_id_account   = NULL;
   obj->obj_init_stb_id_device_id = NULL;
   int rc;

   const char *codec = "PCM_16_16K";

   // Root Object
   rc  = json_object_set_new_nocheck(obj->obj_init,    XRSV_WS_NEXTGEN_JSON_KEY_MSG_TYPE,     json_string(XRSV_WS_NEXTGEN_JSON_MSG_TYPE_INIT));
   rc |= json_object_set_new_nocheck(obj->obj_init,    XRSV_WS_NEXTGEN_JSON_KEY_MSG_PAYLOAD,  obj->obj_init_payload);
   // End Root Object

   // Payload Object
   rc |= json_object_set_new_nocheck(obj->obj_init_payload, XRSV_WS_NEXTGEN_JSON_KEY_API_VERSION,  json_string(XRSV_WS_NEXTGEN_JSON_API_VERSION));
   rc |= json_object_set_new_nocheck(obj->obj_init_payload, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENTS, obj->obj_init_elements);
   // End Payload Object

   // Elements Object
   rc |= json_array_insert_new(obj->obj_init_elements, XRSV_WS_NEXTGEN_JSON_ELEMENT_STB_INDEX, obj->obj_init_stb);

   // STB Element Object
   // TODO: Error checking
   json_t *obj_roles = json_array();
   rc |= json_array_append_new(obj_roles, json_string("input"));
   rc |= json_array_append_new(obj_roles, json_string("envoy"));
   rc |= json_array_append_new(obj_roles, json_string("av"));

   json_t *obj_capabilities = json_array();
   rc |= json_array_append_new(obj_capabilities, json_string("TV_POWER"));
   rc |= json_array_append_new(obj_capabilities, json_string("TV_VOLUME"));
   rc |= json_array_append_new(obj_capabilities, json_string("WBW"));
   if(params->test_flag) {
      rc |= json_array_append_new(obj_capabilities, json_string("TEST"));
   }
   if(params->bypass_wuw_verify_success) {
      rc |= json_array_append_new(obj_capabilities, json_string("BYPASS_WUW_FORCE_SUCCESS"));
   }
   if(params->bypass_wuw_verify_failure) {
      rc |= json_array_append_new(obj_capabilities, json_string("BYPASS_WUW_FORCE_FAILURE"));
   }

   if(params->experience) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_EXPERIENCE, json_string(params->experience));
   }

   if(params->language) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_LANG, json_string(params->language));
   }

   if(params->device_mac) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_MAC, json_string(params->device_mac));
   }


   rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ROLES, obj_roles);
   rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_DOWNSTREAM, json_string(XRSV_WS_NEXTGEN_JSON_DOWNSTREAM_PROTOCOL));
   rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID, obj->obj_init_stb_id);
   rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO, obj->obj_init_stb_audio);
   // TODO: Make capabilities / features configurable
   rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_CAPABILITIES, obj_capabilities);

   // ID Object
   // TODO: TYPE (stb, skyq, etc)
   json_t *obj_id_values = json_array();
   rc |= json_object_set_new_nocheck(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, json_string(XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE_VALUE_STB));
   rc |= json_object_set_new_nocheck(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES, obj_id_values);
   if(params->partner_id) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_PARTNER, json_string(params->partner_id));
   }

   // ID Values Object
   if(params->account_id != NULL) {
      obj->obj_init_stb_id_account = json_object();
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_account, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, json_string(XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE_ACCOUNT_ID));
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_account, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, json_string(params->account_id));

      rc |= json_array_append_new(obj_id_values, obj->obj_init_stb_id_account);
   }
   if(params->device_id != NULL) {
      obj->obj_init_stb_id_device_id = json_object();
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_device_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, json_string(XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE_DEVICE_ID));
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_device_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, json_string(params->device_id));

      rc |= json_array_append_new(obj_id_values, obj->obj_init_stb_id_device_id);
   }
   // End ID Values Object
   // End ID Object
   // Audio Object
   rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_CODEC, json_string(codec));
   if(params->audio_profile) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_PROFILE, json_string(params->audio_profile));
   }
   if(params->audio_model) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_MODEL, json_string(params->audio_model));
   }
   if (params->rf_protocol) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_RF_PROTOCOL, json_string(params->rf_protocol));
   }
   // End Audio Object
   // End STB Element Object

   // Version query param
   snprintf(obj->query_element_version, sizeof(obj->query_element_version), "version=v1");

   if(rc != 0) {
      XLOGD_ERROR("object set failed");
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   }

   if((obj->obj_stream_begin = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   } else if((obj->obj_stream_end = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_stream_begin);
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   } else if((obj->obj_stream_end_payload = json_object()) == NULL) {
      XLOGD_ERROR("object create failed");
      json_decref(obj->obj_stream_begin);
      json_decref(obj->obj_stream_end);
      json_decref(obj->obj_init);
      free(obj);
      return(NULL);
   }

   // SOS Object
   rc  = json_object_set_new_nocheck(obj->obj_stream_begin, XRSV_WS_NEXTGEN_JSON_KEY_MSG_TYPE, json_string(XRSV_WS_NEXTGEN_JSON_MSG_TYPE_SOS));
   // End SOS Object

   // EOS Object
   rc |= json_object_set_new_nocheck(obj->obj_stream_end, XRSV_WS_NEXTGEN_JSON_KEY_MSG_TYPE, json_string(XRSV_WS_NEXTGEN_JSON_MSG_TYPE_EOS));
   rc |= json_object_set_new_nocheck(obj->obj_stream_end, XRSV_WS_NEXTGEN_JSON_KEY_MSG_PAYLOAD, obj->obj_stream_end_payload);

   // EOS Payload
   rc |= json_object_set_new_nocheck(obj->obj_stream_end_payload, XRSV_WS_NEXTGEN_JSON_KEY_REASON, json_integer(0));
   // End EOS Payload
   // End EOS Object

   if(rc != 0) {
      XLOGD_ERROR("object set failed");
      json_decref(obj->obj_init);
      json_decref(obj->obj_stream_end);
      json_decref(obj->obj_stream_begin);
      free(obj);
      return(NULL);
   }

   if(params->device_id != NULL) {
      rc = snprintf(obj->query_element_device_id,     sizeof(obj->query_element_device_id), "id=%s",    params->device_id);
      if(rc >= sizeof(obj->query_element_device_id)) {
         XLOGD_WARN("truncated device id <%d>", rc);
      }
   }

   obj->identifier = XRSV_WS_NEXTGEN_IDENTIFIER;
   obj->mask_pii   = params->mask_pii;
   obj->user_data  = params->user_data;
   obj->recv_event = XRSR_RECV_EVENT_NONE;

   return(obj);
}
bool xrsv_ws_nextgen_handlers(xrsv_ws_nextgen_object_t object, const xrsv_ws_nextgen_handlers_t *handlers_in, xrsr_handlers_t *handlers_out) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }

   bool ret = true;
   handlers_out->data           = obj;
   handlers_out->source_error   = xrsv_ws_nextgen_handler_ws_source_error;
   handlers_out->session_begin  = xrsv_ws_nextgen_handler_ws_session_begin;
   handlers_out->session_config = xrsv_ws_nextgen_handler_ws_session_config;
   handlers_out->session_end    = xrsv_ws_nextgen_handler_ws_session_end;
   handlers_out->stream_begin   = xrsv_ws_nextgen_handler_ws_stream_begin;
   handlers_out->stream_kwd     = xrsv_ws_nextgen_handler_ws_stream_kwd;
   handlers_out->stream_end     = xrsv_ws_nextgen_handler_ws_stream_end;
   handlers_out->connected      = xrsv_ws_nextgen_handler_ws_connected;
   handlers_out->disconnected   = xrsv_ws_nextgen_handler_ws_disconnected;
   handlers_out->recv_msg       = xrsv_ws_nextgen_handler_ws_recv_msg;

   obj->handlers = *handlers_in;
   return(ret);
}

bool xrsv_ws_nextgen_update_user_data(xrsv_ws_nextgen_object_t object, void *user_data) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   obj->user_data = user_data;
   return(true);
}

bool xrsv_ws_nextgen_update_json(json_t *obj, const char *key, json_t *value) {
   if(obj == NULL || key == NULL || value == NULL) {
      XLOGD_ERROR("invalid params");
      return(false);
   }

   // Update the value
   int rc  = json_object_set_new_nocheck(obj, key, value);

   if(rc != 0) {
      XLOGD_ERROR("object set failed");
      return(false);
   }
   return(true);
}

bool xrsv_ws_nextgen_update_json_str(json_t *obj, const char *key, const char *value) {
   return(xrsv_ws_nextgen_update_json(obj, key, json_string(value)));
}

bool xrsv_ws_nextgen_update_device_id(xrsv_ws_nextgen_object_t object, const char *device_id) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = true;
   if(obj->obj_init_stb_id_device_id) {
      rv = xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_id_device_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, device_id);  
   } else {
      int rc = 0;
      json_t *obj_values = json_object_get(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES);
      if(obj_values == NULL) {
         obj_values = json_array();
         rc |= json_object_set_new_nocheck(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES, obj_values);
      }
      if((obj->obj_init_stb_id_device_id = json_object()) == NULL) {
         rv = false;
      } else {
         rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_device_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, json_string(XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE_DEVICE_ID));
         rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_device_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, json_string(device_id));
         rc |= json_array_append_new(obj_values, obj->obj_init_stb_id_device_id);
         if(rc != 0) {
            XLOGD_ERROR("object set error");
            rv = false;
         }
      }
   }

   if(rv) {
      int rc = snprintf(obj->query_element_device_id, sizeof(obj->query_element_device_id), "id=%s", device_id);
      if(rc >= sizeof(obj->query_element_device_id)) {
         XLOGD_WARN("truncated device id <%d>", rc);
      }
   }
   return(rv);
}

bool xrsv_ws_nextgen_update_account_id(xrsv_ws_nextgen_object_t object, const char *account_id) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   bool rv = true;
   if(obj->obj_init_stb_id_account) {
      rv = xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_id_account, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, account_id);  
   } else {
      int rc = 0;
      json_t *obj_values = json_object_get(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES);
      if(obj_values == NULL) {
         obj_values = json_array();
         rc |= json_object_set_new_nocheck(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUES, obj_values);
      }
      if((obj->obj_init_stb_id_account = json_object()) == NULL) {
         rv = false;
      } else {
         rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_account, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, json_string(XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE_ACCOUNT_ID));
         rc |= json_object_set_new_nocheck(obj->obj_init_stb_id_account, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_VALUE, json_string(account_id));
         rc |= json_array_append_new(obj_values, obj->obj_init_stb_id_account);
         if(rc != 0) {
            XLOGD_ERROR("object set error");
            rv = false;
         }
      }
   }
   return(rv);
}

bool xrsv_ws_nextgen_update_device_type(xrsv_ws_nextgen_object_t object, xrsv_ws_nextgen_device_type_t device_type) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   if(device_type == XRSV_WS_NEXTGEN_DEVICE_TYPE_STB) {
      return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE_VALUE_STB));
   } else if(device_type == XRSV_WS_NEXTGEN_DEVICE_TYPE_TV) {
      return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_TYPE_VALUE_TV));
   }

   XLOGD_ERROR("invalid device type");
   return(false);
}

bool xrsv_ws_nextgen_update_partner_id(xrsv_ws_nextgen_object_t object, const char *partner_id) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_id, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_ID_PARTNER, partner_id));
}
 
bool xrsv_ws_nextgen_update_experience(xrsv_ws_nextgen_object_t object, const char *experience) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_EXPERIENCE, experience));
}

bool xrsv_ws_nextgen_update_audio_profile(xrsv_ws_nextgen_object_t object, const char *audio_profile) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_PROFILE, audio_profile));
}

bool xrsv_ws_nextgen_update_audio_model(xrsv_ws_nextgen_object_t object, const char *audio_model) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_MODEL, audio_model));
}

bool xrsv_ws_nextgen_update_audio_rf_protocol(xrsv_ws_nextgen_object_t object, const char *rf_protocol) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_RF_PROTOCOL, rf_protocol));
}

bool xrsv_ws_nextgen_update_language(xrsv_ws_nextgen_object_t object, const char *language) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   return(xrsv_ws_nextgen_update_json_str(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_LANG, language));
}

bool xrsv_ws_nextgen_update_mask_pii(xrsv_ws_nextgen_object_t object, bool enable) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   obj->mask_pii = enable;
   return(true);
}

bool xrsv_ws_nextgen_update_init_app(xrsv_ws_nextgen_object_t object, const char *blob) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }

   // Clean up old app blob
   if(obj->obj_init_app) {
      json_array_remove(obj->obj_init_elements, XRSV_WS_NEXTGEN_JSON_ELEMENT_APP_INDEX);
      obj->obj_init_app = NULL;
   }

   // Load new app blob
   obj->obj_init_app = json_loads((const char *)blob, JSON_REJECT_DUPLICATES, NULL);
   if(obj->obj_init_app == NULL || !json_is_object(obj->obj_init_app)) {
      XLOGD_ERROR("invalid app blob.. null or not object");
      return(false);
   }

   if(json_array_insert_new(obj->obj_init_elements, XRSV_WS_NEXTGEN_JSON_ELEMENT_APP_INDEX, obj->obj_init_app) != 0) {
      XLOGD_ERROR("failed to insert app blob to element array");
      json_decref(obj->obj_init_app);
      obj->obj_init_app = NULL;
      return(false);
   }
   return(true);
}

bool xrsv_ws_nextgen_send_msg(xrsv_ws_nextgen_object_t object, const char *msg) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   xrsr_result_t res = XRSR_RESULT_ERROR;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }

   if(obj->send) {
      if(msg) {
         XLOGD_INFO("msg <%s>", obj->mask_pii ? "***" : msg);
         res = obj->send(obj->param, (const unsigned char *)msg, strlen(msg));
      } else {
         XLOGD_ERROR("msg is null...");
      }
   }
   return((res == XRSR_RESULT_SUCCESS ? true : false));
}

void xrsv_ws_nextgen_destroy(xrsv_ws_nextgen_object_t object) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)object;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   XLOGD_INFO("");

   if(obj->obj_init != NULL) {
      XLOGD_INFO("free init object");
      json_decref(obj->obj_init);
      obj->obj_init = NULL;
   }
   if(obj->obj_stream_begin != NULL) {
      XLOGD_INFO("free stream begin object");
      json_decref(obj->obj_stream_begin);
      obj->obj_stream_begin = NULL;
   }
   if(obj->obj_stream_end != NULL) {
      XLOGD_INFO("free stream end object");
      json_decref(obj->obj_stream_end);
      obj->obj_stream_end = NULL;
   }
   obj->query_element_device_id[0]     = '\0';
   obj->query_element_trx[0]           = '\0';
   obj->query_element_version[0]       = '\0';
   obj->identifier                     = 0;
   free(obj);
}

void xrsv_ws_nextgen_handler_ws_source_error(void *data, xrsr_src_t src) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }

   if(obj->handlers.source_error != NULL) {
      (*obj->handlers.source_error)(src, obj->user_data);
   }
}

void xrsv_ws_nextgen_handler_ws_session_begin(void *data, const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_keyword_detector_result_t *detector_result, xrsr_session_config_out_t *config_out, xrsr_session_config_in_t *config_in, rdkx_timestamp_t *timestamp, const char *transcription_in) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   char uuid_str[37] = {'\0'};
   int rc = 0;
   xrsv_ws_nextgen_stream_params_t stream_params;

   if(detector_result != NULL) {
      stream_params.keyword_sample_begin               = detector_result->offset_kwd_begin - detector_result->offset_buf_begin;
      stream_params.keyword_sample_end                 = detector_result->offset_kwd_end   - detector_result->offset_buf_begin;
      stream_params.keyword_doa                        = detector_result->doa;
      stream_params.keyword_sensitivity                = detector_result->sensitivity;
      stream_params.keyword_sensitivity_triggered      = true;
      stream_params.keyword_sensitivity_high           = 0.0;
      stream_params.keyword_sensitivity_high_support   = false;
      stream_params.keyword_sensitivity_high_triggered = false;
      stream_params.keyword_gain                       = detector_result->kwd_gain;
      stream_params.dynamic_gain                       = detector_result->dynamic_gain;
      stream_params.linear_confidence                  = detector_result->score;
      stream_params.nonlinear_confidence               = 0;
      stream_params.signal_noise_ratio                 = detector_result->snr; // if NULL 255.0 is invalid value;
      stream_params.par_eos_timeout                    = 0;
      stream_params.push_to_talk                       = false;
      stream_params.detector_name                      = (detector_result->detector_name) ? detector_result->detector_name : "unknown";
      stream_params.dsp_name                           = (detector_result->dsp_name)      ? detector_result->dsp_name      : "unknown";
   }

   obj->user_initiated       = config_out->user_initiated;
   obj->first_audio_stream   = true;
   uuid_copy(obj->uuid, uuid);

   if(obj->handlers.session_begin != NULL) {
      (*obj->handlers.session_begin)(uuid, src, dst_index, config_out, (detector_result == NULL) ? NULL : &stream_params, timestamp, obj->user_data);
   }

   // Clear previous audio data
   json_object_del(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW);
   // End Clear

   if (transcription_in != NULL) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_TEXT, json_string(transcription_in));
   } else {
      // Make sure this is cleared in case previous session created it.
      json_object_del(obj->obj_init_stb, XRSV_WS_NEXTGEN_JSON_KEY_TEXT);
   }
   // Root Object
   uuid_unparse_lower(uuid, uuid_str);
   rc |= json_object_set_new_nocheck(obj->obj_init, XRSV_WS_NEXTGEN_JSON_KEY_TRX, json_string(uuid_str));
   // End Root Object

   // SOS object
   rc |= json_object_set_new_nocheck(obj->obj_stream_begin, XRSV_WS_NEXTGEN_JSON_KEY_TRX, json_string(uuid_str));
   // End SOS object

   // EOS object
   rc |= json_object_set_new_nocheck(obj->obj_stream_end, XRSV_WS_NEXTGEN_JSON_KEY_TRX, json_string(uuid_str));
   // End EOS object

   if(rc != 0) {
      XLOGD_ERROR("object set failed");
   }

   // Add attribute-value pairs to query string
   snprintf(obj->query_element_trx, sizeof(obj->query_element_trx), "trx=%s", uuid_str);

   uint32_t i = 0;
   config_in->ws.query_strs[i] = obj->query_element_version;
   i++;
   if(obj->query_element_device_id[0] != '\0') {
      config_in->ws.query_strs[i] = obj->query_element_device_id;
      i++;
   }
   config_in->ws.query_strs[i] = obj->query_element_trx;
   i++;

   config_in->ws.query_strs[i] = NULL;
}

void xrsv_ws_nextgen_handler_ws_session_config(void *data, const uuid_t uuid, xrsr_session_config_in_t *config_in) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   int rc = 0;

   if(config_in == NULL || config_in->ws.app_config == NULL) {
      XLOGD_ERROR("invalid stream params <%p>", config_in);
      return;
   }

   xrsv_ws_nextgen_stream_params_t *stream_params = (xrsv_ws_nextgen_stream_params_t *)config_in->ws.app_config;

   if (stream_params->par_eos_timeout > 0) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TIMEOUT, json_integer(stream_params->par_eos_timeout));
   } else {
      json_object_del(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TIMEOUT);
   }

   // Audio Object
   rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TRIGGER_TIME, json_integer(xrsv_ws_nextgen_time_get()));
   if(obj->user_initiated || stream_params->push_to_talk) {
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TRIGGER, json_string(XRSV_WS_NEXTGEN_JSON_ELEMENT_AUDIO_TRIGGER_PTT));
   } else {
      json_t *obj_wuw      = json_object();
      json_t *obj_detector = json_object();
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_DYNAMIC_GAIN, json_real(stream_params->dynamic_gain));
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_TRIGGER, json_string(XRSV_WS_NEXTGEN_JSON_ELEMENT_AUDIO_TRIGGER_WUW));
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW, obj_wuw);

      // WUW Object
      rc |= json_object_set_new_nocheck(obj_wuw, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_START, json_integer(stream_params->keyword_sample_begin));
      rc |= json_object_set_new_nocheck(obj_wuw, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_END, json_integer(stream_params->keyword_sample_end));
      rc |= json_object_set_new_nocheck(obj_wuw, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DSP_PREPROCESSING, json_string(stream_params->dsp_name));

      rc |= json_object_set_new_nocheck(obj_wuw, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR, obj_detector);
      // Detector Object

      rc |= json_object_set_new_nocheck(obj_detector, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_SENSITIVITY, json_real(stream_params->keyword_sensitivity));
      rc |= json_object_set_new_nocheck(obj_detector, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_SENS_TRIG, stream_params->keyword_sensitivity_triggered ? json_true() : json_false());

      rc |= json_object_set_new_nocheck(obj_detector, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_VENDOR, json_string(stream_params->detector_name));
      rc |= json_object_set_new_nocheck(obj_detector, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_GAIN, json_real(stream_params->keyword_gain));
      rc |= json_object_set_new_nocheck(obj_detector, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_SNR, json_real(stream_params->signal_noise_ratio));
      if(stream_params->nonlinear_confidence > 0) {
         rc |= json_object_set_new_nocheck(obj_detector, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_NONLINEAR, json_integer(stream_params->nonlinear_confidence));
      }
      if(stream_params->linear_confidence > 0) {
         rc |= json_object_set_new_nocheck(obj_detector, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_WUW_DETECTOR_LINEAR, json_real(stream_params->linear_confidence));
      }
      // End Detector Object
      // End WUW Object
   }
   // End Audio Object

   if(rc != 0) {
      XLOGD_ERROR("object set failed");
   }

   free(stream_params);
}

void xrsv_ws_nextgen_handler_ws_session_end(void *data, const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(obj->handlers.session_end != NULL) {
      (*obj->handlers.session_end)(uuid, stats, timestamp, obj->user_data);
   }

   obj->query_element_trx[0] = '\0';
}

void xrsv_ws_nextgen_handler_ws_stream_begin(void *data, const uuid_t uuid, xrsr_src_t src, rdkx_timestamp_t *timestamp) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(!obj->first_audio_stream && obj->send != NULL) { // Create 'start of stream' message.  Note: This may need to be done in the application's context
      uint8_t *buffer = NULL;
      uint32_t length = 0;
      xrsv_ws_nextgen_msg_stream_begin(obj, &buffer, &length);

      if(buffer == NULL || length == 0) {
         XLOGD_ERROR("invalid message");
      } else {
         XLOGD_INFO("msg stream begin <%s>", buffer);

         xrsr_result_t result = (*obj->send)(obj->param, buffer, length);
         free(buffer);

         if(result != XRSR_RESULT_SUCCESS) {
            XLOGD_ERROR("result <%s>", xrsr_result_str(result));
         }
      }
   }
   obj->first_audio_stream = false;

   if(obj->handlers.stream_begin != NULL) {
      (*obj->handlers.stream_begin)(uuid, src, timestamp, obj->user_data);
   }
}

void xrsv_ws_nextgen_handler_ws_stream_kwd(void *data, const uuid_t uuid, rdkx_timestamp_t *timestamp) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(obj->handlers.stream_kwd != NULL) {
      (*obj->handlers.stream_kwd)(uuid, timestamp, obj->user_data);
   }
}

void xrsv_ws_nextgen_handler_ws_stream_end(void *data, const uuid_t uuid, xrsr_stream_stats_t *stats, rdkx_timestamp_t *timestamp) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   if(obj->send != NULL) { // Create 'end of stream' message.  Note: This may need to be done in the application's context
      uint8_t *buffer = NULL;
      uint32_t length = 0;
      xrsv_ws_nextgen_msg_stream_end(obj, 0, &buffer, &length);

      if(buffer == NULL || length == 0) {
         XLOGD_ERROR("invalid message");
      } else {
         XLOGD_INFO("msg stream end <%s>", buffer);

         xrsr_result_t result = (*obj->send)(obj->param, buffer, length);
         free(buffer);

         if(result != XRSR_RESULT_SUCCESS) {
            XLOGD_ERROR("result <%s>", xrsr_result_str(result));
         }
      }
   }

   if(obj->handlers.stream_end != NULL) {
      (*obj->handlers.stream_end)(uuid, stats, timestamp, obj->user_data);
   }
}

bool xrsv_ws_nextgen_handler_ws_connected(void *data, const uuid_t uuid, xrsr_handler_send_t send, void *param, rdkx_timestamp_t *timestamp, xrsr_session_config_update_t *session_config_update) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return false;
   }

   if(obj->handlers.connected != NULL) {
      (*obj->handlers.connected)(uuid, timestamp, obj->user_data);
   }

   // Store connection send function and param
   obj->send  = send;
   obj->param = param;
   obj->session_config_update = session_config_update;

   // Create speech init message
   uint8_t *buffer = NULL;
   uint32_t length = 0;
   xrsv_ws_nextgen_msg_init(obj, &buffer, &length);
   
   if(buffer == NULL || length == 0) {
      XLOGD_ERROR("invalid message");
      return false;
   }
   XLOGD_INFO("msg init <%s>", obj->mask_pii ? "***" : (char *)buffer);
   
   xrsr_result_t result = (*send)(param, buffer, length);
   free(buffer);

   if(result != XRSR_RESULT_SUCCESS) {
      XLOGD_ERROR("result <%s>", xrsr_result_str(result));
   }
   if(obj->handlers.sent_init != NULL) {
      rdkx_timestamp_t ts_sent_init;
      rdkx_timestamp_get_realtime(&ts_sent_init);
      (*obj->handlers.sent_init)(uuid, &ts_sent_init, obj->user_data);
   }
   return (result == XRSR_RESULT_SUCCESS);
}

void xrsv_ws_nextgen_handler_ws_disconnected(void *data, const uuid_t uuid, xrsr_session_end_reason_t reason, bool retry, bool *detect_resume, rdkx_timestamp_t *timestamp) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   obj->send  = NULL;
   obj->param = NULL;
   if(detect_resume != NULL) {
      *detect_resume = true;
   }
   if(obj->handlers.disconnected != NULL) {
      (*obj->handlers.disconnected)(uuid, retry, timestamp, obj->user_data);
   }
}

bool xrsv_ws_nextgen_handler_ws_recv_msg(void *data, xrsr_recv_msg_t type, const uint8_t *buffer, uint32_t length, xrsr_recv_event_t *recv_event) {
   xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   XLOGD_INFO("type <%s> length <%u>", xrsr_recv_msg_str(type), length);
   if(type == XRSR_RECV_MSG_TEXT && obj->handlers.msg) {
      obj->handlers.msg((const char *)buffer, length, obj->user_data);
   }

   json_error_t error;
   json_t *obj_json = json_loads((const char *)buffer, JSON_REJECT_DUPLICATES, &error);
   if(obj_json == NULL) {
      XLOGD_ERROR("invalid json");
      return(false);
   } else if(!json_is_object(obj_json)) {
      XLOGD_ERROR("json object not found");
      return(false);
   }
   bool retval = xrsv_ws_nextgen_msg_decode(obj, obj_json);
   json_decref(obj_json);

   if(recv_event == NULL) {
      XLOGD_ERROR("null event pointer");
      retval = false;
   } else {
      *recv_event = obj->recv_event;
   }
   obj->recv_event = XRSR_RECV_EVENT_NONE;

   return(retval);
}


void xrsv_ws_nextgen_msg_init(xrsv_ws_nextgen_obj_t *obj, uint8_t **buffer, uint32_t *length) {
   json_t *obj_init = obj->obj_init;
   int rc;
   
   // Update the dynamic values
   rc  = json_object_set_new_nocheck(obj_init, XRSV_WS_NEXTGEN_JSON_KEY_CREATED, json_integer(xrsv_ws_nextgen_time_get()));

   if( (obj->session_config_update != NULL) && (obj->session_config_update->update_required == true) ) {
      XLOGD_INFO("Updating dynamic_gain to <%f>", obj->session_config_update->dynamic_gain);
      rc |= json_object_set_new_nocheck(obj->obj_init_stb_audio, XRSV_WS_NEXTGEN_JSON_KEY_ELEMENT_AUDIO_DYNAMIC_GAIN, json_real(obj->session_config_update->dynamic_gain));
   }

   
   if(rc != 0) {
      XLOGD_ERROR("object set failed");
   }

   *buffer = (uint8_t *)json_dumps(obj_init, JSON_COMPACT);
   if(*buffer == NULL) {
      *length = 0;
      XLOGD_ERROR("unable to dump json");
      return;
   }
   *length = strlen((const char *)(*buffer));
}

void xrsv_ws_nextgen_msg_stream_begin(xrsv_ws_nextgen_obj_t *obj, uint8_t **buffer, uint32_t *length) {
   json_t *obj_stream_begin = obj->obj_stream_begin;
   int rc;

   // Update the dynamic values
   rc  = json_object_set_new_nocheck(obj_stream_begin, XRSV_WS_NEXTGEN_JSON_KEY_CREATED, json_integer(xrsv_ws_nextgen_time_get()));

   if(rc != 0) {
      XLOGD_ERROR("object set failed");
   }

   *buffer = (uint8_t *)json_dumps(obj_stream_begin, JSON_COMPACT);
   if(*buffer == NULL) {
      *length = 0;
      XLOGD_ERROR("unable to dump json");
      return;
   }
   *length = strlen((const char *)(*buffer));
}

void xrsv_ws_nextgen_msg_stream_end(xrsv_ws_nextgen_obj_t *obj, int32_t reason, uint8_t **buffer, uint32_t *length) {
   json_t *obj_stream_end = obj->obj_stream_end;
   int rc;

   // Update the dynamic values
   rc  = json_object_set_new_nocheck(obj->obj_stream_end, XRSV_WS_NEXTGEN_JSON_KEY_CREATED, json_integer(xrsv_ws_nextgen_time_get()));
   rc |= json_object_set_new_nocheck(obj->obj_stream_end_payload, XRSV_WS_NEXTGEN_JSON_KEY_REASON, json_integer(reason));

   if(rc != 0) {
      XLOGD_ERROR("object set failed");
   }

   *buffer = (uint8_t *)json_dumps(obj_stream_end, JSON_COMPACT);
   if(*buffer == NULL) {
      *length = 0;
      XLOGD_ERROR("unable to dump json");
      return;
   }
   *length = strlen((const char *)(*buffer));
}

uint64_t xrsv_ws_nextgen_time_get(void) {
    struct timespec ts;
    errno = 0;
    if(clock_gettime(CLOCK_REALTIME, &ts)) {
       int errsv = errno;
       XLOGD_ERROR("unable to get clock <%s>", strerror(errsv));
       return(0);
    }
    // Return the time in milliseconds since epoch
    return(((uint64_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));
}

bool xrsv_ws_nextgen_msg_decode(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   if(xlog_level_active(XLOG_MODULE_ID, XLOG_LEVEL_INFO)) {
      char *str = json_dumps(obj_json, JSON_SORT_KEYS | JSON_INDENT(3));
      XLOGD_INFO("obj \n<%s>", (str == NULL) ? "NULL" : obj->mask_pii ? "***" : str );
      if(str != NULL) {
         free(str);
      }
   }

   json_t *obj_msg_type = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_MSG_TYPE);

   if(obj_msg_type == NULL || !json_is_string(obj_msg_type)) {
      XLOGD_ERROR("message type invalid");
      return(false);
   }
   const char *str_msg_type = json_string_value(obj_msg_type);

   // Call handler based on request type
   xrsv_ws_nextgen_msgtype_handler_t *handler = (str_msg_type == NULL) ? NULL : xrsv_ws_nextgen_msgtype_handler_get(str_msg_type, strlen(str_msg_type));

   if(handler == NULL) {
      XLOGD_ERROR("no handler for msgtype <%s>", (str_msg_type == NULL) ? "NULL" : str_msg_type);
      return(false);
   }

   return((*handler->func)(obj, json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_MSG_PAYLOAD)));
}

bool xrsv_ws_nextgen_msgtype_asr(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   json_t *obj_tran = json_object_get(obj_json, "text");
   json_t *obj_final = json_object_get(obj_json, "isFinal");
   const char *str_tran = NULL;
   bool final = true; // default to true..

   if(obj_tran != NULL && json_is_string(obj_tran)) {
      str_tran = json_string_value(obj_tran);
   }

   if(obj_final != NULL && !json_is_true(obj_final)) {
      final = false;
   }

   XLOGD_INFO("transcription <%s>", (str_tran == NULL) ? "NULL" : obj->mask_pii ? "***" : str_tran);
   if(obj->handlers.asr != NULL) {
      (*obj->handlers.asr)(str_tran, final, obj->user_data);
   }
   return(false);
}

bool xrsv_ws_nextgen_msgtype_listening(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.listening != NULL) {
      (*obj->handlers.listening)(obj->user_data);
   }
   return(false);
}

bool xrsv_ws_nextgen_msgtype_conn_close(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.conn_close != NULL) {
      // Get Reason
      json_t *obj_reason     = NULL;
      const char *str_reason = NULL;
      if(obj_json) {
         obj_reason = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_REASON);
         if(obj_reason && json_is_string(obj_reason)) {
            str_reason = json_string_value(obj_reason);
         }
      }

      // Get Return Code
      int code         = 0;
      json_t *obj_code = NULL;
      if(obj_json) {
         obj_code = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_RETURN_CODE);
         if(obj_code && json_is_integer(obj_code)) {
            code = json_integer_value(obj_code);
         }
      }

      obj->handlers.conn_close(str_reason, code, obj->user_data);
   }
   return(true);
}

bool xrsv_ws_nextgen_msgtype_response_vrex(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.response_vrex != NULL) {
      // Get Return Code
      int code         = -1;
      json_t *obj_code = NULL;
      if(obj_json) {
         obj_code = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_RETURN_CODE);
         if(obj_code && json_is_integer(obj_code)) {
            code = json_integer_value(obj_code);
         }
      }
      obj->handlers.response_vrex(code, obj->user_data);
   }

   // Either way, update the context in the init object
   if(obj_json) {
      json_t *obj_command = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_LAST_COMMAND);
      if(obj_command && json_is_object(obj_command)) {
         json_t *arr_context = json_array(), *obj_context = json_object();
         int rc = json_object_set_nocheck(obj_context, XRSV_WS_NEXTGEN_JSON_KEY_LAST_COMMAND, obj_command);
         rc |= json_array_append_new(arr_context, obj_context);
         rc |= json_object_set_new_nocheck(obj->obj_init_payload, XRSV_WS_NEXTGEN_JSON_KEY_CONTEXT, arr_context);
         // TODO check rc
      }
   }
   return(false);
}

bool xrsv_ws_nextgen_msgtype_wuw_verification(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   if(obj->handlers.wuw_verification != NULL) {
      // Get Passed
      bool passed        = true;
      json_t *obj_passed = NULL;
      if(obj_json) {
         obj_passed = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_PASSED);
         if(obj_passed && json_is_boolean(obj_passed)) {
            passed = json_is_true(obj_passed);
         }
      }

      // Get Confidence
      int confidence         = 0;
      json_t *obj_confidence = NULL;
      if(obj_json) {
         obj_confidence = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_CONFIDENCE);
         if(obj_confidence && json_is_integer(obj_confidence)) {
            confidence = json_integer_value(obj_confidence);
         }
      }
      obj->handlers.wuw_verification(obj->uuid, passed, confidence, obj->user_data);
   }
   return(false);
}

bool xrsv_ws_nextgen_msgtype_server_stream_end(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   int reason         = -1;
   json_t *obj_reason = NULL;

   if(!xrsv_ws_nextgen_object_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }

   obj_reason = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_REASON);
   if(obj_reason == NULL || !json_is_integer(obj_reason)) {
      XLOGD_ERROR("failed to get stream end reason");
      return false;
   }

   reason = json_integer_value(obj_reason);
   obj->recv_event = (reason == XRSV_STREAM_END_END_OF_SPEECH ? XRSR_RECV_EVENT_EOS_SERVER : XRSR_RECV_EVENT_DISCONNECT_REMOTE);

   if(reason == XRSV_STREAM_END_END_OF_SPEECH) {
      return(false);
   } else {
      return(true);
   }
}

bool xrsv_ws_nextgen_msgtype_tv_control(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   json_t *obj_msg_type = json_object_get(obj_json, XRSV_WS_NEXTGEN_JSON_KEY_ACTION);

   if(obj_msg_type == NULL || !json_is_string(obj_msg_type)) {
      XLOGD_ERROR("message type invalid");
      return(false);
   }
   const char *str_msg_type = json_string_value(obj_msg_type);

   // Call handler based on request type
   xrsv_ws_nextgen_tv_control_handler_t *handler = (str_msg_type == NULL) ? NULL : xrsv_ws_nextgen_tv_control_handler_get(str_msg_type, strlen(str_msg_type));

   if(handler == NULL) {
      XLOGD_ERROR("no handler for msgtype <%s>", (str_msg_type == NULL) ? "NULL" : str_msg_type);
      return(false);
   }

   (*handler->func)(obj, obj_json);

   return(false);
}

void xrsv_ws_nextgen_tv_control_power_on(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.tv_power != NULL) {
      (*obj->handlers.tv_power)(true, false, obj->user_data);
   }
}

void xrsv_ws_nextgen_tv_control_power_on_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.tv_power != NULL) {
      (*obj->handlers.tv_power)(true, true, obj->user_data);
   }
}

void xrsv_ws_nextgen_tv_control_power_off(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.tv_power != NULL) {
      (*obj->handlers.tv_power)(false, false, obj->user_data);
   }
}

void xrsv_ws_nextgen_tv_control_power_off_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.tv_power != NULL) {
      (*obj->handlers.tv_power)(false, true, obj->user_data);
   }
}

void xrsv_ws_nextgen_tv_control_volume_up(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   uint32_t ir_repeat_count = 1;
   XLOGD_INFO("ir repeat count <%u> - at the time of development, server didn't implement..", ir_repeat_count);
   if(obj->handlers.tv_volume != NULL) {
      (*obj->handlers.tv_volume)(true, ir_repeat_count, obj->user_data);
   }
}

void xrsv_ws_nextgen_tv_control_volume_down(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   uint32_t ir_repeat_count = 1;
   XLOGD_INFO("ir repeat count <%u> - at the time of development, server didn't implement..", ir_repeat_count);
   if(obj->handlers.tv_volume != NULL) {
      (*obj->handlers.tv_volume)(false, ir_repeat_count, obj->user_data);
   }
}

void xrsv_ws_nextgen_tv_control_volume_mute_toggle(xrsv_ws_nextgen_obj_t *obj, json_t *obj_json) {
   XLOGD_INFO("");
   if(obj->handlers.tv_mute != NULL) {
      (*obj->handlers.tv_mute)(true, obj->user_data);
   }
}
