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
#ifdef HTTP_ENABLED
#define USE_CURL_UNESCAPE
#include <curl/curl.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "xrsr_private.h"

#define XRSR_INVALID_STR_LEN (24)

static char xrsr_invalid_str[XRSR_INVALID_STR_LEN];

static const char *xrsr_invalid_return(int value);

const char *xrsr_invalid_return(int value) {
   snprintf(xrsr_invalid_str, XRSR_INVALID_STR_LEN, "INVALID(%d)", value);
   xrsr_invalid_str[XRSR_INVALID_STR_LEN - 1] = '\0';
   return(xrsr_invalid_str);
}

const char *xrsr_src_str(xrsr_src_t src) {
   switch(src) {
      case XRSR_SRC_RCU_PTT:        return("RCU_PTT");
      case XRSR_SRC_RCU_FF:         return("RCU_FF");
      case XRSR_SRC_MICROPHONE:     return("MICROPHONE");
      case XRSR_SRC_MICROPHONE_TAP: return("MICROPHONE_TAP");
      case XRSR_SRC_INVALID:        return("INVALID");
   }
   return(xrsr_invalid_return(src));
}

const char *xrsr_result_str(xrsr_result_t type) {
   switch(type) {
      case XRSR_RESULT_SUCCESS: return("SUCCESS");
      case XRSR_RESULT_ERROR:   return("ERROR");
      case XRSR_RESULT_INVALID: return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_session_request_type_str(xrsr_session_request_type_t type) {
   switch(type) {
      case XRSR_SESSION_REQUEST_TYPE_TEXT:       return("TEXT");
      case XRSR_SESSION_REQUEST_TYPE_AUDIO_FILE: return("AUDIO_FILE");
      case XRSR_SESSION_REQUEST_TYPE_AUDIO_FD:   return("AUDIO_FD");
      case XRSR_SESSION_REQUEST_TYPE_AUDIO_MIC:  return("AUDIO_MIC");
      case XRSR_SESSION_REQUEST_TYPE_INVALID:    return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_queue_msg_type_str(xrsr_queue_msg_type_t type) {
   switch(type) {
      case XRSR_QUEUE_MSG_TYPE_TERMINATE:                               return("TERMINATE");
      case XRSR_QUEUE_MSG_TYPE_ROUTE_UPDATE:                            return("ROUTE_UPDATE");
      case XRSR_QUEUE_MSG_TYPE_KEYWORD_UPDATE:                          return("KEYWORD_UPDATE");
      case XRSR_QUEUE_MSG_TYPE_HOST_NAME_UPDATE:                        return("HOST_NAME_UPDATE");
      case XRSR_QUEUE_MSG_TYPE_CAPTURE_CONFIG_UPDATE:                   return("CAPTURE_CONFIG_UPDATE");
      case XRSR_QUEUE_MSG_TYPE_POWER_MODE_UPDATE:                       return("POWER_MODE_UPDATE");
      case XRSR_QUEUE_MSG_TYPE_PRIVACY_MODE_UPDATE:                     return("PRIVACY_MODE_UPDATE");
      case XRSR_QUEUE_MSG_TYPE_PRIVACY_MODE_GET:                        return("PRIVACY_MODE_GET");
      case XRSR_QUEUE_MSG_TYPE_XRAUDIO_GRANTED:                         return("XRAUDIO_GRANT");
      case XRSR_QUEUE_MSG_TYPE_XRAUDIO_REVOKED:                         return("XRAUDIO_REVOKE");
      case XRSR_QUEUE_MSG_TYPE_XRAUDIO_EVENT:                           return("XRAUDIO_EVENT");
      case XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECTED:                        return("KEYWORD_DETECTED");
      case XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECT_ERROR:                    return("KEYWORD_DETECT_ERROR");
      case XRSR_QUEUE_MSG_TYPE_KEYWORD_DETECT_SENSITIVITY_LIMITS_GET:   return("KEYWORD_DETECT_SENSITIVITY_LIMITS_GET");
      case XRSR_QUEUE_MSG_TYPE_SESSION_BEGIN:                           return("SESSION_BEGIN");
      case XRSR_QUEUE_MSG_TYPE_SESSION_CONFIG_IN:                       return("SESSION_CONFIG_IN");
      case XRSR_QUEUE_MSG_TYPE_SESSION_TERMINATE:                       return("SESSION_TERMINATE");
      case XRSR_QUEUE_MSG_TYPE_SESSION_AUDIO_STREAM_START:              return("AUDIO_STREAM_START");
      case XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_START:                   return("SESSION_CAPTURE_START");
      case XRSR_QUEUE_MSG_TYPE_SESSION_CAPTURE_STOP:                    return("SESSION_CAPTURE_STOP");
      case XRSR_QUEUE_MSG_TYPE_THREAD_POLL:                             return("THREAD_POLL");
      case XRSR_QUEUE_MSG_TYPE_INVALID:                                 return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_xraudio_state_str(xrsr_xraudio_state_t type) {
   switch(type) {
      case XRSR_XRAUDIO_STATE_CREATED:   return("CREATED");
      case XRSR_XRAUDIO_STATE_REQUESTED: return("REQUESTED");
      case XRSR_XRAUDIO_STATE_GRANTED:   return("GRANTED");
      case XRSR_XRAUDIO_STATE_OPENED:    return("OPENED");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_protocol_str(xrsr_protocol_t type) {
   switch(type) {
      case XRSR_PROTOCOL_HTTP:    return("HTTP");
      case XRSR_PROTOCOL_HTTPS:   return("HTTPS");
      case XRSR_PROTOCOL_WS:      return("WS");
      case XRSR_PROTOCOL_WSS:     return("WSS");
      case XRSR_PROTOCOL_SDT:     return("SDT");
      case XRSR_PROTOCOL_INVALID: return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_session_end_reason_str(xrsr_session_end_reason_t type) {
   switch(type) {
      case XRSR_SESSION_END_REASON_EOS:                     return("EOS");
      case XRSR_SESSION_END_REASON_EOT:                     return("EOT");
      case XRSR_SESSION_END_REASON_DISCONNECT_REMOTE:       return("DISCONNECT_REMOTE");
      case XRSR_SESSION_END_REASON_TERMINATE:               return("TERMINATE");
      case XRSR_SESSION_END_REASON_ERROR_INTERNAL:          return("ERROR_INTERNAL");
      case XRSR_SESSION_END_REASON_ERROR_WS_SEND:           return("ERROR_WS_SEND");
      case XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN:       return("ERROR_AUDIO_BEGIN");
      case XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION:    return("ERROR_AUDIO_DURATION");
      case XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE:   return("ERROR_CONNECT_FAILURE");
      case XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT:   return("ERROR_CONNECT_TIMEOUT");
      case XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT:   return("ERROR_SESSION_TIMEOUT");
      case XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE: return("ERROR_DISCONNECT_REMOTE");
      case XRSR_SESSION_END_REASON_INVALID:                 return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_stream_end_reason_str(xrsr_stream_end_reason_t type) {
   switch(type) {
      case XRSR_STREAM_END_REASON_AUDIO_EOF:         return("AUDIO_EOF");
      case XRSR_STREAM_END_REASON_DISCONNECT_REMOTE: return("DISCONNECT_REMOTE");
      case XRSR_STREAM_END_REASON_DISCONNECT_LOCAL:  return("DISCONNECT_LOCAL");
      case XRSR_STREAM_END_REASON_ERROR_AUDIO_READ:  return("ERROR_AUDIO_READ");
      case XRSR_STREAM_END_REASON_DID_NOT_BEGIN:     return("DID_NOT_BEGIN");
      case XRSR_STREAM_END_REASON_INVALID:           return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_recv_msg_str(xrsr_recv_msg_t type) {
   switch(type) {
      case XRSR_RECV_MSG_TEXT:    return("TEXT");
      case XRSR_RECV_MSG_BINARY:  return("BINARY");
      case XRSR_RECV_MSG_INVALID: return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

const char *xrsr_audio_format_str(xrsr_audio_format_type_t format) {
   switch(format) {
      case XRSR_AUDIO_FORMAT_PCM:              return("PCM");
      case XRSR_AUDIO_FORMAT_PCM_32_BIT:       return("PCM_32_BIT");
      case XRSR_AUDIO_FORMAT_PCM_32_BIT_MULTI: return("PCM_32_BIT_MULTI");
      case XRSR_AUDIO_FORMAT_PCM_RAW:          return("PCM_RAW");
      case XRSR_AUDIO_FORMAT_ADPCM_FRAME:      return("ADPCM_FRAME");
      case XRSR_AUDIO_FORMAT_OPUS:             return("OPUS");
      case XRSR_AUDIO_FORMAT_NONE:             return("NONE");
      default: break;
   }
   return(xrsr_invalid_return(format));
}

const char *xrsr_audio_format_bitmask_str(xrsr_audio_format_type_t formats) {
   static char str[32];
   uint32_t i = 0;
   bool comma = false;

   if(formats == XRSR_AUDIO_FORMAT_NONE) {
      return(xrsr_audio_format_str(formats));
   }

   str[0] = '\0';

   for(i = 1; i < XRSR_AUDIO_FORMAT_MAX; i = i << 1) {
      if(formats & i) {
         if(comma) {
            strlcat(str, ", ", sizeof(str));
         }
         strlcat(str, xrsr_audio_format_str(i), sizeof(str));
         comma = true;
      }
   }

   return(str);
}

const char *xrsr_stream_from_str(xrsr_stream_from_t stream_from) {
   switch(stream_from) {
      case XRSR_STREAM_FROM_BEGINNING:     return("BEGINNING");
      case XRSR_STREAM_FROM_LIVE:          return("LIVE");
      case XRSR_STREAM_FROM_KEYWORD_BEGIN: return("KEYWORD_BEGIN");
      case XRSR_STREAM_FROM_KEYWORD_END:   return("KEYWORD_END");
      case XRSR_STREAM_FROM_INVALID:       return("INVALID");
   }
   return(xrsr_invalid_return(stream_from));
}

const char *xrsr_stream_until_str(xrsr_stream_until_t stream_until) {
   switch(stream_until) {
      case XRSR_STREAM_UNTIL_END_OF_STREAM:  return("END_OF_STREAM");
      case XRSR_STREAM_UNTIL_END_OF_SPEECH:  return("END_OF_SPEECH");
      case XRSR_STREAM_UNTIL_END_OF_KEYWORD: return("END_OF_KEYWORD");
      case XRSR_STREAM_UNTIL_INVALID:        return("INVALID");
   }
   return(xrsr_invalid_return(stream_until));
}

const char *xrsr_power_mode_str(xrsr_power_mode_t power_mode) {
   switch(power_mode) {
      case XRSR_POWER_MODE_FULL:    return("FULL");
      case XRSR_POWER_MODE_LOW:     return("LOW");
      case XRSR_POWER_MODE_SLEEP:   return("SLEEP");
      case XRSR_POWER_MODE_INVALID: return("INVALID");
   }
   return(xrsr_invalid_return(power_mode));
}

const char *xrsr_address_family_str(xrsr_address_family_t family) {
   switch(family) {
      case XRSR_ADDRESS_FAMILY_IPV4:    return("IPV4");
      case XRSR_ADDRESS_FAMILY_IPV6:    return("IPV6");
      case XRSR_ADDRESS_FAMILY_INVALID: return("INVALID");
   }
   return(xrsr_invalid_return(family));
}

const char *xrsr_event_str(xrsr_event_t event) {
   switch(event) {
      case XRSR_EVENT_EOS:                 return("EOS");
      case XRSR_EVENT_STREAM_TIME_MINIMUM: return("STREAM_TIME_MINIMUM");
      case XRSR_EVENT_STREAM_KWD_INFO:     return("STREAM_KWD_INFO");
      case XRSR_EVENT_STREAM_ERROR:        return("STREAM_ERROR");
      case XRSR_EVENT_INVALID:             return("INVALID");
   }
   return(xrsr_invalid_return(event));
}

const char *xrsr_audio_container_str(xrsr_audio_container_t container) {
   switch(container) {
      case XRSR_AUDIO_CONTAINER_NONE:    return("NONE");
      case XRSR_AUDIO_CONTAINER_WAV:     return("WAV");
      case XRSR_AUDIO_CONTAINER_INVALID: return("INVALID");
   }
   return(xrsr_invalid_return(container));
}

const char *xrsr_recv_event_str(xrsr_recv_event_t recv_event) {
   switch(recv_event) {
      case XRSR_RECV_EVENT_EOS_SERVER:        return("EOS SERVER");
      case XRSR_RECV_EVENT_DISCONNECT_REMOTE: return("DISCONNECT REMOTE");
      case XRSR_RECV_EVENT_NONE:              return("NONE");
      case XRSR_RECV_EVENT_INVALID:           return("INVALID");
   }
   return(xrsr_invalid_return(recv_event));
}

const char *xrsr_cert_type_str(xrsr_cert_type_t type) {
   switch(type) {
      case XRSR_CERT_TYPE_NONE:    return("NONE");
      case XRSR_CERT_TYPE_P12:     return("P12");
      case XRSR_CERT_TYPE_PEM:     return("PEM");
      case XRSR_CERT_TYPE_X509:    return("X509");
      case XRSR_CERT_TYPE_INVALID: return("INVALID");
   }
   return(xrsr_invalid_return(type));
}

bool xrsr_url_parse(const char *url, xrsr_url_parts_t *url_parts) {
   if(url == NULL) {
      XLOGD_ERROR("NULL url");
      return(false);
   }
   if(url_parts == NULL) {
      XLOGD_ERROR("NULL url_parts");
      return(false);
   }
   #ifdef USE_CURL_UNESCAPE
   // unescape the url first
   CURL *obj = curl_easy_init();
   if(obj == NULL) {
      XLOGD_ERROR("unable to init curl");
      return(false);
   }
   char *tmp_url = curl_easy_unescape(obj, url, 0, NULL);
   curl_easy_cleanup(obj);
   
   if(tmp_url == NULL) {
      XLOGD_ERROR("unable to unescape");
      return(false);
   }
   XLOGD_INFO("unescaped url <%s>", tmp_url);
   #else
   const char *tmp_url = url;
   #endif
   
   xrsr_protocol_t tmp_prot;
   uint16_t        tmp_port = 443;
   uint32_t        index    = 0;
   if(0 == strncmp(tmp_url, "wss://", 6)) {
      tmp_prot = XRSR_PROTOCOL_WSS;
      index = 6;
   } else if(0 == strncmp(tmp_url, "https://", 8)) {
      tmp_prot = XRSR_PROTOCOL_HTTPS;
      index = 8;
   } else if(0 == strncmp(tmp_url, "ws://", 5)) {
      tmp_prot = XRSR_PROTOCOL_WS;
      tmp_port = 80;
      index = 5;
   } else if(0 == strncmp(tmp_url, "http://", 7)) {
      tmp_prot = XRSR_PROTOCOL_HTTP;
      tmp_port = 80;
      index = 7;
   } else if(0 == strncmp(tmp_url, "sdt://", 6)) {
      tmp_prot = XRSR_PROTOCOL_SDT;
      tmp_port = 80;
      index = 6;
   } else {
      XLOGD_WARN("invalid protocol");
      #ifdef USE_CURL_UNESCAPE
      curl_free(tmp_url);
      #endif
      return(false);
   }
   
   // Find start of path
   char *ptr_path = strchrnul(&tmp_url[index], '/');
   
   // Allocate memory for the unescaped url and user, host
   size_t len_url = strlen(tmp_url) + 1;
   size_t len_uhp = len_url - strlen(ptr_path) - index;
   
   #define PORT_LEN_MAX (6)
   char *ptr_urle = malloc(len_url + len_uhp + PORT_LEN_MAX);
   
   if(ptr_urle == NULL) {
      XLOGD_ERROR("out of memory");
      #ifdef USE_CURL_UNESCAPE
      curl_free(tmp_url);
      #endif
      return(false);
   }
   
   strlcpy(ptr_urle,           tmp_url,         len_url);
   strlcpy(&ptr_urle[len_url], &tmp_url[index], len_uhp);

   char *question = strchr(tmp_url, '?');
   bool has_query    = (NULL == question) ? false : true;
   bool has_param    = has_query;
   if(has_param && question[1] == '\0') { // Check for nothing after ? mark
      has_param = false;
   }
   bool has_fragment = (NULL == strchr(tmp_url, '#')) ? false : true;

   #ifdef USE_CURL_UNESCAPE
   curl_free(tmp_url);
   #endif
   tmp_url = NULL;
   
   // Use url for path pointer
   ptr_path = strchrnul(&ptr_urle[index], '/');
   
   // Chop up user@host:port into pieces
   char *tmp_ptr  = &ptr_urle[len_url];
   
   char *ptr_user = strchr(tmp_ptr, '@');
   if(ptr_user != NULL) { // User field present
      char *tmp   = tmp_ptr;
      *ptr_user++ = '\0';
      tmp_ptr     = ptr_user;
      ptr_user    = tmp;
   } 
   char *ptr_host = tmp_ptr;
   char *ptr_port = strchr(tmp_ptr, ':');
   if(ptr_port != NULL) { // port field present
      *ptr_port++ = '\0';
      errno = 0;
      unsigned long int port = strtoul(ptr_port, NULL, 10);
      if(errno) {
         int errsv = errno;
         XLOGD_ERROR("port conversion <%s>", strerror(errsv));
         free(ptr_urle);
         return(false);
      } else if(port > UINT16_MAX) {
         XLOGD_ERROR("port out of range <%u>", port);
         free(ptr_urle);
         return(false);
      }
      tmp_port = port;
   } else { // Convert port to string at the end of the buffer
      ptr_port = &ptr_urle[len_url + len_uhp];
      snprintf(ptr_port, PORT_LEN_MAX, "%u", tmp_port);
   }

   XLOGD_INFO("url <%s> prot <%s> user <%s> host <%s> port_str <%s> port_int <%u> path <%s>", ptr_urle, xrsr_protocol_str(tmp_prot), ptr_user ? ptr_user : "NULL", ptr_host, ptr_port, tmp_port, ptr_path);
   
   url_parts->urle         = ptr_urle;
   url_parts->user         = ptr_user;
   url_parts->host         = ptr_host;
   url_parts->path         = ptr_path;
   url_parts->prot         = tmp_prot;
   url_parts->port_str     = ptr_port;
   url_parts->port_int     = tmp_port;
   url_parts->family       = XRSR_ADDRESS_FAMILY_INVALID;
   url_parts->has_query    = has_query;
   url_parts->has_param    = has_param;
   url_parts->has_fragment = has_fragment;
   return(true);
}

void xrsr_url_free(xrsr_url_parts_t *url_parts) {
   if(url_parts == NULL) {
      return;
   }
   char *tmp = url_parts->urle;
   url_parts->urle     = NULL;
   url_parts->user     = NULL;
   url_parts->host     = NULL;
   url_parts->path     = NULL;
   url_parts->prot     = XRSR_PROTOCOL_INVALID;
   url_parts->port_str = NULL;
   url_parts->port_int = 0;
   url_parts->family   = XRSR_ADDRESS_FAMILY_INVALID;
   if(tmp) { 
      free(tmp);
   }
}

#ifdef HTTP_ENABLED
const char *xrsr_curlmcode_str(CURLMcode code) {
   switch(code) {
      case CURLM_CALL_MULTI_PERFORM: return("CALL_MULTI_PERFORM");
      case CURLM_OK:                 return("OK");
      case CURLM_BAD_HANDLE:         return("BAD_HANDLE");
      case CURLM_BAD_EASY_HANDLE:    return("BAD_EASY_HANDLE");
      case CURLM_OUT_OF_MEMORY:      return("OUT_OF_MEMORY");
      case CURLM_INTERNAL_ERROR:     return("INTERNAL_ERROR");
      case CURLM_BAD_SOCKET:         return("BAD_SOCKET");
      case CURLM_UNKNOWN_OPTION:     return("UNKNOWN_OPTION");
      case CURLM_ADDED_ALREADY:      return("ADDED_ALREADY");
      #ifdef CURLM_RECURSIVE_API_CALL
      case CURLM_RECURSIVE_API_CALL: return("RECURSIVE_API_CALL");
      #endif
      case CURLM_LAST:               return("LAST");
      default: break;
   }
   return(xrsr_invalid_return(code));
}
#endif
