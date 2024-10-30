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
#include "xrsr_private.h"
#include "xrsr_protocol_http_sm.h"
#define XRSR_HTTP_CURL_FD_MAX (5)
#define XRSR_HTTP_MSG_TIMEOUT         (10000) // in milliseconds

#define CURL_EASY_SETOPT(curl, CURLoption, option) \
   do { \
      CURLcode res = curl_easy_setopt(curl, CURLoption, option); \
      if (res != CURLE_OK) { \
         XLOGD_ERROR("curl_easy_setopt() failed with reason <%s>", curl_easy_strerror(res)); \
      } \
   } while (0);

// Static Global Variables
typedef struct {
    unsigned int        ref;
    unsigned int        easy_handle_cnt;
    CURLM              *multi_handle;
    int                 running;
    rdkx_timer_object_t timer_obj;
    rdkx_timer_id_t     timer_id_multi;
    int                 readfds[XRSR_HTTP_CURL_FD_MAX];
    int                 writefds[XRSR_HTTP_CURL_FD_MAX];
} xrsr_state_http_global_t;

static xrsr_state_http_global_t g_http = {0};
// END -- Static Global Variables

static void xrsr_http_event(xrsr_state_http_t *http, tStEventID id, bool from_state_handler);
static void xrsr_http_reset(xrsr_state_http_t *http);
static void xrsr_http_sm_init(xrsr_state_http_t *http);

static void xrsr_http_timeout_process(void *data);
static void xrsr_http_timeout_response(void *data);
static bool _xrsr_http_connect(xrsr_state_http_t *http);

// Helper functions
void _xrsr_http_fd_add(int fd, int *list) {
    bool added = false;
    int  i     = 0;

    for(i = 0; i < XRSR_HTTP_CURL_FD_MAX; i++) {
        if(list[i] < 0) {
            list[i] = fd;
            added = true;
            break;
        }
    }
    if(!added) {
        XLOGD_ERROR("failed to add fd to list..");
    }
}

void _xrsr_http_fd_remove(int fd, int *list) {
    int  i = 0;

    for(i = 0; i < XRSR_HTTP_CURL_FD_MAX; i++) {
        if(list[i] == fd) {
            list[i] = -1;
        }
    }
}
    
void _xrsr_http_fd_clear(int *list) {
    int  i = 0;
    
    for(i = 0; i < XRSR_HTTP_CURL_FD_MAX; i++) {
        list[i] = -1;
    }
}

// CURL callback functions

size_t _xrsr_http_write_function(char *ptr, size_t size, size_t nmemb, void *userdata) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)userdata;
    size_t             len  = 0;
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
    } else {
        // Get current response length
        len = strnlen(http->write_buffer, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX);
        if(len + (size * nmemb) > XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX) {
            XLOGD_ERROR("response buffer overflow");
            strncpy(&http->write_buffer[len], ptr, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX - len);
        } else { // We have enough room
            strncpy(&http->write_buffer[len], ptr, size * nmemb);
        }
    }
    return(size * nmemb);
}

size_t _xrsr_http_read_function(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t bytes = 0;
    xrsr_state_http_t *http = (xrsr_state_http_t *)userdata;
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
    } else {
        if(http->audio_pipe_fd_read >= 0) {
            int rc = read(http->audio_pipe_fd_read, ptr, size * nmemb);
            if(rc < 0) {
                int errsv = errno;
                if(errsv == EAGAIN || errsv == EWOULDBLOCK) {
                   XLOGD_INFO("read would block");
                } else {
                   XLOGD_ERROR("pipe read error <%s>", strerror(errsv));
                }
                close(http->audio_pipe_fd_read);
                http->audio_pipe_fd_read = -1;
                rc = 0;
                xrsr_http_event(http, SM_EVENT_PIPE_EOS, false);
            } else if(rc == 0) { // EOF
                XLOGD_INFO("pipe read EOF");
                close(http->audio_pipe_fd_read);
                http->audio_pipe_fd_read = -1;
                xrsr_http_event(http, SM_EVENT_PIPE_EOS, false);
            }
            bytes = rc;
        }
    }
    XLOGD_INFO("sent %zu bytes", bytes);
    return(bytes);
}

int _xrsr_http_debug_function(CURL *handle, curl_infotype type, char *data, size_t size, void *userdata) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)userdata;
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
        return(0);
    }
    switch(type) {
        case CURLINFO_TEXT: {
            if(xrsr_http_log_filter_handler_get(data, size) && (http->debug || http->log_filter_enabled )) {
                XLOGD_TELEMETRY("%.*s", (int)size, data);
            } else if (http->debug) {
                XLOGD_NO_LF(XLOG_LEVEL_INFO, "%.*s", (int)size, data);
            }
            break;
        }
        case CURLINFO_HEADER_IN:
        case CURLINFO_HEADER_OUT:
        case CURLINFO_DATA_IN:
        case CURLINFO_DATA_OUT:
        case CURLINFO_SSL_DATA_IN:
        case CURLINFO_SSL_DATA_OUT: {
            XLOGD_DEBUG("%.*s\n", (int)size, data);
            break;
        }
        default: {
            break;
        }
    }
    return(0);
}

int _xrsr_http_socket_function(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp) {
    switch(what) {
        case CURL_POLL_IN: {
            XLOGD_DEBUG("IN %d", s);
            _xrsr_http_fd_remove(s, g_http.readfds);
            _xrsr_http_fd_remove(s, g_http.writefds);
            _xrsr_http_fd_add(s, g_http.readfds);
            break;
        }
        case CURL_POLL_OUT: {
            XLOGD_DEBUG("OUT %d", s);
            _xrsr_http_fd_remove(s, g_http.readfds);
            _xrsr_http_fd_remove(s, g_http.writefds);
            _xrsr_http_fd_add(s, g_http.writefds);
            break;
        }
        case CURL_POLL_INOUT: {
            XLOGD_DEBUG("INOUT %d", s);
            _xrsr_http_fd_remove(s, g_http.readfds);
            _xrsr_http_fd_remove(s, g_http.writefds);
            _xrsr_http_fd_add(s, g_http.readfds);
            _xrsr_http_fd_add(s, g_http.writefds);
            break;
        }
        case CURL_POLL_REMOVE: {
            XLOGD_DEBUG("REMOVE %d", s);
            _xrsr_http_fd_remove(s, g_http.readfds);
            _xrsr_http_fd_remove(s, g_http.writefds);
        }
        default: {
            break;
        }
    }

    return(0);
}

int _xrsr_http_timer_function(CURLM *multi, long timeout_ms, void *userp) {
    if(timeout_ms < 0) { // delete the timer
       if(g_http.timer_id_multi != RDXK_TIMER_ID_INVALID) {
          if(!rdkx_timer_remove(g_http.timer_obj, g_http.timer_id_multi)) {
             XLOGD_ERROR("timer remove");
          }
          g_http.timer_id_multi = RDXK_TIMER_ID_INVALID;
       }
    } else { // add the timer
       rdkx_timestamp_t timeout;
       rdkx_timestamp_get(&timeout);
       rdkx_timestamp_add_ms(&timeout, timeout_ms);

       if(g_http.timer_id_multi == RDXK_TIMER_ID_INVALID) {
          g_http.timer_id_multi = rdkx_timer_insert(g_http.timer_obj, timeout, xrsr_http_timeout_process, NULL);
       } else if(!rdkx_timer_update(g_http.timer_obj, g_http.timer_id_multi, timeout)) {
           XLOGD_ERROR("timer update");
       }
    }
    return(0);
}

// END -- CURL callback functions

void xrsr_protocol_handler_http(xrsr_src_t src, bool retry, bool user_initiated, xraudio_input_format_t xraudio_format, xraudio_keyword_detector_result_t *detector_result, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util) {
    // This function kicks off the session
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

bool xrsr_http_init(xrsr_state_http_t *http, bool debug) {
    // Check params
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
        return(false);
    }

    // Set global http object
    if(g_http.ref == 0) {
        // Open CURL multi handle
        g_http.multi_handle = curl_multi_init();
        if(NULL == g_http.multi_handle) {
            XLOGD_ERROR("failed to init multi-handle");
            return(false);
        }

        // Set CURL multi handle options
        curl_multi_setopt(g_http.multi_handle, CURLMOPT_SOCKETFUNCTION, _xrsr_http_socket_function);
        curl_multi_setopt(g_http.multi_handle, CURLMOPT_SOCKETDATA,     NULL);
        curl_multi_setopt(g_http.multi_handle, CURLMOPT_TIMERFUNCTION,  _xrsr_http_timer_function);
        curl_multi_setopt(g_http.multi_handle, CURLMOPT_TIMERDATA,      NULL);

        // Clear fs
        _xrsr_http_fd_clear(g_http.readfds);
        _xrsr_http_fd_clear(g_http.writefds);
    }
    // Increment global http reference
    g_http.ref++;

    // Init HTTP Structure
    http->debug              = debug;
    http->log_filter_enabled = true;
    http->prot               = XRSR_PROTOCOL_HTTP;
    http->easy_handle        = NULL;
    http->chunk              = NULL;
    http->audio_pipe_fd_read = -1;
    http->timer_obj          = RDXK_TIMER_OBJ_INVALID;
    http->timer_id_rsp       = RDXK_TIMER_ID_INVALID;
    xrsr_http_sm_init(http);
    xrsr_http_reset(http);
    return(true);
}

void xrsr_http_term(xrsr_state_http_t *http, bool closing) {
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
        return;
    }

    if(closing) {
       // Set timer id to invalid so that the call to xrsr_http_reset in the event handler below does not attempt to remove it
       // Otherwise it would fail the thread id check in xr-timer since this call is not in xrsr thread context.
       http->timer_obj       = RDXK_TIMER_OBJ_INVALID;
       http->timer_id_rsp    = RDXK_TIMER_ID_INVALID;
       g_http.timer_id_multi = RDXK_TIMER_ID_INVALID;
    }

    xrsr_http_event(http, SM_EVENT_TERMINATE, false);

    if(g_http.ref > 0) {
        // First check if it has a reference to global http object
        g_http.ref--;
        // Check if global http is still needed
        if(g_http.ref == 0) {
            if(g_http.multi_handle) {
                curl_multi_cleanup(g_http.multi_handle);
                g_http.multi_handle = NULL;
            }
        }
    }
}

bool _xrsr_http_connect(xrsr_state_http_t *http) {
    CURLMcode rc;

    // Add the easy handle to multi handle
    curl_multi_add_handle(g_http.multi_handle, http->easy_handle);
    // Call first socket action, which starts the session
    rc = curl_multi_socket_action(g_http.multi_handle, CURL_SOCKET_TIMEOUT, 0, &g_http.running);
    if(CURLM_OK != rc && CURLM_CALL_MULTI_PERFORM != rc) {
        XLOGD_ERROR("curl multi error <%s>", xrsr_curlmcode_str(rc));
        return(false);
    }

    XLOGD_INFO("Connected");
    return(true);
}

bool xrsr_http_connect(xrsr_state_http_t *http, xrsr_url_parts_t *url_parts, xrsr_src_t audio_src, xraudio_input_format_t xraudio_format, rdkx_timer_object_t timer_obj, bool delay, const char **query_strs, const char* transcription_in) {
    char      url[XRSR_PROTOCOL_HTTP_URL_SIZE_MAX] = {'\0'};
    char      sat_token_str[24 + XRSR_SAT_TOKEN_LEN_MAX] = {'\0'};
#ifdef URL_ENCODE
    char *url_encoded;
#endif
    if(NULL == http || NULL == url_parts) {
        XLOGD_ERROR("NULL parameters");
        return(false);
    }

    // Open CURL easy handle
    http->easy_handle = curl_easy_init();
    if(NULL == http->easy_handle) {
        XLOGD_ERROR("failed to init easy-handle");
        xrsr_http_term(http, false);
        return(false);
    }

    if(g_http.easy_handle_cnt == 0) { // Set global timer obj on first easy handle
       g_http.timer_obj      = timer_obj;
       g_http.timer_id_multi = RDXK_TIMER_ID_INVALID;
    }
    g_http.easy_handle_cnt++;

    // Set up HTTP header
    if (NULL != transcription_in) {
        http->chunk = curl_slist_append(http->chunk, "Content-Type:text/plain");

        char transcription_payload[XRSR_SESSION_BY_TEXT_MAX_LENGTH];
        snprintf(transcription_payload, sizeof(transcription_payload), "%s", transcription_in );
        transcription_payload[sizeof(transcription_payload)-1] = '\0';  //A bit redundant since snprintf does this, but let's be certain because CURLOPT_COPYPOSTFIELDS requires it
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_COPYPOSTFIELDS, transcription_payload);
    } else {
        http->chunk = curl_slist_append(http->chunk, "Transfer-Encoding: chunked");
        http->chunk = curl_slist_append(http->chunk, "Content-Type:application/octet-stream");
    }

    if(http->session_config_in.http.sat_token != NULL && http->session_config_in.http.sat_token[0] != '\0') {
       snprintf(sat_token_str, sizeof(sat_token_str), "Authorization: Bearer %s", http->session_config_in.http.sat_token);
       http->chunk = curl_slist_append(http->chunk, sat_token_str);
    }
    http->chunk = curl_slist_append(http->chunk, "Expect:");

    // Set CURL easy handle options
    if(http->debug || http->log_filter_enabled) {
        // Debug set to true, set VERBOSE curl opt
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_VERBOSE, 1L);
    }
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_WRITEFUNCTION, _xrsr_http_write_function);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_WRITEDATA, (void *)http);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_READFUNCTION, _xrsr_http_read_function);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_READDATA, (void *)http);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_DEBUGFUNCTION, _xrsr_http_debug_function);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_DEBUGDATA, (void *)http);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_XFERINFODATA, (void *)http);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_NOPROGRESS, 1L);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_CONNECTTIMEOUT, 5L);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_PRIVATE, (void *)http);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_HTTPHEADER, http->chunk);

    xrsr_session_config_in_http_t *config_in  = &http->session_config_in.http;

    if(config_in->user_agent != NULL && config_in->user_agent[0] != '\0') {
       CURL_EASY_SETOPT(http->easy_handle, CURLOPT_USERAGENT, config_in->user_agent);
    }
    if(config_in->client_cert.type == XRSR_CERT_TYPE_P12) {
        xrsr_cert_p12_t *cert_p12 = &config_in->client_cert.cert.p12;
        XLOGD_INFO("P12 cert <%s>", cert_p12->filename);
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERTTYPE, "P12");
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERT, cert_p12->filename);
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_KEYPASSWD, cert_p12->passphrase);

        // verify the certificate's name against host (default is what we want)
        // CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYHOST, 2L);
        // verify the peer's SSL certificate (default is what we want)
        // CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYPEER, 1L);

        if(config_in->ocsp_verify_stapling) { // inform the server to attach OSCP confirmation in the response
           // verify the status of the server cert using the "Certificate Status Request" TLS extension (aka. OCSP stapling).
           CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYSTATUS, 1L);
        }
    } else if(config_in->client_cert.type == XRSR_CERT_TYPE_PEM) {
        xrsr_cert_pem_t *cert_pem = &config_in->client_cert.cert.pem;
        XLOGD_INFO("PEM cert <%s> pkey <%s> chain <%s>", cert_pem->filename_cert, cert_pem->filename_pkey, cert_pem->filename_chain);

        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERTTYPE, "PEM");
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERT,   cert_pem->filename_cert);
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLKEY,    cert_pem->filename_pkey);
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_KEYPASSWD, cert_pem->passphrase);
        if(cert_pem->filename_chain != NULL) {
           CURL_EASY_SETOPT(http->easy_handle, CURLOPT_CAINFO, cert_pem->filename_chain);
        }
        if(config_in->ocsp_verify_stapling) { // inform the server to attach OSCP confirmation in the response
           // verify the status of the server cert using the "Certificate Status Request" TLS extension (aka. OCSP stapling).
           CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYSTATUS, 1L);
        }
    } else if(config_in->client_cert.type != XRSR_CERT_TYPE_NONE) {
        XLOGD_ERROR("unsupported cert type <%s>", xrsr_cert_type_str(config_in->client_cert.type));
        return(false);
    }
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_FORBID_REUSE, 1);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_FOLLOWLOCATION, 1L);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_NOSIGNAL, 1L);

    // Check protocol
    if(XRSR_PROTOCOL_HTTP != url_parts->prot && XRSR_PROTOCOL_HTTPS != url_parts->prot) {
        XLOGD_ERROR("unsupported XRSR Protocol");
        return(false);
    }

    http->timer_obj = timer_obj;
    http->audio_src = audio_src;

    // Add user parameters to the URL
    if(NULL == url_parts->urle || strlen(url_parts->urle) == 0) {
        XLOGD_ERROR("url not set");
        return(false);
    }
    errno_t safe_rc = -1;
    safe_rc = strncpy_s(url, sizeof(url), url_parts->urle, XRSR_WS_URL_SIZE_MAX-1); // Copy main url
    ERR_CHK(safe_rc);

    if(query_strs != NULL && *query_strs != NULL) { // add attribute-value pairs to the query string
      if(url_parts->path[0] == '\0') { // Handle case where the "/" may also be omitted if neither <path> nor <searchpart> is present.
         strlcat(url, "/", sizeof(url));
      }

       bool delimit = url_parts->has_param;
       if(!url_parts->has_query) {
          strlcat(url, "?", sizeof(url));
          delimit = false;
       }

       do {
          if(delimit) {
             strlcat(url, "&", sizeof(url));
          }
          strlcat(url, *query_strs, sizeof(url));
          delimit = true;
          query_strs++;
       } while(*query_strs != NULL);
    }

    XLOGD_INFO("user agent <%s>", http->session_config_in.http.user_agent);
    XLOGD_INFO("url <%s>", xrsr_mask_pii() ? "***" : url);

    // Set the URL / Port
#ifdef URL_ENCODE
    url_encoded = curl_easy_escape(http->easy_handle, url, strlen(url_parts->urle));
    if(NULL == url_encoded) {
        XLOGD_ERROR("failed to encode url");
        return(false);
    }
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_URL, url_encoded);
    curl_free(url_encoded);
#else
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_URL, url); // TODO Concat path to the url MAYBE?
#endif
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_POST, 1L);

    if(false == delay) {
        xrsr_http_event(http, SM_EVENT_SESSION_BEGIN, false);
    } else {
        xrsr_http_event(http, SM_EVENT_SESSION_BEGIN_STM, false);
    }
    return(true);
}

void xrsr_http_timeout_response(void *data) {
    XLOGD_TELEMETRY("server response timeout");
    xrsr_state_http_t *http = (xrsr_state_http_t *)data;
    xrsr_http_event(http, SM_EVENT_TIMEOUT, false);
}

void xrsr_http_timeout_process(void *data) {
   if(g_http.timer_id_multi != RDXK_TIMER_ID_INVALID) {
      if(!rdkx_timer_remove(g_http.timer_obj, g_http.timer_id_multi)) {
         XLOGD_ERROR("timer remove");
      }
      g_http.timer_id_multi = RDXK_TIMER_ID_INVALID;
   }
   xrsr_http_handle_fds(NULL, 1, NULL, NULL, NULL);
}

bool xrsr_http_conn_is_ready() {
    return((g_http.running > 0 ? true : false));
}

int  xrsr_http_send(xrsr_state_http_t *http, const uint8_t *buffer, uint32_t length) {
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
        return(-1);
    }
    return(1);
}

int  xrsr_http_recv(xrsr_state_http_t *http, uint8_t *buffer, uint32_t length) {
    int ret = 0;
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
        return(-1);
    }

    ret = strnlen(http->write_buffer, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX) - http->write_buffer_index; // Get remaining bytes
    if(ret > length) {
        ret = length;
    }
    memcpy(buffer, &http->write_buffer[http->write_buffer_index], ret);
    http->write_buffer_index += ret;
    return(ret);
}

int  xrsr_http_recv_pending(xrsr_state_http_t *http) {
    if(NULL == http) {
        XLOGD_ERROR("NULL xrsr_state_http_t");
        return(-1);
    }
    return(strnlen(http->write_buffer, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX)); // FIX THIS
}

void xrsr_http_fd_set(xrsr_state_http_t *http, int size, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    int i;
    if(NULL == http || NULL == nfds || NULL == readfds || NULL == writefds) { // Purposely don't care about exceptfds
        XLOGD_ERROR("NULL params");
        return;
    }

    // Check read fds
    for(i = 0; i < XRSR_HTTP_CURL_FD_MAX; i++) {
        if(g_http.readfds[i] >= 0) {
            FD_SET(g_http.readfds[i], readfds);
            if(g_http.readfds[i] >= *nfds) {
                *nfds = g_http.readfds[i] + 1;
            }
        }
    }

    // Check write fds
    for(i = 0; i < XRSR_HTTP_CURL_FD_MAX; i++) {
        if(g_http.writefds[i] >= 0) {
            FD_SET(g_http.writefds[i], writefds);
            if(g_http.writefds[i] >= *nfds) {
                *nfds = g_http.writefds[i] + 1;
            }
        }
    }
}

void xrsr_http_handle_fds(xrsr_state_http_t *http, int size, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    int i;

    if(NULL == readfds || NULL == writefds) { // Called for timeout
        int rc = curl_multi_socket_action(g_http.multi_handle,CURL_SOCKET_TIMEOUT, 0, &g_http.running);
        if(CURLM_OK != rc && CURLM_CALL_MULTI_PERFORM != rc) {
            XLOGD_ERROR("curl multi error <%s>", xrsr_curlmcode_str(rc));
        }
    } else {
        // Check read fds
        for(i = 0; i < XRSR_HTTP_CURL_FD_MAX; i++) {
            if(g_http.readfds[i] >= 0) {
                if(FD_ISSET(g_http.readfds[i], readfds)) {
                    int rc = curl_multi_socket_action(g_http.multi_handle, g_http.readfds[i], CURL_CSELECT_IN, &g_http.running);
                    if(CURLM_OK != rc && CURLM_CALL_MULTI_PERFORM != rc) {
                        XLOGD_ERROR("curl multi error <%s>", xrsr_curlmcode_str(rc));
                    }
                }
            }
        }

        // Check write fds
        for(i = 0; i < XRSR_HTTP_CURL_FD_MAX; i++) {
            if(g_http.writefds[i] >= 0) {
                if(FD_ISSET(g_http.writefds[i], writefds)) {
                    int rc = curl_multi_socket_action(g_http.multi_handle, g_http.writefds[i], CURL_CSELECT_OUT, &g_http.running);
                    if(CURLM_OK != rc && CURLM_CALL_MULTI_PERFORM != rc) {
                        XLOGD_ERROR("curl multi error <%s>", xrsr_curlmcode_str(rc));
                    }
                }
            }
        }
    }
    // Check status of connection
    do {
        CURLMsg *status = curl_multi_info_read(g_http.multi_handle, &i);
        if(status) {
            if(CURLMSG_DONE == status->msg) {
                xrsr_state_http_t *temp;
                if(status->data.result != CURLE_OK) {
                    XLOGD_TELEMETRY("Transfer finished with result %d <%s>", status->data.result, curl_easy_strerror(status->data.result));
                } else {
                    XLOGD_INFO("Transfer finished successfully");
                }
                if(CURLE_OK == curl_easy_getinfo(status->easy_handle, CURLINFO_PRIVATE, &temp)) {
                    char *primary_ip = NULL;

                    if(NULL == temp->handlers.recv_msg) {
                        XLOGD_WARN("NULL recv_msg handler");
                    } else {
                        (*temp->handlers.recv_msg)(temp->handlers.data, XRSR_RECV_MSG_TEXT, (uint8_t *)temp->write_buffer, strnlen(temp->write_buffer, XRSR_PROTOCOL_HTTP_BUFFER_SIZE_MAX), NULL);
                    }
                    temp->session_stats.ret_code_internal = XRSR_RET_CODE_INTERNAL_SUCCESS;
                    temp->session_stats.ret_code_protocol = 200;
                    curl_easy_getinfo(temp->easy_handle, CURLINFO_HTTP_CODE, &temp->session_stats.ret_code_protocol);
                    temp->session_stats.ret_code_library = status->data.result;
                    curl_easy_getinfo(temp->easy_handle, CURLINFO_PRIMARY_IP, &primary_ip);
                    if(primary_ip && primary_ip[0] != '\0') {
                       errno_t safe_rc = -1;
                       safe_rc = strncpy_s(temp->session_stats.server_ip, sizeof(temp->session_stats.server_ip), primary_ip, sizeof(temp->session_stats.server_ip));
                       ERR_CHK(safe_rc);
                    }
                    curl_easy_getinfo(temp->easy_handle, CURLINFO_CONNECT_TIME, &temp->session_stats.time_connect);
                    curl_easy_getinfo(temp->easy_handle, CURLINFO_NAMELOOKUP_TIME, &temp->session_stats.time_dns);

                    xrsr_http_event(temp, SM_EVENT_MSG_RECV, false);
                }
            }
        }
    } while(i > 0);
}

void xrsr_http_terminate(xrsr_state_http_t *http) {
    if(http) {
        xrsr_http_event(http, SM_EVENT_TERMINATE, false);
    }
}

void xrsr_http_handle_speech_event(xrsr_state_http_t *http, xrsr_speech_event_t *event) {
    if(NULL == event) {
        XLOGD_ERROR("speech event is NULL");
        return;
    }

    switch(event->event) {
        case XRSR_EVENT_EOS: {
            xrsr_http_event(http, SM_EVENT_EOS, false);
            break;
        }
        case XRSR_EVENT_STREAM_TIME_MINIMUM: {
            xrsr_http_event(http, SM_EVENT_STM, false);
            break;
        }
        case XRSR_EVENT_STREAM_KWD_INFO: {
            break;
        }
        default: {
            XLOGD_WARN("unhandled speech event <%s>", xrsr_event_str(event->event));
            break;
        }
    }
}

void xrsr_http_reset(xrsr_state_http_t *http) {
    if(http) {
        if(http->audio_pipe_fd_read >= 0) {
            close(http->audio_pipe_fd_read);
            http->audio_pipe_fd_read = -1;
        }
        if(http->easy_handle) {
            // Remove easy handle from multi handle
            curl_multi_remove_handle(g_http.multi_handle, http->easy_handle);
            curl_easy_cleanup(http->easy_handle);
            http->easy_handle = NULL;

            g_http.easy_handle_cnt--;
            if(g_http.easy_handle_cnt == 0) {
                if(g_http.timer_id_multi >= 0) {
                    if(!rdkx_timer_remove(g_http.timer_obj, g_http.timer_id_multi)) {
                        XLOGD_ERROR("timer remove");
                    }
                }
                g_http.timer_obj      = NULL;
                g_http.timer_id_multi = RDXK_TIMER_ID_INVALID;
            }
        }
        if(http->chunk) {
            curl_slist_free_all(http->chunk);
            http->chunk = NULL;
        }
        memset(&http->write_buffer, 0, sizeof(http->write_buffer));
        http->write_buffer_index = 0;
        if(http->timer_obj != NULL) {
            if(http->timer_id_rsp >= 0) {
                if(!rdkx_timer_remove(http->timer_obj, http->timer_id_rsp)) {
                    XLOGD_ERROR("timer remove");
                }
            }
            http->timer_id_rsp = RDXK_TIMER_ID_INVALID;
        }
        http->timer_obj          = RDXK_TIMER_OBJ_INVALID;
        http->audio_src          = XRSR_SRC_INVALID;
        memset(&http->audio_stats, 0, sizeof(http->audio_stats));
        memset(&http->session_stats, 0, sizeof(http->session_stats));
        http->detect_resume      = true;
        http->session_stats.reason = XRSR_SESSION_END_REASON_EOS;
        http->is_session_by_text   = false;
        http->is_session_by_file   = false;
    }
}

void xrsr_http_sm_init(xrsr_state_http_t *http) {
    if(http) {
        http->state_machine.mInstanceName = "httpSM";
        http->state_machine.bInitFinished = false;

        http->state_machine.bInitFinished = FALSE; 
        http->state_machine.activeEvtQueue.mpQData = http->state_machine_events_active; 
        http->state_machine.activeEvtQueue.mQSize = XRSR_HTTP_SM_EVENTS_MAX; 
        http->state_machine.deferredEvtQueue.mpQData = NULL; 
        http->state_machine.deferredEvtQueue.mQSize = 0;
        
        SmInit( &http->state_machine, &St_Http_Disconnected_Info );
    }
}

void xrsr_http_event(xrsr_state_http_t *http, tStEventID id, bool from_state_handler) {
    if(http) {
        SmEnqueueEvent(&http->state_machine, id, (void *)http);
        if(!from_state_handler) {
            SmProcessEvents(&http->state_machine);
        }
    }
}

void St_Http_Disconnected(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)pEvent->mData;
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
            if(http->handlers.disconnected == NULL) {
                XLOGD_INFO("disconnected handler not available");
            } else {
                (*http->handlers.disconnected)(http->handlers.data, http->uuid, http->session_stats.reason, false, &http->detect_resume, &timestamp);
            }
            char uuid_str[37] = {'\0'};
            uuid_unparse_lower(http->uuid, uuid_str);
            xrsr_session_end(http->uuid, uuid_str, http->audio_src, http->dst_index, &http->session_stats);

            xrsr_http_reset(http);
            break;
        }
        default: {
            break;
        }
    }
}

void St_Http_Buffering(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)pEvent->mData;
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
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_DID_NOT_BEGIN, http->detect_resume, &http->audio_stats);
                    http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION;
                    break;
                }
                case SM_EVENT_TERMINATE: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_DID_NOT_BEGIN, http->detect_resume, &http->audio_stats);
                    http->session_stats.reason = XRSR_SESSION_END_REASON_TERMINATE;
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

void St_Http_Connecting(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)pEvent->mData;
    switch(eAction) {
        case ACT_GUARD: {
            if(bGuardResponse) {
                *bGuardResponse = true;
            }
            break;
        }
        case ACT_ENTER: {
            if(_xrsr_http_connect(http)) {
                xrsr_http_event(http, SM_EVENT_CONNECTED, true);
            } else {
                xrsr_http_event(http, SM_EVENT_DISCONNECTED, true);
            }
            break;
        }
        case ACT_EXIT: {
            switch(pEvent->mID) {
                case SM_EVENT_DISCONNECTED: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_DID_NOT_BEGIN, http->detect_resume, &http->audio_stats);
                    http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE;
                    break;
                }
                case SM_EVENT_CONNECTED: {
                    rdkx_timestamp_t timestamp;
                    rdkx_timestamp_get_realtime(&timestamp);
                    if(http->handlers.connected == NULL) {
                        XLOGD_INFO("connected handler not available");
                    } else {
                        (*http->handlers.connected)(http->handlers.data, http->uuid, NULL, NULL, &timestamp, http->session_config_update);
                    }
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

void St_Http_Connected(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)pEvent->mData;
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
            rdkx_timestamp_add_ms(&timeout, XRSR_HTTP_MSG_TIMEOUT); // TODO may need to tweak this value
            http->timer_id_rsp = rdkx_timer_insert(http->timer_obj, timeout, xrsr_http_timeout_response, http);
            break;
        }
        case ACT_EXIT: {
            switch(pEvent->mID) {
                case SM_EVENT_TIMEOUT: {
                    http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT;
                    break;
                }
                case SM_EVENT_TERMINATE: {
                    http->session_stats.reason = XRSR_SESSION_END_REASON_TERMINATE;
                    break;
                }
                default: {
                    break;
                }
            }
            if(http->timer_obj != NULL) {
                if(http->timer_id_rsp >= 0) {
                    if(!rdkx_timer_remove(http->timer_obj, http->timer_id_rsp)) {
                        XLOGD_ERROR("timer remove");
                    }
                }
                http->timer_id_rsp = RDXK_TIMER_ID_INVALID;
            }
            break;
        }
        default: {
            break;
        }
    }
}

void St_Http_Streaming(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)pEvent->mData;
    switch(eAction) {
        case ACT_GUARD: {
            if(bGuardResponse) {
                *bGuardResponse = true;
            }
            break;
        }
        case ACT_ENTER: {
            char uuid_str[37] = {'\0'};
            uuid_unparse_lower(http->uuid, uuid_str);
            xrsr_session_stream_begin(http->uuid, uuid_str, http->audio_src, http->dst_index);
            if (http->is_session_by_text) {
                xrsr_http_event(http, SM_EVENT_TEXT_SESSION_SUCCESS, true);
            }
            break;
        }
        case ACT_EXIT: {
            switch(pEvent->mID) {
                case SM_EVENT_TERMINATE: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_DISCONNECT_LOCAL, http->detect_resume, &http->audio_stats);
                    http->session_stats.reason = XRSR_SESSION_END_REASON_TERMINATE;
                    break;
                }
                case SM_EVENT_MSG_RECV: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_DISCONNECT_REMOTE, http->detect_resume, &http->audio_stats);
                    http->session_stats.reason = XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE;
                    break;
                }
                case SM_EVENT_PIPE_EOS: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_AUDIO_EOF, http->detect_resume, &http->audio_stats);
                    break;
                }
                case SM_EVENT_TEXT_SESSION_SUCCESS: {
                    XLOGD_INFO("SM_EVENT_TEXT_SESSION_SUCCESS - text-only session started successfully.");
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

void St_Http_TextOnlySession(tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardResponse) {
    xrsr_state_http_t *http = (xrsr_state_http_t *)pEvent->mData;
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
                case SM_EVENT_TERMINATE: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_DISCONNECT_LOCAL, http->detect_resume, &http->audio_stats);
                    http->session_stats.reason = XRSR_SESSION_END_REASON_TERMINATE;
                    break;
                }
                case SM_EVENT_MSG_RECV: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_INVALID, http->detect_resume, &http->audio_stats);
                    http->session_stats.reason = XRSR_SESSION_END_REASON_EOT;
                    break;
                }
                case SM_EVENT_PIPE_EOS: {
                    xrsr_speech_stream_end(http->uuid, http->audio_src, http->dst_index, XRSR_STREAM_END_REASON_AUDIO_EOF, http->detect_resume, &http->audio_stats);
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

bool xrsr_http_is_connected(xrsr_state_http_t *http) {
    bool ret = false;
    if(http) {
        if(SmInThisState(&http->state_machine, &St_Http_Connected_Info) ||
           SmInThisState(&http->state_machine, &St_Http_Streaming_Info) ||
           SmInThisState(&http->state_machine, &St_Http_TextOnlySession_Info)) {
            ret = true;
        }
    }
    return(ret);
    }

bool xrsr_http_is_disconnected(xrsr_state_http_t *http) {
    bool ret = false;
    if(http) {
        if(SmInThisState(&http->state_machine, &St_Http_Disconnected_Info)) {
            ret = true;
        }
    }
    return(ret);
}
