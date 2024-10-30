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
#ifndef __XR_SPEECH_ROUTER__
#define __XR_SPEECH_ROUTER__

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <uuid/uuid.h>
#include <xr_timestamp.h>
#include <xraudio_version.h>
#include <jansson.h>

/// @file xrsr.h
///
/// @defgroup XRSR SPEECH ROUTER
/// @{
///
/// @defgroup XRSR_DEFINITIONS Definitions
/// @defgroup XRSR_ENUMS       Enumerations
/// @defgroup XRSR_STRUCTS     Structures
/// @defgroup XRSR_TYPEDEFS    Type Definitions
/// @defgroup XRSR_FUNCTIONS   Functions
///

/// @addtogroup XRSR_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The speech router provides macros for some parameters which may change in the future.  User applications should use
/// these names to allow the application code to function correctly if the values change.

#define XRSR_VERSION_QTY_MAX (2 + XRAUDIO_VERSION_QTY_MAX) ///< The quantity of version information structures.

#define XRSR_SAT_TOKEN_LEN_MAX             (5120)  ///< Maximum length of the NULL-terminated SAT token string.
#define XRSR_USER_AGENT_LEN_MAX            (256)   ///< Maximum length of the NULL-terminated user agent string.
#define XRSR_SESSION_IP_LEN_MAX            (48)    ///< Maximum length of the NULL-terminated IP address string.

#define XRSR_DST_QTY_MAX                   (1)     ///< Maximum quantity of destinations for a source

#define XRSR_SESSION_BY_TEXT_MAX_LENGTH    (128)   ///< Maximum text string length for text-only sessions
#define XRSR_SESSION_AUDIO_FILE_MAX_LENGTH (256)   ///< Maximum string length for audio file name

#define XRSR_QUERY_STRING_QTY_MAX          (24)    ///< Maximum quantity of query strings supported

/// @}

/// @addtogroup XRSR_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The speech router provides enumerated types for logical groups of values.

/// @brief XRSR source types
/// @details The source type enumeration indicates all the source types which are available.
typedef enum {
   XRSR_SRC_RCU_PTT         = 0, ///< A push to talk remote control
   XRSR_SRC_RCU_FF          = 1, ///< A far field remote control
   XRSR_SRC_MICROPHONE      = 2, ///< A local microphone
   XRSR_SRC_MICROPHONE_TAP  = 3, ///< A local microphone tap
   XRSR_SRC_INVALID         = 4  ///< An invalid source type
} xrsr_src_t;

/// @brief XRSR result types
/// @details The results enumeration indicates all the return codes which may be returned by xrsr apis.
typedef enum {
   XRSR_RESULT_SUCCESS = 0, ///< Operation completed successfully
   XRSR_RESULT_ERROR   = 1, ///< Operation did not completed successfully
   XRSR_RESULT_INVALID = 2, ///< Invalid return code
} xrsr_result_t;

/// @brief XRSR session end reason types
/// @details The session end reason enumeration indicates all the reasons why a voice session may end.
typedef enum {
   XRSR_SESSION_REQUEST_TYPE_TEXT        = 0, ///< Use a text string instead of audio input for the session
   XRSR_SESSION_REQUEST_TYPE_AUDIO_FILE  = 1, ///< Use an audio file for the session
   XRSR_SESSION_REQUEST_TYPE_AUDIO_FD    = 2, ///< Use an audio file descriptor for the session
   XRSR_SESSION_REQUEST_TYPE_AUDIO_MIC   = 3, ///< Use audio from a microphone input for the session
   XRSR_SESSION_REQUEST_TYPE_INVALID     = 4, ///< An invalid session request type
} xrsr_session_request_type_t;

/// @brief XRSR session end reason types
/// @details The session end reason enumeration indicates all the reasons why a voice session may end.
typedef enum {
   XRSR_SESSION_END_REASON_EOS                     = 0,  ///< End of speech detected in the source audio
   XRSR_SESSION_END_REASON_EOT                     = 1,  ///< End of text-only session
   XRSR_SESSION_END_REASON_DISCONNECT_REMOTE       = 2,  ///< Server ended the session
   XRSR_SESSION_END_REASON_TERMINATE               = 3,  ///< Session was terminated before completion
   XRSR_SESSION_END_REASON_ERROR_INTERNAL          = 4,  ///< Session ended due to an internal error
   XRSR_SESSION_END_REASON_ERROR_WS_SEND           = 5,  ///< Session ended due to failure to send websocket data
   XRSR_SESSION_END_REASON_ERROR_AUDIO_BEGIN       = 6,  ///< Session ended since no audio was received from the source
   XRSR_SESSION_END_REASON_ERROR_AUDIO_DURATION    = 7,  ///< Session ended due to an insufficient amount of audio samples received
   XRSR_SESSION_END_REASON_ERROR_CONNECT_FAILURE   = 8,  ///< Session ended due to failure to connect to the consumer endpoint
   XRSR_SESSION_END_REASON_ERROR_CONNECT_TIMEOUT   = 9,  ///< Session ended due to connection timeout to the consumer endpoint
   XRSR_SESSION_END_REASON_ERROR_SESSION_TIMEOUT   = 10, ///< Session ended due to a session timeout expiration
   XRSR_SESSION_END_REASON_ERROR_DISCONNECT_REMOTE = 11, ///< Session ended due to an unexpected server disconnect
   XRSR_SESSION_END_REASON_INVALID                 = 12, ///< An invalid session end reason
} xrsr_session_end_reason_t;

/// @brief XRSR internal return code types
/// @details The internal return code enumeration indicates all the reasons why a voice session may end.
typedef enum {
   XRSR_RET_CODE_INTERNAL_SUCCESS                = 0, ///< Session ended successfully
   XRSR_RET_CODE_INTERNAL_AUDIO_DURATION         = 1, ///< Session ended due to an insufficient amount of audio samples received
   XRSR_RET_CODE_INTERNAL_TERMINATE              = 2, ///< Session was terminated before completion
   XRSR_RET_CODE_INTERNAL_INVALID                = 3, ///< An invalid session end reason
} xrsr_ret_code_internal_t;

/// @brief XRSR stream end reason types
/// @details The stream end reason enumeration indicates all the reasons why an audio stream may end.
typedef enum {
   XRSR_STREAM_END_REASON_AUDIO_EOF         = 0, ///< Stream ended normally due to end of file
   XRSR_STREAM_END_REASON_DISCONNECT_REMOTE = 1, ///< Stream ended due to remote disconnection
   XRSR_STREAM_END_REASON_DISCONNECT_LOCAL  = 2, ///< Stream ended due to local disconnection
   XRSR_STREAM_END_REASON_ERROR_AUDIO_READ  = 3, ///< Stream ended due to an error reading the audio stream
   XRSR_STREAM_END_REASON_DID_NOT_BEGIN     = 4, ///< Stream ended before it could begin
   XRSR_STREAM_END_REASON_INVALID           = 5, ///< An invalid stream end reason
} xrsr_stream_end_reason_t;

/// @brief XRSR protocol types
/// @details The protocol enumeration indicates all the protocols which may be supported by xrsr apis.
typedef enum {
   XRSR_PROTOCOL_HTTP    = 0, ///< Hypertext transfer protocol
   XRSR_PROTOCOL_HTTPS   = 1, ///< Secure hypertext transfer protocol
   XRSR_PROTOCOL_WS      = 2, ///< Websockets protocol
   XRSR_PROTOCOL_WSS     = 3, ///< Secure websockets protocol
   XRSR_PROTOCOL_SDT     = 4, ///< SDT Protocol
   XRSR_PROTOCOL_INVALID = 5, ///< An invalid protocol
} xrsr_protocol_t;

/// @brief XRSR receive message types
/// @details The receive message enumeration indicates all the types of received messages which may be returned by xrsr apis.
typedef enum {
   XRSR_RECV_MSG_TEXT    = 0, ///< A text based message
   XRSR_RECV_MSG_BINARY  = 1, ///< A binary message
   XRSR_RECV_MSG_INVALID = 2, ///< An invalid message type
} xrsr_recv_msg_t;

/// @brief XRSR audio container types
/// @details The audio container enumeration indicates all the audio containers which may be supported by xrsr apis.
typedef enum {
   XRSR_AUDIO_CONTAINER_NONE    = 0, ///< No container is present (raw audio data)
   XRSR_AUDIO_CONTAINER_WAV     = 1, ///< Wave container is present
   XRSR_AUDIO_CONTAINER_INVALID = 2, ///< An invalid audio container
} xrsr_audio_container_t;

/// @brief XRSR audio format types
/// @details The audio format enumeration indicates all the audio formats which may be supported by xrsr apis. The values are structured so that they can also be used as a bitmap.
typedef enum {
   XRSR_AUDIO_FORMAT_NONE             = 0,      ///< No audio format
   XRSR_AUDIO_FORMAT_PCM              = 1 << 0, ///< 16-bit PCM format
   XRSR_AUDIO_FORMAT_PCM_32_BIT       = 1 << 1, ///< 32-bit PCM format
   XRSR_AUDIO_FORMAT_PCM_32_BIT_MULTI = 1 << 2, ///< 32-bit PCM format (multi-channel)
   XRSR_AUDIO_FORMAT_PCM_RAW          = 1 << 3, ///< Raw 32-bit PCM format (unprocessed)
   XRSR_AUDIO_FORMAT_ADPCM_FRAME      = 1 << 4, ///< ADPCM format with framing
   XRSR_AUDIO_FORMAT_OPUS             = 1 << 6, ///< OPUS format
   XRSR_AUDIO_FORMAT_MAX              = 1 << 7  ///< The end of the audio format values (this must be the highest bit)
} xrsr_audio_format_type_t;

/// @brief XRSR stream from types
/// @details The stream from enumeration indicates the point from which to begin streaming.
typedef enum {
   XRSR_STREAM_FROM_BEGINNING     = 0, ///< Record from the beginning of incoming audio data
   XRSR_STREAM_FROM_LIVE          = 1, ///< Record from the live point of incoming audio data
   XRSR_STREAM_FROM_KEYWORD_BEGIN = 2, ///< Record from the keyword begin point
   XRSR_STREAM_FROM_KEYWORD_END   = 3, ///< Record from the keyword end point
   XRSR_STREAM_FROM_INVALID       = 4, ///< Invalid stream from type
} xrsr_stream_from_t;

/// @brief XRSR stream until types
/// @details The stream until enumeration indicates the condition that ends the stream.
typedef enum {
   XRSR_STREAM_UNTIL_END_OF_STREAM  = 0, ///< Stream until end of stream or an error occurs
   XRSR_STREAM_UNTIL_END_OF_SPEECH  = 1, ///< Stream until end of speech is detected or an error occurs
   XRSR_STREAM_UNTIL_END_OF_KEYWORD = 2, ///< Stream until end of keyword or an error occurs
   XRSR_STREAM_UNTIL_INVALID        = 3, ///< Invalid stream until type
} xrsr_stream_until_t;

/// @brief XRSR power mode
/// @details The power mode enumeration indicates the power modes which may be supported.
typedef enum {
   XRSR_POWER_MODE_FULL    = 0, ///< Full power mode
   XRSR_POWER_MODE_LOW     = 1, ///< Low power mode
   XRSR_POWER_MODE_SLEEP   = 2, ///< Lower power mode
   XRSR_POWER_MODE_INVALID = 3, ///< Invalid power mode type
} xrsr_power_mode_t;


typedef enum {
   XRSR_RECV_EVENT_EOS_SERVER        = 0,
   XRSR_RECV_EVENT_DISCONNECT_REMOTE = 1,
   XRSR_RECV_EVENT_NONE              = 2,
   XRSR_RECV_EVENT_INVALID           = 3,
} xrsr_recv_event_t;

typedef enum {
   XRSR_CERT_TYPE_NONE    = 0,
   XRSR_CERT_TYPE_P12     = 1,
   XRSR_CERT_TYPE_PEM     = 2,
   XRSR_CERT_TYPE_X509    = 3,
   XRSR_CERT_TYPE_INVALID = 4
} xrsr_cert_type_t;

/// @}

/// @addtogroup XRSR_STRUCTS
/// @{
/// @brief Structures
/// @details The speech router provides structures for grouping of values.

/// @brief XRSR version information structure
/// @details The version information data structure returned by the xrsr_version() api.
typedef struct {
   const char *name;      ///< component's name
   const char *version;   ///< component's version
   const char *branch;    ///< component's branch name
   const char *commit_id; ///< component's commit identifier
} xrsr_version_info_t;

typedef struct {
   const char *filename;
   const char *passphrase;
} xrsr_cert_p12_t;

typedef struct {
   const char *filename_cert;
   const char *filename_pkey;
   const char *filename_chain;
   const char *passphrase;
} xrsr_cert_pem_t;

typedef struct {
   X509 *          x509;
   EVP_PKEY *      pkey;
   STACK_OF(X509) *chain;
} xrsr_cert_x509_t;

typedef struct {
   xrsr_cert_type_t type;
   union {
   xrsr_cert_p12_t  p12;
   xrsr_cert_pem_t  pem;
   xrsr_cert_x509_t x509;
   } cert;
} xrsr_cert_t;

typedef struct {
   uint8_t size_packet;
   uint8_t size_header;
   uint8_t offset_step_size_index;
   uint8_t offset_predicted_sample_lsb;
   uint8_t offset_predicted_sample_msb;
   uint8_t offset_sequence_value;
   uint8_t sequence_value_min;
   uint8_t sequence_value_max;
} xrsr_adpcm_frame_t;

typedef struct {
   xrsr_audio_format_type_t type;
   union {
      xrsr_adpcm_frame_t adpcm_frame;
   } value;
} xrsr_audio_format_t;

typedef struct {
   const char *text; ///< transcription input for a text-only session (no audio data streamed)
} xrsr_request_text_t;

typedef struct {
   const char *path; ///< path to the audio file input for the session
} xrsr_request_audio_file_t;

/// @brief XRSR data read handler
/// @details Callback function prototype for handling data read return values.
/// @param[in] bytes_read The return value from data pipe read.
/// @param[in] user_data The pointer to user data.
/// @return The function has no return value.
typedef void (*xrsr_input_data_read_cb_t)(int bytes_read, void *user_data);

typedef struct {
   int                       audio_fd;     ///< audio file descriptor input for the session
   xrsr_audio_format_t       audio_format; ///< audio format transmitted over the fd
   xrsr_input_data_read_cb_t callback;     ///< User callback to be called when input file descriptor is read (optional)
   void *                    user_data;    ///< User data to be passed to callback handler (optional)
} xrsr_request_audio_fd_t;

typedef struct {
   bool   stream_params_required; ///< requestor needs missing keyword information
   float *dynamic_gain_update;
} xrsr_request_audio_mic_t;

/// @brief XRSR session request structure
/// @details The session request data structure provides detailed information to be used in specifying input for a voice session.
typedef struct {
   xrsr_session_request_type_t type;
   union {
   xrsr_request_text_t       text;
   xrsr_request_audio_file_t audio_file;
   xrsr_request_audio_fd_t   audio_fd;
   xrsr_request_audio_mic_t  audio_mic;
   } value;
} xrsr_session_request_t;

typedef struct {
   bool  update_required;
   float dynamic_gain;
} xrsr_session_config_update_t;

/// @brief XRSR HTTP session configuration structure
/// @details The HTTP session configuration data structure provides detailed information to be used in a connection using the HTTP/S protocols.
typedef struct {
   const char *        sat_token;                                 ///< NULL-terminated string containing the SAT token
   const char *        user_agent;                                ///< NULL-terminated string containing the user agent field
   const char *        query_strs[XRSR_QUERY_STRING_QTY_MAX + 1]; ///< Pointer to an array of query string parameters.  Last element in the array must be NULL.
   uint32_t            keyword_begin;                             ///< Sample index at which keyword begins
   uint32_t            keyword_duration;                          ///< Duration of keyword, in samples
   xrsr_cert_t         client_cert;                               ///< Client certificate to use for the connection
   bool                host_verify;                               ///< Verify hostname matches certificate if not false
   bool                ocsp_verify_stapling;                      ///< Verify certificate is not revoked via OCSP protocol (stapled response) if not false
   bool                ocsp_verify_ca;                            ///< Verify certificate is not revoked via OCSP protocol (contact CA) if not false
} xrsr_session_config_in_http_t;

/// @brief XRSR websocket session configuration structure
/// @details The websocket session configuration data structure provides detailed information to be used in a connection using the WS/S protocols.
typedef struct {
   const char *        sat_token;                                   ///< NULL-terminated string containing the SAT token
   const char *        query_strs[XRSR_QUERY_STRING_QTY_MAX + 1];   ///< Pointer to an array of query string parameters.  Last element in the array must be NULL.
   uint32_t            keyword_begin;                               ///< Sample index at which keyword begins
   uint32_t            keyword_duration;                            ///< Duration of keyword, in samples
   xrsr_cert_t         client_cert;                                 ///< Client certificate to use for the connection
   bool                host_verify;                                 ///< Verify hostname matches certificate if not false
   bool                ocsp_verify_stapling;                        ///< Verify certificate is not revoked via OCSP protocol (stapled response) if not false
   bool                ocsp_verify_ca;                              ///< Verify certificate is not revoked via OCSP protocol (contact CA) if not false
   bool                cert_expired_allow;                          ///< Allow expired certificates if not false
   bool                cert_revoked_allow;                          ///< Allow revoked certificates if not false
   bool                ocsp_expired_allow;                          ///< Allow expired OCSP responses if not false
   void *              app_config;                                  ///< Opaque application config
} xrsr_session_config_in_ws_t;

/// @brief XRSR SDT session configuration structure
/// @details The SDT session configuration data structure provide detailed information to be used in a connectioN.
typedef struct {
   void               *reserved;
} xrsr_session_config_in_sdt_t;

/// @brief XRSR session configuration input structure
/// @details The session configuration input data structure provides detailed information to be used in a speech router session.
typedef struct {
   xrsr_src_t                    src;  ///< source for the configuration
   union {
   xrsr_session_config_in_http_t http; ///< HTTP session configuration
   xrsr_session_config_in_ws_t   ws;   ///< Websockets session configuration
   xrsr_session_config_in_sdt_t  sdt;  ///< SDT session configuration
   };
} xrsr_session_config_in_t;

typedef void (*xrsr_callback_session_config_t)(const uuid_t uuid, xrsr_session_config_in_t *configuration);

/// @brief XRSR session configuration output structure
/// @details The session configuration output data structure provides detailed information to be used in a speech router session.
typedef struct {
   xrsr_audio_format_t            format;                         ///< Outgoing audio format
   bool                           user_initiated;                 ///< Indicates whether the session was initiated directly by the user (ie. pressing a button)
   xrsr_callback_session_config_t cb_session_config;              ///< If not NULL, function for the application to return input session config
} xrsr_session_config_out_t;

/// @brief XRSR audio stats structure
/// @details The audio statistics data structure indicates the statistics for an audio stream.
typedef struct {
   bool     valid;                ///< True if audio stats are present
   uint32_t packets_processed;    ///< Quantity of audio packets processed
   uint32_t packets_lost;         ///< Quantity of audio packets lost during transmission
   uint32_t samples_processed;    ///< Quantity of audio samples processed
   uint32_t samples_lost;         ///< Quantity of audio samples lost during transmission
   uint32_t decoder_failures;     ///< Number of audio decoder failures reported
   uint32_t samples_buffered_max; ///< Maximum quantity of samples buffered
} xrsr_audio_stats_t;

/// @brief XRSR session stats structure
/// @details The session statistics data structure indicates the statistics for an audio session.
typedef struct {
   xrsr_session_end_reason_t reason;                             ///< Reason why the session ended
   xrsr_ret_code_internal_t  ret_code_internal;                  ///< Internal return code (speech router)
   long                      ret_code_protocol;                  ///< Protocol return code (HTTP, WS, etc)
   long                      ret_code_library;                   ///< Library return code (curl, nopoll, etc)
   char                      server_ip[XRSR_SESSION_IP_LEN_MAX]; ///< NULL-terminated string indicating the server's IP address
   double                    time_connect;                       ///< Amount of time elapsed during server connection (in seconds)
   double                    time_dns;                           ///< Amount of time elapsed during DNS lookup (in seconds)
} xrsr_session_stats_t;

/// @brief XRSR stream stats structure
/// @details The stream stats data structure indicates the statistics for the session's stream.
typedef struct {
   bool               result;      ///< True if the stream was successful, otherwise false.
   xrsr_protocol_t    prot;        ///< Protocol used for the stream
   xrsr_audio_stats_t audio_stats; ///< Audio statistics for the stream
} xrsr_stream_stats_t;

/// @brief XRSR keyword detector result structure
/// @details The keyword detector result data structure returned in the session begin callback function.
typedef struct {
   float        score;                ///< Confidence score from the keyword detection event in percent (0-100)
   float        snr;                  ///< Signal to noise ration in DB (from -100 to +100)
   uint16_t     doa;                  ///< Angular direction of arrival in degrees (0-359)
   int32_t      offset_buf_begin;     ///< Negative offset in samples to the beginning of audio buffer
   int32_t      offset_kwd_begin;     ///< Negative offset in samples to the keyword begin point
   int32_t      offset_kwd_end;       ///< Negative offset in samples to the keyword end point
   float        kwd_gain;             ///< Fixed gain applied to audio input of the keyword detector
   const char * detector_name;        ///< Name of keyword detector that triggered
   const char * dsp_name;             ///< Name of DSP preprocessing in use
   float        dynamic_gain;         ///< Dynamic gain value calculated after keyword detection
   float        sensitivity;          ///< Sensitivity of the keyword detector
   float *      dynamic_gain_update;  ///< Reporting dynamic gain recalculated by xraudio
} xrsr_keyword_detector_result_t;

/// @brief XRSR destination params structure
/// @details The destination params data structure provided for a destination.
typedef struct {
   bool     debug;
   uint32_t connect_check_interval;
   uint32_t timeout_connect;
   uint32_t timeout_inactivity;
   uint32_t timeout_session;
   bool     ipv4_fallback;
   uint32_t backoff_delay;
} xrsr_dst_params_t;

/// @}

/// @addtogroup XRSR_TYPEDEFS
/// @{
/// @brief Type Definitions
/// @details The speech router provides type definitions for renaming types.

/// @brief XRSR data send handler
/// @details Function type to send data across the connection.
/// @param[in] param  Pass-thru of parameter returned by server connected handler
/// @param[in] buffer pointer to the data to send
/// @param[in] length length of the data (in bytes)
/// @return The function returns the result of the operation.
typedef xrsr_result_t (*xrsr_handler_send_t)(void *param, const uint8_t *buffer, uint32_t length);

/// @brief XRSR session begin handler
/// @details Callback function prototype for handling session begin events.
/// @param[in]    uuid            The universally unique identifier for the session
/// @param[in]    src             The source type in use
/// @param[in]    dst_index       The zero based index of the route's destination
/// @param[in]    detector_result Results of the detection event or NULL if no detection is associated with the session
/// @param[in]    config_out      Configuration output information for the session
/// @param[out]   config_in       Configuration input information for the session
/// @return The function has no return value.
typedef void (*xrsr_handler_session_begin_t)(void *data, const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_keyword_detector_result_t *detector_result, xrsr_session_config_out_t *config_out, xrsr_session_config_in_t *config_in, rdkx_timestamp_t *timestamp, const char *transcription_in);

/// @brief XRSR session config handler
/// @details Callback function prototype for handling session config events.
/// @param[in]    uuid            The universally unique identifier for the session
/// @param[inout] config_in       Configuration input information for the session
/// @return The function has no return value.
typedef void (*xrsr_handler_session_config_t)(void *data, const uuid_t uuid, xrsr_session_config_in_t *config_in);

/// @brief XRSR session end handler
/// @details Callback function prototype for handling session end events.
/// @param[in] uuid  The universally unique identifier for the session
/// @param[in] stats Statistics for the session or NULL if not available.
/// @return The function has no return value.
typedef void (*xrsr_handler_session_end_t)(void *data, const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp);

/// @brief XRSR stream begin handler
/// @details Callback function prototype for handling stream begin events.
/// @param[in] uuid The universally unique identifier for the session
/// @param[in] src  The source type in use
/// @return The function has no return value.
typedef void (*xrsr_handler_stream_begin_t)(void *data, const uuid_t uuid, xrsr_src_t src, rdkx_timestamp_t *timestamp);

/// @brief XRSR stream kwd handler
/// @details Callback function prototype for handling stream keyword events.
/// @param[in] uuid The universally unique identifier for the session
/// @return The function has no return value.
typedef void (*xrsr_handler_stream_kwd_t)(void *data, const uuid_t uuid, rdkx_timestamp_t *timestamp);

/// @brief XRSR stream end handler
/// @details Callback function prototype for handling stream end events.
/// @param[in] uuid  The universally unique identifier for the session
/// @param[in] stats Pointer to the stream's statistics or NULL if not available.
/// @return The function has no return value.
typedef void (*xrsr_handler_stream_end_t)(void *data, const uuid_t uuid, xrsr_stream_stats_t *stats, rdkx_timestamp_t *timestamp);

/// @brief XRSR source error handler
/// @details Callback function prototype for handling source error events.
/// @param[in] src  The source type in use
/// @return The function has no return value.
typedef void (*xrsr_handler_source_error_t)(void *data, xrsr_src_t src);

/// @brief XRSR connected handler
/// @details Callback function prototype for handling server connect events.
/// @param[in] send                  Function handler to send data during the session
/// @param[in] param                 Pass-thru parameter to be used when calling the send handler
/// @param[in] session_config_update Optional pointer to a struct to update session configuration parameters to send to host
/// @return The function returns true if successful or false otherwise.
typedef bool (*xrsr_handler_connected_t)(void *data, const uuid_t uuid, xrsr_handler_send_t send, void *param, rdkx_timestamp_t *timestamp, xrsr_session_config_update_t *session_config_update);

/// @brief XRSR disconnected handler
/// @details Callback function prototype for handling server disconnect events.
/// @param[in] reason        Indicates the reason why the session ended
/// @param[in] retry         Indicates whether a retry will be performed (true) or not (false)
/// @param[in] detect_resume Indicates whether audio source detection should continue (true) or not (false)
/// @return The function has no return value.
typedef void (*xrsr_handler_disconnected_t)(void *data, const uuid_t uuid, xrsr_session_end_reason_t reason, bool retry, bool *detect_resume, rdkx_timestamp_t *timestamp);

/// @brief XRSR receive message handler
/// @details Callback function prototype for handling received message events.
/// @param[in] type   The type of message which is stored in buffer.
/// @param[in] buffer A pointer to the received message.
/// @param[in] length The length of the received message (in bytes).
/// @return The function returns true if successful or false otherwise.
typedef bool (*xrsr_handler_recv_msg_t)(void *data, xrsr_recv_msg_t type, const uint8_t *buffer, uint32_t length, xrsr_recv_event_t *event);

/// @brief XRSR thread poll handler
/// @details Callback function prototype for polling XRSR thread.
/// @return The function has no return value.
typedef void (*xrsr_thread_poll_func_t)(void);

/// @brief XRSR send audio handler
/// @details Callback function prototype for handling send audio data.
/// @param[out] buffer A pointer to the audio data.
/// @param[out] length The length of the audio data (in bytes).
/// @return The function returns true if successful or false otherwise.
typedef int (*xrsr_handler_stream_audio_t)(unsigned char* buffer,uint32_t length);

/// @}

/// @addtogroup XRSR_STRUCTS
/// @{
/// @brief Structures
/// @details The speech router provides structures for grouping of values.

/// @brief XRSR handlers structure
/// @details The handlers data structure is used to store the callback function handlers for a given route.
typedef struct {
   void *                        data;           ///< Optional parameter passed to each handler
   xrsr_handler_session_begin_t  session_begin;  ///< Called when a session begins
   xrsr_handler_session_config_t session_config; ///< Called when a session is configured
   xrsr_handler_session_end_t    session_end;    ///< Called when a session ends
   xrsr_handler_stream_begin_t   stream_begin;   ///< Called when a session's audio stream begins
   xrsr_handler_stream_kwd_t     stream_kwd;     ///< Called when they keyword is passed in the stream
   xrsr_handler_stream_audio_t   stream_audio;   ///< Called when the protocol streaming the audio to destinatio
   xrsr_handler_stream_end_t     stream_end;     ///< Called when a sessino's audio stream ends
   xrsr_handler_source_error_t   source_error;   ///< Called when an error occurs with the input source
   xrsr_handler_connected_t      connected;      ///< Called when the protocol connects to the server
   xrsr_handler_disconnected_t   disconnected;   ///< Called when the protocol disconnects from the server
   xrsr_handler_recv_msg_t       recv_msg;       ///< Called when a message payload is received from the server
} xrsr_handlers_t;

/// @brief XRSR route structure
/// @details The route data structure provides detailed information about a route.
typedef struct {
   const char *        url;                             ///< URL for the server which will handle requests
   xrsr_handlers_t     handlers;                        ///< Callback function handlers
   uint32_t            formats;                         ///< Bitmap of the audio formats supported by the destination
   uint16_t            stream_time_min;                 ///< Minimum duration of audio required before establishing a session with the server.  (in milliseconds)
   xrsr_stream_from_t  stream_from;                     ///< Point from which to begin streaming
   int32_t             stream_offset;                   ///< Offset in samples from the stream from point
   xrsr_stream_until_t stream_until;                    ///< Continue streaming until this condition is encountered or an errror occurs
   xrsr_dst_params_t * params[XRSR_POWER_MODE_INVALID]; ///< Optional parameters for the route
} xrsr_dst_t;

/// @brief XRSR route structure
/// @details The route data structure provides detailed information about a route.
typedef struct {
   xrsr_src_t src;                    ///< Source type for the route
   uint32_t   dst_qty;                ///< Quantity of destinations for the route
   xrsr_dst_t dsts[XRSR_DST_QTY_MAX]; ///< Array of destinations for the route
} xrsr_route_t;

/// @brief XRSR keyword configuration structure
/// @details The keyword configuration data structure indicates detailed information for the keyword detector.
typedef struct {
   float sensitivity; ///< Sensitivity level of the keyword detector
} xrsr_keyword_config_t;

/// @brief XRSR capture config structure
/// @details The capture configuration data structure provides information to enable capture of audio streams to files.
typedef struct {
   bool        delete_files;  ///< If true, previous files will be deleted.
   bool        enable;        ///< If true, internal capture will be enabled.
   bool        use_curtail;   ///< If true, curtail will be used for the capture to continously capture until the end of the stream.
   uint32_t    file_qty_max;  ///< The maximum number of captured files to store (retains most recent files).
   uint32_t    file_size_max; ///< The maximum size (in bytes) of a single capture file.
   const char *dir_path;      ///< The full path the capture directory and a prefix for the files. (ie "/opt/logs/capture_")
} xrsr_capture_config_t;

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRSR_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The speech router provides functions to be called directly by the user application.

/// @brief Retrieve the XRSR version
/// @details Retrieves the detailed version information for the XRSR component.
/// @param[in]    version_info Pointer to an array of version information structures
/// @param[inout] qty          Quantity of entries in the version_info array
/// @return The function has no return value.
void xrsr_version(xrsr_version_info_t *version_info, uint32_t *qty);

/// @brief Opens the speech router
/// @details Opens the router and begins processing voice sessions.
/// @param[in] host_name      NULL terminated string for the host name or NULL if not specified.
/// @param[in] routes         Array of routes.  The last entry must contain a src value of XRSR_SRC_INVALID.
/// @param[in] keyword_config Keyword configuration information or NULL if not specified.
/// @param[in] capture_config Capture configuration information or NULL if not specified.
/// @return The function returns true if successful or false otherwise.
bool xrsr_open(const char *host_name, const xrsr_route_t routes[], const xrsr_keyword_config_t *keyword_config, const xrsr_capture_config_t *capture_config, xrsr_power_mode_t power_mode, bool privacy_mode, bool mask_pii, const json_t *json_obj_vsdk);

/// @brief Sets the speech router host name
/// @details Replaces the host name.
/// @param[in] host_name NULL terminated string for the host name or NULL if not specified.
/// @return The function returns true if successful or false otherwise.
bool xrsr_host_name_set(const char *host_name);

/// @brief Sets the speech router keyword config
/// @details Replaces the keyword configuration.
/// @param[in] keyword_config Keyword configuration information.
/// @return The function returns true if successful or false otherwise.
bool xrsr_keyword_config_set(const xrsr_keyword_config_t *keyword_config);

/// @brief Get the speech router keyword sensitivity limits
/// @details Given float pointers, gets the keyword detector sensitivity minimum and maximum limits
/// @param[in] type float pointer sensitivity minimum
/// @param[in] type float pointer sensitivity maximum
/// @return The function returns true if successful or false otherwise
bool xrsr_keyword_sensitivity_limits_get(float *sensitivity_min, float *sensitivity_max);

/// @brief Sets the capture configuration
/// @details Replaces the current capture configuration.
/// @param[in] capture_config Capture configuration information.
/// @return The function returns true if successful or false otherwise.
bool xrsr_capture_config_set(const xrsr_capture_config_t *capture_config);

/// @brief Sets the speech router power mode
/// @details Replaces the current power mode. This call is synchronous and will block until completion or an error occurs.
/// @param[in] power_mode Power mode.
/// @return The function returns true if successful or false otherwise.
bool xrsr_power_mode_set(xrsr_power_mode_t power_mode);

/// @brief Sets the speech router privacy mode
/// @details Replaces the current privacy mode. This call is synchronous and will block until completion or an error occurs.
/// @param[in] enable Enables privacy mode if true, otherwise disables.
/// @return The function returns true if successful or false otherwise.
bool xrsr_privacy_mode_set(bool enable);

/// @brief Get HAL privacy state
/// @details Given a boolean pointer, gets HAL mic mute state
/// @param[in] type bool pointer
/// @return The function returns true if successful or false otherwise
bool xrsr_privacy_mode_get(bool *enabled);

/// @brief Sets the speech router mask pii option
/// @details Replaces the mask pii value.
/// @param[in] enable Enables PII masking if true, otherwise disables.
/// @return The function returns true if successful or false otherwise.
bool xrsr_mask_pii_set(bool enable);

/// @brief Sets the speech router routing table
/// @details Replaces the speech routing information.
/// @param[in] routes Array of routes.  The last entry must contain a src value of XRSR_SRC_INVALID.
/// @return The function returns true if successful or false otherwise.
bool xrsr_route(const xrsr_route_t routes[]);

/// @brief Requests a speech router session
/// @details Requests to start a session manually by user pressing a button on the device or other means.
/// @param[in] src Source type for the session
/// @param[in] output_format Audio output format for the session
/// @param[in] input_format Input format for the session
/// @param[in] uuid UUID for the session (optional)
/// @param[in] low_latency Enables low latency mode if true, otherwise disables.
/// @param[in] low_cpu_util Enables low cpu utilization mode if true, otherwise disables.
/// @return The function returns true if successful or false otherwise.
bool xrsr_session_request(xrsr_src_t src, xrsr_audio_format_t output_format, xrsr_session_request_t input_format, const uuid_t *uuid, bool low_latency, bool low_cpu_util);

/// @brief Updates the file descriptor for a speech router session
/// @details Requests to update the file descriptor for a session that has been granted, but does not have the source file descriptor yet.
/// @param[in] src Source type for the session
/// @param[in] audio_file_fd audio file descriptor input for the session (optional)
/// @return The function returns true if successful or false otherwise.
bool xrsr_session_audio_fd_set(xrsr_src_t src, int audio_file_fd, xrsr_audio_format_t audio_format, xrsr_input_data_read_cb_t callback, void *user_data);

/// @brief Sets keyword info for a speech router session
/// @details Provides the keyword begin point and duration.
/// @param[in] keyword_begin    Point where keyword begins in stream (in samples)
/// @param[in] keyword_duration Duration of keyword (in samples)
/// @return The function returns true if successful or false otherwise.
bool xrsr_session_keyword_info_set(xrsr_src_t src, uint32_t keyword_begin, uint32_t keyword_duration);

/// @brief Starts the speech router capture session
/// @details Starts capturing audio streams for local sources.
/// @param[in] container      Indicates the container for capturing audio streams.
/// @param[in] file_path      Indicates the full path and capture file name prefix (ie "/opt/logs/capture_")
/// @param[in] raw_mic_enable Enables capture of raw microphone input audio data
/// @return The function returns true if successful or false otherwise.
bool xrsr_session_capture_start(xrsr_audio_container_t container, const char *file_path, bool raw_mic_enable);

/// @brief Stops the speech router capture session
/// @details Stops capturing audio streams for local sources.
/// @return The function returns true if successful or false otherwise.
bool xrsr_session_capture_stop(void);

/// @brief XRSR session terminate
/// @details Terminates the current session if it is still in progress.
/// @param[in] src Source type
/// @return The function has no return value.
void xrsr_session_terminate(xrsr_src_t src);

/// @brief XRSR session audio stream start
/// @details Starts a subsequent audio stream on the current session if it is still in progress.
/// @param[in] src Source type
/// @return The function has no return value.
void xrsr_session_audio_stream_start(xrsr_src_t src);

/// @brief Close the speech router interface
/// @details Closes the interface and frees all associated resources.
/// @return The function has no return value.
void xrsr_close(void);

/// @brief Polls the speech router thread
/// @details Polls the thread to determine if it is responsive.
/// @param[in] func Function to call in the context of the xrsr thread.
/// @return The function has no return value.
void xrsr_thread_poll(xrsr_thread_poll_func_t func);

/// @brief Convert enum to a string
/// @details Returns a NULL-terminated string representation of the source type.
/// @param[in] src Source type
/// @return The function returns a read-only string representation of the source type.
const char *xrsr_src_str(xrsr_src_t src);

/// @brief Convert enum to a string
/// @details Returns a NULL-terminated string representation of the result type.
/// @param[in] type Result type
/// @return The function returns a read-only string representation of the result type.
const char *xrsr_result_str(xrsr_result_t type);

/// @brief Convert enum to a string
/// @details Returns a NULL-terminated string representation of the session end reason type.
/// @param[in] type Session end reason type
/// @return The function returns a read-only string representation of the session end reason type.
const char *xrsr_session_request_type_str(xrsr_session_request_type_t type);

/// @brief Convert enum to a string
/// @details Returns a NULL-terminated string representation of the session end reason type.
/// @param[in] type Session end reason type
/// @return The function returns a read-only string representation of the session end reason type.
const char *xrsr_session_end_reason_str(xrsr_session_end_reason_t type);

/// @brief Convert enum to a string
/// @details Returns a NULL-terminated string representation of the stream end reason type.
/// @param[in] type Stream end reason type
/// @return The function returns a read-only string representation of the stream end reason type.
const char *xrsr_stream_end_reason_str(xrsr_stream_end_reason_t type);

/// @brief Convert enum to a string
/// @details Returns a NULL-terminated string representation of the protocol type.
/// @param[in] type Protocol type
/// @return The function returns a read-only string representation of the protocol type.
const char *xrsr_protocol_str(xrsr_protocol_t type);

/// @brief Convert enum to a string
/// @details Retrieves the string.
/// @param[in] type Receive message type
/// @return The function returns a read-only string representation of the receive message type.
const char *xrsr_recv_msg_str(xrsr_recv_msg_t type);

/// @brief Convert enum to a string
/// @details Retrieves the string.
/// @param[in] type Receive event type
/// @return The function returns a read-only string representation of the receive event type.
const char *xrsr_recv_event_str(xrsr_recv_event_t type);

/// @brief Convert enum to a string
/// @details Returns a NULL-terminated string representation of the audio container type.
/// @param[in] container Container type
/// @return The function returns a read-only string representation of the audio container type.
const char *xrsr_audio_container_str(xrsr_audio_container_t container);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif
