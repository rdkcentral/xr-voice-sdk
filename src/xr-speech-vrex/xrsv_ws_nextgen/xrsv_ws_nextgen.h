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
#ifndef __XR_SPEECH_VREX_WS_NEXTGEN__
#define __XR_SPEECH_VREX_WS_NEXTGEN__

#include <stdint.h>
#include <stdbool.h>
#include <xrsr.h>
#include <xr_timestamp.h>
#include <jansson.h>
#include <xrsv.h>

/// @file xrsv_ws_nextgen.h
///
/// @defgroup XRSV_WS_NEXTGEN VREX SPEECH REQUEST HANDLER
/// @{
///
/// @defgroup XRSV_WS_NEXTGEN_DEFINITIONS Definitions
/// @defgroup XRSV_WS_NEXTGEN_ENUMS       Enumerations
/// @defgroup XRSV_WS_NEXTGEN_STRUCTS     Structures
/// @defgroup XRSV_WS_NEXTGEN_TYPEDEFS    Type Definitions
/// @defgroup XRSV_WS_NEXTGEN_FUNCTIONS   Functions
///

/// @addtogroup XRSV_WS_NEXTGEN_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The VREX speech request handler provides macros for some parameters which may change in the future.  User applications should use
/// these names to allow the application code to function correctly if the values change.

#define XRSV_WS_NEXTGEN_SESSION_ID_LEN_MAX      (64)  ///< Session identifier maximum length including NULL termination
#define XRSV_WS_NEXTGEN_SESSION_STR_LEN_MAX     (512) ///< Session strings maximum length including NULL termination

/// @}

/// @addtogroup XRSV_WS_NEXTGEN_ENUMS
/// @{
/// @brief Enumerations for groups of values
/// @details The VREX speech request handler provides enumerations for some parameters which may change in the future.  User applications should use
/// these names to allow the application code to function correctly if the values change.

typedef enum {
   XRSV_WS_NEXTGEN_DEVICE_TYPE_STB     = 0,
   XRSV_WS_NEXTGEN_DEVICE_TYPE_TV      = 1,
   XRSV_WS_NEXTGEN_DEVICE_TYPE_INVALID = 2
} xrsv_ws_nextgen_device_type_t;

/// @}

/// @addtogroup XRSV_WS_NEXTGEN_STRUCTS
/// @{
/// @brief Structures
/// @details The VREX speech request handler provides structures for grouping of values.

/// @brief XRSV_WS_NEXTGEN param structure
/// @details The param data structure is used to provide input parameters to the xrsv_ws_nextgen_open() function.  All string parameters must be NULL-terminated.  If a string parameter is not present, NULL must be set for it.
typedef struct {
   const char *device_id;                 ///< The client device's unique identifier
   const char *account_id;                ///< The user's account identifier
   const char *partner_id;                ///< The network's partner identifier
   const char *experience;                ///< User experience identifier
   const char *audio_profile;             ///< Device audio profile
   const char *audio_model;               ///< Device audio model
   const char *language;                  ///< The device's language
   const char *device_mac;                ///< The device's MAC address
   const char *rf_protocol;               ///< The device's RF protocol
   bool        test_flag;                 ///< True if the device is used for testing only, otherwise false
   bool        bypass_wuw_verify_success; ///< True if the server WUW verification is bypassed (return success), otherwise false
   bool        bypass_wuw_verify_failure; ///< True if the server WUW verification is bypassed (return failure), otherwise false
   bool        mask_pii;                  ///< True if the PII must be masked from the log
   void       *user_data;                 ///< User data that is passed in to all of the callbacks
} xrsv_ws_nextgen_params_t;

/// @brief XRSV_WS_NEXTGEN received message structure
/// @details The received message data structure is returned in the receive message callback function.
typedef struct {
   long    ret_code;                                ///< Return code for the operation (if applicable)
   char    message[XRSV_WS_NEXTGEN_SESSION_STR_LEN_MAX];       ///< The message payload
   char    transcription[XRSV_WS_NEXTGEN_SESSION_STR_LEN_MAX]; ///< The transcription of the speech (if applicable)
   char    session_id[XRSV_WS_NEXTGEN_SESSION_ID_LEN_MAX];     ///< The session identifier (UUID or TRX)
} xrsv_ws_nextgen_recv_msg_t;

/// @brief XRSV_WS_NEXTGEN stream parameter structure
/// @details The stream parameter data structure is returned in the session begin callback function.
typedef struct {
   uint32_t     keyword_sample_begin;               ///< The offset in samples from the beginning of the buffered audio to the beginning of the keyword
   uint32_t     keyword_sample_end;                 ///< The offset in samples from the beginning of the buffered audio to the end of the keyword
   uint16_t     keyword_doa;                        ///< The direction of arrival in degrees (0-359)
   double       keyword_sensitivity;                ///<
   uint16_t     keyword_sensitivity_triggered;      ///<
   double       keyword_sensitivity_high;           ///<
   bool         keyword_sensitivity_high_support;   ///<
   bool         keyword_sensitivity_high_triggered; ///<
   double       keyword_gain;                       ///< The gain applied to the audio at the input of the keyword detector
   double       dynamic_gain;                       ///< The gain applied to the streamed audio
   double       signal_noise_ratio;                 ///<
   double       linear_confidence;                  ///<
   int32_t      nonlinear_confidence;               ///<
   bool         push_to_talk;                       ///< True if the session was started by the user pressing a button
   const char * detector_name;                      ///< Name of keyword detector that initiated session, if applicable
   const char * dsp_name;                           ///< Name of DSP preprocessing in use, if applicable
   uint16_t     par_eos_timeout;                    ///< Press-and-release end-of-speech timeout
} xrsv_ws_nextgen_stream_params_t;

/// @}

/// @addtogroup XRSV_WS_NEXTGEN_TYPEDEFS
/// @{
/// @brief Type Definitions
/// @details The VREX speech request handler provides type definitions for renaming types.

/// @brief xrsv ws object type
/// @details The xrsv ws object type is returned by the xrsv_ws_nextgen_open api.  It is used in all subsequent calls to xrsv_ws_nextgen api's.
typedef void * xrsv_ws_nextgen_object_t;

/// @brief XRSV_WS_NEXTGEN session begin handler
/// @details Function type to handle session begin events from the speech router.
/// @param[in] uuid          the session's unique identifier
/// @param[in] src           the input source for the audio stream
/// @param[in] configuration session configuration from the speech router
/// @param[in] stream_params parameters which describe the stream
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_session_begin_t)(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_session_config_out_t *configuration, xrsv_ws_nextgen_stream_params_t *stream_params, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN session end handler
/// @details Function type to handle session end events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] stats sesssion statistics from the speech router
/// @param[in] user_data     the data set by the user
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_session_end_t)(const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN stream begin handler
/// @details Function type to handle stream begin events from the speech router.
/// @param[in] uuid the session's unique identifier
/// @param[in] src  the input source for the error
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_stream_begin_t)(const uuid_t uuid, xrsr_src_t src, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN stream kwd handler
/// @details Function type to handle stream kwd events from the speech router.
/// @param[in] uuid the session's unique identifier
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_stream_kwd_t)(const uuid_t uuid, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN stream end handler
/// @details Function type to handle stream end events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] stats stream statistics from the speech router
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_stream_end_t)(const uuid_t uuid, xrsr_stream_stats_t *stats, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN stream connect handler
/// @details Function type to handle stream connect events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_connected_t)(const uuid_t uuid, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN stream disconnect handler
/// @details Function type to handle stream disconnect events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_disconnected_t)(const uuid_t uuid, bool retry, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN stream sent init handler
/// @details Function type to handle initilization message sent events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_sent_init_t)(const uuid_t uuid, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_WS_NEXTGEN listening handler
/// @details Function type to handle listening events during the session.
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_listening_t)(void *user_data);

/// @brief XRSV_WS_NEXTGEN asr handler
/// @details Function type to handle asr events during the session.
/// @param[in] text text associated with the asr event
/// @param[in] final boolean describing if text is final
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_asr_t)(const char *text, bool final, void *user_data);

/// @brief XRSV_WS_NEXTGEN conn close handler
/// @details Function type to handle connection close events during the session.
/// @param[in] reason reason string from the server
/// @param[in] ret_code return code from the server
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_conn_close_t)(const char *reason, long ret_code, void *user_data);

/// @brief XRSV_WS_NEXTGEN vrex response handler
/// @details Function type to handle vrex response events during the session.
/// @param[in] ret_code return code from the server
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_response_vrex_t)(long ret_code, void *user_data);

/// @brief XRSV_WS_NEXTGEN WUW verification handler
/// @details Function type to handle wuw verification events during the session.
/// @param[in] passed boolean describing if the keyword passed cloud verification
/// @param[in] confidence the confidence value from the cloud
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_wuw_verification_t)(const uuid_t uuid, bool passed, long confidence, void *user_data);

/// @brief XRSV_WS_NEXTGEN msg handler
/// @details Function type to handle raw messages from the server.
/// @param[in] msg the message from the server
/// @param[in] length the length of the message
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_msg_t)(const char *msg, unsigned long length, void *user_data);

/// @brief XRSV_WS_NEXTGEN source error handler
/// @details Function type to handle source error events during the session.
/// @param[in] src Source input which generated the error
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_source_error_t)(xrsr_src_t src, void *user_data);

/// @brief XRSV_WS_NEXTGEN data send handler
/// @details Function type to handle TV mute events during the session.
/// @param[in] mute True to mute the TV, False to unmute
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_tv_mute_t)(bool mute, void *user_data);

/// @brief XRSV_WS_NEXTGEN TV power handler
/// @details Function type to handle TV power events during the session.
/// @param[in] power True to turn TV power ON, False to turn TV power OFF
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_tv_power_t)(bool power, bool toggle, void *user_data);

/// @brief XRSV_WS_NEXTGEN TV volume handler
/// @details Function type to handle TV volume events during the session.
/// @param[in] up           True to increase volume, False to decrease volume
/// @param[in] repeat_count Quantity of increment to the volume
/// @param[in] user_data     the data set by the user
/// @return The function has no return value.
typedef void (*xrsv_ws_nextgen_handler_tv_volume_t)(bool up, uint32_t repeat_count, void *user_data);

/// @}

/// @addtogroup XRSV_WS_NEXTGEN_STRUCTS
/// @{

/// @brief XRSV_WS_NEXTGEN handlers structure
/// @details The handlers data structure is used to set all callback handlers for the vrex speech handler.  If a handler is not needed, it must be set to NULL.
typedef struct {
   xrsv_ws_nextgen_handler_session_begin_t     session_begin;     ///< Indicates that a voice session has started
   xrsv_ws_nextgen_handler_session_end_t       session_end;       ///< Indicates that a voice session has ended
   xrsv_ws_nextgen_handler_stream_begin_t      stream_begin;      ///< An audio stream has started
   xrsv_ws_nextgen_handler_stream_kwd_t        stream_kwd;        ///< The keyword has been passed in the stream
   xrsv_ws_nextgen_handler_stream_end_t        stream_end;        ///< An audio stream has ended
   xrsv_ws_nextgen_handler_connected_t         connected;         ///< The session has connected
   xrsv_ws_nextgen_handler_disconnected_t      disconnected;      ///< The session has disconnected
   xrsv_ws_nextgen_handler_sent_init_t         sent_init;         ///< The init message was sent to the server
   xrsv_ws_nextgen_handler_listening_t         listening;         ///< The server is listening to the audio
   xrsv_ws_nextgen_handler_asr_t               asr;               ///< The server notifying ASR results
   xrsv_ws_nextgen_handler_conn_close_t        conn_close;        ///< The server is closing the connection
   xrsv_ws_nextgen_handler_response_vrex_t     response_vrex;     ///< The server response.
   xrsv_ws_nextgen_handler_wuw_verification_t  wuw_verification;  ///< The server cloud wuw verification status
   xrsv_ws_nextgen_handler_msg_t               msg;               ///< Raw messages from the server
   xrsv_ws_nextgen_handler_source_error_t      source_error;      ///< The source has encountered an error
   xrsv_ws_nextgen_handler_tv_mute_t           tv_mute;           ///< The server wants to mute/unmute the TV
   xrsv_ws_nextgen_handler_tv_power_t          tv_power;          ///< The server wants to control the TV power
   xrsv_ws_nextgen_handler_tv_volume_t         tv_volume;         ///< The server wants to control the TV's volume
} xrsv_ws_nextgen_handlers_t;

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRSV_WS_NEXTGEN_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The VREX speech request handler provides functions to be called directly by the user application.

/// @brief Open the vrex speech request handler
/// @details Function which opens the vrex speech request handler interface.
/// @param[in] params Pointer to a structure of params which will be used while opening the interace.  Many of these parameters can be updated while the interface is open.
/// @return The function returns true for success, otherwise false.
xrsv_ws_nextgen_object_t xrsv_ws_nextgen_create(const xrsv_ws_nextgen_params_t *params);

/// @brief Set the vrex speech request handlers
/// @details Function type to set the handlers for a given protocol.
/// @param[in] handlers_in  Set of handlers that are set by the application.
/// @param[in] handlers_out Set of handlers provided by this component for use by the application.
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_handlers(xrsv_ws_nextgen_object_t object, const xrsv_ws_nextgen_handlers_t *handlers_in, xrsr_handlers_t *handlers_out);

/// @brief Update the user data for vrex speech handlers
/// @details Function to update the user data for all of the handlers.
/// @param[in] user_data the data the user wants to be passed in every handler.
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_user_data(xrsv_ws_nextgen_object_t object, void *user_data);

/// @brief Update the vrex speech request handler's device id
/// @details Function used to update the device id.
/// @param[in] device_id Unique identifier for the device stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_device_id(xrsv_ws_nextgen_object_t object, const char *device_id);

/// @brief Update the vrex speech request handler's account id
/// @details Function used to update the user's account identifier.
/// @param[in] account_id User's account identifier stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_account_id(xrsv_ws_nextgen_object_t object, const char *account_id);

/// @brief Update the vrex speech request handler's device type
/// @details Function used to update the device type identifier.
/// @param[in] device_type Device's identifier stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_device_type(xrsv_ws_nextgen_object_t object, xrsv_ws_nextgen_device_type_t device_type);

/// @brief Update the vrex speech request handler's partner id
/// @details Function used to update the partner identifier.
/// @param[in] partner_id Network's partner identifier stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_partner_id(xrsv_ws_nextgen_object_t object, const char *partner_id);

/// @brief Update the vrex speech request handler's user experience id
/// @details Function used to update the user experience identifier.
/// @param[in] experience User experience identifier stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_experience(xrsv_ws_nextgen_object_t object, const char *experience);

/// @brief Update the vrex speech request handler's audio profile
/// @details Function used to update the device's audio profile.
/// @param[in] audio_profile Audio profile name stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_audio_profile(xrsv_ws_nextgen_object_t object, const char *audio_profile);

/// @brief Update the vrex speech request handler's audio model
/// @details Function used to update the device's audio model.
/// @param[in] audio_model Audio model name stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_audio_model(xrsv_ws_nextgen_object_t object, const char *audio_model);

/// @brief Update the vrex speech request handler's audio RF protocol
/// @details Function used to update the device's RF protocol.
/// @param[in] rf_protocol Audio device's RF protocol name stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_audio_rf_protocol(xrsv_ws_nextgen_object_t object, const char *rf_protocol);

/// @brief Update the vrex speech request handler's language
/// @details Function used to update the device's language.
/// @param[in] language Current language setting stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_language(xrsv_ws_nextgen_object_t object, const char *language);

/// @brief Update the vrex speech request handler's PII mask
/// @details Function used to update the mask PII option.
/// @param[in] enable Masks PII if not false;
/// @return The function returns true for success, otherwise false.
bool xrsv_ws_nextgen_update_mask_pii(xrsv_ws_nextgen_object_t object, bool enable);

/// @brief Update application init blob
/// @details Function used to update the application blob in the init message
/// @param[in] blob NULL Terminated JSON blob to be added to init message
/// @return The function returns true for success, otherwise false
bool xrsv_ws_nextgen_update_init_app(xrsv_ws_nextgen_object_t object, const char *blob);

/// @brief Send message
/// @details Function used to send a message over the WS.
/// @param[in] msg NULL Terminated message to send
/// @return The function returns true for success, otherwise false
bool xrsv_ws_nextgen_send_msg(xrsv_ws_nextgen_object_t object, const char *msg);

/// @brief Close the vrex speech request handler
/// @details Function used to close the vrex speech request interface.
/// @return The function has no return value.
void xrsv_ws_nextgen_destroy(xrsv_ws_nextgen_object_t object);

/// @brief vrex speech request handler message string
/// @details Function used to convert an enum to a string.
/// @param[in] type Receive message type to convert to a string
/// @return The function returns the result of the operation.
const char *xrsr_recv_msg_str(xrsr_recv_msg_t type);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif
