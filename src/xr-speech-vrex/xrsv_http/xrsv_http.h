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
#ifndef __XR_SPEECH_VREX_HTTP__
#define __XR_SPEECH_VREX_HTTP__

#include <stdint.h>
#include <stdbool.h>
#include <xrsr.h>
#include <xr_timestamp.h>
#include <jansson.h>
#include <xrsv.h>

/// @file xrsv_http.h
///
/// @defgroup XRSV_HTTP VREX SPEECH REQUEST HANDLER
/// @{
///
/// @defgroup XRSV_HTTP_DEFINITIONS Definitions
/// @defgroup XRSV_HTTP_ENUMS       Enumerations
/// @defgroup XRSV_HTTP_STRUCTS     Structures
/// @defgroup XRSV_HTTP_TYPEDEFS    Type Definitions
/// @defgroup XRSV_HTTP_FUNCTIONS   Functions
///

/// @addtogroup XRSV_HTTP_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The VREX speech request handler provides macros for some parameters which may change in the future.  User applications should use
/// these names to allow the application code to function correctly if the values change.

#define XRSV_HTTP_SESSION_ID_LEN_MAX      (64)  ///< Session identifier maximum length including NULL termination
#define XRSV_HTTP_SESSION_STR_LEN_MAX     (512) ///< Session strings maximum length including NULL termination

/// @}

/// @addtogroup XRSV_HTTP_STRUCTS
/// @{
/// @brief Structures
/// @details The VREX speech request handler provides structures for grouping of values.

/// @brief XRSV_HTTP param structure
/// @details The param data structure is used to provide input parameters to the xrsv_http_open() function.  All string parameters must be NULL-terminated.  If a string parameter is not present, NULL must be set for it.
typedef struct {
   const char *device_id;        ///< The client device's unique identifier
   const char *receiver_id;      ///< The client device's receiver identifier
   const char *partner_id;       ///< The network's partner identifier
   const char *experience;       ///< User experience identifier
   const char *app_id;           ///< The application identifier for HTTP requests from the client device
   const char *language;         ///< The device's language
   bool        test_flag;        ///< True if the device is used for testing only, otherwise false
   bool        mask_pii;         ///< True if the PII must be masked from the log
   void       *user_data;        ///< User data that is passed in to all of the callbacks
} xrsv_http_params_t;

/// @brief XRSV_HTTP received message structure
/// @details The received message data structure is returned in the receive message callback function.
typedef struct {
   long    ret_code;                                ///< Return code for the operation (if applicable)
   char    message[XRSV_HTTP_SESSION_STR_LEN_MAX];       ///< The message payload
   char    transcription[XRSV_HTTP_SESSION_STR_LEN_MAX]; ///< The transcription of the speech (if applicable)
   char    session_id[XRSV_HTTP_SESSION_ID_LEN_MAX];     ///< The session identifier (UUID or TRX)
} xrsv_http_recv_msg_t;

/// @}

/// @addtogroup XRSV_HTTP_TYPEDEFS
/// @{
/// @brief Type Definitions
/// @details The VREX speech request handler provides type definitions for renaming types.

/// @brief xrsv http object type
/// @details The xrsv http object type is returned by the xrsv_http_open api.  It is used in all subsequent calls to xrsv_http api's.
typedef void * xrsv_http_object_t;

/// @brief XRSV_HTTP session begin handler
/// @details Function type to handle session begin events from the speech router.
/// @param[in] uuid          the session's unique identifier
/// @param[in] src           the input source for the audio stream
/// @param[in] configuration session configuration from the speech router
/// @param[in] stream_params parameters which describe the stream
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_session_begin_t)(const uuid_t uuid, xrsr_src_t src, uint32_t dst_index, xrsr_session_config_out_t *configuration, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_HTTP session end handler
/// @details Function type to handle session end events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] stats sesssion statistics from the speech router
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_session_end_t)(const uuid_t uuid, xrsr_session_stats_t *stats, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_HTTP stream begin handler
/// @details Function type to handle stream begin events from the speech router.
/// @param[in] uuid the session's unique identifier
/// @param[in] src  the input source for the error
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_stream_begin_t)(const uuid_t uuid, xrsr_src_t src, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_HTTP stream end handler
/// @details Function type to handle stream end events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] stats stream statistics from the speech router
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_stream_end_t)(const uuid_t uuid, xrsr_stream_stats_t *stats, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_HTTP stream connect handler
/// @details Function type to handle stream connect events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_connected_t)(const uuid_t uuid, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_HTTP stream disconnect handler
/// @details Function type to handle stream disconnect events from the speech router.
/// @param[in] uuid  the session's unique identifier
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_disconnected_t)(const uuid_t uuid, rdkx_timestamp_t *timestamp, void *user_data);

/// @brief XRSV_HTTP receive message handler
/// @details Function type to handle received messages during the session.
/// @param[in] msg Pointer to the received message.
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_recv_msg_t)(xrsv_http_recv_msg_t *msg, void *user_data);

/// @brief XRSV_HTTP source error handler
/// @details Function type to handle source error events during the session.
/// @param[in] src Source input which generated the error
/// @param[in] user_data Data set by the user
/// @return The function has no return value.
typedef void (*xrsv_http_handler_source_error_t)(xrsr_src_t src, void *user_data);

/// @}

/// @addtogroup XRSV_HTTP_STRUCTS
/// @{

/// @brief XRSV_HTTP handlers structure
/// @details The handlers data structure is used to set all callback handlers for the vrex speech handler.  If a handler is not needed, it must be set to NULL.
typedef struct {
   xrsv_http_handler_session_begin_t     session_begin;     ///< Indicates that a voice session has started
   xrsv_http_handler_session_end_t       session_end;       ///< Indicates that a voice session has ended
   xrsv_http_handler_stream_begin_t      stream_begin;      ///< An audio stream has started
   xrsv_http_handler_stream_end_t        stream_end;        ///< An audio stream has ended
   xrsv_http_handler_connected_t         connected;         ///< The session has connected
   xrsv_http_handler_disconnected_t      disconnected;      ///< The session has disconnected
   xrsv_http_handler_recv_msg_t          recv_msg;          ///< A message was received from the server
   xrsv_http_handler_source_error_t      source_error;      ///< The source has encountered an error
} xrsv_http_handlers_t;

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRSV_HTTP_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The VREX speech request handler provides functions to be called directly by the user application.

/// @brief Open the vrex speech request handler
/// @details Function which opens the vrex speech request handler interface.
/// @param[in] params Pointer to a structure of params which will be used while opening the interace.  Many of these parameters can be updated while the interface is open.
/// @return The function returns true for success, otherwise false.
xrsv_http_object_t xrsv_http_create(const xrsv_http_params_t *params);

/// @brief Set the vrex speech request handlers
/// @details Function type to set the handlers for a given protocol.
/// @param[in] prot         Protocol for which the handlers apply
/// @param[in] handlers_in  Set of handlers that are set by the application.
/// @param[in] handlers_out Set of handlers provided by this component for use by the application.
/// @return The function returns true for success, otherwise false.
bool xrsv_http_handlers(xrsv_http_object_t object, const xrsv_http_handlers_t *handlers_in, xrsr_handlers_t *handlers_out);

/// @brief Update user data
/// @details Function to update the pointer which is passed to all of the callbacks
/// @param[in] user_data The pointer to the user data
/// @return The function returns true on success, otherwise false
bool xrsv_http_update_user_data(xrsv_http_object_t object, void *user_data);

/// @brief Update the vrex speech request handler's device id
/// @details Function used to update the device id.
/// @param[in] device_id Unique identifier for the device stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_http_update_device_id(xrsv_http_object_t object, const char *device_id);

/// @brief Update the vrex speech request handler's receiver id
/// @details Function used to update the receiver id.
/// @param[in] receiver_id Unique identifier for the receiver stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_http_update_receiver_id(xrsv_http_object_t object, const char *receiver_id);

/// @brief Update the vrex speech request handler's partner id
/// @details Function used to update the partner identifier.
/// @param[in] partner_id Network's partner identifier stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_http_update_partner_id(xrsv_http_object_t object, const char *partner_id);

/// @brief Update the vrex speech request handler's user experience id
/// @details Function used to update the user experience identifier.
/// @param[in] experience User experience identifier stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_http_update_experience(xrsv_http_object_t object, const char *experience);

/// @brief Update the vrex speech request handler's application id
/// @details Function used to update the application identifer.
/// @param[in] app_id Application identifier stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_http_update_app_id(xrsv_http_object_t object, const char *app_id);

/// @brief Update the vrex speech request handler's language
/// @details Function used to update the device's language.
/// @param[in] language Current language setting stored as a NULL-terminated string
/// @return The function returns true for success, otherwise false.
bool xrsv_http_update_language(xrsv_http_object_t object, const char *language);

/// @brief Update the vrex speech request handler's PII mask
/// @details Function used to update the mask PII option.
/// @param[in] enable Masks PII if not false;
/// @return The function returns true for success, otherwise false.
bool xrsv_http_update_mask_pii(xrsv_http_object_t object, bool enable);

/// @brief Close the vrex speech request handler
/// @details Function used to close the vrex speech request interface.
/// @return The function has no return value.
void xrsv_http_destroy(xrsv_http_object_t object);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif
