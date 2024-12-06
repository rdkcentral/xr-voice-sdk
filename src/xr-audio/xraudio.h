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
#ifndef _XRAUDIO_H_
#define _XRAUDIO_H_

/// @file xraudio.h
///
/// @defgroup XRAUDIO CLIENT API
/// @{
///
/// @defgroup XRAUDIO_DEFINITIONS Constants
/// @defgroup XRAUDIO_ENUMS       Enumerations
/// @defgroup XRAUDIO_STRUCTS     Structures
/// @defgroup XRAUDIO_CALLBACKS   Callbacks
/// @defgroup XRAUDIO_FUNCTIONS   Functions
///
/// @mainpage XR Audio Library Interface
/// This document describes the interfaces that component use to interact with audio in the system.
///
/// @addtogroup XRAUDIO_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The xraudio API provides macros for some parameters which may change in the future.  Clients should use
/// these names to allow the client code to function correctly if the values change.

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <uuid/uuid.h>
#include <xraudio_common.h>
#include <xraudio_version.h>
#include <xraudio_kwd.h>
#include <xraudio_eos.h>
#include <xraudio_ppr.h>

#define XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE      (16000)                             ///< Default input sample rate (in Hertz)
#define XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE      (2)                                 ///< Default input sample size (in bytes)
#define XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY      (1)                                 ///< Default input channel quantity

#define XRAUDIO_INPUT_MIN_SAMPLE_RATE          (16000)                             ///< Minimum input sample rate supported (in Hertz)
#define XRAUDIO_INPUT_MAX_SAMPLE_RATE          (16000)                             ///< Maximum input sample rate supported (in Hertz)

#define XRAUDIO_INPUT_MIN_SAMPLE_SIZE          (XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE) ///< Minimum input sample size supported (in bytes)
#define XRAUDIO_INPUT_MAX_SAMPLE_SIZE          (4)                                 ///< Maximum input sample size supported (in bytes)

#define XRAUDIO_INPUT_MIN_CHANNEL_QTY          (XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY) ///< Minimum input channel quantity
#define XRAUDIO_INPUT_MAX_CHANNEL_QTY          (4)                                 ///< Maximum input channel quantity

#define XRAUDIO_INPUT_MAX_DEVICE_QTY           (3)                                 ///< Maximum input devices (ff, ptt, mic)

#define XRAUDIO_INPUT_MIN_FRAME_GROUP_QTY      (1)                                 ///< Minimum input frame group quantity
#define XRAUDIO_INPUT_MAX_FRAME_GROUP_QTY      (10)                                ///< Maximum input frame group quantity
#define XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY  (XRAUDIO_INPUT_MIN_FRAME_GROUP_QTY) ///< Default input frame group quantity

#define XRAUDIO_PRE_DETECTION_DURATION_MAX     (3000)                              ///< Maximum amount of audio data saved prior to keyword detection

#define XRAUDIO_STREAM_TIME_MINIMUM_MAX        (500)                               ///< Maxmium minimum audio data threshold
#define XRAUDIO_STREAM_TIME_MINIMUM_DEFAULT    (0)                                 ///< Maxmium minimum audio data threshold

#define XRAUDIO_OUTPUT_MIN_SAMPLE_RATE         (16000)                             ///< Minimum output sample rate (in Hertz)
#define XRAUDIO_OUTPUT_MAX_SAMPLE_RATE         (48000)                             ///< Maximum output sample rate (in Hertz)

#define XRAUDIO_OUTPUT_MIN_SAMPLE_SIZE         (2)                                 ///< Minimum output sample size (in bytes)
#define XRAUDIO_OUTPUT_MAX_SAMPLE_SIZE         (2)                                 ///< Maximum output sample size (in bytes)

#define XRAUDIO_OUTPUT_MIN_CHANNEL_QTY         (1)                                 ///< Minimum output channel quantity
#define XRAUDIO_OUTPUT_MAX_CHANNEL_QTY         (2)                                 ///< Maximum output channel quantity

#define XRAUDIO_OUTPUT_MAX_DEVICE_QTY          (1)                                 ///< Maximum output devices

#define XRAUDIO_STREAM_ID_SIZE_MAX             (64)

#define XRAUDIO_INPUT_DEFAULT_KEYWORD_SENSITIVITY  (0.3)                           ///< Default keyword detector sensitivity
/// @}

/// @addtogroup XRAUDIO_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio library provides enumerated types for logical groups of values.

/// @brief xraudio results
/// @details The results enumeration indicates all the return codes which may be returned by xraudio apis.
typedef enum {
   XRAUDIO_RESULT_OK                   = 0,  ///< Operation completed successfully
   XRAUDIO_RESULT_ERROR_OBJECT         = 1,  ///< Invalid xraudio object specified
   XRAUDIO_RESULT_ERROR_INTERNAL       = 2,  ///< Internal error occurred
   XRAUDIO_RESULT_ERROR_OUTPUT         = 3,  ///< Speaker error occurred
   XRAUDIO_RESULT_ERROR_INPUT          = 4,  ///< Microphone error occurred
   XRAUDIO_RESULT_ERROR_OPEN           = 5,  ///< Operation failed due to invalid open state
   XRAUDIO_RESULT_ERROR_PARAMS         = 6,  ///< Invalid parameters specified
   XRAUDIO_RESULT_ERROR_STATE          = 7,  ///< Operation failed due to invalid state transition
   XRAUDIO_RESULT_ERROR_CONTAINER      = 8,  ///< Invalid container specified
   XRAUDIO_RESULT_ERROR_ENCODING       = 9,  ///< Invalid encoding specified
   XRAUDIO_RESULT_ERROR_FILE_OPEN      = 10, ///< Error opening input file
   XRAUDIO_RESULT_ERROR_FILE_SEEK      = 11, ///< Error performing seek on input file
   XRAUDIO_RESULT_ERROR_FIFO_OPEN      = 12, ///< Error opening specified FIFO
   XRAUDIO_RESULT_ERROR_FIFO_CONTROL   = 13, ///< Error setting FIFO parameters
   XRAUDIO_RESULT_ERROR_OUTPUT_OPEN    = 14, ///< Error opening speaker device
   XRAUDIO_RESULT_ERROR_OUTPUT_VOLUME  = 15, ///< Error setting speaker volume
   XRAUDIO_RESULT_ERROR_WAVE_HEADER    = 16, ///< Invalid wave header format
   XRAUDIO_RESULT_ERROR_RESOURCE       = 17, ///< Resources have not been granted for this instance
   XRAUDIO_RESULT_ERROR_CAPTURE        = 18, ///< Invalid capture specified
   XRAUDIO_RESULT_ERROR_MIC_OPEN       = 19, ///< Error opening microphone input
   XRAUDIO_RESULT_ERROR_DISABLED       = 20, ///< Feature is disabled
   XRAUDIO_RESULT_ERROR_IN_USE         = 21, ///< Feature is unavaliable since it is being actively used
   XRAUDIO_RESULT_ERROR_INVALID        = 22  ///< Invalid error code
} xraudio_result_t;

/// @brief Microphone Record Until
/// @details The microphone record from enumeration is used in the record and stream api's to indicate from which point to start recording the session.
typedef enum {
   XRAUDIO_INPUT_RECORD_FROM_BEGINNING     = 0, ///< Record from the beginning of incoming audio data
   XRAUDIO_INPUT_RECORD_FROM_LIVE          = 1, ///< Record from the current live point of incoming audio data
   XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN = 2, ///< Record from the keyword begin point
   XRAUDIO_INPUT_RECORD_FROM_KEYWORD_END   = 3, ///< Record from the keyword end point
   XRAUDIO_INPUT_RECORD_FROM_INVALID       = 4, ///< Invalid record until type
} xraudio_input_record_from_t;

/// @details The microphone record until enumeration is used in the record and stream api's to indicate when to stop recording the session.
typedef enum {
   XRAUDIO_INPUT_RECORD_UNTIL_END_OF_STREAM  = 0, ///< Record until xraudio_playback_stop is called or end of stream or an error occurs
   XRAUDIO_INPUT_RECORD_UNTIL_END_OF_SPEECH  = 1, ///< Record until end of speech is detected
   XRAUDIO_INPUT_RECORD_UNTIL_END_OF_KEYWORD = 2, ///< Record until end of keyword
   XRAUDIO_INPUT_RECORD_UNTIL_INVALID        = 3, ///< Invalid record until type
} xraudio_input_record_until_t;

/// @brief Audio Out Callback Events
/// @details The audio out callback enumeration is used in audio_out_callback_t callbacks to indicate events while processing the outgoing audio stream.
typedef enum {
   AUDIO_OUT_CALLBACK_EVENT_OK          = 0, ///< Event to indicate completion of asynchronous operation (play, pause, resume, stop)
   AUDIO_OUT_CALLBACK_EVENT_FIRST_FRAME = 1, ///< Event to indicate that the first frame has been played
   AUDIO_OUT_CALLBACK_EVENT_EOF         = 2, ///< Event to indicate that the end of the file has been reached
   AUDIO_OUT_CALLBACK_EVENT_UNDERFLOW   = 3, ///< Event to indicate that an underflow has occurred
   AUDIO_OUT_CALLBACK_EVENT_ERROR       = 4, ///< Event to indicate generic playback error
} audio_out_callback_event_t;

/// @brief Audio In Callback Events
/// @details The audio in callback event enumeration is used in audio_in_callback_t callbacks to indicate events while processing the incoming audio stream.
typedef enum {
   AUDIO_IN_CALLBACK_EVENT_OK                  = 0, ///< Event to indicate completion of asynchronous operation
   AUDIO_IN_CALLBACK_EVENT_EOS                 = 1, ///< Event to indicate that the end of the stream has been reached
   AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_INITIAL = 2, ///< Event to indicate that the end of the stream has been reached. No speech detected within timeout period
   AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_END     = 3, ///< Event to indicate that the end of the stream has been reached. No EOS detected within timeout period
   AUDIO_IN_CALLBACK_EVENT_FIRST_FRAME         = 4, ///< Event to indicate that the first frame has been recorded
   AUDIO_IN_CALLBACK_EVENT_END_OF_BUFFER       = 5, ///< Event to indicate that the end of the record buffer was reached
   AUDIO_IN_CALLBACK_EVENT_OVERFLOW            = 6, ///< Event to indicate that an overflow has occurred
   AUDIO_IN_CALLBACK_EVENT_STREAM_TIME_MINIMUM = 7, ///< Event to indicate that the minimum audio threshold has been reached
   AUDIO_IN_CALLBACK_EVENT_STREAM_KWD_INFO     = 8, ///< Event to indicate that the keyword information is available
   AUDIO_IN_CALLBACK_EVENT_ERROR               = 9, ///< Event to indicate generic record error
} audio_in_callback_event_t;

/// @brief Keywork Callback Events
/// @details The keywork callback event enumeration is used in keyword_callback_t callbacks to indicate events during the keyword detection process.
typedef enum {
   KEYWORD_CALLBACK_EVENT_DETECTED = 0, ///< Event to indicate that the keyword has been detected
   KEYWORD_CALLBACK_EVENT_ERROR_FD = 1, ///< Event to indicate that a file descriptor is invalid
   KEYWORD_CALLBACK_EVENT_ERROR    = 2, ///< Event to indicate generic keyword detection error
} keyword_callback_event_t;

/// @brief Resource Priorities
/// @details The resource priority enumeration is used in xraudio_resource_request calls to indicate the priority of the request.  Priority will be used to determine which requests are granted resources.
typedef enum {
   XRAUDIO_RESOURCE_PRIORITY_LOW     = 0, ///< Low priority resource request
   XRAUDIO_RESOURCE_PRIORITY_MEDIUM  = 1, ///< Medium priority resource request
   XRAUDIO_RESOURCE_PRIORITY_HIGH    = 2, ///< High priority resource request
   XRAUDIO_RESOURCE_PRIORITY_INVALID = 3, ///< Invalid resource priority
} xraudio_resource_priority_t;

/// @brief Resource Events
/// @details The resource events enumeration is used in resource_notification_callback_t callbacks in response to resource requests and when resources are revoked after being previously granted.
typedef enum {
   XRAUDIO_RESOURCE_EVENT_GRANTED = 0, ///< Requested resources have been granted.  The client can successfully call xraudio_open after receiving this event.
   XRAUDIO_RESOURCE_EVENT_REVOKED = 1, ///< Granted resources have been revoked.  The client must stop, close and release resources upon receipt of this event.
   XRAUDIO_RESOURCE_EVENT_INVALID = 2, ///< Invalid resource event
} xraudio_resource_event_t;

/// @brief Capture Types
/// @details The capture enumeration indicates all the types of microphone input and meta data which may be supported by xraudio.
typedef enum {
   XRAUDIO_CAPTURE_INPUT_MONO   = 0x00, ///< Mono microphone input
   XRAUDIO_CAPTURE_INPUT_ALL    = 0x01, ///< All microphone inputs
   XRAUDIO_CAPTURE_DOA          = 0x02, ///< direction of arrival
   XRAUDIO_CAPTURE_KWD          = 0x04, ///< keyword detector input (per channel)
   XRAUDIO_CAPTURE_EOS          = 0x08, ///< end of speech detector input (per channel)
   XRAUDIO_CAPTURE_DGA          = 0x10, ///< input to dynamic gain adjustment calculation
   XRAUDIO_CAPTURE_OUTPUT       = 0x20, ///< output to destination
} xraudio_capture_t;

/// @brief Keyword Phrase Types
/// @details The keyword phrase enumeration indicates all the keyword phrases supported by xraudio.
typedef enum {
   XRAUDIO_KEYWORD_PHRASE_INVALID     = 0, ///< Invalid keyword phrase type
} xraudio_keyword_phrase_t;

/// @brief Keyword Config Types
/// @details The keyword config enumeration indicates all the keyword configuration supported by xraudio.
typedef enum {
   XRAUDIO_KEYWORD_CONFIG_1       = 0,  ///<
   XRAUDIO_KEYWORD_CONFIG_2       = 1,  ///<
   XRAUDIO_KEYWORD_CONFIG_3       = 2,  ///<
   XRAUDIO_KEYWORD_CONFIG_4       = 3,  ///<
   XRAUDIO_KEYWORD_CONFIG_5       = 4,  ///<
   XRAUDIO_KEYWORD_CONFIG_6       = 5,  ///<
   XRAUDIO_KEYWORD_CONFIG_7       = 6,  ///<
   XRAUDIO_KEYWORD_CONFIG_8       = 7,  ///<
   XRAUDIO_KEYWORD_CONFIG_9       = 8,  ///<
   XRAUDIO_KEYWORD_CONFIG_10      = 9,  ///<
   XRAUDIO_KEYWORD_CONFIG_11      = 10, ///<
   XRAUDIO_KEYWORD_CONFIG_12      = 11, ///<
   XRAUDIO_KEYWORD_CONFIG_13      = 12, ///<
   XRAUDIO_KEYWORD_CONFIG_14      = 13, ///<
   XRAUDIO_KEYWORD_CONFIG_15      = 14, ///<
   XRAUDIO_KEYWORD_CONFIG_INVALID = 15, ///< Invalid keyword config type
} xraudio_keyword_config_t;

/// @brief xraudio object type
/// @details The xraudio object type is returned by the xraudio_object_create api.  It is used in all subsequent calls to xraudio api's.
typedef void *          xraudio_object_t;

/// @brief xraudio sample
/// @details The xraudio sample is used to store a single 16-bit signed sample of audio.
typedef int16_t         xraudio_sample_t;

/// @}

/// @addtogroup XRAUDIO_STRUCTS
/// @{
/// @brief Structure definitions
/// @details The xraudio library provides structures for grouping of values.

/// @brief xraudio keyword detection result structure
/// @details The keyword detection result data structure returned by keyword callback.
typedef struct {
   uint32_t                  chan_selected;
   xraudio_kwd_endpoints_t   endpoints;
   xraudio_kwd_chan_result_t channels[XRAUDIO_INPUT_MAX_CHANNEL_QTY];
   const char *              detector_name;
   const char *              dsp_name;
   float                     sensitivity;
   float *                   dynamic_gain_update;
} xraudio_keyword_detector_result_t;

typedef struct {
   uint32_t byte_qty; // Number of bytes from beginning of stream until end of the keyword
} xraudio_stream_keyword_info_t;

typedef struct {
   bool        enable;
   bool        use_curtail;
   uint32_t    file_qty_max;
   uint32_t    file_size_max;
   const char *dir_path;
} xraudio_internal_capture_params_t;

typedef struct {
   uint32_t packets_processed;
   uint32_t packets_lost;
   uint32_t samples_processed;
   uint32_t samples_lost;
   uint32_t decoder_failures;
   uint32_t samples_buffered_max;
} xraudio_audio_stats_t;

typedef struct {
   int                          pipe;
   xraudio_input_record_from_t  from;
   int32_t                      offset;
   xraudio_input_record_until_t until;
} xraudio_dst_pipe_t;

/// @}

/// @addtogroup XRAUDIO_CALLBACKS
/// @{
/// @brief Function callback definitions
/// @details The xraudio client api provides callbacks that are used to inform the client of asynchronous events.

/// @brief xraudio keywork callback
/// @details The xraudio keyword detection callback is used to inform the xraudio client of keyword detection events.
/// Detection results, if any, are returned in the data structure detect_results. Otherwise, this parameter will be set to NULL
typedef void (*keyword_callback_t)(xraudio_devices_input_t source, const uuid_t *uuid, keyword_callback_event_t event, void *param, xraudio_keyword_detector_result_t *detector_result, xraudio_input_format_t format);

/// @brief xraudio audio out callback
/// @details The xraudio audio out callback is used to inform the xraudio client of audio out events.
typedef void (*audio_out_callback_t)(audio_out_callback_event_t event, void *param);

/// @brief xraudio audio in callback
/// @details The xraudio audio in callback is used to inform the xraudio client of audio in events.
///
/// So far, the only event that sends an event_param that is not NULL is the AUDIO_IN_CALLBACK_EVENT_EOS event. This event sends a pointer to a xraudio_audio_stats_t structure.
typedef void (*audio_in_callback_t)(xraudio_devices_input_t source, audio_in_callback_event_t event, void *event_param, void *user_param);

/// @brief xraudio audio out data callback
/// @details The xraudio audio out data callback is used to receive outgoing audio frames from the xraudio client.
typedef int  (*audio_out_data_callback_t)(xraudio_sample_t *frame, uint32_t sample_qty, void *param);

/// @brief xraudio audio in data callback
/// @details The xraudio audio in data callback is used to send incoming audio frames to the xraudio client.
typedef int  (*audio_in_data_callback_t)(xraudio_devices_input_t source, xraudio_sample_t *frame, uint32_t sample_qty, void *param);

/// @brief xraudio resource notification callback
/// @details The xraudio resource notification callback is used to inform the xraudio client of resource events.
typedef void (*resource_notification_callback_t)(xraudio_resource_event_t event, void *param);

/// @brief xraudio thread poll callback
/// @details The xraudio thread poll callback is used to inform the xraudio client when the xraudio thread is responsive.
typedef void (*xraudio_thread_poll_func_t)(void);

/// @brief xraudio data read handler
/// @details Callback function prototype for handling data read return values.
/// @param[in] bytes_read The return value from data pipe read.
/// @param[in] user_data The pointer to user data.
/// @return The function has no return value.
typedef void (*xraudio_input_data_read_cb_t)(int bytes_read, void *user_data);

/// @}

/// @addtogroup XRAUDIO_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio client api provides functions to be called directly by the client.

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Create an xraudio object
/// @details Create an xraudio object and return a pointer to the object or NULL if an error occurred.
xraudio_object_t xraudio_object_create(const json_t *json_obj_xraudio_config);

/// @brief Destroy an xraudio object
/// @details Destroy an xraudio object.  If playback or recording sessions are active, they will be stopped. If xraudio devices are opened, they will be closed.  If resources have been allocated, they will be released.
void             xraudio_object_destroy(xraudio_object_t object);

/// @brief Get available input and output devices
/// @details Return an array of the available input and output devices from xraudio
xraudio_result_t xraudio_available_devices_get(xraudio_object_t object, xraudio_devices_input_t *inputs, uint32_t input_qty_max, xraudio_devices_output_t *outputs, uint32_t output_qty_max);

/// @brief Request resources
/// @details Request the specified input and output devices.  The priority parameter provides a course level with which the resources will be allocated.  Higher priority requests will be granted before lower priority requests.
/// Requests of the same priority will be granted in the order they are received.  The callback parameter is required to notify the client of resource events (grant, revoke).  A user defined parameter can optionally be passed to
/// the callback function.
xraudio_result_t xraudio_resource_request(xraudio_object_t object, xraudio_devices_input_t input, xraudio_devices_output_t output, xraudio_resource_priority_t priority, resource_notification_callback_t callback, void *param);

/// @brief Release resources
/// @details Release the previously requested or granted resources.  The client can release the resources when they are no longer needed or in response to receiving the revoke event in the resource notification callback.
/// Prior to releasing resources, all active recording and playback sessions must be stopped.
void             xraudio_resource_release(xraudio_object_t object);

/// @brief Set up internal capture
/// @details Allow the user the ability to enable/disable internal audio capture to file on recording operations.  This must be called prior to xraudio_open().
xraudio_result_t xraudio_internal_capture_params_set(xraudio_object_t object, xraudio_internal_capture_params_t *params);
/// @brief Deletes files written by internal capture
/// @details Allow the user the ability to delete files which were created by internal audio capture on recording operations.  This must be called prior to xraudio_open().
xraudio_result_t xraudio_internal_capture_delete_files(xraudio_object_t object, const char *dir_path);

/// @brief Open an xraudio device(s)
/// @details Open the specified input and output devices.  The microphone input format can optionally be specified using the format parameter.  Prior to opening the devices, the resources must have previously been granted.
/// Upon success, the xraudio client can utilize recording and playback api's.
xraudio_result_t xraudio_open(xraudio_object_t object, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_devices_input_t input, xraudio_devices_output_t output, xraudio_input_format_t *format);

/// @brief Close an xraudio device
/// @details Close a previously opened xraudio device.  If playback or recording sessions are active, they will be stopped.  The resources will remain allocated and can be used for subsequent calls to xraudio_open.
void             xraudio_close(xraudio_object_t object);

/// @brief Polls the xraudio thread
/// @details Polls the xraudio thread to determine if it is responsive.  If the thread is responsive, the input function will be called.
void             xraudio_thread_poll(xraudio_object_t object, xraudio_thread_poll_func_t func);

/// @brief Updates the xraudio power mode
/// @details Updates the power mode.  This call is synchronous and the new mode is active after the call returns.
xraudio_result_t xraudio_power_mode_update(xraudio_object_t object, xraudio_power_mode_t power_mode);

/// @brief Updates the xraudio privacy mode
/// @details Updates the privacy mode.  This call is synchronous and the new mode is active after the call returns.  if enable is true, privacy mode is enabled.  Otherwise it is disabled.
xraudio_result_t xraudio_privacy_mode_update(xraudio_object_t object, xraudio_devices_input_t input, bool enable);

/// @brief Gets the xraudio privacy mode
/// @details Gets the privacy mode. The input parameter is a boolean with true indicating privacy mode is enabled, otherwise it is disabled
xraudio_result_t xraudio_privacy_mode_get(xraudio_object_t object, xraudio_devices_input_t input, bool *enabled);

// Recording APIs - Synchronous if callback is NULL
/// @brief Set keyword detection parameters
/// @details Sets the keyword detection parameters.  The parameters will remain persistent until the xraudio object is destroyed.  The parameters will take effect on the next call to xraudio_keyword_detect.
xraudio_result_t xraudio_detect_params(xraudio_object_t object, xraudio_keyword_phrase_t keyword_phrase, xraudio_keyword_sensitivity_t keyword_sensitivity);
/// @brief Start keyword detection
/// @details Starts a keyword detection session.  The detector begins processing incoming audio data and provides keyword detection events by invoking the callback.
xraudio_result_t xraudio_detect_keyword(xraudio_object_t object, keyword_callback_t callback, void *param);
/// @brief Stop keyword detection
/// @details Stop the keyword detection session.  The detector stops processing incoming audio data.
xraudio_result_t xraudio_detect_stop(xraudio_object_t object);
/// @brief Get the keyword detection sensitivity limits
/// @details Gets the keyword detection sensitivity limits from the detector.
xraudio_result_t xraudio_detect_sensitivity_limits_get(xraudio_object_t object, xraudio_keyword_sensitivity_t *keyword_sensitivity_min, xraudio_keyword_sensitivity_t *keyword_sensitivity_max);
/// @brief Indicates the source's input file descriptor
/// @details This function sets the file descriptor from which to read the input stream for the specified source.
xraudio_result_t xraudio_source_fd_set(xraudio_object_t object, xraudio_devices_input_t source, int fd, xraudio_input_format_t format, xraudio_input_data_read_cb_t callback, void *user_data);
/// @brief Transfer sound intensity data to the specified fifo
/// @details This function sets a named pipe (fifo) in which to transfer sound intensity measurements when a recording session is in process.
xraudio_result_t xraudio_record_sound_intensity_transfer(xraudio_object_t object, const char *fifo_name);
/// @brief Record incoming audio data to a file
/// @details Record the incoming audio stream to the file specified in audio_file_path using the specified container format.  The recording will continue until the condition in the until parameter is reached or an error occurs.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with recording events delivered via the callback.
xraudio_result_t xraudio_record_to_file(xraudio_object_t object, xraudio_devices_input_t source, xraudio_container_t container, const char *audio_file_path, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param);
/// @brief Record incoming audio data to memory
/// @details Record the incoming audio stream to the memory location specified in the buf_samples parameter.  The number of samples that can be stored in the buffer is specified by the sample_qty parameter.
/// The recording will continue until the condition in the until parameter is reached or an error occurs.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with recording events delivered via the callback.
xraudio_result_t xraudio_record_to_memory(xraudio_object_t object, xraudio_devices_input_t source, xraudio_sample_t *buf_samples, uint32_t sample_qty, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, audio_in_callback_t callback, void *param);
/// @brief Stop an active recording session
/// @details This function stops the active recording session.
xraudio_result_t xraudio_record_stop(xraudio_object_t object, xraudio_devices_input_t source);
/// @brief Indicates the amount of audio data needed to event minimum audio threshold
/// @details This function sets the amount of milliseconds of audio data will cause a minimum audio threshold event to occur.
xraudio_result_t xraudio_stream_time_minimum(xraudio_object_t object, xraudio_devices_input_t source, uint16_t ms);
/// @brief Indicates information about the keyword present in the stream
/// @details This function sets the keyword information.
xraudio_result_t xraudio_stream_keyword_info(xraudio_object_t object, xraudio_devices_input_t source, uint32_t keyword_begin, uint32_t keyword_duration);
/// @brief Obtains information about the keyword to be inserted into the stream - for example device DSP detected keyword and initiates a session
//  @details This function queries the HAL for keyword information
xraudio_result_t xraudio_stream_keyword_info_get(xraudio_object_t object, xraudio_devices_input_t source, xraudio_keyword_detector_result_t *keyword_result);
/// @brief Transfer sound intensity data to the specified fifo
/// @details This function sets a named pipe (fifo) in which to transfer sound intensity measurements when a streaming session is in process.
xraudio_result_t xraudio_stream_sound_intensity_transfer(xraudio_object_t object, const char *fifo_name);
/// @brief Sets the stream latency mode
/// @details Prior to streaming sets the stream latency mode. Low latency mode allows the client to process the incoming audio with minimal latency. Default is latency mode is normal.
xraudio_result_t xraudio_stream_latency_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_latency_mode_t latency_mode);
/// @brief Sets the stream cpu util mode
/// @details Prior to streaming sets the stream cpu utilization mode. Low cpu utilization mode allows the client to process the incoming audio with reduced cpu consumption. Default is cpu utilization mode is normal.
xraudio_result_t xraudio_stream_cpu_util_mode_set(xraudio_object_t object, xraudio_devices_input_t source, xraudio_stream_cpu_util_mode_t cpu_util_mode);
/// @brief Set the frame group quantity
/// @details When streaming the audio data will be written in frame sized chunks to the destination.  Setting the frame group quantity increases the size of audio data written to the streaming interface
/// a multiple of the frame size.  This allows the client to process incoming audio data in larger sized chunks.  The default quantity is XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY.
xraudio_result_t xraudio_stream_frame_group_quantity_set(xraudio_object_t object, xraudio_devices_input_t source, uint8_t quantity);
/// @brief Set the stream identifier string
/// @details Prior to streaming, the stream identifer string can be set to provide an identifier for the stream.
xraudio_result_t xraudio_stream_identifier_set(xraudio_object_t object, xraudio_devices_input_t source, const char *identifier);
/// @brief Stream incoming audio data to a fifo
/// @details Stream the incoming audio stream to the named pipe (fifo).  The recording will continue until the condition in the until parameter is reached or an error occurs.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with recording events delivered via the callback.
xraudio_result_t xraudio_stream_to_fifo(xraudio_object_t object, xraudio_devices_input_t source, const char *fifo_name, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param);
/// @brief Stream incoming audio data to a pipe
/// @details Stream the incoming audio stream to the specified array of pipes.  The recording will continue until the condition in the until parameter is reached or an error occurs.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with recording events delivered via the callback.
xraudio_result_t xraudio_stream_to_pipe(xraudio_object_t object, xraudio_devices_input_t source, xraudio_dst_pipe_t dsts[], xraudio_input_format_t *format_decoded, bool subsequent, audio_in_callback_t callback, void *param);
/// @brief Stream incoming audio data to a user-defined handler
/// @details Stream the incoming audio stream to the user-defined handler in the data parameter.  The streaming will continue until the condition in the until parameter is reached or an error occurs.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with recording events delivered via the callback.
xraudio_result_t xraudio_stream_to_user(xraudio_object_t object, xraudio_devices_input_t source, audio_in_data_callback_t data, xraudio_input_record_from_t from, int32_t offset, xraudio_input_record_until_t until, xraudio_input_format_t *format_decoded, audio_in_callback_t callback, void *param);
/// @brief Stop an active streaming session
/// @details This function stops the active streaming session.
xraudio_result_t xraudio_stream_stop(xraudio_object_t object, xraudio_devices_input_t source, int32_t index);

// Playback APIs - Synchronous if callback is NULL
/// @brief Transfer sound intensity data to the specified fifo
/// @details This function sets a named pipe (fifo) in which to transfer sound intensity measurements when a playback session is in process.
xraudio_result_t xraudio_play_sound_intensity_transfer(xraudio_object_t object, const char *fifo_name);
/// @brief Play audio data from a file
/// @details Play the audio from the file specified in the audio_file_path parameter.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with playback events delivered via the callback.
xraudio_result_t xraudio_play_from_file(xraudio_object_t object, const char *audio_file_path, audio_out_callback_t callback, void *param);
/// @brief Play audio data from memory
/// @details Play the audio from the memory location specified in the audio_buf parameter.  The size of the audio data (in bytes) is specified in the size parameter.  The format parameter is used
/// to specify additional details about the audio format.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with playback events delivered via the callback.
xraudio_result_t xraudio_play_from_memory(xraudio_object_t object, xraudio_output_format_t *format, const uint8_t *audio_buf, uint32_t size, audio_out_callback_t callback, void *param);
/// @brief Play audio data from a pipe
/// @details Play the audio from the pipe specified in the pipe parameter.  The format parameter is used to specify additional details about the audio format.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with playback events delivered via the callback.
xraudio_result_t xraudio_play_from_pipe(xraudio_object_t object, xraudio_output_format_t *format, int pipe, audio_out_callback_t callback, void *param);
/// @brief Play audio data from a user-defined handler
/// @details Play the audio using a user-defined data callback.  The format parameter is used to specify additional details about the audio format.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with playback events delivered via the callback.
xraudio_result_t xraudio_play_from_user(xraudio_object_t object, xraudio_output_format_t *format, audio_out_data_callback_t data, audio_out_callback_t callback, void *param);
/// @brief Pause an active playback session
/// @details Pause an active playback session.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with playback events delivered via the callback.
xraudio_result_t xraudio_play_pause(xraudio_object_t object, audio_out_callback_t callback, void *param);
/// @brief Resume a paused playback session
/// @details Resumes a paused playback session.
/// The operation is performed synchronously if the callback parameter is NULL.  Otherwise the operation is performed asynchronously with playback events delivered via the callback.
xraudio_result_t xraudio_play_resume(xraudio_object_t object, audio_out_callback_t callback, void *param);
/// @brief Stop an active playback session
/// @details This function stops an active playback session.
xraudio_result_t xraudio_play_stop(xraudio_object_t object);
/// @brief Set the absolute volume for playback
/// @details The volume can be set for playback sessions that are in progress or prior to starting a playback.  The volume value must be within the range XRAUDIO_VOLUME_MIN and XRAUDIO_VOLUME_MAX.
/// In case of mono playback, the right channel will be used. Smooth ramping between volume levels and limit bumper sounds are enabled as defaults.
xraudio_result_t xraudio_play_volume_set(xraudio_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right);
/// @brief Set the absolute volume with ramp control for playback
/// @details The volume can be set for playback sessions that are in progress or prior to starting a playback.  The volume value must be within the range XRAUDIO_VOLUME_MIN and XRAUDIO_VOLUME_MAX.
/// In case of mono playback, the right channel will be used. Smooth ramping between volume levels can be enabled or disabled.
xraudio_result_t xraudio_play_volume_ramp_set(xraudio_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right, int8_t ramp_en);
/// @brief Get the current absolute volume and ramp control setting from a playback session
/// @details Returns the current absolute volume value and current ramp enable/disable from a playback session.
/// In case of mono playback, the left and right channel will return the same volume value.
xraudio_result_t xraudio_play_volume_get(xraudio_object_t object, xraudio_volume_step_t *left, xraudio_volume_step_t *right, int8_t *ramp_en);
/// @brief Set the relative volume with ramp control for playback
/// @details The volume can be changed relative to the current value for playback sessions that are in progress or prior to starting a playback.
/// In case of mono playback, the right channel will be used. Smooth ramping between volume levels can be enabled or disabled.
xraudio_result_t xraudio_play_volume_set_rel(xraudio_object_t object, xraudio_volume_step_t left, xraudio_volume_step_t right, int8_t ramp_en);
/// @brief Set volume control configuration settings
/// @details Set or update volume control maximum, minimum, step size (positive tenths of dB e.g., 20 = 2.0 dB), and if gain is applied externally.
/// All parameters are necessary. Find current values using xraudio_play_volume_config_get().
xraudio_result_t xraudio_play_volume_config_set(xraudio_object_t object, xraudio_volume_step_t max_volume, xraudio_volume_step_t min_volume, xraudio_volume_step_size_t volume_step_dB, int8_t use_ext_gain);
/// @brief Get the current volume control configuration settings
/// @details Returns the current volume control maximum, minimum, step size (positive tenths of dB e.g., 20 = 2.0 dB), and if gain is applied using external audio HAL.
/// Enter NULL for unused parameters.
xraudio_result_t xraudio_play_volume_config_get(xraudio_object_t object, xraudio_volume_step_t *max_volume, xraudio_volume_step_t *min_volume, xraudio_volume_step_size_t *volume_step_dB, int8_t *use_ext_gain);

// Statistics functions
/// @brief Clear statistics
/// @details The statistics to clear are specified by the bitwise statistics parameter using the XRAUDIO_STATISTICS_* definitions.
void             xraudio_statistics_clear(xraudio_object_t object, uint32_t statistics);
/// @brief Print statistics
/// @details The statistics to print are specified by the bitwise statistics parameter using the XRAUDIO_STATISTICS_* definitions.
void             xraudio_statistics_print(xraudio_object_t object, uint32_t statistics);

/// @brief Stop an active capture session
/// @details This function starts bluetooth HFP audio bypass.
xraudio_result_t xraudio_bluetooth_hfp_start(xraudio_object_t object, xraudio_input_format_t *format);
/// @details This function stops bluetooth HFP audio bypass.
xraudio_result_t xraudio_bluetooth_hfp_stop(xraudio_object_t object);
/// @details This function mutes and unmutes bluetooth HFP microphone.
xraudio_result_t xraudio_bluetooth_hfp_mute(xraudio_object_t object, unsigned char enable);


// Diagnostics Functions
/// @brief Capture incoming audio and meta data to a file
/// @details Record the incoming audio stream to the file specified in audio_file_path using the specified capture and container format.  The recording will continue until the capture is stopped by
/// the user or an error occurs. The operation is performed asynchronously.  If the callback parameter is not NULL, capture events will delivered via the callback. When enabled, raw microphone data can be captured.
xraudio_result_t xraudio_capture_to_file_start(xraudio_object_t object, xraudio_capture_t capture, xraudio_container_t container, const char *audio_file_path, bool raw_mic_enable, audio_in_callback_t callback, void *param);
/// @brief Stop an active capture session
/// @details This function stops the active capture session.
xraudio_result_t xraudio_capture_stop(xraudio_object_t object);


// Utility functions
/// @brief Convert the result type to a string
const char *     xraudio_result_str(xraudio_result_t type);
/// @brief Convert the resource priority type to a string
const char *     xraudio_resource_priority_str(xraudio_resource_priority_t type);
/// @brief Convert the audio out event to a string
const char *     audio_out_callback_event_str(audio_out_callback_event_t type);
/// @brief Convert the audio in event to a string
const char *     audio_in_callback_event_str(audio_in_callback_event_t type);
/// @brief Convert the keyword event type to a string
const char *     keyword_callback_event_str(keyword_callback_event_t type);
/// @brief Convert the resource event type to a string
const char *     xraudio_resource_event_str(xraudio_resource_event_t type);
/// @brief Convert the capture type to a string
const char *     xraudio_capture_str(xraudio_capture_t type);
/// @brief Convert the keyword_phrase type to a string
const char *     xraudio_keyword_phrase_str(xraudio_keyword_phrase_t type);
/// @brief Convert the keyword_config type to a string
const char *     xraudio_keyword_config_str(xraudio_keyword_config_t type);
/// @brief Convert the xraudio_eos_event_t type to a string
const char *     xraudio_eos_event_str(xraudio_eos_event_t type);
/// @brief Convert the xraudio_ppr_event_t type to a string
const char *     xraudio_ppr_event_str(xraudio_ppr_event_t type);
/// @brief Convert the xraudio_ppr_command_t type to a string
const char *     xraudio_ppr_command_str(xraudio_ppr_command_t command);
/// @brief Convert the xraudio_kwd_criterion_t type to a string
const char *     xraudio_keyword_criterion_str(xraudio_kwd_criterion_t criterion);
/// @brief Convert the xraudio_stream_latency_mode_t type to a string
const char *     xraudio_stream_latency_mode_str(xraudio_stream_latency_mode_t latency_mode);
/// @brief Convert the xraudio_stream_latency_mode_t type to a string
const char *     xraudio_stream_cpu_util_mode_str(xraudio_stream_cpu_util_mode_t cpu_util_mode);

/// @brief Generate a wave file header
/// @details Generate a wave header at the memory location specified by the header parameter using the specified audio_format, num_channels, sample_rate, bits_per_sample and pcm_data_size parameters.
void             xraudio_wave_header_gen(uint8_t *header, uint16_t audio_format, uint16_t num_channels, uint32_t sample_rate, uint16_t bits_per_sample, uint32_t pcm_data_size, uint32_t padding);
/// @brief Parse a wave header
/// @details Parse the wave header at the beginning of the specified fh or memory location (header, size) and return the offset to the beginning of audio data or -1 in case of error.
/// The details of the audio format are written into the location specified by the format parameter.
int32_t          xraudio_container_header_parse_wave(int fd, const uint8_t *header, uint32_t size, xraudio_output_format_t *format, uint32_t *data_length);

#ifdef __cplusplus
}
#endif
/// @}

/// @}

#endif
