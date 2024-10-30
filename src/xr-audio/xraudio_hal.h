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
#ifndef _XRAUDIO_HAL_H_
#define _XRAUDIO_HAL_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <uuid/uuid.h>
#include "xraudio_common.h"
#include "xraudio_eos.h"
#include "xraudio_version.h"

/// @file xraudio_hal.h
///
/// @defgroup XRAUDIO_HAL XRAUDIO - HAL
/// @{
///
/// @defgroup XRAUDIO_HAL_DEFINITIONS Constants
/// @defgroup XRAUDIO_HAL_ENUMS       Enumerations
/// @defgroup XRAUDIO_HAL_STRUCTS     Structures
/// @defgroup XRAUDIO_HAL_FUNCTIONS   Functions
///

/// @addtogroup XRAUDIO_HAL_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio library provides enumerated types for logical groups of values.

typedef enum {
   XRAUDIO_SDF_MODE_NONE              = 0,
   XRAUDIO_SDF_MODE_KEYWORD_DETECTION = 1,
   XRAUDIO_SDF_MODE_STRONGEST_SECTOR  = 2,
   XRAUDIO_SDF_MODE_INVALID           = 3,
} xraudio_sdf_mode_t;

typedef enum {
   XRAUDIO_EOS_CMD_SESSION_BEGIN     = 0,
   XRAUDIO_EOS_CMD_SESSION_TERMINATE = 1,
   XRAUDIO_EOS_CMD_INVALID           = 2,
} xraudio_eos_cmd_t;

typedef void * xraudio_hal_obj_t;

typedef enum {
   XRAUDIO_RESOURCE_ID_INPUT_1       = 0,
   XRAUDIO_RESOURCE_ID_INPUT_2       = 1,
   XRAUDIO_RESOURCE_ID_INPUT_3       = 2,
   XRAUDIO_RESOURCE_ID_INPUT_INVALID = 3,
} xraudio_resource_id_input_t;

typedef enum {
   XRAUDIO_RESOURCE_ID_OUTPUT_1       = 0,
   XRAUDIO_RESOURCE_ID_OUTPUT_2       = 1,
   XRAUDIO_RESOURCE_ID_OUTPUT_3       = 2,
   XRAUDIO_RESOURCE_ID_OUTPUT_INVALID = 3,
} xraudio_resource_id_output_t;

/// @}

/// @addtogroup XRAUDIO_HAL_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The xraudio API provides macros for some parameters which may change in the future.  Clients should use
/// these names to allow the client code to function correctly if the values change.

#define XRAUDIO_INPUT_QTY_MAX   (XRAUDIO_RESOURCE_ID_INPUT_INVALID)
#define XRAUDIO_OUTPUT_QTY_MAX  (XRAUDIO_RESOURCE_ID_OUTPUT_INVALID)

// Input capabilities
#define XRAUDIO_CAPS_INPUT_NONE             (0x0000)
#define XRAUDIO_CAPS_INPUT_LOCAL            (0x0001) // Source is from local microphone in 16-bit PCM format
#define XRAUDIO_CAPS_INPUT_SELECT           (0x0008) // Supports calling select on input fd
#define XRAUDIO_CAPS_INPUT_LOCAL_32_BIT     (0x0010) // Source is from local microphone in 32-bit PCM format
#define XRAUDIO_CAPS_INPUT_EOS_DETECTION    (0x0020) // Source supports EOS detection

// Output capabilities
#define XRAUDIO_CAPS_OUTPUT_NONE                    (0x0000)      // default PCM processing within xraudio
#define XRAUDIO_CAPS_OUTPUT_HAL_VOLUME_CONTROL      (0x0001)      // volume control within audio hal
#define XRAUDIO_CAPS_OUTPUT_OFFLOAD                 (0x0002)      // stream processing within audio hal
#define XRAUDIO_CAPS_OUTPUT_DIRECT_PCM              (0x0004)      // PCM stream processing within xraudio

// DSP test app support
#define XRAUDIO_DSP_TESTAPP_FIFO_WR                 "/tmp/xr_dsp_testapp_fifo_wr"   // fifo from dsp test app to audio hal
#define XRAUDIO_DSP_TESTAPP_FIFO_RD                 "/tmp/xr_dsp_testapp_fifo_rd"   // fifo from audio hal to dsp test app
#define XRAUDIO_DSP_TESTAPP_MESSAGE_SIZE_MAX        964                             // maximum dsp testapp message char size

/// @}

/// @addtogroup XRAUDIO_HAL_STRUCTS
/// @{
/// @brief Structures
/// @details The xraudio library provides structures for grouping of values.

typedef struct {
   uint8_t  input_qty;
   uint8_t  output_qty;
   uint16_t input_caps[XRAUDIO_INPUT_QTY_MAX];
   uint16_t output_caps[XRAUDIO_OUTPUT_QTY_MAX];
} xraudio_hal_capabilities;

typedef enum {
   XRAUDIO_MSG_TYPE_SESSION_REQUEST = 0,
   XRAUDIO_MSG_TYPE_SESSION_BEGIN   = 1,
   XRAUDIO_MSG_TYPE_SESSION_END     = 2,
   XRAUDIO_MSG_TYPE_INPUT_ERROR     = 3,
   XRAUDIO_MSG_TYPE_INVALID         = 4
} xraudio_hal_msg_type_t;

typedef struct {
   xraudio_hal_msg_type_t  type;
   xraudio_devices_input_t source;
} xraudio_hal_msg_header_t;

typedef struct {
   xraudio_hal_msg_header_t header;
} xraudio_hal_msg_session_request_t;

typedef struct {
   bool         valid;
   int32_t      kwd_pre;
   int32_t      kwd_begin;
   int32_t      kwd_end;
   const char * keyword_detector;
   const char * dsp_name;
   int16_t      kwd_peak_power_dBFS;
   float        dsp_kwd_gain;
   float        sensitivity;
} xraudio_hal_stream_params_t;

typedef struct {
   xraudio_hal_msg_header_t    header;
   xraudio_input_format_t      format;
   const uuid_t *              uuid;
   //Optional field for keyword detect on DSP
   xraudio_hal_stream_params_t stream_params;
} xraudio_hal_msg_session_begin_t;

typedef struct {
   xraudio_hal_msg_header_t header;
} xraudio_hal_msg_session_end_t;

typedef struct {
   xraudio_hal_msg_header_t header;
} xraudio_hal_msg_input_error_t;

typedef bool (*xraudio_hal_msg_callback_t)(void *msg);

typedef struct {
   int                  fd;
   xraudio_interval_t   interval;
   uint8_t              pcm_bit_qty;
   xraudio_power_mode_t power_mode;
   bool                 privacy_mode;
} xraudio_device_input_configuration_t;

typedef struct {
   uint32_t    samples_buffered_max;
   uint32_t    samples_lost;
   float       snr[XRAUDIO_INPUT_MAX_CHANNEL_QTY + XRAUDIO_INPUT_MAX_CHANNEL_QTY_EC_REF];
   uint8_t     vad_confidence[XRAUDIO_INPUT_MAX_CHANNEL_QTY + XRAUDIO_INPUT_MAX_CHANNEL_QTY_EC_REF];
   const char *dsp_name;
   uint16_t    mic_acoustic_overload_dbspl;
} xraudio_hal_input_stats_t;

typedef struct {
   bool    ppr_enabled;
   bool    dga_enabled;
   bool    eos_enabled;
   uint8_t input_asr_max_channel_qty;
   uint8_t input_kwd_max_channel_qty;
   float   aop_adjust;
   bool    dsp_output_override_enable;
} xraudio_hal_dsp_config_t;

/// @}

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup XRAUDIO_HAL_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio client api provides functions to be called directly by the client.

void              xraudio_hal_version(xraudio_version_info_t *version_info, uint32_t *qty);
bool              xraudio_hal_init(json_t *obj_config);
void              xraudio_hal_capabilities_get(xraudio_hal_capabilities *caps);
bool              xraudio_hal_dsp_config_get(xraudio_hal_dsp_config_t *dsp_config);
bool              xraudio_hal_available_devices_get(xraudio_devices_input_t *inputs, uint32_t input_qty_max, xraudio_devices_output_t *outputs, uint32_t output_qty_max);
xraudio_hal_obj_t xraudio_hal_open(bool debug, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_hal_msg_callback_t callback);
bool              xraudio_hal_power_mode(xraudio_hal_obj_t obj, xraudio_power_mode_t power_mode);
bool              xraudio_hal_privacy_mode(xraudio_hal_obj_t obj, bool enable);
bool              xraudio_hal_privacy_mode_get(xraudio_hal_obj_t obj, bool *enabled);
void              xraudio_hal_close(xraudio_hal_obj_t obj);
bool              xraudio_hal_thread_poll(void);

typedef void * xraudio_hal_input_obj_t;
typedef void * xraudio_hal_output_obj_t;

typedef void (*xraudio_hal_input_data_read_cb_t)(int bytes_sent, void *user_data);

xraudio_hal_input_obj_t  xraudio_hal_input_open(xraudio_hal_obj_t hal_obj, xraudio_devices_input_t device, xraudio_input_format_t format, xraudio_device_input_configuration_t *configuration);
void                     xraudio_hal_input_close(xraudio_hal_input_obj_t obj);
uint32_t                 xraudio_hal_input_buffer_size_get(xraudio_hal_input_obj_t obj);
int32_t                  xraudio_hal_input_read(xraudio_hal_input_obj_t obj, uint8_t *data, uint32_t size, xraudio_eos_event_t *eos_event);
bool                     xraudio_hal_input_mute(xraudio_hal_input_obj_t obj, xraudio_devices_input_t device, bool enable);
bool                     xraudio_hal_input_focus(xraudio_hal_input_obj_t obj, xraudio_sdf_mode_t mode);
bool                     xraudio_hal_input_stats(xraudio_hal_input_obj_t obj, xraudio_hal_input_stats_t *input_stats, bool reset);
bool                     xraudio_hal_input_detection(xraudio_hal_input_obj_t obj, uint32_t chan, bool *ignore);
bool                     xraudio_hal_input_eos_cmd(xraudio_hal_input_obj_t obj, xraudio_eos_cmd_t cmd, uint32_t chan);
bool                     xraudio_hal_input_stream_params_get(xraudio_hal_input_obj_t obj, xraudio_hal_stream_params_t *stream_params);
bool                     xraudio_hal_input_stream_start_set(xraudio_hal_input_obj_t obj, uint32_t start_sample);
bool                     xraudio_hal_input_keyword_detector_reset(xraudio_hal_input_obj_t obj);
bool                     xraudio_hal_input_test_mode(xraudio_hal_input_obj_t obj, bool enable);
bool                     xraudio_hal_input_stream_latency_set(xraudio_hal_input_obj_t obj, xraudio_stream_latency_mode_t latency_mode);

xraudio_hal_output_obj_t xraudio_hal_output_open(xraudio_hal_obj_t hal_obj, xraudio_devices_output_t device, xraudio_resource_id_output_t resource, uint8_t user_id, xraudio_output_format_t *format, xraudio_volume_step_t left, xraudio_volume_step_t right);
void                     xraudio_hal_output_close(xraudio_hal_output_obj_t obj, xraudio_devices_output_t device);
uint32_t                 xraudio_hal_output_buffer_size_get(xraudio_hal_output_obj_t obj);
int32_t                  xraudio_hal_output_write(xraudio_hal_output_obj_t obj, uint8_t *data, uint32_t size);
bool                     xraudio_hal_output_volume_set_int(xraudio_hal_output_obj_t obj, xraudio_devices_output_t device, xraudio_volume_step_t left, xraudio_volume_step_t right);
bool                     xraudio_hal_output_volume_set_float(xraudio_hal_output_obj_t obj, xraudio_devices_output_t device, float left, float right);
uint32_t                 xraudio_hal_output_latency_get(xraudio_hal_output_obj_t obj);

const char *xraudio_resource_id_output_str(xraudio_resource_id_output_t type);
const char *xraudio_resource_id_input_str(xraudio_resource_id_input_t type);
const char *xraudio_capabilities_input_str(uint16_t type);
const char *xraudio_capabilities_output_str(uint16_t type);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif
