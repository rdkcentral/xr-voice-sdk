/*
 * If not stated otherwise in this file or this component's license file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef SRC_XR_FFV_HAL_XR_FFV_HAL_INTERFACE_H_
#define SRC_XR_FFV_HAL_XR_FFV_HAL_INTERFACE_H_

#include <jansson.h>
#include "xraudio.h"
#include "xraudio_version.h"
#include "xraudio_common.h"
//#include "xraudio_hal.h"
#include <xr_ffv_hal_plugin.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @file xr_ffv_hal_interface.h
///
/// @defgroup XR_FFV_HAL FFV - HAL
/// @{
///
/// @defgroup XR_FFV_HAL_DEFINITIONS Constants
/// @defgroup XR_FFV_HAL_ENUMS       Enumerations
/// @defgroup XR_FFV_HAL_STRUCTS     Structures
/// @defgroup XR_FFV_HAL_FUNCTIONS   Functions
///

/// @addtogroup XRAUDIO_HAL_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xraudio library provides enumerated types for logical groups of values.

/// @}

/// @addtogroup XRAUDIO_HAL_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The xraudio API provides macros for some parameters which may change in the future.  Clients should use
/// these names to allow the client code to function correctly if the values change.

/// @}

/// @addtogroup XRAUDIO_HAL_STRUCTS
/// @{
/// @brief Structures
/// @details The xraudio library provides structures for grouping of values.

/// @}

/// @addtogroup XRAUDIO_HAL_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xraudio client api provides functions to be called directly by the client.

#if 0
/// @addtogroup XR_FFV_HAL_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xr ffv hal library provides enumerated types for logical groups of values.

typedef enum {
   XR_FFV_HAL_SDF_MODE_NONE              = 0,
   XR_FFV_HAL_SDF_MODE_KEYWORD_DETECTION = 1,
   XR_FFV_HAL_SDF_MODE_STRONGEST_SECTOR  = 2,
   XR_FFV_HAL_SDF_MODE_INVALID           = 3,
} xr_ffv_sdf_mode_t;

typedef enum {
   XR_FFV_HAL_EOS_CMD_SESSION_BEGIN     = 0,
   XR_FFV_HAL_EOS_CMD_SESSION_TERMINATE = 1,
   XR_FFV_HAL_EOS_CMD_INVALID           = 2,
} xr_ffv_eos_cmd_t;

typedef void * xr_ffv_hal_obj_t;

typedef enum {
   XR_FFV_HAL_RESOURCE_ID_INPUT_1       = 0,
   XR_FFV_HAL_RESOURCE_ID_INPUT_2       = 1,
   XR_FFV_HAL_RESOURCE_ID_INPUT_3       = 2,
   XR_FFV_HAL_RESOURCE_ID_INPUT_INVALID = 3,
} xr_ffv_hal_resource_id_input_t;

typedef enum {
   XR_FFV_HAL_RESOURCE_ID_OUTPUT_1       = 0,
   XR_FFV_HAL_RESOURCE_ID_OUTPUT_2       = 1,
   XR_FFV_HAL_RESOURCE_ID_OUTPUT_3       = 2,
   XR_FFV_HAL_RESOURCE_ID_OUTPUT_INVALID = 3,
} xr_ffv_hal_resource_id_output_t;

/// @addtogroup XR_FFV_HAL_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The xr ffv hal API provides macros for some parameters which may change in the future.  Clients should use
/// these names to allow the client code to function correctly if the values change.

#define XR_FFV_HAL_INPUT_QTY_MAX   (XR_FFV_HAL_RESOURCE_ID_INPUT_INVALID)
#define XR_FFV_HAL_OUTPUT_QTY_MAX  (XR_FFV_HAL_RESOURCE_ID_OUTPUT_INVALID)

// Input capabilities
#define XR_FFV_HAL_CAPS_INPUT_NONE             (0x0000)
#define XR_FFV_HAL_CAPS_INPUT_LOCAL            (0x0001) // Source is from local microphone in 16-bit PCM format
#define XR_FFV_HAL_CAPS_INPUT_SELECT           (0x0008) // Supports calling select on input fd
#define XR_FFV_HAL_CAPS_INPUT_LOCAL_32_BIT     (0x0010) // Source is from local microphone in 32-bit PCM format
#define XR_FFV_HAL_CAPS_INPUT_EOS_DETECTION    (0x0020) // Source supports EOS detection

// Output capabilities
#define XR_FFV_HAL_CAPS_OUTPUT_NONE                    (0x0000)      // default PCM processing within xraudio
#define XR_FFV_HAL_CAPS_OUTPUT_HAL_VOLUME_CONTROL      (0x0001)      // volume control within audio hal
#define XR_FFV_HAL_CAPS_OUTPUT_OFFLOAD                 (0x0002)      // stream processing within audio hal
#define XR_FFV_HAL_CAPS_OUTPUT_DIRECT_PCM              (0x0004)      // PCM stream processing within xraudio

// DSP test app support
#define XR_FFV_HAL_DSP_TESTAPP_FIFO_WR                 "/tmp/xr_dsp_testapp_fifo_wr"   // fifo from dsp test app to audio hal
#define XR_FFV_HAL_DSP_TESTAPP_FIFO_RD                 "/tmp/xr_dsp_testapp_fifo_rd"   // fifo from audio hal to dsp test app
#define XR_FFV_HAL_DSP_TESTAPP_MESSAGE_SIZE_MAX        964                             // maximum dsp testapp message char size

/// @addtogroup XR_FFV_HAL_HAL_STRUCTS
/// @{
/// @brief Structures
/// @details The xr ffv hal library provides structures for grouping of values.

typedef struct {
   uint8_t  input_qty;
   uint8_t  output_qty;
   uint16_t input_caps[XR_FFV_HAL_INPUT_QTY_MAX];
   uint16_t output_caps[XR_FFV_HAL_OUTPUT_QTY_MAX];
} xr_ffv_hal_capabilities;

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
} xr_ffv_hal_stream_params_t;

typedef struct {
   int                  fd;
   xraudio_interval_t   interval;
   uint8_t              pcm_bit_qty;
   xraudio_power_mode_t power_mode;
   bool                 privacy_mode;
} xr_ffv_device_input_configuration_t;

typedef struct {
   uint32_t    samples_buffered_max;
   uint32_t    samples_lost;
   float       snr[XRAUDIO_INPUT_MAX_CHANNEL_QTY + XRAUDIO_INPUT_MAX_CHANNEL_QTY_EC_REF];
   uint8_t     vad_confidence[XRAUDIO_INPUT_MAX_CHANNEL_QTY + XRAUDIO_INPUT_MAX_CHANNEL_QTY_EC_REF];
   const char *dsp_name;
   uint16_t    mic_acoustic_overload_dbspl;
} xr_ffv_hal_input_stats_t;

typedef struct {
   bool    ppr_enabled;
   bool    dga_enabled;
   bool    eos_enabled;
   uint8_t input_asr_max_channel_qty;
   uint8_t input_kwd_max_channel_qty;
   float   aop_adjust;
   bool    dsp_output_override_enable;
} xr_ffv_hal_dsp_config_t;

/// @brief xr ffv input devices
/// @details The input devices enumeration indicates all the input devices which may be supported by the ffv hal.
typedef uint32_t xr_ffv_hal_devices_input_t;

/// @brief sr ffv output devices
/// @details The output devices enumeration indicates all the speaker devices which may be supported by the ffv hal.
typedef uint32_t xr_ffv_hal_devices_output_t;

/// @addtogroup XR_FFV_HAL_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The far field voice hal client api provides functions to be called directly by the client.

typedef void              (*xr_ffv_hal_func_version_t)(xraudio_version_info_t *version_info, uint32_t *qty);
typedef bool              (*xr_ffv_hal_func_init_t)(json_t *obj_config);
typedef void              (*xr_ffv_hal_func_capabilities_get_t)(xr_ffv_hal_capabilities *caps);
typedef bool              (*xr_ffv_hal_func_dsp_config_get_t)(xr_ffv_hal_dsp_config_t *dsp_config);
typedef bool              (*xr_ffv_hal_func_available_devices_get_t)(xr_ffv_hal_devices_input_t *inputs, uint32_t input_qty_max, xr_ffv_hal_devices_output_t *outputs, uint32_t output_qty_max);
typedef xr_ffv_hal_obj_t  (*xr_ffv_hal_func_open_t)(void);
typedef bool              (*xr_ffv_hal_func_power_mode_t)(xr_ffv_hal_obj_t obj, xraudio_power_mode_t power_mode);
typedef bool              (*xr_ffv_hal_func_privacy_mode_t)(xr_ffv_hal_obj_t obj, bool enable);
typedef bool              (*xr_ffv_hal_func_privacy_mode_get_t)(xr_ffv_hal_obj_t obj, bool *enabled);
typedef void              (*xr_ffv_hal_func_close_t)(xr_ffv_hal_obj_t obj);
typedef bool              (*xr_ffv_hal_func_thread_poll_t)(void);

typedef void * xr_ffv_hal_input_obj_t;
typedef void * xr_ffv_hal_output_obj_t;

typedef void (*xr_ffv_hal_input_data_read_cb_t)(int bytes_sent, void *user_data);

typedef xr_ffv_hal_input_obj_t   (*xr_ffv_hal_func_input_open_t)(xr_ffv_hal_obj_t hal_obj, xr_ffv_hal_devices_input_t device, xraudio_input_format_t format, xr_ffv_device_input_configuration_t *configuration);
typedef void                     (*xr_ffv_hal_func_input_close_t)(xr_ffv_hal_input_obj_t obj);
typedef uint32_t                 (*xr_ffv_hal_func_input_buffer_size_get_t)(xr_ffv_hal_input_obj_t obj);
typedef int32_t                  (*xr_ffv_hal_func_input_read_t)(xr_ffv_hal_input_obj_t obj, uint8_t *data, uint32_t size, xraudio_eos_event_t *eos_event);
typedef bool                     (*xr_ffv_hal_func_input_mute_t)(xr_ffv_hal_input_obj_t obj, xr_ffv_hal_devices_input_t device, bool enable);
typedef bool                     (*xr_ffv_hal_func_input_focus_t)(xr_ffv_hal_input_obj_t obj, xr_ffv_sdf_mode_t mode);
typedef bool                     (*xr_ffv_hal_func_input_stats_t)(xr_ffv_hal_input_obj_t obj, xr_ffv_hal_input_stats_t *input_stats, bool reset);
typedef bool                     (*xr_ffv_hal_func_input_detection_t)(xr_ffv_hal_input_obj_t obj, uint32_t chan, bool *ignore);
typedef bool                     (*xr_ffv_hal_func_input_eos_cmd_t)(xr_ffv_hal_input_obj_t obj, xr_ffv_eos_cmd_t cmd, uint32_t chan);
typedef bool                     (*xr_ffv_hal_func_input_stream_params_get_t)(xr_ffv_hal_input_obj_t obj, xr_ffv_hal_stream_params_t *stream_params);
typedef bool                     (*xr_ffv_hal_func_input_stream_start_set_t)(xr_ffv_hal_input_obj_t obj, uint32_t start_sample);
typedef bool                     (*xr_ffv_hal_func_input_keyword_detector_reset_t)(xr_ffv_hal_input_obj_t obj);
typedef bool                     (*xr_ffv_hal_func_input_test_mode_t)(xr_ffv_hal_input_obj_t obj, bool enable);
typedef bool                     (*xr_ffv_hal_func_input_stream_latency_set_t)(xr_ffv_hal_input_obj_t obj, xraudio_stream_latency_mode_t latency_mode);

typedef xr_ffv_hal_output_obj_t  (*xr_ffv_hal_func_output_open_t)(xr_ffv_hal_obj_t hal_obj, xr_ffv_hal_devices_output_t device, xr_ffv_hal_resource_id_output_t resource, uint8_t user_id, xraudio_output_format_t *format, xraudio_volume_step_t left, xraudio_volume_step_t right);
typedef void                     (*xr_ffv_hal_func_output_close_t)(xr_ffv_hal_output_obj_t obj, xr_ffv_hal_devices_output_t device);
typedef uint32_t                 (*xr_ffv_hal_func_output_buffer_size_get_t)(xr_ffv_hal_output_obj_t obj);
typedef int32_t                  (*xr_ffv_hal_func_output_write_t)(xr_ffv_hal_output_obj_t obj, uint8_t *data, uint32_t size);
typedef bool                     (*xr_ffv_hal_func_output_volume_set_int_t)(xr_ffv_hal_output_obj_t obj, xr_ffv_hal_devices_output_t device, xraudio_volume_step_t left, xraudio_volume_step_t right);
typedef bool                     (*xr_ffv_hal_func_output_volume_set_float_t)(xr_ffv_hal_output_obj_t obj, xr_ffv_hal_devices_output_t device, float left, float right);
typedef uint32_t                 (*xr_ffv_hal_func_output_latency_get_t)(xr_ffv_hal_output_obj_t obj);

typedef struct {
   xr_ffv_hal_func_version_t               version;
   xr_ffv_hal_func_init_t                  init;
   xr_ffv_hal_func_capabilities_get_t      capabilities_get;
   xr_ffv_hal_func_dsp_config_get_t        dsp_config_get;
   xr_ffv_hal_func_available_devices_get_t available_devices_get;
   xr_ffv_hal_func_open_t                  open;
   xr_ffv_hal_func_power_mode_t            power_mode;
   xr_ffv_hal_func_privacy_mode_t          privacy_mode;
   xr_ffv_hal_func_privacy_mode_get_t      privacy_mode_get;
   xr_ffv_hal_func_close_t                 close;
   xr_ffv_hal_func_thread_poll_t           thread_poll;

   xr_ffv_hal_func_input_open_t                   input_open;
   xr_ffv_hal_func_input_close_t                  input_close;
   xr_ffv_hal_func_input_buffer_size_get_t        input_buffer_size_get;
   xr_ffv_hal_func_input_read_t                   input_read;
   xr_ffv_hal_func_input_mute_t                   input_mute;
   xr_ffv_hal_func_input_focus_t                  input_focus;
   xr_ffv_hal_func_input_stats_t                  input_stats;
   xr_ffv_hal_func_input_detection_t              input_detection;
   xr_ffv_hal_func_input_eos_cmd_t                input_eos_cmd;
   xr_ffv_hal_func_input_stream_params_get_t      input_stream_params_get;
   xr_ffv_hal_func_input_stream_start_set_t       input_stream_start_set;
   xr_ffv_hal_func_input_keyword_detector_reset_t input_keyword_detector_reset;
   xr_ffv_hal_func_input_test_mode_t              input_test_mode;
   xr_ffv_hal_func_input_stream_latency_set_t     input_stream_latency_set;

   xr_ffv_hal_func_output_open_t             output_open;
   xr_ffv_hal_func_output_close_t            output_close;
   xr_ffv_hal_func_output_buffer_size_get_t  output_buffer_size_get;
   xr_ffv_hal_func_output_write_t            output_write;
   xr_ffv_hal_func_output_volume_set_int_t   output_volume_set_int;
   xr_ffv_hal_func_output_volume_set_float_t output_volume_set_float;
   xr_ffv_hal_func_output_latency_get_t      output_latency_get;
} xr_ffv_hal_plugin_api_t;

typedef xr_ffv_hal_plugin_api_t *(*xr_ffv_hal_plugin_api_get_t)(void);

xr_ffv_hal_plugin_api_t *xr_ffv_hal_plugin_api_get(void);
void *xr_ffv_hal_plugin_handle_get(void);
#endif
typedef FFVhalHandle       (*FFVhal_getService_t)(void);
typedef bool               (*FFVhal_init_t)(void);
typedef void               (*FFVhal_destroy_t)(FFVhalHandle handle);
typedef FFVhalApiStatus_t  (*FFVhal_GetCapabilities_t)(FFVhalHandle handle, FFVhalCapabilities_t *pCapabilities);
typedef FFVhalApiStatus_t  (*FFVhal_getState_t)(FFVhalHandle handle, FFVhalState_t *pState);
typedef FFVhalApiStatus_t  (*FFVhal_getStatus_t)(FFVhalHandle handle, FFVhalStatus_t *pStatus);
typedef FFVhalApiStatus_t  (*FFVhal_getChannelStatus_t)(FFVhalHandle handle, const char *pChannelType, FFVhalChannelStatus_t *pChannelStatus);
typedef FFVhalApiStatus_t  (*FFVhal_getKeywordMetaData_t)(FFVhalHandle handle, unsigned char **ppMetaData);
typedef FFVhalApiStatus_t  (*FFVhal_setConfiguration_t)(FFVhalHandle handle, char *pConfiguration);
typedef FFVhalApiStatus_t  (*FFVhal_registerEventListeners_t)(FFVhalHandle handle, FFVhalOnStateChangedCb_t onStateChanged, FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode, FFVhalOnHardwareFailedCb_t onHardwareFailed);
typedef FFVhalApiStatus_t  (*FFVhal_unregisterEventListeners_t)(FFVhalHandle handle, FFVhalOnStateChangedCb_t onStateChanged, FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode, FFVhalOnHardwareFailedCb_t onHardwareFailed);
typedef FFVhalApiStatus_t  (*FFVhal_open_t)(FFVhalHandle handle, FFVhalOnKeywordDetectedCb_t onKeywordDetected, FFVhalOnEndOfCommand_t onEndOfCommand, FFVhalControlHandle *pControllerHandle);
typedef FFVhalApiStatus_t  (*FFVhal_close_t)(FFVhalHandle handle);
typedef FFVhalApiStatus_t  (*FFVhal_openChannel_t)(FFVhalControlHandle controllerHandle, const char *pChannelType, FFVhalFileDescriptor *pFileDescriptor);
typedef FFVhalApiStatus_t  (*FFVhal_closeChannel_t)(FFVhalControlHandle controllerHandle, const char *pChannelType);
typedef FFVhalApiStatus_t  (*FFVhal_setPrivacyState_t)(FFVhalControlHandle controllerHandle, bool activate);
typedef FFVhalApiStatus_t  (*FFVhal_setPowerMode_t)(FFVhalControlHandle controllerHandle,FFVhalPowerMode_t powerMode);

typedef void * xr_ffv_hal_obj_t;
typedef void * xr_ffv_hal_input_obj_t;
typedef void * xr_ffv_hal_output_obj_t;

typedef struct {
   FFVhal_getService_t               get_handle;
   FFVhal_init_t                     init;
   FFVhal_destroy_t                  destroy;
   FFVhal_GetCapabilities_t          get_capabilities;
   FFVhal_getState_t                 get_state;
   FFVhal_getStatus_t                get_status;
   FFVhal_getChannelStatus_t         get_channel_status;
   FFVhal_getKeywordMetaData_t       get_keyword_meta_data;
   FFVhal_setConfiguration_t         set_configuration;
   FFVhal_registerEventListeners_t   register_event_listeners;
   FFVhal_unregisterEventListeners_t unregister_event_listeners;
   FFVhal_open_t                     open;
   FFVhal_close_t                    close;
   FFVhal_openChannel_t              open_channel;
   FFVhal_closeChannel_t             close_channel;
   FFVhal_setPrivacyState_t          set_privacy_state;
   FFVhal_setPowerMode_t             set_power_mode;
} xr_ffv_hal_plugin_func_t;

typedef struct {
   FFVhal_getService_t               get_handle_plugin_api;
   FFVhal_destroy_t                  destroy_plugin_api;
   FFVhal_GetCapabilities_t          get_capabilities_plugin_api;
   FFVhal_getState_t                 get_state_plugin_api;
   FFVhal_getStatus_t                get_status_plugin_api;
   FFVhal_getChannelStatus_t         get_channel_status_plugin_api;
   FFVhal_getKeywordMetaData_t       get_keyword_meta_data_plugin_api;
   FFVhal_setConfiguration_t         set_configuration_plugin_api;
   FFVhal_registerEventListeners_t   register_event_listeners_plugin_api;
   FFVhal_unregisterEventListeners_t unregister_event_listeners_plugin_api;
   FFVhal_open_t                     open_plugin_api;
   FFVhal_close_t                    close_plugin_api;
   FFVhal_openChannel_t              open_channel_plugin_api;
   FFVhal_closeChannel_t             close_channel_plugin_api;
   FFVhal_setPrivacyState_t          set_privacy_state_plugin_api;
   FFVhal_setPowerMode_t             set_power_mode_plugin_api;
} xr_ffv_hal_plugin_api_t;

xr_ffv_hal_plugin_func_t *xr_ffv_hal_plugin_func_get(void);
void *xr_ffv_hal_plugin_handle_get(void);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* SRC_XR_FFV_HAL_XR_FFV_HAL_INTERFACE_H_ */
