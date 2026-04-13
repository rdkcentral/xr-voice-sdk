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
/// @defgroup XR_FFV_HAL_CALLBACKS   Callbacks
/// @defgroup XR_FFV_HAL_FUNCTIONS   Functions
///

/// @addtogroup XR_FFV_HAL_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The xr ffv hal API provides macros for some parameters which may change in the future.  Clients should use
/// these names to allow the client code to function correctly if the values change.

#include <jansson.h>
#include "xraudio.h"
#include "xraudio_version.h"
#include "xraudio_common.h"
//#include "xraudio_hal.h"
#include <xr_ffv_hal_plugin.h>

/// @}

/// @addtogroup XR_FFV_HAL_HAL_ENUMS
/// @{
/// @brief Enumerated Types
/// @details The xr ffv hal library provides enumerated types for logical groups of values.

/// @}

/// @addtogroup XR_FFV_HAL_STRUCTS
/// @{
/// @brief Structures
/// @details The xr ffv hal library provides structures for grouping of values.

/// @}

/// @addtogroup XR_FFV_HAL_CALLBACKS
/// @{
/// @brief Function callback definitions
/// @details The xr ffv hal client api provides callbacks that are used to inform the client of asynchronous events.

/// @brief xr ffv hal keyword callback
/// @details The xr ffv hal keyword detection callback is used to inform the client of a keyword detection on the KEYWORD channel.
typedef void (*xr_ffv_hal_keyword_callback_t)(void);

/// @brief xr ffv hal state changed callback
/// @details The xr ffv hal state changed callback is used to inform the client of a state transition.
typedef void (*xr_ffv_hal_state_changed_callback_t)(FFVhalState_t oldState, FFVhalState_t newState);

/// @brief xr ffv hal power mode entered callback
/// @details The xr ffv hal power mode entered callback is used to inform the client of a power mode transition.
typedef void (*xr_ffv_hal_power_mode_entered_callback_t)(FFVhalPowerMode_t powerMode);

/// @brief xr ffv hal hardeare failure callback
/// @details The xr ffv hal hardware failure callback is used to inform the client of a hardware failure.
typedef void (*xr_ffv_hal_hardware_failed_callback_t)(FFVhalFailureCode_t failureCode);

/// @brief xr ffv hal end-of-command callback
/// @details The xr ffv hal end-of-command callback is used to inform the client of the end of a voice command on the KEYWORD channel.
typedef void (*xr_ffv_hal_end_of_command_callback_t)(int32_t sampleOffset, bool timedOut);

/// @}

/// @addtogroup XR_FFV_HAL_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The xr ffv hal client api provides functions to be called directly by the client.

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

// Methods used by the client to access middleware xr ffv hal interface apis
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

// Methods used by the xr ffv hal interface to access vendor layer xr ffv hal plugin library apis
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

/// @brief Get the xr ffv hal plugin functions
/// @details Returns a pointer to the xr ffv hal plugin function table
xr_ffv_hal_plugin_func_t *xr_ffv_hal_plugin_func_get(void);
/// @brief Get the xr ffv hal plugin handle
/// @details Returns an xr ffv hal plugin library handle
void *xr_ffv_hal_plugin_handle_get(void);

// Utility functions
/// @brief Convert a status type to a string
const char *xr_ffv_hal_status_str(FFVhalApiStatus_t status);
/// @brief Convert a state type to a string
const char *xr_ffv_hal_state_str(FFVhalState_t state);
/// @brief Convert a power mode type to a string
const char *xr_ffv_hal_power_mode_str(FFVhalPowerMode_t mode);
/// @brief Convert a failure code type to a string
const char *xr_ffv_hal_failure_code_str(FFVhalFailureCode_t failure_code);
/// @brief Convert an xraudio power mode type to xr ffv hal power mode type
FFVhalPowerMode_t xraudio_power_mode_xr_ffv_hal(xraudio_power_mode_t power_mode);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* SRC_XR_FFV_HAL_XR_FFV_HAL_INTERFACE_H_ */
