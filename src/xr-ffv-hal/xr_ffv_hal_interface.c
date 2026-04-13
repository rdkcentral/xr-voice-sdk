/*
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License")
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
#include <dlfcn.h>
#include <xr_ffv_hal_interface.h>

#define XR_FFV_HAL_GLOBAL_IDENTIFIER  (0x97400349)
#define XR_FFV_HAL_SESSION_IDENTIFIER (0x53760293)
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRAUDIO
#define  XLOG_PRINT_LINE
#include <rdkx_logger.h>
#include <string.h>

typedef struct {
   void                      *xr_ffv_hal_plugin_handle;
   FFVhalHandle               ffv_handle;
   uint32_t                   identifier;
   const char                *channel_types[MAX_FFV_CHAN_TYPES];
   int32_t                    mic_channel_count;
   FFVhalState_t              xr_ffv_hal_state;
   xr_ffv_hal_plugin_api_t    xr_ffv_hal_plugin_api;
} xr_ffv_hal_intf_obj_t;

static xr_ffv_hal_intf_obj_t g_local_xr_ffv_hal_obj = {
   .xr_ffv_hal_plugin_handle  = NULL,
   .identifier                = XR_FFV_HAL_SESSION_IDENTIFIER,
   .channel_types             = { "NONE", "NONE" },
   .mic_channel_count         = 0,
   .xr_ffv_hal_state          = CLOSED,
};

static FFVhalHandle xr_ffv_hal_get_handle(void);
static void xr_ffv_hal_destroy(FFVhalHandle handle);
static bool xr_ffv_hal_init(void);
static FFVhalApiStatus_t xr_ffv_hal_get_capabilities(FFVhalHandle ffv_handle, FFVhalCapabilities_t *pCapabilities);
static FFVhalApiStatus_t xr_ffv_hal_get_state(FFVhalHandle handle, FFVhalState_t *pState);
static FFVhalApiStatus_t xr_ffv_hal_get_status(FFVhalHandle handle, FFVhalStatus_t *pStatus);
static FFVhalApiStatus_t xr_ffv_hal_get_channel_status(FFVhalHandle handle, const char *pChannelType, FFVhalChannelStatus_t *pChannelStatus);
static FFVhalApiStatus_t xr_ffv_hal_get_keyword_meta_data(FFVhalHandle handle, unsigned char **ppMetaData);
static FFVhalApiStatus_t xr_ffv_hal_set_configuration(FFVhalHandle handle, char *pConfiguration);
static FFVhalApiStatus_t xr_ffv_hal_register_event_listeners(FFVhalHandle handle, FFVhalOnStateChangedCb_t onStateChanged, FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode, FFVhalOnHardwareFailedCb_t onHardwareFailed);
static FFVhalApiStatus_t xr_ffv_hal_unregister_event_listeners(FFVhalHandle handle, FFVhalOnStateChangedCb_t onStateChanged, FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode, FFVhalOnHardwareFailedCb_t onHardwareFailed);
static FFVhalApiStatus_t xr_ffv_hal_open(FFVhalHandle handle, FFVhalOnKeywordDetectedCb_t onKeywordDetected, FFVhalOnEndOfCommand_t onEndOfCommand, FFVhalControlHandle *pControllerHandle);
static FFVhalApiStatus_t xr_ffv_hal_close(FFVhalHandle handle);
static FFVhalApiStatus_t xr_ffv_hal_open_channel(FFVhalControlHandle controllerHandle, const char *pChannelType, FFVhalFileDescriptor *pFileDescriptor);
static FFVhalApiStatus_t xr_ffv_hal_close_channel(FFVhalControlHandle controllerHandle, const char *pChannelType);
static FFVhalApiStatus_t xr_ffv_hal_set_privacy_state(FFVhalControlHandle controllerHandle, bool activate);
static FFVhalApiStatus_t xr_ffv_hal_set_power_mode(FFVhalControlHandle controllerHandle,FFVhalPowerMode_t powerMode);

static bool xr_ffv_hal_plugin_api_get(void);

void *xr_ffv_hal_plugin_handle_get(void) {
   XLOGD_INFO("");
   void *handle = NULL;
   const char *so_path_vd = "/opt/mount/vendor/lib/libxr-ffv-hal.so";

   if(so_path_vd != NULL) {
      handle = dlopen(so_path_vd, RTLD_NOW);
   } else {
      XLOGD_INFO("FFV HAL plugin is not present.");
      return(NULL);
   }

   if(NULL == handle) {
      XLOGD_ERROR("Failed to load FFV HAL plugin <%s>", dlerror());
      return(NULL);
   }
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_handle = handle;

   return(handle);
}

xr_ffv_hal_plugin_func_t *xr_ffv_hal_plugin_func_get(void) {
   XLOGD_INFO("");
   static xr_ffv_hal_plugin_func_t g_xr_ffv_hal_plugin_funcs = {
      .get_handle                   = xr_ffv_hal_get_handle,
      .init                         = xr_ffv_hal_init,
      .destroy                      = xr_ffv_hal_destroy,
      .get_capabilities             = xr_ffv_hal_get_capabilities,
      .get_state                    = xr_ffv_hal_get_state,
      .get_status                   = xr_ffv_hal_get_status,
      .get_channel_status           = xr_ffv_hal_get_channel_status,
      .get_keyword_meta_data        = xr_ffv_hal_get_keyword_meta_data,
      .set_configuration            = xr_ffv_hal_set_configuration,
      .register_event_listeners     = xr_ffv_hal_register_event_listeners,
      .unregister_event_listeners   = xr_ffv_hal_unregister_event_listeners,
      .open                         = xr_ffv_hal_open,
      .close                        = xr_ffv_hal_close,
      .open_channel                 = xr_ffv_hal_open_channel,
      .close_channel                = xr_ffv_hal_close_channel,
      .set_privacy_state            = xr_ffv_hal_set_privacy_state,
      .set_power_mode               = xr_ffv_hal_set_power_mode
   };

   if(xr_ffv_hal_plugin_api_get() == false) {
      return(NULL);
   }

   return &g_xr_ffv_hal_plugin_funcs;
}

bool xr_ffv_hal_init(void) {
   XLOGD_INFO("not implemented");
   return(true);
}

FFVhalHandle xr_ffv_hal_get_handle(void) {
   XLOGD_INFO("");
   FFVhalHandle ffv_handle = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_handle_plugin_api();
   if(ffv_handle == NULL) {
      XLOGD_ERROR("unable to get xr ffv hal handle");
      return(NULL);
   }
   g_local_xr_ffv_hal_obj.ffv_handle = ffv_handle;
   XLOGD_INFO("successfully created xr ffv hal handle");
   return(ffv_handle);
}

void xr_ffv_hal_destroy(FFVhalHandle ffv_handle) {
   XLOGD_INFO("");
   if(ffv_handle == NULL) {
      return;
   }
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.destroy_plugin_api(ffv_handle);
   XLOGD_INFO("ffv hal handle destroyed");
}

FFVhalApiStatus_t xr_ffv_hal_get_capabilities(FFVhalHandle ffv_handle, FFVhalCapabilities_t *pCapabilities) {
   XLOGD_INFO("");
   FFVhalApiStatus_t status = EX_NONE;

   if(ffv_handle == NULL) {
      XLOGD_ERROR("ffv handle is null");
      return(EX_NULL_POINTER);
   }

   if(pCapabilities == NULL) {
      XLOGD_ERROR("capabilities pointer is null");
      return(EX_NULL_POINTER);
   }

   status = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_capabilities_plugin_api(ffv_handle, pCapabilities);
   if(status != EX_NONE) {
      XLOGD_ERROR("failed to get capabilities. status <%s>", xr_ffv_hal_status_str(status));
      return(status);
   }

   g_local_xr_ffv_hal_obj.mic_channel_count = pCapabilities->microphoneChannelCount;
   XLOGD_INFO("input qty <%u>", g_local_xr_ffv_hal_obj.mic_channel_count);
   for(int i = 0; i < MAX_FFV_CHAN_TYPES; i++) {
      XLOGD_INFO("channelTypes[%d] <%s>", i, pCapabilities->channelTypes[i]);
      strcpy((char *)&g_local_xr_ffv_hal_obj.channel_types[i], pCapabilities->channelTypes[i]);
   }

   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_get_state(FFVhalHandle handle, FFVhalState_t *pState) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_get_status(FFVhalHandle handle, FFVhalStatus_t *pStatus) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_get_channel_status(FFVhalHandle handle, const char *pChannelType, FFVhalChannelStatus_t *pChannelStatus) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_get_keyword_meta_data(FFVhalHandle handle, unsigned char **ppMetaData) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_set_configuration(FFVhalHandle handle, char *pConfiguration) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_register_event_listeners(FFVhalHandle handle, FFVhalOnStateChangedCb_t onStateChanged, FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode, FFVhalOnHardwareFailedCb_t onHardwareFailed) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_unregister_event_listeners(FFVhalHandle handle, FFVhalOnStateChangedCb_t onStateChanged, FFVhalOnEnteredPowerModeCb_t onEnteredPowerMode, FFVhalOnHardwareFailedCb_t onHardwareFailed) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_open(FFVhalHandle ffv_handle, FFVhalOnKeywordDetectedCb_t onKeywordDetected, FFVhalOnEndOfCommand_t onEndOfCommand, FFVhalControlHandle *pControllerHandle) {
   XLOGD_INFO("");
   FFVhalApiStatus_t status = EX_NONE;

   if(ffv_handle == NULL) {
      XLOGD_ERROR("ffv handle is null");
      return(EX_NULL_POINTER);
   }

   FFVhalState_t state = UNKNOWN;
   status = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_state_plugin_api(ffv_handle, &state);
   if(status != EX_NONE) {
      XLOGD_ERROR("failed to get current state of the xr ffv hal plugin. status <%s>", xr_ffv_hal_status_str(status));
      return(status);
   }
   if(state != CLOSED) {
      XLOGD_INFO("xr ffv hal plugin not closed. state <%s>", xr_ffv_hal_state_str(state));
      return(EX_NONE);
   }
   status = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.open_plugin_api(ffv_handle, onKeywordDetected, onEndOfCommand, pControllerHandle);
   if(status != EX_NONE) {
      XLOGD_ERROR("failed to open xr ffv hal plugin. status <%s>", xr_ffv_hal_status_str(status));
      return(status);
   }

   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_close(FFVhalHandle ffv_handle) {
   XLOGD_INFO("");
   FFVhalApiStatus_t status = EX_NONE;

   if(ffv_handle == NULL) {
      XLOGD_ERROR("ffv handle is null");
      return(EX_NULL_POINTER);
   }

   status = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.close_plugin_api(ffv_handle);
   if(status != EX_NONE) {
      XLOGD_ERROR("failed to close xr ffv hal plugin. status <%s>", xr_ffv_hal_status_str(status));
      return(status);
   }

   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_open_channel(FFVhalControlHandle controllerHandle, const char *pChannelType, FFVhalFileDescriptor *pFileDescriptor) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_close_channel(FFVhalControlHandle controllerHandle, const char *pChannelType) {
   FFVhalApiStatus_t status = EX_NONE;

   XLOGD_INFO("not implemented");
   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_set_privacy_state(FFVhalControlHandle controllerHandle, bool activate) {
   XLOGD_INFO("");
   FFVhalApiStatus_t status = EX_NONE;

   if(controllerHandle == NULL) {
      XLOGD_ERROR("ffv controller handle is null");
      return(EX_NULL_POINTER);
   }

   status = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.set_privacy_state_plugin_api(controllerHandle, activate);
   if(status != EX_NONE) {
      XLOGD_ERROR("failed to set xr ffv hal plugin privacy state. status <%s>", xr_ffv_hal_status_str(status));
      return(status);
   }

   return(status);
}

FFVhalApiStatus_t xr_ffv_hal_set_power_mode(FFVhalControlHandle controllerHandle, FFVhalPowerMode_t powerMode) {
   XLOGD_INFO("");
   FFVhalApiStatus_t status = EX_NONE;

   if(controllerHandle == NULL) {
      XLOGD_ERROR("ffv controller handle is null");
      return(EX_NULL_POINTER);
   }

   status = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.set_power_mode_plugin_api(controllerHandle, powerMode);
   if(status != EX_NONE) {
      XLOGD_ERROR("failed to set xr ffv hal plugin power state. status <%s>", xr_ffv_hal_status_str(status));
      return(status);
   }

   return(status);
}

bool xr_ffv_hal_plugin_api_get(void) {
   XLOGD_INFO("");
   void *handle = g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_handle;
   if(handle == NULL) {
      XLOGD_ERROR("unable to get ffv hal plugin handle");
      return(false);
   }

   memset(&g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api, 0, sizeof(xr_ffv_hal_plugin_api_t));

   FFVhal_getService_t               FFVhal_getService               = (FFVhal_getService_t)dlsym(handle, "FFVhal_getService");
   FFVhal_destroy_t                  FFVhal_destroy                  = (FFVhal_destroy_t)dlsym(handle, "FFVhal_destroy");
   FFVhal_GetCapabilities_t          FFVhal_GetCapabilities          = (FFVhal_GetCapabilities_t)dlsym(handle, "FFVhal_GetCapabilities");
   FFVhal_getState_t                 FFVhal_getState                 = (FFVhal_getState_t)dlsym(handle, "FFVhal_getState");
   FFVhal_getStatus_t                FFVhal_getStatus                = (FFVhal_getStatus_t)dlsym(handle, "FFVhal_getStatus");
   FFVhal_getChannelStatus_t         FFVhal_getChannelStatus         = (FFVhal_getChannelStatus_t)dlsym(handle, "FFVhal_getChannelStatus");
   FFVhal_getKeywordMetaData_t       FFVhal_getKeywordMetaData       = (FFVhal_getKeywordMetaData_t)dlsym(handle, "FFVhal_getKeywordMetaData");
   FFVhal_setConfiguration_t         FFVhal_setConfiguration         = (FFVhal_setConfiguration_t)dlsym(handle, "FFVhal_setConfiguration");
   FFVhal_registerEventListeners_t   FFVhal_registerEventListeners   = (FFVhal_registerEventListeners_t)dlsym(handle, "FFVhal_registerEventListeners");
   FFVhal_unregisterEventListeners_t FFVhal_unregisterEventListeners = (FFVhal_unregisterEventListeners_t)dlsym(handle, "FFVhal_unregisterEventListeners");
   FFVhal_open_t                     FFVhal_open                     = (FFVhal_open_t)dlsym(handle, "FFVhal_open");
   FFVhal_close_t                    FFVhal_close                    = (FFVhal_close_t)dlsym(handle, "FFVhal_close");
   FFVhal_openChannel_t              FFVhal_openChannel              = (FFVhal_openChannel_t)dlsym(handle, "FFVhal_openChannel");
   FFVhal_closeChannel_t             FFVhal_closeChannel             = (FFVhal_closeChannel_t)dlsym(handle, "FFVhal_closeChannel");
   FFVhal_setPrivacyState_t          FFVhal_setPrivacyState          = (FFVhal_setPrivacyState_t)dlsym(handle, "FFVhal_setPrivacyState");
   FFVhal_setPowerMode_t             FFVhal_setPowerMode             = (FFVhal_setPowerMode_t)dlsym(handle, "FFVhal_setPowerMode");

   if((FFVhal_getService == NULL)               ||
      (FFVhal_destroy == NULL)                  ||
      (FFVhal_GetCapabilities == NULL)          ||
      (FFVhal_getState == NULL)                 ||
      (FFVhal_getStatus == NULL)                ||
      (FFVhal_getChannelStatus == NULL)         ||
      (FFVhal_getKeywordMetaData == NULL)       ||
      (FFVhal_setConfiguration == NULL)         ||
      (FFVhal_registerEventListeners == NULL)   ||
      (FFVhal_unregisterEventListeners == NULL) ||
      (FFVhal_open == NULL)                     ||
      (FFVhal_close == NULL)                    ||
      (FFVhal_openChannel == NULL)              ||
      (FFVhal_closeChannel == NULL)             ||
      (FFVhal_setPrivacyState == NULL)          ||
      (FFVhal_setPowerMode == NULL)) {
      XLOGD_ERROR("XR FFV HAL plugin API incomplete");
      memset(&g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api, 0, sizeof(xr_ffv_hal_plugin_api_t));
      return(false);
   }
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_handle_plugin_api = FFVhal_getService;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.destroy_plugin_api = FFVhal_destroy;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_capabilities_plugin_api = FFVhal_GetCapabilities;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_state_plugin_api = FFVhal_getState;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_status_plugin_api = FFVhal_getStatus;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_channel_status_plugin_api = FFVhal_getChannelStatus;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.get_keyword_meta_data_plugin_api = FFVhal_getKeywordMetaData;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.set_configuration_plugin_api = FFVhal_setConfiguration;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.register_event_listeners_plugin_api = FFVhal_registerEventListeners;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.unregister_event_listeners_plugin_api = FFVhal_unregisterEventListeners;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.open_plugin_api = FFVhal_open;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.close_plugin_api = FFVhal_close;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.open_channel_plugin_api = FFVhal_openChannel;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.close_channel_plugin_api = FFVhal_closeChannel;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.set_privacy_state_plugin_api = FFVhal_setPrivacyState;
   g_local_xr_ffv_hal_obj.xr_ffv_hal_plugin_api.set_power_mode_plugin_api = FFVhal_setPowerMode;
   return(true);
}

const char *xr_ffv_hal_status_str(FFVhalApiStatus_t status) {
   switch(status) {
      case EX_NONE:                  return("OK");
      case EX_SECURITY:              return("SECURITY");
      case EX_BAD_PARCELABLE:        return("BAD_PARCELABLE");
      case EX_ILLEGAL_ARGUMENT:      return("ILLEGAL_ARGUMENT");
      case EX_NULL_POINTER:          return("NULL_POINTER");
      case EX_ILLEGAL_STATE:         return("ILLEGAL_STATE");
      case EX_NETWORK_MAIN_THREAD:   return("NETWORK_MAIN_THREAD");
      case EX_UNSUPPORTED_OPERATION: return("UNSUPPORTED_OPERATION");
      case EX_SERVICE_SPECIFIC:      return("SERVICE_SPECIFIC");
      case EX_HAS_REPLY_HEADER:      return("HAS_REPLY_HEADER");
      case EX_TRANSACTION_FAILED:    return("TRANSACTION_FAILED");
   }
   return("UNKNOWN");
}

const char *xr_ffv_hal_state_str(FFVhalState_t state) {
   switch(state) {
      case UNKNOWN:  return("UNKNOWN");
      case CLOSED:   return("CLOSED");
      case OPENING:  return("OPENING");
      case READY:    return("READY");
      case STARTING: return("STARTING");
      case STARTED:  return("STARTED");
      case FLUSHING: return("FLUSHING");
      case STOPPING: return("STOPPING");
      case CLOSING:  return("CLOSING");
   }
   return("UNKNOWN");
}

const char *xr_ffv_hal_power_mode_str(FFVhalPowerMode_t power_mode) {
   switch(power_mode) {
      case NONE:       return("NONE");
      case FULL_POWER: return("FULL_POWER");
      case STANDBY:    return("STANDBY");
      case DEEP_SLEEP: return("DEEP_SLEEP");
   }
   return("UNKNOWN");
}

const char *xr_ffv_hal_failure_code_str(FFVhalFailureCode_t failure_code) {
   switch(failure_code) {
      case SUB_COMPONENT_FAILURE: return("SUB_COMPONENT_FAILURE");
      case IO_FAILURE:            return("IO_FAILURE");
   }
   return("UNKNOWN");
}

FFVhalPowerMode_t xraudio_power_mode_xr_ffv_hal(xraudio_power_mode_t power_mode) {
   switch(power_mode) {
   case XRAUDIO_POWER_MODE_FULL:    return(FULL_POWER);
   case XRAUDIO_POWER_MODE_LOW:     return(STANDBY);
   case XRAUDIO_POWER_MODE_SLEEP:   return(DEEP_SLEEP);
   case XRAUDIO_POWER_MODE_INVALID: return(NONE);
   }
   return(NONE);
}
