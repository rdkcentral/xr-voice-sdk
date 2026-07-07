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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <xr_voice_sdk.h>
#include <vsdk_version.h>
#include <vsdk_private.h>
#ifndef PJT_OLD_HAL
#include <unistd.h>
#include <errno.h>
#include "xr_ffv_hal_interface.h"
#endif
#define VSDK_VENDOR_OPTIONS_FILE  "/etc/vendor/input/vsdk_options.json"

typedef struct {
   void *handle_ffv_hal;
   void *handle_ffv_kwd;
   void *handle_ffv_alg;
   void *handle_ffv_sdf;
   void *handle_ffv_ovc;
   void *handle_ffv_ppr;
} vsdk_ffv_plugin_handles_t;

typedef struct {
   bool                      initialized;
   bool                      curtail_xraudio;
   bool                    xraudio_allow_input_failure;
   vsdk_ffv_plugin_handles_t ffv_plugins;
   bool                      hal_in_enabled;
   bool                      hal_out_enabled;
   xraudio_hal_plugin_api_t *hal_plugin;
   xraudio_kwd_plugin_api_t *kwd_plugin;
   xraudio_eos_plugin_api_t *eos_plugin;
   xraudio_dga_plugin_api_t *dga_plugin;
   #ifndef PJT_OLD_HAL   
   xr_ffv_hal_plugin_func_t *ffv_hal_interface_plugin;
   #endif
   xraudio_sdf_plugin_api_t *sdf_plugin;
   xraudio_ovc_plugin_api_t *ovc_plugin;
   xraudio_ppr_plugin_api_t *ppr_plugin;
   vsdk_thread_poll_func_t   func;
   void *                    data;
} vsdk_global_t;

static vsdk_global_t g_vsdk;

static void  vsdk_thread_response(void);
static bool  vsdk_file_exists(const char *filename);
static void  vsdk_parse_options(bool *curtail_xlog, bool *curtail_xraudio, bool *xraudio_allow_input_failure);
static bool  vsdk_load_plugin_ffv(vsdk_ffv_plugin_handles_t *handles);
static void *vsdk_load_plugin_ffv_hal(bool *out_enabled);
#ifdef PJT_OLD_HAL
static void *vsdk_load_plugin_ffv_kwd(void);
static void *vsdk_load_plugin_ffv_alg(void **handle_ppr);
#endif
static void *vsdk_load_plugin_ffv_sdf(void);
static void *vsdk_load_plugin_ffv_ovc(void);

#ifndef PJT_OLD_HAL
typedef xr_ffv_hal_plugin_func_t *(*xr_ffv_hal_plugin_func_get_t)(void);

#define VSDK_FFV_HAL_OBJ_MAGIC   (0x7668646f) // "vhdo"
#define VSDK_FFV_INPUT_OBJ_MAGIC (0x7668696f) // "vhio"

typedef struct {
   uint32_t                    magic;
   xr_ffv_hal_plugin_func_t   *ffv_api;
   FFVhalHandle                ffv_handle;
   FFVhalControlHandle         ffv_controller;
   xraudio_hal_msg_callback_t  callback;
   xraudio_power_mode_t        power_mode;
   bool                        privacy_mode;
   xraudio_devices_input_t     source;
} vsdk_ffv_hal_obj_t;

typedef struct {
   uint32_t                 magic;
   vsdk_ffv_hal_obj_t      *hal_obj;
   FFVhalFileDescriptor     fd;
   const char              *channel_type;
   xraudio_devices_input_t  source;
} vsdk_ffv_input_obj_t;

static vsdk_ffv_hal_obj_t *g_vsdk_ffv_hal_active_obj = NULL;

static FFVhalPowerMode_t vsdk_ffv_power_mode_from_xraudio(xraudio_power_mode_t power_mode) {
   switch(power_mode) {
      case XRAUDIO_POWER_MODE_FULL:  return(FULL_POWER);
      case XRAUDIO_POWER_MODE_LOW:   return(STANDBY);
      case XRAUDIO_POWER_MODE_SLEEP: return(DEEP_SLEEP);
      default:                       return(NONE);
   }
}

//This function decides whether we're requesting keyword or microphone channel
static bool vsdk_ffv_channel_is_keyword(xraudio_input_format_t format) {
   XLOGD_INFO("format.container=%d, format.encoding.type=%d, format.sample_rate=%d, format.sample_size=%d, format.channel_qty=%d", format.container, format.encoding.type, format.sample_rate, format.sample_size, format.channel_qty);
   //This is not a good test but will maybe do the job here
   if(format.sample_size == 2) {
      XLOGD_INFO("sample_size is %d, not a keyword channel", format.sample_size);
      return(false);
   }
   return(true);
}

static bool vsdk_ffv_source_is_local(xraudio_devices_input_t source) {
   return((XRAUDIO_DEVICE_INPUT_LOCAL_GET(source) != XRAUDIO_DEVICE_INPUT_NONE) || (source == XRAUDIO_DEVICE_INPUT_FF));
}

static void vsdk_ffv_emit_session_request(vsdk_ffv_hal_obj_t *obj) {
   if((obj == NULL) || (obj->callback == NULL)) {
      return;
   }

   xraudio_hal_msg_session_request_t msg;
   memset(&msg, 0, sizeof(msg));
   msg.header.type   = XRAUDIO_MSG_TYPE_SESSION_REQUEST;
   msg.header.source = obj->source;
   obj->callback(&msg);
}

static void vsdk_ffv_emit_session_begin(vsdk_ffv_hal_obj_t *obj) {
   if((obj == NULL) || (obj->callback == NULL)) {
      return;
   }

   xraudio_hal_msg_session_begin_t msg;
   memset(&msg, 0, sizeof(msg));
   msg.header.type            = XRAUDIO_MSG_TYPE_SESSION_BEGIN;
   msg.header.source          = obj->source;
   msg.format.container       = XRAUDIO_CONTAINER_NONE;
   msg.format.encoding.type   = XRAUDIO_ENCODING_PCM;
   msg.format.sample_rate     = 16000;
   msg.format.sample_size     = 2;
   msg.format.channel_qty     = 1;
   msg.stream_params.valid    = true;
   msg.stream_params.kwd_pre  = 0;
   msg.stream_params.kwd_begin= 0;
   msg.stream_params.kwd_end  = 0;
   msg.stream_params.keyword_detector = "ffv-hal";
   msg.stream_params.dsp_name = "ffv-hal";
   msg.stream_params.sensitivity = 0.0f;

   obj->callback(&msg);
}

static void vsdk_ffv_emit_session_end(vsdk_ffv_hal_obj_t *obj) {
   if((obj == NULL) || (obj->callback == NULL)) {
      return;
   }

   xraudio_hal_msg_session_end_t msg;
   memset(&msg, 0, sizeof(msg));
   msg.header.type   = XRAUDIO_MSG_TYPE_SESSION_END;
   msg.header.source = obj->source;
   obj->callback(&msg);
}

static void vsdk_ffv_on_state_changed_cb(FFVhalState_t oldState, FFVhalState_t newState) {
   (void)oldState;
   (void)newState;
   XLOGD_INFO("FFV HAL state changed from %d to %d", oldState, newState);
}

static void vsdk_ffv_on_entered_power_mode_cb(FFVhalPowerMode_t powerMode) {
   (void)powerMode;
   XLOGD_INFO("FFV HAL entered power mode %d", powerMode);
}

static const char *vsdk_ffv_failure_code_str(FFVhalFailureCode_t failureCode) {
   switch(failureCode) {
      case SUB_COMPONENT_FAILURE: return("SUB_COMPONENT_FAILURE");
      case IO_FAILURE:            return("IO_FAILURE");
      default:                    return("UNKNOWN");
   }
}

static void vsdk_ffv_on_hardware_failed_cb(FFVhalFailureCode_t failureCode) {
   XLOGD_ERROR("FFV HAL hardware failure <%s> (%d)", vsdk_ffv_failure_code_str(failureCode), failureCode);
   if((g_vsdk_ffv_hal_active_obj == NULL) || (g_vsdk_ffv_hal_active_obj->callback == NULL)) {
      return;
   }

   // If a session is active, force an end before reporting the input error.
   vsdk_ffv_emit_session_end(g_vsdk_ffv_hal_active_obj);

   xraudio_hal_msg_input_error_t msg;
   memset(&msg, 0, sizeof(msg));
   msg.header.type   = XRAUDIO_MSG_TYPE_INPUT_ERROR;
   msg.header.source = g_vsdk_ffv_hal_active_obj->source;
   g_vsdk_ffv_hal_active_obj->callback(&msg);
}

static void vsdk_ffv_on_keyword_detected_cb(void) {
   XLOGD_INFO("");
   if(g_vsdk_ffv_hal_active_obj == NULL) {
      XLOGD_ERROR("FFV HAL keyword detected but no active HAL object");
      return;
   }
   vsdk_ffv_emit_session_request(g_vsdk_ffv_hal_active_obj);
   vsdk_ffv_emit_session_begin(g_vsdk_ffv_hal_active_obj);
}

static void vsdk_ffv_on_end_of_command_cb(int32_t sampleOffset, bool timedOut) {
   (void)sampleOffset;
   (void)timedOut;
   XLOGD_INFO("end of command detected at sample offset %d, timed out=%d", sampleOffset, timedOut);
   if(g_vsdk_ffv_hal_active_obj == NULL) {
      XLOGD_ERROR("FFV HAL end of command detected but no active HAL object");
      return;
   }
   vsdk_ffv_emit_session_end(g_vsdk_ffv_hal_active_obj);
}

static void vsdk_ffv_adapter_version(xraudio_version_info_t *version_info, uint32_t *qty) {
   if((version_info == NULL) || (qty == NULL) || (*qty == 0)) {
      XLOGD_ERROR("Invalid parameters to vsdk_ffv_adapter_version");
      return;
   }
   XLOGD_INFO("vsdk_ffv_adapter_version called, returning version info");
   version_info[0].name      = "ffv-hal-interface-adapter";
   version_info[0].version   = "1.0";
   version_info[0].branch    = "main";
   version_info[0].commit_id = "n/a";
   *qty = 1;
}

static bool vsdk_ffv_adapter_init(json_t *obj_config) {
   (void)obj_config;
   XLOGD_INFO("xffv_hal_interface_plugin is %p", g_vsdk.ffv_hal_interface_plugin);
   if(g_vsdk.ffv_hal_interface_plugin == NULL) {
      XLOGD_ERROR("FFV HAL interface plugin not loaded");
      return(false);
   }
   return(true);
}

static void vsdk_ffv_adapter_capabilities_get(xraudio_hal_capabilities *caps) {
   if(caps == NULL) {
      XLOGD_ERROR("Invalid parameters");
      return;
   }
   memset(caps, 0, sizeof(*caps));
   XLOGD_INFO("xffv_hal_interface_plugin is %p", g_vsdk.ffv_hal_interface_plugin);
   if(g_vsdk.ffv_plugins.handle_ffv_hal == NULL) {
      return;
   }

   //This is here because xraudio wants to check capabilities before opening and for the moment we'll just open and close to get caps
   xr_ffv_hal_plugin_func_t *ffv_api = g_vsdk.ffv_hal_interface_plugin;
   if((ffv_api == NULL) || (ffv_api->get_handle == NULL) || (ffv_api->get_capabilities == NULL) || (ffv_api->destroy == NULL)) {
      return;
   }

   FFVhalHandle handle = ffv_api->get_handle();
   if(handle == NULL) {
      XLOGD_ERROR("FFV HAL handle is NULL");
      return;
   }

   FFVhalCapabilities_t ffv_caps;
   memset(&ffv_caps, 0, sizeof(ffv_caps));
   FFVhalApiStatus_t status = ffv_api->get_capabilities(handle, &ffv_caps);
   if(status == EX_NONE) {
      caps->input_qty      = 1;
      caps->input_caps[0]  = XRAUDIO_CAPS_INPUT_LOCAL | XRAUDIO_CAPS_INPUT_SELECT;
      if(ffv_caps.channelTypes[0] != NULL || ffv_caps.channelTypes[1] != NULL) {
         caps->input_caps[0] |= XRAUDIO_CAPS_INPUT_EOS_DETECTION;
      }
      if(ffv_caps.microphoneChannelCount > 1) {
         caps->input_caps[0] |= XRAUDIO_CAPS_INPUT_LOCAL_32_BIT;
      }
      caps->output_qty = 0;
   }

   /*
   //Just close the handle we'll open it back up later for reading
   XLOGD_WARN("destroying FFV HAL handle %p", handle);
   ffv_api->destroy(handle);
   */
}

static bool vsdk_ffv_adapter_dsp_config_get(xraudio_hal_dsp_config_t *dsp_config) {
   if(dsp_config == NULL) {
      XLOGD_ERROR("Invalid parameters");
      return(false);
   }
   XLOGD_INFO("");
//Not sure we need this at all with new HAL but for now we'll just return some defaults
   memset(dsp_config, 0, sizeof(*dsp_config));
   dsp_config->ppr_enabled               = (g_vsdk.ppr_plugin != NULL);
   dsp_config->dga_enabled               = false;
   dsp_config->eos_enabled               = true;
   dsp_config->input_asr_max_channel_qty = XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY;
   dsp_config->input_kwd_max_channel_qty = XRAUDIO_INPUT_KWD_MAX_CHANNEL_QTY;
   dsp_config->aop_adjust                = 0.0f;
   dsp_config->dsp_output_override_enable= false;
   return(true);
}

static bool vsdk_ffv_adapter_available_devices_get(xraudio_devices_input_t *inputs, uint32_t input_qty_max, xraudio_devices_output_t *outputs, uint32_t output_qty_max) {
   //if((inputs == NULL) || (input_qty_max < XRAUDIO_INPUT_MAX_DEVICE_QTY) || (outputs == NULL) || (output_qty_max < XRAUDIO_OUTPUT_MAX_DEVICE_QTY)) {
   if((inputs == NULL) || (input_qty_max < 1) || (outputs == NULL) || (output_qty_max < 1)) {
      XLOGD_ERROR("Invalid parameters");
      return(false);
   }

   memset(inputs, 0, sizeof(*inputs) * input_qty_max);
   memset(outputs, 0, sizeof(*outputs) * output_qty_max);

   inputs[0] = XRAUDIO_DEVICE_INPUT_SINGLE;
   outputs[0] = XRAUDIO_DEVICE_OUTPUT_NONE;
   return(true);
}

static xraudio_hal_obj_t vsdk_ffv_adapter_open(bool debug, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_hal_msg_callback_t callback) {
   (void)debug;

   xr_ffv_hal_plugin_func_t *ffv_api = g_vsdk.ffv_hal_interface_plugin;

   if((ffv_api == NULL) ||
      (ffv_api->get_handle == NULL) ||
      (ffv_api->register_event_listeners == NULL) ||
      (ffv_api->open == NULL) ||
      (ffv_api->close == NULL) ||
      (ffv_api->unregister_event_listeners == NULL) ||
      (ffv_api->destroy == NULL)) {
      XLOGD_ERROR("FFV HAL interface API incomplete");
      return(NULL);
   }

   vsdk_ffv_hal_obj_t *obj = (vsdk_ffv_hal_obj_t *)calloc(1, sizeof(*obj));
   if(obj == NULL) {
      return(NULL);
   }

   obj->magic        = VSDK_FFV_HAL_OBJ_MAGIC;
   obj->ffv_api      = ffv_api;
   obj->callback     = callback;
   obj->power_mode   = power_mode;
   obj->privacy_mode = privacy_mode;
   obj->source       = XRAUDIO_DEVICE_INPUT_SINGLE;

   if(obj->ffv_handle == NULL) {
         XLOGD_INFO("There is no ffv_handle so get one");
         obj->ffv_handle = ffv_api->get_handle();
         if(obj->ffv_handle == NULL) {
            XLOGD_ERROR("FFVhal_getService failed");
            free(obj);
            return(NULL);
         }
   }

   XLOGD_WARN("Registering state %p power mode %p hardware failed %p callbacks", vsdk_ffv_on_state_changed_cb, vsdk_ffv_on_entered_power_mode_cb, vsdk_ffv_on_hardware_failed_cb);
   if(ffv_api->register_event_listeners(obj->ffv_handle,
                                        vsdk_ffv_on_state_changed_cb,
                                        vsdk_ffv_on_entered_power_mode_cb,
                                        vsdk_ffv_on_hardware_failed_cb) != EX_NONE) {
      XLOGD_ERROR("FFVhal_registerEventListeners failed");
      ffv_api->destroy(obj->ffv_handle);
      free(obj);
      return(NULL);
   }

   XLOGD_INFO("Opening FFV HAL adapter with power mode <%d> privacy mode <%d>", power_mode, privacy_mode);
   if(ffv_api->open(obj->ffv_handle, vsdk_ffv_on_keyword_detected_cb, vsdk_ffv_on_end_of_command_cb, &obj->ffv_controller) != EX_NONE) {
      XLOGD_ERROR("FFVhal_open failed");
      ffv_api->unregister_event_listeners(obj->ffv_handle,
                                          vsdk_ffv_on_state_changed_cb,
                                          vsdk_ffv_on_entered_power_mode_cb,
                                          vsdk_ffv_on_hardware_failed_cb);
      ffv_api->destroy(obj->ffv_handle);
      free(obj);
      return(NULL);
   }

   if(ffv_api->set_power_mode(obj->ffv_controller, vsdk_ffv_power_mode_from_xraudio(power_mode)) != EX_NONE) {
      XLOGD_WARN("FFVhal_setPowerMode failed");
   }
   if(ffv_api->set_privacy_state(obj->ffv_controller, privacy_mode) != EX_NONE) {
      XLOGD_WARN("FFVhal_setPrivacyState failed");
   }

   g_vsdk_ffv_hal_active_obj = obj;
   XLOGD_INFO("FFV HAL adapter opened successfully");
   XLOGD_INFO("source is 0x%x", obj->source);
   return((xraudio_hal_obj_t)obj);
}

static bool vsdk_ffv_adapter_power_mode(xraudio_hal_obj_t hal_obj, xraudio_power_mode_t power_mode) {
   vsdk_ffv_hal_obj_t *obj = (vsdk_ffv_hal_obj_t *)hal_obj;
   XLOGD_INFO("power mode <%s>", xraudio_power_mode_str(power_mode));
   if((obj == NULL) || (obj->magic != VSDK_FFV_HAL_OBJ_MAGIC) || (obj->ffv_api == NULL) || (obj->ffv_api->set_power_mode == NULL)) {
      return(false);
   }
   if(obj->ffv_api->set_power_mode(obj->ffv_controller, vsdk_ffv_power_mode_from_xraudio(power_mode)) != EX_NONE) {
      return(false);
   }
   obj->power_mode = power_mode;
   return(true);
}

static bool vsdk_ffv_adapter_privacy_mode(xraudio_hal_obj_t hal_obj, bool enable) {
   vsdk_ffv_hal_obj_t *obj = (vsdk_ffv_hal_obj_t *)hal_obj;
   XLOGD_INFO("enable <%d>", enable);
   if((obj == NULL) || (obj->magic != VSDK_FFV_HAL_OBJ_MAGIC) || (obj->ffv_api == NULL) || (obj->ffv_api->set_privacy_state == NULL)) {
      return(false);
   }
   if(obj->ffv_api->set_privacy_state(obj->ffv_controller, enable) != EX_NONE) {
      return(false);
   }
   obj->privacy_mode = enable;
   return(true);
}

static bool vsdk_ffv_adapter_privacy_mode_get(xraudio_hal_obj_t hal_obj, bool *enabled) {
   vsdk_ffv_hal_obj_t *obj = (vsdk_ffv_hal_obj_t *)hal_obj;
   if((obj == NULL) || (obj->magic != VSDK_FFV_HAL_OBJ_MAGIC) || (enabled == NULL)) {
      XLOGD_ERROR("invalid parameters (obj %p, magic 0x%x, enabled %p)", obj, (obj != NULL) ? obj->magic : 0, enabled);
      return(false);
   }

   FFVhalStatus_t status = {0};
   obj->ffv_api->get_status(obj->ffv_handle, &status);
   *enabled = status.privacyStateActive;

   return(true);
}

static void vsdk_ffv_adapter_close(xraudio_hal_obj_t hal_obj) {
   vsdk_ffv_hal_obj_t *obj = (vsdk_ffv_hal_obj_t *)hal_obj;
   XLOGD_INFO("");
   if((obj == NULL) || (obj->magic != VSDK_FFV_HAL_OBJ_MAGIC) || (obj->ffv_api == NULL)) {
      XLOGD_ERROR("invalid parameters (obj %p, magic 0x%x)", obj, (obj != NULL) ? obj->magic : 0);
      return;
   }

   if(g_vsdk_ffv_hal_active_obj == obj) {
      g_vsdk_ffv_hal_active_obj = NULL;
   }

   if(obj->ffv_handle == NULL) {
      obj->magic = 0;
      free(obj);
      return;
   }

   if(obj->ffv_api->close(obj->ffv_handle) != EX_NONE) {
      XLOGD_WARN("FFVhal_close failed");
   }

   if(obj->ffv_api->unregister_event_listeners(obj->ffv_handle,
                                               vsdk_ffv_on_state_changed_cb,
                                               vsdk_ffv_on_entered_power_mode_cb,
                                               vsdk_ffv_on_hardware_failed_cb) != EX_NONE) {
      XLOGD_WARN("FFVhal_unregisterEventListeners failed");
   }

   obj->ffv_api->destroy(obj->ffv_handle);
   obj->ffv_handle = NULL;

   obj->magic = 0;
   free(obj);
   XLOGD_INFO("FFV HAL adapter closed");
}

static bool vsdk_ffv_adapter_thread_poll(void) {
   return(true);
}

static xraudio_hal_input_obj_t vsdk_ffv_adapter_input_open(xraudio_hal_obj_t hal_obj, xraudio_devices_input_t device, xraudio_input_format_t format, xraudio_device_input_configuration_t *configuration) {
   vsdk_ffv_hal_obj_t *obj = NULL;
   vsdk_ffv_input_obj_t *existing = (vsdk_ffv_input_obj_t *)hal_obj;
   if((existing != NULL) && (existing->magic == VSDK_FFV_INPUT_OBJ_MAGIC)) {
      obj = existing->hal_obj;
      configuration->fd = existing->fd;
      XLOGD_INFO("called with existing input object, reusing HAL object %p and fd %d", obj, configuration->fd);
      return((xraudio_hal_input_obj_t)existing);
   } else {
      obj = (vsdk_ffv_hal_obj_t *)hal_obj;
   }

   if((obj == NULL) || (obj->magic != VSDK_FFV_HAL_OBJ_MAGIC) || (obj->ffv_api == NULL) || (obj->ffv_api->open_channel == NULL)) {
      return(NULL);
   }
   if(!vsdk_ffv_source_is_local(device)) {
      return(NULL);
   }

   const char *channel = vsdk_ffv_channel_is_keyword(format) ? "KEYWORD" : "MICROPHONES";
   FFVhalFileDescriptor fd = -1;
   XLOGD_INFO("channel %s, device 0x%x", channel, device);
   if(obj->ffv_api->open_channel(obj->ffv_controller, channel, &fd) != EX_NONE) {
      XLOGD_ERROR("FFVhal_open_channel failed for channel %s", channel);
      return(NULL);
   }

   vsdk_ffv_input_obj_t *input = (vsdk_ffv_input_obj_t *)calloc(1, sizeof(*input));
   if(input == NULL) {
      (void)obj->ffv_api->close_channel(obj->ffv_controller, channel);
      return(NULL);
   }

   input->magic       = VSDK_FFV_INPUT_OBJ_MAGIC;
   input->hal_obj     = obj;
   input->fd          = fd;
   input->channel_type= channel;
   input->source      = device;
   obj->source        = device;
   configuration->fd = fd;
   XLOGD_INFO("channel %s, fd %d", channel, fd);

   return((xraudio_hal_input_obj_t)input);
}

static void vsdk_ffv_adapter_input_close(xraudio_hal_input_obj_t input_obj) {
   vsdk_ffv_input_obj_t *obj = (vsdk_ffv_input_obj_t *)input_obj;
   if((obj == NULL) || (obj->magic != VSDK_FFV_INPUT_OBJ_MAGIC) || (obj->hal_obj == NULL)) {
      XLOGD_ERROR("Invalid input object");
      return;
   }

   if((obj->hal_obj->ffv_api != NULL) && (obj->hal_obj->ffv_api->close_channel != NULL) && (obj->channel_type != NULL)) {
      (void)obj->hal_obj->ffv_api->close_channel(obj->hal_obj->ffv_controller, obj->channel_type);
   }
   if(obj->fd >= 0) {
      (void)close(obj->fd);
   }

   obj->magic = 0;
   free(obj);
}

static uint32_t vsdk_ffv_adapter_input_buffer_size_get(xraudio_hal_input_obj_t obj) {
   (void)obj;
   return(4096);
}

static int32_t vsdk_ffv_adapter_input_read(xraudio_hal_input_obj_t input_obj, uint8_t *data, uint32_t size, xraudio_eos_event_t *eos_event) {
   vsdk_ffv_input_obj_t *obj = (vsdk_ffv_input_obj_t *)input_obj;
   if((obj == NULL) || (obj->magic != VSDK_FFV_INPUT_OBJ_MAGIC) || (data == NULL) || (size == 0) || (obj->fd < 0)) {
      return(-1);
   }

   if(eos_event != NULL) {
      memset(eos_event, 0, sizeof(*eos_event));
   }

   ssize_t rc = read(obj->fd, data, size);
   if(rc < 0) {
      if((errno == EAGAIN) || (errno == EINTR)) {
         return(0);
      }
      return(-1);
   }
   return((int32_t)rc);
}

static bool vsdk_ffv_adapter_input_mute(xraudio_hal_input_obj_t obj, xraudio_devices_input_t device, bool enable) {
   (void)obj;
   (void)device;
   (void)enable;
   return(true);
}

static bool vsdk_ffv_adapter_input_focus(xraudio_hal_input_obj_t obj, xraudio_sdf_mode_t mode) {
   (void)obj;
   (void)mode;
   return(true);
}

static bool vsdk_ffv_adapter_input_stats(xraudio_hal_input_obj_t obj, xraudio_hal_input_stats_t *input_stats, bool reset) {
   (void)obj;
   (void)reset;
   if(input_stats != NULL) {
      memset(input_stats, 0, sizeof(*input_stats));
      input_stats->dsp_name = "ffv-hal";
   }
   return(true);
}

static bool vsdk_ffv_adapter_input_detection(xraudio_hal_input_obj_t obj, uint32_t chan, bool *ignore) {
   (void)obj;
   (void)chan;
   if(ignore != NULL) {
      *ignore = false;
   }
   return(true);
}

static bool vsdk_ffv_adapter_input_eos_cmd(xraudio_hal_input_obj_t obj, xraudio_eos_cmd_t cmd, uint32_t chan) {
   (void)obj;
   (void)cmd;
   (void)chan;
   return(true);
}

static bool vsdk_ffv_adapter_input_stream_params_get(xraudio_hal_input_obj_t obj, xraudio_hal_stream_params_t *stream_params) {
   (void)obj;
   if(stream_params == NULL) {
      return(false);
   }
   memset(stream_params, 0, sizeof(*stream_params));
   stream_params->valid = false;
   return(true);
}

static bool vsdk_ffv_adapter_input_stream_start_set(xraudio_hal_input_obj_t obj, uint32_t start_sample) {
   (void)obj;
   (void)start_sample;
   return(true);
}

static bool vsdk_ffv_adapter_input_keyword_detector_reset(xraudio_hal_input_obj_t obj) {
   (void)obj;
   return(true);
}

static bool vsdk_ffv_adapter_input_test_mode(xraudio_hal_input_obj_t obj, bool enable) {
   (void)obj;
   (void)enable;
   return(true);
}

static bool vsdk_ffv_adapter_input_stream_latency_set(xraudio_hal_input_obj_t obj, xraudio_stream_latency_mode_t latency_mode) {
   (void)obj;
   (void)latency_mode;
   return(true);
}

static xraudio_hal_plugin_api_t g_vsdk_ffv_adapter_api = {
   .version                      = vsdk_ffv_adapter_version,
   .init                         = vsdk_ffv_adapter_init,
   .capabilities_get             = vsdk_ffv_adapter_capabilities_get,
   .dsp_config_get               = vsdk_ffv_adapter_dsp_config_get,
   .available_devices_get        = vsdk_ffv_adapter_available_devices_get,
   .open                         = vsdk_ffv_adapter_open,
   .power_mode                   = vsdk_ffv_adapter_power_mode,
   .privacy_mode                 = vsdk_ffv_adapter_privacy_mode,
   .privacy_mode_get             = vsdk_ffv_adapter_privacy_mode_get,
   .close                        = vsdk_ffv_adapter_close,
   .thread_poll                  = vsdk_ffv_adapter_thread_poll,
   .input_open                   = vsdk_ffv_adapter_input_open,
   .input_close                  = vsdk_ffv_adapter_input_close,
   .input_buffer_size_get        = vsdk_ffv_adapter_input_buffer_size_get,
   .input_read                   = vsdk_ffv_adapter_input_read,
   .input_mute                   = vsdk_ffv_adapter_input_mute,
   .input_focus                  = vsdk_ffv_adapter_input_focus,
   .input_stats                  = vsdk_ffv_adapter_input_stats,
   .input_detection              = vsdk_ffv_adapter_input_detection,
   .input_eos_cmd                = vsdk_ffv_adapter_input_eos_cmd,
   .input_stream_params_get      = vsdk_ffv_adapter_input_stream_params_get,
   .input_stream_start_set       = vsdk_ffv_adapter_input_stream_start_set,
   .input_keyword_detector_reset = vsdk_ffv_adapter_input_keyword_detector_reset,
   .input_test_mode              = vsdk_ffv_adapter_input_test_mode,
   .input_stream_latency_set     = vsdk_ffv_adapter_input_stream_latency_set,
   .output_open                  = NULL,
   .output_close                 = NULL,
   .output_buffer_size_get       = NULL,
   .output_write                 = NULL,
   .output_volume_set_int        = NULL,
   .output_volume_set_float      = NULL,
   .output_latency_get           = NULL,
};
#endif

void vsdk_version(vsdk_version_info_t *version_info, uint32_t *qty) {
   if(qty == NULL || *qty < VSDK_VERSION_QTY_MAX || version_info == NULL) {
      return;
   }
   uint32_t qty_avail = *qty;

   version_info->name      = "xr-voice-sdk";
   version_info->version   = VSDK_VERSION;
   version_info->branch    = VSDK_BRANCH;
   version_info->commit_id = VSDK_COMMIT_ID;
   version_info++;
   qty_avail--;

   *qty -= qty_avail;
}

int vsdk_init(bool ansi_color, const char *filename, uint32_t file_size_max) {
   if(g_vsdk.initialized) {
      return(0);
   }

   bool curtail_xlog        = false;
   bool curtail_xraudio     = false;
   bool allow_input_failure = true;

   vsdk_parse_options(&curtail_xlog, &curtail_xraudio, &allow_input_failure);
   int rc = xlog_init(XLOG_MODULE_ID_VSDK, filename, file_size_max, ansi_color, curtail_xlog);

   // Store the value so it can be used when xraudio is initialized
   g_vsdk.curtail_xraudio             = curtail_xraudio;
   g_vsdk.xraudio_allow_input_failure = allow_input_failure;
   g_vsdk.hal_out_enabled             = false;
   g_vsdk.hal_in_enabled              = vsdk_load_plugin_ffv(&g_vsdk.ffv_plugins);

   if(rc == 0) {
      g_vsdk.initialized = true;
   }
   return(rc);
}

int vsdk_init_user_print(xlog_print_t print, xlog_print_t print_safe, bool ansi_color, const char *filename, uint32_t file_size_max) {
   if(g_vsdk.initialized) {
      return(0);
   }
   
   bool curtail_xlog        = false;
   bool curtail_xraudio     = false;
   bool allow_input_failure = true;

   vsdk_parse_options(&curtail_xlog, &curtail_xraudio, &allow_input_failure);

   int rc = xlog_init_user_print(XLOG_MODULE_ID_VSDK, print, print_safe, filename, file_size_max, ansi_color, curtail_xlog);

   // Store the value so it can be used when xraudio is initialized
   g_vsdk.curtail_xraudio             = curtail_xraudio;
   g_vsdk.xraudio_allow_input_failure = allow_input_failure;
   g_vsdk.hal_out_enabled             = false;
   g_vsdk.hal_in_enabled              = vsdk_load_plugin_ffv(&g_vsdk.ffv_plugins);

   if(rc == 0) {
      g_vsdk.initialized = true;
   }
   return(rc);
}

void vsdk_term(void) {
   if(!g_vsdk.initialized) {
      return;
   }
   xlog_term();

   if(g_vsdk.hal_in_enabled || g_vsdk.hal_out_enabled) {
      XLOGD_INFO("unload FFV hal");
      if(dlclose(g_vsdk.ffv_plugins.handle_ffv_hal) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV HAL <%s>", (err != NULL) ? err : "unknown error");
      }
      if(dlclose(g_vsdk.ffv_plugins.handle_ffv_kwd) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV KWD <%s>", (err != NULL) ? err : "unknown error");
      }
      if(dlclose(g_vsdk.ffv_plugins.handle_ffv_alg) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV ALG <%s>", (err != NULL) ? err : "unknown error");
      }
      g_vsdk.ffv_plugins.handle_ffv_hal = NULL;
      g_vsdk.ffv_plugins.handle_ffv_kwd = NULL;
      g_vsdk.ffv_plugins.handle_ffv_alg = NULL;
   }
   if(g_vsdk.ffv_plugins.handle_ffv_sdf != NULL) {
      XLOGD_INFO("unload FFV SDF");
      if(dlclose(g_vsdk.ffv_plugins.handle_ffv_sdf) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV SDF <%s>", (err != NULL) ? err : "unknown error");
      }
      g_vsdk.ffv_plugins.handle_ffv_sdf = NULL;
   }
   if(g_vsdk.ffv_plugins.handle_ffv_ovc != NULL) {
      XLOGD_INFO("unload FFV OVC");
      if(dlclose(g_vsdk.ffv_plugins.handle_ffv_ovc) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV OVC <%s>", (err != NULL) ? err : "unknown error");
      }
      g_vsdk.ffv_plugins.handle_ffv_ovc = NULL;
   }
   if(g_vsdk.ffv_plugins.handle_ffv_ppr != NULL) {
      XLOGD_INFO("unload FFV PPR");
      if(dlclose(g_vsdk.ffv_plugins.handle_ffv_ppr) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV PPR <%s>", (err != NULL) ? err : "unknown error");
      }
      g_vsdk.ffv_plugins.handle_ffv_ppr = NULL;
   }

   g_vsdk.initialized = false;
}

xlog_level_t vsdk_log_level_get(xlog_module_id_t id) {
   return(xlog_level_get(id));
}

void vsdk_log_level_set(xlog_module_id_t id, xlog_level_t level) {
   xlog_level_set(id, level);
}

void vsdk_log_level_set_all(xlog_level_t level) {
   xlog_level_set_all(level);
}

void vsdk_thread_poll(vsdk_thread_poll_func_t func, void *data) {
   if(func == NULL) {
      XLOG_ERROR("invalid params");
      return;
   }

   if(!g_vsdk.initialized) { // not initialized.  just call the function immediately without checking anything
      XLOG_INFO("not initialized");
      (*func)(data);
      return;
   }

   g_vsdk.func = func;
   g_vsdk.data = data;

   // Check speech router thread
   xrsr_thread_poll(vsdk_thread_response);
}

void vsdk_thread_response(void) {
   if(g_vsdk.initialized && g_vsdk.func != NULL) {
      (*g_vsdk.func)(g_vsdk.data);
   }
}

bool vsdk_curtail_xraudio_enabled(void) {
   return(g_vsdk.curtail_xraudio);
}

bool vsdk_hal_in_enabled(void) {
   return(g_vsdk.hal_in_enabled);
}

bool vsdk_hal_out_enabled(void) {
   return(g_vsdk.hal_out_enabled);
}

xraudio_hal_plugin_api_t *vsdk_hal_plugin_get(void) {
   return(g_vsdk.hal_plugin);
}

xraudio_kwd_plugin_api_t *vsdk_kwd_plugin_get(void) {
   return(g_vsdk.kwd_plugin);
}

xraudio_eos_plugin_api_t *vsdk_eos_plugin_get(void) {
   return(g_vsdk.eos_plugin);
}

xraudio_dga_plugin_api_t *vsdk_dga_plugin_get(void) {
   return(g_vsdk.dga_plugin);
}

xraudio_sdf_plugin_api_t *vsdk_sdf_plugin_get(void) {
   return(g_vsdk.sdf_plugin);
}

xraudio_ovc_plugin_api_t *vsdk_ovc_plugin_get(void) {
   return(g_vsdk.ovc_plugin);
}

xraudio_ppr_plugin_api_t *vsdk_ppr_plugin_get(void) {
   return(g_vsdk.ppr_plugin);
}

bool vsdk_xraudio_allow_input_failure(void) {
   return(g_vsdk.xraudio_allow_input_failure);
}

bool vsdk_file_exists(const char *filename) {
   if(filename == NULL) {
      return false;
   }
   struct stat buffer;
   if(stat(filename, &buffer) == 0) {
      return true;
   }
   return false;
}

void vsdk_parse_options(bool *curtail_xlog, bool *curtail_xraudio, bool *xraudio_allow_input_failure) {
   bool crtl_xlog           = false;
   bool crtl_xraudio        = false;
   bool allow_input_failure = true;

   // If the vendor supplied options are provided, use them.  Otherwise use the default values.
   const char *vendor_options_file = VSDK_VENDOR_OPTIONS_FILE;

   if(vsdk_file_exists(vendor_options_file)) {
      XLOGD_INFO("Using vendor options file: %s", vendor_options_file);

      json_t *json_obj_vendor_options = json_load_file(vendor_options_file, JSON_REJECT_DUPLICATES, NULL);

      if(json_obj_vendor_options == NULL || !json_is_object(json_obj_vendor_options)) {
         XLOGD_ERROR("invalid vendor options file format");
      } else {
         json_t *option = json_object_get(json_obj_vendor_options, "curtail_xlog");
         if(option == NULL) {
            // Not present
         } else if(!json_is_boolean(option)) {
            XLOGD_ERROR("invalid vendor option format - curtail_xlog");
         } else {
            crtl_xlog = json_boolean_value(option);
            XLOGD_INFO("curtail xlog is <%s>", crtl_xlog ? "enabled" : "disabled");
         }
         option = json_object_get(json_obj_vendor_options, "curtail_xraudio");
         if(option == NULL) {
            // Not present
         } else if(!json_is_boolean(option)) {
            XLOGD_ERROR("invalid vendor option format - curtail_xraudio");
         } else {
            crtl_xraudio = json_boolean_value(option);
            XLOGD_INFO("curtail xraudio is <%s>", crtl_xraudio ? "enabled" : "disabled");
         }
         option = json_object_get(json_obj_vendor_options, "allow_input_failure");
         if(option == NULL) {
            // Not present
         } else if(!json_is_boolean(option)) {
            XLOGD_ERROR("invalid vendor option format - allow_input_failure");
         } else {
            allow_input_failure = json_boolean_value(option);
            XLOGD_INFO("allow input failure is <%s>", allow_input_failure ? "enabled" : "disabled");
         }
      }
      if(json_obj_vendor_options != NULL) {
         json_decref(json_obj_vendor_options);
         json_obj_vendor_options = NULL;
      }

      if(curtail_xlog != NULL) {
         *curtail_xlog = crtl_xlog;
      }
      if(curtail_xraudio != NULL) {
         *curtail_xraudio = crtl_xraudio;
      }
      if(xraudio_allow_input_failure != NULL) {
         *xraudio_allow_input_failure = allow_input_failure;
      }
   }
}

bool vsdk_load_plugin_ffv(vsdk_ffv_plugin_handles_t *handles) {
   if(handles == NULL) {
      XLOGD_ERROR("handles is null");
      return(false);
   }

   bool ret = false;
   memset(handles, 0, sizeof(*handles));
   do {
      handles->handle_ffv_hal = vsdk_load_plugin_ffv_hal(&g_vsdk.hal_out_enabled);

      if(handles->handle_ffv_hal == NULL) {
         break;
      }

      #ifdef PJT_OLD_HAL
      handles->handle_ffv_kwd  = vsdk_load_plugin_ffv_kwd();

      if(handles->handle_ffv_kwd == NULL) {
         break;
      }

      handles->handle_ffv_alg = vsdk_load_plugin_ffv_alg(&handles->handle_ffv_ppr);

      if(handles->handle_ffv_alg == NULL) {
         break;
      }
      #endif

      handles->handle_ffv_sdf = vsdk_load_plugin_ffv_sdf();
      handles->handle_ffv_ovc = vsdk_load_plugin_ffv_ovc();
      ret = true;
   } while(0);

   if(!ret) {
      if(handles->handle_ffv_hal != NULL) {
         if(dlclose(handles->handle_ffv_hal) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV HAL <%s>", (err != NULL) ? err : "unknown error");
         }
         handles->handle_ffv_hal = NULL;
      }
      #ifdef PJT_OLD_HAL
      if(handles->handle_ffv_kwd != NULL) {
         if(dlclose(handles->handle_ffv_kwd) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV KWD <%s>", (err != NULL) ? err : "unknown error");
         }
         handles->handle_ffv_kwd = NULL;
      }
      #endif
      if(handles->handle_ffv_alg != NULL) {
         if(dlclose(handles->handle_ffv_alg) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV ALG <%s>", (err != NULL) ? err : "unknown error");
         }
         handles->handle_ffv_alg = NULL;
      }
      if(handles->handle_ffv_sdf != NULL) {
         if(dlclose(handles->handle_ffv_sdf) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV SDF <%s>", (err != NULL) ? err : "unknown error");
         }
         handles->handle_ffv_sdf = NULL;
      }
      if(handles->handle_ffv_ovc != NULL) {
         if(dlclose(handles->handle_ffv_ovc) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV OVC <%s>", (err != NULL) ? err : "unknown error");
         }
         handles->handle_ffv_ovc = NULL;
      }
      if(handles->handle_ffv_ppr != NULL) {
         if(dlclose(handles->handle_ffv_ppr) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV PPR <%s>", (err != NULL) ? err : "unknown error");
         }
         handles->handle_ffv_ppr = NULL;
      }
   }

   XLOGD_INFO("FFV plugin is <%s>", ret ? "enabled" : "disabled");

   return(ret);
}

#ifdef PJT_OLD_HAL
void *vsdk_load_plugin_ffv_kwd(void) {
   void *handle = NULL;
   const char *so_path_vd = "/vendor/lib/libxraudio-ffv-kwd.so";
   const char *so_path_mw = "/usr/lib/libxraudio-ffv-kwd.so";
   if(vsdk_file_exists(so_path_vd)) {
      handle = dlopen(so_path_vd, RTLD_NOW);
   } else if(vsdk_file_exists(so_path_mw)) {
      handle = dlopen(so_path_mw, RTLD_NOW);
   } else {
      XLOGD_INFO("FFV KWD plugin is not present.");
      return(NULL);
   }

   if(NULL == handle) {
      XLOGD_ERROR("Failed to load FFV KWD plugin <%s>", dlerror());
      return(NULL);
   }

   dlerror();  // Clear any existing error

   xraudio_kwd_plugin_api_get_t plugin_api_get = (xraudio_kwd_plugin_api_get_t)dlsym(handle, "xraudio_kwd_plugin_api_get");
   char *error = dlerror();

   if(error != NULL) {
      XLOGD_ERROR("Required plugin KWD not present, error <%s>", error);
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV KWD <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }

   XLOGD_INFO("Loading required plugin KWD.");
   g_vsdk.kwd_plugin = plugin_api_get();

   if(g_vsdk.kwd_plugin == NULL) {
      XLOGD_ERROR("KWD plugin API get failed");
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV KWD <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   if(g_vsdk.kwd_plugin->version                == NULL ||
      g_vsdk.kwd_plugin->object_create          == NULL ||
      g_vsdk.kwd_plugin->object_destroy         == NULL ||
      g_vsdk.kwd_plugin->init                   == NULL ||
      g_vsdk.kwd_plugin->update                 == NULL ||
      g_vsdk.kwd_plugin->run                    == NULL ||
      g_vsdk.kwd_plugin->run_int16              == NULL ||
      g_vsdk.kwd_plugin->postprocess            == NULL ||
      g_vsdk.kwd_plugin->result                 == NULL ||
      g_vsdk.kwd_plugin->term                   == NULL ||
      g_vsdk.kwd_plugin->sensitivity_limits_get == NULL ||
      g_vsdk.kwd_plugin->sensitivity_lut_check  == NULL) {
      XLOGD_ERROR("KWD plugin API incomplete");
      g_vsdk.kwd_plugin = NULL;
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV KWD <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   XLOGD_INFO("Loaded required plugin KWD.");

   return(handle);
}
#endif

#ifdef PJT_OLD_HAL
void *vsdk_load_plugin_ffv_alg(void **handle_ppr) {
   void *handle = NULL;
   #ifdef PJT_OLD_HAL
   const char *so_path_vd = "/vendor/lib/libxraudio-ffv-algorithms.so";
   const char *so_path_mw = "/usr/lib/libxraudio-ffv-algorithms.so";
   #else
   const char *so_path_vd = "/data/jason/usr/lib/libxraudio-ffv-algorithms.so";
   const char *so_path_mw = "/data/jason/usr/lib/libxraudio-ffv-algorithms.so";

   #endif
   if(vsdk_file_exists(so_path_vd)) {
      handle = dlopen(so_path_vd, RTLD_NOW);
   } else if(vsdk_file_exists(so_path_mw)) {
      handle = dlopen(so_path_mw, RTLD_NOW);
   } else {
      XLOGD_INFO("FFV ALG plugin is not present.");
      return(NULL);
   }

   if(NULL == handle) {
      XLOGD_ERROR("Failed to load FFV ALG plugin <%s>", dlerror());
      return(NULL);
   }

   dlerror();  // Clear any existing error

   char *error = dlerror();

   #ifdef PJT_OLD_HAL
   xraudio_eos_plugin_api_get_t eos_plugin_api_get = (xraudio_eos_plugin_api_get_t)dlsym(handle, "xraudio_eos_plugin_api_get");
   char *error = dlerror();

   if(error != NULL) {
      XLOGD_ERROR("Required plugin EOS not present, error <%s>", error);
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV EOS <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }

   XLOGD_INFO("Loading required plugin EOS.");
   g_vsdk.eos_plugin = eos_plugin_api_get();

   if(g_vsdk.eos_plugin == NULL) {
      XLOGD_ERROR("EOS plugin API get failed");
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV EOS <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   if(g_vsdk.eos_plugin->version                   == NULL ||
      g_vsdk.eos_plugin->object_create             == NULL ||
      g_vsdk.eos_plugin->init                      == NULL ||
      g_vsdk.eos_plugin->object_destroy            == NULL ||
      g_vsdk.eos_plugin->run_float                 == NULL ||
      g_vsdk.eos_plugin->run_int16                 == NULL ||
      g_vsdk.eos_plugin->state_set_speech_begin    == NULL ||
      g_vsdk.eos_plugin->state_set_speech_end      == NULL ||
      g_vsdk.eos_plugin->signal_level_get          == NULL ||
      g_vsdk.eos_plugin->signal_to_noise_ratio_get == NULL) {
      XLOGD_ERROR("EOS plugin API incomplete");
      g_vsdk.eos_plugin = NULL;
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV EOS <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   XLOGD_INFO("Loaded required plugin EOS.");

   dlerror();  // Clear any existing error

   xraudio_dga_plugin_api_get_t dga_plugin_api_get = (xraudio_dga_plugin_api_get_t)dlsym(handle, "xraudio_dga_plugin_api_get");
   error = dlerror();

   if(error != NULL) {
      XLOGD_ERROR("Required plugin DGA not present, error <%s>", error);
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV DGA <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }

   XLOGD_INFO("Loading required plugin DGA.");
   g_vsdk.dga_plugin = dga_plugin_api_get();

   if(g_vsdk.dga_plugin == NULL) {
      XLOGD_ERROR("DGA plugin API get failed");
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV DGA <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   if(g_vsdk.dga_plugin->version        == NULL ||
      g_vsdk.dga_plugin->object_create  == NULL ||
      g_vsdk.dga_plugin->object_destroy == NULL ||
      g_vsdk.dga_plugin->calculate      == NULL ||
      g_vsdk.dga_plugin->update         == NULL ||
      g_vsdk.dga_plugin->apply          == NULL) {
      XLOGD_ERROR("DGA plugin API incomplete");
      g_vsdk.dga_plugin = NULL;
      g_vsdk.eos_plugin = NULL;
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV DGA <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   XLOGD_INFO("Loaded required plugin DGA.");

   dlerror();  // Clear any existing error
#else
   g_vsdk.dga_plugin = NULL;
   g_vsdk.eos_plugin = NULL;
#endif

   xraudio_ppr_plugin_api_get_t ppr_plugin_api_get = (xraudio_ppr_plugin_api_get_t)dlsym(handle, "xraudio_ppr_plugin_api_get");
   error = dlerror();

   if(error != NULL) {
      XLOGD_INFO("Optional plugin PPR not present, error <%s>", error);
   } else {
      XLOGD_INFO("Loading optional plugin PPR.");
      g_vsdk.ppr_plugin = ppr_plugin_api_get();

      if(g_vsdk.ppr_plugin == NULL) {
         XLOGD_ERROR("PPR plugin API get failed");
         if(dlclose(handle) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV PPR <%s>", (err != NULL) ? err : "unknown error");
         }
         g_vsdk.dga_plugin = NULL;
         g_vsdk.eos_plugin = NULL;
         return(NULL);
      }
      if(g_vsdk.ppr_plugin->version          == NULL ||
         g_vsdk.ppr_plugin->object_create    == NULL ||
         g_vsdk.ppr_plugin->init             == NULL ||
         g_vsdk.ppr_plugin->object_destroy   == NULL ||
         g_vsdk.ppr_plugin->run              == NULL ||
         g_vsdk.ppr_plugin->command          == NULL ||
         g_vsdk.ppr_plugin->get_status       == NULL ||
         g_vsdk.ppr_plugin->get_lookback_pcm == NULL) {
         XLOGD_ERROR("PPR plugin API incomplete");
         g_vsdk.ppr_plugin = NULL;
         if(dlclose(handle) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV PPR <%s>", (err != NULL) ? err : "unknown error");
         }
         g_vsdk.dga_plugin = NULL;
         g_vsdk.eos_plugin = NULL;
         return(NULL);
      }
      XLOGD_INFO("Loaded optional plugin PPR.");
   }

   XLOGD_INFO("FFV ALG plugin is loaded."); // TODO Print the version info here
   
   return(handle);
}
#endif

void *vsdk_load_plugin_ffv_hal(bool *out_enabled) {
   void *handle = NULL;
   #ifdef PJT_OLD_HAL
   const char *so_path_vd = "/vendor/lib/libxraudio-ffv-hal.so";
   const char *so_path_mw = "/usr/lib/libxraudio-ffv-hal.so";
   #else
   const char *so_path_vd = "/data/jason/usr/lib/libxr-ffv-hal.so";
   const char *so_path_mw = "/data/jason/usr/usr/lib/libxr-ffv-hal.so";
   #endif 

   XLOGD_WARN("opening %s", so_path_vd);

   if(vsdk_file_exists(so_path_vd)) {
      handle = dlopen(so_path_vd, RTLD_NOW);
   } else if(vsdk_file_exists(so_path_mw)) {
      handle = dlopen(so_path_mw, RTLD_NOW);
   } else {
      XLOGD_INFO("FFV HAL plugin is not present.");
      return(NULL);
   }

   if(NULL == handle) {
      XLOGD_ERROR("Failed to load FFV HAL plugin <%s>", dlerror());
      return(NULL);
   }

   dlerror();  // Clear any existing error

   xraudio_hal_plugin_api_get_t plugin_api_get = (xraudio_hal_plugin_api_get_t)dlsym(handle, "xraudio_hal_plugin_api_get");
   char *error = dlerror();

   #ifndef PJT_OLD_HAL
   if(error != NULL) {
      dlerror();  // Clear any existing error
      xr_ffv_hal_plugin_func_get_t ffv_plugin_func_get = (xr_ffv_hal_plugin_func_get_t)dlsym(handle, "xr_ffv_hal_plugin_func_get");
      error = dlerror();

      if(error == NULL) {
         xr_ffv_hal_plugin_func_t *ffv_api = ffv_plugin_func_get();
         if((ffv_api == NULL) ||
            (ffv_api->get_handle == NULL) ||
            (ffv_api->destroy == NULL) ||
            (ffv_api->get_capabilities == NULL) ||
            (ffv_api->open == NULL) ||
            (ffv_api->close == NULL) ||
            (ffv_api->open_channel == NULL) ||
            (ffv_api->close_channel == NULL) ||
            (ffv_api->set_privacy_state == NULL) ||
            (ffv_api->set_power_mode == NULL)) {
               //PJT finish filling this out it doesn't have all the functions
            XLOGD_ERROR("FFV HAL interface API incomplete");
            if(dlclose(handle) != 0) {
               const char *err = dlerror();
               XLOGD_ERROR("dlclose failed for FFV HAL <%s>", (err != NULL) ? err : "unknown error");
            }
            return(NULL);
         }

         XLOGD_INFO("Loading required plugin HAL through xr_ffv_hal_interface adapter.");
         g_vsdk.ffv_hal_interface_plugin = ffv_api;
         g_vsdk.hal_plugin = &g_vsdk_ffv_adapter_api;

         if(out_enabled != NULL) {
            *out_enabled = false;
         }

         return(handle);
      }
   }
   #endif

   if(error != NULL) {
      XLOGD_ERROR("Required plugin HAL not present, error <%s>", error);
      return(NULL);
   }
   g_vsdk.hal_plugin = plugin_api_get();

   if(g_vsdk.hal_plugin == NULL) {
      XLOGD_ERROR("HAL plugin API get failed");
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV HAL <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   if(g_vsdk.hal_plugin->version                      == NULL ||
      g_vsdk.hal_plugin->init                         == NULL ||
      g_vsdk.hal_plugin->capabilities_get             == NULL ||
      g_vsdk.hal_plugin->dsp_config_get               == NULL ||
      g_vsdk.hal_plugin->available_devices_get        == NULL ||
      g_vsdk.hal_plugin->open                         == NULL ||
      g_vsdk.hal_plugin->power_mode                   == NULL ||
      g_vsdk.hal_plugin->privacy_mode                 == NULL ||
      g_vsdk.hal_plugin->privacy_mode_get             == NULL ||
      g_vsdk.hal_plugin->close                        == NULL ||
      g_vsdk.hal_plugin->thread_poll                  == NULL ||
      g_vsdk.hal_plugin->input_open                   == NULL ||
      g_vsdk.hal_plugin->input_close                  == NULL ||
      g_vsdk.hal_plugin->input_buffer_size_get        == NULL ||
      g_vsdk.hal_plugin->input_read                   == NULL ||
      g_vsdk.hal_plugin->input_mute                   == NULL ||
      g_vsdk.hal_plugin->input_focus                  == NULL ||
      g_vsdk.hal_plugin->input_stats                  == NULL ||
      g_vsdk.hal_plugin->input_detection              == NULL ||
      g_vsdk.hal_plugin->input_eos_cmd                == NULL ||
      g_vsdk.hal_plugin->input_stream_params_get      == NULL ||
      g_vsdk.hal_plugin->input_stream_start_set       == NULL ||
      g_vsdk.hal_plugin->input_keyword_detector_reset == NULL ||
      g_vsdk.hal_plugin->input_test_mode              == NULL ||
      g_vsdk.hal_plugin->input_stream_latency_set     == NULL) {
      XLOGD_ERROR("HAL plugin API incomplete");
      g_vsdk.hal_plugin = NULL;
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for FFV HAL <%s>", (err != NULL) ? err : "unknown error");
      }
      return(NULL);
   }
   if(g_vsdk.hal_plugin->output_open             == NULL ||
      g_vsdk.hal_plugin->output_close            == NULL ||
      g_vsdk.hal_plugin->output_buffer_size_get  == NULL ||
      g_vsdk.hal_plugin->output_write            == NULL ||
      g_vsdk.hal_plugin->output_volume_set_int   == NULL ||
      g_vsdk.hal_plugin->output_volume_set_float == NULL ||
      g_vsdk.hal_plugin->output_latency_get      == NULL) {
      XLOGD_INFO("HAL plugin OUTPUT API not present");
      if(out_enabled != NULL) {
         *out_enabled = false;
      }
   } else {
      if(out_enabled != NULL) {
         *out_enabled = true;
      }
   }

   XLOGD_INFO("Loaded required plugin HAL.");
      
   return(handle);
}

void *vsdk_load_plugin_ffv_sdf(void) {
   void *handle = NULL;
   const char *so_path_vd = "/vendor/lib/libxraudio-sdf.so";
   const char *so_path_mw = "/usr/lib/libxraudio-sdf.so";
   if(vsdk_file_exists(so_path_vd)) {
      handle = dlopen(so_path_vd, RTLD_NOW);
   } else if(vsdk_file_exists(so_path_mw)) {
      handle = dlopen(so_path_mw, RTLD_NOW);
   } else {
      XLOGD_INFO("FFV SDF plugin is not present.");
      return(NULL);
   }

   if(NULL == handle) {
      XLOGD_ERROR("Failed to load FFV SDF plugin <%s>", dlerror());
      return(NULL);
   }

   dlerror();  // Clear any existing error

   xraudio_sdf_plugin_api_get_t plugin_api_get = (xraudio_sdf_plugin_api_get_t)dlsym(handle, "xraudio_sdf_plugin_api_get");
   char *error = dlerror();

   if(error != NULL) {
      XLOGD_INFO("Optional plugin SDF not present, error <%s>", error);
   } else {
      XLOGD_INFO("Loading optional plugin SDF.");
      g_vsdk.sdf_plugin = plugin_api_get();

      if(g_vsdk.sdf_plugin == NULL) {
         XLOGD_ERROR("SDF plugin API get failed");
         if(dlclose(handle) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV SDF <%s>", (err != NULL) ? err : "unknown error");
         }
         return(NULL);
      }
      if(g_vsdk.sdf_plugin->object_create        == NULL ||
         g_vsdk.sdf_plugin->object_destroy       == NULL ||
         g_vsdk.sdf_plugin->focus_set            == NULL ||
         g_vsdk.sdf_plugin->focus_update         == NULL ||
         g_vsdk.sdf_plugin->signal_direction_get == NULL ||
         g_vsdk.sdf_plugin->statistics_clear     == NULL ||
         g_vsdk.sdf_plugin->statistics_print     == NULL) {
         XLOGD_ERROR("SDF plugin API incomplete");
         g_vsdk.sdf_plugin = NULL;
         if(dlclose(handle) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV SDF <%s>", (err != NULL) ? err : "unknown error");
         }
         return(NULL);
      }
      XLOGD_INFO("Loaded optional plugin SDF.");
   }
   
   return(handle);
}

void *vsdk_load_plugin_ffv_ovc(void) {
   void *handle = NULL;
   const char *so_path_vd = "/vendor/lib/libxraudio-ovc.so";
   const char *so_path_mw = "/usr/lib/libxraudio-ovc.so";
   if(vsdk_file_exists(so_path_vd)) {
      handle = dlopen(so_path_vd, RTLD_NOW);
   } else if(vsdk_file_exists(so_path_mw)) {
      handle = dlopen(so_path_mw, RTLD_NOW);
   } else {
      XLOGD_INFO("FFV OVC plugin is not present.");
      return(NULL);
   }

   if(NULL == handle) {
      XLOGD_ERROR("Failed to load FFV OVC plugin <%s>", dlerror());
      return(NULL);
   }

   dlerror();  // Clear any existing error

   xraudio_ovc_plugin_api_get_t plugin_api_get = (xraudio_ovc_plugin_api_get_t)dlsym(handle, "xraudio_ovc_plugin_api_get");
   char *error = dlerror();

   if(error != NULL) {
      XLOGD_INFO("Optional plugin OVC not present, error <%s>", error);
   } else {
      XLOGD_INFO("Loading optional plugin OVC.");
      g_vsdk.ovc_plugin = plugin_api_get();

      if(g_vsdk.ovc_plugin == NULL) {
         XLOGD_ERROR("OVC plugin API get failed");
         if(dlclose(handle) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV OVC <%s>", (err != NULL) ? err : "unknown error");
         }
         return(NULL);
      }
      if(g_vsdk.ovc_plugin->version                 == NULL ||
         g_vsdk.ovc_plugin->object_create           == NULL ||
         g_vsdk.ovc_plugin->object_destroy          == NULL ||
         g_vsdk.ovc_plugin->config_get              == NULL ||
         g_vsdk.ovc_plugin->config_set              == NULL ||
         g_vsdk.ovc_plugin->set_gain                == NULL ||
         g_vsdk.ovc_plugin->increase                == NULL ||
         g_vsdk.ovc_plugin->decrease                == NULL ||
         g_vsdk.ovc_plugin->apply_gain_multichannel == NULL ||
         g_vsdk.ovc_plugin->get_scale               == NULL ||
         g_vsdk.ovc_plugin->is_ramp_active          == NULL) {
         XLOGD_ERROR("OVC plugin API incomplete");
         g_vsdk.ovc_plugin = NULL;
         if(dlclose(handle) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV OVC <%s>", (err != NULL) ? err : "unknown error");
         }
         return(NULL);
      }
      XLOGD_INFO("Loaded optional plugin OVC.");
   }
   
   return(handle);
}
