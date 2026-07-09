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
#ifndef USE_RDKV_HAL

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include <xr_voice_sdk.h>

#include "vsdk_ffv_adapter.h"

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

typedef struct {
   xr_ffv_hal_plugin_func_t *ffv_hal_interface_plugin;
   vsdk_ffv_hal_obj_t       *active_hal_obj;
   xraudio_hal_plugin_api_t  plugin_api;
} vsdk_ffv_adapter_t;

static vsdk_ffv_adapter_t g_vsdk_ffv_adapter = {0};

static FFVhalPowerMode_t vsdk_ffv_power_mode_from_xraudio(xraudio_power_mode_t power_mode) {
   switch(power_mode) {
      case XRAUDIO_POWER_MODE_FULL:  return(FULL_POWER);
      case XRAUDIO_POWER_MODE_LOW:   return(STANDBY);
      case XRAUDIO_POWER_MODE_SLEEP: return(DEEP_SLEEP);
      default:                       return(NONE);
   }
}

//This function decides whether we're requesting keyword or microphone channel, needs updating
static bool vsdk_ffv_channel_is_keyword(xraudio_input_format_t format) {
   XLOGD_INFO("format.container=%d, format.encoding.type=%d, format.sample_rate=%d, format.sample_size=%d, format.channel_qty=%d", format.container, format.encoding.type, format.sample_rate, format.sample_size, format.channel_qty);
   //This is not a good test but will do for the moment
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
   //Need to fill this out.
   XLOGD_INFO("FFV HAL state changed from %d to %d", oldState, newState);
}

static void vsdk_ffv_on_entered_power_mode_cb(FFVhalPowerMode_t powerMode) {
   (void)powerMode;
   //Do we need to do anything here given that the HAL changed power mode because vsdk said to?
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
   if((g_vsdk_ffv_adapter.active_hal_obj == NULL) || (g_vsdk_ffv_adapter.active_hal_obj->callback == NULL)) {
      return;
   }

   // If a session is active, force an end before reporting the input error.
   vsdk_ffv_emit_session_end(g_vsdk_ffv_adapter.active_hal_obj);

   xraudio_hal_msg_input_error_t msg;
   memset(&msg, 0, sizeof(msg));
   msg.header.type   = XRAUDIO_MSG_TYPE_INPUT_ERROR;
   msg.header.source = g_vsdk_ffv_adapter.active_hal_obj->source;
   g_vsdk_ffv_adapter.active_hal_obj->callback(&msg);
}

static void vsdk_ffv_on_keyword_detected_cb(void) {
   XLOGD_INFO("");
   if(g_vsdk_ffv_adapter.active_hal_obj == NULL) {
      XLOGD_ERROR("FFV HAL keyword detected but no active HAL object");
      return;
   }
   vsdk_ffv_emit_session_request(g_vsdk_ffv_adapter.active_hal_obj);
   vsdk_ffv_emit_session_begin(g_vsdk_ffv_adapter.active_hal_obj);
}

static void vsdk_ffv_on_end_of_command_cb(int32_t sampleOffset, bool timedOut) {
   (void)sampleOffset;
   (void)timedOut;
   XLOGD_INFO("end of command detected at sample offset %d, timed out=%d", sampleOffset, timedOut);
   if(g_vsdk_ffv_adapter.active_hal_obj == NULL) {
      XLOGD_ERROR("FFV HAL end of command detected but no active HAL object");
      return;
   }
   vsdk_ffv_emit_session_end(g_vsdk_ffv_adapter.active_hal_obj);
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
   XLOGD_INFO("xffv_hal_interface_plugin is %p", g_vsdk_ffv_adapter.ffv_hal_interface_plugin);
   if(g_vsdk_ffv_adapter.ffv_hal_interface_plugin == NULL) {
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
   XLOGD_INFO("xffv_hal_interface_plugin is %p", g_vsdk_ffv_adapter.ffv_hal_interface_plugin);

   xr_ffv_hal_plugin_func_t *ffv_api = g_vsdk_ffv_adapter.ffv_hal_interface_plugin;
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
}

static bool vsdk_ffv_adapter_dsp_config_get(xraudio_hal_dsp_config_t *dsp_config) {
   if(dsp_config == NULL) {
      XLOGD_ERROR("Invalid parameters");
      return(false);
   }
   XLOGD_INFO("");
   memset(dsp_config, 0, sizeof(*dsp_config));
   dsp_config->ppr_enabled               = false;
   dsp_config->dga_enabled               = false;
   dsp_config->eos_enabled               = true;
   dsp_config->input_asr_max_channel_qty = XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY;
   dsp_config->input_kwd_max_channel_qty = XRAUDIO_INPUT_KWD_MAX_CHANNEL_QTY;
   dsp_config->aop_adjust                = 0.0f;
   dsp_config->dsp_output_override_enable= false;
   return(true);
}

static bool vsdk_ffv_adapter_available_devices_get(xraudio_devices_input_t *inputs, uint32_t input_qty_max, xraudio_devices_output_t *outputs, uint32_t output_qty_max) {
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

   xr_ffv_hal_plugin_func_t *ffv_api = g_vsdk_ffv_adapter.ffv_hal_interface_plugin;

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

   g_vsdk_ffv_adapter.active_hal_obj = obj;
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

   if(g_vsdk_ffv_adapter.active_hal_obj == obj) {
      g_vsdk_ffv_adapter.active_hal_obj = NULL;
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
   //Call the HAL status function here
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
   static int doit = 1;

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
   if(doit) {
      for(uint32_t i = 0; i < (uint32_t)rc; i+=8) {
         XLOGD_INFO("data[%d]: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x", i, data[i], data[i+1], data[i+2], data[i+3], data[i+4], data[i+5], data[i+6], data[i+7]);
      }
      doit = 0;
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

static void vsdk_ffv_adapter_plugin_api_init(vsdk_ffv_adapter_t *vsdk_ffv_adapter) {
   vsdk_ffv_adapter->plugin_api = (xraudio_hal_plugin_api_t){
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
}

void vsdk_ffv_adapter_set_interface_plugin(xr_ffv_hal_plugin_func_t *plugin) {
   g_vsdk_ffv_adapter.ffv_hal_interface_plugin = plugin;
}

xraudio_hal_plugin_api_t *vsdk_ffv_adapter_api_get(void) {
   vsdk_ffv_adapter_plugin_api_init(&g_vsdk_ffv_adapter);
   return(&g_vsdk_ffv_adapter.plugin_api);
}

#endif
