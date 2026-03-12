/*
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2026 RDK Management
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
#include <xraudio_hal.h>
#include <xr_ffv_hal_plugin.h>

#define XLOG_MODULE_ID XLOG_MODULE_ID_XRAUDIO
#include <rdkx_logger.h>
#include <string.h>

typedef struct {
   uint32_t            xraudio_frame_size;
   uint32_t            xraudio_frame_sample_qty;
   bool                xraudio_privacy_mode;
   bool                eos_session_active;
   xraudio_eos_event_t eos_event;
   bool                xraudio_test_mode;
   #if defined(LSPI_XRAUDIO_NOTIFY_DISABLE) && defined(LSPI_XRAUDIO_NOTIFY_DISABLE_WITH_READ)
   uint8_t             dummy_frame_buffer[12800];
   #endif
   #ifdef LSPI_TIMING_STATS_PRINT
   uint64_t            qty_samples_next_print_stats;
   #endif
   #ifdef LSPI_TIMING_BUFFER_LEVEL_PRINT
   uint64_t            qty_samples_next_print_bufl;
   #endif
   //lspi_fpm_t          full_power_mode;
   uint16_t            nsm_false_accept_rate_uint16;
   float               nsm_false_accept_rate_float;
   uint32_t            frame_read_pending_qty;
   float               aop_adjust_lpm;
   float               aop_adjust_fpm_pass_thru;
   float               aop_adjust_fpm_dspc;
   float               aop_adjust_fpm_comcast;
   bool                dsp_output_override_enable;
   bool                dsp_aec_context_blob_available;
   char               *dsp_aec_context_blob_file_path;
   json_t *            obj_config_mic;
} xr_ffv_hal_input_global_t;

static void xraudio_hal_version(xraudio_version_info_t *version_info, uint32_t *qty);
static bool xraudio_hal_init(json_t *obj_config);
static void xraudio_hal_capabilities_get(xraudio_hal_capabilities *caps);
static bool xraudio_hal_dsp_config_get(xraudio_hal_dsp_config_t *dsp_config);
static bool xraudio_hal_available_devices_get(xraudio_devices_input_t *inputs, uint32_t input_qty_max, xraudio_devices_output_t *outputs, uint32_t output_qty_max);
static xraudio_hal_obj_t xraudio_hal_open(bool debug, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_hal_msg_callback_t callback);
static bool xraudio_hal_power_mode(xraudio_hal_obj_t object, xraudio_power_mode_t power_mode);
static bool xraudio_hal_privacy_mode(xraudio_hal_obj_t object, bool enable);
static bool xraudio_hal_privacy_mode_get(xraudio_hal_obj_t object, bool *enable);
static void xraudio_hal_close(xraudio_hal_obj_t object);
static bool xraudio_hal_thread_poll(void);

static xraudio_hal_input_obj_t xraudio_hal_input_open(xraudio_hal_obj_t hal_obj, xraudio_devices_input_t device, xraudio_input_format_t format, xraudio_device_input_configuration_t *configuration);
static void xraudio_hal_input_close(xraudio_hal_input_obj_t obj);
static uint32_t xraudio_hal_input_buffer_size_get(xraudio_hal_input_obj_t obj);
static int32_t xraudio_hal_input_read(xraudio_hal_input_obj_t obj, uint8_t *data, uint32_t size, xraudio_eos_event_t *eos_event);
static bool xraudio_hal_input_mute(xraudio_hal_input_obj_t obj, xraudio_devices_input_t device, bool enable);
static bool xraudio_hal_input_focus(xraudio_hal_input_obj_t obj, xraudio_sdf_mode_t mode);
static bool xraudio_hal_input_stats(xraudio_hal_input_obj_t obj, xraudio_hal_input_stats_t *input_stats, bool reset);
static bool xraudio_hal_input_detection(xraudio_hal_input_obj_t obj, uint32_t chan, bool *ignore);
static bool xraudio_hal_input_eos_cmd(xraudio_hal_input_obj_t obj, xraudio_eos_cmd_t cmd, uint32_t chan);
static bool xraudio_hal_input_stream_params_get(xraudio_hal_input_obj_t obj, xraudio_hal_stream_params_t *stream_params);
static bool xraudio_hal_input_stream_start_set(xraudio_hal_input_obj_t obj, uint32_t start_sample);
static bool xraudio_hal_input_keyword_detector_reset(xraudio_hal_input_obj_t obj);
static bool xraudio_hal_input_test_mode(xraudio_hal_input_obj_t obj, bool enable);
static bool xraudio_hal_input_stream_latency_set(xraudio_hal_input_obj_t obj, xraudio_stream_latency_mode_t latency_mode);

//static xr_ffv_hal_input_global_t g_xr_ffv_hal_input_global;

xraudio_hal_plugin_api_t *xraudio_hal_plugin_api_get(void) {
   static xraudio_hal_plugin_api_t g_xr_ffv_hal_plugin_api = {
      .version                      = xraudio_hal_version,
      .init                         = xraudio_hal_init,
      .capabilities_get             = xraudio_hal_capabilities_get,
      .dsp_config_get               = xraudio_hal_dsp_config_get,
      .available_devices_get        = xraudio_hal_available_devices_get,
      .open                         = xraudio_hal_open,
      .power_mode                   = xraudio_hal_power_mode,
      .privacy_mode                 = xraudio_hal_privacy_mode,
      .privacy_mode_get             = xraudio_hal_privacy_mode_get,
      .close                        = xraudio_hal_close,
      .thread_poll                  = xraudio_hal_thread_poll,

      .input_open                   = xraudio_hal_input_open,
      .input_close                  = xraudio_hal_input_close,
      .input_buffer_size_get        = xraudio_hal_input_buffer_size_get,
      .input_read                   = xraudio_hal_input_read,
      .input_mute                   = xraudio_hal_input_mute,
      .input_focus                  = xraudio_hal_input_focus,
      .input_stats                  = xraudio_hal_input_stats,
      .input_detection              = xraudio_hal_input_detection,
      .input_eos_cmd                = xraudio_hal_input_eos_cmd,
      .input_stream_params_get      = xraudio_hal_input_stream_params_get,
      .input_stream_start_set       = xraudio_hal_input_stream_start_set,
      .input_keyword_detector_reset = xraudio_hal_input_keyword_detector_reset,
      .input_test_mode              = xraudio_hal_input_test_mode,
      .input_stream_latency_set     = xraudio_hal_input_stream_latency_set,

      .output_open                  = NULL,
      .output_close                 = NULL,
      .output_buffer_size_get       = NULL,
      .output_write                 = NULL,
      .output_volume_set_int        = NULL,
      .output_volume_set_float      = NULL,
      .output_latency_get           = NULL
   };

   return &g_xr_ffv_hal_plugin_api;
}

void xraudio_hal_version(xraudio_version_info_t *version_info, uint32_t *qty) {
   XLOGD_INFO("xraudio_hal_version");
}
bool xraudio_hal_init(json_t *obj_config) {
   XLOGD_INFO("xraudio_hal_init");
   return(true);
}
void xraudio_hal_capabilities_get(xraudio_hal_capabilities *caps) {
   memset(caps, 0, sizeof(xraudio_hal_capabilities));
   XLOGD_INFO("xraudio_hal_capabilities_get");
}
bool xraudio_hal_dsp_config_get(xraudio_hal_dsp_config_t *dsp_config) {
   dsp_config = NULL;
   XLOGD_INFO("xraudio_hal_dsp_config_get");
   return(true);
}
bool xraudio_hal_available_devices_get(xraudio_devices_input_t *inputs, uint32_t input_qty_max, xraudio_devices_output_t *outputs, uint32_t output_qty_max) {
   XLOGD_INFO("xraudio_hal_available_devices_get");
   return(true);
}
xraudio_hal_obj_t xraudio_hal_open(bool debug, xraudio_power_mode_t power_mode, bool privacy_mode, xraudio_hal_msg_callback_t callback) {
   XLOGD_INFO("xraudio_hal_open: power_mode <%d> privacy_mode <%s>", power_mode, privacy_mode ? "muted" : "unmuted");
   return(NULL);
}
bool xraudio_hal_power_mode(xraudio_hal_obj_t object, xraudio_power_mode_t power_mode) {
   XLOGD_INFO("xraudio_hal_power_mode <%d>", power_mode);
   return(true);
}
bool xraudio_hal_privacy_mode(xraudio_hal_obj_t object, bool enable) {
   XLOGD_INFO("xraudio_hal_privacy_mode <%s>", enable ? "enabled" : "disabled");
   return(true);
}
bool xraudio_hal_privacy_mode_get(xraudio_hal_obj_t object, bool *enable) {
   XLOGD_INFO("xraudio_hal_privacy_mode_get");
   *enable = false;
   return(true);
}
void xraudio_hal_close(xraudio_hal_obj_t object) {
   XLOGD_INFO("xraudio_hal_close");
}
bool xraudio_hal_thread_poll(void) {
   XLOGD_INFO("xraudio_hal_thread_poll");
   return(true);
}

xraudio_hal_input_obj_t xraudio_hal_input_open(xraudio_hal_obj_t hal_obj, xraudio_devices_input_t device, xraudio_input_format_t format, xraudio_device_input_configuration_t *configuration) {
   XLOGD_INFO("xraudio_hal_input_open: device <%u>", device);
   return(NULL);
}
void xraudio_hal_input_close(xraudio_hal_input_obj_t obj) {
   XLOGD_INFO("xraudio_hal_input_close");
}
uint32_t xraudio_hal_input_buffer_size_get(xraudio_hal_input_obj_t obj) {
   XLOGD_INFO("xraudio_hal_input_close");
   return(0);
}
int32_t xraudio_hal_input_read(xraudio_hal_input_obj_t obj, uint8_t *data, uint32_t size, xraudio_eos_event_t *eos_event) {
   XLOGD_INFO("xraudio_hal_input_read");
   return(0);
}
bool xraudio_hal_input_mute(xraudio_hal_input_obj_t obj, xraudio_devices_input_t device, bool enable) {
   XLOGD_INFO("xraudio_hal_input_mute <%s>", enable ? "enabled" : "disabled");
   return(true);
}
bool xraudio_hal_input_focus(xraudio_hal_input_obj_t obj, xraudio_sdf_mode_t mode) {
   XLOGD_INFO("xraudio_hal_input_focus: mode <%d>", mode);
   return(true);
}
bool xraudio_hal_input_stats(xraudio_hal_input_obj_t obj, xraudio_hal_input_stats_t *input_stats, bool reset) {
   XLOGD_INFO("xraudio_hal_input_stats");
   return(true);
}
bool xraudio_hal_input_detection(xraudio_hal_input_obj_t obj, uint32_t chan, bool *ignore) {
   XLOGD_INFO("xraudio_hal_input_detection");
   return(true);
}
bool xraudio_hal_input_eos_cmd(xraudio_hal_input_obj_t obj, xraudio_eos_cmd_t cmd, uint32_t chan) {
   XLOGD_INFO("xraudio_hal_input_eos_cmd");
   return(true);
}
bool xraudio_hal_input_stream_params_get(xraudio_hal_input_obj_t obj, xraudio_hal_stream_params_t *stream_params) {
   XLOGD_INFO("xraudio_hal_input_stream_params_get");
   return(true);
}
bool xraudio_hal_input_stream_start_set(xraudio_hal_input_obj_t obj, uint32_t start_sample) {
   XLOGD_INFO("xraudio_hal_input_stream_start_set");
   return(true);
}
bool xraudio_hal_input_keyword_detector_reset(xraudio_hal_input_obj_t obj) {
   XLOGD_INFO("xraudio_hal_input_keyword_detector_reset");
   return(true);
}
bool xraudio_hal_input_test_mode(xraudio_hal_input_obj_t obj, bool enable) {
   XLOGD_INFO("xraudio_hal_input_test_mode");
   return(true);
}
bool xraudio_hal_input_stream_latency_set(xraudio_hal_input_obj_t obj, xraudio_stream_latency_mode_t latency_mode) {
   XLOGD_INFO("xraudio_hal_input_stream_latency_set");
   return(true);
}

