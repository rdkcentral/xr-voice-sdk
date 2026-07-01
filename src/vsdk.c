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
   void                     *mfv_handle;
   bool                      hal_in_enabled;
   bool                      hal_out_enabled;
   bool                      mfv_enabled;
   xraudio_hal_plugin_api_t *hal_plugin;
   xraudio_kwd_plugin_api_t *kwd_plugin;
   xraudio_eos_plugin_api_t *eos_plugin;
   xraudio_dga_plugin_api_t *dga_plugin;
   xraudio_sdf_plugin_api_t *sdf_plugin;
   xraudio_ovc_plugin_api_t *ovc_plugin;
   xraudio_ppr_plugin_api_t *ppr_plugin;
   xraudio_mfv_plugin_api_t *mfv_plugin;
   vsdk_thread_poll_func_t   func;
   void *                    data;
} vsdk_global_t;

static vsdk_global_t g_vsdk;

static void  vsdk_thread_response(void);
static bool  vsdk_file_exists(const char *filename);
static void  vsdk_parse_options(bool *curtail_xlog, bool *curtail_xraudio, bool *xraudio_allow_input_failure);
static bool  vsdk_load_plugin_ffv(vsdk_ffv_plugin_handles_t *handles);
static bool  vsdk_load_plugin_mfv(void);
static void *vsdk_load_plugin_ffv_hal(bool *out_enabled);
static void *vsdk_load_plugin_ffv_kwd(void);
static void *vsdk_load_plugin_ffv_alg(void **handle_ppr);
static void *vsdk_load_plugin_ffv_sdf(void);
static void *vsdk_load_plugin_ffv_ovc(void);

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
   g_vsdk.mfv_enabled                 = vsdk_load_plugin_mfv();

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
   if(g_vsdk.mfv_handle != NULL) {
      XLOGD_INFO("Unloading MFV plugin.");
      if(dlclose(g_vsdk.mfv_handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for MFV <%s>", (err != NULL) ? err : "unknown error");
      }
      g_vsdk.mfv_handle = NULL;
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

xraudio_mfv_plugin_api_t *vsdk_mfv_plugin_get(void) {
   return(g_vsdk.mfv_plugin);
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
      return(false);
   }

   bool ret = false;

   memset(handles, 0, sizeof(*handles));
   do {
      handles->handle_ffv_hal = vsdk_load_plugin_ffv_hal(&g_vsdk.hal_out_enabled);

      if(handles->handle_ffv_hal == NULL) {
         break;
      }

      handles->handle_ffv_kwd  = vsdk_load_plugin_ffv_kwd();

      if(handles->handle_ffv_kwd == NULL) {
         break;
      }

      handles->handle_ffv_alg = vsdk_load_plugin_ffv_alg(&handles->handle_ffv_ppr);

      if(handles->handle_ffv_alg == NULL) {
         break;
      }

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
      if(handles->handle_ffv_kwd != NULL) {
         if(dlclose(handles->handle_ffv_kwd) != 0) {
            const char *err = dlerror();
            XLOGD_ERROR("dlclose failed for FFV KWD <%s>", (err != NULL) ? err : "unknown error");
         }
         handles->handle_ffv_kwd = NULL;
      }
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

void *vsdk_load_plugin_ffv_alg(void **handle_ppr) {
   void *handle = NULL;
   const char *so_path_vd = "/vendor/lib/libxraudio-ffv-algorithms.so";
   const char *so_path_mw = "/usr/lib/libxraudio-ffv-algorithms.so";
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

void *vsdk_load_plugin_ffv_hal(bool *out_enabled) {
   void *handle = NULL;
   const char *so_path_vd = "/vendor/lib/libxraudio-ffv-hal.so";
   const char *so_path_mw = "/usr/lib/libxraudio-ffv-hal.so";
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

   if(error != NULL) {
      XLOGD_ERROR("Required plugin HAL not present, error <%s>", error);
      return(NULL);
   }
   XLOGD_INFO("Loading required plugin HAL.");
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

bool vsdk_load_plugin_mfv(void) {
   bool ret = false;

   void *handle = NULL;
   const char *so_path_vd = "/vendor/lib/libxraudio-mfv.so";
   const char *so_path_mw = "/usr/lib/libxraudio-mfv.so";

   if(vsdk_file_exists(so_path_vd)) {
      handle = dlopen(so_path_vd, RTLD_NOW);
   } else if(vsdk_file_exists(so_path_mw)) {
      handle = dlopen(so_path_mw, RTLD_NOW);
   } else {
      XLOGD_INFO("MFV plugin is not present.");
      return false;
   }

   if(handle == NULL) {
      XLOGD_ERROR("Failed to load MFV plugin <%s>", dlerror());
      return false;
   }

   dlerror();  // Clear any existing error

   xraudio_mfv_plugin_api_get_t plugin_api_get = (xraudio_mfv_plugin_api_get_t)dlsym(handle, "xraudio_mfv_plugin_api_get");
   char *error = dlerror();

   if(error != NULL) {
      XLOGD_ERROR("MFV plugin entry point not found, error <%s>", error);
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for MFV <%s>", (err != NULL) ? err : "unknown error");
      }
      return false;
   }

   XLOGD_INFO("Loading MFV plugin.");
   xraudio_mfv_plugin_api_t *mfv_plugin = plugin_api_get();

   if(mfv_plugin == NULL) {
      XLOGD_ERROR("MFV plugin API get failed");
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for MFV <%s>", (err != NULL) ? err : "unknown error");
      }
      return false;
   }

   // Validate required function pointers
   if(mfv_plugin->object_create         == NULL ||
      mfv_plugin->object_destroy        == NULL ||
      mfv_plugin->session_open          == NULL ||
      mfv_plugin->session_close         == NULL ||
      mfv_plugin->session_info          == NULL ||
      mfv_plugin->session_process_audio == NULL) {
      XLOGD_ERROR("MFV plugin API incomplete");
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for MFV <%s>", (err != NULL) ? err : "unknown error");
      }
      return false;
   }

   // Validate optional function pointers against advertised capabilities
   if((mfv_plugin->capabilities & XRAUDIO_MFV_CAPS_REFERENCE_AUDIO) &&
      (mfv_plugin->reference_audio_open == NULL ||
       mfv_plugin->reference_audio_close == NULL)) {
      XLOGD_ERROR("MFV plugin advertises REFERENCE_AUDIO capability but missing function pointers");
      if(dlclose(handle) != 0) {
         const char *err = dlerror();
         XLOGD_ERROR("dlclose failed for MFV <%s>", (err != NULL) ? err : "unknown error");
      }
      return false;
   }

   XLOGD_INFO("Loaded MFV plugin (API version %u, capabilities 0x%04X).", mfv_plugin->api_version, mfv_plugin->capabilities);

   g_vsdk.mfv_handle = handle;
   g_vsdk.mfv_plugin = mfv_plugin;
   ret = true;

   XLOGD_INFO("MFV plugin loaded");

   return(ret);
}
