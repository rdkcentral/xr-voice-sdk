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
#include <sys/stat.h>
#include <xr_voice_sdk.h>
#include <vsdk_version.h>

#define VSDK_VENDOR_OPTIONS_FILE  "/etc/vendor/input/vsdk_options.json"

typedef struct {
   bool                    initialized;
   bool                    curtail_xraudio;
   vsdk_thread_poll_func_t func;
   void *                  data;
} vsdk_global_t;

static vsdk_global_t g_vsdk;

static void vsdk_thread_response(void);
static bool vsdk_file_exists(const char *filename);
static void vsdk_parse_options(bool *curtail_xlog, bool *curtail_xraudio);

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

   xrsr_version_info_t xrsr_version_info[XRSR_VERSION_QTY_MAX];
   memset(xrsr_version_info, 0, sizeof(xrsr_version_info));

   uint32_t qty_xrsr = XRSR_VERSION_QTY_MAX;
   xrsr_version(xrsr_version_info, &qty_xrsr);

   for(uint32_t index = 0; index < qty_xrsr; index++) {
      xrsr_version_info_t *entry = &xrsr_version_info[index];
      version_info->name      = entry->name;
      version_info->version   = entry->version;
      version_info->branch    = entry->branch;
      version_info->commit_id = entry->commit_id;
      version_info++;
      qty_avail--;
   }
   *qty -= qty_avail;
}

int vsdk_init(const char *filename, uint32_t file_size_max) {
   if(g_vsdk.initialized) {
      return(0);
   }

   bool curtail_xlog    = false;
   bool curtail_xraudio = false;

   vsdk_parse_options(&curtail_xlog, &curtail_xraudio);

   int rc = xlog_init(XLOG_MODULE_ID_VSDK, filename, file_size_max, curtail_xlog);

   // Store the value so it can be used when xraudio is initialized
   g_vsdk.curtail_xraudio = curtail_xraudio;

   if(rc == 0) {
      g_vsdk.initialized = true;
   }
   return(rc);
}

int vsdk_init_user_print(xlog_print_t print, xlog_print_t print_safe, const char *filename, uint32_t file_size_max) {
   if(g_vsdk.initialized) {
      return(0);
   }
   
   bool curtail_xlog    = false;
   bool curtail_xraudio = false;

   vsdk_parse_options(&curtail_xlog, &curtail_xraudio);

   int rc = xlog_init_user_print(XLOG_MODULE_ID_VSDK, print, print_safe, filename, file_size_max, curtail_xlog);

   // Store the value so it can be used when xraudio is initialized
   g_vsdk.curtail_xraudio = curtail_xraudio;

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

void vsdk_parse_options(bool *curtail_xlog, bool *curtail_xraudio) {
   bool crtl_xlog    = false;
   bool crtl_xraudio = false;
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
   }
}
