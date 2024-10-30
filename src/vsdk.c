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
#include <xr_voice_sdk.h>
#include <vsdk_version.h>

typedef struct {
   bool                    initialized;
   vsdk_thread_poll_func_t func;
   void *                  data;
} vsdk_global_t;

static vsdk_global_t g_vsdk;

static void vsdk_thread_response(void);

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

int vsdk_init(void) {
   if(g_vsdk.initialized) {
      return(0);
   }
   int rc = xlog_init(XLOG_MODULE_ID_VSDK, NULL, 0);

   if(rc == 0) {
      g_vsdk.initialized = true;
   }
   return(rc);
}

int vsdk_init_user_print(xlog_print_t print, xlog_print_t print_safe) {
   if(g_vsdk.initialized) {
      return(0);
   }
   int rc = xlog_init_user_print(XLOG_MODULE_ID_VSDK, print, print_safe);

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
