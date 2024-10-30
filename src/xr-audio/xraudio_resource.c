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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>
#include "xraudio.h"
#include "xraudio_private.h"

#define XRAUDIO_RESOURCE_UPDATE_INTERVAL (5) // Time interval (in seconds) to poll for updates to handle processes that exit while holding resources

//#define XRAUDIO_RESOURCE_DEBUG

typedef struct {
   bool                             running;
   pid_t                            pid;
   xr_mq_t                          msgq;
   rdkx_timer_object_t              timer_obj;
   rdkx_timer_id_t                  timer_resource_update;
   int                              fifo;
   uint8_t                          user_id;
   xraudio_shared_mem_t *           shared_mem;
   xraudio_object_t                 object;
   resource_notification_callback_t callback;
   void *                           cb_param;
   xraudio_resource_entry_t *       entry;
} xraudio_resource_params_t;

typedef void (*xraudio_rsrc_msg_handler_t)(xraudio_resource_params_t *params, void *msg);

static void timer_resource_update(void *data);
static void resource_request_grant_inform(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry);
static void resource_request_grant(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry);
static void resource_request_release(xraudio_resource_params_t *params);
static void resource_request_revoke_inform(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry);
static void resource_request_revoke(xraudio_resource_params_t *params);
static void resource_request_update(xraudio_resource_params_t *params);
static void resource_request_list_scrub(xraudio_resource_params_t *params);

#ifdef XRAUDIO_RESOURCE_DEBUG
static void resource_entries_print(xraudio_resource_params_t *params);
#endif

static void resource_entry_add(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry);
static void resource_entry_remove(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry, bool locked);
static xraudio_resource_entry_t *resource_entry_malloc(xraudio_resource_params_t *params);
static void                      resource_entry_free(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry, bool locked);

static void xraudio_resource_list_insert_head(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry);
static void xraudio_resource_list_insert_after(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry, xraudio_resource_entry_t *new_entry);
static void xraudio_resource_list_remove(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry);

static xraudio_resource_id_input_t  resource_allocate_record(xraudio_shared_mem_t *shared_mem);
static xraudio_resource_id_output_t resource_allocate_playback(xraudio_shared_mem_t *shared_mem, xraudio_devices_output_t req_output);
static void                         resource_free_record(xraudio_shared_mem_t *shared_mem, xraudio_resource_id_input_t id);
static void                         resource_free_playback(xraudio_shared_mem_t *shared_mem, xraudio_resource_id_output_t id);

static bool process_exists(pid_t pid);

static void xraudio_rsrc_msg_resource_request(xraudio_resource_params_t *params, void *msg);
static void xraudio_rsrc_msg_resource_release(xraudio_resource_params_t *params, void *msg);
static void xraudio_rsrc_msg_resource_grant(xraudio_resource_params_t *params, void *msg);
static void xraudio_rsrc_msg_resource_revoke(xraudio_resource_params_t *params, void *msg);
static void xraudio_rsrc_msg_terminate(xraudio_resource_params_t *params, void *msg);

static const xraudio_rsrc_msg_handler_t g_xraudio_rsrc_msg_handlers[XRAUDIO_RSRC_QUEUE_MSG_TYPE_INVALID] = {
   xraudio_rsrc_msg_resource_request,
   xraudio_rsrc_msg_resource_release,
   xraudio_rsrc_msg_resource_grant,
   xraudio_rsrc_msg_resource_revoke,
   xraudio_rsrc_msg_terminate
};

void xraudio_resource_list_init(xraudio_shared_mem_t *shared_mem) {
   for(uint8_t index = 0; index < XRAUDIO_RESOURCE_ID_OUTPUT_INVALID; index++) {
      shared_mem->resource_playback[index] = false;
   }
   for(uint8_t index = 0; index < XRAUDIO_RESOURCE_ID_INPUT_INVALID; index++) {
      shared_mem->resource_record[index]   = false;
   }

   shared_mem->resource_list_offset_head = 0; // Initialize the list.
   for(uint8_t index = 0; index < XRAUDIO_RESOURCE_LIST_QTY_MAX; index++) {
      shared_mem->resource_list[index].offset_next = 0;
      resource_entry_free(NULL, &shared_mem->resource_list[index], true);
   }

   xraudio_hal_capabilities_get(&shared_mem->capabilities);
}

xraudio_resource_entry_t *xraudio_resource_list_get_head(xraudio_shared_mem_t *shared_mem) {
   if(shared_mem->resource_list_offset_head == 0) {
      return(NULL);
   }
   return((xraudio_resource_entry_t *)(((uint8_t*)shared_mem) + shared_mem->resource_list_offset_head));
}

xraudio_resource_entry_t *xraudio_resource_list_get_next(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry) {
   if(entry->offset_next == 0) {
      return(NULL);
   }
   return((xraudio_resource_entry_t *)(((uint8_t*)shared_mem) + entry->offset_next));
}

void xraudio_resource_list_insert_head(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry) {
   uint32_t offset = ((uint8_t*)entry) - ((uint8_t*)shared_mem);

   entry->offset_next                    = shared_mem->resource_list_offset_head;
   shared_mem->resource_list_offset_head = offset;
}

void xraudio_resource_list_insert_after(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry, xraudio_resource_entry_t *new_entry) {
   uint32_t offset = ((uint8_t*)new_entry) - ((uint8_t*)shared_mem);
   new_entry->offset_next = entry->offset_next;
   entry->offset_next     = offset;
}

void xraudio_resource_list_remove(xraudio_shared_mem_t *shared_mem, xraudio_resource_entry_t *entry) {
   uint32_t offset = ((uint8_t*)entry) - ((uint8_t*)shared_mem);
   
   if(offset == shared_mem->resource_list_offset_head) {
      shared_mem->resource_list_offset_head = entry->offset_next;
   } else {
      // Locate previous entry
      xraudio_resource_entry_t *prev_entry;
      for(prev_entry = xraudio_resource_list_get_head(shared_mem); prev_entry != NULL; prev_entry = xraudio_resource_list_get_next(shared_mem, prev_entry)) {
         if(prev_entry->offset_next == offset) {
            break;
         }
      }
      if(prev_entry == NULL) {
         XLOGD_ERROR("Not found in list");
      } else {
         prev_entry->offset_next = entry->offset_next;
      }
   }
   entry->offset_next = 0;
}

void *xraudio_resource_thread(void *param) {
   xraudio_resource_thread_params_t thread_params = *((xraudio_resource_thread_params_t *)param);
   xraudio_resource_params_t               params;
   char msg[XRAUDIO_MSG_QUEUE_MSG_SIZE_MAX];
   XLOGD_DEBUG("Started");
   
   params.running               = true;
   params.pid                   = getpid();
   params.msgq                  = thread_params.msgq;
   params.fifo                  = thread_params.fifo;
   params.user_id               = thread_params.user_id;
   params.shared_mem            = thread_params.shared_mem;
   params.object                = NULL;
   params.callback              = NULL;
   params.cb_param              = NULL;
   params.entry                 = NULL;
   params.timer_obj             = rdkx_timer_create(4, true, true);
   params.timer_resource_update = RDXK_TIMER_ID_INVALID;

   // Unblock the caller that launched this thread
   sem_post(thread_params.semaphore);

   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("Enter main loop");
   #endif
   do {
      int src;
      int nfds = (params.fifo > params.msgq) ? params.fifo + 1 :  params.msgq + 1;
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(params.msgq, &rfds);
      if(params.fifo >= 0) {
         FD_SET(params.fifo, &rfds);
      }

      struct timeval tv;
      rdkx_timer_handler_t handler = NULL;
      void *data = NULL;
      rdkx_timer_id_t timer_id = rdkx_timer_next_get(params.timer_obj, &tv, &handler, &data);

      errno = 0;
      if(timer_id >= 0) {
         src = select(nfds, &rfds, NULL, NULL, &tv);
      } else {
         src = select(nfds, &rfds, NULL, NULL, NULL);
      }

      if(src < 0) { // error occurred
         if(errno == EINTR) {
            continue;
         } else {
            int errsv = errno;
            XLOGD_ERROR("select failed <%s>", strerror(errsv));
            break;
         }
      }
      
      if(src == 0) { // Timeout
         if(data == NULL) {
            XLOGD_ERROR("timeout data invalid");
            if(!rdkx_timer_remove(params.timer_obj, timer_id)) {
               XLOGD_ERROR("timer remove");
            }
         } else {
            (*handler)(data);
         }
         continue;
      }
      if(FD_ISSET(params.msgq, &rfds)) {      // Process message queue if it is ready
         xr_mq_msg_size_t bytes_read = xr_mq_pop(params.msgq, msg, sizeof(msg));
         if(bytes_read <= 0) {
            XLOGD_ERROR("xr_mq_pop failed <%d>", bytes_read);
         } else {
            xraudio_rsrc_queue_msg_header_t *header = (xraudio_rsrc_queue_msg_header_t *)msg;

            if((uint32_t)header->type >= XRAUDIO_RSRC_QUEUE_MSG_TYPE_INVALID) {
               XLOGD_ERROR("invalid msg type <%s>", xraudio_rsrc_queue_msg_type_str(header->type));
            } else {
               (*g_xraudio_rsrc_msg_handlers[header->type])(&params, msg);
            }
         }
      }
      if(FD_ISSET(params.fifo, &rfds)) {      // Process fifo if it is ready
         errno = 0;
         ssize_t bytes_read = read(params.fifo, msg, sizeof(msg));
         if(bytes_read <= 0) {
            int errsv = errno;
            XLOGD_ERROR("fifo read failed <%d> <%s>", bytes_read, strerror(errsv));
         } else if(bytes_read == 0) {
            XLOGD_ERROR("fifo read EOF");
            params.fifo = -1;
         } else {
            xraudio_rsrc_queue_msg_header_t *header = (xraudio_rsrc_queue_msg_header_t *)msg;

            if((uint32_t)header->type >= XRAUDIO_RSRC_QUEUE_MSG_TYPE_INVALID) {
               XLOGD_ERROR("invalid msg type <%s>", xraudio_rsrc_queue_msg_type_str(header->type));
            } else {
               (*g_xraudio_rsrc_msg_handlers[header->type])(&params, msg);
            }
         }
      }
   } while(params.running);


   rdkx_timer_destroy(params.timer_obj);

   return(NULL);
}

void xraudio_rsrc_msg_resource_request(xraudio_resource_params_t *params, void *msg) {
   xraudio_queue_msg_resource_request_t *request = (xraudio_queue_msg_resource_request_t *)msg;
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("pid <%d>", params->pid);
   #endif

   params->object     = request->object;
   params->callback   = request->callback;
   params->cb_param   = request->cb_param;

   resource_request_list_scrub(params);

   if(params->entry != NULL) { // Remove current entry from the list
      resource_entry_remove(params, params->entry, false);
   } else { // Allocate a list entry
      params->entry = resource_entry_malloc(params);
   }
   if(params->entry == NULL) {
      XLOGD_ERROR("Unable to allocate list entry");
   } else { // Add the resource entry to the list
      params->entry->priority       = request->priority;
      params->entry->pid            = params->pid;
      params->entry->msgq           = params->msgq;
      params->entry->user_id        = params->user_id;
      params->entry->req_input      = request->input;
      params->entry->req_output     = request->output;

      resource_entry_add(params, params->entry);
      #ifdef XRAUDIO_RESOURCE_DEBUG
      resource_entries_print(params);
      #endif
      resource_request_update(params);

      // Set the request pending timer so the thread will poll periodically to
      // remove resource owners/requests when their process ends
      rdkx_timestamp_t timeout;
      rdkx_timestamp_get(&timeout);
      rdkx_timestamp_add_secs(&timeout, XRAUDIO_RESOURCE_UPDATE_INTERVAL);

      if(params->timer_resource_update == RDXK_TIMER_ID_INVALID) {
         params->timer_resource_update = rdkx_timer_insert(params->timer_obj, timeout, timer_resource_update, params);
      } else {
         rdkx_timer_update(params->timer_obj, params->timer_resource_update, timeout);
      }
   }
}

void xraudio_rsrc_msg_resource_release(xraudio_resource_params_t *params, void *msg) {
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("pid <%d>", params->pid);
   #endif
   resource_request_list_scrub(params);
   resource_request_release(params);
   #ifdef XRAUDIO_RESOURCE_DEBUG
   resource_entries_print(params);
   #endif
   resource_request_update(params);
   if(params->timer_resource_update != RDXK_TIMER_ID_INVALID) {
      rdkx_timer_remove(params->timer_obj, params->timer_resource_update);
      params->timer_resource_update = RDXK_TIMER_ID_INVALID;
   }
}

void xraudio_rsrc_msg_resource_grant(xraudio_resource_params_t *params, void *msg) {
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("pid <%d>", params->pid);
   #endif
   resource_request_grant(params, params->entry);
   if(params->timer_resource_update != RDXK_TIMER_ID_INVALID) {
      rdkx_timer_remove(params->timer_obj, params->timer_resource_update);
      params->timer_resource_update = RDXK_TIMER_ID_INVALID;
   }
}

void xraudio_rsrc_msg_resource_revoke(xraudio_resource_params_t *params, void *msg) {
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("pid <%d> msgq %d user id %u cb %p", params->pid, params->msgq, params->user_id, params->callback);
   #endif
   resource_request_revoke(params);
}

void xraudio_rsrc_msg_terminate(xraudio_resource_params_t *params, void *msg) {
   xraudio_rsrc_queue_msg_terminate_t *terminate = (xraudio_rsrc_queue_msg_terminate_t *)msg;
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("pid <%d>", params->pid);
   #endif
   sem_post(terminate->semaphore);
   params->running = false;
}

void timer_resource_update(void *data) {
   xraudio_resource_params_t *params = (xraudio_resource_params_t *)data;
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("[%d]", params->pid);
   #endif
   resource_request_list_scrub(params);
   resource_request_update(params);

   // Update the timeout
   rdkx_timestamp_t timeout;
   rdkx_timestamp_get(&timeout);
   rdkx_timestamp_add_secs(&timeout, XRAUDIO_RESOURCE_UPDATE_INTERVAL);

   rdkx_timer_update(params->timer_obj, params->timer_resource_update, timeout);
}

void resource_request_release(xraudio_resource_params_t *params) {
   // Remove request from the list
   resource_entry_remove(params, params->entry, false);
   resource_entry_free(params, params->entry, false);
   params->entry = NULL;
}

void resource_request_revoke(xraudio_resource_params_t *params) {
   // Call the callback to release the resources
   params->callback(XRAUDIO_RESOURCE_EVENT_REVOKED, params->cb_param);
}

void resource_request_update(xraudio_resource_params_t *params) {
   XRAUDIO_SHARED_MEM_LOCK(params->object);
   xraudio_resource_entry_t *head = xraudio_resource_list_get_head(params->shared_mem);
   
   if(head == NULL) {
      #ifdef XRAUDIO_RESOURCE_DEBUG
      XLOGD_INFO("empty list");
      #endif
      XRAUDIO_SHARED_MEM_UNLOCK(params->object);
      return;
   }
   #ifdef SINGLE_PROCESS_OWNER
   pid_t owner_pid = head->pid;
   #endif
   uint8_t playback_cnt      = 0;
   uint8_t record_cnt        = 0;
   bool    resources_revoked = false;
   
   // Add head entry's playback and record resource requests (regardless if they are allocated)
   if(head->req_input != XRAUDIO_DEVICE_INPUT_NONE) {
      record_cnt++;
   }
   if(head->req_output != XRAUDIO_DEVICE_OUTPUT_NONE) {
      playback_cnt++;
   }
   
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("capabilities input <%u> output <%u>", params->shared_mem->capabilities.input_qty, params->shared_mem->capabilities.output_qty);
   XLOGD_INFO("record_cnt <%u> playback_cnt <%u>", record_cnt, playback_cnt);
   #endif

   // Traverse list (after head entry) and send revokes to free resources
   for(xraudio_resource_entry_t *entry = xraudio_resource_list_get_next(params->shared_mem, head); entry != NULL; entry = xraudio_resource_list_get_next(params->shared_mem, entry)) {
      #ifdef XRAUDIO_RESOURCE_DEBUG
      XLOGD_INFO("entry pid <%d> id record <%s> playback <%s>", entry->pid, xraudio_resource_id_input_str(entry->id_record), xraudio_resource_id_output_str(entry->id_playback));
      #endif
      #ifdef SINGLE_PROCESS_OWNER
      if(entry->pid != owner_pid) {
         if(entry->id_record < XRAUDIO_RESOURCE_ID_INPUT_INVALID || entry->id_playback < XRAUDIO_RESOURCE_ID_OUTPUT_INVALID) {
            // Revoke the resources
            if(!entry->notified) {
               entry->notified = true;
               resource_request_revoke_inform(params, entry);
            }
            resources_revoked = true;
            continue;
         }
      }
      #endif
      if(entry->id_record < XRAUDIO_RESOURCE_ID_INPUT_INVALID) {
         if(record_cnt < params->shared_mem->capabilities.input_qty) {
            record_cnt++;
         } else { // Revoke the resources
            if(!entry->notified) {
               entry->notified = true;
               resource_request_revoke_inform(params, entry);
            #ifdef XRAUDIO_RESOURCE_DEBUG
            } else {
            XLOGD_INFO("already notified");
            #endif
            }
            resources_revoked = true;
            continue;
         }
      }
      if(entry->id_playback < XRAUDIO_RESOURCE_ID_OUTPUT_INVALID) {
         if(playback_cnt < params->shared_mem->capabilities.output_qty) {
            playback_cnt++;
         } else { // Revoke the resources
            if(!entry->notified) {
               entry->notified = true;
               resource_request_revoke_inform(params, entry);
            }
            resources_revoked = true;
            continue;
         }
      }
   }
   
   if(resources_revoked) { // Wait for resource owners to release the resources
      #ifdef XRAUDIO_RESOURCE_DEBUG
      XLOGD_INFO("wait for resources to be released");
      #endif
      XRAUDIO_SHARED_MEM_UNLOCK(params->object);
      return;
   }
   
   // Traverse list (including head entry) and send grants to resource requests
   playback_cnt = 0;
   record_cnt   = 0;
   for(xraudio_resource_entry_t *entry = head; entry != NULL; entry = xraudio_resource_list_get_next(params->shared_mem, entry)) {
      #ifdef SINGLE_PROCESS_OWNER
      // Skip over requests from processes that don't match the head pid
      if(entry->pid != owner_pid) {
         continue;
      }
      #endif
      
      if(entry->id_record < XRAUDIO_RESOURCE_ID_INPUT_INVALID || entry->id_playback < XRAUDIO_RESOURCE_ID_OUTPUT_INVALID) {
         // Resources have already been allocated
         record_cnt   += (entry->id_record   < XRAUDIO_RESOURCE_ID_INPUT_INVALID)   ? 1 : 0;
         playback_cnt += (entry->id_playback < XRAUDIO_RESOURCE_ID_OUTPUT_INVALID) ? 1 : 0;
         continue;
      }
      
      // TODO Need to grant resources based on capabilities instead of treating them all the same
      
      if((entry->req_input != XRAUDIO_DEVICE_INPUT_NONE) && (entry->req_output != XRAUDIO_DEVICE_OUTPUT_NONE)) { // Entry wants microphone and speaker
         if((record_cnt < params->shared_mem->capabilities.input_qty) && (playback_cnt < params->shared_mem->capabilities.output_qty)) {
            // Grant the resources to the requester if not already notified
            if(!entry->notified) {
               entry->notified     = true;
               entry->id_record    = resource_allocate_record(params->shared_mem);
               entry->id_playback  = resource_allocate_playback(params->shared_mem, entry->req_output);
               resource_request_grant_inform(params, entry);
            }
            record_cnt++;
            playback_cnt++;
         }
      } else if(entry->req_input != XRAUDIO_DEVICE_INPUT_NONE) { // Entry wants just microphone
         if(record_cnt < params->shared_mem->capabilities.input_qty) {
            // Grant the resources to the requester if not already notified
            if(!entry->notified) {
               entry->notified = true;
               entry->id_record    = resource_allocate_record(params->shared_mem);
               entry->id_playback  = XRAUDIO_RESOURCE_ID_OUTPUT_INVALID;
               resource_request_grant_inform(params, entry);
            }
            record_cnt++;
         }
      } else if(entry->req_output != XRAUDIO_DEVICE_OUTPUT_NONE) { // Entry wants just speaker
         if(playback_cnt < params->shared_mem->capabilities.output_qty) {
            // Grant the resources to the requester if not already notified
            if(!entry->notified) {
               entry->notified = true;
               entry->id_record    = XRAUDIO_RESOURCE_ID_INPUT_INVALID;
               entry->id_playback  = resource_allocate_playback(params->shared_mem, entry->req_output);
               resource_request_grant_inform(params, entry);
            }
            playback_cnt++;
         }
      }
      //XLOGD_INFO("req_microphone = %d, req_output = %d, record_cnt = %d, playback_cnt = %d", entry->req_microphone, entry->req_output, record_cnt, playback_cnt);
      //XLOGD_INFO("id_record = %d, id_playback = %d", entry->id_record, entry->id_playback);
   }
   XRAUDIO_SHARED_MEM_UNLOCK(params->object);
}

xraudio_resource_id_input_t resource_allocate_record(xraudio_shared_mem_t *shared_mem) {
   for(uint8_t index = 0; index < XRAUDIO_RESOURCE_ID_INPUT_INVALID; index++) {
      if(!shared_mem->resource_record[index]) {
         shared_mem->resource_record[index] = true;
         return((xraudio_resource_id_input_t)index);
      }
   }
   return(XRAUDIO_RESOURCE_ID_INPUT_INVALID);
}

xraudio_resource_id_output_t resource_allocate_playback(xraudio_shared_mem_t *shared_mem, xraudio_devices_output_t req_output) {
   // Allocate playback resources in decending order. Allocate Playback 1 as last resort except for HFP.
   for(int8_t index = (XRAUDIO_RESOURCE_ID_OUTPUT_INVALID - 1); index >= 0; index--) {
      //XLOGD_INFO("req_output= %d, index = %d, output_caps = 0x%x, playback = %d", req_output, index, shared_mem->capabilities.output_caps[index], shared_mem->resource_playback[index]);
      if(!shared_mem->resource_playback[index]) {
         switch(req_output) {
         case XRAUDIO_DEVICE_OUTPUT_HFP:
             if(shared_mem->capabilities.output_caps[index] & XRAUDIO_CAPS_OUTPUT_OFFLOAD) {
                shared_mem->resource_playback[index] = true;
                XLOGD_INFO("HFP playback resource %d", index);
                return((xraudio_resource_id_output_t)index);
             } else {
                continue;
             }
             break;
         case XRAUDIO_DEVICE_OUTPUT_NORMAL:
             if(shared_mem->capabilities.output_caps[index] & XRAUDIO_CAPS_OUTPUT_DIRECT_PCM) {
                shared_mem->resource_playback[index] = true;
                XLOGD_INFO("NORMAL playback resource %d", index);
                return((xraudio_resource_id_output_t)index);
             } else {
                continue;
             }
             break;
         default:
             continue;
             break;
         }
      }
   }
   return(XRAUDIO_RESOURCE_ID_OUTPUT_INVALID);
}

void resource_free_record(xraudio_shared_mem_t *shared_mem, xraudio_resource_id_input_t id) {
   if(id >= 0 && id < XRAUDIO_RESOURCE_ID_INPUT_INVALID) {
      shared_mem->resource_record[id] = false;
   }
}

void resource_free_playback(xraudio_shared_mem_t *shared_mem, xraudio_resource_id_output_t id) {
   if(id >= 0 && id < XRAUDIO_RESOURCE_ID_OUTPUT_INVALID) {
      shared_mem->resource_playback[id] = false;
   }
}

void resource_request_grant_inform(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry) {
   // Dispatch the grant to the owner's queue
   xraudio_rsrc_queue_msg_generic_t msg;
   msg.header.type = XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_GRANT;

   if(params->pid == entry->pid) { // requester is in this process, use the existing msgq
      #ifdef XRAUDIO_RESOURCE_DEBUG
      XLOGD_INFO("Notify SAME process %d queue %d", entry->pid, entry->msgq);
      #endif
      queue_msg_push(entry->msgq, (const char *)&msg, sizeof(msg));
   } else {
      char name[XRAUDIO_FIFO_NAME_LENGTH_MAX];
      xraudio_resource_fifo_name_get(name, entry->user_id);
      
      errno = 0;
      int fifo = open(name, O_WRONLY);
      if(fifo < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to open fifo <%s> <%s>", name, strerror(errsv));
      } else {
         #ifdef XRAUDIO_RESOURCE_DEBUG
         XLOGD_INFO("Notify OTHER process %d fifo name <%s> id %d", entry->pid, name, entry->msgq);
         #endif
         write(fifo, &msg, sizeof(msg));
         close(fifo);
      }
   }
}

void resource_request_revoke_inform(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry) {
   // Dispatch the revoke to the owner's queue
   xraudio_rsrc_queue_msg_generic_t msg;
   msg.header.type = XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_REVOKE;

   if(params->pid == entry->pid) { // owner is in this process, use the existing msgq
      #ifdef XRAUDIO_RESOURCE_DEBUG
      XLOGD_INFO("Notify SAME process %d queue %d", entry->pid, entry->msgq);
      #endif
      queue_msg_push(entry->msgq, (const char *)&msg, sizeof(msg));
   } else {
      char name[XRAUDIO_FIFO_NAME_LENGTH_MAX];
      xraudio_resource_fifo_name_get(name, entry->user_id);

      #ifdef XRAUDIO_RESOURCE_DEBUG
      XLOGD_INFO("Notify OTHER process %d fifo name <%s>", entry->pid, name);
      #endif

      errno = 0;
      int fifo = open(name, O_RDWR);
      if(fifo < 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to open fifo <%s> <%s>", name, strerror(errsv));
      } else {
         write(fifo, &msg, sizeof(msg));
         close(fifo);
      }
   }
}

void resource_request_grant(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry) {
   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("GRANTED <%s> <%s>", xraudio_resource_id_input_str(entry->id_record), xraudio_resource_id_output_str(entry->id_playback));
   #endif
   // Mark the entry as owned
   entry->notified = false;
   
   uint16_t caps_record   = (entry->id_record   >= params->shared_mem->capabilities.input_qty)   ? XRAUDIO_CAPS_INPUT_NONE   : params->shared_mem->capabilities.input_caps[entry->id_record];
   uint16_t caps_playback = (entry->id_playback >= params->shared_mem->capabilities.output_qty) ? XRAUDIO_CAPS_OUTPUT_NONE : params->shared_mem->capabilities.output_caps[entry->id_playback];

   // Mark the appropriate resources as allocated in the xraudio object
   xraudio_resource_grant(params->object, entry->id_record, entry->id_playback, caps_record, caps_playback);
   
   // Call the callback with the resource granted message
   params->callback(XRAUDIO_RESOURCE_EVENT_GRANTED, params->cb_param);
}

// Remove stale entries as would occur when a process exits without releasing resources
void resource_request_list_scrub(xraudio_resource_params_t *params) {
   pid_t pid;
   XRAUDIO_SHARED_MEM_LOCK(params->object);
   for(xraudio_resource_entry_t *entry = xraudio_resource_list_get_head(params->shared_mem); entry != NULL; entry = xraudio_resource_list_get_next(params->shared_mem, entry)) {
      pid = entry->pid;
      XLOGD_DEBUG("Checking pid %d", pid);
      if(pid > 0 && !process_exists(pid)) { // Process is no longer running
         #ifdef XRAUDIO_RESOURCE_DEBUG
         XLOGD_INFO("Removed stale request list entry - pid %d", pid);
         #endif
         resource_entry_remove(params, entry, true);
         resource_entry_free(params, entry, true);
      }
   }
   XRAUDIO_SHARED_MEM_UNLOCK(params->object);
}

xraudio_resource_entry_t *resource_entry_malloc(xraudio_resource_params_t *params) {
   XRAUDIO_SHARED_MEM_LOCK(params->object);
   xraudio_resource_entry_t *entry = params->shared_mem->resource_list;
   for(uint8_t index = 0; index < XRAUDIO_RESOURCE_LIST_QTY_MAX; index++) {
      // Check the priority which is used to indicate that the entry is being used
      if(entry[index].priority >= XRAUDIO_RESOURCE_PRIORITY_INVALID) {
         XRAUDIO_SHARED_MEM_UNLOCK(params->object);
         return(&entry[index]);
      }
   }
   XRAUDIO_SHARED_MEM_UNLOCK(params->object);
   XLOGD_ERROR("Out of resource list entries!");
   return(NULL);
}

#ifdef XRAUDIO_RESOURCE_DEBUG
void resource_entries_print(xraudio_resource_params_t *params) {
   XRAUDIO_SHARED_MEM_LOCK(params->object);
   XLOGD_INFO("BEGIN %p", xraudio_resource_list_get_head(params->shared_mem));
   for(xraudio_resource_entry_t *entry = xraudio_resource_list_get_head(params->shared_mem); entry != NULL; entry = xraudio_resource_list_get_next(params->shared_mem, entry)) {
      XLOGD_INFO("%p Priority <%s> Pid %d msgq %d", entry, xraudio_resource_priority_str(entry->priority), entry->pid, entry->msgq);
   }
   XLOGD_INFO("END");
   XRAUDIO_SHARED_MEM_UNLOCK(params->object);
}
#endif

void resource_entry_add(xraudio_resource_params_t *params, xraudio_resource_entry_t *new_entry) {
   XRAUDIO_SHARED_MEM_LOCK(params->object);
   xraudio_resource_entry_t *head = xraudio_resource_list_get_head(params->shared_mem);
   
   if(head == NULL) {
      #ifdef XRAUDIO_RESOURCE_DEBUG
      XLOGD_INFO("Add EMPTY %p", new_entry);
      #endif
      xraudio_resource_list_insert_head(params->shared_mem, new_entry);
      XRAUDIO_SHARED_MEM_UNLOCK(params->object);
      return;
   }
   
   xraudio_resource_entry_t *last_entry = NULL;
   for(xraudio_resource_entry_t *entry = head; entry != NULL; entry = xraudio_resource_list_get_next(params->shared_mem, entry)) {
      if(new_entry->priority > entry->priority) {
         if(entry == head) {
            #ifdef XRAUDIO_RESOURCE_DEBUG
            XLOGD_INFO("Add HEAD %p", new_entry);
            #endif
            xraudio_resource_list_insert_head(params->shared_mem, new_entry);
            XRAUDIO_SHARED_MEM_UNLOCK(params->object);
            return;
         } else {
            #ifdef XRAUDIO_RESOURCE_DEBUG
            XLOGD_INFO("Add AFTER %p", new_entry);
            #endif
            xraudio_resource_list_insert_after(params->shared_mem, entry, new_entry);
            XRAUDIO_SHARED_MEM_UNLOCK(params->object);
            return;
         }
      }
      last_entry = entry;
   }

   #ifdef XRAUDIO_RESOURCE_DEBUG
   XLOGD_INFO("Add TAIL %p", new_entry);
   #endif
   xraudio_resource_list_insert_after(params->shared_mem, last_entry, new_entry);
   XRAUDIO_SHARED_MEM_UNLOCK(params->object);
}

void resource_entry_remove(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry, bool locked) {
   if(!locked) { XRAUDIO_SHARED_MEM_LOCK(params->object); }
   xraudio_resource_list_remove(params->shared_mem, entry);
   if(!locked) { XRAUDIO_SHARED_MEM_UNLOCK(params->object); }
}

void resource_entry_free(xraudio_resource_params_t *params, xraudio_resource_entry_t *entry, bool locked) {
   if(entry) { // Mark the entry as invalid
      if(!locked) { XRAUDIO_SHARED_MEM_LOCK(params->object); }
      entry->priority       = XRAUDIO_RESOURCE_PRIORITY_INVALID;
      entry->pid            = -1;
      entry->msgq           = -1;
      entry->user_id        = XRAUDIO_USER_ID_MAX;
      entry->notified       = false;
      entry->req_input      = XRAUDIO_DEVICE_INPUT_NONE;
      entry->req_output     = XRAUDIO_DEVICE_OUTPUT_NONE;
      if(params != NULL) {
         resource_free_record(params->shared_mem, entry->id_record);
         resource_free_playback(params->shared_mem, entry->id_playback);
      }
      entry->id_record      = XRAUDIO_RESOURCE_ID_INPUT_INVALID;
      entry->id_playback    = XRAUDIO_RESOURCE_ID_OUTPUT_INVALID;
      if(!locked) { XRAUDIO_SHARED_MEM_UNLOCK(params->object); }
   }
}

bool process_exists(pid_t pid) {
   if(kill(pid, 0) == 0) {
      return(true);
   }
   return(false);
}
