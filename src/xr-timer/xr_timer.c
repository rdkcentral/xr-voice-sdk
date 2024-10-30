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
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <semaphore.h>
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRTIMER
#include <rdkx_logger.h>
#include <xr_timestamp.h>
#include <xr_timer.h>

#define RDKX_TIMER_IDENTIFIER (0x4005A1D4)

typedef struct rdkx_timer_entry_s {
   struct rdkx_timer_entry_s *next;
   bool                       in_use;
   rdkx_timer_id_t            timer_id;
   rdkx_timestamp_t           timeout;
   rdkx_timer_handler_t       handler;
   const void *               data;
} rdkx_timer_entry_t;

typedef struct {
   uint32_t            identifier;
   uint32_t            qty_max;
   bool                single_thread;
   bool                thread_id_check;
   pthread_t           thread_id;
   sem_t               semaphore;
   rdkx_timer_entry_t *list_head;
   rdkx_timer_entry_t *entries;
} rdkx_timer_obj_t;

static bool rdkx_timer_obj_is_valid(rdkx_timer_obj_t *obj);
static void rdkx_timer_list_add(rdkx_timer_obj_t *obj, rdkx_timer_id_t timer_id);
static void rdkx_timer_list_remove(rdkx_timer_obj_t *obj, rdkx_timer_id_t timer_id);

#define RDKX_TIMER_MUTEX_WAIT() if(!obj->single_thread) {                                 \
                                   sem_wait(&obj->semaphore);                             \
                                } else if(obj->thread_id_check) {                         \
                                   assert(pthread_equal(obj->thread_id, pthread_self())); \
                                }


#define RDKX_TIMER_MUTEX_POST() if(!obj->single_thread) {     \
                                   sem_post(&obj->semaphore); \
                                }

rdkx_timer_object_t rdkx_timer_create(uint32_t qty, bool single_thread, bool thread_id_check) {
   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)malloc(sizeof(rdkx_timer_obj_t) + (sizeof(rdkx_timer_entry_t) * qty));

   if(obj == NULL) {
      XLOGD_ERROR("Out of memory");
      return(NULL);
   }
   obj->identifier      = RDKX_TIMER_IDENTIFIER;
   obj->qty_max         = qty;
   obj->single_thread   = single_thread;
   obj->thread_id_check = thread_id_check;
   obj->list_head       = NULL;
   obj->entries         = (rdkx_timer_entry_t *)&obj[1];
   
   // intialize the list
   for(uint32_t index = 0; index < obj->qty_max; index++) {
      obj->entries[index].next     = NULL;
      obj->entries[index].timer_id = RDXK_TIMER_ID_INVALID;
      obj->entries[index].in_use   = false;
   }
   memset(obj->entries, 0, sizeof(rdkx_timer_entry_t) * obj->qty_max);
   
   if(!obj->single_thread) { // Semaphore to control access to the object
      sem_init(&obj->semaphore, 0, 0);
   } else { // Store thread id to assert when not called from same thread
      obj->thread_id = pthread_self();
   }
   return(obj);
}

void rdkx_timer_destroy(rdkx_timer_object_t object) {
   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)object;
   if(rdkx_timer_obj_is_valid(obj)) {
      obj->identifier = 0;
      free(obj);
   }
}

bool rdkx_timer_obj_is_valid(rdkx_timer_obj_t *obj) {
   if(obj != NULL && obj->identifier == RDKX_TIMER_IDENTIFIER) {
      RDKX_TIMER_MUTEX_WAIT();
      return(true);
   }
   return(false);
}

rdkx_timer_id_t rdkx_timer_insert(rdkx_timer_object_t object, struct timespec timeout, const rdkx_timer_handler_t handler, const void *data) {
   if(handler == NULL) {
      XLOGD_ERROR("invalid handler");
      return(RDXK_TIMER_ID_INVALID);
   }
   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)object;
   if(!rdkx_timer_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid timer object");
      return(RDXK_TIMER_ID_INVALID);
   }
   
   rdkx_timer_id_t timer_id = RDXK_TIMER_ID_INVALID;
   
   // Find an available timer id
   for(uint32_t index = 0; index < obj->qty_max; index++) {
      if(!obj->entries[index].in_use) {
         timer_id = index;
         break;
      }
   }
   if(timer_id == RDXK_TIMER_ID_INVALID) {
      XLOGD_ERROR("no more timers available");
      RDKX_TIMER_MUTEX_POST();
      return(timer_id);
   }
   
   rdkx_timer_entry_t *entry = &obj->entries[timer_id];
   
   entry->next     = NULL;
   entry->in_use   = true;
   entry->timer_id = timer_id;
   entry->timeout  = timeout;
   entry->handler  = handler;
   entry->data     = data;
   
   // Add the timer to the list in order of timeout
   rdkx_timer_list_add(obj, timer_id);
   
   RDKX_TIMER_MUTEX_POST();
   return(timer_id);
}

bool rdkx_timer_update(rdkx_timer_object_t object, rdkx_timer_id_t timer_id, struct timespec timeout) {
   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)object;
   
   if(!rdkx_timer_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid timer object");
      return(false);
   }

   if((uint32_t)timer_id >= obj->qty_max) {
      XLOGD_ERROR("invalid params");
      RDKX_TIMER_MUTEX_POST();
      return(false);
   }

   // Remove the timer from the list
   rdkx_timer_list_remove(obj, timer_id);
   
   // Update the timeout values
   rdkx_timer_entry_t *entry = &obj->entries[timer_id];
   entry->timeout = timeout;
   
   // Add back to the list
   rdkx_timer_list_add(obj, timer_id);
   
   RDKX_TIMER_MUTEX_POST();
   return(true);
}

bool rdkx_timer_update_handler(rdkx_timer_object_t object, rdkx_timer_id_t timer_id, struct timespec timeout, const rdkx_timer_handler_t handler, const void *data) {
   if(handler == NULL) {
      XLOGD_ERROR("invalid handler");
      return(false);
   }

   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)object;

   if(!rdkx_timer_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid timer object");
      return(false);
   }

   if((uint32_t)timer_id >= obj->qty_max) {
      XLOGD_ERROR("invalid params");
      RDKX_TIMER_MUTEX_POST();
      return(false);
   }

   // Remove the timer from the list
   rdkx_timer_list_remove(obj, timer_id);

   // Update the timeout values
   rdkx_timer_entry_t *entry = &obj->entries[timer_id];
   entry->timeout = timeout;
   entry->handler = handler;
   entry->data    = data;

   // Add back to the list
   rdkx_timer_list_add(obj, timer_id);

   RDKX_TIMER_MUTEX_POST();
   return(true);
}

bool rdkx_timer_remove(rdkx_timer_object_t object, rdkx_timer_id_t timer_id) {
   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)object;

   if(!rdkx_timer_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid timer object");
      return(false);
   }

   if((uint32_t)timer_id >= obj->qty_max) {
      XLOGD_ERROR("invalid params");
      RDKX_TIMER_MUTEX_POST();
      return(false);
   }

   // Remove the timer from the list
   rdkx_timer_list_remove(obj, timer_id);
   
   // Mark the entry as unused
   rdkx_timer_entry_t *entry = &obj->entries[timer_id];
   
   entry->in_use   = false;
   entry->timer_id = RDXK_TIMER_ID_INVALID;
   
   RDKX_TIMER_MUTEX_POST();
   return(true);
}

rdkx_timer_id_t rdkx_timer_next_get(rdkx_timer_object_t object, struct timeval *tv, rdkx_timer_handler_t *handler, void **data) {
   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)object;
   
   if(tv == NULL || data == NULL) {
      XLOGD_ERROR("invalid params");
      return(RDXK_TIMER_ID_INVALID);
   }
   
   if(!rdkx_timer_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid timer object");
      return(RDXK_TIMER_ID_INVALID);
   }
   
   if(obj->list_head == NULL) {
      RDKX_TIMER_MUTEX_POST();
      return(RDXK_TIMER_ID_INVALID);
   }
   
   rdkx_timer_entry_t *entry = obj->list_head;
   
   // Return the timeout time and handler for the next timer
   unsigned long long usecs = rdkx_timestamp_until_us(entry->timeout);
   *handler = entry->handler;
   *data    = (void *)entry->data;
   tv->tv_sec  = usecs / 1000000;
   tv->tv_usec = usecs % 1000000;
   
   RDKX_TIMER_MUTEX_POST();
   return(entry->timer_id);
}

rdkx_timer_id_t rdkx_timer_next_get_ts(rdkx_timer_object_t object, struct timespec *ts, rdkx_timer_handler_t *handler, void **data) {
   rdkx_timer_obj_t *obj = (rdkx_timer_obj_t *)object;

   if(ts == NULL || data == NULL) {
      XLOGD_ERROR("invalid params");
      return(RDXK_TIMER_ID_INVALID);
   }

   if(!rdkx_timer_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid timer object");
      return(RDXK_TIMER_ID_INVALID);
   }

   if(obj->list_head == NULL) {
      RDKX_TIMER_MUTEX_POST();
      return(RDXK_TIMER_ID_INVALID);
   }

   rdkx_timer_entry_t *entry = obj->list_head;

   // Return the timeout time and handler for the next timer
   unsigned long long nsecs = rdkx_timestamp_until_ns(entry->timeout);
   *handler = entry->handler;
   *data    = (void *)entry->data;
   ts->tv_sec  = nsecs / 1000000000;
   ts->tv_nsec = nsecs % 1000000000;

   RDKX_TIMER_MUTEX_POST();
   return(entry->timer_id);
}

void rdkx_timer_list_add(rdkx_timer_obj_t *obj, rdkx_timer_id_t timer_id) {
   rdkx_timer_entry_t *next  = obj->list_head;
   rdkx_timer_entry_t *entry = &obj->entries[timer_id];
   
   if(next == NULL) { // Place at head of list
      obj->list_head = entry;
      entry->next    = NULL;
   } else { // Traverse single linked list
      rdkx_timer_entry_t *prev = NULL;
      while(next != NULL) {
         if(rdkx_timestamp_cmp(entry->timeout, next->timeout) < 0) { // Place timer before this one
            entry->next = next;
            if(prev != NULL) {
               prev->next = entry;
            } else {
               obj->list_head = entry;
            }
            break;
         }
         
         prev = next;
         next = next->next;
      }
      if(next == NULL) { // Place at tail of list
         prev->next  = entry;
         entry->next = NULL;
      }
   }
}

void rdkx_timer_list_remove(rdkx_timer_obj_t *obj, rdkx_timer_id_t timer_id) {
   rdkx_timer_entry_t *next = obj->list_head;
   rdkx_timer_entry_t *prev = NULL;
   
   while(next != NULL) {
      if(next->timer_id == timer_id) {
         if(prev == NULL) { // Removing head
            obj->list_head = next->next;
         } else { // Remove from middle or tail
            prev->next = next->next;
         }
         next->next     = NULL;
         break;
      }
      prev = next;
      next = next->next;
   }
}

