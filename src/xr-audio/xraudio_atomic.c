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
#include "xraudio_atomic.h"
#ifdef USE_ATOMIC
int xraudio_atomic_int_get(xraudio_atomic_int_t *atomic) {
    return(atomic_load(atomic));
}

void xraudio_atomic_int_set(xraudio_atomic_int_t *atomic, int new_val) {
    return(atomic_store(atomic, new_val));
}

bool xraudio_atomic_compare_and_set(xraudio_atomic_int_t *atomic, int old_val, int new_val) {
    return(atomic_compare_exchange_strong(atomic, &old_val, new_val));
}
#else
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

int xraudio_atomic_int_get(xraudio_atomic_int_t *atomic) {
    int ret;
    pthread_mutex_lock(&g_mutex);
    ret = *atomic;
    pthread_mutex_unlock(&g_mutex);
    return(ret);
}

void xraudio_atomic_int_set(xraudio_atomic_int_t *atomic, int new_val) {
    pthread_mutex_lock(&g_mutex);
    *atomic = new_val;
    pthread_mutex_unlock(&g_mutex);
}

bool xraudio_atomic_compare_and_set(xraudio_atomic_int_t *atomic, int old_val, int new_val) {
    bool ret = false;
    pthread_mutex_lock(&g_mutex);
    ret = (*atomic == old_val);
    if(ret) {
        *atomic = new_val;
    }
    pthread_mutex_unlock(&g_mutex);
    return(ret);
}
#endif
