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
#ifndef __XRAUDIO_ATOMIC_H__
#define __XRAUDIO_ATOMIC_H__

/* Atomic is only supported by GCC 4.9 or higher */
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
#ifndef __STDC_NO_ATOMICS__
#define USE_ATOMIC
#endif
#endif

#include <stdlib.h>
#include <stdbool.h>
#ifdef USE_ATOMIC
#include <stdatomic.h>

typedef atomic_int xraudio_atomic_int_t;
#else
#warning "STDC Atomics not supported.. Falling back to using pthread implementation."
#include <pthread.h>

typedef volatile int xraudio_atomic_int_t;
#endif

int  xraudio_atomic_int_get(xraudio_atomic_int_t *atomic);
void xraudio_atomic_int_set(xraudio_atomic_int_t *atomic, int new_val);
bool xraudio_atomic_compare_and_set(xraudio_atomic_int_t *atomic, int old_val, int new_val);

#endif
