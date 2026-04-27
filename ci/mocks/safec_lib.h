/*
 * If not stated otherwise in this file or this component's license file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Compatibility shim: maps the local safec_lib.h include name to the
 * system libsafec-dev package headers, or provides a minimal dummy API
 * when USE_SAFEC=OFF (SAFEC_DUMMY_API defined by cov_build.sh).
 */
#ifndef _SAFEC_LIB_H_
#define _SAFEC_LIB_H_

#ifdef SAFEC_DUMMY_API

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

typedef int errno_t;
#define EOK 0

static inline errno_t strcpy_s(char *dest, size_t dmax, const char *src) {
    (void)dmax;
    if (dest == NULL || src == NULL) { return -1; }
    strcpy(dest, src);
    return EOK;
}

static inline errno_t strncpy_s(char *dest, size_t dmax, const char *src, size_t count) {
    size_t to_copy;

    if (dest == NULL || src == NULL || dmax == 0) { return -1; }

    to_copy = dmax - 1;
    if (count < to_copy) {
        to_copy = count;
    }

    if (to_copy > 0) {
        memcpy(dest, src, to_copy);
    }
    dest[to_copy] = '\0';
    return EOK;
}

static inline errno_t memset_s(void *dest, size_t dmax, int value, size_t count) {
    (void)dmax;
    if (dest == NULL) { return -1; }
    memset(dest, value, count);
    return EOK;
}

static inline errno_t memcpy_s(void *dest, size_t dmax, const void *src, size_t count) {
    (void)dmax;
    if (dest == NULL || src == NULL) { return -1; }
    memcpy(dest, src, count);
    return EOK;
}

#define ERR_CHK(rc) do { (void)(rc); } while(0)

#else /* use system libsafec headers */

#include <safeclib/safe_lib.h>
#include <safeclib/safe_str_lib.h>
#include <safeclib/safe_mem_lib.h>

#define ERR_CHK(rc) do { (void)(rc); } while(0)

#endif /* SAFEC_DUMMY_API */
#endif /* _SAFEC_LIB_H_ */
