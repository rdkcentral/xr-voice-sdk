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

// xraudio.c calls rdkversion unconditionally but the SDK only links it when RDK_VERSION_ENABLED is set.
// Failing the parse makes xraudio take its existing fallback (production_build = true).

#include <stdbool.h>
#include "rdkversion.h"

unsigned char rdk_version_parse_version(rdk_version_info_t *version_info) {
   (void)version_info;
   return(1);
}

void rdk_version_object_free(rdk_version_info_t *obj) {
   (void)obj;
}
