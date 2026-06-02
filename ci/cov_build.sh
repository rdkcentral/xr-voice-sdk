#!/bin/bash
#
# If not stated otherwise in this file or this component's license file the
# following copyright and licenses apply:
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

set -x
set -e
##############################
GITHUB_WORKSPACE="${PWD}"
cd "${GITHUB_WORKSPACE}"

git config --global --add safe.directory "${GITHUB_WORKSPACE}"

############################
# Build xr-voice-sdk
echo "building xr-voice-sdk"

HEADERS_DIR="$GITHUB_WORKSPACE/ci/headers"

cmake -G Ninja -S "$GITHUB_WORKSPACE" -B build/xr-voice-sdk \
    -DCMAKE_INSTALL_PREFIX="${GITHUB_WORKSPACE}/install/usr" \
    -DCMAKE_INSTALL_SYSCONFDIR="${GITHUB_WORKSPACE}/install/etc" \
    -DSTAGING_BINDIR_NATIVE=/usr/bin \
    -DCMAKE_VERBOSE_MAKEFILE=ON \
    -DCMAKE_PROJECT_VERSION="1.0.0" \
    -DVSDK_VENDOR_XLOG=OFF \
    -DWS_ENABLED=ON \
    -DWS_NOPOLL_PATCHES=OFF \
    -DVAD_ENABLED=OFF \
    -DCMAKE_C_FLAGS=" \
    -I ${HEADERS_DIR} \
    -DSAFEC_DUMMY_API \
    -Wall -Wno-error"

# We should remove this hack to disable -Werror once the warnings are fixed in the codebase.
find "${GITHUB_WORKSPACE}/build/xr-voice-sdk" \( -name "*.ninja" -o -name "flags.make" \) -exec sed -i 's/\(^\|[[:space:]]\)-Werror\([[:space:]]\|$\)/\1\2/g' {} \;

cmake --build build/xr-voice-sdk -j$(nproc) 2>&1
echo "======================================================================================"
echo "xr-voice-sdk build complete"
exit 0
