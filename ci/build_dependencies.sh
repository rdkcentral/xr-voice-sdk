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

# #############################
# 1. Install Dependencies and packages

apt update
apt install -y \
    pkg-config \
    libbsd-dev \
    libcurl4-openssl-dev \
    libjansson-dev \
    libopus-dev \
    libssl-dev \
    uuid-dev \
    autoconf \
    automake \
    gperf \
    libtool \
    make \
    python3 \
    python3-pip \
    libwebrtc-audio-processing-dev

###########################################
# 2. Clone the required repositories

git clone --depth 1 --filter=blob:none --sparse --branch develop https://github.com/rdkcentral/rdkversion.git
git -C rdkversion sparse-checkout set src

git clone --depth 1 --filter=blob:none --sparse https://github.com/rdkcentral/meta-rdk-oss-reference.git
git -C meta-rdk-oss-reference sparse-checkout set recipes-common/safec-common-wrapper/files

RDKVERSION_DIR="$GITHUB_WORKSPACE/rdkversion"
SAFEC_WRAPPER_DIR="$GITHUB_WORKSPACE/meta-rdk-oss-reference/recipes-common/safec-common-wrapper/files"

###########################################
# 3. Clone and build nopoll from source
# (libnopoll-dev is not available in the CI docker image)

git clone --depth 1 https://github.com/ASPLes/nopoll.git

echo "======================================================================================"
echo "building nopoll"

cd nopoll
./autogen.sh --prefix=/usr
make -j$(nproc)
make install
cd "${GITHUB_WORKSPACE}"

############################
# 4. Create stub headers for external dependencies
echo "======================================================================================"
echo "Creating stub headers"

HEADERS_DIR="$GITHUB_WORKSPACE/ci/headers"
mkdir -p "${HEADERS_DIR}"

cd "${HEADERS_DIR}"

# rdkversion.h — real header from upstream
cp "$RDKVERSION_DIR/src/rdkversion.h" rdkversion.h
[ -f rdkversion.h ]

# Use the Yocto safec_lib.h sysroot header for CI builds without libsafec.
# Add include guards because the upstream header does not provide them.
cp "$SAFEC_WRAPPER_DIR/safec_lib.h" safec_lib.h
sed -i '1s/^/#ifndef XR_VOICE_SDK_CI_SAFEC_LIB_H\n#define XR_VOICE_SDK_CI_SAFEC_LIB_H\n/' safec_lib.h
printf '\n#endif /* XR_VOICE_SDK_CI_SAFEC_LIB_H */\n' >> safec_lib.h

echo "Stub headers created successfully"

cd "${GITHUB_WORKSPACE}"
echo "======================================================================================"
echo "build_dependencies.sh complete"
