#!/bin/bash
set -x
set -e
##############################
GITHUB_WORKSPACE="${PWD}"
ls -la ${GITHUB_WORKSPACE}

############################

# Build xr-voice-sdk
echo "building xr-voice-sdk"

MOCK_DIR="$GITHUB_WORKSPACE/ci/mocks"
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
    -DCMAKE_C_FLAGS=" \
    -I ${MOCK_DIR} \
    -I ${HEADERS_DIR} \
    -Wall -Wno-error \
    -DSAFEC_DUMMY_API"

# xr-voice-sdk's CMakeLists.txt adds -Werror via target_compile_options, which appends
# after CMAKE_C_FLAGS and overrides our -Wno-error. Strip it from generated build files.
find "${GITHUB_WORKSPACE}/build/xr-voice-sdk" \( -name "*.ninja" -o -name "flags.make" \) -exec sed -i 's/\(^\|[[:space:]]\)-Werror\([[:space:]]\|$\)/\1\2/g' {} \;

cmake --build build/xr-voice-sdk -j$(nproc) 2>&1
echo "======================================================================================"
echo "xr-voice-sdk build complete"
exit 0
