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

# Contract test: builds the SDK with HTTP enabled, runs a Prism mock of contracts/vrex-http.yaml
# and drives real SDK sessions against it. Run after ci/build_dependencies.sh. Requires Node (npx).

set -x
set -e
##############################
GITHUB_WORKSPACE="${PWD}"
cd "${GITHUB_WORKSPACE}"

PRISM_VERSION="5.16.0"
PRISM_PORT="4010"
CONTRACT="${GITHUB_WORKSPACE}/contracts/vrex-http.yaml"
BUILD_DIR="${GITHUB_WORKSPACE}/build/contract"
HEADERS_DIR="${GITHUB_WORKSPACE}/ci/headers"
PRISM_LOG="${BUILD_DIR}/prism.log"

############################
# 1. Build xr-voice-sdk with HTTP enabled (cov_build.sh leaves it off); WS is also required since HTTP-only builds don't compile
SAFEC_CFLAGS="$(pkg-config --cflags libsafec)"
SAFEC_LIBS="$(pkg-config --libs libsafec)"

cmake -G Ninja -S "$GITHUB_WORKSPACE" -B "$BUILD_DIR" \
    -DCMAKE_INSTALL_PREFIX="${GITHUB_WORKSPACE}/install/usr" \
    -DCMAKE_INSTALL_SYSCONFDIR="${GITHUB_WORKSPACE}/install/etc" \
    -DSTAGING_BINDIR_NATIVE=/usr/bin \
    -DCMAKE_PROJECT_VERSION="1.0.0" \
    -DVSDK_VENDOR_XLOG=OFF \
    -DHTTP_ENABLED=ON \
    -DWS_ENABLED=ON \
    -DWS_NOPOLL_PATCHES=OFF \
    -DCMAKE_C_FLAGS="${SAFEC_CFLAGS} -I ${HEADERS_DIR} -Wall" \
    -DCMAKE_C_STANDARD_LIBRARIES="${SAFEC_LIBS}"

cmake --build "$BUILD_DIR" -j"$(nproc)"

SDK_LIB="$(find "$BUILD_DIR" -name 'libxr-voice-sdk.so' | head -n1)"
SDK_LIB_DIR="$(dirname "$SDK_LIB")"
GEN_DIR="$(dirname "$(find "$BUILD_DIR" -name 'rdkx_logger.h' | head -n1)")"

############################
# 2. Build the harness against the freshly built SDK
SRC="${GITHUB_WORKSPACE}/src"
gcc -std=gnu11 -Wall -Werror -D_REENTRANT -D_GNU_SOURCE \
    ${SAFEC_CFLAGS} -I "$HEADERS_DIR" \
    -I "$SRC" -I "$SRC/xr-logger" -I "$SRC/xr-timestamp" -I "$SRC/xr-speech-router" \
    -I "$SRC/xr-speech-vrex" -I "$SRC/xr-speech-vrex/xrsv_http" -I "$GEN_DIR" \
    "${GITHUB_WORKSPACE}/tests/contract/vrex_http_harness.c" \
    "${GITHUB_WORKSPACE}/tests/contract/rdkversion_stub.c" \
    -L "$SDK_LIB_DIR" -lxr-voice-sdk -ljansson -luuid -lpthread \
    -o "$BUILD_DIR/vrex_http_harness"

############################
# 3. Start the Prism mock (--errors turns any request/response violation into an error response)
npx --yes "@stoplight/prism-cli@${PRISM_VERSION}" mock --errors -h 127.0.0.1 -p "$PRISM_PORT" "$CONTRACT" > "$PRISM_LOG" 2>&1 &
PRISM_PID=$!
trap 'kill "$PRISM_PID" 2>/dev/null || true; echo "===== prism log ====="; cat "$PRISM_LOG"' EXIT

for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PRISM_PORT}") 2>/dev/null; then
        break
    fi
    kill -0 "$PRISM_PID" # fail fast if Prism exited (e.g. invalid contract)
    sleep 1
done

############################
# 4. Run the scenarios
export LD_LIBRARY_PATH="${SDK_LIB_DIR}:${LD_LIBRARY_PATH}"
HARNESS="$BUILD_DIR/vrex_http_harness"
URL="http://127.0.0.1:${PRISM_PORT}/speech"

# Positive: SDK request must satisfy the contract and SDK must parse the contract's example response
"$HARNESS" --url "$URL" --sat "contract-test-sat" --expect-status 200

# Positive: audio-file session exercises the chunked application/octet-stream upload path
TONE_WAV="$BUILD_DIR/tone.wav"
python3 "${GITHUB_WORKSPACE}/tests/contract/make_tone_wav.py" "$TONE_WAV"
"$HARNESS" --url "$URL" --sat "contract-test-sat" --audio-file "$TONE_WAV" --expect-status 200

# Negative control: no SAT token must be rejected, proving the mock is actually enforcing the contract
"$HARNESS" --url "$URL" --expect-status 401

echo "======================================================================================"
echo "contract tests passed"
