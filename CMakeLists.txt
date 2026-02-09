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

cmake_minimum_required(VERSION 3.16)

if(CMAKE_VERSION GREATER_EQUAL 3.21)
   set(CMAKE_C_STANDARD 23)
else()
   set(CMAKE_C_STANDARD 11)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_BUILD_TYPE Release)

project(xr-voice-sdk VERSION ${CMAKE_PROJECT_VERSION})

set(STAGING_BINDIR_NATIVE,     "invalid" CACHE PATH "staging bin dir native")

option(HTTP_ENABLED,            "speech router http protocol"                 OFF)
option(WS_ENABLED,              "speech router websocket protocol"            OFF)
option(WS_NOPOLL_PATCHES,       "speech router websocket nopoll patches"      OFF)
option(SDT_ENABLED,             "speech router secure data transfer protocol" OFF)

add_library(xr-voice-sdk SHARED)
set_target_properties(xr-voice-sdk PROPERTIES
    SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR} # Major version number
    VERSION   ${CMAKE_PROJECT_VERSION}       # Full version number (major.minor.patch)
)

target_include_directories(xr-voice-sdk PUBLIC 
                           ${CMAKE_CURRENT_BINARY_DIR}
                           ./
                           ./src/
                           ./src/xr-mq/
                           ./src/xr-fdc/
                           ./src/xr-timestamp/
                           ./src/xr-timer/
                           ./src/xr-audio/
                           ./src/xr-sm-engine/
                           ./src/xr-speech-router/
                           ./src/xr-speech-vrex/
                           ./src/xr-speech-vrex/xrsv_http/
                           ./src/xr-speech-vrex/xrsv_ws_nextgen/
                           ./src/xr-logger/
                           ${CMAKE_SYSROOT}/usr/include/safeclib/
                           ${CMAKE_SYSROOT}/usr/include/libsafec/
                          )

target_sources(xr-voice-sdk PUBLIC
               vsdk_version.h
               xrsr_config.h
               xraudio_config.h
               src/vsdk.c
               rdkx_logger_modules.c
               rdkx_logger_level.c
               rdkx_logger_modules_lookup.c
               src/xr-logger/rdkx_logger.c
               src/xr-timer/xr_timer.c
               src/xr-timestamp/xr_timestamp.c
               src/xr-mq/xr_mq.c
               src/xr-fdc/xr_fdc.c
               src/xr-sm-engine/xr_sm_engine.c
               src/xr-speech-router/xrsr.c
               src/xr-speech-router/xrsr_msgq.c
               src/xr-speech-router/xrsr_xraudio.c
               src/xr-speech-router/xrsr_utils.c
               src/xr-speech-vrex/xrsv_utils.c
               src/xr-speech-vrex/xrsv_http/xrsv_http.c
               src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.c
               xrsv_ws_nextgen_msgtype.c
               xrsv_ws_nextgen_tv_control.c
               src/xr-audio/xraudio.c
               src/xr-audio/xraudio_input.c
               src/xr-audio/xraudio_output.c
               src/xr-audio/xraudio_thread.c
               src/xr-audio/xraudio_utils.c
               src/xr-audio/xraudio_atomic.c)

target_compile_options(xr-voice-sdk PUBLIC -fPIC -rdynamic -Wall -Werror)

target_compile_definitions(xr-voice-sdk PUBLIC _REENTRANT _POSIX_C_SOURCE=200809L _GNU_SOURCE)

target_link_libraries(xr-voice-sdk c bsd m pthread anl rdkversion uuid jansson)

# BUILD OPTIONS

if(HTTP_ENABLED)
   target_sources(xr-voice-sdk PUBLIC src/xr-speech-router/xrsr_protocol_http.c xrsr_protocol_http_log_filter.c)
   target_compile_definitions(xr-voice-sdk PUBLIC HTTP_ENABLED)
   target_link_libraries(xr-voice-sdk curl)

   add_custom_command(
   OUTPUT xrsr_protocol_http_log_filter.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=xrsr_protocol_http_log_filter.c ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-router/xrsr_protocol_http_log_filter.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-router/xrsr_protocol_http_log_filter.hash
   VERBATIM)
endif()

if(WS_ENABLED)
   target_sources(xr-voice-sdk PUBLIC src/xr-speech-router/xrsr_protocol_ws.c)
   target_compile_definitions(xr-voice-sdk PUBLIC WS_ENABLED)
   if(WS_NOPOLL_PATCHES)
      target_compile_definitions(xr-voice-sdk PUBLIC WS_NOPOLL_PATCHES)
   endif()
   target_include_directories(xr-voice-sdk PUBLIC ${CMAKE_SYSROOT}/usr/include/nopoll/)
   target_link_libraries(xr-voice-sdk nopoll)
endif()

if(SDT_ENABLED)
   target_sources(xr-voice-sdk PUBLIC src/xr-speech-router/xrsr_protocol_sdt.c)
   target_compile_definitions(xr-voice-sdk PUBLIC SDT_ENABLED)
endif()
   
target_sources(xr-voice-sdk PUBLIC src/xr-audio/adpcm/adpcm_decode.c)
target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DECODE_ADPCM)
target_include_directories(xr-voice-sdk PUBLIC src/xr-audio/adpcm/)
   
find_library(OPUS_LIBRARY NAMES opus)
if(OPUS_LIBRARY)
   target_sources(xr-voice-sdk PUBLIC src/xr-audio/opus/xraudio_opus.c)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DECODE_OPUS)
   target_link_libraries(xr-voice-sdk ${OPUS_LIBRARY})
   target_include_directories(xr-voice-sdk PUBLIC src/xr-audio/opus/)
endif()
   
find_library(CURTAIL_LIBRARY NAMES curtail)
if(CURTAIL_LIBRARY)
   target_compile_definitions(xr-voice-sdk PUBLIC VSDK_CURTAIL_ENABLED)
   target_link_libraries(xr-voice-sdk ${CURTAIL_LIBRARY})
endif()

# CONFIG FILES
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vsdk_config.json DESTINATION ${CMAKE_INSTALL_SYSCONFDIR} COMPONENT config )

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rdkx_logger.json TYPE SYSCONF)

# HEADER FILES
install(FILES src/xr_voice_sdk.h TYPE INCLUDE)
install(FILES src/xr-speech-router/xrsr.h TYPE INCLUDE)
install(FILES src/xr-speech-vrex/xrsv.h TYPE INCLUDE)
install(FILES src/xr-speech-vrex/xrsv_http/xrsv_http.h TYPE INCLUDE)
install(FILES src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h TYPE INCLUDE)

# LIBRARY FILES
install(TARGETS xr-voice-sdk LIBRARY DESTINATION lib)


# GENERATED FILES

add_custom_command(
   OUTPUT vsdk_version.h
   COMMAND echo -n "#define VSDK_BRANCH    \"" >> vsdk_version.h
   COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} branch --all --contains | sed -n -e "s/^\\s*remotes\\/origin\\///" -e "2p" | tr -d "\\n" >> vsdk_version.h
   COMMAND echo "\"" >> vsdk_version.h
   COMMAND echo -n "#define VSDK_COMMIT_ID " >> vsdk_version.h
   COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} log --format=\"%H\" -n 1 >> vsdk_version.h
   COMMAND echo -n "#define VSDK_VERSION   \"${CMAKE_PROJECT_VERSION}" >> vsdk_version.h
   COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} diff --quiet || echo -n "++" >> vsdk_version.h
   COMMAND echo "\"" >> vsdk_version.h
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_modules.hash rdkx_logger_modules_lookup.c
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/rdkx_logger_modules_to_c.py" ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json rdkx_logger_modules
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_modules.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_modules.c rdkx_logger_modules.hash
   DEPENDS rdkx_logger_modules.hash rdkx_logger.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_level.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_level.c ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkx_logger_level.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkx_logger_level.hash
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger.json
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json -a ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_global.json -o rdkx_logger.json
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)

add_custom_command(
   OUTPUT xraudio_config.h
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_to_header.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-audio/xraudio_config_default.json -o xraudio_config.h -m 2
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-audio/xraudio_config_default.json
   VERBATIM)

add_custom_command(
   OUTPUT vsdk_config.json
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-router/xrsr_config_default.json -a ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-audio/xraudio_config_default.json:xraudio -o vsdk_config.json
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-router/xrsr_config_default.json ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-audio/xraudio_config_default.json
   VERBATIM)

add_custom_command(
   OUTPUT xrsr_config.h
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_to_header.py" -i vsdk_config.json -o xrsr_config.h -v "ws,http"
   DEPENDS vsdk_config.json
   VERBATIM)

add_custom_command(
   OUTPUT xrsv_ws_nextgen_msgtype.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=xrsv_ws_nextgen_msgtype.c ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_msgtype.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_msgtype.hash
   VERBATIM)

add_custom_command(
   OUTPUT xrsv_ws_nextgen_tv_control.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=xrsv_ws_nextgen_tv_control.c ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_tv_control.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_tv_control.hash
   VERBATIM)
