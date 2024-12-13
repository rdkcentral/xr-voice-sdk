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

project(xr-voice-sdk)

option(GIT_BRANCH,      "Repository Branch" OFF)

set(STAGING_BINDIR_NATIVE,     "invalid" CACHE PATH "staging bin dir native")

option(HTTP_ENABLED,            "speech router http protocol"                 OFF)
option(WS_ENABLED,              "speech router websocket protocol"            OFF)
option(WS_NOPOLL_PATCHES,       "speech router websocket nopoll patches"      OFF)
option(SDT_ENABLED,             "speech router secure data transfer protocol" OFF)
option(MICROPHONE_TAP_ENABLED,  "speech router microphone tap"                OFF)

option(XRSR_ALLOW_INPUT_FAILURE,  "speech router allow input failure"         OFF)

set(XRSR_KEYWORD_PHRASE, "" CACHE STRING "speech router keyword phrase")

option(XRAUDIO_RESOURCE_MGMT,   "xraudio resource management"                 OFF)
option(XRAUDIO_DECODE_ADPCM,    "xraudio adpcm decoder"                       ON)
option(XRAUDIO_DECODE_OPUS,     "xraudio opus decoder"                        ON)
option(XRAUDIO_CURTAIL_ENABLED, "xraudio curtail"                             OFF)

set(XRAUDIO_CONFIG_JSON_HAL, "" CACHE FILEPATH "xraudio config hal")
set(XRAUDIO_CONFIG_JSON_KWD, "" CACHE FILEPATH "xraudio config kwd")
set(XRAUDIO_CONFIG_JSON_EOS, "" CACHE FILEPATH "xraudio config eos")
set(XRAUDIO_CONFIG_JSON_DGA, "" CACHE FILEPATH "xraudio config dga")
set(XRAUDIO_CONFIG_JSON_SDF, "" CACHE FILEPATH "xraudio config sdf")
set(XRAUDIO_CONFIG_JSON_OVC, "" CACHE FILEPATH "xraudio config ovc")
set(XRAUDIO_CONFIG_JSON_PPR, "" CACHE FILEPATH "xraudio config ppr")
set(XRAUDIO_CONFIG_JSON_SUB, "" CACHE FILEPATH "xraudio config sub")
set(XRAUDIO_CONFIG_JSON_ADD, "" CACHE FILEPATH "xraudio config add")

option(XRAUDIO_KWD_ENABLED,    "xraudio keyword detector" OFF)
option(XRAUDIO_EOS_ENABLED,    "xraudio end of speech"    OFF)
option(XRAUDIO_DGA_ENABLED,    "xraudio dynamic gain"     OFF)
option(XRAUDIO_SDF_ENABLED,    "xraudio sound focus"      OFF)
option(XRAUDIO_OVC_ENABLED,    "xraudio ovc"              OFF)
option(XRAUDIO_PPR_ENABLED,    "xraudio pre-processing"   OFF)
option(XRAUDIO_OUTPUT_ENABLED, "xraudio output"           OFF)

option(XLOG_CURTAIL_ENABLED, "xlog curtail"             OFF)

add_library(xr-voice-sdk SHARED)
set_target_properties(xr-voice-sdk PROPERTIES
    SOVERSION 1              # Major version number
    VERSION 1.0.0            # Full version number (major.minor.patch)
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
               src/xr-audio/xraudio_thread.c
               src/xr-audio/xraudio_utils.c
               src/xr-audio/xraudio_atomic.c)

target_compile_options(xr-voice-sdk PUBLIC -fPIC -rdynamic -Wall -Werror)

target_compile_definitions(xr-voice-sdk PUBLIC _REENTRANT _POSIX_C_SOURCE=200809L _GNU_SOURCE)

target_link_libraries(xr-voice-sdk c bsd m pthread anl rdkversion uuid jansson)

#CFLAGS_append = " -std=c11 -fPIC -D_REENTRANT -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -Wall -Werror -rdynamic"

# TODO MAY NEED THESE LINK FLAGS AROUND HAL
#  -Wl,-whole-archive -lxraudio-hal -Wl,-no-whole-archive

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

if(MICROPHONE_TAP_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC MICROPHONE_TAP_ENABLED)
endif()

if(XRSR_ALLOW_INPUT_FAILURE)
   target_compile_definitions(xr-voice-sdk PUBLIC XRSR_ALLOW_INPUT_FAILURE)
endif()

if(XRSR_KEYWORD_PHRASE STREQUAL hello_sky)
   target_compile_definitions(xr-voice-sdk PUBLIC XRSR_KEYWORD_PHRASE_HELLO_SKY)
elseif(XRSR_KEYWORD_PHRASE STREQUAL hey_xfinity)
   target_compile_definitions(xr-voice-sdk PUBLIC XRSR_KEYWORD_PHRASE_HEY_XFINITY)
endif()

if(XRAUDIO_RESOURCE_MGMT)
   target_sources(xr-voice-sdk PUBLIC src/xr-audio/xraudio_resource.c)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_RESOURCE_MGMT)
   target_link_libraries(xr-voice-sdk rt)
endif()
   
if(XRAUDIO_DECODE_ADPCM)
   target_sources(xr-voice-sdk PUBLIC src/xr-audio/adpcm/adpcm_decode.c)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DECODE_ADPCM)
   target_include_directories(xr-voice-sdk PUBLIC src/xr-audio/adpcm/)
endif()
   
if(XRAUDIO_DECODE_OPUS)
   target_sources(xr-voice-sdk PUBLIC src/xr-audio/opus/xraudio_opus.c)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DECODE_OPUS)
   target_link_libraries(xr-voice-sdk opus)
   target_include_directories(xr-voice-sdk PUBLIC src/xr-audio/opus/)
endif()
   
if(XRAUDIO_CURTAIL_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC CURTAIL_ENABLED)
endif()

if(XLOG_CURTAIL_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XLOG_USE_CURTAIL)
   target_link_libraries(xr-voice-sdk curtail)
endif()

if(XRAUDIO_KWD_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_KWD_ENABLED)
   target_link_libraries(xr-voice-sdk xraudio-ffv-hal)
   target_link_libraries(xr-voice-sdk xraudio-kwd)
endif()

if(XRAUDIO_EOS_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_EOS_ENABLED)
   target_link_libraries(xr-voice-sdk xraudio-eos)
endif()

if(XRAUDIO_DGA_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DGA_ENABLED)
   target_link_libraries(xr-voice-sdk xraudio-dga)
endif()

if(XRAUDIO_SDF_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_SDF_ENABLED)
   target_link_libraries(xr-voice-sdk xraudio-sdf)
endif()

if(XRAUDIO_OVC_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_OVC_ENABLED)
   target_link_libraries(xr-voice-sdk xraudio-ovc)
endif()

if(XRAUDIO_PPR_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_PPR_ENABLED)
   target_link_libraries(xr-voice-sdk xraudio-ppr)
endif()

if(XRAUDIO_OUTPUT_ENABLED)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_OUTPUT_ENABLED)
   target_sources(xr-voice-sdk PUBLIC src/xr-audio/xraudio_output.c)
endif()

# CONFIG FILES
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xrsr_config.json TYPE INCLUDE)

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
   COMMAND echo "#define VSDK_VER_MAJOR \"1\"" > vsdk_version.h
   COMMAND echo -n "#define VSDK_VER_MINOR \"" >> vsdk_version.h
   COMMAND bash -c "echo -n $(git -C ${CMAKE_CURRENT_SOURCE_DIR} rev-list --count 4b825dc642cb6eb9a060e54bf8d69288fbee4904..HEAD) >> vsdk_version.h"
   COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} diff --quiet || echo -n "++" >> vsdk_version.h
   COMMAND echo "\"" >> vsdk_version.h
   COMMAND echo "#define VSDK_BRANCH    \"${GIT_BRANCH}\"" >> vsdk_version.h
   COMMAND echo -n "#define VSDK_COMMIT_ID " >> vsdk_version.h
   COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} log --format=\"%H\" -n 1 >> vsdk_version.h
   COMMAND echo "#define VSDK_VERSION (VSDK_VER_MAJOR \".\" VSDK_VER_MINOR)" >> vsdk_version.h
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
   COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json rdkx_logger.json
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)

add_custom_command(
   OUTPUT xraudio_config.json
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-audio/xraudio_config_default.json -a "${XRAUDIO_CONFIG_JSON_HAL}:hal" -a "${XRAUDIO_CONFIG_JSON_KWD}:input,kwd" -a "${XRAUDIO_CONFIG_JSON_EOS}:input,eos" -a "${XRAUDIO_CONFIG_JSON_DGA}:input,dga" -a "${XRAUDIO_CONFIG_JSON_SDF}:input,sdf" -a "${XRAUDIO_CONFIG_JSON_OVC}:output,ovc" -a "${XRAUDIO_CONFIG_JSON_PPR}:input,ppr" -s "${XRAUDIO_CONFIG_JSON_SUB}" -a "${XRAUDIO_CONFIG_JSON_ADD}" -o xraudio_config.json
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-audio/xraudio_config_default.json
   VERBATIM)

add_custom_command(
   OUTPUT xraudio_config.h
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_to_header.py" -i xraudio_config.json -o xraudio_config.h -m 2
   DEPENDS xraudio_config.json
   VERBATIM)

add_custom_command(
   OUTPUT xrsr_config.json
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-router/xrsr_config_default.json -a "xraudio_config.json:xraudio" -s "${XRSR_CONFIG_JSON_SUB}" -a "${XRSR_CONFIG_JSON_ADD}" -o xrsr_config.json
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/xr-speech-router/xrsr_config_default.json xraudio_config.json
   VERBATIM)

add_custom_command(
   OUTPUT xrsr_config.h
   COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vsdk_json_to_header.py" -i xrsr_config.json -o xrsr_config.h -v "ws,http"
   DEPENDS xrsr_config.json
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
