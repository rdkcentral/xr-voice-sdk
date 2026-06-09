option(RDK_VERSION_ENABLED,     "Build with RDK versioning support"           OFF)
option(HTTP_ENABLED,            "speech router http protocol"                 OFF)
option(WS_ENABLED,              "speech router websocket protocol"            OFF)
option(WS_NOPOLL_PATCHES,       "speech router websocket nopoll patches"      OFF)
option(SDT_ENABLED,             "speech router secure data transfer protocol" OFF)
option(USE_SAFEC,               "Use safec"                                   OFF)
option(VAD_TEST_ENABLED,        "Build the VAD wave-file processing test"     OFF)

add_library(xr-voice-sdk SHARED)
set_target_properties(xr-voice-sdk PROPERTIES
    SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR} # Major version number
    VERSION   ${CMAKE_PROJECT_VERSION}       # Full version number (major.minor.patch)
)

target_include_directories(xr-voice-sdk PUBLIC 
                           ${CMAKE_CURRENT_BINARY_DIR}
                           ./
                           ./xr-mq/
                           ./xr-fdc/
                           ./xr-timestamp/
                           ./xr-timer/
                           ./xr-audio/
                           ./xr-sm-engine/
                           ./xr-speech-router/
                           ./xr-speech-vrex/
                           ./xr-speech-vrex/xrsv_http/
                           ./xr-speech-vrex/xrsv_ws_nextgen/
                           ./xr-logger/
                           ${CMAKE_SYSROOT}/usr/include/safeclib/
                           ${CMAKE_SYSROOT}/usr/include/libsafec/
                          )

target_sources(xr-voice-sdk PRIVATE
               vsdk_version.h
               xrsr_config.h
               xraudio_config.h
               rdkx_logger.h
               rdkx_logger_modules.c
               rdkx_logger_level.c
               rdkx_logger_modules_lookup.c
               xrsv_ws_nextgen_msgtype.c
               xrsv_ws_nextgen_tv_control.c
               )

target_sources(xr-voice-sdk PUBLIC
               vsdk.c
               xr-logger/rdkx_logger.c
               xr-timer/xr_timer.c
               xr-timestamp/xr_timestamp.c
               xr-mq/xr_mq.c
               xr-fdc/xr_fdc.c
               xr-sm-engine/xr_sm_engine.c
               xr-speech-router/xrsr.c
               xr-speech-router/xrsr_msgq.c
               xr-speech-router/xrsr_xraudio.c
               xr-speech-router/xrsr_utils.c
               xr-speech-vrex/xrsv_utils.c
               xr-speech-vrex/xrsv_http/xrsv_http.c
               xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.c
               xr-audio/xraudio.c
               xr-audio/xraudio_input.c
               xr-audio/xraudio_output.c
               xr-audio/xraudio_thread.c
               xr-audio/xraudio_vad.cpp
               xr-audio/xraudio_utils.c
               xr-audio/xraudio_atomic.c)

target_compile_options(xr-voice-sdk PUBLIC -fPIC -rdynamic -Wall -Werror)

target_compile_definitions(xr-voice-sdk PUBLIC _REENTRANT _POSIX_C_SOURCE=200809L _GNU_SOURCE)

target_link_libraries(xr-voice-sdk c bsd m pthread anl uuid jansson)

# BUILD OPTIONS

if(RDK_VERSION_ENABLED)
   target_link_libraries(xr-voice-sdk rdkversion)
   target_compile_definitions(xr-voice-sdk PUBLIC VSDK_RDK_VERSION)
endif()

if(HTTP_ENABLED)
   target_sources(xr-voice-sdk PUBLIC xr-speech-router/xrsr_protocol_http.c)
   target_sources(xr-voice-sdk PRIVATE xrsr_protocol_http_log_filter.c)
   target_compile_definitions(xr-voice-sdk PUBLIC HTTP_ENABLED)
   target_link_libraries(xr-voice-sdk curl)

   add_custom_command(
   OUTPUT xrsr_protocol_http_log_filter.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=xrsr_protocol_http_log_filter.c ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-router/xrsr_protocol_http_log_filter.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-router/xrsr_protocol_http_log_filter.hash
   VERBATIM)
endif()

if(WS_ENABLED)
   target_sources(xr-voice-sdk PUBLIC xr-speech-router/xrsr_protocol_ws.c)
   target_compile_definitions(xr-voice-sdk PUBLIC WS_ENABLED)
   if(WS_NOPOLL_PATCHES)
      target_compile_definitions(xr-voice-sdk PUBLIC WS_NOPOLL_PATCHES)
   endif()
   target_include_directories(xr-voice-sdk PUBLIC ${CMAKE_SYSROOT}/usr/include/nopoll/)
   target_link_libraries(xr-voice-sdk ssl crypto nopoll)
endif()

if(SDT_ENABLED)
   target_sources(xr-voice-sdk PUBLIC xr-speech-router/xrsr_protocol_sdt.c)
   target_compile_definitions(xr-voice-sdk PUBLIC SDT_ENABLED)
endif()
   
target_sources(xr-voice-sdk PUBLIC xr-audio/adpcm/adpcm_decode.c)
target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DECODE_ADPCM)
target_include_directories(xr-voice-sdk PUBLIC xr-audio/adpcm/)
   
find_library(OPUS_LIBRARY NAMES opus)
if(OPUS_LIBRARY)
   target_sources(xr-voice-sdk PUBLIC xr-audio/opus/xraudio_opus.c)
   target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DECODE_OPUS)
   target_link_libraries(xr-voice-sdk ${OPUS_LIBRARY})
   target_include_directories(xr-voice-sdk PUBLIC xr-audio/opus/)
endif()
   
find_library(CURTAIL_LIBRARY NAMES curtail)
if(CURTAIL_LIBRARY)
   target_compile_definitions(xr-voice-sdk PUBLIC VSDK_CURTAIL_ENABLED)
   target_link_libraries(xr-voice-sdk ${CURTAIL_LIBRARY})
endif()

if(USE_SAFEC)
   find_package(PkgConfig)
   pkg_check_modules(SAFEC REQUIRED libsafec)
   if(SAFEC_FOUND)
      target_link_libraries(xr-voice-sdk ${SAFEC_LIBRARIES})
   endif()
else()
   add_compile_definitions(SAFEC_DUMMY_API)
endif()

target_include_directories(xr-voice-sdk PUBLIC ${CMAKE_SYSROOT}/usr/include/webrtc_audio_processing/)
target_link_libraries(xr-voice-sdk webrtc_audio_processing)

# VAD component test (optional)
if(VAD_TEST_ENABLED)
   add_subdirectory(xr-audio/test)
endif()

# CONFIG FILES
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vsdk_config.json DESTINATION ${CMAKE_INSTALL_SYSCONFDIR} COMPONENT config )

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rdkx_logger.json TYPE SYSCONF)

# HEADER FILES
install(FILES xr_voice_sdk.h TYPE INCLUDE)
install(FILES xr-speech-router/xrsr.h TYPE INCLUDE)
install(FILES xr-speech-vrex/xrsv.h TYPE INCLUDE)
install(FILES xr-speech-vrex/xrsv_http/xrsv_http.h TYPE INCLUDE)
install(FILES xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen.h TYPE INCLUDE)

# LIBRARY FILES
install(TARGETS xr-voice-sdk LIBRARY DESTINATION lib)

# GENERATED FILES

add_custom_command(
   OUTPUT vsdk_version.h
   COMMAND echo -n "#define VSDK_BRANCH    \"" > vsdk_version.h
   COMMAND git -C ${CMAKE_SOURCE_DIR} branch --all --contains | sed -n -e "s/^\\s*remotes\\/origin\\///" -e "2p" | tr -d "\\n" >> vsdk_version.h
   COMMAND echo "\"" >> vsdk_version.h
   COMMAND echo -n "#define VSDK_COMMIT_ID " >> vsdk_version.h
   COMMAND git -C ${CMAKE_SOURCE_DIR} log --format=\"%H\" -n 1 >> vsdk_version.h
   COMMAND echo -n "#define VSDK_VERSION   \"${CMAKE_PROJECT_VERSION}" >> vsdk_version.h
   COMMAND git -C ${CMAKE_SOURCE_DIR} diff --quiet || echo -n "++" >> vsdk_version.h
   COMMAND echo "\"" >> vsdk_version.h
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_modules.hash rdkx_logger_modules_lookup.c
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/rdkx_logger_modules_to_c.py" ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkv/rdkx_logger_modules.json rdkx_logger_modules "mw"
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_modules.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_modules.c rdkx_logger_modules.hash
   DEPENDS rdkx_logger_modules.hash rdkx_logger.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_level.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_level.c ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkx_logger_level_mw.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkx_logger_level_mw.hash
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger.json
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkv/rdkx_logger_modules.json -a ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkv/rdkx_logger_global.json -o rdkx_logger.json
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)

add_custom_command(
   OUTPUT xraudio_config.h
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_to_header.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/xr-audio/xraudio_config_default.json -o xraudio_config.h -m 2
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-audio/xraudio_config_default.json
   VERBATIM)

add_custom_command(
   OUTPUT vsdk_config.json
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-router/xrsr_config_default.json -a ${CMAKE_CURRENT_SOURCE_DIR}/xr-audio/xraudio_config_default.json:xraudio -o vsdk_config.json
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-router/xrsr_config_default.json ${CMAKE_CURRENT_SOURCE_DIR}/xr-audio/xraudio_config_default.json
   VERBATIM)

add_custom_command(
   OUTPUT xrsr_config.h
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_to_header.py" -i vsdk_config.json -o xrsr_config.h -v "ws,http,xraudio"
   DEPENDS vsdk_config.json
   VERBATIM)

add_custom_command(
   OUTPUT xrsv_ws_nextgen_msgtype.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=xrsv_ws_nextgen_msgtype.c ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_msgtype.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_msgtype.hash
   VERBATIM)

add_custom_command(
   OUTPUT xrsv_ws_nextgen_tv_control.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=xrsv_ws_nextgen_tv_control.c ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_tv_control.hash
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-vrex/xrsv_ws_nextgen/xrsv_ws_nextgen_tv_control.hash
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger.h
   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkx_logger_mw.h rdkx_logger.h
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-logger/rdkx_logger_mw.h
   VERBATIM)
