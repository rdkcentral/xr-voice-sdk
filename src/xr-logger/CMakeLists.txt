project(xr-voice-sdk-xlog VERSION ${CMAKE_PROJECT_VERSION})

add_library(xr-voice-sdk-xlog SHARED)
set_target_properties(xr-voice-sdk-xlog PROPERTIES
    SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR} # Major version number
    VERSION   ${CMAKE_PROJECT_VERSION}       # Full version number (major.minor.patch)
)

target_include_directories(xr-voice-sdk-xlog PUBLIC 
                           ${CMAKE_CURRENT_BINARY_DIR}
                           ./
                           ./src/
                           ./src/xr-logger/
                          )

target_sources(xr-voice-sdk-xlog PUBLIC
               rdkx_logger_modules.c
               rdkx_logger_level.c
               rdkx_logger_modules_lookup.c
               rdkx_logger.c)

target_compile_options(xr-voice-sdk-xlog PUBLIC -fPIC -rdynamic -Wall -Werror)

target_compile_definitions(xr-voice-sdk-xlog PUBLIC _REENTRANT _POSIX_C_SOURCE=200809L _GNU_SOURCE)

target_link_libraries(xr-voice-sdk-xlog c jansson)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rdkx_logger.json TYPE SYSCONF RENAME rdkx_logger_vd.json)

# HEADER FILES
install(FILES ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger_vd.h TYPE INCLUDE RENAME rdkx_logger.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rdkx_logger_modules.h TYPE INCLUDE)

# LIBRARY FILES
install(TARGETS xr-voice-sdk-xlog LIBRARY DESTINATION lib)

add_custom_command(
   OUTPUT rdkx_logger_modules.hash rdkx_logger_modules_lookup.c
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/rdkx_logger_modules_to_c.py" ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json rdkx_logger_modules "vd"
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_modules.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_modules.c rdkx_logger_modules.hash
   DEPENDS rdkx_logger_modules.hash rdkx_logger.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_level.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_level.c ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger_level_vd.hash
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger_level_vd.hash
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger.json
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json -a ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_global.json -o rdkx_logger.json
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)