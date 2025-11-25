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
               rdkx_logger_vendor.h
               rdkx_logger_vendor_modules.c
               rdkx_logger_vendor_level.c
               rdkx_logger_vendor_modules_lookup.c
               rdkx_logger_vendor.c)

target_compile_options(xr-voice-sdk-xlog PUBLIC -fPIC -rdynamic -Wall -Werror)

target_compile_definitions(xr-voice-sdk-xlog PUBLIC _REENTRANT _POSIX_C_SOURCE=200809L _GNU_SOURCE)

target_link_libraries(xr-voice-sdk-xlog c jansson)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rdkx_logger_vendor.json TYPE SYSCONF)

# HEADER FILES
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rdkx_logger_vendor.h TYPE INCLUDE)

# LIBRARY FILES
install(TARGETS xr-voice-sdk-xlog LIBRARY DESTINATION lib)

add_custom_command(
   OUTPUT rdkx_logger_vendor.h
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/rdkx_logger_to_vendor.py" ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger.h rdkx_logger_vendor.h
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger.h ${CMAKE_SOURCE_DIR}/scripts/rdkx_logger_to_vendor.py
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_vendor.c
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/rdkx_logger_to_vendor.py" ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger.c rdkx_logger_vendor.c
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger.c ${CMAKE_SOURCE_DIR}/scripts/rdkx_logger_to_vendor.py
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_vendor_modules.hash rdkx_logger_vendor_modules_lookup.c
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/rdkx_logger_modules_to_c.py" ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json rdkx_logger_vendor_modules
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_vendor_modules.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_vendor_modules.c rdkx_logger_vendor_modules.hash
   DEPENDS rdkx_logger_vendor_modules.hash rdkx_logger_vendor.json
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_vendor_level.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf --output-file=rdkx_logger_vendor_level.c ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger_level.hash
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkx_logger_level.hash
   VERBATIM)

add_custom_command(
   OUTPUT rdkx_logger_vendor.json
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_combine.py" -i ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json -a ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_global.json -o rdkx_logger_vendor.json
   DEPENDS ${CMAKE_SOURCE_DIR}/src/xr-logger/rdkv/rdkx_logger_modules.json
   VERBATIM)