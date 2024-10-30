/*
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
*/
#ifndef __RDKX_LOGGER__
#define __RDKX_LOGGER__

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include "rdkx_logger_modules.h"

// Value to disable each parameter in the output
#define XLOG_COLOR_NONE    NULL
#define XLOG_FUNCTION_NONE NULL
#define XLOG_LINE_NONE     -1

#define XLOG_COLOR_NRM  "\x1b[0m"
#define XLOG_COLOR_BLK  "\x1b[30m"
#define XLOG_COLOR_RED  "\x1b[31m"
#define XLOG_COLOR_GRN  "\x1b[32m"
#define XLOG_COLOR_YEL  "\x1b[33m"
#define XLOG_COLOR_BLU  "\x1b[34m"
#define XLOG_COLOR_MAG  "\x1b[35m"
#define XLOG_COLOR_CYN  "\x1b[36m"
#define XLOG_COLOR_WHT  "\x1b[37m"

// must define the XLOG_MODULE_ID value before including this file to make lookup fast
#ifndef XLOG_MODULE_ID
#error Please define XLOG_MODULE_ID with the appropriate definition from rdkx_logger_modules.h and add name to rdkx_logger.json as needed.
#endif

// Default static log level setting
#ifndef XLOG_LEVEL
#define XLOG_LEVEL XLOG_PP_LEVEL_INFO
#endif

// Default output stream
#ifndef XLOGD_OUTPUT
#define XLOGD_OUTPUT stdout
#endif

#define XLOG_FLUSH() fflush(XLOGD_OUTPUT)

// define XLOG_PRINT_FUNCTION or XLOG_OMIT_FUNCTION to control printing of function name
#ifdef XLOG_OMIT_FUNCTION
#define XLOG_PARAM_FUNCTION XLOG_FUNCTION_NONE
#else
#define XLOG_PARAM_FUNCTION __FUNCTION__
#endif

// define XLOG_PRINT_LINE to control printing of line number
#ifdef XLOG_PRINT_LINE
#define XLOG_PARAM_LINE __LINE__
#else
#define XLOG_PARAM_LINE XLOG_LINE_NONE
#endif

// XLOG options
#define XLOG_OPTS_NONE      (0)
#define XLOG_OPTS_GMT       (1)
#define XLOG_OPTS_DATE      (1 << 1)
#define XLOG_OPTS_TIME      (1 << 2)
#define XLOG_OPTS_LF        (1 << 3)
#define XLOG_OPTS_MOD_NAME  (1 << 4)
#define XLOG_OPTS_LEVEL     (1 << 5)
#define XLOG_OPTS_COLOR     (1 << 6)

// define XLOG_OPTS_DEFAULT to control the default options
#ifndef XLOG_OPTS_DEFAULT
#define XLOG_OPTS_DEFAULT (XLOG_OPTS_DATE | XLOG_OPTS_TIME | XLOG_OPTS_LF | XLOG_OPTS_MOD_NAME | XLOG_OPTS_LEVEL | XLOG_OPTS_COLOR)
#endif

// Log arguments can be made static for a run-time speedup, but this increases the size...
#ifdef XLOG_OPTIMIZE_SPEED
#define XLOG_STATIC_ARGS static
#else
#define XLOG_STATIC_ARGS
#endif

// Definitions to allow the preprocessor comparisons below
#define XLOG_PP_LEVEL_ALL       0
#define XLOG_PP_LEVEL_DEBUG     1
#define XLOG_PP_LEVEL_INFO      2
#define XLOG_PP_LEVEL_WARN      3
#define XLOG_PP_LEVEL_ERROR     4
#define XLOG_PP_LEVEL_FATAL     5
#define XLOG_PP_LEVEL_TELEMETRY 6
#define XLOG_PP_LEVEL_INVALID   7

// This value indicates the maximum print size and also the size of local stack variable
#define XLOG_BUF_SIZE_DEFAULT (4096)

typedef enum {
   XLOG_LEVEL_ALL       = XLOG_PP_LEVEL_ALL,
   XLOG_LEVEL_DEBUG     = XLOG_PP_LEVEL_DEBUG,
   XLOG_LEVEL_INFO      = XLOG_PP_LEVEL_INFO,
   XLOG_LEVEL_WARN      = XLOG_PP_LEVEL_WARN,
   XLOG_LEVEL_ERROR     = XLOG_PP_LEVEL_ERROR,
   XLOG_LEVEL_FATAL     = XLOG_PP_LEVEL_FATAL,
   XLOG_LEVEL_TELEMETRY = XLOG_PP_LEVEL_TELEMETRY,
   XLOG_LEVEL_INVALID   = XLOG_PP_LEVEL_INVALID
} xlog_level_t;

typedef struct {
   uint32_t         options;  // Bitfield of XLOG_OPTS_ options
   const char *     color;    // ANSI color code or NULL to skip
   const char *     function; // Function name or NULL to skip
   int              line;     // Line number or negative number to skip
   xlog_level_t     level;    // Log level (XLOG_LEVEL_)
   xlog_module_id_t id;       // Module Id from rdkx_logger_modules.h
   uint32_t         size_max; // Maximum size of output buffer in bytes
} xlog_args_t;

typedef int (*xlog_print_t)(xlog_level_t level, const char *buffer, uint32_t size);

// Internal use only.  This is required to avoid parameter expansion when using XLOGD macros below.
extern xlog_level_t  g_xlog_modules[];

#ifdef __cplusplus
extern "C" {
#endif

int          xlog_init(xlog_module_id_t id, const char *filename, uint32_t file_size_max);
int          xlog_init_user_print(xlog_module_id_t id, xlog_print_t print, xlog_print_t print_safe);
void         xlog_term(void);
xlog_level_t xlog_level_get(xlog_module_id_t id);
void         xlog_level_set(xlog_module_id_t id, xlog_level_t level);
void         xlog_level_set_all(xlog_level_t level);
bool         xlog_level_active(xlog_module_id_t id, xlog_level_t level);

// Asynchronous safe - can be used in signal handlers
int xlog_printf_safe(const xlog_args_t *args, const char *string);
int xlog_fprintf_safe(const xlog_args_t *args, FILE *stream, const char *string);

int xlog_printf(const xlog_args_t *args, const char *format, ...);
int xlog_fprintf(const xlog_args_t *args, FILE *stream, const char *format, ...);
int xlog_dprintf(const xlog_args_t *args, int fd, const char *format, ...);
int xlog_snprintf(const xlog_args_t *args, char *str, size_t size, const char *format, ...);

#define xlog_vprintf(args, format, ap) xlog_vfprintf(args, stdout, format, ap)
int xlog_vfprintf(const xlog_args_t *args, FILE *stream, const char *format, va_list ap);
int xlog_vdprintf(const xlog_args_t *args, int fd, const char *format, va_list ap);
int xlog_vsnprintf(const xlog_args_t *args, char *str, size_t size, const char *format, va_list ap);

#ifdef __cplusplus
}
#endif

// Unformatted logging
#define XLOG_RAW(...)            fprintf(XLOGD_OUTPUT, __VA_ARGS__)

// Formatted logging to FILE *
#define XLOG(LEVEL, OPTS, COLOR, BUF_SIZE, FORMAT, ...) do { if(LEVEL < g_xlog_modules[XLOG_MODULE_ID]) { break; } XLOG_STATIC_ARGS const xlog_args_t xlog_args__ = {.options = OPTS, .color = COLOR, .function = XLOG_PARAM_FUNCTION, .line = XLOG_PARAM_LINE, .level = LEVEL, .id = XLOG_MODULE_ID, .size_max = BUF_SIZE}; xlog_fprintf(&xlog_args__, XLOGD_OUTPUT, FORMAT, ##__VA_ARGS__);} while(0)
#define XLOG_NO_LF(FORMAT, ...)        XLOG(XLOG_LEVEL_INVALID, (XLOG_OPTS_DEFAULT & ~XLOG_OPTS_LF), XLOG_COLOR_NONE, XLOG_BUF_SIZE_DEFAULT, FORMAT, ##__VA_ARGS__)

// Dynamic log macros
#define XLOGD(LEVEL, OPTS, COLOR, BUF_SIZE, ...) XLOG(LEVEL, OPTS, COLOR, BUF_SIZE, ##__VA_ARGS__)
#define XLOGD_NO_LF(LEVEL, ...)        XLOGD(LEVEL, (XLOG_OPTS_DEFAULT & ~XLOG_OPTS_LF), XLOG_COLOR_NONE, XLOG_BUF_SIZE_DEFAULT, ##__VA_ARGS__)

#define XLOGD_DEBUG(...)     XLOGD(XLOG_LEVEL_DEBUG, XLOG_OPTS_DEFAULT, XLOG_COLOR_GRN,  XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_INFO(...)      XLOGD(XLOG_LEVEL_INFO,  XLOG_OPTS_DEFAULT, XLOG_COLOR_NONE, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_WARN(...)      XLOGD(XLOG_LEVEL_WARN,  XLOG_OPTS_DEFAULT, XLOG_COLOR_YEL,  XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_ERROR(...)     XLOGD(XLOG_LEVEL_ERROR, XLOG_OPTS_DEFAULT, XLOG_COLOR_RED,  XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_FATAL(...)     do { XLOGD(XLOG_LEVEL_FATAL, XLOG_OPTS_DEFAULT, XLOG_COLOR_RED, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__); XLOG_FLUSH(); } while(0)
#define XLOGD_TELEMETRY(...) XLOGD(XLOG_LEVEL_TELEMETRY, XLOG_OPTS_DEFAULT, XLOG_COLOR_BLU,  XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)

#define XLOGD_DEBUG_COLOR(COLOR, ...)  XLOGD(XLOG_LEVEL_DEBUG,  XLOG_OPTS_DEFAULT, COLOR, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_INFO_COLOR(COLOR, ...)   XLOGD(XLOG_LEVEL_INFO,   XLOG_OPTS_DEFAULT, COLOR, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_WARN_COLOR(COLOR, ...)   XLOGD(XLOG_LEVEL_WARN,   XLOG_OPTS_DEFAULT, COLOR, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_ERROR_COLOR(COLOR, ...)  XLOGD(XLOG_LEVEL_ERROR,  XLOG_OPTS_DEFAULT, COLOR, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#define XLOGD_FATAL_COLOR(COLOR, ...)  do { XLOGD(XLOG_LEVEL_FATAL,  XLOG_OPTS_DEFAULT, COLOR, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__); XLOG_FLUSH(); } while(0)

#define XLOGD_DEBUG_OPTS(OPTS, BUF_SIZE, ...)  XLOGD(XLOG_LEVEL_DEBUG,  OPTS, XLOG_COLOR_GRN,  BUF_SIZE, __VA_ARGS__)
#define XLOGD_INFO_OPTS(OPTS, BUF_SIZE, ...)   XLOGD(XLOG_LEVEL_INFO,   OPTS, XLOG_COLOR_NONE, BUF_SIZE, __VA_ARGS__)
#define XLOGD_WARN_OPTS(OPTS, BUF_SIZE, ...)   XLOGD(XLOG_LEVEL_WARN,   OPTS, XLOG_COLOR_YEL,  BUF_SIZE, __VA_ARGS__)
#define XLOGD_ERROR_OPTS(OPTS, BUF_SIZE, ...)  XLOGD(XLOG_LEVEL_ERROR,  OPTS, XLOG_COLOR_RED,  BUF_SIZE, __VA_ARGS__)
#define XLOGD_FATAL_OPTS(OPTS, BUF_SIZE, ...)  do { XLOGD(XLOG_LEVEL_FATAL,  OPTS, XLOG_COLOR_RED, BUF_SIZE, __VA_ARGS__); XLOG_FLUSH(); } while(0)

#define XLOGD_SAFE(LEVEL, OPTS, COLOR, BUF_SIZE, STRING) do { if(LEVEL < g_xlog_modules[XLOG_MODULE_ID]) { break; } XLOG_STATIC_ARGS const xlog_args_t xlog_args__ = {.options = OPTS, .color = COLOR, .function = XLOG_PARAM_FUNCTION, .line = XLOG_PARAM_LINE, .level = LEVEL, .id = XLOG_MODULE_ID, .size_max = BUF_SIZE}; xlog_fprintf_safe(&xlog_args__, XLOGD_OUTPUT, STRING);} while(0)

#define XLOGD_SAFE_DEBUG(STRING) XLOGD_SAFE(XLOG_LEVEL_DEBUG, XLOG_OPTS_DEFAULT, XLOG_COLOR_GRN,  XLOG_BUF_SIZE_DEFAULT, STRING)
#define XLOGD_SAFE_INFO(STRING)  XLOGD_SAFE(XLOG_LEVEL_INFO,  XLOG_OPTS_DEFAULT, XLOG_COLOR_NONE, XLOG_BUF_SIZE_DEFAULT, STRING)
#define XLOGD_SAFE_WARN(STRING)  XLOGD_SAFE(XLOG_LEVEL_WARN,  XLOG_OPTS_DEFAULT, XLOG_COLOR_YEL,  XLOG_BUF_SIZE_DEFAULT, STRING)
#define XLOGD_SAFE_ERROR(STRING) XLOGD_SAFE(XLOG_LEVEL_ERROR, XLOG_OPTS_DEFAULT, XLOG_COLOR_RED,  XLOG_BUF_SIZE_DEFAULT, STRING)
#define XLOGD_SAFE_FATAL(STRING) XLOGD_SAFE(XLOG_LEVEL_FATAL, XLOG_OPTS_DEFAULT, XLOG_COLOR_RED,  XLOG_BUF_SIZE_DEFAULT, STRING)

// Static log macros
#if (XLOG_LEVEL <= XLOG_PP_LEVEL_DEBUG)
   #define XLOG_DEBUG(...) XLOG(XLOG_LEVEL_DEBUG, XLOG_OPTS_DEFAULT, XLOG_COLOR_GRN, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#else
   #define XLOG_DEBUG(...) do { } while(0)
#endif

#if (XLOG_LEVEL <= XLOG_PP_LEVEL_INFO)
   #define XLOG_INFO(...) XLOG(XLOG_LEVEL_INFO, XLOG_OPTS_DEFAULT, XLOG_COLOR_NONE, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#else
   #define XLOG_INFO(...) do { } while(0)
#endif

#if (XLOG_LEVEL <= XLOG_PP_LEVEL_WARN)
   #define XLOG_WARN(...) XLOG(XLOG_LEVEL_WARN, XLOG_OPTS_DEFAULT, XLOG_COLOR_YEL, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#else
   #define XLOG_WARN(...) do { } while(0)
#endif

#if (XLOG_LEVEL <= XLOG_PP_LEVEL_ERROR)
   #define XLOG_ERROR(...) XLOG(XLOG_LEVEL_ERROR, XLOG_OPTS_DEFAULT, XLOG_COLOR_RED, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#else
   #define XLOG_ERROR(...) do { } while(0)
#endif

#if (XLOG_LEVEL <= XLOG_PP_LEVEL_FATAL)
   #define XLOG_FATAL(...) do { XLOG(XLOG_LEVEL_FATAL, XLOG_OPTS_DEFAULT, XLOG_COLOR_RED, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__); XLOG_FLUSH(); } while(0)
#else
   #define XLOG_FATAL(...) do { } while(0)
#endif

#if (XLOG_LEVEL <= XLOG_PP_LEVEL_TELEMETRY)
   #define XLOG_TELEMETRY(...) XLOG(XLOG_LEVEL_TELEMETRY, XLOG_OPTS_DEFAULT, XLOG_COLOR_BLU, XLOG_BUF_SIZE_DEFAULT, __VA_ARGS__)
#else
   #define XLOG_TELEMETRY(...) do { } while(0)
#endif

#endif

