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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "jansson.h"
#define XLOG_RDK_PLATFORM 
#ifdef XLOG_RDK_PLATFORM
#include "rdkversion.h"
#endif
#define XLOG_MODULE_ID XLOG_MODULE_ID_XLOG
#include "rdkx_logger.h"
#include "rdkx_logger_private.h"
#include "errno.h"
#ifdef XLOG_USE_CURTAIL
#include "curtail.h"
#endif

#define XLOG_PREFIX_SIZE (22)

#ifndef XLOG_CONFIG_FILE_DIR_NAME_PRD
#define XLOG_CONFIG_FILE_DIR_NAME_PRD "/etc"
#endif

#ifndef XLOG_CONFIG_FILE_DIR_NAME_DEV
#define XLOG_CONFIG_FILE_DIR_NAME_DEV "/opt"
#endif

#define XLOG_CONFIG_FILE_PRD      XLOG_CONFIG_FILE_DIR_NAME_PRD "/rdkx_logger.json"
#define XLOG_CONFIG_FILE_PRD_ROOT XLOG_CONFIG_FILE_DIR_NAME_PRD "/rdkx_logger_"
#define XLOG_CONFIG_FILE_DEV      XLOG_CONFIG_FILE_DIR_NAME_DEV "/rdkx_logger.json"
#define XLOG_CONFIG_FILE_DEV_ROOT XLOG_CONFIG_FILE_DIR_NAME_DEV "/rdkx_logger_"

xlog_level_t  g_xlog_modules[XLOG_MODULE_QTY_MAX];

static bool          g_xlog_init       = false;
static xlog_print_t  g_xlog_print      = NULL;
static xlog_print_t  g_xlog_print_safe = NULL;

#ifdef XLOG_USE_CURTAIL
static bool g_crtl_init = false;
#endif

static const xlog_args_t g_xlog_args_default = {
   .options   = XLOG_OPTS_DEFAULT,
   .color     = XLOG_COLOR_NONE,
   .function  = XLOG_FUNCTION_NONE,
   .line      = XLOG_LINE_NONE,
   .level     = XLOG_LEVEL_INFO,
   .id        = XLOG_MODULE_ID_XLOG,
   .size_max  = XLOG_BUF_SIZE_DEFAULT
};

extern const char * const g_xlog_module_id_to_str[];

static int      xlog_init_int(xlog_module_id_t id, const char *filename, uint32_t file_size_max, xlog_print_t print, xlog_print_t print_safe);
static uint32_t xlog_date_time(const xlog_args_t *args, char *buffer);
static int      xlog_prefix(const xlog_args_t *args, char *str, size_t size);
static int      xlog_postfix(const xlog_args_t *args, char *str, size_t size);

#define MACRO_LEVEL_CHECK
#ifndef MACRO_LEVEL_CHECK
static __inline bool xlog_level_enabled(xlog_module_id_t id, xlog_level_t level);
#endif

static __inline int     xlog_vfprintf_dvi(const xlog_args_t *args, FILE *stream, const char *format, va_list ap);
static __inline int     xlog_vdprintf_dvi(const xlog_args_t *args, int fd, const char *format, va_list ap);
static __inline int     xlog_vsnprintf_dvi(const xlog_args_t *args, char *str, size_t size, const char *format, va_list ap);

static xlog_level_t     xlog_level_str_to_enum(const char *level);
static xlog_module_id_t xlog_module_to_id(const char *module);
static json_t *         xlog_config_load(xlog_module_id_t id);
static bool             xlog_file_get_contents(const char *file, char **contents);

#ifndef XLOG_PREFIX_SIZE
#error XLOG_PREFIX_SIZE is not defined
#elif XLOG_PREFIX_SIZE < 22
#error XLOG_PREFIX_SIZE is too small
#endif

int xlog_init(xlog_module_id_t id, const char *filename, uint32_t file_size_max) {
   return(xlog_init_int(id, filename, file_size_max, NULL, NULL));
}

int xlog_init_user_print(xlog_module_id_t id, xlog_print_t print, xlog_print_t print_safe) {
   return(xlog_init_int(id, NULL, 0, print, print_safe));
}

int xlog_init_int(xlog_module_id_t id, const char *filename, uint32_t file_size_max, xlog_print_t print, xlog_print_t print_safe) {
   if(g_xlog_init) {
      XLOGD_WARN("Already initialized");
      return(-1);
   }
   g_xlog_init = true;
   XLOGD_INFO("Initializing...");

   if(filename != NULL) {
      #ifndef XLOG_USE_CURTAIL
      XLOGD_WARN("curtail is not enabled. ignoring filename parameter.");
      #else
      XLOGD_INFO("crtl_init...");
      g_crtl_init = crtl_init(filename, file_size_max, CRTL_LEVEL_WARN, false);
      if(!g_crtl_init) {
         int errsv = errno;
         XLOGD_WARN("curtail init error <%s>", strerror(errsv));
         return(-1);
      }
      #endif
   }
   g_xlog_print_safe = print_safe;
   g_xlog_print      = print;

   // First, initialize to INFO level
   for(uint32_t index = 0; index < XLOG_MODULE_QTY_MAX; index++) {
      g_xlog_modules[index] = XLOG_LEVEL_INFO;
   }

   // Load module name and level from config file
   json_t *obj = xlog_config_load(id);

   if(obj == NULL) {
      return(0);
   }
   if(!json_is_object(obj)) {
      XLOGD_ERROR("unable to load config file - not a json object");
      return(0);
   }

   const char *module;
   json_t *value;

   json_object_foreach(obj, module, value) {
       if(!json_is_string(value)) {
          XLOGD_WARN("module <%s> value is not a string", module);
          continue;
       }
       const char *level_str = json_string_value(value);
       if(level_str == NULL) {
          XLOGD_WARN("module <%s> value string is NULL", module);
          continue;
       }
       xlog_module_id_t module_id = xlog_module_to_id(module);
       if(((uint32_t)module_id) >= XLOG_MODULE_QTY_MAX) {
          XLOGD_WARN("module <%s> not found", module);
          continue;
       }
       xlog_level_t level = xlog_level_str_to_enum(level_str);
       if(((uint32_t)level) >= XLOG_LEVEL_INVALID) {
          XLOGD_WARN("module <%s> level <%s> is invalid", module, level_str);
          continue;
       }

       g_xlog_modules[module_id] = level;
       XLOGD_INFO("module <%s> level <%s>", module, level_str);
   }

   json_decref(obj);

   return(0);
}

void xlog_term(void) {
   #ifdef XLOG_USE_CURTAIL
   if(g_crtl_init) {
      crtl_term();
      g_crtl_init = false;
   }
   #endif
}

json_t *xlog_config_load(xlog_module_id_t id) {
   const char *config_fn_dev   = XLOG_CONFIG_FILE_DEV;
   const char *config_fn_prd   = XLOG_CONFIG_FILE_PRD;
   char config_fn_dev_mod[128] = { '\0' };
   char config_fn_prd_mod[128] = { '\0' };
   char *contents = NULL;

   #ifdef XLOG_RDK_PLATFORM
   // Get production flag
   rdk_version_info_t info;
   memset(&info, 0, sizeof(info));

   bool is_production = true;

   if(0 == rdk_version_parse_version(&info)) {
      is_production = info.production_build;
   }
   rdk_version_object_free(&info);
   #else
   bool is_production = false;
   #endif

   // Get module string
   bool module_valid = true;
   if(((uint32_t)id) >= XLOG_MODULE_ID_INVALID) {
      XLOGD_WARN("invalid module id <%d>", id);
      module_valid = false;
   } else {
      snprintf(config_fn_dev_mod, sizeof(config_fn_dev_mod), "%s%s.json", XLOG_CONFIG_FILE_DEV_ROOT, g_xlog_module_id_to_str[id]);
      snprintf(config_fn_prd_mod, sizeof(config_fn_prd_mod), "%s%s.json", XLOG_CONFIG_FILE_PRD_ROOT, g_xlog_module_id_to_str[id]);
   }

   if(!is_production && module_valid && (0 == access(config_fn_dev_mod, F_OK)) && xlog_file_get_contents(config_fn_dev_mod, &contents)) {
      XLOGD_INFO("Read configuration from <%s>", config_fn_dev_mod);
   } else if(!is_production && (0 == access(config_fn_dev, F_OK)) && xlog_file_get_contents(config_fn_dev, &contents)) {
      XLOGD_INFO("Read configuration from <%s>", config_fn_dev);
   } else if(module_valid && (0 == access(config_fn_prd_mod, F_OK)) && xlog_file_get_contents(config_fn_prd_mod, &contents)) {
      XLOGD_INFO("Read configuration from <%s>", config_fn_prd_mod);
   } else if((0 == access(config_fn_prd, F_OK)) && xlog_file_get_contents(config_fn_prd, &contents)) {
      XLOGD_INFO("Read configuration from <%s>", config_fn_prd);
   } else {
      XLOGD_WARN("Configuration error. Configuration file(s) missing, using defaults");
      return(NULL);
   }

   if(NULL == contents) {
      XLOGD_WARN("Configuration error. Empty configuration file, using defaults");
      return(NULL);
   }
   json_error_t json_error;
   memset(&json_error, 0, sizeof(json_error));
   json_t *obj = json_loads(contents, JSON_REJECT_DUPLICATES, &json_error);
   free(contents);

   if(obj == NULL) {
      XLOGD_ERROR("unable to load config file <%s>", json_error.text ? json_error.text : "");
   }
   return(obj);
}

bool xlog_file_get_contents(const char *file, char **contents) {
   int fd = -1;
   if(file == NULL || contents == NULL) {
      XLOGD_ERROR("invalid params");
      return(false);
   }
   XLOGD_DEBUG("open <%s>", file);
   // Open file
   do {
      errno = 0;
      fd = open(file, O_RDONLY, 0444);
      if(fd < 0) {
         if(errno == EINTR) {
            continue;
         }
         int errsv = errno;
         XLOGD_ERROR("file open <%s>", strerror(errsv));
         return(false);
      }
      break;
   } while(1);

   // Get size
   off_t file_size = 0;
   do {
      file_size = lseek(fd, 0, SEEK_END);
      if(file_size < 0) {
         if(errno == EINTR) {
            continue;
         }
         int errsv = errno;
         XLOGD_ERROR("unable to seek end of file <%s>", strerror(errsv));
         close(fd);
         return(false);
      }
      if(file_size == 0) {
         XLOGD_ERROR("empty file");
         close(fd);
         return(false);
      }
      break;
   } while(1);

   // Seek to beginning of file
   do {
      if(lseek(fd, 0, SEEK_SET) < 0) {
         if(errno == EINTR) {
            continue;
         }
         int errsv = errno;
         XLOGD_ERROR("unable to seek start of file <%s>", strerror(errsv));
         close(fd);
         return(false);
      }
      break;
   } while(1);

   // Allocate memory
   *contents = malloc(file_size + 1);

   if(*contents == NULL) {
      XLOGD_ERROR("out of memory <%u>", file_size);
      close(fd);
      return(false);
   }

   // Read contents
   bool result = false;
   do {
      ssize_t bytes_read = read(fd, *contents, file_size);
      if(bytes_read < 0) {
         if(errno == EINTR) {
            continue;
         }
         int errsv = errno;
         XLOGD_ERROR("read error <%s>", strerror(errsv));
         break;
      }
      if(bytes_read != file_size) {
         XLOGD_ERROR("read error <%u> <%u>", bytes_read, file_size);
         break;
      }
      // Null terminate the contents
      (*contents)[file_size] = '\0';
      XLOGD_DEBUG("read <%s>", *contents);
      result = true;
      break;
   } while(1);

   close(fd);

   if(!result) {
      free(*contents);
      *contents = NULL;
   }

   return(result);
}

#ifdef MACRO_LEVEL_CHECK
// NOTE: The level check has been removed from the macro for a small speedup as no adverse effects should occur.  If level is
//       invalid, the result will be to print the message.
#define xlog_level_enabled(id, level) ({          \
   if(((uint32_t)id) >= XLOG_MODULE_ID_INVALID) { \
      XLOGD_WARN("invalid module id <%d>", id);   \
      return(false);                              \
   }                                              \
   (level >= g_xlog_modules[id]);                 \
})
#else
bool xlog_level_enabled(xlog_module_id_t id, xlog_level_t level) {
   if(((uint32_t)id) >= XLOG_MODULE_ID_INVALID) {
      XLOGD_WARN("invalid module id <%d>", id);
      return(false);
   }
   if(((uint32_t)level) >= XLOG_LEVEL_INVALID) {
      XLOGD_WARN("invalid level <%d>", level);
      return(false);
   }
   //printf("%s: module <%s> id <%d> level <%d> log level <%u> enabled <%s>\n", __FUNCTION__, g_xlog_module_id_to_str[id], id, g_xlog_modules[id], level, (level >= g_xlog_modules[id]) ? "YES" : "NO");
   return(level >= g_xlog_modules[id]);
}
#endif

xlog_level_t xlog_level_str_to_enum(const char *level) {
   rdkx_logger_level_t *mod = rdkx_logger_level_str_to_num(level, strlen(level));

   if(mod == NULL || ((uint32_t)mod->level) >= XLOG_LEVEL_INVALID) {
      return(XLOG_LEVEL_INVALID);
   }

   return((xlog_level_t)mod->level);
}

xlog_module_id_t xlog_module_to_id(const char *module) {
   rdkx_logger_module_t *mod = rdkx_logger_module_str_to_index(module, strlen(module));

   if(mod == NULL) {
      return(XLOG_MODULE_QTY_MAX);
   }

   return(mod->id);
}

xlog_level_t xlog_level_get(xlog_module_id_t id) {
   if(((uint32_t)id) >= XLOG_MODULE_ID_INVALID) {
      return(XLOG_LEVEL_INVALID);
   }

   if(((uint32_t)g_xlog_modules[id]) >= XLOG_LEVEL_INVALID) {
      return(XLOG_LEVEL_INVALID);
   }
   return(g_xlog_modules[id]);
}

void xlog_level_set(xlog_module_id_t id, xlog_level_t level) {
   if(((uint32_t)level) >= XLOG_LEVEL_INVALID) {
      XLOGD_ERROR("invalid log level <%d>", level);
      return;
   }

   if(((uint32_t)id) >= XLOG_MODULE_QTY_MAX) {
      XLOGD_ERROR("invalid module id <%d>", id);
      return;
   }

   g_xlog_modules[id] = level;
}

void xlog_level_set_all(xlog_level_t level) {
   if(((uint32_t)level) >= XLOG_LEVEL_INVALID) {
      XLOGD_ERROR("invalid log level <%d>", level);
      return;
   }
   for(uint32_t id = 0; id < XLOG_MODULE_QTY_MAX; id++) {
      g_xlog_modules[id] = level;
   }
}

bool xlog_level_active(xlog_module_id_t id, xlog_level_t level) {
   return(xlog_level_enabled(id, level));
}

uint32_t xlog_date_time(const xlog_args_t *args, char *buffer) {
   if(buffer == NULL) {
      return(0);
   }
   if(!(args->options & (XLOG_OPTS_DATE | XLOG_OPTS_TIME))) {
      buffer[0] = '\n';
      return(0);
   }

   struct tm tm_val;
   struct timeval tv;

   uint16_t msecs;
   gettimeofday(&tv, NULL);
   if(args->options & XLOG_OPTS_GMT) {
      gmtime_r(&tv.tv_sec, &tm_val);
   } else {
      localtime_r(&tv.tv_sec, &tm_val);
   }
   msecs = (uint16_t)(tv.tv_usec/1000);
   
   size_t rc = 0;
   if((args->options & (XLOG_OPTS_DATE | XLOG_OPTS_TIME)) == (XLOG_OPTS_DATE | XLOG_OPTS_TIME)) {
      rc = strftime(buffer, 18, "%Y%m%d %T", &tm_val);
   } else if(args->options & XLOG_OPTS_TIME) {
      rc = strftime(buffer, 18, "%T", &tm_val);
   } else if(args->options & XLOG_OPTS_DATE) {
      rc = strftime(buffer, 18, "%Y%m%d", &tm_val);
   }
   
   if(args->options & XLOG_OPTS_TIME && (rc + 5 <= XLOG_PREFIX_SIZE)) {
      //printing milliseconds as ":XXX "
      buffer[rc + 4] = '\0';                             //Null terminate milliseconds
      buffer[rc + 3] = (msecs % 10) + '0'; msecs  /= 10; //get the 1's digit
      buffer[rc + 2] = (msecs % 10) + '0'; msecs  /= 10; //get the 10's digit
      buffer[rc + 1] = (msecs % 10) + '0';               //get the 100's digit
      buffer[rc] = ':';
   }
   return(rc + 4);
}

int xlog_prefix(const xlog_args_t *args, char *str, size_t size) {
   int used = 0;
   // Color Begin (copy direct to destination)
   if((args->options & XLOG_OPTS_COLOR) && args->color != NULL && (size >= (sizeof(XLOG_COLOR_NRM) + 1))) {
      size_t len = strlen(args->color);
      if(len < 4 || len > 5) {
         return(-1);
      }
      memcpy(&str[used], args->color, len + 1);
      used += len;
   }
   // Date and Time
   if(args->options & (XLOG_OPTS_DATE | XLOG_OPTS_TIME) && ((size - used) > XLOG_PREFIX_SIZE)) {
      used += xlog_date_time(args, &str[used]);
      str[used++] = ' ';
   }

   // Module Name
   uint32_t name_len = strlen(g_xlog_module_id_to_str[args->id]); // TODO: create lookup table for this
   if((args->options & XLOG_OPTS_MOD_NAME) && ((size - used) > name_len)) {
      memcpy(&str[used], g_xlog_module_id_to_str[args->id], name_len);
      used += name_len;
      str[used++] = ' ';
   }

   if((args->options & XLOG_OPTS_LEVEL) && args->level >= XLOG_LEVEL_WARN && (size - used) > 9) {
      str[used++] = ':';
      str[used++] = ' ';
      if(args->level == XLOG_LEVEL_WARN) {
         str[used++] = 'W';
         str[used++] = 'A';
         str[used++] = 'R';
         str[used++] = 'N';
      } else if(args->level == XLOG_LEVEL_ERROR) {
         str[used++] = 'E';
         str[used++] = 'R';
         str[used++] = 'R';
         str[used++] = 'O';
         str[used++] = 'R';
      } else if(args->level == XLOG_LEVEL_FATAL) {
         str[used++] = 'F';
         str[used++] = 'A';
         str[used++] = 'T';
         str[used++] = 'A';
         str[used++] = 'L';
      } else if(args->level == XLOG_LEVEL_TELEMETRY) {
         str[used++] = 'T';
         str[used++] = 'E';
         str[used++] = 'L';
         str[used++] = 'E';
      } else {
         str[used++] = 'I';
         str[used++] = 'N';
         str[used++] = 'V';
         str[used++] = 'A';
         str[used++] = 'L';
         str[used++] = 'I';
         str[used++] = 'D';
      }
      str[used]   = '\0';
   }

   // Function
   if(args->function != NULL && (size - used)>2) {
      str[used++] = ':';
      str[used++] = ' ';
      uint32_t func_len = strlen(args->function);
      if(((size - used) > func_len)) {
         memcpy(&str[used], args->function, func_len);
         used += func_len;
      }
   }

   // Line Number
   if(args->line >= 0){
      int line = args->line;
      str[used++] = '(';

      uint8_t digit_qty = 10;
      if(line < 10) {
         digit_qty = 1;
      } else if(line < 100) {
         digit_qty = 2;
      } else if(line < 1000) {
         digit_qty = 3;
      } else if(line < 10000) {
         digit_qty = 4;
      } else if(line < 100000) {
         digit_qty = 5;
      } else if(line < 1000000) {
         digit_qty = 6;
      } else if(line < 10000000) {
         digit_qty = 7;
      } else if(line < 100000000) {
         digit_qty = 8;
      } else if(line < 1000000000) {
         digit_qty = 9;
      }

      used += digit_qty;
      for(uint8_t index = 1; index <= digit_qty; index++) {
         str[used - index] = (line % 10) + '0';
         line /= 10;
      }

      str[used++] = ')';
   }

   if((size - used) > 2) {
      str[used++] = ':';
      str[used++] = ' ';
      str[used]   = '\0';
   }

   return(used);
}

int xlog_postfix(const xlog_args_t *args, char *str, size_t size) {
   int used = 0;
   // Color End (copy direct to destination)
   if((args->options & XLOG_OPTS_COLOR) && args->color != NULL && (size_t)(used + sizeof(XLOG_COLOR_NRM) - 1) < size) {
      memcpy(&str[used], XLOG_COLOR_NRM, sizeof(XLOG_COLOR_NRM));
      used += sizeof(XLOG_COLOR_NRM) - 1;
   }

   // Line Feed (copy direct to destination)
   if((args->options & XLOG_OPTS_LF) && ((size_t)(used + 1) < size)) {
      str[used++] = '\n';
      str[used]   = '\0';
   }
   return(used);
}

int xlog_printf_safe(const xlog_args_t *args, const char *string) {
   return(xlog_fprintf_safe(args, stdout, string));
}

int xlog_fprintf_safe(const xlog_args_t *args, FILE *stream, const char *string) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(string == NULL) {
      return(-1);
   }
   char buffer[(args->size_max == 0) ? XLOG_BUF_SIZE_DEFAULT : args->size_max];

   int rc = xlog_prefix(args, buffer, sizeof(buffer));

   if(rc < 0) {
      return(rc);
   }
   size_t size = sizeof(buffer);
   size_t used = rc;

   uint32_t str_len = strlen(string);
   if(((size - used) > str_len)) {
      memcpy(&buffer[used], string, str_len);
      used += str_len;
   }

   rc = xlog_postfix(args, &buffer[used], sizeof(buffer) - used);

   if(rc < 0) {
      return(rc);
   }
   used += rc;

   if(g_xlog_print_safe != NULL) {
      return(g_xlog_print_safe(args->level, buffer, ((size_t)used > sizeof(buffer)) ? sizeof(buffer) : used));
   }

   return(fwrite(buffer, 1, ((size_t)used > sizeof(buffer)) ? sizeof(buffer) : used, stream));
}

int xlog_printf(const xlog_args_t *args, const char *format, ...) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(format == NULL) {
      XLOGD_WARN("NULL format string");
      return(-1);
   }
   va_list ap;
   va_start(ap, format);
   int rc = xlog_vfprintf_dvi(args, stdout, format, ap);
   va_end(ap);
   return(rc);
}

int xlog_fprintf(const xlog_args_t *args, FILE *stream, const char *format, ...) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(format == NULL) {
      XLOGD_WARN("NULL format string");
      return(-1);
   }
   if(stream == NULL) {
      XLOGD_WARN("NULL stream");
      return(-1);
   }

   va_list ap;
   va_start(ap, format);
   int rc = xlog_vfprintf_dvi(args, stream, format, ap);
   va_end(ap);
   return(rc);
}

int xlog_dprintf(const xlog_args_t *args, int fd, const char *format, ...) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(format == NULL) {
      XLOGD_WARN("NULL format string");
      return(-1);
   }
   if(fd < 0) {
      XLOGD_WARN("Invalid fd <%d>", fd);
      return(-1);
   }

   va_list ap;
   va_start(ap, format);
   int rc = xlog_vdprintf_dvi(args, fd, format, ap);
   va_end(ap);
   
   return(rc);
}

int xlog_snprintf(const xlog_args_t *args, char *str, size_t size, const char *format, ...) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(format == NULL) {
      XLOGD_WARN("NULL format string");
      return(-1);
   }
   if(str == NULL) {
      XLOGD_WARN("NULL buffer");
      return(-1);
   }

   va_list ap;
   va_start(ap, format);
   int rc = xlog_vsnprintf_dvi(args, str, size, format, ap);
   va_end(ap);

   return(rc);
}

int xlog_vfprintf(const xlog_args_t *args, FILE *stream, const char *format, va_list ap) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(format == NULL) {
      XLOGD_WARN("NULL format string");
      return(-1);
   }
   if(stream == NULL) {
      XLOGD_WARN("NULL stream");
      return(-1);
   }

   return(xlog_vfprintf_dvi(args, stream, format, ap));
}

int xlog_vfprintf_dvi(const xlog_args_t *args, FILE *stream, const char *format, va_list ap) {
   char buffer[(args->size_max == 0) ? XLOG_BUF_SIZE_DEFAULT : args->size_max];
   
   int rc = xlog_prefix(args, buffer, sizeof(buffer));

   if(rc < 0) {
      return(rc);
   }
   size_t used = rc;

   do {
      if(used >= sizeof(buffer)) {
         break;
      }
   
      rc = vsnprintf(&buffer[used], sizeof(buffer) - used, format, ap);
   
      if(rc < 0) {
         break;
      }
      used += rc;
   
      if(used >= sizeof(buffer)) {
         break;
      }
      rc = xlog_postfix(args, &buffer[used], sizeof(buffer) - used);
   
      if(rc < 0) {
         break;
      }
      used += rc;
   } while(0);
   
   if(rc < 0) {
      return(rc);
   }

   if(g_xlog_print != NULL) {
      return(g_xlog_print(args->level, buffer, ((size_t)used > sizeof(buffer)) ? sizeof(buffer) : used));
   }

   return(fwrite(buffer, 1, ((size_t)used > sizeof(buffer)) ? sizeof(buffer) : used, stream));
}

int xlog_vdprintf(const xlog_args_t *args, int fd, const char *format, va_list ap) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(format == NULL) {
      XLOGD_WARN("NULL format string");
      return(-1);
   }
   if(fd < 0) {
      XLOGD_WARN("Invalid fd <%d>", fd);
      return(-1);
   }

   return(xlog_vdprintf_dvi(args, fd, format, ap));
}

int xlog_vdprintf_dvi(const xlog_args_t *args, int fd, const char *format, va_list ap) {
   char buffer[(args->size_max == 0) ? XLOG_BUF_SIZE_DEFAULT : args->size_max];

   int rc = xlog_prefix(args, buffer, sizeof(buffer));

   if(rc < 0) {
      return(rc);
   }
   size_t used = rc;
   
   do {
      if(used >= sizeof(buffer)) {
         break;
      }
   
      rc = vsnprintf(&buffer[used], sizeof(buffer) - used, format, ap);
   
      if(rc < 0) {
         break;
      }
      used += rc;
   
      if((size_t)used >= sizeof(buffer)) {
         break;
      }
      rc = xlog_postfix(args, &buffer[used], sizeof(buffer) - used);
   
      if(rc < 0) {
         break;
      }
      used += rc;
   } while(0);
   
   if(rc < 0) {
      return(rc);
   }
   
   return(write(fd, buffer, (used > sizeof(buffer)) ? sizeof(buffer) : used));
}

int xlog_vsnprintf(const xlog_args_t *args, char *str, size_t size, const char *format, va_list ap) {
   if(args == NULL) {
      args = &g_xlog_args_default;
   } else if(!xlog_level_enabled(args->id, args->level)) {
      return(0);
   }
   if(format == NULL) {
      XLOGD_WARN("NULL format string");
      return(-1);
   }
   if(str == NULL) {
      XLOGD_WARN("NULL buffer");
      return(-1);
   }

   return(xlog_vsnprintf_dvi(args, str, size, format, ap));
}

int xlog_vsnprintf_dvi(const xlog_args_t *args, char *str, size_t size, const char *format, va_list ap) {
   int used = xlog_prefix(args, str, size);

   if(used < 0) {
      return(used);
   }

   if((size_t)used >= size) {
      return(used);
   }

   int rc = vsnprintf(&str[used], size - used, format, ap);

   if(rc < 0) {
      return(rc);
   }
   used += rc;

   if((size_t)used >= size) {
      return(used);
   }
   rc = xlog_postfix(args, &str[used], size - used);

   if(rc < 0) {
      return(rc);
   }
   used += rc;

   return(used);
}
