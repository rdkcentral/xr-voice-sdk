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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <bsd/string.h>
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRFDC
#include <rdkx_logger.h>
#include <xr_fdc.h>

#define XR_FDC_PATH "/proc/self/fd/"

static int32_t xr_fdc_fd_iterate(bool print);
static void    xr_fdc_print(bool header, int fd);
static void    xr_fdc_flags_str(int flags, char *buf, uint32_t len);
static void    xr_fdc_mode_str(mode_t mode, char *buf, uint32_t len);

// Return the number of open fd's for the process
int32_t xr_fdc_fd_qty_get(void) {
   return(xr_fdc_fd_iterate(false));
}

int32_t xr_fdc_fd_iterate(bool print) {
   int fd_qty = -1;
   
   errno = 0;
   DIR *dirp = opendir(XR_FDC_PATH);
   
   if(dirp == NULL) {
      int errsv = errno;
      XLOGD_ERROR("opendir failed <%s>", strerror(errsv));
      return(fd_qty);
   }
   
   if(print) {
      xr_fdc_print(true, -1);
   }
   
   struct dirent *direntp;
   do {
      errno = 0;
      direntp = readdir(dirp);
      fd_qty++;
      
      if(errno != 0) {
         int errsv = errno;
         XLOGD_ERROR("readdir failed <%s>", strerror(errsv));
         fd_qty = -1;
      }
      if(direntp == NULL || direntp->d_name == NULL) {
         continue;
      } else if(direntp->d_name[0] == '.') { // Skip . and ..
         fd_qty--;
         continue;
      }
      if(print) {
         errno = 0;
         int fd = strtol(direntp->d_name, NULL, 10);
         if(errno != 0) {
            int errsv = errno;
            XLOGD_ERROR("strtol failed <%s>", strerror(errsv));
         } else {
            xr_fdc_print(false, fd);
         }
      }
   } while(direntp != NULL);
   
   closedir(dirp);
   return(fd_qty);
}

int32_t xr_fdc_check(uint32_t limit_soft, uint32_t limit_hard, bool print) {
   XLOGD_DEBUG("limit soft <%u> hard <%u> print <%s>", limit_soft, limit_hard, print ? "YES" : "NO");
   int fd_qty = xr_fdc_fd_qty_get();
   if(fd_qty < 0) {
      return(fd_qty);
   }
   
   if(fd_qty >= limit_hard) {
      XLOGD_ERROR("hard limit reached <%d>", fd_qty);
      if(print) { // Iterate over each fd and print details about it
         xr_fdc_fd_iterate(true);
      }
      return(1);
   } else if(fd_qty >= limit_soft) {
      XLOGD_WARN("soft limit reached <%d>", fd_qty);
   }
   return(0);
}

void xr_fdc_print(bool header, int fd) {
   if(header) {
      XLOGD_INFO("%4s : %16s | %16s", "fd", "flags", "mode");
      return;
   }
   char flags_str[32];
   char mode_str[32];
   char *flags = flags_str;
   char *mode  = mode_str;
   if(fd < 0 || fd > FD_SETSIZE) {
      flags = "UNKNOWN";
      mode  = "UNKNOWN";
   } else {
      flags_str[0] = '\0';
      mode_str[0]  = '\0';
      int rc = fcntl(fd, F_GETFL);
      if(rc < 0) {
         int errsv = errno;
         snprintf(flags_str, sizeof(flags_str), "%s", strerror(errsv));
      } else {
         xr_fdc_flags_str(rc, flags_str, sizeof(flags_str));
      }
      struct stat buf_stat;
      rc = fstat(fd, &buf_stat);
      if(rc < 0) {
         int errsv = errno;
         snprintf(mode_str, sizeof(mode_str), "%s", strerror(errsv));
      } else {
         xr_fdc_mode_str(buf_stat.st_mode, mode_str, sizeof(mode_str));
      }
   }
   XLOGD_INFO("%4d : %17s| %16s", fd, flags, mode);
}

void xr_fdc_flags_str(int flags, char *buf, uint32_t len) {
   buf[0] = '\0';
   if(flags & O_APPEND)    { strlcat(buf, "APPEND ", len);    }
   if(flags & O_ASYNC)     { strlcat(buf, "ASYNC ", len);     }
   if(flags & O_CLOEXEC)   { strlcat(buf, "CLOEXEC ", len);   }
   if(flags & O_CREAT)     { strlcat(buf, "CREAT ", len);     }
   #ifdef O_DIRECT
   if(flags & O_DIRECT)    { strlcat(buf, "DIRECT ", len);    }
   #endif
   if(flags & O_DIRECTORY) { strlcat(buf, "DIRECTORY ", len); }
   if(flags & O_DSYNC)     { strlcat(buf, "DSYNC ", len);     }
   if(flags & O_EXCL)      { strlcat(buf, "EXCL ", len);      }
   #ifdef O_LARGEFILE
   if(flags & O_LARGEFILE) { strlcat(buf, "LARGEFILE ", len); }
   #endif
   #ifdef O_NOATIME
   if(flags & O_NOATIME)   { strlcat(buf, "NOATIME ", len);   }
   #endif
   if(flags & O_NOCTTY)    { strlcat(buf, "NOCTTY ", len);    }
   if(flags & O_NOFOLLOW)  { strlcat(buf, "NOFOLLOW ", len);  }
   if(flags & O_NONBLOCK)  { strlcat(buf, "NONBLOCK ", len);  }
   #ifdef O_PATH
   if(flags & O_PATH)      { strlcat(buf, "PATH ", len);      }
   #endif
   if(flags & O_SYNC)      { strlcat(buf, "SYNC ", len);      }
   #ifdef O_TMPFILE
   if(flags & O_TMPFILE)   { strlcat(buf, "TMPFILE ", len);   }
   #endif
   if(flags & O_TRUNC)     { strlcat(buf, "TRUNC ", len);     }
}

void xr_fdc_mode_str(mode_t mode, char *buf, uint32_t len) {
   buf[0] = '\0';
   if(S_ISREG(mode))  { strlcat(buf, "REG ",  len); }
   if(S_ISDIR(mode))  { strlcat(buf, "DIR ",  len); }
   if(S_ISCHR(mode))  { strlcat(buf, "CHR ",  len); }
   if(S_ISBLK(mode))  { strlcat(buf, "BLK ",  len); }
   if(S_ISFIFO(mode)) { strlcat(buf, "FIFO ", len); }
   if(S_ISLNK(mode))  { strlcat(buf, "LINK ", len); }
   if(S_ISSOCK(mode)) { strlcat(buf, "SOCK ", len); }
}
