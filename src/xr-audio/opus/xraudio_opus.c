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
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRAUDIO
#include <rdkx_logger.h>
#include <xraudio_opus.h>
#include <opus/opus.h>

#define XRAUDIO_OPUS_IDENTIFIER (0x378D6F5A)

#define XRAUDIO_OPUS_HEADER_LENGTH (1)
#define XRAUDIO_OPUS_CMD_ID_BEGIN  (0x20)
#define XRAUDIO_OPUS_CMD_ID_END    (0x3F)

typedef struct {
   uint32_t     identifier;
   OpusDecoder *decoder;
   uint8_t      cmd_id_next;
} xraudio_opus_obj_t;

static bool xraudio_opus_obj_is_valid(xraudio_opus_obj_t *obj);
static inline void xraudio_opus_cmd_id_inc(uint8_t *cmd_id);
static const char *opus_error_str(int error);

bool xraudio_opus_obj_is_valid(xraudio_opus_obj_t *obj) {
   if(obj != NULL && obj->identifier == XRAUDIO_OPUS_IDENTIFIER) {
      return(true);
   }
   return(false);
}

xraudio_opus_object_t xraudio_opus_create(void) {
   
   xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)malloc(sizeof(xraudio_opus_obj_t) + opus_decoder_get_size(1));

   if(obj == NULL) {
      XLOGD_ERROR("Out of memory");
      return(NULL);
   }
   obj->identifier  = XRAUDIO_OPUS_IDENTIFIER;
   obj->decoder     = (OpusDecoder *)&obj[1];
   obj->cmd_id_next = XRAUDIO_OPUS_CMD_ID_BEGIN;

   int rc = opus_decoder_init(obj->decoder, 16000, 1);
   if(rc != OPUS_OK) {
      XLOGD_ERROR("unable to create opus decoder <%d>", rc);
      free(obj);
      obj = NULL;
   }

   return(obj);
}

void xraudio_opus_cmd_id_inc(uint8_t *cmd_id) {
   (*cmd_id)++;
   if(*cmd_id > XRAUDIO_OPUS_CMD_ID_END) {
      *cmd_id = XRAUDIO_OPUS_CMD_ID_BEGIN;
   }
}

int32_t xraudio_opus_deframe(xraudio_opus_object_t object, uint8_t *inbuf, uint32_t inlen) {
   xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)object;
   if(!xraudio_opus_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(-1);
   }
   if(inbuf == NULL) {
      XLOGD_ERROR("invalid params");
      return(-1);
   }

   if(inlen < XRAUDIO_OPUS_HEADER_LENGTH + 1) {
      XLOGD_ERROR("invalid inlen <%u>", inlen);
      return(-1);
   }

   // Remove the RF4CE framing and return only the opus stream
   uint8_t cmd_id = inbuf[0];
   
   if(cmd_id < XRAUDIO_OPUS_CMD_ID_BEGIN || cmd_id > XRAUDIO_OPUS_CMD_ID_END) {
      XLOGD_ERROR("invalid cmd id <0x%02X>", cmd_id);
      return(-1);
   }
   if(cmd_id != obj->cmd_id_next) {
      XLOGD_ERROR("discontinuity cmd id <0x%02X> expected <0x%02X", cmd_id, obj->cmd_id_next);
      obj->cmd_id_next = cmd_id;
   }
   
   xraudio_opus_cmd_id_inc(&obj->cmd_id_next);
   
   // Shift the data to remove the header (would be nice to optimize this copy away later)
   uint8_t *payload = &inbuf[XRAUDIO_OPUS_HEADER_LENGTH];
   for(uint32_t i = XRAUDIO_OPUS_HEADER_LENGTH; i < inlen; i++) {
      *inbuf = *payload;
   }

   return(inlen - XRAUDIO_OPUS_HEADER_LENGTH);
}

int32_t xraudio_opus_decode(xraudio_opus_object_t object, uint8_t framed, uint8_t *inbuf, uint32_t inlen, pcm_t *outbuf, uint32_t outlen) {
   xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)object;
   uint8_t buf_index = 0;
   uint8_t buf_len   = inlen;

   if(!xraudio_opus_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(-1);
   }
   if(inbuf == NULL || outbuf == NULL) {
      XLOGD_ERROR("invalid params");
      return(-1);
   }

   if(inlen < (framed ? XRAUDIO_OPUS_HEADER_LENGTH + 1 : 1)) {
      XLOGD_ERROR("invalid inlen <%u>", inlen);
      return(-1);
   }

   if(framed) {
       // Process the RF4CE framing
      uint8_t cmd_id = inbuf[0];
      
      if(cmd_id < XRAUDIO_OPUS_CMD_ID_BEGIN || cmd_id > XRAUDIO_OPUS_CMD_ID_END) {
         XLOGD_ERROR("invalid cmd id <0x%02X>", cmd_id);
         return(-1);
      }
      if(cmd_id != obj->cmd_id_next) {
         XLOGD_ERROR("discontinuity cmd id <0x%02X> expected <0x%02X", cmd_id, obj->cmd_id_next);
         obj->cmd_id_next = cmd_id;
      }
      
      xraudio_opus_cmd_id_inc(&obj->cmd_id_next);
      buf_index = XRAUDIO_OPUS_HEADER_LENGTH;
      buf_len   = inlen - XRAUDIO_OPUS_HEADER_LENGTH;
   }
   
   int samples = opus_decode(obj->decoder, &inbuf[buf_index], buf_len, outbuf, outlen, 0);
   if(samples < 0) {
      if(framed) {
         XLOGD_ERROR("failed to decode opus frame <%s>.  cmd id <0x%02X> len <%u>", opus_error_str(samples), inbuf[0], inlen);
      } else {
         XLOGD_ERROR("failed to decode opus frame <%s>.  inlen <%u> outlen <%u>", opus_error_str(samples), inlen, outlen);
      }
      return(samples);
   }
   return(samples * sizeof(pcm_t));
}

bool xraudio_opus_stats(xraudio_opus_object_t object, xraudio_opus_stats_t *stats) {
   xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)object;
   if(!xraudio_opus_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   if(stats == NULL) {
      XLOGD_ERROR("invalid param");
      return(false);
   }
   
   return(true);
}

bool xraudio_opus_reset(xraudio_opus_object_t object) {
   xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)object;
   if(!xraudio_opus_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return(false);
   }
   
   obj->cmd_id_next = XRAUDIO_OPUS_CMD_ID_BEGIN;
   
   int rc = opus_decoder_ctl(obj->decoder, OPUS_RESET_STATE);
   if(rc != OPUS_OK) {
      XLOGD_ERROR("unable to reset opus decoder state <%s>", opus_error_str(rc));
      return(false);
   }

   return(true);
}

void xraudio_opus_destroy(xraudio_opus_object_t object) {
   xraudio_opus_obj_t *obj = (xraudio_opus_obj_t *)object;
   if(!xraudio_opus_obj_is_valid(obj)) {
      XLOGD_ERROR("invalid object");
      return;
   }
   obj->identifier = 0;
   free(obj);
}

const char *opus_error_str(int error) {
   switch(error) {
      case OPUS_BAD_ARG:          return("OPUS_BAD_ARG");
      case OPUS_BUFFER_TOO_SMALL: return("OPUS_BUFFER_TOO_SMALL");
      case OPUS_INTERNAL_ERROR:   return("OPUS_INTERNAL_ERROR");
      case OPUS_INVALID_PACKET:   return("OPUS_INVALID_PACKET");
      case OPUS_UNIMPLEMENTED:    return("OPUS_UNIMPLEMENTED");
      case OPUS_INVALID_STATE:    return("OPUS_INVALID_STATE");
      case OPUS_ALLOC_FAIL:       return("OPUS_ALLOC_FAIL");
   }
   return("INVALID");
}
