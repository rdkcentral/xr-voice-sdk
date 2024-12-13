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
#include <stdio.h>
#include <string.h>
#include <bsd/string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "xraudio.h"
#include "xraudio_private.h"

#define XRAUDIO_INVALID_STR_LEN (24)

static char xraudio_invalid_str[XRAUDIO_INVALID_STR_LEN];

static const char *xraudio_invalid_return(int value);

#ifndef USE_RDKX_LOGGER
void xraudio_get_log_time(char *log_buffer) {
   struct tm *local;
   struct timeval tv;
   uint16_t msecs;
   gettimeofday(&tv, NULL);
   local = localtime(&tv.tv_sec);
   msecs = (uint16_t)(tv.tv_usec/1000);
   strftime(log_buffer, 9, "%T", local);
   //printing milliseconds as ":XXX "
   log_buffer[12] = '\0';                             //Null terminate milliseconds
   log_buffer[11] = (msecs % 10) + '0'; msecs  /= 10; //get the 1's digit
   log_buffer[10] = (msecs % 10) + '0'; msecs  /= 10; //get the 10's digit
   log_buffer[9]  = (msecs % 10) + '0';               //get the 100's digit
   log_buffer[8]  = ':';
}
#endif

void xraudio_wave_header_gen(uint8_t *header, uint16_t audio_format, uint16_t num_channels, uint32_t sample_rate, uint16_t bits_per_sample, uint32_t pcm_data_size, uint32_t padding) {
   uint32_t byte_rate      = sample_rate * num_channels * bits_per_sample / 8;
   uint32_t chunk_size     = pcm_data_size + 36;
   uint16_t block_align    = num_channels * bits_per_sample / 8;
   uint32_t  fmt_chunk_size = 16;
   header[0]  = 'R';
   header[1]  = 'I';
   header[2]  = 'F';
   header[3]  = 'F';
   header[4]  = (uint8_t)(chunk_size);
   header[5]  = (uint8_t)(chunk_size >> 8);
   header[6]  = (uint8_t)(chunk_size >> 16);
   header[7]  = (uint8_t)(chunk_size >> 24);
   header[8]  = 'W';
   header[9]  = 'A';
   header[10] = 'V';
   header[11] = 'E';
   header[12] = 'f';
   header[13] = 'm';
   header[14] = 't';
   header[15] = ' ';
   header[16] = (uint8_t)(fmt_chunk_size);
   header[17] = (uint8_t)(fmt_chunk_size >> 8);
   header[18] = (uint8_t)(fmt_chunk_size >> 16);
   header[19] = (uint8_t)(fmt_chunk_size >> 24);
   header[20] = (uint8_t)(audio_format);
   header[21] = (uint8_t)(audio_format >> 8);
   header[22] = (uint8_t)(num_channels);
   header[23] = (uint8_t)(num_channels >> 8);
   header[24] = (uint8_t)(sample_rate);
   header[25] = (uint8_t)(sample_rate >> 8);
   header[26] = (uint8_t)(sample_rate >> 16);
   header[27] = (uint8_t)(sample_rate >> 24);
   header[28] = (uint8_t)(byte_rate);
   header[29] = (uint8_t)(byte_rate >> 8);
   header[30] = (uint8_t)(byte_rate >> 16);
   header[31] = (uint8_t)(byte_rate >> 24);
   header[32] = (uint8_t)(block_align);
   header[33] = (uint8_t)(block_align >> 8);
   header[34] = (uint8_t)(bits_per_sample);
   header[35] = (uint8_t)(bits_per_sample >> 8);

   uint32_t i = 36;
   if(padding >= 8) {
      padding -= 8;
      header[i++] = 'p';
      header[i++] = 'a';
      header[i++] = 'd';
      header[i++] = ' ';
      header[i++] = (uint8_t)(padding);
      header[i++] = (uint8_t)(padding >> 8);
      header[i++] = (uint8_t)(padding >> 16);
      header[i++] = (uint8_t)(padding >> 24);
      for(uint32_t index = 0; index < padding; index++) {
         header[i++] = 0;
      }
   }
   header[i++] = 'd';
   header[i++] = 'a';
   header[i++] = 't';
   header[i++] = 'a';
   header[i++] = (uint8_t)(pcm_data_size);
   header[i++] = (uint8_t)(pcm_data_size >> 8);
   header[i++] = (uint8_t)(pcm_data_size >> 16);
   header[i++] = (uint8_t)(pcm_data_size >> 24);
}

const char *xraudio_invalid_return(int value) {
   snprintf(xraudio_invalid_str, XRAUDIO_INVALID_STR_LEN, "INVALID(%d)", value);
   xraudio_invalid_str[XRAUDIO_INVALID_STR_LEN - 1] = '\0';
   return(xraudio_invalid_str);
}

const char *xraudio_channel_qty_str(unsigned char channel_qty) {
   switch(channel_qty) {
      case 0:return("none");
      case 1:return("mono");
      case 2:return("stereo");
      case 3:return("tri");
      case 4:return("quad");
   }
   snprintf(xraudio_invalid_str, XRAUDIO_INVALID_STR_LEN, "%u chans", channel_qty);
   xraudio_invalid_str[XRAUDIO_INVALID_STR_LEN - 1] = '\0';
   return(xraudio_invalid_str);
}

bool xraudio_devices_input_local_is_valid(xraudio_devices_input_t devices) {
   switch(XRAUDIO_DEVICE_INPUT_LOCAL_GET(devices)) {
      case XRAUDIO_DEVICE_INPUT_NONE:
      case XRAUDIO_DEVICE_INPUT_SINGLE:
      case XRAUDIO_DEVICE_INPUT_TRI:
      case XRAUDIO_DEVICE_INPUT_QUAD:
      case XRAUDIO_DEVICE_INPUT_HFP:
      case XRAUDIO_DEVICE_INPUT_MIC_TAP: {
         break;
      }
      default: {
         return(false);
      }
   }

   switch(XRAUDIO_DEVICE_INPUT_EC_REF_GET(devices)) {
      case XRAUDIO_DEVICE_INPUT_EC_REF_NONE:
      case XRAUDIO_DEVICE_INPUT_EC_REF_MONO:
      case XRAUDIO_DEVICE_INPUT_EC_REF_STEREO:
      case XRAUDIO_DEVICE_INPUT_EC_REF_5_1: {
         break;
      }
      default: {
         return(false);
      }
   }
   return(true);
}

bool xraudio_devices_input_external_is_valid(xraudio_devices_input_t devices) {
   bool ret = true;
   devices = XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(devices);
   if((devices & ~(XRAUDIO_DEVICE_INPUT_PTT | XRAUDIO_DEVICE_INPUT_FF))) {
      ret = false;
   }
   return(ret);
}

bool xraudio_devices_input_is_valid(xraudio_devices_input_t devices) {
   return(xraudio_devices_input_local_is_valid(devices) && xraudio_devices_input_external_is_valid(devices));
}

bool xraudio_devices_output_is_valid(xraudio_devices_output_t devices) {
   bool ret = true;
   switch(devices) {
      case XRAUDIO_DEVICE_OUTPUT_NONE:
      case XRAUDIO_DEVICE_OUTPUT_NORMAL:
      case XRAUDIO_DEVICE_OUTPUT_EC_REF:
      case XRAUDIO_DEVICE_OUTPUT_OFFLOAD:
      case XRAUDIO_DEVICE_OUTPUT_HFP: {
         break;
      }
      default: {
         ret = false;
         break;
      }
   }
   return(ret);
}

const char *xraudio_devices_input_str(xraudio_devices_input_t type) {
   static char str[64];

   if(type == XRAUDIO_DEVICE_INPUT_NONE) {
      return("NONE");
   }

   str[0] = '\0';

   if(type & XRAUDIO_DEVICE_INPUT_SINGLE) {
      strlcat(str, "SINGLE", sizeof(str));
   }
   if(type & XRAUDIO_DEVICE_INPUT_TRI) {
      if(str[0] != '\0') {
         strlcat(str, ", TRI", sizeof(str));
      } else {
         strlcat(str, "TRI", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_QUAD) {
      if(str[0] != '\0') {
         strlcat(str, ", QUAD", sizeof(str));
      } else {
         strlcat(str, "QUAD", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_HFP) {
      if(str[0] != '\0') {
         strlcat(str, ", HFP", sizeof(str));
      } else {
         strlcat(str, "HFP", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_EC_REF_MONO) {
      if(str[0] != '\0') {
         strlcat(str, ", EC_REF_MONO", sizeof(str));
      } else {
         strlcat(str, "EC_REF_MONO", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_EC_REF_STEREO) {
      if(str[0] != '\0') {
         strlcat(str, ", EC_REF_STEREO", sizeof(str));
      } else {
         strlcat(str, "EC_REF_STEREO", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_EC_REF_5_1) {
      if(str[0] != '\0') {
         strlcat(str, ", EC_REF_5_1", sizeof(str));
      } else {
         strlcat(str, "EC_REF_5_1", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_PTT) {
      if(str[0] != '\0') {
         strlcat(str, ", PTT", sizeof(str));
      } else {
         strlcat(str, "PTT", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_FF) {
      if(str[0] != '\0') {
         strlcat(str, ", FF", sizeof(str));
      } else {
         strlcat(str, "FF", sizeof(str));
      }
   }
   if(type & XRAUDIO_DEVICE_INPUT_MIC_TAP) {
      if(str[0] != '\0') {
         strlcat(str, ", MIC_TAP", sizeof(str));
      } else {
         strlcat(str, "MIC_TAP", sizeof(str));
      }
   }

   if(str[0] != '\0') {
      return(str);
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_devices_output_str(xraudio_devices_output_t type) {
   switch(type) {
      case XRAUDIO_DEVICE_OUTPUT_NONE:    return("NONE");
      case XRAUDIO_DEVICE_OUTPUT_NORMAL:  return("NORMAL");
      case XRAUDIO_DEVICE_OUTPUT_EC_REF:  return("EC REF");
      case XRAUDIO_DEVICE_OUTPUT_OFFLOAD: return("OFFLOAD");
      case XRAUDIO_DEVICE_OUTPUT_HFP:     return("HFP");
      case XRAUDIO_DEVICE_OUTPUT_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_resource_priority_str(xraudio_resource_priority_t type) {
   switch(type) {
      case XRAUDIO_RESOURCE_PRIORITY_LOW:     return("LOW");
      case XRAUDIO_RESOURCE_PRIORITY_MEDIUM:  return("MEDIUM");
      case XRAUDIO_RESOURCE_PRIORITY_HIGH:    return("HIGH");
      case XRAUDIO_RESOURCE_PRIORITY_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_result_str(xraudio_result_t type) {
   switch(type) {
      case XRAUDIO_RESULT_OK:                   return("OK");
      case XRAUDIO_RESULT_ERROR_OBJECT:         return("INVALID OBJECT");
      case XRAUDIO_RESULT_ERROR_INTERNAL:       return("INTERNAL ERROR");
      case XRAUDIO_RESULT_ERROR_OUTPUT:         return("SPEAKER NOT AVAILABLE");
      case XRAUDIO_RESULT_ERROR_INPUT:          return("MICROPHONE NOT AVAILABLE");
      case XRAUDIO_RESULT_ERROR_OPEN:           return("XRAUDIO IS NOT OPEN");
      case XRAUDIO_RESULT_ERROR_PARAMS:         return("INVALID PARAMETERS");
      case XRAUDIO_RESULT_ERROR_STATE:          return("INVALID STATE");
      case XRAUDIO_RESULT_ERROR_CONTAINER:      return("INVALID CONTAINER");
      case XRAUDIO_RESULT_ERROR_ENCODING:       return("INVALID ENCODING");
      case XRAUDIO_RESULT_ERROR_FILE_OPEN:      return("FILE OPEN");
      case XRAUDIO_RESULT_ERROR_FILE_SEEK:      return("FILE SEEK");
      case XRAUDIO_RESULT_ERROR_FIFO_OPEN:      return("FIFO OPEN");
      case XRAUDIO_RESULT_ERROR_FIFO_CONTROL:   return("FIFO CONTROL");
      case XRAUDIO_RESULT_ERROR_OUTPUT_OPEN:    return("SPEAKER OPEN");
      case XRAUDIO_RESULT_ERROR_OUTPUT_VOLUME:  return("SPEAKER VOLUME");
      case XRAUDIO_RESULT_ERROR_WAVE_HEADER:    return("WAVE HEADER");
      case XRAUDIO_RESULT_ERROR_RESOURCE:       return("RESOURCE");
      case XRAUDIO_RESULT_ERROR_CAPTURE:        return("CAPTURE");
      case XRAUDIO_RESULT_ERROR_MIC_OPEN:       return("MIC_OPEN_ERROR");
      case XRAUDIO_RESULT_ERROR_DISABLED:       return("DISABLED");
      case XRAUDIO_RESULT_ERROR_IN_USE:         return("IN_USE");
      case XRAUDIO_RESULT_ERROR_INVALID:        return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_container_str(xraudio_container_t type) {
   switch(type) {
      case XRAUDIO_CONTAINER_NONE:    return("NONE");
      case XRAUDIO_CONTAINER_WAV:     return("WAV");
      case XRAUDIO_CONTAINER_MP3:     return("MP3");
      case XRAUDIO_CONTAINER_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_encoding_str(xraudio_encoding_type_t type) {
   switch(type) {
      case XRAUDIO_ENCODING_PCM:              return("PCM");
      case XRAUDIO_ENCODING_PCM_RAW:          return("PCM_RAW");
      case XRAUDIO_ENCODING_ADPCM_FRAME:      return("ADPCM_FRAME");
      case XRAUDIO_ENCODING_ADPCM:            return("ADPCM");
      case XRAUDIO_ENCODING_OPUS_XVP:         return("OPUS_XVP");
      case XRAUDIO_ENCODING_OPUS:             return("OPUS");
      case XRAUDIO_ENCODING_INVALID:          return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_resource_id_input_str(xraudio_resource_id_input_t type) {
   switch(type) {
      case XRAUDIO_RESOURCE_ID_INPUT_1:       return("INPUT_1");
      case XRAUDIO_RESOURCE_ID_INPUT_2:       return("INPUT_2");
      case XRAUDIO_RESOURCE_ID_INPUT_3:       return("INPUT_3");
      case XRAUDIO_RESOURCE_ID_INPUT_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_resource_id_output_str(xraudio_resource_id_output_t type) {
   switch(type) {
      case XRAUDIO_RESOURCE_ID_OUTPUT_1:       return("OUTPUT_1");
      case XRAUDIO_RESOURCE_ID_OUTPUT_2:       return("OUTPUT_2");
      case XRAUDIO_RESOURCE_ID_OUTPUT_3:       return("OUTPUT_3");
      case XRAUDIO_RESOURCE_ID_OUTPUT_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_main_queue_msg_type_str(xraudio_main_queue_msg_type_t type) {
   switch(type) {
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_START:               return("RECORD IDLE START");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_IDLE_STOP:                return("RECORD IDLE STOP");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_START:                    return("RECORD START");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_RECORD_STOP:                     return("RECORD STOP");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_START:                   return("CAPTURE START");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_STOP:                    return("CAPTURE STOP");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_IDLE:                       return("PLAY IDLE");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_START:                      return("PLAY START");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_PAUSE:                      return("PLAY PAUSE");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_RESUME:                     return("PLAY RESUME");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PLAY_STOP:                       return("PLAY STOP");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT:                          return("DETECT");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_PARAMS:                   return("DETECT_PARAMS");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_SENSITIVITY_LIMITS_GET:   return("DETECT SENSITIVITY LIMITS");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_DETECT_STOP:                     return("DETECT STOP");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_BEGIN:             return("SESSION_BEGIN");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_END:               return("SESSION_END");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_INPUT_ERROR:               return("INPUT_ERROR");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_TERMINATE:                       return("TERMINATE");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_THREAD_POLL:                     return("THREAD_POLL");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_POWER_MODE:                      return("POWER_MODE");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE:                    return("PRIVACY_MODE");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_PRIVACY_MODE_GET:                return("PRIVACY_MODE_GET");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_CAPTURE_PARAMS_SET:              return("CAPTURE_PARAMS_SET");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_INPUT_SOURCE_FD_SET:             return("INPUT_SOURCE_FD_SET");
      case XRAUDIO_MAIN_QUEUE_MSG_TYPE_INVALID:                         return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

#ifdef XRAUDIO_RESOURCE_MGMT
const char *xraudio_rsrc_queue_msg_type_str(xraudio_rsrc_queue_msg_type_t type) {
   switch(type) {
      case XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_REQUEST:    return("RESOURCE_REQUEST");
      case XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_RELEASE:    return("RESOURCE_RELEASE");
      case XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_GRANT:      return("RESOURCE_GRANT");
      case XRAUDIO_RSRC_QUEUE_MSG_TYPE_RESOURCE_REVOKE:     return("RESOURCE_REVOKE");
      case XRAUDIO_RSRC_QUEUE_MSG_TYPE_TERMINATE:           return("TERMINATE");
      case XRAUDIO_RSRC_QUEUE_MSG_TYPE_INVALID:             return("INVALID");
   }
   return(xraudio_invalid_return(type));
}
#endif

#ifdef XRAUDIO_OUTPUT_ENABLED
const char *xraudio_output_state_str(xraudio_output_state_t type) {
   switch(type) {
      case XRAUDIO_OUTPUT_STATE_CREATED: return("CREATED");
      case XRAUDIO_OUTPUT_STATE_IDLING:  return("IDLING");
      case XRAUDIO_OUTPUT_STATE_PLAYING: return("PLAYING");
      case XRAUDIO_OUTPUT_STATE_PAUSED:  return("PAUSED");
      case XRAUDIO_OUTPUT_STATE_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}
#endif

const char *xraudio_input_state_str(xraudio_input_state_t type) {
   switch(type) {
      case XRAUDIO_INPUT_STATE_CREATED:   return("CREATED");
      case XRAUDIO_INPUT_STATE_IDLING:    return("IDLING");
      case XRAUDIO_INPUT_STATE_RECORDING: return("RECORDING");
      case XRAUDIO_INPUT_STATE_STREAMING: return("STREAMING");
      case XRAUDIO_INPUT_STATE_DETECTING: return("DETECTING");
      case XRAUDIO_INPUT_STATE_INVALID:   return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_input_record_from_str(xraudio_input_record_from_t type) {
   switch(type) {
      case XRAUDIO_INPUT_RECORD_FROM_BEGINNING:     return("BEGINNING");
      case XRAUDIO_INPUT_RECORD_FROM_LIVE:          return("LIVE");
      case XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN: return("KEYWORD_BEGIN");
      case XRAUDIO_INPUT_RECORD_FROM_KEYWORD_END:   return("KEYWORD_END");
      case XRAUDIO_INPUT_RECORD_FROM_INVALID:       return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_input_record_until_str(xraudio_input_record_until_t type) {
   switch(type) {
      case XRAUDIO_INPUT_RECORD_UNTIL_END_OF_STREAM:  return("END OF STREAM");
      case XRAUDIO_INPUT_RECORD_UNTIL_END_OF_SPEECH:  return("END OF SPEECH");
      case XRAUDIO_INPUT_RECORD_UNTIL_END_OF_KEYWORD: return("END OF KEYWORD");
      case XRAUDIO_INPUT_RECORD_UNTIL_INVALID:        return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_stream_latency_mode_str(xraudio_stream_latency_mode_t type) {
   switch(type) {
      case XRAUDIO_STREAM_LATENCY_NORMAL:    return("NORMAL");
      case XRAUDIO_STREAM_LATENCY_LOW:       return("LOW");
      case XRAUDIO_STREAM_LATENCY_INVALID:   return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_stream_cpu_util_mode_str(xraudio_stream_cpu_util_mode_t type) {
   switch(type) {
      case XRAUDIO_STREAM_CPU_UTIL_NORMAL:  return("NORMAL");
      case XRAUDIO_STREAM_CPU_UTIL_LOW:     return("LOW");
      case XRAUDIO_STREAM_CPU_UTIL_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *audio_out_callback_event_str(audio_out_callback_event_t type) {
   switch(type) {
      case AUDIO_OUT_CALLBACK_EVENT_OK:          return("OK");
      case AUDIO_OUT_CALLBACK_EVENT_FIRST_FRAME: return("FIRST FRAME");
      case AUDIO_OUT_CALLBACK_EVENT_EOF:         return("EOF");
      case AUDIO_OUT_CALLBACK_EVENT_UNDERFLOW:   return("UNDERFLOW");
      case AUDIO_OUT_CALLBACK_EVENT_ERROR:       return("ERROR");
   }
   return(xraudio_invalid_return(type));
}

const char *audio_in_callback_event_str(audio_in_callback_event_t type) {
   switch(type) {
      case AUDIO_IN_CALLBACK_EVENT_OK:                  return("OK");
      case AUDIO_IN_CALLBACK_EVENT_EOS:                 return("EOS");
      case AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_INITIAL: return("EOS TIMEOUT INITIAL");
      case AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_END:     return("EOS TIMEOUT END");
      case AUDIO_IN_CALLBACK_EVENT_FIRST_FRAME:         return("FIRST FRAME");
      case AUDIO_IN_CALLBACK_EVENT_END_OF_BUFFER:       return("END OF BUFFER");
      case AUDIO_IN_CALLBACK_EVENT_OVERFLOW:            return("OVERFLOW");
      case AUDIO_IN_CALLBACK_EVENT_STREAM_TIME_MINIMUM: return("STREAM TIME MINIMUM");
      case AUDIO_IN_CALLBACK_EVENT_STREAM_KWD_INFO:     return("STREAM KWD_INFO");
      case AUDIO_IN_CALLBACK_EVENT_ERROR:               return("ERROR");
   }
   return(xraudio_invalid_return(type));
}

const char *keyword_callback_event_str(keyword_callback_event_t type) {
   switch(type) {
      case KEYWORD_CALLBACK_EVENT_DETECTED: return("DETECTED");
      case KEYWORD_CALLBACK_EVENT_ERROR_FD: return("ERROR_FD");
      case KEYWORD_CALLBACK_EVENT_ERROR:    return("ERROR");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_resource_event_str(xraudio_resource_event_t type) {
   switch(type) {
      case XRAUDIO_RESOURCE_EVENT_GRANTED: return("GRANTED");
      case XRAUDIO_RESOURCE_EVENT_REVOKED: return("REVOKED");
      case XRAUDIO_RESOURCE_EVENT_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_capture_str(xraudio_capture_t type) {
   static char str[64];

   str[0] = '\0';

   if(type & XRAUDIO_CAPTURE_INPUT_ALL) {
      strlcat(str, "ALL_CHANS", sizeof(str));
   } else {
      strlcat(str, "ONE_CHAN", sizeof(str));
   }
   if(type & XRAUDIO_CAPTURE_DOA) {
      strlcat(str, ", DOA", sizeof(str));
   }
   if(type & XRAUDIO_CAPTURE_KWD) {
      strlcat(str, ", KWD", sizeof(str));
   }
   if(type & XRAUDIO_CAPTURE_EOS) {
      strlcat(str, ", EOS", sizeof(str));
   }
   if(type & XRAUDIO_CAPTURE_OUTPUT) {
      strlcat(str, ", OUTPUT", sizeof(str));
   }

   if(str[0] != '\0') {
      return(str);
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_keyword_phrase_str(xraudio_keyword_phrase_t type) {
   switch(type) {
      case XRAUDIO_KEYWORD_PHRASE_HEY_XFINITY: return("HEY_XFINITY");
      case XRAUDIO_KEYWORD_PHRASE_HELLO_SKY:   return("HELLO_SKY");
      case XRAUDIO_KEYWORD_PHRASE_INVALID:     return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_keyword_config_str(xraudio_keyword_config_t type) {
   switch(type) {
      case XRAUDIO_KEYWORD_CONFIG_1:       return("CONFIG_1");
      case XRAUDIO_KEYWORD_CONFIG_2:       return("CONFIG_2");
      case XRAUDIO_KEYWORD_CONFIG_3:       return("CONFIG_3");
      case XRAUDIO_KEYWORD_CONFIG_4:       return("CONFIG_4");
      case XRAUDIO_KEYWORD_CONFIG_5:       return("CONFIG_5");
      case XRAUDIO_KEYWORD_CONFIG_6:       return("CONFIG_6");
      case XRAUDIO_KEYWORD_CONFIG_7:       return("CONFIG_7");
      case XRAUDIO_KEYWORD_CONFIG_8:       return("CONFIG_8");
      case XRAUDIO_KEYWORD_CONFIG_9:       return("CONFIG_9");
      case XRAUDIO_KEYWORD_CONFIG_10:      return("CONFIG_10");
      case XRAUDIO_KEYWORD_CONFIG_11:      return("CONFIG_11");
      case XRAUDIO_KEYWORD_CONFIG_12:      return("CONFIG_12");
      case XRAUDIO_KEYWORD_CONFIG_13:      return("CONFIG_13");
      case XRAUDIO_KEYWORD_CONFIG_14:      return("CONFIG_14");
      case XRAUDIO_KEYWORD_CONFIG_15:      return("CONFIG_15");
      case XRAUDIO_KEYWORD_CONFIG_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_capabilities_input_str(uint16_t type) {
   static char str[64];

   if(type == XRAUDIO_CAPS_INPUT_NONE) {
      return("NONE");
   }

   str[0] = '\0';

   if(type & XRAUDIO_CAPS_INPUT_LOCAL) {
      strlcat(str, "LOCAL_16_BIT", sizeof(str));
   }
   if(type & XRAUDIO_CAPS_INPUT_SELECT) {
      if(str[0] != '\0') {
         strlcat(str, ", SELECT", sizeof(str));
      } else {
         strlcat(str, "SELECT", sizeof(str));
      }
   }
   if(type & XRAUDIO_CAPS_INPUT_LOCAL_32_BIT) {
      if(str[0] != '\0') {
         strlcat(str, ", LOCAL_32_BIT", sizeof(str));
      } else {
         strlcat(str, "LOCAL_32_BIT", sizeof(str));
      }
   }
   if(type & XRAUDIO_CAPS_INPUT_EOS_DETECTION) {
      if(str[0] != '\0') {
         strlcat(str, ", EOS", sizeof(str));
      } else {
         strlcat(str, "EOS", sizeof(str));
      }
   }

   if(str[0] != '\0') {
      return(str);
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_capabilities_output_str(uint16_t type) {
   static char str[64];

   if(type == XRAUDIO_CAPS_OUTPUT_NONE) {
      return("NONE");
   }

   str[0] = '\0';

   if(type & XRAUDIO_CAPS_OUTPUT_HAL_VOLUME_CONTROL) {
      strlcat(str, "VOLUME_CONTROL", sizeof(str));
   }
   if(type & XRAUDIO_CAPS_OUTPUT_OFFLOAD) {
      if(str[0] != '\0') {
         strlcat(str, ", OFFLOAD", sizeof(str));
      } else {
         strlcat(str, "OFFLOAD", sizeof(str));
      }
   }
   if(type & XRAUDIO_CAPS_OUTPUT_DIRECT_PCM) {
      if(str[0] != '\0') {
         strlcat(str, ", DIRECT_PCM", sizeof(str));
      } else {
         strlcat(str, "DIRECT_PCM", sizeof(str));
      }
   }

   if(str[0] != '\0') {
      return(str);
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_eos_event_str(xraudio_eos_event_t type) {
   switch(type) {
      case XRAUDIO_EOS_EVENT_NONE:            return("NONE");
      case XRAUDIO_EOS_EVENT_STARTOFSPEECH:   return("STARTOFSPEECH");
      case XRAUDIO_EOS_EVENT_ENDOFSPEECH:     return("ENDOFSPEECH");
      case XRAUDIO_EOS_EVENT_TIMEOUT_INITIAL: return("TIMEOUT_INITIAL");
      case XRAUDIO_EOS_EVENT_TIMEOUT_END:     return("TIMEOUT_END");
      case XRAUDIO_EOS_EVENT_END_OF_WAKEWORD: return("END_OF_WAKEWORD");
      case XRAUDIO_EOS_EVENT_INVALID:         return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_power_mode_str(xraudio_power_mode_t type) {
   switch(type) {
      case XRAUDIO_POWER_MODE_FULL:    return("FULL");
      case XRAUDIO_POWER_MODE_LOW:     return("LOW");
      case XRAUDIO_POWER_MODE_SLEEP:   return("SLEEP");
      case XRAUDIO_POWER_MODE_INVALID: return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_ppr_event_str(xraudio_ppr_event_t type) {
   switch(type) {
      case XRAUDIO_PPR_EVENT_NONE:                       return("NONE");
      case XRAUDIO_PPR_EVENT_STARTOFSPEECH:              return("STARTOFSPEECH");
      case XRAUDIO_PPR_EVENT_ENDOFSPEECH:                return("ENDOFSPEECH");
      case XRAUDIO_PPR_EVENT_TIMEOUT_INITIAL:            return("TIMEOUT_INITIAL");
      case XRAUDIO_PPR_EVENT_TIMEOUT_END:                return("TIMEOUT_END");
      case XRAUDIO_PPR_EVENT_LOCAL_KEYWORD_DETECTED:     return("LOCAL_KEYWORD_DETECTED");
      case XRAUDIO_PPR_EVENT_REFERENCE_KEYWORD_DETECTED: return("REFERENCE_KEYWORD_DETECTED");
      case XRAUDIO_PPR_EVENT_INVALID:                    return("INVALID");
   }
   return(xraudio_invalid_return(type));
}

const char *xraudio_ppr_command_str(xraudio_ppr_command_t command) {
   switch(command) {
      case XRAUDIO_PPR_COMMAND_KEYWORD_DETECT:        return("KEYWORD_DETECT");
      case XRAUDIO_PPR_COMMAND_PUSH_TO_TALK:          return("PUSH_TO_TALK");
      case XRAUDIO_PPR_PRIVACY:                       return("PRIVACY");
      case XRAUDIO_PPR_END_PRIVACY:                   return("END_PRIVACY");
      case XRAUDIO_PPR_COMMAND_END_OF_SESSION:        return("END_OF_SESSION");
      case XRAUDIO_PPR_COMMAND_TUNING_INTERFACE_ON:   return("TUNING_INTERFACE_ON");
      case XRAUDIO_PPR_COMMAND_TUNING_INTERFACE_OFF:  return("TUNING_INTERFACE_OFF");
      case XRAUDIO_PPR_COMMAND_INVALID:               return("INVALID");
   }
   return(xraudio_invalid_return(command));
}

const char *xraudio_keyword_criterion_str(xraudio_kwd_criterion_t criterion) {
   switch(criterion) {
      case XRAUDIO_KWD_CRITERION_SCORE:               return("SCORE");
      case XRAUDIO_KWD_CRITERION_SNR:                 return("SNR");
      case XRAUDIO_KWD_CRITERION_INVALID:             return("INVALID");
   }
   return(xraudio_invalid_return(criterion));
}

const char *xraudio_input_session_group_str(xraudio_input_session_group_t group) {
   switch(group) {
      case XRAUDIO_INPUT_SESSION_GROUP_DEFAULT: return("DEFAULT");
      #ifdef MICROPHONE_TAP_ENABLED
      case XRAUDIO_INPUT_SESSION_GROUP_MIC_TAP: return("MIC_TAP");
      #endif
      case XRAUDIO_INPUT_SESSION_GROUP_QTY:     return("INVALID");
   }
   return(xraudio_invalid_return(group));
}
