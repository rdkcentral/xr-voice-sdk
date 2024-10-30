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
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/select.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <math.h>
#include "xraudio.h"
#include "xraudio_private.h"
#include "xraudio_atomic.h"
#ifdef XRAUDIO_DECODE_ADPCM
#include "adpcm.h"
#endif
#ifdef XRAUDIO_DECODE_OPUS
#include "xraudio_opus.h"
#endif

//#define MASK_FIRST_WRITE_DELAY
//#define MASK_FIRST_READ_DELAY

#define XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY   (XRAUDIO_INPUT_MAX_CHANNEL_QTY + XRAUDIO_INPUT_MAX_CHANNEL_QTY_EC_REF)

#define XRAUDIO_INPUT_FRAME_SAMPLE_QTY     (XRAUDIO_INPUT_FRAME_PERIOD * XRAUDIO_INPUT_MAX_SAMPLE_RATE / 1000) // X ms @ microphone sample rate
#define XRAUDIO_INPUT_FRAME_SAMPLE_QTY_MAX (XRAUDIO_INPUT_FRAME_SAMPLE_QTY * XRAUDIO_INPUT_MAX_CHANNEL_QTY)
#define XRAUDIO_INPUT_SUPERFRAME_SAMPLE_QTY_MAX    (XRAUDIO_INPUT_FRAME_SAMPLE_QTY * XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY)

#define XRAUDIO_INPUT_FRAME_SIZE_MAX       (XRAUDIO_INPUT_FRAME_SAMPLE_QTY_MAX * XRAUDIO_INPUT_MAX_SAMPLE_SIZE)
#define XRAUDIO_INPUT_SUPERFRAME_SIZE_MAX  (XRAUDIO_INPUT_SUPERFRAME_SAMPLE_QTY_MAX * XRAUDIO_INPUT_MAX_SAMPLE_SIZE)

#define XRAUDIO_INPUT_BEAM_INDEX_CENTER    (1)
#define XRAUDIO_INPUT_BEAM_INDEX_NONE      (0xFF)

#ifdef XRAUDIO_DECODE_OPUS
#define XRAUDIO_INPUT_EXTERNAL_FRAME_SAMPLE_QTY MAX(XRAUDIO_INPUT_OPUS_FRAME_SAMPLE_QTY, XRAUDIO_INPUT_ADPCM_FRAME_SAMPLE_QTY)
#else
#define XRAUDIO_INPUT_EXTERNAL_FRAME_SAMPLE_QTY XRAUDIO_INPUT_ADPCM_FRAME_SAMPLE_QTY
#endif

#define XRAUDIO_OUTPUT_FRAME_SIZE_MAX    (XRAUDIO_OUTPUT_FRAME_PERIOD * XRAUDIO_OUTPUT_MAX_SAMPLE_SIZE * XRAUDIO_OUTPUT_MAX_CHANNEL_QTY * XRAUDIO_OUTPUT_MAX_SAMPLE_RATE / 1000) // X ms @ speaker sample rate (use microphone sample size and sample rate)

#if XRAUDIO_INPUT_FRAME_PERIOD != XRAUDIO_OUTPUT_FRAME_PERIOD
#error Unsynchronized microphone and speaker periods are not supported.
#endif

#define STSF_DOA_MULT    (10)               /* direction of arrival angle multiplier */
#define KEYWORD_TRIGGER_DETECT_THRESHOLD (5) /* Cumulative frames after trigger from all detectors before informing xraudio */

#define CAPTURE_INTERNAL_EXT_WAV         ".wav"
#define CAPTURE_INTERNAL_EXT_PCM         ".pcm"
#define CAPTURE_INTERNAL_EXT_ADPCM_FRAME ".adpcm.frame"
#define CAPTURE_INTERNAL_EXT_ADPCM       ".adpcm"
#define CAPTURE_INTERNAL_EXT_OPUS_XVP    ".opus.xvp"
#define CAPTURE_INTERNAL_EXT_OPUS        ".opus"

#ifndef CAPTURE_INTERNAL_FILENAME_PREFIX
#define CAPTURE_INTERNAL_FILENAME_PREFIX "vsdk_capture"
#endif

#define CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT "_%05u"

#define CAPTURE_INTERNAL_FILENAME_WAV         "%s/" CAPTURE_INTERNAL_FILENAME_PREFIX CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT "%s%s" CAPTURE_INTERNAL_EXT_WAV
#define CAPTURE_INTERNAL_FILENAME_ADPCM_FRAME "%s/" CAPTURE_INTERNAL_FILENAME_PREFIX CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT "%s%s" CAPTURE_INTERNAL_EXT_ADPCM_FRAME
#define CAPTURE_INTERNAL_FILENAME_ADPCM       "%s/" CAPTURE_INTERNAL_FILENAME_PREFIX CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT "%s%s" CAPTURE_INTERNAL_EXT_ADPCM
#define CAPTURE_INTERNAL_FILENAME_OPUS_XVP    "%s/" CAPTURE_INTERNAL_FILENAME_PREFIX CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT "%s%s" CAPTURE_INTERNAL_EXT_OPUS_XVP
#define CAPTURE_INTERNAL_FILENAME_OPUS        "%s/" CAPTURE_INTERNAL_FILENAME_PREFIX CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT "%s%s" CAPTURE_INTERNAL_EXT_OPUS

#define CAPTURE_INTERNAL_FILENAME_SIZE_MAX (sizeof(CAPTURE_INTERNAL_FILENAME_ADPCM_FRAME) - 2 + XRAUDIO_STREAM_ID_SIZE_MAX)

#define PCM_32_BIT_MAX ( 2147483647)
#define PCM_32_BIT_MIN (-2147483648)
#define PCM_24_BIT_MAX ( 8388607)
#define PCM_24_BIT_MIN (-8388608)
#define PCM_16_BIT_MAX (32767)
#define PCM_16_BIT_MIN (-32768)

#define XRAUDIO_PRE_KWD_STREAM_LAG_SAMPLES (1600)

struct xraudio_session_record_t;
typedef struct xraudio_session_record_t xraudio_session_record_t;
struct xraudio_session_record_inst_t;
typedef struct xraudio_session_record_inst_t xraudio_session_record_inst_t;

typedef int (*xraudio_in_record_t)(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance);

#ifdef XRAUDIO_KWD_ENABLED
typedef struct {
   bool                         triggered;
   xraudio_kwd_score_t          score;
   xraudio_kwd_snr_t            snr;
   xraudio_kwd_endpoints_t      endpoints;
   float                        pre_detection_buffer_fp32[(XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE * XRAUDIO_PRE_DETECTION_DURATION_MAX) / 1000];
   uint32_t                     pd_sample_qty;
   uint32_t                     pd_index_write;
   uint8_t                      post_frame_count; // count of audio frames since this channel triggered
} xraudio_keyword_detector_chan_t;
#endif

typedef struct {
   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_kwd_object_t              kwd_object;
   xraudio_keyword_sensitivity_t     sensitivity;
   bool                              active;
   bool                              triggered;
   xraudio_keyword_detector_chan_t   channels[XRAUDIO_INPUT_MAX_CHANNEL_QTY];
   uint32_t                          post_frame_count_trigger;  // count of audio frames since the first detector triggered
   uint32_t                          post_frame_count_callback; // count of audio frames since detection callback
   uint8_t                           active_chan;               // kwd active ("best") channel
   xraudio_kwd_criterion_t           criterion;                 // kwd criterion for choosing active channel
   #endif
   keyword_callback_t                callback;
   void *                            cb_param;
   xraudio_keyword_detector_result_t result;
   uint8_t                           input_kwd_max_channel_qty;
   uint8_t                           input_asr_kwd_channel_qty;
   uint8_t                           single_channel;            // operates with only this channel when specified
   xraudio_single_chan_mode_t        single_channel_mode;       // single channel processing modifier
} xraudio_keyword_detector_t;

typedef struct {
   uint8_t                           single_channel;            // operates with only this channel when specified
   xraudio_single_chan_mode_t        single_channel_mode;       // single channel processing modifier
} xraudio_eos_detector_t;

typedef struct {
   int                     fd;
   uint32_t                audio_data_size;
   xraudio_input_format_t  format;
   bool                    has_header;
   #ifdef CURTAIL_ENABLED
   bool                    header_truncated;
   uint32_t                logical_block_size;
   #endif
} xraudio_capture_file_t;

typedef struct {
   int32_t max;
   int32_t min;
} xraudio_pcm_range_t;

typedef struct {
   xraudio_capture_file_t file;
   xraudio_pcm_range_t    pcm_range;
} xraudio_capture_point_t;

typedef struct {
   bool                    active;
   xraudio_capture_t       type;
   audio_in_callback_t     callback;
   void *                  param;
   xraudio_capture_point_t input[XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY];
   xraudio_capture_point_t kwd[XRAUDIO_INPUT_MAX_CHANNEL_QTY];
   xraudio_capture_point_t eos[XRAUDIO_INPUT_MAX_CHANNEL_QTY];
   xraudio_capture_point_t output[XRAUDIO_INPUT_SESSION_GROUP_QTY];
   char                    audio_file_path[128];
   xraudio_container_t     container;
   bool                    raw_mic_enable;
} xraudio_capture_session_t;

typedef struct {
   bool                    enabled;
   bool                    use_curtail;
   char *                  dir_path;
   uint32_t                file_qty_max;
   uint32_t                file_size_max;
   uint32_t                file_index;
} xraudio_capture_internal_t;

typedef struct {
   bool                    active;
   xraudio_capture_file_t  native;
   xraudio_capture_file_t  decoded;
} xraudio_capture_instance_t;

typedef struct {
   int16_t samples[XRAUDIO_INPUT_FRAME_SAMPLE_QTY];
} xraudio_audio_frame_int16_t;

#ifdef XRAUDIO_PPR_ENABLED
typedef struct {
   int32_t samples[XRAUDIO_INPUT_FRAME_SAMPLE_QTY];
} xraudio_audio_frame_int32_t;
#endif

typedef struct {
   xraudio_audio_frame_int16_t frames[XRAUDIO_INPUT_MAX_FRAME_GROUP_QTY];
} xraudio_audio_group_int16_t;

typedef struct {
   float samples[XRAUDIO_INPUT_FRAME_SAMPLE_QTY];
} xraudio_audio_frame_float_t;

typedef struct {
   xraudio_audio_frame_float_t frames[XRAUDIO_INPUT_MAX_FRAME_GROUP_QTY];
} xraudio_audio_group_float_t;

typedef void (*xraudio_handler_unpack_t)(xraudio_session_record_t *session, void *buffer_in, uint8_t chan_qty, xraudio_audio_group_int16_t *frame_buffer_int16, xraudio_audio_group_float_t *frame_buffer_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame);

struct xraudio_session_record_inst_t {
   xraudio_devices_input_t        source;
   bool                           mode_changed;
   xraudio_in_record_t            record_callback;
   int                            fifo_audio_data[XRAUDIO_FIFO_QTY_MAX];
   xraudio_input_record_from_t    stream_from[XRAUDIO_FIFO_QTY_MAX];
   xraudio_input_record_until_t   stream_until[XRAUDIO_FIFO_QTY_MAX];
   int32_t                        stream_begin_offset[XRAUDIO_FIFO_QTY_MAX];
   xraudio_input_format_t         format_out;
   uint32_t                       frame_size_out;
   uint8_t                        frame_group_qty;

   int                            fd;
   xraudio_sample_t *             audio_buf_samples;
   uint32_t                       audio_buf_sample_qty;
   uint32_t                       audio_buf_index;
   audio_in_data_callback_t       data_callback;

   bool                           synchronous;
   sem_t *                        semaphore;
   audio_in_callback_t            callback;
   void *                         param;
   int                            fifo_sound_intensity;

   bool                           keyword_triggered;
   uint32_t                       keyword_end_samples;
   bool                           keyword_flush;

   #ifdef XRAUDIO_DGA_ENABLED
   bool                           dynamic_gain_set;
   uint8_t                        dynamic_gain_pcm_bit_qty;
   int16_t                        hal_kwd_peak_power_dBFS;
   #endif

   uint32_t                       stream_time_min_value; // samples or bytes depending on source
   xraudio_stream_latency_mode_t  latency_mode;
   xraudio_stream_cpu_util_mode_t cpu_util_mode;
   #ifdef XRAUDIO_KWD_ENABLED
   uint32_t                       pre_detection_sample_qty;
   #endif

   xraudio_audio_stats_t          stats; // for internal microphone only
   xraudio_eos_event_t            eos_event;
   bool                           eos_vad_forced;
   uint32_t                       eos_end_of_wake_word_samples;
   bool                           use_hal_eos;
   bool                           eos_hal_cmd_pending;
   #ifdef XRAUDIO_KWD_ENABLED
   bool                           raw_mic_enable;
   uint32_t                       raw_mic_frame_skip;
   #endif

   xraudio_capture_instance_t     capture_internal;
};

struct xraudio_session_record_t {
   bool                           recording;
   uint8_t                        pcm_bit_qty;
   xraudio_input_format_t         format_in;
   uint32_t                       timeout;
   xraudio_handler_unpack_t       handler_unpack;
   xraudio_audio_group_int16_t    frame_buffer_int16[XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY];
   xraudio_audio_group_float_t    frame_buffer_fp32[XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY];
   uint8_t                        frame_group_index;
   uint32_t                       frame_size_in;
   uint32_t                       frame_sample_qty;
   xraudio_stream_latency_mode_t  latency_mode;
   xraudio_stream_cpu_util_mode_t cpu_util_mode;
   #ifdef XRAUDIO_DGA_ENABLED
   xraudio_dga_object_t           obj_dga;
   bool                           dynamic_gain_enabled;
   #endif
   xraudio_keyword_detector_t     keyword_detector;
   xraudio_eos_detector_t         eos_detector;
   xraudio_devices_input_t        devices_input;
   rdkx_timestamp_t               timestamp_next;
   xraudio_capture_session_t      capture_session;
   xraudio_capture_internal_t     capture_internal;
   #ifdef MASK_FIRST_READ_DELAY
   xraudio_thread_t               first_read_thread;
   bool                           first_read_pending;
   bool                           first_read_complete;
   #endif
   int                            external_fd;
   uint8_t                        external_frame_group_qty;
   uint8_t                        external_frame_group_index;
   uint32_t                       external_frame_size_in;
   uint32_t                       external_frame_size_out;
   uint8_t                        external_frame_buffer[(XRAUDIO_INPUT_EXTERNAL_FRAME_SAMPLE_QTY * sizeof(int16_t)) * XRAUDIO_INPUT_MAX_FRAME_GROUP_QTY];
   xraudio_input_format_t         external_format;
   uint32_t                       external_data_len;
   uint32_t                       external_frame_bytes_read;
   xraudio_input_data_read_cb_t   external_callback;
   void *                         external_user_data;
   int8_t                         input_aop_adjust_shift;
   float                          input_aop_adjust_dB;
   #ifdef XRAUDIO_KWD_ENABLED
   int                            fd;
   bool                           raw_mic_enable;
   #endif
   uint8_t *                      hal_mic_frame_ptr;
   uint32_t                       hal_mic_frame_size;

   xraudio_session_record_inst_t  instances[XRAUDIO_INPUT_SESSION_GROUP_QTY];
};

#ifdef XRAUDIO_OUTPUT_ENABLED
typedef struct {
   xraudio_hal_output_obj_t  hal_output_obj;
   bool                      playing;
   bool                      mode_changed;
   bool                      synchronous;
   audio_out_callback_t      callback;
   void *                    param;
   sem_t *                   semaphore;
   xraudio_output_format_t   format;
   int                       fd;
   const unsigned char *     audio_buf;
   uint32_t                  audio_buf_size;
   uint32_t                  audio_buf_index;
   audio_out_data_callback_t data_callback;
   int                       pipe_audio_data;
   uint32_t                  timeout;
   unsigned char             frame_buffer[XRAUDIO_OUTPUT_FRAME_SIZE_MAX];
   uint32_t                  frame_size;
   int                       fifo_sound_intensity;
   rdkx_timestamp_t          timestamp_next;
   #ifdef MASK_FIRST_WRITE_DELAY
   xraudio_thread_t          first_write_thread;
   bool                      first_write_pending;
   bool                      first_write_complete;
   #endif
} xraudio_session_playback_t;
#endif

typedef struct {
   #ifdef XRAUDIO_DECODE_ADPCM
   adpcm_dec_t *             adpcm;
   #endif
   #ifdef XRAUDIO_DECODE_OPUS
   xraudio_opus_object_t     opus;
   #endif
} xraudio_decoders_t;

typedef struct {
   xraudio_main_thread_params_t params;
   bool                         running;
   rdkx_timer_object_t          timer_obj;
   rdkx_timer_id_t              timer_id_frame;
   xraudio_session_record_t     record;
   #ifdef XRAUDIO_OUTPUT_ENABLED
   xraudio_session_playback_t   playback;
   #endif
   xraudio_decoders_t           decoders;
} xraudio_thread_state_t;

#ifdef MASK_FIRST_WRITE_DELAY
typedef struct {
   xraudio_main_thread_params_t *params;
   xraudio_session_playback_t *  session;
} xraudio_thread_first_write_params_t;
#endif

#ifdef MASK_FIRST_READ_DELAY
typedef struct {
   xraudio_main_thread_params_t *params;
   xraudio_session_record_t *  session;
} xraudio_thread_first_read_params_t;
#endif

typedef struct {
   bool                    init;
   int                     msgq;
   int                     detecting;
   xraudio_devices_input_t sources_supported;
   xraudio_atomic_int_t    source[XRAUDIO_INPUT_SESSION_GROUP_QTY];
} xraudio_session_voice_t;

typedef void (*xraudio_msg_handler_t)(xraudio_thread_state_t *state, void *msg);

#if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_OUTPUT_ENABLED)
static void timer_frame_process(void *data);
#endif

#ifdef XRAUDIO_KWD_ENABLED
static void xraudio_process_mic_data(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, unsigned long *timeout);
static void xraudio_process_mic_error(xraudio_session_record_t *session);
static void xraudio_unpack_mono_int16(xraudio_session_record_t *session, void *buffer_in, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame);
static void xraudio_unpack_mono_int32(xraudio_session_record_t *session, void *buffer_in, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame);
static void xraudio_unpack_multi_int16(xraudio_session_record_t *session, void *buffer_in, uint8_t chan_qty, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame);
static void xraudio_unpack_multi_int32(xraudio_session_record_t *session, void *buffer_in, uint8_t chan_qty, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame);
#endif

static void xraudio_process_input_external_data(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_decoders_t *decoders);
static ssize_t xraudio_external_fd_read(xraudio_session_record_t *session, void *buf, size_t count);
static void xraudio_in_flush(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance);
static int  xraudio_in_write_to_file(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance);
static int  xraudio_in_write_to_memory(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance);
static int  xraudio_in_write_to_pipe(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance);
static int  xraudio_in_write_to_user(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance);

#ifdef XRAUDIO_KWD_ENABLED
static void     xraudio_keyword_detector_init(xraudio_keyword_detector_t *detector, json_t* jkwd_config);
static void     xraudio_keyword_detector_term(xraudio_keyword_detector_t *detector);
static void     xraudio_keyword_detector_session_init(xraudio_keyword_detector_t *detector, uint8_t chan_qty, xraudio_keyword_sensitivity_t sensitivity);
static bool     xraudio_keyword_detector_session_is_active(xraudio_keyword_detector_t *detector);
static uint32_t xraudio_keyword_detector_session_pd_avail(xraudio_keyword_detector_t *detector, uint8_t active_chan);
static void     xraudio_keyword_detector_session_term(xraudio_keyword_detector_t *detector);
static int      xraudio_in_write_to_keyword_detector(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance);
static void     xraudio_in_write_to_keyword_buffer(xraudio_keyword_detector_chan_t *keyword_detector_chan, float *frame_buffer_fp32, uint32_t sample_qty);
static bool     xraudio_in_pre_detection_chunks(xraudio_keyword_detector_chan_t *keyword_detector_chan, uint32_t sample_qty, uint32_t offset_from_end, float **chunk_1_data, uint32_t *chunk_1_qty, float **chunk_2_data, uint32_t *chunk_2_qty);
#endif
static void xraudio_keyword_detector_session_disarm(xraudio_keyword_detector_t *detector);
static void xraudio_keyword_detector_session_arm(xraudio_keyword_detector_t *detector, keyword_callback_t callback, void *cb_param, xraudio_keyword_sensitivity_t sensitivity);
static bool xraudio_keyword_detector_session_is_armed(xraudio_keyword_detector_t *detector);

static void xraudio_eos_detector_init(xraudio_eos_detector_t *detector);
static void xraudio_eos_detector_term(xraudio_eos_detector_t *detector);

#ifdef XRAUDIO_KWD_ENABLED
static void xraudio_keyword_detector_session_event(xraudio_keyword_detector_t *detector, xraudio_devices_input_t source, const uuid_t *uuid, keyword_callback_event_t event, xraudio_keyword_detector_result_t *detector_result, xraudio_input_format_t format);
static void xraudio_in_sound_intensity_transfer(xraudio_main_thread_params_t *params, xraudio_session_record_t *session);
#endif

#ifdef XRAUDIO_OUTPUT_ENABLED
static void xraudio_process_spkr_data(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size, unsigned long *timeout, rdkx_timestamp_t *timestamp_sync);
static int  xraudio_out_write_from_file(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size);
static int  xraudio_out_write_from_memory(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size);
static int  xraudio_out_write_from_pipe(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size);
static int  xraudio_out_write_from_user(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size);
static int  xraudio_out_write_silence(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size);
static void xraudio_out_sound_intensity_transfer(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session);
static int  xraudio_out_write_hal(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned char *buffer, unsigned long frame_size);
#endif

static void xraudio_record_container_process_begin(xraudio_capture_file_t *capture_file);
static void xraudio_record_container_process_end(int fd, xraudio_input_format_t format, unsigned long audio_data_size, bool header_truncated);
static void xraudio_in_capture_internal_input_begin(xraudio_input_format_t *native, xraudio_input_format_t *decoded, xraudio_capture_internal_t *capture_internal, xraudio_capture_instance_t *capture_instance, const char *stream_id);
static void xraudio_in_capture_internal_end(xraudio_capture_instance_t *capture_instance);
static int  xraudio_in_capture_internal_to_file(xraudio_session_record_t *session, uint8_t *data_in, uint32_t data_size, xraudio_capture_file_t *capture_file);
static bool xraudio_in_capture_internal_filename_get(char *filename, const char *dir_path, uint32_t filename_size, xraudio_encoding_t encoding, uint32_t file_index, const char *stream_id);

#if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_DGA_ENABLED)
static void xraudio_samples_convert_fp32_int16(int16_t *samples_int16, float *samples_fp32, uint32_t sample_qty, uint32_t bit_qty);
#endif
#ifdef XRAUDIO_PPR_ENABLED
static void xraudio_preprocess_mic_data(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_ppr_event_t *ppr_event);
//static void xraudio_samples_convert_int16_int32(int16_t *int16buf, int32_t *int32buf, uint32_t sample_qty_frame, uint8_t sample_size);
static void xraudio_samples_convert_int32_int16(int16_t *int16buf, int32_t *int32buf, uint32_t sample_qty_frame, uint32_t bit_qty);
static void xraudio_samples_convert_int32_fp32(float *fp32buf, int32_t *int32buf, uint32_t sample_qty_frame, uint32_t bit_qty);
#endif
#if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_PPR_ENABLED)
static void xraudio_samples_convert_fp32_int32(int32_t *int32buf, float *fp32buf, uint32_t sample_qty_frame, uint32_t bit_qty);
#endif

static int      xraudio_capture_file_filter_all(const struct dirent *name);
static int      xraudio_capture_file_filter_by_index(const struct dirent *name);
static uint32_t xraudio_capture_next_file_index(const char *dir_path, uint32_t file_qty_max);
static bool     xraudio_capture_file_index_in_use(const char *dir_path, uint32_t index);
static void     xraudio_capture_file_delete(const char *dir_path, uint32_t index);
static time_t   xraudio_get_file_timestamp(char *filename);

static int  xraudio_in_capture_session_to_file_int16(xraudio_capture_point_t *capture_point, int16_t *samples, uint32_t sample_qty);
static int  xraudio_in_capture_session_to_file_int32(xraudio_capture_point_t *capture_point, int32_t *samples, uint32_t sample_qty);
#if defined(XRAUDIO_KWD_ENABLED) && defined(XRAUDIO_DGA_ENABLED)
static int  xraudio_in_capture_session_to_file_float(xraudio_capture_point_t *capture_point, float *samples, uint32_t sample_qty);
#endif

static xraudio_devices_input_t xraudio_in_session_group_source_get(xraudio_input_session_group_t group);
static bool xraudio_in_session_group_semaphore_lock(xraudio_devices_input_t source);
static void xraudio_in_session_group_semaphore_unlock(xraudio_thread_state_t *state, xraudio_devices_input_t source);
static void xraudio_in_session_record_group_semaphore_unlock(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_devices_input_t source);
static xraudio_session_record_inst_t *xraudio_in_source_to_inst(xraudio_session_record_t *session, xraudio_devices_input_t source);

static void xraudio_cpu_util_mode_enter(xraudio_thread_state_t *state, xraudio_session_record_inst_t *instance);
static void xraudio_cpu_util_mode_exit(xraudio_session_record_t *session);

static void xraudio_msg_record_idle_start(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_record_idle_stop(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_record_start(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_record_stop(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_capture_start(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_capture_stop(xraudio_thread_state_t *state, void *msg);
#ifdef XRAUDIO_OUTPUT_ENABLED
static void xraudio_msg_play_idle(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_play_start(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_play_pause(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_play_resume(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_play_stop(xraudio_thread_state_t *state, void *msg);
#else
static void xraudio_msg_dummy(xraudio_thread_state_t *state, void *msg);
#endif
static void xraudio_msg_detect(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_detect_params(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_detect_sensitivity_limits_get(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_detect_stop(xraudio_thread_state_t *state, void *msg);
#ifdef XRAUDIO_KWD_ENABLED
static void xraudio_msg_async_session_begin(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_async_session_end(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_async_input_error(xraudio_thread_state_t *state, void *msg);
#endif
static void xraudio_msg_terminate(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_thread_poll(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_power_mode(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_privacy_mode(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_privacy_mode_get(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_capture_params_set(xraudio_thread_state_t *state, void *msg);
static void xraudio_msg_input_source_fd_set(xraudio_thread_state_t *state, void *msg);

static void xraudio_encoding_parameters_get(xraudio_input_format_t *format, uint32_t frame_duration, uint32_t *frame_size, uint16_t stream_time_min_ms, uint32_t *min_audio_data_len);
#ifdef XRAUDIO_KWD_ENABLED
static bool xraudio_in_aop_adjust_apply(int32_t *buffer, uint32_t sample_qty_frame, int8_t input_aop_adjust_shift);
#endif
#ifdef CURTAIL_ENABLED
static void xraudio_capture_file_size_max_verify(uint32_t *file_size_max);
#endif

static const xraudio_msg_handler_t g_xraudio_msg_handlers[XRAUDIO_MAIN_QUEUE_MSG_TYPE_INVALID] = {
   xraudio_msg_record_idle_start,
   xraudio_msg_record_idle_stop,
   xraudio_msg_record_start,
   xraudio_msg_record_stop,
   xraudio_msg_capture_start,
   xraudio_msg_capture_stop,
   #ifdef XRAUDIO_OUTPUT_ENABLED
   xraudio_msg_play_idle,
   xraudio_msg_play_start,
   xraudio_msg_play_pause,
   xraudio_msg_play_resume,
   xraudio_msg_play_stop,
   #else
   xraudio_msg_dummy, xraudio_msg_dummy, xraudio_msg_dummy, xraudio_msg_dummy, xraudio_msg_dummy,
   #endif
   xraudio_msg_detect,
   xraudio_msg_detect_params,
   xraudio_msg_detect_sensitivity_limits_get,
   xraudio_msg_detect_stop,
   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_msg_async_session_begin,
   xraudio_msg_async_session_end,
   xraudio_msg_async_input_error,
   #else
   xraudio_msg_dummy, xraudio_msg_dummy, xraudio_msg_dummy,
   #endif
   xraudio_msg_terminate,
   xraudio_msg_thread_poll,
   xraudio_msg_power_mode,
   xraudio_msg_privacy_mode,
   xraudio_msg_privacy_mode_get,
   xraudio_msg_capture_params_set,
   xraudio_msg_input_source_fd_set
};

#ifdef MASK_FIRST_WRITE_DELAY
static void *xraudio_thread_first_write(void *param);

xraudio_thread_first_write_params_t g_thread_params_write;
#endif

#ifdef MASK_FIRST_READ_DELAY
static void *xraudio_thread_first_read(void *param);

xraudio_thread_first_read_params_t g_thread_params_read;
#endif

static unsigned char g_frame_silence[2 * XRAUDIO_OUTPUT_FRAME_SIZE_MAX];

static xraudio_session_voice_t g_voice_session = {0};

void *xraudio_main_thread(void *param) {
   xraudio_thread_state_t *state = (xraudio_thread_state_t *)malloc(sizeof(xraudio_thread_state_t));
   if(state == NULL) {
      XLOGD_ERROR("out of memory");
      return(NULL);
   }
   memset(state, 0, sizeof(*state));
#ifdef XRAUDIO_KWD_ENABLED
   json_t *jkwd_config = NULL;
#endif
#ifdef XRAUDIO_DGA_ENABLED
   json_t *jdga_config = NULL;
#endif

   state->params = *((xraudio_main_thread_params_t *)param);

   #ifdef XRAUDIO_KWD_ENABLED
   if(state->params.dsp_config.input_kwd_max_channel_qty > XRAUDIO_INPUT_KWD_MAX_CHANNEL_QTY) {
      XLOGD_WARN("Input kwd chan qty > maximum (%d) - default to max", XRAUDIO_INPUT_KWD_MAX_CHANNEL_QTY);
      state->params.dsp_config.input_kwd_max_channel_qty = XRAUDIO_INPUT_KWD_MAX_CHANNEL_QTY;
   }

   if(state->params.dsp_config.input_asr_max_channel_qty > XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY) {
      XLOGD_WARN("Input asr chan qty > maximum (%d) - default to max", XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY);
      state->params.dsp_config.input_asr_max_channel_qty = XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY;
   }

   if((state->params.dsp_config.input_kwd_max_channel_qty + state->params.dsp_config.input_asr_max_channel_qty) > XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
      XLOGD_ERROR("Total quantity of keyword and asr postprocess channels cannot be greater than maximum input channel quantity");
      free(state);
      return(NULL);
   }
   #endif

   if(!g_voice_session.init) {
      g_voice_session = (xraudio_session_voice_t) { .init              = true,
                                                    .msgq              = state->params.msgq,
                                                    .detecting         = 0,
                                                    .sources_supported = XRAUDIO_DEVICE_INPUT_NONE,
                                                    .source            = { XRAUDIO_DEVICE_INPUT_INVALID } };
   }

   state->record.recording            = false;
   #ifdef XRAUDIO_KWD_ENABLED
   state->record.fd                   = -1;
   #endif
   state->record.format_in            = (xraudio_input_format_t) { .container     = XRAUDIO_CONTAINER_INVALID,
                                                                   .encoding.type = XRAUDIO_ENCODING_INVALID,
                                                                   .sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                                   .sample_size   = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                                   .channel_qty   = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };
   state->record.timeout                = 0;
   state->record.frame_group_index      = 0;
   state->record.frame_size_in          = 0;
   state->record.frame_sample_qty       = 0;
   state->record.latency_mode           = XRAUDIO_STREAM_LATENCY_NORMAL;
   state->record.cpu_util_mode          = XRAUDIO_STREAM_CPU_UTIL_NORMAL;

   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_session_record_inst_t *instance = &state->record.instances[group];

      instance->source                 = XRAUDIO_DEVICE_INPUT_NONE;
      instance->frame_size_out         = 0;
      instance->frame_group_qty        = XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY;
      instance->mode_changed           = false;
      instance->record_callback        = NULL;
      instance->fd                     = -1;
      instance->audio_buf_samples      = NULL;
      instance->audio_buf_sample_qty   = 0;
      instance->audio_buf_index        = 0;
      instance->data_callback          = NULL;
      instance->callback               = NULL;
      instance->param                  = NULL;
      instance->fifo_sound_intensity   = -1;
      instance->synchronous            = false;
      instance->semaphore              = NULL;
      instance->latency_mode           = XRAUDIO_STREAM_LATENCY_NORMAL;
      instance->cpu_util_mode          = XRAUDIO_STREAM_CPU_UTIL_NORMAL;

      for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
         instance->fifo_audio_data[index]     = -1;
         instance->stream_from[index]         = XRAUDIO_INPUT_RECORD_FROM_INVALID;
         instance->stream_until[index]        = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
         instance->stream_begin_offset[index] = 0;
      }

      #ifdef XRAUDIO_DGA_ENABLED
      instance->dynamic_gain_set         = false;
      instance->dynamic_gain_pcm_bit_qty = 0;
      instance->hal_kwd_peak_power_dBFS  = -96;
      #endif
      #ifdef XRAUDIO_KWD_ENABLED
      instance->pre_detection_sample_qty = 0;
      #endif

      memset(&instance->stats, 0, sizeof(instance->stats));

      instance->eos_event                    = XRAUDIO_EOS_EVENT_NONE;
      instance->eos_vad_forced               = false;
      instance->eos_end_of_wake_word_samples = 0;
      instance->use_hal_eos                  = false;
      instance->eos_hal_cmd_pending          = false;
      #ifdef XRAUDIO_KWD_ENABLED
      instance->raw_mic_enable               = false;
      instance->raw_mic_frame_skip           = 0;
      #endif
      instance->keyword_triggered            = false;

      instance->capture_internal.active                  = false;
      instance->capture_internal.native.fd               = -1;
      instance->capture_internal.native.audio_data_size  = 0;
      instance->capture_internal.native.format           = (xraudio_input_format_t) { .container     = XRAUDIO_CONTAINER_INVALID,
                                                                                      .encoding.type = XRAUDIO_ENCODING_INVALID,
                                                                                      .sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                                                      .sample_size   = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                                                      .channel_qty   = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };
      instance->capture_internal.decoded.fd              = -1;
      instance->capture_internal.decoded.audio_data_size = 0;
      instance->capture_internal.decoded.format          = (xraudio_input_format_t) { .container     = XRAUDIO_CONTAINER_INVALID,
                                                                                      .encoding.type = XRAUDIO_ENCODING_INVALID,
                                                                                      .sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                                                      .sample_size   = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                                                      .channel_qty   = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };

   }

   #ifdef XRAUDIO_KWD_ENABLED
   if(NULL == state->params.json_obj_input) {
      XLOGD_INFO("parameter json_obj_input is null, using defaults");
   } else {
      jkwd_config = json_object_get(state->params.json_obj_input, JSON_OBJ_NAME_INPUT_KWD);
      if(NULL == jkwd_config) {
         XLOGD_INFO("KWD config not found, using defaults");
      } else {
         if(!json_is_object(jkwd_config)) {
            XLOGD_INFO("jkwd_config is not object, using defaults");
            jkwd_config = NULL;
         }
      }
   }
   state->record.keyword_detector.input_kwd_max_channel_qty = state->params.dsp_config.input_kwd_max_channel_qty;
   state->record.keyword_detector.input_asr_kwd_channel_qty = state->params.dsp_config.input_asr_max_channel_qty + state->params.dsp_config.input_kwd_max_channel_qty;
   state->record.keyword_detector.single_channel_mode       = state->params.dsp_config.dsp_output_override_enable ? XRAUDIO_SINGLE_CHANNEL_SKIP : XRAUDIO_SINGLE_CHANNEL_ONLY;
   xraudio_keyword_detector_init(&state->record.keyword_detector, jkwd_config);
   XLOGD_DEBUG("keyword_detector.single_channel_mode <%s>", (state->record.keyword_detector.single_channel_mode == XRAUDIO_SINGLE_CHANNEL_SKIP) ? "SKIP" : "ONLY");
   #endif

   #ifdef XRAUDIO_KWD_ENABLED
   state->record.eos_detector.single_channel_mode = state->params.dsp_config.dsp_output_override_enable ? XRAUDIO_SINGLE_CHANNEL_SKIP : XRAUDIO_SINGLE_CHANNEL_ONLY;
   #else
   state->record.eos_detector.single_channel_mode = XRAUDIO_SINGLE_CHANNEL_ONLY;
   #endif
   xraudio_eos_detector_init(&state->record.eos_detector);
   XLOGD_DEBUG("eos_detector.single_channel_mode <%s>", (state->record.eos_detector.single_channel_mode == XRAUDIO_SINGLE_CHANNEL_SKIP) ? "SKIP" : "ONLY");

   #ifdef XRAUDIO_DGA_ENABLED
   if(NULL == state->params.json_obj_input) {
      XLOGD_INFO("parameter json_obj_input is null, using defaults");
   } else {
      jdga_config = json_object_get(state->params.json_obj_input, JSON_OBJ_NAME_INPUT_DGA);
      if(NULL == jdga_config) {
         XLOGD_INFO("DGA config not found, using defaults");
      } else {
         if(!json_is_object(jdga_config)) {
            XLOGD_INFO("jdga_config is not object, using defaults");
            jdga_config = NULL;
         }
      }
   }
   state->record.obj_dga                  = xraudio_dga_object_create(jdga_config);
   state->record.dynamic_gain_enabled     = true;
   #endif

   state->record.devices_input                = XRAUDIO_DEVICE_INPUT_NONE;
   state->record.timestamp_next               = (rdkx_timestamp_t) { .tv_sec = 0, .tv_nsec = 0 };
   memset(state->record.frame_buffer_int16, 0, sizeof(state->record.frame_buffer_int16));
   memset(state->record.frame_buffer_fp32, 0, sizeof(state->record.frame_buffer_fp32));

   memset(&state->record.capture_session, 0, sizeof(state->record.capture_session));

   if(state->params.internal_capture_params.enable) {
      XLOGD_INFO("internal capture dir path <%s> file qty max <%u> file size max <%u> curtail <%s>", state->params.internal_capture_params.dir_path, state->params.internal_capture_params.file_qty_max, state->params.internal_capture_params.file_size_max, state->params.internal_capture_params.use_curtail ? "YES" : "NO");
      state->record.capture_internal.enabled                 = state->params.internal_capture_params.enable;
      state->record.capture_internal.use_curtail             = state->params.internal_capture_params.use_curtail;
      state->record.capture_internal.dir_path                = strdup(state->params.internal_capture_params.dir_path);
      state->record.capture_internal.file_qty_max            = state->params.internal_capture_params.file_qty_max;
      state->record.capture_internal.file_size_max           = state->params.internal_capture_params.file_size_max;
      state->record.capture_internal.file_index              = xraudio_capture_next_file_index(state->params.internal_capture_params.dir_path, state->params.internal_capture_params.file_qty_max);

      #ifdef CURTAIL_ENABLED
      xraudio_capture_file_size_max_verify(&state->record.capture_internal.file_size_max);
      #endif
   } else {
      XLOGD_INFO("internal capture disabled");
      state->record.capture_internal.enabled                 = false;
      state->record.capture_internal.use_curtail             = false;
      state->record.capture_internal.dir_path                = NULL;
      state->record.capture_internal.file_qty_max            = 0;
      state->record.capture_internal.file_size_max           = 0;
      state->record.capture_internal.file_index              = 0;

   }

   #ifdef MASK_FIRST_READ_DELAY
   state->record.first_read_thread.id      = 0;
   state->record.first_read_thread.running = false;
   state->record.first_read_pending        = false;
   state->record.first_read_complete       = false;
   #endif

   state->record.external_fd                = -1;
   state->record.external_callback          = NULL;
   state->record.external_user_data         = NULL;
   state->record.external_frame_group_qty   = XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY;
   state->record.external_frame_group_index = 0;
   state->record.external_frame_size_in     = 0;
   state->record.external_frame_size_out    = 0;
   memset(state->record.external_frame_buffer, 0, sizeof(state->record.external_frame_buffer));
   memset(&state->record.external_format,      0, sizeof(state->record.external_format));

   #ifdef XRAUDIO_OUTPUT_ENABLED
   state->playback.hal_output_obj       = NULL;
   state->playback.playing              = false;
   state->playback.mode_changed         = false;
   state->playback.synchronous          = false;
   state->playback.callback             = NULL;
   state->playback.param                = NULL;
   state->playback.semaphore            = NULL;
   state->playback.format               = (xraudio_output_format_t) { .container   = XRAUDIO_CONTAINER_INVALID,
                                                                     .encoding    = XRAUDIO_ENCODING_INVALID,
                                                                     .sample_rate = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                                     .sample_size = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                                     .channel_qty = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };
   state->playback.fd                   = -1;
   state->playback.audio_buf            = NULL;
   state->playback.audio_buf_size       = 0;
   state->playback.audio_buf_index      = 0;
   state->playback.data_callback        = NULL;
   state->playback.pipe_audio_data      = -1;
   state->playback.timeout              = 0;
   memset(state->playback.frame_buffer, 0, sizeof(state->playback.frame_buffer));
   state->playback.frame_size           = 0;
   state->playback.timestamp_next       = (rdkx_timestamp_t) { .tv_sec = 0, .tv_nsec = 0 };
   #ifdef MASK_FIRST_WRITE_DELAY
   state->playback.first_write_thread.id      = 0;
   state->playback.first_write_thread.running = false;
   state->playback.first_write_pending        = false;
   state->playback.first_write_complete       = false;
   #endif
   #endif

   #ifdef XRAUDIO_KWD_ENABLED
   state->record.input_aop_adjust_shift       = XRAUDIO_IN_AOP_ADJ_DB_TO_SHIFT(state->params.dsp_config.aop_adjust);
   state->record.input_aop_adjust_dB          = state->params.dsp_config.aop_adjust;
   XLOGD_INFO("input AOP adjusted by <%f> dB (shifted right <%d> bits)", state->record.input_aop_adjust_dB, state->record.input_aop_adjust_shift);

   state->record.raw_mic_enable     = false;
   #endif

   memset(g_frame_silence, 0, sizeof(g_frame_silence));

   state->running        = true;
   state->timer_obj      = rdkx_timer_create(4, true, true);
   state->timer_id_frame = RDXK_TIMER_ID_INVALID;

   #ifdef XRAUDIO_DECODE_ADPCM
   // Create ADPCM decoder
   state->decoders.adpcm = adpcm_decode_create();
   #endif
   #ifdef XRAUDIO_DECODE_OPUS
   state->decoders.opus = xraudio_opus_create();
   if(state->decoders.opus == NULL) {
      XLOGD_ERROR("unable to create opus decoder");
   }
   #endif

   char msg[XRAUDIO_MSG_QUEUE_MSG_SIZE_MAX];
   XLOGD_DEBUG("Started");

   // Unblock the caller that launched this thread
   sem_post(state->params.semaphore);

   XLOGD_INFO("Enter main loop");
   do {

      int src;
      int nfds = state->params.msgq + 1;
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(state->params.msgq, &rfds);
      #ifdef XRAUDIO_KWD_ENABLED
      if(state->record.fd >= 0) {
         if(state->record.fd > state->params.msgq) {
            nfds = state->record.fd + 1;
         }
         FD_SET(state->record.fd, &rfds);
      }
      #endif
      xraudio_session_record_inst_t *instance = &state->record.instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];
      xraudio_devices_input_t ext_source = XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(instance->source);
      if(ext_source != XRAUDIO_DEVICE_INPUT_NONE && state->record.external_fd >= 0 && ext_source == xraudio_in_session_group_source_get(XRAUDIO_INPUT_SESSION_GROUP_DEFAULT)) {
         if(state->record.external_fd > state->params.msgq) {
            nfds = state->record.external_fd + 1;
         }
         FD_SET(state->record.external_fd, &rfds);
      }

      struct timeval tv;
      rdkx_timer_handler_t handler = NULL;
      void *data = NULL;
      rdkx_timer_id_t timer_id = rdkx_timer_next_get(state->timer_obj, &tv, &handler, &data);

      errno = 0;
      if(timer_id >= 0) {
         src = select(nfds, &rfds, NULL, NULL, &tv);
      } else {
         src = select(nfds, &rfds, NULL, NULL, NULL);
      }

      if(src < 0) { // error occurred
         if(errno == EINTR) {
            continue;
         } else {
            int errsv = errno;
            XLOGD_ERROR("select failed <%s>", strerror(errsv));
            break;
         }
      }

      if(src == 0) { // timeout occurred
         if(data == NULL) {
            XLOGD_ERROR("timeout data invalid");
            if(!rdkx_timer_remove(state->timer_obj, timer_id)) {
               XLOGD_ERROR("timer remove");
            }
         } else {
            (*handler)(data);
         }
         continue;
      }

      #ifdef XRAUDIO_KWD_ENABLED
      if(state->record.fd >= 0) {
         if(FD_ISSET(state->record.fd, &rfds)) {
            uint64_t val;
            errno = 0;
            ssize_t rc = read(state->record.fd, &val, sizeof(val));
            if(rc != sizeof(val)) {
               if(rc < 0) {
                  int errsv = errno;
                  XLOGD_ERROR("record fd read error <%s>", strerror(errsv));
               } else {
                  XLOGD_ERROR("record fd read error <%d>", rc);
               }
            } else {
               XLOGD_DEBUG("val <%llu>", val);
               if(val > 0) {
                  unsigned long timeout;
                  xraudio_process_mic_data(&state->params, &state->record, &timeout);
               }
            }
         }
      }
      #endif
      if(state->record.external_fd >= 0) {
         if(FD_ISSET(state->record.external_fd, &rfds)) {
            // Read more audio data from the external fd interface
            xraudio_process_input_external_data(&state->params, &state->record, &state->decoders);
         }
      }

      // Process message queue if it is ready
      if(FD_ISSET(state->params.msgq, &rfds)) {
         xr_mq_msg_size_t bytes_read = xr_mq_pop(state->params.msgq, msg, sizeof(msg));
         if(bytes_read <= 0) {
            XLOGD_ERROR("xr_mq_pop failed <%d>", bytes_read);
            continue;
         }
         xraudio_main_queue_msg_header_t *header = (xraudio_main_queue_msg_header_t *)msg;

         if((uint32_t)header->type >= XRAUDIO_MAIN_QUEUE_MSG_TYPE_INVALID) {
            XLOGD_ERROR("invalid msg type <%s>", xraudio_main_queue_msg_type_str(header->type));
         } else {
            (*g_xraudio_msg_handlers[header->type])(state, msg);
         }
      }
   } while(state->running);

   rdkx_timer_destroy(state->timer_obj);

   #ifdef XRAUDIO_DGA_ENABLED
   if(state->record.obj_dga != NULL) {
      xraudio_dga_object_destroy(state->record.obj_dga);
      state->record.obj_dga = NULL;
   }
   #endif

   #ifdef XRAUDIO_DECODE_ADPCM
   adpcm_decode_destroy(state->decoders.adpcm);
   #endif
   #ifdef XRAUDIO_DECODE_OPUS
   if(state->decoders.opus != NULL) {
      xraudio_opus_destroy(state->decoders.opus);
      state->decoders.opus = NULL;
   }
   #endif
   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_keyword_detector_term(&state->record.keyword_detector);
   #endif

   xraudio_eos_detector_term(&state->record.eos_detector);

   if(state->record.capture_internal.dir_path != NULL) {
      free(state->record.capture_internal.dir_path);
   }
   free(state);

   return(NULL);
}

void xraudio_msg_record_idle_start(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_idle_start_t *idle_start = (xraudio_queue_msg_idle_start_t *)msg;
   XLOGD_DEBUG("");

   xraudio_session_record_inst_t *instance = &state->record.instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   instance->source                        = XRAUDIO_DEVICE_INPUT_NONE;
   instance->frame_group_qty               = XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY;
   instance->frame_size_out                = 0;
   instance->fd                            = -1;
   instance->audio_buf_samples             = NULL;
   instance->audio_buf_sample_qty          = 0;
   instance->data_callback                 = NULL;
   instance->callback                      = NULL;
   instance->param                         = NULL;
   instance->fifo_sound_intensity          = -1;
   instance->synchronous                   = false;
   instance->semaphore                     = NULL;
   #ifdef XRAUDIO_DGA_ENABLED
   instance->dynamic_gain_set              = false;
   #endif
   instance->eos_event                     = XRAUDIO_EOS_EVENT_NONE;
   instance->eos_vad_forced                = false;
   instance->eos_end_of_wake_word_samples  = 0;
   instance->use_hal_eos                   = (idle_start->capabilities & XRAUDIO_CAPS_INPUT_EOS_DETECTION) ? true : false;
   instance->eos_hal_cmd_pending           = false;

   for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
      instance->fifo_audio_data[index]     = -1;
      instance->stream_from[index]         = XRAUDIO_INPUT_RECORD_FROM_INVALID;
      instance->stream_until[index]        = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
      instance->stream_begin_offset[index] = 0;
   }

   #ifdef XRAUDIO_KWD_ENABLED
   state->record.fd                        = idle_start->fd;
   #endif
   state->record.format_in                 = idle_start->format;
   state->record.pcm_bit_qty               = idle_start->pcm_bit_qty;
   state->record.devices_input             = idle_start->devices_input;
   //XLOGD_INFO("record device = %s", xraudio_devices_input_str(state->record.devices_input));

   // Set timeout for next chunk (in microseconds)
   state->record.timeout           = XRAUDIO_INPUT_FRAME_PERIOD * 1000;
   state->record.frame_sample_qty  = (XRAUDIO_INPUT_FRAME_PERIOD * state->record.format_in.sample_rate * state->record.format_in.channel_qty) / 1000;
   state->record.frame_size_in     = state->record.frame_sample_qty * state->record.format_in.sample_size;
   state->record.frame_group_index = 0;
   state->record.latency_mode      = XRAUDIO_STREAM_LATENCY_NORMAL;
   state->record.cpu_util_mode     = XRAUDIO_STREAM_CPU_UTIL_NORMAL;

   state->record.external_frame_group_qty   = XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY;
   state->record.external_frame_group_index = 0;
   state->record.external_frame_size_in     = 0;
   state->record.external_frame_size_out    = 0;

   instance->record_callback = NULL;

   xraudio_in_session_group_semaphore_unlock(state, instance->source);

   if(state->record.recording) { // Only changing back to idle so don't read the microphone data until it's time
      return;
   }

   instance->audio_buf_index   = 0;
   instance->keyword_triggered = false;

   #ifdef XRAUDIO_KWD_ENABLED
   // TODO may need to add these back
   //xraudio_input_timing_data_clear(state->params.obj_input);
   //xraudio_input_statistics_clear(state->params.obj_input);

   //XLOGD_INFO("Max Score: %.0f, Max Detect Chan: %d", state->record.keyword_max_score, state->record.keyword_max_detector);
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(state->record.devices_input) != XRAUDIO_DEVICE_INPUT_NONE) {
      unsigned long timeout_val;

      XLOGD_DEBUG("nominal timeout %u us frame size in %u bytes", state->record.timeout, state->record.frame_size_in);

      if(state->record.format_in.sample_size > 2) {
         state->record.handler_unpack = xraudio_unpack_multi_int32;
      } else {
         state->record.handler_unpack = xraudio_unpack_multi_int16;
      }

      if(state->record.fd < 0) {
         xraudio_process_mic_data(&state->params, &state->record, &timeout_val);

         // Update the timeout
         rdkx_timestamp_t timeout;
         rdkx_timestamp_get(&timeout);
         rdkx_timestamp_add_us(&timeout, timeout_val);

         if(state->timer_id_frame == RDXK_TIMER_ID_INVALID) {
            state->timer_id_frame = rdkx_timer_insert(state->timer_obj, timeout, timer_frame_process, state);
         } else {
            rdkx_timer_update(state->timer_obj, state->timer_id_frame, timeout);
         }
      }
   }
   #endif
}

void xraudio_msg_record_idle_stop(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_record_idle_stop_t *idle_stop = (xraudio_queue_msg_record_idle_stop_t *)msg;
   XLOGD_DEBUG("");
   state->record.recording = false;
   
   #ifdef XRAUDIO_KWD_ENABLED
   if(state->record.fd >= 0) {
      close(state->record.fd);
      state->record.fd = -1;
   }

   xraudio_keyword_detector_session_term(&state->record.keyword_detector);
   #endif
   if(idle_stop->semaphore == NULL) {
      XLOGD_ERROR("synchronous stop with no semaphore set!");
   } else {
      sem_post(idle_stop->semaphore);
   }
}

void xraudio_msg_record_start(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_record_start_t *record = (xraudio_queue_msg_record_start_t *)msg;

   XLOGD_DEBUG("<%s> intensity <%s>", record->semaphore ? "SYNC" : "ASYNC", record->fifo_sound_intensity >= 0 ? "YES" : "NO");

   xraudio_session_record_inst_t *instance = xraudio_in_source_to_inst(&state->record, record->source);

   instance->frame_group_qty               = record->frame_group_qty;
   instance->synchronous                   = (record->callback == NULL) ? true : false;
   instance->callback                      = record->callback;
   instance->param                         = record->param;
   instance->semaphore                     = record->semaphore;

   instance->source                        = record->source;
   instance->fd                            = record->fd;
   instance->audio_buf_samples             = record->audio_buf_samples;
   instance->audio_buf_sample_qty          = record->audio_buf_sample_qty;
   instance->data_callback                 = record->data_callback;

   for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
      instance->fifo_audio_data[index]     = record->fifo_audio_data[index];
      instance->stream_from[index]         = record->stream_from[index];
      instance->stream_until[index]        = record->stream_until[index];
      instance->stream_begin_offset[index] = record->stream_begin_offset[index];
   }

   instance->fifo_sound_intensity          = record->fifo_sound_intensity;
   instance->eos_event                     = XRAUDIO_EOS_EVENT_NONE;

   bool external_src = (XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(instance->source) != XRAUDIO_DEVICE_INPUT_NONE) ? true : false;

   #ifdef XRAUDIO_KWD_ENABLED
   uint8_t  active_chan                 = state->record.keyword_detector.active_chan;
   uint32_t pre_detection_samples_avail = xraudio_keyword_detector_session_pd_avail(&state->record.keyword_detector, active_chan);
   int32_t  kwd_begin                   = state->record.keyword_detector.result.endpoints.begin;
   int32_t  kwd_end                     = state->record.keyword_detector.result.endpoints.end;
   int32_t  offset                      = record->stream_begin_offset[0];

   xraudio_input_record_from_t stream_from = record->stream_from[0];
   XLOGD_DEBUG("<%s> active chan <%u> samples avail <%u> kwd begin <%d> end <%d> offset <%d>\n", xraudio_input_record_from_str(stream_from), active_chan, pre_detection_samples_avail, kwd_begin, kwd_end, offset);

   if(record->subsequent && XRAUDIO_DEVICE_INPUT_LOCAL_GET(instance->source) != XRAUDIO_DEVICE_INPUT_NONE) { // Use same input beam and dynamic gain from last stream
      instance->dynamic_gain_set = true;
      XLOGD_DEBUG("dynamic gain bit qty <%u> chan <%u>", instance->dynamic_gain_pcm_bit_qty, active_chan);
   }

   switch(stream_from) {
      case XRAUDIO_INPUT_RECORD_FROM_BEGINNING: {
         if(external_src) {
            instance->pre_detection_sample_qty = 0;
         } else {
            instance->pre_detection_sample_qty = pre_detection_samples_avail - offset;
         }
         break;
      }
      case XRAUDIO_INPUT_RECORD_FROM_LIVE: {
         instance->pre_detection_sample_qty = 0;
         break;
      }
      case XRAUDIO_INPUT_RECORD_FROM_KEYWORD_BEGIN: {
         // this is the start of streaming where the pre-detection sample qty is calculated
         // this is the qty of data that is read from circular buffer and the rest is streamed directly as it comes in

         instance->pre_detection_sample_qty = - kwd_begin - offset;
         XLOGD_DEBUG("pre_detection_sample_qty <%u>\n", instance->pre_detection_sample_qty);
         break;
      }
      case XRAUDIO_INPUT_RECORD_FROM_KEYWORD_END: {
         instance->pre_detection_sample_qty = 0 - offset;

         if(!state->record.keyword_detector.triggered) { // session was initiated without keyword detected
            state->record.keyword_detector.post_frame_count_callback = 0;
         }
         break;
      }
      default: {
         XLOGD_ERROR("invalid parameter <%s>", xraudio_input_record_from_str(stream_from));
         break;
      }
   }
   if(!external_src && stream_from != XRAUDIO_INPUT_RECORD_FROM_LIVE && state->record.keyword_detector.post_frame_count_callback) { // Compensate for audio frames that arrive between keyword detect callback and record start request
      uint32_t chan_sample_qty = state->record.frame_sample_qty / state->record.format_in.channel_qty;

      instance->pre_detection_sample_qty += state->record.keyword_detector.post_frame_count_callback * chan_sample_qty;
      XLOGD_DEBUG("stream request compensate frames <%u> samples <%u>", state->record.keyword_detector.post_frame_count_callback, state->record.keyword_detector.post_frame_count_callback * chan_sample_qty);
   }
   if(instance->pre_detection_sample_qty > pre_detection_samples_avail) {
      XLOGD_WARN("request out of range <%u> max <%u>", instance->pre_detection_sample_qty, pre_detection_samples_avail);
      instance->pre_detection_sample_qty = pre_detection_samples_avail;
   }

   #ifdef XRAUDIO_DGA_ENABLED
   XLOGD_INFO("record->kwd_peak_power_dBFS is %d", record->kwd_peak_power_dBFS);
   if(record->kwd_peak_power_dBFS != 0) {
      instance->dynamic_gain_set         = true;
      instance->hal_kwd_peak_power_dBFS  = record->kwd_peak_power_dBFS;
      instance->dynamic_gain_pcm_bit_qty = state->record.pcm_bit_qty;

      // calculate dynamic gain using use keyword peak power measurement from external detector
      int16_t hal_kwd_peak_power_aop_adjusted = instance->hal_kwd_peak_power_dBFS - (int16_t)(state->record.input_aop_adjust_dB);
      XLOGD_INFO("peak power aop adjusted <%d dBFS>, peak power <%d dBFS>, aop_adjust <%d dB>", hal_kwd_peak_power_aop_adjusted, instance->hal_kwd_peak_power_dBFS, (int16_t)state->record.input_aop_adjust_dB);
      float dynamic_gain;
      xraudio_dga_update(state->record.obj_dga, &instance->dynamic_gain_pcm_bit_qty, hal_kwd_peak_power_aop_adjusted, &dynamic_gain);
      dynamic_gain -= state->record.input_aop_adjust_dB;
      state->record.keyword_detector.result.channels[state->record.keyword_detector.active_chan].dynamic_gain = dynamic_gain;
      if(record->dynamic_gain_update != NULL) {
         *record->dynamic_gain_update = dynamic_gain;
      }
      XLOGD_DEBUG("pcm bit qty in <%u> out <%u>", state->record.pcm_bit_qty, instance->dynamic_gain_pcm_bit_qty);
   }
   #endif
   #endif

   if(record->source != XRAUDIO_DEVICE_INPUT_MIC_TAP) {
      xraudio_keyword_detector_session_disarm(&state->record.keyword_detector);
   }

   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(instance->source) == XRAUDIO_DEVICE_INPUT_SINGLE) {
      instance->format_out     = record->format_native;
   } else {
      instance->format_out     = record->format_decoded;
   }

   instance->latency_mode          = record->latency_mode;
   instance->cpu_util_mode         = record->cpu_util_mode;
   instance->mode_changed          = true;
   instance->keyword_flush         = false;
   #ifdef XRAUDIO_KWD_ENABLED
   instance->raw_mic_frame_skip    = 0;
   #endif
   
   if(external_src) {
      state->record.external_frame_group_qty   = record->frame_group_qty;
      state->record.external_data_len          = 0;
      state->record.external_frame_bytes_read  = 0;
      state->record.external_frame_group_index = 0;
   } else {
      // Set timeout for next chunk (in microseconds)
      state->record.timeout           = XRAUDIO_INPUT_FRAME_PERIOD * 1000;
      instance->frame_size_out        = (XRAUDIO_INPUT_FRAME_PERIOD * instance->format_out.sample_rate * instance->format_out.channel_qty * instance->format_out.sample_size) / 1000;
      state->record.frame_sample_qty  = (XRAUDIO_INPUT_FRAME_PERIOD * state->record.format_in.sample_rate * state->record.format_in.channel_qty) / 1000;
      state->record.frame_group_index = 0;
   }

   bool decoding = false;

   if(external_src) {
      xraudio_encoding_type_t encoding_in  = state->record.external_format.encoding.type;
      xraudio_encoding_type_t encoding_out = instance->format_out.encoding.type;
      xraudio_adpcm_frame_t *adpcm_frame   = &state->record.external_format.encoding.value.adpcm_frame;
      uint32_t frame_duration;
      if (encoding_in == XRAUDIO_ENCODING_ADPCM_FRAME) {
         frame_duration = 1000 * 1000 * 2 * (adpcm_frame->size_packet - adpcm_frame->size_header) / state->record.external_format.sample_rate;
      } else {
         frame_duration = 20000;
      }
      if(encoding_in == encoding_out) {
         xraudio_encoding_parameters_get(&state->record.external_format, frame_duration, &state->record.external_frame_size_in, record->stream_time_minimum, &instance->stream_time_min_value);
         state->record.external_frame_size_out = state->record.external_frame_size_in;
         XLOGD_INFO("native format <%s> frame size <%u>", xraudio_encoding_str(encoding_in), state->record.external_frame_size_in);
      } else if(encoding_in == XRAUDIO_ENCODING_ADPCM_FRAME && encoding_out == XRAUDIO_ENCODING_PCM) {
         state->record.external_frame_size_in = adpcm_frame->size_packet;
         xraudio_encoding_parameters_get(&instance->format_out, frame_duration, &state->record.external_frame_size_out, record->stream_time_minimum, &instance->stream_time_min_value);
         XLOGD_INFO("decoding <%s> to <%s> frame size in <%u> out <%u>", xraudio_encoding_str(encoding_in), xraudio_encoding_str(encoding_out), state->record.external_frame_size_in, state->record.external_frame_size_out);
         decoding = true;
      } else if(encoding_in == XRAUDIO_ENCODING_ADPCM_FRAME && encoding_out == XRAUDIO_ENCODING_ADPCM) {
         state->record.external_frame_size_in = adpcm_frame->size_packet;
         xraudio_encoding_parameters_get(&instance->format_out, frame_duration, &state->record.external_frame_size_out, record->stream_time_minimum, &instance->stream_time_min_value);
         XLOGD_INFO("decoding <%s> to <%s> frame size in <%u> out <%u>", xraudio_encoding_str(encoding_in), xraudio_encoding_str(encoding_out), state->record.external_frame_size_in, state->record.external_frame_size_out);
         decoding = true;
      } else if(encoding_in == XRAUDIO_ENCODING_OPUS_XVP && encoding_out == XRAUDIO_ENCODING_PCM) {
         xraudio_encoding_parameters_get(&instance->format_out, frame_duration, &state->record.external_frame_size_out, record->stream_time_minimum, &instance->stream_time_min_value);
         XLOGD_INFO("decoding <%s> to <%s> frame size in <%u> out <%u>", xraudio_encoding_str(encoding_in), xraudio_encoding_str(encoding_out), state->record.external_frame_size_in, state->record.external_frame_size_out);
         decoding = true;
      } else if(encoding_in == XRAUDIO_ENCODING_OPUS_XVP && encoding_out == XRAUDIO_ENCODING_OPUS) {
         xraudio_encoding_parameters_get(&instance->format_out, frame_duration, &state->record.external_frame_size_out, record->stream_time_minimum, &instance->stream_time_min_value);
         XLOGD_INFO("decoding <%s> to <%s> frame size in <%u> out <%u>", xraudio_encoding_str(encoding_in), xraudio_encoding_str(encoding_out), state->record.external_frame_size_in, state->record.external_frame_size_out);
         decoding = true;
      } else if(encoding_in == XRAUDIO_ENCODING_OPUS && encoding_out == XRAUDIO_ENCODING_PCM) {
         xraudio_encoding_parameters_get(&instance->format_out, frame_duration, &state->record.external_frame_size_out, record->stream_time_minimum, &instance->stream_time_min_value);
         XLOGD_INFO("decoding <%s> to <%s> frame size in <%u> out <%u>", xraudio_encoding_str(encoding_in), xraudio_encoding_str(encoding_out), state->record.external_frame_size_in, state->record.external_frame_size_out);
         decoding = true;
      } else {
         xraudio_encoding_parameters_get(&state->record.external_format, frame_duration, &state->record.external_frame_size_in, record->stream_time_minimum, &instance->stream_time_min_value);
         state->record.external_frame_size_out = state->record.external_frame_size_in;
         XLOGD_ERROR("xraudio does not support this conversion <%s> to <%s>. output is native format <%s> frame size <%u>.", xraudio_encoding_str(encoding_in), xraudio_encoding_str(encoding_out), xraudio_encoding_str(encoding_in), state->record.external_frame_size_in);
      }

      if(record->stream_keyword_duration != 0) { // Keyword is present in the stream
         instance->keyword_triggered  = true;

         if(encoding_out != XRAUDIO_ENCODING_PCM) {
            XLOGD_ERROR("xraudio doesn't handle keyword endpoint for encoded output formats.");
            instance->keyword_end_samples = 0;
         } else {
            instance->keyword_end_samples = record->stream_keyword_begin + record->stream_keyword_duration;
         }
      } else {
         instance->keyword_triggered   = false;
         instance->keyword_end_samples = 0;
      }
   } else {
      // Reset local mic stats
      instance->stats.packets_processed    = 0;
      instance->stats.packets_lost         = 0;
      instance->stats.samples_processed    = 0;
      instance->stats.samples_lost         = 0;
      instance->stats.decoder_failures     = 0;
      instance->stats.samples_buffered_max = 0;

      instance->stream_time_min_value = record->stream_time_minimum * state->record.format_in.sample_rate / 1000;
      instance->keyword_end_samples   = (record->stream_keyword_duration != 0) ? record->stream_keyword_begin + record->stream_keyword_duration : 0;
      instance->keyword_triggered     = (record->stream_keyword_duration != 0) ? true : false;

      #ifdef XRAUDIO_KWD_ENABLED
      if(record->stream_until[0] == XRAUDIO_INPUT_RECORD_UNTIL_END_OF_SPEECH && instance->use_hal_eos) {
         if(!xraudio_hal_input_eos_cmd(state->params.hal_input_obj, XRAUDIO_EOS_CMD_SESSION_BEGIN, state->record.keyword_detector.active_chan)) {
            XLOGD_ERROR("unable to begin hal eos session");
         } else {
            instance->eos_hal_cmd_pending = true;
         }
      }
      #endif

      if(instance->format_out.encoding.type != XRAUDIO_ENCODING_PCM_RAW && instance->latency_mode != XRAUDIO_STREAM_LATENCY_NORMAL && state->record.latency_mode != instance->latency_mode) {
         #ifdef XRAUDIO_KWD_ENABLED
         if(!xraudio_hal_input_stream_latency_set(state->params.hal_input_obj, instance->latency_mode)) {
            XLOGD_ERROR("unable to set hal input latency mode <%s>", xraudio_stream_latency_mode_str(instance->latency_mode));
         }
         #endif
         state->record.latency_mode = instance->latency_mode;
      }
      if(instance->cpu_util_mode != XRAUDIO_STREAM_CPU_UTIL_NORMAL && state->record.cpu_util_mode != instance->cpu_util_mode) {
         xraudio_cpu_util_mode_enter(state, instance);
      }

      #ifdef XRAUDIO_KWD_ENABLED
      if(instance->format_out.encoding.type == XRAUDIO_ENCODING_PCM_RAW) { // Set raw mic mode
         instance->raw_mic_enable = true;
         if(xraudio_hal_input_test_mode(state->params.hal_input_obj, true)) {
            XLOGD_INFO("hal input set to raw mic test mode");
            state->record.raw_mic_enable = true;
         } else {
            XLOGD_ERROR("unable to set hal input to raw mic test mode");
         }
         // Need to wait until non-raw audio frames have been read by xraudio before servicing the record request
         instance->raw_mic_frame_skip = 3;

         // Dump pre detection samples since all audio needs to come after test mode is enabled
         instance->pre_detection_sample_qty = 0;
      } else if(instance->format_out.encoding.type == XRAUDIO_ENCODING_PCM && instance->format_out.sample_size > 2) {
         // Dump pre detection samples for 32-bit PCM since they are not available until circular buffer is converted from float to int32_t (no use case for this yet)
         instance->pre_detection_sample_qty = 0;
      }
      #endif
   }

   XLOGD_DEBUG("internal capture <%s>", (state->record.capture_internal.enabled ? "enabled" : "disabled"));
   if(state->record.capture_internal.enabled) {// Start internal capture
      // Capture input format
      if(external_src) {
         xraudio_in_capture_internal_input_begin(&state->record.external_format, decoding ? &instance->format_out : NULL, &state->record.capture_internal, &instance->capture_internal, record->identifier);
      } else {
         xraudio_in_capture_internal_input_begin(&instance->format_out, NULL, &state->record.capture_internal, &instance->capture_internal, record->identifier);
      }
   }
   if(instance->fifo_audio_data[0] >= 0){ // Stream to pipe
      instance->record_callback = xraudio_in_write_to_pipe;
   } else if(instance->fd >= 0) { // Record to file
      instance->record_callback = xraudio_in_write_to_file;
   } else if(instance->audio_buf_samples != NULL && instance->audio_buf_sample_qty > 0) { // Record to memory
      instance->record_callback = xraudio_in_write_to_memory;
   } else if(instance->data_callback != NULL){ // Stream to user
      instance->record_callback = xraudio_in_write_to_user;
   }

   #ifdef XRAUDIO_DECODE_ADPCM
   if(!adpcm_decode_reset(state->decoders.adpcm)) {
      XLOGD_ERROR("unable to reset adpcm decoder state");
   }
   #endif
   #ifdef XRAUDIO_DECODE_OPUS
   if(state->decoders.opus != NULL) {
      if(!xraudio_opus_reset(state->decoders.opus)) {
         XLOGD_ERROR("unable to reset opus decoder state");
      }
   }
   #endif

   XLOGD_DEBUG("nominal timeout %u us", state->record.timeout);
}

void xraudio_msg_record_stop(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_record_stop_t *stop = (xraudio_queue_msg_record_stop_t *)msg;
   XLOGD_DEBUG("");

   bool more_streams = false;

   xraudio_session_record_inst_t *instance = xraudio_in_source_to_inst(&state->record, stop->source);

   if(stop->index >= 0 && stop->index < XRAUDIO_FIFO_QTY_MAX) {
      if(instance->fifo_audio_data[stop->index] >= 0) {
         close(instance->fifo_audio_data[stop->index]);
         instance->fifo_audio_data[stop->index] = -1;
      }
      for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
         if(instance->fifo_audio_data[index] >= 0) {
            more_streams = true;
            break;
         }
      }
   }

   if(!more_streams) {
      // Flush any partial data
      xraudio_in_flush(stop->source, &state->params, &state->record, instance);

      if(instance->fd >= 0) { // Record to file
         xraudio_record_container_process_end(instance->fd, instance->format_out, instance->audio_buf_index, false);
      }
      instance->fd                        = -1;
      instance->audio_buf_samples         = NULL;
      instance->audio_buf_sample_qty      = 0;
      instance->data_callback             = NULL;

      for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
         instance->fifo_audio_data[index] = -1;
      }


      instance->callback                  = NULL;
      instance->param                     = NULL;

      if(instance->capture_internal.active) {
         xraudio_in_capture_internal_end(&instance->capture_internal);
      }

      #ifdef XRAUDIO_KWD_ENABLED
      if(instance->raw_mic_enable) { // Clear raw mic mode
         instance->raw_mic_enable = false;

         if(state->record.raw_mic_enable) {
            if(xraudio_hal_input_test_mode(state->params.hal_input_obj, false)) {
               XLOGD_INFO("hal input restored to normal test mode");
            } else {
               XLOGD_ERROR("unable to restore hal input to normal test mode");
            }
            state->record.raw_mic_enable = false;
         }
      }
      #endif
      if(instance->latency_mode != XRAUDIO_STREAM_LATENCY_NORMAL && state->record.latency_mode != XRAUDIO_STREAM_LATENCY_NORMAL) {
         #ifdef XRAUDIO_KWD_ENABLED
         if(xraudio_hal_input_stream_latency_set(state->params.hal_input_obj, XRAUDIO_STREAM_LATENCY_NORMAL)) {
            XLOGD_INFO("hal input restored to normal latency mode");
         } else {
            XLOGD_ERROR("unable to restore hal input to normal latency mode");
         }
         #endif
         state->record.latency_mode = XRAUDIO_STREAM_LATENCY_NORMAL;
      }
      if(instance->cpu_util_mode != XRAUDIO_STREAM_CPU_UTIL_NORMAL && state->record.cpu_util_mode != XRAUDIO_STREAM_CPU_UTIL_NORMAL) {
         // Return to normal cpu utilization mode
         xraudio_cpu_util_mode_exit(&state->record);

         XLOGD_INFO("restored cpu util mode <%s>", xraudio_stream_cpu_util_mode_str(state->record.cpu_util_mode));
      }
   }

   if(stop->synchronous) {
      if(stop->semaphore == NULL) {
         XLOGD_ERROR("synchronous stop with no semaphore set!");
      } else {
         sem_post(stop->semaphore);
      }
   } else if(stop->callback != NULL){
      (*stop->callback)(stop->source, AUDIO_IN_CALLBACK_EVENT_OK, NULL, stop->param);
   }

   if(!more_streams) {
      #ifdef XRAUDIO_KWD_ENABLED
      if(instance->eos_hal_cmd_pending) { // an EOS command is pending with the HAL, so terminate the EOS session
         if(!xraudio_hal_input_eos_cmd(state->params.hal_input_obj, XRAUDIO_EOS_CMD_SESSION_TERMINATE, state->record.keyword_detector.active_chan)) {
            XLOGD_ERROR("unable to terminate hal eos session");
         }
         instance->eos_hal_cmd_pending = false;
      }
      #endif

      instance->source          = XRAUDIO_DEVICE_INPUT_NONE;
      instance->record_callback = NULL;

      if(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(stop->source) != XRAUDIO_DEVICE_INPUT_NONE) {
         state->record.external_fd        = -1;
         state->record.external_callback  = NULL;
         state->record.external_user_data = NULL;

         memset(&state->record.external_format, 0, sizeof(state->record.external_format));
      }

      xraudio_in_session_group_semaphore_unlock(state, stop->source);
   }
}

void xraudio_msg_capture_start(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_capture_start_t *capture = (xraudio_queue_msg_capture_start_t *)msg;
   char filename[128];
   XLOGD_DEBUG("");
   state->record.capture_session.active          = true;
   state->record.capture_session.type            = capture->capture_type;
   state->record.capture_session.callback        = capture->callback;
   state->record.capture_session.param           = capture->param;
   state->record.capture_session.container       = capture->container;
   snprintf(state->record.capture_session.audio_file_path, sizeof(state->record.capture_session.audio_file_path), "%s", capture->audio_file_path);
   state->record.capture_session.raw_mic_enable  = capture->raw_mic_enable;

   // Set fd to NULL in case they weren't closed
   for(uint8_t chan = 0; chan < XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY; chan++) {
      if(state->record.capture_session.input[chan].file.fd >= 0) {
         close(state->record.capture_session.input[chan].file.fd);
         state->record.capture_session.input[chan].file.fd = -1;
      }

      if(chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
         if(state->record.capture_session.kwd[chan].file.fd >= 0) {
            close(state->record.capture_session.kwd[chan].file.fd);
            state->record.capture_session.kwd[chan].file.fd = -1;
         }
         if(state->record.capture_session.eos[chan].file.fd >= 0) {
            close(state->record.capture_session.eos[chan].file.fd);
            state->record.capture_session.eos[chan].file.fd = -1;
         }
      }
   }
   for(uint8_t index = 0; index < XRAUDIO_INPUT_SESSION_GROUP_QTY; index++) {
      if(state->record.capture_session.output[index].file.fd >= 0) {
         close(state->record.capture_session.output[index].file.fd);
         state->record.capture_session.output[index].file.fd = -1;
      }
   }

   uint8_t chan_qty = (capture->capture_type & XRAUDIO_CAPTURE_INPUT_ALL) ? XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY : 1;

   const char *extension = (capture->container == XRAUDIO_CONTAINER_WAV) ? CAPTURE_INTERNAL_EXT_WAV : CAPTURE_INTERNAL_EXT_PCM;
   xraudio_capture_file_t *capture_file = NULL;
   xraudio_pcm_range_t    *pcm_range    = NULL;

   xraudio_input_format_t format_16k_16bit_mono;
   format_16k_16bit_mono.container     = capture->container;
   format_16k_16bit_mono.encoding.type = XRAUDIO_ENCODING_PCM;
   format_16k_16bit_mono.sample_rate   = 16000;
   format_16k_16bit_mono.sample_size   = 2;
   format_16k_16bit_mono.channel_qty   = 1;

   for(uint8_t chan = 0; chan < chan_qty; chan++) {
      capture_file = &state->record.capture_session.input[chan].file;
      pcm_range    = &state->record.capture_session.input[chan].pcm_range;

      capture_file->audio_data_size = 0;

      pcm_range->max = PCM_32_BIT_MIN;
      pcm_range->min = PCM_32_BIT_MAX;

      snprintf(filename, sizeof(filename), "%s%s%u%s", capture->audio_file_path, "_input_", chan, extension);

      errno = 0;
      capture_file->fd = open(filename, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
      if(capture_file->fd < 0) {
         int errsv = errno;
         XLOGD_ERROR("Unable to open file <%s> <%s>", filename, strerror(errsv));
      } else if(capture->container == XRAUDIO_CONTAINER_WAV) { // Write space for the wave header (need to know pcm data size so generate at the end of recording)
         uint8_t header[WAVE_HEADER_SIZE_MIN];
         memset(header, 0, WAVE_HEADER_SIZE_MIN);

         errno = 0;
         ssize_t bytes_written = write(capture_file->fd, header, sizeof(header));
         if(bytes_written != sizeof(header)) {
            int errsv = errno;
            XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
         }
      }

      capture_file->format.container   = capture->container;
      capture_file->format.encoding    = state->record.format_in.encoding;
      capture_file->format.sample_rate = state->record.format_in.sample_rate;
      capture_file->format.sample_size = (state->record.pcm_bit_qty > 16) ? 4 : 2;
      capture_file->format.channel_qty = 1;

      if((capture->capture_type & XRAUDIO_CAPTURE_KWD) && (chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY)) {
         capture_file = &state->record.capture_session.kwd[chan].file;
         pcm_range    = &state->record.capture_session.kwd[chan].pcm_range;

         capture_file->audio_data_size = 0;

         pcm_range->max = PCM_32_BIT_MIN;
         pcm_range->min = PCM_32_BIT_MAX;

         snprintf(filename, sizeof(filename), "%s%s%u%s", capture->audio_file_path, "_kwd_", chan, extension);

         errno = 0;
         capture_file->fd = open(filename, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
         if(capture_file->fd < 0) {
            int errsv = errno;
            XLOGD_ERROR("Unable to open file <%s> <%s>", filename, strerror(errsv));
         } else if(capture->container == XRAUDIO_CONTAINER_WAV) { // Write space for the wave header (need to know pcm data size so generate at the end of recording)
            uint8_t header[WAVE_HEADER_SIZE_MIN];
            memset(header, 0, WAVE_HEADER_SIZE_MIN);

            errno = 0;
            ssize_t bytes_written = write(capture_file->fd, header, sizeof(header));
            if(bytes_written != sizeof(header)) {
               int errsv = errno;
               XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
            }
         }

         capture_file->format = format_16k_16bit_mono;
      }
      if((capture->capture_type & XRAUDIO_CAPTURE_EOS) && (chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY)) {
         capture_file = &state->record.capture_session.eos[chan].file;
         pcm_range    = &state->record.capture_session.eos[chan].pcm_range;

         capture_file->audio_data_size = 0;

         pcm_range->max = PCM_32_BIT_MIN;
         pcm_range->min = PCM_32_BIT_MAX;

         snprintf(filename, sizeof(filename), "%s%s%u%s", capture->audio_file_path, "_eos_", chan, extension);

         errno = 0;
         capture_file->fd = open(filename, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
         if(capture_file->fd < 0) {
            int errsv = errno;
            XLOGD_ERROR("Unable to open file <%s> <%s>", filename, strerror(errsv));
         } else if(capture->container == XRAUDIO_CONTAINER_WAV) { // Write space for the wave header (need to know pcm data size so generate at the end of recording)
            uint8_t header[WAVE_HEADER_SIZE_MIN];
            memset(header, 0, WAVE_HEADER_SIZE_MIN);

            errno = 0;
            ssize_t bytes_written = write(capture_file->fd, header, sizeof(header));
            if(bytes_written != sizeof(header)) {
               int errsv = errno;
               XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
            }
         }

         capture_file->format = format_16k_16bit_mono;
      }
   }

   for(uint8_t index = 0; index < XRAUDIO_INPUT_SESSION_GROUP_QTY; index++) {
      xraudio_session_record_inst_t *instance = xraudio_in_source_to_inst(&state->record, state->record.instances[index].source);
      if(capture->capture_type & XRAUDIO_CAPTURE_OUTPUT) {
         capture_file = &state->record.capture_session.output[index].file;
         pcm_range    = &state->record.capture_session.output[index].pcm_range;

         capture_file->audio_data_size = 0;

         pcm_range->max = PCM_32_BIT_MIN;
         pcm_range->min = PCM_32_BIT_MAX;

         snprintf(filename, sizeof(filename), "%s%s%u%s", capture->audio_file_path, "_output_", index, extension);

         errno = 0;
         capture_file->fd = open(filename, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
         if(capture_file->fd < 0) {
            int errsv = errno;
            XLOGD_ERROR("Unable to open file <%s> <%s>", filename, strerror(errsv));
         } else if(capture->container == XRAUDIO_CONTAINER_WAV) { // Write space for the wave header (need to know pcm data size so generate at the end of recording)
            uint8_t header[WAVE_HEADER_SIZE_MIN];
            memset(header, 0, WAVE_HEADER_SIZE_MIN);

            errno = 0;
            ssize_t bytes_written = write(capture_file->fd, header, sizeof(header));
            if(bytes_written != sizeof(header)) {
               int errsv = errno;
               XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
            }
         }

         if(instance->source != XRAUDIO_DEVICE_INPUT_NONE) {
            capture_file->format.container     = capture->container;
            capture_file->format.encoding.type = XRAUDIO_ENCODING_PCM;
            capture_file->format.sample_rate   = 16000;
            capture_file->format.sample_size   = instance->format_out.sample_size;
            capture_file->format.channel_qty   = instance->format_out.channel_qty;
         } else {
            capture_file->format = format_16k_16bit_mono;
         }
      }
   }

   #ifdef XRAUDIO_KWD_ENABLED
   if(state->record.capture_session.raw_mic_enable) {
      if(xraudio_hal_input_test_mode(state->params.hal_input_obj, true)) {
         XLOGD_INFO("hal input set to raw mic test mode");
      } else {
         XLOGD_ERROR("unable to set hal input to raw mic test mode");
         state->record.capture_session.raw_mic_enable = false;
      }
   }
   #endif

   if(capture->semaphore == NULL) {
      XLOGD_ERROR("synchronous start with no semaphore set!");
   } else {
      sem_post(capture->semaphore);
   }
}

void xraudio_msg_capture_stop(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_capture_stop_t *stop = (xraudio_queue_msg_capture_stop_t *)msg;
   XLOGD_DEBUG("");

   uint8_t chan_qty = (state->record.capture_session.type & XRAUDIO_CAPTURE_INPUT_ALL) ? XRAUDIO_INPUT_SUPERFRAME_MAX_CHANNEL_QTY: 1;

   for(uint8_t chan = 0; chan < chan_qty; chan++) {
      xraudio_capture_point_t *input = &state->record.capture_session.input[chan];

      if(input->file.fd >= 0) {
         xraudio_record_container_process_end(input->file.fd, input->file.format, input->file.audio_data_size, false);
         close(input->file.fd);
         input->file.fd = -1;
      }

      if(chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY) {
         xraudio_capture_point_t *kwd   = &state->record.capture_session.kwd[chan];
         xraudio_capture_point_t *eos   = &state->record.capture_session.eos[chan];
         if(kwd->file.fd >= 0) {
            xraudio_record_container_process_end(kwd->file.fd, kwd->file.format, kwd->file.audio_data_size, false);
            close(kwd->file.fd);
            kwd->file.fd = -1;
         }

         if(eos->file.fd >= 0) {
            xraudio_record_container_process_end(eos->file.fd, eos->file.format, eos->file.audio_data_size, false);
            close(eos->file.fd);
            eos->file.fd = -1;
         }
         XLOGD_INFO("chan %u: input <%d to %d> kwd <%d to %d> eos <%d to %d>", chan, input->pcm_range.min, input->pcm_range.max, kwd->pcm_range.min, kwd->pcm_range.max, eos->pcm_range.min, eos->pcm_range.max);
      } else {
         XLOGD_INFO("chan %u: input <%d to %d>", chan, input->pcm_range.min, input->pcm_range.max);
      }
   }

   for(uint8_t index = 0; index < XRAUDIO_INPUT_SESSION_GROUP_QTY; index++) {
      xraudio_session_record_inst_t *instance = xraudio_in_source_to_inst(&state->record, state->record.instances[index].source);
      xraudio_capture_point_t *output = &state->record.capture_session.output[index];
      if(output->file.fd >= 0) {
         xraudio_record_container_process_end(output->file.fd, output->file.format, output->file.audio_data_size, false);
         close(output->file.fd);
         output->file.fd = -1;
      }
      XLOGD_INFO("group %u: stream output: pcm range <%d to %d>", xraudio_input_source_to_group(instance->source), output->pcm_range.min, output->pcm_range.max);
   }

   state->record.capture_session.active          = false;
   state->record.capture_session.type            = XRAUDIO_CAPTURE_INPUT_MONO;
   state->record.capture_session.callback        = NULL;
   state->record.capture_session.param           = NULL;

   #ifdef XRAUDIO_KWD_ENABLED
   if(state->record.capture_session.raw_mic_enable) {
      if(xraudio_hal_input_test_mode(state->params.hal_input_obj, false)) {
         XLOGD_INFO("hal input restored to normal test mode");
      } else {
         XLOGD_ERROR("unable to restore hal input to normal test mode");
      }
      state->record.capture_session.raw_mic_enable = false;
   }
   #endif

   if(stop->semaphore == NULL) {
      XLOGD_ERROR("synchronous stop with no semaphore set!");
   } else {
      sem_post(stop->semaphore);
   }
}

#ifdef XRAUDIO_OUTPUT_ENABLED
void xraudio_msg_play_idle(xraudio_thread_state_t *state, void *msg) {
   XLOGD_DEBUG("");
   state->playback.synchronous          = false;
   state->playback.callback             = NULL;
   state->playback.param                = NULL;
   state->playback.semaphore            = NULL;
   state->playback.fd                   = -1;
   state->playback.audio_buf            = NULL;
   state->playback.audio_buf_size       = 0;
   state->playback.audio_buf_index      = 0;
   state->playback.data_callback        = NULL;
   state->playback.pipe_audio_data      = -1;
   state->playback.fifo_sound_intensity = -1;
   state->playback.timeout              = XRAUDIO_OUTPUT_FRAME_PERIOD * 1000;
   state->playback.frame_size           = (XRAUDIO_OUTPUT_FRAME_PERIOD * state->playback.format.sample_rate * state->playback.format.sample_size * state->playback.format.channel_qty) / 1000;

   // Send first chunk (2x chunk period) to the speaker
   unsigned long first_frame_size = 2 * state->playback.frame_size;

   if(state->playback.playing) { // Only changing back to idle so don't write first data frame
      return;
   }

   unsigned long timeout_val = 0;
   xraudio_process_spkr_data(&state->params, &state->playback, first_frame_size, &timeout_val, NULL);

   // Update the timeout
   rdkx_timestamp_t timeout;
   rdkx_timestamp_get(&timeout);
   rdkx_timestamp_add_us(&timeout, timeout_val);

   if(state->timer_id_frame == RDXK_TIMER_ID_INVALID) {
      state->timer_id_frame = rdkx_timer_insert(state->timer_obj, timeout, timer_frame_process, state);
   } else {
      rdkx_timer_update(state->timer_obj, state->timer_id_frame, timeout);
   }
}

void xraudio_msg_play_start(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_play_start_t *play = (xraudio_queue_msg_play_start_t *)msg;
   XLOGD_DEBUG("<%s> intensity <%s> wave <%s,%u-bit,%u Hz>", (play->callback == NULL) ? "SYNC" : "ASYNC", play->fifo_sound_intensity >= 0 ? "YES" : "NO",
         xraudio_channel_qty_str(play->format.channel_qty), play->format.sample_size * 8, play->format.sample_rate);

   state->playback.hal_output_obj         = play->hal_output_obj;
   state->playback.synchronous          = (play->callback == NULL) ? true : false;
   state->playback.callback             = play->callback;
   state->playback.param                = play->param;
   state->playback.semaphore            = play->semaphore;
   state->playback.fd                   = play->fd;
   state->playback.audio_buf            = play->audio_buf;
   state->playback.audio_buf_size       = play->audio_buf_size;
   state->playback.audio_buf_index      = 0;
   state->playback.data_callback        = play->data_callback;
   state->playback.pipe_audio_data      = play->pipe;
   state->playback.fifo_sound_intensity = play->fifo_sound_intensity;

   // Set timeout for next chunk (x ms of audio data for y Hz LED refresh rate)
   state->playback.timeout      = XRAUDIO_OUTPUT_FRAME_PERIOD * 1000;
   state->playback.frame_size   = (XRAUDIO_OUTPUT_FRAME_PERIOD * play->format.channel_qty * play->format.sample_size * play->format.sample_rate) / 1000;

   state->playback.mode_changed         = true;
   #ifdef MASK_FIRST_WRITE_DELAY
   state->playback.first_write_complete = false;
   #endif

   XLOGD_DEBUG("nominal timeout %u us frame size %u bytes hal buffer size %u", state->playback.timeout, state->playback.frame_size, xraudio_hal_output_buffer_size_get(state->playback.hal_output_obj));

   // Send first chunk (2x chunk period) to the speaker
   unsigned long first_frame_size = 2 * state->playback.frame_size;

   unsigned long timeout_val = 0;
   #ifdef MASK_FIRST_READ_DELAY
   if(state->params.obj_input != NULL && (state->record.recording || !state->record.first_read_complete)) {
   #else
   if(state->params.obj_input != NULL && state->record.recording) {
   #endif
      xraudio_process_spkr_data(&state->params, &state->playback, first_frame_size, &timeout_val, &state->record.timestamp_next);
   } else {
      xraudio_process_spkr_data(&state->params, &state->playback, first_frame_size, &timeout_val, NULL);
   }

   // Update the timeout
   rdkx_timestamp_t timeout;
   rdkx_timestamp_get(&timeout);
   rdkx_timestamp_add_us(&timeout, timeout_val);

   if(state->timer_id_frame == RDXK_TIMER_ID_INVALID) {
      state->timer_id_frame = rdkx_timer_insert(state->timer_obj, timeout, timer_frame_process, state);
   } else {
      rdkx_timer_update(state->timer_obj, state->timer_id_frame, timeout);
   }
}

void xraudio_msg_play_pause(xraudio_thread_state_t *state, void *msg) {
   //xraudio_queue_msg_play_pause_t *pause = (xraudio_queue_msg_play_pause_t *)msg;
   XLOGD_DEBUG("");
}

void xraudio_msg_play_resume(xraudio_thread_state_t *state, void *msg) {
   //xraudio_queue_msg_play_resume_t *resume = (xraudio_queue_msg_play_resume_t *)msg;
   XLOGD_DEBUG("");
}

void xraudio_msg_play_stop(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_play_stop_t *stop = (xraudio_queue_msg_play_stop_t *)msg;
   XLOGD_DEBUG("");

   state->playback.hal_output_obj     = NULL;
   state->playback.fd                 = -1;
   state->playback.audio_buf          = NULL;
   state->playback.audio_buf_size     = 0;
   state->playback.data_callback      = NULL;
   state->playback.callback           = NULL;
   state->playback.param              = NULL;


   if(state->playback.pipe_audio_data >= 0) { // Close the read side of the pipe
      close(state->playback.pipe_audio_data);
      state->playback.pipe_audio_data = -1;
   }

   if(stop->synchronous) {
      if(stop->semaphore == NULL) {
         XLOGD_ERROR("synchronous stop with no semaphore set!");
      } else {
         sem_post(stop->semaphore);
      }
   } else if(stop->callback != NULL){
      (*stop->callback)(AUDIO_OUT_CALLBACK_EVENT_OK, stop->param);
   }
}
#else
void xraudio_msg_dummy(xraudio_thread_state_t *state, void *msg) {
   return;
}
#endif

void xraudio_msg_detect(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_detect_t *detect = (xraudio_queue_msg_detect_t *)msg;
   XLOGD_DEBUG("");

   xraudio_session_record_inst_t *instance = &state->record.instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   instance->frame_size_out        = 0;
   instance->frame_group_qty       = XRAUDIO_INPUT_DEFAULT_FRAME_GROUP_QTY;
   instance->record_callback       = NULL;
   instance->stream_until[0]       = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
   instance->fifo_audio_data[0]    = -1;
   instance->fd                    = -1;
   instance->audio_buf_samples     = NULL;
   instance->audio_buf_sample_qty  = 0;
   instance->data_callback         = NULL;
   instance->synchronous           = false;
   instance->callback              = NULL;
   instance->param                 = NULL;
   #ifdef XRAUDIO_DGA_ENABLED
   instance->dynamic_gain_set      = false;
   #endif
   instance->fifo_sound_intensity  = -1;

   instance->eos_event                    = XRAUDIO_EOS_EVENT_NONE;
   instance->eos_vad_forced               = false;
   instance->eos_end_of_wake_word_samples = 0;

   #ifdef XRAUDIO_KWD_ENABLED
   // Initialize the session upon receipt of first detect request which contains the sensitivity needed to start the session
   if(!xraudio_keyword_detector_session_is_active(&state->record.keyword_detector)) {
      xraudio_keyword_detector_session_init(&state->record.keyword_detector, detect->chan_qty, detect->sensitivity);
   }
   #endif

   #ifdef XRAUDIO_KWD_ENABLED
   if(state->params.hal_input_obj != NULL) {
      if(!xraudio_hal_input_keyword_detector_reset(state->params.hal_input_obj)) {
         XLOGD_ERROR("unable to reset HAL keyword detector");
         //Allow internal detector to run
     }
   }
   #endif
   xraudio_keyword_detector_session_arm(&state->record.keyword_detector, detect->callback, detect->param, detect->sensitivity);

   // Set timeout for next chunk (in microseconds)
   state->record.timeout           = XRAUDIO_INPUT_FRAME_PERIOD * 1000;
   state->record.frame_sample_qty  = (XRAUDIO_INPUT_FRAME_PERIOD * state->record.format_in.sample_rate * state->record.format_in.channel_qty) / 1000;
   state->record.frame_group_index = 0;

   xraudio_input_sound_focus_set(state->params.obj_input, XRAUDIO_SDF_MODE_KEYWORD_DETECTION);

   if(detect->semaphore != NULL) {
      sem_post(detect->semaphore);
   }
}

void xraudio_msg_detect_params(xraudio_thread_state_t *state, void *msg) {
   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_queue_msg_detect_params_t *detect_params = (xraudio_queue_msg_detect_params_t *)msg;
   XLOGD_DEBUG("");

   xraudio_keyword_detector_t *detector = &state->record.keyword_detector;
   if(xraudio_keyword_detector_session_is_armed(detector) && (detector->sensitivity != detect_params->sensitivity)) {
      xraudio_keyword_detector_session_arm(detector, detector->callback, detector->cb_param, detect_params->sensitivity);
   }
   #endif
}

void xraudio_msg_detect_sensitivity_limits_get(xraudio_thread_state_t *state, void *msg) {
   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_main_queue_msg_detect_sensitivity_limits_get_t *detect_sensitivity_limits_get = (xraudio_main_queue_msg_detect_sensitivity_limits_get_t *)msg;
   XLOGD_DEBUG("");

   xraudio_result_t result = XRAUDIO_RESULT_OK;

   xraudio_keyword_detector_t *detector = &state->record.keyword_detector;
   if(!xraudio_kwd_sensitivity_limits_get(detector->kwd_object, detect_sensitivity_limits_get->min, detect_sensitivity_limits_get->max)) {
      result = XRAUDIO_RESULT_ERROR_INTERNAL;
   }

   if(detect_sensitivity_limits_get->semaphore != NULL) {
      if(detect_sensitivity_limits_get->result != NULL) {
         *(detect_sensitivity_limits_get->result) = result;
      }
      sem_post(detect_sensitivity_limits_get->semaphore);
   }
   #endif
}

void xraudio_msg_detect_stop(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_detect_stop_t *detect_stop = (xraudio_queue_msg_detect_stop_t *)msg;
   XLOGD_DEBUG("");

   xraudio_keyword_detector_t *detector = &state->record.keyword_detector;

   if(!xraudio_keyword_detector_session_is_armed(detector)) {
      XLOGD_WARN("detector is not armed");
   } else {
      xraudio_keyword_detector_session_disarm(detector);
   }
   if(detect_stop->synchronous) {
      if(detect_stop->semaphore == NULL) {
         XLOGD_ERROR("synchronous stop with no semaphore set!");
      } else {
         sem_post(detect_stop->semaphore);
      }
   }
}

#ifdef XRAUDIO_KWD_ENABLED
void xraudio_msg_async_session_begin(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_async_session_begin_t *begin = (xraudio_queue_msg_async_session_begin_t *)msg;
   XLOGD_DEBUG("");

   if(!xraudio_keyword_detector_session_is_armed(&state->record.keyword_detector)) {
      XLOGD_ERROR("detector is not armed");
      return;
   }
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(begin->source) == XRAUDIO_DEVICE_INPUT_NONE) {
      XLOGD_ERROR("unsupported source");
      return;
   }
   keyword_callback_event_t event = KEYWORD_CALLBACK_EVENT_DETECTED;
   xraudio_device_input_configuration_t configuration;

   memset(&configuration, 0, sizeof(configuration));
   configuration.fd = -1;

   xraudio_keyword_detector_result_t detector_result;
   uint8_t ii;

   memset(&detector_result, 0, sizeof(xraudio_keyword_detector_result_t));

   //mic fd may have changed with firmware load
   xraudio_input_hal_obj_external_get(state->params.hal_input_obj, begin->source, begin->format, &configuration);
   state->record.fd                 = configuration.fd;

   if(state->record.fd < 0) {
      XLOGD_ERROR("invalid fd for HAL read <%d>", state->record.fd);
      event = KEYWORD_CALLBACK_EVENT_ERROR_FD;
   }

   if(!begin->stream_params.valid) {
      XLOGD_ERROR("HAL stream params not valid");
      event = KEYWORD_CALLBACK_EVENT_ERROR;
   } else {
      for(ii=0;ii<XRAUDIO_INPUT_MAX_CHANNEL_QTY;ii++) {
         detector_result.chan_selected             = 0;
         detector_result.channels[ii].doa          = 0;
         detector_result.channels[ii].score        = 1.0;
         detector_result.channels[ii].snr          = 10.0;
         detector_result.channels[ii].dynamic_gain = 0.0;
      }

      detector_result.endpoints.valid     = true;
      detector_result.endpoints.pre       = begin->stream_params.kwd_pre;
      detector_result.endpoints.begin     = begin->stream_params.kwd_begin;
      detector_result.endpoints.end       = begin->stream_params.kwd_end;
      detector_result.detector_name       = begin->stream_params.keyword_detector;
      detector_result.dsp_name            = begin->stream_params.dsp_name;
      detector_result.endpoints.kwd_gain  = begin->stream_params.dsp_kwd_gain;
      detector_result.sensitivity         = begin->stream_params.sensitivity;
   }

   state->record.keyword_detector.active_chan = 0;
   #ifdef XRAUDIO_DGA_ENABLED
   xraudio_session_record_inst_t *instance = &state->record.instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   instance->dynamic_gain_set         = true;
   instance->hal_kwd_peak_power_dBFS  = begin->stream_params.kwd_peak_power_dBFS;
   instance->dynamic_gain_pcm_bit_qty = state->record.pcm_bit_qty;

   // calculate dynamic gain using use keyword peak power measurement from external detector
   int16_t hal_kwd_peak_power_aop_adjusted = instance->hal_kwd_peak_power_dBFS - (int16_t)(state->record.input_aop_adjust_dB);
   XLOGD_INFO("peak power aop adjusted <%d dBFS>, peak power <%d dBFS>, aop_adjust <%d dB>", hal_kwd_peak_power_aop_adjusted, instance->hal_kwd_peak_power_dBFS, (int16_t)state->record.input_aop_adjust_dB);
   float dynamic_gain;
   xraudio_dga_update(state->record.obj_dga, &instance->dynamic_gain_pcm_bit_qty, hal_kwd_peak_power_aop_adjusted, &dynamic_gain);
   dynamic_gain -= state->record.input_aop_adjust_dB;
   detector_result.channels[state->record.keyword_detector.active_chan].dynamic_gain = dynamic_gain;
   XLOGD_DEBUG("pcm bit qty in <%u> out <%u>", state->record.pcm_bit_qty, instance->dynamic_gain_pcm_bit_qty);
   #endif

   //xraudio_msg_record_start uses some data from state->record.keyword_detector and it's not in use now so let's borrow
   memcpy(&state->record.keyword_detector.result, &detector_result, sizeof(xraudio_keyword_detector_result_t));

   xraudio_keyword_detector_session_event(&state->record.keyword_detector, begin->source, uuid_is_null(begin->uuid) ? NULL : &begin->uuid, event, &detector_result, begin->format);
}

void xraudio_msg_async_session_end(xraudio_thread_state_t *state, void *msg) {
   XLOGD_DEBUG("");
}

void xraudio_msg_async_input_error(xraudio_thread_state_t *state, void *msg) {
   xraudio_queue_msg_async_input_error_t *error = (xraudio_queue_msg_async_input_error_t *)msg;
   XLOGD_DEBUG("");
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(error->source) != XRAUDIO_DEVICE_INPUT_NONE) {
      xraudio_process_mic_error(&state->record);
      return;
   }
   if(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(error->source) != XRAUDIO_DEVICE_INPUT_NONE && XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(error->source) == xraudio_in_session_group_source_get(XRAUDIO_INPUT_SESSION_GROUP_DEFAULT)) {
      XLOGD_INFO("resetting xraudio session state due to input error");
      xraudio_atomic_int_set(&g_voice_session.source[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT], XRAUDIO_DEVICE_INPUT_NONE);
   }
}
#endif

void xraudio_msg_terminate(xraudio_thread_state_t *state, void *msg) {
   xraudio_main_queue_msg_terminate_t *terminate = (xraudio_main_queue_msg_terminate_t *)msg;
   XLOGD_INFO("");
   sem_post(terminate->semaphore);
   state->running = false;
}

void xraudio_msg_thread_poll(xraudio_thread_state_t *state, void *msg) {
   xraudio_main_queue_msg_thread_poll_t *thread_poll = (xraudio_main_queue_msg_thread_poll_t *)msg;

   #if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_OUTPUT_ENABLED)
   // Call hal to ensure that it is ok
   if(!xraudio_hal_thread_poll()) {
      XLOGD_ERROR("xraudio HAL is NOT responsive");
      return;
   }
   #endif
   if(thread_poll->func != NULL) {
      (*thread_poll->func)();
   }
}

void xraudio_msg_power_mode(xraudio_thread_state_t *state, void *msg) {
   xraudio_main_queue_msg_power_mode_t *power_mode = (xraudio_main_queue_msg_power_mode_t *)msg;

   xraudio_result_t result = XRAUDIO_RESULT_OK;
   #ifdef XRAUDIO_KWD_ENABLED
   // Call HAL to enter the power mode
   if(!xraudio_hal_power_mode(state->params.hal_obj, power_mode->power_mode)) {
      result = XRAUDIO_RESULT_ERROR_INTERNAL;
   }
   #endif

   if(power_mode->semaphore != NULL) {
      if(power_mode->result != NULL) {
         *(power_mode->result) = result;
      }
      sem_post(power_mode->semaphore);
   }
}

void xraudio_msg_privacy_mode(xraudio_thread_state_t *state, void *msg) {
   xraudio_main_queue_msg_privacy_mode_t *privacy_mode = (xraudio_main_queue_msg_privacy_mode_t *)msg;

   xraudio_result_t result = XRAUDIO_RESULT_OK;
   #ifdef XRAUDIO_KWD_ENABLED
   // Call HAL to enter the privacy mode
   if(!xraudio_hal_privacy_mode(state->params.hal_obj, privacy_mode->enable)) {
      result = XRAUDIO_RESULT_ERROR_INTERNAL;
   }
   #endif

   if(privacy_mode->semaphore != NULL) {
      if(privacy_mode->result != NULL) {
         *(privacy_mode->result) = result;
      }
      sem_post(privacy_mode->semaphore);
   }
}

void xraudio_msg_privacy_mode_get(xraudio_thread_state_t *state, void *msg) {
   xraudio_main_queue_msg_privacy_mode_get_t *privacy_mode_get = (xraudio_main_queue_msg_privacy_mode_get_t *)msg;

   xraudio_result_t result = XRAUDIO_RESULT_OK;
   #ifdef XRAUDIO_KWD_ENABLED
   //Call HAL to get mute state
  if(!xraudio_hal_privacy_mode_get(state->params.hal_obj, privacy_mode_get->enabled)) {
      result = XRAUDIO_RESULT_ERROR_INTERNAL;
   }
   #endif

   if(privacy_mode_get->semaphore != NULL) {
      if(privacy_mode_get->result != NULL) {
         *(privacy_mode_get->result) = result;
      }
      sem_post(privacy_mode_get->semaphore);
   }
}


void xraudio_msg_capture_params_set(xraudio_thread_state_t *state, void *msg) {
   xraudio_main_queue_msg_capture_params_set_t *capture_params_set = (xraudio_main_queue_msg_capture_params_set_t *)msg;

   xraudio_result_t result = XRAUDIO_RESULT_OK;

   xraudio_internal_capture_params_t *capture_params = &capture_params_set->capture_params;

   if(state->record.capture_internal.dir_path != NULL) {
      free(state->record.capture_internal.dir_path);
   }

   if(capture_params->enable) {
      XLOGD_INFO("internal capture dir path <%s> file qty max <%u> file size max <%u> curtail <%s>", capture_params->dir_path, capture_params->file_qty_max, capture_params->file_size_max, capture_params->use_curtail ? "YES" : "NO");
      state->record.capture_internal.enabled                 = capture_params->enable;
      state->record.capture_internal.use_curtail             = capture_params->use_curtail;
      state->record.capture_internal.dir_path                = strdup(capture_params->dir_path);
      state->record.capture_internal.file_qty_max            = capture_params->file_qty_max;
      state->record.capture_internal.file_size_max           = capture_params->file_size_max;
      state->record.capture_internal.file_index              = xraudio_capture_next_file_index(capture_params->dir_path, capture_params->file_qty_max);

      #ifdef CURTAIL_ENABLED
      xraudio_capture_file_size_max_verify(&state->record.capture_internal.file_size_max);
      #endif
   } else {
      XLOGD_INFO("internal capture disabled");
      state->record.capture_internal.enabled                 = false;
      state->record.capture_internal.use_curtail             = false;
      state->record.capture_internal.dir_path                = NULL;
      state->record.capture_internal.file_qty_max            = 0;
      state->record.capture_internal.file_size_max           = 0;
      state->record.capture_internal.file_index              = 0;
   }

   if(capture_params_set->semaphore != NULL) {
      if(capture_params_set->result != NULL) {
         *(capture_params_set->result) = result;
      }
      sem_post(capture_params_set->semaphore);
   }
}

void xraudio_msg_input_source_fd_set(xraudio_thread_state_t *state, void *msg) {
   xraudio_main_queue_msg_input_source_fd_set_t *input_source_fd_set = (xraudio_main_queue_msg_input_source_fd_set_t *)msg;

   xraudio_result_t result = XRAUDIO_RESULT_OK;

   uint32_t group = xraudio_input_source_to_group(input_source_fd_set->source);
   if(input_source_fd_set->source != xraudio_in_session_group_source_get(group)) { // Acquire the session
      if(!xraudio_in_session_group_semaphore_lock(input_source_fd_set->source)) {
         XLOGD_ERROR("could not acquire session");
         result = XRAUDIO_RESULT_ERROR_IN_USE;
      }
   }

   if(result == XRAUDIO_RESULT_OK) {
      state->record.external_format    = input_source_fd_set->format;
      state->record.external_fd        = input_source_fd_set->fd;
      state->record.external_callback  = input_source_fd_set->callback;
      state->record.external_user_data = input_source_fd_set->user_data;

      XLOGD_INFO("src <%s> fd <%d> encoding <%s>", xraudio_devices_input_str(input_source_fd_set->source), state->record.external_fd, xraudio_encoding_str(state->record.external_format.encoding.type));
   }

   if(input_source_fd_set->semaphore != NULL) {
      if(input_source_fd_set->result != NULL) {
         *(input_source_fd_set->result) = result;
      }
      sem_post(input_source_fd_set->semaphore);
   }
}

#if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_OUTPUT_ENABLED)
void timer_frame_process(void *data) {
   xraudio_thread_state_t *state = (xraudio_thread_state_t *)data;

   unsigned long timeout_mic  = 0;
   unsigned long timeout_spkr = 0;
   unsigned long timeout_val  = 0;

   bool playback_active = false;

   #ifdef MASK_FIRST_READ_DELAY
   if(state->params.obj_input != NULL && (state->record.recording || !state->record.first_read_complete)) {
   #else
   if(state->params.obj_input != NULL && state->record.recording) {
   #endif
      #ifdef XRAUDIO_KWD_ENABLED
      xraudio_process_mic_data(&state->params, &state->record, &timeout_mic);
      #endif
      #ifdef XRAUDIO_OUTPUT_ENABLED
      if(state->params.obj_output != NULL) { // Simultaneous record and playback
         xraudio_process_spkr_data(&state->params, &state->playback, state->playback.frame_size, &timeout_spkr, &state->record.timestamp_next);
      }
   } else if(state->params.obj_output != NULL) { // Only playback
      xraudio_process_spkr_data(&state->params, &state->playback, state->playback.frame_size, &timeout_spkr, NULL);
      #endif
   }

   // if speaker processed data use it's timeout value otherwise use microphone's value
   if(timeout_spkr) {
      timeout_val = timeout_spkr;
      playback_active  = true;
   } else {
      timeout_val = timeout_mic;
   }

   if(state->params.obj_input != NULL && state->record.recording) {
      xraudio_input_stats_playback_status(state->params.obj_input, playback_active);
   }

   if(timeout_val == 0) {
      if(!rdkx_timer_remove(state->timer_obj, state->timer_id_frame)) {
         XLOGD_ERROR("timer remove");
      }
      state->timer_id_frame = RDXK_TIMER_ID_INVALID;
   } else {
      // Update the timeout
      rdkx_timestamp_t timeout;
      rdkx_timestamp_get(&timeout);
      rdkx_timestamp_add_us(&timeout, timeout_val);

      rdkx_timer_update(state->timer_obj, state->timer_id_frame, timeout);
   }
}
#endif

#ifdef XRAUDIO_KWD_ENABLED
void xraudio_process_mic_data(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, unsigned long *timeout) {
   int rc = -1;
   audio_in_callback_event_t event = AUDIO_IN_CALLBACK_EVENT_OK;

   #ifdef MASK_FIRST_READ_DELAY
   if(!session->first_read_complete) {
      // Deal with long delay in first call to qahw_out_read (several hundred milliseconds)
      if(!session->first_read_pending && !session->first_read_thread.running) {
         g_thread_params_read.params  = params;
         g_thread_params_read.session = session;

         session->first_read_pending = true;

         // Perform first read in a separate thread
         if(!xraudio_thread_create(&session->first_read_thread, "xraudio_1st_rd", xraudio_thread_first_read, &g_thread_params_read)) {
            XLOGD_ERROR("unable to launch thread");
         }

         rdkx_timestamp_get(&session->timestamp_next); // Mark starting timestamp
      }

      if(session->first_read_pending) { // the first call to qahw_out_read has not completed yet
         // Add the timeout interval to determine the next timestamp
         rdkx_timestamp_add_us(&session->timestamp_next, session->timeout);
         // Calculate the amount of time until next chunk in microseconds
         uint32_t until = rdkx_timestamp_until_us(session->timestamp_next);
         if(until == 0) {
            *timeout = 1;
         } else {
            *timeout = until;
         }
         return;
      } else if(session->first_read_thread.running) {
         xraudio_thread_join(&session->first_read_thread);
         session->first_read_complete       = true;
      }
   }
   #endif

   if(!session->recording) {
      rdkx_timestamp_get(&session->timestamp_next); // Mark starting timestamp
   }

   xraudio_input_stats_timestamp_frame_ready(params->obj_input, session->timestamp_next);

   uint32_t mic_frame_size;
   uint32_t mic_frame_samples;
   xraudio_devices_input_t device_input_local = XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input);
   xraudio_devices_input_t device_input_ecref = XRAUDIO_DEVICE_INPUT_EC_REF_GET(session->devices_input);

   uint8_t chan_qty_mic   = (device_input_local == XRAUDIO_DEVICE_INPUT_QUAD) ? 4 : (device_input_local == XRAUDIO_DEVICE_INPUT_TRI) ? 3 : 1;
   uint8_t chan_qty_ecref = (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_5_1) ? 6 : (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_STEREO) ? 2 : (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_MONO) ? 1 : 0;
   uint8_t chan_qty_total = (chan_qty_mic + chan_qty_ecref);
   uint8_t sample_size = (session->pcm_bit_qty > 16) ? 4 : 2;   // HAL sample size does not change even though downstream it may need to be different

   mic_frame_samples = chan_qty_total * XRAUDIO_INPUT_FRAME_PERIOD * session->format_in.sample_rate / 1000;
   mic_frame_size = mic_frame_samples * sample_size;    // X channels * (20 msec @ 16kHz * (2 or 4 bytes per sample))  = 640*X bytes or 1280*X bytes per frame
   uint8_t mic_frame_data[mic_frame_size];

   xraudio_eos_event_t eos_event_hal = XRAUDIO_EOS_EVENT_NONE;

   rc = xraudio_hal_input_read(params->hal_input_obj, mic_frame_data, mic_frame_size, &eos_event_hal);
   XLOGD_DEBUG("bytes read %d, bytes expected %u, frame size %u", rc, mic_frame_size, session->frame_size_in);
   if(rc != (int) mic_frame_size) {
      if(rc < 0) {
         XLOGD_ERROR("hal mic read: error %d", rc);
      } else {
         XLOGD_ERROR("hal mic read: got %d, expected %u bytes", rc, mic_frame_size);
      }
      // End the session
      xraudio_process_mic_error(session);
      return;
   }

   session->handler_unpack(session, mic_frame_data, chan_qty_total, &session->frame_buffer_int16[0], &session->frame_buffer_fp32[0], session->frame_group_index, mic_frame_samples);

   if(!session->recording) { // qahw seems to take 120ms on the first call probably with first time initialization so let's account for this
      session->recording = true;
      rdkx_timestamp_get(&session->timestamp_next); // Mark starting timestamp
   }
   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_session_record_inst_t *instance = &session->instances[group];

      if(instance->mode_changed) {
         if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input) == instance->source && instance->callback != NULL){
            (*instance->callback)(XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input), AUDIO_IN_CALLBACK_EVENT_FIRST_FRAME, NULL, instance->param);
         }
         instance->mode_changed = false;
      }
   }

   xraudio_input_stats_timestamp_frame_read(params->obj_input);

   #ifdef XRAUDIO_PPR_ENABLED
   xraudio_ppr_event_t ppr_event;
   if (params->dsp_config.ppr_enabled) {
      xraudio_preprocess_mic_data(params, session, &ppr_event);
   }
   #endif

   for(uint8_t chan = 0; chan < chan_qty_mic; ++chan) {
      if(session->eos_detector.single_channel < chan_qty_mic) { // If single channel is specified, handle it accordingly
         if(session->eos_detector.single_channel_mode == XRAUDIO_SINGLE_CHANNEL_SKIP) {
            if(chan == session->eos_detector.single_channel) { // skip only specified single channel
               continue;
            }
         } else {
            if(chan != session->eos_detector.single_channel) { // skip all channels except the one specified
               continue;
            }
         }
      }
      uint32_t sample_qty_chan = session->frame_sample_qty / session->format_in.channel_qty;
      int16_t scaled_eos_samples[sample_qty_chan]; //declaring buffer here instead of EOS because EOS init doesn't know sample_qty
      float *frame_buffer_fp32 = &session->frame_buffer_fp32[chan].frames[session->frame_group_index].samples[0];

      xraudio_eos_event_t eos_event = xraudio_input_eos_run(params->obj_input, chan, frame_buffer_fp32, sample_qty_chan, &scaled_eos_samples[0] );

      #if defined(XRAUDIO_KWD_ENABLED)
      uint8_t active_chan = (params->dsp_config.input_asr_max_channel_qty == 0) ? session->keyword_detector.active_chan : 0;   // kwd active ("best") channel
      #else
      uint8_t active_chan = 0;                                       // ASR channel reserved for channel 0
      #endif
      if(session->recording && chan == active_chan) {
         xraudio_session_record_inst_t *instance = &session->instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];
         instance->eos_event = eos_event;
         if(eos_event != XRAUDIO_EOS_EVENT_NONE) {
            XLOGD_DEBUG("eos event: %s", xraudio_eos_event_str(eos_event));
         }
         #ifdef XRAUDIO_PPR_ENABLED
         xraudio_eos_event_t eos_event_ppr = XRAUDIO_EOS_EVENT_NONE;
         if (params->dsp_config.ppr_enabled) {
            if(ppr_event != XRAUDIO_PPR_EVENT_NONE) {
               XLOGD_DEBUG("ppr event: %s", xraudio_ppr_event_str(ppr_event));
            }
            switch(ppr_event) {
               case XRAUDIO_PPR_EVENT_ENDOFSPEECH:     eos_event_ppr = XRAUDIO_EOS_EVENT_ENDOFSPEECH;     break;
               case XRAUDIO_PPR_EVENT_TIMEOUT_INITIAL: eos_event_ppr = XRAUDIO_EOS_EVENT_TIMEOUT_INITIAL; break;
               case XRAUDIO_PPR_EVENT_TIMEOUT_END:     eos_event_ppr = XRAUDIO_EOS_EVENT_TIMEOUT_END;     break;
               case XRAUDIO_PPR_EVENT_NONE:
               case XRAUDIO_PPR_EVENT_STARTOFSPEECH:
               case XRAUDIO_PPR_EVENT_LOCAL_KEYWORD_DETECTED:
               case XRAUDIO_PPR_EVENT_REFERENCE_KEYWORD_DETECTED:
               case XRAUDIO_PPR_EVENT_INVALID:       break;
            }
         }
         if (!params->dsp_config.eos_enabled) {
            eos_event = eos_event_ppr;
         }
         #endif
         if(instance->use_hal_eos) {
            if(eos_event_hal == XRAUDIO_EOS_EVENT_NONE) {
               eos_event = XRAUDIO_EOS_EVENT_NONE;
            } else if(!instance->eos_hal_cmd_pending) {
               XLOGD_ERROR("cmd not pending - hal eos event <%s>", xraudio_eos_event_str(eos_event_hal));
               eos_event = XRAUDIO_EOS_EVENT_NONE;
            } else {
               eos_event                    = eos_event_hal; // when HAL supports EOS, use it instead of the ppr or eos subcomponents
               instance->eos_hal_cmd_pending = false;
            }
         }
         switch(eos_event) {
            case XRAUDIO_EOS_EVENT_ENDOFSPEECH:     event = AUDIO_IN_CALLBACK_EVENT_EOS; instance->eos_vad_forced = false; break;
            case XRAUDIO_EOS_EVENT_TIMEOUT_INITIAL: event = AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_INITIAL; instance->eos_vad_forced = false; break;
            case XRAUDIO_EOS_EVENT_TIMEOUT_END:     event = AUDIO_IN_CALLBACK_EVENT_EOS_TIMEOUT_END; instance->eos_vad_forced = false; break;
            case XRAUDIO_EOS_EVENT_END_OF_WAKEWORD: instance->eos_vad_forced = false; break;
            case XRAUDIO_EOS_EVENT_NONE:
            case XRAUDIO_EOS_EVENT_STARTOFSPEECH: 
            case XRAUDIO_EOS_EVENT_INVALID:       break;
         }
         if(instance->eos_vad_forced) {
            instance->eos_end_of_wake_word_samples += sample_qty_chan;
            XLOGD_DEBUG("eos_end_of_wake_word_samples <%u>", instance->eos_end_of_wake_word_samples);
         }
      }
      if(session->capture_session.active && session->capture_session.eos[chan].file.fd >= 0) {
         int rc_cap = xraudio_in_capture_session_to_file_int16(&session->capture_session.eos[chan], &scaled_eos_samples[0], sample_qty_chan);
         if(rc_cap < 0) {
            session->capture_session.active = false;
         }
      }
   }

   xraudio_input_stats_timestamp_frame_eos(params->obj_input);

   // Increment the frame group index to count number of frames, 1-based
   session->frame_group_index++;

   // Update the sound focus
   xraudio_input_sound_focus_update(params->obj_input, session->frame_sample_qty);

   xraudio_input_stats_timestamp_frame_sound_focus(params->obj_input);

   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_session_record_inst_t *instance = &session->instances[group];

      if(instance->record_callback != NULL) { // Recording

         session->hal_mic_frame_ptr  = mic_frame_data;
         session->hal_mic_frame_size = mic_frame_size;

         rc = instance->record_callback(instance->source, params, session, instance);
      }
   }


   #ifdef XRAUDIO_KWD_ENABLED
   // stream audio to keyword detector
   xraudio_in_write_to_keyword_detector(XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input), params, session, &session->instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT]);
   #endif // XRAUDIO_KWD_ENABLED

   xraudio_input_stats_timestamp_frame_process(params->obj_input);

   // Update sound intensity
   xraudio_in_sound_intensity_transfer(params, session);

   // Wrap the frame group index (based on default group's group qty)
   if(session->frame_group_index >= session->instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT].frame_group_qty) {
      session->frame_group_index = 0;
   }

   if(rc < 0) {
      // Clear timeout
      *timeout = 0;
      XLOGD_ERROR("Error (%d)", rc);
      event = AUDIO_IN_CALLBACK_EVENT_ERROR;
   } else {
      // Add the timeout interval to determine the next timestamp
      rdkx_timestamp_add_us(&session->timestamp_next, session->timeout);
      // Calculate the amount of time until next chunk in microseconds
      unsigned long until = rdkx_timestamp_until_us(session->timestamp_next);
      if(until == 0) {
         *timeout = 1;
         //XLOGD_DEBUG("behind %llu us", rdkx_timestamp_since_us(session->timestamp_next));
      } else {
         *timeout = until;
      }
   }

   xraudio_input_stats_timestamp_frame_end(params->obj_input);

   xraudio_session_record_inst_t *instance = &session->instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];

   if(instance->stream_until[0] == XRAUDIO_INPUT_RECORD_UNTIL_END_OF_SPEECH && event != AUDIO_IN_CALLBACK_EVENT_OK) { // Session ended, notify

      // Flush any partial data
      xraudio_in_flush(XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input), params, session, instance);
      session->frame_group_index = 0;

      for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
         if(instance->fifo_audio_data[index] >= 0) { // Close the write side of the pipe so the read side gets EOF
            XLOGD_DEBUG("Close write side of pipe to send EOF to read side");
            close(instance->fifo_audio_data[index]);
            instance->fifo_audio_data[index] = -1;
         }
         instance->stream_until[index] = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
      }

      if(instance->fd >= 0) {
         xraudio_record_container_process_end(instance->fd, instance->format_out, instance->audio_buf_index, false);
      }

      if(instance->synchronous) {
         if(instance->semaphore == NULL) {
            XLOGD_ERROR("synchronous record with no semaphore set!");
         } else {
            sem_post(instance->semaphore);
            instance->semaphore = NULL;
         }
      } else if(instance->callback != NULL) {
         if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(instance->source) != XRAUDIO_DEVICE_INPUT_NONE) {
            xraudio_hal_input_stats_t input_stats = { 0 };

            // Read statistics from the hal which were reset at the point to start counting
            if(!xraudio_hal_input_stats(params->hal_input_obj, &input_stats, false)) {
               XLOGD_ERROR("unable to read input stats!");
            } else {
               // Determine how many samples were lost from keyword end to end of stream
               instance->stats.samples_lost         = input_stats.samples_lost;
               instance->stats.samples_buffered_max = input_stats.samples_buffered_max;

               XLOGD_DEBUG("HAL samples buffered max <%u> lost <%u>", input_stats.samples_buffered_max, input_stats.samples_lost);
            }

            (*instance->callback)(XRAUDIO_DEVICE_INPUT_LOCAL_GET(instance->source), event, &instance->stats, instance->param);
         }
      }
      // Clear the session so no further incoming data is processed
      instance->fd                       = -1;
      instance->audio_buf_samples        = NULL;
      instance->audio_buf_sample_qty     = 0;
      instance->audio_buf_index          = 0;
   }
}

void xraudio_process_mic_error(xraudio_session_record_t *session) {
   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_session_record_inst_t *instance = &session->instances[group];

      if(instance->synchronous) {
         if(instance->semaphore == NULL) {
            XLOGD_ERROR("synchronous record with no semaphore set!");
         } else {
            sem_post(instance->semaphore);
            instance->semaphore = NULL;
         }
      } else {
         xraudio_devices_input_t device_local = XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input);
         xraudio_devices_input_t source_local = XRAUDIO_DEVICE_INPUT_LOCAL_GET(instance->source);
         if((instance->callback != NULL) && (device_local != XRAUDIO_DEVICE_INPUT_NONE) && (source_local != XRAUDIO_DEVICE_INPUT_NONE)) {
            (*instance->callback)(instance->source, AUDIO_IN_CALLBACK_EVENT_ERROR, NULL, instance->param);
         } else if(device_local != XRAUDIO_DEVICE_INPUT_NONE && xraudio_keyword_detector_session_is_armed(&session->keyword_detector)) {
            xraudio_keyword_detector_session_event(&session->keyword_detector, device_local, NULL, KEYWORD_CALLBACK_EVENT_ERROR, NULL, session->format_in);
         }
      }
   }
   session->recording = false;
}

void xraudio_unpack_mono_int16(xraudio_session_record_t *session, void *buffer_in, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame) {
   int16_t *buffer_in_int16 = (int16_t *)buffer_in;
   uint32_t frame_size = sample_qty_frame * sizeof(int16_t);

   XLOGD_DEBUG("group <%u> sample qty frame <%u> frame size <%u>", frame_group_index, sample_qty_frame, frame_size);

   memcpy(&audio_group_int16->frames[frame_group_index].samples[0], buffer_in_int16, frame_size);
   float *buffer_out_fp32 = &audio_group_fp32->frames[frame_group_index].samples[0];
   for(uint32_t j = 0; j < sample_qty_frame; j++) {
      *buffer_out_fp32  = *buffer_in_int16;
      buffer_out_fp32++;
      buffer_in_int16++;
   }
}

void xraudio_unpack_multi_int16(xraudio_session_record_t *session, void *buffer_in, uint8_t chan_qty, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame) {
   int16_t *buffer_in_int16 = (int16_t *)buffer_in;
   uint32_t sample_qty_channel = sample_qty_frame / chan_qty;
   XLOGD_DEBUG("group <%u> sample qty frame <%u> sample qty channel <%u>", frame_group_index, sample_qty_frame, sample_qty_channel);

   for(uint32_t chan = 0; chan < chan_qty; chan++) {
      int16_t *samples = &buffer_in_int16[chan * sample_qty_channel];
      xraudio_unpack_mono_int16(session, samples, &audio_group_int16[chan], &audio_group_fp32[chan], frame_group_index, sample_qty_channel);
      if(session->capture_session.active && session->capture_session.input[chan].file.fd >= 0) {
         int rc_cap = xraudio_in_capture_session_to_file_int16(&session->capture_session.input[chan], samples, sample_qty_channel);
         if(rc_cap < 0) {
            session->capture_session.active = false;
         }
      }
   }
}

void xraudio_unpack_mono_int32(xraudio_session_record_t *session, void *buffer_in, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame) {
   int32_t *buffer_in_int32 = (int32_t *)buffer_in;

   //XLOGD_DEBUG("group <%u> sample qty frame <%u>", frame_group_index, sample_qty_frame);

   if(!session->capture_session.raw_mic_enable && !session->raw_mic_enable) {
      xraudio_in_aop_adjust_apply(buffer_in_int32, sample_qty_frame, session->input_aop_adjust_shift);
   }

   int16_t *buffer_out_int16 = &audio_group_int16->frames[frame_group_index].samples[0];
   float *  buffer_out_fp32  = &audio_group_fp32->frames[frame_group_index].samples[0];
   for(uint32_t i = 0; i < sample_qty_frame; i++) {
      *buffer_out_int16 = (int16_t)(*buffer_in_int32 >> 16);
      *buffer_out_fp32  = *buffer_in_int32;
      buffer_out_int16++;
      buffer_out_fp32++;
      buffer_in_int32++;
   }
}

void xraudio_unpack_multi_int32(xraudio_session_record_t *session, void *buffer_in, uint8_t chan_qty, xraudio_audio_group_int16_t *audio_group_int16, xraudio_audio_group_float_t *audio_group_fp32, uint32_t frame_group_index, uint32_t sample_qty_frame) {
   int32_t *buffer_in_int32 = (int32_t *)buffer_in;
   uint32_t sample_qty_channel = sample_qty_frame / chan_qty;

   //XLOGD_DEBUG("group <%u> sample qty frame <%u> sample qty channel <%u>", frame_group_index, sample_qty_frame, sample_qty_channel);

   for(uint32_t chan = 0; chan < chan_qty; chan++) {
      int32_t *samples = &buffer_in_int32[chan * sample_qty_channel];
      xraudio_unpack_mono_int32(session, samples, &audio_group_int16[chan], &audio_group_fp32[chan], frame_group_index, sample_qty_channel);
      if(session->capture_session.active && session->capture_session.input[chan].file.fd >= 0) {
         int rc_cap = xraudio_in_capture_session_to_file_int32(&session->capture_session.input[chan], samples, sample_qty_channel);
         if(rc_cap < 0) {
            session->capture_session.active = false;
         }
      }
   }
}
#endif

void xraudio_in_flush(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance) {
   if(source != XRAUDIO_DEVICE_INPUT_MIC_TAP) {
      instance->frame_group_qty = 1;
   }

   if(instance->record_callback) { // Call the record handler to handle all the pending data
      instance->record_callback(source, params, session, instance);
   }
}

int xraudio_in_write_to_file(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance) {
   uint8_t *frame_buffer      = NULL;
   uint32_t frame_size        = 0;
   uint8_t  frame_group_index = 0;
   if(source != instance->source) {
      XLOGD_DEBUG("different source is being recorded");
      return(0);
   }
   if(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(source) != XRAUDIO_DEVICE_INPUT_NONE) {
      // External source, set frame vars
      frame_buffer      = session->external_frame_buffer;
      frame_size        = session->external_frame_size_out;
      frame_group_index = session->external_frame_group_index;
   } else {
      // Local source, set frame vars
      uint8_t chan = 0;
      #if defined(XRAUDIO_KWD_ENABLED)
      if(params->dsp_config.input_asr_max_channel_qty == 0) {
         chan = session->keyword_detector.active_chan;
      }
      #endif

      frame_buffer      = (uint8_t *)&session->frame_buffer_int16[chan].frames[0];
      frame_size        = instance->frame_size_out;
      frame_group_index = session->frame_group_index;
   }
   if(frame_group_index >= instance->frame_group_qty) {
      // Write requested size into file
      errno = 0;
      ssize_t bytes_written = write(instance->fd, frame_buffer, frame_size * frame_group_index);

      if(bytes_written != (frame_size * frame_group_index)) {
         int errsv = errno;
         XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
         return(-1);
      }

      instance->audio_buf_index += (frame_size * frame_group_index);
   }

   return(0);
}

#ifdef XRAUDIO_KWD_ENABLED
int xraudio_in_write_to_keyword_detector(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance) {
   uint32_t frame_group_index = session->frame_group_index - 1;
   xraudio_devices_input_t device_input_local = XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input);

   uint8_t chan_qty_mic   = (device_input_local == XRAUDIO_DEVICE_INPUT_QUAD) ? 4 : (device_input_local == XRAUDIO_DEVICE_INPUT_TRI) ? 3 : 1;

   bool all_triggered = true;
   xraudio_keyword_detector_t *detector = &session->keyword_detector;

   if(!xraudio_keyword_detector_session_is_active(detector)) {
      return(0);
   }

   uint32_t chan_sample_qty = session->frame_sample_qty / session->format_in.channel_qty;
   bool is_armed = xraudio_keyword_detector_session_is_armed(detector);

   // check each detector for trigger. After first detector triggers, start timer for detectors

   // If ASR channel is defined, then channel 0 is reserved for ASR channel streamed to the cloud.
   // Buffer but skip keyword detection on the ASR channel. Keep looking for keyword on remaining input channels.
   uint8_t first_chan_kwd = params->dsp_config.input_asr_max_channel_qty;
   uint8_t last_chan_kwd = params->dsp_config.input_asr_max_channel_qty + params->dsp_config.input_kwd_max_channel_qty - 1;

   for(uint8_t chan = 0; chan < chan_qty_mic; chan++) {
      if(detector->single_channel <= last_chan_kwd) { // If single channel is specified, handle it accordingly
         if(detector->single_channel_mode == XRAUDIO_SINGLE_CHANNEL_SKIP) {
            if(chan == detector->single_channel) { // skip only specified single channel
               continue;
            }
         } else {
            if(chan != detector->single_channel) { // skip all channels except the one specified
               continue;
            }
         }
      }
      if(chan > last_chan_kwd) {
         XLOGD_ERROR("No keyword detector on input channel <%u>", chan);
         return(0);
      }
      xraudio_keyword_detector_chan_t *detector_chan = &detector->channels[chan];
      bool detected = false;
      int16_t scaled_kwd_samples[chan_sample_qty]; //declaring buffer here instead of KWD because KWD init does not know sample_qty

      xraudio_in_write_to_keyword_buffer(detector_chan, &session->frame_buffer_fp32[chan].frames[frame_group_index].samples[0], chan_sample_qty);

      if((chan < first_chan_kwd) || (chan > last_chan_kwd)) {
         if(session->capture_session.active && session->capture_session.kwd[chan].file.fd >= 0) {
            #ifdef XRAUDIO_INPUT_KWD_FLOAT
            int rc_cap = xraudio_in_capture_session_to_file_float(&session->capture_session.kwd[chan], &session->frame_buffer_fp32[chan].frames[frame_group_index].samples[0], chan_sample_qty);
            #else
            int rc_cap = xraudio_in_capture_session_to_file_int16(&session->capture_session.kwd[chan], &session->frame_buffer_int16[chan].frames[frame_group_index].samples[0], chan_sample_qty);
            #endif
            if(rc_cap < 0) {
               session->capture_session.active = false;
            }
         }
         continue;
      }
      uint8_t instance_kwd = chan - first_chan_kwd;

      float *frame_buffer_fp32 = &session->frame_buffer_fp32[chan].frames[frame_group_index].samples[0];
      if(!xraudio_kwd_run(detector->kwd_object, instance_kwd, frame_buffer_fp32, chan_sample_qty, &detected, &scaled_kwd_samples[0])) {
         XLOGD_ERROR("kwd run fail, chan <%u> instance <%u>", chan, instance_kwd);
      }
      if(session->capture_session.active && session->capture_session.kwd[chan].file.fd >= 0) {
         #ifdef XRAUDIO_INPUT_KWD_FLOAT
         int rc_cap = xraudio_in_capture_session_to_file_float(&session->capture_session.kwd[chan], &session->frame_buffer_fp32[chan].frames[frame_group_index].samples[0], chan_sample_qty);
         #else
         int rc_cap = xraudio_in_capture_session_to_file_int16(&session->capture_session.kwd[chan], &scaled_kwd_samples[0], chan_sample_qty);
         #endif
         if(rc_cap < 0) {
            session->capture_session.active = false;
         }
      }

      if(!is_armed) {
         continue;
      }

      if(detector_chan->triggered) {
         if(!instance->eos_vad_forced) {   // don't increment post frame counts if EOS enabled and looking for end of wake word
            detector_chan->post_frame_count++;
         }
      } else if(detected) {
         XLOGD_DEBUG("keyword detected for channel <%u> instance <%u>", chan, instance_kwd);

         if(!detector->triggered) {
            detector->triggered = true;
         }
         // Get the detection results
         if(!xraudio_kwd_result(detector->kwd_object, instance_kwd, &detector_chan->score, &detector_chan->snr, &detector_chan->endpoints)) {
            XLOGD_ERROR("keyword result channel <%u> instance <%u>", chan, instance_kwd);
         } else {
            // if kwd detector snr used as a criterion and available from the HAL, update it
            xraudio_hal_input_stats_t input_stats;
            if(xraudio_hal_input_stats(params->hal_input_obj, &input_stats, false)) {
               if(detector->criterion == XRAUDIO_KWD_CRITERION_SNR) {
                  detector_chan->snr = input_stats.snr[chan];
               }
               // if hal provided DSP PPR info, send it along
               if(input_stats.dsp_name != NULL) {
                  detector->result.dsp_name = input_stats.dsp_name;
               }
            }
            //if kwd detector provided detector_name, use it
            if(detector_chan->endpoints.detector_name != NULL) {
               detector->result.detector_name = detector_chan->endpoints.detector_name;
            }

            // update channel's results
            detector->result.channels[chan].score = detector_chan->score;
            detector->result.channels[chan].snr   = detector_chan->snr;
            detector->result.channels[chan].doa   = instance_kwd * 90;

            // update max score or max snr, depending on active channel selection criterion, if clearly the highest so far
            if(detector->result.chan_selected >= params->dsp_config.input_kwd_max_channel_qty ||
                  ((detector->criterion == XRAUDIO_KWD_CRITERION_SCORE) &&
                   (detector_chan->score > detector->result.channels[detector->result.chan_selected].score ||
                   (fabs(detector_chan->score - detector->result.channels[detector->result.chan_selected].score) < 0.000001))) ||
                  ((detector->criterion == XRAUDIO_KWD_CRITERION_SNR) &&
                   (detector_chan->snr > detector->result.channels[detector->result.chan_selected].snr ||
                   (fabs(detector_chan->snr - detector->result.channels[detector->result.chan_selected].snr) < 0.000001)))) {
               XLOGD_DEBUG("New max score/SNR detected: chan <%u>: <%0.6f/%0.4f> using criterion %s", chan, detector_chan->score, detector_chan->snr, xraudio_keyword_criterion_str(detector->criterion));
               detector->result.chan_selected = chan;
               detector->active_chan          = chan;

               if((((int32_t)detector_chan->pd_sample_qty) + detector_chan->endpoints.begin) < 0) { // keyword endpoint out of range
                  XLOGD_ERROR("keyword endpoint out of range <%u> <%d>", detector_chan->pd_sample_qty, detector->result.endpoints.begin);
               } else {
                  detector->result.endpoints     = detector_chan->endpoints;

                  // qty samples in circular buffer - small constant to account for frames that may arrive before user begins streaming
                  if((((int32_t)detector_chan->pd_sample_qty) + detector->result.endpoints.begin) < XRAUDIO_PRE_KWD_STREAM_LAG_SAMPLES) {
                     detector->result.endpoints.pre  = 0 - detector_chan->pd_sample_qty;
                  } else  {
                     detector->result.endpoints.pre  = 0 - (detector_chan->pd_sample_qty - XRAUDIO_PRE_KWD_STREAM_LAG_SAMPLES);
                  }
                  XLOGD_DEBUG("chan <%u> keyword endpoints pre <%d> begin <%d> end <%d>", chan, detector->result.endpoints.pre, detector->result.endpoints.begin, detector->result.endpoints.end);
               }
            }
         }
         detector_chan->triggered        = true;
         detector_chan->post_frame_count = 0;

         xraudio_input_sound_focus_set(params->obj_input, XRAUDIO_SDF_MODE_STRONGEST_SECTOR);
      } else {
         all_triggered = false;
      }
   }

   detector->post_frame_count_callback++;

   if(!is_armed || !detector->triggered) {
      return(0);
   }

   detector->post_frame_count_trigger++;

   XLOGD_DEBUG("all triggered <%s> post frame count <%u>", all_triggered ? "YES" : "NO", detector->post_frame_count_trigger);
   if(!all_triggered && detector->post_frame_count_trigger <= KEYWORD_TRIGGER_DETECT_THRESHOLD) {
      // Wait up to N frames for other detectors to fire
      return(0);
   }

   xraudio_keyword_detector_chan_t *detector_chan = &detector->channels[detector->active_chan];

   // inform EOS detector that keyword was detected for case when extended end of keyword detection IS enabled
   if(detector->triggered) {
      if(detector_chan->endpoints.end_of_wuw_ext_enabled) {
         if(instance->eos_event == XRAUDIO_EOS_EVENT_END_OF_WAKEWORD) {
            // EOS reports end of wake word. Adjust end of wakeword result then proceed with reporting keyword detection event
            detector->result.endpoints.begin -= instance->eos_end_of_wake_word_samples;

            // post process detection results, if enabled, to find and adjust start and end of wake word for current detector library
            int32_t start_wuw      = 0;
            int32_t end_wuw        = 0;
            if(xraudio_kwd_postprocess(detector->kwd_object, detector->active_chan, &start_wuw, &end_wuw)) {
               detector->result.endpoints.begin -= start_wuw;
               detector->result.endpoints.end   -= end_wuw;
               detector->result.endpoints.valid = true;
            }
            XLOGD_DEBUG("begin <%d>, end <%d>, start_wuw <%d>, end_wuw <%d>, eos_eowuw <%d>", detector->result.endpoints.begin, detector->result.endpoints.end,
                  start_wuw, end_wuw, instance->eos_end_of_wake_word_samples);
         } else if((instance->eos_event == XRAUDIO_EOS_EVENT_ENDOFSPEECH) ||
               (instance->eos_event == XRAUDIO_EOS_EVENT_TIMEOUT_INITIAL) ||
               (instance->eos_event == XRAUDIO_EOS_EVENT_TIMEOUT_END)) {
            // In rare cases other EOS events may occur while waiting for end of wakeword. Handle these cases so FFV continues to work
            XLOGD_DEBUG("Unexpected EOS event occurred while waiting for end of wakeword <%s>", xraudio_eos_event_str(instance->eos_event));
         } else if(instance->eos_vad_forced) {
            // wait to report detection event until end of wake word (vad forced flag is cleared)
            detector->post_frame_count_trigger--;     // correct for extra count while looping
            return(0);
         } else {
            XLOGD_DEBUG("Keyword detected on active chan <%u> active instance <%u>", detector->active_chan, detector->active_chan - first_chan_kwd);
            xraudio_input_eos_state_set_speech_begin(params->obj_input);
            xraudio_input_ppr_state_set_speech_begin(params->obj_input);
            #ifdef XRAUDIO_EOS_ENABLED
            if(params->dsp_config.eos_enabled && !instance->use_hal_eos) {
               // notify EOS, if enabled, to begin looking for end of wake word (not used for HAL EOS detector)
               instance->eos_vad_forced = true;
               detector->post_frame_count_trigger--;  // correct for extra count while looping
               return(0);
            }
            #endif
         }
      } else {
         // post process detection results, if enabled, to find and adjust start and end of wake word for current detector library
         int32_t start_wuw      = 0;
         int32_t end_wuw        = 0;
         if(xraudio_kwd_postprocess(detector->kwd_object, detector->active_chan, &start_wuw, &end_wuw)) {
            detector->result.endpoints.begin -= start_wuw;
            detector->result.endpoints.end   -= end_wuw;
            detector->result.endpoints.valid = true;
         }
         XLOGD_DEBUG("begin <%d>, end <%d>, start_wuw <%d>, end_wuw <%d>", detector->result.endpoints.begin, detector->result.endpoints.end,
               start_wuw, end_wuw);
      }
   }

   // Inform the HAL that keyword has been detected
   bool ignore = false;
   if(!xraudio_hal_input_detection(params->hal_input_obj, detector->active_chan, &ignore)) {
      XLOGD_ERROR("unable to inform hal of detection");
   } else if(ignore) { // HAL says to ignore the detection so re-arm the detector
      xraudio_keyword_detector_t *detector = &session->keyword_detector;
      xraudio_keyword_detector_session_arm(detector, detector->callback, detector->cb_param, detector->sensitivity);
      return(0);
   }

   if(!xraudio_in_session_group_semaphore_lock(source)) {
      XLOGD_ERROR("could not acquire session");
      return(0);
   }

   #ifdef XRAUDIO_DGA_ENABLED
   if(session->dynamic_gain_enabled && params->dsp_config.dga_enabled) {
      instance->dynamic_gain_set = true;


      uint32_t begin = -detector->result.endpoints.begin;
      uint32_t end   = -detector->result.endpoints.end;
      float   *samples[2]    = { NULL, NULL };
      uint32_t sample_qty[2] = {0, 0};

      if(xraudio_in_pre_detection_chunks(detector_chan, begin - end, end, &samples[0], &sample_qty[0], &samples[1], &sample_qty[1])) {
         XLOGD_DEBUG("chunk1=<%p, %d> chunk2 <%p, %d>", samples[0], sample_qty[0], samples[1], sample_qty[1]);

         if(session->capture_session.active && (session->capture_session.type & XRAUDIO_CAPTURE_DGA)) {
            char filename[256];
            xraudio_capture_point_t capture_point;
            const char *extension = (session->capture_session.container == XRAUDIO_CONTAINER_WAV) ? CAPTURE_INTERNAL_EXT_WAV : CAPTURE_INTERNAL_EXT_PCM;

            capture_point.file.format.container     = session->capture_session.container;
            capture_point.file.format.encoding.type = XRAUDIO_ENCODING_PCM;
            capture_point.file.format.channel_qty   = 1;
            capture_point.file.format.sample_size   = 3;
            capture_point.file.format.sample_rate   = 16000;


            if(sample_qty[0] > 0) {
               snprintf(filename, sizeof(filename), "%s_keyword_0%s", session->capture_session.audio_file_path, extension);
               capture_point.pcm_range.max        = PCM_24_BIT_MIN;
               capture_point.pcm_range.min        = PCM_24_BIT_MAX;
               capture_point.file.audio_data_size = 0;
               capture_point.file.fd              = open(filename, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
               if(capture_point.file.fd >= 0) {
                  xraudio_record_container_process_begin(&capture_point.file);
                  xraudio_in_capture_session_to_file_float(&capture_point, samples[0], sample_qty[0]);
                  xraudio_record_container_process_end(capture_point.file.fd, capture_point.file.format, capture_point.file.audio_data_size, false);
                  close(capture_point.file.fd);
                  XLOGD_INFO("keyword chunk 0 - pcm max <%d> min <%d>", capture_point.pcm_range.max, capture_point.pcm_range.min);
               }
            }
            if(sample_qty[1] > 0) {
               snprintf(filename, sizeof(filename), "%s_keyword_1%s", session->capture_session.audio_file_path, extension);
               capture_point.pcm_range.max        = PCM_24_BIT_MIN;
               capture_point.pcm_range.min        = PCM_24_BIT_MAX;
               capture_point.file.audio_data_size = 0;
               capture_point.file.fd              = open(filename, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
               if(capture_point.file.fd >= 0) {
                  xraudio_record_container_process_begin(&capture_point.file);
                  xraudio_in_capture_session_to_file_float(&capture_point, samples[1], sample_qty[1]);
                  xraudio_record_container_process_end(capture_point.file.fd, capture_point.file.format, capture_point.file.audio_data_size, false);
                  close(capture_point.file.fd);
                  XLOGD_INFO("keyword chunk 1 - pcm max <%d> min <%d>", capture_point.pcm_range.max, capture_point.pcm_range.min);
               }
            }
         }

         uint32_t  frame_qty = (samples[0] != NULL) + (samples[1] != NULL);

         instance->dynamic_gain_pcm_bit_qty = session->pcm_bit_qty;
         float dynamic_gain;
         float talker_level_dBFS;
         xraudio_dga_calculate(session->obj_dga, &instance->dynamic_gain_pcm_bit_qty, frame_qty, (const float **)samples, sample_qty, &dynamic_gain, &talker_level_dBFS);
         dynamic_gain -= session->input_aop_adjust_dB;
         detector->result.channels[detector->active_chan].dynamic_gain = dynamic_gain;

         XLOGD_DEBUG("pcm bit qty in <%u> out <%u>", session->pcm_bit_qty, instance->dynamic_gain_pcm_bit_qty);

         // if talker level threshold test is enabled, ignore detections below the threshold (likely noise)
         if(detector->result.endpoints.talker_thresh_enabled) {
            xraudio_hal_input_stats_t input_stats;
            if(xraudio_hal_input_stats(params->hal_input_obj, &input_stats, false)) {
               float talker_threshold_dBSPL = detector->result.endpoints.talker_threshold_dBSPL;
               float mic_acoustic_overload_dbspl = (float)input_stats.mic_acoustic_overload_dbspl;
               float talker_level_dBSPL = talker_level_dBFS + mic_acoustic_overload_dbspl + session->input_aop_adjust_dB;
               XLOGD_INFO("talker level <%3.1f dBSPL> talker level threshold <%3.1f dBSPL>", talker_level_dBSPL, talker_threshold_dBSPL);
               XLOGD_DEBUG("mic AOP <%3.1f dBSPL> talker_level <%3.1f dBFS>", mic_acoustic_overload_dbspl, talker_level_dBFS);
               if(talker_level_dBSPL < talker_threshold_dBSPL) {
                  xraudio_keyword_detector_t *detector = &session->keyword_detector;
                  xraudio_keyword_detector_session_arm(detector, detector->callback, detector->cb_param, detector->sensitivity);
                  if(detector_chan->endpoints.end_of_wuw_ext_enabled) {
                     instance->eos_end_of_wake_word_samples = 0;
                  }
                  XLOGD_INFO("ignore keyword detection. Talker level is below threshold", talker_level_dBSPL, talker_threshold_dBSPL);
                  xraudio_in_session_record_group_semaphore_unlock(params, session, source); // unlock semaphore to allow for next detection
                  return(0);
               }
            }
         }
      }
   }
   #endif

   // Adjust the keyword endpoints based on received audio frames since this channel triggered
   int32_t sample_adjustment = detector_chan->post_frame_count * chan_sample_qty;

   if(sample_adjustment) {
      detector->result.endpoints.pre   -= sample_adjustment;
      detector->result.endpoints.begin -= sample_adjustment;
      detector->result.endpoints.end   -= sample_adjustment;
      XLOGD_DEBUG("sample_adjustment <%d> samples <%u> post frame count <%u>", sample_adjustment, chan_sample_qty, detector_chan->post_frame_count);
      detector_chan->post_frame_count   = 0;
   }

   // inform EOS detector that keyword was detected for case when extended end of keyword detection IS NOT enabled
   if((session->keyword_detector.triggered) && !(detector_chan->endpoints.end_of_wuw_ext_enabled)){
      XLOGD_DEBUG("Keyword detected on chan <%u> instance <<%u>", detector->active_chan, detector->active_chan - first_chan_kwd);
      xraudio_input_eos_state_set_speech_begin(params->obj_input);
      xraudio_input_ppr_state_set_speech_begin(params->obj_input);
   }

   if(!xraudio_hal_input_stats(params->hal_input_obj, NULL, true)) {
      XLOGD_ERROR("unable to reset input stats!");
   }

   // Reset frame counter to count frames since keyword detector callback was called
   detector->post_frame_count_callback = 0;

   //If we don't have dsp_name yet then we're running PPR on the CPU so get that info
   if(detector->result.dsp_name == NULL) {
      xraudio_input_ppr_info_get(params->obj_input, (char**)&detector->result.dsp_name);
      if(detector->result.dsp_name == NULL) {
        XLOGD_WARN("dsp_name NULL");
      }
   }

   // include AOP adjustment in the reported keyword detector gain
   detector->result.endpoints.kwd_gain -= session->input_aop_adjust_dB;

   detector->result.sensitivity = detector->sensitivity;

   xraudio_keyword_detector_session_event(detector, source, NULL, KEYWORD_CALLBACK_EVENT_DETECTED, &detector->result, session->format_in);

   return(0);
}

void xraudio_in_write_to_keyword_buffer(xraudio_keyword_detector_chan_t *keyword_detector_chan, float *frame_buffer_fp32, uint32_t sample_qty) {
   if(sample_qty != XRAUDIO_INPUT_FRAME_SAMPLE_QTY) {
      XLOGD_ERROR("unexpected sample qty <%u>", sample_qty);
      return;
   }

   uint32_t size = sample_qty * sizeof(float);
   memcpy(&keyword_detector_chan->pre_detection_buffer_fp32[keyword_detector_chan->pd_index_write], frame_buffer_fp32, size);
   if(keyword_detector_chan->pd_sample_qty < sizeof(keyword_detector_chan->pre_detection_buffer_fp32) / sizeof(float)) {
      keyword_detector_chan->pd_sample_qty += sample_qty;
   }
   keyword_detector_chan->pd_index_write += sample_qty;
   if(keyword_detector_chan->pd_index_write >= sizeof(keyword_detector_chan->pre_detection_buffer_fp32) / sizeof(float)) {
      keyword_detector_chan->pd_index_write = 0;
   }
}

uint32_t xraudio_keyword_detector_session_pd_avail(xraudio_keyword_detector_t *detector, uint8_t active_chan) {
   return(detector->channels[active_chan].pd_sample_qty);
}

#endif

int xraudio_in_write_to_memory(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance) {
   uint8_t *frame_buffer      = NULL;
   uint32_t frame_size        = 0;
   uint8_t  frame_group_index = 0;
   if(source != instance->source) {
      XLOGD_DEBUG("different source is being recorded");
      return(0);
   }
   if(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(source) != XRAUDIO_DEVICE_INPUT_NONE) {
      // External source, set frame vars
      frame_buffer      = session->external_frame_buffer;
      frame_size        = session->external_frame_size_out;
      frame_group_index = session->external_frame_group_index;
   } else {
      uint8_t chan = 0;
      #if defined(XRAUDIO_KWD_ENABLED)
      if(params->dsp_config.input_asr_max_channel_qty == 0) {
         chan = session->keyword_detector.active_chan;
      }
      #endif

      // Local source, set frame vars
      frame_buffer      = (uint8_t *)&session->frame_buffer_int16[chan].frames[0];
      frame_size        = instance->frame_size_out;
      frame_group_index = session->frame_group_index;
   }

   if(frame_group_index >= instance->frame_group_qty) {
      if(instance->audio_buf_index + (frame_size * frame_group_index) > (instance->audio_buf_sample_qty * instance->format_out.sample_size * frame_group_index)) {
         XLOGD_DEBUG("End of buffer reached");

         if(instance->callback != NULL){
            (*instance->callback)(source, AUDIO_IN_CALLBACK_EVENT_END_OF_BUFFER, NULL, instance->param);
         }
         instance->audio_buf_samples    = NULL;
         instance->audio_buf_sample_qty = 0;
         instance->audio_buf_index      = 0;
      } else {
         unsigned long sample_index = instance->audio_buf_index / instance->format_out.sample_size;
         size_t            data_size  = frame_size * frame_group_index;
         xraudio_sample_t *samples    = (xraudio_sample_t *)frame_buffer;
         #ifdef XRAUDIO_DGA_ENABLED
         if(instance->dynamic_gain_set && params->dsp_config.dga_enabled) {
            uint8_t chan = 0;
            #if defined(XRAUDIO_KWD_ENABLED)
            if(params->dsp_config.input_asr_max_channel_qty == 0) {
               chan = session->keyword_detector.active_chan;
            }
            #endif
            float* frame_buffer_fp32 = &session->frame_buffer_fp32[chan].frames[0].samples[0];
            uint32_t sample_qty = data_size / sizeof(float);
            // Apply gain to group of audio frames
            xraudio_dga_apply(session->obj_dga, frame_buffer_fp32, sample_qty * frame_group_index);
            // Convert float to int16
            xraudio_samples_convert_fp32_int16(samples, frame_buffer_fp32, sample_qty * frame_group_index, instance->dynamic_gain_pcm_bit_qty);
         }
         #endif

         memcpy(&instance->audio_buf_samples[sample_index], samples, data_size);

         instance->audio_buf_index += (frame_size * frame_group_index);
      }
   }

   return(frame_size);
}

int xraudio_in_write_to_pipe(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance) {
   ssize_t rc   = 0;
   uint8_t chan = 0; // default to use first channel
   int16_t *frame_buffer_int16 = NULL;
   #ifdef XRAUDIO_DGA_ENABLED
   float *  frame_buffer_fp32  = NULL;
   #endif
   uint32_t frame_size_int16   = 0;
   uint8_t  frame_group_index  = 0;
   bool     flush_audio_data   = false;
   if((XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(source) != instance->source) && (XRAUDIO_DEVICE_INPUT_LOCAL_GET(source) != instance->source)) {
      XLOGD_WARN("different source <%s> is being recorded", xraudio_devices_input_str(instance->source));
      XLOGD_WARN("requested source <%s>", xraudio_devices_input_str(source));
      return(0);
   }
   #if defined(XRAUDIO_KWD_ENABLED)
   uint32_t bit_qty = session->pcm_bit_qty;
   #endif
   uint32_t group = xraudio_input_source_to_group(source);

   bool is_external = (XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(source) != XRAUDIO_DEVICE_INPUT_NONE);
   if(is_external) {
      // External source, set frame vars
      frame_buffer_int16 = (int16_t *)session->external_frame_buffer;
      frame_size_int16   = session->external_frame_size_out;
      frame_group_index  = session->external_frame_group_index;

      if(instance->keyword_flush) { // keyword was just passed
         flush_audio_data = true;
         instance->keyword_flush = false;
      }
   } else {
      #if defined(XRAUDIO_KWD_ENABLED)
      if(params->dsp_config.input_asr_max_channel_qty == 0) { // No ASR channel specified
         if(instance->keyword_triggered) { // instance was triggered by keyword detection
            // use the best "beam" output
            chan = session->keyword_detector.active_chan;
         } else if(session->devices_input & XRAUDIO_DEVICE_INPUT_TRI) { // input device is three microphone beams
            // use the center "beam" output
            chan = 1;
         }
      }
      #endif

      // Local source, set frame vars
      frame_buffer_int16 = &session->frame_buffer_int16[chan].frames[0].samples[0];
      #ifdef XRAUDIO_DGA_ENABLED
      frame_buffer_fp32  = &session->frame_buffer_fp32[chan].frames[0].samples[0];
      #endif
      frame_size_int16   = instance->frame_size_out;
      frame_group_index  = session->frame_group_index;
   }

   #ifdef XRAUDIO_KWD_ENABLED
   xraudio_keyword_detector_t *detector = &session->keyword_detector;

   if(instance->pre_detection_sample_qty > 0) { // Write pre-detection data to pipe
      float   *chunk_1_samples_fp32 = NULL;
      float   *chunk_2_samples_fp32 = NULL;
      uint32_t chunk_1_sample_qty   = 0;
      uint32_t chunk_2_sample_qty   = 0;

      if(!is_external) {
         xraudio_in_pre_detection_chunks(&detector->channels[detector->active_chan], instance->pre_detection_sample_qty, 0, &chunk_1_samples_fp32, &chunk_1_sample_qty, &chunk_2_samples_fp32, &chunk_2_sample_qty);
         XLOGD_DEBUG("chunk 1 %u chunk 2 %u", chunk_1_sample_qty, chunk_2_sample_qty);

         XLOGD_DEBUG("prepending keyword utterance from channel <%u> instance <%u> to stream", detector->active_chan, detector->active_chan - params->dsp_config.input_asr_max_channel_qty);

         if(chunk_1_sample_qty) {
            #ifdef XRAUDIO_DGA_ENABLED
            if(instance->dynamic_gain_set && params->dsp_config.dga_enabled) {
               xraudio_dga_apply(session->obj_dga, chunk_1_samples_fp32, chunk_1_sample_qty);
               bit_qty = instance->dynamic_gain_pcm_bit_qty;
            }
            #endif
            uint32_t size;
            void *chunk_1_samples = (void *)chunk_1_samples_fp32; // use same buffer
            if(instance->format_out.sample_size > 2) {
               xraudio_samples_convert_fp32_int32((int32_t *)chunk_1_samples, chunk_1_samples_fp32, chunk_1_sample_qty, bit_qty);
               size = chunk_1_sample_qty * sizeof(int32_t);
            } else {
               xraudio_samples_convert_fp32_int16((int16_t *)chunk_1_samples, chunk_1_samples_fp32, chunk_1_sample_qty, bit_qty);
               size = chunk_1_sample_qty * sizeof(int16_t);
            }
            for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
               if(instance->fifo_audio_data[index] < 0) {
                  break;
               }
               errno = 0;
               rc = write(instance->fifo_audio_data[index], chunk_1_samples, size);
               if(rc != (int)size) {
                  int errsv = errno;
                  if(errsv == EAGAIN || errsv == EWOULDBLOCK) { // Data is lost due to insufficient space in the pipe
                     if(instance->callback != NULL){
                        (*instance->callback)(source, AUDIO_IN_CALLBACK_EVENT_OVERFLOW, NULL, instance->param);
                     }
                  } else {
                     XLOGD_TELEMETRY("unable to write fifo <%d> <%s>", instance->fifo_audio_data[index], strerror(errsv));
                  }
               }
            }
            if(session->capture_session.active && session->capture_session.output[group].file.fd >= 0) {
               int rc_cap = -1;
               if(session->capture_session.output[group].file.format.sample_size > 2) {
                  rc_cap = xraudio_in_capture_session_to_file_int32(&session->capture_session.output[group], (int32_t *)chunk_1_samples, chunk_1_sample_qty);
               } else {
                  rc_cap = xraudio_in_capture_session_to_file_int16(&session->capture_session.output[group], (int16_t *)chunk_1_samples, chunk_1_sample_qty);
               }
               if(rc_cap < 0) {
                  session->capture_session.active = false;
               }
            }
            if(instance->capture_internal.active) {
               int rc_cap = xraudio_in_capture_internal_to_file(session, (uint8_t *)chunk_1_samples, size, &instance->capture_internal.native);
               if(rc_cap < 0) {
                  xraudio_in_capture_internal_end(&instance->capture_internal);
               }
            }
         }
         if(chunk_2_sample_qty) {
            #ifdef XRAUDIO_DGA_ENABLED
            if(instance->dynamic_gain_set && params->dsp_config.dga_enabled) {
               xraudio_dga_apply(session->obj_dga, chunk_2_samples_fp32, chunk_2_sample_qty);
               bit_qty = instance->dynamic_gain_pcm_bit_qty;
            }
            #endif
            uint32_t size;
            void *chunk_2_samples = (void *)chunk_2_samples_fp32; // use same buffer
            if(instance->format_out.sample_size > 2) {
               xraudio_samples_convert_fp32_int32((int32_t *)chunk_2_samples, chunk_2_samples_fp32, chunk_2_sample_qty, bit_qty);
               size = chunk_2_sample_qty * sizeof(int32_t);
            } else {
               xraudio_samples_convert_fp32_int16((int16_t *)chunk_2_samples, chunk_2_samples_fp32, chunk_2_sample_qty, bit_qty);
               size = chunk_2_sample_qty * sizeof(int16_t);
            }
            for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
               if(instance->fifo_audio_data[index] < 0) {
                  break;
               }
               errno = 0;
               rc = write(instance->fifo_audio_data[index], chunk_2_samples, size);
               if(rc != (int)size) {
                  int errsv = errno;
                  if(errsv == EAGAIN || errsv == EWOULDBLOCK) { // Data is lost due to insufficient space in the pipe
                     if(instance->callback != NULL){
                        (*instance->callback)(source, AUDIO_IN_CALLBACK_EVENT_OVERFLOW, NULL, instance->param);
                     }
                  } else {
                     XLOGD_TELEMETRY("unable to write fifo <%d> <%s>", instance->fifo_audio_data[index], strerror(errsv));
                  }
               }
            }
            if(session->capture_session.active && session->capture_session.output[group].file.fd >= 0) {
               int rc_cap = -1;
               if(session->capture_session.output[group].file.format.sample_size > 2) {
                  rc_cap = xraudio_in_capture_session_to_file_int32(&session->capture_session.output[group], (int32_t *)chunk_2_samples, chunk_2_sample_qty);
               } else {
                  rc_cap = xraudio_in_capture_session_to_file_int16(&session->capture_session.output[group], (int16_t *)chunk_2_samples, chunk_2_sample_qty);
               }
               if(rc_cap < 0) {
                  session->capture_session.active = false;
               }
            }
            if(instance->capture_internal.active) {
               int rc_cap = xraudio_in_capture_internal_to_file(session, (uint8_t *)chunk_2_samples, size, &instance->capture_internal.native);
               if(rc_cap < 0) {
                  xraudio_in_capture_internal_end(&instance->capture_internal);
               }
            }
         }

         instance->stats.packets_processed = 1; // keyword counts as 1 packet
         instance->stats.samples_processed = instance->pre_detection_sample_qty;

         instance->pre_detection_sample_qty = 0;
      }
   }
   #endif

   if(!is_external) { // increment session stats for internal source
      instance->stats.packets_processed++;
      instance->stats.samples_processed += (frame_size_int16 / sizeof(int16_t));

      if((instance->stream_time_min_value > 0) && (instance->stats.samples_processed >= instance->stream_time_min_value)) {
         if(instance->callback) {
            (*instance->callback)(instance->source, AUDIO_IN_CALLBACK_EVENT_STREAM_TIME_MINIMUM, NULL, instance->param);
         }
         instance->stream_time_min_value = 0;
      }

      if((instance->keyword_end_samples > 0) && (instance->stats.samples_processed >= instance->keyword_end_samples)) {
         if(instance->callback != NULL) {
            xraudio_stream_keyword_info_t kwd_info;
            kwd_info.byte_qty = instance->keyword_end_samples;
            (*instance->callback)(instance->source, AUDIO_IN_CALLBACK_EVENT_STREAM_KWD_INFO, &kwd_info, instance->param);
         }
         instance->keyword_end_samples = 0;
         instance->keyword_flush       = true;
      }
   }

   if(frame_group_index >= instance->frame_group_qty || flush_audio_data) {
      #ifdef XRAUDIO_KWD_ENABLED
      if(instance->format_out.encoding.type == XRAUDIO_ENCODING_PCM_RAW && instance->raw_mic_frame_skip > 0) {
         instance->raw_mic_frame_skip--;
      } else 
      #endif
      {
         size_t data_size;
         void * data_ptr;

         if(instance->format_out.encoding.type == XRAUDIO_ENCODING_PCM_RAW) {
            data_size = session->hal_mic_frame_size;
            data_ptr  = session->hal_mic_frame_ptr;
         } else if(instance->format_out.encoding.type == XRAUDIO_ENCODING_PCM && instance->format_out.sample_size == 4) { // 32-bit PCM
            if(instance->format_out.channel_qty > 1) { // All channels
               data_size = session->hal_mic_frame_size;
               data_ptr  = session->hal_mic_frame_ptr;
            } else { // Single channel
               data_size = instance->frame_size_out;
               data_ptr  = &session->hal_mic_frame_ptr[data_size * chan];
            }
         } else {
            data_size = frame_size_int16 * frame_group_index;
            data_ptr  = frame_buffer_int16;

            #ifdef XRAUDIO_DGA_ENABLED
            if(!is_external && instance->dynamic_gain_set && params->dsp_config.dga_enabled) {
               uint32_t sample_qty = data_size / sizeof(int16_t);
               float frame_buffer_temp[sample_qty];

               // make a copy of the audio because dga will modify the audio, and it's still needed for later stages
               for(uint32_t index = 0; index < sample_qty; index++) {
                  frame_buffer_temp[index] = frame_buffer_fp32[index];
               }
               // Apply gain to group of audio frames
               xraudio_dga_apply(session->obj_dga, frame_buffer_temp, sample_qty);
               // Convert float to int16
               xraudio_samples_convert_fp32_int16(frame_buffer_int16, frame_buffer_temp, sample_qty, instance->dynamic_gain_pcm_bit_qty);
            }
            #endif
         }

         for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
            //XLOGD_DEBUG("streaming channel %d", chan);
            if(instance->fifo_audio_data[index] < 0) {
               break;
            }
            //XLOGD_INFO("src <%s> pipe <%d> size <%u> hal_mic_frame_size <%u> frame_size_out <%u>", xraudio_devices_input_str(source), instance->fifo_audio_data[index], data_size, session->hal_mic_frame_size, instance->frame_size_out);
            errno = 0;
            rc = write(instance->fifo_audio_data[index], data_ptr, data_size);

            if(rc != (int)(data_size)) {
               int errsv = errno;
               if(errsv == EAGAIN || errsv == EWOULDBLOCK) {
                  // Data is lost due to insufficient space in the pipe
                  rc = 0;
                  if(instance->callback != NULL){
                     (*instance->callback)(source, AUDIO_IN_CALLBACK_EVENT_OVERFLOW, NULL, instance->param);
                  }
               } else {
                  XLOGD_ERROR("unable to write fifo %d <%s>", instance->fifo_audio_data[index], strerror(errsv));
               }
            } else if(flush_audio_data && instance->stream_until[index] == XRAUDIO_INPUT_RECORD_UNTIL_END_OF_KEYWORD) {
               if(instance->fifo_audio_data[index] >= 0) { // Close the write side of the pipe so the read side gets EOF
                  XLOGD_DEBUG("Close write side of pipe to send EOF to read side");
                  close(instance->fifo_audio_data[index]);
                  instance->fifo_audio_data[index] = -1;
               }
               instance->stream_until[index] = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
            }
         }
         if(session->capture_session.active && session->capture_session.output[group].file.fd >= 0) {
            uint8_t sample_size  = session->capture_session.output[group].file.format.sample_size;
            uint32_t sample_qty  = (sample_size > 2 ? data_size / sizeof(int32_t) : data_size / sizeof(int16_t));
            int rc_cap;
            if(sample_size > 2) {
               rc_cap = xraudio_in_capture_session_to_file_int32(&session->capture_session.output[group], data_ptr, sample_qty);
            } else {
               rc_cap = xraudio_in_capture_session_to_file_int16(&session->capture_session.output[group], data_ptr, sample_qty);
            }
            if(rc_cap < 0) {
               session->capture_session.active = false;
            }
         }

         if(instance->capture_internal.active && !is_external) {
            int rc_cap = xraudio_in_capture_internal_to_file(session, (uint8_t *)data_ptr, data_size, &instance->capture_internal.native);
            if(rc_cap < 0) {
               xraudio_in_capture_internal_end(&instance->capture_internal);
            }
         }
      }
   }

   return(rc);
}

int xraudio_in_write_to_user(xraudio_devices_input_t source, xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_session_record_inst_t *instance) {
   int rc = 0;
   uint8_t *frame_buffer      = NULL;
   uint8_t  frame_group_index = 0;
   uint32_t sample_qty        = 0;
   if(source != instance->source) {
      XLOGD_DEBUG("different source is being recorded");
      return(0);
   }

   if(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(source) != XRAUDIO_DEVICE_INPUT_NONE) {
      // External source, set frame vars
      frame_buffer      = session->external_frame_buffer;
      frame_group_index = session->external_frame_group_index;
      sample_qty        = session->external_frame_size_out;
   } else {
      uint8_t chan = 0;
      #if defined(XRAUDIO_KWD_ENABLED)
      if(params->dsp_config.input_asr_max_channel_qty == 0) {
         chan = session->keyword_detector.active_chan;
      }
      #endif

      // Local source, set frame vars
      frame_buffer      = (uint8_t *)&session->frame_buffer_int16[chan].frames[0];
      frame_group_index = session->frame_group_index;
      sample_qty        = session->frame_sample_qty;
   }

   if(frame_group_index >= instance->frame_group_qty) {
      errno = 0;
      xraudio_sample_t *samples = (xraudio_sample_t *)frame_buffer;
      #ifdef XRAUDIO_DGA_ENABLED
      if(instance->dynamic_gain_set && params->dsp_config.dga_enabled) {
         uint8_t chan = 0;
         #if defined(XRAUDIO_KWD_ENABLED)
         if(params->dsp_config.input_asr_max_channel_qty == 0) {
            chan = session->keyword_detector.active_chan;
         }
         #endif
         float* frame_buffer_fp32 = &session->frame_buffer_fp32[chan].frames[0].samples[0];
         // Apply gain to group of audio frames
         xraudio_dga_apply(session->obj_dga, frame_buffer_fp32, sample_qty * frame_group_index);
         // Convert float to int16
         xraudio_samples_convert_fp32_int16(samples, frame_buffer_fp32, sample_qty * frame_group_index, instance->dynamic_gain_pcm_bit_qty);
      }
      #endif

      rc = (*instance->data_callback)(source, samples, sample_qty * frame_group_index, instance->param);
   }

   return(rc);
}

#ifdef XRAUDIO_KWD_ENABLED
void xraudio_in_sound_intensity_transfer(xraudio_main_thread_params_t *params, xraudio_session_record_t *session) {
   for(uint32_t group = XRAUDIO_INPUT_SESSION_GROUP_DEFAULT; group < XRAUDIO_INPUT_SESSION_GROUP_QTY; group++) {
      xraudio_session_record_inst_t *instance = &session->instances[group];

      if(instance->fifo_sound_intensity < 0) {
         continue;
      }
      uint16_t buf[2];
      uint8_t active_chan = 0;

      #if defined(XRAUDIO_KWD_ENABLED)
      if(params->dsp_config.input_asr_max_channel_qty == 0) {
         active_chan = session->keyword_detector.active_chan;
      }
      #endif
      #ifdef MICROPHONE_TAP_ENABLED
      if(group == XRAUDIO_INPUT_SESSION_GROUP_MIC_TAP) {
         active_chan = XRAUDIO_INPUT_BEAM_INDEX_CENTER; // default to center channel for MIC TAP
      }
      #endif

      uint16_t intensity = xraudio_input_signal_level_get(params->obj_input, active_chan);
      uint16_t direction = xraudio_input_signal_direction_get(params->obj_input);

      //XLOGD_DEBUG("intensity %u%% %f sum %llu sample qty %lu", intensity, mean_intensity, sum, session->sample_qty);

      // Write to fifo (use host endianness)
      buf[0] = intensity;
      buf[1] = direction;

      errno = 0;
      ssize_t rc = write(instance->fifo_sound_intensity, buf, sizeof(buf));
      if ((rc != sizeof(buf)) && (errno != EWOULDBLOCK)) {
         int errsv = errno;
         XLOGD_ERROR("unable to write fifo %d <%s> : error  %d", instance->fifo_sound_intensity, strerror(errsv), errsv);
      }
   }
}
#endif

#ifdef XRAUDIO_KWD_ENABLED
void xraudio_keyword_detector_init(xraudio_keyword_detector_t *detector, json_t *jkwd_config) {
   XLOGD_DEBUG("");
   detector->kwd_object                = xraudio_kwd_object_create(jkwd_config);
   detector->sensitivity               = 0.0;
   detector->active                    = false;
   detector->triggered                 = false;
   detector->post_frame_count_trigger  = 0;
   detector->post_frame_count_callback = 0;
   detector->active_chan               = 0;
   detector->single_channel            = XRAUDIO_INPUT_BEAM_INDEX_NONE;
   detector->callback                  = NULL;
   detector->cb_param                  = NULL;
   detector->result.chan_selected      = detector->input_kwd_max_channel_qty;
   detector->criterion                 = XRAUDIO_KWD_CRITERION_INVALID;

   for(uint8_t chan = 0; chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY; chan++) {
      detector->result.channels[chan].score        = -1.0;
      detector->result.channels[chan].snr          =  0.0;
      detector->result.channels[chan].doa          =    0;
      detector->result.channels[chan].dynamic_gain =  0.0;

      if(chan < detector->input_asr_kwd_channel_qty) {
         xraudio_keyword_detector_chan_t *channel = &detector->channels[chan];
         channel->triggered                        = false;
         channel->score                            = 0.0;
         channel->snr                              = 0.0;
         channel->endpoints.valid                  = false;
         channel->endpoints.pre                    = 0;
         channel->endpoints.begin                  = 0;
         channel->endpoints.end                    = 0;
         channel->endpoints.end_of_wuw_ext_enabled = false;
         channel->endpoints.kwd_gain               = 0.0;
         channel->pd_sample_qty                    = 0;
         channel->pd_index_write                   = 0;
         channel->post_frame_count                 = 0;
         memset(channel->pre_detection_buffer_fp32, 0, sizeof(channel->pre_detection_buffer_fp32));
      }
   }
}

void xraudio_keyword_detector_term(xraudio_keyword_detector_t *detector) {
   if(detector->kwd_object != NULL) {
      xraudio_kwd_object_destroy(detector->kwd_object);
      detector->kwd_object = NULL;
   }
}

void xraudio_keyword_detector_session_init(xraudio_keyword_detector_t *detector, uint8_t chan_qty, xraudio_keyword_sensitivity_t sensitivity) {
   XLOGD_DEBUG("");
   if(detector == NULL) {
      XLOGD_ERROR("Invalid parameters");
      return;
   }
   detector->active                    = true;
   detector->triggered                 = false;
   detector->sensitivity               = sensitivity;
   detector->post_frame_count_trigger  = 0;
   detector->post_frame_count_callback = 0;
   detector->active_chan               = 0;
   detector->callback                  = NULL;
   detector->cb_param                  = NULL;
   detector->result.chan_selected      = detector->input_kwd_max_channel_qty;
   if(chan_qty > detector->input_kwd_max_channel_qty) {
      XLOGD_INFO("kwd instances <%u> requested more than max kwd instances <%u> allowed", chan_qty, detector->input_kwd_max_channel_qty);
      chan_qty = detector->input_kwd_max_channel_qty;
   }

   XLOGD_INFO("init <%u> kwd instances", chan_qty);

   if(chan_qty==0) {
      return;
   }

   for(uint8_t chan = 0; chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY; chan++) {
      detector->result.channels[chan].score        = -1.0;
      detector->result.channels[chan].snr          =  0.0;
      detector->result.channels[chan].doa          =    0;
      detector->result.channels[chan].dynamic_gain =  0.0;

      if(chan < detector->input_asr_kwd_channel_qty) {
         xraudio_keyword_detector_chan_t *detector_chan = &detector->channels[chan];
         detector_chan->triggered                        = false;
         detector_chan->score                            = 0.0;
         detector_chan->snr                              = 0.0;
         detector_chan->endpoints.valid                  = false;
         detector_chan->endpoints.pre                    = 0;
         detector_chan->endpoints.begin                  = 0;
         detector_chan->endpoints.end                    = 0;
         detector_chan->endpoints.end_of_wuw_ext_enabled = false;
         detector_chan->endpoints.kwd_gain               = 0.0;
         detector_chan->pd_sample_qty                    = 0;
         detector_chan->pd_index_write                   = 0;
         detector_chan->post_frame_count                 = 0;
         memset(detector_chan->pre_detection_buffer_fp32, 0, sizeof(detector_chan->pre_detection_buffer_fp32));
      }
   }

   if(!xraudio_kwd_init(detector->kwd_object, chan_qty, sensitivity, NULL, &detector->criterion)) {
      XLOGD_ERROR("kwd init failed");
   }
}

bool xraudio_keyword_detector_session_is_active(xraudio_keyword_detector_t *detector) {
   return(detector->active);
}

void xraudio_keyword_detector_session_term(xraudio_keyword_detector_t *detector) {
   XLOGD_DEBUG("release memory");
   if(detector == NULL) {
      XLOGD_ERROR("Invalid parameters");
      return;
   }
   detector->active   = false;
   detector->callback = NULL;
   detector->cb_param = NULL;

   xraudio_kwd_term(detector->kwd_object);
}
#endif

void xraudio_keyword_detector_session_disarm(xraudio_keyword_detector_t *detector) {
   detector->callback          = NULL;
   detector->cb_param          = NULL;
   #ifdef XRAUDIO_KWD_ENABLED
   detector->triggered         = false;
   XLOGD_DEBUG("");

   for(uint8_t chan = 0; chan < detector->input_asr_kwd_channel_qty; chan++) {
      xraudio_keyword_detector_chan_t *detector_chan = &detector->channels[chan];
      detector_chan->triggered        = false;
      detector_chan->score            = 0.0;
      detector_chan->snr              = 0.0;
      detector_chan->endpoints.valid  = false;
      detector_chan->endpoints.pre    = 0;
      detector_chan->endpoints.begin  = 0;
      detector_chan->endpoints.end    = 0;

      detector_chan->post_frame_count = 0;
   }
   #endif
}

void xraudio_keyword_detector_session_arm(xraudio_keyword_detector_t *detector, keyword_callback_t callback, void *cb_param, xraudio_keyword_sensitivity_t sensitivity) {
   detector->callback                  = callback;
   detector->cb_param                  = cb_param;
   detector->result.chan_selected      = detector->input_kwd_max_channel_qty;
   #ifdef XRAUDIO_KWD_ENABLED
   detector->triggered                 = false;
   detector->post_frame_count_trigger  = 0;
   detector->post_frame_count_callback = 0;
   XLOGD_DEBUG("");

   // Do NOT reset active channel since it may be used by subsequent audio streams in the same session
   // detector->active_chan               = 0;

   for(uint8_t chan = 0; chan < XRAUDIO_INPUT_MAX_CHANNEL_QTY; chan++) {
      detector->result.channels[chan].score        = -1.0;
      detector->result.channels[chan].snr          =  0.0;
      detector->result.channels[chan].doa          =    0;
      detector->result.channels[chan].dynamic_gain =  0.0;

      if(chan < detector->input_asr_kwd_channel_qty) {
         xraudio_keyword_detector_chan_t *detector_chan = &detector->channels[chan];
         detector_chan->triggered            = false;
         detector_chan->score                = 0.0;
         detector_chan->snr                  = 0.0;
         detector_chan->endpoints.valid      = false;
         detector_chan->endpoints.pre        = 0;
         detector_chan->endpoints.begin      = 0;
         detector_chan->endpoints.end        = 0;
         detector_chan->endpoints.kwd_gain   = 0.0;

         detector_chan->post_frame_count = 0;
      }
   }

   if(detector->sensitivity != sensitivity) {
      XLOGD_INFO("update sensitivity <%f>", sensitivity);
      if(!xraudio_kwd_update(detector->kwd_object, sensitivity)) {
         XLOGD_ERROR("kwd update failed");
      } else {
         detector->sensitivity = sensitivity;
      }
   }
   #endif
}

bool xraudio_keyword_detector_session_is_armed(xraudio_keyword_detector_t *detector) {
   return((detector->callback != NULL) ? true : false);
}

#ifdef XRAUDIO_KWD_ENABLED
void xraudio_keyword_detector_session_event(xraudio_keyword_detector_t *detector, xraudio_devices_input_t source, const uuid_t *uuid, keyword_callback_event_t event, xraudio_keyword_detector_result_t *detector_result, xraudio_input_format_t format) {
   xraudio_devices_input_t current_source = xraudio_in_session_group_source_get(XRAUDIO_INPUT_SESSION_GROUP_DEFAULT);

   if(!xraudio_keyword_detector_session_is_armed(detector)) {
      XLOGD_ERROR("detector is not armed");
      return;
   }
   if(((uint32_t)event) > KEYWORD_CALLBACK_EVENT_ERROR) {
      XLOGD_ERROR("invalid event <%s>", keyword_callback_event_str(event));
      return;
   }

   if(event == KEYWORD_CALLBACK_EVENT_DETECTED && current_source != source) {
      XLOGD_ERROR("source <%s> does not own the session", xraudio_devices_input_str(source));
      return;
   }

   detector->callback(source, uuid, event, detector->cb_param, detector_result, format);
   xraudio_keyword_detector_session_disarm(detector);
}
#endif

void xraudio_eos_detector_init(xraudio_eos_detector_t *detector) {
   detector->single_channel = XRAUDIO_INPUT_BEAM_INDEX_NONE;
}

void xraudio_eos_detector_term(xraudio_eos_detector_t *detector) {
}

#ifdef XRAUDIO_OUTPUT_ENABLED
void xraudio_process_spkr_data(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size, unsigned long *timeout, rdkx_timestamp_t *timestamp_sync) {
   int rc = -1;
   if(session->hal_output_obj == NULL) { // speaker not open
      *timeout = 0;
      return;
   }

   if(!session->playing) {
      session->playing = true;
   }
   if(session->mode_changed) {
      #ifdef MASK_FIRST_WRITE_DELAY
      if(!session->first_write_complete) {
         // Deal with long delay in first call to qahw_out_write (several hundred milliseconds)
         if(!session->first_write_pending && !session->first_write_thread.running) {
            g_thread_params_write.params  = params;
            g_thread_params_write.session = session;

            session->first_write_pending = true;

            // Perform first write (of silence) in a separate thread
            if(!xraudio_thread_create(&session->first_write_thread, "xraudio_1st_wr", xraudio_thread_first_write, &g_thread_params_write)) {
               XLOGD_ERROR("unable to launch thread");
            }
            rdkx_timestamp_get(&session->timestamp_next); // Mark starting timestamp
         }

         if(session->first_write_pending) { // the first call to qahw_out_write has not completed yet
            if(timestamp_sync != NULL) { // Sync time with mic
               session->timestamp_next = *timestamp_sync;
            } else {
               // Add the timeout interval to determine the next timestamp
               rdkx_timestamp_add_us(&session->timestamp_next, session->timeout);
            }
            // Calculate the amount of time until next chunk in microseconds
            uint32_t until = rdkx_timestamp_until_us(session->timestamp_next);
            if(until == 0) {
               *timeout = 1;
            } else {
               *timeout = until;
            }
            return;
         } else if(session->first_write_thread.running) {
            xraudio_thread_join(&session->first_write_thread);
            session->first_write_complete = true;
         }
      }
      #endif

      if(timestamp_sync == NULL) { // not syncing time with mic
         rdkx_timestamp_get(&session->timestamp_next); // Mark starting timestamp
      }

      if(session->callback != NULL){
         (*session->callback)(AUDIO_OUT_CALLBACK_EVENT_FIRST_FRAME, session->param);
      }
      session->mode_changed = false;
   }

   if(session->fd >= 0) { // Playback from file
      rc = xraudio_out_write_from_file(params, session, frame_size);
   } else if(session->audio_buf != NULL && session->audio_buf_size > 0) { // Playback from memory
      rc = xraudio_out_write_from_memory(params, session, frame_size);
   } else if(session->pipe_audio_data >= 0) { // Playback from pipe
      rc = xraudio_out_write_from_pipe(params, session, frame_size);
   } else if(session->data_callback != NULL) { // Playback from user
      rc = xraudio_out_write_from_user(params, session, frame_size);
   } else if(session->hal_output_obj != NULL) { // Playback silence
      rc = xraudio_out_write_silence(params, session, frame_size);
   } else { // speaker not open
      *timeout = 0;
      return;
   }

   if(rc == 0) {
      // Clear timeout
      *timeout = 0;
      XLOGD_DEBUG("EOF");
   } else if(rc < 0) {
      // Clear timeout
      *timeout = 0;
      XLOGD_ERROR("Error (%d)", rc);
   } else {
      if(timestamp_sync != NULL) { // Sync time with mic
         session->timestamp_next = *timestamp_sync;
      } else {
         // Add the timeout interval to determine the next timestamp
         rdkx_timestamp_add_us(&session->timestamp_next, session->timeout);
      }
      // Calculate the amount of time until next chunk in microseconds
      unsigned long until = rdkx_timestamp_until_us(session->timestamp_next);
      if(until == 0) {
         *timeout = 1;
      } else {
         *timeout = until;
      }
   }

   if(rc <= 0) { // Session ended, notify
      if(session->synchronous) {
         if(session->semaphore == NULL) {
            XLOGD_ERROR("synchronous playback with no semaphore set!");
         } else {
            sem_post(session->semaphore);
            session->semaphore = NULL;
         }
      } else if(session->callback != NULL){
         (*session->callback)(rc < 0 ? AUDIO_OUT_CALLBACK_EVENT_ERROR : AUDIO_OUT_CALLBACK_EVENT_EOF, session->param);
      }
   }
}

#ifdef MASK_FIRST_WRITE_DELAY
void *xraudio_thread_first_write(void *param) {
   xraudio_thread_first_write_params_t params = *((xraudio_thread_first_write_params_t *)param);

   #if 0
   rdkx_timestamp_t start, finish;
   rdkx_timestamp_get(&start);
   #endif
   // Perform first write
   xraudio_out_write_silence(params.params, params.session, params.session->frame_size);

   #if 0
   rdkx_timestamp_get(&finish);
   XLOGD_INFO("write silence end %lld us frame size %u", rdkx_timestamp_subtract_us(start, finish), params.session->frame_size);
   #endif
   // Send message to signal completion
   params.session->first_write_pending = false;
   return(NULL);
}
#endif
#endif

#ifdef MASK_FIRST_READ_DELAY
void *xraudio_thread_first_read(void *param) {
   xraudio_thread_first_read_params_t params = *((xraudio_thread_first_read_params_t *)param);

   #if 0
   rdkx_timestamp_t start, finish;
   rdkx_timestamp_get(&start);
   #endif
   // Perform first read
   uint8_t  mic_frame_data[XRAUDIO_INPUT_FRAME_SIZE_MAX];
   uint32_t mic_frame_size;

   xraudio_devices_input_t device_input_local = XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input);
   xraudio_devices_input_t device_input_ecref = XRAUDIO_DEVICE_INPUT_EC_REF_GET(session->devices_input);

   uint8_t chan_qty_mic   = (device_input_local == XRAUDIO_DEVICE_INPUT_QUAD) ? 4 : (device_input_local == XRAUDIO_DEVICE_INPUT_TRI) ? 3 : 1;
   uint8_t chan_qty_ecref = (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_5_1) ? 6 : (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_STEREO) ? 2 : (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_MONO) ? 1 : 0;

   mic_frame_size = (chan_qty_mic + chan_qty_ecref) * params.session->frame_size_in;  // normal frame @ 16kHz = 640 bytes. compressed frame @ 48kHz = 2560 bytes

   xraudio_hal_input_read(params.params->hal_input_obj, mic_frame_data, mic_frame_size, NULL);

   #if 0
   rdkx_timestamp_get(&finish);
   XLOGD_INFO("read end %lld us frame size %u", rdkx_timestamp_subtract_us(start, finish), params.session->frame_size);
   #endif
   // Send message to signal completion
   params.session->first_read_pending = false;
   return(NULL);
}
#endif

#ifdef XRAUDIO_OUTPUT_ENABLED
int xraudio_out_write_from_file(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size) {
   int rc = 0;

   if(frame_size > sizeof(session->frame_buffer)) {
      XLOGD_ERROR("frame size too big! frame size %lu frame buffer size %zu", frame_size, sizeof(session->frame_buffer));
      return(-1);
   }

   // Read requested size into buffer
   errno = 0;
   ssize_t bytes_read = read(session->fd, session->frame_buffer, frame_size);
   bool    eof        = false;

   if(bytes_read != frame_size) {
      if(bytes_read == 0) { // End of file reached
         XLOGD_DEBUG("EOF");
         eof = true;
      } else { // Error occurred
         int errsv = errno;
         XLOGD_ERROR("Error (%zd) <%s>", bytes_read, strerror(errsv));
         return(-1);
      }
   }

   if(bytes_read > 0) {
      rc = xraudio_out_write_hal(params, session, session->frame_buffer, bytes_read);
   }

   if(eof) {
      // Remove fd so that no further reads occur
      session->fd = -1;
   }

   return(eof ? 0 : rc);
}

int xraudio_out_write_from_memory(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size) {
   size_t bytes_read = frame_size;
   bool eof = false;

   if(session->audio_buf_index + frame_size >= session->audio_buf_size) {
      bytes_read = session->audio_buf_size - session->audio_buf_index;
      XLOGD_DEBUG("EOF");
      eof = true;
   }

   // Copy to frame buffer so we can apply volume control
   memcpy(session->frame_buffer, &session->audio_buf[session->audio_buf_index], bytes_read);

   int rc = xraudio_out_write_hal(params, session, session->frame_buffer, bytes_read);

   session->audio_buf_index += bytes_read;

   if(eof) {
      session->audio_buf      = NULL;
      session->audio_buf_size = 0;
   }

   return(eof ? 0 : rc);
}

int xraudio_out_write_from_pipe(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size) {
   bool eof = false;

   // TODO need to read with timeout until next frame start time

   errno = 0;
   int rc = read(session->pipe_audio_data, session->frame_buffer, frame_size);
   if(rc != (int)frame_size) {
      int errsv = errno;
      if(rc == 0) { // EOF
         XLOGD_DEBUG("EOF");
         eof = true;
         // Fill the frame with silence
         memset(session->frame_buffer, 0, frame_size);
      } else if(rc < 0) {
         if(errsv == EAGAIN || errsv == EWOULDBLOCK) { // No data available
            // Fill the frame with silence
            memset(session->frame_buffer, 0, frame_size);
            if(session->callback != NULL){
               (*session->callback)(AUDIO_OUT_CALLBACK_EVENT_UNDERFLOW, session->param);
            }
         } else {
            XLOGD_ERROR("unable to read from pipe %d <%s>", rc, strerror(errsv));
            return(-1);
         }
      } else if(rc > (int)frame_size) {
         XLOGD_ERROR("too much data read from pipe %d", rc);
         return(-1);
      } else { // Partial data
         XLOGD_DEBUG("partial data read from pipe %d", rc);

         // Fill the rest of the frame with silence
         memset(&session->frame_buffer[rc], 0, frame_size - rc);
      }
   }

   rc = xraudio_out_write_hal(params, session, session->frame_buffer, frame_size);

   session->audio_buf_index += frame_size;

   if(eof) {
      session->pipe_audio_data = -1;
   }

   return(eof ? 0 : rc);
}

int xraudio_out_write_from_user(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size) {
   bool eof = false;

   // TODO need to read with timeout until next frame start time

   unsigned long samples_size = frame_size / sizeof(xraudio_sample_t);
   int rc = (*session->data_callback)((xraudio_sample_t *)session->frame_buffer, samples_size, session->param);
   if(rc != (int)samples_size) {
      if(rc == 0) { // EOF
         XLOGD_DEBUG("EOF");
         eof = true;
         // Fill the frame with silence
         memset(session->frame_buffer, 0, frame_size);
      } else if(rc < 0) {
         XLOGD_ERROR("unable to read from user %d", rc);
         return(-1);
      } else if(rc > (int)samples_size) {
         XLOGD_ERROR("too much data read from user %d", rc);
         return(-1);
      } else { // Partial data
         XLOGD_DEBUG("partial data read from user %d", rc);

         // Fill the rest of the frame with silence
         unsigned long offset = rc * sizeof(xraudio_sample_t);
         memset(&session->frame_buffer[offset], 0, frame_size - offset);
      }
   }

   rc = xraudio_out_write_hal(params, session, session->frame_buffer, frame_size);

   session->audio_buf_index += frame_size;

   if(eof) {
      session->pipe_audio_data = -1;
   }

   return(eof ? 0 : rc);
}
int xraudio_out_write_silence(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned long frame_size) {

   if(frame_size == 0 || frame_size > sizeof(g_frame_silence)) {
      XLOGD_ERROR("invalid frame size! frame size %lu frame buffer size %zu", frame_size, sizeof(g_frame_silence));
      return(-1);
   }

   return(xraudio_out_write_hal(params, session, g_frame_silence, frame_size));
}

int xraudio_out_write_hal(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session, unsigned char *buffer, unsigned long frame_size) {
   // Provide PCM data to the EOS algorithm to calculate sound intensity
   xraudio_output_eos_run(params->obj_output, (int16_t *)buffer, frame_size / sizeof(xraudio_sample_t));

   int32_t chans = (int32_t)session->format.channel_qty;
   xraudio_output_volume_gain_apply(params->obj_output, buffer, frame_size, chans);

   int rc = xraudio_hal_output_write(session->hal_output_obj, buffer, frame_size);
   if(rc < 0) {
      XLOGD_ERROR("Audio out write failed %d stream handle %p", rc, session->hal_output_obj);
   } else if(rc < (int)frame_size) {
      XLOGD_WARN("Audio out write partial data (%d, %lu)", rc, frame_size);
   }


   xraudio_out_sound_intensity_transfer(params, session);
   return(rc);
}

void xraudio_out_sound_intensity_transfer(xraudio_main_thread_params_t *params, xraudio_session_playback_t *session) {
   if(session->fifo_sound_intensity < 0) {
      return;
   }
   uint16_t buf[2];
   uint16_t intensity = xraudio_output_signal_level_get(params->obj_output);
   uint16_t direction = 0;

   //XLOGD_DEBUG("intensity %u%% %f sum %llu sample qty %lu", intensity, mean_intensity, sum, sample_qty);

   // Write to fifo (use host endianness)
   buf[0] = intensity;
   buf[1] = direction;

   errno = 0;
   ssize_t rc = write(session->fifo_sound_intensity, buf, sizeof(buf));
   if(rc != sizeof(buf)) {
      int errsv = errno;
      XLOGD_ERROR("unable to write fifo %d <%s>", rc, strerror(errsv));
   }
}
#endif

void xraudio_record_container_process_begin(xraudio_capture_file_t *capture_file) {
   capture_file->has_header = false;
   switch(capture_file->format.container) {
      case XRAUDIO_CONTAINER_WAV: {
         // Write space for the wave header (need to know pcm data size so generate at the end of recording)
         uint8_t header[WAVE_HEADER_SIZE_MIN];
         memset(header, 0, WAVE_HEADER_SIZE_MIN);

         errno = 0;
         ssize_t bytes_written = write(capture_file->fd, header, sizeof(header));
         if(bytes_written != sizeof(header)) {
            int errsv = errno;
            XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
            break;
         }
         capture_file->has_header = true;
         break;
      }
      default: {
         break;
      }
   }
}

void xraudio_record_container_process_end(int fd, xraudio_input_format_t format, unsigned long audio_data_size, bool header_truncated) {
   switch(format.container) {
      case XRAUDIO_CONTAINER_WAV: {
         // Write wave header
         int rc = lseek(fd, 0, SEEK_SET);
         if(rc) {
            int errsv = errno;
            XLOGD_ERROR("Seek <%s>", strerror(errsv));
         } else {
            uint8_t header[WAVE_HEADER_SIZE_MIN + WAVE_HEADER_PADDING_MAX];
            if(format.sample_size > 3) { // Wave files don't seem to support 32-bit PCM so it's converted to 24-bit
               format.sample_size = 3;
            }

            XLOGD_DEBUG("write wave header - %u-bit PCM %u hz %u chans %lu bytes", format.sample_size * 8, format.sample_rate, format.channel_qty, audio_data_size);

            uint32_t padding = 0;
            if(header_truncated) { // File was truncated at the beginning so no header is present
               uint32_t frame_size       = format.sample_size * format.channel_qty;  // Size of a single audio frame
               uint32_t partial_size     = audio_data_size % frame_size;             // Number of bytes of partial audio frame at start of the file
               uint32_t header_size_min  = WAVE_HEADER_SIZE_MIN + 8;                 // Always include padding block for consistency even though it could be eliminated if the data is aligned

               // Calculate integer multiple of frames to drop to make space for the header
               uint32_t frame_qty   = ((header_size_min - partial_size) + frame_size - 1) / frame_size;

               // Calculate the header size based on the partial frame size + frames to drop
               uint32_t header_size = (partial_size + (frame_size * frame_qty));

               // Adjust the audio data size based on header + padding size (alignment)
               audio_data_size -= header_size;

               padding = 8 + header_size - header_size_min;
               if(padding > WAVE_HEADER_PADDING_MAX) {
                  XLOGD_ERROR("padding is too big <%u>", padding);
                  padding = WAVE_HEADER_PADDING_MAX;
               }
            }

            xraudio_wave_header_gen(header, 1, format.channel_qty, format.sample_rate, format.sample_size * 8, audio_data_size, padding);

            uint32_t header_size = WAVE_HEADER_SIZE_MIN + padding;
            errno = 0;
            ssize_t bytes_written = write(fd, header, header_size);
            if(bytes_written != header_size) {
               int errsv = errno;
               XLOGD_ERROR("wave header write <%s>", strerror(errsv));
            }
         }
         break;
      }
      default: {
         break;
      }
   }
}

#ifdef XRAUDIO_KWD_ENABLED
bool xraudio_in_pre_detection_chunks(xraudio_keyword_detector_chan_t *kwd_detector_chan, uint32_t sample_qty, uint32_t offset_from_end, float **chunk_1_data, uint32_t *chunk_1_qty, float **chunk_2_data, uint32_t *chunk_2_qty) {
   int samples_in_buffer = kwd_detector_chan->pd_sample_qty;
   *chunk_1_qty  = *chunk_2_qty  = 0;
   *chunk_1_data = *chunk_2_data = NULL;
   uint32_t begin = offset_from_end + sample_qty;
   if(begin > samples_in_buffer) {
      XLOGD_ERROR("begin <%u> is greater than pre-detect sample qty avail <%d>", sample_qty, samples_in_buffer);
      return false;
   }
   uint32_t end =   offset_from_end;
   float *buf_ptr = kwd_detector_chan->pre_detection_buffer_fp32;
   uint32_t tail = kwd_detector_chan->pd_index_write;

   float *chunk1_ptr = buf_ptr + (tail - begin);
   if (chunk1_ptr < buf_ptr) {
      chunk1_ptr += samples_in_buffer;
   }
   uint32_t chunk1_size = begin - end;
   if (chunk1_ptr - buf_ptr + chunk1_size > samples_in_buffer) {
      chunk1_size = samples_in_buffer - (chunk1_ptr - buf_ptr);
      *chunk_2_qty = begin - end - chunk1_size;
      *chunk_2_data = buf_ptr;
      }
   *chunk_1_data = chunk1_ptr;
   *chunk_1_qty = chunk1_size;
   return true;
}

#endif

bool xraudio_in_capture_internal_filename_get(char *filename, const char *dir_path, uint32_t filename_size, xraudio_encoding_t encoding, uint32_t file_index, const char *stream_id) {
   const char *separator = "_";
   if(stream_id == NULL || *stream_id == '\0') {
      separator = "";
      stream_id = "";
   }
   switch(encoding.type) {
      case XRAUDIO_ENCODING_PCM:
      case XRAUDIO_ENCODING_PCM_RAW: {
         snprintf(filename, filename_size, CAPTURE_INTERNAL_FILENAME_WAV, dir_path, file_index, separator, stream_id);
         break;
      }
      case XRAUDIO_ENCODING_ADPCM_FRAME: {
         snprintf(filename, filename_size, CAPTURE_INTERNAL_FILENAME_ADPCM_FRAME, dir_path, file_index, separator, stream_id);
         break;
      }
      case XRAUDIO_ENCODING_ADPCM: {
         snprintf(filename, filename_size, CAPTURE_INTERNAL_FILENAME_ADPCM, dir_path, file_index, separator, stream_id);
         break;
      }
      case XRAUDIO_ENCODING_OPUS_XVP: {
         snprintf(filename, filename_size, CAPTURE_INTERNAL_FILENAME_OPUS_XVP, dir_path, file_index, separator, stream_id);
         break;
      }
      case XRAUDIO_ENCODING_OPUS: {
         snprintf(filename, filename_size, CAPTURE_INTERNAL_FILENAME_OPUS, dir_path, file_index, separator, stream_id);
         break;
      }
      default:
         XLOGD_ERROR("Unsupported encoding <%s>", xraudio_encoding_str(encoding.type));
         return(false);
   }
   return(true);
}

void xraudio_in_capture_internal_input_begin(xraudio_input_format_t *native, xraudio_input_format_t *decoded, xraudio_capture_internal_t *capture_internal, xraudio_capture_instance_t *capture_instance, const char *stream_id) {
   xraudio_capture_file_t *captures[2];
   captures[0] = &capture_instance->native;
   captures[1] = (decoded != NULL) ? &capture_instance->decoded : NULL;

   capture_instance->active = true;

   capture_instance->native.format = *native;
   if(decoded != NULL) {
      capture_instance->decoded.format = *decoded;
   } else {
      capture_instance->decoded.format = (xraudio_input_format_t) { .container     = XRAUDIO_CONTAINER_INVALID,
                                                                    .encoding.type = XRAUDIO_ENCODING_INVALID,
                                                                    .sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                                    .sample_size   = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                                    .channel_qty   = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };
   }

   for(uint32_t index = 0; index < 2; index++) {
      char filename[CAPTURE_INTERNAL_FILENAME_SIZE_MAX];
      xraudio_capture_file_t *capture = captures[index];
      if(capture == NULL) {
         continue;
      }

      // Check to make sure the index we're about to use is not in use and if so find the next available one
      bool found_next_index = false;
      for(uint32_t next_file_index = capture_internal->file_index; next_file_index < capture_internal->file_qty_max; next_file_index++) {
         if(xraudio_capture_file_index_in_use(capture_internal->dir_path, next_file_index)) {
            XLOGD_WARN("skipping over index <%u>", next_file_index);
         } else {
            capture_internal->file_index = next_file_index;
            found_next_index             = true;
            break;
         }
      }
      if(!found_next_index) { // Continue search from index 0
         for(uint32_t next_file_index = 0; next_file_index < capture_internal->file_index; next_file_index++) {
            if(xraudio_capture_file_index_in_use(capture_internal->dir_path, next_file_index)) {
               XLOGD_WARN("skipping over index <%u>", next_file_index);
            } else {
               capture_internal->file_index = next_file_index;
               found_next_index             = true;
               break;
            }
         }
      }
      if(!found_next_index) { // All files in use
         XLOGD_ERROR("all capture indexes are in use!");
         capture_instance->active = false;
         break;
      }

      if(!xraudio_in_capture_internal_filename_get(filename, capture_internal->dir_path, sizeof(filename), capture->format.encoding, capture_internal->file_index, stream_id)) {
         capture_instance->active = false;
         break;
      }

      // Delete file with the same index
      xraudio_capture_file_delete(capture_internal->dir_path, capture_internal->file_index);

      capture->audio_data_size    = 0;
      capture->format.container = (capture->format.encoding.type == XRAUDIO_ENCODING_PCM || capture->format.encoding.type == XRAUDIO_ENCODING_PCM_RAW) ? XRAUDIO_CONTAINER_WAV : XRAUDIO_CONTAINER_NONE;

      XLOGD_INFO("%s file <%s> container <%s> encoding <%s> chan_qty <%u> %u Hz %u-bit", (index == 0) ? "native" : "decoded", filename, xraudio_container_str(capture->format.container), xraudio_encoding_str(capture->format.encoding.type), capture->format.channel_qty, capture->format.sample_rate, (capture->format.sample_size <= 2) ? capture->format.sample_size * 8 : 24 );

      errno = 0;
      capture->fd = open(filename, XRAUDIO_CAPTURE_FILE_FLAGS, XRAUDIO_CAPTURE_FILE_MODE);
      if(capture->fd < 0) {
         int errsv = errno;
         XLOGD_ERROR("Unable to open file <%s> <%s>", filename, strerror(errsv));
         capture_instance->active = false;
         break;
      }

      int rc = flock(capture->fd, LOCK_EX | LOCK_NB);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to flock file <%s>", strerror(errsv));
         capture_instance->active = false;
         close(capture->fd);
         capture->fd = -1;
         break;
      }

      #ifdef CURTAIL_ENABLED
      struct stat statbuf;

      rc = fstat(capture->fd, &statbuf);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to stat file <%s>", strerror(errsv));
         capture_instance->active = false;
         close(capture->fd);
         capture->fd = -1;
         break;
      }

      capture->header_truncated   = false;
      capture->logical_block_size = statbuf.st_blksize;
      #endif

      xraudio_record_container_process_begin(capture);

      capture_internal->file_index++;
      if(capture_internal->file_index >= capture_internal->file_qty_max) {
         capture_internal->file_index = 0;
      }
   }

   if(!capture_instance->active) {
      for(uint32_t index = 0; index < 2; index++) {
         xraudio_capture_file_t *capture = captures[index];
         if(capture == NULL) {
            continue;
         }
         if(capture->fd >= 0) {
            close(capture->fd);
            capture->fd = -1;
         }
      }
   }
}

void xraudio_in_capture_internal_end(xraudio_capture_instance_t *capture_instancce) {
   xraudio_capture_file_t *captures[2];
   captures[0] = &capture_instancce->native;
   captures[1] = (capture_instancce->decoded.format.encoding.type != XRAUDIO_ENCODING_INVALID) ? &capture_instancce->decoded : NULL;

   for(uint32_t index = 0; index < 2; index++) {
      xraudio_capture_file_t *capture = captures[index];
      if(capture == NULL) {
         continue;
      }

      // Update container
      if(capture->fd >= 0) {
         #ifdef CURTAIL_ENABLED
         bool header_truncated = capture->header_truncated;
         #else
         bool header_truncated = false;
         #endif
         xraudio_record_container_process_end(capture->fd, capture->format, capture->audio_data_size, header_truncated);
         close(capture->fd);
         capture->fd = -1;
      }
      capture->audio_data_size = 0;
      capture->format = (xraudio_input_format_t) { .container     = XRAUDIO_CONTAINER_INVALID,
                                                   .encoding.type = XRAUDIO_ENCODING_INVALID,
                                                   .sample_rate   = XRAUDIO_INPUT_DEFAULT_SAMPLE_RATE,
                                                   .sample_size   = XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE,
                                                   .channel_qty   = XRAUDIO_INPUT_DEFAULT_CHANNEL_QTY };
   }
   capture_instancce->active = false;
}

void reorder_samples(uint8_t *dst_buf, uint8_t *src_buf, uint32_t data_size, uint32_t src_buf_align) {
    int i, j;
    uint8_t *p_cap_buf = dst_buf;
    for(i = 0; i < (data_size / XRAUDIO_INPUT_MAX_CHANNEL_QTY / XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE); i++) {
        for(j = 0; j < XRAUDIO_INPUT_MAX_CHANNEL_QTY; j++) {
            *p_cap_buf++ = *(src_buf + (j * src_buf_align));
            *p_cap_buf++ = *(src_buf + (j * src_buf_align) + 1);
        }
        src_buf += XRAUDIO_INPUT_DEFAULT_SAMPLE_SIZE;
    }
}

int xraudio_in_capture_internal_to_file(xraudio_session_record_t *session, uint8_t *data_in, uint32_t data_size, xraudio_capture_file_t *capture_file) {
   // Check for maximum file size
   uint32_t file_size = capture_file->audio_data_size + WAVE_HEADER_SIZE_MIN;

   if(capture_file->format.container == XRAUDIO_CONTAINER_WAV && capture_file->format.sample_size == 4) { // Only 24-bits are stored so reduce file size accordingly
      file_size += (data_size * 3) / 4;
   } else {
      file_size += data_size;
   }

   #ifndef CURTAIL_ENABLED
   if(file_size > session->capture_internal.file_size_max) {
      return(-1);
   }
   #else
   if(capture_file->header_truncated) { // Header was truncated so remove it from file size calculation
      file_size -= WAVE_HEADER_SIZE_MIN;
   }

   if(file_size > session->capture_internal.file_size_max) {
      if(!session->capture_internal.use_curtail) {
         return(-1);
      }

      // Free up some space in the file
      int numblocks = (capture_file->audio_data_size + data_size - session->capture_internal.file_size_max + (capture_file->logical_block_size - 1)) / capture_file->logical_block_size;
      errno = 0;
      if(0 > fallocate(capture_file->fd, FALLOC_FL_COLLAPSE_RANGE, 0, capture_file->logical_block_size * numblocks)) {
         int errsv = errno;
         XLOGD_ERROR("fallocate failed <%s> fd <%d> block size <%u> qty <%u> file size <%u> data size <%u>", strerror(errsv), capture_file->fd, capture_file->logical_block_size, numblocks, file_size, data_size);
         return(-1);
      } else {
         XLOGD_DEBUG("truncated file from <%u> to <%u> bytes (numblocks: %d)", capture_file->audio_data_size, capture_file->audio_data_size - (capture_file->logical_block_size * numblocks), numblocks);

         if(!capture_file->header_truncated && capture_file->has_header) {
            capture_file->header_truncated = true;
            capture_file->audio_data_size -= ((capture_file->logical_block_size * numblocks) - WAVE_HEADER_SIZE_MIN);
         } else {
            capture_file->audio_data_size -= (capture_file->logical_block_size * numblocks);
         }

         // Reset the file pointer to the new end of the file
         errno = 0;
         off_t offset_end = lseek(capture_file->fd, 0, SEEK_END);
         if(offset_end < 0) {
            int errsv = errno;
            XLOGD_ERROR("unable to seek end of file <%s>", strerror(errsv));
            return(-1);
         }
      }
   }
   #endif

   if(capture_file->format.encoding.type == XRAUDIO_ENCODING_OPUS_XVP || capture_file->format.encoding.type == XRAUDIO_ENCODING_OPUS) {
      // OPUS packets aren't self delimiting so add the packet size to indicate the size of the next packet
      uint8_t packet_size[2];
      packet_size[0] = (data_size & 0xFF);
      packet_size[1] = (data_size >> 8) & 0xFF;

      errno = 0;
      ssize_t size = write(capture_file->fd, &packet_size, sizeof(packet_size));
      if(size != sizeof(packet_size)) {
         int errsv = errno;
         XLOGD_ERROR("Error (%zd) <%s>", size, strerror(errsv));
         return(-1);
      }
   }

   if(capture_file->format.channel_qty == 1 && capture_file->format.sample_size <= 2) { // single channel 16-bit PCM
      // Write requested size into capture file
      errno = 0;
      ssize_t bytes_written = write(capture_file->fd, data_in, data_size);

      if(bytes_written != data_size) {
         int errsv = errno;
         XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
         return(-1);
      }
      capture_file->audio_data_size += data_size;
   } else if(capture_file->format.sample_size == 4) { // single/multi channel 32-bit PCM
      uint32_t sample_qty  = data_size / (capture_file->format.sample_size * capture_file->format.channel_qty);
      uint8_t  channel_qty = capture_file->format.channel_qty;
      uint32_t sample_size = (capture_file->format.container == XRAUDIO_CONTAINER_WAV) ? 3: 4; // Must reduce to 24-bit for wave format

      for(uint32_t index = 0; index < sample_qty; index++) {
         uint32_t tmp_data_size = channel_qty * sample_size;
         uint8_t  tmp_buf[tmp_data_size];
         uint32_t j = 0;
         for(uint32_t mic = 0; mic < channel_qty; mic++) {
            int32_t (*audio_frames)[sample_qty] = (void *)data_in;

            int32_t sample = audio_frames[mic][index];

            // Handle endian difference for wave container
            #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            tmp_buf[j++] = (sample >> 24) & 0xFF;
            tmp_buf[j++] = (sample >> 16) & 0xFF;
            tmp_buf[j++] = (sample >>  8) & 0xFF;
            if(sample_size == 4) {
               tmp_buf[j++] = (sample   ) & 0xFF;
            }
            #elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            if(sample_size == 4) {
               tmp_buf[j++] = (sample   ) & 0xFF;
            }
            tmp_buf[j++] = (sample >>  8) & 0xFF;
            tmp_buf[j++] = (sample >> 16) & 0xFF;
            tmp_buf[j++] = (sample >> 24) & 0xFF;
            #else
            #error unhandled byte order
            #endif
         }

         errno = 0;
         ssize_t bytes_written = write(capture_file->fd, &tmp_buf[0], tmp_data_size);

         if(bytes_written != tmp_data_size) {
            int errsv = errno;
            XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
         }
         capture_file->audio_data_size += tmp_data_size;
      }
   } else {
      XLOGD_ERROR("unsupported format");
      return(-1);
   }
   return(0);
}

int xraudio_capture_file_filter_all(const struct dirent *name) {
   XLOGD_DEBUG("checking <%s>", name->d_name ? name->d_name : "NULL");
   if(name == NULL) {
      return(0);
   }
   return(0 == strncmp(CAPTURE_INTERNAL_FILENAME_PREFIX, name->d_name, sizeof(CAPTURE_INTERNAL_FILENAME_PREFIX) - 1));
}

int xraudio_capture_file_filter_by_index(const struct dirent *name) {
   XLOGD_DEBUG("checking <%s>", name->d_name ? name->d_name : "NULL");
   static char prefix[sizeof(CAPTURE_INTERNAL_FILENAME_PREFIX) + 6];
   if(name == NULL) {
      return(0);
   } else if(name->d_type == 0xFF) {
      int rc = snprintf(prefix, sizeof(prefix), "%s", name->d_name);
      if(rc != sizeof(prefix) - 1) {
          XLOGD_ERROR("set filter to <%s> rc <%d>", prefix, rc);
      } else {
          XLOGD_INFO("set filter to <%s>", prefix);
      }
   }

   return(0 == strncmp(prefix, name->d_name, sizeof(prefix) - 1));
}

uint32_t xraudio_capture_next_file_index(const char *dir_path, uint32_t file_qty_max) {
   struct dirent **namelist = NULL;
   uint32_t next_file_index = 0;

   errno = 0;
   int entry_qty = scandir(dir_path, &namelist, xraudio_capture_file_filter_all, alphasort);
   if(entry_qty < 0) {
      int errsv = errno;
      XLOGD_ERROR("scandir returned error <%s>", strerror(errsv));
      return(0);
   }

   if(entry_qty < file_qty_max) { // haven't reached limit yet
      next_file_index = entry_qty;
   } else { // limit has been reached
      for(int entry = 0; entry < entry_qty - 1; entry++) {
         char internal_capture_filename_1[PATH_MAX];
         char internal_capture_filename_2[PATH_MAX];

         snprintf(internal_capture_filename_1, sizeof(internal_capture_filename_1), "%s/%s", dir_path, namelist[entry]->d_name);
         snprintf(internal_capture_filename_2, sizeof(internal_capture_filename_2), "%s/%s", dir_path, namelist[entry + 1]->d_name);

         XLOGD_DEBUG("comparing %s vs %s", internal_capture_filename_1, internal_capture_filename_2);
         double seconds = difftime(xraudio_get_file_timestamp(internal_capture_filename_1), xraudio_get_file_timestamp(internal_capture_filename_2));
         XLOGD_DEBUG("seconds difference is %f", seconds);
         if(seconds > 0) {
            // internal_capture_filename_1 is newer
            next_file_index = entry + 1;
            break;
         }
      }
   }

   while(entry_qty--) {
      free(namelist[entry_qty]);
   }
   free(namelist);

   XLOGD_DEBUG("next file index <%u>", next_file_index);
   return(next_file_index);
}

bool xraudio_capture_file_index_in_use(const char *dir_path, uint32_t index) {
   struct dirent **namelist = NULL;

   bool in_use = false;

   // Call once to set the filter up
   struct dirent filter;
   filter.d_type = 0xFF; // This is really slick or stupid depending on how you look at it.
   snprintf(filter.d_name, sizeof(filter.d_name), CAPTURE_INTERNAL_FILENAME_PREFIX CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT, index);
   xraudio_capture_file_filter_by_index(&filter);

   errno = 0;
   int entry_qty = scandir(dir_path, &namelist, xraudio_capture_file_filter_by_index, alphasort);
   if(entry_qty < 0) {
      int errsv = errno;
      XLOGD_ERROR("scandir returned error <%s>", strerror(errsv));
      return(true);
   }

   while(entry_qty--) {
      char filename[PATH_MAX];

      snprintf(filename, sizeof(filename), "%s/%s", dir_path, namelist[entry_qty]->d_name);

      // Check if the file is still in use
      errno = 0;
      int fd = open(filename, O_RDONLY);
      if(fd < 0) {
         int errsv = errno;
         XLOGD_WARN("unable to open file <%s> <%s>", filename, strerror(errsv));
         continue;
      }
      errno = 0;
      int rc = flock(fd, LOCK_EX | LOCK_NB);
      if(rc < 0) {
         int errsv = errno;
         if(errsv == EWOULDBLOCK) {
            XLOGD_WARN("capture in progress on file <%s>", filename);
            in_use = true;
         } else {
            XLOGD_WARN("unable to flock file <%s> <%s>", filename, strerror(errsv));
         }
      }
      close(fd);
      free(namelist[entry_qty]);
   }
   free(namelist);

   return(in_use);
}

void xraudio_capture_file_delete(const char *dir_path, uint32_t index) {
   struct dirent **namelist = NULL;

   XLOGD_INFO("index <%u>", index);

   // Call once to set the filter up
   struct dirent filter;
   filter.d_type = 0xFF; // This is really slick or stupid depending on how you look at it.
   snprintf(filter.d_name, sizeof(filter.d_name), CAPTURE_INTERNAL_FILENAME_PREFIX CAPTURE_INTERNAL_FILENAME_INDEX_FORMAT, index);
   xraudio_capture_file_filter_by_index(&filter);

   errno = 0;
   int entry_qty = scandir(dir_path, &namelist, xraudio_capture_file_filter_by_index, alphasort);
   if(entry_qty < 0) {
      int errsv = errno;
      XLOGD_ERROR("scandir returned error <%s>", strerror(errsv));
      return;
   }

   while(entry_qty--) {
      char filename[PATH_MAX];

      snprintf(filename, sizeof(filename), "%s/%s", dir_path, namelist[entry_qty]->d_name);

      XLOGD_INFO("remove file <%s>", filename);
      errno = 0;
      int rc = remove(filename);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to remove file <%s> <%s>", filename, strerror(errsv));
      }
      free(namelist[entry_qty]);
   }
   free(namelist);
}

xraudio_result_t xraudio_capture_file_delete_all(const char *dir_path) {
   struct dirent **namelist = NULL;
   errno = 0;
   int entry_qty = scandir(dir_path, &namelist, xraudio_capture_file_filter_all, alphasort);
   if(entry_qty < 0) {
      int errsv = errno;
      XLOGD_ERROR("scandir returned error <%s>", strerror(errsv));
      return(XRAUDIO_RESULT_ERROR_PARAMS);
   }

   while(entry_qty--) {
      char filename[PATH_MAX];

      snprintf(filename, sizeof(filename), "%s/%s", dir_path, namelist[entry_qty]->d_name);

      XLOGD_INFO("remove file <%s>", filename);
      errno = 0;
      int rc = remove(filename);
      if(rc != 0) {
         int errsv = errno;
         XLOGD_ERROR("unable to remove file <%s> <%s>", filename, strerror(errsv));
      }
      free(namelist[entry_qty]);
   }
   free(namelist);

   return(XRAUDIO_RESULT_OK);
}

time_t xraudio_get_file_timestamp(char *filename) {
   struct stat attrib;
   errno = 0;
   if(stat(filename, &attrib) != 0) {
      int errsv = errno;
      XLOGD_ERROR("stat returned error <%s>", strerror(errsv));
   }
   return attrib.st_ctime;
}

#ifdef XRAUDIO_KWD_ENABLED
bool xraudio_hal_msg_async_handler(void *msg) {
   xraudio_hal_msg_header_t *header = (xraudio_hal_msg_header_t *)msg;
   bool ret = false;
   if(NULL == header) {
      XLOGD_ERROR("async message null");
      return ret;
   }

   switch(header->type) {
      case XRAUDIO_MSG_TYPE_SESSION_REQUEST: {
         if(!XRAUDIO_DEVICE_INPUT_CONTAINS(g_voice_session.sources_supported, header->source)) {
            XLOGD_ERROR("requested source <%s> is not supported", xraudio_devices_input_str(header->source));
            XLOGD_ERROR("supported sources <%s>", xraudio_devices_input_str(g_voice_session.sources_supported));
         } else {
            ret = xraudio_in_session_group_semaphore_lock(header->source);
         }
         break;
      }
      case XRAUDIO_MSG_TYPE_SESSION_BEGIN: {
         xraudio_hal_msg_session_begin_t *begin = (xraudio_hal_msg_session_begin_t *)msg;
         uint32_t group = xraudio_input_source_to_group(begin->header.source);
         if(xraudio_in_session_group_source_get(group) != begin->header.source) {
            ret = false;
         } else {
            // Send message to queue
            xraudio_queue_msg_async_session_begin_t begin_msg;
            begin_msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_BEGIN;
            begin_msg.source = begin->header.source;
            memcpy(&begin_msg.format, &begin->format, sizeof(xraudio_input_format_t));
            memcpy(&begin_msg.stream_params, &begin->stream_params, sizeof(xraudio_hal_stream_params_t));
            if(begin->uuid != NULL) {
               uuid_copy(begin_msg.uuid, *(begin->uuid));
            } else {
               uuid_clear(begin_msg.uuid);
            }
            queue_msg_push(g_voice_session.msgq, (char *)&begin_msg, sizeof(begin_msg));
            ret = true;
         }
         break;
      }
      case XRAUDIO_MSG_TYPE_SESSION_END: {
         xraudio_hal_msg_session_end_t *end = (xraudio_hal_msg_session_end_t *)msg;
         uint32_t group = xraudio_input_source_to_group(end->header.source);
         if(xraudio_in_session_group_source_get(group) != end->header.source) {
            ret = false;
         } else {
            // Send message to queue
            xraudio_queue_msg_async_session_end_t end_msg;
            end_msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_SESSION_END;
            end_msg.source = end->header.source;
            queue_msg_push(g_voice_session.msgq, (char *)&end_msg, sizeof(end_msg));
            ret = true;
         }
         break;
      }
      case XRAUDIO_MSG_TYPE_INPUT_ERROR: {
         xraudio_hal_msg_input_error_t *input_error = (xraudio_hal_msg_input_error_t *)msg;
         // Send message to queue
         xraudio_queue_msg_async_input_error_t error_msg;
         error_msg.header.type = XRAUDIO_MAIN_QUEUE_MSG_TYPE_ASYNC_INPUT_ERROR;
         error_msg.source      = input_error->header.source;
         queue_msg_push(g_voice_session.msgq, (char *)&error_msg, sizeof(error_msg));
         ret = true;
         break;
      }
      case XRAUDIO_MSG_TYPE_INVALID: {
         break;
      }
   }
   return ret;
}
#endif

ssize_t xraudio_external_fd_read(xraudio_session_record_t *session, void *buf, size_t count) {
   ssize_t retcode = read(session->external_fd, buf, count);
   if(session->external_callback != NULL) {
      (*session->external_callback)(retcode, session->external_user_data);
   }

   return(retcode);
}

void xraudio_process_input_external_data(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_decoders_t *decoders) {
   xraudio_session_record_inst_t *instance = &session->instances[XRAUDIO_INPUT_SESSION_GROUP_DEFAULT];
   xraudio_capture_file_t *capture_file = &instance->capture_internal.native;
   int32_t bytes_read = 0;

   xraudio_encoding_type_t enc_input  = session->external_format.encoding.type;
   xraudio_encoding_type_t enc_output = instance->format_out.encoding.type;
   uint8_t *inbuf = &session->external_frame_buffer[session->external_frame_group_index * session->external_frame_size_out];
   uint32_t inlen = session->external_frame_size_in;
   #ifdef XRAUDIO_DECODE_ADPCM
   xraudio_adpcm_frame_t *adpcm_frame = &session->external_format.encoding.value.adpcm_frame;
   #endif

   switch(enc_input) {
      case XRAUDIO_ENCODING_ADPCM_FRAME: {
         if(enc_output == XRAUDIO_ENCODING_PCM) {
            #ifndef XRAUDIO_DECODE_ADPCM
            XLOGD_ERROR("ADPCM decode is not supported");
            return;
            #else
            if(adpcm_frame->size_packet > XRAUDIO_INPUT_ADPCM_BUFFER_SIZE) {
               XLOGD_ERROR("ADPCM packet size is too big <%u>", adpcm_frame->size_packet);
               return;
            }
            adpcm_t buffer[XRAUDIO_INPUT_ADPCM_BUFFER_SIZE] = {'\0'};
            bytes_read = xraudio_external_fd_read(session, buffer, adpcm_frame->size_packet);
            if(bytes_read > 0) {
               if(instance->capture_internal.active) {
                  int rc_cap = xraudio_in_capture_internal_to_file(session, buffer, (uint32_t)bytes_read, capture_file);
                  if(rc_cap < 0) {
                     xraudio_in_capture_internal_end(&instance->capture_internal);
                  }
                  capture_file = &instance->capture_internal.decoded;
               }
               bytes_read = adpcm_decode(decoders->adpcm, buffer, bytes_read, (pcm_t *)inbuf, (adpcm_frame->size_packet - adpcm_frame->size_header) * 2, adpcm_frame, false);
               if(bytes_read < 0) {
                  XLOGD_ERROR("failed to decode adpcm");
               } else {
                  bytes_read *= sizeof(pcm_t);
               }
            }
            #endif
         } else if(enc_output == XRAUDIO_ENCODING_ADPCM_FRAME) {
            bytes_read = xraudio_external_fd_read(session, inbuf, inlen);
            #ifdef XRAUDIO_DECODE_ADPCM
            if(bytes_read > 0) {
               adpcm_analyze(decoders->adpcm, inbuf, inlen, adpcm_frame);
            }
            #endif
         } else {
            XLOGD_ERROR("unsupported conversion <%s> to <%s>", xraudio_encoding_str(enc_input), xraudio_encoding_str(enc_output));
            return;
         }
         break;
      }
      case XRAUDIO_ENCODING_OPUS_XVP: {
         if(enc_output == XRAUDIO_ENCODING_PCM) {
            #ifndef XRAUDIO_DECODE_OPUS
            XLOGD_ERROR("OPUS decode is not supported");
            return;
            #else
            if(decoders->opus == NULL) {
               XLOGD_ERROR("OPUS decoder is disabled");
               return;
            }
            uint8_t buffer[XRAUDIO_INPUT_OPUS_BUFFER_SIZE] = {'\0'};
            bytes_read = xraudio_external_fd_read(session, buffer, XRAUDIO_INPUT_OPUS_BUFFER_SIZE);
            if(bytes_read > 0) {
               if(instance->capture_internal.active) {
                  int rc_cap = xraudio_in_capture_internal_to_file(session, buffer, (uint32_t)bytes_read, capture_file);
                  if(rc_cap < 0) {
                     xraudio_in_capture_internal_end(&instance->capture_internal);
                  }
                  capture_file = &instance->capture_internal.decoded;
               }
               bytes_read = xraudio_opus_decode(decoders->opus, 1, buffer, bytes_read, (pcm_t *)inbuf, XRAUDIO_INPUT_OPUS_FRAME_SAMPLE_QTY); // decode framed audio
               if(bytes_read < 0) {
                  XLOGD_ERROR("failed to decode opus");
               } else {
                  // Accept any frame size from opus stream since  we can't reliably know the expected frame size
                  session->external_frame_size_out = bytes_read;
               }
            }
            #endif
         } else if(enc_output == XRAUDIO_ENCODING_OPUS_XVP) {
            bytes_read = xraudio_external_fd_read(session, inbuf, inlen);
         } else if(enc_output == XRAUDIO_ENCODING_OPUS) {
            // TODO should read header first from the HAL into a temp buffer and then the payload into inbuf
            bytes_read = xraudio_external_fd_read(session, inbuf, inlen);
            #ifdef XRAUDIO_DECODE_OPUS
            if(bytes_read > 0) {
               bytes_read = xraudio_opus_deframe(decoders->opus, inbuf, bytes_read);
            }
            #endif
         } else {
            XLOGD_ERROR("unsupported conversion <%s> to <%s>", xraudio_encoding_str(enc_input), xraudio_encoding_str(enc_output));
            return;
         }
         break;
      }
      case XRAUDIO_ENCODING_OPUS: {
         if(enc_output == XRAUDIO_ENCODING_PCM) {
            #ifndef XRAUDIO_DECODE_OPUS
            XLOGD_ERROR("OPUS decode is not supported");
            return;
            #else
            if(decoders->opus == NULL) {
               XLOGD_ERROR("OPUS decoder is disabled");
               return;
            }

            // Since there is no packet length in the transport, self-delimiting frames must be used (See Appendix B. of opus specification)

            // Frame Length Byte 0
            uint8_t length_bytes[2] = { '\0' };
            bytes_read = xraudio_external_fd_read(session, &length_bytes[0], 1);
            if(bytes_read != 1 && bytes_read != 0) {
               XLOGD_ERROR("OPUS frame length byte 0 <%d>", bytes_read);
               return;
            }

            uint16_t frame_length = length_bytes[0];

            if(frame_length >= 252) { // frame length is (second_byte*4) + first_byte
               bytes_read = xraudio_external_fd_read(session, &length_bytes[1], 1);
               if(bytes_read != 1 && bytes_read != 0) {
                  XLOGD_ERROR("OPUS frame length byte 1 <%d>", bytes_read);
                  return;
               }
               frame_length += (length_bytes[1] * 4);
            }
            if(bytes_read == 1) {
               if(frame_length == 0) {
                  XLOGD_WARN("OPUS skipping zero length frame");
                  return;
               }

               uint8_t buffer[frame_length];
               memset(buffer, 0, sizeof(buffer));

               bytes_read = xraudio_external_fd_read(session, buffer, frame_length);
               if(bytes_read != frame_length) {
                  XLOGD_ERROR("OPUS frame length exp <%u> read <%d>", frame_length, bytes_read);
                  return;
               } else {
                  if(instance->capture_internal.active) {
                     int rc_cap = xraudio_in_capture_internal_to_file(session, length_bytes, (frame_length >= 252) ? 2 : 1, capture_file);
                     if(rc_cap < 0) {
                        xraudio_in_capture_internal_end(&instance->capture_internal);
                     } else {
                        rc_cap = xraudio_in_capture_internal_to_file(session, buffer, (uint32_t)bytes_read, capture_file);
                        if(rc_cap < 0) {
                           xraudio_in_capture_internal_end(&instance->capture_internal);
                        }
                     }
                     capture_file = &instance->capture_internal.decoded;
                  }

                  bytes_read = xraudio_opus_decode(decoders->opus, 0, buffer, bytes_read, (pcm_t *)inbuf, XRAUDIO_INPUT_OPUS_FRAME_SAMPLE_QTY); // decode audio (not framed)
                  if(bytes_read < 0) {
                     XLOGD_ERROR("failed to decode opus");
                  } else {
                     // Accept any frame size from opus stream since  we can't reliably know the expected frame size
                     session->external_frame_size_out = bytes_read;
                  }
               }
            }
            #endif
         } else if(enc_output == XRAUDIO_ENCODING_OPUS) {
            bytes_read = xraudio_external_fd_read(session, inbuf, inlen);
         } else {
            XLOGD_ERROR("unsupported conversion <%s> to <%s>", xraudio_encoding_str(enc_input), xraudio_encoding_str(enc_output));
            return;
         }
         break;
      }
      case XRAUDIO_ENCODING_PCM: {
         if(enc_output == XRAUDIO_ENCODING_PCM) {
            // PCM is a stream, it is possible to read < a frame size
            if(session->external_frame_bytes_read > 0) {
               inbuf += session->external_frame_bytes_read;
               inlen  = session->external_frame_size_in - session->external_frame_bytes_read;
            }
            bytes_read = xraudio_external_fd_read(session, inbuf, inlen);
            if(bytes_read <= 0) break;
            bytes_read += session->external_frame_bytes_read;
            session->external_frame_bytes_read = bytes_read;
            if(session->external_frame_size_out != bytes_read) {
               session->external_frame_bytes_read = bytes_read;
               return;
            } else {
               session->external_frame_bytes_read = 0;
            }
         } else {
            XLOGD_ERROR("%s: unsupported encoding from %s to %s\n", __FUNCTION__, xraudio_encoding_str(enc_input), xraudio_encoding_str(enc_output));
         }
         break;
      }
      default: {
         XLOGD_ERROR("unsupported input encoding <%s>", xraudio_encoding_str(enc_input));
         return;
      }
   }

   if(bytes_read <= 0) {
      if(instance->stream_until[0] == XRAUDIO_INPUT_RECORD_UNTIL_END_OF_STREAM) { // Session ended, notify

         if(instance->capture_internal.active && session->external_frame_bytes_read > 0) {
            int rc_cap = xraudio_in_capture_internal_to_file(session, &session->external_frame_buffer[session->external_frame_group_index * session->external_frame_size_out], (uint32_t)session->external_frame_bytes_read, capture_file); // Subtract 1 from frame group index because we added one for record callback
            if(rc_cap < 0) {
               xraudio_in_capture_internal_end(&instance->capture_internal);
            }
         }

         xraudio_in_flush(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(instance->source), params, session, instance);

         for(uint32_t index = 0; index < XRAUDIO_FIFO_QTY_MAX; index++) {
            if(instance->fifo_audio_data[index] < 0) {
               break;
            }
            if(instance->fifo_audio_data[index] >= 0) { // Close the write side of the pipe so the read side gets EOF
               close(instance->fifo_audio_data[index]);
               instance->fifo_audio_data[index] = -1;
            }
            instance->stream_until[index] = XRAUDIO_INPUT_RECORD_UNTIL_INVALID;
         }
         if(instance->fd >= 0) {
            xraudio_record_container_process_end(instance->fd, session->external_format, instance->audio_buf_index, false);
         }
         if(instance->synchronous) {
            if(instance->semaphore == NULL) {
               XLOGD_ERROR("synchronous record with no semaphore set!");
            } else {
               sem_post(instance->semaphore);
               instance->semaphore = NULL;
            }
         } else if(instance->callback != NULL){
            switch(enc_input) {
            #ifdef XRAUDIO_DECODE_ADPCM
               case XRAUDIO_ENCODING_ADPCM_FRAME: {
                  xraudio_audio_stats_t stats;
                  adpcm_decode_stats_t adpcm_stats;
                  memset(&stats, 0, sizeof(stats));
                  if(adpcm_decode_stats(decoders->adpcm, &adpcm_stats)) {
                     uint32_t frame_sample_qty  = ((adpcm_frame->size_packet - adpcm_frame->size_header) * 2);
                     stats.packets_processed    = adpcm_stats.frames_processed;
                     stats.packets_lost         = adpcm_stats.frames_lost;
                     stats.samples_processed    = adpcm_stats.frames_processed * frame_sample_qty;
                     stats.samples_lost         = adpcm_stats.frames_lost * frame_sample_qty;
                     stats.decoder_failures     = adpcm_stats.failed_decodes;
                     stats.samples_buffered_max = 0;
                  }
                  (*instance->callback)(instance->source, AUDIO_IN_CALLBACK_EVENT_EOS, &stats, instance->param);
                  break;
               }
            #endif
               default: {
                  (*instance->callback)(instance->source, AUDIO_IN_CALLBACK_EVENT_EOS, NULL, instance->param);
                  break;
               }
            }
         }
         // Clear the session so no further incoming data is processed
         instance->fd                        = -1;
         instance->audio_buf_samples         = NULL;
         instance->audio_buf_sample_qty      = 0;
         instance->audio_buf_index           = 0;

         if(session->external_fd >= 0) {
            XLOGD_DEBUG("close external fd <%d>", session->external_fd);
            close(session->external_fd);
         }
         session->external_fd                = -1;
         session->external_frame_group_index = 0;
      }
      return;
   }

   if(session->external_frame_size_out != bytes_read) {
      XLOGD_ERROR("external data read wrong size (expected %u, received %d)", session->external_frame_size_out, bytes_read);
      return;
   }

   if(instance->stream_time_min_value          > 0                               &&
      session->external_data_len               < instance->stream_time_min_value &&
      session->external_data_len + bytes_read >= instance->stream_time_min_value &&
      instance->callback) {
         (*instance->callback)(instance->source, AUDIO_IN_CALLBACK_EVENT_STREAM_TIME_MINIMUM, NULL, instance->param);
   }

   session->external_data_len += bytes_read;

   if(instance->keyword_end_samples > 0 && session->external_data_len >= (instance->keyword_end_samples * sizeof(int16_t))) {
      if(instance->callback != NULL) {
         xraudio_stream_keyword_info_t kwd_info;
         kwd_info.byte_qty = (instance->keyword_end_samples * sizeof(int16_t)); // 16-bit pcm
         (*instance->callback)(instance->source, AUDIO_IN_CALLBACK_EVENT_STREAM_KWD_INFO, &kwd_info, instance->param);
      }
      instance->keyword_end_samples = 0;
      instance->keyword_flush       = true;
   }

   session->external_frame_group_index++;

   int rc = -1;
   if(instance->record_callback) {
      rc = instance->record_callback(XRAUDIO_DEVICE_INPUT_EXTERNAL_GET(instance->source), params, session, instance);
   }

   if(instance->capture_internal.active) {
      int rc_cap = xraudio_in_capture_internal_to_file(session, &session->external_frame_buffer[(session->external_frame_group_index - 1) * session->external_frame_size_out], (uint32_t)bytes_read, capture_file); // Subtract 1 from frame group index because we added one for record callback
      if(rc_cap < 0) {
         xraudio_in_capture_internal_end(&instance->capture_internal);
      }
   }

   if(session->external_frame_group_index >= session->external_frame_group_qty || (rc > 0)) {
      session->external_frame_group_index = 0;
      memset(session->external_frame_buffer, 0, sizeof(session->external_frame_buffer));
   }
}

bool xraudio_thread_create(xraudio_thread_t *thread, const char *name, void *(*start_routine) (void *), void *arg) {
   pthread_attr_t attr;
   pthread_attr_t *attr_param = NULL;

   if(pthread_attr_init(&attr) != 0) {
      XLOGD_WARN("pthread_attr_init");
   } else {
      attr_param = &attr;
   }

   if(0 != pthread_create(&thread->id, attr_param, start_routine, arg)) {
      XLOGD_ERROR("unable to launch thread");
      return(false);
   }

   if(name != NULL) {
      char name_max[16];
      snprintf(name_max, sizeof(name_max), "%s", name);
      XLOGD_DEBUG("set name <%s>", name_max);
      if(pthread_setname_np(thread->id, name_max) != 0) {
         XLOGD_WARN("pthread_setname_np");
      }
   }

   thread->running = true;
   return(true);
}

bool xraudio_thread_join(xraudio_thread_t *thread) {
   if(!thread->running) {
      return(false);
   }
   void *retval = NULL;
   pthread_join(thread->id, &retval);
   thread->running = false;
   return(true);
}

void xraudio_encoding_parameters_get(xraudio_input_format_t *format, uint32_t frame_duration, uint32_t *frame_size, uint16_t stream_time_min_ms, uint32_t *min_audio_data_len) {
   switch(format->encoding.type) {
      case XRAUDIO_ENCODING_ADPCM:
      case XRAUDIO_ENCODING_ADPCM_FRAME: {
         *frame_size         = format->encoding.value.adpcm_frame.size_packet;
         *min_audio_data_len = *frame_size * (((stream_time_min_ms * 1000) + frame_duration - 1) / frame_duration);
         break;
      }
      case XRAUDIO_ENCODING_OPUS_XVP: {
         *frame_size         = XRAUDIO_INPUT_OPUS_BUFFER_SIZE;
         *min_audio_data_len = *frame_size * (((stream_time_min_ms * 1000) + frame_duration - 1) / frame_duration); // 20 ms per packet
         break;
      }
      case XRAUDIO_ENCODING_OPUS: {
         *frame_size         = XRAUDIO_INPUT_OPUS_BUFFER_SIZE - 1;
         *min_audio_data_len = *frame_size * (((stream_time_min_ms * 1000) + frame_duration - 1) / frame_duration); // 20 ms per packet
         break;
      }
      case XRAUDIO_ENCODING_PCM: {
         *frame_size         = (format->sample_rate / 1000 * format->sample_size * frame_duration) / 1000;
         *min_audio_data_len = (format->sample_rate * format->sample_size / 1000) * stream_time_min_ms;
         break;
      }
      default: {
         XLOGD_ERROR("unsupported encoding <%s>", xraudio_encoding_str(format->encoding.type));
         break;
      }
   }
}

#if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_DGA_ENABLED)
void xraudio_samples_convert_fp32_int16(int16_t *samples_int16, float *samples_fp32, uint32_t sample_qty, uint32_t bit_qty) {
   XLOGD_DEBUG("sample qty <%u> bit qty <%u>", sample_qty, bit_qty);

   for(uint32_t i = 0; i < sample_qty; i++) {
      if(*samples_fp32 < INT32_MIN) {
         *samples_int16 = INT16_MIN;
      } else if(*samples_fp32 > INT32_MAX) {
         *samples_int16 = INT16_MAX;
      } else {
         *samples_int16 = (int16_t)(((int32_t)(*samples_fp32)) >> 16);
      }

      samples_fp32++;
      samples_int16++;
   }
}
#endif //defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_DGA_ENABLED)
#ifdef XRAUDIO_PPR_ENABLED
/*void xraudio_samples_convert_int16_int32(int16_t *int16buf, int32_t *int32buf, uint32_t sample_qty_frame, uint32_t bit_qty) {
   uint32_t sample;
   int32_t *pi32 = int32buf;
   int16_t *pi16 = int16buf;

   for(sample = 0; sample < sample_qty_frame; sample++) {
      *pi32 = *pi16;
      *pi32 <<= 16;
      pi32++;
      pi16++;
   }
}*/

void xraudio_samples_convert_int32_int16(int16_t *int16buf, int32_t *int32buf, uint32_t sample_qty_frame, uint32_t bit_qty) {
   int32_t *pi32 = int32buf;
   int16_t *pi16 = int16buf;

   for(uint32_t sample = 0; sample < sample_qty_frame; sample++) {
      *pi16 = (*pi32 >> 16);
      pi16++;
      pi32++;
   }
}

void xraudio_samples_convert_int32_fp32(float *fp32buf, int32_t *int32buf, uint32_t sample_qty_frame, uint32_t bit_qty) {
   int32_t *pi32 = int32buf;
   float *pf32 = fp32buf;

   for(uint32_t sample = 0; sample < sample_qty_frame; sample++) {
      *pf32++ = *pi32++;
   }
}
#endif

#if defined(XRAUDIO_KWD_ENABLED) || defined(XRAUDIO_PPR_ENABLED)
void xraudio_samples_convert_fp32_int32(int32_t *int32buf, float *fp32buf, uint32_t sample_qty_frame, uint32_t bit_qty) {
   uint32_t sample;
   int32_t *pi32 = int32buf;
   float *pf32 = fp32buf;

   for(sample = 0; sample < sample_qty_frame; sample++) {
      if(*pf32 < INT32_MIN) {
         *pi32 = INT32_MIN;
      } else if(*pf32 > INT32_MAX) {
         *pi32 = INT32_MAX;
      } else {
         *pi32 = *pf32;
      }
      pf32++;
      pi32++;
   }
}
#endif

int xraudio_in_capture_session_to_file_input(xraudio_session_record_t *session, uint8_t chan, void *data, uint32_t size) {
   // Write requested data into capture file
   errno = 0;
   ssize_t bytes_written = write(session->capture_session.input[chan].file.fd, data, size);
   if(bytes_written != size) {
      int errsv = errno;
      XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
      return(-1);
   }
   session->capture_session.input[chan].file.audio_data_size += size;

   return(size);
}

int xraudio_in_capture_session_to_file_int32(xraudio_capture_point_t *capture_point, int32_t *samples, uint32_t sample_qty_frame) {
   size_t data_size           = sample_qty_frame * sizeof(int32_t);
   uint8_t chan_qty           = capture_point->file.format.channel_qty;
   uint32_t sample_qty_chan   = sample_qty_frame / chan_qty;

   void *buffer = samples;

   // Need to convert to 24-bit for wave format
   uint8_t tmp_buf[sample_qty_frame * 3];
   if(capture_point->file.format.container == XRAUDIO_CONTAINER_WAV) {
      uint32_t j = 0;
      int32_t (*audio_frames)[sample_qty_chan] = (void *)samples;
      for(uint32_t index = 0; index < sample_qty_chan; index++) {
         // interleave samples for multichannel wave file
         for(uint32_t chan = 0; chan < chan_qty; chan++) {
            int32_t sample = audio_frames[chan][index];
            // Handle endian difference for wave container
            #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            tmp_buf[j++] = (sample >> 24) & 0xFF;
            tmp_buf[j++] = (sample >> 16) & 0xFF;
            tmp_buf[j++] = (sample >>  8) & 0xFF;
            #elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            tmp_buf[j++] = (sample >>  8) & 0xFF;
            tmp_buf[j++] = (sample >> 16) & 0xFF;
            tmp_buf[j++] = (sample >> 24) & 0xFF;
            #else
            #error unhandled byte order
            #endif
         }
      }
      buffer    = &tmp_buf[0];
      data_size = sample_qty_frame * 3;
   }

   // Write requested data into capture file
   errno = 0;
   ssize_t bytes_written = write(capture_point->file.fd, buffer, data_size);
   if(bytes_written != data_size) {
      int errsv = errno;
      XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
      return(-1);
   }
   capture_point->file.audio_data_size += data_size;

   // update max/min
   for(uint32_t index = 0; index < sample_qty_frame; index++) {
      if(*samples > capture_point->pcm_range.max) {
         capture_point->pcm_range.max = *samples;
      } else if(*samples < capture_point->pcm_range.min) {
         capture_point->pcm_range.min = *samples;
      }
      samples++;
   }

   return(data_size);
}

int xraudio_in_capture_session_to_file_int16(xraudio_capture_point_t *capture_point, int16_t *samples, uint32_t sample_qty_frame) {
   size_t data_size           = sample_qty_frame * sizeof(int16_t);
   uint8_t chan_qty           = capture_point->file.format.channel_qty;
   uint32_t sample_qty_chan   = sample_qty_frame / chan_qty;

   void *buffer = samples;

   uint8_t tmp_buf[data_size];
   if(capture_point->file.format.container == XRAUDIO_CONTAINER_WAV) {
      uint32_t j = 0;
      int16_t (*audio_frames)[sample_qty_chan] = (void *)samples;
      for(uint32_t index = 0; index < sample_qty_chan; index++) {
         // interleave samples for multichannel wave file
         for(uint32_t chan = 0; chan < chan_qty; chan++) {
            int16_t sample = audio_frames[chan][index];
            // Handle endian difference if wave container
            #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            tmp_buf[j++] = (sample >>  8) & 0xFF;
            tmp_buf[j++] = (sample)       & 0xFF;
            #elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            tmp_buf[j++] = (sample)       & 0xFF;
            tmp_buf[j++] = (sample >>  8) & 0xFF;
            #else
            #error unhandled byte order
            #endif
         }
      }
      buffer   = &tmp_buf[0];
   }

   // Write requested data into capture file
   errno = 0;
   ssize_t bytes_written = write(capture_point->file.fd, buffer, data_size);
   if(bytes_written != data_size) {
      int errsv = errno;
      XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
      return(-1);
   }
   capture_point->file.audio_data_size += data_size;

   // update max/min
   for(uint32_t index = 0; index < sample_qty_frame; index++) {
      if(*samples > capture_point->pcm_range.max) {
         capture_point->pcm_range.max = *samples;
      } else if(*samples < capture_point->pcm_range.min) {
         capture_point->pcm_range.min = *samples;
      }
      samples++;
   }

   return(data_size);
}

#if defined(XRAUDIO_KWD_ENABLED) && defined(XRAUDIO_DGA_ENABLED)
int xraudio_in_capture_session_to_file_float(xraudio_capture_point_t *capture_point, float *samples, uint32_t sample_qty_frame) {
   size_t data_size           = sample_qty_frame * sizeof(int32_t);
   uint8_t chan_qty           = capture_point->file.format.channel_qty;
   uint32_t sample_qty_chan   = sample_qty_frame / chan_qty;

   void *buffer = samples;

   // Need to convert to 24-bit for wave format
   uint8_t tmp_buf[sample_qty_frame * 3];
   if(capture_point->file.format.container == XRAUDIO_CONTAINER_WAV) {
      uint32_t j = 0;
      float (*audio_frames)[sample_qty_chan] = (void *)samples;
      for(uint32_t index = 0; index < sample_qty_chan; index++) {
         // interleave samples for multichannel wave file
         for(uint32_t chan = 0; chan < chan_qty; chan++) {
            float sample = audio_frames[chan][index];
            // Handle endian difference for wave container
            #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            tmp_buf[j++] = ((int32_t)sample >> 24) & 0xFF;
            tmp_buf[j++] = ((int32_t)sample >> 16) & 0xFF;
            tmp_buf[j++] = ((int32_t)sample >>  8) & 0xFF;
            #elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            tmp_buf[j++] = ((int32_t)sample >>  8) & 0xFF;
            tmp_buf[j++] = ((int32_t)sample >> 16) & 0xFF;
            tmp_buf[j++] = ((int32_t)sample >> 24) & 0xFF;
            #else
            #error unhandled byte order
            #endif
         }

      }
      buffer    = &tmp_buf[0];
      data_size = sample_qty_frame * 3;
   }

   // Write requested data into capture file
   errno = 0;
   ssize_t bytes_written = write(capture_point->file.fd, buffer, data_size);
   if(bytes_written != data_size) {
      int errsv = errno;
      XLOGD_ERROR("Error (%zd) <%s>", bytes_written, strerror(errsv));
      return(-1);
   }
   capture_point->file.audio_data_size += data_size;

   // update max/min
   for(uint32_t index = 0; index < sample_qty_frame; index++) {
      if(*samples > capture_point->pcm_range.max) {
         capture_point->pcm_range.max = *samples;
      } else if(*samples < capture_point->pcm_range.min) {
         capture_point->pcm_range.min = *samples;
      }
      samples++;
   }

   return(data_size);
}
#endif

xraudio_devices_input_t xraudio_in_session_group_source_get(xraudio_input_session_group_t group) {
   return(xraudio_atomic_int_get(&g_voice_session.source[group]));
}

bool xraudio_in_session_group_semaphore_lock(xraudio_devices_input_t source) {
   uint32_t group = xraudio_input_source_to_group(source); // Select the group based on source type

   if(xraudio_atomic_compare_and_set(&g_voice_session.source[group], XRAUDIO_DEVICE_INPUT_NONE, source)) {
      XLOGD_TELEMETRY("group <%s> source <%s>", xraudio_input_session_group_str(group), xraudio_devices_input_str(source));
      return(true);
   }
   //xraudio_devices_input_str() returns the address of a static variable, so cannot use it twice in a single print
   XLOGD_ERROR("group <%s> Voice Session denied for source <%s>", xraudio_input_session_group_str(group), xraudio_devices_input_str(source));
   XLOGD_ERROR("Existing session still in progress on source <%s>", xraudio_devices_input_str(xraudio_in_session_group_source_get(group)));
   return(false);
}

void xraudio_in_session_record_group_semaphore_unlock(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_devices_input_t source) {
   uint32_t group = xraudio_input_source_to_group(source); // Select the group based on source type
   xraudio_atomic_int_set(&g_voice_session.source[group], XRAUDIO_DEVICE_INPUT_NONE);
   g_voice_session.detecting         = 1; // Used to make sure we don't close HAL when detecting stops
   g_voice_session.sources_supported = session->devices_input;
   g_voice_session.msgq              = params->msgq;
   #ifdef MICROPHONE_TAP_ENABLED
   if(XRAUDIO_DEVICE_INPUT_LOCAL_GET(g_voice_session.sources_supported)) {
      g_voice_session.sources_supported |= XRAUDIO_DEVICE_INPUT_MIC_TAP;
   }
   #endif

   XLOGD_INFO("group <%s>", xraudio_input_session_group_str(group));
}

void xraudio_in_session_group_semaphore_unlock(xraudio_thread_state_t *state, xraudio_devices_input_t source) {
   xraudio_in_session_record_group_semaphore_unlock(&state->params, &state->record, source);
}

xraudio_session_record_inst_t *xraudio_in_source_to_inst(xraudio_session_record_t *session, xraudio_devices_input_t source) {
   return(&session->instances[xraudio_input_source_to_group(source)]);
}

#ifdef XRAUDIO_KWD_ENABLED
bool xraudio_in_aop_adjust_apply(int32_t *buffer, uint32_t sample_qty_frame, int8_t input_aop_adjust_shift) {
   int32_t *buffer_in_int32 = buffer;
   if(input_aop_adjust_shift >= 0) {
      return(false); // xraudio AOP greater than input mic AOP not supported
   }
   int32_t max_value = INT32_MAX >> abs(input_aop_adjust_shift);
   int32_t min_value = INT32_MIN >> abs(input_aop_adjust_shift);

   for(uint32_t i = 0; i < sample_qty_frame; i++) {
      if(*buffer_in_int32 > max_value) {
         *buffer_in_int32 = INT32_MAX;
      } else if(*buffer_in_int32 < min_value) {
         *buffer_in_int32 = INT32_MIN;
      } else {
         *buffer_in_int32 <<= abs(input_aop_adjust_shift);
      }
      buffer_in_int32++;
   }
   return(true);
}
#endif

#ifdef CURTAIL_ENABLED
#define DEFAULT_SECTOR_SIZE (4096)
void xraudio_capture_file_size_max_verify(uint32_t *file_size_max) {
   if(*file_size_max % DEFAULT_SECTOR_SIZE) {
      *file_size_max -= *file_size_max % DEFAULT_SECTOR_SIZE;
      XLOGD_WARN("file size max should be an integer multiple of the block size (%u bytes) updated to <%u>", DEFAULT_SECTOR_SIZE, *file_size_max);
   }
   if(*file_size_max < 2 * DEFAULT_SECTOR_SIZE) {
      *file_size_max = 2 * DEFAULT_SECTOR_SIZE;
      XLOGD_WARN("file size max must be greater than 2x block size (%u bytes) updated to <%u>", DEFAULT_SECTOR_SIZE, *file_size_max);
   }
}
#endif

void xraudio_cpu_util_mode_enter(xraudio_thread_state_t *state, xraudio_session_record_inst_t *instance) {
   #ifdef XRAUDIO_KWD_ENABLED
   // Set keyword detector to single channel to conserve cpu
   uint8_t first_chan_kwd = state->params.dsp_config.input_asr_max_channel_qty;
   state->record.keyword_detector.single_channel = first_chan_kwd + XRAUDIO_INPUT_BEAM_INDEX_CENTER;

   // Set EOS detector to single channel to conserve cpu
   state->record.eos_detector.single_channel = XRAUDIO_INPUT_BEAM_INDEX_CENTER;
   #endif

   state->record.cpu_util_mode = instance->cpu_util_mode;
}

void xraudio_cpu_util_mode_exit(xraudio_session_record_t *session) {
   // Set keyword detector back to multi channel
   session->keyword_detector.single_channel = XRAUDIO_INPUT_BEAM_INDEX_NONE;

   // Set eos detector back to multi channel
   session->eos_detector.single_channel = XRAUDIO_INPUT_BEAM_INDEX_NONE;

   session->cpu_util_mode = XRAUDIO_STREAM_CPU_UTIL_NORMAL;
}

#ifdef XRAUDIO_PPR_ENABLED
void xraudio_preprocess_mic_data(xraudio_main_thread_params_t *params, xraudio_session_record_t *session, xraudio_ppr_event_t *ppr_event) {
   xraudio_devices_input_t device_input_local = XRAUDIO_DEVICE_INPUT_LOCAL_GET(session->devices_input);
   xraudio_devices_input_t device_input_ecref = XRAUDIO_DEVICE_INPUT_EC_REF_GET(session->devices_input);
   uint8_t chan_qty_mic   = (device_input_local == XRAUDIO_DEVICE_INPUT_QUAD) ? 4 : (device_input_local == XRAUDIO_DEVICE_INPUT_TRI) ? 3 : 1;
   uint8_t chan_qty_ecref = (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_5_1) ? 6 : (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_STEREO) ? 2 : (device_input_ecref == XRAUDIO_DEVICE_INPUT_EC_REF_MONO) ? 1 : 0;
   uint8_t chan_qty_total = (chan_qty_mic + chan_qty_ecref);
   uint32_t bit_qty = session->pcm_bit_qty;

   // Preprocess mic and ref input buffers and postprocess kwd, asr, and ref output buffers
   // Declare arrays of pointers to int32 frame buffers needed for preprocess
   xraudio_audio_frame_int32_t ppmic_input_buffers[chan_qty_mic];
   xraudio_audio_frame_int32_t ppref_input_buffers[chan_qty_ecref];
   xraudio_audio_frame_int32_t ppasr_output_buffers[XRAUDIO_INPUT_ASR_MAX_CHANNEL_QTY];
   xraudio_audio_frame_int32_t ppkwd_output_buffers[XRAUDIO_INPUT_KWD_MAX_CHANNEL_QTY];
   xraudio_audio_frame_int32_t ppref_output_buffers[chan_qty_ecref];
   const int32_t **ppmic_inputs = (const int32_t **)&ppmic_input_buffers[0];
   const int32_t **ppref_inputs = (const int32_t **)&ppref_input_buffers[0];
   int32_t **ppasr_outputs = (int32_t **)&ppasr_output_buffers[0];
   int32_t **ppkwd_outputs = (int32_t **)&ppkwd_output_buffers[0];
   int32_t **ppref_outputs = (int32_t **)&ppref_output_buffers[0];

   // prepare input buffer pointers for preprocess: convert 16 bit int samples to 32 bit int samples
   uint8_t ref_chan = 0;
   int16_t *pi16 = NULL;
   int32_t *pi32 = NULL;
   float *pf32 = NULL;
   for(uint8_t chan = 0; chan < chan_qty_total; ++chan) {
      if(chan < chan_qty_mic) {
         pf32 = &session->frame_buffer_fp32[chan].frames[session->frame_group_index].samples[0];
         pi32 = &ppmic_input_buffers[chan].samples[0];
         xraudio_samples_convert_fp32_int32(pi32, pf32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
      } else {
         pf32 = &session->frame_buffer_fp32[chan].frames[session->frame_group_index].samples[0];
         pi32 = &ppref_input_buffers[ref_chan].samples[0];
         xraudio_samples_convert_fp32_int32(pi32, pf32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
         ref_chan++;
      }
   }
   #define XRAUDIO_PPR_DEBUGoff

   #ifdef XRAUDIO_PPR_DEBUG
   // bypass xraudio_ppr for debugging
   memcpy((uint8_t *)ppasr_outputs, (const uint8_t *)ppmic_inputs, sizeof(int32_t)*params->dsp_config.input_asr_max_channel_qty*XRAUDIO_INPUT_FRAME_SAMPLE_QTY);
   memcpy((uint8_t *)ppkwd_outputs, (const uint8_t *)ppmic_inputs + sizeof(int32_t)*params->dsp_config.input_asr_max_channel_qty*XRAUDIO_INPUT_FRAME_SAMPLE_QTY, sizeof(int32_t)*params->dsp_config.input_kwd_max_channel_qty*XRAUDIO_INPUT_FRAME_SAMPLE_QTY);
   memcpy((uint8_t *)ppref_outputs, (const uint8_t *)ppref_inputs, sizeof(int32_t)*chan_qty_ecref*XRAUDIO_INPUT_FRAME_SAMPLE_QTY);
   *ppr_event = XRAUDIO_PPR_EVENT_NONE;
   #else
   *ppr_event = xraudio_input_ppr_run(
         params->obj_input,
         XRAUDIO_INPUT_FRAME_SAMPLE_QTY,
         (const int32_t **)&ppmic_inputs,
         (const int32_t **)&ppref_inputs,
         (int32_t **)&ppkwd_outputs,
         (int32_t **)&ppasr_outputs,
         (int32_t **)&ppref_outputs
         );
   #endif

   // update contents of postprocess buffers after preprocess
   ref_chan = 0;
   uint8_t kwd_chan = 0;
   for(uint8_t chan = 0; chan < chan_qty_total; ++chan) {
      if(chan < params->dsp_config.input_asr_max_channel_qty) {
         pi32 = &ppasr_output_buffers[chan].samples[0];
         pi16 = &session->frame_buffer_int16[chan].frames[session->frame_group_index].samples[0];
         pf32 = &session->frame_buffer_fp32[chan].frames[session->frame_group_index].samples[0];
         xraudio_samples_convert_int32_int16(pi16, pi32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
         xraudio_samples_convert_int32_fp32(pf32, pi32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
      } else if(chan < params->dsp_config.input_kwd_max_channel_qty + params->dsp_config.input_asr_max_channel_qty) {
         pi32 = &ppkwd_output_buffers[kwd_chan].samples[0];
         pi16 = &session->frame_buffer_int16[chan].frames[session->frame_group_index].samples[0];
         pf32 = &session->frame_buffer_fp32[chan].frames[session->frame_group_index].samples[0];
         xraudio_samples_convert_int32_int16(pi16, pi32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
         xraudio_samples_convert_int32_fp32(pf32, pi32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
         kwd_chan++;
      } else if(chan >= chan_qty_mic) {
         pi32 = &ppref_output_buffers[ref_chan].samples[0];
         pi16 = &session->frame_buffer_int16[chan].frames[session->frame_group_index].samples[0];
         pf32 = &session->frame_buffer_fp32[chan].frames[session->frame_group_index].samples[0];
         xraudio_samples_convert_int32_int16(pi16, pi32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
         xraudio_samples_convert_int32_fp32(pf32, pi32, XRAUDIO_INPUT_FRAME_SAMPLE_QTY, bit_qty);
         ref_chan++;
      }
   }
}
#endif  // end #define XRAUDIO_PPR_ENABLED
