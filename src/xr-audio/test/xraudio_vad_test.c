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

/*
 * xraudio_vad_test.c
 *
 * Standalone test program for the xraudio VAD component.
 *
 * Usage:
 *   xraudio_vad_test [OPTIONS] <wave_dir> <output_file>
 *
 * Arguments:
 *   wave_dir     Directory containing 16-bit mono 16 kHz PCM WAV files
 *   output_file  Path to write the statistics report (JSON format)
 *
 * Options:
 *   --sensitivity <0.0-1.0>       VAD sensitivity (default: 0.9)
 *   --analysis-window <ms>        Analysis window in ms  (default: 100)
 *   --rms-level-min <dB>          Minimum RMS level dB   (default: -60)
 *   --intro-window <ms>           Intro window in ms     (default: 100)
 *   --frame-size-ms <ms>          Frame size in ms       (default: 20)
 *   --help                        Print this help message
 *
 * The output file contains a top-level JSON object with the keys:
 *   "config"  - VAD configuration used for all files
 *   "files"   - Array of per-file result objects
 *   "summary" - Aggregate statistics across all processed files
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <math.h>
#include <time.h>

#include "xraudio_vad.h"
#include "xraudio_common.h"

/* -------------------------------------------------------------------------
 * WAV file parsing
 * ------------------------------------------------------------------------- */

#define WAV_RIFF_TAG       0x46464952u  /* "RIFF" little-endian */
#define WAV_WAVE_TAG       0x45564157u  /* "WAVE" little-endian */
#define WAV_FMT_TAG        0x20746d66u  /* "fmt " little-endian */
#define WAV_DATA_TAG       0x61746164u  /* "data" little-endian */
#define WAV_PCM_FORMAT     1
#define WAV_REQUIRED_RATE  16000
#define WAV_REQUIRED_BITS  16
#define WAV_REQUIRED_CHANS 1

typedef struct {
    uint32_t chunk_id;
    uint32_t chunk_size;
    uint32_t format;
} wav_riff_header_t;

typedef struct {
    uint16_t audio_format;
    uint16_t num_channels;
    uint32_t sample_rate;
    uint32_t byte_rate;
    uint16_t block_align;
    uint16_t bits_per_sample;
} wav_fmt_chunk_t;

typedef struct {
    FILE    *fp;
    uint32_t sample_rate;
    uint16_t bits_per_sample;
    uint16_t num_channels;
    uint32_t data_bytes;   /* total bytes in the data chunk */
    long     data_offset;  /* file offset of first data byte */
} wav_file_t;

/*
 * Read a sub-chunk header (id + size) from fp.
 * Returns true on success, false on EOF or error.
 */
static bool wav_read_chunk_header(FILE *fp, uint32_t *id, uint32_t *size) {
    uint8_t buf[8];
    if (fread(buf, 1, 8, fp) != 8) {
        return false;
    }
    *id   = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    *size = (uint32_t)buf[4] | ((uint32_t)buf[5] << 8) | ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 24);
    return true;
}

/*
 * Open and validate a WAV file.  Only 16-bit mono 16 kHz PCM is accepted.
 * Returns true on success, false on error (details printed to stderr).
 */
static bool wav_open(const char *path, wav_file_t *wav) {
    memset(wav, 0, sizeof(*wav));

    wav->fp = fopen(path, "rb");
    if (wav->fp == NULL) {
        fprintf(stderr, "  ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return false;
    }

    /* RIFF header */
    wav_riff_header_t riff;
    if (fread(&riff, 1, sizeof(riff), wav->fp) != sizeof(riff)) {
        fprintf(stderr, "  ERROR: '%s': truncated RIFF header\n", path);
        fclose(wav->fp);
        return false;
    }
    if (riff.chunk_id != WAV_RIFF_TAG || riff.format != WAV_WAVE_TAG) {
        fprintf(stderr, "  ERROR: '%s': not a valid WAVE file\n", path);
        fclose(wav->fp);
        return false;
    }

    /* Walk sub-chunks looking for "fmt " and "data" */
    bool found_fmt  = false;
    bool found_data = false;
    while (!found_data) {
        uint32_t chunk_id, chunk_size;
        if (!wav_read_chunk_header(wav->fp, &chunk_id, &chunk_size)) {
            break;
        }

        if (chunk_id == WAV_FMT_TAG) {
            if (chunk_size < sizeof(wav_fmt_chunk_t)) {
                fprintf(stderr, "  ERROR: '%s': fmt chunk too small (%u bytes)\n", path, chunk_size);
                fclose(wav->fp);
                return false;
            }
            wav_fmt_chunk_t fmt;
            if (fread(&fmt, 1, sizeof(fmt), wav->fp) != sizeof(fmt)) {
                fprintf(stderr, "  ERROR: '%s': truncated fmt chunk\n", path);
                fclose(wav->fp);
                return false;
            }
            /* Skip any extra fmt bytes */
            if (chunk_size > sizeof(fmt)) {
                fseek(wav->fp, (long)(chunk_size - sizeof(fmt)), SEEK_CUR);
            }

            if (fmt.audio_format != WAV_PCM_FORMAT) {
                fprintf(stderr, "  ERROR: '%s': unsupported audio format %u (only PCM)\n", path, fmt.audio_format);
                fclose(wav->fp);
                return false;
            }
            if (fmt.num_channels != WAV_REQUIRED_CHANS) {
                fprintf(stderr, "  ERROR: '%s': %u channels (mono required)\n", path, fmt.num_channels);
                fclose(wav->fp);
                return false;
            }
            if (fmt.sample_rate != WAV_REQUIRED_RATE) {
                fprintf(stderr, "  ERROR: '%s': %u Hz sample rate (%u Hz required)\n", path, fmt.sample_rate, WAV_REQUIRED_RATE);
                fclose(wav->fp);
                return false;
            }
            if (fmt.bits_per_sample != WAV_REQUIRED_BITS) {
                fprintf(stderr, "  ERROR: '%s': %u bits per sample (%u required)\n", path, fmt.bits_per_sample, WAV_REQUIRED_BITS);
                fclose(wav->fp);
                return false;
            }

            wav->sample_rate    = fmt.sample_rate;
            wav->bits_per_sample = fmt.bits_per_sample;
            wav->num_channels   = fmt.num_channels;
            found_fmt           = true;

        } else if (chunk_id == WAV_DATA_TAG) {
            if (!found_fmt) {
                fprintf(stderr, "  ERROR: '%s': data chunk before fmt chunk\n", path);
                fclose(wav->fp);
                return false;
            }
            wav->data_bytes  = chunk_size;
            wav->data_offset = ftell(wav->fp);
            found_data       = true;

        } else {
            /* Unknown chunk — skip */
            fseek(wav->fp, (long)chunk_size, SEEK_CUR);
        }
    }

    if (!found_data) {
        fprintf(stderr, "  ERROR: '%s': no data chunk found\n", path);
        fclose(wav->fp);
        return false;
    }

    return true;
}

static void wav_close(wav_file_t *wav) {
    if (wav->fp) {
        fclose(wav->fp);
        wav->fp = NULL;
    }
}

/* -------------------------------------------------------------------------
 * Per-file result
 * ------------------------------------------------------------------------- */

typedef struct {
    char               filename[512];
    bool               processed;
    uint32_t           duration_ms;
    xraudio_vad_stats_t stats;
} vad_file_result_t;

/* -------------------------------------------------------------------------
 * JSON helpers — minimal hand-rolled output to avoid external deps
 * ------------------------------------------------------------------------- */

static void json_write_uint(FILE *fp, const char *key, uint32_t value) {
    fprintf(fp, "      \"%s\": %u", key, value);
}

static void json_write_float(FILE *fp, const char *key, float value, int decimals) {
    fprintf(fp, "      \"%s\": %.*f", key, decimals, (double)value);
}

/* -------------------------------------------------------------------------
 * Report writing
 * ------------------------------------------------------------------------- */

static void write_stats_fields(FILE *fp, const xraudio_vad_stats_t *s) {
    json_write_uint(fp,  "frames_processed",   s->frames_processed);   fprintf(fp, ",\n");
    json_write_uint(fp,  "frames_voice",        s->frames_voice);        fprintf(fp, ",\n");
    json_write_uint(fp,  "frames_silence",      s->frames_silence);      fprintf(fp, ",\n");
    json_write_uint(fp,  "state_transitions",   s->state_transitions);   fprintf(fp, ",\n");
    json_write_float(fp, "rms_level_average",   s->rms_level_average,  2); fprintf(fp, ",\n");
    json_write_float(fp, "rms_level_peak",      s->rms_level_peak,     2); fprintf(fp, ",\n");
    json_write_float(fp, "confidence_average",  s->confidence_average, 4); fprintf(fp, ",\n");
    json_write_float(fp, "confidence_peak",     s->confidence_peak,    4); fprintf(fp, ",\n");
    json_write_float(fp, "cpu_utilization",     s->cpu_utilization,    2);
}

static bool write_report(const char *output_path,
                         const xraudio_input_vad_config_t *config,
                         uint32_t frame_size_ms,
                         const vad_file_result_t *results,
                         uint32_t result_count)
{
    FILE *fp = fopen(output_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: cannot open output file '%s': %s\n", output_path, strerror(errno));
        return false;
    }

    /* Timestamp */
    time_t now = time(NULL);
    char   ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    fprintf(fp, "{\n");
    fprintf(fp, "  \"generated\": \"%s\",\n", ts);

    /* Configuration block */
    fprintf(fp, "  \"config\": {\n");
    fprintf(fp, "    \"sensitivity\": %.4f,\n",       (double)config->sensitivity);
    fprintf(fp, "    \"analysis_window_ms\": %u,\n",  (unsigned)config->analysis_window_ms);
    fprintf(fp, "    \"audio_rms_level_min\": %.2f,\n",(double)config->audio_rms_level_min);
    fprintf(fp, "    \"intro_window_ms\": %u,\n",     (unsigned)config->intro_window_ms);
    fprintf(fp, "    \"frame_size_ms\": %u\n",        (unsigned)frame_size_ms);
    fprintf(fp, "  },\n");

    /* Per-file results */
    fprintf(fp, "  \"files\": [\n");
    uint32_t processed_count = 0;
    for (uint32_t i = 0; i < result_count; i++) {
        const vad_file_result_t *r = &results[i];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"filename\": \"%s\",\n",  r->filename);
        fprintf(fp, "      \"processed\": %s,\n",     r->processed ? "true" : "false");
        if (r->processed) {
            fprintf(fp, "      \"duration_ms\": %u,\n", r->duration_ms);
            write_stats_fields(fp, &r->stats);
            fprintf(fp, "\n");
            processed_count++;
        }
        fprintf(fp, "    }%s\n", (i + 1 < result_count) ? "," : "");
    }
    fprintf(fp, "  ],\n");

    /* Summary — aggregate over successfully processed files */
    fprintf(fp, "  \"summary\": {\n");
    fprintf(fp, "    \"total_files\": %u,\n",      result_count);
    fprintf(fp, "    \"processed_files\": %u,\n",  processed_count);
    fprintf(fp, "    \"failed_files\": %u", result_count - processed_count);

    if (processed_count > 0) {
        xraudio_vad_stats_t agg;
        memset(&agg, 0, sizeof(agg));
        agg.rms_level_peak    = -200.0f;
        agg.confidence_peak   = 0.0f;

        uint32_t total_duration_ms = 0;

        for (uint32_t i = 0; i < result_count; i++) {
            const vad_file_result_t *r = &results[i];
            if (!r->processed) { continue; }
            const xraudio_vad_stats_t *s = &r->stats;

            agg.frames_processed += s->frames_processed;
            agg.frames_voice     += s->frames_voice;
            agg.frames_silence   += s->frames_silence;
            agg.state_transitions+= s->state_transitions;

            if (s->rms_level_peak  > agg.rms_level_peak)  { agg.rms_level_peak  = s->rms_level_peak;  }
            if (s->confidence_peak > agg.confidence_peak) { agg.confidence_peak = s->confidence_peak; }

            /* Weighted average by frame count */
            if (agg.frames_processed > 0) {
                agg.rms_level_average  += s->rms_level_average  * (float)s->frames_processed;
                agg.confidence_average += s->confidence_average * (float)s->frames_processed;
            }

            total_duration_ms += r->duration_ms;
        }

        /* Normalise weighted averages */
        if (agg.frames_processed > 0) {
            agg.rms_level_average  /= (float)agg.frames_processed;
            agg.confidence_average /= (float)agg.frames_processed;
        }

        float voice_percent = (agg.frames_processed > 0)
            ? 100.0f * (float)agg.frames_voice / (float)agg.frames_processed
            : 0.0f;

        fprintf(fp, ",\n");
        fprintf(fp, "    \"total_duration_ms\": %u,\n",     total_duration_ms);
        fprintf(fp, "    \"total_frames_processed\": %u,\n", agg.frames_processed);
        fprintf(fp, "    \"total_frames_voice\": %u,\n",     agg.frames_voice);
        fprintf(fp, "    \"total_frames_silence\": %u,\n",   agg.frames_silence);
        fprintf(fp, "    \"total_state_transitions\": %u,\n",agg.state_transitions);
        fprintf(fp, "    \"voice_percent\": %.2f,\n",        (double)voice_percent);
        fprintf(fp, "    \"rms_level_average\": %.2f,\n",    (double)agg.rms_level_average);
        fprintf(fp, "    \"rms_level_peak\": %.2f,\n",       (double)agg.rms_level_peak);
        fprintf(fp, "    \"confidence_average\": %.4f,\n",   (double)agg.confidence_average);
        fprintf(fp, "    \"confidence_peak\": %.4f\n",       (double)agg.confidence_peak);
    } else {
        fprintf(fp, "\n");
    }

    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return true;
}

/* -------------------------------------------------------------------------
 * Usage
 * ------------------------------------------------------------------------- */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS] <wave_dir> <output_file>\n"
        "\n"
        "Arguments:\n"
        "  wave_dir     Directory containing 16-bit mono 16 kHz PCM WAV files\n"
        "  output_file  Path for the JSON statistics report\n"
        "\n"
        "Options:\n"
        "  --sensitivity <0.0-1.0>   VAD sensitivity          (default: %.1f)\n"
        "  --analysis-window <ms>    Analysis window in ms     (default: %u)\n"
        "  --rms-level-min <dB>      Minimum audio RMS dB      (default: %.0f)\n"
        "  --intro-window <ms>       Intro window in ms        (default: %u)\n"
        "  --frame-size-ms <ms>      Audio frame size in ms    (default: %u, min: 10)\n"
        "  --help                    Print this help message\n",
        prog,
        (double)XRAUDIO_VAD_DEFAULT_SENSITIVITY,
        (unsigned)XRAUDIO_VAD_DEFAULT_ANALYSIS_WINDOW_MS,
        (double)XRAUDIO_VAD_DEFAULT_AUDIO_RMS_LEVEL_MIN,
        (unsigned)XRAUDIO_VAD_DEFAULT_INTRO_WINDOW_MS,
        20u);
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    /* Default VAD configuration */
    xraudio_input_vad_config_t config = {
        .sensitivity         = (float)XRAUDIO_VAD_DEFAULT_SENSITIVITY,
        .analysis_window_ms  = XRAUDIO_VAD_DEFAULT_ANALYSIS_WINDOW_MS,
        .audio_rms_level_min = (float)XRAUDIO_VAD_DEFAULT_AUDIO_RMS_LEVEL_MIN,
        .intro_window_ms     = XRAUDIO_VAD_DEFAULT_INTRO_WINDOW_MS,
    };
    uint32_t frame_size_ms = 20;

    /* Parse optional arguments */
    int arg_idx = 1;
    for (; arg_idx < argc; arg_idx++) {
        if (strcmp(argv[arg_idx], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[arg_idx], "--sensitivity") == 0 && arg_idx + 1 < argc) {
            config.sensitivity = (float)atof(argv[++arg_idx]);
        } else if (strcmp(argv[arg_idx], "--analysis-window") == 0 && arg_idx + 1 < argc) {
            config.analysis_window_ms = (uint16_t)atoi(argv[++arg_idx]);
        } else if (strcmp(argv[arg_idx], "--rms-level-min") == 0 && arg_idx + 1 < argc) {
            config.audio_rms_level_min = (float)atof(argv[++arg_idx]);
        } else if (strcmp(argv[arg_idx], "--intro-window") == 0 && arg_idx + 1 < argc) {
            config.intro_window_ms = (uint16_t)atoi(argv[++arg_idx]);
        } else if (strcmp(argv[arg_idx], "--frame-size-ms") == 0 && arg_idx + 1 < argc) {
            frame_size_ms = (uint32_t)atoi(argv[++arg_idx]);
            if (frame_size_ms < 10) {
                fprintf(stderr, "ERROR: --frame-size-ms must be >= 10\n");
                return 1;
            }
        } else {
            /* Not an option — stop parsing */
            break;
        }
    }

    if (argc - arg_idx < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *wave_dir    = argv[arg_idx];
    const char *output_file = argv[arg_idx + 1];

    /* Validate wave_dir */
    struct stat dir_stat;
    if (stat(wave_dir, &dir_stat) != 0 || !S_ISDIR(dir_stat.st_mode)) {
        fprintf(stderr, "ERROR: '%s' is not a valid directory\n", wave_dir);
        return 1;
    }

    /* Collect sorted list of *.wav files */
    DIR *dp = opendir(wave_dir);
    if (dp == NULL) {
        fprintf(stderr, "ERROR: cannot open directory '%s': %s\n", wave_dir, strerror(errno));
        return 1;
    }

    /* First pass: count */
    uint32_t wav_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) { continue; }
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcasecmp(entry->d_name + len - 4, ".wav") == 0) {
            wav_count++;
        }
    }
    rewinddir(dp);

    if (wav_count == 0) {
        fprintf(stderr, "WARNING: no .wav files found in '%s'\n", wave_dir);
        closedir(dp);
        /* Write an empty report */
        write_report(output_file, &config, frame_size_ms, NULL, 0);
        return 0;
    }

    /* Collect filenames */
    char **wav_names = (char **)calloc(wav_count, sizeof(char *));
    if (wav_names == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        closedir(dp);
        return 1;
    }
    uint32_t name_idx = 0;
    while ((entry = readdir(dp)) != NULL && name_idx < wav_count) {
        if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) { continue; }
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcasecmp(entry->d_name + len - 4, ".wav") == 0) {
            wav_names[name_idx] = strdup(entry->d_name);
            if (wav_names[name_idx] == NULL) {
                fprintf(stderr, "ERROR: out of memory\n");
                closedir(dp);
                return 1;
            }
            name_idx++;
        }
    }
    closedir(dp);
    wav_count = name_idx; /* actual count after second pass */

    /* Sort alphabetically for deterministic output */
    for (uint32_t i = 0; i < wav_count - 1; i++) {
        for (uint32_t j = i + 1; j < wav_count; j++) {
            if (strcmp(wav_names[i], wav_names[j]) > 0) {
                char *tmp    = wav_names[i];
                wav_names[i] = wav_names[j];
                wav_names[j] = tmp;
            }
        }
    }

    /* Allocate result array */
    vad_file_result_t *results = (vad_file_result_t *)calloc(wav_count, sizeof(vad_file_result_t));
    if (results == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        return 1;
    }

    /* Frame size in samples (16 kHz, 16-bit mono) */
    const uint32_t samples_per_frame = (WAV_REQUIRED_RATE * frame_size_ms) / 1000u;
    const size_t   bytes_per_frame   = samples_per_frame * sizeof(int16_t);
    int16_t       *frame_buf         = (int16_t *)malloc(bytes_per_frame);
    if (frame_buf == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        free(results);
        return 1;
    }

    fprintf(stdout, "xraudio_vad_test: processing %u file(s) from '%s'\n", wav_count, wave_dir);
    fprintf(stdout, "  sensitivity=%.2f  analysis_window=%u ms  rms_min=%.1f dB"
                    "  intro_window=%u ms  frame=%u ms (%u samples)\n",
            (double)config.sensitivity,
            (unsigned)config.analysis_window_ms,
            (double)config.audio_rms_level_min,
            (unsigned)config.intro_window_ms,
            (unsigned)frame_size_ms,
            (unsigned)samples_per_frame);

    /* Process each file */
    for (uint32_t i = 0; i < wav_count; i++) {
        vad_file_result_t *res = &results[i];
        snprintf(res->filename, sizeof(res->filename), "%s", wav_names[i]);
        res->processed = false;

        /* Build full path */
        char path[1024];
        int  path_len = snprintf(path, sizeof(path), "%s/%s", wave_dir, wav_names[i]);
        if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
            fprintf(stderr, "  [%u/%u] SKIP '%s': path too long\n", i + 1, wav_count, wav_names[i]);
            continue;
        }

        fprintf(stdout, "  [%u/%u] %s ... ", i + 1, wav_count, wav_names[i]);
        fflush(stdout);

        /* Open WAV */
        wav_file_t wav;
        if (!wav_open(path, &wav)) {
            fprintf(stdout, "FAILED (open)\n");
            continue;
        }

        uint32_t total_samples = wav.data_bytes / sizeof(int16_t);
        res->duration_ms = (total_samples * 1000u) / WAV_REQUIRED_RATE;

        /* Create VAD object */
        xraudio_vad_object_t vad = xraudio_vad_create(&config, WAV_REQUIRED_RATE);
        if (vad == NULL) {
            fprintf(stdout, "FAILED (vad_create)\n");
            wav_close(&wav);
            continue;
        }

        /* Feed frames */
        uint32_t              frames_submitted = 0;
        xraudio_vad_event_data_t vad_event;
        bool                  read_error = false;

        while (true) {
            size_t bytes_read = fread(frame_buf, 1, bytes_per_frame, wav.fp);
            if (bytes_read == 0) { break; }

            /* Zero-pad a partial final frame */
            if (bytes_read < bytes_per_frame) {
                memset((uint8_t *)frame_buf + bytes_read, 0, bytes_per_frame - bytes_read);
            }

            uint32_t samples_in_read = (uint32_t)(bytes_read / sizeof(int16_t));
            /* Always pass a full frame to xraudio_vad_process_frame */
            uint32_t samples_to_pass = samples_per_frame;

            memset(&vad_event, 0, sizeof(vad_event));
            xraudio_result_t rc = xraudio_vad_process_frame(vad,
                                                            (const xraudio_sample_t *)frame_buf,
                                                            samples_to_pass,
                                                            &vad_event);
            if (rc != XRAUDIO_RESULT_OK) {
                fprintf(stderr, "\n  WARNING: xraudio_vad_process_frame returned %d on frame %u\n",
                        rc, frames_submitted);
                read_error = true;
                break;
            }
            frames_submitted++;
            (void)samples_in_read; /* used for partial frame handling above */
        }

        wav_close(&wav);

        if (!read_error) {
            /* Retrieve statistics with finalize=true */
            xraudio_result_t rc = xraudio_vad_get_stats(vad, &res->stats, true);
            if (rc != XRAUDIO_RESULT_OK) {
                fprintf(stdout, "FAILED (vad_get_stats rc=%d)\n", rc);
            } else {
                res->processed = true;
                fprintf(stdout, "OK  (%u frames, voice=%.1f%%)\n",
                        res->stats.frames_processed,
                        res->stats.frames_processed > 0
                            ? 100.0 * (double)res->stats.frames_voice / (double)res->stats.frames_processed
                            : 0.0);
            }
        } else {
            fprintf(stdout, "FAILED (process_frame)\n");
        }

        xraudio_vad_destroy(vad);
    }

    free(frame_buf);

    /* Write the report */
    bool report_ok = write_report(output_file, &config, frame_size_ms, results, wav_count);
    if (report_ok) {
        fprintf(stdout, "\nReport written to: %s\n", output_file);
    }

    /* Free resources */
    for (uint32_t i = 0; i < wav_count; i++) {
        free(wav_names[i]);
    }
    free(wav_names);
    free(results);

    return report_ok ? 0 : 1;
}
