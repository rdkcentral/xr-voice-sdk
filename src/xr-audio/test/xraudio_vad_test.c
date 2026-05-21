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
 *   wave_dir     Directory containing two subdirectories:
 *                  silent/  - WAV files expected to be rejected by the VAD
 *                  normal/  - WAV files expected to be accepted by the VAD
 *                Each subdirectory must contain 16-bit mono 16 kHz PCM WAV files.
 *   output_file  Path to write the statistics report (JSON format)
 *
 * The output summary includes:
 *   "false_accept_rate" - % of silent files incorrectly accepted by the VAD
 *   "false_reject_rate" - % of normal files incorrectly rejected by the VAD
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

typedef enum {
    VAD_CATEGORY_SILENT = 0,  /* file should be rejected by the VAD */
    VAD_CATEGORY_NORMAL = 1,  /* file should be accepted by the VAD */
} vad_file_category_t;

typedef struct {
    char                filename[512];   /* relative path: "silent/foo.wav" or "normal/foo.wav" */
    vad_file_category_t category;
    bool                processed;
    bool                vad_accepted;    /* true if VAD detected voice activity (frames_voice > 0) */
    uint32_t            duration_ms;
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
        fprintf(fp, "      \"category\": \"%s\",\n",  r->category == VAD_CATEGORY_SILENT ? "silent" : "normal");
        fprintf(fp, "      \"processed\": %s,\n",     r->processed ? "true" : "false");
        if (r->processed) {
            fprintf(fp, "      \"vad_accepted\": %s,\n", r->vad_accepted ? "true" : "false");
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
    fprintf(fp, "    \"failed_files\": %u,\n",     result_count - processed_count);

    /* Per-category VAD accuracy metrics */
    uint32_t silent_total = 0, silent_processed = 0, silent_false_accepts = 0;
    uint32_t normal_total = 0, normal_processed = 0, normal_false_rejects  = 0;

    for (uint32_t i = 0; i < result_count; i++) {
        const vad_file_result_t *r = &results[i];
        if (r->category == VAD_CATEGORY_SILENT) {
            silent_total++;
            if (r->processed) {
                silent_processed++;
                if (r->vad_accepted) { silent_false_accepts++; }
            }
        } else {
            normal_total++;
            if (r->processed) {
                normal_processed++;
                if (!r->vad_accepted) { normal_false_rejects++; }
            }
        }
    }

    float false_accept_rate = (silent_processed > 0)
        ? 100.0f * (float)silent_false_accepts / (float)silent_processed : 0.0f;
    float false_reject_rate = (normal_processed > 0)
        ? 100.0f * (float)normal_false_rejects / (float)normal_processed : 0.0f;

    fprintf(fp, "    \"silent_files\": %u,\n",         silent_total);
    fprintf(fp, "    \"silent_processed\": %u,\n",     silent_processed);
    fprintf(fp, "    \"silent_false_accepts\": %u,\n", silent_false_accepts);
    fprintf(fp, "    \"false_accept_rate\": %.2f,\n",  (double)false_accept_rate);
    fprintf(fp, "    \"normal_files\": %u,\n",         normal_total);
    fprintf(fp, "    \"normal_processed\": %u,\n",     normal_processed);
    fprintf(fp, "    \"normal_false_rejects\": %u,\n", normal_false_rejects);
    fprintf(fp, "    \"false_reject_rate\": %.2f",     (double)false_reject_rate);

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
 * File collection
 * ------------------------------------------------------------------------- */

/*
 * Scan dir_path for .wav files, sort them alphabetically, and populate a
 * newly-allocated vad_file_result_t array.  Each entry's filename field is
 * set to "subdir_name/basename.wav" for both display and path construction.
 *
 * Returns the number of entries placed in *out_results (may be 0).
 * The caller must free(*out_results).
 */
static uint32_t collect_wav_files(const char          *dir_path,
                                   const char          *subdir_name,
                                   vad_file_category_t  category,
                                   vad_file_result_t  **out_results)
{
    *out_results = NULL;

    struct stat st;
    if (stat(dir_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "WARNING: subdirectory '%s' not found or not a directory\n", dir_path);
        return 0;
    }

    DIR *dp = opendir(dir_path);
    if (dp == NULL) {
        fprintf(stderr, "WARNING: cannot open directory '%s': %s\n", dir_path, strerror(errno));
        return 0;
    }

    /* Count .wav files */
    uint32_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) { continue; }
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcasecmp(entry->d_name + len - 4, ".wav") == 0) {
            count++;
        }
    }
    rewinddir(dp);

    if (count == 0) {
        fprintf(stderr, "WARNING: no .wav files found in '%s'\n", dir_path);
        closedir(dp);
        return 0;
    }

    /* Collect filenames */
    char **names = (char **)calloc(count, sizeof(char *));
    if (names == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        closedir(dp);
        return 0;
    }
    uint32_t idx = 0;
    while ((entry = readdir(dp)) != NULL && idx < count) {
        if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) { continue; }
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcasecmp(entry->d_name + len - 4, ".wav") == 0) {
            names[idx] = strdup(entry->d_name);
            if (names[idx] == NULL) {
                fprintf(stderr, "ERROR: out of memory\n");
                for (uint32_t j = 0; j < idx; j++) { free(names[j]); }
                free(names);
                closedir(dp);
                return 0;
            }
            idx++;
        }
    }
    closedir(dp);
    count = idx;

    /* Sort alphabetically for deterministic ordering */
    for (uint32_t i = 0; i < count - 1; i++) {
        for (uint32_t j = i + 1; j < count; j++) {
            if (strcmp(names[i], names[j]) > 0) {
                char *tmp  = names[i];
                names[i]   = names[j];
                names[j]   = tmp;
            }
        }
    }

    /* Build result entries */
    vad_file_result_t *res = (vad_file_result_t *)calloc(count, sizeof(vad_file_result_t));
    if (res == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        for (uint32_t i = 0; i < count; i++) { free(names[i]); }
        free(names);
        return 0;
    }

    for (uint32_t i = 0; i < count; i++) {
        snprintf(res[i].filename, sizeof(res[i].filename), "%s/%s", subdir_name, names[i]);
        res[i].category     = category;
        res[i].processed    = false;
        res[i].vad_accepted = false;
        free(names[i]);
    }
    free(names);

    *out_results = res;
    return count;
}

/* -------------------------------------------------------------------------
 * Usage
 * ------------------------------------------------------------------------- */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS] <wave_dir> <output_file>\n"
        "\n"
        "Arguments:\n"
        "  wave_dir     Directory containing 'silent' and 'normal' subdirectories,\n"
        "               each holding 16-bit mono 16 kHz PCM WAV files.\n"
        "                 silent/  files expected to be rejected by the VAD\n"
        "                 normal/  files expected to be accepted by the VAD\n"
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

    /* Build subdirectory paths */
    char silent_dir[1024];
    char normal_dir[1024];
    if (snprintf(silent_dir, sizeof(silent_dir), "%s/silent", wave_dir) >= (int)sizeof(silent_dir) ||
        snprintf(normal_dir, sizeof(normal_dir), "%s/normal", wave_dir) >= (int)sizeof(normal_dir)) {
        fprintf(stderr, "ERROR: wave_dir path too long\n");
        return 1;
    }

    /* Validate wave_dir */
    struct stat dir_stat;
    if (stat(wave_dir, &dir_stat) != 0 || !S_ISDIR(dir_stat.st_mode)) {
        fprintf(stderr, "ERROR: '%s' is not a valid directory\n", wave_dir);
        return 1;
    }

    /* Collect wav files from the 'silent' and 'normal' subdirectories */
    vad_file_result_t *silent_results = NULL;
    vad_file_result_t *normal_results = NULL;
    uint32_t silent_count = collect_wav_files(silent_dir, "silent", VAD_CATEGORY_SILENT, &silent_results);
    uint32_t normal_count = collect_wav_files(normal_dir, "normal", VAD_CATEGORY_NORMAL, &normal_results);
    uint32_t wav_count    = silent_count + normal_count;

    if (wav_count == 0) {
        fprintf(stderr, "WARNING: no .wav files found in '%s/silent' or '%s/normal'\n", wave_dir, wave_dir);
        write_report(output_file, &config, frame_size_ms, NULL, 0);
        return 0;
    }

    /* Merge into a single results array: silent files first, then normal */
    vad_file_result_t *results = (vad_file_result_t *)calloc(wav_count, sizeof(vad_file_result_t));
    if (results == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        free(silent_results);
        free(normal_results);
        return 1;
    }
    if (silent_count > 0) {
        memcpy(results,                silent_results, silent_count * sizeof(vad_file_result_t));
    }
    if (normal_count > 0) {
        memcpy(results + silent_count, normal_results, normal_count * sizeof(vad_file_result_t));
    }
    free(silent_results);
    free(normal_results);

    /* Frame size in samples (16 kHz, 16-bit mono) */
    const uint32_t samples_per_frame = (WAV_REQUIRED_RATE * frame_size_ms) / 1000u;
    const size_t   bytes_per_frame   = samples_per_frame * sizeof(int16_t);
    int16_t       *frame_buf         = (int16_t *)malloc(bytes_per_frame);
    if (frame_buf == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        free(results);
        return 1;
    }

    fprintf(stdout, "xraudio_vad_test: processing %u silent + %u normal file(s) from '%s'\n",
            silent_count, normal_count, wave_dir);
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
        res->processed    = false;
        res->vad_accepted = false;

        /* Construct full path from wave_dir and the relative filename stored by collect_wav_files */
        char path[1024];
        int  path_len = snprintf(path, sizeof(path), "%s/%s", wave_dir, res->filename);
        if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
            fprintf(stderr, "  [%u/%u] SKIP '%s': path too long\n", i + 1, wav_count, res->filename);
            continue;
        }

        fprintf(stdout, "  [%u/%u] %s ... ", i + 1, wav_count, res->filename);
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
                res->processed    = true;
                res->vad_accepted = (res->stats.confidence_peak >= config.sensitivity);
                fprintf(stdout, "OK  (%u frames, voice=%.1f%%, %s)\n",
                        res->stats.frames_processed,
                        res->stats.frames_processed > 0
                            ? 100.0 * (double)res->stats.frames_voice / (double)res->stats.frames_processed
                            : 0.0,
                        res->vad_accepted ? "ACCEPTED" : "REJECTED");
            }
        } else {
            fprintf(stdout, "FAILED (process_frame)\n");
        }

        xraudio_vad_destroy(vad);
    }

    free(frame_buf);

    /* Print accuracy summary to stdout */
    uint32_t s_processed = 0, s_false_accepts = 0;
    uint32_t n_processed = 0, n_false_rejects  = 0;
    for (uint32_t i = 0; i < wav_count; i++) {
        const vad_file_result_t *r = &results[i];
        if (!r->processed) { continue; }
        if (r->category == VAD_CATEGORY_SILENT) {
            s_processed++;
            if (r->vad_accepted) { s_false_accepts++; }
        } else {
            n_processed++;
            if (!r->vad_accepted) { n_false_rejects++; }
        }
    }
    float far_pct = (s_processed > 0) ? 100.0f * (float)s_false_accepts / (float)s_processed : 0.0f;
    float frr_pct = (n_processed > 0) ? 100.0f * (float)n_false_rejects / (float)n_processed : 0.0f;
    fprintf(stdout, "\nFalse Accept Rate (FAR): %.2f%% (%u/%u silent files accepted by VAD)\n",
            (double)far_pct, s_false_accepts, s_processed);
    fprintf(stdout, "False Reject Rate (FRR): %.2f%% (%u/%u normal files rejected by VAD)\n",
            (double)frr_pct, n_false_rejects, n_processed);

    /* Write the report */
    bool report_ok = write_report(output_file, &config, frame_size_ms, results, wav_count);
    if (report_ok) {
        fprintf(stdout, "\nReport written to: %s\n", output_file);
    }

    free(results);

    return report_ok ? 0 : 1;
}
