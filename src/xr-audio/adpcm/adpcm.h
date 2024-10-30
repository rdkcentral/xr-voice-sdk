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
#ifndef __ADPCM_H__
#define __ADPCM_H__

/**
 * @file adpcm.h
 * @author Chris Buchter
 * @brief File contains the ADPCM Encode/Decode API.
 * @version 1.0
 * 
 * This file contains the API for ADPCM Encoding and Decoding.
 */

/** @defgroup defines
 * @{
 */

/**
 * @}
 */

/** @defgroup includes
 * @{
 */
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <xraudio_common.h>

/**
 * @}
 */

/** @defgroup structs
 * @{
 */
typedef        uint8_t     adpcm_t;     ///> ADPCM data is sent in even amount of bytes.
typedef        int16_t     pcm_t;       ///> PCM data is 16-bit signed.
/**
 * @}
 */

/** @defgroup structs_decode
 * @{
 */
typedef struct adpcm_dec_t adpcm_dec_t; ///> ADPCM decoder that will be passed in for each API call.

/**
 * @brief Decoding stats.
 * 
 * This structure contains statistics for a decoding session.
 */
typedef struct {
    uint32_t samples_decoded;            ///< The number of samples decoded.
    uint32_t failed_decodes;             ///< The number of decoding fails.
    uint32_t frames_processed;           ///< The number of frames processed.
    uint32_t frames_lost;                ///< The number of frames lost.
    uint32_t step_size_mismatch;         ///< The number of step size mismatches that occurred.
    uint32_t predicted_sample_mismatch;  ///< The number of predicted sample mismatches that occurred.
} adpcm_decode_stats_t;
/**
 * @}
 */

#ifdef __cplusplus
extern "C"
{
#endif

/** @defgroup api_common
 * @{
 */
/**
 * @}
 */

/** @defgroup api_decode
 * @{
 */

/**
 * @breif Create an adpcm decoder.
 * 
 * This function creates and initializes a new adpcm decoder.
 * @return adpcm_dec_t* on sucess, NULL on failure
 */
adpcm_dec_t *adpcm_decode_create();

/**
 * @brief Deframe ADPCM packet.
 *
 * This function removes the framing from an ADPCM framed packet as defined by the adpcm_frame structure.
 *
 * @param decoder An adpcm decoder
 * @param inbuf A pointer to the data from the XVP data adpcm command data.
 * @param inlen The length of the inbuf data.
 * @param adpcm_frame The adpcm framing details.
 * @return Number of bytes in the payload on success, -1 on failure.
 */
int32_t adpcm_deframe(adpcm_dec_t *decoder, uint8_t *inbuf, uint32_t inlen, xraudio_adpcm_frame_t *adpcm_frame);

/**
 * @brief Analyze ADPCM packet.
 * 
 * This function analyzes the adpcm packet checking for packet loss, header mismatches, and decoder failures.
 * 
 * @param decoder An adpcm decoder
 * @param inbuf A pointer to the data fromn the XVP data adpcm command data.
 * @param inlen The length of the inbuf data.
 * @param adpcm_frame The adpcm framing details.
 * @return Whether we should actually decode the data or not
 */
bool adpcm_analyze(adpcm_dec_t *decoder, uint8_t *inbuf, uint32_t inlen, xraudio_adpcm_frame_t *adpcm_frame);

/**
 * @brief Decode ADPCM packet.
 * 
 * This function decodes an ADPCM frame.
 * 
 * @param decoder An adpcm decoder
 * @param inbuf A pointer to the data from the XVP data adpcm command data.
 * @param inlen The length of the inbuf data.
 * @param outbuf The pcm buffer where the result will be stored.
 * @param outlen The length of the of pcm buffer.
 * @param adpcm_frame The adpcm framing details.
 * @param is_big_endian in XVP spec it should be true, meaning each byte stores samples like { 2nd sample, 1st sample }, {4th sample, 3rd sample} etc
 * @return Number of samples decoded on success, -1 on failure.
 */
int32_t adpcm_decode(adpcm_dec_t *decoder, adpcm_t *inbuf, uint32_t inlen, pcm_t *outbuf, uint32_t outlen, xraudio_adpcm_frame_t *adpcm_frame, bool is_big_endian);

/**
 * @brief Get decode stats.
 * 
 * This function gets the decoding stats from a adpcm decoder.
 * @param decoder The adpcm decoder.
 * @param stats A pointer to the adpcm_decode_stats_t where the stats will be returned.
 * @return true on success, false on failure.
 */
bool adpcm_decode_stats(adpcm_dec_t *decoder, adpcm_decode_stats_t *stats);

/**
 * @brief Reset decoder
 * 
 * This function resets the decoder state and stats. This allows the user to 
 * keep the same decoder object for multiple decoding sessions.
 * @param decoder The decoder to reset.
 * @return true on success, false on failure.
 */
bool adpcm_decode_reset(adpcm_dec_t *decoder);

/**
 * @breif Destroy adpcm decoder.
 * 
 * This function destroys and releases resources for the adpcm decoder.
 * @param decoder The adpcm decoder to be destroyed.
 */
void adpcm_decode_destroy(adpcm_dec_t *decoder);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
