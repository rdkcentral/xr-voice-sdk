#!/bin/bash
#
# TEMPORARY DIAGNOSTIC — NOT part of the normal CI pipeline.
#
# Builds the exact real safeclib the product pins
# (meta-openembedded/meta-oe/recipes-core/safec/safec_3.7.1.bb,
# SRCREV f9add9245b97c7bda6e28cceb0ee37fb7e254fd8, upstream
# github.com/rurban/safeclib) and runs a standalone repro of the
# strncpy_s(dst, sizeof(dst), src, sizeof(dst)) call shape now used
# at xrsr.c:2133/2074 (audio_file_in, 256 bytes) and xrsr.c:2066
# (transcription_in, 128 bytes) — no headroom on the 4th arg — to see
# what the REAL library actually does, as opposed to the CI-only
# SAFEC_DUMMY_API stub, which can't tell us anything about this.
#
# Only the two buffer sizes are reproduced here, not the real
# xrsr_msg_session_begin() call sites themselves: strncpy_s's behavior
# is driven entirely by dmax/slen, not by which struct field it's
# copying into, and reaching those call sites for real would require
# spinning up xr-voice-sdk's whole thread/queue/global-state machinery
# for no extra signal.
#
# Not applying the two RDK-local safec patches (configure_ac.patch,
# hotspot.patch) here: hotspot.patch only raises RSIZE_MAX_STR from
# 4KB to 32KB, configure_ac.patch only disables the doxygen check —
# neither affects strncpy_s behavior for our 128/256-byte buffers.
#
# Delete this file and its step in .github/workflows/native_full_build.yml
# once you've seen the result — it's not meant to be merged.

set -x
set -e

apt update
apt install -y autoconf automake libtool make pkg-config

git clone --depth 1 https://github.com/rurban/safeclib.git /tmp/safeclib
cd /tmp/safeclib
git fetch --depth 1 origin f9add9245b97c7bda6e28cceb0ee37fb7e254fd8
git checkout f9add9245b97c7bda6e28cceb0ee37fb7e254fd8
./autogen.sh
./configure --disable-wchar --prefix=/usr
make -j"$(nproc)"
make install
ldconfig

cat > /tmp/test_strncpy_dmax.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <safe_str_lib.h>

/* Reproduces strncpy_s(dst, dmax, src, dmax) for a given dmax and a
 * source string of src_len chars (no null within the first dmax bytes
 * when src_len >= dmax), matching the no-headroom call shape now used
 * in xrsr.c. */
static void run_case(const char *label, size_t dmax, size_t src_len) {
    char *dst = malloc(dmax);
    char *src = malloc(src_len + 1);
    memset(dst, 0x55, dmax);              /* poison so we can see what survives */
    memset(src, 'A', src_len);
    src[src_len] = '\0';

    errno_t rc = strncpy_s(dst, dmax, src, dmax);

    printf("%-28s dmax=%3zu src_len=%3zu rc=%2d strlen(dst)=%3zu dst[0]=%02x dst[last]=%02x\n",
           label, dmax, src_len, rc, strlen(dst),
           (unsigned char)dst[0], (unsigned char)dst[dmax - 1]);

    free(dst);
    free(src);
}

int main(void) {
    printf("EOK=%d ESNOSPC=%d ESLEMAX=%d ESNULLP=%d\n\n", EOK, ESNOSPC, ESLEMAX, ESNULLP);

    /* audio_file_in (xrsr.c:2133 / 2074) — 256-byte buffer, WS + HTTP */
    run_case("audio_file_in [under]", 256, 15);
    run_case("audio_file_in [== dmax]", 256, 256);
    run_case("audio_file_in [over]", 256, 300);

    /* transcription_in (xrsr.c:2066) — 128-byte buffer, HTTP only */
    run_case("transcription_in [under]", 128, 15);
    run_case("transcription_in [== dmax]", 128, 128);
    run_case("transcription_in [over]", 128, 150);

    return 0;
}
EOF

gcc $(pkg-config --cflags libsafec) -o /tmp/test_strncpy_dmax /tmp/test_strncpy_dmax.c $(pkg-config --libs libsafec)

echo "======================================================================================"
echo "real-safeclib strncpy_s(dst, dmax, src, dmax) repro (audio_file_in + transcription_in shapes):"
/tmp/test_strncpy_dmax
echo "======================================================================================"
