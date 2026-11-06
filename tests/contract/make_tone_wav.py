#!/usr/bin/env python3
#
# If not stated otherwise in this file or this component's license file the
# following copyright and licenses apply:
#
# Copyright 2026 RDK Management
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

# Writes a 440 Hz tone as a WAV in the only format xrsr accepts for audio-file sessions: 16 kHz, mono, 16-bit PCM.

import math
import struct
import sys
import wave

SAMPLE_RATE = 16000
DURATION_S  = 1.0  # must fit the xrsr session pipe (10 s max)
FREQ_HZ     = 440.0
AMPLITUDE   = 0.3 * 32767

def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <output.wav>", file=sys.stderr)
        return 2
    n = int(SAMPLE_RATE * DURATION_S)
    frames = b"".join(struct.pack("<h", int(AMPLITUDE * math.sin(2 * math.pi * FREQ_HZ * i / SAMPLE_RATE))) for i in range(n))
    with wave.open(sys.argv[1], "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(SAMPLE_RATE)
        wav.writeframes(frames)
    return 0

if __name__ == "__main__":
    sys.exit(main())
