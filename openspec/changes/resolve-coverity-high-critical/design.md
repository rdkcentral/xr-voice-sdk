# Design

## Context

CID 55776 flags the internal-capture call near the end of `xraudio_process_input_external_data()` (`src/xr-audio/xraudio_thread.c`). The call runs after the frame has been accounted for and `external_frame_group_index` has been incremented:

```c
int rc_cap = xraudio_in_capture_internal_to_file(session,
      &session->external_frame_buffer[(session->external_frame_group_index - 1) * session->external_frame_size_out],
      (uint32_t)bytes_read, capture_file);
```

`bytes_read` is an `int32_t` local. Depending on the input/output encoding pair, the `switch(enc_input)` above sets it from one of these:
- `xraudio_external_fd_read()` (`ssize_t`: `-1`, `0`, or `<= count`)
- `adpcm_decode()` (`-1` or samples `<= outlen`)
- `xraudio_opus_decode()` / `xraudio_opus_deframe()` (`int32_t`, negative on error)
- arithmetic on those results

The Coverity scan's line numbers may be stale. The defect was located by function name and the event text, which matches this call exactly. The CID's event chain follows only the PCM→PCM path, and its line numbers match the current branch:
1. cast_overflow at `bytes_read = xraudio_external_fd_read(session, inbuf, inlen)` (4989)
2. `bytes_read += session->external_frame_bytes_read` (4991), marked as possibly overflowed
3. the `(uint32_t)bytes_read` sink (5114)

## Goals / Non-Goals

**Goals:**
- Decide CID 55776 with a written range argument that a reviewer can check against the source.
- Keep runtime behavior and the public ABI unchanged.

**Non-Goals:**
- Changing the shape of the decode paths or the frame-group logic.
- Addressing other `(uint32_t)bytes_read` casts in the function that have no High/Critical CID.

## Decisions

### D1: CID 55776 is a false positive. Triage it; do not change code.

**Range of `bytes_read` at the flagged point.** All per-path values are inclusive.

| Path (in → out) | Value assigned before the common tail | Range |
|---|---|---|
| ADPCM_FRAME → PCM | `adpcm_decode()` result × `sizeof(pcm_t)`. Read errors map to `-1`, EOF to `0`. | `-1`, `0`, or `0..560`. `size_packet <= XRAUDIO_INPUT_ADPCM_BUFFER_SIZE (140)`, so the decoder's output limit is at most 280 samples, which is at most 560 bytes. |
| ADPCM_FRAME → ADPCM_FRAME | `xraudio_external_fd_read(inbuf, inlen)` | `-1..inlen` |
| OPUS_XVP → PCM | `xraudio_opus_decode()` (or a read error/EOF if nothing was read) | `<0` on error; otherwise `<= XRAUDIO_INPUT_OPUS_FRAME_SAMPLE_QTY` bound |
| OPUS_XVP → OPUS_XVP / OPUS | read, optionally `xraudio_opus_deframe()` | `<0` on error; otherwise `<= inlen` |
| OPUS → PCM | read errors `return` early; then `xraudio_opus_decode()` | `<0` on error; otherwise decoded size |
| OPUS → OPUS | read | `-1..inlen` |
| PCM → PCM | read + `external_frame_bytes_read`. A short frame `return`s early. | `-1`, `0`, or exactly `external_frame_size_out` |

**The traced PCM→PCM path, step by step.**

- **Invariant: `external_frame_bytes_read < external_frame_size_in` between calls.** The field is written only in four places:
  - `= 0` at record start (1181)
  - `= sum` at 4992 and 4994. The sum is kept only when it differs from `external_frame_size_out`. On PCM→PCM that equals `external_frame_size_in` (1204–1205, `encoding_in == encoding_out`), and the sum is at most `external_frame_size_in` (see 4991 below). A kept sum is therefore strictly less than `external_frame_size_in`.
  - `= 0` at 4997, once a full frame has been read.

  So `inlen = external_frame_size_in - external_frame_bytes_read` is at least 1 and cannot underflow.
- **4989, cast_overflow.** `read()` returns `-1` or at most `inlen`, and `inlen <= external_frame_size_in`. That is one 20 ms PCM frame, `sample_rate/1000 × sample_size × 20`, which is 640 bytes at 16 kHz/16-bit. Narrowing the result from `ssize_t` to `int32_t` cannot overflow.
- **4991, addition.** This line runs only when `bytes_read > 0`; otherwise the `break` at 4990 skips it. The sum is at most `inlen + external_frame_bytes_read = external_frame_size_in`, so it cannot overflow.
- **4993 and 5082.** On PCM→PCM, `external_frame_size_out == external_frame_size_in`. The `!=` → return checks therefore pin `bytes_read` to exactly the frame size from 4993 to the sink.
- **5114, the sink.** The guard `if(bytes_read <= 0) { ... return; }` at 5010 is common to all paths, and `bytes_read` is not reassigned after it. At the sink, `bytes_read` is in `[1, INT32_MAX]`, and on PCM→PCM it equals the frame size. Any positive `int32_t` converts to `uint32_t` without wrap or truncation, so `(uint32_t)bytes_read` keeps its value.

The same `> 0` guard keeps the cast value-preserving on the untraced paths in the table. The `external_frame_size_out != bytes_read` check pins the value on PCM→PCM only. On OPUS→PCM and OPUS_XVP→PCM, `external_frame_size_out` is assigned from `bytes_read` just before that check, so it limits nothing there.

The buffer offset in the same call does not underflow either. `(external_frame_group_index - 1)` is evaluated just after `external_frame_group_index++`, so the index is at least 1. This is not part of the CID.

**Action:** in Coverity, set CID 55776 to Classification *False Positive*, Action *Ignore*. Use a comment along the lines of: "PCM→PCM trace: read() returns at most inlen = external_frame_size_in - external_frame_bytes_read, and external_frame_bytes_read < external_frame_size_in between calls, so neither the read cast (4989) nor the sum (4991) can exceed external_frame_size_in (one 20 ms PCM frame). The size_out == size_in checks (4993/5082) pin bytes_read to the frame size, and the bytes_read <= 0 → return guard (5010) makes the int32→uint32 cast at 5114 value-preserving. See openspec change resolve-coverity-high-critical, design.md D1."

**Behavior:** unchanged. No code is modified.

**Alternatives considered:**
- *Silence the checker in code.* Options include making the arithmetic stay in `int32_t` (`bytes_read *= (int32_t)sizeof(pcm_t)`), adding a redundant explicit bound before the cast, or passing `session->external_frame_size_out` instead of `(uint32_t)bytes_read`. Each would be behavior-preserving. All were rejected for this change: the project rule is to triage false positives rather than edit code, and each option would touch a hot audio path only to satisfy the analyzer. This remains the fallback if the triage is rejected.
- *Add a Coverity annotation comment (`// coverity[...]`).* Rejected. It puts tool-specific markup in the source for a defect that is not real, and the triage database already records the decision.

## Risks / Trade-offs

- [A future edit breaks `external_frame_bytes_read < external_frame_size_in`, for example by changing `external_frame_size_in` mid-session or dropping the 1181/4997 resets] → The triage comment cites the invariant. Coverity re-raises the CID if that code changes enough.
- [A future edit moves or removes the `bytes_read <= 0` guard, or reassigns `bytes_read` after it, so the false-positive reasoning becomes wrong] → The triage comment cites the guard. Coverity re-raises the CID as new if the code shape changes enough.
- [The triage is rejected by the reviewer or by Coverity policy] → Fall back to the code-change alternative above as a follow-up change.

## Migration Plan

None. No code or configuration is deployed. Rollback means reopening the CID in Coverity.
