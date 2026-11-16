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

The Coverity scan's line numbers may be stale. The defect was located by function name and the event text, which matches this call exactly. The full Coverity event trace, including which upstream expression it marks as the "overflow" source, is not in the repo.

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

Two guards are common to all paths and run before the flagged call:

1. `if(bytes_read <= 0) { ... return; }`. Every error return (`-1`, other negative decoder errors) and EOF (`0`) leaves the function here.
2. `if(session->external_frame_size_out != bytes_read) { ... return; }`. Guard 1 established `bytes_read > 0`, so the implicit conversion to `uint32_t` in this comparison preserves the value. Passing the guard means `bytes_read == external_frame_size_out` exactly.

`bytes_read` is not modified between guard 2 and the flagged call. At the flagged point it is therefore in `[1, INT32_MAX]`, and it equals `external_frame_size_out`. Any positive `int32_t` converts to `uint32_t` without wrap or truncation, so `(uint32_t)bytes_read` cannot overflow. This holds regardless of which upstream arithmetic Coverity treats as the overflow source. The most likely candidates are `bytes_read *= sizeof(pcm_t)` in the ADPCM→PCM path and `bytes_read += session->external_frame_bytes_read` in the PCM path. Both are bounded as shown above. Even an out-of-range result would be filtered by guards 1 and 2 before the cast.

The buffer offset in the same call does not underflow either. `(external_frame_group_index - 1)` is evaluated just after `external_frame_group_index++`, so the index is at least 1. This is not part of the CID.

**Action:** in Coverity, set CID 55776 to Classification *False Positive*, Action *Ignore*. Use a comment along the lines of: "bytes_read is guarded `> 0` and `== external_frame_size_out` immediately before this call (see openspec change resolve-coverity-high-critical, design.md D1); the int32→uint32 conversion is value-preserving."

**Behavior:** unchanged. No code is modified.

**Alternatives considered:**
- *Silence the checker in code.* Options include making the arithmetic stay in `int32_t` (`bytes_read *= (int32_t)sizeof(pcm_t)`), adding a redundant explicit bound before the cast, or passing `session->external_frame_size_out` instead of `(uint32_t)bytes_read`. Each would be behavior-preserving. All were rejected for this change: the project rule is to triage false positives rather than edit code, and each option would touch a hot audio path only to satisfy the analyzer. This remains the fallback if the triage is rejected.
- *Add a Coverity annotation comment (`// coverity[...]`).* Rejected. It puts tool-specific markup in the source for a defect that is not real, and the triage database already records the decision.

## Risks / Trade-offs

- [The Coverity event trace for CID 55776 points at a source expression not covered above] → Before triaging, compare the trace's "overflow" event against the table in D1. If it identifies a path where `bytes_read` can reach the flagged call without passing both guards, stop and replace this decision with a code fix in an updated change.
- [A future edit moves or removes guard 1 or guard 2, so the false-positive reasoning becomes wrong] → The triage comment cites the guards. Coverity re-raises the CID as new if the code shape changes enough.
- [The triage is rejected by the reviewer or by Coverity policy] → Fall back to the code-change alternative above as a follow-up change.

## Migration Plan

None. No code or configuration is deployed. Rollback means reopening the CID in Coverity.
