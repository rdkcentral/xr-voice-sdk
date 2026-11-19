# Proposal

## Why

The Coverity scan of xr-voice-sdk reports one High-severity defect: CID 55776 (INTEGER_OVERFLOW) in xraudio's external-input path. It needs a decision so the High/Critical backlog reaches zero. Analysis of the current source shows the flagged value is range-checked before the flagged call and cannot overflow at runtime. Per project rule, the change still adds a minimal defensive bound so the range is explicit to Coverity.

## What Changes

- **CID 55776, INTEGER_OVERFLOW, High**: `src/xr-audio/xraudio_thread.c`, `xraudio_process_input_external_data()`. Coverity reports that `(uint32_t)bytes_read` "might have overflowed" where it is passed to `xraudio_in_capture_internal_to_file()` in the internal-capture block at the end of the function. The event chain starts where the `ssize_t` result of `xraudio_external_fd_read()` is narrowed into `int32_t bytes_read` on the PCM→PCM path.
  - Disposition: **cannot occur at runtime; defensive fix added**. At the flagged call, `bytes_read` has already passed the `bytes_read <= 0` → `return` guard, so it is in `[1, INT32_MAX]`, and on PCM→PCM it is bounded by one frame. Converting any positive `int32_t` to `uint32_t` keeps the value.
  - Action: on the PCM→PCM path, read into an `ssize_t` local and reject any result greater than `inlen` as a read error (`-1`) before narrowing to `int32_t` (design.md D1).
- One source edit in `src/xr-audio/xraudio_thread.c`. No header, ABI, or build changes. No behavior change for valid inputs.

### Out of scope

- All Medium and Low Coverity findings.
- The other `(uint32_t)bytes_read` capture calls in the same function (in the OPUS_XVP→PCM and OPUS→PCM paths). They are separate call sites and are not flagged under CID 55776.
- Coverity triage of CID 55776. It is no longer needed unless the CID persists after the fix.
- Confirming the fix in Coverity, which is tracked outside OpenSpec.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- None. No spec-level behavior changes, so the change sets `skip_specs: true`.

## Impact

- Code: `xraudio_process_input_external_data()` in `src/xr-audio/xraudio_thread.c`, PCM→PCM read only.
- Public headers / ABI: unchanged (ctrlm and the out-of-tree HAL plugins are unaffected).
- Threading/locking: unchanged.
- Process: CI native build on the PR to develop as the regular gate. No Coverity triage action.
