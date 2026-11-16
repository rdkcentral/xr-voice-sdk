# Proposal

## Why

The Coverity scan of xr-voice-sdk reports one High-severity defect: CID 55776 (INTEGER_OVERFLOW) in xraudio's external-input path. It needs a decision so the High/Critical backlog reaches zero. Analysis of the current source shows the flagged value is range-checked before the flagged call and cannot overflow. This change therefore resolves the finding through Coverity triage, not a code edit.

## What Changes

- **CID 55776, INTEGER_OVERFLOW, High**: `src/xr-audio/xraudio_thread.c`, `xraudio_process_input_external_data()`. Coverity reports that `(uint32_t)bytes_read` "might have overflowed" where it is passed to `xraudio_in_capture_internal_to_file()` in the internal-capture block at the end of the function.
  - Disposition: **false positive**. At the flagged call, `bytes_read` has already passed two guards. It is `> 0` and equals `session->external_frame_size_out`, a frame size bounded by `sizeof(external_frame_buffer)`. The cast cannot wrap or truncate.
  - Action: triage the CID in Coverity as *False Positive* (classification: False Positive, action: Ignore), with the range justification from design.md as the triage comment.
- No source, header, or build changes. No runtime behavior changes.

### Out of scope

- All Medium and Low Coverity findings.
- The other `(uint32_t)bytes_read` capture calls in the same function (in the OPUS_XVP→PCM and OPUS→PCM paths). They are separate call sites and are not flagged under CID 55776.
- A defensive code change that only silences the checker (for example, an extra explicit bound before the cast). This was considered and deferred; see design.md, Alternatives. If the Coverity triage is rejected, a follow-up change can take that route.
- Confirming the triage in Coverity, which is tracked outside OpenSpec.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- None. No spec-level behavior changes, so the change sets `skip_specs: true`.

## Impact

- Code: none expected. The decision covers `xraudio_process_input_external_data()` in `src/xr-audio/xraudio_thread.c`.
- Public headers / ABI: unchanged (ctrlm and the out-of-tree HAL plugins are unaffected).
- Threading/locking: unchanged.
- Process: one Coverity triage action for CID 55776. CI native build on the PR to develop as the regular gate.
