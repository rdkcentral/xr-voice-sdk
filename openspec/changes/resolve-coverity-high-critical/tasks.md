# Tasks

## 1. Coverity findings

- [ ] 1.1 CID 55776 (INTEGER_OVERFLOW): add a defensive bound on the PCM→PCM read result in `xraudio_process_input_external_data()` (`src/xr-audio/xraudio_thread.c`).
  - Re-read the function on the current branch. Verify that the `bytes_read <= 0` → return guard from design.md D1 still sits between the `switch(enc_input)` and the flagged `xraudio_in_capture_internal_to_file(..., (uint32_t)bytes_read, capture_file)` call. Also verify that `bytes_read` is not reassigned between that guard and the call.
  - **Done 2026-11-16:** the event chain runs PCM→PCM only (4989 → 4991 → 5114) and matches D1; no path reaches the call with `bytes_read <= 0`.
  - Apply the D1 change: read into an `ssize_t read_result`, treat `read_result > (ssize_t)inlen` as a read error (`-1`), then assign `bytes_read = (int32_t)read_result`.
  - Done when the D1 bound is in place, the new `read_result` local does not shadow or conflict with the one in the ADPCM block, and the native build passes.

## 2. Integration

- [ ] 2.1 Push `feature/RDKEMW-28692` and open or update the PR to `develop`. Done when the native build workflow passes on the PR and `git diff develop -- src/` touches only `xraudio_process_input_external_data()` in `src/xr-audio/xraudio_thread.c`. Coverity confirmation of CID 55776 is tracked outside OpenSpec.

## Workflow follow-up

- Archive the change once the native build passes on the PR (task 2.1); do not wait for merge.
