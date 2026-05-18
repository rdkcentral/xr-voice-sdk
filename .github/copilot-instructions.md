# Copilot Instructions

## Repository overview
This is the **xr-voice-sdk** — a C library providing voice/speech recognition service routing for RDK platforms.

## ci/ directory
The `ci/` directory contains **native CI build support files only**. It is not part of the library.

- `ci/build_dependencies.sh` / `ci/cov_build.sh` — scripts that build the library in a CI container without a full RDK target image
- `ci/mocks/` — minimal stub headers that stand in for platform libraries (rdkversion, etc.) unavailable in the CI environment. These are **not** production implementations.
- `ci/headers/` — stub headers generated at CI build time (e.g. safec_lib.h); not committed to source

When suggesting code or answering questions, treat `ci/mocks/` as CI scaffolding, not as authoritative API definitions.
