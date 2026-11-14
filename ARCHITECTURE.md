# xr-voice-sdk – Architecture Overview

## Introduction

The **xr-voice-sdk** is engineered for delivering efficient voice interaction capabilities to XR devices, with a modular C-based core and optional Python bindings for prototyping and automation. This document outlines the high-level architecture, key modules, and main workflows.

---

## High-Level Architecture

```
+-------------------------+
|    Application Layer    |    <-- XR Platform Integrators
+-------------------------+
           |
           |
+-------------------------+
|     SDK Core Layer      |    <-- xr-voice-sdk (C APIs)
|-------------------------|
| - Initialization        |
| - Device Management     |
| - Audio Capture         |
| - Speech Processing     |
| - Event Dispatch        |
+-------------------------+
           |
           |
+--------------------------+
|  Voice Engine/Plugins    |   <-- Speech-to-text, command recognition (native/cloud)
+--------------------------+
           |
           |
+--------------------------+
|   Hardware Interface     |   <-- Microphones, audio subsystems
+--------------------------+
```

---

## Main Components

### 1. **SDK Core Layer (C API)**

#### a. **Initialization & Configuration**
- Handles system setup, device selection, buffer allocation, and runtime parameters.

#### b. **Audio Capture Module**
- Interfaces with device drivers or OS sound APIs to collect microphone data in real-time.
- Performs initial data formatting and buffering.

#### c. **Speech Processing Pipeline**
- Applies digital signal processing: noise reduction, echo cancellation, gain control.
- Modularized for easy extension or customization.

#### d. **Voice Command Recognition**
- Integrates third-party or custom engines for speech-to-text and command parsing.
- Events passed back to application via callbacks or event handlers.

#### e. **Event Dispatch System**
- Decouples SDK internals from application logic.
- Delivers processed results to user-defined handlers.

### 2. **Python Bindings & Utilities (Optional)**
- Lightweight wrapper over core C APIs for prototyping or test automation.
- Sample scripts for batch audio processing and automated testing.

### 3. **Plugin/Extension Interface**
- Allows swapping or augmenting speech recognition engines without changing core SDK flow.
- Supports both native and cloud-based integration.

#### FFV HAL function table

With `USE_RDKV_HAL`, the SDK loads `libxraudio-ffv-hal.so` and obtains
`xraudio_hal_plugin_api_get()`, as provided by vsdk-xraudio-hal-llama.
Without that define, it loads `/vendor/lib/libxr-ffv-hal.so`. It first checks
for the existing xraudio getter, then resolves `xr_ffv_hal_plugin_func_get()`
for the native FFV HAL supplied by xr-ffv-hal-sky-llama.

The native C ABI and its 16-entry function table are defined by the standalone
`xr-ffv-hal-interface` package's `xr_ffv_hal_plugin.h` header. Both the middleware
and vendor builds must stage version 1.x of that package in their own sysroots.
Neither build requires the other component's headers or libraries. CMake resolves
the package with `find_package(xr-ffv-hal-interface 1 CONFIG REQUIRED)`.
The interface package owns header installation; neither consumer keeps a copy.

The SDK validates every native table entry before passing the table to
[vsdk_ffv_adapter.c](src/vsdk_ffv_adapter.c), which exposes xraudio operations
to the existing audio pipeline. The native HAL owns keyword detection and DSP
algorithms, so separate KWD/ALG plugins are not required in this configuration.
Native FFV output is disabled. The table remains valid while its shared library
is loaded.

The native adapter exposes the `KEYWORD` channel as 16 kHz, signed 16-bit
mono PCM; it does not expose the raw 32-bit `MICROPHONES` channel. Session
start reuses the existing keyword input object and pipe so that audio buffered
at detection is preserved. The audio thread waits until the recording consumer
is installed before monitoring the native pipe, and reads its PCM directly on
readability without treating it as an event counter or consuming it on a frame
timer. This preserves the HAL's leading and keyword audio during session setup.
Reads accumulate a complete requested PCM frame,
retry interrupted reads, and wait for readability if the pipe is nonblocking.
The HAL owns both pipe descriptors and closes them through `close_channel`.
The `USE_RDKV_HAL` session-start reopen behavior is unchanged.

The adapter reads `wuw.sowuw` and `wuw.eowuw` from the HAL's keyword metadata.
These are sample offsets from the start of the pipe audio. The native consumer's
endpoints are relative to the start of the delivered audio. The adapter discards
`sowuw - 1600` leading samples
so the output begins exactly 1600 samples (100 ms at 16 kHz) before the keyword.
It reports `pre = 0`, `begin = 1600`, and `end = eowuw - (sowuw - 1600)`.
Missing, malformed, out-of-range endpoints or fewer than 1600 available leading
samples are logged and reported as invalid session parameters.

The HAL's end-of-command callback records the final sample offset and timeout
status; it does not close the pipe while command audio is still buffered.
The adapter reports HAL EOS once reads reach that offset, rounding up to the
complete PCM frame required by xraudio. The HAL-relative byte count includes
discarded leading audio, so trimming does not delay EOS. Native local recording
sessions explicitly select HAL EOS at record start because they skip the
RDKV idle-start initialization. Software EOS cannot end these streams before
the HAL endpoint is drained, including when the HAL reports a timeout.
The final frame group is flushed to the output before the output pipe is closed.
After EOS, native reads
pause until the capture is stopped. Stopping the final local capture closes and
reopens the `KEYWORD` channel to rearm HAL detection, resets the byte count and
trim offset, and updates xraudio's pipe descriptor. Explicit early capture stops
also rearm detection.

---

## Build & Deployment Model

- **CMake Configuration**: Provides platform-agnostic build scripts; supports cross-compilation for ARM, x86, and custom XR hardware.
- **Static/Dynamic Library Builds**: SDK can be included as a static or shared library within target XR applications.
- **Language Bindings**: Python components compile as extension modules, leveraging shared core logic.

---

## Data Flow

```
[Microphone Input]
      |
      v
[Audio Capture Module]
      |
      v
[Signal Processing Chain]
      |
      v
[Voice Recognition Engine]
      |
      v
[Event Dispatcher]
      |
      v
[Application Callback Layer]
```
- **Audio data** is captured, processed in the pipeline, passed through the recognition engine, and eventual command events are dispatched to application logic.

---

## Extensibility & Customization

- **Processing Stages:** Each pipeline stage exposes configuration points and interfaces for custom modules (i.e., different DSP blocks).
- **Engine Plugins:** Developers can register new voice engines via clear APIs and plug-ins.
- **Event System:** User applications subscribe to and handle specific voice events defined in the SDK.

---

## Platform & Device Support

- **Hardware Agnostic:** Uses abstraction layers for hardware interfaces, supporting desktop, embedded, and XR-specific devices.
- **Target Platforms:** Designed for easy porting across XR headsets, AR glasses, smart displays, and other voice-enabled systems.

---

## Security & Resource Management

- **Buffer Management:** Ensures efficient low-latency audio data handling.
- **Thread Safety:** Key components are designed for concurrent environments typical in XR systems.
- **Isolation:** Plugins and bindings operate within predefined memory and execution boundaries.

---

## Summary

The xr-voice-sdk architecture enables fast, flexible development and deployment of voice-driven features in XR applications. Its modular design, robust API, and extensible plugin interfaces make it suitable for diverse platforms and evolving voice technologies.

_See repository documentation and source for module details, integration guides, and API references._
