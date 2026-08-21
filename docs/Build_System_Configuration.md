# XR Voice SDK - Build System Configuration Documentation

## Overview

The XR Voice SDK uses CMake as its primary build system, providing flexible configuration options for different platforms, features, and deployment scenarios. The build system supports cross-compilation, optional feature sets, and modular component builds.

## Build System Architecture

### CMake Structure
```
CMakeLists.txt              # Root project configuration
├── src/CMakeLists.txt      # Main SDK library build  
└── src/xr-logger/CMakeLists.txt  # Optional vendor logging library
```

### Build Targets
1. **`xr-voice-sdk`** - Main shared library (default)
2. **`xr-voice-sdk-xlog`** - Vendor logging library (optional)

## CMake Requirements and Configuration

### Minimum Requirements
```cmake
cmake_minimum_required(VERSION 3.16)
```

### C Standard Selection
```cmake
# Automatic C standard selection based on CMake version
if(CMAKE_VERSION GREATER_EQUAL 3.21)
   set(CMAKE_C_STANDARD 23)  # Use C23 for newer CMake
else()
   set(CMAKE_C_STANDARD 11)  # Fall back to C11 for compatibility
endif()
```

### Default Build Configuration
```cmake
set(CMAKE_VERBOSE_MAKEFILE ON)  # Enable verbose build output
set(CMAKE_BUILD_TYPE Release)   # Default to optimized release build
```

## Build Configuration Options

### Core SDK Options

#### VSDK_VENDOR_XLOG
```cmake
option(VSDK_VENDOR_XLOG, "vendor layer logging" OFF)
```
**Purpose:** Enable vendor-specific logging layer
- **Default:** OFF (use integrated logging)
- **When enabled:** Builds separate `xr-voice-sdk-xlog` library
- **Use case:** Vendor-specific logging integration requirements

#### RDK_VERSION_ENABLED  
```cmake
option(RDK_VERSION_ENABLED, "Build with RDK versioning support" OFF)
```
**Purpose:** Enable RDK platform versioning integration
- **Default:** OFF (use standard versioning)
- **Dependencies:** Requires `rdkversion` library
- **Platform:** RDK-specific deployments

### Protocol Support Options

#### HTTP_ENABLED
```cmake
option(HTTP_ENABLED, "speech router http protocol" OFF)
```
**Purpose:** Enable HTTP protocol support for speech routing
- **Dependencies:** `curl` library
- **Source files:** `xrsr_protocol_http.c`, `xrsr_protocol_http_log_filter.c`
- **Generated files:** HTTP log filter hash tables
- **Use case:** REST-based speech services integration

#### WS_ENABLED  
```cmake
option(WS_ENABLED, "speech router websocket protocol" OFF)
```
**Purpose:** Enable WebSocket protocol support
- **Dependencies:** `nopoll` WebSocket library
- **Source files:** `xrsr_protocol_ws.c`
- **Additional option:** `WS_NOPOLL_PATCHES` for patched nopoll support
- **Use case:** Real-time bidirectional speech communication

#### SDT_ENABLED
```cmake
option(SDT_ENABLED, "speech router secure data transfer protocol" OFF)
```
**Purpose:** Enable Secure Data Transfer protocol
- **Dependencies:** None (built-in implementation)
- **Source files:** `xrsr_protocol_sdt.c`  
- **Use case:** Secure, encrypted speech data transmission

#### WS_NOPOLL_PATCHES
```cmake
option(WS_NOPOLL_PATCHES, "speech router websocket nopoll patches" OFF)
```
**Purpose:** Enable patches for nopoll WebSocket library
- **Dependency:** Requires `WS_ENABLED`
- **Use case:** Custom nopoll library with vendor-specific patches

### Build Option Examples

#### Full Feature Build
```bash
cmake -DHTTP_ENABLED=ON \
      -DWS_ENABLED=ON \
      -DSDT_ENABLED=ON \
      -DRDK_VERSION_ENABLED=ON \
      ..
```

#### Minimal Build
```bash
cmake -DHTTP_ENABLED=OFF \
      -DWS_ENABLED=OFF \
      -DSDT_ENABLED=OFF \
      ..
```

#### Vendor Logging Build
```bash
cmake -DVSDK_VENDOR_XLOG=ON \
      -DRDK_VERSION_ENABLED=ON \
      ..
```

## Library Configuration

### Shared Library Properties
```cmake
add_library(xr-voice-sdk SHARED)
set_target_properties(xr-voice-sdk PROPERTIES
    SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}  # ABI version
    VERSION   ${CMAKE_PROJECT_VERSION}        # Full version
)
```

### Compilation Options
```cmake
target_compile_options(xr-voice-sdk PUBLIC 
    -fPIC          # Position independent code for shared library
    -rdynamic      # Export symbols for plugin loading
    -Wall          # Enable all warnings
    -Werror        # Treat warnings as errors
)
```

### Preprocessor Definitions
```cmake
target_compile_definitions(xr-voice-sdk PUBLIC 
    _REENTRANT                # Thread-safe library functions
    _POSIX_C_SOURCE=200809L   # POSIX.1-2008 standard
    _GNU_SOURCE               # GNU extensions
)
```

## Dependency Management

### Required System Libraries
```cmake
target_link_libraries(xr-voice-sdk 
    c          # Standard C library
    bsd        # BSD compatibility functions  
    m          # Math library
    pthread    # POSIX threading
    anl        # Asynchronous name lookup
    uuid       # UUID generation
    jansson    # JSON parsing
)
```

### Optional Feature Libraries

#### HTTP Protocol Dependencies
```cmake
if(HTTP_ENABLED)
    target_link_libraries(xr-voice-sdk curl)
endif()
```

#### WebSocket Protocol Dependencies  
```cmake
if(WS_ENABLED)
    target_include_directories(xr-voice-sdk PUBLIC 
        ${CMAKE_SYSROOT}/usr/include/nopoll/)
    target_link_libraries(xr-voice-sdk nopoll)
endif()
```

#### Audio Codec Dependencies
```cmake
# Opus codec (auto-detected)
find_library(OPUS_LIBRARY NAMES opus)
if(OPUS_LIBRARY)
    target_compile_definitions(xr-voice-sdk PUBLIC XRAUDIO_DECODE_OPUS)
    target_link_libraries(xr-voice-sdk ${OPUS_LIBRARY})
endif()

# Curtail library (auto-detected)
find_library(CURTAIL_LIBRARY NAMES curtail)  
if(CURTAIL_LIBRARY)
    target_compile_definitions(xr-voice-sdk PUBLIC VSDK_CURTAIL_ENABLED)
    target_link_libraries(xr-voice-sdk ${CURTAIL_LIBRARY})
endif()
```

## Cross-Platform Support

### Platform Abstraction Strategy
- **Threading:** POSIX threads (`pthread`)
- **Networking:** Standard sockets with protocol abstraction
- **Audio:** Hardware Abstraction Layer (HAL) plugins
- **File I/O:** Standard C I/O with path normalization

### Compiler Support
- **GCC:** Primary supported compiler
- **Clang:** Compatible (tested)
- **Cross-compilers:** Support via CMake toolchain files

### Target Platform Support

#### Linux (Native)
```bash
# Standard Linux build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

#### Linux (Embedded/Cross-compilation)
```bash
# ARM cross-compilation example
cmake -DCMAKE_TOOLCHAIN_FILE=arm-linux-gnueabihf.cmake \
      -DCMAKE_SYSROOT=/opt/arm-sysroot \
      -DSTAGING_BINDIR_NATIVE=/usr/bin \
      ..
```

#### Custom Embedded Platforms
```bash
# Custom cross-compilation
cmake -DCMAKE_C_COMPILER=custom-gcc \
      -DCMAKE_SYSROOT=/custom/sysroot \
      -DCMAKE_FIND_ROOT_PATH=/custom/rootfs \
      ..
```

## Code Generation Pipeline

### Configuration File Processing

#### Audio Configuration Generation
```cmake
add_custom_command(
   OUTPUT xraudio_config.h
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_to_header.py" 
           -i ${CMAKE_CURRENT_SOURCE_DIR}/xr-audio/xraudio_config_default.json 
           -o xraudio_config.h -m 2
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xr-audio/xraudio_config_default.json
)
```

#### Speech Router Configuration
```cmake  
add_custom_command(
   OUTPUT vsdk_config.json
   COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/vsdk_json_combine.py"
           -i ${CMAKE_CURRENT_SOURCE_DIR}/xr-speech-router/xrsr_config_default.json
           -a ${CMAKE_CURRENT_SOURCE_DIR}/xr-audio/xraudio_config_default.json:xraudio
           -o vsdk_config.json
)
```

### Hash Table Generation
```cmake
# Perfect hash function generation using gperf
add_custom_command(
   OUTPUT rdkx_logger_modules.c
   COMMAND ${STAGING_BINDIR_NATIVE}/gperf 
           --output-file=rdkx_logger_modules.c rdkx_logger_modules.hash
   DEPENDS rdkx_logger_modules.hash rdkx_logger.json
)
```

### Version Information Generation
```cmake
add_custom_command(
   OUTPUT vsdk_version.h
   COMMAND echo -n "#define VSDK_BRANCH    \"" > vsdk_version.h
   COMMAND git -C ${CMAKE_SOURCE_DIR} branch --all --contains | 
           sed -n -e "s/^\\s*remotes\\/origin\\///" -e "2p" | 
           tr -d "\\n" >> vsdk_version.h
   COMMAND echo "\"" >> vsdk_version.h
   COMMAND echo -n "#define VSDK_COMMIT_ID " >> vsdk_version.h  
   COMMAND git -C ${CMAKE_SOURCE_DIR} log --format=\"%H\" -n 1 >> vsdk_version.h
   COMMAND echo -n "#define VSDK_VERSION   \"${CMAKE_PROJECT_VERSION}" >> vsdk_version.h
   COMMAND git -C ${CMAKE_SOURCE_DIR} diff --quiet || echo -n "++" >> vsdk_version.h
   COMMAND echo "\"" >> vsdk_version.h
)
```

## Installation Configuration

### Directory Structure
```cmake
# Configuration files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vsdk_config.json 
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR} COMPONENT config)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rdkx_logger.json TYPE SYSCONF)

# Header files  
install(FILES xr_voice_sdk.h TYPE INCLUDE)
install(FILES xr-speech-router/xrsr.h TYPE INCLUDE)
install(FILES xr-speech-vrex/xrsv.h TYPE INCLUDE)

# Library files
install(TARGETS xr-voice-sdk LIBRARY DESTINATION lib)
```

### Installation Paths
- **Headers:** `${CMAKE_INSTALL_PREFIX}/include/`
- **Libraries:** `${CMAKE_INSTALL_PREFIX}/lib/`
- **Config files:** `${CMAKE_INSTALL_PREFIX}/etc/`

## Build Workflow Examples

### Development Build
```bash
# Debug build with all protocols
mkdir build-debug
cd build-debug
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DHTTP_ENABLED=ON \
      -DWS_ENABLED=ON \
      -DSDT_ENABLED=ON \
      ..
make -j$(nproc)
```

### Production Build
```bash
# Optimized release build
mkdir build-release  
cd build-release
cmake -DCMAKE_BUILD_TYPE=Release \
      -DHTTP_ENABLED=ON \
      -DWS_ENABLED=ON \
      ..
make -j$(nproc)
make install DESTDIR=/staging
```

### Cross-Compilation Build
```bash
# ARM embedded target
mkdir build-arm
cd build-arm
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchains/arm-linux-gnueabihf.cmake \
      -DCMAKE_SYSROOT=/opt/arm-rootfs \
      -DSTAGING_BINDIR_NATIVE=/usr/bin \
      -DHTTP_ENABLED=ON \
      ..
make -j$(nproc)
```

## Build System Tools and Scripts

### Python Processing Scripts
- **`vsdk_json_combine.py`** - Combine multiple JSON configuration files
- **`vsdk_json_to_header.py`** - Generate C headers from JSON configuration  
- **`rdkx_logger_modules_to_c.py`** - Generate logging module lookup code

### External Tool Dependencies
- **`gperf`** - Perfect hash function generator
- **`git`** - Version information extraction
- **`python3`** - Configuration processing scripts

### Build Time Dependencies
```bash
# Required build tools
sudo apt-get install cmake build-essential python3 gperf git

# Required libraries  
sudo apt-get install libjansson-dev libuuid1 libbsd-dev

# Optional protocol libraries
sudo apt-get install libcurl4-openssl-dev  # HTTP support
sudo apt-get install libnopoll-dev         # WebSocket support
sudo apt-get install libopus-dev           # Opus codec support
```

## Build Customization Patterns

### Custom Toolchain File
```cmake
# arm-linux-gnueabihf.cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

### Custom Configuration Override
```cmake  
# Override default configuration in parent CMakeLists.txt
set(CUSTOM_CONFIG_PATH "/custom/config" CACHE PATH "Custom config directory")

# Custom audio configuration
configure_file(${CUSTOM_CONFIG_PATH}/xraudio_config.json
               ${CMAKE_BINARY_DIR}/xraudio_config_default.json
               COPYONLY)
```

## Troubleshooting Build Issues

### Common Build Problems

#### Missing Dependencies
```bash
# Check for missing libraries
ldd build/src/libxr-voice-sdk.so

# Install missing development packages
sudo apt-get install lib<name>-dev
```

#### Cross-Compilation Issues
```bash
# Verify toolchain configuration
cmake -LA .. | grep CMAKE_C_COMPILER
cmake -LA .. | grep CMAKE_SYSROOT

# Check library search paths
cmake -LA .. | grep CMAKE_FIND_ROOT_PATH
```

#### Generated File Issues
```bash
# Clean generated files
make clean
rm -rf CMakeFiles/ CMakeCache.txt

# Regenerate build system
cmake ..
```

### Build Performance Optimization
```bash
# Parallel build with optimal job count
make -j$(nproc)

# Use Ninja generator for faster builds  
cmake -GNinja ..
ninja
```

## Testing and Validation

### Build Verification
```bash
# Verify library symbols
nm -D build/src/libxr-voice-sdk.so | grep vsdk_init

# Check library dependencies  
objdump -p build/src/libxr-voice-sdk.so | grep NEEDED
```

### Cross-Platform Validation
```bash
# Verify executable format
file build/src/libxr-voice-sdk.so

# Check architecture compatibility
readelf -h build/src/libxr-voice-sdk.so
```

## Summary

The XR Voice SDK build system provides:

- **Flexible Configuration:** Modular feature enabling through CMake options
- **Cross-Platform Support:** Standard CMake patterns with toolchain file support
- **Automated Code Generation:** Configuration processing and hash table generation
- **Dependency Management:** Automatic library detection and optional feature handling
- **Production Ready:** Optimized builds with proper versioning and installation support
- **Developer Friendly:** Debug builds, verbose output, and comprehensive error checking

This architecture enables deployment across diverse platforms while maintaining consistency and reliability in the build process.