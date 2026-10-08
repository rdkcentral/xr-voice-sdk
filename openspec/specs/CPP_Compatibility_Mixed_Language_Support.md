# XR Voice SDK C++ Compatibility and Mixed-Language Project Support

## Overview

The XR Voice SDK is implemented in C but provides comprehensive C++ compatibility and mixed-language project support. This document outlines the SDK's C++ integration capabilities, build system compatibility, and best practices for using the SDK in mixed-language environments.

## C++ Compatibility Architecture

### Language Interface Design

The SDK follows industry-standard C/C++ interoperability patterns:

- **Pure C Implementation**: Core SDK written in C11/C23 for maximum portability
- **C++ Compatible Headers**: All public headers include proper `extern "C"` blocks
- **ABI Compatibility**: Maintains stable C ABI for cross-language compatibility
- **Exception Safety**: C functions are exception-neutral for C++ integration

### Header File Structure

All SDK header files implement consistent C++ compatibility:

```cpp
#ifdef __cplusplus
extern "C" {
#endif

// C function declarations and types

#ifdef __cplusplus
}
#endif
```

This pattern is implemented across:
- Main SDK header: `xr_voice_sdk.h`
- Component headers: `xraudio.h`, `xrsr.h`, `xrsv.h`
- Utility headers: `xr_timer.h`, `xr_mq.h`, etc.

## C++ Integration Patterns

### Basic C++ Integration

```cpp
#include <xr_voice_sdk.h>
#include <iostream>
#include <memory>

class VoiceSDKManager {
private:
    bool initialized;
    
public:
    VoiceSDKManager() : initialized(false) {}
    
    bool initialize() {
        int result = vsdk_init(true, "app.log", 1024 * 1024);
        initialized = (result == 0);
        return initialized;
    }
    
    ~VoiceSDKManager() {
        if (initialized) {
            vsdk_term();
        }
    }
};
```

### RAII Wrapper Classes

```cpp
// Smart pointer for SDK handles
class XRAudioHandle {
private:
    xraudio_object_t handle;
    bool valid;

public:
    XRAudioHandle() : handle(XRAUDIO_OBJECT_INVALID), valid(false) {}
    
    bool open(xraudio_devices_input_t source) {
        xraudio_result_t result = xraudio_open(source, &handle);
        valid = (result == XRAUDIO_RESULT_OK);
        return valid;
    }
    
    ~XRAudioHandle() {
        if (valid) {
            xraudio_close(handle);
        }
    }
    
    xraudio_object_t get() const { return handle; }
    bool is_valid() const { return valid; }
};
```

### Exception-Safe Callback Wrappers

```cpp
class SafeCallbackWrapper {
private:
    std::function<void()> cpp_callback;
    
public:
    // Static C callback that wraps C++ functionality
    static void c_callback_wrapper(void* user_data) {
        try {
            SafeCallbackWrapper* wrapper = 
                static_cast<SafeCallbackWrapper*>(user_data);
            if (wrapper && wrapper->cpp_callback) {
                wrapper->cpp_callback();
            }
        } catch (...) {
            // Log error but don't let exception escape to C code
            std::cerr << "Exception in callback, suppressing" << std::endl;
        }
    }
    
    void set_callback(std::function<void()> callback) {
        cpp_callback = callback;
    }
};
```

## Mixed-Language Project Support

### CMake Integration for C++ Projects

```cmake
cmake_minimum_required(VERSION 3.16)
project(VoiceApp CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find or build XR Voice SDK
find_package(PkgConfig REQUIRED)
pkg_check_modules(XRVOICE REQUIRED xr-voice-sdk)

# Create executable
add_executable(voice_app
    main.cpp
    voice_manager.cpp
)

# Link against SDK
target_link_libraries(voice_app 
    ${XRVOICE_LIBRARIES}
)

target_include_directories(voice_app PRIVATE
    ${XRVOICE_INCLUDE_DIRS}
)

target_compile_options(voice_app PRIVATE
    ${XRVOICE_CFLAGS_OTHER}
)
```

### Multi-Language Build Configuration

```cmake
# Mixed C/C++ project with SDK
project(MixedVoiceApp C CXX)

# C components
add_library(c_audio_processing STATIC
    audio_proc.c
    dsp_filters.c
)

# C++ components  
add_library(cpp_ui_layer STATIC
    ui_manager.cpp
    event_handler.cpp
)

# Main application linking both
add_executable(mixed_app
    main.cpp
)

target_link_libraries(mixed_app
    c_audio_processing
    cpp_ui_layer
    xr-voice-sdk
)
```

## Language-Specific Considerations

### Memory Management

**C++ Best Practices:**
```cpp
// Use smart pointers for automatic cleanup
std::unique_ptr<char[]> buffer(new char[buffer_size]);

// RAII for SDK initialization
class SDKInitializer {
public:
    SDKInitializer() {
        if (vsdk_init(true, "app.log", 1024*1024) != 0) {
            throw std::runtime_error("SDK initialization failed");
        }
    }
    ~SDKInitializer() { vsdk_term(); }
};
```

**Memory Ownership Rules:**
- SDK owns returned string pointers (don't delete)
- Application owns allocated buffers passed to SDK
- Use RAII for automatic resource management

### Error Handling Integration

```cpp
// Convert C error codes to C++ exceptions
class SDKException : public std::runtime_error {
public:
    SDKException(int error_code, const std::string& operation) 
        : std::runtime_error(format_error(error_code, operation))
        , code(error_code) {}
    
    int error_code() const { return code; }
    
private:
    int code;
    static std::string format_error(int code, const std::string& op);
};

// Helper function for error checking
inline void check_result(int result, const std::string& operation) {
    if (result != 0) {
        throw SDKException(result, operation);
    }
}
```

### Threading and Concurrency

```cpp
// Thread-safe C++ wrapper
class ThreadSafeVoiceSDK {
private:
    std::mutex mutex_;
    bool initialized_;
    
public:
    void initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            check_result(vsdk_init(true, "app.log", 1024*1024), 
                        "SDK initialization");
            initialized_ = true;
        }
    }
    
    void set_log_level(xlog_module_id_t module, xlog_level_t level) {
        std::lock_guard<std::mutex> lock(mutex_);
        vsdk_log_level_set(module, level);
    }
};
```

## Platform-Specific Mixed-Language Support

### Unity C# Integration

```csharp
// P/Invoke declarations in C#
public class VoiceSDK {
    [DllImport("xr-voice-sdk")]
    public static extern int vsdk_init(bool ansi_color, 
                                      string filename, 
                                      uint file_size_max);
    
    [DllImport("xr-voice-sdk")]
    public static extern void vsdk_term();
    
    // Managed wrapper
    public class ManagedVoiceSDK : IDisposable {
        private bool disposed = false;
        
        public bool Initialize() {
            return vsdk_init(true, "unity_voice.log", 1024 * 1024) == 0;
        }
        
        public void Dispose() {
            if (!disposed) {
                vsdk_term();
                disposed = true;
            }
        }
    }
}
```

### Unreal Engine C++ Integration

```cpp
// Unreal Engine module integration
DECLARE_LOG_CATEGORY_EXTERN(LogVoiceSDK, Log, All);

class VOICEMODULE_API VoiceSDKSubsystem : public UEngineSubsystem {
    GENERATED_BODY()
    
public:
    // USubsystem interface
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;
    
    UFUNCTION(BlueprintCallable, Category = "Voice SDK")
    bool InitializeVoiceSDK();
    
private:
    bool bInitialized = false;
};
```

### JavaScript/Node.js Integration

```javascript
// Node.js native addon integration
const { VoiceSDK } = require('./build/Release/voice_sdk_addon');

class VoiceSDKManager {
    constructor() {
        this.initialized = false;
    }
    
    initialize() {
        try {
            const result = VoiceSDK.init(true, 'node_voice.log', 1024 * 1024);
            this.initialized = (result === 0);
            return this.initialized;
        } catch (error) {
            console.error('Voice SDK initialization failed:', error);
            return false;
        }
    }
    
    cleanup() {
        if (this.initialized) {
            VoiceSDK.term();
            this.initialized = false;
        }
    }
}
```

## Build System Integration

### pkg-config Support

```bash
# SDK provides pkg-config file
pkg-config --cflags xr-voice-sdk
pkg-config --libs xr-voice-sdk

# Integration in Makefile
CFLAGS += $(shell pkg-config --cflags xr-voice-sdk)
LDFLAGS += $(shell pkg-config --libs xr-voice-sdk)
```

### Autotools Integration

```m4
# configure.ac integration
PKG_CHECK_MODULES([XRVOICE], [xr-voice-sdk >= 1.0])
AC_SUBST([XRVOICE_CFLAGS])
AC_SUBST([XRVOICE_LIBS])
```

### Meson Build System

```python
# meson.build
xrvoice_dep = dependency('xr-voice-sdk')

executable('voice_app',
    sources: ['main.cpp', 'voice_manager.cpp'],
    dependencies: [xrvoice_dep],
    cpp_std: 'c++17'
)
```

## Best Practices for Mixed-Language Projects

### Namespace Management

```cpp
// Use namespaces to organize C++ wrappers
namespace xr {
namespace voice {

class SDK {
public:
    static bool initialize(const std::string& log_file = "voice.log",
                          size_t max_size = 1024 * 1024) {
        return vsdk_init(true, log_file.c_str(), max_size) == 0;
    }
    
    static void terminate() {
        vsdk_term();
    }
};

} // namespace voice
} // namespace xr
```

### Configuration Management

```cpp
// C++ configuration wrapper
class SDKConfig {
private:
    std::string log_file_;
    size_t max_log_size_;
    bool ansi_colors_;
    
public:
    SDKConfig() 
        : log_file_("voice.log")
        , max_log_size_(1024 * 1024)
        , ansi_colors_(true) {}
    
    SDKConfig& log_file(const std::string& file) {
        log_file_ = file;
        return *this;
    }
    
    SDKConfig& max_log_size(size_t size) {
        max_log_size_ = size;
        return *this;
    }
    
    bool initialize() const {
        return vsdk_init(ansi_colors_, 
                        log_file_.c_str(), 
                        max_log_size_) == 0;
    }
};
```

### Performance Considerations

1. **Minimize Boundary Crossings**: Batch operations when possible
2. **Use Appropriate Data Types**: Match C types to avoid conversions
3. **Memory Layout Compatibility**: Ensure struct layouts match between languages
4. **Callback Performance**: Minimize C++ overhead in callbacks

### Debugging Mixed-Language Code

```cpp
// Debug helpers for mixed-language environment
#ifdef DEBUG
#define VOICE_SDK_CALL(func) \
    do { \
        std::cout << "Calling: " << #func << std::endl; \
        auto result = func; \
        if (result != 0) { \
            std::cerr << #func << " failed with code: " << result << std::endl; \
        } \
    } while(0)
#else
#define VOICE_SDK_CALL(func) func
#endif
```

## Conclusion

The XR Voice SDK provides robust support for C++ integration and mixed-language development through:
- Full C++ header compatibility with `extern "C"` blocks
- Stable C ABI for cross-language interoperability  
- Support for modern C++ patterns (RAII, smart pointers, exceptions)
- Integration with popular build systems (CMake, pkg-config, Autotools, Meson)
- Platform-specific wrapper examples (Unity, Unreal, Node.js)

This design enables seamless integration into existing C++ codebases and mixed-language projects while maintaining the performance and portability benefits of the underlying C implementation.