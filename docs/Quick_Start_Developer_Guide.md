# XR Voice SDK Quick-Start Guide

## Overview

This quick-start guide provides developers with everything needed to integrate voice capabilities into XR applications using the XR Voice SDK. Follow this guide to get up and running with voice interaction in under 30 minutes.

## Prerequisites

### System Requirements
- **Operating System:** Linux (Ubuntu 20.04+), Windows 10/11, or macOS 10.15+
- **Compiler:** GCC 9+, Clang 10+, or MSVC 2019+
- **CMake:** Version 3.16 or higher
- **Dependencies:** Standard build tools, pkg-config

### Hardware Requirements
- **Audio Input:** Microphone or microphone array
- **Network:** Internet connection for voice recognition services
- **Memory:** Minimum 512MB available RAM
- **CPU:** Multi-core processor recommended for real-time processing

## 5-Minute Integration

### Step 1: Project Setup

**For New CMake Projects:**
```cmake
cmake_minimum_required(VERSION 3.16)
project(VoiceEnabledApp CXX)

# Find XR Voice SDK
find_package(PkgConfig REQUIRED)
pkg_check_modules(XRVOICE REQUIRED xr-voice-sdk)

# Create your application
add_executable(voice_app main.cpp)

# Link against the SDK
target_link_libraries(voice_app ${XRVOICE_LIBRARIES})
target_include_directories(voice_app PRIVATE ${XRVOICE_INCLUDE_DIRS})
```

**For Existing Projects:**
```cmake
# Add to existing CMakeLists.txt
pkg_check_modules(XRVOICE REQUIRED xr-voice-sdk)
target_link_libraries(your_existing_target ${XRVOICE_LIBRARIES})
target_include_directories(your_existing_target PRIVATE ${XRVOICE_INCLUDE_DIRS})
```

### Step 2: Basic SDK Integration

**Minimal C Application:**
```c
#include <xr_voice_sdk.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Initialize the Voice SDK
    int result = vsdk_init(true, "voice_app.log", 1024 * 1024);
    if (result != 0) {
        printf("Failed to initialize Voice SDK: %d\n", result);
        return 1;
    }
    
    printf("XR Voice SDK initialized successfully!\n");
    
    // Your application logic here
    
    // Cleanup
    vsdk_term();
    return 0;
}
```

**Minimal C++ Application:**
```cpp
#include <xr_voice_sdk.h>
#include <iostream>
#include <stdexcept>

class VoiceApp {
private:
    bool initialized = false;
    
public:
    void initialize() {
        int result = vsdk_init(true, "voice_app.log", 1024 * 1024);
        if (result != 0) {
            throw std::runtime_error("Failed to initialize Voice SDK");
        }
        initialized = true;
        std::cout << "XR Voice SDK initialized successfully!" << std::endl;
    }
    
    ~VoiceApp() {
        if (initialized) {
            vsdk_term();
        }
    }
};

int main() try {
    VoiceApp app;
    app.initialize();
    
    // Your application logic here
    
    return 0;
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
}
```

### Step 3: Build and Run

```bash
mkdir build && cd build
cmake ..
make
./voice_app
```

**Expected Output:**
```
XR Voice SDK initialized successfully!
```

## 15-Minute Voice Recognition Setup

### Step 1: Enable Voice Recognition Components

**CMake Configuration:**
```cmake
# Enable required protocols
option(HTTP_ENABLED "Enable HTTP voice recognition" ON)
option(WS_ENABLED "Enable WebSocket voice recognition" ON)

# Configure build
add_definitions(-DHTTP_ENABLED -DWS_ENABLED)
```

### Step 2: Basic Voice Recognition

```c
#include <xr_voice_sdk.h>
#include <xrsr.h>
#include <xrsv.h>
#include <stdio.h>

// Voice recognition callback
void voice_result_callback(const char* result, void* user_data) {
    printf("Voice Recognition Result: %s\n", result);
}

// Session end callback  
void session_end_callback(xrsr_session_end_reason_t reason, void* user_data) {
    printf("Voice session ended, reason: %d\n", reason);
}

int main() {
    // Initialize SDK
    if (vsdk_init(true, "voice_app.log", 1024 * 1024) != 0) {
        printf("SDK initialization failed\n");
        return 1;
    }
    
    // TODO: Configure voice recognition session
    // This would include XRSR session setup and XRSV integration
    // See full examples in platform integration guides
    
    printf("Voice recognition setup complete\n");
    
    // Keep application running for voice input
    printf("Listening for voice input... (Press Enter to exit)\n");
    getchar();
    
    vsdk_term();
    return 0;
}
```

## Platform-Specific Integration

### Unity Integration (C#)

**1. Create Unity Package Structure:**
```
Assets/
├── Plugins/
│   ├── xr-voice-sdk.dll (Windows)
│   ├── libxr-voice-sdk.so (Linux)
│   └── libxr-voice-sdk.dylib (macOS)
└── Scripts/
    └── VoiceSDK.cs
```

**2. C# Wrapper Script:**
```csharp
using System;
using System.Runtime.InteropServices;
using UnityEngine;

public class VoiceSDK : MonoBehaviour
{
    // P/Invoke declarations
    [DllImport("xr-voice-sdk")]
    private static extern int vsdk_init(bool ansi_color, string filename, uint file_size_max);
    
    [DllImport("xr-voice-sdk")]
    private static extern void vsdk_term();
    
    void Start()
    {
        // Initialize Voice SDK
        int result = vsdk_init(true, Application.persistentDataPath + "/voice.log", 1024 * 1024);
        if (result == 0)
        {
            Debug.Log("Voice SDK initialized successfully");
        }
        else
        {
            Debug.LogError($"Voice SDK initialization failed: {result}");
        }
    }
    
    void OnDestroy()
    {
        vsdk_term();
    }
}
```

### Unreal Engine Integration (C++)

**1. Add to Build.cs file:**
```cpp
// YourProject.Build.cs
PublicDependencyModuleNames.AddRange(new string[] { 
    "Core", 
    "CoreUObject", 
    "Engine",
    "XRVoiceSDK" // Add this line
});

// Add library path
PublicLibraryPaths.Add("path/to/xr-voice-sdk/lib");
PublicAdditionalLibraries.Add("xr-voice-sdk");
```

**2. Voice Component Header:**
```cpp
// VoiceComponent.h
#pragma once

#include "CoreMinimal.h"
#include "Components/ActorComponent.h"
#include "xr_voice_sdk.h"
#include "VoiceComponent.generated.h"

UCLASS(ClassGroup=(Custom), meta=(BlueprintSpawnableComponent))
class YOURPROJECT_API UVoiceComponent : public UActorComponent
{
    GENERATED_BODY()

public:
    UVoiceComponent();

    UFUNCTION(BlueprintCallable, Category = "Voice")
    bool InitializeVoice();
    
    UFUNCTION(BlueprintCallable, Category = "Voice")
    void ShutdownVoice();

protected:
    virtual void BeginPlay() override;
    virtual void EndPlay(const EEndPlayReason::Type EndPlayReason) override;

private:
    bool bVoiceInitialized = false;
};
```

**3. Voice Component Implementation:**
```cpp
// VoiceComponent.cpp
#include "VoiceComponent.h"
#include "Engine/Engine.h"

UVoiceComponent::UVoiceComponent()
{
    PrimaryComponentTick.bCanEverTick = false;
}

void UVoiceComponent::BeginPlay()
{
    Super::BeginPlay();
    InitializeVoice();
}

bool UVoiceComponent::InitializeVoice()
{
    if (!bVoiceInitialized)
    {
        FString LogPath = FPaths::ProjectLogDir() + TEXT("voice.log");
        int32 Result = vsdk_init(true, TCHAR_TO_ANSI(*LogPath), 1024 * 1024);
        
        bVoiceInitialized = (Result == 0);
        
        if (bVoiceInitialized)
        {
            UE_LOG(LogTemp, Log, TEXT("Voice SDK initialized successfully"));
        }
        else
        {
            UE_LOG(LogTemp, Error, TEXT("Voice SDK initialization failed: %d"), Result);
        }
    }
    
    return bVoiceInitialized;
}

void UVoiceComponent::EndPlay(const EEndPlayReason::Type EndPlayReason)
{
    ShutdownVoice();
    Super::EndPlay(EndPlayReason);
}

void UVoiceComponent::ShutdownVoice()
{
    if (bVoiceInitialized)
    {
        vsdk_term();
        bVoiceInitialized = false;
        UE_LOG(LogTemp, Log, TEXT("Voice SDK shutdown complete"));
    }
}
```

## Configuration Quick Setup

### Basic Configuration File

**Create `voice_config.json`:**
```json
{
  "xraudio": {
    "input": {
      "kwd": {
        "enabled": true,
        "sensitivity": 0.5
      },
      "eos": {
        "enabled": true,
        "timeout": 2000
      }
    },
    "output": {
      "enabled": true
    }
  },
  "xrsr": {
    "http": {
      "debug": false,
      "timeout": 5000
    },
    "ws": {
      "debug": false,
      "fpm": {
        "timeout_connect": 2000,
        "timeout_session": 10000
      }
    }
  }
}
```

### Runtime Configuration Updates

```c
// Update log levels at runtime
vsdk_log_level_set(XLOG_MODULE_ID_XRAUDIO, XLOG_LEVEL_INFO);
vsdk_log_level_set(XLOG_MODULE_ID_XRSR, XLOG_LEVEL_DEBUG);

// Get current log level
xlog_level_t current_level = vsdk_log_level_get(XLOG_MODULE_ID_XRAUDIO);
printf("Current XRAudio log level: %d\n", current_level);
```

## Common Integration Patterns

### Error Handling Pattern

```c
#include <xr_voice_sdk.h>

typedef enum {
    APP_RESULT_SUCCESS = 0,
    APP_RESULT_INIT_FAILED = 1,
    APP_RESULT_AUDIO_FAILED = 2,
    APP_RESULT_NETWORK_FAILED = 3
} app_result_t;

app_result_t initialize_voice_system(void) {
    // Initialize SDK
    int sdk_result = vsdk_init(true, "app.log", 2 * 1024 * 1024);
    if (sdk_result != 0) {
        printf("SDK initialization failed with code: %d\n", sdk_result);
        return APP_RESULT_INIT_FAILED;
    }
    
    // Additional initialization steps would go here
    
    return APP_RESULT_SUCCESS;
}

void cleanup_voice_system(void) {
    vsdk_term();
    printf("Voice system cleanup complete\n");
}
```

### Resource Management Pattern

```cpp
#include <xr_voice_sdk.h>
#include <memory>

class VoiceSDKManager {
private:
    bool initialized_;
    
public:
    VoiceSDKManager() : initialized_(false) {}
    
    bool initialize(const std::string& log_file = "voice.log", 
                   size_t log_size = 1024 * 1024) {
        if (!initialized_) {
            int result = vsdk_init(true, log_file.c_str(), log_size);
            initialized_ = (result == 0);
        }
        return initialized_;
    }
    
    ~VoiceSDKManager() {
        if (initialized_) {
            vsdk_term();
        }
    }
    
    bool is_initialized() const { return initialized_; }
};

// Usage with RAII
int main() {
    auto voice_manager = std::make_unique<VoiceSDKManager>();
    
    if (!voice_manager->initialize()) {
        std::cerr << "Failed to initialize voice system" << std::endl;
        return 1;
    }
    
    // Use voice system
    std::cout << "Voice system ready!" << std::endl;
    
    // Automatic cleanup when voice_manager goes out of scope
    return 0;
}
```

## Troubleshooting

### Common Issues and Solutions

**Issue 1: SDK Initialization Fails**
```c
// Check return codes
int result = vsdk_init(true, "voice.log", 1024 * 1024);
switch (result) {
    case 0:
        printf("Success\n");
        break;
    default:
        printf("Initialization failed with code: %d\n", result);
        // Check log file for detailed error information
        break;
}
```

**Issue 2: Missing Dependencies**
```bash
# Ubuntu/Debian
sudo apt-get install libjansson-dev libuuid1 libcurl4-openssl-dev

# CentOS/RHEL  
sudo yum install jansson-devel libuuid-devel libcurl-devel

# Check library availability
pkg-config --exists xr-voice-sdk && echo "SDK found" || echo "SDK not found"
```

**Issue 3: Audio Device Access**
```c
// Enable debug logging to diagnose audio issues
vsdk_log_level_set_all(XLOG_LEVEL_DEBUG);

// Check audio device permissions (Linux)
// Ensure user is in 'audio' group
```

### Debug Configuration

```json
{
  "debug_config": {
    "enable_all_logging": true,
    "log_to_console": true,
    "log_to_file": true,
    "audio_debug": true,
    "network_debug": true
  }
}
```

## Next Steps

### Advanced Features
1. **Multi-Protocol Voice Recognition** - [XRSR Architecture Guide](XRSR_Architecture_Protocol_Analysis.md)
2. **Audio Processing Customization** - [XRAudio Component Analysis](XRAudio_Component_Analysis.md)  
3. **Performance Optimization** - [Performance Analysis Framework](Performance_Analysis_Framework.md)
4. **Security Implementation** - [Security Analysis](Security_Analysis.md)

### Platform-Specific Guides
- **Unity Deep Integration** - [XR Platform Integration Guide](XR_Platform_Integration_Guide_for_Developers.md#unity-integration)
- **Unreal Engine Advanced Setup** - [XR Platform Integration Guide](XR_Platform_Integration_Guide_for_Developers.md#unreal-integration)
- **Native OpenXR Integration** - [XR Platform Integration Guide](XR_Platform_Integration_Guide_for_Developers.md#openxr-integration)

### Complete API Reference
- **Core SDK APIs** - [API Interface Documentation](API_Interface_Documentation.md)
- **Configuration Management** - [Configuration Schema Documentation](Configuration_Schema_Documentation.md)
- **Error Handling** - [Error Handling Patterns](Error_Handling_Patterns_Return_Code_Conventions.md)

## Support Resources

### Documentation Navigation
- **Main Documentation Index** - [README.md](README.md)
- **Cross-Reference System** - [Cross Reference Navigation](Cross_Reference_Navigation_System.md)
- **Component Analysis** - Individual component documentation files

### Development Tools
- **Build System Reference** - [Build System Configuration](Build_System_Configuration.md)
- **Threading Guidelines** - [Threading Model](Threading_Model.md)
- **Integration Patterns** - [Cross Component Integration Analysis](Cross_Component_Integration_Analysis.md)

This quick-start guide provides the essential information needed to integrate the XR Voice SDK into your application. For detailed implementation guidance and advanced features, refer to the comprehensive documentation linked throughout this guide.