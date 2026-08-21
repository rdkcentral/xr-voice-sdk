# XR Voice SDK Integration Guide for Platform Developers

## Overview

This comprehensive integration guide provides XR platform developers with everything needed to successfully integrate the XR Voice SDK into extended reality applications and platforms. The SDK is designed for seamless integration across VR, AR, and MR environments, providing robust voice interaction capabilities with minimal platform-specific modifications.

## Quick Start Integration

### Prerequisites

#### System Requirements
```bash
# Minimum system requirements
- Operating System: Linux (Ubuntu 18.04+, CentOS 7+)
- Architecture: x86_64, ARM64
- Memory: 512MB RAM (minimum), 2GB RAM (recommended)
- Storage: 100MB available space
- Network: Internet connectivity for voice services

# Development dependencies  
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config
sudo apt-get install libasound2-dev libssl-dev libcurl4-openssl-dev
sudo apt-get install libjson-c-dev libpthread-stubs0-dev
```

#### Audio Hardware Requirements
```c
// Supported audio configurations
- Input: 16kHz PCM, 1-2 channels, 16-bit samples
- Output: 16kHz-48kHz PCM, 1-2 channels, 16-bit samples  
- Latency: <50ms round-trip (recommended)
- Devices: ALSA-compatible audio interfaces
```

### Basic Integration Steps

#### Step 1: SDK Initialization
```c
#include "xr_voice_sdk.h"

// Basic SDK initialization
int main() {
    vsdk_obj_t vsdk_obj = NULL;
    vsdk_result_t result;
    
    // Configure SDK parameters
    vsdk_config_t config = {
        .audio = {
            .input_device = VSDK_AUDIO_DEVICE_DEFAULT,
            .output_device = VSDK_AUDIO_DEVICE_DEFAULT,
            .sample_rate = 16000,
            .channels = 1,
            .frame_size = 320  // 20ms frames
        },
        .speech_router = {
            .protocols_enabled = VSDK_PROTOCOL_HTTPS | VSDK_PROTOCOL_WSS,
            .endpoint = "wss://voice-service.example.com/v1/speech",
            .authentication_token = "your_api_token_here"
        },
        .logging = {
            .level = VSDK_LOG_LEVEL_INFO,
            .output_file = "/var/log/xr_voice.log"
        }
    };
    
    // Initialize SDK
    result = vsdk_open(&vsdk_obj, &config);
    if(result != VSDK_RESULT_OK) {
        fprintf(stderr, "SDK initialization failed: %d\n", result);
        return -1;
    }
    
    printf("XR Voice SDK initialized successfully\n");
    
    // Your application code here...
    
    // Cleanup
    vsdk_close(vsdk_obj);
    return 0;
}
```

#### Step 2: Event Handler Registration
```c
// Voice interaction event handlers
void voice_session_callback(vsdk_session_event_t event, 
                           const vsdk_session_data_t *data,
                           void *user_data) {
    switch(event) {
        case VSDK_SESSION_EVENT_STARTED:
            printf("Voice session started\n");
            break;
            
        case VSDK_SESSION_EVENT_AUDIO_BEGIN:
            printf("Audio capture began\n");
            break;
            
        case VSDK_SESSION_EVENT_SPEECH_DETECTED:
            printf("Speech detected: confidence=%.2f\n", data->confidence);
            break;
            
        case VSDK_SESSION_EVENT_TRANSCRIPTION:
            printf("Transcription: %s\n", data->transcription.text);
            break;
            
        case VSDK_SESSION_EVENT_RESULT:
            printf("Final result: %s\n", data->result.text);
            // Process voice command in your XR application
            process_voice_command(data->result.text, data->result.intent);
            break;
            
        case VSDK_SESSION_EVENT_ERROR:
            printf("Session error: %s\n", data->error.message);
            break;
            
        case VSDK_SESSION_EVENT_ENDED:
            printf("Voice session ended\n");
            break;
    }
}

// Register event handlers
vsdk_callbacks_t callbacks = {
    .session_callback = voice_session_callback,
    .audio_callback = audio_data_callback,  // Optional raw audio access
    .error_callback = error_handling_callback
};

result = vsdk_callbacks_register(vsdk_obj, &callbacks, your_app_context);
```

#### Step 3: Voice Session Management
```c
// Start a voice interaction session
vsdk_result_t start_voice_interaction() {
    vsdk_session_config_t session_config = {
        .activation_type = VSDK_ACTIVATION_PUSH_TO_TALK,  // or VSDK_ACTIVATION_KEYWORD
        .language = "en-US",
        .timeout_speech = 5000,    // 5 seconds speech timeout
        .timeout_silence = 2000,   // 2 seconds silence timeout
        .enable_partial_results = true,
        .audio_format = {
            .sample_rate = 16000,
            .channels = 1,
            .bit_depth = 16
        }
    };
    
    vsdk_session_t session;
    vsdk_result_t result = vsdk_session_begin(vsdk_obj, &session_config, &session);
    if(result != VSDK_RESULT_OK) {
        printf("Failed to start voice session: %d\n", result);
        return result;
    }
    
    printf("Voice session started, listening for speech...\n");
    return VSDK_RESULT_OK;
}

// End voice session
vsdk_result_t end_voice_interaction(vsdk_session_t session) {
    return vsdk_session_end(vsdk_obj, session);
}
```

## Platform-Specific Integration

### Unity Integration

#### Unity C# Wrapper
```csharp
using System;
using System.Runtime.InteropServices;
using UnityEngine;

public class XRVoiceSDK : MonoBehaviour
{
    // Native SDK interop
    [DllImport("xr_voice_sdk")]
    private static extern int vsdk_open(out IntPtr obj, ref VSDKConfig config);
    
    [DllImport("xr_voice_sdk")]
    private static extern int vsdk_session_begin(IntPtr obj, ref SessionConfig config, out IntPtr session);
    
    [DllImport("xr_voice_sdk")]
    private static extern int vsdk_callbacks_register(IntPtr obj, ref VSDKCallbacks callbacks, IntPtr userData);
    
    // Configuration structures
    [StructLayout(LayoutKind.Sequential)]
    public struct VSDKConfig
    {
        public AudioConfig audio;
        public SpeechRouterConfig speechRouter;
        public LoggingConfig logging;
    }
    
    [StructLayout(LayoutKind.Sequential)]  
    public struct AudioConfig
    {
        public int inputDevice;
        public int outputDevice;
        public int sampleRate;
        public int channels;
        public int frameSize;
    }
    
    // Unity voice interaction events
    public event Action<string> OnTranscriptionReceived;
    public event Action<string, string> OnVoiceCommandReceived;
    public event Action<string> OnErrorOccurred;
    
    private IntPtr sdkObject;
    private bool isInitialized = false;
    
    void Start()
    {
        InitializeSDK();
    }
    
    void InitializeSDK()
    {
        VSDKConfig config = new VSDKConfig
        {
            audio = new AudioConfig
            {
                inputDevice = 0,  // Default device
                outputDevice = 0,
                sampleRate = 16000,
                channels = 1,
                frameSize = 320
            },
            speechRouter = new SpeechRouterConfig
            {
                endpoint = "wss://your-voice-service.com/v1/speech",
                authToken = "your_unity_app_token"
            }
        };
        
        int result = vsdk_open(out sdkObject, ref config);
        if(result == 0)
        {
            isInitialized = true;
            RegisterCallbacks();
            Debug.Log("XR Voice SDK initialized successfully");
        }
        else
        {
            Debug.LogError($"SDK initialization failed: {result}");
        }
    }
    
    public void StartVoiceCapture()
    {
        if(!isInitialized) return;
        
        SessionConfig sessionConfig = new SessionConfig
        {
            activationType = 1,  // Push to talk
            language = "en-US",
            timeoutSpeech = 5000,
            timeoutSilence = 2000
        };
        
        IntPtr session;
        int result = vsdk_session_begin(sdkObject, ref sessionConfig, out session);
        if(result != 0)
        {
            Debug.LogError($"Failed to start voice session: {result}");
        }
    }
    
    // Voice command processing for Unity XR
    void ProcessVoiceCommand(string transcription, string intent)
    {
        // Example voice commands for XR applications
        switch(intent.ToLower())
        {
            case "teleport":
                HandleTeleportCommand(transcription);
                break;
            case "select_object":
                HandleObjectSelection(transcription);
                break;
            case "menu_navigation":
                HandleMenuNavigation(transcription);
                break;
            case "volume_control":
                HandleVolumeControl(transcription);
                break;
            default:
                Debug.Log($"Unknown voice command: {transcription}");
                break;
        }
    }
}
```

### Unreal Engine Integration

#### Unreal C++ Integration
```cpp
// XRVoiceSDKComponent.h
#pragma once

#include "CoreMinimal.h"
#include "Components/ActorComponent.h" 
#include "xr_voice_sdk.h"
#include "XRVoiceSDKComponent.generated.h"

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnTranscriptionReceived, const FString&, Transcription);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FOnVoiceCommandReceived, const FString&, Command, const FString&, Intent);

UCLASS(ClassGroup=(Custom), meta=(BlueprintSpawnableComponent))
class YOURPROJECT_API UXRVoiceSDKComponent : public UActorComponent
{
    GENERATED_BODY()

public:
    UXRVoiceSDKComponent();

protected:
    virtual void BeginPlay() override;
    virtual void EndPlay(const EEndPlayReason::Type EndPlayReason) override;

public:
    UFUNCTION(BlueprintCallable, Category = "XR Voice")
    bool InitializeVoiceSDK();
    
    UFUNCTION(BlueprintCallable, Category = "XR Voice")
    bool StartVoiceCapture();
    
    UFUNCTION(BlueprintCallable, Category = "XR Voice") 
    bool StopVoiceCapture();
    
    // Blueprint events
    UPROPERTY(BlueprintAssignable, Category = "XR Voice")
    FOnTranscriptionReceived OnTranscriptionReceived;
    
    UPROPERTY(BlueprintAssignable, Category = "XR Voice")  
    FOnVoiceCommandReceived OnVoiceCommandReceived;

private:
    vsdk_obj_t SDKObject;
    bool bIsInitialized;
    
    static void SessionEventCallback(vsdk_session_event_t Event, 
                                   const vsdk_session_data_t* Data,
                                   void* UserData);
    
    void ProcessVoiceCommand(const FString& Command, const FString& Intent);
};
```

#### Unreal Blueprint Integration
```cpp
// XRVoiceSDKComponent.cpp
#include "XRVoiceSDKComponent.h"
#include "Engine/Engine.h"

UXRVoiceSDKComponent::UXRVoiceSDKComponent()
{
    PrimaryComponentTick.bCanEverTick = false;
    SDKObject = nullptr;
    bIsInitialized = false;
}

void UXRVoiceSDKComponent::BeginPlay()
{
    Super::BeginPlay();
    InitializeVoiceSDK();
}

bool UXRVoiceSDKComponent::InitializeVoiceSDK()
{
    vsdk_config_t Config = {};
    
    // Configure audio settings
    Config.audio.input_device = VSDK_AUDIO_DEVICE_DEFAULT;
    Config.audio.output_device = VSDK_AUDIO_DEVICE_DEFAULT;
    Config.audio.sample_rate = 16000;
    Config.audio.channels = 1;
    Config.audio.frame_size = 320;
    
    // Configure speech router
    Config.speech_router.protocols_enabled = VSDK_PROTOCOL_WSS;
    strcpy(Config.speech_router.endpoint, "wss://your-voice-service.com/v1/speech");
    strcpy(Config.speech_router.authentication_token, "your_unreal_app_token");
    
    vsdk_result_t Result = vsdk_open(&SDKObject, &Config);
    if(Result == VSDK_RESULT_OK)
    {
        // Register callbacks
        vsdk_callbacks_t Callbacks = {};
        Callbacks.session_callback = &UXRVoiceSDKComponent::SessionEventCallback;
        
        vsdk_callbacks_register(SDKObject, &Callbacks, this);
        
        bIsInitialized = true;
        UE_LOG(LogTemp, Log, TEXT("XR Voice SDK initialized successfully"));
        return true;
    }
    else
    {
        UE_LOG(LogTemp, Error, TEXT("SDK initialization failed: %d"), Result);
        return false;
    }
}

void UXRVoiceSDKComponent::SessionEventCallback(vsdk_session_event_t Event,
                                               const vsdk_session_data_t* Data,
                                               void* UserData)
{
    UXRVoiceSDKComponent* Component = static_cast<UXRVoiceSDKComponent*>(UserData);
    
    switch(Event)
    {
        case VSDK_SESSION_EVENT_TRANSCRIPTION:
            Component->OnTranscriptionReceived.Broadcast(FString(Data->transcription.text));
            break;
            
        case VSDK_SESSION_EVENT_RESULT:
            Component->OnVoiceCommandReceived.Broadcast(
                FString(Data->result.text), 
                FString(Data->result.intent)
            );
            Component->ProcessVoiceCommand(FString(Data->result.text), FString(Data->result.intent));
            break;
    }
}
```

### Native XR Platform Integration

#### OpenXR Integration
```c
// OpenXR integration example
#include <openxr/openxr.h>
#include "xr_voice_sdk.h"

typedef struct {
    XrInstance xr_instance;
    XrSession xr_session; 
    vsdk_obj_t voice_sdk;
    bool voice_active;
} xr_app_context_t;

// Initialize XR application with voice support
XrResult xr_app_initialize_with_voice(xr_app_context_t* app_ctx) {
    // Initialize OpenXR session first
    XrResult xr_result = xr_session_initialize(&app_ctx->xr_instance, &app_ctx->xr_session);
    if(XR_FAILED(xr_result)) {
        return xr_result;
    }
    
    // Initialize Voice SDK
    vsdk_config_t voice_config = {
        .audio = {
            .input_device = VSDK_AUDIO_DEVICE_DEFAULT,
            .sample_rate = 16000,
            .channels = 1
        },
        .speech_router = {
            .protocols_enabled = VSDK_PROTOCOL_WSS,
            .endpoint = "wss://xr-voice-service.com/v1/speech"
        }
    };
    
    vsdk_result_t voice_result = vsdk_open(&app_ctx->voice_sdk, &voice_config);
    if(voice_result != VSDK_RESULT_OK) {
        fprintf(stderr, "Voice SDK initialization failed: %d\n", voice_result);
        return XR_ERROR_INITIALIZATION_FAILED;
    }
    
    app_ctx->voice_active = false;
    return XR_SUCCESS;
}

// Handle XR input events with voice activation
void xr_handle_input_events(xr_app_context_t* app_ctx, XrActionStateGetInfo* get_info) {
    XrActionStateBoolean voice_button_state = {XR_TYPE_ACTION_STATE_BOOLEAN};
    XrResult result = xrGetActionStateBoolean(app_ctx->xr_session, get_info, &voice_button_state);
    
    if(XR_SUCCEEDED(result) && voice_button_state.isActive) {
        // Voice button pressed
        if(voice_button_state.currentState && !app_ctx->voice_active) {
            // Start voice capture
            vsdk_session_config_t session_config = {
                .activation_type = VSDK_ACTIVATION_PUSH_TO_TALK,
                .language = "en-US",
                .timeout_speech = 5000
            };
            
            vsdk_session_t session;
            vsdk_session_begin(app_ctx->voice_sdk, &session_config, &session);
            app_ctx->voice_active = true;
        }
        else if(!voice_button_state.currentState && app_ctx->voice_active) {
            // Voice button released - end capture
            vsdk_session_end_current(app_ctx->voice_sdk);
            app_ctx->voice_active = false;
        }
    }
}
```

## Advanced Integration Scenarios

### Multi-User Voice Support

#### Concurrent Voice Session Management
```c
// Multi-user voice session management
typedef struct {
    uint32_t user_id;
    vsdk_session_t session;
    bool active;
    char user_profile[64];
} user_voice_session_t;

typedef struct {
    user_voice_session_t sessions[MAX_CONCURRENT_USERS];
    int active_session_count;
    pthread_mutex_t sessions_mutex;
} multi_user_voice_manager_t;

// Initialize multi-user voice capability
vsdk_result_t multi_user_voice_init(multi_user_voice_manager_t* manager, 
                                   vsdk_obj_t voice_sdk) {
    memset(manager, 0, sizeof(multi_user_voice_manager_t));
    
    if(pthread_mutex_init(&manager->sessions_mutex, NULL) != 0) {
        return VSDK_RESULT_ERROR_INTERNAL;
    }
    
    return VSDK_RESULT_OK;
}

// Start voice session for specific user
vsdk_result_t start_user_voice_session(multi_user_voice_manager_t* manager,
                                      vsdk_obj_t voice_sdk,
                                      uint32_t user_id,
                                      const char* user_profile) {
    pthread_mutex_lock(&manager->sessions_mutex);
    
    // Find available session slot
    user_voice_session_t* session_slot = NULL;
    for(int i = 0; i < MAX_CONCURRENT_USERS; i++) {
        if(!manager->sessions[i].active) {
            session_slot = &manager->sessions[i];
            break;
        }
    }
    
    if(session_slot == NULL) {
        pthread_mutex_unlock(&manager->sessions_mutex);
        return VSDK_RESULT_ERROR_BUSY;  // No available slots
    }
    
    // Configure session for specific user
    vsdk_session_config_t session_config = {
        .activation_type = VSDK_ACTIVATION_KEYWORD,
        .language = "en-US", 
        .user_profile = user_profile,
        .isolation_mode = VSDK_ISOLATION_PER_USER  // Isolate audio per user
    };
    
    vsdk_result_t result = vsdk_session_begin(voice_sdk, &session_config, 
                                             &session_slot->session);
    if(result == VSDK_RESULT_OK) {
        session_slot->user_id = user_id;
        session_slot->active = true;
        strncpy(session_slot->user_profile, user_profile, 
               sizeof(session_slot->user_profile) - 1);
        manager->active_session_count++;
    }
    
    pthread_mutex_unlock(&manager->sessions_mutex);
    return result;
}
```

### Spatial Audio Integration

#### 3D Positional Voice Processing
```c
// Spatial voice processing for XR environments
typedef struct {
    float position[3];      // X, Y, Z coordinates
    float orientation[4];   // Quaternion rotation
    float distance;         // Distance from listener
    float volume_scale;     // Distance-based volume scaling
} spatial_audio_params_t;

// Configure spatial audio for voice processing
vsdk_result_t configure_spatial_voice_processing(vsdk_obj_t voice_sdk,
                                                const spatial_audio_params_t* spatial_params) {
    vsdk_audio_config_t audio_config = {
        .spatial_processing = true,
        .position = {spatial_params->position[0], 
                    spatial_params->position[1], 
                    spatial_params->position[2]},
        .orientation = {spatial_params->orientation[0],
                       spatial_params->orientation[1], 
                       spatial_params->orientation[2],
                       spatial_params->orientation[3]},
        .distance_attenuation = spatial_params->volume_scale,
        .reverb_processing = true,
        .room_size = VSDK_ROOM_SIZE_MEDIUM
    };
    
    return vsdk_audio_config_update(voice_sdk, &audio_config);
}

// Update spatial parameters during XR interaction
void update_voice_spatial_position(vsdk_obj_t voice_sdk,
                                  float x, float y, float z,
                                  float qx, float qy, float qz, float qw) {
    spatial_audio_params_t params = {
        .position = {x, y, z},
        .orientation = {qx, qy, qz, qw},
        .distance = sqrtf(x*x + y*y + z*z),
        .volume_scale = 1.0f / (1.0f + params.distance * 0.1f)  // Distance attenuation
    };
    
    configure_spatial_voice_processing(voice_sdk, &params);
}
```

### Voice Command Routing

#### Intelligent Command Disambiguation
```c
// Context-aware voice command processing for XR
typedef struct {
    char command_text[256];
    char intent[64];
    float confidence;
    char context[128];      // XR context (menu, game, etc.)
    uint32_t timestamp;
} xr_voice_command_t;

// Process voice command with XR context awareness
void process_xr_voice_command(const xr_voice_command_t* command,
                             xr_app_context_t* xr_context) {
    // Context-sensitive command interpretation
    if(strcmp(command->context, "menu_navigation") == 0) {
        handle_menu_voice_commands(command, xr_context);
    }
    else if(strcmp(command->context, "object_manipulation") == 0) {
        handle_object_voice_commands(command, xr_context);
    }
    else if(strcmp(command->context, "system_control") == 0) {
        handle_system_voice_commands(command, xr_context);
    }
    else {
        // Global commands available in any context
        handle_global_voice_commands(command, xr_context);
    }
}

// Menu navigation voice commands
void handle_menu_voice_commands(const xr_voice_command_t* command,
                               xr_app_context_t* xr_context) {
    if(strstr(command->command_text, "select") != NULL) {
        xr_menu_select_current_item(xr_context);
    }
    else if(strstr(command->command_text, "back") != NULL || 
            strstr(command->command_text, "previous") != NULL) {
        xr_menu_navigate_back(xr_context);
    }
    else if(strstr(command->command_text, "next") != NULL) {
        xr_menu_navigate_next(xr_context);
    }
    else if(strstr(command->command_text, "close") != NULL) {
        xr_menu_close(xr_context);
    }
}

// Object manipulation voice commands
void handle_object_voice_commands(const xr_voice_command_t* command,
                                 xr_app_context_t* xr_context) {
    if(strstr(command->command_text, "grab") != NULL ||
       strstr(command->command_text, "pick up") != NULL) {
        xr_object_grab_selected(xr_context);
    }
    else if(strstr(command->command_text, "release") != NULL ||
            strstr(command->command_text, "drop") != NULL) {
        xr_object_release_held(xr_context);
    }
    else if(strstr(command->command_text, "rotate") != NULL) {
        xr_object_rotate_selected(xr_context, command->command_text);
    }
    else if(strstr(command->command_text, "scale") != NULL ||
            strstr(command->command_text, "resize") != NULL) {
        xr_object_scale_selected(xr_context, command->command_text);
    }
}
```

## Configuration and Customization

### Platform-Specific Configuration Templates

#### VR Optimized Configuration
```c
// Configuration optimized for VR applications
vsdk_config_t create_vr_optimized_config() {
    vsdk_config_t config = {
        .audio = {
            .input_device = VSDK_AUDIO_DEVICE_DEFAULT,
            .output_device = VSDK_AUDIO_DEVICE_DEFAULT,
            .sample_rate = 16000,
            .channels = 2,           // Stereo for spatial audio
            .frame_size = 160,       // 10ms frames for low latency
            .noise_suppression = true,
            .echo_cancellation = true,
            .spatial_processing = true
        },
        .speech_router = {
            .protocols_enabled = VSDK_PROTOCOL_WSS,  // WebSocket for low latency
            .timeout_connect = 2000,    // Quick connection timeout
            .timeout_session = 30000,   // Extended session for VR
            .retry_attempts = 5,
            .low_latency_mode = true
        },
        .voice_recognition = {
            .language = "en-US",
            .enable_partial_results = true,
            .confidence_threshold = 0.7f,
            .context_hints = {"VR", "virtual reality", "immersive", "spatial"}
        },
        .performance = {
            .power_mode = VSDK_POWER_MODE_HIGH_PERFORMANCE,
            .cpu_optimization = VSDK_CPU_OPTIMIZE_LATENCY,
            .memory_pool_size = 8 * 1024 * 1024  // 8MB for VR
        }
    };
    
    return config;
}
```

#### AR Optimized Configuration  
```c
// Configuration optimized for AR applications
vsdk_config_t create_ar_optimized_config() {
    vsdk_config_t config = {
        .audio = {
            .sample_rate = 16000,
            .channels = 1,           // Mono for power efficiency
            .frame_size = 320,       // 20ms frames for balanced performance
            .adaptive_noise_suppression = true,  // Dynamic environment noise
            .wind_noise_reduction = true,        // Outdoor AR scenarios
            .ambient_noise_adaptation = true
        },
        .speech_router = {
            .protocols_enabled = VSDK_PROTOCOL_HTTPS | VSDK_PROTOCOL_WSS,
            .adaptive_protocol_selection = true,  // Switch based on network
            .timeout_connect = 5000,
            .timeout_session = 15000,
            .bandwidth_optimization = true
        },
        .voice_recognition = {
            .enable_context_switching = true,    // Switch between AR contexts
            .background_noise_adaptation = true,
            .outdoor_optimization = true,
            .context_hints = {"AR", "augmented reality", "overlay", "marker"}
        },
        .performance = {
            .power_mode = VSDK_POWER_MODE_BALANCED,
            .cpu_optimization = VSDK_CPU_OPTIMIZE_BALANCED,
            .battery_optimization = true
        }
    };
    
    return config;
}
```

### Dynamic Configuration Updates

#### Runtime Configuration Adaptation
```c
// Adapt configuration based on XR application state
void adapt_voice_config_to_xr_context(vsdk_obj_t voice_sdk, 
                                      xr_application_state_t xr_state) {
    vsdk_config_t updated_config = {};
    
    switch(xr_state) {
        case XR_STATE_MENU:
            // Menu interaction - prioritize accuracy
            updated_config.voice_recognition.confidence_threshold = 0.8f;
            updated_config.audio.noise_suppression = true;
            updated_config.performance.power_mode = VSDK_POWER_MODE_LOW;
            break;
            
        case XR_STATE_ACTIVE_GAMEPLAY:
            // Active gameplay - prioritize low latency
            updated_config.audio.frame_size = 160;  // 10ms frames
            updated_config.speech_router.low_latency_mode = true;
            updated_config.performance.power_mode = VSDK_POWER_MODE_HIGH_PERFORMANCE;
            break;
            
        case XR_STATE_MULTIPLAYER:
            // Multiplayer - optimize for network and multiple users
            updated_config.speech_router.bandwidth_optimization = true;
            updated_config.audio.echo_cancellation = true;
            updated_config.voice_recognition.multi_user_mode = true;
            break;
            
        case XR_STATE_BACKGROUND:
            // Background/minimized - conserve resources
            updated_config.performance.power_mode = VSDK_POWER_MODE_LOW;
            updated_config.audio.sample_rate = 8000;  // Lower quality
            updated_config.speech_router.connection_pooling = false;
            break;
    }
    
    vsdk_config_update_runtime(voice_sdk, &updated_config);
}
```

## Troubleshooting and Debugging

### Common Integration Issues

#### Audio Device Issues
```c
// Diagnose audio device problems
vsdk_result_t diagnose_audio_issues(vsdk_obj_t voice_sdk) {
    vsdk_audio_diagnostics_t diagnostics = {};
    vsdk_result_t result = vsdk_audio_diagnostics_get(voice_sdk, &diagnostics);
    
    if(result != VSDK_RESULT_OK) {
        printf("Failed to get audio diagnostics: %d\n", result);
        return result;
    }
    
    printf("Audio Device Diagnostics:\n");
    printf("  Input Device: %s (available: %s)\n", 
           diagnostics.input_device_name,
           diagnostics.input_available ? "yes" : "no");
    printf("  Output Device: %s (available: %s)\n",
           diagnostics.output_device_name,
           diagnostics.output_available ? "yes" : "no");
    printf("  Sample Rate: %d Hz (supported: %s)\n",
           diagnostics.current_sample_rate,
           diagnostics.sample_rate_supported ? "yes" : "no");
    printf("  Latency: Input=%dms, Output=%dms\n",
           diagnostics.input_latency_ms,
           diagnostics.output_latency_ms);
    
    // Suggestions based on diagnostics
    if(!diagnostics.input_available) {
        printf("ISSUE: Input device not available\n");
        printf("SOLUTION: Check microphone permissions and device connection\n");
    }
    
    if(diagnostics.input_latency_ms > 50) {
        printf("WARNING: High input latency (%dms)\n", diagnostics.input_latency_ms);
        printf("SOLUTION: Try reducing frame size or using different device\n");
    }
    
    return VSDK_RESULT_OK;
}
```

#### Network Connectivity Issues
```c
// Diagnose network connectivity problems
vsdk_result_t diagnose_network_issues(vsdk_obj_t voice_sdk) {
    vsdk_network_diagnostics_t diagnostics = {};
    vsdk_result_t result = vsdk_network_diagnostics_get(voice_sdk, &diagnostics);
    
    printf("Network Diagnostics:\n");
    printf("  Connection Status: %s\n", 
           diagnostics.connected ? "Connected" : "Disconnected");
    printf("  Endpoint: %s\n", diagnostics.endpoint_url);
    printf("  Protocol: %s\n", diagnostics.active_protocol);
    printf("  Latency: %dms\n", diagnostics.round_trip_latency_ms);
    printf("  Bandwidth: %.2f kbps\n", diagnostics.bandwidth_kbps);
    
    if(!diagnostics.connected) {
        printf("ISSUE: Not connected to voice service\n");
        printf("SOLUTIONS:\n");
        printf("  1. Check internet connectivity\n");
        printf("  2. Verify endpoint URL and authentication\n");  
        printf("  3. Check firewall settings\n");
    }
    
    if(diagnostics.round_trip_latency_ms > 500) {
        printf("WARNING: High network latency (%dms)\n", 
               diagnostics.round_trip_latency_ms);
        printf("SOLUTION: Consider using edge servers or caching\n");
    }
    
    return VSDK_RESULT_OK;
}
```

### Performance Optimization

#### Audio Performance Tuning
```c
// Optimize audio performance for XR applications
void optimize_audio_performance(vsdk_obj_t voice_sdk, 
                               xr_performance_profile_t profile) {
    vsdk_audio_config_t audio_config = {};
    
    switch(profile) {
        case XR_PERFORMANCE_ULTRA_LOW_LATENCY:
            audio_config.frame_size = 80;        // 5ms frames
            audio_config.buffer_count = 2;       // Minimal buffering
            audio_config.processing_threads = 4; // Dedicated threads
            audio_config.real_time_priority = true;
            break;
            
        case XR_PERFORMANCE_BALANCED:
            audio_config.frame_size = 320;       // 20ms frames
            audio_config.buffer_count = 4;       // Moderate buffering
            audio_config.processing_threads = 2;
            audio_config.real_time_priority = false;
            break;
            
        case XR_PERFORMANCE_POWER_EFFICIENT:
            audio_config.frame_size = 640;       // 40ms frames
            audio_config.buffer_count = 8;       // More buffering
            audio_config.processing_threads = 1;
            audio_config.real_time_priority = false;
            audio_config.power_saving_mode = true;
            break;
    }
    
    vsdk_audio_config_update(voice_sdk, &audio_config);
}
```

#### Memory Usage Optimization
```c
// Monitor and optimize memory usage
void optimize_memory_usage(vsdk_obj_t voice_sdk) {
    vsdk_memory_stats_t mem_stats = {};
    vsdk_memory_stats_get(voice_sdk, &mem_stats);
    
    printf("Memory Usage Statistics:\n");
    printf("  Total Allocated: %zu bytes\n", mem_stats.total_allocated);
    printf("  Audio Buffers: %zu bytes\n", mem_stats.audio_buffers);
    printf("  Network Buffers: %zu bytes\n", mem_stats.network_buffers);
    printf("  Processing Buffers: %zu bytes\n", mem_stats.processing_buffers);
    
    // Apply memory optimizations if usage is high
    if(mem_stats.total_allocated > (16 * 1024 * 1024)) {  // 16MB threshold
        vsdk_memory_config_t mem_config = {
            .buffer_pool_size = mem_stats.total_allocated / 2,
            .enable_buffer_reuse = true,
            .compression_enabled = true,
            .lazy_allocation = true
        };
        
        vsdk_memory_config_update(voice_sdk, &mem_config);
        printf("Applied memory optimizations\n");
    }
}
```

## Best Practices

### 1. **Resource Management**
- Always initialize the SDK in the main thread
- Use appropriate power modes for different XR scenarios
- Implement proper cleanup in application shutdown handlers
- Monitor memory and CPU usage regularly

### 2. **Audio Quality Optimization**
- Choose frame sizes based on latency requirements (5-40ms)
- Enable noise suppression in noisy environments
- Use spatial audio processing for immersive experiences
- Test with various audio devices and configurations

### 3. **Network Optimization**  
- Use WebSocket connections for low-latency scenarios
- Implement connection retry logic with exponential backoff
- Cache frequently used voice models locally when possible
- Monitor network quality and adapt protocols accordingly

### 4. **User Experience**
- Provide visual feedback for voice activation states
- Implement context-aware voice command interpretation
- Support multiple activation methods (button, keyword, gesture)
- Handle voice recognition errors gracefully with user feedback

### 5. **Error Handling and Recovery**
- Register error callbacks for proactive issue detection
- Implement automatic recovery for transient failures
- Log detailed error information for debugging
- Provide fallback interaction methods when voice fails

## Platform-Specific Considerations

### Unity Specific
- Use Unity's job system for audio processing when possible
- Integrate with Unity's audio mixer for spatial effects
- Handle scene transitions and SDK lifecycle properly
- Use Unity Analytics to monitor voice interaction metrics

### Unreal Engine Specific  
- Leverage Unreal's audio engine for enhanced spatial processing
- Use Blueprint nodes for rapid voice interaction prototyping
- Integrate with Unreal's input system for multimodal interaction
- Utilize Unreal's profiling tools for performance optimization

### Native Platforms
- Follow platform audio session management guidelines
- Implement proper background/foreground state handling
- Use platform-specific audio APIs for optimal performance
- Ensure compatibility with platform security requirements

## Conclusion

The XR Voice SDK provides a powerful foundation for integrating voice interaction capabilities into extended reality applications. By following this integration guide, developers can:

- **Quickly integrate** voice capabilities into existing XR applications
- **Optimize performance** for specific XR use cases and hardware constraints
- **Handle platform-specific requirements** across Unity, Unreal, and native platforms
- **Implement robust error handling** and recovery mechanisms
- **Provide excellent user experiences** with context-aware voice interactions

For additional support, consult the API reference documentation, component analysis documents, and platform-specific integration examples provided with the SDK.