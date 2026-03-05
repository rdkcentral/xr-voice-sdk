# XR Voice SDK - Versioning System and Component Version Management

## Overview

The XR Voice SDK implements a comprehensive versioning system that provides detailed version information for the SDK and its components, supports Git-based version tracking, and integrates with platform-specific versioning systems. The versioning approach ensures traceability, compatibility checking, and proper component identification across different deployment scenarios.

## Versioning Architecture

### Multi-Level Version Management
The SDK employs a three-tier versioning approach:

1. **SDK-Level Versioning** - Overall SDK version with Git integration
2. **Component-Level Versioning** - Individual component version tracking  
3. **Platform Integration** - Optional RDK platform versioning support

### Version Information Structure
```c
typedef struct {
   const char *name;      ///< Component name identifier
   const char *version;   ///< Semantic version string
   const char *branch;    ///< Git branch name
   const char *commit_id; ///< Git commit identifier
} vsdk_version_info_t;
```

## SDK Version Management

### Version Information API
The SDK provides a public API for retrieving comprehensive version information:

```c
#define VSDK_VERSION_QTY_MAX (2)  ///< Maximum version structures supported

void vsdk_version(vsdk_version_info_t *version_info, uint32_t *qty);
```

### Version Data Population
```c
void vsdk_version(vsdk_version_info_t *version_info, uint32_t *qty) {
   if(qty == NULL || *qty < VSDK_VERSION_QTY_MAX || version_info == NULL) {
      return;
   }
   uint32_t qty_avail = *qty;

   // Primary SDK version information
   version_info->name      = "xr-voice-sdk";
   version_info->version   = VSDK_VERSION;    // Generated version string
   version_info->branch    = VSDK_BRANCH;     // Git branch name
   version_info->commit_id = VSDK_COMMIT_ID;  // Git commit hash
   version_info++;
   qty_avail--;

   *qty -= qty_avail;  // Return number of entries filled
}
```

## Automated Version Generation

### Build-Time Version Creation
The SDK uses CMake custom commands to automatically generate version information during build:

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
   VERBATIM)
```

### Generated Version Header Structure
The build process creates `vsdk_version.h` with the following format:
```c
#define VSDK_BRANCH    "main"
#define VSDK_COMMIT_ID "a1b2c3d4e5f6789012345678901234567890abcd"
#define VSDK_VERSION   "1.0.0"      // or "1.0.0++" if working directory is dirty
```

### Version Components

#### Version String Format
- **Base Version**: `${CMAKE_PROJECT_VERSION}` (e.g., "1.0.0")
- **Development Indicator**: Appends "++" if Git working directory has uncommitted changes
- **Example Versions**: 
  - "1.0.0" - Clean release build
  - "1.0.0++" - Development build with local modifications

#### Branch Information  
```bash
git branch --all --contains | sed -n -e "s/^\\s*remotes\\/origin\\///" -e "2p"
```
- Extracts the remote branch name containing the current commit
- Removes "remotes/origin/" prefix for clean branch identification
- Provides deployment context and source tracking

#### Commit Identification
```bash
git log --format="%H" -n 1
```
- Full SHA-1 commit hash for precise source identification
- Enables exact source code correlation and debugging
- Supports binary-to-source traceability

## Component Version Management

### Audio Component Versioning
The xr-audio component defines its own version information structure:

```c
// xr-audio/xraudio_version.h
typedef struct {
   const char *name;      // Component name
   const char *version;   // Component version  
   const char *branch;    // Git branch
   const char *commit_id; // Git commit hash
} xraudio_version_info_t;
```

### Component Registration Pattern
Each major component can provide its own version information following the standardized structure, enabling:
- Independent component versioning
- Component compatibility verification
- Granular update tracking

## Platform Integration Versioning

### RDK Platform Support
The SDK provides optional integration with RDK platform versioning:

```cmake
option(RDK_VERSION_ENABLED, "Build with RDK versioning support" OFF)

if(RDK_VERSION_ENABLED)
   target_link_libraries(xr-voice-sdk rdkversion)
   target_compile_definitions(xr-voice-sdk PUBLIC VSDK_RDK_VERSION)
endif()
```

### RDK Version Integration
```c
#ifdef VSDK_RDK_VERSION
#include "rdkversion.h"

// RDK version information integration
rdk_version_info_t info;
if(0 == rdk_version_parse_version(&info)) {
   // Process RDK platform version information
   // Integrate with SDK version reporting
   rdk_version_object_free(&info);
}
#endif
```

## Library Version Management

### Shared Library Versioning
The build system configures proper shared library versioning:

```cmake
set_target_properties(xr-voice-sdk PROPERTIES
    SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}  # ABI compatibility version
    VERSION   ${CMAKE_PROJECT_VERSION}        # Full semantic version
)
```

### Version Compatibility Strategy
- **SOVERSION**: Major version number for ABI compatibility
  - Incremented when ABI breaking changes occur
  - Ensures runtime compatibility checking
  
- **VERSION**: Full semantic version (major.minor.patch)
  - Complete version identification
  - Supports detailed compatibility analysis

### Vendor Logging Library Versioning
When vendor logging is enabled, a separate library maintains independent versioning:

```cmake
# src/xr-logger/CMakeLists.txt  
project(xr-voice-sdk-xlog VERSION ${CMAKE_PROJECT_VERSION})

set_target_properties(xr-voice-sdk-xlog PROPERTIES
    SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
    VERSION   ${CMAKE_PROJECT_VERSION}
)
```

## Version Usage Patterns

### Application Integration Example
```c
#include <xr_voice_sdk.h>

void print_sdk_version() {
    vsdk_version_info_t versions[VSDK_VERSION_QTY_MAX];
    uint32_t count = VSDK_VERSION_QTY_MAX;
    
    vsdk_version(versions, &count);
    
    for(uint32_t i = 0; i < count; i++) {
        printf("Component: %s\n", versions[i].name);
        printf("Version: %s\n", versions[i].version);
        printf("Branch: %s\n", versions[i].branch);
        printf("Commit: %s\n", versions[i].commit_id);
        printf("---\n");
    }
}
```

### Version Compatibility Checking
```c
bool check_sdk_compatibility(const char *required_version) {
    vsdk_version_info_t versions[VSDK_VERSION_QTY_MAX];
    uint32_t count = VSDK_VERSION_QTY_MAX;
    
    vsdk_version(versions, &count);
    
    for(uint32_t i = 0; i < count; i++) {
        if(strcmp(versions[i].name, "xr-voice-sdk") == 0) {
            return version_compare(versions[i].version, required_version) >= 0;
        }
    }
    return false;
}
```

### Development Build Detection
```c
bool is_development_build() {
    vsdk_version_info_t versions[VSDK_VERSION_QTY_MAX];
    uint32_t count = VSDK_VERSION_QTY_MAX;
    
    vsdk_version(versions, &count);
    
    // Check for "++" suffix indicating uncommitted changes
    return strstr(versions[0].version, "++") != NULL;
}
```

## Version Information Lifecycle

### Build-Time Generation
1. **CMake Configuration**: Sets `CMAKE_PROJECT_VERSION` from project definition
2. **Git Information Extraction**: Queries current Git state for branch and commit
3. **Version Header Generation**: Creates `vsdk_version.h` with version constants
4. **Compilation Integration**: Includes version information in binary

### Runtime Access
1. **API Invocation**: Application calls `vsdk_version()`
2. **Structure Population**: SDK populates version information structures
3. **Information Retrieval**: Application accesses version data for logging/display

### Deployment Tracking
1. **Release Identification**: Version strings identify specific releases
2. **Source Correlation**: Commit hashes enable source code correlation  
3. **Deployment Verification**: Applications verify expected SDK versions
4. **Support Analysis**: Version information aids in debugging and support

## Version Management Best Practices

### Development Workflow
1. **Clean Builds**: Ensure no uncommitted changes for release builds
2. **Version Tagging**: Tag Git commits for official releases
3. **Branch Management**: Use descriptive branch names for context
4. **Change Documentation**: Maintain changelogs correlating with version increments

### Deployment Considerations
1. **Version Verification**: Always check SDK version during application startup
2. **Compatibility Testing**: Test against minimum required SDK versions
3. **Upgrade Planning**: Use version information for upgrade path planning
4. **Support Information**: Include version data in support and diagnostic logs

### Build System Integration
1. **Automated Generation**: Leverage automated version generation for consistency
2. **CI/CD Integration**: Ensure build systems populate version information correctly
3. **Release Processes**: Validate version information during release procedures
4. **Distribution Packaging**: Include version metadata in distribution packages

## Troubleshooting Version Issues

### Common Version Problems

#### Missing Version Information
```bash
# Check if version header was generated
ls -la build/src/vsdk_version.h

# Verify Git information availability
git status
git log --oneline -n 5
```

#### Incorrect Version Generation
```bash
# Regenerate version information
rm build/src/vsdk_version.h
make vsdk_version.h

# Check generated content  
cat build/src/vsdk_version.h
```

#### Runtime Version Mismatches
```c
// Debug version information at runtime
vsdk_version_info_t versions[VSDK_VERSION_QTY_MAX];
uint32_t count = VSDK_VERSION_QTY_MAX;
vsdk_version(versions, &count);

// Log detailed version information for debugging
for(uint32_t i = 0; i < count; i++) {
    log_debug("Component %s: version=%s, branch=%s, commit=%s",
              versions[i].name, versions[i].version,
              versions[i].branch, versions[i].commit_id);
}
```

## Cross-Platform Version Considerations

### Git Availability Requirements
- **Build Environment**: Git must be available during build process
- **Source Distribution**: Alternative versioning for Git-free builds
- **Cross-Compilation**: Git operations must work in cross-compilation environment

### Platform-Specific Integration
- **RDK Platforms**: Optional RDK versioning integration
- **Embedded Systems**: Consider version information size in resource-constrained environments
- **Development vs Production**: Different version detail requirements

## Future Versioning Enhancements

### Extensibility Considerations
- **Component Registration**: Framework for individual component version registration
- **Version History**: Tracking version evolution and compatibility matrices
- **API Versioning**: Interface version tracking for ABI compatibility management
- **Plugin Versioning**: Version management for dynamically loaded plugins

### Integration Opportunities
- **Build Metadata**: Extended build information (compiler, host, build flags)
- **Distribution Information**: Package version and distribution channel tracking
- **Runtime Telemetry**: Version information in usage analytics and crash reports

## Summary

The XR Voice SDK versioning system provides:

- **Comprehensive Tracking**: Git-integrated version information with commit-level precision
- **Automated Generation**: Build-time version information creation without manual maintenance
- **Component Granularity**: Support for individual component version management
- **Platform Integration**: Optional integration with platform-specific versioning systems
- **Runtime Access**: Public API for application version verification and logging
- **Development Support**: Clear distinction between release and development builds
- **Compatibility Management**: ABI versioning for shared library compatibility
- **Traceability**: Complete source-to-binary correlation for debugging and support

This versioning architecture ensures reliable version management across the entire SDK lifecycle from development through deployment and support.