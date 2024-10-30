/*
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
*/
#ifndef __XR_VOICE_SDK__
#define __XR_VOICE_SDK__

#include <xrsr.h>
#include <xrsv.h>

#ifndef XLOG_MODULE_ID
#define XLOG_MODULE_ID (XLOG_MODULE_ID_VSDK)
#endif

#include <rdkx_logger.h>

/// @file xr_voice_sdk.h
///
/// @defgroup VSDK VOICE SDK
/// @{
///
/// @defgroup VSDK_DEFINITIONS Definitions
/// @defgroup VSDK_STRUCTS     Structures
/// @defgroup VSDK_FUNCTIONS   Functions
///

/// @addtogroup VSDK_DEFINITIONS
/// @{
/// @brief Macros for constant values
/// @details The voice SDK provides macros for some parameters which may change in the future.  User applications should use
/// these names to allow the application code to function correctly if the values change.

#define VSDK_VERSION_QTY_MAX (2 + XRSR_VERSION_QTY_MAX) ///< The quantity of version information structures.

/// @}

/// @addtogroup VSDK_STRUCTS
/// @{
/// @brief Structures
/// @details The voice SDK provides structures for grouping of values.

/// @brief VSDK version information structure
/// @details The version information data structure returned by the vsdk_version() api.
typedef struct {
   const char *name;      ///< component's name
   const char *version;   ///< component's version
   const char *branch;    ///< component's branch name
   const char *commit_id; ///< component's commit identifier
} vsdk_version_info_t;

/// @}

/// @brief VSDK thread poll handler
/// @details Callback function prototype for polling VSDK threads.
/// @return The function has no return value.
typedef void (*vsdk_thread_poll_func_t)(void *data);

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup VSDK_FUNCTIONS
/// @{
/// @brief Function definitions
/// @details The voice SDK provides functions to be called directly by the user application.

/// @brief Retrieve the XRSR version
/// @details Retrieves the detailed version information for the voice SDK components.
/// @param[in]    version_info Pointer to an array of version information structures
/// @param[inout] qty          Quantity of entries in the version_info array (in), quantity used (out)
/// @return The function has no return value.
void vsdk_version(vsdk_version_info_t *version_info, uint32_t *qty);

/// @brief Initialize the voice SDK
/// @details Initializes the voice SDK component.
/// @return The function returns 0 for success.  All other values indicate a failure.
int  vsdk_init(void);

/// @brief Initialize the voice SDK
/// @details Initializes the voice SDK component with external logging functions.
/// @param[in] print      Pointer to a print function
/// @param[in] print_safe Pointer to a print function which is safe to use in a signal handler
/// @return The function returns 0 for success.  All other values indicate a failure.
int  vsdk_init_user_print(xlog_print_t print, xlog_print_t print_safe);

/// @brief Terminates the voice SDK
/// @details Terminates the voice SDK components and frees all associated resources.
/// @return The function has no return value.
void vsdk_term(void);

/// @brief Get a log level
/// @details Retrieves the log level associated with the specified module id.
/// @param[in] id Module id of the component to retrieve the log level
/// @return The function returns the log level.
xlog_level_t vsdk_log_level_get(xlog_module_id_t id);

/// @brief Set a log level
/// @details Sets the log level associated with the specified module id.
/// @param[in] id    Module id of the component to set the log level
/// @param[in] level Log level to set for the module
/// @return The function has no return value.
void         vsdk_log_level_set(xlog_module_id_t id, xlog_level_t level);

/// @brief Set a log level for all components
/// @details Sets the log level for all module id's.
/// @param[in] level Log level to set for all modules
/// @return The function has no return value.
void         vsdk_log_level_set_all(xlog_level_t level);

/// @brief Polls the VSDK threads
/// @details Polls VSDK threads to determine if they are responsive.
/// @param[in] func Function to call if all threads are responsive.
/// @param[in] data Parameter to pass to the callback function.
/// @return The function has no return value.
void         vsdk_thread_poll(vsdk_thread_poll_func_t func, void *data);

/// @}

#ifdef __cplusplus
}
#endif

/// @}

#endif
