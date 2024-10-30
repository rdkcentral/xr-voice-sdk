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
#include "xr_sm_engine.h"

//-------------------------------------------------------------------------------
// State Events
//-------------------------------------------------------------------------------
#define SM_EVENT_SESSION_BEGIN            (0)
#define SM_EVENT_SESSION_BEGIN_STM        (1)
#define SM_EVENT_DISCONNECTED             (2)
#define SM_EVENT_STM                      (3)
#define SM_EVENT_EOS                      (4)
#define SM_EVENT_TERMINATE                (5)
#define SM_EVENT_TIMEOUT                  (6)
#define SM_EVENT_CONNECTED                (7)
#define SM_EVENT_MSG_RECV                 (8)
#define SM_EVENT_PIPE_EOS                 (9)
#define SM_EVENT_TEXT_SESSION_SUCCESS     (10)

//-------------------------------------------------------------------------------
// States
//-------------------------------------------------------------------------------

STATE_DECLARE( St_Http_Disconnected );
STATE_DECLARE( St_Http_Buffering );
STATE_DECLARE( St_Http_Connecting );
STATE_DECLARE( St_Http_Connected );
STATE_DECLARE( St_Http_Streaming );
STATE_DECLARE( St_Http_TextOnlySession );

// St_Http_Disconnected State Description ----------------------------------------------------------------
tStateGuard St_Http_Disconnected_NextStates[] = 
{
    { SM_EVENT_SESSION_BEGIN, &St_Http_Connecting_Info },
    { SM_EVENT_SESSION_BEGIN_STM, &St_Http_Buffering_Info }
};

tStateInfo St_Http_Disconnected_Info = 
{
    SHOW_ST_NAME( "St_Http_Disconnected" )
    St_Http_Disconnected,
    ARRAY_COUNT( St_Http_Disconnected_NextStates ),
    St_Http_Disconnected_NextStates,
    0,
    NULL
};

// St_Http_Buffering State Description ----------------------------------------------------------------
tStateGuard St_Http_Buffering_NextStates[] = 
{
    { SM_EVENT_EOS, &St_Http_Disconnected_Info },
    { SM_EVENT_TERMINATE, &St_Http_Disconnected_Info },
    { SM_EVENT_STM, &St_Http_Connecting_Info }
};

tStateInfo St_Http_Buffering_Info = 
{
    SHOW_ST_NAME( "St_Http_Buffering" )
    St_Http_Buffering,
    ARRAY_COUNT( St_Http_Buffering_NextStates ),
    St_Http_Buffering_NextStates,
    0,
    NULL
};

// St_Http_Connecting State Description ----------------------------------------------------------------
tStateGuard St_Http_Connecting_NextStates[] = 
{
    { SM_EVENT_DISCONNECTED, &St_Http_Disconnected_Info },
    { SM_EVENT_CONNECTED, &St_Http_Streaming_Info }
};

tStateInfo St_Http_Connecting_Info = 
{
    SHOW_ST_NAME( "St_Http_Connecting" )
    St_Http_Connecting,
    ARRAY_COUNT( St_Http_Connecting_NextStates ),
    St_Http_Connecting_NextStates,
    0,
    NULL
};

// St_Http_Connected State Description ----------------------------------------------------------------
tStateGuard St_Http_Connected_NextStates[] = 
{
    { SM_EVENT_MSG_RECV,  &St_Http_Disconnected_Info },
    { SM_EVENT_TERMINATE, &St_Http_Disconnected_Info },
    { SM_EVENT_TIMEOUT, &St_Http_Disconnected_Info }
};

tStateInfo St_Http_Connected_Info = 
{
    SHOW_ST_NAME( "St_Http_Connected" )
    St_Http_Connected,
    ARRAY_COUNT( St_Http_Connected_NextStates ),
    St_Http_Connected_NextStates,
    0,
    NULL
};

// St_Http_Streaming State Description ----------------------------------------------------------------
tStateGuard St_Http_Streaming_NextStates[] = 
{
    { SM_EVENT_PIPE_EOS, &St_Http_Connected_Info },
    { SM_EVENT_TERMINATE, &St_Http_Disconnected_Info },
    { SM_EVENT_MSG_RECV, &St_Http_Disconnected_Info },
    { SM_EVENT_TEXT_SESSION_SUCCESS, &St_Http_TextOnlySession_Info }
};

tStateInfo St_Http_Streaming_Info = 
{
    SHOW_ST_NAME( "St_Http_Streaming" )
    St_Http_Streaming,
    ARRAY_COUNT( St_Http_Streaming_NextStates ),
    St_Http_Streaming_NextStates,
    0,
    NULL
};

// St_Http_TextOnlySession State Description ----------------------------------------------------------------
tStateGuard St_Http_TextOnlySession_NextStates[] = 
{
    { SM_EVENT_PIPE_EOS, &St_Http_Connected_Info },
    { SM_EVENT_TERMINATE, &St_Http_Disconnected_Info },
    { SM_EVENT_MSG_RECV, &St_Http_Disconnected_Info }
};

tStateInfo St_Http_TextOnlySession_Info = 
{
    SHOW_ST_NAME( "St_Http_TextOnlySession" )
    St_Http_TextOnlySession,
    ARRAY_COUNT( St_Http_TextOnlySession_NextStates ),
    St_Http_TextOnlySession_NextStates,
    0,
    NULL
};
