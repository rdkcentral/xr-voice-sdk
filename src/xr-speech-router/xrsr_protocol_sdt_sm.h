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
#define SM_EVENT_XRSR_ERROR               (6)
#define SM_EVENT_TIMEOUT                  (7)
#define SM_EVENT_CONNECTED                (8)
#define SM_EVENT_RETRY                    (9)
#define SM_EVENT_ESTABLISHED              (10)
#define SM_EVENT_WS_CLOSE                 (11)
#define SM_EVENT_CONNECT_TIMEOUT          (12)
#define SM_EVENT_MSG_RECV                 (13)
#define SM_EVENT_APP_CLOSE                (14)
#define SM_EVENT_EOS_PIPE                 (15)
#define SM_EVENT_WS_ERROR                 (16)
#define SM_EVENT_AUDIO_ERROR              (17)
#define SM_EVENT_ESTABLISH_TIMEOUT        (18)

//-------------------------------------------------------------------------------
// States
//-------------------------------------------------------------------------------

STATE_DECLARE( St_Sdt_Disconnected );
STATE_DECLARE( St_Sdt_Disconnecting );
STATE_DECLARE( St_Sdt_Buffering );
STATE_DECLARE( St_Sdt_Connecting );
STATE_DECLARE( St_Sdt_Connected );
STATE_DECLARE( St_Sdt_Connection_Retry );
STATE_DECLARE( St_Sdt_Established );
STATE_DECLARE( St_Sdt_Streaming );

// St_Ws_Disconnected State Description ----------------------------------------------------------------
tStateGuard St_Sdt_Disconnected_NextStates[] = 
{
    { SM_EVENT_SESSION_BEGIN, &St_Sdt_Connecting_Info },
    { SM_EVENT_SESSION_BEGIN_STM, &St_Sdt_Buffering_Info }
};

tStateInfo St_Sdt_Disconnected_Info = 
{
    SHOW_ST_NAME( "St_Sdt_Disconnected" )
    St_Sdt_Disconnected,
    ARRAY_COUNT( St_Sdt_Disconnected_NextStates ),
    St_Sdt_Disconnected_NextStates,
    0,
    NULL
};

// St_Ws_Disconnecting State Description ----------------------------------------------------------------
tStateGuard St_Sdt_Disconnecting_NextStates[] = 
{
    { SM_EVENT_DISCONNECTED, &St_Sdt_Disconnected_Info }
};

tStateInfo St_Sdt_Disconnecting_Info = 
{
    SHOW_ST_NAME( "St_Sdt_Disconnecting" )
    St_Sdt_Disconnecting,
    ARRAY_COUNT( St_Sdt_Disconnecting_NextStates ),
    St_Sdt_Disconnecting_NextStates,
    0,
    NULL
};

// St_Ws_Buffering State Description ----------------------------------------------------------------
tStateGuard St_Sdt_Buffering_NextStates[] = 
{
    { SM_EVENT_EOS, &St_Sdt_Disconnected_Info },
    { SM_EVENT_TERMINATE, &St_Sdt_Disconnected_Info },
    { SM_EVENT_STM, &St_Sdt_Connecting_Info }
};

tStateInfo St_Sdt_Buffering_Info = 
{
    SHOW_ST_NAME( "St_Sdt_Buffering" )
    St_Sdt_Buffering,
    ARRAY_COUNT( St_Sdt_Buffering_NextStates ),
    St_Sdt_Buffering_NextStates,
    0,
    NULL
};


tStateGuard St_Sdt_Connecting_NextStates[] =
{
    { SM_EVENT_CONNECT_TIMEOUT, &St_Sdt_Disconnected_Info },
    { SM_EVENT_TERMINATE, &St_Sdt_Disconnected_Info },
    { SM_EVENT_XRSR_ERROR, &St_Sdt_Disconnected_Info },
    { SM_EVENT_TIMEOUT, &St_Sdt_Connecting_Info },
    { SM_EVENT_RETRY, &St_Sdt_Connection_Retry_Info },
    { SM_EVENT_CONNECTED, &St_Sdt_Connected_Info }
};

tStateInfo St_Sdt_Connecting_Info =
{
    SHOW_ST_NAME( "St_Sdt_Connecting" )
    St_Sdt_Connecting,
    ARRAY_COUNT( St_Sdt_Connecting_NextStates ),
    St_Sdt_Connecting_NextStates,
    0,
    NULL
};


// St_Ws_Connected State Description ----------------------------------------------------------------
tStateGuard St_Sdt_Connected_NextStates[] = 
{
    { SM_EVENT_ESTABLISH_TIMEOUT, &St_Sdt_Disconnecting_Info },
    { SM_EVENT_TERMINATE, &St_Sdt_Disconnecting_Info },
    { SM_EVENT_WS_CLOSE, &St_Sdt_Disconnected_Info },
    { SM_EVENT_TIMEOUT, &St_Sdt_Connected_Info },
    { SM_EVENT_ESTABLISHED, &St_Sdt_Streaming_Info }
};

tStateInfo St_Sdt_Connected_Info = 
{
    SHOW_ST_NAME( "St_Sdt_Connected" )
    St_Sdt_Connected,
    ARRAY_COUNT( St_Sdt_Connected_NextStates ),
    St_Sdt_Connected_NextStates,
    0,
    NULL
};

// St_Ws_Established State Description ----------------------------------------------------------------
tStateGuard St_Sdt_Established_NextStates[] = 
{
    { SM_EVENT_APP_CLOSE, &St_Sdt_Disconnecting_Info },
    { SM_EVENT_TERMINATE, &St_Sdt_Disconnecting_Info },
    { SM_EVENT_EOS, &St_Sdt_Disconnecting_Info },
    { SM_EVENT_MSG_RECV, &St_Sdt_Established_Info },
    { SM_EVENT_WS_CLOSE, &St_Sdt_Disconnected_Info }
};

tStateInfo St_Sdt_Established_Info = 
{
    SHOW_ST_NAME( "St_Sdt_Established" )
    St_Sdt_Established,
    ARRAY_COUNT( St_Sdt_Established_NextStates ),
    St_Sdt_Established_NextStates,
    0,
    NULL
};

// St_Sdt_Streaming State Description ----------------------------------------------------------------
tStateGuard St_Sdt_Streaming_NextStates[] = 
{
    { SM_EVENT_EOS_PIPE, &St_Sdt_Established_Info },
    { SM_EVENT_TERMINATE, &St_Sdt_Disconnecting_Info },
    { SM_EVENT_WS_ERROR, &St_Sdt_Disconnecting_Info },
    { SM_EVENT_WS_CLOSE, &St_Sdt_Disconnected_Info },
    { SM_EVENT_AUDIO_ERROR, &St_Sdt_Established_Info }
};

tStateInfo St_Sdt_Streaming_Info = 
{
    SHOW_ST_NAME( "St_Sdt_Streaming" )
    St_Sdt_Streaming,
    ARRAY_COUNT( St_Sdt_Streaming_NextStates ),
    St_Sdt_Streaming_NextStates,
    0,
    NULL
};

