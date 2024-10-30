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
#define SM_EVENT_SOS                      (4)
#define SM_EVENT_EOS                      (5)
#define SM_EVENT_TERMINATE                (6)
#define SM_EVENT_XRSR_ERROR               (7)
#define SM_EVENT_TIMEOUT                  (8)
#define SM_EVENT_CONNECTED                (9)
#define SM_EVENT_RETRY                    (10)
#define SM_EVENT_ESTABLISHED              (11)
#define SM_EVENT_WS_CLOSE                 (12)
#define SM_EVENT_CONNECT_TIMEOUT          (13)
#define SM_EVENT_MSG_RECV                 (14)
#define SM_EVENT_APP_CLOSE                (15)
#define SM_EVENT_EOS_PIPE                 (16)
#define SM_EVENT_WS_ERROR                 (17)
#define SM_EVENT_AUDIO_ERROR              (18)
#define SM_EVENT_ESTABLISH_TIMEOUT        (19)
#define SM_EVENT_TEXT_SESSION_SUCCESS     (20)

//-------------------------------------------------------------------------------
// States
//-------------------------------------------------------------------------------

STATE_DECLARE( St_Ws_Disconnected );
STATE_DECLARE( St_Ws_Disconnecting );
STATE_DECLARE( St_Ws_Buffering );
STATE_DECLARE( St_Ws_Connecting );
STATE_DECLARE( St_Ws_Connected );
STATE_DECLARE( St_Ws_Connection_Retry );
STATE_DECLARE( St_Ws_Established );
STATE_DECLARE( St_Ws_Streaming );
STATE_DECLARE( St_Ws_TextOnlySession );

// St_Ws_Disconnected State Description ----------------------------------------------------------------
tStateGuard St_Ws_Disconnected_NextStates[] = 
{
    { SM_EVENT_TERMINATE,         &St_Ws_Disconnected_Info },
    { SM_EVENT_SESSION_BEGIN,     &St_Ws_Connecting_Info },
    { SM_EVENT_SESSION_BEGIN_STM, &St_Ws_Buffering_Info }
};

tStateInfo St_Ws_Disconnected_Info = 
{
    SHOW_ST_NAME( "St_Ws_Disconnected" )
    St_Ws_Disconnected,
    ARRAY_COUNT( St_Ws_Disconnected_NextStates ),
    St_Ws_Disconnected_NextStates,
    0,
    NULL
};

// St_Ws_Disconnecting State Description ----------------------------------------------------------------
tStateGuard St_Ws_Disconnecting_NextStates[] = 
{
    { SM_EVENT_TERMINATE,    &St_Ws_Disconnected_Info },
    { SM_EVENT_DISCONNECTED, &St_Ws_Disconnected_Info }
};

tStateInfo St_Ws_Disconnecting_Info = 
{
    SHOW_ST_NAME( "St_Ws_Disconnecting" )
    St_Ws_Disconnecting,
    ARRAY_COUNT( St_Ws_Disconnecting_NextStates ),
    St_Ws_Disconnecting_NextStates,
    0,
    NULL
};

// St_Ws_Buffering State Description ----------------------------------------------------------------
tStateGuard St_Ws_Buffering_NextStates[] = 
{
    { SM_EVENT_EOS,       &St_Ws_Disconnected_Info },
    { SM_EVENT_TERMINATE, &St_Ws_Disconnected_Info },
    { SM_EVENT_STM,       &St_Ws_Connecting_Info }
};

tStateInfo St_Ws_Buffering_Info = 
{
    SHOW_ST_NAME( "St_Ws_Buffering" )
    St_Ws_Buffering,
    ARRAY_COUNT( St_Ws_Buffering_NextStates ),
    St_Ws_Buffering_NextStates,
    0,
    NULL
};

// St_Ws_Connecting State Description ----------------------------------------------------------------
tStateGuard St_Ws_Connecting_NextStates[] = 
{
    { SM_EVENT_CONNECT_TIMEOUT, &St_Ws_Disconnected_Info },
    { SM_EVENT_TERMINATE,       &St_Ws_Disconnected_Info },
    { SM_EVENT_XRSR_ERROR,      &St_Ws_Disconnected_Info },
    { SM_EVENT_TIMEOUT,         &St_Ws_Connecting_Info },
    { SM_EVENT_RETRY,           &St_Ws_Connection_Retry_Info },
    { SM_EVENT_CONNECTED,       &St_Ws_Connected_Info }
};

tStateInfo St_Ws_Connecting_Info = 
{
    SHOW_ST_NAME( "St_Ws_Connecting" )
    St_Ws_Connecting,
    ARRAY_COUNT( St_Ws_Connecting_NextStates ),
    St_Ws_Connecting_NextStates,
    0,
    NULL
};

// St_Ws_Connected State Description ----------------------------------------------------------------
tStateGuard St_Ws_Connected_NextStates[] = 
{
    { SM_EVENT_ESTABLISH_TIMEOUT, &St_Ws_Disconnecting_Info },
    { SM_EVENT_TERMINATE,         &St_Ws_Disconnecting_Info },
    { SM_EVENT_WS_CLOSE,          &St_Ws_Disconnected_Info },
    { SM_EVENT_TIMEOUT,           &St_Ws_Connected_Info },
    { SM_EVENT_ESTABLISHED,       &St_Ws_Streaming_Info }
};

tStateInfo St_Ws_Connected_Info = 
{
    SHOW_ST_NAME( "St_Ws_Connected" )
    St_Ws_Connected,
    ARRAY_COUNT( St_Ws_Connected_NextStates ),
    St_Ws_Connected_NextStates,
    0,
    NULL
};

// St_Ws_Established State Description ----------------------------------------------------------------
tStateGuard St_Ws_Established_NextStates[] = 
{
    { SM_EVENT_APP_CLOSE, &St_Ws_Disconnecting_Info },
    { SM_EVENT_TERMINATE, &St_Ws_Disconnecting_Info },
    { SM_EVENT_TIMEOUT,   &St_Ws_Disconnecting_Info },
    { SM_EVENT_MSG_RECV,  &St_Ws_Established_Info },
    { SM_EVENT_EOS,       &St_Ws_Established_Info },
    { SM_EVENT_EOS_PIPE,  &St_Ws_Established_Info },
    { SM_EVENT_SOS,       &St_Ws_Streaming_Info },
    { SM_EVENT_WS_CLOSE,  &St_Ws_Disconnected_Info }
};

tStateInfo St_Ws_Established_Info = 
{
    SHOW_ST_NAME( "St_Ws_Established" )
    St_Ws_Established,
    ARRAY_COUNT( St_Ws_Established_NextStates ),
    St_Ws_Established_NextStates,
    0,
    NULL
};

// St_Ws_Streaming State Description ----------------------------------------------------------------
tStateGuard St_Ws_Streaming_NextStates[] = 
{
    { SM_EVENT_MSG_RECV,             &St_Ws_Streaming_Info },
    { SM_EVENT_EOS,                  &St_Ws_Streaming_Info },
    { SM_EVENT_EOS_PIPE,             &St_Ws_Established_Info },
    { SM_EVENT_TERMINATE,            &St_Ws_Disconnecting_Info },
    { SM_EVENT_WS_ERROR,             &St_Ws_Disconnecting_Info },
    { SM_EVENT_WS_CLOSE,             &St_Ws_Disconnected_Info },
    { SM_EVENT_AUDIO_ERROR,          &St_Ws_Established_Info },
    { SM_EVENT_TEXT_SESSION_SUCCESS, &St_Ws_TextOnlySession_Info },
    { SM_EVENT_STM,                  &St_Ws_Streaming_Info }
};

tStateInfo St_Ws_Streaming_Info = 
{
    SHOW_ST_NAME( "St_Ws_Streaming" )
    St_Ws_Streaming,
    ARRAY_COUNT( St_Ws_Streaming_NextStates ),
    St_Ws_Streaming_NextStates,
    0,
    NULL
};

// St_Ws_TextOnlySession State Description ----------------------------------------------------------------
tStateGuard St_Ws_TextOnlySession_NextStates[] = 
{
    { SM_EVENT_EOS_PIPE,    &St_Ws_Established_Info },
    { SM_EVENT_TERMINATE,   &St_Ws_Disconnecting_Info },
    { SM_EVENT_WS_ERROR,    &St_Ws_Disconnecting_Info },
    { SM_EVENT_WS_CLOSE,    &St_Ws_Disconnected_Info },
    { SM_EVENT_AUDIO_ERROR, &St_Ws_Established_Info }
};

tStateInfo St_Ws_TextOnlySession_Info = 
{
    SHOW_ST_NAME( "St_Ws_TextOnlySession" )
    St_Ws_TextOnlySession,
    ARRAY_COUNT( St_Ws_TextOnlySession_NextStates ),
    St_Ws_TextOnlySession_NextStates,
    0,
    NULL
};

// St_Ws_Connection_Retry State Description ----------------------------------------------------------------
tStateGuard St_Ws_Connection_Retry_NextStates[] = 
{
    { SM_EVENT_TERMINATE, &St_Ws_Disconnected_Info },
    { SM_EVENT_TIMEOUT,   &St_Ws_Connecting_Info }
};

tStateInfo St_Ws_Connection_Retry_Info = 
{
    SHOW_ST_NAME( "St_Ws_Connection_Retry" )
    St_Ws_Connection_Retry,
    ARRAY_COUNT( St_Ws_Connection_Retry_NextStates ),
    St_Ws_Connection_Retry_NextStates,
    0,
    NULL
};
