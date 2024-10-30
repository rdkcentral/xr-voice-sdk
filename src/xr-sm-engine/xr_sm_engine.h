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

 File: xr_sm_engine.h
 Descripton:
 This file contains the types and defintions for the State Machine Engine.
 The entry point (function pointer) to the state is called at different
 times for the various actions ( eStateAction ).
 
 The state entry is called with the ACT_GUARD when the current state wants to call a possible
 new/next state to see if it is possible to transition to the new state.  The transition will only
 happen if the new state returns TRUE in the bGuardResponse.  So when we are at state A and
 a new event comes in, the SM Engine will walk through all the next states listed in mpNextStates.
 The first thing that is done is to compare the new event to the event list in the tStateGuard
 structure to see if they match.  If they do not then the SM Engine moves to the next
 state in the list until it finds a match.  When it finds a match then the state is called
 to check the guard value.
 Author: Jon Norenberg
 */
 
#ifndef XR_SM_ENGINE_H_
#define XR_SM_ENGINE_H_


//#include <xrpOs.h>
//#include <xrpDebug.h>

//#include <xrpTimer.h>


//-------------------------------------------------------------------------------
// RDK Adapter Defines
//-------------------------------------------------------------------------------
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define RDK
#define BOOL                             bool
#define TRUE                             true
#define FALSE                            false
#define UInt8                            uint8_t
#define ui8                              UInt8
#define UInt16                           uint16_t
#define ui16                             UInt16
#define ARRAY_COUNT( a )                 ( sizeof( a ) / sizeof( (a)[0] ) )
 
//-------------------------------------------------------------------------------
// Macros
//-------------------------------------------------------------------------------

// this adds state name ascii string to each state
// allows for state names to be printed when entering and exiting
// so to turn on names, the DBG_MODULE_SM_ENGINE must be enabled in xrpDebug.h
// AND the DBG_LEVEL_SM_ENGINE must be set to DBG_LEVEL_NOISE in xrpDebug.h
#if ( ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) ) || defined( RDK ) )
#define STATE_NAME                      char *mStateName;
#define SHOW_ST_NAME( sName )           sName,
#define ST_NAME                         ,pSM->pCurrState->mStateName   
#define NEXT_ST_NAME                    ,pNextStateInfo->mStateName
#else
#define STATE_NAME 
#define SHOW_ST_NAME( sName )                          
#define ST_NAME                                        
#define NEXT_ST_NAME                                        
#endif    

#if ( ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) ) || defined( RDK ) )
#define INSTANCE_NAME                   char *mInstanceName;
#define SHOW_INSTANCE_NAME( iName )     iName,
#define INST_NAME                       ,pSM->mInstanceName               
#else
#define INSTANCE_NAME 
#define SHOW_INSTANCE_NAME( iName )                          
#define INST_NAME                                        
#endif

//-------------------------------------------------------------------------------
// Typedefs
//-------------------------------------------------------------------------------

// Actions that can be sent to the state entry point
typedef enum
{
        // return true if it is ok to move to the new state
    ACT_GUARD = 0,
        // sent when the new state is entered, nothing returned
    ACT_ENTER,
        // sent when the state is being exited, nothing returned
    ACT_EXIT,
        // used to send an exit to the existing state
    ACT_INTERNAL
    
} eStateAction;

typedef ui16 tStEventID;
// this is the same size as the tKey, so we can pass around keys
//typedef ui16 tStEventData;
typedef void * tStEventData; // Changed for the RDK
typedef ui8 tStateCount;


// this is the thing that is pushed to the state machine to make it move states
typedef struct _StateEvent
{
    tStEventID          mID;
    tStEventData        mData;
} tStateEvent;


// Every state must have this entry point
typedef void ( *tStateEntryPoint )( tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardRespone );


// Structure that describes the next state list
typedef struct _StateGuard
{
    tStEventID          mID;
    void                *mStInfo;
} tStateGuard;

typedef struct _StateInfo
{
        // allows state name to be printed during debug
    STATE_NAME
        // the function pointer for the state, usually St_xxxx
    tStateEntryPoint    mEntry;
    
        // POTENTIAL NEXT STATE 
    tStateCount         mNextStCount;
        // points to an array of possible next states for this state
    tStateGuard         *mpNextStates;    
        // DEFERRED EVENTS INFO
    tStateCount         mDeferEvtIDCount;
        // points to an array of possible deferred event ids that this state allows
    tStEventID          *mpDeferEvtIDs;
} tStateInfo;

typedef struct _SmQueueEvt
{
    UInt16          mQHead;
    UInt16          mQTail;
    UInt16          mQCount;
    UInt16          mQSize;
    tStateEvent     *mpQData;
} tSmQueueEvt;


typedef struct _SMInstance
{
    // allows state name to be printed during debug
    INSTANCE_NAME
    tStateInfo      *pCurrState;
    tSmQueueEvt     activeEvtQueue;
    tSmQueueEvt     deferredEvtQueue;
    BOOL            bInitFinished;
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
    UInt8           debugFlags;
#endif
} tSmInstance;


//-------------------------------------------------------------------------------
// Prototypes
//-------------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif
void SmInit( tSmInstance *pSM, tStateInfo *pInitialStateInfo );
void SmEnqueueEvent( tSmInstance *pSM, tStEventID evtID, tStEventData evtData );
BOOL SmInThisState( tSmInstance *pSM, tStateInfo *pInitialStateInfo );
void SmSetThisState( tSmInstance *pSM, tStateInfo *pInitialStateInfo );
void SmProcessEvents( tSmInstance *pSM );
#ifdef __cplusplus
}
#endif

#define STATE_DECLARE( _newState_ ) \
    void _newState_( tStateEvent *pEvent, eStateAction eAction, BOOL *bGuardRespone );  \
    tStateInfo _newState_##_Info;

#endif
