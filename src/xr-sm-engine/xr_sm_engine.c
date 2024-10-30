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

   File: xr_sm_engine.c
   Descripton:
   This file contains the State Machine Engine implementation.  The state machine (SM)
   has two queues, a active event and a deferred event queue.  The SM is
   driven by events that are enqueued into the active event queue using SMEnqueueEvent().
   An event contains an event id and then some event data.  The event data is passed
   to the next state if the event moves it to a new state.
   The state machine uses a state info structure to transition to a new state based
   on a enqueued event.  The state info structure contains the possible next states
   for each accepted event id.  The structure also contains a list of event ids that
   the state will allow to be deferred.  One example is when a state is "playing"
   a led blink sequence.  The state can decide if it wants to defer any key presses
   during that blink and then they will be handled later.
   So, at init we are at the idle state, a simple state change would be if the user
   moves the remote so that the accel will enqueue a SM_EVT_ACC_MOVEMENT event.  By
   enqueueing the event, the SM will be scheduled to run.  When it runs it will dequeue
   each event off the active queue and go through the next state event list.  If
   a match is found then that state's entry point is also part of that list.
   For example:
    tStateGuard ST_AccelBacklightOn_NextStates[] =
    {
    { SM_EVT_TMR_BL_OFF, St_Idle_Info },
    { SM_EVT_KEY_DWN, St_FirstKeyPress_Info },
    { SM_EVT_KEY_DWN, St_MicKeyPress_Info }
    };
   This list has the event id and then the next state function pointer.  So, the dequeued
   event is matched against the list.  If there is a match then the next state function is
   called with the Guard action, which asks the state if it wants to accept this event
   given the current state of the system (keys pressed, no keys pressed, ...).  If it accepts
   the event then the current state's entry point is called with the EXIT action.  This
   allows the current state to clean up anything is wants.  The new state's function is then
   called with the ENTER action which the state then returns a pointer to it's state info
   structure.  This is the pointer that keeps track of the current state of the SM.
   The new state's function is then called with the ENTER action.
   The SM can now exit unless there are deferred events to be processed.  If so then the same
   process happens as described above except that the events are dequeued off the deferred event
   queue.
   After event has been enqueued the client must call SmProcessEvents.
   Author: Jon Norenberg
   */

//#include <xrpOs.h>
//#include <xrpTimer.h>
//#include <xrpDebug.h>

#include "xr_sm_engine.h"

//-------------------------------------------------------------------------------
// Macros
//-------------------------------------------------------------------------------
#define DBG_MODULE_LEVEL  DBG_LEVEL_SM_ENGINE

//-------------------------------------------------------------------------------
// Typedefs
//-------------------------------------------------------------------------------


//-------------------------------------------------------------------------------
// Prototypes
//-------------------------------------------------------------------------------

void _SmEngine( void *unused );

//-------------------------------------------------------------------------------
// Globals
//-------------------------------------------------------------------------------

#ifdef RDK
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRSM
#include <rdkx_logger.h>
#endif

/*********************************************************************
 *
 * Set the initial state in our global.  State machine is ready to
 * rock and roll.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *  pInitialStateInfo - the start state for the state machine.
 *
 * Returns:
 *  none
 *
 *********************************************************************/
void SmInit( tSmInstance *pSM, tStateInfo *pInitialStateInfo )
{
    pSM->pCurrState = pInitialStateInfo;
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
        if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
        {
            DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_NOISE, "%s Init: %s" INST_NAME ST_NAME );
        }
#elif defined( RDK )
    XLOGD_INFO( "%s Init: %s" INST_NAME ST_NAME );
#endif

    pSM->activeEvtQueue.mQCount = 0;
    pSM->activeEvtQueue.mQHead = 0;
    pSM->activeEvtQueue.mQTail = 0;

    pSM->deferredEvtQueue.mQCount = 0;
    pSM->deferredEvtQueue.mQHead = 0;
    pSM->deferredEvtQueue.mQTail = 0;

    pSM->bInitFinished = TRUE;
}

/*********************************************************************
 *
 * Caller wants to know if we are in a certain state.  Compare the
 * state pointer passed in, to the state pointer kept by the SM.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *  pTestStateInfo - a pointer to the state of the state machine.
 *
 * Returns:
 *  TRUE, if we are currently in that state
 *  FALSE, if NOT in that state
 *
 *********************************************************************/
BOOL SmInThisState( tSmInstance *pSM, tStateInfo *pTestStateInfo )
{
    // compare the 2 pointers to determine if the SM is in that state
    return pSM->pCurrState == pTestStateInfo;
}

/*********************************************************************
 *
 * Caller wants to set a certain state.  Assign the passed in pointer
 * to the variable that keeps track of the SM current state.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *  pNewStateInfo - a pointer to the state of the state machine.
 *
 * Returns:
 *  none
 *
 *********************************************************************/
void SmSetThisState( tSmInstance *pSM, tStateInfo *pNewStateInfo )
{
    // force the SM to a certain state
    pSM->pCurrState = pNewStateInfo;
}

/*********************************************************************
 *
 * Simple full check for the queue.  Check the count against the size.
 *
 * Parameters:
 *  pEvQ, pointer to either the active or deferred queue
 *
 * Returns:
 *  TRUE, if the queue is full
 *  FALSE, if the queue is NOT full
 *
 *********************************************************************/
BOOL _SmQFull( tSmQueueEvt *pEvQ )
{
    return ( pEvQ->mQCount == pEvQ->mQSize ) ? TRUE : FALSE;
}

/*********************************************************************
 *
 * Simple empty check for the queue.
 *
 * Parameters:
 *  pEvQ, pointer to either the active or deferred queue
 *
 * Returns:
 *  TRUE, if the queue is empty
 *  FALSE, if the queue is NOT empty
 *
 *********************************************************************/
BOOL _SmQEmpty( tSmQueueEvt *pEvQ )
{
    return ( 0 == pEvQ->mQCount ) ? TRUE : FALSE;
}

/*********************************************************************
 *
 * This routine puts the event onto the queue/array.
 *
 * Parameters:
 *  pEvQ, pointer to either the active or deferred queue
 *  evtID, event to enqueue onto the queue
 *  evtData, data associated with the event
 *
 * Returns:
 *  none
 *
 *********************************************************************/
void _SmEnqueueEvent( tSmQueueEvt *pEvQ, tStEventID evtID, tStEventData evtData )
{
    if ( TRUE == _SmQFull( pEvQ ) )
    {   // this should never happen
        //DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_FATAL, "%s: event q is full!" INST_NAME );
        return;
    }

    // go to the next element in the array
    ++pEvQ->mQTail;
    ++pEvQ->mQCount;

    // valid tail: pEvQ->mQSize - 1, so wrap to 0
    if ( pEvQ->mQTail == pEvQ->mQSize )
    {
        pEvQ->mQTail = 0;
    }

    // save the event
    pEvQ->mpQData[ pEvQ->mQTail ].mID = evtID;
    pEvQ->mpQData[ pEvQ->mQTail ].mData = evtData;
}

void SmEnqueueEvent( tSmInstance *pSM, tStEventID evtID, tStEventData evtData )
{
    if ( FALSE == pSM->bInitFinished )
    {   // don't accept events until our init routine is called
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
        if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
        {
            DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_FATAL, "%s Enqueue: No init, tossing e: %d, c: %d " INST_NAME, evtID, pSM->activeEvtQueue.mQCount );
        }
#elif defined( RDK )
        XLOGD_FATAL( "%s Enqueue: No init, tossing e: %d, c: %d " INST_NAME, evtID, pSM->activeEvtQueue.mQCount );
#endif
        return;
    }

    _SmEnqueueEvent( &pSM->activeEvtQueue, evtID, evtData );
    //DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_INFO, "%s Enqueue: e: %d, c: %d " INST_NAME, evtID, gSmActEvtQueue.mQCount );
#ifdef RDK
    XLOGD_DEBUG( "%s Enqueue: e: %d, c: %d " INST_NAME, evtID, pSM->activeEvtQueue.mQCount );
#endif
}

void _SmEnqueueDeferredEvent( tSmInstance *pSM, tStEventID evtID, tStEventData evtData )
{
    _SmEnqueueEvent( &pSM->deferredEvtQueue, evtID, evtData );
    //DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_INFO, "%s DefQueue: e: %d, c: %d " INST_NAME, evtID, pSM->deferredEvtQueue.mQCount );
#ifdef RDK
    XLOGD_DEBUG( "%s DefQueue: e: %d, c: %d " INST_NAME, evtID, pSM->deferredEvtQueue.mQCount );
#endif
}

/*********************************************************************
 *
 * This routine returns an event if there is one on the queue.
 *
 * Parameters:
 *  pEvQ, pointer to queue data structure
 *  pNewEvent, place to put the dequeued event
 *
 * Returns:
 *  TRUE, if event was dequeued off the queue
 *  FALSE, if no event was found
 *
 *********************************************************************/
BOOL _SmDequeueEvent( tSmQueueEvt *pEvQ, tStateEvent *pNewEvent )
{
    if ( TRUE == _SmQEmpty( pEvQ ) )
    {
        return FALSE;
    }

    // move head to the next element in the array
    ++pEvQ->mQHead;
    --pEvQ->mQCount;

    // valid head: pEvQ->mQSize - 1, so wrap to 0
    if ( pEvQ->mQHead == pEvQ->mQSize )
    {
        pEvQ->mQHead = 0;
    }

    // copy the event out of the array
    *pNewEvent = pEvQ->mpQData[ pEvQ->mQHead ];

    return TRUE;
}

BOOL _SmDequeueActiveEvent( tSmInstance *pSM, tStateEvent *pActEvent )
{
    BOOL bGotEvent = _SmDequeueEvent( &pSM->activeEvtQueue, pActEvent );

    if ( TRUE == bGotEvent )
    {
        //DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_INFO, "SmDequeue, e: %d, c: %d ", pActEvent->mID, gSmActEvtQueue.mQCount );
#ifdef RDK
        XLOGD_DEBUG( "SmDequeue, e: %d, c: %d ", pActEvent->mID, pSM->activeEvtQueue.mQCount );
#endif
    }

    return bGotEvent;
}

BOOL _SmDequeueDeferredEvent( tSmInstance *pSM, tStateEvent *pDefEvent )
{
    BOOL bGotEvent = _SmDequeueEvent( &pSM->deferredEvtQueue, pDefEvent );

    if ( TRUE == bGotEvent )
    {
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
        if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
        {
            DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_INFO, "%s dq def event: e: %d, c: %d " INST_NAME, pDefEvent->mID, pSM->deferredEvtQueue.mQCount );
        }
#elif defined( RDK )
        XLOGD_DEBUG( "%s dq def event: e: %d, c: %d " INST_NAME, pDefEvent->mID, pSM->deferredEvtQueue.mQCount );
#endif
    }

    return bGotEvent;
}

/*********************************************************************
 *
 * This routine processes one event at a time.  This is the heart
 * of the state machine.  Match the new event to the current state's
 * event ids that allow the state to transition to a new state.  If
 * there is a match then call the the potential new states action guard
 * to see if the new state will accept this event.  If it
 * does then call the exit action of the current state and then
 * call the entry action of the new state.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *  pNewEvent - process this event
 *
 * Returns:
 *  TRUE, if we transitioned to a new state because of this event
 *  FALSE, event was not used by the current state
 *
 *********************************************************************/
BOOL _SmProcessEvent( tSmInstance *pSM, tStateEvent *pNewEvent )
{
    BOOL bEventUsed = FALSE;
    BOOL bStGuard;

    int nextStateCount, nextStateIdx;
    tStEventID nextStateEventID;
    tStateEntryPoint nextStateFunction;
    tStateInfo *pNextStateInfo;

    // from the current state, how many new/next states can we transition to
    nextStateCount = pSM->pCurrState->mNextStCount;

    // walk through each possible next state asking if it will accept this event
    for ( nextStateIdx = 0 ; nextStateIdx < nextStateCount ; ++nextStateIdx )
    {
        // what event does this next state need in order to make the transition
        nextStateEventID = pSM->pCurrState->mpNextStates[ nextStateIdx ].mID;

        if ( nextStateEventID == pNewEvent->mID )
        {   // found a next state that will accept this event
            // get the next state's info
            pNextStateInfo = ( tStateInfo * ) pSM->pCurrState->mpNextStates[ nextStateIdx ].mStInfo;

            // get the entry point to the possible next state
            nextStateFunction = pNextStateInfo->mEntry;

            // an event can be sent to the current state, don't call ACT_GUARD,
            // or ACT_EVENT, just ACT_INTERNAL
            if ( pSM->pCurrState == pNextStateInfo )
            {
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
                if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
                {
                    DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_NOISE, "%s internal: %s, e: %d, d: %d" INST_NAME ST_NAME, pNewEvent->mID, pNewEvent->mData );
                }
#elif defined( RDK )
                XLOGD_DEBUG( "%s internal: %s, e: %d, d: %p" INST_NAME ST_NAME, pNewEvent->mID, pNewEvent->mData );
#endif
                nextStateFunction( pNewEvent, ACT_INTERNAL, NULL );
                bEventUsed = TRUE;
                break;
            }
            else
            {   // normal case, try to send event to next state
                // the next state must check it's guard to see if the conditions are right for the transition
                // the state can ignore the newEvent since we aleady did a match on it
                nextStateFunction( pNewEvent, ACT_GUARD, &bStGuard );
                if ( TRUE == bStGuard )
                {   // this next state accepts the event and guard says yes
                    // tell the current state that we are leaving/exit
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
                    if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
                    {
                        DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_NOISE, "%s exit: %s, e: %d, d: %d" INST_NAME ST_NAME, pNewEvent->mID, pNewEvent->mData );
                    }
#elif defined( RDK )
                    XLOGD_DEBUG( "%s exit: %s, e: %d, d: %p" INST_NAME ST_NAME, pNewEvent->mID, pNewEvent->mData );
#endif

                    pSM->pCurrState->mEntry( pNewEvent, ACT_EXIT, NULL );

                    // we have now officially moved states
                    pSM->pCurrState = pNextStateInfo;

                    // send the enter action to the new state

#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
                    if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
                    {
                        DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_NOISE, "%s enter: %s, e: %d, d: %d" INST_NAME ST_NAME, pNewEvent->mID, pNewEvent->mData );
                    }
#elif defined( RDK )
                    XLOGD_DEBUG( "%s enter: %s, e: %d, d: %p" INST_NAME ST_NAME, pNewEvent->mID, pNewEvent->mData );
#endif

                    nextStateFunction( pNewEvent, ACT_ENTER, NULL );

                    // this event was consumed by this state
                    bEventUsed = TRUE;
                    break;
                }
                else
                {   // next state guard rejected the event
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
                    if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
                    {
                        DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_NOISE, "%s event rejected by: %s, e: %d, d: %d" INST_NAME NEXT_ST_NAME, pNewEvent->mID, pNewEvent->mData );                    
                    }
#elif defined( RDK )
                    XLOGD_DEBUG( "%s event rejected by: %s, e: %d, d: %p" INST_NAME NEXT_ST_NAME, pNewEvent->mID, pNewEvent->mData );
#endif
                }
            }
        }
    }

    return bEventUsed;
}

/*********************************************************************
 *
 * This event was not useable by the current state so now check
 * if the state will allow this event to be deferred.  If the state
 * has it in it's deferred event id list, then enqueue it onto the
 * deferred event queue.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *  pNewEvent, event that is trying to be deferred
 *
 * Returns:
 *  none
 *
 *********************************************************************/
void _SmDeferEvent( tSmInstance *pSM, tStateEvent *pNewEvent )
{
    BOOL bCanDefer = FALSE;
    tStateCount idx;

    // must check current state to see if it will accept the deferral
    for ( idx = 0 ; idx < pSM->pCurrState->mDeferEvtIDCount ; ++idx )
    {
        if ( pNewEvent->mID == pSM->pCurrState->mpDeferEvtIDs[ idx ] )
        {
            bCanDefer = TRUE;
            break;
        }
    }

    if ( TRUE == bCanDefer )
    {
        _SmEnqueueDeferredEvent( pSM, pNewEvent->mID, pNewEvent->mData );
    }
    else
    {
#if ( ( ( DGB_ENABLED_MODULES ) & DBG_MODULE_SM_ENGINE ) && ( DBG_LEVEL_SM_ENGINE >= DBG_MODULE_LEVEL ) )
        if ( DGB_ENABLED_SM_PRINT & pSM->debugFlags )
        {
            DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_FATAL, "%s event unused: e: %d, d: %d" INST_NAME, pNewEvent->mID, pNewEvent->mData );
            DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_NOISE, "%s state: %s" INST_NAME ST_NAME );
        }
#elif defined( RDK )
        XLOGD_ERROR( "%s state: %s event unused: e: %d, d: %p" INST_NAME ST_NAME, pNewEvent->mID, pNewEvent->mData );
#endif
    }
}

/*********************************************************************
 *
 * Walk/dequeue all the events off the active event queue and see if
 * the state machine will consume/use the event.  If the event
 * is not used then try to defer it.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *
 * Returns:
 *  TRUE, if the state changed
 *  FALSE, the state has NOT changed
 *
 *********************************************************************/
BOOL _SmProcessActiveEvents( tSmInstance *pSM )
{
    tStateEvent newEvent;
    int consumedEventCount = 0;
    BOOL bFoundEvent, bConsumedEvent;

    do
    {
        bFoundEvent = _SmDequeueActiveEvent( pSM, &newEvent );

        if ( bFoundEvent )
        {
            bConsumedEvent = _SmProcessEvent( pSM, &newEvent );

            if ( TRUE == bConsumedEvent )
            {
                //DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_INFO, "%s: consumed e: %d, c: %d", INST_NAME newEvent.mID, pSM->activeEvtQueue.mQCount );
#ifdef RDK
                XLOGD_DEBUG( "%s: consumed e: %d, c: %d" INST_NAME, newEvent.mID, pSM->activeEvtQueue.mQCount );
#endif
                ++consumedEventCount;
            }
            else
            {   // the current state could not use this event
                // check if the state will defer this event
                _SmDeferEvent( pSM, &newEvent );
            }
        }
    } while ( TRUE == bFoundEvent );

    return consumedEventCount ? TRUE : FALSE;
}

/*********************************************************************
 *
 * Walk/dequeue all the events off the deferred event queue and see if
 * the state machine will consume/use the event.  If the event
 * is not used then try to defer it.
 *
 * Must be careful to not get into an endless looped since we might
 * dequeue a deferred event and then the state machine rejects it so
 * we put it back on the deferred queue and try to dequeue it again.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *
 * Returns:
 *  none
 *
 *********************************************************************/
BOOL _SmProcessDeferredEvents( tSmInstance *pSM )
{
    tStateEvent newEvent;
    BOOL bFoundEvent, bConsumedEvent;
    int consumedEventCount = 0;

    int maxLoopCount = pSM->deferredEvtQueue.mQCount;
    int idx = 0;

    // we are only going through the deferred queue once, otherwise
    // we could get in a loop of rechecking the same deferred event
    do
    {
        bFoundEvent = _SmDequeueDeferredEvent( pSM, &newEvent );

        if ( bFoundEvent )
        {
            bConsumedEvent = _SmProcessEvent( pSM, &newEvent );

            if ( TRUE == bConsumedEvent )
            {
                ++consumedEventCount;
            }
            else
            {   // the current state could not use this event
                // check if the state will defer this event
                _SmDeferEvent( pSM, &newEvent );
            }

            ++idx;
        }
    } while ( ( TRUE == bFoundEvent ) && ( idx < maxLoopCount ) );

    return consumedEventCount ? TRUE : FALSE;
}

/*********************************************************************
 *
 * This routine is scheduled every time an event is enqueued.  When it
 * runs it will process all the active events and then try to
 * process any deferred events.
 *
 * Parameters:
 *  pSM - pointer to state machine instance
 *
 * Returns:
 *  none
 *
 *********************************************************************/
void _SmEngine( void *pParam  )
{
    BOOL bChangedStatesUsingActiveEvents;
    BOOL bChangedStatesUsingDeferredEvents;
    tSmInstance *pSM = ( tSmInstance * ) pParam;

    do
    {
        bChangedStatesUsingDeferredEvents = FALSE;

        // try and process all the active events that are waiting
        bChangedStatesUsingActiveEvents = _SmProcessActiveEvents( pSM );

        // if at least one event was consumed which means the state has changed then
        // try the deferred events on this new state

        if ( ( TRUE == bChangedStatesUsingActiveEvents ) && ( 0 != pSM->deferredEvtQueue.mQCount ) )
        {
            bChangedStatesUsingDeferredEvents = _SmProcessDeferredEvents( pSM );
        }
    } while ( TRUE == bChangedStatesUsingDeferredEvents );

    //DbgLog( DBG_MODULE_SM_ENGINE, DBG_LEVEL_FATAL, "%s exit: a: %d, d: %d", INST_NAME pSM->activeEvtQueue.mQCount, pSM->deferredEvtQueue.mQCount );
#ifdef RDK
    XLOGD_DEBUG( "%s exit: a: %d, d: %d" INST_NAME, pSM->activeEvtQueue.mQCount, pSM->deferredEvtQueue.mQCount );
#endif
}

void SmProcessEvents( tSmInstance *pSM )
{
    _SmEngine( pSM );
}
