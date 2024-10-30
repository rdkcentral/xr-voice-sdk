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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/eventfd.h>
#define XLOG_MODULE_ID XLOG_MODULE_ID_XRMQ
#include <rdkx_logger.h>
#include "xr_mq.h"

typedef struct {
    xr_mq_t          fd;
    xr_mq_msg_size_t max_msg_size;
    uint8_t          max_msg;
    uint8_t          msg_index_push;
    uint8_t          msg_index_pop;
    uint8_t          msg_used;
    uint8_t         *msg_queue;
    pthread_mutex_t  mq_mutex;
}_xr_mq_t;

typedef struct _xr_mq_node_t {
    _xr_mq_t              mq;
    struct _xr_mq_node_t *next;
} _xr_mq_node_t;

typedef struct {
    uint8_t           mq_count;
    _xr_mq_node_t    *mq_node;
} _xr_mq_list_t;

static pthread_mutex_t g_mutex   = PTHREAD_MUTEX_INITIALIZER;
static _xr_mq_list_t   g_mq_list = {0};

xr_mq_t xr_mq_create(xr_mq_attr_t *attr) {
    _xr_mq_node_t *node = NULL;
    xr_mq_attr_t   attributes;
    if(NULL == attr) {
        XLOGD_INFO("using default attribute values");
        attributes.max_msg      = XR_MQ_DEFAULT_MAX_MSG;
        attributes.max_msg_size = XR_MQ_DEFAULT_MAX_MSG_SIZE;
    } else {
        attributes.max_msg      = attr->max_msg;
        attributes.max_msg_size = attr->max_msg_size + sizeof(xr_mq_msg_size_t); // Need to keep size of message too
    }

    // Allocate node for mq linked list
    if(NULL == (node = (_xr_mq_node_t *)malloc(sizeof(_xr_mq_node_t)))) {
        XLOGD_ERROR("failed to allocate memory for mq node");
        return(XR_MQ_INVALID);
    }

    // Set up mq and node
    memset(node, 0, sizeof(*node));
    node->mq.max_msg      = attributes.max_msg;
    node->mq.max_msg_size = attributes.max_msg_size;
    if(NULL == (node->mq.msg_queue = (uint8_t *)malloc(node->mq.max_msg * (node->mq.max_msg_size * sizeof(uint8_t))))) {
        XLOGD_ERROR("failed to allocate memory for mq");
        free(node);
        return(XR_MQ_INVALID);
    }
    if((node->mq.fd = eventfd(0, EFD_NONBLOCK)) < 0) {
        XLOGD_ERROR("failed to create eventfd for mq");
        free(node->mq.msg_queue);
        free(node);
        return(XR_MQ_INVALID);
    }
    if(pthread_mutex_init(&node->mq.mq_mutex, NULL)) {
        XLOGD_ERROR("failed to init mutex for mq");
        close(node->mq.fd);
        free(node->mq.msg_queue);
        free(node);
        return(XR_MQ_INVALID);
    }

    // Add node to list
    pthread_mutex_lock(&g_mutex);
    if(NULL == g_mq_list.mq_node) {
        g_mq_list.mq_node = node;
        g_mq_list.mq_count++;
    } else {
        _xr_mq_node_t *temp = g_mq_list.mq_node;
        while(temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = node;
        g_mq_list.mq_count++;
    }
    pthread_mutex_unlock(&g_mutex);
    return(node->mq.fd);
}

bool xr_mq_push(xr_mq_t mq, const void *msg, xr_mq_msg_size_t msg_size) {
    _xr_mq_t       *msgq    = NULL;
    _xr_mq_node_t  *node    = NULL;
    uint64_t        num_msg = 1;

    // Lock global mutex
    pthread_mutex_lock(&g_mutex);
    node = g_mq_list.mq_node;
    while(node != NULL) {
        if(node->mq.fd == mq) {
            msgq = &node->mq;
            break;
        }
        node = node->next;
    }
    if(NULL == msgq) {
        pthread_mutex_unlock(&g_mutex);
        XLOGD_ERROR("mq provided is not valid");
        return(false);
    } else {
        pthread_mutex_lock(&node->mq.mq_mutex);
    }
    pthread_mutex_unlock(&g_mutex);

    // We have the mq now and have the lock, lets push the message
    if(msgq->msg_used >= msgq->max_msg) {
        XLOGD_ERROR("mq full");
        pthread_mutex_unlock(&node->mq.mq_mutex);
        return(false);
    } else if(msg_size + sizeof(xr_mq_msg_size_t) > msgq->max_msg_size) {
        XLOGD_ERROR("message too large");
        pthread_mutex_unlock(&node->mq.mq_mutex);
        return(false);
    }

    memcpy(&msgq->msg_queue[msgq->msg_index_push * msgq->max_msg_size], &msg_size, sizeof(msg_size)); // Copy size
    memcpy(&msgq->msg_queue[(msgq->msg_index_push * msgq->max_msg_size) + sizeof(xr_mq_msg_size_t)], msg, msg_size); // Copy message
    if(sizeof(num_msg) != write(msgq->fd, (void *)&num_msg, sizeof(num_msg))) { // Write to pipe to signify a message has been added
        XLOGD_ERROR("failed to write to eventfd");
        pthread_mutex_unlock(&node->mq.mq_mutex);
        return(false);
    }
    msgq->msg_used++;
    msgq->msg_index_push = (msgq->msg_index_push + 1) % msgq->max_msg;
    pthread_mutex_unlock(&node->mq.mq_mutex);
    return(true);
}

xr_mq_msg_size_t xr_mq_pop(xr_mq_t mq, void *msg, xr_mq_msg_size_t msg_size) {
    xr_mq_msg_size_t ret    = 0;
    _xr_mq_t       *msgq    = NULL;
    _xr_mq_node_t  *node    = NULL;
    uint64_t        num_msg = 0;

    // Lock global mutex
    pthread_mutex_lock(&g_mutex);
    node = g_mq_list.mq_node;
    while(node != NULL) {
        if(node->mq.fd == mq) {
            msgq = &node->mq;
            break;
        }
        node = node->next;
    }
    if(NULL == msgq) {
        pthread_mutex_unlock(&g_mutex);
        XLOGD_ERROR("mq provided is not valid");
        return(0);
    } else {
        pthread_mutex_lock(&node->mq.mq_mutex);
    }
    pthread_mutex_unlock(&g_mutex);

    // We have the mq now and have the lock, lets pop the message
    if(msgq->msg_used == 0) {
        XLOGD_ERROR("mq empty");
        pthread_mutex_unlock(&node->mq.mq_mutex);
        return(0);
    }

    memcpy(&ret, &msgq->msg_queue[msgq->msg_index_pop * msgq->max_msg_size], sizeof(xr_mq_msg_size_t)); // Copy size
    
    if(msg_size < ret) {
        XLOGD_ERROR("message buffer too small");
        pthread_mutex_unlock(&node->mq.mq_mutex);
        return(0);
    }

    memcpy(msg, &msgq->msg_queue[(msgq->msg_index_pop * msgq->max_msg_size) + sizeof(xr_mq_msg_size_t)], ret); // Copy message
    if(sizeof(num_msg) != read(msgq->fd, &num_msg, sizeof(num_msg))) {
        XLOGD_ERROR("failed to read from eventfd");
        pthread_mutex_unlock(&node->mq.mq_mutex);
        return(0);
    }
    msgq->msg_used--;
    msgq->msg_index_pop = (msgq->msg_index_pop + 1) % msgq->max_msg;
    if(num_msg > 1) {
        num_msg--;
        if(sizeof(num_msg) != write(msgq->fd, &num_msg, sizeof(num_msg))) {
            XLOGD_ERROR("failed to write to eventfd");
        }
    }
    pthread_mutex_unlock(&node->mq.mq_mutex);
    return(ret);
}

void xr_mq_destroy(xr_mq_t mq) {
    _xr_mq_node_t  *node     = NULL;
    _xr_mq_node_t  *previous = NULL;

    // Lock global mutex
    pthread_mutex_lock(&g_mutex);
    node = g_mq_list.mq_node;
    while(node != NULL) {
        if(node->mq.fd == mq) {
            break;
        }
        previous = node;
        node = node->next;
    }
    if(NULL == node) {
        pthread_mutex_unlock(&g_mutex);
        XLOGD_ERROR("mq provided is not valid");
        return;
    } else {
        pthread_mutex_lock(&node->mq.mq_mutex);
    }

    // Now we have both the global lock and the mq lock. Destroy the queue
    if(NULL == previous) {
        g_mq_list.mq_node = node->next;
    } else {
        previous->next = node->next;
    }
    g_mq_list.mq_count--;
    close(node->mq.fd);
    pthread_mutex_unlock(&node->mq.mq_mutex);
    pthread_mutex_destroy(&node->mq.mq_mutex);
    free(node->mq.msg_queue);
    free(node);
    pthread_mutex_unlock(&g_mutex);
}
