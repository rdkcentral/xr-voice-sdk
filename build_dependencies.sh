#!/bin/bash
set -x
set -e
##############################
GITHUB_WORKSPACE="${PWD}"
ls -la ${GITHUB_WORKSPACE}
cd ${GITHUB_WORKSPACE}

git config --global --add safe.directory "${GITHUB_WORKSPACE}"

###########################################
# 1. Install Dependencies and packages

apt update
apt install -y \
    libbsd-dev \
    libcurl4-openssl-dev \
    libjansson-dev \
    libnopoll-dev \
    libopus-dev \
    libssl-dev \
    uuid-dev \
    gperf \
    python3

###########################################
# 2. Clone the required repositories

git clone --depth 1 --branch feature/RDKEMW-14537 https://$GITHUB_TOKEN@github.com/rdkcentral/entservices-testframework.git

############################
# 3. Create stub headers for external dependencies
echo "======================================================================================"
echo "Creating stub headers"

HEADERS_DIR="$GITHUB_WORKSPACE/entservices-testframework/Tests/headers"
mkdir -p "${HEADERS_DIR}"

cd "${HEADERS_DIR}"

# safec - needs actual dummy API content (guarded by SAFEC_DUMMY_API, which cov_build.sh defines)
cat > safec_lib.h << 'SAFEC_EOF'
#ifndef _SAFEC_LIB_H_
#define _SAFEC_LIB_H_
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#ifdef SAFEC_DUMMY_API
typedef int errno_t;
#define EOK 0

static inline errno_t strcpy_s(char *dest, size_t dmax, const char *src) {
    (void)dmax;
    if(dest == NULL || src == NULL) {
        return -1;
    }
    strcpy(dest, src);
    return EOK;
}

static inline errno_t strncpy_s(char *dest, size_t dmax, const char *src, size_t count) {
    (void)dmax;
    if(dest == NULL || src == NULL) {
        return -1;
    }
    strncpy(dest, src, count);
    return EOK;
}

static inline errno_t memset_s(void *dest, size_t dmax, int value, size_t count) {
    (void)dmax;
    if(dest == NULL) {
        return -1;
    }
    memset(dest, value, count);
    return EOK;
}

static inline errno_t memcpy_s(void *dest, size_t dmax, const void *src, size_t count) {
    (void)dmax;
    if(dest == NULL || src == NULL) {
        return -1;
    }
    memcpy(dest, src, count);
    return EOK;
}

#define ERR_CHK(rc) do { (void)(rc); } while(0)
#endif
#endif
SAFEC_EOF

echo "Stub headers created successfully"

cd ${GITHUB_WORKSPACE}
