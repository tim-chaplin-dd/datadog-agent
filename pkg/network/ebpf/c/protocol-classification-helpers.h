#ifndef __PROTOCOL_CLASSIFICATION_HELPERS_H
#define __PROTOCOL_CLASSIFICATION_HELPERS_H

#include <linux/types.h>

#include "protocol-classification-defs.h"

// The method checks if the given buffer starts with the HTTP2 marker as defined in https://datatracker.ietf.org/doc/html/rfc7540.
// We check that the given buffer is not empty and its size is at least 24 bytes.
static __always_inline bool is_http2(const char* buf, __u32 buf_size) {
    if (buf_size < HTTP2_MARKER_SIZE) {
        return false;
    }

    if (buf == NULL) {
        return false;
    }


    #pragma unroll
    for (int i = 0; i < HTTP2_MARKER_SIZE; i++) {
        if (buf[i] != HTTP2_PREFIX[i]) {
            return false;
        }
    }

    return true;
}

// Checks if the given buffers start with `HTTP` prefix (represents a response) or starts with `<method> /` which represents
// a request, where <method> is one of: GET, POST, PUT, DELETE, HEAD, OPTIONS, or PATCH.
static __always_inline bool is_http(const char *buf, __u32 size) {
    if (size < HTTP_MIN_SIZE) {
        return false;
    }
    if (buf == NULL) {
        return false;
    }

    if ((buf[0] == 'H') && (buf[1] == 'T') && (buf[2] == 'T') && (buf[3] == 'P')) {
        return true;
    } else if ((buf[0] == 'G') && (buf[1] == 'E') && (buf[2] == 'T') && (buf[3]  == ' ') && (buf[4] == '/')) {
        return true;
    } else if ((buf[0] == 'P') && (buf[1] == 'O') && (buf[2] == 'S') && (buf[3] == 'T') && (buf[4]  == ' ') && (buf[5] == '/')) {
        return true;
    } else if ((buf[0] == 'P') && (buf[1] == 'U') && (buf[2] == 'T') && (buf[3]  == ' ') && (buf[4] == '/')) {
        return true;
    } else if ((buf[0] == 'D') && (buf[1] == 'E') && (buf[2] == 'L') && (buf[3] == 'E') && (buf[4] == 'T') && (buf[5] == 'E') && (buf[6]  == ' ') && (buf[7] == '/')) {
        return true;
    } else if ((buf[0] == 'H') && (buf[1] == 'E') && (buf[2] == 'A') && (buf[3] == 'D') && (buf[4]  == ' ') && (buf[5] == '/')) {
        return true;
    } else if ((buf[0] == 'O') && (buf[1] == 'P') && (buf[2] == 'T') && (buf[3] == 'I') && (buf[4] == 'O') && (buf[5] == 'N') && (buf[6] == 'S') && (buf[7]  == ' ') && ((buf[8] == '/') || (buf[8] == '*'))) {
        return true;
    } else if ((buf[0] == 'P') && (buf[1] == 'A') && (buf[2] == 'T') && (buf[3] == 'C') && (buf[4] == 'H') && (buf[5]  == ' ') && (buf[6] == '/')) {
        return true;
    }

    return false;
}

// Determines the protocols of the given buffer. If we already classified the payload (a.k.a protocol out param
// has a known protocol), then we do nothing.
static __always_inline void classify_protocol(protocol_t *protocol, const char *buf, __u32 size) {
    if (protocol == NULL || (*protocol != PROTOCOL_UNKNOWN && *protocol != PROTOCOL_UNCLASSIFIED)) {
        return;
    }

    if (is_http(buf, size)) {
        *protocol = PROTOCOL_HTTP;
    } else if (is_http2(buf, size)) {
        *protocol = PROTOCOL_HTTP2;
    } else {
        *protocol = PROTOCOL_UNKNOWN;
    }

    log_debug("[guy protocol classification]: Classified protocol as %d %d %s\n", *protocol, size, buf);
}

#endif
