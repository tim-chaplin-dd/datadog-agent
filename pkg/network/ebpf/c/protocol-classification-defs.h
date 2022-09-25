#ifndef __PROTOCOL_CLASSIFICATION_DEFS_H
#define __PROTOCOL_CLASSIFICATION_DEFS_H

#include <linux/types.h>

// Represents the max buffer size required to classify protocols.
// ATM, it is like HTTP2_MARKER_SIZE.
#define CLASSIFICATION_MAX_BUFFER 24

// Checkout https://datatracker.ietf.org/doc/html/rfc7540 under "HTTP/2 Connection Preface" section
#define HTTP2_MARKER_SIZE 24

// The minimal HTTP response has 17 characters: HTTP/1.1 200 OK\r\n
// The minimal HTTP request has 16 characters: GET x HTTP/1.1\r\n
#define HTTP_MIN_SIZE 16

// The enum below represents all different protocols we know to classify.
// We set the size of the enum to be 16 bits, by adding max value (max uint16 which is 65535) and
// `__attribute__ ((packed))` to tell the compiler to use as minimum bits as needed. Due to our max
// value we will use 16 bits for the enum.
typedef enum {
    PROTOCOL_UNCLASSIFIED = 0,
    PROTOCOL_UNKNOWN,
    PROTOCOL_HTTP,
    PROTOCOL_HTTP2,
    PROTOCOL_TLS,
    //  Add new protocols before that line.
    MAX_PROTOCOLS,
    __MAX_UINT16 = 65535,
} __attribute__ ((packed)) protocol_t;

const char HTTP2_PREFIX[] = {0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a};

#endif
