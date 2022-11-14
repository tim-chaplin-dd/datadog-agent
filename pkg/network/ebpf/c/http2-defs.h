#ifndef __HTTP2_DEFS_H
#define __HTTP2_DEFS_H

#include <linux/types.h>


// A limit of max frames we will upload from a single connection to the user mode.
// NOTE: we may need to revisit this const if we need to capture more connections.
#define HTTP2_MAX_FRAMES 40

// All types of http2 frames exist in the protocol.
// Checkout https://datatracker.ietf.org/doc/html/rfc7540 under "Frame Type Registry" section.
typedef enum {
    kDataFrame          = 0,
    kHeadersFrame       = 1,
    kPriorityFrame      = 2,
    kRSTStreamFrame     = 3,
    kSettingsFrame      = 4,
    kPushPromiseFrame   = 5,
    kPingFrame          = 6,
    kGoAwayFrame        = 7,
    kWindowUpdateFrame  = 8,
    kContinuationFrame  = 9,
} __attribute__ ((packed)) frame_type_t;

// Struct which represent the http2 frame by its fields.
// Checkout https://datatracker.ietf.org/doc/html/rfc7540#section-4.1 for frame format.
struct http2_frame {
    __u32 length;
    frame_type_t type;
    __u8 flags;
    __u32 stream_id;
};

typedef enum {
    kAuthority = 0,
    kMethod,
    kPath,
    kScheme,
    kStatus,
} __attribute__ ((packed)) header_key;

typedef enum {
    kGET = 0,
    kSchemeHTTP,
} __attribute__ ((packed)) header_value;

typedef struct {
    header_key name;
    header_value value;
} static_table_value;

#define MAX_STATIC_TABLE_INDEX 64


#endif
