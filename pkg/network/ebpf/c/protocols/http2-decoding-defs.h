#ifndef __HTTP2_DECODING_DEFS_H
#define __HTTP2_DECODING_DEFS_H

#include <linux/types.h>

#define HTTP2_BUFFER_SIZE (8 * 20)
#define HTTP2_MAX_FRAMES 5
#define HTTP2_END_OF_STREAM 0x1
#define HTTP2_MAX_HEADERS_COUNT 30

typedef struct {
    char request_fragment[HTTP2_BUFFER_SIZE];

    __u32 offset;
    conn_tuple_t tup;
} http2_connection_t;

typedef enum {
    kMethod = 2,
    kPath = 4,
    kStatus = 9,
} __attribute__ ((packed)) header_key;

typedef enum {
    kGET = 2,
    kPOST = 3,
    kEmptyPath = 4,
    kIndexPath = 5,
    k200 = 8,
    k204 = 9,
    k206 = 10,
    k304 = 11,
    k400 = 12,
    k404 = 13,
    k500 = 14,
} __attribute__ ((packed)) header_value;

typedef struct {
    header_key key;
    header_value value;
} static_table_entry_t;

#endif
