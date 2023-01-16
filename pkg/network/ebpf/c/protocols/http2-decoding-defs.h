#ifndef __HTTP2_DECODING_DEFS_H
#define __HTTP2_DECODING_DEFS_H

#include <linux/types.h>

#define HTTP2_BUFFER_SIZE (8 * 20)
#define HTTP2_MAX_FRAMES 5
#define HTTP2_END_OF_STREAM 0x1
#define HTTP2_MAX_HEADERS_COUNT 30

typedef struct {
    char request_fragment[HTTP2_BUFFER_SIZE];

    conn_tuple_t tup;
} http2_connection_t;

#endif
