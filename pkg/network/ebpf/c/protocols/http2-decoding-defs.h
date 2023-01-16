#ifndef __HTTP2_DECODING_DEFS_H
#define __HTTP2_DECODING_DEFS_H

#include <linux/types.h>

#define HTTP2_BUFFER_SIZE (8 * 20)

typedef struct {
    conn_tuple_t tup;
    char request_fragment[HTTP2_BUFFER_SIZE] __attribute__ ((aligned (8)));
    __u32 current_offset_in_request_fragment;
} http2_connection_t;

#endif
