#ifndef __HTTP2_MAPS_DEFS_CLASSIFY_H
#define __HTTP2_MAPS_DEFS_CLASSIFY_H

/* This map is used to keep track of in-flight HTTP transactions for each TCP connection */
//BPF_LRU_MAP(http2_in_flight, conn_tuple_t, http2_transaction_t, 0)

/* This map is used to keep track of in-flight HTTP transactions for each TCP connection */
BPF_LRU_MAP(http2_stream_in_flight, http2_stream_key_t, http2_stream_t, 0)

typedef struct {
    char request_fragment[HTTP2_BUFFER_SIZE];
    __u32 current_offset_in_request_fragment;
} heap_buffer_t;

/* thread_struct id too big for allocation on stack in eBPF function, we use an array as a heap allocator */
BPF_PERCPU_ARRAY_MAP(http2_heap_buffer, __u32, heap_buffer_t, 1)
BPF_PERCPU_ARRAY_MAP(http_trans_alloc, __u32, http_transaction_t, 1)

#endif
