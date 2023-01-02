#ifndef __HTTP2_MAPS_H
#define __HTTP2_MAPS_H

#include "map-defs.h"
#include "http2-defs.h"
#include "bpf_helpers.h"

BPF_HASH_MAP(http2_static_table, u64, static_table_value, 1024)

BPF_HASH_MAP(http2_dynamic_table, u64, dynamic_table_value, 1024)

BPF_HASH_MAP(http2_dynamic_counter_table, conn_tuple_t, u64, 1024)

/* thread_struct id too big for allocation on stack in eBPF function, we use an array as a heap allocator */
BPF_PERCPU_ARRAY_MAP(http2_trans_alloc, __u32, http2_transaction_t, 1)

#endif
