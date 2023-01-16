#ifndef __HTTP2_DECODING_MAPS_H
#define __HTTP2_DECODING_MAPS_H

#include "http2-decoding-defs.h"

// http2_static_table is the map that holding the supported static values by index and its static value.
BPF_HASH_MAP(http2_static_table, u64, static_table_entry_t, 15)

BPF_PERCPU_ARRAY_MAP(http2_trans_alloc, __u32, http2_connection_t, 1)

#endif
