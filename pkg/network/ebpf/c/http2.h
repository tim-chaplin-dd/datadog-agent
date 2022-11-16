#ifndef __HTTP2_H
#define __HTTP2_H

#include "bpf_builtins.h"
#include "bpf_helpers.h"
#include "map-defs.h"
#include "http2-defs.h"

BPF_HASH_MAP(http2_static_table, u64, static_table_value, 20)

static __always_inline uint32_t as_uint32_t(unsigned char input) {
    return (uint32_t)input;
}

// This function checks if the http2 frame header is empty.
static __always_inline bool is_empty_frame_header(const char *frame) {
#pragma unroll
    for (uint32_t i = 0; i < HTTP2_FRAME_HEADER_SIZE; i++) {
        if (frame[i] != 0) {
            return false;
        }
    }
    return true;
}

// This function reads the http2 frame header and validate the frame.
static __always_inline bool read_http2_frame_header(const char *buf, size_t buf_size, struct http2_frame *out) {
    if (buf == NULL) {
        return false;
    }

    if (buf_size < HTTP2_FRAME_HEADER_SIZE) {
        return false;
    }

    if (is_empty_frame_header(buf)) {
        return false;
    }

// We extract the frame by its shape to fields.
// See: https://datatracker.ietf.org/doc/html/rfc7540#section-4.1
    out->length = as_uint32_t(buf[0])<<16 | as_uint32_t(buf[1])<<8 | as_uint32_t(buf[2]);
    out->type = (frame_type_t)buf[3];
    out->flags = (uint8_t)buf[4];
    out->stream_id = (as_uint32_t(buf[5]) << 24 |
                      as_uint32_t(buf[6]) << 16 |
                      as_uint32_t(buf[7]) << 8 |
                      as_uint32_t(buf[8])) & 2147483647;

    return true;
}

// read_var_int reads an unsigned variable length integer off the
// beginning of p. n is the parameter as described in
// https://httpwg.org/specs/rfc7541.html#rfc.section.5.1.
//
// n must always be between 1 and 8.
//
// The returned remain buffer is either a smaller suffix of p, or err != nil.
// The error is errNeedMore if p doesn't contain a complete integer.
static __always_inline __u64 read_var_int(const char *payload, size_t *pos, char n){
    if (n < 1 || n > 8) {
        return -1;
    }

    __u64 index = (__u64)(payload[*pos]);
    __u64 n2 = n;
    if (n < 8) {
        index &= (1 << n2) - 1;
    }

    if (index < (1 << n2) - 1) {
        *pos += 1;
        return index;
    }

    // Error
    return -1;
}

static __always_inline void parse_field_indexed(const char *payload, size_t *pos){
    __u64 index = read_var_int(payload, pos, 7);
    if (index) {
        log_debug("[http2] the index is %llu", index);
    }
//
//    log_debug("[slavin] the index is: %d", key);
//
//    static_table_value *static_value = bpf_map_lookup_elem(&http2_static_table, &key);
//    if (static_value != NULL) {
//        log_debug("[slavin] the name is %d", static_value->name);
//        log_debug("[slavin] the value is %d", static_value->value);
//    } else {
//        log_debug("[slavin] value is null");
//    }
}

static __always_inline void parse_header_field_repr(const char *payload) {
    char first_char = payload[0];

    size_t pos = 0;
    if ((first_char&128) != 0) {
        log_debug("[http2] first char %d & 128 != 0; calling parse_field_indexed", first_char);
        parse_field_indexed(payload, &pos);
    }

}

// This function reads the http2 headers frame.
static __always_inline bool decode_http2_headers_frame(const char *payload, size_t payload_size) {
    if (payload == NULL) {
        return false;
    }

    // TODO: Add a loop until we reach the given payload size
    parse_header_field_repr(payload);

    return true;
}

// This function filters the needed frames from the http2 session.
static __always_inline void process_http2_frames(struct __sk_buff *skb, size_t pos) {
    struct http2_frame current_frame = {};
    char buf[HTTP2_FRAME_HEADER_SIZE];
    char payload[100];

#pragma unroll
    // Iterate till max frames to avoid high connection rate.
    for (uint32_t i = 0; i < HTTP2_MAX_FRAMES; ++i) {
        if (pos + HTTP2_FRAME_HEADER_SIZE > skb->len) {
          return;
        }

        // Load the current HTTP2_FRAME_HEADER_SIZE into the buffer.
        bpf_skb_load_bytes(skb, pos, buf, HTTP2_FRAME_HEADER_SIZE);
        pos += HTTP2_FRAME_HEADER_SIZE;

        // Load the current frame into http2_frame strct in order to filter the needed frames.
        if (!read_http2_frame_header(buf, HTTP2_FRAME_HEADER_SIZE, &current_frame)){
            log_debug("unable to read http2 frame header");
            break;
        }

        // Filter all types of frames except header frame.
        if (current_frame.type != kHeadersFrame) {
            pos += (__u32)current_frame.length;
            continue;
        }

        bpf_skb_load_bytes(skb, pos, payload, 100);
        // Load the current frame into http2_frame strct in order to filter the needed frames.
        if (!decode_http2_headers_frame(payload, 100)){
            log_debug("unable to read http2 header frame");
            break;
        }

        pos += (__u32)current_frame.length;
    }
}

#endif
