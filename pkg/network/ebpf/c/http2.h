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

    // TODO: compare with original code.
    return -1;
}


// readString decoded string an hpack string from payload.
//
// wantStr is whether s will be used. If false, decompression and
// []byte->string garbage are skipped if s will be ignored
// anyway. This does mean that huffman decoding errors for non-indexed
// strings past the MAX_HEADER_LIST_SIZE are ignored, but the server
// is returning an error anyway, and because they're not indexed, the error
// won't affect the decoding state.
static __always_inline __u64 read_string(const char *payload, size_t *pos, char n, size_t payload_size){
    bool is_huff = false;
    if ((payload[0]&128) != 0) {
        is_huff = true;
    }
    __u64 str_len = read_var_int(payload, pos, 7);
    log_debug("[slavin] the string len is %llu, pos is now %d", str_len, *pos);

    if (str_len > payload_size) {
        return -1;
    }

    char full_string[21];
    bpf_probe_read_kernel((char*)full_string, 21,(void*)(payload + *pos));

    log_debug("[http2] -------------------1 buf is %d %d %d", full_string[0], full_string[1], full_string[2]);
    log_debug("[http2] -------------------2 buf is %d %d %d", full_string[3], full_string[4], full_string[5]);
    log_debug("[http2] -------------------3 buf is %d %d %d", full_string[6], full_string[7], full_string[8]);
    log_debug("[http2] -------------------4 buf is %d %d %d", full_string[9], full_string[10], full_string[11]);
    log_debug("[http2] -------------------5 buf is %d %d %d", full_string[12], full_string[13], full_string[14]);
    log_debug("[http2] -------------------6 buf is %d %d %d", full_string[15], full_string[16], full_string[17]);
    log_debug("[http2] -------------------7 buf is %d %d %d", full_string[18], full_string[19], full_string[20]);

    return str_len;
}

static __always_inline void parse_field_literal(const char *payload, size_t *pos, bool index_type, size_t payload_size){
    __u64 index = read_var_int(payload, pos, 6);
    if (index > 0) {
        log_debug("[http2] the index in parse_field_literal is %llu, pos is now %d", index, *pos);

        dynamic_table_value dynamic_value = {};
        static_table_value *static_value = bpf_map_lookup_elem(&http2_static_table, &index);
        if (static_value != NULL) {
            if (index_type){
                dynamic_value.name = static_value->name;
                log_debug("[http2] the dynamic name is %d", dynamic_value.name);
                __u64 str_len = read_string(payload, pos, 6, payload_size);
                if (str_len ==0){
                    return;
                }
                pos += str_len;
            }
        } else {
            log_debug("[http2] value is null");
        }
    }

    log_debug("[http2] the index is: %d in parse_field_literal", index);

    static_table_value *static_value = bpf_map_lookup_elem(&http2_static_table, &index);
    if (static_value != NULL) {
        log_debug("[http2] the name is %d", static_value->name);
        log_debug("[http2] the value is %d", static_value->value);
    } else {
        log_debug("[http2] value is null");
    }
}

static __always_inline void parse_field_indexed(const char *payload, size_t *pos){
    __u64 index = read_var_int(payload, pos, 7);
    if (index) {
        log_debug("[http2] the index is parse_field_indexed %llu, pos is now %d", index, *pos);
    }

    static_table_value *static_value = bpf_map_lookup_elem(&http2_static_table, &index);
    if (static_value != NULL) {
        log_debug("[http2] the static name in parse_field_indexed is %d", static_value->name);
        log_debug("[http2] the static value in parse_field_indexed is %d", static_value->value);
    } else {
        log_debug("[http2] value is null");
    }
}

static __always_inline void parse_header_field_repr(const char *payload, size_t payload_size) {
    log_debug("http2 parse_header_field_repr is in");
    volatile size_t pos = 0; // understand ?!

#pragma unroll
    for (int i = 0; i < 3; i++) {
        __u8 first_char = payload[pos];

        log_debug("[http2] first char %d", first_char);
        if ((first_char&128) != 0) {
            log_debug("[http2] pos is %d first char %d & 128 != 0; calling parse_field_indexed", pos, first_char);
            parse_field_indexed(payload, (size_t*)&pos);
        } if ((first_char&192) == 64) {
            log_debug("[http2] pos is %d first char %d & 128 != 0; calling parse_field_literal", pos, first_char);
            parse_field_literal(payload, (size_t*)&pos, true, payload_size);
        }
    }
}

// This function reads the http2 headers frame.
static __always_inline bool decode_http2_headers_frame(const char *payload, size_t payload_size) {
    log_debug("[http2] decode_http2_headers_frame is in");

    if (payload == NULL) {
        return false;
    }

    // TODO: Add a loop until we reach the given payload size
    parse_header_field_repr(payload, payload_size);

    return true;
}

// This function filters the needed frames from the http2 session.
static __always_inline void process_http2_frames(struct __sk_buff *skb, size_t pos) {
    log_debug("http2 process_http2_frames");

    struct http2_frame current_frame = {};
    char buf[HTTP2_FRAME_HEADER_SIZE];
    char payload[HTTP2_MAX_FRAME_LEN];

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

        // Verify size of pos with max of XX not bigger then the packet.
        if (pos + (__u32)current_frame.length > skb->len) {
            return;
        }

        // Verify size for reading max of XX not bigger then current_frame.length

        // Choose the max size to load for payload which will not be bigger then the HTTP2_MAX_FRAME_LEN to pass the
        // verifier.
//        __u32 final_size = current_frame.length > HTTP2_MAX_FRAME_LEN ? HTTP2_MAX_FRAME_LEN:current_frame.length;
//        if (final_size > 0) {
//            log_debug("http2 the final size is %d", final_size);
//        }

        // 2. Iterate if needed
        bpf_skb_load_bytes(skb, pos, payload, 91);
        // Load the current frame into http2_frame strct in order to filter the needed frames.
        if (!decode_http2_headers_frame(payload, 91)){
            log_debug("unable to read http2 header frame");
            break;
        }

        pos += (__u32)current_frame.length;
    }
}

#endif
