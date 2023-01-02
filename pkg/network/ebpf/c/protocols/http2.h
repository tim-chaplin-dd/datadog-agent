#ifndef __HTTP2_H
#define __HTTP2_H

#include "http2-defs.h"
#include "http2-maps.h"

// This function checks if the http2 frame header is empty.
static __always_inline bool is_empty_frame_header(const char *frame) {

#define EMPTY_FRAME_HEADER "\0\0\0\0\0\0\0\0\0"

    return !bpf_memcmp(frame, EMPTY_FRAME_HEADER, sizeof(EMPTY_FRAME_HEADER) - 1);
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
    *out = *((struct http2_frame*)buf);
    out->length = bpf_ntohl(out->length << 8);
    out->stream_id = bpf_ntohl(out->stream_id << 1);

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
static __always_inline __u64 read_var_int(http2_transaction_t* http2_transaction, char n){
    if (http2_transaction->current_offset_in_request_fragment > HTTP2_BUFFER_SIZE) {
        return false;
    }

    __u64 index = (__u64)(http2_transaction->request_fragment[http2_transaction->current_offset_in_request_fragment]);
    __u64 n2 = n;
    if (n < 8) {
        index &= (1 << n2) - 1;
    }

    if (index < (1 << n2) - 1) {
        http2_transaction->current_offset_in_request_fragment += 1;
        return index;
    }

    // TODO: compare with original code if needed.
    return -1;
}

// parse_field_indexed is handling the case which the header frame is part of the static table.
static __always_inline void parse_field_indexed(http2_transaction_t* http2_transaction) {
    __u8 index = read_var_int(http2_transaction, 7);

    log_debug("[http2] ************************ the current index at parse_field_indexed is: %d", index);

    // TODO: use constants with meaning
    if (index == 3){
        http2_transaction->request_method = index;
        http2_transaction->packet_type = 2; // this will be request and we need to make it better
    } else if (index == 6) {
        http2_transaction->schema = index;
    }
}

// readString decoded string an hpack string from payload.
//
// wantStr is whether s will be used. If false, decompression and
// []byte->string garbage are skipped if s will be ignored
// anyway. This does mean that huffman decoding errors for non-indexed
// strings past the MAX_HEADER_LIST_SIZE are ignored, but the server
// is returning an error anyway, and because they're not indexed, the error
// won't affect the decoding state.
static __always_inline bool read_string(http2_transaction_t* http2_transaction, __u32 *offset, __u64 *out_str_len, size_t payload_size){
    // need to make sure that I am right but it seems like this part is interesting for headers which are not interesting
    // for as for example te:trailers, if so we may consider not supporting this part of the code in order to avoid
    // complexity and drop each index which is not interesting for us.
//    bool is_huff = false;
//    __u8 first_char = *(http2_transaction->request_fragment + *offset);
//    bool is_huff = first_char&128;
//    if ((first_char&128) != 0) {
//        is_huff = true;
//    }

    *out_str_len = read_var_int(http2_transaction, 7);
    return true;
}

// parse_field_literal handling the case when the key is part of the static table and the value is a dynamic string
// which will be stored in the dynamic table.
static __always_inline void parse_field_literal(http2_transaction_t* http2_transaction, bool index_type, size_t payload_size, uint8_t n){
    __u64 counter = 0;
    __u64 *counter_ptr = bpf_map_lookup_elem(&http2_dynamic_counter_table, &http2_transaction->tup);
    if (counter_ptr != NULL) {
//        counter = *counter_ptr;
    }
    counter += 1;

//    __u64 index = read_var_int(http2_transaction, offset, n);
//    log_debug("[tasik] the index is parse_field_indexed %llu with counter %d", index, counter);

//    bpf_map_update_elem(&http2_dynamic_counter_table, &http2_transaction->tup, &counter, BPF_ANY);
//    if (index) {}
//    static_table_value *static_value = bpf_map_lookup_elem(&http2_static_table, &index);
//    if (static_value == NULL) {
//        log_debug("[http2] unable to find the static value in map");
//        return;
//    }
//
//    dynamic_table_value dynamic_value = {};
//    if (index_type) {
//        dynamic_value.index = static_value->name;
//        log_debug("[http2] ************************** the dynamic index is %d", dynamic_value.index);
//    }

    return;
//    __u64 str_len = 0;
//    bool ok = read_string(http2_transaction, 6, &str_len, payload_size);
//    if (!ok || str_len <= 0){
//        return;
//    }
//
//    log_debug("[http2] the string len is %llu", str_len);
//    if (http2_transaction->current_offset_in_request_fragment + str_len > sizeof(http2_transaction->request_fragment)) {
//        return;
//    } else if (http2_transaction->current_offset_in_request_fragment > sizeof(http2_transaction->request_fragment)) {
//        return;
//    }
//
//    char *beginning = http2_transaction->request_fragment + http2_transaction->current_offset_in_request_fragment;
    // TODO: use const __u64 size11 = str_len < HTTP2_MAX_PATH_LEN ? str_len : HTTP2_MAX_PATH_LEN;
//    bpf_memcpy(http2_transaction->request_fragment_bla, beginning, HTTP2_MAX_PATH_LEN);
//
//         log_debug("[http2] ------------ first char bla in 0 spot is %c", http2_transaction->request_fragment_bla[0]);
//         log_debug("[http2] ------------ first char bla in 1 spot is %c", http2_transaction->request_fragment_bla[1]);
//         log_debug("[http2] ------------ first char bla in 2 spot is %c", http2_transaction->request_fragment_bla[2]);
//         log_debug("[http2] ------------ first char bla in 3 spot is %c", http2_transaction->request_fragment_bla[3]);
//         log_debug("[http2] ------------ first char bla in 4 spot is %c", http2_transaction->request_fragment_bla[4]);
//         log_debug("[http2] ------------ first char bla in 5 spot is %c", http2_transaction->request_fragment_bla[5]);
//         log_debug("[http2] ------------ first char bla in 6 spot is %c", http2_transaction->request_fragment_bla[6]);
//         log_debug("[http2] ------------ first char bla in 7 spot is %c", http2_transaction->request_fragment_bla[7]);
//         log_debug("[http2] ------------ first char bla in 8 spot is %c", http2_transaction->request_fragment_bla[8]);
//         log_debug("[http2] ------------ first char bla in 9 spot is %c", http2_transaction->request_fragment_bla[9]);
//         log_debug("[http2] ------------ first char bla in 10 spot is %c", http2_transaction->request_fragment_bla[10]);
//         log_debug("[http2] ------------ first char bla in 11 spot is %c", http2_transaction->request_fragment_bla[11]);
//         log_debug("[http2] ------------ first char bla in 12 spot is %c", http2_transaction->request_fragment_bla[12]);
//         log_debug("[http2] ------------ first char bla in 13 spot is %c", http2_transaction->request_fragment_bla[13]);
//         log_debug("[http2] ------------ first char bla in 14 spot is %c", http2_transaction->request_fragment_bla[14]);
//
//    bpf_memcpy(dynamic_value.value.path_buffer, beginning, HTTP2_MAX_PATH_LEN);
//    log_debug("[http2] ------------ first char for the dynamic table in 0 spot is %c", dynamic_value.value.path_buffer[0]);
//    dynamic_value.index = index;
//    log_debug("[http2] ------------ first index for the dynamic value is %d", dynamic_value.index);
//
//     // static table index starts from index 62
////        __u64 index2 = (__u64)(static_value->name + 62);
//    log_debug("[http2] ------------ the internal_dynamic_counter  %d", http2_transaction->internal_dynamic_counter);
//
//    bpf_map_update_elem(&http2_dynamic_table, &http2_transaction->internal_dynamic_counter, &dynamic_value, BPF_ANY);
//
//    http2_transaction->internal_dynamic_counter += 1;
//    log_debug("[http2] ------------ the internal_dynamic_counter is %d", http2_transaction->internal_dynamic_counter);
//
//    // index 5 represents the :path header - from static table
//    if ((index == 5) && (sizeof(http2_transaction->request_fragment_bla)>0)){
//        bpf_memcpy(http2_transaction->path, http2_transaction->request_fragment_bla, HTTP2_MAX_PATH_LEN);
//    }
//
//    // index 1 represents the :authority header
//    if ((index == 1) && (sizeof(http2_transaction->request_fragment_bla)>0)){
//        bpf_memcpy(http2_transaction->authority, http2_transaction->request_fragment_bla, HTTP2_MAX_PATH_LEN);
//    }

//        __u64 currnet_blabla = http2_transaction->internal_dynamic_counter - 1;
//        dynamic_table_value *dynamic_value_new = bpf_map_lookup_elem(&http2_dynamic_table, &currnet_blabla);
//
//        if (dynamic_value_new != NULL) {
//            log_debug("[http2] ******************** the dynamic2 index is %d", dynamic_value_new->index);
//            log_debug("[http2] ******************** the dynamic value in spot 0 is %c", dynamic_value_new->value.path_buffer[0]);
//            log_debug("[http2] ******************** the dynamic value in spot 2 is %c", dynamic_value_new->value.path_buffer[2]);
//        } else {
//            log_debug("[http2] ******************** UNABLE TO FIND THE DYNAMIC VALUE IN THE TABLE!!!");
//        }
//
//    http2_transaction->current_offset_in_request_fragment += str_len;
//
//        if (http2_transaction->current_offset_in_request_fragment > sizeof(http2_transaction->request_fragment)) {
//            return ;
//        }
//        __u8 current_char = *(http2_transaction->request_fragment + http2_transaction->current_offset_in_request_fragment);
//        log_debug("[http2] ------------ the current char is  %d", current_char);
//        if (current_char > 0) {
//            log_debug("[http2] blblablalbalblabllba");
//        }
//    }
}

// parse_header_field_repr is handling the header frame by bit calculation and is storing the needed data for our
// internal hpack algorithm.
static __always_inline void parse_header_field_repr(http2_transaction_t* http2_transaction, size_t payload_size) {
    __u8 first_char = http2_transaction->request_fragment[http2_transaction->current_offset_in_request_fragment];
//    log_debug("[http2] first char %d", first_char);

    if ((first_char&128) != 0) {
        // Indexed representation.
        // MSB bit set.
        // https://httpwg.org/specs/rfc7541.html#rfc.section.6.1
        parse_field_indexed(http2_transaction);
    } else if ((first_char&192) == 64) {
        // 6.2.1 Literal Header Field with Incremental Indexing
        // top two bits are 10
        // https://httpwg.org/specs/rfc7541.html#rfc.section.6.2.1
        parse_field_literal(http2_transaction, true, payload_size, 6);
    }
//    else if ((first_char&240) == 16) {
//        // 6.2.2 Literal Header Field without Indexing
//        // top four bits are 0000
//        // https://httpwg.org/specs/rfc7541.html#rfc.section.6.2.2
//        log_debug("[http2] first char %d & 240 == 0; calling parse_field_literal", first_char);
//        parse_field_literal(http2_transaction, false, payload_size, 4);
//    }
}

// This function reads the http2 headers frame.
static __always_inline bool decode_http2_headers_frame(http2_transaction_t* http2_transaction, __u32 payload_size) {
// need to come back and understand how many times I will iterate over the current frame
#pragma unroll (HTTP2_MAX_HEADER)
    for (int i = 0; i < HTTP2_MAX_HEADER; i++) {
        if (http2_transaction->current_offset_in_request_fragment > HTTP2_BUFFER_SIZE) {
            return false;
        }
        parse_header_field_repr(http2_transaction, payload_size);
    }

    return true;
}

// This function filters the needed frames from the http2 session.
static __always_inline void process_http2_frames(http2_transaction_t* http2_transaction, struct __sk_buff *skb) {
    struct http2_frame current_frame = {};
    const __u32 skb_len = skb->len;
    // TODO: guy - increase loop
#pragma unroll (HTTP2_MAX_FRAMES)
    // Iterate till max frames to avoid high connection rate.
    for (uint32_t i = 0; i < HTTP2_MAX_FRAMES; ++i) {
        if (http2_transaction->current_offset_in_request_fragment + HTTP2_FRAME_HEADER_SIZE > skb_len) {
            log_debug("[http2] size is too big!");
            return;
        }

        // Load the current frame into http2_frame strct in order to filter the needed frames.
        if (http2_transaction->current_offset_in_request_fragment > HTTP2_BUFFER_SIZE) {
            return;
        }

        if (!read_http2_frame_header(http2_transaction->request_fragment + http2_transaction->current_offset_in_request_fragment, HTTP2_FRAME_HEADER_SIZE, &current_frame)){
            return;
        }
        http2_transaction->current_offset_in_request_fragment += HTTP2_FRAME_HEADER_SIZE;

        if (current_frame.length == 0) {
            continue;
        }

        // Filter all types of frames except header frame.
        if (current_frame.type != kHeadersFrame) {
            http2_transaction->current_offset_in_request_fragment += (__u32)current_frame.length;
            continue;
        }

        // Verify size of pos with max of XX not bigger then the packet.
        if (http2_transaction->current_offset_in_request_fragment + (__u32)current_frame.length > skb_len) {
            return;
        }

        // Load the current frame into http2_frame strct in order to filter the needed frames.
        if (!decode_http2_headers_frame(http2_transaction, current_frame.length)){
            log_debug("[http2] unable to read http2 header frame");
            return;
        }

        http2_transaction->current_offset_in_request_fragment += (__u32)current_frame.length;
    }
}

#endif
