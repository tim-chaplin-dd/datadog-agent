#ifndef __PROTOCOL_CLASSIFICATION_HELPERS_H
#define __PROTOCOL_CLASSIFICATION_HELPERS_H

#include <linux/types.h>

#include "protocol-classification-defs.h"
#include "protocol-classification-maps.h"
#include "bpf_builtins.h"
#include "bpf_telemetry.h"
#include "ip.h"
#include "http2.h"

// Patch to support old kernels that don't contain bpf_skb_load_bytes, by adding a dummy implementation to bypass runtime compilation.
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
long bpf_skb_load_bytes_with_telemetry(const void *skb, u32 offset, void *to, u32 len) {return 0;}
#endif

#define CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, min_buff_size)   \
    if (buf_size < min_buff_size) {                                         \
        return false;                                                       \
    }                                                                       \
                                                                            \
    if (buf == NULL) {                                                      \
        return false;                                                       \
    }                                                                       \

static __inline int32_t read_big_endian_int32(const char* buf) {
    int32_t *val = (int32_t*)buf;
    return bpf_ntohl(*val);
}

static __inline int16_t read_big_endian_int16(const char* buf) {
    int16_t *val = (int16_t*)buf;
    return bpf_ntohs(*val);
}

// Checking if the buffer represents kafka message
static __always_inline bool is_kafka(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, KAFKA_MIN_SIZE)

    const int32_t message_size = read_big_endian_int32(buf);
    size_t offset = sizeof(message_size);

    if (message_size <= 0) {
        return false;
    }

    const int16_t request_api_key = read_big_endian_int16(buf + offset);
    offset += sizeof(request_api_key);
    if (request_api_key != 0 && request_api_key != 1) {
        return false;
    }

    const int16_t request_api_version = read_big_endian_int16(buf + offset);
    offset += sizeof(request_api_version);
    if (request_api_version < 0) {
        return false;
    }

    if (request_api_key == 0) {
        if (message_size < KAFKA_MIN_SIZE + 6) {
            return false;
        }
        if (request_api_version > 9) {
            return false;
        }
    }
    if (request_api_key == 1) {
        if (message_size < KAFKA_MIN_SIZE + 12) {
            return false;
        }
        if (request_api_version > 13) {
            return false;
        }
    }

    const int32_t correlation_id = read_big_endian_int32(buf + offset);
    log_debug("guy_ %d %d", message_size, correlation_id);
    log_debug("guy$ %d %d", request_api_key, request_api_version);
    return correlation_id > 0;
}

static __always_inline bool is_http2_server_settings(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, 15)

    struct http2_frame frame_header;
    if (!read_http2_frame_header(buf, buf_size, &frame_header)) {
        return false;
    }

    return frame_header.type == kSettingsFrame && frame_header.stream_id == 0 && frame_header.length == 6;
}

// The method checks if the given buffer starts with the HTTP2 marker as defined in https://datatracker.ietf.org/doc/html/rfc7540.
// We check that the given buffer is not empty and its size is at least 24 bytes.
static __always_inline bool is_http2(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, HTTP2_MARKER_SIZE)

#define HTTP2_SIGNATURE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    bool match = !bpf_memcmp(buf, HTTP2_SIGNATURE, sizeof(HTTP2_SIGNATURE)-1);

    return match;
}

// Checks if the given buffers start with `HTTP` prefix (represents a response) or starts with `<method> /` which represents
// a request, where <method> is one of: GET, POST, PUT, DELETE, HEAD, OPTIONS, or PATCH.
static __always_inline bool is_http(const char *buf, __u32 size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, size, HTTP_MIN_SIZE)

#define HTTP "HTTP/"
#define GET "GET /"
#define POST "POST /"
#define PUT "PUT /"
#define DELETE "DELETE /"
#define HEAD "HEAD /"
#define OPTIONS1 "OPTIONS /"
#define OPTIONS2 "OPTIONS *"
#define PATCH "PATCH /"

    // memcmp returns
    // 0 when s1 == s2,
    // !0 when s1 != s2.
    bool http = !(bpf_memcmp(buf, HTTP, sizeof(HTTP)-1)
        && bpf_memcmp(buf, GET, sizeof(GET)-1)
        && bpf_memcmp(buf, POST, sizeof(POST)-1)
        && bpf_memcmp(buf, PUT, sizeof(PUT)-1)
        && bpf_memcmp(buf, DELETE, sizeof(DELETE)-1)
        && bpf_memcmp(buf, HEAD, sizeof(HEAD)-1)
        && bpf_memcmp(buf, OPTIONS1, sizeof(OPTIONS1)-1)
        && bpf_memcmp(buf, OPTIONS2, sizeof(OPTIONS2)-1)
        && bpf_memcmp(buf, PATCH, sizeof(PATCH)-1));

    return http;
}

// Determines the protocols of the given buffer. If we already classified the payload (a.k.a protocol out param
// has a known protocol), then we do nothing.
static __always_inline void classify_protocol(protocol_t *protocol, const char *buf, __u32 size) {
    if (protocol == NULL || *protocol != PROTOCOL_UNKNOWN) {
        return;
    }

    if (is_http(buf, size)) {
        *protocol = PROTOCOL_HTTP;
    } else if (is_http2(buf, size)) {
        *protocol = PROTOCOL_HTTP2;
    } else if (is_http2_server_settings(buf, size)) {
        *protocol = PROTOCOL_HTTP2;
    } else if (is_kafka(buf, size)) {
        *protocol = PROTOCOL_KAFKA;
    } else {
        *protocol = PROTOCOL_UNKNOWN;
    }

    log_debug("[protocol classification]: Classified protocol as %d %d; %s\n", *protocol, size, buf);
}

// Decides if the protocol_classifier should process the packet. We process not empty TCP packets.
static __always_inline bool should_process_packet(struct __sk_buff *skb, skb_info_t *skb_info, conn_tuple_t *tup) {
    // we're only interested in TCP traffic
    if (!(tup->metadata & CONN_TYPE_TCP)) {
        return false;
    }

    bool empty_payload = skb_info->data_off == skb->len;
    return !empty_payload;
}

// The method is used to read the data buffer from the __sk_buf struct. Similar implementation as `read_into_buffer_skb`
// from http parsing, but uses a different constant (CLASSIFICATION_MAX_BUFFER).
static __always_inline void read_into_buffer_for_classification(char *buffer, struct __sk_buff *skb, skb_info_t *info) {
    u64 offset = (u64)info->data_off;

#define BLK_SIZE (16)
    const u32 len = CLASSIFICATION_MAX_BUFFER < (skb->len - (u32)offset) ? (u32)offset + CLASSIFICATION_MAX_BUFFER : skb->len;

    unsigned i = 0;

#pragma unroll(CLASSIFICATION_MAX_BUFFER / BLK_SIZE)
    for (; i < (CLASSIFICATION_MAX_BUFFER / BLK_SIZE); i++) {
        if (offset + BLK_SIZE - 1 >= len) { break; }

        bpf_skb_load_bytes_with_telemetry(skb, offset, &buffer[i * BLK_SIZE], BLK_SIZE);
        offset += BLK_SIZE;
    }

    // This part is very hard to write in a loop and unroll it.
    // Indeed, mostly because of older kernel verifiers, we want to make sure the offset into the buffer is not
    // stored on the stack, so that the verifier is able to verify that we're not doing out-of-bound on
    // the stack.
    // Basically, we should get a register from the code block above containing an fp relative address. As
    // we are doing `buffer[0]` here, there is not dynamic computation on that said register after this,
    // and thus the verifier is able to ensure that we are in-bound.
    void *buf = &buffer[i * BLK_SIZE];
    if (offset + 14 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 15);
    } else if (offset + 13 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 14);
    } else if (offset + 12 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 13);
    } else if (offset + 11 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 12);
    } else if (offset + 10 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 11);
    } else if (offset + 9 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 10);
    } else if (offset + 8 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 9);
    } else if (offset + 7 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 8);
    } else if (offset + 6 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 7);
    } else if (offset + 5 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 6);
    } else if (offset + 4 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 5);
    } else if (offset + 3 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 4);
    } else if (offset + 2 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 3);
    } else if (offset + 1 < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 2);
    } else if (offset < len) {
        bpf_skb_load_bytes_with_telemetry(skb, offset, buf, 1);
    }
}

static __always_inline protocol_t get_protocol_2(struct __sk_buff *skb, conn_tuple_t *skb_tup_ptr) {
    conn_tuple_t skb_tup = *skb_tup_ptr;
    // The classifier is a socket filter and there we are not accessible for pid and netns.
    // The key is based of the source & dest addresses and ports, and the metadata.
    protocol_t *cached_protocol_ptr = bpf_map_lookup_elem(&connection_protocol, &skb_tup);
    if (cached_protocol_ptr != NULL) {
        log_debug("guy %p get_protocol_2 found from 1; %d", skb, *cached_protocol_ptr);
        return *cached_protocol_ptr;
    }

    conn_tuple_t *cached_socket_conn_tup_ptr = bpf_map_lookup_elem(&skb_conn_tuple_to_socket_conn_tuple, &skb_tup);

    flip_tuple(&skb_tup);
    cached_protocol_ptr = bpf_map_lookup_elem(&connection_protocol, &skb_tup);
    if (cached_protocol_ptr != NULL) {
        log_debug("guy %p get_protocol_2 found from 2; %d", skb, *cached_protocol_ptr);
        return *cached_protocol_ptr;
    }

    if (cached_socket_conn_tup_ptr != NULL) {
        conn_tuple_t socket_conn_tuple = *cached_socket_conn_tup_ptr;
        cached_protocol_ptr = bpf_map_lookup_elem(&connection_protocol, &socket_conn_tuple);
        if (cached_protocol_ptr != NULL) {
            log_debug("guy %p get_protocol_2 found from 3; %d", skb, *cached_protocol_ptr);
            return *cached_protocol_ptr;
        }
    }

    cached_socket_conn_tup_ptr = bpf_map_lookup_elem(&skb_conn_tuple_to_socket_conn_tuple, &skb_tup);
    if (cached_socket_conn_tup_ptr != NULL) {
        conn_tuple_t socket_conn_tuple = *cached_socket_conn_tup_ptr;
        cached_protocol_ptr = bpf_map_lookup_elem(&connection_protocol, &socket_conn_tuple);
        if (cached_protocol_ptr != NULL) {
            log_debug("guy %p get_protocol_2 found from 4; %d", skb, *cached_protocol_ptr);
            return *cached_protocol_ptr;
        }
    }

    log_debug("guy %p get_protocol_2 not found", skb);
    return PROTOCOL_UNKNOWN;
}

// A shared implementation for the runtime & prebuilt socket filter that classifies the protocols of the connections.
static __always_inline void protocol_classifier_entrypoint(struct __sk_buff *skb) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return;
    }

    // We process a non empty TCP packets, rather than that - we skip the packet.
    if (!should_process_packet(skb, &skb_info, &skb_tup)) {
        return;
    }

    protocol_t cur_fragment_protocol = get_protocol_2(skb, &skb_tup);
    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        return;
    }

    char request_fragment[CLASSIFICATION_MAX_BUFFER];
    bpf_memset(request_fragment, 0, sizeof(request_fragment));
    read_into_buffer_for_classification((char *)request_fragment, skb, &skb_info);
    const size_t payload_length = skb->len - skb_info.data_off;
    classify_protocol(&cur_fragment_protocol, request_fragment, payload_length);
    // If there has been a change in the classification, save the new protocol.
    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        log_debug("guy classifying %p as %d", skb, cur_fragment_protocol);
        bpf_map_update_with_telemetry(connection_protocol, &skb_tup, &cur_fragment_protocol, BPF_NOEXIST);
        conn_tuple_t *cached_socket_conn_tup_ptr = bpf_map_lookup_elem(&skb_conn_tuple_to_socket_conn_tuple, &skb_tup);
        if (cached_socket_conn_tup_ptr != NULL) {
            conn_tuple_t socket_conn_tuple = *cached_socket_conn_tup_ptr;
            bpf_map_update_with_telemetry(connection_protocol, &socket_conn_tuple, &cur_fragment_protocol, BPF_NOEXIST);
        }
    }
}

#endif
