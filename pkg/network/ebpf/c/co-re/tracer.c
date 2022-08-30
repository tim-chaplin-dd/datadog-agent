#include "tracer.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

enum telemetry_counter{tcp_sent_miscounts, missed_tcp_close, udp_send_processed, udp_send_missed};

/* This is a key/value store with the keys being a conn_tuple_t for send & recv calls
 * and the values being conn_stats_ts_t *.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0); // This will get overridden at runtime using max_tracked_connections
    __type(key, conn_tuple_t);
    __type(value, conn_stats_ts_t);
} conn_stats SEC(".maps");

/* This is a key/value store with the keys being a conn_tuple_t (but without the PID being used)
 * and the values being a tcp_stats_t *.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0); // This will get overridden at runtime using max_tracked_connections
    __type(key, conn_tuple_t);
    __type(value, tcp_stats_t);
} tcp_stats SEC(".maps");

/* Will hold the tcp close events
 * The keys are the cpu number and the values a perf file descriptor for a perf event
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tcp_close_event SEC(".maps");

/* We use this map as a container for batching closed tcp connections
 * The key represents the CPU core. Ideally we should use a BPF_MAP_TYPE_PERCPU_HASH map
 * or BPF_MAP_TYPE_PERCPU_ARRAY, but they are not available in
 * some of the Kernels we support (4.4 ~ 4.6)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, batch_t);
} tcp_close_batch SEC(".maps");

/* This map is used for telemetry in kernelspace
 * only key 0 is used
 * value is a telemetry object
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u16);
    __type(value, telemetry_t);
} telemetry SEC(".maps");

static __always_inline bool is_ipv6_enabled() {
    return TRACER_IPV6_ENABLED;
}

/* check if IPs are IPv4 mapped to IPv6 ::ffff:xxxx:xxxx
 * https://tools.ietf.org/html/rfc4291#section-2.5.5
 * the addresses are stored in network byte order so IPv4 adddress is stored
 * in the most significant 32 bits of part saddr_l and daddr_l.
 * Meanwhile the end of the mask is stored in the least significant 32 bits.
 */
static __always_inline bool is_ipv4_mapped_ipv6(u64 saddr_h, u64 saddr_l, u64 daddr_h, u64 daddr_l) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((saddr_h == 0 && ((u32)(saddr_l >> 32) == 0x0000FFFF)) || (daddr_h == 0 && ((u32)(daddr_l >> 32) == 0x0000FFFF)));
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((saddr_h == 0 && ((u32)saddr_l == 0xFFFF0000)) || (daddr_h == 0 && ((u32)daddr_l == 0xFFFF0000)));
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
}

static __always_inline bool check_family(struct sock* sk, u16 expected_family) {
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    return family == expected_family;
}

static __always_inline int read_conn_tuple(conn_tuple_t* t, struct sock* skp, u64 pid_tgid, metadata_mask_t type) {
    t->saddr_h = 0;
    t->saddr_l = 0;
    t->daddr_h = 0;
    t->daddr_l = 0;
    t->sport = 0;
    t->dport = 0;
    t->pid = pid_tgid >> 32;
    t->metadata = type;

    // Retrieve addresses
    if (check_family(skp, AF_INET)) {
        t->metadata |= CONN_V4;
        t->saddr_l = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        t->daddr_l = BPF_CORE_READ(skp, __sk_common.skc_daddr);

        if (!t->saddr_l || !t->daddr_l) {
            log_debug("ERR(read_conn_tuple.v4): src/dst addr not set src:%d,dst:%d\n", t->saddr_l, t->daddr_l);
            return 0;
        }
    } else if (is_ipv6_enabled() && check_family(skp, AF_INET6)) {
        // TODO cleanup? having it split on 64 bits is not nice for kernel reads
        __be32 *v6src = BPF_CORE_READ(skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        __be32 *v6dst = BPF_CORE_READ(skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32);

        bpf_probe_read(&t->saddr_h, sizeof(t->saddr_h), v6src);
        bpf_probe_read(&t->saddr_l, sizeof(t->saddr_l), v6src + sizeof(u64));
        bpf_probe_read(&t->daddr_h, sizeof(t->daddr_h), v6dst);
        bpf_probe_read(&t->daddr_l, sizeof(t->daddr_l), v6dst + sizeof(u64));

//        BPF_CORE_READ_INTO(&t->saddr_h, skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
//        BPF_CORE_READ_INTO(&t->saddr_l, skp, &(__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]));
//        BPF_CORE_READ_INTO(&t->daddr_h, skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
//        BPF_CORE_READ_INTO(&t->daddr_l, skp, &(__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]));

        // We can only pass 4 args to bpf_trace_printk
        // so split those 2 statements to be able to log everything
        if (!(t->saddr_h || t->saddr_l)) {
            log_debug("ERR(read_conn_tuple.v6): src addr not set: src_l:%d,src_h:%d\n",
                t->saddr_l, t->saddr_h);
            return 0;
        }

        if (!(t->daddr_h || t->daddr_l)) {
            log_debug("ERR(read_conn_tuple.v6): dst addr not set: dst_l:%d,dst_h:%d\n",
                t->daddr_l, t->daddr_h);
            return 0;
        }

        // Check if we can map IPv6 to IPv4
        if (is_ipv4_mapped_ipv6(t->saddr_h, t->saddr_l, t->daddr_h, t->daddr_l)) {
            t->metadata |= CONN_V4;
            t->saddr_h = 0;
            t->daddr_h = 0;
            t->saddr_l = (u32)(t->saddr_l >> 32);
            t->daddr_l = (u32)(t->daddr_l >> 32);
        } else {
            t->metadata |= CONN_V6;
        }
    }

    // Retrieve ports
    t->sport = BPF_CORE_READ((struct inet_sock *)skp, inet_sport);
    t->dport = BPF_CORE_READ(skp, __sk_common.skc_dport);
    if (t->sport == 0 || t->dport == 0) {
        log_debug("ERR(read_conn_tuple.v4): src/dst port not set: src:%d, dst:%d\n", t->sport, t->dport);
        return 0;
    }

    // Making ports human-readable
    t->sport = bpf_ntohs(t->sport);
    t->dport = bpf_ntohs(t->dport);

    // Retrieve network namespace id
    t->netns = BPF_CORE_READ(skp, __sk_common.skc_net.net, ns.inum);

    return 1;
}

static __always_inline void update_conn_stats(conn_tuple_t* t, size_t sent_bytes, size_t recv_bytes, u64 ts) {
    conn_stats_ts_t* val;

    // initialize-if-no-exist the connection stat, and load it
    conn_stats_ts_t empty = {};
    bpf_map_update_elem(&conn_stats, t, &empty, BPF_NOEXIST);
    val = bpf_map_lookup_elem(&conn_stats, t);

    // If already in our map, increment size in-place
    if (val != NULL) {
        if (sent_bytes) {
            __sync_fetch_and_add(&val->sent_bytes, sent_bytes);
        }
        if (recv_bytes) {
            __sync_fetch_and_add(&val->recv_bytes, recv_bytes);
        }
        val->timestamp = ts;
    }
}

static __always_inline void update_tcp_stats(conn_tuple_t* t, tcp_stats_t stats) {
    // query stats without the PID from the tuple
    u32 pid = t->pid;
    t->pid = 0;

    // initialize-if-no-exist the connetion state, and load it
    tcp_stats_t empty = {};
    bpf_map_update_elem(&tcp_stats, t, &empty, BPF_NOEXIST);

    tcp_stats_t* val = bpf_map_lookup_elem(&tcp_stats, t);
    t->pid = pid;
    if (val == NULL) {
        return;
    }

    if (stats.retransmits > 0) {
        __sync_fetch_and_add(&val->retransmits, stats.retransmits);
    }

    if (stats.rtt > 0) {
        // For more information on the bit shift operations see:
        // https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
        val->rtt = stats.rtt >> 3;
        val->rtt_var = stats.rtt_var >> 2;
    }

    if (stats.state_transitions > 0) {
        val->state_transitions |= stats.state_transitions;
    }
}

static __always_inline void increment_telemetry_count(enum telemetry_counter counter_name) {
    __u64 key = 0;
    telemetry_t empty = {};
    telemetry_t* val;
    bpf_map_update_elem(&telemetry, &key, &empty, BPF_NOEXIST);
    val = bpf_map_lookup_elem(&telemetry, &key);

    if (val == NULL) {
        return;
    }
    switch (counter_name) {
        case tcp_sent_miscounts:
            __sync_fetch_and_add(&val->tcp_sent_miscounts, 1);
            break;
        case missed_tcp_close:
            __sync_fetch_and_add(&val->missed_tcp_close, 1);
            break;
        case udp_send_processed:
            __sync_fetch_and_add(&val->udp_sends_processed, 1);
            break;
        case udp_send_missed:
            __sync_fetch_and_add(&val->udp_sends_missed, 1);
            break;
    }
    return;
}

static __always_inline void cleanup_tcp_conn(conn_tuple_t* tup) {
    u32 cpu = bpf_get_smp_processor_id();

    // Will hold the full connection data to send through the perf buffer
    tcp_conn_t conn = {};
    bpf_probe_read(&(conn.tup), sizeof(conn_tuple_t), tup);
    tcp_stats_t* tst;
    conn_stats_ts_t* cst;

    // TCP stats don't have the PID
    conn.tup.pid = 0;
    tst = bpf_map_lookup_elem(&tcp_stats, &(conn.tup));
    bpf_map_delete_elem(&tcp_stats, &(conn.tup));
    conn.tup.pid = tup->pid;

    cst = bpf_map_lookup_elem(&conn_stats, &(conn.tup));
    // Delete this connection from our stats map
    bpf_map_delete_elem(&conn_stats, &(conn.tup));

    if (tst != NULL) {
        conn.tcp_stats = *tst;
    }
    conn.tcp_stats.state_transitions |= (1 << TCP_CLOSE);

    if (cst != NULL) {
        cst->timestamp = bpf_ktime_get_ns();
        conn.conn_stats = *cst;
    }

    // Batch TCP closed connections before generating a perf event
    batch_t* batch_ptr = bpf_map_lookup_elem(&tcp_close_batch, &cpu);
    if (batch_ptr == NULL) {
        return;
    }

    // TODO: Can we turn this into a macro based on TCP_CLOSED_BATCH_SIZE?
    switch (batch_ptr->pos) {
    case 0:
        batch_ptr->c0 = conn;
        batch_ptr->pos++;
        return;
    case 1:
        batch_ptr->c1 = conn;
        batch_ptr->pos++;
        return;
    case 2:
        batch_ptr->c2 = conn;
        batch_ptr->pos++;
        return;
    case 3:
        batch_ptr->c3 = conn;
        batch_ptr->pos++;
        return;
    case 4:
        // In this case the batch is ready to be flushed, which we defer to kretprobe/tcp_close
        // in order to cope with the eBPF stack limitation of 512 bytes.
        batch_ptr->c4 = conn;
        batch_ptr->pos++;
        return;
    }

    // If we hit this section it means we had one or more interleaved tcp_close calls.
    // This could result in a missed tcp_close event, so we track it using our telemetry map.
    increment_telemetry_count(missed_tcp_close);
}

static __always_inline int handle_message(conn_tuple_t* t, size_t sent_bytes, size_t recv_bytes) {
    u64 ts = bpf_ktime_get_ns();

    update_conn_stats(t, sent_bytes, recv_bytes, ts);

    return 0;
}

static __always_inline int handle_retransmit(struct sock* sk) {
    conn_tuple_t t = {};
    u64 zero = 0;

    if (!read_conn_tuple(&t, sk, zero, CONN_TYPE_TCP)) {
        return 0;
    }

    tcp_stats_t stats = { .retransmits = 1, .rtt = 0, .rtt_var = 0 };
    update_tcp_stats(&t, stats);

    return 0;
}

static __always_inline void handle_tcp_stats(conn_tuple_t* t, struct sock* sk) {
    u32 rtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);
    u32 rtt_var = BPF_CORE_READ((struct tcp_sock *)sk, rttvar_us);

    tcp_stats_t stats = { .retransmits = 0, .rtt = rtt, .rtt_var = rtt_var };
    update_tcp_stats(t, stats);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe__tcp_sendmsg, struct sock* sk, struct msghdr *msg, size_t size) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kprobe/tcp_sendmsg: pid_tgid: %d, size: %d\n", pid_tgid, size);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    handle_tcp_stats(&t, sk);
    return handle_message(&t, size, 0);
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe__tcp_sendmsg, int ret) {
    log_debug("kretprobe/tcp_sendmsg: return: %d\n", ret);
    // If ret < 0 it means an error occurred but we still counted the bytes as being sent
    // let's increment our miscount count
    if (ret < 0) {
        increment_telemetry_count(tcp_sent_miscounts);
    }

    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kprobe__tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied < 0) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kprobe/tcp_cleanup_rbuf: pid_tgid: %d, copied: %d\n", pid_tgid, copied);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    return handle_message(&t, 0, copied);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe__tcp_close, struct sock *sk, long timeout) {
    conn_tuple_t t = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
#if defined(DEBUG)
    // Get network namespace id
    u32 net_ns_inum = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    log_debug("kprobe/tcp_close: pid_tgid: %d, ns: %d\n", pid_tgid, net_ns_inum);
#endif

    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    cleanup_tcp_conn(&t);
    return 0;
}

SEC("kretprobe/tcp_close")
int BPF_KRETPROBE(kretprobe__tcp_close) {
    u32 cpu = bpf_get_smp_processor_id();
    batch_t* batch_ptr = bpf_map_lookup_elem(&tcp_close_batch, &cpu);
    if (batch_ptr == NULL) {
        return 0;
    }

    if (batch_ptr->pos >= TCP_CLOSED_BATCH_SIZE) {
        // Here we copy the batch data to a variable allocated in the eBPF stack
        // This is necessary for older Kernel versions only (we validated this behavior on 4.4.0),
        // since you can't directly write a map entry to the perf buffer.
        batch_t batch_copy = {};
        __builtin_memcpy(&batch_copy, batch_ptr, sizeof(batch_copy));
        bpf_perf_event_output(ctx, &tcp_close_event, cpu, &batch_copy, sizeof(batch_copy));
        batch_ptr->pos = 0;
    }

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(kprobe__tcp_retransmit_skb, struct sock* sk) {
    log_debug("kprobe/tcp_retransmit\n");

    return handle_retransmit(sk);
}

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)