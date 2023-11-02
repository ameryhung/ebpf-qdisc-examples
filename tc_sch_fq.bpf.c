#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>

#define ORPHAN_MASK 1023
#define TC_PRIO_CONTROL  7
#define TC_PRIO_MAX  15

#define PSCHED_MTU 64 * 1024 + 14

#define NUM_QUEUE_LOG 10
#define NUM_QUEUE (1 << NUM_QUEUE_LOG)

#define COMP_DROP_PKT_DELAY 0

#define NS_PER_SEC              1000000000

#define FQ_PLIMIT               10000
#define FQ_FLOW_PLIMIT          1000
#define FQ_QUANTUM              2 * PSCHED_MTU
#define FQ_INITIAL_QUANTUM      10 * PSCHED_MTU
#define FQ_HORIZON              NS_PER_SEC * 10ULL
#define FQ_HORIZON_DROP         1
#define FQ_FLOW_REFILL_DELAY    40 * 10000

unsigned int fq_qlen = 0;
unsigned long ktime_cache = 0;
unsigned long time_next_delayed_flow = ~0ULL;
unsigned long unthrottle_latency_ns = 0ULL;

struct skb_node {
        u64 tstamp;
        struct sk_buff __kptr *skb;
        struct bpf_rb_node node;
};

struct fq_flow_node {
        u32 hash;
        int credit;
        u32 qlen;
        u16 is_detached;
        u64 age;
        u64 time_next_packet;
        struct bpf_rb_node rb_node;
        struct bpf_list_node list_node;
        struct bpf_rb_root queue __contains(skb_node, node);
        struct bpf_spin_lock lock;
        struct bpf_refcount refcount;
};

static bool skbn_tstamp_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
        struct skb_node *node_a;
        struct skb_node *node_b;

        node_a = container_of(a, struct skb_node, node);
        node_b = container_of(b, struct skb_node, node);

        return node_a->tstamp < node_b->tstamp;
}

static bool fn_time_next_packet_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
        struct fq_flow_node *node_a;
        struct fq_flow_node *node_b;

        node_a = container_of(a, struct fq_flow_node, rb_node);
        node_b = container_of(b, struct fq_flow_node, rb_node);

        return node_a->time_next_packet < node_b->time_next_packet;
}

struct unset_throttled_flows_ctx {
        u64 now;
};

struct dequeue_nonprio_ctx {
        struct sk_buff __kptr *skb;
        u64 delay;
        u64 now;
};

struct fq_stashed_flow {
        struct fq_flow_node __kptr *node;
        bool is_created;
};

/* [NUM_QUEUE] for TC_PRIO_CONTROL
 * [0, NUM_QUEUE - 1] for others
 */
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct fq_stashed_flow);
        __uint(max_entries, NUM_QUEUE + 1);
} fq_stashed_flows SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, __u64);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, 16);
} rate_map SEC(".maps");

#ifdef COMP_DROP_PKT_DELAY
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, __u64);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, 16);
} comp_map SEC(".maps");
#endif

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(A) struct bpf_spin_lock fq_delayed_lock;
private(A) struct bpf_rb_root fq_delayed __contains(fq_flow_node, rb_node);

private(B) struct bpf_spin_lock fq_new_flows_lock;
private(B) struct bpf_list_head fq_new_flows __contains(fq_flow_node, list_node);

private(C) struct bpf_spin_lock fq_old_flows_lock;
private(C) struct bpf_list_head fq_old_flows __contains(fq_flow_node, list_node);

struct sk_buff *bpf_skb_acquire(struct sk_buff *p) __ksym;
void bpf_skb_release(struct sk_buff *p) __ksym;
u32 bpf_skb_get_hash(struct sk_buff *p) __ksym;

static inline int hash_ptr(u64 val, int bits)
{
        return val * 0x61C8864680B583EBull >> (64 - bits);
}

void fq_flows_add_head(struct bpf_list_head *head, struct bpf_spin_lock *lock,
                      struct fq_flow_node *flow)
{
        bpf_spin_lock(lock);
        bpf_list_push_front(head, &flow->list_node);
        bpf_spin_unlock(lock);
}

void fq_flows_add_tail(struct bpf_list_head *head, struct bpf_spin_lock *lock,
                      struct fq_flow_node *flow)
{
        bpf_spin_lock(lock);
        bpf_list_push_back(head, &flow->list_node);
        bpf_spin_unlock(lock);
}

bool fq_flows_is_empty(struct bpf_list_head *head, struct bpf_spin_lock *lock)
{
        struct bpf_list_node *node;

        bpf_spin_lock(lock);
        node = bpf_list_pop_front(head);
        if (node) {
                bpf_list_push_front(head, node);
                bpf_spin_unlock(lock);
                return false;
        }
        bpf_spin_unlock(lock);

        return true;
}

int fq_new_stashed_flow(struct fq_stashed_flow* sflow, u32 hash)
{
        struct fq_flow_node *flow;
        struct fq_stashed_flow new_sflow = {
                .node = NULL,
                .is_created = 0,
        };

        if (!sflow)
                return -1; //unexpected

        flow = bpf_obj_new(typeof(*flow));
        if (!flow)
                return -1;

        sflow->is_created = true;

        flow->hash = hash;
        flow->credit = FQ_INITIAL_QUANTUM;
        flow->qlen = 0;
        flow->is_detached = 1;
        flow->time_next_packet = 0;

        flow = bpf_kptr_xchg(&sflow->node, flow);
        if (flow) {
                bpf_obj_drop(flow); //unexpected
                return -1;
        }

        return 0;
}

bool sk_listener(struct sock *sk)
{
        return (1 << sk->__sk_common.skc_state) & (TCPF_LISTEN | TCPF_NEW_SYN_RECV);
}

void fq_classify(struct sk_buff *skb, u32 *hash, struct fq_stashed_flow **sflow)
{
        int err;
        u32 skc_hash;
        struct sock *sk = skb->sk;

        if ((skb->priority & TC_PRIO_MAX) == TC_PRIO_CONTROL) {
                *hash = NUM_QUEUE + 1;
                return;
        } else {
                if (!sk || sk_listener(sk)) {
                        *hash = bpf_skb_get_hash(skb) & ORPHAN_MASK;
                } else if (sk->__sk_common.skc_state == TCP_CLOSE) {
                        *hash = bpf_skb_get_hash(skb) & ORPHAN_MASK;
                } else {
                        skc_hash = sk->__sk_common.skc_hash;
                        *hash = hash_ptr(skc_hash, NUM_QUEUE_LOG);
                }
        }

        *sflow = bpf_map_lookup_elem(&fq_stashed_flows, hash);
        return;
}

bool fq_packet_beyond_horizon(struct sk_buff *skb)
{
        return (s64)skb->tstamp > (s64)(ktime_cache + FQ_HORIZON);
}

static void skb_write_fq_cb(struct sk_buff *skb, void *src, u32 size, u32 off)
{
        unsigned int i = 0;

#pragma unroll
        for (int i = 0; i < size; i++)
                skb->cb[off + i] = *((char *)src + i);
}


SEC("qdisc/enqueue")
int enqueue_prog(struct sch_bpf_ctx *ctx)
{
        u64 time_to_send, jiffies, delay_ns, *comp_ns, *rate;
        struct fq_flow_node *flow = NULL, *flow_copy;
        struct sk_buff *old, *skb = ctx->skb;
        struct fq_stashed_flow *sflow;
        struct bpf_rb_node *node;
        struct skb_node *skbn;
        u32 hash, plen, daddr;
        void *flow_queue;
        long err;
        void *data = (void *)(unsigned long long)skb->data;
        void *daddr_p = data + sizeof(struct ethhdr) + offsetof(struct iphdr, daddr);
        struct fq_stashed_flow new_flow_val = {
                .node = NULL,
                .is_created = 0,
        };

        if (fq_qlen >= FQ_PLIMIT)
                goto drop;

        skb = bpf_skb_acquire(ctx->skb);
        if (!skb->tstamp) {
                time_to_send = ktime_cache = bpf_ktime_get_ns();
        } else {
                if (fq_packet_beyond_horizon(skb)) {
                        ktime_cache = bpf_ktime_get_ns();
                        if (fq_packet_beyond_horizon(skb)) {
                                if (FQ_HORIZON_DROP) {
                                        goto rel_and_drop;
                                }
                                skb->tstamp = ktime_cache + FQ_HORIZON;
                        }
                }
                time_to_send = skb->tstamp;
        }
        skb_write_fq_cb(skb, &time_to_send, sizeof(time_to_send), 8);

        fq_classify(skb, &hash, &sflow);
        if (hash != NUM_QUEUE + 1) {
                if (!sflow || !sflow->is_created) {
                        err = fq_new_stashed_flow(sflow, hash);
                        if (err)
                                goto rel_and_drop;
                }

                flow = bpf_kptr_xchg(&sflow->node, flow);
                if (!flow)
                        goto rel_and_drop; //unexpected

                if (flow->is_detached == 1) {
                        flow_copy = bpf_refcount_acquire(flow);
                        flow_copy->is_detached = 0;

                        jiffies = bpf_jiffies64();
                        if ((s64)(jiffies - (flow_copy->age + FQ_FLOW_REFILL_DELAY)) > 0) {
                                if (flow_copy->credit < FQ_QUANTUM)
                                        flow_copy->credit = FQ_QUANTUM;
                        }
                        fq_flows_add_tail(&fq_new_flows, &fq_new_flows_lock, flow_copy);
                }

                skbn = bpf_obj_new(typeof(*skbn));
                if (!skbn) {
                        flow = bpf_kptr_xchg(&sflow->node, flow);
                        if (flow) {
                                bpf_obj_drop(flow);
                        }
                        goto rel_and_drop;
                }

                skbn->tstamp = time_to_send;
                skbn->skb = skb;

                bpf_spin_lock(&flow->lock);
                bpf_rbtree_add(&flow->queue, &skbn->node, skbn_tstamp_less);
                bpf_spin_unlock(&flow->lock);

                flow->qlen++;
                flow = bpf_kptr_xchg(&sflow->node, flow);
                if (flow) {
                        bpf_obj_drop(flow);
                }
        }

        bpf_skb_release(skb);
        fq_qlen++;
        return SCH_BPF_QUEUED;
rel_and_drop:
        bpf_skb_release(skb);
drop:
#ifdef COMP_DROP_PKT_DELAY
        bpf_probe_read_kernel(&plen, sizeof(plen), (void *)(ctx->skb->cb));
        bpf_probe_read_kernel(&daddr, sizeof(daddr), daddr_p);
        rate = bpf_map_lookup_elem(&rate_map, &daddr);
        comp_ns = bpf_map_lookup_elem(&comp_map, &daddr);
        if (rate && comp_ns) {
                delay_ns = (u64)plen * NS_PER_SEC / (*rate);
                __sync_fetch_and_add(comp_ns, delay_ns);
        }
#endif
        return SCH_BPF_DROP;
}


static __u64
fq_unset_throttled_flows(u32 index, struct unset_throttled_flows_ctx *ctx)
{
        struct bpf_rb_node *node = NULL;
        struct fq_flow_node *flow;
        u32 hash;

        bpf_spin_lock(&fq_delayed_lock);

        node = bpf_rbtree_first(&fq_delayed);
        if (!node) {
                bpf_spin_unlock(&fq_delayed_lock);
                return 1;
        }

        flow = container_of(node, struct fq_flow_node, rb_node);
        if (flow->time_next_packet > ctx->now) {
                time_next_delayed_flow = flow->time_next_packet;
                bpf_spin_unlock(&fq_delayed_lock);
                return 1;
        }

        node = bpf_rbtree_remove(&fq_delayed, &flow->rb_node);

        bpf_spin_unlock(&fq_delayed_lock);

        if (!node)
                return 1; //unexpected

        flow = container_of(node, struct fq_flow_node, rb_node);
        flow->is_detached = 0;
        fq_flows_add_tail(&fq_old_flows, &fq_old_flows_lock, flow);

        return 0;
}

inline static void fq_flow_set_throttled(struct fq_flow_node *flow)
{
        if (time_next_delayed_flow > flow->time_next_packet)
                time_next_delayed_flow = flow->time_next_packet;

        bpf_spin_lock(&fq_delayed_lock);
        bpf_rbtree_add(&fq_delayed, &flow->rb_node, fn_time_next_packet_less);
        bpf_spin_unlock(&fq_delayed_lock);
}

static void fq_check_throttled(u64 now)
{
        unsigned long sample;
        struct unset_throttled_flows_ctx cb_ctx = {
                .now = now,
        };

        if (time_next_delayed_flow > now)
                return;

        sample = (unsigned long)(now - time_next_delayed_flow);
        unthrottle_latency_ns -= unthrottle_latency_ns >> 3;
        unthrottle_latency_ns += sample >> 3;

        time_next_delayed_flow = ~0ULL;
        bpf_loop(NUM_QUEUE, fq_unset_throttled_flows, &cb_ctx, 0);
}

void fq_flow_set_detached(struct fq_flow_node *flow)
{
        flow->age = bpf_jiffies64();
        flow->is_detached = 1;
        bpf_obj_drop(flow);
}

static __u64
fq_dequeue_nonprio(u32 index, struct dequeue_nonprio_ctx *ctx)
{
        struct bpf_list_head *head;
        struct bpf_spin_lock *lock;
        struct bpf_list_node *node;
        struct fq_flow_node *flow;
        struct bpf_rb_node *rb_node;
        struct skb_node *skbn;
        u64 time_next_packet, time_to_send;
        u64 skb_p, qdisc_cb_p;
        u32 hash, plen;
        bool is_empty;

        head = &fq_new_flows;
        lock = &fq_new_flows_lock;
        bpf_spin_lock(&fq_new_flows_lock);
        node = bpf_list_pop_front(&fq_new_flows);
        bpf_spin_unlock(&fq_new_flows_lock);
        if (!node) {
                head = &fq_old_flows;
                lock = &fq_old_flows_lock;
                bpf_spin_lock(&fq_old_flows_lock);
                node = bpf_list_pop_front(&fq_old_flows);
                bpf_spin_unlock(&fq_old_flows_lock);
                if (!node) {
                        if (time_next_delayed_flow != ~0ULL)
                                ctx->delay = time_next_delayed_flow;
                        return 1;
                }
        }

        flow = container_of(node, struct fq_flow_node, list_node);
        if (flow->credit <= 0) {
                flow->credit += FQ_QUANTUM;
                fq_flows_add_tail(&fq_old_flows, &fq_old_flows_lock, flow);
                return 0;
        }

        bpf_spin_lock(&flow->lock);
        rb_node = bpf_rbtree_first(&flow->queue);
        if (!rb_node) {
                bpf_spin_unlock(&flow->lock);
                is_empty = fq_flows_is_empty(&fq_old_flows, &fq_old_flows_lock);
                if (head == &fq_new_flows && !is_empty) {
                        fq_flows_add_tail(&fq_old_flows, &fq_old_flows_lock, flow);
                } else {
                        fq_flow_set_detached(flow);
                }
                return 0;
        }

        skbn = container_of(rb_node, struct skb_node, node);
        rb_node = bpf_rbtree_remove(&flow->queue, &skbn->node);
        skb_p = (u64)skbn->skb;
        qdisc_cb_p = skb_p + offsetof(struct sk_buff, cb);
        bpf_spin_unlock(&flow->lock);

        if (!rb_node) {
                fq_flows_add_tail(head, lock, flow);
                return 0; //unexpected
        }

        bpf_probe_read_kernel(&time_to_send, sizeof(time_to_send),
                              (void *)(qdisc_cb_p + 8));
        time_next_packet = (time_to_send > flow->time_next_packet)?
                time_to_send : flow->time_next_packet;
        if (ctx->now < time_next_packet - 1) {
                bpf_spin_lock(&flow->lock);
                bpf_rbtree_add(&flow->queue, rb_node, skbn_tstamp_less);
                bpf_spin_unlock(&flow->lock);
                flow->time_next_packet = time_next_packet;
                fq_flow_set_throttled(flow);
                return 0;
        }

        bpf_probe_read_kernel(&plen, sizeof(plen), (void *)qdisc_cb_p);

        flow->credit -= plen;
        flow->qlen--;

        ctx->skb = (struct sk_buff *)skb_p;
        skbn = container_of(rb_node, struct skb_node, node);
        bpf_obj_drop(skbn);
        fq_flows_add_head(head, lock, flow);
        fq_qlen--;

        return 1;
}

u64 fq_dequeue_prio()
{
        struct bpf_rb_node *node;
        struct skb_node *skbn;
        struct fq_flow_node *flow = NULL;
        struct fq_stashed_flow *sflow;
        u32 internal_hash = NUM_QUEUE;
        u64 skb;

        sflow = bpf_map_lookup_elem(&fq_stashed_flows, &internal_hash);
        if (!sflow)
                return 0; //unexpected

        flow = bpf_kptr_xchg(&sflow->node, flow);
        if (!flow)
                return 0;

        bpf_spin_lock(&flow->lock);
        node = bpf_rbtree_first(&flow->queue);
        if (!node) {
                bpf_spin_unlock(&flow->lock);
                flow = bpf_kptr_xchg(&sflow->node, flow);
                if (flow)
                        bpf_obj_drop(flow);
                return 0;
        }

        skbn = container_of(node, struct skb_node, node);
        skb = (u64)skbn->skb;
        node = bpf_rbtree_remove(&flow->queue, &skbn->node);
        bpf_spin_unlock(&flow->lock);

        fq_qlen--;

        if (node) {
                skbn = container_of(node, struct skb_node, node);
                bpf_obj_drop(skbn);
        }

        flow = bpf_kptr_xchg(&sflow->node, flow);
        if (flow)
                bpf_obj_drop(flow); //unexpected

        return skb;
}


SEC("qdisc/dequeue")
int dequeue_prog(struct sch_bpf_ctx *ctx)
{
        u64 now, skb;
        struct dequeue_nonprio_ctx cb_ctx = {
                .skb = NULL,
                .delay = 0,
        };

        skb = fq_dequeue_prio();
        if (skb) {
                ctx->skb = (struct sk_buff*)skb;
                return SCH_BPF_DEQUEUED;
        }

        ktime_cache = now = bpf_ktime_get_ns();
        fq_check_throttled(now);

        cb_ctx.now = now;
        bpf_loop(FQ_PLIMIT, fq_dequeue_nonprio, &cb_ctx, 0);

        if (cb_ctx.skb) {
                ctx->skb = cb_ctx.skb;
                return SCH_BPF_DEQUEUED;
        }

        if (cb_ctx.delay) {
                ctx->expire = cb_ctx.delay;
                return SCH_BPF_THROTTLE;
        }
        return SCH_BPF_DROP;
}

char _license[] SEC("license") = "GPL";
