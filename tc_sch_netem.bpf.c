#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>

unsigned int q_count = 0;
unsigned int q_limit = 1000;

struct skb_node {
        u64 tstamp;
        struct sk_buff __kptr *skb;
        struct bpf_rb_node node;
};

struct clg_state {
        u64 state;
        u32 a1;
        u32 a2;
        u32 a3;
        u32 a4;
        u32 a5;
};

static bool skbn_tstamp_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
        struct skb_node *node_a;
        struct skb_node *node_b;

        node_a = container_of(a, struct skb_node, node);
        node_b = container_of(b, struct skb_node, node);

        return node_a->tstamp < node_b->tstamp;
}

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct clg_state);
        __uint(max_entries, 1);
} g_clg_state SEC(".maps");

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(A) struct bpf_spin_lock t_root_lock;
private(A) struct bpf_rb_root t_root __contains(skb_node, node);

struct sk_buff *bpf_skb_acquire(struct sk_buff *p) __ksym;
void bpf_skb_release(struct sk_buff *p) __ksym;

static bool loss_gilb_ell()
{
        bool ret = false;
        u32 r1, r2, key = 0;
        struct clg_state *clg = bpf_map_lookup_elem(&g_clg_state, &key);
        if (!clg)
                return false;

        r1 = bpf_get_prandom_u32();
        r2 = bpf_get_prandom_u32();

        switch (clg->state) {
        case GOOD_STATE:
                if (r1 < clg->a1) {
                        __sync_val_compare_and_swap(&clg->state, GOOD_STATE, BAD_STATE);
                }
                if (r2 < clg->a4) {
                        ret = true;
                }
                break;
        case BAD_STATE:
                if (r1 < clg->a2) {
                        __sync_val_compare_and_swap(&clg->state, BAD_STATE, GOOD_STATE);
                }
                if (r2 > clg->a3) {
                        ret = true;
                }
        }

        return ret;
}

void tfifo_enqueue(struct skb_node *skbn)
{
        bpf_spin_lock(&t_root_lock);
        bpf_rbtree_add(&t_root, &skbn->node, skbn_tstamp_less);
        bpf_spin_unlock(&t_root_lock);
}

SEC("qdisc/enqueue")
int enqueue_prog(struct sch_bpf_ctx *ctx)
{
        struct sk_buff *old, *skb = ctx->skb;
        struct skb_node *skbn;
        s64 delay = 0;
        int count = 1;
        u64 now;

        if (loss_gilb_ell()) {
                --count;
        }

        if (count == 0) {
                return SCH_BPF_PASS;
        }

        q_count++;
        if (q_count > q_limit)
                return SCH_BPF_DROP;


        skb = bpf_skb_acquire(ctx->skb);
        skbn = bpf_obj_new(typeof(*skbn));
        if (!skbn) {
                bpf_skb_release(skb);
                return SCH_BPF_DROP;
        }

        now = bpf_ktime_get_ns();

        skbn->tstamp = now + delay;
        skbn->skb = skb;

        bpf_skb_release(skb);
        tfifo_enqueue(skbn);

        return SCH_BPF_QUEUED;
}


SEC("qdisc/dequeue")
int dequeue_prog(struct sch_bpf_ctx *ctx)
{
        u64 now;
        struct skb_node *skbn;
        struct bpf_rb_node *node = NULL;

        now = bpf_ktime_get_ns();

        bpf_spin_lock(&t_root_lock);
        node = bpf_rbtree_first(&t_root);
        if (!node) {
                bpf_spin_unlock(&t_root_lock);
                return SCH_BPF_DROP;
        }

        skbn = container_of(node, struct skb_node, node);
        ctx->skb = skbn->skb;
        node = bpf_rbtree_remove(&t_root, &skbn->node);
        bpf_spin_unlock(&t_root_lock);

        if (node) {
            skbn = container_of(node, struct skb_node, node);
            bpf_obj_drop(skbn);
        }

        q_count--;
        return SCH_BPF_DEQUEUED;
}

char _license[] SEC("license") = "GPL";
