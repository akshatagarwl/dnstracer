#pragma once

static __always_inline void fill_event_header(struct trace_event_header *h,
                                              enum event_type type) {
  h->type = type;
  h->timestamp = bpf_ktime_get_ns();
}

static __always_inline struct dns_event *reserve_dns_event(void) {
#ifdef USE_RING_BUF
  return bpf_ringbuf_reserve(&events, sizeof(struct dns_event), 0);
#else
  u32 zero = 0;
  return bpf_map_lookup_elem(&dns_heap, &zero);
#endif
}

static __always_inline void send_dns_event(void *ctx, struct dns_event *e) {
#ifdef USE_RING_BUF
  bpf_ringbuf_submit(e, 0);
#else
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(struct dns_event));
#endif
}
