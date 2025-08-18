#pragma once

enum event_type {
  EVENT_TYPE_DNS_QUERY = 1,
  EVENT_TYPE_DNS_RESPONSE = 2,
};

struct trace_event_header {
  enum event_type type;
  u64 timestamp;
};

struct dns_event {
  struct trace_event_header header;
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u16 dns_len;
  u8 dns_data[512];
};

const struct dns_event *unused_dns __attribute__((unused));

