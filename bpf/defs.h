#pragma once

enum event_type {
  EVENT_TYPE_DNS_QUERY = 1,
  EVENT_TYPE_DNS_RESPONSE = 2,
};

enum ip_version {
  IP_VERSION_IPV4 = 4,
  IP_VERSION_IPV6 = 6,
};

struct trace_event_header {
  enum event_type type;
  u64 timestamp;
};

struct dns_event {
  struct trace_event_header header;
  enum ip_version ip_version;
  union {
    struct {
      u32 saddr;
      u32 daddr;
    } ipv4;
    struct {
      u8 saddr[16];
      u8 daddr[16];
    } ipv6;
  } addr;
  u16 sport;
  u16 dport;
  u16 dns_len;
  u8 dns_data[512];
};

const struct dns_event *unused_dns __attribute__((unused));

