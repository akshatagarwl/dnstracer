#ifdef __TARGET_ARCH_x86
#include "vmlinux/x86_64.h"
#else
#include "vmlinux/arm64.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "defs.h"
#include "maps.h"
#include "helpers.h"

char LICENSE[] SEC("license") = "GPL";


static __always_inline int parse_ipv4_dns_packet(struct __sk_buff *skb, struct dns_event *event, u32 offset) {
  struct iphdr ip;
  if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
    return 0;
  offset += ip.ihl * 4;
  
  if (ip.protocol != IPPROTO_UDP) return 0;
  
  struct udphdr udp;
  if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
    return 0;
  offset += sizeof(udp);
  
  if (udp.dest != bpf_htons(53) && udp.source != bpf_htons(53)) return 0;
  
  u16 udp_len = bpf_ntohs(udp.len);
  u16 dns_len = udp_len - sizeof(udp);
  
  if (dns_len > 512) dns_len = 512;
  
  event->ip_version = IP_VERSION_IPV4;
  event->addr.ipv4.saddr = ip.saddr;
  event->addr.ipv4.daddr = ip.daddr;
  event->sport = bpf_ntohs(udp.source);
  event->dport = bpf_ntohs(udp.dest);
  event->dns_len = dns_len;
  
  __builtin_memset(event->dns_data, 0, 512);
  
  if (dns_len > 0 && offset + dns_len <= skb->len) {
    if (bpf_skb_load_bytes(skb, offset, event->dns_data, dns_len) < 0) {
      return 0;
    }
  }
  
  return 1;
}

static __always_inline int parse_ipv6_dns_packet(struct __sk_buff *skb, struct dns_event *event, u32 offset) {
  struct ipv6hdr ip6;
  if (bpf_skb_load_bytes(skb, offset, &ip6, sizeof(ip6)) < 0)
    return 0;
  offset += sizeof(ip6);
  
  if (ip6.nexthdr != IPPROTO_UDP) return 0;
  
  struct udphdr udp;
  if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
    return 0;
  offset += sizeof(udp);
  
  if (udp.dest != bpf_htons(53) && udp.source != bpf_htons(53)) return 0;
  
  u16 udp_len = bpf_ntohs(udp.len);
  u16 dns_len = udp_len - sizeof(udp);
  
  if (dns_len > 512) dns_len = 512;
  
  event->ip_version = IP_VERSION_IPV6;
  __builtin_memcpy(event->addr.ipv6.saddr, &ip6.saddr, 16);
  __builtin_memcpy(event->addr.ipv6.daddr, &ip6.daddr, 16);
  event->sport = bpf_ntohs(udp.source);
  event->dport = bpf_ntohs(udp.dest);
  event->dns_len = dns_len;
  
  __builtin_memset(event->dns_data, 0, 512);
  
  if (dns_len > 0 && offset + dns_len <= skb->len) {
    if (bpf_skb_load_bytes(skb, offset, event->dns_data, dns_len) < 0) {
      return 0;
    }
  }
  
  return 1;
}

static __always_inline int parse_dns_packet(struct __sk_buff *skb, struct dns_event *event) {
  u32 offset = 0;
  
  struct ethhdr eth;
  if (bpf_skb_load_bytes(skb, offset, &eth, sizeof(eth)) < 0)
    return 0;
  offset += sizeof(eth);
  
  if (eth.h_proto == bpf_htons(0x0800)) {
    // IPv4
    return parse_ipv4_dns_packet(skb, event, offset);
  } else if (eth.h_proto == bpf_htons(0x86DD)) {
    // IPv6
    return parse_ipv6_dns_packet(skb, event, offset);
  }
  
  return 0;
}

SEC("socket")
int dns_packet_parser(struct __sk_buff *skb) {
  struct dns_event *e = reserve_dns_event();
  if (!e) return 0;
  
  if (!parse_dns_packet(skb, e)) {
#ifdef USE_RING_BUF
    bpf_ringbuf_discard(e, 0);
#endif
    return 0;
  }
  
  enum event_type event_type = (e->dport == 53) ? EVENT_TYPE_DNS_QUERY : EVENT_TYPE_DNS_RESPONSE;
  fill_event_header(&e->header, event_type);
  
  send_dns_event(skb, e);
  return 0;
}
