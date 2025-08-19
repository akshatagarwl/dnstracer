//go:build ignore

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -cc clang -cflags "-O2 -g -Wall -I../../bpf -I../../bpf/include" -type event_type -type trace_event_header -type dns_event -target amd64,arm64 Bpf ../../bpf/tracer.bpf.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -cc clang -cflags "-O2 -g -Wall -I../../bpf -I../../bpf/include -DUSE_RING_BUF" -no-global-types -target amd64,arm64 BpfRingbuf ../../bpf/tracer.bpf.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -cc clang -cflags "-O2 -g -Wall -I../../bpf -I../../bpf/include" -no-global-types -target amd64,arm64 BpfPerfbuf ../../bpf/tracer.bpf.c
