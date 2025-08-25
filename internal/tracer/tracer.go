//go:build linux

package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"github.com/akshatagarwl/dnstracer/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type Tracer struct {
	dnsSocket         int
	ringReader        *ringbuf.Reader
	perfReader        *perf.Reader
	ringObjs          *bpf.BpfRingbufObjects
	perfObjs          *bpf.BpfPerfbufObjects
	queryProcessor    DNSProcessor
	responseProcessor DNSProcessor
}

func New(usePerfBuf bool, interfaceName string) (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	kernelSupportsRingBuf := features.HaveMapType(ebpf.RingBuf) == nil

	useRingBuf := kernelSupportsRingBuf && !usePerfBuf

	if !kernelSupportsRingBuf && !usePerfBuf {
		useRingBuf = false
	}

	t := &Tracer{
		queryProcessor:    NewQueryProcessor(),
		responseProcessor: NewResponseProcessor(),
	}

	if useRingBuf {
		ringObjs := &bpf.BpfRingbufObjects{}
		if err := bpf.LoadBpfRingbufObjects(ringObjs, nil); err != nil {
			return nil, fmt.Errorf("load ringbuf objects: %w", err)
		}
		t.ringObjs = ringObjs

		rd, err := ringbuf.NewReader(ringObjs.Events)
		if err != nil {
			ringObjs.Close()
			return nil, fmt.Errorf("new ringbuf reader: %w", err)
		}
		t.ringReader = rd

		dnsSocket, err := attachDNSTracer(ringObjs.DnsPacketParser, interfaceName)
		if err != nil {
			slog.Warn("failed to attach DNS tracer", "error", err)
			t.dnsSocket = -1
		} else {
			t.dnsSocket = dnsSocket
		}
	} else {
		perfObjs := &bpf.BpfPerfbufObjects{}
		if err := bpf.LoadBpfPerfbufObjects(perfObjs, nil); err != nil {
			return nil, fmt.Errorf("load perfbuf objects: %w", err)
		}
		t.perfObjs = perfObjs

		rd, err := perf.NewReader(perfObjs.Events, 4096)
		if err != nil {
			perfObjs.Close()
			return nil, fmt.Errorf("new perf reader: %w", err)
		}
		t.perfReader = rd

		dnsSocket, err := attachDNSTracer(perfObjs.DnsPacketParser, interfaceName)
		if err != nil {
			slog.Warn("failed to attach DNS tracer", "error", err)
			t.dnsSocket = -1
		} else {
			t.dnsSocket = dnsSocket
		}
	}

	return t, nil
}

func attachDNSTracer(prog *ebpf.Program, interfaceName string) (int, error) {
	fd, err := unix.Socket(syscall.AF_PACKET, unix.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return -1, fmt.Errorf("create raw socket: %w", err)
	}

	if interfaceName == "" {
		interfaceName = "eth0"
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("get interface %s: %w", interfaceName, err)
	}

	sockAddr := &unix.SockaddrLinklayer{
		Protocol: 0x0300, // htons(ETH_P_ALL) - network byte order
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sockAddr); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind socket to interface: %w", err)
	}

	const SO_ATTACH_BPF = 50
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("attach bpf to socket: %w", err)
	}

	return fd, nil
}

func (t *Tracer) Run() error {
	slog.Info("tracing events", "message", "press ctrl+c to stop")

	for {
		var rawSample []byte

		if t.ringReader != nil {
			record, readErr := t.ringReader.Read()
			if readErr != nil {
				if errors.Is(readErr, ringbuf.ErrClosed) {
					return nil
				}
				slog.Error("reading event", "error", readErr)
				continue
			}
			rawSample = record.RawSample
		} else {
			for {
				record, readErr := t.perfReader.Read()
				if readErr != nil {
					if errors.Is(readErr, perf.ErrClosed) {
						return nil
					}
					slog.Error("reading event", "error", readErr)
					continue
				}
				if record.LostSamples > 0 {
					slog.Warn("lost samples", "count", record.LostSamples)
					continue
				}
				rawSample = record.RawSample
				break
			}
		}

		if len(rawSample) < 4 {
			slog.Error("event too small", "size", len(rawSample))
			continue
		}

		var event bpf.BpfDnsEvent
		if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("parsing dns event", "error", err)
			continue
		}

		switch event.Header.Type {
		case bpf.BpfEventTypeEVENT_TYPE_DNS_QUERY:
			if err := t.queryProcessor.Process(&event); err != nil {
				slog.Error("processing DNS query", "error", err)
			}
		case bpf.BpfEventTypeEVENT_TYPE_DNS_RESPONSE:
			if err := t.responseProcessor.Process(&event); err != nil {
				slog.Error("processing DNS response", "error", err)
			}
		default:
			slog.Warn("unknown event type", "type", event.Header.Type)
		}
	}
}

func (t *Tracer) Close() error {
	if t.ringReader != nil {
		t.ringReader.Close()
	}
	if t.perfReader != nil {
		t.perfReader.Close()
	}
	if t.dnsSocket != -1 {
		unix.Close(t.dnsSocket)
	}
	if t.ringObjs != nil {
		t.ringObjs.Close()
	}
	if t.perfObjs != nil {
		t.perfObjs.Close()
	}
	return nil
}
