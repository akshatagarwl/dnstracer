//go:build linux

package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/akshatagarwl/dnstracer/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

type Tracer struct {
	dnsSocket  int
	ringReader *ringbuf.Reader
	perfReader *perf.Reader
	ringObjs   *bpf.BpfRingbufObjects
	perfObjs   *bpf.BpfPerfbufObjects
}

func New(usePerfBuf bool) (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	kernelSupportsRingBuf := features.HaveMapType(ebpf.RingBuf) == nil

	useRingBuf := kernelSupportsRingBuf && !usePerfBuf

	if !kernelSupportsRingBuf && !usePerfBuf {
		useRingBuf = false
	}

	t := &Tracer{}

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

		dnsSocket, err := attachDNSTracer(ringObjs.DnsPacketParser)
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

		dnsSocket, err := attachDNSTracer(perfObjs.DnsPacketParser)
		if err != nil {
			slog.Warn("failed to attach DNS tracer", "error", err)
			t.dnsSocket = -1
		} else {
			t.dnsSocket = dnsSocket
		}
	}

	return t, nil
}

func attachDNSTracer(prog *ebpf.Program) (int, error) {
	fd, err := unix.Socket(syscall.AF_PACKET, unix.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return -1, fmt.Errorf("create raw socket: %w", err)
	}

	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("get interface eth0: %w", err)
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
		case bpf.BpfEventTypeEVENT_TYPE_DNS_QUERY, bpf.BpfEventTypeEVENT_TYPE_DNS_RESPONSE:
			
			// Parse addresses based on IP version
			var srcAddr, dstAddr netip.Addr
			if event.IpVersion == bpf.BpfIpVersionIP_VERSION_IPV4 {
				srcAddr = netip.AddrFrom4([4]byte{byte(event.Addr.Ipv4.Saddr), byte(event.Addr.Ipv4.Saddr >> 8), byte(event.Addr.Ipv4.Saddr >> 16), byte(event.Addr.Ipv4.Saddr >> 24)})
				dstAddr = netip.AddrFrom4([4]byte{byte(event.Addr.Ipv4.Daddr), byte(event.Addr.Ipv4.Daddr >> 8), byte(event.Addr.Ipv4.Daddr >> 16), byte(event.Addr.Ipv4.Daddr >> 24)})
			} else if event.IpVersion == bpf.BpfIpVersionIP_VERSION_IPV6 {
				// Access IPv6 addresses from the union byte array
				// IPv6 source address starts at the beginning of the union
				addrPtr := unsafe.Pointer(&event.Addr)
				srcAddr = netip.AddrFrom16(*(*[16]byte)(addrPtr))
				// IPv6 destination address starts 16 bytes after source
				dstAddr = netip.AddrFrom16(*(*[16]byte)(unsafe.Pointer(uintptr(addrPtr) + 16)))
			} else {
				slog.Error("unsupported IP version", "version", event.IpVersion)
				continue
			}
			
			dnsData := event.DnsData[:event.DnsLen]
			msg := new(dns.Msg)
			if err := msg.Unpack(dnsData); err != nil {
				slog.Error("failed to parse DNS packet", "error", err, 
					"src", net.JoinHostPort(srcAddr.String(), strconv.Itoa(int(event.Sport))),
					"dst", net.JoinHostPort(dstAddr.String(), strconv.Itoa(int(event.Dport))),
					"dns_len", event.DnsLen)
				continue
			}
			
			var questions []string
			var questionTypes []string
			for _, q := range msg.Question {
				questions = append(questions, q.Name)
				questionTypes = append(questionTypes, dns.TypeToString[q.Qtype])
			}
			
			var answers []string
			for _, rr := range msg.Answer {
				switch v := rr.(type) {
				case *dns.A:
					answers = append(answers, v.A.String())
				case *dns.AAAA:
					answers = append(answers, v.AAAA.String())
				case *dns.CNAME:
					answers = append(answers, v.Target)
				case *dns.MX:
					answers = append(answers, strconv.Itoa(int(v.Preference))+" "+v.Mx)
				case *dns.TXT:
					answers = append(answers, strings.Join(v.Txt, " "))
				case *dns.NS:
					answers = append(answers, v.Ns)
				case *dns.PTR:
					answers = append(answers, v.Ptr)
				case *dns.SOA:
					answers = append(answers, v.Ns)
				}
			}
			
			slog.Info("dns",
				"type", event.Header.Type,
				"ip_version", event.IpVersion,
				"src", net.JoinHostPort(srcAddr.String(), strconv.Itoa(int(event.Sport))),
				"dst", net.JoinHostPort(dstAddr.String(), strconv.Itoa(int(event.Dport))),
				"id", msg.Id,
				"question", strings.Join(questions, ", "),
				"qtype", strings.Join(questionTypes, ", "),
				"answer", strings.Join(answers, ", "),
			)

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
