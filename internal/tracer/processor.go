//go:build linux

package tracer

import (
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/akshatagarwl/dnstracer/internal/bpf"
	"github.com/miekg/dns"
)

type DNSProcessor interface {
	Process(event *bpf.BpfDnsEvent) error
}

type QueryProcessor struct{}

func NewQueryProcessor() *QueryProcessor {
	return &QueryProcessor{}
}

func (p *QueryProcessor) Process(event *bpf.BpfDnsEvent) error {
	srcAddr := netip.AddrFrom4([4]byte{byte(event.Saddr), byte(event.Saddr >> 8), byte(event.Saddr >> 16), byte(event.Saddr >> 24)})
	dstAddr := netip.AddrFrom4([4]byte{byte(event.Daddr), byte(event.Daddr >> 8), byte(event.Daddr >> 16), byte(event.Daddr >> 24)})

	dnsData := event.DnsData[:event.DnsLen]
	msg := new(dns.Msg)
	if err := msg.Unpack(dnsData); err != nil {
		slog.Error("failed to parse DNS query packet", "error", err,
			"src", net.JoinHostPort(srcAddr.String(), strconv.Itoa(int(event.Sport))),
			"dst", net.JoinHostPort(dstAddr.String(), strconv.Itoa(int(event.Dport))),
			"dns_len", event.DnsLen)
		return err
	}

	var questions []string
	var questionTypes []string
	for _, q := range msg.Question {
		questions = append(questions, q.Name)
		questionTypes = append(questionTypes, dns.TypeToString[q.Qtype])
	}

	slog.Info("dns",
		"type", "query",
		"src", net.JoinHostPort(srcAddr.String(), strconv.Itoa(int(event.Sport))),
		"dst", net.JoinHostPort(dstAddr.String(), strconv.Itoa(int(event.Dport))),
		"id", msg.Id,
		"question", strings.Join(questions, ", "),
		"qtype", strings.Join(questionTypes, ", "),
	)

	return nil
}

type ResponseProcessor struct{}

func NewResponseProcessor() *ResponseProcessor {
	return &ResponseProcessor{}
}

func (p *ResponseProcessor) Process(event *bpf.BpfDnsEvent) error {
	srcAddr := netip.AddrFrom4([4]byte{byte(event.Saddr), byte(event.Saddr >> 8), byte(event.Saddr >> 16), byte(event.Saddr >> 24)})
	dstAddr := netip.AddrFrom4([4]byte{byte(event.Daddr), byte(event.Daddr >> 8), byte(event.Daddr >> 16), byte(event.Daddr >> 24)})

	dnsData := event.DnsData[:event.DnsLen]
	msg := new(dns.Msg)
	if err := msg.Unpack(dnsData); err != nil {
		slog.Error("failed to parse DNS response packet", "error", err,
			"src", net.JoinHostPort(srcAddr.String(), strconv.Itoa(int(event.Sport))),
			"dst", net.JoinHostPort(dstAddr.String(), strconv.Itoa(int(event.Dport))),
			"dns_len", event.DnsLen)
		return err
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
		"type", "response",
		"src", net.JoinHostPort(srcAddr.String(), strconv.Itoa(int(event.Sport))),
		"dst", net.JoinHostPort(dstAddr.String(), strconv.Itoa(int(event.Dport))),
		"id", msg.Id,
		"question", strings.Join(questions, ", "),
		"qtype", strings.Join(questionTypes, ", "),
		"answer", strings.Join(answers, ", "),
	)

	return nil
}
