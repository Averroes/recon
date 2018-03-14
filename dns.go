// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package recon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type googleDNSResolve struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	RD       bool `json:"RD"`
	RA       bool `json:"RA"`
	AD       bool `json:"AD"`
	CD       bool `json:"CD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer    []DNSAnswer `json:"Answer"`
	Authority []DNSAnswer `json:"Authority"`
}

type request struct {
	Name   string
	Server string
	Type   uint16
	Ans    chan []DNSAnswer
}

var dnsRequest chan *request

func init() {
	dnsRequest = make(chan *request, 50)

	go dnsQuery()
}

func ResolveDNS(name, server, qtype string) ([]DNSAnswer, error) {
	var qt uint16

	switch qtype {
	case "CNAME":
		qt = dns.TypeCNAME
	case "A":
		qt = dns.TypeA
	case "AAAA":
		qt = dns.TypeAAAA
	case "PTR":
		qt = dns.TypePTR
	case "NS":
		qt = dns.TypeNS
	case "MX":
		qt = dns.TypeMX
	default:
		return []DNSAnswer{}, errors.New("Unsupported DNS type")
	}

	answer := make(chan []DNSAnswer)
	dnsRequest <- &request{
		Name:   name,
		Server: server,
		Type:   qt,
		Ans:    answer,
	}

	a := <-answer
	if len(a) == 0 {
		return []DNSAnswer{}, errors.New("The query was unsuccessful")
	}
	return a, nil
}

// dnsQuery encapsulates all the miekg/dns usage
func dnsQuery() {
	c := new(dns.Client)
	c.Net = "udp"

	for {
		go DNSExchange(c, <-dnsRequest)
	}
}

func DNSExchange(client *dns.Client, req *request) {
	qc := uint16(dns.ClassINET)
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
			Id:                dns.Id(),
			Rcode:             dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{Name: dns.Fqdn(req.Name), Qtype: req.Type, Qclass: qc}

	var answers []DNSAnswer

	r, rtt, err := client.Exchange(m, req.Server)
	if err != nil {
		req.Ans <- answers
		return
	}

	if r != nil && r.Rcode != dns.RcodeSuccess {
		req.Ans <- answers
		return
	}

	var data []string
	for _, a := range r.Answer {
		if a.Header().Rrtype == req.Type {
			switch req.Type {
			case dns.TypeA:
				if ta, ok := a.(*dns.A); ok {
					data = append(data, ta.A.String())
				}
			case dns.TypeAAAA:
				if ta, ok := a.(*dns.AAAA); ok {
					data = append(data, ta.AAAA.String())
				}
			case dns.TypeCNAME:
				if ta, ok := a.(*dns.CNAME); ok {
					data = append(data, ta.Target)
				}
			case dns.TypePTR:
				if ta, ok := a.(*dns.PTR); ok {
					data = append(data, ta.Ptr)
				}
			case dns.TypeNS:
				if ta, ok := a.(*dns.NS); ok {
					data = append(data, ta.Ns)
				}
			case dns.TypeMX:
				if ta, ok := a.(*dns.MX); ok {
					data = append(data, ta.Mx)
				}
			}
		}
	}

	for _, a := range data {
		answers = append(answers, DNSAnswer{
			Name: req.Name,
			Type: int(req.Type),
			TTL:  int(rtt),
			Data: strings.TrimSpace(a),
		})
	}
	req.Ans <- answers
}

func ReverseDNS(ip, server string) (string, error) {
	var name string

	addr := reverseIP(ip) + ".in-addr.arpa"
	answers, err := ResolveDNS(addr, server, "PTR")
	if err == nil {
		if answers[0].Type == 12 {
			l := len(answers[0].Data)

			name = answers[0].Data[:l-1]
		}

		if name == "" {
			err = errors.New("PTR record not found")
		}
	}
	return name, err
}

func GoogleResolveDNS(name, t string) ([]DNSAnswer, error) {
	var answers []DNSAnswer

	u, _ := url.Parse("https://dns.google.com/resolve")
	// Do not send our location information with the query
	u.RawQuery = url.Values{"name": {name}, "type": {t}, "edns_client_subnet": {"0.0.0.0/0"}}.Encode()

	page := GetWebPage(u.String())
	if page == "" {
		return answers, errors.New("Failed to reach the Google DNS service")
	}

	var r googleDNSResolve

	err := json.Unmarshal([]byte(page), &r)
	if err != nil {
		return answers, err
	}

	for _, a := range r.Authority {
		if a.Type == 6 {
			err = errors.New(a.Data)
		} else {
			err = fmt.Errorf("Querying %s record returned status: %d", t, r.Status)
		}
		return answers, err
	}

	for _, a := range r.Answer {
		answers = append(answers, a)
	}
	return answers, nil
}

// Goes through the DNS answers looking for A and AAAA records,
// and returns the first Data field found for those types
func GetARecordData(answers []DNSAnswer) string {
	var data string

	for _, a := range answers {
		if a.Type == 1 || a.Type == 28 {
			data = a.Data
			break
		}
	}
	return data
}

/* Private functions & methods */

func reverseIP(ip string) string {
	var reversed []string

	parts := strings.Split(ip, ".")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}
