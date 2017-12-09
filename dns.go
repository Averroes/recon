// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package recon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type DnsWildcard struct {
	HasWildcard bool
	IP          string
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

func ResolveDNS(name, t string) ([]DNSAnswer, error) {
	var answers []DNSAnswer

	u, _ := url.Parse("https://dns.google.com/resolve")
	// do not send our location information with the query
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

func ReverseDNS(ip string) (string, error) {
	var name string

	addr := reverseIP(ip) + ".in-addr.arpa"
	answers, err := Resolve(addr, "PTR")
	if err == nil {
		for _, a := range answers {
			if a.Type == 12 {
				l := len(a.Data)

				name = a.Data[:l-1]
				break
			}
		}

		if name == "" {
			err = errors.New("PTR record not found")
		}
	}

	return name, err
}

// CheckDomainForWildcard detects if a domain returns an IP
// address for "bad" names, and if so, which address is used
func CheckDomainForWildcard(domain string) DnsWildcard {
	var ip1, ip2, ip3 string

	name1 := "81very92unlikely03name." + domain
	name2 := "45another34random99name." + domain
	name3 := "just555little333me." + domain

	if a1, err := ResolveDNS(name1, "A"); err == nil {
		ip1 = getARecordData(a1)
	}

	if a2, err := ResolveDNS(name2, "A"); err == nil {
		ip2 = getARecordData(a2)
	}

	if a3, err := ResolveDNS(name3, "A"); err == nil {
		ip3 = getARecordData(a3)
	}

	if ip1 != "" && (ip1 == ip2 && ip2 == ip3) {
		return DnsWildcard{HasWildcard: true, IP: ip1}
	}
	return DnsWildcard{HasWildcard: false, IP: ""}
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
