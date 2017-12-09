// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package recon

import (
	"regexp"
	"sort"
	"strings"

	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
)

var badWordFilter map[string]struct{}

// ReverseWhois - Returns a slice of domain names related to the domain provided
func ReverseWhois(domain string) []string {
	// Get the whois for the provided domain name
	w, err := whois.Whois(domain)
	if err != nil {
		return nil
	}
	// Parse the whois information just queried
	target, err := whois_parser.Parser(w)
	if err != nil {
		return nil
	}
	// Make a list of strings that are good to match on
	tlist := list(domain, target)
	// Get the list of domain names discovered through
	// the reverse DNS service
	domainlist := viewDNSReverseWhois(domain)
	if domainlist == nil {
		return nil
	}

	done := make(chan string, 10)

	for _, d := range domainlist {
		go attemptMatch(domain, d, tlist, done)
	}

	var results []string

	for count, l := 0, len(domainlist); count < l; count++ {
		match := <-done

		if match != "" {
			results = append(results, match)
		}
	}

	sort.Strings(results)
	return results
}

/* Private functions */

func init() {
	badWordFilter = make(map[string]struct{})

	badWordFilter["domain administrator"] = struct{}{}
	badWordFilter["private registration"] = struct{}{}
	badWordFilter["registration private"] = struct{}{}
	badWordFilter["registration"] = struct{}{}
	badWordFilter["domain manager"] = struct{}{}
	badWordFilter["domain name coordinator"] = struct{}{}
	badWordFilter["techcontact"] = struct{}{}
	badWordFilter["technical contact"] = struct{}{}
	badWordFilter["internet"] = struct{}{}
	badWordFilter["hostmaster"] = struct{}{}
	badWordFilter["united states"] = struct{}{}
	badWordFilter["information"] = struct{}{}
	badWordFilter["security officer"] = struct{}{}
	badWordFilter["chief information security officer"] = struct{}{}
	badWordFilter["chief information officer"] = struct{}{}
	badWordFilter["information officer"] = struct{}{}
	badWordFilter["information technology services"] = struct{}{}
	badWordFilter["domains by proxy"] = struct{}{}
	badWordFilter["perfect privacy"] = struct{}{}
}

// Obtains the portion of the ViewDNS webpage that contains the results
func getTable(page string) string {
	var begin, end int
	s := page

	for i := 0; i < 4; i++ {
		b := strings.Index(s, "<table")
		if b == -1 {
			return ""
		}
		begin += b + 6

		e := strings.Index(s[b:], "</table>")
		if e == -1 {
			return ""
		}

		end = begin + e

		s = page[end+8:]
	}

	i := strings.Index(page[begin:end], "<table")
	i = strings.Index(page[begin+i+6:end], "<table")
	return page[begin+i : end]
}

// Returns the domain names discovered by the ViewDNS Reverse Whois
func viewDNSReverseWhois(domain string) []string {
	re, err := regexp.Compile(SUBRE + "[a-zA-Z]+")
	if err != nil {
		return nil
	}

	// Grab the web page containing the ViewDNS search results
	page := GetWebPage("http://viewdns.info/reversewhois/?q=" + domain)
	if page == "" {
		return nil
	}

	// Pull out the table containing the domain names
	table := getTable(page)
	if table == "" {
		return nil
	}

	var unique []string

	for _, name := range re.FindAllString(table, -1) {
		unique = UniqueAppend(unique, name)
	}

	return unique
}

func compare(domain string, l []string, data whois_parser.WhoisInfo) bool {
	match := false
	dlist := list(domain, data)

	if len(dlist) == 0 {
		return false
	}

	for _, v := range l {
		if listCompare(v, dlist) {
			match = true
			break
		}
	}

	return match
}

// Returns a slice of strings that could contain useful information to match on
func breakout(r whois_parser.Registrant) []string {
	var list []string

	list = UniqueAppend(list, strings.Split(r.Name, ",")...)
	list = UniqueAppend(list, strings.Split(r.Organization, ",")...)
	list = UniqueAppend(list, strings.Split(r.Street, ",")...)
	list = UniqueAppend(list, strings.Split(r.StreetExt, ",")...)
	list = UniqueAppend(list, strings.Split(r.Phone, ",")...)
	list = UniqueAppend(list, strings.Split(r.Email, ",")...)
	return list
}

func listCompare(s string, list []string) bool {
	var match bool

	if s == "" {
		for _, l := range list {
			if l == "" {
				continue
			}

			l = strings.TrimSpace(l)
			l = strings.ToLower(l)

			if strings.Compare(s, l) == 0 {
				match = true
				break
			}
		}
	}
	return match
}

// Returns a new list with the bad word filter applied
func filterList(list []string) []string {
	var fl []string

	for _, v := range list {
		if len(v) < 10 {
			continue
		}

		if _, ok := badWordFilter[v]; !ok {
			fl = append(fl, v)
		}
	}

	return fl
}

// Returns elements from the whois data that will be good to match on
func list(domain string, data whois_parser.WhoisInfo) []string {
	var first, list []string

	// Obtain the elements from the whois data
	first = UniqueAppend(first, strings.Split(data.Registrar.NameServers, ",")...)
	first = UniqueAppend(first, breakout(data.Registrant)...)
	first = UniqueAppend(first, breakout(data.Admin)...)
	first = UniqueAppend(first, breakout(data.Tech)...)
	first = UniqueAppend(first, breakout(data.Bill)...)

	// Remove elements containing the domain name
	for _, v := range first {
		if !strings.Contains(domain, v) {
			list = append(list, v)
		}
	}
	// Perform the bad word filtering before returning
	return filterList(list)
}

func attemptMatch(domain, candidate string, list []string, done chan string) {
	var result string

	if candidate == domain {
		done <- result
		return
	}

	c, err := whois.Whois(candidate)
	if err != nil {
		done <- result
		return
	}

	parsed, err := whois_parser.Parser(c)
	if err == nil {
		if compare(domain, list, parsed) {
			result = candidate
		}
	}

	done <- result
	return
}
