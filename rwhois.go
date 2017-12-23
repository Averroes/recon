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

const SUBRE = "(([a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"

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
	tlist := matchData(domain, target)
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
	list := []string{
		"domain administrator",
		"private registration",
		"registration private",
		"registration",
		"domain manager",
		"domain name coordinator",
		"techcontact",
		"technical contact",
		"internet",
		"hostmaster",
		"united states",
		"information",
		"security officer",
		"chief information security officer",
		"chief information officer",
		"information officer",
		"information technology services",
		"domains by proxy",
		"perfect privacy",
	}

	for _, word := range list {
		badWordFilter[word] = struct{}{}
	}
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
	table := getViewDNSTable(page)
	if table == "" {
		return nil
	}

	var unique []string
	for _, name := range re.FindAllString(table, -1) {
		unique = UniqueAppend(unique, name)
	}
	return unique
}

// Obtains the portion of the ViewDNS webpage that contains the results
func getViewDNSTable(page string) string {
	var begin, end int
	s := page

	for i := 0; i < 4; i++ {
		if b := strings.Index(s, "<table"); b == -1 {
			return ""
		} else {
			begin += b + 6
		}

		if e := strings.Index(s[b:], "</table>"); e == -1 {
			return ""
		} else {
			end = begin + e
		}

		s = page[end+8:]
	}

	i := strings.Index(page[begin:end], "<table")
	i = strings.Index(page[begin+i+6:end], "<table")
	return page[begin+i : end]
}

// Returns elements from the whois data that will be good to match on
func matchData(domain string, data whois_parser.WhoisInfo) []string {
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

// Returns a new list with the bad word filter applied
func filterList(list []string) []string {
	var fl []string

	for _, v := range list {
		if _, ok := badWordFilter[v]; !ok && len(v) >= 10 {
			fl = append(fl, v)
		}
	}
	return fl
}

func attemptMatch(domain, candidate string, list []string, done chan string) {
	var result string

	if candidate == domain {
		done <- result
		return
	}

	c, err := whois.Whois(candidate)
	if err == nil {
		parsed, err := whois_parser.Parser(c)
		if err == nil {
			if compare(domain, list, parsed) {
				result = candidate
			}
		}
	}
	done <- result
	return
}

func compare(domain string, l []string, data whois_parser.WhoisInfo) bool {
	dlist := matchData(domain, data)

	if len(dlist) == 0 {
		return false
	}

	var match bool
	for _, v := range l {
		if listCompare(v, dlist) {
			match = true
			break
		}
	}

	return match
}

func listCompare(s string, list []string) bool {
	if s == "" {
		return false
	}

	var match bool
	for _, l := range list {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		l = strings.ToLower(l)

		if strings.Compare(s, l) == 0 {
			match = true
			break
		}
	}
	return match
}
