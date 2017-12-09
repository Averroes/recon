// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package recon

func ShodanHostLookup(addr string) string {
	return GetWebPage("https://www.shodan.io/host/" + addr)
}
