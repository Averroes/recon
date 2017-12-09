// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package recon

import (
	"strings"
)

func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		for _, ov := range orig {
			if s == ov {
				found = true
			}
		}

		for _, nv := range n {
			if s == nv {
				found = true
			}
		}

		if !found {
			n = append(n, s)
		}
	}
	return n
}

func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}
