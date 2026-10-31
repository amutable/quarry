// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package generics

// TakeOne takes the first value out of a slice and returns the remaining slice.
// If the slice is empty or nil then (nil, s) is returned.
func TakeOne[S ~[]E, E any](s S) (*E, []E) {
	if len(s) > 0 {
		return Ptr(s[0]), s[1:]
	}
	return nil, s
}
