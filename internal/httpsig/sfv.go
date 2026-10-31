// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"fmt"
	"strings"

	"github.com/shogo82148/go-sfv"
)

// encodeMember serialises a single list/dictionary member value (an item or
// an inner list, with its parameters).
func encodeMember(m sfv.Item) (string, error) {
	return sfv.EncodeList(sfv.List{m})
}

// validKey reports whether s is a valid sf-key (RFC 9651 section 3.1.2).
// go-sfv doesn't export its key check, but its encoder applies it.
func validKey(s string) bool {
	_, err := sfv.EncodeDictionary(sfv.Dictionary{{Key: s, Item: sfv.Item{Value: true}}})
	return err == nil
}

// validToken reports whether s is a valid RFC 9110 token, the syntax of an
// HTTP field name.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// paramValue converts a WithExtraParamValue value into an sf bare item.
func paramValue(v any) (sfv.Value, error) {
	switch v := v.(type) {
	case string:
		if !sfv.IsValidString(v) {
			return nil, fmt.Errorf("%q is not a valid sf-string", v)
		}
		return v, nil
	case int64:
		if v < sfv.MinInteger || v > sfv.MaxInteger {
			return nil, fmt.Errorf("%d is out of range for an sf-integer", v)
		}
		return v, nil
	case bool:
		return v, nil
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", v)
	}
}
