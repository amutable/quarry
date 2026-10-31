// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/shogo82148/go-sfv"
)

// field is an HTTP field component (RFC 9421 section 2.1).
type field struct {
	fieldName string
	trailer   bool
	enc       fieldEncoding
}

// fieldEncoding turns a field's raw line values into its base value.
// Implementations must be comparable so that [Component] is.
type fieldEncoding interface {
	params() sfv.Parameters
	validate() error
	// encode returns the value, or false if it is absent (a missing
	// dictionary member).
	encode(lines []string) (value string, present bool, err error)
}

// Field returns an HTTP field component. name is case-insensitive and is
// stored lowercased.
func Field(name string, opts ...FieldOption) Component {
	f := &field{fieldName: strings.ToLower(name), enc: rawEncoding{}}
	for _, opt := range opts {
		opt(f)
	}
	return Component{kind: *f}
}

// FieldOption sets a parameter of a [Field] component. A field has exactly
// one value encoding ([Key], [Structured], [StructuredAs] or
// [ByteSequence]); the last one given wins.
type FieldOption func(*field)

// Key adds ";key=member", covering one member of a dictionary field.
func Key(member string) FieldOption {
	return func(f *field) { f.enc = dictMemberEncoding{key: member} }
}

// Structured adds ";sf", strictly re-serialising the field as a structured
// field. Its type comes from a built-in table of fields whose type is defined
// by an RFC; other fields need [StructuredAs].
func Structured() FieldOption {
	return func(f *field) { f.enc = structuredEncoding{typ: sfTypes[f.fieldName]} }
}

// StructuredAs adds ";sf", strictly re-serialising the field as a structured
// field of type t.
func StructuredAs(t SFType) FieldOption {
	return func(f *field) { f.enc = structuredEncoding{typ: t} }
}

// ByteSequence adds ";bs", wrapping each field line value as a byte sequence.
func ByteSequence() FieldOption {
	return func(f *field) { f.enc = byteSeqEncoding{} }
}

// Trailer adds ";tr", taking the value from the trailer fields.
func Trailer() FieldOption {
	return func(f *field) { f.trailer = true }
}

func (f field) name() string { return f.fieldName }

func (f field) params() sfv.Parameters {
	params := f.enc.params()
	if f.trailer {
		params = append(params, sfv.Parameter{Key: "tr", Value: true})
	}
	return params
}

func (f field) validate() error {
	if !validToken(f.fieldName) {
		return fmt.Errorf("%q is not a valid field name", f.fieldName)
	}
	return f.enc.validate()
}

func (f field) resolve(m message) (string, bool, error) {
	lines, ok, err := m.fieldValues(f.fieldName, f.trailer)
	if err != nil || !ok {
		return "", false, err
	}
	return f.enc.encode(lines)
}

// rawEncoding is a field's plain value (RFC 9421 section 2.1).
type rawEncoding struct{}

func (rawEncoding) params() sfv.Parameters { return nil }
func (rawEncoding) validate() error        { return nil }

func (rawEncoding) encode(lines []string) (string, bool, error) {
	values := make([]string, len(lines))
	for i, v := range lines {
		values[i] = strings.Trim(v, " \t")
	}
	return strings.Join(values, ", "), true, nil
}

// byteSeqEncoding is ";bs" (RFC 9421 section 2.1.3).
type byteSeqEncoding struct{}

func (byteSeqEncoding) params() sfv.Parameters {
	return sfv.Parameters{{Key: "bs", Value: true}}
}

func (byteSeqEncoding) validate() error { return nil }

func (byteSeqEncoding) encode(lines []string) (string, bool, error) {
	values := make([]string, len(lines))
	for i, v := range lines {
		values[i] = ":" + base64.StdEncoding.EncodeToString([]byte(strings.Trim(v, " \t"))) + ":"
	}
	return strings.Join(values, ", "), true, nil
}

// SFType is the top-level type of a structured field, needed to
// re-serialise it strictly for ;sf.
type SFType int

// Structured field types (RFC 9651 section 3).
const (
	SFItem SFType = iota + 1
	SFList
	SFDictionary
)

// sfTypes holds the fields whose structured type is defined by an RFC, for
// [Structured].
var sfTypes = map[string]SFType{
	"accept-ch":           SFList,       // RFC 8942
	"accept-signature":    SFDictionary, // RFC 9421
	"cache-status":        SFList,       // RFC 9211
	"cdn-cache-control":   SFDictionary, // RFC 9213
	"client-cert":         SFItem,       // RFC 9440
	"client-cert-chain":   SFList,       // RFC 9440
	"content-digest":      SFDictionary, // RFC 9530
	"priority":            SFDictionary, // RFC 9218
	"proxy-status":        SFList,       // RFC 9209
	"repr-digest":         SFDictionary, // RFC 9530
	"signature":           SFDictionary, // RFC 9421
	"signature-input":     SFDictionary, // RFC 9421
	"want-content-digest": SFDictionary, // RFC 9530
	"want-repr-digest":    SFDictionary, // RFC 9530
}

// structuredEncoding is ";sf" (RFC 9421 section 2.1.1).
type structuredEncoding struct {
	typ SFType // zero if Structured found no type for the field
}

func (structuredEncoding) params() sfv.Parameters {
	return sfv.Parameters{{Key: "sf", Value: true}}
}

func (e structuredEncoding) validate() error {
	switch e.typ {
	case SFItem, SFList, SFDictionary:
		return nil
	case 0:
		return errors.New("structured type of field is not known, use StructuredAs")
	default:
		return fmt.Errorf("unknown structured field type %d", e.typ)
	}
}

func (e structuredEncoding) encode(lines []string) (string, bool, error) {
	var (
		value string
		err   error
	)
	switch e.typ {
	case SFItem:
		var item sfv.Item
		if item, err = sfv.DecodeItem(lines); err == nil {
			value, err = sfv.EncodeItem(item)
		}
	case SFList:
		var list sfv.List
		if list, err = sfv.DecodeList(lines); err == nil {
			value, err = sfv.EncodeList(list)
		}
	case SFDictionary:
		var dict sfv.Dictionary
		if dict, err = sfv.DecodeDictionary(lines); err == nil {
			value, err = sfv.EncodeDictionary(dict)
		}
	default:
		err = fmt.Errorf("unknown structured field type %d", e.typ)
	}
	if err != nil {
		return "", false, fmt.Errorf("%w: re-serialise structured field: %w", ErrInvalidComponent, err)
	}
	return value, true, nil
}

// dictMemberEncoding is ";key" (RFC 9421 section 2.1.2).
type dictMemberEncoding struct {
	key string
}

func (e dictMemberEncoding) params() sfv.Parameters {
	return sfv.Parameters{{Key: "key", Value: e.key}}
}

func (e dictMemberEncoding) validate() error {
	if !validKey(e.key) {
		return fmt.Errorf("%q is not a valid dictionary key", e.key)
	}
	return nil
}

func (e dictMemberEncoding) encode(lines []string) (string, bool, error) {
	dict, err := sfv.DecodeDictionary(lines)
	if err != nil {
		return "", false, fmt.Errorf("%w: parse as dictionary: %w", ErrInvalidComponent, err)
	}
	member := dict.Get(e.key)
	if member.Value == nil {
		return "", false, nil
	}
	value, err := encodeMember(member)
	if err != nil {
		return "", false, fmt.Errorf("%w: serialise member %q: %w", ErrInvalidComponent, e.key, err)
	}
	return value, true, nil
}
