// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/shogo82148/go-sfv"

	"go.amutable.dev/quarry/internal/generics"
)

// Signature parameters defined by the RFC, which cannot be specified using
// [WithExtraParam].
var reservedParams = map[string]struct{}{
	"created": {},
	"expires": {},
	"nonce":   {},
	"alg":     {},
	"keyid":   {},
	"tag":     {},
}

// Base is a signature base template: the covered components and the
// parameters that are fixed for every signature made from it. A Base is
// immutable and safe for concurrent use.
//
// The order of the covered components and of the parameters is randomised
// for every signature, so that verifiers cannot depend on it.
type Base struct {
	components map[string]coveredComponent // by identifier
	expiry     *time.Duration              // nil means no expiry
	noNonce    bool
	noAlg      bool
	tag        string
	extra      map[string]any
}

// coveredComponent is a component of a [Base], with whether it may be absent.
type coveredComponent struct {
	Component
	optional bool
}

// BaseOption configures a [Base] in [NewBase].
type BaseOption func(*Base)

// WithComponents adds components that must be present in every message
// signed with the Base. A component with the same identifier as an earlier
// one replaces it.
func WithComponents(cs ...Component) BaseOption {
	return withComponents(cs, false)
}

// WithOptionalComponents adds components that are covered only when the
// message has them. A signature over a message without one leaves it out of
// the covered components entirely. A [Key] component is only present if the
// field exists and has that member. A component with the same identifier as
// an earlier one replaces it.
func WithOptionalComponents(cs ...Component) BaseOption {
	return withComponents(cs, true)
}

func withComponents(cs []Component, optional bool) BaseOption {
	cs = slices.Clone(cs)
	return func(b *Base) {
		if b.components == nil {
			b.components = make(map[string]coveredComponent)
		}
		for _, c := range cs {
			b.components[c.String()] = coveredComponent{Component: c, optional: optional}
		}
	}
}

// WithExpiry adds an "expires" parameter set to the signature's reference
// time (its "created" value) plus d. d must be positive.
func WithExpiry(d time.Duration) BaseOption {
	return func(b *Base) { b.expiry = generics.Ptr(d) }
}

// WithoutExpiry omits the "expires" parameter, which is also the default.
func WithoutExpiry() BaseOption {
	return func(b *Base) { b.expiry = nil }
}

// WithNonce explicitly includes the "nonce" parameter, which is also the
// default. The value will be 128 bits of fresh randomness or the value from
// [WithNonceValue], if specified.
func WithNonce() BaseOption {
	return func(b *Base) { b.noNonce = false }
}

// WithoutNonce omits the "nonce" parameter.
func WithoutNonce() BaseOption {
	return func(b *Base) { b.noNonce = true }
}

// WithAlg explicitly includes the "alg" parameter, which is also the default.
func WithAlg() BaseOption {
	return func(b *Base) { b.noAlg = false }
}

// WithoutAlg omits the "alg" parameter. This is not recommended, but some
// profiles (e.g., WIMSE) forbid the usage of "alg".
func WithoutAlg() BaseOption {
	return func(b *Base) { b.noAlg = true }
}

// WithTag sets the "tag" parameter to the given application-specific value.
func WithTag(tag string) BaseOption {
	return func(b *Base) { b.tag = tag }
}

// WithoutTag omits the "tag" parameter, which is also the default.
func WithoutTag() BaseOption {
	return WithTag("")
}

// WithExtraParam declares an application-defined signature parameter, as well
// as an optional default value. If no default value is provided, each
// signature must provide a value with [WithExtraParamValue] at signing time.
// This function panics if more than one argument is passed for defaultValue.
// name must be a valid sf-key and must not be a parameter defined by RFC 9421
// ("created", "expires", "nonce", "alg", "keyid", "tag").
func WithExtraParam(name string, defaultValue ...any) BaseOption {
	v, rest := generics.TakeOne(defaultValue)
	if len(rest) > 0 {
		panic(fmt.Sprintf("WithExtraParam called with too many parameters: %q %v", name, defaultValue))
	}
	var value any
	if v != nil {
		value = *v
	}
	return func(b *Base) {
		if b.extra == nil {
			b.extra = make(map[string]any)
		}
		b.extra[name] = value
	}
}

// NewBase returns a [Base] configured by opts. Options are applied in order,
// so later options override earlier ones. Every problem with the components
// and options is reported at once.
func NewBase(opts ...BaseOption) (*Base, error) {
	var b Base
	for _, opt := range opts {
		opt(&b)
	}

	var errs []error
	for _, c := range b.components {
		if err := c.validate(); err != nil {
			errs = append(errs, err)
		}
	}

	if b.expiry != nil && *b.expiry <= 0 {
		errs = append(errs, fmt.Errorf("%w: expiry %s is not positive", ErrInvalidParameter, *b.expiry))
	}
	if b.tag != "" && !sfv.IsValidString(b.tag) {
		errs = append(errs, fmt.Errorf("%w: tag %q is not a valid sf-string", ErrInvalidParameter, b.tag))
	}
	for name := range b.extra {
		switch {
		case !validKey(name):
			errs = append(errs, fmt.Errorf("%w: %q is not a valid parameter name", ErrInvalidParameter, name))
		case generics.MapContains(reservedParams, name):
			errs = append(errs, fmt.Errorf("%w: %q is defined by RFC 9421", ErrInvalidParameter, name))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &b, nil
}
