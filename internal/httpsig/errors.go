// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"errors"
	"fmt"
)

// Errors returned by [NewBase] and [Base.SignRequest], for use with
// [errors.Is].
var (
	// ErrInvalidComponent is a component that is malformed, can't be covered
	// in this message, or whose value can't be parsed as it requires.
	ErrInvalidComponent = errors.New("invalid component")

	// ErrResponseOnlyComponent is a response-only component ("@status" or
	// ";req") in a request.
	ErrResponseOnlyComponent = errors.New("component is only valid for responses")

	// ErrMissingComponent is a covered component the message doesn't have.
	ErrMissingComponent = errors.New("covered component not present in message")

	// ErrInvalidParameter is a signature parameter name or value that is
	// invalid, reserved, undeclared or can't be serialised.
	ErrInvalidParameter = errors.New("invalid signature parameter")

	// ErrMissingParameter is a parameter declared with [WithExtraParam] that
	// was given no value.
	ErrMissingParameter = errors.New("declared signature parameter has no value")

	// ErrInvalidLabel is a [WithSigLabel] label that is not a valid sf-key.
	ErrInvalidLabel = errors.New("invalid signature label")

	// ErrLabelExists is a [WithSigLabel] label already on the request.
	ErrLabelExists = errors.New("signature label already in use")

	// ErrMalformedSignature is an existing Signature or Signature-Input field
	// that can't be parsed.
	ErrMalformedSignature = errors.New("malformed existing Signature or Signature-Input field")

	// ErrUnsupportedKey is a signer whose public key has no RFC 9421
	// algorithm.
	ErrUnsupportedKey = errors.New("unsupported public key type")

	// ErrUnsupportedSignerOpts is a [crypto.SignerOpts] that selects no RFC
	// 9421 algorithm for the signer's key.
	ErrUnsupportedSignerOpts = errors.New("signer options do not match an RFC 9421 algorithm")

	// ErrNonceNotEnabled is a [WithNonceValue] for a [Base] made with
	// [WithoutNonce].
	ErrNonceNotEnabled = errors.New("nonce value given for a base without nonce")
)

// ComponentError wraps one of the package's sentinel errors with the
// offending component.
type ComponentError struct {
	Component Component
	Err       error
}

func (e *ComponentError) Error() string {
	return fmt.Sprintf("component %s: %v", e.Component, e.Err)
}

func (e *ComponentError) Unwrap() error {
	return e.Err
}

func componentErr(c Component, err error) error {
	return &ComponentError{Component: c, Err: err}
}
