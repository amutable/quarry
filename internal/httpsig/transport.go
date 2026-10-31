// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"crypto"
	"fmt"
	"net/http"
	"slices"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// Transport is an [http.RoundTripper] that signs requests with Base before
// passing them to Next. There are no restrictions for which Host this
// Transport will sign requests -- if you need such restrictions you will need
// to wrap the Transport in another [http.RoundTripper].
//
// NOTE: At the moment, only the initial request is signed and all subsequent
// redirect requests have their signatures stripped. The former is mostly a
// matter of caution for the initial implementation, and the latter is
// essentially required by RFC 9421.
//
// Some caveats:
//
//   - Fields that [http.Transport] adds while sending (e.g., Accept-Encoding
//     and the default User-Agent) are never seen by [Base.SignRequest] as they
//     are not available at RoundTrip time. This means that they cannot be
//     covered by the signature, and attempting to do so will cause spurious
//     errors.
//   - The request body is never read, meaning that covering Content-Digest
//     will require you to have already included it as a header before sending
//     the request through this Transport.
type Transport struct {
	// Base describes the signature added to each request.
	Base *Base
	// Signer signs each request.
	Signer crypto.Signer
	// Options are passed to [Base.SignRequest] for each request.
	Options []SignOption
	// Prepare is called on the request before signing, allowing for the custom
	// setting of header fields or addition of new [SignOption]s based on the
	// request. An error fails the request, so it is never sent unsigned.
	Prepare func(req *http.Request) ([]SignOption, error)
	// Next sends the request; nil means [http.DefaultTransport].
	Next http.RoundTripper
}

func (t *Transport) next() http.RoundTripper {
	if t.Next != nil {
		return t.Next
	}
	return http.DefaultTransport
}

// RoundTrip implements [http.RoundTripper].
func (t *Transport) RoundTrip(req *http.Request) (_ *http.Response, Err error) {
	req = req.Clone(req.Context())
	// Close the Body on error until we forward to the next transport, at which
	// point we do not attempt to close the body. This is required for
	// [http.RoundTripper] implementations.
	var sent bool
	defer funchelpers.OnError(&Err, func() error {
		if sent || req.Body == nil {
			return nil
		}
		return req.Body.Close()
	})
	send := func(req *http.Request) (*http.Response, error) {
		sent = true
		return t.next().RoundTrip(req)
	}
	if req.Response != nil {
		// This is a redirect, do not sign the request.
		//
		// TODO: Since we set wimse-aud to a unique value for the request,
		// maybe it would be okay to sign later requests as long as we keep the
		// *original* wimse-aud? Otherwise this restriction on redirects is a
		// bit too extreme...
		// TODO: Or maybe we should at least allow same-origin redirects by
		// default?
		req.Header.Del(headerSignature)
		req.Header.Del(headerSignatureInput)
		return send(req)
	}
	opts := t.Options
	if t.Prepare != nil {
		extra, err := t.Prepare(req)
		if err != nil {
			return nil, err
		}
		opts = append(slices.Clone(opts), extra...)
	}
	if _, err := t.Base.SignRequest(t.Signer, req, opts...); err != nil {
		return nil, fmt.Errorf("sign request to %s: %w", req.URL.Host, err)
	}
	return send(req)
}
