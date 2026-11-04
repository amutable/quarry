// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package wimseagent implements WIMSE workload-to-workload authentication
// using [httpsig], in accordance with WIMSE draft-08 profile of RFC 9421:
// <https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/08/>.
//
// The signing key used is a special-purpose WIT that is signed by the local
// machine's identity provider (com.amutable.IdentityAgent) to allow for better
// audience segregation.
package wimseagent

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go4org/hashtriemap"

	"go.amutable.dev/quarry/internal/httpsig"
)

const (
	witHeader      = "Workload-Identity-Token"
	signatureLabel = "wimse"
	signatureTag   = "wimse-workload-to-workload"
	audienceParam  = "wimse-aud"
	wimseExpiry    = 2 * time.Minute
)

// witBase is the request signature of draft-ietf-wimse-http-signature-08
// section 3.
var witBase = func() *httpsig.Base {
	base, err := httpsig.NewBase(
		httpsig.WithComponents(
			httpsig.Method(),
			httpsig.Path(),
			httpsig.Query(),
			httpsig.Field(witHeader),
		),
		httpsig.WithOptionalComponents(
			httpsig.Field("Content-Type"),
			httpsig.Field("Content-Digest"),
			httpsig.Field("Authorization"),
			httpsig.Field("Txn-Token"),
		),
		httpsig.WithoutAlg(), // explicitly disallowed by the spec
		httpsig.WithExpiry(wimseExpiry),
		httpsig.WithNonce(),
		httpsig.WithTag(signatureTag),
		httpsig.WithExtraParam(audienceParam),
	)
	if err != nil {
		panic(err)
	}
	return base
}()

// Transport is an [http.RoundTripper] that signs requests using WIMSE
// workload-to-workload HTTP Signed Requests.
//
// A request with a body must carry a Content-Digest, which Transport does
// not add.
type Transport struct {
	// WitCred is the underlying credential used for this transport. It must be
	// non-nil.
	WitCred *WitCred
	// WimseAudience is the WIMSE audience included in the [httpsig] signed
	// requests. If empty, the WIMSE audience defaults to the initial request's
	// URI (akin to @target-uri).
	//
	// TODO: We almost certainly should support expandos (or custom functions
	// to generate WimseAudience) so users can configure custom wimse-aud
	// values that are variable based on the request URL (and possibly the
	// repository name).
	WimseAudience string

	signerOnce sync.Once
	signer     *httpsig.Transport
}

// RoundTrip implements [http.RoundTripper]. It fails the request if no WIT can
// be obtained, rather than sending it unsigned.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// NOTE: We are trusting [httpsig.Transport] to restrict signing of
	// redirects and other nonsense based on its own policy (at the moment, it
	// only permits the first request to be signed).
	// TODO: Should also we have some restriction on the hosts we sign for?
	return t.httpsigTransport().RoundTrip(req)
}

// httpsigTransport returns the transport that signs requests using [WitCred].
func (t *Transport) httpsigTransport() *httpsig.Transport {
	t.signerOnce.Do(func() {
		t.signer = &httpsig.Transport{
			Base:   witBase,
			Signer: t.WitCred.Signer(),
			Options: []httpsig.SignOption{
				httpsig.WithSigLabel(signatureLabel),
			},
			Prepare: func(req *http.Request) ([]httpsig.SignOption, error) {
				opts := make([]httpsig.SignOption, 0, 2)

				// NOTE: This is currently static but in the future
				signerOpts, err := t.WitCred.SignerOpts()
				if err != nil {
					return nil, fmt.Errorf("get WIT signing options: %w", err)
				}
				opts = append(opts, httpsig.WithSignerOpts(signerOpts))

				audience := t.WimseAudience
				if audience == "" {
					var err error
					audience, err = httpsig.RequestTargetURI(req)
					if err != nil {
						return nil, fmt.Errorf("compute default wimse-aud from request: %w", err)
					}
				}
				opts = append(opts, httpsig.WithExtraParamValue(audienceParam, audience))

				wit, err := t.WitCred.Credential(req.Context())
				if err != nil {
					return nil, fmt.Errorf("get WIT for %s from the identity agent: %w", req.URL.Host, err)
				}
				req.Header.Set(witHeader, wit)

				return opts, nil
			},
		}
	})
	return t.signer
}

type clientID struct {
	id            ID
	wimseAudience string
}

var clients = new(hashtriemap.HashTrieMap[clientID, *http.Client])

// Client returns a [http.Client] that can be used to sign requests using the
// given [WitCred]. These are cached, so if there is an existing client using
// the same [ID] and WIMSE audience it will be reused.
//
// TODO: Maybe we should instead take an [ID] and call [NewCred] implicitly
// with the default key?
func Client(wit *WitCred, wimseAudience string) *http.Client {
	id := clientID{id: wit.ID(), wimseAudience: wimseAudience}
	client, _ := clients.LoadOrStore(id, &http.Client{
		Transport: &Transport{
			WitCred:       wit,
			WimseAudience: wimseAudience,
		},
	})
	return client
}
