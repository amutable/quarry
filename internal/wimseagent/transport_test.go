// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package wimseagent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/shogo82148/go-sfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// witComponents are the components every signed request covers.
var witComponents = []string{"@method", "@path", "@query", "workload-identity-token"}

// verify checks a request the way the quarry-worker does, with the key the
// agent was asked to bind into the WIT.
func verify(t *testing.T, r *http.Request, wimseAudience string, boundKey jose.JSONWebKey, wantComponents []string) {
	t.Helper()
	input, ok := strings.CutPrefix(r.Header.Get("Signature-Input"), "wimse=")
	require.True(t, ok, "Signature-Input %q", r.Header.Get("Signature-Input"))
	inputs, err := sfv.DecodeDictionary([]string{r.Header.Get("Signature-Input")})
	require.NoError(t, err, "parse Signature-Input")
	require.Len(t, inputs, 1, "signatures")
	covered, ok := inputs[0].Item.Value.(sfv.InnerList)
	require.True(t, ok, "covered components are an inner list")

	var base strings.Builder
	ids := make([]string, 0, len(covered))
	for _, c := range covered {
		id, ok := c.Value.(string)
		require.True(t, ok, "component identifier is a string")
		require.Empty(t, c.Parameters, "component %q has no parameters", id)
		ids = append(ids, id)
		var value string
		switch id {
		case "@method":
			value = r.Method
		case "@path":
			value = r.URL.EscapedPath()
		case "@query":
			value = "?" + r.URL.RawQuery
		default:
			value = r.Header.Get(id)
		}
		fmt.Fprintf(&base, "%q: %s\n", id, value)
	}
	base.WriteString(`"@signature-params": ` + input)
	assert.ElementsMatch(t, wantComponents, ids, "covered components")

	params := inputs[0].Item.Parameters
	keys := make([]string, 0, len(params))
	for _, p := range params {
		keys = append(keys, p.Key)
	}
	assert.ElementsMatch(t, []string{"created", "expires", "nonce", "tag", "wimse-aud"}, keys, "signature parameters")
	created, _ := params.Get("created").(int64)
	assert.InDelta(t, time.Now().Unix(), created, 5, "created")
	assert.Equal(t, created+int64(wimseExpiry/time.Second), params.Get("expires"), "expires")
	assert.Equal(t, "wimse-workload-to-workload", params.Get("tag"), "tag")
	assert.Equal(t, wimseAudience, params.Get("wimse-aud"), "wimse-aud")

	sigB64, ok := strings.CutPrefix(r.Header.Get("Signature"), "wimse=:")
	require.True(t, ok, "Signature %q", r.Header.Get("Signature"))
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(sigB64, ":"))
	require.NoError(t, err, "decode signature")
	assert.True(t, verifySig(t, boundKey.Key, []byte(base.String()), sig),
		"signature verifies with the key bound into the WIT")
}

// verifySig checks an RFC 9421 signature (section 3.3) over msg.
func verifySig(t *testing.T, pub crypto.PublicKey, msg, sig []byte) bool {
	t.Helper()
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		require.Len(t, sig, 2*size, "ECDSA signature is r||s")
		hash := map[int]crypto.Hash{32: crypto.SHA256, 48: crypto.SHA384}[size]
		h := hash.New()
		h.Write(msg)
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(pub, h.Sum(nil), r, s)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, msg, sig)
	case *rsa.PublicKey:
		h := crypto.SHA512.New()
		h.Write(msg)
		return rsa.VerifyPSS(pub, crypto.SHA512, h.Sum(nil), sig,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}
	t.Fatalf("unsupported bound key %T", pub)
	return false
}

// signedRequest sends one GET through transport and returns the request the
// server saw.
func signedRequest(t *testing.T, transport http.RoundTripper) *http.Request {
	t.Helper()
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r }))
	defer srv.Close()
	res, err := get(t, &http.Client{Transport: transport}, srv.URL+"/machine-id/abc/1.root.json?x=1")
	require.NoError(t, err, "GET")
	_ = res.Body.Close()
	require.NotNil(t, got, "request reached the server")
	return got
}

func TestTransportSigns(t *testing.T) {
	agent, calls := startFakeAgent(t, expiringIn(3600))
	cred := newCred(t, "urn:amutable:wit", agent)

	var got []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = append(got, r)
	}))
	defer srv.Close()

	client := &http.Client{Transport: &Transport{WitCred: cred, WimseAudience: "urn:amutable:quarry-worker"}}
	for _, path := range []string{"/machine-id/abc/1.root.json?x=1", "/machine-id/abc/timestamp.json"} {
		res, err := get(t, client, srv.URL+path)
		require.NoError(t, err, "GET %s", path)
		_ = res.Body.Close()
	}

	require.Len(t, calls(), 1, "the WIT is reused across requests")
	assert.Equal(t, "urn:amutable:wit", calls()[0].Audience, "the WIT is for the WIT audience")
	require.Len(t, got, 2, "requests")
	for _, r := range got {
		assert.Equal(t, "wit-1", r.Header.Get("Workload-Identity-Token"), "WIT header")
		verify(t, r, "urn:amutable:quarry-worker", calls()[0].JWK, witComponents)
	}
}

func TestTransportsShareCredential(t *testing.T) {
	agent, calls := startFakeAgent(t, expiringIn(3600))
	cred := newCred(t, "urn:amutable:wit", agent)

	for _, wimseAudience := range []string{"urn:example:one", "urn:example:two"} {
		got := signedRequest(t, &Transport{WitCred: cred, WimseAudience: wimseAudience})
		assert.Equal(t, "wit-1", got.Header.Get("Workload-Identity-Token"), "WIT header")
		verify(t, got, wimseAudience, calls()[0].JWK, witComponents)
	}
	assert.Len(t, calls(), 1, "one WIT for both WIMSE audiences")
}

func TestTransportDefaultWimseAudience(t *testing.T) {
	agent, calls := startFakeAgent(t, expiringIn(3600))
	cred := newCred(t, "aud", agent)

	got := signedRequest(t, &Transport{WitCred: cred})
	verify(t, got, "http://"+got.Host+"/machine-id/abc/1.root.json?x=1", calls()[0].JWK, witComponents)
}

func TestTransportFailsWhenAgentIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request went out unsigned")
	}))
	defer srv.Close()

	cred := newCred(t, "aud", "unix:"+filepath.Join(t.TempDir(), "missing")) //nolint:forbidigo // test code
	client := &http.Client{Transport: &Transport{WitCred: cred, WimseAudience: "aud"}}
	_, err := get(t, client, srv.URL+"/x") //nolint:bodyclose // Do fails
	require.ErrorContains(t, err, "identity agent", "GET without a WIT")
}

func TestTransportCoversBodyFields(t *testing.T) {
	agent, calls := startFakeAgent(t, expiringIn(3600))
	cred := newCred(t, "aud", agent)

	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r
	}))
	defer srv.Close()

	client := &http.Client{Transport: &Transport{WitCred: cred, WimseAudience: "wimse"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/upload", strings.NewReader(`{"a":1}`))
	require.NoError(t, err, "NewRequest")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Digest", "sha-256=:AAAA:")
	res, err := client.Do(req)
	require.NoError(t, err, "POST")
	_ = res.Body.Close()

	require.NotNil(t, got, "request reached the server")
	verify(t, got, "wimse", calls()[0].JWK, append(slices.Clone(witComponents), "content-type", "content-digest"))
}

func TestTransportRedirectDropsWIT(t *testing.T) {
	agent, _ := startFakeAgent(t, expiringIn(3600))
	cred := newCred(t, "aud", agent)

	var mu sync.Mutex
	seen := map[string]http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Clone()
		mu.Unlock()
		if r.URL.Path == "/from" {
			http.Redirect(w, r, "/to", http.StatusFound)
		}
	}))
	defer srv.Close()

	client := &http.Client{Transport: &Transport{WitCred: cred, WimseAudience: "wimse"}}
	res, err := get(t, client, srv.URL+"/from")
	require.NoError(t, err, "GET")
	_ = res.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	assert.NotEmpty(t, seen["/from"].Get("Workload-Identity-Token"), "first request is signed")
	require.Contains(t, seen, "/to", "redirect followed")
	for _, h := range []string{"Workload-Identity-Token", "Signature", "Signature-Input"} {
		assert.Empty(t, seen["/to"].Values(h), "redirect hop has no %s", h)
	}
}

func TestClientIsSharedPerIdentityAndAudience(t *testing.T) {
	provider := "unix:" + filepath.Join(t.TempDir(), "agent") //nolint:forbidigo // test code
	cred := newCred(t, "aud", provider)
	client := Client(cred, "wimse")
	assert.Same(t, client, Client(cred, "wimse"), "same identity and WIMSE audience")
	assert.NotSame(t, client, Client(cred, "other"), "other WIMSE audience")
	assert.NotSame(t, client, Client(newCred(t, "other", provider), "wimse"), "other identity")
}

func get(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err, "NewRequest")
	return client.Do(req)
}
