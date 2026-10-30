// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package identityagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"snai.pe/go-varlink"
)

// startFakeAgent serves GetWorkloadIdentityToken, recording the keys it was
// asked to bind, and replies with a WIT naming the call number.
func startFakeAgent(t *testing.T, expiresIn int64) (string, func() []witParams) {
	t.Helper()
	uri := "unix:" + filepath.Join(t.TempDir(), vlInterface) //nolint:forbidigo // test code
	listener, err := varlink.Listen(uri)
	require.NoError(t, err, "listen on fake agent socket")
	t.Cleanup(func() { _ = listener.Close() })

	var mu sync.Mutex
	var calls []witParams
	var mux varlink.ServeMux
	mux.HandleFunc(vlInterface+".GetWorkloadIdentityToken", func(w varlink.ReplyWriter, c *varlink.Call) {
		var p witParams
		if err := c.Unmarshal(&p); err != nil {
			_ = w.WriteError(err)
			return
		}
		mu.Lock()
		calls = append(calls, p)
		n := len(calls)
		mu.Unlock()
		_ = w.WriteReply(witReply{Token: "wit-" + strconv.Itoa(n), ExpiresIn: expiresIn})
	})
	srv := &varlink.Server{Handler: &mux}
	go func() { _ = srv.Serve(listener) }()
	return uri, func() []witParams {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(calls)
	}
}

var inputRe = regexp.MustCompile(`^wimse=(\("workload-identity-token" "@method" "@target-uri"\);created=(\d+);nonce="[0-9a-f]{32}";tag="wimse-workload-to-workload")$`)

// verify checks a request the way the quarry-worker does, with the key the
// agent was asked to bind into the WIT.
func verify(t *testing.T, r *http.Request, boundKey string) {
	t.Helper()
	m := inputRe.FindStringSubmatch(r.Header.Get("Signature-Input"))
	require.NotNil(t, m, "Signature-Input %q", r.Header.Get("Signature-Input"))
	created, err := strconv.ParseInt(m[2], 10, 64)
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Unix(), created, 5)

	sigB64, ok := strings.CutPrefix(r.Header.Get("Signature"), "wimse=:")
	require.True(t, ok)
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(sigB64, ":"))
	require.NoError(t, err)
	require.Len(t, sig, 64)

	base := `"workload-identity-token": ` + r.Header.Get("Workload-Identity-Token") + "\n" +
		`"@method": ` + r.Method + "\n" +
		`"@target-uri": http://` + r.Host + r.URL.RequestURI() + "\n" +
		`"@signature-params": ` + m[1]
	digest := sha256.Sum256([]byte(base))

	raw, err := base64.RawURLEncoding.DecodeString(boundKey)
	require.NoError(t, err)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	require.NoError(t, err)
	assert.True(t, ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])),
		"signature verifies with the key bound into the WIT")
}

func TestTransportSignsWithTheBoundKey(t *testing.T) {
	agent, calls := startFakeAgent(t, 3600)

	var got []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = append(got, r)
	}))
	defer srv.Close()
	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	client := &http.Client{Transport: &Transport{
		Audience:  "urn:amutable:quarry-worker",
		Host:      srvURL.Host,
		SocketURI: agent,
	}}
	for _, path := range []string{"/machine-id/abc/1.root.json?x=1", "/machine-id/abc/timestamp.json"} {
		res, err := get(t, client, srv.URL+path)
		require.NoError(t, err)
		_ = res.Body.Close()
	}

	require.Len(t, calls(), 1, "the WIT is reused until it nears expiry")
	assert.Equal(t, "urn:amutable:quarry-worker", calls()[0].Audience)
	require.Len(t, got, 2)
	for _, r := range got {
		assert.Equal(t, "wit-1", r.Header.Get("Workload-Identity-Token"))
		verify(t, r, calls()[0].PublicKey)
	}

	// Same server reached under another host name: not the signed host.
	res, err := get(t, client, "http://localhost:"+srvURL.Port()+"/targets/x")
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Len(t, got, 3)
	assert.Empty(t, got[2].Header.Get("Workload-Identity-Token"), "WIT must not leave for another host")
}

func TestTransportRefreshesNearExpiry(t *testing.T) {
	// Already inside refreshMargin, so every request asks for a new WIT.
	agent, calls := startFakeAgent(t, int64(refreshMargin/time.Second)-1)

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	client := &http.Client{Transport: &Transport{Audience: "aud", Host: srvURL.Host, SocketURI: agent}}
	for range 2 {
		res, err := get(t, client, srv.URL+"/x")
		require.NoError(t, err)
		_ = res.Body.Close()
	}
	require.Len(t, calls(), 2)
	assert.Equal(t, calls()[0].PublicKey, calls()[1].PublicKey, "the key outlives the WIT")
}

func TestTransportFailsWhenAgentIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request went out unsigned")
	}))
	defer srv.Close()
	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	client := &http.Client{Transport: &Transport{
		Audience:  "aud",
		Host:      srvURL.Host,
		SocketURI: "unix:" + filepath.Join(t.TempDir(), "missing"), //nolint:forbidigo // test code
	}}
	_, err = get(t, client, srv.URL+"/x")
	require.ErrorContains(t, err, "identity agent")
}

func TestClientIsSharedPerAudienceAndHost(t *testing.T) {
	a := Client("aud", "example.com", "")
	assert.Same(t, a, Client("aud", "example.com", ""), "a rebuilt config reuses the key and WIT")
	assert.NotSame(t, a, Client("other", "example.com", ""))
	assert.NotSame(t, a, Client("aud", "example.org", ""))
	assert.NotSame(t, a, Client("aud", "example.com", "unix:/run/other"))
}

func get(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	return client.Do(req)
}
