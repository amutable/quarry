// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recorder is a test server that records the headers of each request by
// path, and redirects /redirect/<status> to the "to" query parameter.
type recorder struct {
	*httptest.Server

	mu   sync.Mutex
	seen map[string][]http.Header
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{seen: map[string][]http.Header{}}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen[req.URL.Path] = append(r.seen[req.URL.Path], req.Header.Clone())
		r.mu.Unlock()
		if status, ok := redirectStatus(req.URL.Path); ok {
			http.Redirect(w, req, req.URL.Query().Get("to"), status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.Close)
	return r
}

func redirectStatus(path string) (int, bool) {
	const prefix = "/redirect/"
	if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
		return 0, false
	}
	status, err := strconv.Atoi(path[len(prefix):])
	return status, err == nil
}

func (r *recorder) headers(path string) []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[path]
}

const testTokenHeader = "Workload-Identity-Token"

func newTestTransport(t *testing.T) *Transport {
	t.Helper()
	return &Transport{
		Base:    mustBase(t, WithComponents(Method(), TargetURI(), Field(testTokenHeader))),
		Signer:  rfcEd25519Key(t),
		Options: []SignOption{WithSigLabel("test")},
		Prepare: func(req *http.Request) ([]SignOption, error) {
			req.Header.Set(testTokenHeader, "token")
			return []SignOption{WithKeyID("prepared")}, nil
		},
	}
}

func TestTransportSigns(t *testing.T) {
	srv := newRecorder(t)
	client := &http.Client{Transport: newTestTransport(t)}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/file", nil)
	require.NoError(t, err, "NewRequest")
	req.Header.Set("X-Caller", "1")
	before := req.Header.Clone()

	resp, err := client.Do(req)
	require.NoError(t, err, "Do")
	_ = resp.Body.Close()
	assert.Equal(t, before, req.Header, "caller's request is unchanged")

	seen := srv.headers("/file")
	require.Len(t, seen, 1, "requests to /file")
	assert.Equal(t, "token", seen[0].Get(testTokenHeader), "Prepare-set field")
	input := signatureInput(t, seen[0], "test")
	assert.Equal(t, "prepared", input.Parameters.Get("keyid"), "keyid from Prepare options")
	assert.ElementsMatch(t, []string{`"@method"`, `"@target-uri"`, `"workload-identity-token"`}, coveredIDs(t, input), "covered components")
	signatureFromHeader(t, seen[0], "test")
}

func TestTransportPrepareError(t *testing.T) {
	srv := newRecorder(t)
	tr := newTestTransport(t)
	errPrepare := errors.New("no token")
	tr.Prepare = func(*http.Request) ([]SignOption, error) { return nil, errPrepare }
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/file", nil)
	require.NoError(t, err, "NewRequest")
	_, err = client.Do(req) //nolint:bodyclose // Do fails
	require.ErrorIs(t, err, errPrepare, "Do")
	assert.Empty(t, srv.headers("/file"), "request is never sent")
}

func TestTransportSignError(t *testing.T) {
	srv := newRecorder(t)
	tr := newTestTransport(t)
	tr.Prepare = nil // the covered token field is then missing
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/file", nil)
	require.NoError(t, err, "NewRequest")
	_, err = client.Do(req) //nolint:bodyclose // Do fails
	require.ErrorIs(t, err, ErrMissingComponent, "Do")
	assert.Empty(t, srv.headers("/file"), "request is never sent unsigned")
}

func TestTransportRedirects(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	} {
		for _, crossHost := range []bool{false, true} {
			for _, callerSigned := range []bool{false, true} {
				name := strconv.Itoa(status)
				if crossHost {
					name += "/cross-host"
				}
				if callerSigned {
					name += "/caller-signed"
				}
				t.Run(name, func(t *testing.T) {
					first, second := newRecorder(t), newRecorder(t)
					target := first.URL + "/final"
					if crossHost {
						target = second.URL + "/final"
					}
					client := &http.Client{Transport: newTestTransport(t)}

					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
						first.URL+"/redirect/"+strconv.Itoa(status)+"?to="+target, nil)
					require.NoError(t, err, "NewRequest")
					if callerSigned {
						// Without the Transport removing them, net/http
						// would copy these to every hop.
						_, err := mustBase(t, WithComponents(Method())).SignRequest(rfcEd25519Key(t), req)
						require.NoError(t, err, "caller SignRequest")
					}

					resp, err := client.Do(req)
					require.NoError(t, err, "Do")
					_ = resp.Body.Close()
					assert.Equal(t, http.StatusNoContent, resp.StatusCode, "final status")

					hop := first.headers("/redirect/" + strconv.Itoa(status))
					require.Len(t, hop, 1, "first hop requests")
					signatureInput(t, hop[0], "test")

					finalSrv := first
					if crossHost {
						finalSrv = second
					}
					final := finalSrv.headers("/final")
					require.Len(t, final, 1, "redirected requests")
					for _, h := range []string{"Signature", "Signature-Input", testTokenHeader} {
						assert.Empty(t, final[0].Values(h), "redirect hop has no %s", h)
					}
				})
			}
		}
	}
}

func TestTransportConcurrent(t *testing.T) {
	srv := newRecorder(t)
	client := &http.Client{Transport: newTestTransport(t)}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/file", nil)
				if err != nil {
					t.Errorf("NewRequest: %v", err)
					return
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("Do: %v", err)
					return
				}
				_ = resp.Body.Close()
			}
		})
	}
	wg.Wait()
	assert.Len(t, srv.headers("/file"), 80, "requests")
}
