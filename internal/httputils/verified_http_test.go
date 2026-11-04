// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httputils_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/umoci/pkg/hardening"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/httputils"
	"go.amutable.dev/quarry/internal/tufext"
)

func staticServer(t *testing.T, status int, body []byte) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func sha512Of(b []byte) []byte {
	sum := sha512.Sum512(b)
	return sum[:]
}

func TestVerifiedHTTPGet_HappyPath(t *testing.T) {
	body := []byte("hello, verified world")
	u := staticServer(t, http.StatusOK, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(body)}

	rdr, res, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, int64(len(body)), hashes)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)

	got, err := io.ReadAll(rdr)
	require.NoError(t, err)
	assert.Equal(t, body, got)
	require.NoError(t, rdr.Close())
}

func TestVerifiedHTTPGet_MultipleHashes_AllValid(t *testing.T) {
	body := []byte("multi-hash payload")
	u := staticServer(t, http.StatusOK, body)
	hashes := tufmetadata.Hashes{
		"sha256": sha256Of(body),
		"sha512": sha512Of(body),
	}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, int64(len(body)), hashes)
	require.NoError(t, err)

	// Layer order is an implementation detail of HashesToDigest; only the set
	// of digests in the stack is part of the contract.
	var stackDigests []digest.Digest
	var cur io.Reader = rdr
	for {
		vr, ok := cur.(*hardening.VerifiedReadCloser)
		if !ok {
			break
		}
		stackDigests = append(stackDigests, vr.ExpectedDigest)
		assert.Equal(t, int64(len(body)), vr.ExpectedSize, "ExpectedSize must propagate to every layer")
		cur = vr.Reader
	}
	assert.ElementsMatch(t, []digest.Digest{
		digest.NewDigestFromBytes(digest.SHA256, sha256Of(body)),
		digest.NewDigestFromBytes(digest.SHA512, sha512Of(body)),
	}, stackDigests, "every supplied digest must appear exactly once in the stack")

	got, err := io.ReadAll(rdr)
	require.NoError(t, err)
	assert.Equal(t, body, got)
	require.NoError(t, rdr.Close())
}

func TestVerifiedHTTPGet_MultipleHashes_OneWrong(t *testing.T) {
	body := []byte("multi-hash payload")
	u := staticServer(t, http.StatusOK, body)
	hashes := tufmetadata.Hashes{
		"sha256": sha256Of(body),
		"sha512": make([]byte, sha512.Size),
	}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, int64(len(body)), hashes)
	require.NoError(t, err)
	_, err = io.ReadAll(rdr)
	err = errOrClose(err, rdr)
	assert.ErrorIs(t, err, hardening.ErrDigestMismatch, "every digest in the stack must be checked")
}

func TestVerifiedHTTPGet_DigestMismatch(t *testing.T) {
	body := []byte("the real content")
	u := staticServer(t, http.StatusOK, body)
	wrong := []byte("the fake content")
	require.Len(t, wrong, len(body), "test setup: lengths must match to isolate digest mismatch")
	hashes := tufmetadata.Hashes{"sha256": sha256Of(wrong)}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, int64(len(body)), hashes)
	require.NoError(t, err)
	_, err = io.ReadAll(rdr)
	err = errOrClose(err, rdr)
	assert.ErrorIs(t, err, hardening.ErrDigestMismatch)
}

func TestVerifiedHTTPGet_ShortBody(t *testing.T) {
	body := []byte("only seven")
	u := staticServer(t, http.StatusOK, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(body)}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, int64(len(body))+10, hashes)
	require.NoError(t, err)

	got, readErr := io.ReadAll(rdr)
	assert.Equal(t, body, got, "all bytes from the underlying stream should still be returned")
	require.ErrorIs(t, readErr, hardening.ErrSizeMismatch, "verify() runs on the EOF-bearing Read")
	assert.ErrorIs(t, rdr.Close(), hardening.ErrSizeMismatch, "Close must re-surface the mismatch for callers that only check Close")
}

func TestVerifiedHTTPGet_LongBody(t *testing.T) {
	body := []byte("this body is intentionally longer than the declared length")
	u := staticServer(t, http.StatusOK, body)
	declared := int64(5)
	// Hash the truncated prefix so size-mismatch isn't masked by digest-mismatch
	// (digest-mismatch takes precedence in verify()).
	hashes := tufmetadata.Hashes{"sha256": sha256Of(body[:declared])}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, declared, hashes)
	require.NoError(t, err)
	got, readErr := io.ReadAll(rdr)
	assert.Equal(t, body[:declared], got, "read should be truncated to declared length")

	err = errOrClose(readErr, rdr)
	assert.ErrorIs(t, err, hardening.ErrSizeMismatch)
}

func TestVerifiedHTTPGet_ZeroLengthEmptyBody(t *testing.T) {
	u := staticServer(t, http.StatusOK, nil)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.NoError(t, err)
	got, err := io.ReadAll(rdr)
	require.NoError(t, err)
	assert.Empty(t, got)
	require.NoError(t, rdr.Close())
}

func TestVerifiedHTTPGet_ZeroLengthNonEmptyBody(t *testing.T) {
	body := []byte("unexpected payload")
	u := staticServer(t, http.StatusOK, body)
	// Pair declared length 0 with the empty-string digest so size-mismatch
	// isn't masked by digest-mismatch.
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.NoError(t, err)
	_, err = io.ReadAll(rdr)
	err = errOrClose(err, rdr)
	assert.ErrorIs(t, err, hardening.ErrSizeMismatch)
}

func TestVerifiedHTTPGet_NegativeLength(t *testing.T) {
	body := []byte("anything")
	u := staticServer(t, http.StatusOK, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(body)}

	// The wrapper does not validate length itself; VerifiedReadCloser surfaces
	// ErrInvalidExpectedSize on the first Read/Close.
	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, -1, hashes)
	require.NoError(t, err)
	_, err = io.ReadAll(rdr)
	err = errOrClose(err, rdr)
	assert.ErrorIs(t, err, hardening.ErrInvalidExpectedSize)
}

func TestVerifiedHTTPGet_EmptyHashes(t *testing.T) {
	u := staticServer(t, http.StatusOK, []byte("anything"))

	rdr, res, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, tufmetadata.Hashes{})
	require.Error(t, err)
	assert.ErrorIs(t, err, tufext.ErrNoSupportedHashTypes) //nolint:testifylint // assert is fine for error path checks
	assert.Nil(t, rdr)
	assert.Nil(t, res)
}

func TestVerifiedHTTPGet_OnlyUnsupportedHash(t *testing.T) {
	u := staticServer(t, http.StatusOK, []byte("anything"))
	hashes := tufmetadata.Hashes{"md5": []byte("does-not-matter")}

	rdr, res, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.ErrorIs(t, err, tufext.ErrNoSupportedHashTypes) //nolint:testifylint // assert is fine for error path checks
	assert.Nil(t, rdr)
	assert.Nil(t, res)
}

func TestVerifiedHTTPGet_UnsupportedHashIgnoredAlongsideSupported(t *testing.T) {
	body := []byte("payload with mixed hash entries")
	u := staticServer(t, http.StatusOK, body)
	hashes := tufmetadata.Hashes{
		"sha256": sha256Of(body),
		"md5":    []byte("unsupported, should be ignored"),
	}

	rdr, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, int64(len(body)), hashes)
	require.NoError(t, err)
	got, err := io.ReadAll(rdr)
	require.NoError(t, err)
	assert.Equal(t, body, got)
	require.NoError(t, rdr.Close())
}

func TestVerifiedHTTPGet_NotFound(t *testing.T) {
	u := staticServer(t, http.StatusNotFound, []byte("not here"))
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	rdr, res, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist) //nolint:testifylint // assert is fine for error path checks
	assert.Nil(t, rdr)
	require.NotNil(t, res, "404 should still return the response for inspection")
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

func TestVerifiedHTTPGet_InternalServerError(t *testing.T) {
	u := staticServer(t, http.StatusInternalServerError, []byte("boom"))
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	rdr, res, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.NotErrorIs(t, err, fs.ErrNotExist, "non-404 status must not masquerade as ENOENT") //nolint:testifylint // assert is fine for error path checks
	assert.Contains(t, err.Error(), "500")
	assert.Nil(t, rdr)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
}

func TestVerifiedHTTPGet_ContextCancelledBeforeRequest(t *testing.T) {
	u := staticServer(t, http.StatusOK, []byte("never read"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	rdr, _, err := httputils.VerifiedHTTPGet(ctx, http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled) //nolint:testifylint // assert is fine for error path checks
	assert.Nil(t, rdr)
}

func TestVerifiedHTTPGet_ResponseBodyEqualsReturnedReader(t *testing.T) {
	body := []byte("guarded body")
	u := staticServer(t, http.StatusOK, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(body)}

	rdr, res, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, int64(len(body)), hashes)
	require.NoError(t, err)
	assert.Same(t, rdr, res.Body, "res.Body must point at the verified reader, not the raw transport stream")
	require.NoError(t, rdr.Close())
}

func TestVerifiedHTTPGet_ErrorBodyCaptured(t *testing.T) {
	body := []byte("backend says: artifact corrupt")
	u := staticServer(t, http.StatusInternalServerError, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	_, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server response:",
		"error must label the captured response body so operators can spot it")
	assert.Contains(t, err.Error(), "backend says: artifact corrupt",
		"server's response body must be surfaced in the error for diagnostics")
}

func TestVerifiedHTTPGet_ErrorBodyTruncatedAtMaxBytes(t *testing.T) {
	prefix := bytes.Repeat([]byte("A"), 8*1024)
	tail := []byte("ZZZ-SENTINEL-PAST-CAP")
	body := append(prefix, tail...)
	u := staticServer(t, http.StatusBadGateway, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	_, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AAAA",
		"a sample of the captured prefix must appear so we know capture happened, not just that the tail was dropped")
	assert.NotContains(t, err.Error(), "ZZZ-SENTINEL",
		"bytes after MaxErrorBytes (%d) must not appear in the error",
		httputils.MaxErrorBytes)
	assert.Less(t, len(err.Error()), 1024,
		"error string must remain bounded even when the server floods us")
}

func TestVerifiedHTTPGet_ErrorBodyQuotedNoRawControlBytes(t *testing.T) {
	body := []byte("\x1b[31mPWNED\x1b[0m\n\x00malicious\ttail")
	u := staticServer(t, http.StatusBadRequest, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	_, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	msg := err.Error()
	assert.NotContains(t, msg, "\x1b", "raw escape byte must not leak into the error")
	assert.NotContains(t, msg, "\x00", "raw NUL must not leak into the error")
	assert.Contains(t, msg, `\x1b`, "ANSI escape must appear escaped, not raw")
	assert.Contains(t, msg, `\x00`, "NUL must appear escaped, not raw")
}

func TestVerifiedHTTPGet_ErrorBodyEmpty(t *testing.T) {
	u := staticServer(t, http.StatusInternalServerError, nil)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	_, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server response empty",
		"an empty error body should be reported as such rather than as a read failure")
	assert.Contains(t, err.Error(), "500", "status code must remain in the error")
}

func TestVerifiedHTTPGet_ErrorBodySlowRollReturnsWithBufferedPrefixOnly(t *testing.T) {
	// No post-park writes: bytes written after VerifiedHTTPGet returns are
	// trivially absent from the frozen error string and would only invite
	// flakes. The test verifies that the function does not block waiting
	// for more bytes, by relying on the server never sending any.
	block := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(block) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("test server response writer does not implement http.Flusher")
			return
		}
		_, _ = w.Write([]byte("EARLY-CHUNK"))
		flusher.Flush()
		<-block
	}))
	// Cleanup is LIFO: unblock must run before srv.Close so the still-parked
	// handler can return; otherwise srv.Close deadlocks waiting on it.
	t.Cleanup(srv.Close)
	t.Cleanup(unblock)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	_, _, err = httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EARLY-CHUNK",
		"the prefix buffered before the server parked must be captured")
}

func TestVerifiedHTTPGet_ErrorBodyDeadlineFiresOnHangingServer(t *testing.T) {
	block := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(block) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-block
	}))
	// Cleanup is LIFO: unblock must run before srv.Close so the still-parked
	// handler can return; otherwise srv.Close deadlocks waiting on it.
	t.Cleanup(srv.Close)
	t.Cleanup(unblock)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	start := time.Now()
	_, _, err = httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "server response read failed",
		"a Read aborted by the deadline must take the read-failed branch (no body bytes were ever sent)")
	assert.GreaterOrEqual(t, elapsed, httputils.ErrorReadDeadline,
		"the deadline must not fire early; got %s < %s", elapsed, httputils.ErrorReadDeadline)
	// The lower bound is the load-bearing security check; the 20x upper
	// bound is just a generous hang guard for slow CI.
	assert.Less(t, elapsed, 20*httputils.ErrorReadDeadline,
		"ErrorReadDeadline must abort the Read, not let us hang; got %s", elapsed)
}

func TestVerifiedHTTPGet_NotFoundIncludesBody(t *testing.T) {
	body := []byte("artifact 'sha256:cafe' absent from index")
	u := staticServer(t, http.StatusNotFound, body)
	hashes := tufmetadata.Hashes{"sha256": sha256Of(nil)}

	_, _, err := httputils.VerifiedHTTPGet(t.Context(), http.DefaultClient, u, 0, hashes)
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist) //nolint:testifylint // assert is fine for error path checks
	assert.Contains(t, err.Error(), "artifact 'sha256:cafe' absent",
		"404 path must also surface the server's response body, not just ErrNotExist")
}

// errOrClose collapses Read vs Close error sourcing for callers that don't
// care which one surfaces the verification failure.
func errOrClose(readErr error, rdr io.ReadCloser) error {
	if readErr != nil {
		_ = rdr.Close()
		return readErr
	}
	return rdr.Close()
}
