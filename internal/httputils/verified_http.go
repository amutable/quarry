// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httputils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"time"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufext"
)

// MaxErrorBytes is the maximum number of bytes that will be read from the HTTP
// server in the case of an error (for the purposes of providing diagnostic
// information to the user).
const MaxErrorBytes = 128

// ErrorReadDeadline is how long the client will wait for an error message from
// the server.
const ErrorReadDeadline = 200 * time.Millisecond

// VerifiedHTTPGet is a wrapper around client.Do but the returned
// [io.ReadCloser] is wrapped in a [hardening.VerifiedReadCloser] so that
// endless read and other attacks are protected against. You *must* check the
// error return from [io.ReadCloser.Close] once you are done reading data and
// before you use it for anything.
//
// TODO: Should we also return the response information...?
func VerifiedHTTPGet(ctx context.Context, client *http.Client, url *url.URL, length int64, hashes tufmetadata.Hashes) (_ io.ReadCloser, _ *http.Response, Err error) {
	// Make sure the hashes are good before doing the request -- they get
	// re-converted later in [tufext.VerifiedReadCloser].
	if _, err := tufext.HashesToDigest(hashes); err != nil {
		return nil, nil, fmt.Errorf("convert TUF hashes to digests: %w", err)
	}

	// cancelReq is used in the error path to kill slow connections.
	reqCtx, cancelReq := context.WithCancel(ctx)
	defer func() {
		if Err != nil {
			cancelReq()
		}
	}()
	req, err := http.NewRequestWithContext(reqCtx, "GET", url.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create http request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if res.StatusCode != http.StatusOK {
		err := fmt.Errorf("fetch %s failed with status code %.3d", url, res.StatusCode)

		// Make sure we do not block here too long.
		cancelTimer := time.AfterFunc(ErrorReadDeadline, func() { cancelReq() })
		defer cancelTimer.Stop()

		// Try to read some bytes of the body to include in the error message.
		data := make([]byte, MaxErrorBytes)

		// Read can return (n > 0, err) so if we got any data just use
		// that, otherwise include the error, and finally if everything was
		// empty say so. This is all just for diagnostics, no need to be
		// super rigorous.
		n, readErr := res.Body.Read(data)
		switch {
		case n > 0:
			err = fmt.Errorf("%w [server response: %q]", err, string(data[:n]))
		case readErr == nil, errors.Is(readErr, io.EOF):
			err = fmt.Errorf("%w [server response empty]", err)
		default:
			err = fmt.Errorf("%w [server response read failed: %w]", err, readErr)
		}
		if closeErr := res.Body.Close(); closeErr != nil {
			err = fmt.Errorf("%w (and error when closing body: %w)", err, closeErr)
		}
		if res.StatusCode == http.StatusNotFound {
			// Emulate ENOENT for 404.
			err = fmt.Errorf("%w: %w", err, fs.ErrNotExist)
		}
		return nil, res, err
	}
	rdr, err := tufext.VerifiedReadCloser(res.Body, length, hashes)
	if err != nil {
		// Unreachable thanks to the pre-flight check above, but be safe.
		_ = res.Body.Close()
		return nil, res, err
	}
	// Replace the response reader with the hardened version to avoid caller
	// bugs where they accidentally read from Response.Body.
	res.Body = rdr
	return rdr, res, nil
}
