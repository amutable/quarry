//go:build http

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/gorilla/handlers"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

func init() {
	app.Commands = append(app.Commands, httpCommand)
}

func httpErrHandler(fn func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := fn(rw, req)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			slog.ErrorContext(ctx, "Internal Server Error", "err", err.Error())
		}
	}
}

// sha256Empty is the sha256 hash of the empty string (used as a dummy
// value for BEST-BEFORE-YYYY-MM-DD).
const sha256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func validSysupdatePath(path string) bool {
	const _PATH_MAX = 4096 //nolint:revive // match unix.PAGE_SIZE naming style
	if path == "" || len(path) > _PATH_MAX || strings.HasPrefix(path, "/") {
		return false
	}
	for comp := range strings.SplitSeq(path, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return false
		}
	}
	return true
}

func serveSHA256SUMS(rw http.ResponseWriter, req *http.Request) (Err error) {
	ctx := req.Context()

	// FIXME: This needs to be re-created every time because go-tuf has no
	// mechanism to refresh an updater that has already been used to fetch
	// information.
	// TODO: Add support for a Refresh in Client that doesn't break like that.
	client, err := getClient(ctx)
	if err != nil {
		return fmt.Errorf("get tuf-client updaters: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, client)

	// Refresh all of the updaters first.
	var (
		errs   []error
		expiry time.Time
	)
	for repoName, updater := range client.IterRepos(ctx) {
		// Construct BEST-BEFORE-YYYY-MM-DD based on the earliest timestamp
		// expiry in any of the enabled repositories.
		meta := updater.GetTrustedMetadataSet()
		if meta.Timestamp == nil {
			// FIXME: The local client TrustedMetadata state does not get
			// filled until we do a refresh but go-tuf's client does not
			// allow Refresh on the same updater more than once(?!). So we
			// do a refresh here opportunistically.
			// TODO: Add a (*Client).Refresh helper to make this much less
			// fragile.
			if err := updater.Refresh(); err != nil {
				err := fmt.Errorf("refresh repo %s: %w", repoName, err)
				errs = append(errs, err)
			}
			meta = updater.GetTrustedMetadataSet()
		}
		timestampExpiry := meta.Timestamp.Signed.Expires
		if expiry.IsZero() || expiry.After(timestampExpiry) {
			// The BEST-BEFORE-* format only has day-resolution, so round to
			// the next day so that we never indicate that a repository is
			// invalid early. This tag in SHA256SUMS is also not really
			// security critical, TUF is actually protecting against the freeze
			// attack here.
			expiry = timestampExpiry.Add(24 * time.Hour)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("refresh repos: %w", err)
	}

	// TODO: We do not write to the ResponseWriter directly because we might
	// encounter errors during execution -- is that okay?
	sumfileBuf := bytes.NewBuffer(make([]byte, 0, 1<<16))

	if !expiry.IsZero() {
		fmt.Fprintf(sumfileBuf, "%s  BEST-BEFORE-%s\n", sha256Empty, expiry.Format(time.DateOnly))
	}

	for target, err := range client.IterTargetFiles(ctx) {
		if err != nil {
			return err
		}
		// Extension targets are consumed by quarry-sysupdate itself, not by
		// systemd-sysupdate.
		if _, _, ok := xsysupdate.CutExtensionTargetPrefix(target.Path); ok {
			slog.Debug("Stripped quarry extension target from generated SHA256SUMS",
				"target", target.Path)
			continue
		}
		if !validSysupdatePath(target.Path) {
			slog.Info("Stripped sysupdate-incompatible pathname from generated SHA256SUMS",
				"target", target.Path)
			continue
		}
		fmt.Fprintf(sumfileBuf, "%s  %s\n", target.Hashes["sha256"], target.Path)
	}

	rw.Header().Set("Content-Length", strconv.Itoa(sumfileBuf.Len()))
	rw.Header().Set("Content-Type", "text/plain")

	_, _ = io.Copy(rw, sumfileBuf)
	return nil
}

// rfc9530HashAlgos maps TUF hash algorithm names to the equivalent hash
// algorithm keys registered for use in RFC 9530 digest fields.
var rfc9530HashAlgos = map[string]string{
	"sha256": "sha-256",
	"sha512": "sha-512",
}

// hashesToContentDigest converts a set of TUF-represented hashes into an RFC
// 9530 Content-Digest dictionary value. Hash algorithms with no registered RFC
// 9530 equivalent are skipped, and users should make sure to not set
// Content-Digest if the returned string is empty (as that violates RFC 9530).
func hashesToContentDigest(hashes tufmetadata.Hashes) string {
	digests := make([]string, 0, len(hashes))
	for _, algoName := range slices.Sorted(maps.Keys(hashes)) {
		rfcAlgoName, ok := rfc9530HashAlgos[algoName]
		if !ok {
			continue
		}
		digests = append(digests, fmt.Sprintf("%s=:%s:",
			rfcAlgoName, base64.StdEncoding.EncodeToString(hashes[algoName])))
	}
	return strings.Join(digests, ", ")
}

func proxyTargetFile(rw http.ResponseWriter, req *http.Request) (Err error) {
	ctx := req.Context()

	// FIXME: This needs to be re-created every time because go-tuf has no
	// mechanism to refresh an updater that has already been used to fetch
	// information.
	// TODO: Add support for a Refresh in Client that doesn't break like that.
	client, err := getClient(ctx)
	if err != nil {
		return fmt.Errorf("get tuf-client updaters: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, client)

	// TODO: The updaters really should be sorted here so we can pick the first
	// one with a matching file.

	targetPath := filepath.Join(".", req.PathValue("target")) //nolint:forbidigo // lexical path conversion from absolute to relative

	info, err := client.GetTargetInfo(ctx, targetPath)
	if errors.Is(err, fs.ErrNotExist) {
		// Could not find the target file.
		http.NotFound(rw, req)
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetch target %s info: %w", targetPath, err)
	}
	infoExt := tufext.TargetFilesExt(info.TargetFiles)

	// Serve inline data directly if available to save on redirects.
	if data, err := infoExt.InlineData(); err != nil {
		return fmt.Errorf("bad target data in repo %s for target %s: %w", info.Repo.Name, targetPath, err)
	} else if data != nil {
		rw.Header().Set("Content-Length", strconv.Itoa(len(data)))
		rw.Header().Set("Content-Type", "application/octet-stream")
		if digestValue := hashesToContentDigest(info.Hashes); digestValue != "" {
			rw.Header().Set("Content-Digest", digestValue)
			// Include Repr-Digest for inline data as well as redirects so that
			// users can rely on just Repr-Digest if they prefer.
			rw.Header().Set("Repr-Digest", digestValue)
		}
		_, _ = rw.Write(data)
		return nil
	}

	// A redirect would send systemd-pull to the repo without this repo's
	// request signatures, so targets of a repo with auth are proxied instead.
	if info.Repo.Client != nil {
		return streamTargetFile(rw, req, info)
	}

	// Redirect to the first target URL.
	// TODO(uapi16): Once we get UAPI.16 support into systemd, we can serve a
	// manifest that lists every URL candidate as an alternative contents source
	// (as "quarry-client list --uapi-16" does) and drop this shim entirely.
	dataRootURL, err := info.Repo.DataURL()
	if err != nil {
		return fmt.Errorf("bad repo %s definition: cannot compute target url: %w", info.Repo.Name, err)
	}
	for url, err := range infoExt.FetchURLs(dataRootURL) {
		if err != nil {
			return fmt.Errorf("bad target data in repo %s for target %s: cannot compute target url: %w", info.Repo.Name, targetPath, err)
		}
		// We cannot use Content-Digest or Content-Length with redirects (they
		// represent the body of the redirect itself) but RFC 9530 section 3
		// implies that Repr-Digest is valid to use in this case. Unfortunately
		// there is no Repr-Length so we need a custom header for that.
		rw.Header().Set("X-Quarry-Content-Length", strconv.FormatInt(info.Length, 10))
		if digestValue := hashesToContentDigest(info.Hashes); digestValue != "" {
			rw.Header().Set("Repr-Digest", digestValue)
			// Include our old extension header for compatibility.
			rw.Header().Set("X-Quarry-Content-Digest", digestValue)
		}
		// In order for Repr-Digest to be valid (and to reduce noise), stop
		// [http.Redirect] from outputting a dummy HTML note body for the
		// redirect.
		rw.Header()["Content-Type"] = nil
		http.Redirect(rw, req, url.String(), http.StatusFound)
		return nil
	}
	return errors.New("no fetch urls defined for target")
}

// streamTargetFile serves the target's contents, fetched with the repo's own
// HTTP client. The digest is only checked at EOF, after the whole body has been
// written, so a mismatch aborts the connection but cannot take back the bytes:
// the client must check the body against Content-Digest.
func streamTargetFile(rw http.ResponseWriter, req *http.Request, info *tufclient.TargetInfo) error {
	ctx := req.Context()

	rdr, err := info.Fetch(ctx)
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(rw, req)
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetch target %s from repo %s: %w", info.Path, info.Repo.Name, err)
	}

	rw.Header().Set("Content-Length", strconv.FormatInt(info.Length, 10))
	rw.Header().Set("Content-Type", "application/octet-stream")
	if digestValue := hashesToContentDigest(info.Hashes); digestValue != "" {
		rw.Header().Set("Content-Digest", digestValue)
		rw.Header().Set("Repr-Digest", digestValue)
	}
	_, copyErr := io.Copy(rw, rdr)
	if err := errors.Join(copyErr, rdr.Close()); err != nil {
		slog.ErrorContext(ctx, "Aborting target response",
			"repo", info.Repo.Name, "target", info.Path, "err", err.Error())
		panic(http.ErrAbortHandler)
	}
	return nil
}

// newSysupdateHandler returns a [http.Handler] that impements our sysupdate
// SHA256SUM-based compatibility shim.
func newSysupdateHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/SHA256SUMS", httpErrHandler(serveSHA256SUMS))
	mux.HandleFunc("/{target...}", httpErrHandler(proxyTargetFile))
	return mux
}

var httpCommand = &cli.Command{
	Name:  "http",
	Usage: "spawn a compatibility-shim SHA256SUMS-based sysupdate http server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "bind-address",
			Aliases: []string{"H"},
			Usage:   "address ([host]:port) to bind to",
			Value:   ":20835", // hex("Qc")
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		listeners, err := activation.Listeners()
		if err != nil {
			return err
		}

		// TODO: Support serving via TLS?

		var proto http.Protocols
		proto.SetHTTP1(true)
		proto.SetHTTP2(false) // no TLS
		proto.SetUnencryptedHTTP2(true)

		handler := newSysupdateHandler()
		handler = handlers.CombinedLoggingHandler(os.Stdout, handler)

		server := &http.Server{
			Addr:        cmd.String("bind-address"),
			Handler:     handler,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
			Protocols:   &proto,
		}
		mustFprintf(os.Stdout, "Listening on http://%s...\n", server.Addr)

		var (
			wg    sync.WaitGroup
			errCh = make(chan error, len(listeners)+1)
		)
		if len(listeners) > 0 {
			for _, listener := range listeners {
				wg.Go(func() {
					if err := server.Serve(listener); err != nil {
						errCh <- err
					}
				})
			}
		} else {
			wg.Go(func() {
				if err := server.ListenAndServe(); err != nil {
					errCh <- err
				}
			})
		}
		if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
			_ = server.Close()
			return err
		}
		wg.Wait()
		close(errCh)

		// TODO: Support graceful shutdown and ErrServerClosed.
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	},
}
