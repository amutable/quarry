//go:build http && insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"snai.pe/go-varlink"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

// releaseFile is one file of a release, split into the image name and the rest
// of the file name so that a [releaseLayout] can decide where the version goes.
type releaseFile struct{ name, suffix string }

// releaseLayout maps a release file (of the given version) to its target path.
type releaseLayout func(version string, file releaseFile) string

// The target names are modelled on the nightly AmutableOS update repository: a
// UKI, the /usr partition image with its verity data and signature, the SBOM
// supplement, and a sysext built against that OS version -- all for x86-64.
var (
	efiFile       = releaseFile{"AmutableOS", "x86-64.efi"}
	usrFile       = releaseFile{"AmutableOS", "x86-64.usr-x86-64.5d899b8f98855501c027fb6ea711cc5c.raw"}
	verityFile    = releaseFile{"AmutableOS", "x86-64.usr-x86-64-verity.355016fbc19bac124b46220e43dcc3d4.raw"}
	veritySigFile = releaseFile{"AmutableOS", "x86-64.usr-x86-64-verity-sig.3bcd158bcf694db58280e58febae49eb.raw"}
	sbomFile      = releaseFile{"AmutableOS", "x86-64.cdx.json"}
	sysextFile    = releaseFile{"interactive", "x86-64.sysext.raw"}

	releaseFiles = []releaseFile{efiFile, usrFile, verityFile, veritySigFile, sbomFile, sysextFile}
)

// flatLayout is the current nightly layout, with every file in the repository
// root with the classic <os>_@v_<suffix> name.
func flatLayout(version string, file releaseFile) string {
	return file.name + "_" + version + "_" + file.suffix
}

// subdirLayout is the proposed layout: each release in its own versioned
// directory, so the sysext lives next to the OS version it was built against.
func subdirLayout(version string, file releaseFile) string {
	return "nightly-" + version + "/" + file.name + "_" + file.suffix
}

// releaseLayouts are the release layouts the server must handle, each paired
// with the other one (whose names for the same files must not exist).
var releaseLayouts = []struct {
	name          string
	layout, other releaseLayout
}{
	{"Flat", flatLayout, subdirLayout},
	{"Subdir", subdirLayout, flatLayout},
}

// nightlyVersion is the release most tests publish (in the flat layout, with
// the *Target names below), as they do not care about the layout.
const nightlyVersion = "26.08.25-0502"

var (
	efiTarget       = flatLayout(nightlyVersion, efiFile)
	usrTarget       = flatLayout(nightlyVersion, usrFile)
	veritySigTarget = flatLayout(nightlyVersion, veritySigFile)
	sysextTarget    = flatLayout(nightlyVersion, sysextFile)
)

// layouts are the set of possible repo structures we might end up seeing.
var layouts = []struct {
	name string
	opts []testrepo.Option
}{
	{"Standard", nil},
	{"MetaSubdir", []testrepo.Option{testrepo.WithMetaSubdir("update/tuf")}},
	{"DataSubdir", []testrepo.Option{testrepo.WithDataSubdir("update")}},
	{"SharedParent", []testrepo.Option{
		testrepo.WithMetaSubdir("update/tuf"),
		testrepo.WithDataSubdir("update/images"),
	}},
	{"DataAtRoot", []testrepo.Option{
		testrepo.WithMetaSubdir("tuf"),
		testrepo.WithDataSubdir(""),
	}},
}

// startServer serves the sysupdate compatibility server with ctx as the base
// context of every request, mirroring how "quarry-client http" wires up
// [http.Server].
func startServer(ctx context.Context, t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(newSysupdateHandler())
	server.Config.BaseContext = func(net.Listener) context.Context { return ctx }
	server.Start()
	t.Cleanup(server.Close)
	return server
}

// newServer serves the server for a client configured with the given
// repository blocks (see [testrepo.Server.ConfigBlock]).
func newServer(t *testing.T, repoBlocks ...string) *httptest.Server {
	t.Helper()
	cfg := testrepo.Config(t, repoBlocks...)
	return startServer(cliext.WithCtxConfig(t.Context(), cfg), t)
}

// withOrderIndex returns a [testrepo.ConfigBlockOption] that sets the
// repository order index.
func withOrderIndex(index int64) testrepo.ConfigBlockOption {
	return testrepo.ConfigWithExtraLines(fmt.Sprintf("order_index = %d", index))
}

func serverDo(t *testing.T, server *httptest.Server, path string, followRedirects bool) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, http.NoBody)
	require.NoError(t, err)

	client := &http.Client{Transport: server.Client().Transport}
	if !followRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp, body
}

// serverGet does a GET request against the server and returns the response along
// with its body. Redirects are not followed, so that the redirect response
// (which is what sysupdate sees first) can be inspected directly.
func serverGet(t *testing.T, server *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	return serverDo(t, server, path, false)
}

// serverGetFollow is like [serverGet] but follows redirects, returning the final
// response (which for redirected targets comes from the repository server).
func serverGetFollow(t *testing.T, server *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	return serverDo(t, server, path, true)
}

// dataURL returns the URL the given target is served from by the repository
// server, which is where the server is expected to redirect to.
func dataURL(srv *testrepo.Server, target string) string {
	return srv.DataRootURL() + "/" + target
}

// dataURLPath returns the URL path of [dataURL], for use as a mux pattern with
// [testrepo.Server.Handle].
func dataURLPath(srv *testrepo.Server, target string) string {
	return strings.TrimPrefix(dataURL(srv, target), srv.URL)
}

// sha256Digest returns the RFC 9530 digest dictionary the server is expected to
// emit for a target with the given contents (and only a sha256 hash).
func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// newTargetFiles returns target file metadata describing data. The path is
// left unset, as [testrepo.AddTargetOp] keys the target by its path argument.
func newTargetFiles(data []byte) *tufmetadata.TargetFiles {
	sum := sha256.Sum256(data)
	return &tufmetadata.TargetFiles{
		Length: int64(len(data)),
		Hashes: tufmetadata.Hashes{"sha256": sum[:]},
	}
}

// publishRelease publishes one release (every one of releaseFiles) of the
// given version to srv using layout, and returns the contents keyed by target
// path along with the new timestamp. Like the real repository, the /usr image
// carries the "supplemented-by" custom metadata linking it to its SBOM.
func publishRelease(t *testing.T, srv *testrepo.Server, layout releaseLayout, version string) (map[string][]byte, *tufext.SignedTimestamp) {
	t.Helper()
	files := make(map[string][]byte, len(releaseFiles))
	ops := make([]tufrepo.TxnOp, 0, len(releaseFiles))
	for _, file := range releaseFiles {
		path := layout(version, file)
		data := []byte(file.name + " " + file.suffix + " " + version)
		target := srv.WriteTarget(t, path, bytes.NewReader(data))
		if file == usrFile {
			custom := json.RawMessage(`{"quarry":{"supplemented-by":{"` + layout(version, sbomFile) + `":{"type":"application/vnd.cyclonedx+json"}}}}`)
			target.Custom = &custom
		}
		files[path] = data
		ops = append(ops, testrepo.AddTargetOp(path, target))
	}
	return files, srv.Publish(t, ops...)
}

// publishNightlyImage publishes the nightlyVersion release in the flat layout,
// for tests that do not care about the layout.
func publishNightlyImage(t *testing.T, srv *testrepo.Server) (map[string][]byte, *tufext.SignedTimestamp) {
	t.Helper()
	return publishRelease(t, srv, flatLayout, nightlyVersion)
}

// waitForNextVersion makes sure a subsequent publish gets a distinct metadata
// version -- versions are derived from the transaction start time in
// milliseconds, so two publishes within the same millisecond would collide.
func waitForNextVersion() {
	time.Sleep(2 * time.Millisecond)
}

// sumsLine returns the SHA256SUMS line for the given target contents.
func sumsLine(name string, data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name
}

// expectedSums returns the sorted SHA256SUMS lines for the given targets.
func expectedSums(files map[string][]byte) []string {
	entries := make([]string, 0, len(files))
	for name, data := range files {
		entries = append(entries, sumsLine(name, data))
	}
	slices.Sort(entries)
	return entries
}

// bestBeforeLine returns the BEST-BEFORE line the server generates for metadata
// that expires at expiry (which is rounded up to the next day).
func bestBeforeLine(expiry time.Time) string {
	return sha256Empty + "  BEST-BEFORE-" + expiry.Add(24*time.Hour).Format(time.DateOnly)
}

// parseSums splits a SHA256SUMS body into its BEST-BEFORE line (if any) and
// the sorted remaining lines. The server emits the entries in TUF metadata
// iteration order, which is not stable, so they have to be compared as a set.
func parseSums(t *testing.T, body []byte) (bestBefore string, entries []string) {
	t.Helper()
	if len(body) == 0 {
		return "", nil
	}
	text := string(body)
	require.True(t, strings.HasSuffix(text, "\n"), "SHA256SUMS must end with a newline")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if strings.HasPrefix(lines[0], sha256Empty+"  BEST-BEFORE-") {
		bestBefore, lines = lines[0], lines[1:]
	}
	slices.Sort(lines)
	return bestBefore, lines
}

// Every target that is not inlined is forwarded with a redirect to its
// location under the repository's data_root_url, carrying the target's size
// and digest so that clients can verify the body without any extra
// round-trips. The redirect body must be empty (and must not be described by
// Content-* headers) for Repr-Digest to be meaningful (RFC 9530 section 3).
func TestHTTPProxyTarget_Redirect(t *testing.T) {
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			srv := testrepo.New(t, layout.opts...)
			files, _ := publishNightlyImage(t, srv)
			server := newServer(t, srv.ConfigBlock("nightly"))

			for name, data := range files {
				t.Run(name, func(t *testing.T) {
					resp, body := serverGet(t, server, "/"+name)
					assert.Equal(t, http.StatusFound, resp.StatusCode)
					assert.Empty(t, body)
					assert.Equal(t, dataURL(srv, name), resp.Header.Get("Location"))
					assert.Equal(t, strconv.Itoa(len(data)), resp.Header.Get("X-Quarry-Content-Length"))
					assert.Equal(t, sha256Digest(data), resp.Header.Get("Repr-Digest"))
					assert.Equal(t, sha256Digest(data), resp.Header.Get("X-Quarry-Content-Digest"))
					assert.Empty(t, resp.Header.Values("Content-Type"))
					assert.Empty(t, resp.Header.Values("Content-Digest"))
				})
			}
		})
	}
}

// Following the redirect must land on the repository's copy of the target --
// the redirect has to point at where the data actually lives.
func TestHTTPProxyTarget_FollowRedirect(t *testing.T) {
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			srv := testrepo.New(t, layout.opts...)
			files, _ := publishNightlyImage(t, srv)
			server := newServer(t, srv.ConfigBlock("nightly"))

			resp, body := serverGetFollow(t, server, "/"+usrTarget)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, files[usrTarget], body)
			assert.Equal(t, dataURL(srv, usrTarget), resp.Request.URL.String())
		})
	}
}

// Targets with an override URL are redirected there rather than to the
// data_root_url -- the override is where the data is, and the default location
// might not have it at all.
func TestHTTPProxyTarget_OverrideURL(t *testing.T) {
	data := []byte("sysext image hosted on a mirror")
	srv := testrepo.New(t)
	// Serve the sysext from a non-standard location only.
	mirrorPath := "/mirror/" + sysextTarget
	srv.Handle(mirrorPath, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write(data)
	}))
	mirrorURL, err := url.Parse(srv.URL + mirrorPath)
	require.NoError(t, err)

	target := newTargetFiles(data)
	tufext.TargetFilesExt(target).WithOverrideURL(mirrorURL)
	srv.Publish(t, testrepo.AddTargetOp(sysextTarget, target))
	server := newServer(t, srv.ConfigBlock("nightly"))

	resp, _ := serverGet(t, server, "/"+sysextTarget)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, mirrorURL.String(), resp.Header.Get("Location"))
	assert.Equal(t, strconv.Itoa(len(data)), resp.Header.Get("X-Quarry-Content-Length"))
	assert.Equal(t, sha256Digest(data), resp.Header.Get("Repr-Digest"))

	// The default location does not have the target, so only the override URL
	// can satisfy a client following the redirect.
	resp, body := serverGetFollow(t, server, "/"+sysextTarget)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, data, body)
}

// Small targets (like the 16KiB verity signature in the nightly repository)
// can be inlined into the TUF metadata, in which case the server serves them
// directly instead of redirecting -- with both Content-Digest and Repr-Digest
// so that clients can rely on either.
func TestHTTPProxyTarget_InlineData(t *testing.T) {
	data := []byte("/usr verity roothash signature (inlined)")
	srv := testrepo.New(t)
	// Inlined targets are usually not uploaded at all, so fail if anything
	// tries to fetch it (the exact-path pattern wins over the data root).
	srv.Handle(dataURLPath(srv, veritySigTarget), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Errorf("unexpected request for inlined target: %s", req.URL)
		http.NotFound(rw, req)
	}))
	target := newTargetFiles(data)
	tufext.TargetFilesExt(target).WithInlineData(data)
	srv.Publish(t, testrepo.AddTargetOp(veritySigTarget, target))
	server := newServer(t, srv.ConfigBlock("nightly"))

	resp, body := serverGetFollow(t, server, "/"+veritySigTarget)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, data, body)
	assert.Equal(t, server.URL+"/"+veritySigTarget, resp.Request.URL.String())
	assert.Empty(t, resp.Header.Values("Location"))
	assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, strconv.Itoa(len(data)), resp.Header.Get("Content-Length"))
	assert.Equal(t, sha256Digest(data), resp.Header.Get("Content-Digest"))
	assert.Equal(t, sha256Digest(data), resp.Header.Get("Repr-Digest"))
}

// Empty targets are served directly even when the repository did not inline
// them -- their contents are known from the metadata alone, so there is
// nothing worth redirecting to.
func TestHTTPProxyTarget_ZeroLength(t *testing.T) {
	const emptyTarget = "an-empty-file.txt"
	srv := testrepo.New(t)
	// The target is deliberately never uploaded, so fail if anything tries to
	// fetch it (the exact-path pattern wins over the data root).
	srv.Handle(dataURLPath(srv, emptyTarget), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Errorf("unexpected request for empty target: %s", req.URL)
		http.NotFound(rw, req)
	}))
	srv.Publish(t, testrepo.AddTargetOp(emptyTarget, newTargetFiles([]byte{})))
	server := newServer(t, srv.ConfigBlock("nightly"))

	resp, body := serverGetFollow(t, server, "/"+emptyTarget)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t, server.URL+"/"+emptyTarget, resp.Request.URL.String())
	assert.Empty(t, resp.Header.Values("Location"))
	assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "0", resp.Header.Get("Content-Length"))
	assert.Equal(t, sha256Digest(nil), resp.Header.Get("Content-Digest"))
	assert.Equal(t, sha256Digest(nil), resp.Header.Get("Repr-Digest"))
}

// Inline data that does not match the target's hashes is rejected. Unlike
// [tufclient.TargetInfo.Fetch] (which falls back to the fetch URLs), the server
// treats this as a server error rather than redirecting to a copy that might
// be fine. This pins that behaviour so that any change to it is deliberate.
func TestHTTPProxyTarget_InlineDataCorrupt(t *testing.T) {
	data := []byte("the genuine signature")
	srv := testrepo.New(t)
	target := srv.WriteTarget(t, veritySigTarget, bytes.NewReader(data))
	tufext.TargetFilesExt(target).WithInlineData([]byte("a corrupted signature"))
	srv.Publish(t, testrepo.AddTargetOp(veritySigTarget, target))
	server := newServer(t, srv.ConfigBlock("nightly"))

	resp, body := serverGet(t, server, "/"+veritySigTarget)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "Internal Server Error\n", string(body))
}

// Every hash algorithm with an RFC 9530 registration is included in the digest
// headers (in sorted order), while other algorithms in the TUF metadata are
// left out.
func TestHTTPProxyTarget_DigestAlgorithms(t *testing.T) {
	data := []byte("unified kernel image with several hashes")
	srv := testrepo.New(t)
	target := srv.WriteTarget(t, efiTarget, bytes.NewReader(data))
	sha512Sum := sha512.Sum512(data)
	target.Hashes["sha512"] = sha512Sum[:]
	target.Hashes["blake2b-256"] = bytes.Repeat([]byte{0xaa}, 32) // no RFC 9530 registration
	srv.Publish(t, testrepo.AddTargetOp(efiTarget, target))
	server := newServer(t, srv.ConfigBlock("nightly"))

	want := sha256Digest(data) + ", sha-512=:" + base64.StdEncoding.EncodeToString(sha512Sum[:]) + ":"
	resp, _ := serverGet(t, server, "/"+efiTarget)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, want, resp.Header.Get("Repr-Digest"))
	assert.Equal(t, want, resp.Header.Get("X-Quarry-Content-Digest"))
}

// Unknown targets are a 404 -- including the repository root, which sysupdate
// never requests but the catch-all route still has to answer sensibly.
func TestHTTPProxyTarget_NotFound(t *testing.T) {
	srv := testrepo.New(t)
	publishNightlyImage(t, srv)
	server := newServer(t, srv.ConfigBlock("nightly"))

	for _, path := range []string{
		"/AmutableOS_26.08.24-0000_x86-64.efi", // an older build that was never published
		"/" + strings.ToLower(efiTarget),       // target names are case-sensitive
		"/nightly/" + efiTarget,                // the repository name is not part of the path
		"/",
	} {
		t.Run(path, func(t *testing.T) {
			resp, _ := serverGet(t, server, path)
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}

// The nightly repository also publishes its own SHA256SUMS (and a detached
// SHA256SUMS.gpg signature) as regular targets, but the server must always serve
// the SHA256SUMS it generates from the TUF metadata -- that is the whole point
// of the server -- while any other target with a SHA256SUMS prefix is proxied
// like everything else.
func TestHTTPProxyTarget_SHA256SUMSPrecedence(t *testing.T) {
	upstreamSums := []byte("0000000000000000000000000000000000000000000000000000000000000000  stale.raw\n")
	srv := testrepo.New(t)
	files, _ := publishNightlyImage(t, srv)
	waitForNextVersion()
	timestamp := srv.Publish(t,
		srv.AddTarget(t, "SHA256SUMS", bytes.NewReader(upstreamSums)),
		srv.AddTarget(t, "SHA256SUMS.gpg", strings.NewReader("detached signature")),
	)
	files["SHA256SUMS"] = upstreamSums
	files["SHA256SUMS.gpg"] = []byte("detached signature")
	server := newServer(t, srv.ConfigBlock("nightly"))

	resp, body := serverGet(t, server, "/SHA256SUMS")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
	bestBefore, entries := parseSums(t, body)
	assert.Equal(t, bestBeforeLine(timestamp.Signed.Expires), bestBefore)
	assert.Equal(t, expectedSums(files), entries)
	assert.NotContains(t, string(body), "stale.raw", "the upstream SHA256SUMS target must not be served")

	resp, _ = serverGet(t, server, "/SHA256SUMS.gpg")
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, dataURL(srv, "SHA256SUMS.gpg"), resp.Header.Get("Location"))
}

// Non-canonical request paths never reach the target lookup: [http.ServeMux]
// redirects them (with a 307) to the cleaned path first, which sysupdate then
// follows, so "..", "." and doubled slashes cannot be used to name a target. A
// trailing slash is the exception -- it survives the cleaning and is stripped
// by the target path conversion instead.
func TestHTTPProxyTarget_PathCleaning(t *testing.T) {
	srv := testrepo.New(t)
	publishNightlyImage(t, srv)
	server := newServer(t, srv.ConfigBlock("nightly"))

	for _, tc := range []struct{ path, cleaned string }{
		{"//" + efiTarget, "/" + efiTarget},
		{"/./" + efiTarget, "/" + efiTarget},
		{"/older-build/../" + efiTarget, "/" + efiTarget},
		{"/../" + efiTarget, "/" + efiTarget},
	} {
		t.Run(tc.path, func(t *testing.T) {
			resp, _ := serverGet(t, server, tc.path)
			assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
			assert.Equal(t, tc.cleaned, resp.Header.Get("Location"))
		})
	}

	t.Run("TrailingSlash", func(t *testing.T) {
		resp, _ := serverGet(t, server, "/"+efiTarget+"/")
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, dataURL(srv, efiTarget), resp.Header.Get("Location"))
	})
}

// Repositories are consulted in order_index order, so a target present in
// several repositories is forwarded to the highest-priority repository that
// has it, and lower-priority repositories only supply the targets that the
// higher-priority ones lack.
func TestHTTPProxyTarget_MultiRepo(t *testing.T) {
	stable, nightly := testrepo.New(t), testrepo.New(t)
	stableEFI, nightlyEFI := []byte("stable unified kernel image"), []byte("nightly unified kernel image")
	stable.Publish(t, stable.AddTarget(t, efiTarget, bytes.NewReader(stableEFI)))
	nightly.Publish(t,
		nightly.AddTarget(t, efiTarget, bytes.NewReader(nightlyEFI)),
		nightly.AddTarget(t, sysextTarget, strings.NewReader("nightly sysext")),
	)
	// Listed out of order (and with names sorting the other way) to make sure
	// order_index is what decides.
	server := newServer(t,
		nightly.ConfigBlock("nightly", withOrderIndex(200)),
		stable.ConfigBlock("stable", withOrderIndex(10)),
	)

	resp, _ := serverGet(t, server, "/"+efiTarget)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, dataURL(stable, efiTarget), resp.Header.Get("Location"))
	assert.Equal(t, sha256Digest(stableEFI), resp.Header.Get("Repr-Digest"))
	_, body := serverGetFollow(t, server, "/"+efiTarget)
	assert.Equal(t, stableEFI, body)

	resp, _ = serverGet(t, server, "/"+sysextTarget)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, dataURL(nightly, sysextTarget), resp.Header.Get("Location"))
}

// A repository whose root.json cannot be fetched is skipped by the client, so
// the server keeps serving the remaining repositories. With nothing left to
// serve, targets are 404 and SHA256SUMS is empty (there is no metadata to
// derive a BEST-BEFORE date from).
func TestHTTP_BrokenRepo(t *testing.T) {
	valid, broken := testrepo.New(t), testrepo.NewBroken(t)
	files, timestamp := publishNightlyImage(t, valid)

	t.Run("AlongsideValid", func(t *testing.T) {
		server := newServer(t, valid.ConfigBlock("nightly"), broken.ConfigBlock("broken"))

		resp, _ := serverGet(t, server, "/"+efiTarget)
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, dataURL(valid, efiTarget), resp.Header.Get("Location"))

		resp, body := serverGet(t, server, "/SHA256SUMS")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		bestBefore, entries := parseSums(t, body)
		assert.Equal(t, bestBeforeLine(timestamp.Signed.Expires), bestBefore)
		assert.Equal(t, expectedSums(files), entries)
	})

	t.Run("Alone", func(t *testing.T) {
		server := newServer(t, broken.ConfigBlock("broken"))

		resp, _ := serverGet(t, server, "/"+efiTarget)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		resp, body := serverGet(t, server, "/SHA256SUMS")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "0", resp.Header.Get("Content-Length"))
		assert.Empty(t, body)
	})
}

// The generated SHA256SUMS lists every target in the coreutils sha256sum
// format that systemd-sysupdate parses, preceded by the BEST-BEFORE marker
// derived from the timestamp expiry. Custom target metadata (like the nightly
// repository's SBOM links) has no effect on the listing.
func TestHTTPSHA256SUMS(t *testing.T) {
	srv := testrepo.New(t)
	files, timestamp := publishNightlyImage(t, srv)
	server := newServer(t, srv.ConfigBlock("nightly"))

	resp, body := serverGet(t, server, "/SHA256SUMS")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
	assert.Equal(t, strconv.Itoa(len(body)), resp.Header.Get("Content-Length"))

	bestBefore, entries := parseSums(t, body)
	assert.Equal(t, bestBeforeLine(timestamp.Signed.Expires), bestBefore)
	assert.Equal(t, expectedSums(files), entries)
}

// Targets that systemd-sysupdate cannot consume are left out of SHA256SUMS:
// quarry's own extension targets (transfer definitions) and
// paths that sysupdate would reject or misinterpret. Targets in subdirectories
// are fine.
func TestHTTPSHA256SUMS_Filtered(t *testing.T) {
	srv := testrepo.New(t)
	files, _ := publishNightlyImage(t, srv)
	waitForNextVersion()
	nestedSysext := []byte("sysext in a subdirectory")
	timestamp := srv.Publish(t,
		srv.AddTarget(t, "sysexts/"+sysextTarget, bytes.NewReader(nestedSysext)),
		// Consumed by quarry-sysupdate itself.
		testrepo.AddTargetOp(xsysupdate.TransferFilePrefix+"AmutableOS.transfer", newTargetFiles([]byte("[Transfer]\n"))),
		// Paths sysupdate must never see.
		testrepo.AddTargetOp("/"+efiTarget, newTargetFiles([]byte("absolute path"))),
		testrepo.AddTargetOp("../"+efiTarget, newTargetFiles([]byte("parent directory"))),
		testrepo.AddTargetOp("sysexts/../"+efiTarget, newTargetFiles([]byte("interior parent directory"))),
		testrepo.AddTargetOp("sysexts/./"+sysextTarget, newTargetFiles([]byte("interior current directory"))),
		testrepo.AddTargetOp("sysexts//"+sysextTarget, newTargetFiles([]byte("empty component"))),
		testrepo.AddTargetOp("sysexts/", newTargetFiles([]byte("trailing slash"))),
	)
	files["sysexts/"+sysextTarget] = nestedSysext
	server := newServer(t, srv.ConfigBlock("nightly"))

	resp, body := serverGet(t, server, "/SHA256SUMS")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	bestBefore, entries := parseSums(t, body)
	assert.Equal(t, bestBeforeLine(timestamp.Signed.Expires), bestBefore)
	assert.Equal(t, expectedSums(files), entries)
}

// With several repositories, SHA256SUMS lists each target once (from the
// highest-priority repository that has it) and BEST-BEFORE reflects the
// earliest timestamp expiry across all of them -- the listing is only as fresh
// as its least fresh source.
func TestHTTPSHA256SUMS_MultiRepo(t *testing.T) {
	stable, nightly := testrepo.New(t), testrepo.New(t)
	stableEFI, nightlyEFI, nightlySysext := []byte("stable unified kernel image"), []byte("nightly unified kernel image"), []byte("nightly sysext")
	stableTimestamp := stable.Publish(t, stable.AddTarget(t, efiTarget, bytes.NewReader(stableEFI)))

	// Publish the nightly repository "from the future" so that its timestamp
	// expires well after the stable repository's one.
	tx := nightly.TxnStart(t)
	tx.RefTime = tx.RefTime.Add(3 * 24 * time.Hour)
	require.NoError(t, tx.Apply(t.Context(),
		nightly.AddTarget(t, efiTarget, bytes.NewReader(nightlyEFI)),
		nightly.AddTarget(t, sysextTarget, bytes.NewReader(nightlySysext)),
	))
	nightlyTimestamp := nightly.TxnCommit(t, tx)
	require.True(t, nightlyTimestamp.Signed.Expires.After(stableTimestamp.Signed.Expires.Add(48*time.Hour)),
		"nightly timestamp must expire days after the stable one")

	server := newServer(t,
		nightly.ConfigBlock("nightly", withOrderIndex(200)),
		stable.ConfigBlock("stable", withOrderIndex(10)),
	)
	resp, body := serverGet(t, server, "/SHA256SUMS")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	bestBefore, entries := parseSums(t, body)
	assert.Equal(t, bestBeforeLine(stableTimestamp.Signed.Expires), bestBefore)
	assert.Equal(t, expectedSums(map[string][]byte{
		efiTarget:    stableEFI,
		sysextTarget: nightlySysext,
	}), entries)
}

// Every request re-reads the repository, so a release published after the
// server started shows up in the next SHA256SUMS (and can be fetched) without
// restarting the server -- sysupdate polls the same server URL indefinitely.
func TestHTTP_RefreshPerRequest(t *testing.T) {
	const nextVersion = "26.08.26-0000"
	nextEFI := flatLayout(nextVersion, efiFile)

	srv := testrepo.New(t)
	files, _ := publishNightlyImage(t, srv)
	server := newServer(t, srv.ConfigBlock("nightly"))

	_, body := serverGet(t, server, "/SHA256SUMS")
	_, entries := parseSums(t, body)
	assert.Equal(t, expectedSums(files), entries)
	resp, _ := serverGet(t, server, "/"+nextEFI)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	waitForNextVersion()
	nextFiles, timestamp := publishRelease(t, srv, flatLayout, nextVersion)
	maps.Copy(files, nextFiles)

	_, body = serverGet(t, server, "/SHA256SUMS")
	bestBefore, entries := parseSums(t, body)
	assert.Equal(t, bestBeforeLine(timestamp.Signed.Expires), bestBefore)
	assert.Equal(t, expectedSums(files), entries)
	resp, _ = serverGet(t, server, "/"+nextEFI)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, dataURL(srv, nextEFI), resp.Header.Get("Location"))
}

// The server honours --ref-time like the rest of quarry-client. A reference time
// past the timestamp expiry makes the repository stale, which must be a hard
// failure rather than serving a listing that TUF no longer vouches for.
func TestHTTP_ExpiredMetadata(t *testing.T) {
	srv := testrepo.New(t)
	_, timestamp := publishNightlyImage(t, srv)
	ctx := cliext.WithCtxConfig(t.Context(), testrepo.Config(t, srv.ConfigBlock("nightly")))
	ctx = context.WithValue(ctx, ctxext.RefTimeCtxKey, timestamp.Signed.Expires.Add(time.Hour))
	server := startServer(ctx, t)

	resp, body := serverGet(t, server, "/SHA256SUMS")
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "Internal Server Error\n", string(body))
	resp, _ = serverGet(t, server, "/"+efiTarget)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// Once a repository has been bootstrapped, failing to fetch its metadata is
// not skippable: it is reported as a server error rather than silently
// dropping the repository (and its targets) from the responses.
func TestHTTP_MetadataFetchError(t *testing.T) {
	srv := testrepo.New(t)
	publishNightlyImage(t, srv)
	server := newServer(t, srv.ConfigBlock("nightly"))

	// Bootstrap the repository (caching its root.json) while it is healthy.
	resp, _ := serverGet(t, server, "/SHA256SUMS")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Break timestamp.json (the exact-path pattern wins over the metadata
	// root) -- unlike a 404, a 500 is not treated as a missing repository.
	srv.Handle("/timestamp.json", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	resp, body := serverGet(t, server, "/SHA256SUMS")
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "Internal Server Error\n", string(body))
	resp, _ = serverGet(t, server, "/"+efiTarget)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// A release is forwarded wherever its layout puts the files: in the repository
// root with the version in every file name (the current nightly layout), or in
// a versioned directory (the proposed layout). SHA256SUMS lists the paths
// verbatim and every redirect points at the same path under the data root. The
// full path is the target name, so the same file under the other layout (or an
// unversioned name, or a directory) does not exist.
func TestHTTP_ReleaseLayouts(t *testing.T) {
	const oldVersion, newVersion = "26.08.24-0000", "26.08.25-0502"

	for _, rl := range releaseLayouts {
		t.Run(rl.name, func(t *testing.T) {
			for _, layout := range layouts {
				t.Run(layout.name, func(t *testing.T) {
					srv := testrepo.New(t, layout.opts...)
					files, _ := publishRelease(t, srv, rl.layout, oldVersion)
					waitForNextVersion()
					newFiles, timestamp := publishRelease(t, srv, rl.layout, newVersion)
					maps.Copy(files, newFiles)
					server := newServer(t, srv.ConfigBlock("nightly"))

					resp, body := serverGet(t, server, "/SHA256SUMS")
					require.Equal(t, http.StatusOK, resp.StatusCode)
					bestBefore, entries := parseSums(t, body)
					assert.Equal(t, bestBeforeLine(timestamp.Signed.Expires), bestBefore)
					assert.Equal(t, expectedSums(files), entries)

					// Following the redirect has to yield the contents of the
					// requested release, not the other one's.
					for name, data := range files {
						t.Run(name, func(t *testing.T) {
							resp, _ := serverGet(t, server, "/"+name)
							require.Equal(t, http.StatusFound, resp.StatusCode)
							assert.Equal(t, dataURL(srv, name), resp.Header.Get("Location"))
							assert.Equal(t, strconv.Itoa(len(data)), resp.Header.Get("X-Quarry-Content-Length"))
							assert.Equal(t, sha256Digest(data), resp.Header.Get("Repr-Digest"))

							resp, body := serverGetFollow(t, server, "/"+name)
							assert.Equal(t, http.StatusOK, resp.StatusCode)
							assert.Equal(t, data, body)
						})
					}

					assertNotFound := func(name string) {
						t.Run(name, func(t *testing.T) {
							resp, _ := serverGet(t, server, "/"+name)
							assert.Equal(t, http.StatusNotFound, resp.StatusCode)
						})
					}
					for _, name := range []string{
						rl.layout("26.08.26-0000", efiFile), // never published
						"nightly-" + newVersion,             // directories are not targets
						"nightly-" + newVersion + "/",
						efiFile.name + "_" + efiFile.suffix, // no layout has unversioned names
					} {
						assertNotFound(name)
					}
					for _, file := range releaseFiles {
						assertNotFound(rl.other(newVersion, file))
					}
				})
			}
		})
	}
}

// startFakeIdentityAgent serves GetWorkloadIdentityToken with a fixed WIT and
// returns the agent's varlink URI.
func startFakeIdentityAgent(t *testing.T) string {
	t.Helper()
	uri := "unix:" + filepath.Join(t.TempDir(), "agent") //nolint:forbidigo // test code
	listener, err := varlink.Listen(uri)
	require.NoError(t, err, "listen on fake agent socket")
	t.Cleanup(func() { _ = listener.Close() })

	var mux varlink.ServeMux
	mux.HandleFunc("com.amutable.IdentityAgent.GetWorkloadIdentityToken", func(w varlink.ReplyWriter, _ *varlink.Call) {
		_ = w.WriteReply(map[string]any{"token": "wit", "expires_in": 3600})
	})
	srv := &varlink.Server{Handler: &mux}
	go func() { _ = srv.Serve(listener) }()
	return uri
}

// Targets of a repo with auth are served by quarry-client itself, fetched with
// the repo's signing client: a redirect would make sysupdate fetch them
// unsigned. The gate in front of the repo refuses any request without a WIT.
func TestHTTPProxyTarget_AuthRepoIsStreamed(t *testing.T) {
	srv := testrepo.New(t)
	files, _ := publishNightlyImage(t, srv)

	repoURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(repoURL)
	gate := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Workload-Identity-Token") == "" {
			http.Error(rw, "unsigned", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(rw, req)
	}))
	t.Cleanup(gate.Close)

	auth := fmt.Sprintf(`auth = { type = "wimse", audience = "urn:amutable:quarry-worker", varlink = %q }`, startFakeIdentityAgent(t))
	block := srv.ConfigBlock("nightly", testrepo.ConfigWithExtraLines(auth))
	server := newServer(t, strings.ReplaceAll(block, srv.URL, gate.URL))

	resp, body := serverGet(t, server, "/"+usrTarget)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, files[usrTarget], body)
	assert.Empty(t, resp.Header.Values("Location"))
	assert.Equal(t, sha256Digest(files[usrTarget]), resp.Header.Get("Content-Digest"))
}
