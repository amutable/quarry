//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
)

// newClient constructs a [tufclient.Client] whose resources are cleaned up
// when the test finishes.
func newClient(t *testing.T, cfg *config.Config) *tufclient.Client {
	t.Helper()
	client, err := tufclient.NewClient(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	return client
}

// configWithOrderIndex returns a [testrepo.ConfigBlockOption] that sets the
// repository order index.
func configWithOrderIndex(index int64) testrepo.ConfigBlockOption {
	return testrepo.ConfigWithExtraLines(fmt.Sprintf("order_index = %d", index))
}

// clientRepoNames returns the names of all repositories usable by the client,
// in iteration order.
func clientRepoNames(t *testing.T, client *tufclient.Client) []string {
	t.Helper()
	var names []string
	for name := range client.IterRepos(t.Context()) {
		names = append(names, name)
	}
	return names
}

// Repositories whose root.json cannot be fetched from the root_trust source
// are silently dropped from the client rather than causing a fatal error.
func TestNewClient_SkipsBrokenRepo(t *testing.T) {
	valid, broken := testrepo.New(t), testrepo.NewBroken(t)
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		broken.ConfigBlock("broken-repo"),
	)

	client := newClient(t, cfg)
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// A client with no usable repositories is valid but all lookups fail with
// [fs.ErrNotExist].
func TestNewClient_NoUsableRepos(t *testing.T) {
	broken := testrepo.NewBroken(t)
	cfg := testrepo.Config(t, broken.ConfigBlock("broken-repo"))

	client := newClient(t, cfg)
	assert.Empty(t, clientRepoNames(t, client))

	_, err := client.GetTargetInfo(t.Context(), "some/target.txt")
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// WithRepos restricts the client to the given repositories.
func TestWithRepos(t *testing.T) {
	repoA, repoB, repoC := testrepo.New(t), testrepo.New(t), testrepo.New(t)
	cfg := testrepo.Config(t,
		repoA.ConfigBlock("repo-a"),
		repoB.ConfigBlock("repo-b"),
		repoC.ConfigBlock("repo-c"),
	)

	client := newClient(t, cfg)
	require.ElementsMatch(t, []string{"repo-a", "repo-b", "repo-c"}, clientRepoNames(t, client))

	require.NoError(t, client.WithRepos("repo-a"))
	assert.Equal(t, []string{"repo-a"}, clientRepoNames(t, client))

	require.NoError(t, client.WithRepos("repo-a", "repo-c"))
	assert.ElementsMatch(t, []string{"repo-a", "repo-c"}, clientRepoNames(t, client))
}

// Calling WithRepos with no names re-enables all loaded repositories.
func TestWithRepos_EmptyReenablesAll(t *testing.T) {
	repoA, repoB := testrepo.New(t), testrepo.New(t)
	cfg := testrepo.Config(t,
		repoA.ConfigBlock("repo-a"),
		repoB.ConfigBlock("repo-b"),
	)

	client := newClient(t, cfg)
	require.NoError(t, client.WithRepos("repo-a"))
	require.Equal(t, []string{"repo-a"}, clientRepoNames(t, client))

	require.NoError(t, client.WithRepos())
	assert.ElementsMatch(t, []string{"repo-a", "repo-b"}, clientRepoNames(t, client))
}

// Requesting a repository that is not defined in the configuration at all is
// an error.
func TestWithRepos_UnknownRepo(t *testing.T) {
	valid := testrepo.New(t)
	cfg := testrepo.Config(t, valid.ConfigBlock("valid-repo"))

	client := newClient(t, cfg)
	err := client.WithRepos("nonexistent-repo")
	require.ErrorContains(t, err, "unknown repository nonexistent-repo")

	// A failed subset is not applied -- the previous state is kept.
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// Explicitly requesting a repository that failed to load (and so was skipped
// by NewClient) returns the load error instead of silently dropping the
// repository from the subset.
func TestWithRepos_BrokenRepoError(t *testing.T) {
	valid, broken := testrepo.New(t), testrepo.NewBroken(t)
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		broken.ConfigBlock("broken-repo"),
	)

	client := newClient(t, cfg)

	err := client.WithRepos("broken-repo")
	require.ErrorIs(t, err, tufclient.ErrSkippableRepo)
	require.ErrorContains(t, err, "broken-repo")

	// The subset also fails if only some of the requested repositories are
	// broken.
	err = client.WithRepos("valid-repo", "broken-repo")
	require.ErrorIs(t, err, tufclient.ErrSkippableRepo)

	// A failed subset is not applied -- the previous state is kept.
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// A skipped repository outside the requested subset does not cause an error.
func TestWithRepos_SkippedRepoOutsideSubset(t *testing.T) {
	valid, broken := testrepo.New(t), testrepo.NewBroken(t)
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		broken.ConfigBlock("broken-repo"),
	)

	client := newClient(t, cfg)
	require.NoError(t, client.WithRepos("valid-repo"))
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// A repository whose remote root_trust source serves an invalid root.json is
// skippable -- NewClient drops it, but WithRepos still surfaces the
// underlying validation error if the repository is requested explicitly.
func TestNewClient_SkipsInvalidRemoteRoot(t *testing.T) {
	valid, invalid := testrepo.New(t), testrepo.NewBroken(t)
	invalid.Handle("/1.root.json", http.HandlerFunc(func(wtr http.ResponseWriter, _ *http.Request) {
		_, _ = wtr.Write([]byte("this is not json {"))
	}))
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		invalid.ConfigBlock("invalid-repo"),
	)

	client := newClient(t, cfg)
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))

	err := client.WithRepos("invalid-repo")
	require.ErrorIs(t, err, tufclient.ErrSkippableRepo)
	require.ErrorContains(t, err, "root_trust root.json is invalid JSON")
}

// A remote root_trust fetch that fails for any reason but a 404 (here, the
// server refusing the client) is fatal for NewClient: only a missing
// repository may be skipped.
func TestNewClient_RemoteRootFetchErrorFatal(t *testing.T) {
	valid, denied := testrepo.New(t), testrepo.NewBroken(t)
	denied.Handle("/1.root.json", http.HandlerFunc(func(wtr http.ResponseWriter, _ *http.Request) {
		wtr.WriteHeader(http.StatusUnauthorized)
	}))
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		denied.ConfigBlock("denied-repo"),
	)

	_, err := tufclient.NewClient(t.Context(), cfg)
	require.NotErrorIs(t, err, tufclient.ErrSkippableRepo)
	require.ErrorContains(t, err, "bad repo denied-repo")
	require.ErrorContains(t, err, "status code 401")
}

// A repository with a non-remote root_trust source that fails to load is a
// fatal error for NewClient, never a skippable one -- local sources are meant
// to always exist and be valid.
func TestNewClient_LocalRootTrustFatal(t *testing.T) {
	for _, test := range []struct {
		name, trustValue, expectedErr string
	}{
		{"BundledMissingPath", `{ type = "bundled", path = "/nonexistent/quarry-test/root.json" }`, "fetch trusted root.json"},
		{"InlineInvalidJSON", `{ type = "inline", "root.json" = 'this is not json {' }`, "root_trust root.json is invalid JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := testrepo.New(t)
			cfg := testrepo.Config(t,
				srv.ConfigBlock("local-trust-repo", testrepo.ConfigWithRootTrust(testrepo.ConfigRootTrust{
					RawValue: test.trustValue,
				})),
			)

			_, err := tufclient.NewClient(t.Context(), cfg)
			require.Error(t, err)
			require.NotErrorIs(t, err, tufclient.ErrSkippableRepo,
				"errors from non-remote root_trust sources must not be skippable")
			require.ErrorContains(t, err, "bad repo local-trust-repo")
			require.ErrorContains(t, err, test.expectedErr)
		})
	}
}

// IterRepos must iterate in ascending order-index order, with the repository
// name as a tie-breaker.
func TestIterRepos_Order(t *testing.T) {
	// The same server can act as several repositories -- each repository
	// keeps its own cache directory based on its name.
	srv := testrepo.New(t)
	for _, tc := range []struct {
		name  string
		repos map[string]string // repository name -> order_index line ("" for default)
		want  []string
	}{
		{
			name:  "NameTieBreak",
			repos: map[string]string{"charlie": "", "alpha": "", "bravo": ""},
			want:  []string{"alpha", "bravo", "charlie"},
		},
		{
			name: "AscendingOrderIndex",
			repos: map[string]string{
				"first":  `order_index = 1`,
				"middle": `order_index = 100`,
				"last":   `order_index = 9000`,
			},
			want: []string{"first", "middle", "last"},
		},
		{
			name: "OrderIndexBeatsName",
			repos: map[string]string{
				"aaa": `order_index = 500`,
				"zzz": `order_index = 1`,
			},
			want: []string{"zzz", "aaa"},
		},
		{
			// An explicit order index of 100 ties with the implicit default.
			name: "MixedTieBreak",
			repos: map[string]string{
				"delta":   `order_index = 200`,
				"charlie": "",
				"beta":    `order_index = 200`,
				"alpha":   `order_index = 100`,
			},
			want: []string{"alpha", "charlie", "beta", "delta"},
		},
		{
			name: "ZeroAndNegative",
			repos: map[string]string{
				"neg":  `order_index = -10`,
				"zero": `order_index = 0`,
				"def":  "",
			},
			want: []string{"neg", "zero", "def"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocks := make([]string, 0, len(tc.repos))
			for name, indexLine := range tc.repos {
				var opts []testrepo.ConfigBlockOption
				if indexLine != "" {
					opts = append(opts, testrepo.ConfigWithExtraLines(indexLine))
				}
				blocks = append(blocks, srv.ConfigBlock(name, opts...))
			}
			client := newClient(t, testrepo.Config(t, blocks...))
			assert.Equal(t, tc.want, clientRepoNames(t, client))
		})
	}
}

// Once a repository's root.json has been cached, the root_trust source is no
// longer consulted -- a broken local trust source does not stop the client
// from loading the repository from the cache.
func TestNewClient_CachedRootIgnoresRootTrust(t *testing.T) {
	srv := testrepo.New(t)

	rootJSON, err := srv.Root.ToBytes(false)
	require.NoError(t, err)
	rootPath := filepath.Join(t.TempDir(), "root.json")         //nolint:forbidigo // test code writing inside a test tempdir
	require.NoError(t, os.WriteFile(rootPath, rootJSON, 0o644)) //nolint:forbidigo // test code writing inside a test tempdir

	// bundled paths are %-expanded by config.Parse, and t.TempDir() embeds
	// the test name -- which may contain "%" for some subtests.
	escapedPath := strings.ReplaceAll(rootPath, "%", "%%")
	cfg := testrepo.Config(t,
		srv.ConfigBlock("cached-repo", testrepo.ConfigWithRootTrust(testrepo.ConfigRootTrust{
			RawValue: fmt.Sprintf(`{ type = "bundled", path = %q }`, escapedPath),
		})),
	)

	// The first client fetches root.json from the bundled path and caches it.
	client := newClient(t, cfg)
	assert.Equal(t, []string{"cached-repo"}, clientRepoNames(t, client))

	// Remove the bundled file -- a fresh client sharing the same cache_dir
	// must still load the repository from the cached root.json, even though
	// the (fatal, non-remote) trust source is now broken.
	require.NoError(t, os.Remove(rootPath)) //nolint:forbidigo // test code removing a file inside a test tempdir
	client = newClient(t, cfg)
	assert.Equal(t, []string{"cached-repo"}, clientRepoNames(t, client))
}

// GetTargetInfo and IterTargetFiles rely on the iteration order being stable
// to consistently mask shadowed targets, so re-iterating (both the same
// iterator and fresh ones) must always produce the same order.
func TestIterRepos_ConsistentOrder(t *testing.T) {
	srv := testrepo.New(t)
	client := newClient(t, testrepo.Config(t,
		srv.ConfigBlock("charlie"),
		srv.ConfigBlock("alpha"),
		srv.ConfigBlock("bravo", configWithOrderIndex(500)),
		srv.ConfigBlock("delta"),
		srv.ConfigBlock("echo", configWithOrderIndex(-1)),
	))

	first := clientRepoNames(t, client)
	require.Equal(t, []string{"echo", "alpha", "charlie", "delta", "bravo"}, first)
	seq := client.IterRepos(t.Context())
	for range 10 {
		var names []string
		for name := range seq {
			names = append(names, name)
		}
		assert.Equal(t, first, names)
	}
}

// Stopping iteration early must terminate the loop cleanly after the
// earliest-sorting repository.
func TestIterRepos_EarlyBreak(t *testing.T) {
	srv := testrepo.New(t)
	client := newClient(t, testrepo.Config(t,
		srv.ConfigBlock("best", configWithOrderIndex(1)),
		srv.ConfigBlock("worst", configWithOrderIndex(500)),
	))

	var names []string
	for name := range client.IterRepos(t.Context()) {
		names = append(names, name)
		break
	}
	assert.Equal(t, []string{"best"}, names)
}

// Updates published through a [testrepo.Server] transaction must be visible
// to (fresh) clients of the repository.
// Breaking out of IterTargetFiles must stop the walk cleanly, and the returned
// sequence must be re-rangeable afterwards: each range starts over and sees
// every target.
func TestClient_IterTargetFiles_EarlyBreak(t *testing.T) {
	srv := testrepo.New(t)
	srv.Publish(t,
		srv.AddTarget(t, "a.txt", bytes.NewReader([]byte("a"))),
		srv.AddTarget(t, "b.txt", bytes.NewReader([]byte("b"))),
	)
	client := newClient(t, testrepo.Config(t, srv.ConfigBlock("test-repo")))
	seq := client.IterTargetFiles(t.Context())

	var yielded int
	for _, err := range seq {
		require.NoError(t, err)
		yielded++
		break
	}
	assert.Equal(t, 1, yielded)

	var paths []string
	for info, err := range seq {
		require.NoError(t, err)
		paths = append(paths, info.Path)
	}
	assert.ElementsMatch(t, []string{"a.txt", "b.txt"}, paths, "a fresh range must start over")
}

func TestClient_TargetUpdates(t *testing.T) {
	targetData := []byte("hello quarry")

	srv := testrepo.New(t)
	cfg := testrepo.Config(t, srv.ConfigBlock("test-repo"))

	client := newClient(t, cfg)
	_, err := client.GetTargetInfo(t.Context(), "foo/hello.txt")
	require.ErrorIs(t, err, fs.ErrNotExist, "target must not exist before being published")

	srv.Publish(t, srv.AddTarget(t, "foo/hello.txt", bytes.NewReader(targetData)))

	// A go-tuf updater only refreshes once, so use a fresh client (which
	// shares the same metadata cache directory) to observe the update.
	client2 := newClient(t, cfg)
	info, err := client2.GetTargetInfo(t.Context(), "foo/hello.txt")
	require.NoError(t, err)
	assert.Equal(t, "test-repo", info.Repo.Name)
	assert.Equal(t, targetData, fetchAll(t, info))
}

// A target defined in multiple repositories must be resolved (masked) in
// favour of the repository that sorts earliest in the iteration order, both
// for direct lookups and when iterating over all targets.
func TestClient_OrderMasking(t *testing.T) {
	alphaData, betaData := []byte("alpha data"), []byte("beta data...")

	alpha, beta := testrepo.New(t), testrepo.New(t)
	alpha.Publish(t,
		alpha.AddTarget(t, "shared.txt", bytes.NewReader(alphaData)),
		alpha.AddTarget(t, "alpha-only.txt", bytes.NewReader(alphaData)))
	beta.Publish(t,
		beta.AddTarget(t, "shared.txt", bytes.NewReader(betaData)),
		beta.AddTarget(t, "beta-only.txt", bytes.NewReader(betaData)))
	cfg := testrepo.Config(t,
		alpha.ConfigBlock("alpha", configWithOrderIndex(1)),
		beta.ConfigBlock("beta"),
	)

	client := newClient(t, cfg)

	// Iteration masks the shadowed copy entirely -- shared.txt must show up
	// exactly once, from the earliest-sorting repo. Iterating on a fresh client
	// (before any GetTargetInfo call auto-refreshes the updaters) is
	// deliberate: it exercises the opportunistic-refresh path inside
	// IterTargetFiles.
	targetRepos := make(map[string]string)
	for info, err := range client.IterTargetFiles(t.Context()) {
		require.NoError(t, err)
		_, seen := targetRepos[info.Path]
		require.False(t, seen, "target %s yielded more than once", info.Path)
		targetRepos[info.Path] = info.Repo.Name
	}
	assert.Equal(t, map[string]string{
		"shared.txt":     "alpha",
		"alpha-only.txt": "alpha",
		"beta-only.txt":  "beta",
	}, targetRepos)

	// Direct lookups resolve shadowed targets to the earliest-sorting repo,
	// but non-shadowed targets are still reachable in later repos.
	info, err := client.GetTargetInfo(t.Context(), "shared.txt")
	require.NoError(t, err)
	assert.Equal(t, "alpha", info.Repo.Name)
	assert.Equal(t, alphaData, fetchAll(t, info))

	info, err = client.GetTargetInfo(t.Context(), "beta-only.txt")
	require.NoError(t, err)
	assert.Equal(t, "beta", info.Repo.Name)
}
