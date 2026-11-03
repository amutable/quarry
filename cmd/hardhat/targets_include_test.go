// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/tufext"
)

func TestAddIncludedOverrideURLs(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	_, err := addInlineBytes(builder, ".quarry/sysupdate.d/a.transfer", []byte("abc"))
	require.NoError(t, err)
	kept, err := builder.AddTargetFile("kept.raw", 1, hashAlgorithm.FromBytes([]byte("k")))
	require.NoError(t, err)
	tufext.TargetFilesExt(kept).WithOverrideURL(&url.URL{Scheme: "https", Host: "elsewhere.example", Path: "/kept.raw"})
	_, err = builder.AddTargetFile("dir/plain.raw", 1, hashAlgorithm.FromBytes([]byte("p")))
	require.NoError(t, err)

	root, err := url.Parse("https://data.example/repo/")
	require.NoError(t, err)
	targets := builder.TargetsType().Targets
	require.NoError(t, addIncludedOverrideURLs(targets, root))

	urlOf := func(path string) string {
		u, err := tufext.TargetFilesExt(targets[path]).OverrideURL()
		require.NoError(t, err)
		if u == nil {
			return ""
		}
		return u.String()
	}
	// Inline data needs no URL, and an existing URL is kept.
	assert.Empty(t, urlOf(".quarry/sysupdate.d/a.transfer"))
	assert.Equal(t, "https://elsewhere.example/kept.raw", urlOf("kept.raw"))
	assert.Equal(t, "https://data.example/repo/dir/plain.raw", urlOf("dir/plain.raw"))
}

// A signed targets file is included into an unsigned one, which needs no
// keystore, and its targets point at --data-root-url.
func TestTargetsUnsignedIncludeWithOverrideURLs(t *testing.T) {
	dir := t.TempDir()
	include := filepath.Join(dir, "include.json") //nolint:forbidigo // test code
	abcHash := hashAlgorithm.FromBytes([]byte("abc")).Encoded()
	doc := `{"signatures": [{"keyid": "x", "sig": "00"}], "signed": {
		"_type": "targets", "spec_version": "1.0.31", "version": 42, "expires": "2030-01-01T00:00:00Z",
		"targets": {
			"a.raw": {"length": 1, "hashes": {"sha256": "` + strings.Repeat("a", 64) + `"}},
			".quarry/sysupdate.d/a.transfer": {"length": 3, "hashes": {"sha256": "` + abcHash + `"}, "x-quarry-inline-data": "YWJj"}
		}}}`
	require.NoError(t, os.WriteFile(include, []byte(doc), 0o644)) //nolint:forbidigo // test code
	out := filepath.Join(dir, "targets.json")                     //nolint:forbidigo // test code

	require.NoError(t, targetsCommand.Run(t.Context(), []string{
		"targets",
		"--unsigned",
		"--include-from", include,
		"--data-root-url", "https://data.example/repo",
		"--ext-override-url",
		"--output", out,
	}))

	data, err := os.ReadFile(out) //nolint:forbidigo // test code
	require.NoError(t, err)
	var got struct {
		Signatures []json.RawMessage          `json:"signatures"`
		Signed     map[string]json.RawMessage `json:"signed"`
	}
	require.NoError(t, json.Unmarshal(data, &got))
	assert.NotNil(t, got.Signatures)
	assert.Empty(t, got.Signatures)
	// The zero time states that the expiry is not checked, and version 1 that
	// the version is not compared.
	assert.JSONEq(t, `"0001-01-01T00:00:00Z"`, string(got.Signed["expires"]))
	assert.JSONEq(t, `1`, string(got.Signed["version"]))
	var targets map[string]map[string]any
	require.NoError(t, json.Unmarshal(got.Signed["targets"], &targets))
	assert.Equal(t, "https://data.example/repo/a.raw", targets["a.raw"]["x-quarry-override-url"])
	assert.NotContains(t, targets[".quarry/sysupdate.d/a.transfer"], "x-quarry-override-url")
}

// An unsigned targets file depends only on its input, not on when it is
// written, so a build that writes one is reproducible.
func TestTargetsUnsignedReproducible(t *testing.T) {
	dir := t.TempDir()
	include := filepath.Join(dir, "include.json") //nolint:forbidigo // test code
	doc := `{"signatures": [], "signed": {
		"_type": "targets", "spec_version": "1.0.31", "version": 1, "expires": "0001-01-01T00:00:00Z",
		"targets": {"a.raw": {"length": 1, "hashes": {"sha256": "` + strings.Repeat("a", 64) + `"}}}}}`
	require.NoError(t, os.WriteFile(include, []byte(doc), 0o644)) //nolint:forbidigo // test code

	write := func(name string) []byte {
		out := filepath.Join(dir, name) //nolint:forbidigo // test code
		require.NoError(t, targetsCommand.Run(t.Context(), []string{
			"targets", "--unsigned", "--include-from", include, "--output", out,
		}))
		data, err := os.ReadFile(out) //nolint:forbidigo // test code
		require.NoError(t, err)
		return data
	}
	first := write("first.json")
	// A version from the wall-clock time counts milliseconds.
	time.Sleep(2 * time.Millisecond)
	assert.Equal(t, string(first), string(write("second.json")))
}
