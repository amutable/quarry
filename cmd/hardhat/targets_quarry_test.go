// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/tufext"
)

func writeDefinitions(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(dir, rel)                                //nolint:forbidigo // test code
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))     //nolint:forbidigo // test code
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:forbidigo // test code
	}
	return dir
}

func inlineString(t *testing.T, builder *tufext.TargetsBuilder, path string) string {
	t.Helper()
	target := builder.TargetsType().Targets[path]
	require.NotNil(t, target, "target %s", path)
	data, err := tufext.TargetFilesExt(target).InlineData()
	require.NoError(t, err)
	return string(data)
}

func TestAddQuarryTargets(t *testing.T) {
	base := writeDefinitions(t, t.TempDir(), map[string]string{
		"10-usr.transfer":          "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\n",
		"10-usr.transfer.d/x.conf": "[Transfer]\nVerify=no\n",
		"docker.feature":           "[Feature]\nSuggestOnMachineTag=amutable.ext.docker\n",
	})
	k8s := writeDefinitions(t, t.TempDir(), map[string]string{
		"k8s.transfer": "[Transfer]\n\n[Source]\nType=url-file\n",
	})
	shipped := writeDefinitions(t, t.TempDir(), map[string]string{
		"own.transfer":                   "[Transfer]\n",
		"own.component":                  "[Component]\nDescription=Own\n",
		"own.component.d/10-enable.conf": "[Component]\nEnabled=no\n",
	})
	spec := []quarryTransferSource{
		{componentDir: "sysupdate.d", source: base},
		{componentDir: "sysupdate.k8s.d", source: k8s},
		{componentDir: "sysupdate.own.d", source: shipped},
	}
	builder := tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))

	// The files are published as they are.
	const baseDir = ".quarry/sysupdate.d/"
	assert.Equal(t, "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\n", inlineString(t, builder, baseDir+"10-usr.transfer"))
	assert.Equal(t, "[Transfer]\nVerify=no\n", inlineString(t, builder, baseDir+"10-usr.transfer.d/x.conf"))
	assert.Equal(t, "[Feature]\nSuggestOnMachineTag=amutable.ext.docker\n", inlineString(t, builder, baseDir+"docker.feature"))

	// Component files are published next to, not inside, their directory.
	assert.Equal(t, "[Component]\nDescription=k8s\n",
		inlineString(t, builder, ".quarry/sysupdate.k8s.component"), "a missing component file is generated")
	assert.Equal(t, "[Component]\nDescription=Own\n", inlineString(t, builder, ".quarry/sysupdate.own.component"))
	assert.NotContains(t, builder.TargetsType().Targets, ".quarry/sysupdate.own.d/own.component")
	// So are component drop-ins.
	assert.Equal(t, "[Component]\nEnabled=no\n", inlineString(t, builder, ".quarry/sysupdate.own.component.d/10-enable.conf"))
	assert.NotContains(t, builder.TargetsType().Targets, ".quarry/sysupdate.own.d/own.component.d/10-enable.conf")

	targets := builder.TargetsType().Targets
	assert.Len(t, targets, 8)
	for path, target := range targets {
		assert.Nil(t, target.Custom, "%s: quarry metadata belongs to no version", path)
	}
}

func TestAddQuarryTargetsRejects(t *testing.T) {
	dir := writeDefinitions(t, t.TempDir(), map[string]string{})
	spec := []quarryTransferSource{{componentDir: "sysupdate.d", source: dir}}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "holds no definition files")

	// A path already in the targets with different contents is an error
	// rather than a silent replacement.
	dir = writeDefinitions(t, t.TempDir(), map[string]string{"x.transfer": "[Transfer]\n"})
	builder := tufext.NewTargetsBuilder()
	_, err := addInlineBytes(builder, ".quarry/sysupdate.d/x.transfer", nil)
	require.NoError(t, err)
	spec = []quarryTransferSource{{componentDir: "sysupdate.d", source: dir}}
	require.ErrorContains(t, addQuarryTargets(builder, spec), "given twice with different contents")

	// Only a named component's own component file and drop-in directory, at
	// the top of the source, are allowed.
	for name, test := range map[string]struct {
		componentDir string
		files        map[string]string
	}{
		"default component": {"sysupdate.d", map[string]string{"x.component": "[Component]\n"}},
		"other component":   {"sysupdate.k8s.d", map[string]string{"other.component": "[Component]\n"}},
		"nested":            {"sysupdate.k8s.d", map[string]string{"sub/k8s.component": "[Component]\n"}},

		"default component drop-in": {"sysupdate.d", map[string]string{"x.component.d/a.conf": "[Component]\n"}},
		"other component drop-in":   {"sysupdate.k8s.d", map[string]string{"other.component.d/a.conf": "[Component]\n"}},
		"nested drop-in":            {"sysupdate.k8s.d", map[string]string{"sub/k8s.component.d/a.conf": "[Component]\n"}},
		"component file in drop-in": {"sysupdate.k8s.d", map[string]string{"k8s.component.d/k8s.component": "[Component]\n"}},
		"drop-in in drop-in":        {"sysupdate.k8s.d", map[string]string{"k8s.component.d/k8s.component.d/a.conf": "[Component]\n"}},
	} {
		dir := writeDefinitions(t, t.TempDir(), test.files)
		spec := []quarryTransferSource{{componentDir: test.componentDir, source: dir}}
		require.Error(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), name)
	}
}

// A path already in the targets with the same contents keeps the existing
// entry, adding the inline data if it has none.
func TestAddQuarryTargets_ExistingIdentical(t *testing.T) {
	const data = "[Transfer]\n"
	dir := writeDefinitions(t, t.TempDir(), map[string]string{"x.transfer": data})

	builder := tufext.NewTargetsBuilder()
	existing, err := builder.AddTargetFile(".quarry/sysupdate.d/x.transfer", int64(len(data)), hashAlgorithm.FromString(data))
	require.NoError(t, err)
	custom := json.RawMessage(`{"keep": true}`)
	existing.Custom = &custom

	spec := []quarryTransferSource{{componentDir: "sysupdate.d", source: dir}}
	require.NoError(t, addQuarryTargets(builder, spec))
	target := builder.TargetsType().Targets[".quarry/sysupdate.d/x.transfer"]
	assert.Same(t, existing, target, "the existing entry is kept")
	assert.JSONEq(t, `{"keep": true}`, string(*target.Custom))
	assert.Equal(t, data, inlineString(t, builder, ".quarry/sysupdate.d/x.transfer"), "inline data is added")

	// An existing entry that already has the inline data is left alone.
	require.NoError(t, addQuarryTargets(builder, spec))
	assert.Same(t, existing, builder.TargetsType().Targets[".quarry/sysupdate.d/x.transfer"])
}

// A confext source generates the definitions. The transfer comes from
// hardhat's template, and the component file is generated as for any component
// directory without one.
func TestAddQuarryTargets_Confext(t *testing.T) {
	spec := []quarryTransferSource{
		{componentDir: "sysupdate.edge-gw.d", source: "confext:edge-gw"},
	}
	builder := tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))

	const dir = ".quarry/sysupdate.edge-gw.d/"
	transfer := inlineString(t, builder, dir+"50-edge-gw.transfer")
	assert.True(t, strings.HasPrefix(transfer, "[Transfer]\nVerify=no\n"), transfer)
	for _, want := range []string{
		"MatchPattern=**/edge-gw_@v.confext.raw\n",
		"Path=/var/lib/confexts/edge-gw.raw.v\n",
		"MatchPattern=edge-gw_@v.raw\n",
	} {
		assert.Contains(t, transfer, want)
	}
	assert.Equal(t, "[Component]\nDescription=edge-gw\n", inlineString(t, builder, ".quarry/sysupdate.edge-gw.component"))

	// Several sources merge into one directory.
	extra := writeDefinitions(t, t.TempDir(), map[string]string{"60-extra.transfer": "[Transfer]\n"})
	spec = []quarryTransferSource{
		{componentDir: "sysupdate.gw.d", source: "confext:gw"},
		{componentDir: "sysupdate.gw.d", source: "confext:gw-certs"},
		{componentDir: "sysupdate.gw.d", source: extra},
	}
	builder = tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))
	assert.Contains(t, inlineString(t, builder, ".quarry/sysupdate.gw.d/50-gw.transfer"), "MatchPattern=**/gw_@v.confext.raw\n")
	assert.Contains(t, inlineString(t, builder, ".quarry/sysupdate.gw.d/50-gw-certs.transfer"), "MatchPattern=**/gw-certs_@v.confext.raw\n")
	assert.Equal(t, "[Transfer]\n", inlineString(t, builder, ".quarry/sysupdate.gw.d/60-extra.transfer"))
	assert.Len(t, builder.TargetsType().Targets, 4, "the component file is generated once")

	// The same file in two sources is fine, but different contents are an
	// error.
	spec = []quarryTransferSource{
		{componentDir: "sysupdate.gw.d", source: extra},
		{componentDir: "sysupdate.gw.d", source: extra},
	}
	require.NoError(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec))
	other := writeDefinitions(t, t.TempDir(), map[string]string{"60-extra.transfer": "[Transfer]\nVerify=no\n"})
	spec = []quarryTransferSource{
		{componentDir: "sysupdate.gw.d", source: extra},
		{componentDir: "sysupdate.gw.d", source: other},
	}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "given twice with different contents")

	for _, name := range []string{"", "a_b", "a/b", "..", "a b", "a\nb"} {
		spec := []quarryTransferSource{
			{componentDir: "sysupdate.x.d", source: "confext:" + name},
		}
		require.Error(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "confext name %q", name)
	}
}

func TestSetQuarryCustomVersion(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	target, err := addInlineBytes(builder, "x", []byte("x"))
	require.NoError(t, err)
	// Existing custom fields, inside and outside quarry, survive.
	existing := json.RawMessage(`{"quarry": {"update": true}, "other": 1}`)
	target.Custom = &existing
	require.NoError(t, setQuarryCustomVersion(target, "2"))
	assert.JSONEq(t, `{"quarry": {"update": true, "version": "2"}, "other": 1}`, string(*target.Custom))

	null := json.RawMessage(`{"quarry": null}`)
	target.Custom = &null
	require.NoError(t, setQuarryCustomVersion(target, "3"))
	assert.JSONEq(t, `{"quarry": {"version": "3"}}`, string(*target.Custom))
}

// quarrySpecFor runs quarrySpecFromFlags on a dummy command with the args.
func quarrySpecFor(t *testing.T, args ...string) ([]quarryTransferSource, error) {
	t.Helper()
	var (
		spec    []quarryTransferSource
		specErr error
	)
	cmd := &cli.Command{
		Name:  "targets",
		Flags: quarryTargetsFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			spec, specErr = quarrySpecFromFlags(cmd)
			return nil
		},
	}
	require.NoError(t, cmd.Run(t.Context(), append([]string{"targets"}, args...)))
	return spec, specErr
}

func TestQuarrySpecFromFlags(t *testing.T) {
	spec, err := quarrySpecFor(t,
		"--quarry-transfer-dir=sysupdate.gw.d=confext:gw",
		"--quarry-transfer-dir=sysupdate.d=/defs",
		"--quarry-transfer-dir=sysupdate.gw.d=confext:gw-certs",
		"--quarry-transfer-dir=sysupdate.k8s.d=/k8s",
	)
	require.NoError(t, err)
	assert.Equal(t, []quarryTransferSource{
		{componentDir: "sysupdate.gw.d", source: "confext:gw"},
		{componentDir: "sysupdate.d", source: "/defs"},
		{componentDir: "sysupdate.gw.d", source: "confext:gw-certs"},
		{componentDir: "sysupdate.k8s.d", source: "/k8s"},
	}, spec)

	for name, args := range map[string][]string{
		"invalid component dir": {"--quarry-transfer-dir=other.d=/defs"},
		"no source":             {"--quarry-transfer-dir=sysupdate.d="},
	} {
		_, err := quarrySpecFor(t, args...)
		require.Error(t, err, name)
	}
}
