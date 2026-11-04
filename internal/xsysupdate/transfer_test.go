//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyphar.com/go-pathrs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufext"
)

var testRepo = &tufext.Repository{Name: "test.example.com/repo"}

// testEnv's paths are EvalSymlinks'd so they match the canonicalised names
// that libpathrs caches on the corresponding [pathrs.Root] handles.
type testEnv struct {
	rootPath string
	etcPath  string
	storeDir string
}

func setupTestEnv(t *testing.T) (*testEnv, context.Context) {
	t.Helper()

	etc, err := filepath.EvalSymlinks(t.TempDir()) //nolint:forbidigo // test code
	require.NoError(t, err)
	origHostDir := hostDefinitionsDir
	hostDefinitionsDir = etc
	t.Cleanup(func() { hostDefinitionsDir = origHostDir })

	rootPath, err := filepath.EvalSymlinks(t.TempDir()) //nolint:forbidigo // test code
	require.NoError(t, err)
	root, err := pathrs.OpenRoot(rootPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	ctx := context.WithValue(context.Background(), RootDirCtxKey, root)

	return &testEnv{
		rootPath: rootPath,
		etcPath:  etc,
		storeDir: filepath.Join(rootPath, "transfers"), //nolint:forbidigo // test code
	}, ctx
}

func initExt(ctx context.Context, t *testing.T) *TransferFileExtension {
	t.Helper()
	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })
	return ext
}

// inlineTarget returns a target whose data is embedded in its metadata, so
// that Fetch needs no repository server.
func inlineTarget(path string, data []byte) *tufclient.TargetInfo {
	sum := sha256.Sum256(data)
	target := &tufmetadata.TargetFiles{
		Path:   path,
		Length: int64(len(data)),
		Hashes: tufmetadata.Hashes{"sha256": sum[:]},
	}
	tufext.TargetFilesExt(target).WithInlineData(data)
	// Embedding round-trips the struct through JSON, which drops the
	// (json:"-") path a client otherwise takes from the metadata key.
	target.Path = path
	return &tufclient.TargetInfo{TargetFiles: target, Repo: testRepo}
}

func applyAll(ctx context.Context, t *testing.T, ext *TransferFileExtension, infos ...*tufclient.TargetInfo) {
	t.Helper()
	for _, info := range infos {
		applied, err := ext.ApplyTarget(ctx, info)
		require.NoError(t, err, "target %s", info.Path)
		require.True(t, applied, "target %s", info.Path)
	}
}

func TestParseTransferPath(t *testing.T) {
	for _, tc := range []struct {
		path            string
		component, file string
		ok, wantErr     bool
	}{
		{path: "regular/target.bin"},
		{path: ".quarry/machine-tags/amutable.foo"},
		{path: ".quarry/sysupdate-other/x"}, // another extension, not claimed
		{path: ".quarry/sysupdate"},
		{path: ".quarry/sysupdate.d/10-usr.transfer", file: "10-usr.transfer", ok: true},
		{path: ".quarry/sysupdate.k8s.d/k8s.transfer", component: "k8s", file: "k8s.transfer", ok: true},
		{path: ".zzz-quarry-special/sysupdate.k8s.d/k8s.transfer", component: "k8s", file: "k8s.transfer", ok: true}, // legacy prefix
		{path: ".quarry/sysupdate.k8s.d/k8s.component", component: "k8s", file: "k8s.component", ok: true},
		{path: ".quarry/sysupdate.k8s.d/k8s.transfer.d/10-x.conf", component: "k8s", file: "k8s.transfer.d/10-x.conf", ok: true},
		// These are malformed. They are part of the extension but rejected.
		{path: ".quarry/sysupdate.d", ok: true, wantErr: true},
		{path: ".quarry/sysupdate.d/", ok: true, wantErr: true},
		{path: ".quarry/sysupdate.d/../x.transfer", ok: true, wantErr: true},
		{path: ".quarry/sysupdate.d/a//b", ok: true, wantErr: true},
		{path: ".quarry/sysupdate.d/./b", ok: true, wantErr: true},
		{path: ".quarry/sysupdate..d/x.transfer", ok: true, wantErr: true},
		{path: ".quarry/sysupdate.a.b.d/x.transfer", ok: true, wantErr: true},
		{path: ".quarry/sysupdate.transfer", ok: true, wantErr: true},
		{path: ".quarry/sysupdate.foo/x.transfer", ok: true, wantErr: true},
	} {
		component, file, ok, err := ParseTransferPath(tc.path)
		assert.Equal(t, tc.ok, ok, "path %q", tc.path)
		if tc.wantErr {
			require.Error(t, err, "path %q", tc.path)
			continue
		}
		require.NoError(t, err, "path %q", tc.path)
		assert.Equal(t, tc.component, component, "path %q", tc.path)
		assert.Equal(t, tc.file, file, "path %q", tc.path)
	}

	// What hardhat writes (transferlayout) parses back to the same values.
	for _, tc := range []struct{ component, file string }{
		{"", "12-usr.transfer"},
		{"", "docker.feature"},
		{"k8s", "k8s.component"},
		{"k8s", "k8s.transfer.d/10-x.conf"},
	} {
		path, err := transferlayout.TargetPath(transferlayout.ComponentDir(tc.component), tc.file)
		require.NoError(t, err)
		component, file, ok, err := ParseTransferPath(path)
		require.NoError(t, err, path)
		assert.True(t, ok, path)
		assert.Equal(t, tc.component, component, path)
		assert.Equal(t, tc.file, file, path)
	}
}

func TestInit_FreshStore(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NotNil(t, ext.storeDir)
	entries, err := os.ReadDir(env.storeDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// Staging directories of earlier runs (kept on failure) are removed.
func TestInit_PrunesStaleRuns(t *testing.T) {
	env, ctx := setupTestEnv(t)
	stale := filepath.Join(env.storeDir, "sysupdate.foo.d", "sysupdate.foo.d")                 //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(stale, 0o755))                                              //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(stale, "foo.transfer"), []byte("x"), 0o644)) //nolint:forbidigo // test code

	initExt(ctx, t)

	_, err := os.Stat(filepath.Join(env.storeDir, "sysupdate.foo.d")) //nolint:forbidigo // test code
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestApplyTarget_NotForUs(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	applied, err := ext.ApplyTarget(ctx, inlineTarget("regular/target.bin", []byte("x")))
	require.NoError(t, err)
	assert.False(t, applied)
	applied, err = ext.ApplyTarget(ctx, inlineTarget(".quarry/machine-tags/amutable.foo", nil))
	require.NoError(t, err)
	assert.False(t, applied)
	assert.Empty(t, ext.Transfers())
}

func TestApplyTarget_Collects(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	transfer := []byte("[Transfer]\nProtectVersion=%A\n")
	applyAll(ctx, t, ext,
		inlineTarget(".quarry/sysupdate.d/10-usr.transfer", transfer),
		inlineTarget(".quarry/sysupdate.d/docker.feature", []byte("[Feature]\n")),
		inlineTarget(".quarry/sysupdate.foo.d/foo.transfer", transfer),
		inlineTarget(".quarry/sysupdate.foo.d/foo.component", []byte("[Component]\n")),
		// For duplicates (e.g. from a second repository), the first one wins.
		inlineTarget(".quarry/sysupdate.d/10-usr.transfer", []byte("[Transfer]\nother=1\n")),
		// Malformed paths are claimed (and ignored) rather than aborting.
		inlineTarget(".quarry/sysupdate.bar/x.transfer", transfer),
		inlineTarget(".quarry/sysupdate.d/../x.transfer", transfer),
	)

	transfers := ext.Transfers()
	require.Len(t, transfers, 2)
	assert.Empty(t, transfers[""].Component)
	assert.Equal(t, []string{"10-usr.transfer", "docker.feature"}, transfers[""].Files())
	assert.Equal(t, ".quarry/sysupdate.d", transfers[""].String())
	data, err := tufext.TargetFilesExt(transfers[""].files["10-usr.transfer"].TargetFiles).InlineData()
	require.NoError(t, err)
	assert.Equal(t, transfer, data, "the first one wins")
	assert.Equal(t, "foo", transfers["foo"].Component)
	assert.Equal(t, []string{"foo.component", "foo.transfer"}, transfers["foo"].Files())
	assert.Equal(t, ".quarry/sysupdate.foo.d", transfers["foo"].String())
}

func TestStage_DefaultComponent(t *testing.T) {
	env, ctx := setupTestEnv(t)
	proxyURL := "http://localhost:9999/"
	ext := &TransferFileExtension{OverrideSourcePathURL: &proxyURL}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	transfer := []byte(strings.TrimSpace(`
[Transfer]
ProtectVersion=%A

[Source]
Type=url-file
Path=https://upstream.example.com/orig/
MatchPattern=**/foo_@v.raw

[Target]
Type=partition
MatchPattern=foo_@v
`) + "\n")
	applyAll(ctx, t, ext,
		inlineTarget(".quarry/sysupdate.d/10-usr.transfer", transfer),
		inlineTarget(".quarry/sysupdate.d/docker.feature", []byte("[Feature]\nEnabled=false\nSuggestOnMachineTag=amutable.ext.docker\n")),
		inlineTarget(".quarry/sysupdate.d/containerd.feature", []byte("[Feature]\nSuggestOnMachineTag=amutable.ext.containerd\n")),
		inlineTarget(".quarry/sysupdate.d/10-usr.transfer.d/x.conf", []byte("[Transfer]\nVerify=no\n")),
		inlineTarget(".quarry/sysupdate.d/10-usr.transfer.d/y.conf", []byte("[Source]\nPath=https://elsewhere.example.com/\n")),
	)

	staged, err := ext.Stage(ctx, ext.Transfers()[""], StageOptions{MachineTags: []string{"amutable.ext.docker", "acp.x=1"}})
	require.NoError(t, err)
	require.NotNil(t, staged, "the default component is always staged")
	t.Cleanup(func() { _ = staged.Close() })

	stagePath := filepath.Join(env.storeDir, "sysupdate.d") //nolint:forbidigo // test code
	assert.Equal(t, stagePath, staged.Path())
	assert.Empty(t, staged.Component)
	assert.Equal(t, []string{"docker"}, staged.EnabledFeatures)
	assert.Equal(t, []string{stagePath + "/sysupdate.d:/run/sysupdate.d"}, staged.BindPaths())

	out, err := os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "10-usr.transfer")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err := loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, proxyURL, cfg.Section("Source").Key("Path").String())
	assert.Equal(t, "**/foo_@v.raw", cfg.Section("Source").Key("MatchPattern").String())

	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "docker.feature")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err = loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, "true", cfg.Section("Feature").Key("Enabled").String())

	// A feature the machine does not enable is left as shipped. Enabled= is
	// only ever set to true and never written as false.
	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "containerd.feature")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, "[Feature]\nSuggestOnMachineTag=amutable.ext.containerd\n", string(out))

	// Other files are staged verbatim, nested paths included.
	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "10-usr.transfer.d", "x.conf")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, "[Transfer]\nVerify=no\n", string(out))

	// A transfer drop-in that sets Path= also points at the proxy.
	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "10-usr.transfer.d", "y.conf")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err = loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, proxyURL, cfg.Section("Source").Key("Path").String())

	// The default component gets no component file.
	entries, err := os.ReadDir(stagePath)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "sysupdate.d", entries[0].Name())

	// Remove deletes the component's staging directory.
	require.NoError(t, staged.Remove())
	_, err = os.Stat(stagePath)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestStage_Component(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	applyAll(ctx, t, ext,
		inlineTarget(".quarry/sysupdate.foo.d/foo.transfer", []byte("[Transfer]\n\n[Source]\nType=url-file\nPath=https://example.com/\n")),
		inlineTarget(".quarry/sysupdate.foo.d/foo.component", []byte("[Component]\nDescription=Foo\nEnabled=false\nSuggestOnMachineTag=amutable.foo\n")),
	)

	staged, err := ext.Stage(ctx, ext.Transfers()["foo"], StageOptions{MachineTags: []string{"amutable.foo"}})
	require.NoError(t, err)
	require.NotNil(t, staged)
	t.Cleanup(func() { _ = staged.Close() })

	stagePath := filepath.Join(env.storeDir, "sysupdate.foo.d") //nolint:forbidigo // test code
	assert.Equal(t, []string{
		stagePath + "/sysupdate.foo.d:/run/sysupdate.foo.d",
		stagePath + "/sysupdate.foo.component:/run/sysupdate.foo.component",
	}, staged.BindPaths())

	// The shipped component file is staged as a sibling of the definitions
	// directory and not inside it.
	out, err := os.ReadFile(filepath.Join(stagePath, "sysupdate.foo.component")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err := loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, "Foo", cfg.Section("Component").Key("Description").String())
	assert.Equal(t, "true", cfg.Section("Component").Key("Enabled").String())
	_, err = os.Stat(filepath.Join(stagePath, "sysupdate.foo.d", "foo.component")) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Without a configured override URL, the source path is untouched.
	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.foo.d", "foo.transfer")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err = loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/", cfg.Section("Source").Key("Path").String())

	// A failed run keeps the staging directory (Close only), which the next
	// run's Init prunes.
	require.NoError(t, staged.Close())
	require.NoError(t, ext.Close())
	_, err = os.Stat(stagePath)
	require.NoError(t, err)
	initExt(ctx, t)
	_, err = os.Stat(stagePath)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// A component whose component file neither enables it nor is suggested for
// the machine is not staged.
func TestStage_SkipsComponent(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	applyAll(ctx, t, ext,
		inlineTarget(".quarry/sysupdate.foo.d/foo.transfer", []byte("[Transfer]\n")),
		inlineTarget(".quarry/sysupdate.foo.d/foo.component", []byte("[Component]\nEnabled=false\nSuggestOnMachineTag=amutable.foo\n")),
		inlineTarget(".quarry/sysupdate.bar.d/bar.transfer", []byte("[Transfer]\n")),
		inlineTarget(".quarry/sysupdate.bar.d/bar.component", []byte("[Component]\nEnabled=no\nSuggestOnArchitecture=x86-64\n")),
	)
	for _, component := range []string{"foo", "bar"} {
		staged, err := ext.Stage(ctx, ext.Transfers()[component], StageOptions{MachineTags: []string{"amutable.other"}})
		require.NoError(t, err, component)
		assert.Nil(t, staged, component)
	}
	entries, err := os.ReadDir(env.storeDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// Staging rewrites transfer, feature and component files and keeps the rest
// of each file as it is.
func TestStage_Rewrites(t *testing.T) {
	proxyURL := "http://proxy/"
	for _, tc := range []struct {
		name     string
		files    map[string]string // in sysupdate.foo.d/
		override *string
		tags     []string
		want     map[string]string // in the staging directory
		missing  []string          // in the staging directory
	}{
		{
			name: "transfer keeps repeated keys",
			files: map[string]string{
				"foo.transfer": "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\nPath=https://example.com/\nMatchPattern=foo_@v.raw\nMatchPattern=**/foo_@v.raw\n",
			},
			override: &proxyURL,
			want: map[string]string{
				"sysupdate.foo.d/foo.transfer": "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\nMatchPattern=foo_@v.raw\nMatchPattern=**/foo_@v.raw\nPath=http://proxy/\n",
			},
			// A component without a component file is staged without one,
			// which sysupdate treats as enabled.
			missing: []string{"sysupdate.foo.component"},
		},
		{
			name:     "transfer without source section",
			files:    map[string]string{"foo.transfer": "[Target]\nType=partition\n"},
			override: &proxyURL,
			want:     map[string]string{"sysupdate.foo.d/foo.transfer": "[Target]\nType=partition\n\n[Source]\nPath=http://proxy/\n"},
		},
		{
			name: "features",
			files: map[string]string{
				"foo.transfer":        "[Transfer]\n",
				"docker.feature":      "[Feature]\nDescription=Docker\nEnabled=false\nSuggestOnMachineTag=amutable.ext.*\n",
				"containerd.feature":  "[Feature]\nEnabled=false\nSuggestOnMachineTag=amutable.ext.containerd\n",
				"interactive.feature": "[Feature]\nEnabled=yes\nSuggestOnMachineTag=amutable.ext.none\n",
				"arch.feature":        "[Feature]\nSuggestOnArchitecture=x86-64\n",
			},
			tags: []string{"amutable.ext.docker=x", "amutable.ext.interactive"},
			want: map[string]string{
				// Stamping moves Enabled= to the end of the section.
				"sysupdate.foo.d/docker.feature": "[Feature]\nDescription=Docker\nSuggestOnMachineTag=amutable.ext.*\nEnabled=true\n",
				// A feature that is not suggested is left as shipped.
				"sysupdate.foo.d/containerd.feature": "[Feature]\nEnabled=false\nSuggestOnMachineTag=amutable.ext.containerd\n",
				// An enabled feature keeps its own settings.
				"sysupdate.foo.d/interactive.feature": "[Feature]\nEnabled=yes\nSuggestOnMachineTag=amutable.ext.none\n",
				// quarry does not evaluate other conditions.
				"sysupdate.foo.d/arch.feature": "[Feature]\nSuggestOnArchitecture=x86-64\n",
			},
		},
		{
			name: "suggested component",
			files: map[string]string{
				"foo.transfer":  "[Transfer]\n",
				"foo.component": "[Component]\nDescription=Foo\nEnabled=false\nSuggestOnMachineTag=amutable.foo\n",
			},
			tags: []string{"amutable.foo"},
			want: map[string]string{"sysupdate.foo.component": "[Component]\nDescription=Foo\nSuggestOnMachineTag=amutable.foo\nEnabled=true\n"},
		},
		{
			name: "enabled component",
			files: map[string]string{
				"foo.transfer":  "[Transfer]\n",
				"foo.component": "[Component]\nDescription=Foo\nEnabled=True\nSuggestOnMachineTag=amutable.foo\n",
			},
			want: map[string]string{"sysupdate.foo.component": "[Component]\nDescription=Foo\nEnabled=True\nSuggestOnMachineTag=amutable.foo\n"},
		},
		{
			name: "component enabled by default",
			files: map[string]string{
				"foo.transfer":  "[Transfer]\n",
				"foo.component": "[Component]\nDescription=Foo\n",
			},
			want: map[string]string{"sysupdate.foo.component": "[Component]\nDescription=Foo\n"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ctx := setupTestEnv(t)
			ext := &TransferFileExtension{OverrideSourcePathURL: tc.override}
			_, err := ext.Init(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = ext.Close() })

			for file, data := range tc.files {
				applyAll(ctx, t, ext, inlineTarget(".quarry/sysupdate.foo.d/"+file, []byte(data)))
			}
			staged, err := ext.Stage(ctx, ext.Transfers()["foo"], StageOptions{MachineTags: tc.tags})
			require.NoError(t, err)
			require.NotNil(t, staged)
			t.Cleanup(func() { _ = staged.Remove() })

			for file, want := range tc.want {
				out, err := os.ReadFile(filepath.Join(staged.Path(), file)) //nolint:forbidigo // test code
				require.NoError(t, err)
				assert.Equal(t, want, string(out), file)
			}
			for _, file := range tc.missing {
				_, err := os.Stat(filepath.Join(staged.Path(), file)) //nolint:forbidigo // test code
				require.ErrorIs(t, err, fs.ErrNotExist, file)
			}
		})
	}
}

func TestBeforeUpdate_HostDefinitions(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	// Nothing on the host is fine.
	require.NoError(t, ext.BeforeUpdate(ctx))
	found, err := hostDefinitions()
	require.NoError(t, err)
	assert.Empty(t, found)

	// Host definitions only produce a warning, but are found.
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755))                             //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(env.etcPath, "sysupdate.d", "x.transfer"), []byte("x"), 0o644)) //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.foo.d"), 0o755))                         //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(env.etcPath, "sysupdate.foo.component"), []byte("x"), 0o644))   //nolint:forbidigo // test code
	require.NoError(t, ext.BeforeUpdate(ctx))
	found, err = hostDefinitions()
	require.NoError(t, err)
	assert.Equal(t, []string{
		filepath.Join(env.etcPath, "sysupdate.d", "x.transfer"), //nolint:forbidigo // test code
		filepath.Join(env.etcPath, "sysupdate.foo.component"),   //nolint:forbidigo // test code
		filepath.Join(env.etcPath, "sysupdate.foo.d"),           //nolint:forbidigo // test code
	}, found)
}

func TestAbort_RemovesStaged(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	applyAll(ctx, t, ext, inlineTarget(".quarry/sysupdate.d/x.transfer", []byte("[Transfer]\n")))
	staged, err := ext.Stage(ctx, ext.Transfers()[""], StageOptions{})
	require.NoError(t, err)
	require.NoError(t, staged.Close())

	require.NoError(t, ext.Abort(ctx, errors.New("test")))

	_, err = os.Stat(filepath.Join(env.storeDir, "sysupdate.d")) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, ext.storeDir)
}

func TestAbort_Idempotent(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, ext.Abort(ctx, errors.New("first")))
	require.NoError(t, ext.Abort(ctx, errors.New("second")))
}

func TestClose_Idempotent(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, ext.Close())
	require.NoError(t, ext.Close())
}
