//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyphar.com/go-pathrs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"gopkg.in/ini.v1"

	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufext"
)

var fixedRefTime = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

// Mirrors the production format string in transfer.go's Init.
var fixedNewDirSubpath = fmt.Sprintf("update-%s.%d", fixedRefTime.Format(time.DateOnly), fixedRefTime.UnixMilli())

const priorSubpath = "update-prior"

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
	origTransfer, origExtension := transferInstallDir, extensionInstallDir
	transferInstallDir = etc
	extensionInstallDir = filepath.Join(etc, "extensions") //nolint:forbidigo // test code
	t.Cleanup(func() {
		transferInstallDir = origTransfer
		extensionInstallDir = origExtension
	})

	rootPath, err := filepath.EvalSymlinks(t.TempDir()) //nolint:forbidigo // test code
	require.NoError(t, err)
	root, err := pathrs.OpenRoot(rootPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	ctx := context.WithValue(context.Background(), RootDirCtxKey, root)
	ctx = context.WithValue(ctx, ctxext.RefTimeCtxKey, fixedRefTime)

	return &testEnv{
		rootPath: rootPath,
		etcPath:  etc,
		storeDir: filepath.Join(rootPath, "transfers"), //nolint:forbidigo // test code
	}, ctx
}

func (env *testEnv) populateUpdateDir(t *testing.T, subdir string, files map[string][]byte) {
	t.Helper()
	base := filepath.Join(env.storeDir, subdir)  //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(base, 0o755)) //nolint:forbidigo // test code
	for name, content := range files {
		full := filepath.Join(base, name)                          //nolint:forbidigo // test code
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755)) //nolint:forbidigo // test code
		require.NoError(t, os.WriteFile(full, content, 0o644))     //nolint:forbidigo // test code
	}
}

func (env *testEnv) makeLive(t *testing.T) {
	t.Helper()
	require.NoError(t, os.MkdirAll(env.storeDir, 0o755))                                //nolint:forbidigo // test code
	require.NoError(t, os.Symlink(priorSubpath, filepath.Join(env.storeDir, liveLink))) //nolint:forbidigo // test code
}

func initExt(ctx context.Context, t *testing.T) *TransferFileExtension {
	t.Helper()
	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })
	return ext
}

// makeRepo returns the [tufext.Repository] backed by the given test repository
// server.
func makeRepo(t *testing.T, srv *testrepo.Server, name string) *tufext.Repository {
	t.Helper()
	cfg := testrepo.Config(t, srv.ConfigBlock(name))
	repo, ok := cfg.Repos[name]
	require.True(t, ok, "testrepo config did not yield repository %q", name)
	return repo.AsRepository()
}

func TestPatchTransferFile_OverrideSourcePath(t *testing.T) {
	u := "http://localhost:555/"
	ext := &TransferFileExtension{OverrideSourcePathURL: &u}

	input := strings.TrimSpace(`
[Transfer]
ProtectVersion=%A

[Source]
Type=url-file
Path=https://example.com/orig/
MatchPattern=foo_@v.raw

[Target]
Type=partition
MatchPattern=foo_@v
`) + "\n"

	var out bytes.Buffer
	require.NoError(t, ext.patchTransferFile(&out, strings.NewReader(input)))

	cfg, err := ini.Load(out.Bytes())
	require.NoError(t, err)
	assert.Equal(t, u, cfg.Section("Source").Key("Path").String())
	assert.Equal(t, "url-file", cfg.Section("Source").Key("Type").String())
	assert.Equal(t, "foo_@v.raw", cfg.Section("Source").Key("MatchPattern").String())
	assert.Equal(t, "%A", cfg.Section("Transfer").Key("ProtectVersion").String())
	assert.Equal(t, "partition", cfg.Section("Target").Key("Type").String())
}

func TestPatchTransferFile_NoOverride(t *testing.T) {
	ext := &TransferFileExtension{}
	input := "[Source]\nPath=https://example.com/\n"

	var out bytes.Buffer
	require.NoError(t, ext.patchTransferFile(&out, strings.NewReader(input)))

	cfg, err := ini.Load(out.Bytes())
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/", cfg.Section("Source").Key("Path").String())
}

func TestPatchTransferFile_CreatesSourceIfMissing(t *testing.T) {
	u := "http://proxy/"
	ext := &TransferFileExtension{OverrideSourcePathURL: &u}
	input := "[Target]\nType=partition\n"

	var out bytes.Buffer
	require.NoError(t, ext.patchTransferFile(&out, strings.NewReader(input)))

	cfg, err := ini.Load(out.Bytes())
	require.NoError(t, err)
	assert.Equal(t, u, cfg.Section("Source").Key("Path").String())
	assert.Equal(t, "partition", cfg.Section("Target").Key("Type").String())
}

func TestInit_FreshStore(t *testing.T) {
	env, ctx := setupTestEnv(t)

	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	require.NotNil(t, ext.storeDir)
	require.NotNil(t, ext.newDir)
	assert.Equal(t, fixedNewDirSubpath, ext.newDirSubpath)
	assert.Empty(t, ext.oldDirSubpath)
	assert.False(t, ext.modifiedEtc)

	info, err := os.Stat(filepath.Join(env.storeDir, fixedNewDirSubpath)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// /etc/extensions/ is a workaround for the systemd CurrentSymlink= bug.
	info, err = os.Stat(filepath.Join(env.etcPath, "extensions")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	_, err = os.Lstat(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Lstat(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestInit_WithExistingLive(t *testing.T) {
	env, ctx := setupTestEnv(t)
	env.populateUpdateDir(t, priorSubpath, nil)
	env.makeLive(t)

	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	assert.Equal(t, priorSubpath, ext.oldDirSubpath)
	assert.Equal(t, fixedNewDirSubpath, ext.newDirSubpath)

	target, err := os.Readlink(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, priorSubpath, target)

	_, err = os.Lstat(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestInit_LiveIsNotSymlink(t *testing.T) {
	env, ctx := setupTestEnv(t)
	require.NoError(t, os.MkdirAll(env.storeDir, 0o755))                                //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(env.storeDir, liveLink), nil, 0o644)) //nolint:forbidigo // test code

	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.Error(t, err)
	// Mirror the orchestrator: abortOnError calls Abort, which also releases
	// the partial storeDir handle.
	require.NoError(t, ext.Abort(ctx, err))
}

func TestUnlinkTransfers_RemovesQuarryLinks(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	target := filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.d", "quarry.transfer") //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))                                //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(target, []byte("dummy"), 0o644))                            //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755))           //nolint:forbidigo // test code
	link := filepath.Join(env.etcPath, "sysupdate.d", "quarry.transfer")                        //nolint:forbidigo // test code
	require.NoError(t, os.Symlink(target, link))                                                //nolint:forbidigo // test code

	require.NoError(t, ext.unlinkTransfers())

	_, err := os.Lstat(link)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// Covers the `sysupdate.*.d` glob (whole-component-dir symlinks), which is
// linked and unlinked differently from base-pattern files.
func TestUnlinkTransfers_RemovesQuarryComponentDir(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	target := filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.comp.d")         //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(target, 0o755))                                        //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(target, "x.conf"), []byte("x"), 0o644)) //nolint:forbidigo // test code
	link := filepath.Join(env.etcPath, "sysupdate.comp.d")                                //nolint:forbidigo // test code
	require.NoError(t, os.Symlink(target, link))                                          //nolint:forbidigo // test code

	require.NoError(t, ext.unlinkTransfers())

	_, err := os.Lstat(link)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// Covers the `sysupdate.*.component` glob (component definition files, which
// live directly in /etc rather than in a sysupdate directory).
func TestUnlinkTransfers_RemovesQuarryComponentFile(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	target := filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.comp.component") //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))                          //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(target, []byte("dummy"), 0o644))                      //nolint:forbidigo // test code
	link := filepath.Join(env.etcPath, "sysupdate.comp.component")                        //nolint:forbidigo // test code
	require.NoError(t, os.Symlink(target, link))                                          //nolint:forbidigo // test code

	require.NoError(t, ext.unlinkTransfers())

	_, err := os.Lstat(link)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// Component drop-in directories are matched by the `sysupdate.*.d` glob.
func TestUnlinkTransfers_RemovesQuarryComponentDropInDir(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	target := filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.comp.component.d") //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(target, 0o755))                                          //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(target, "x.conf"), []byte("x"), 0o644))   //nolint:forbidigo // test code
	link := filepath.Join(env.etcPath, "sysupdate.comp.component.d")                        //nolint:forbidigo // test code
	require.NoError(t, os.Symlink(target, link))                                            //nolint:forbidigo // test code

	require.NoError(t, ext.unlinkTransfers())

	_, err := os.Lstat(link)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestUnlinkTransfers_SkipsNonSymlinks(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755)) //nolint:forbidigo // test code
	realFile := filepath.Join(env.etcPath, "sysupdate.d", "foo.transfer")             //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(realFile, []byte("sysadmin owned"), 0o644))       //nolint:forbidigo // test code

	require.NoError(t, ext.unlinkTransfers())

	_, err := os.Stat(realFile)
	assert.NoError(t, err)
}

// Quarry must not delete symlinks it doesn't own.
func TestUnlinkTransfers_SkipsNonQuarrySymlinks(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755)) //nolint:forbidigo // test code
	link := filepath.Join(env.etcPath, "sysupdate.d", "foo.transfer")                 //nolint:forbidigo // test code
	require.NoError(t, os.Symlink("/somewhere/else/foo.transfer", link))              //nolint:forbidigo // test code

	require.NoError(t, ext.unlinkTransfers())

	_, err := os.Lstat(link)
	assert.NoError(t, err)
}

func TestLinkTransfers_BaseAndComponent(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/base.transfer":         []byte("base"),
		"sysupdate.comp.d/component.conf":   []byte("component"),
		"sysupdate.comp.component":          []byte("[Component]"),
		"sysupdate.comp.component.d/x.conf": []byte("[Component]"),
	})

	// This also fails if the component drop-in directory is linked twice.
	require.NoError(t, ext.linkTransfers(fixedNewDirSubpath))

	baseLink := filepath.Join(env.etcPath, "sysupdate.d", "base.transfer") //nolint:forbidigo // test code
	target, err := os.Readlink(baseLink)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.d", "base.transfer"), target) //nolint:forbidigo // test code
	// Stat after Readlink: guards against a regression where base files
	// landed at /etc/<filename> instead of /etc/sysupdate.d/<filename>.
	_, err = os.Stat(baseLink)
	require.NoError(t, err)

	// Component dirs are symlinked as a whole, not file-by-file.
	compLink := filepath.Join(env.etcPath, "sysupdate.comp.d") //nolint:forbidigo // test code
	target, err = os.Readlink(compLink)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.comp.d"), target) //nolint:forbidigo // test code

	// Component definition files are linked directly into /etc, not inside
	// the component directory.
	defLink := filepath.Join(env.etcPath, "sysupdate.comp.component") //nolint:forbidigo // test code
	target, err = os.Readlink(defLink)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.comp.component"), target) //nolint:forbidigo // test code
	info, err := os.Stat(defLink)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())

	// Component drop-in directories are symlinked as a whole as well.
	dropInLink := filepath.Join(env.etcPath, "sysupdate.comp.component.d") //nolint:forbidigo // test code
	target, err = os.Readlink(dropInLink)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.comp.component.d"), target) //nolint:forbidigo // test code
}

func TestLinkTransfers_CreatesSysupdateDirIfMissing(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/foo.transfer": []byte("foo"),
	})

	_, err := os.Stat(filepath.Join(env.etcPath, "sysupdate.d")) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	require.NoError(t, ext.linkTransfers(fixedNewDirSubpath))

	info, err := os.Stat(filepath.Join(env.etcPath, "sysupdate.d")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestLinkTransfers_FailsOnConflictingNonQuarryFile(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/foo.transfer": []byte("new"),
	})
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755))                                      //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(env.etcPath, "sysupdate.d", "foo.transfer"), []byte("sysadmin"), 0o644)) //nolint:forbidigo // test code

	err := ext.linkTransfers(fixedNewDirSubpath)
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrExist)
}

func TestBeforeUpdate_HappyPath(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/foo.transfer": []byte("transfer"),
	})

	require.NoError(t, ext.BeforeUpdate(ctx))

	assert.True(t, ext.modifiedEtc)

	liveTarget, err := os.Readlink(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, fixedNewDirSubpath, liveTarget)

	foo := filepath.Join(env.etcPath, "sysupdate.d", "foo.transfer") //nolint:forbidigo // test code
	target, err := os.Readlink(foo)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.d", "foo.transfer"), target) //nolint:forbidigo // test code
}

// Exercises the inner-unlink recovery path when linkTransfers fails partway:
// partial Quarry-managed links must be removed, but pre-existing non-Quarry
// files and the already-created `live` symlink must survive for Abort.
func TestBeforeUpdate_LinkPartialFailureCleansUp(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	// filepath.Glob is sorted: "alpha" links first, then "conflict" collides
	// with the pre-planted non-Quarry file.
	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/alpha.transfer":    []byte("alpha"),
		"sysupdate.d/conflict.transfer": []byte("new"),
	})
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755)) //nolint:forbidigo // test code
	conflict := filepath.Join(env.etcPath, "sysupdate.d", "conflict.transfer")        //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(conflict, []byte("sysadmin"), 0o644))             //nolint:forbidigo // test code

	err := ext.BeforeUpdate(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrExist)

	_, err = os.Lstat(filepath.Join(env.etcPath, "sysupdate.d", "alpha.transfer")) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	got, err := os.ReadFile(conflict) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, []byte("sysadmin"), got)

	liveTarget, err := os.Readlink(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, fixedNewDirSubpath, liveTarget)
}

func TestBeforeUpdate_ReplacesOldQuarryLinks(t *testing.T) {
	env, ctx := setupTestEnv(t)

	env.populateUpdateDir(t, priorSubpath, map[string][]byte{
		"sysupdate.d/old.transfer": []byte("old"),
	})
	env.makeLive(t)
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755)) //nolint:forbidigo // test code
	oldLink := filepath.Join(env.etcPath, "sysupdate.d", "old.transfer")              //nolint:forbidigo // test code
	require.NoError(t, os.Symlink(                                                    //nolint:forbidigo // test code
		filepath.Join(env.storeDir, priorSubpath, "sysupdate.d", "old.transfer"), //nolint:forbidigo // test code
		oldLink,
	))

	ext := initExt(ctx, t)
	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/new.transfer": []byte("new"),
	})

	require.NoError(t, ext.BeforeUpdate(ctx))

	// `live` flipped to the new dir, `last` retained so Abort can roll back.
	liveTarget, err := os.Readlink(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, fixedNewDirSubpath, liveTarget)
	lastTarget, err := os.Readlink(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, priorSubpath, lastTarget)

	_, err = os.Lstat(oldLink)
	require.ErrorIs(t, err, fs.ErrNotExist)
	target, err := os.Readlink(filepath.Join(env.etcPath, "sysupdate.d", "new.transfer")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.d", "new.transfer"), target) //nolint:forbidigo // test code
}

func TestAbort_FreshState(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, ext.Abort(ctx, errors.New("test")))

	_, err := os.Stat(filepath.Join(env.storeDir, fixedNewDirSubpath)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	_, err = os.Lstat(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Lstat(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	assert.Nil(t, ext.storeDir)
	assert.Nil(t, ext.newDir)
	assert.Empty(t, ext.oldDirSubpath)
	assert.Empty(t, ext.newDirSubpath)
}

// Covers the `else if ext.modifiedEtc` branch in Abort: no prior `live` to
// swap back, just remove the one BeforeUpdate created.
func TestAbort_FirstUpdateRemovesLive(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/foo.transfer": []byte("foo"),
	})
	require.NoError(t, ext.BeforeUpdate(ctx))
	_, err := os.Lstat(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.NoError(t, err)

	require.NoError(t, ext.Abort(ctx, errors.New("test")))

	_, err = os.Lstat(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Lstat(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(filepath.Join(env.storeDir, fixedNewDirSubpath)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Lstat(filepath.Join(env.etcPath, "sysupdate.d", "foo.transfer")) //nolint:forbidigo // test code
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestAbort_AfterBeforeUpdate_RestoresPriorState(t *testing.T) {
	env, ctx := setupTestEnv(t)

	env.populateUpdateDir(t, priorSubpath, map[string][]byte{
		"sysupdate.d/prior.transfer": []byte("prior"),
	})
	env.makeLive(t)

	ext := initExt(ctx, t)
	env.populateUpdateDir(t, fixedNewDirSubpath, map[string][]byte{
		"sysupdate.d/new.transfer": []byte("new"),
	})
	require.NoError(t, ext.BeforeUpdate(ctx))

	require.NoError(t, ext.Abort(ctx, errors.New("test")))

	target, err := os.Readlink(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, priorSubpath, target)

	// `last` is consumed by Rename(last, live).
	_, err = os.Lstat(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	_, err = os.Lstat(filepath.Join(env.etcPath, "sysupdate.d", "new.transfer")) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	priorTarget, err := os.Readlink(filepath.Join(env.etcPath, "sysupdate.d", "prior.transfer")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.storeDir, priorSubpath, "sysupdate.d", "prior.transfer"), priorTarget) //nolint:forbidigo // test code

	_, err = os.Stat(filepath.Join(env.storeDir, fixedNewDirSubpath)) //nolint:forbidigo // test code
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestAbort_Idempotent(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, ext.Abort(ctx, errors.New("first")))
	require.NoError(t, ext.Abort(ctx, errors.New("second")))
}

// Init renames live->last and then fails before constructing newDir. Abort
// must restore live from last using the still-open storeDir.
func TestAbort_RecoversAfterInitFailure(t *testing.T) {
	env, ctx := setupTestEnv(t)
	env.populateUpdateDir(t, priorSubpath, nil)
	env.makeLive(t)

	// Planting a regular file at newDirSubpath makes Init's MkdirAll fail
	// after the live->last rename has already succeeded.
	require.NoError(t, os.WriteFile(filepath.Join(env.storeDir, fixedNewDirSubpath), nil, 0o644)) //nolint:forbidigo // test code

	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.Error(t, err)

	_, err = os.Lstat(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	lastTarget, err := os.Readlink(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	require.Equal(t, priorSubpath, lastTarget)

	require.NoError(t, ext.Abort(ctx, errors.New("init failed")))

	liveTarget, err := os.Readlink(filepath.Join(env.storeDir, liveLink)) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, priorSubpath, liveTarget)

	_, err = os.Lstat(filepath.Join(env.storeDir, lastLink)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	// The blocking file is also gone -- RemoveAll(newDirSubpath) cleared it.
	_, err = os.Lstat(filepath.Join(env.storeDir, fixedNewDirSubpath)) //nolint:forbidigo // test code
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestApplyTarget_NotForUs(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	info := &tufclient.TargetInfo{
		TargetFiles: &tufmetadata.TargetFiles{Path: "regular/target.bin"},
	}
	applied, err := ext.ApplyTarget(ctx, info)
	require.NoError(t, err)
	assert.False(t, applied)
}

func TestApplyTarget_FullFlow(t *testing.T) {
	env, ctx := setupTestEnv(t)

	body := []byte(strings.TrimSpace(`
[Source]
Type=url-file
Path=https://upstream.example.com/orig/
MatchPattern=foo_@v.raw

[Target]
Type=partition
MatchPattern=foo_@v
`) + "\n")

	const targetPath = ".quarry/sysupdate.d/foo.transfer"
	srv := testrepo.New(t)
	target := srv.WriteTarget(t, targetPath, bytes.NewReader(body))

	proxyURL := "http://localhost:9999/"
	ext := &TransferFileExtension{OverrideSourcePathURL: &proxyURL}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	info := &tufclient.TargetInfo{
		TargetFiles: target,
		Repo:        makeRepo(t, srv, "testrepo"),
	}
	applied, err := ext.ApplyTarget(ctx, info)
	require.NoError(t, err)
	assert.True(t, applied)

	out, err := os.ReadFile(filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.d", "foo.transfer")) //nolint:forbidigo // test code
	require.NoError(t, err)

	cfg, err := ini.Load(out)
	require.NoError(t, err)
	assert.Equal(t, proxyURL, cfg.Section("Source").Key("Path").String())
	assert.Equal(t, "url-file", cfg.Section("Source").Key("Type").String())
	assert.Equal(t, "partition", cfg.Section("Target").Key("Type").String())
}

// Uses a non-systemd-feature path shape (sysupdate.d/foo.transfer.d/x.conf)
// to exercise multi-level MkdirAll in ApplyTarget for future extensions.
func TestApplyTarget_NestedPath(t *testing.T) {
	env, ctx := setupTestEnv(t)

	body := []byte("dummy=value\n")

	const targetPath = ".quarry/sysupdate.d/foo.transfer.d/x.conf"
	srv := testrepo.New(t)
	target := srv.WriteTarget(t, targetPath, bytes.NewReader(body))

	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	info := &tufclient.TargetInfo{
		TargetFiles: target,
		Repo:        makeRepo(t, srv, "testrepo"),
	}
	applied, err := ext.ApplyTarget(ctx, info)
	require.NoError(t, err)
	assert.True(t, applied)

	info2, err := os.Stat(filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.d", "foo.transfer.d", "x.conf")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.True(t, info2.Mode().IsRegular())
}

func TestIsPatchableDefinition(t *testing.T) {
	for transferPath, want := range map[string]bool{
		"sysupdate.d/foo.transfer":              true,
		"sysupdate.k8s.d/foo.transfer":          true,
		"sysupdate.d/foo.transfer.d/x.conf":     true,
		"sysupdate.k8s.d/foo.transfer.d/x.conf": true,
		"sysupdate.k8s.component":               false,
		"sysupdate.k8s.component.d/x.conf":      false,
		"sysupdate.d/docker.feature":            false,
		"sysupdate.d/docker.feature.d/x.conf":   false,
		"sysupdate.d/foo.transfer.d/x.txt":      false,
		"sysupdate.d/foo.conf":                  false,
	} {
		assert.Equal(t, want, isPatchableDefinition(transferPath), transferPath)
	}
}

// Only transfer files and their drop-ins get the source path override. Other
// definitions are installed byte-for-byte.
func TestApplyTarget_PatchesOnlyTransfers(t *testing.T) {
	env, ctx := setupTestEnv(t)

	const (
		componentBody = "[Component]\nDescription=k8s\n"
		dropinBody    = "[Source]\nPath=https://upstream.example.com/\n"
	)
	srv := testrepo.New(t)
	componentTarget := srv.WriteTarget(t, ".quarry/sysupdate.k8s.component", strings.NewReader(componentBody))
	dropinTarget := srv.WriteTarget(t, ".quarry/sysupdate.k8s.d/foo.transfer.d/x.conf", strings.NewReader(dropinBody))
	repo := makeRepo(t, srv, "testrepo")

	proxyURL := "http://localhost:9999/"
	ext := &TransferFileExtension{OverrideSourcePathURL: &proxyURL}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	for _, target := range []*tufmetadata.TargetFiles{componentTarget, dropinTarget} {
		applied, err := ext.ApplyTarget(ctx, &tufclient.TargetInfo{TargetFiles: target, Repo: repo})
		require.NoError(t, err)
		assert.True(t, applied, target.Path)
	}

	out, err := os.ReadFile(filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.k8s.component")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, componentBody, string(out), "component file is not patched")

	out, err = os.ReadFile(filepath.Join(env.storeDir, fixedNewDirSubpath, "sysupdate.k8s.d", "foo.transfer.d", "x.conf")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err := ini.Load(out)
	require.NoError(t, err)
	assert.Equal(t, proxyURL, cfg.Section("Source").Key("Path").String(), "transfer drop-in is patched")
}

func TestClose_Idempotent(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, ext.Close())
	require.NoError(t, ext.Close())
}
