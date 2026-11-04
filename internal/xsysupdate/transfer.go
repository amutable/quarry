// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"cyphar.com/go-pathrs"
	"golang.org/x/sys/unix"
	"gopkg.in/ini.v1"

	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufclient"
)

const (
	// TransferFilePrefix is the prefix used for our "auto-applied transfer files"
	// extension to sysupdate. A repository ships the sysupdate definitions of
	// a component as the target files
	//
	//	.quarry/sysupdate.d/<file>              (default component)
	//	.quarry/sysupdate.<component>.d/<file>  (component)
	//
	// where <file> is a *.transfer, *.feature or <component>.component
	// definition or a drop-in. [TransferFileExtension.Stage] lays them out for
	// a single systemd-sysupdate run (with the [Source] Path= adjusted to point
	// to the local quarry-http-client server).
	TransferFilePrefix = ExtensionTargetPrefix + transferFileName

	// transferFileName is [TransferFilePrefix] without the
	// [ExtensionTargetPrefix].
	transferFileName = "sysupdate."

	// maxDefinitionFileSize bounds how much of a definition file is read.
	maxDefinitionFileSize = 1 << 20 // 1 MiB

	// bindMountDir is where the staged definitions are bind-mounted for
	// systemd-sysupdate. It is /run rather than /etc because systemd creates
	// missing mount points on the host filesystem (the service only has a
	// private mount table), and on /run (a tmpfs in sysupdate's search path)
	// these empty placeholders do not persist.
	bindMountDir = "/run"
)

// hostDefinitionsDir is the highest-precedence sysupdate search directory on
// the host. Definitions there take precedence over our bind mounts, so we warn
// about them. This is a variable so that tests can override it.
var hostDefinitionsDir = "/etc"

// TransferDir is the definitions directory of one sysupdate component as
// shipped by the repositories (see [TransferFilePrefix]).
type TransferDir struct {
	// Component is the sysupdate component name ("" for the default
	// component).
	Component string

	// files are the definition files (relative to the directory) and the
	// targets providing them.
	files map[string]*tufclient.TargetInfo
	// path is the target path of the directory, for log messages.
	path string
}

// Files returns the sorted list of definition files in the directory.
func (dir *TransferDir) Files() []string {
	return slices.Sorted(maps.Keys(dir.files))
}

// String returns the target path of the directory.
func (dir *TransferDir) String() string { return dir.path }

// componentFileName returns the name of the component definition file of a
// non-default component ("sysupdate.<component>.component").
func componentFileName(component string) string {
	return "sysupdate." + component + ".component"
}

// ParseTransferPath parses a target path of the transfer definition directory
// extension into the component ("" for the default component) and the file
// path relative to the directory. ok is false if the target is not part of
// this extension at all. err is non-nil if it is part of it but is malformed.
func ParseTransferPath(path string) (component, file string, ok bool, err error) {
	rest, _, ok := CutExtensionTargetPrefix(path)
	if !ok || !strings.HasPrefix(rest, transferFileName) {
		return "", "", false, nil
	}
	dirName, file, found := strings.Cut(rest, "/")
	if !found || file == "" {
		return "", "", true, fmt.Errorf("transfer target %s has no file component", path)
	}
	for part := range strings.SplitSeq(file, "/") {
		if !transferlayout.ValidPathComponent(part) {
			return "", "", true, fmt.Errorf("transfer target %s has an invalid file path %q", path, file)
		}
	}
	component, err = transferlayout.ParseComponentDir(dirName)
	if err != nil {
		return "", "", true, fmt.Errorf("transfer target %s: %w", path, err)
	}
	return component, file, true, nil
}

// TransferFileExtension is an [Extension] that implements auto-installation of
// target files from Quarry repositories.
// It collects the transfer definition directories (see [TransferFilePrefix]).
// quarry-sysupdate stages each component from
// [TransferFileExtension.Transfers] for systemd-sysupdate with
// [TransferFileExtension.Stage].
type TransferFileExtension struct {
	// OverrideSourcePathURL (if non-nil) is a URL which replaces all [Source]
	// Path entries in transfer files when persisting them to disk. This is
	// intended to be the URL to the "quarry-client http" server that proxies
	// sysupdate requests.
	OverrideSourcePathURL *string

	// storeDir is the storage for the staged transfer files.
	storeDir *pathrs.Root

	// dirs are the collected transfer directories, keyed by component.
	dirs map[string]*TransferDir
}

var _ Extension = &TransferFileExtension{}

// Name returns the name of this extension.
func (ext *TransferFileExtension) Name() string { return "transfers" }

// Init constructs the storage area for the auto-enabled transfer files.
// Staging directories left behind by earlier runs (they are kept on failure,
// for debugging) are removed.
func (ext *TransferFileExtension) Init(ctx context.Context) (context.Context, error) {
	ctx, err := makeExtStoreDir(ctx, ext)
	if err != nil {
		return nil, fmt.Errorf("make %s extension store: %w", ext.Name(), err)
	}
	ext.storeDir = ctxExtStoreDir(ctx, ext)
	// storeDir will be closed by Abort on error.

	if err := ext.pruneStore(); err != nil {
		return nil, fmt.Errorf("prune old staging directories: %w", err)
	}

	ext.dirs = map[string]*TransferDir{}
	return ctx, nil
}

// pruneStore removes everything in the store directory. Staged definitions
// are only needed while their update runs, so anything present at the start
// of a run is a leftover from a failed (or interrupted) one.
func (ext *TransferFileExtension) pruneStore() (Err error) {
	dir, err := ext.storeDir.OpenFile(".", unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, dir)

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("list store: %w", err)
	}
	for _, entry := range entries {
		slog.Info("[xsysupdate transfers] Removing staging directory.",
			"name", entry.Name())
		if err := ext.storeDir.RemoveAll(entry.Name()); err != nil {
			return fmt.Errorf("remove staging directory %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// dir returns the (possibly new) transfer directory record for the given
// component, whose target path is path.
func (ext *TransferFileExtension) dir(component, path string) *TransferDir {
	dir, ok := ext.dirs[component]
	if !ok {
		dir = &TransferDir{
			Component: component,
			files:     map[string]*tufclient.TargetInfo{},
			path:      path,
		}
		ext.dirs[component] = dir
	}
	return dir
}

// readTarget fetches and verifies a (small) target file.
func readTarget(ctx context.Context, info *tufclient.TargetInfo, maxSize int64) (_ []byte, Err error) {
	file, err := info.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch target %s: %w", info.Path, err)
	}
	defer funchelpers.VerifyClose(&Err, file)

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read target %s: %w", info.Path, err)
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("target %s is too large (limit %d)", info.Path, maxSize)
	}
	// The stream is hash-verified on Close, so this must succeed before the
	// data is used for anything.
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("verify target %s: %w", info.Path, err)
	}
	return data, nil
}

// ApplyTarget collects the target into its transfer directory. A malformed
// target is ignored with a warning rather than aborting the update, so that
// one bad entry cannot block the updates of other components.
func (ext *TransferFileExtension) ApplyTarget(_ context.Context, info *tufclient.TargetInfo) (bool, error) {
	component, file, ok, err := ParseTransferPath(info.Path)
	if !ok {
		return false, nil // not for this extension
	}
	if err != nil {
		slog.Warn("[xsysupdate transfers target] Ignoring invalid transfer target.",
			"target", info.Path, "repository", info.Repo.Name, "err", err.Error())
		return true, nil
	}
	dir := ext.dir(component, strings.TrimSuffix(info.Path, "/"+file))

	// For equal paths (e.g. from two repositories) the first one seen wins.
	if _, seen := dir.files[file]; seen {
		slog.Info("[xsysupdate transfers target] Ignoring duplicate transfer definition.",
			"target", info.Path, "repository", info.Repo.Name)
		return true, nil
	}
	slog.Info("[xsysupdate transfers target] Collected transfer definition.",
		"target", info.Path, "repository", info.Repo.Name, "component", transferlayout.ComponentDir(component))
	dir.files[file] = info
	return true, nil
}

// Transfers returns the collected transfer directories, keyed by component.
func (ext *TransferFileExtension) Transfers() map[string]*TransferDir {
	return ext.dirs
}

// hostDefinitions returns the sysupdate definitions present in
// [hostDefinitionsDir], which take precedence over the staged ones.
func hostDefinitions() ([]string, error) {
	var found []string
	for _, pattern := range []string{"sysupdate.d/*", "sysupdate.*.d", "sysupdate.*.component"} {
		pattern = filepath.Join(hostDefinitionsDir, pattern) //nolint:forbidigo // host-controlled directory
		matches, err := filepath.Glob(pattern)               //nolint:forbidigo // host-controlled directory
		if err != nil {
			return nil, fmt.Errorf("could not glob %q pattern: %w", pattern, err)
		}
		found = append(found, matches...)
	}
	slices.Sort(found)
	return found, nil
}

// BeforeUpdate warns about sysupdate definitions on the host that would
// take precedence over the staged ones.
func (ext *TransferFileExtension) BeforeUpdate(_ context.Context) error {
	found, err := hostDefinitions()
	if err != nil {
		return err
	}
	if len(found) > 0 {
		slog.Warn("[xsysupdate transfers before-update] Host has sysupdate definitions that take precedence over the repository ones.",
			"definitions", found)
	}
	return nil
}

// Abort resets the transfer file state to before the update was started.
// Init left the store empty, so everything in it was staged by this run.
func (ext *TransferFileExtension) Abort(_ context.Context, srcErr error) error {
	var errs []error
	if ext.storeDir != nil {
		slog.Info("[xsysupdate transfers abort] Removing staged transfer definitions.",
			"err", srcErr.Error())
		if err := ext.pruneStore(); err != nil {
			errs = append(errs, fmt.Errorf("remove staged transfer definitions: %w", err))
		}
	}
	if err := ext.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close transfer extension resources: %w", err))
	}
	// Clear the internal state so a double-abort doesn't do any thing dumb.
	*ext = TransferFileExtension{
		OverrideSourcePathURL: ext.OverrideSourcePathURL,
	}
	return errors.Join(errs...)
}

// Close clears any resources used by the extension. Staged definitions that
// were not removed are left in place until the next Init.
func (ext *TransferFileExtension) Close() error {
	var err error
	if ext.storeDir != nil {
		if err = ext.storeDir.Close(); errors.Is(err, fs.ErrClosed) {
			err = nil
		}
		ext.storeDir = nil
	}
	ext.dirs = nil
	return err
}

func init() {
	// Write "Key=Value" like the definitions we are given (and systemd
	// itself), not the library's default "Key = Value". These are package
	// globals of the ini library. Nothing else in quarry writes ini files.
	ini.PrettyFormat = false
	ini.PrettyEqual = false
}

// loadINI parses a systemd-style definition file. Repeated keys are kept
// verbatim (sysupdate allows e.g. multiple MatchPattern= lines) and "#" and
// ";" only start a comment at the start of a line.
func loadINI(source any) (*ini.File, error) {
	return ini.LoadSources(ini.LoadOptions{
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		IgnoreInlineComment:        true,
	}, source)
}

// setKey sets the key to exactly one value, dropping any repeated (shadow)
// assignments, as systemd would only honour the last one anyway.
func setKey(section *ini.Section, name, value string) {
	section.DeleteKey(name)
	section.Key(name).SetValue(value)
}

// rewriteINI parses a definition file (see [loadINI]), applies edit to it and
// serialises the result.
func rewriteINI(data []byte, edit func(*ini.File)) ([]byte, error) {
	file, err := loadINI(data)
	if err != nil {
		return nil, fmt.Errorf("load ini: %w", err)
	}
	edit(file)
	var out bytes.Buffer
	if _, err := file.WriteTo(&out); err != nil {
		return nil, fmt.Errorf("serialise ini: %w", err)
	}
	return out.Bytes(), nil
}

// enableINI stamps Enabled=true into the [section] of a definition file.
func enableINI(data []byte, section string) ([]byte, error) {
	return rewriteINI(data, func(def *ini.File) {
		setKey(def.Section(section), "Enabled", "true")
	})
}

// suggestedForMachine returns whether the [section] of a component or feature
// definition from the target is suggested for a machine with the given tags
// (see [definitionSuggested]). A definition that quarry cannot evaluate is
// not suggested, which is logged as a warning.
func suggestedForMachine(info *tufclient.TargetInfo, data []byte, section string, machineTags []string) bool {
	suggested, err := definitionSuggested(data, section, machineTags)
	if err != nil {
		slog.Warn("[xsysupdate transfers stage] Treating definition as not suggested because quarry cannot evaluate it.",
			"target", info.Path, "err", err.Error())
		return false
	}
	return suggested
}

// isTransferDropIn returns whether the file of a definitions directory is a
// drop-in of a transfer file ("<name>.transfer.d/<drop-in>.conf").
func isTransferDropIn(file string) bool {
	dir, dropIn, ok := strings.Cut(file, "/")
	return ok && strings.HasSuffix(dir, ".transfer.d") && !strings.Contains(dropIn, "/") && strings.HasSuffix(dropIn, ".conf")
}

// setsSourcePath returns whether a definition assigns [Source] Path=.
func setsSourcePath(data []byte) bool {
	return slices.ContainsFunc(sectionAssignments(data, "Source"), func(a assignment) bool {
		return a.key == "Path"
	})
}

// StageOptions are the options for [TransferFileExtension.Stage].
type StageOptions struct {
	// MachineTags are the machine tags currently set on the host, which
	// decide the enablement of components and features (see
	// [TransferFileExtension.Stage]).
	MachineTags []string
}

// StagedTransfers are the definitions of one component laid out for a
// systemd-sysupdate run, see [TransferFileExtension.Stage].
type StagedTransfers struct {
	// Component is the staged component.
	Component string
	// EnabledFeatures are the features the staging enabled.
	EnabledFeatures []string

	// hasComponentFile records that a component file was staged.
	hasComponentFile bool
	// root is the staging directory of the component.
	root *pathrs.Root
	// removeFn removes the staging directory.
	removeFn func() error
}

// Path returns the absolute path of the staging directory.
func (staged *StagedTransfers) Path() string {
	return staged.root.IntoFile().Name()
}

// BindPaths returns the "<source>:<destination>" bind mounts that make
// systemd-sysupdate see the staged definitions (as BindReadOnlyPaths=
// values), which are the definitions directory of the component and, if one
// was staged, its component file.
func (staged *StagedTransfers) BindPaths() []string {
	names := []string{transferlayout.ComponentDir(staged.Component)}
	if staged.hasComponentFile {
		names = append(names, componentFileName(staged.Component))
	}
	path := staged.Path()
	binds := make([]string, 0, len(names))
	for _, name := range names {
		binds = append(binds, path+"/"+name+":"+bindMountDir+"/"+name)
	}
	return binds
}

// Close releases the staging directory handle but leaves the directory in
// place for debugging a failed run. It is removed at the start of the next
// run.
func (staged *StagedTransfers) Close() error {
	if staged.root == nil {
		return nil
	}
	err := staged.root.Close()
	staged.root = nil
	if err != nil && !errors.Is(err, fs.ErrClosed) {
		return err
	}
	return nil
}

// Remove deletes the staging directory.
func (staged *StagedTransfers) Remove() error {
	return errors.Join(staged.Close(), staged.removeFn())
}

// Stage lays the definitions of the given component out for a
// systemd-sysupdate run, in a staging directory of its own:
//
//	<store>/sysupdate.d/sysupdate.d/*                                   (default component)
//	<store>/sysupdate.<component>.d/sysupdate.<component>.d/*           (component)
//	<store>/sysupdate.<component>.d/sysupdate.<component>.component
//
// Transfer files get their [Source] Path= replaced by OverrideSourcePathURL,
// and so do transfer drop-ins that set one.
//
// The machine tags decide the enablement because sysupdate does not enable
// suggested components and features by itself. The default component and a
// component without a component file are enabled as for sysupdate. A
// component file that does not enable its component gets [Component]
// Enabled=true if it is suggested for the machine (see
// [definitionSuggested]). Otherwise the component is skipped, and Stage
// returns nil without an error. A feature that is not enabled gets [Feature]
// Enabled=true if it is suggested for the machine. Otherwise it is staged as
// shipped. Only the component or feature file itself is evaluated for this.
// Enabled= and SuggestOn*= in its drop-ins are not, although sysupdate still
// applies an Enabled= from a drop-in. The caller removes the staging
// directory once the run succeeded (or closes it to keep it for debugging).
func (ext *TransferFileExtension) Stage(ctx context.Context, dir *TransferDir, opts StageOptions) (_ *StagedTransfers, Err error) {
	if ext.storeDir == nil {
		return nil, errors.New("transfer extension is not initialised")
	}

	// Everything is read first because the component file decides whether
	// the component is staged at all.
	files := make(map[string][]byte, len(dir.files))
	for file, info := range dir.files {
		data, err := readTarget(ctx, info, maxDefinitionFileSize)
		if err != nil {
			return nil, err
		}
		files[file] = data
	}
	var (
		componentFile    []byte
		hasComponentFile bool
	)
	if dir.Component != "" {
		// It is staged as a sibling of the definitions directory below.
		name := dir.Component + ".component"
		componentFile, hasComponentFile = files[name]
		delete(files, name)
		if hasComponentFile && !definitionEnabled(componentFile, "Component", true) {
			if !suggestedForMachine(dir.files[name], componentFile, "Component", opts.MachineTags) {
				slog.Info("[xsysupdate transfers stage] Skipping component not enabled on this machine.",
					"directory", dir.path)
				return nil, nil //nolint:nilnil // nil indicates a skipped component
			}
			var err error
			if componentFile, err = enableINI(componentFile, "Component"); err != nil {
				return nil, fmt.Errorf("patch %s: %w", dir.files[name].Path, err)
			}
			slog.Info("[xsysupdate transfers stage] Enabling suggested component.",
				"directory", dir.path)
		}
	}

	subdir := transferlayout.ComponentDir(dir.Component)
	if err := ext.storeDir.RemoveAll(subdir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("remove old staging dir %s: %w", subdir, err)
	}
	handle, err := ext.storeDir.MkdirAll(subdir, 0o755)
	if err != nil {
		return nil, fmt.Errorf("create staging dir %s: %w", subdir, err)
	}
	defer funchelpers.VerifyClose(&Err, handle)
	root, err := pathrs.RootFromFile(handle.IntoFile())
	if err != nil {
		return nil, fmt.Errorf("convert staging dir %s to root: %w", subdir, err)
	}
	staged := &StagedTransfers{
		Component:        dir.Component,
		hasComponentFile: hasComponentFile,
		root:             root,
		removeFn: func() error {
			if err := ext.storeDir.RemoveAll(subdir); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove staging dir %s: %w", subdir, err)
			}
			return nil
		},
	}
	defer func() {
		if Err != nil {
			Err = errors.Join(Err, staged.Remove())
		}
	}()

	slog.Info("[xsysupdate transfers stage] Staging transfer definitions.",
		"directory", dir.path, "path", staged.Path())

	for _, file := range slices.Sorted(maps.Keys(files)) {
		info, data := dir.files[file], files[file]
		var err error
		switch {
		case strings.HasSuffix(file, ".transfer"):
			data, err = rewriteINI(data, func(transfer *ini.File) {
				if overrideURL := ext.OverrideSourcePathURL; overrideURL != nil {
					// This allocates a new Source section and Path value if missing.
					setKey(transfer.Section("Source"), "Path", *overrideURL)
				}
			})
		case isTransferDropIn(file):
			// sysupdate reads the drop-in after its transfer file, so a Path=
			// here would bypass the proxy. Other drop-ins are staged verbatim.
			if overrideURL := ext.OverrideSourcePathURL; overrideURL != nil && setsSourcePath(data) {
				data, err = rewriteINI(data, func(dropIn *ini.File) {
					setKey(dropIn.Section("Source"), "Path", *overrideURL)
				})
			}
		case strings.HasSuffix(file, ".feature"):
			enabled := definitionEnabled(data, "Feature", false)
			if !enabled && suggestedForMachine(info, data, "Feature", opts.MachineTags) {
				data, err = enableINI(data, "Feature")
				enabled = true
				staged.EnabledFeatures = append(staged.EnabledFeatures, strings.TrimSuffix(file, ".feature"))
			}
			slog.Info("[xsysupdate transfers stage] Decided feature enablement.",
				"feature", file, "enabled", enabled)
		}
		if err != nil {
			return nil, fmt.Errorf("patch %s: %w", info.Path, err)
		}
		if err := pathrsext.WriteFile(root, subdir+"/"+file, data); err != nil {
			return nil, fmt.Errorf("stage %s: %w", info.Path, err)
		}
	}
	if hasComponentFile {
		if err := pathrsext.WriteFile(root, componentFileName(dir.Component), componentFile); err != nil {
			return nil, fmt.Errorf("stage component file of %s: %w", dir.path, err)
		}
	}
	return staged, nil
}
