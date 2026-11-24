// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyphar.com/go-pathrs"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sys/unix"
	"gopkg.in/ini.v1"

	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient"
)

const (
	// TransferFilePrefix is the prefix used for our "auto-applied transfer files"
	// extension to sysupdate. Any target file in a repository with this prefix
	// will be installed as /etc/sysupdate.* (with the [Source] Path= adjusted to
	// point to the local quarry-http-client server).
	TransferFilePrefix = ExtensionTargetPrefix + transferFileName

	// transferFileName is [TransferFilePrefix] without the
	// [ExtensionTargetPrefix].
	transferFileName = "sysupdate."

	liveLink = "live"
	lastLink = "last"
)

// These are variables so that we can modify them in tests.
var (
	// transferInstallDir is the directory where the transfer file *symlinks*
	// will be installed. This needs to be one of systemd-sysupdate's search
	// directories, be writable, and be persistent across reboot.
	//
	// On AmutableOS, only /etc fits the bill.
	transferInstallDir = "/etc" // .../sysupdate{.*,.d}
	// extensionInstallDir is where sysext and confexts are linked by default
	// using CurrentSymlink.
	// FIXME: This is only needed for the systemd bug workaround in Init.
	extensionInstallDir = transferInstallDir + "/extensions"
)

// transferInstallPatterns are a set of globs that will match the symlink names
// in /etc and in /var/lib/quarry-sysupdate/xsysupdate/transfers/.
var transferInstallPatterns = [...]string{
	"sysupdate.d/*",         // base system transfer files
	"sysupdate.*.component", // component definition files
	// NOTE: This covers both component transfer files (sysupdate.foo.d) and
	// component drop-in files (sysupdate.foo.component.d) as we cannot
	// differentiate the two with a standard glob.
	"sysupdate.*.d",
}

// TransferFileExtension is an [Extension] that implements auto-installation of
// target files from Quarry repositories.
type TransferFileExtension struct {
	// OverrideSourcePathURL (if non-nil) is a URL which replaces all [Source]
	// Path entries in transfer files when persisting them to disk. This is
	// intended to be the URL to the "quarry-client http" server that proxies
	// sysupdate requests.
	OverrideSourcePathURL *string

	// storeDir is the storage for transfer files in general.
	storeDir *pathrs.Root
	// subdirectory in storeDir where the previous update's files live.
	oldDirSubpath string
	// subdirectory in which our new transfer files live.
	newDir        *pathrs.Root
	newDirSubpath string

	// modifiedEtc is set to true once BeforeUpdate has been called and we have
	// modified the global /etc (meaning on Abort we need to undo our changes).
	modifiedEtc bool
}

var _ Extension = &TransferFileExtension{}

// Name returns the name of this extension.
func (ext *TransferFileExtension) Name() string { return "transfers" }

func (ext *TransferFileExtension) unlinkTransfers() error {
	storeDirPrefix := ext.storeDir.IntoFile().Name() + "/"
	for _, pattern := range transferInstallPatterns {
		pattern = filepath.Join(transferInstallDir, pattern) //nolint:forbidigo // host-controlled directory
		matches, err := filepath.Glob(pattern)               //nolint:forbidigo // host-controlled directory
		if err != nil {
			return fmt.Errorf("could not glob %q pattern: %w", pattern, err)
		}
		for _, match := range matches {
			linkTarget, err := os.Readlink(match)
			if err != nil {
				if errors.Is(err, unix.EINVAL) {
					// Not a symlink.
					slog.Info("[xsysupdate transfers] Skipping non-symlink transfer file.",
						"transfer", match)
				} else {
					// Some other error.
					slog.Warn("[xsysupdate transfers] Skipping otherwise-invalid transfer file.",
						"transfer", match, "err", err.Error())
				}
				continue
			}
			if !strings.HasPrefix(linkTarget, storeDirPrefix) {
				slog.Info("[xsysupdate transfers] Skipping non-quarry transfer file link.",
					"transfer", match, "linkTarget", linkTarget, "wantPrefix", storeDirPrefix)
				continue
			}
			if err := os.Remove(match); err != nil { //nolint:forbidigo // host-controlled directory with fixed patterns
				return fmt.Errorf("remove old quarry transfer file link %s: %w", match, err)
			}
		}
	}
	return nil
}

// linkTransfers takes an xsysypdate/transfers/* directory full of transfer
// files and links them into [transferInstallDir].
func (ext *TransferFileExtension) linkTransfers(subdir string) error {
	srcTransferDir := filepath.Join(ext.storeDir.IntoFile().Name(), subdir) //nolint:forbidigo // TODO: Implement pathrsext.Glob.
	slog.Info("[xsysupdate transfers] Linking auto-enable transfers into host sysupdate directory.",
		"transferDir", srcTransferDir, "installDir", transferInstallDir)
	for _, pattern := range transferInstallPatterns {
		pattern = filepath.Join(srcTransferDir, pattern) //nolint:forbidigo // TODO: Implement pathrsext.Glob.
		matches, err := filepath.Glob(pattern)           //nolint:forbidigo // TODO: Implement pathrsext.Glob.
		if err != nil {
			return fmt.Errorf("could not glob %q pattern: %w", pattern, err)
		}
		for _, match := range matches {
			transferName, hasPrefix := strings.CutPrefix(match, srcTransferDir)
			if !hasPrefix {
				// Should never happen!
				return fmt.Errorf("match %q is missing transfer dir prefix %q", match, srcTransferDir)
			}
			// TODO: Ideally we would do this through a pathrs.Root handle to
			// /etc, to avoid all of these fairly concerning path operations.
			// But in practice, the danger of writing to the wrong /etc file is
			// just as bad as writing outside of /etc...
			linkname := filepath.Join(transferInstallDir, transferName)        //nolint:forbidigo  // restricted lexical pathname in host-controlled directory
			if err := os.MkdirAll(filepath.Dir(linkname), 0o755); err != nil { //nolint:forbidigo // host-controlled directory // TODO: We should do this with pathrs.Root anyway...
				return fmt.Errorf("make transfer %s directory: %w", match, err)
			}
			if err := os.Symlink(match, linkname); err != nil { //nolint:forbidigo // host-controlled directory // TODO: We should do this with pathrs.Root anyway...
				return fmt.Errorf("link transfer %s: %w", match, err)
			}
			slog.Info("[xsysupdate transfers] Linked auto-enable transfer.",
				"transfer", match, "link", linkname)
		}
	}
	return nil
}

// Init constructs the storage area for the auto-enabled transfer files.
func (ext *TransferFileExtension) Init(ctx context.Context) (_ context.Context, Err error) {
	ctx, err := makeExtStoreDir(ctx, ext)
	if err != nil {
		return nil, fmt.Errorf("make %s extension store: %w", ext.Name(), err)
	}
	ext.storeDir = ctxExtStoreDir(ctx, ext)
	// storeDir will be closed by Abort on error.

	// FIXME: sysupdate does not auto-create the parent directory of
	// CurrentSymlink=, which causes update failures.See
	// <https://github.com/systemd/systemd/pull/42093>.
	if err := os.MkdirAll(extensionInstallDir, 0o755); err != nil { //nolint:forbidigo // fixed host-controlled path
		return nil, err
	}

	// Get the current "live" directory subpath for recovery purposes in Abort.
	// If there is no such symlink, ignore the error as that is the initial
	// state and we just need to skip linkTransfers in the Abort path.
	if subpath, err := ext.storeDir.Readlink(liveLink); errors.Is(err, fs.ErrNotExist) {
		slog.Info("[xsysupdate transfers init] No existing 'live' link found -- Abort will not restore anything.",
			"err", err.Error())
	} else if err != nil {
		return nil, fmt.Errorf("old %s link is invalid: %w", liveLink, err)
	} else {
		ext.oldDirSubpath = subpath
		// Move the "live" link to "last", for abort purposes.
		if err := ext.storeDir.Rename(liveLink, lastLink, 0); err != nil {
			return nil, fmt.Errorf("swap %s link to %s link: %w", liveLink, lastLink, err)
		}
	}

	// Create a new time-based directory path. The reference time is the same
	// for every update pass of a run, so skip the directories of earlier
	// passes -- the last one is live and is what Abort restores.
	refTime, _ := ctxext.RefTime(ctx)
	base := fmt.Sprintf("update-%s.%d", refTime.Format(time.DateOnly), refTime.UnixMilli())
	ext.newDirSubpath = base
	for n := 2; ; n++ {
		// Anything else in the way is left for MkdirAll to complain about.
		if info, err := pathrsext.Stat(ext.storeDir, ext.newDirSubpath); err != nil || !info.IsDir() {
			break
		}
		ext.newDirSubpath = fmt.Sprintf("%s.%d", base, n)
	}

	newDirHandle, err := ext.storeDir.MkdirAll(ext.newDirSubpath, 0o755)
	if err != nil {
		return nil, fmt.Errorf("create new update subdir: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, newDirHandle)

	ext.newDir, err = pathrs.RootFromFile(newDirHandle.IntoFile())
	if err != nil {
		return nil, fmt.Errorf("convert update subdir to root: %w", err)
	}
	// newDir will be closed by Abort on error.

	return ctx, nil
}

// patchTransferFile writes out a transfer file, after rewriting the source
// path with OverrideSourcePathURL (if set).
func (ext *TransferFileExtension) patchTransferFile(wtr io.Writer, rdr io.Reader) error {
	transfer, err := ini.Load(rdr)
	if err != nil {
		return fmt.Errorf("load transfer file ini: %w", err)
	}
	if overrideURL := ext.OverrideSourcePathURL; overrideURL != nil {
		// This allocates a new Source section and Path value if missing.
		transfer.Section("Source").Key("Path").SetValue(*overrideURL)
	}
	if _, err := transfer.WriteTo(wtr); err != nil {
		return fmt.Errorf("serialise transfer file: %w", err)
	}
	return nil
}

// isPatchableDefinition returns whether transferPath is a file which should be
// patched with a custom [Source] Path= value (in particular, .transfer files
// or any .transfer.d/*.conf drop-ins).
func isPatchableDefinition(transferPath string) bool {
	dir, file := filepath.Split(transferPath)      //nolint:forbidigo // lexical check only
	return strings.HasSuffix(file, ".transfer") || // transfer file
		(strings.HasSuffix(file, ".conf") && strings.HasSuffix(dir, ".transfer.d/")) // drop-in
}

// ApplyTarget saves the transfer file from the repository to the per-update
// transfer directory.
func (ext *TransferFileExtension) ApplyTarget(ctx context.Context, info *tufclient.TargetInfo) (_ bool, Err error) {
	transferPath, _, ok := CutExtensionTargetPrefix(info.Path)
	if !ok || !strings.HasPrefix(transferPath, transferFileName) {
		return false, nil // not for this extension
	}

	slog.Info("[xsysupdate transfers target] Applying transfer file.",
		"target", info.Path, "repository", info.Repo.Name)

	srcTransferFile, err := info.Fetch(ctx)
	if err != nil {
		return false, fmt.Errorf("fetch transfer file %s: %w", info.Path, err)
	}
	defer funchelpers.VerifyClose(&Err, srcTransferFile)

	dstTransferTmpFile, err := ext.newDir.Create(".", unix.O_TMPFILE|unix.O_RDWR|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return false, fmt.Errorf("create tmpfile for transfer file %s: %w", info.Path, err)
	}
	defer funchelpers.VerifyClose(&Err, dstTransferTmpFile)

	srcRdr := progressbar.NewReader(srcTransferFile,
		progressbar.DefaultBytes(info.Length, info.Path))
	if isPatchableDefinition(transferPath) {
		err = ext.patchTransferFile(dstTransferTmpFile, &srcRdr)
	} else {
		_, err = io.Copy(dstTransferTmpFile, &srcRdr)
	}
	if err != nil {
		return false, fmt.Errorf("write transfer file %s to tmpfile: %w", info.Path, err)
	}
	if err := srcTransferFile.Close(); err != nil {
		return false, fmt.Errorf("transfer file %s close check failed: %w", info.Path, err)
	}
	if err := dstTransferTmpFile.Sync(); err != nil {
		return false, fmt.Errorf("sync writes to transfer tmpfile %s: %w", info.Path, err)
	}

	transferPathDir, _ := filepath.Split(transferPath) //nolint:forbidigo // lexical path to be passed to libpathrs
	if handle, err := ext.newDir.MkdirAll(transferPathDir, 0o755); err != nil {
		return false, fmt.Errorf("mkdir transfer file parent dir %s: %w", transferPathDir, err)
	} else if err := handle.Close(); err != nil {
		return false, fmt.Errorf("close transfer file parent dir %s: %w", transferPathDir, err)
	}

	if err := pathrsext.AttachIntoRoot(ext.newDir, transferPath, dstTransferTmpFile); err != nil {
		return false, fmt.Errorf("attach transfer tmpfile %s into %s/%s: %w", info.Path, ext.newDir.IntoFile().Name(), transferPath, err)
	}
	return true, nil
}

// BeforeUpdate adds /etc symlinks for all of the transfer files installed
// during this update, and removes any old quarry-managed transfer files.
func (ext *TransferFileExtension) BeforeUpdate(_ context.Context) (Err error) {
	if err := ext.storeDir.Symlink(ext.newDirSubpath, liveLink); err != nil {
		return fmt.Errorf("add %s link to %s: %w", liveLink, ext.newDirSubpath, err)
	}

	// We are now modifying the host.
	ext.modifiedEtc = true

	// Replace the /etc/sysupdate.* links.
	if err := ext.unlinkTransfers(); err != nil {
		return fmt.Errorf("unlink old transfer files: %w", err)
	}
	if err := ext.linkTransfers(ext.newDirSubpath); err != nil {
		err = fmt.Errorf("link new transfer files from %s: %w", ext.newDirSubpath, err)
		// Remove any partially-added transfer files.
		slog.Warn("[xsysupdate transfers before-update] Removing partially-added transfer files on error.",
			"newDir", ext.newDirSubpath, "err", err.Error())
		if err2 := ext.unlinkTransfers(); err2 != nil {
			err = fmt.Errorf("%w (failure during removal of new files: %w)", err, err2)
		}
		return err
	}
	return nil
}

// Abort resets the transfer file state to before the update was started.
func (ext *TransferFileExtension) Abort(_ context.Context, srcErr error) error {
	var errs []error
	// Revert the old transfer files (if we modified the host).
	if ext.modifiedEtc {
		slog.Info("[xsysupdate transfers abort] Reverting transfer files to old reposistory state.",
			"oldDir", ext.oldDirSubpath, "err", srcErr.Error())
		if err := ext.unlinkTransfers(); err != nil {
			errs = append(errs, fmt.Errorf("unlink old transfer files: %w", err))
		}
		if ext.oldDirSubpath != "" {
			if err := ext.linkTransfers(ext.oldDirSubpath); err != nil {
				errs = append(errs, fmt.Errorf("link old transfer files from %s: %w", ext.oldDirSubpath, err))
			}
		}
	}
	// Kill the new update directory.
	if ext.newDirSubpath != "" {
		slog.Info("[xsysupdate transfers abort] Removing broken transfer file directory.",
			"dir", ext.newDirSubpath, "err", srcErr.Error())
		if err := ext.storeDir.RemoveAll(ext.newDirSubpath); err != nil {
			errs = append(errs, fmt.Errorf("remove new transfer dir %s: %w", ext.newDirSubpath, err))
		}
	}
	// Swap back "last" over "live".
	if ext.oldDirSubpath != "" {
		slog.Info("[xsysupdate transfers abort] Swapping back last link to live link.")
		if err := ext.storeDir.Rename(lastLink, liveLink, 0); err != nil {
			errs = append(errs, fmt.Errorf("swap back %s link to %s link: %w", lastLink, liveLink, err))
		}
	} else if ext.modifiedEtc {
		slog.Info("[xsysupdate transfers abort] Removing live link (no previous update).")
		if err := ext.storeDir.Remove(liveLink); err != nil {
			errs = append(errs, fmt.Errorf("remove %s link: %w", liveLink, err))
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

// Close clears any resources used by the extension.
func (ext *TransferFileExtension) Close() error {
	var errs []error
	if ext.storeDir != nil {
		err := ext.storeDir.Close()
		if err != nil && !errors.Is(err, fs.ErrClosed) {
			errs = append(errs, err)
		}
		ext.storeDir = nil
	}
	if ext.newDir != nil {
		err := ext.newDir.Close()
		if err != nil && !errors.Is(err, fs.ErrClosed) {
			errs = append(errs, err)
		}
		ext.newDir = nil
	}
	return errors.Join(errs...)
}
