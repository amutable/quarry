// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package pathrsext

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"cyphar.com/go-pathrs"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// WriteFile writes data to path inside root, creating parent directories as
// needed. The data is written to an unlinked temporary file first and only
// attached under its name once synced. An existing file is unlinked before
// that, so the replacement is not atomic. A failed attach leaves no file.
func WriteFile(root *pathrs.Root, path string, data []byte) (Err error) {
	if dir, _ := filepath.Split(path); dir != "" { //nolint:forbidigo // lexical path to be passed to libpathrs
		dir = strings.TrimSuffix(dir, "/")
		handle, err := root.MkdirAll(dir, 0o755)
		if err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := handle.Close(); err != nil {
			return fmt.Errorf("close %s: %w", dir, err)
		}
	}
	tmpFile, err := root.Create(".", unix.O_TMPFILE|unix.O_RDWR|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("create tmpfile for %s: %w", path, err)
	}
	defer funchelpers.VerifyClose(&Err, tmpFile)
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("write tmpfile for %s: %w", path, err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync tmpfile for %s: %w", path, err)
	}
	// linkat(2) does not replace, so make room for the new file first.
	if err := root.RemoveFile(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove old %s: %w", path, err)
	}
	if err := AttachIntoRoot(root, path, tmpFile); err != nil {
		return fmt.Errorf("attach tmpfile as %s: %w", path, err)
	}
	return nil
}
