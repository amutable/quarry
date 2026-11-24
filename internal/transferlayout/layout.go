// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package transferlayout describes the repository layout of what quarry
// ships as special TUF targets for systemd-sysupdate. This covers the
// transfer definition directories, component files and component drop-in
// directories under ".quarry/".
//
// hardhat writes this layout ("hardhat targets --quarry-*") and
// quarry-sysupdate (internal/xsysupdate) reads it, so both sides share the
// names and rules here.
package transferlayout

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// Prefix is the target path prefix of everything quarry-specific in a
	// repository. Such a target is never a file that a client installs
	// directly.
	Prefix = ".quarry/"

	// defaultDir is the definitions directory of the default (component-less)
	// sysupdate component. The directory of a named component is
	// "sysupdate.<component>.d".
	defaultDir = "sysupdate.d"
)

// ValidPathComponent returns whether name is usable as one path element.
func ValidPathComponent(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/")
}

// ComponentDir returns the definitions directory name of a component. The
// component "" names the default component.
func ComponentDir(component string) string {
	if component == "" {
		return defaultDir
	}
	return "sysupdate." + component + ".d"
}

// ParseComponentDir returns the component a definitions directory name is
// for. It returns "" for the default component's directory "sysupdate.d".
func ParseComponentDir(dir string) (string, error) {
	if dir == defaultDir {
		return "", nil
	}
	if !strings.HasPrefix(dir, "sysupdate.") || !strings.HasSuffix(dir, ".d") {
		return "", fmt.Errorf("invalid definitions directory name %q", dir)
	}
	component := strings.TrimSuffix(strings.TrimPrefix(dir, "sysupdate."), ".d")
	if !ValidPathComponent(component) || strings.Contains(component, ".") {
		return "", fmt.Errorf("invalid component name %q in directory %q", component, dir)
	}
	return component, nil
}

// TargetPath returns the target path of one file of a transfer definition
// directory, which is "<Prefix><dir>/<file>".
func TargetPath(dir, file string) (string, error) {
	if _, err := ParseComponentDir(dir); err != nil {
		return "", err
	}
	if err := checkFilePath(file); err != nil {
		return "", err
	}
	return Prefix + dir + "/" + file, nil
}

// checkFilePath returns an error unless file is a relative path made of valid
// path elements.
func checkFilePath(file string) error {
	for part := range strings.SplitSeq(file, "/") {
		if !ValidPathComponent(part) {
			return fmt.Errorf("invalid transfer file path %q", file)
		}
	}
	return nil
}

// ComponentFilePath returns the target path of a named component's definition
// file, which is "<Prefix>sysupdate.<component>.component". The default
// component has no component file.
func ComponentFilePath(component string) (string, error) {
	if component == "" {
		return "", errors.New("the default component has no component file")
	}
	if _, err := ParseComponentDir(ComponentDir(component)); err != nil {
		return "", err
	}
	return Prefix + "sysupdate." + component + ".component", nil
}

// ComponentDropInPath returns the target path of one file of a named
// component's drop-in directory, which is
// "<Prefix>sysupdate.<component>.component.d/<file>".
func ComponentDropInPath(component, file string) (string, error) {
	componentPath, err := ComponentFilePath(component)
	if err != nil {
		return "", err
	}
	if err := checkFilePath(file); err != nil {
		return "", err
	}
	return componentPath + ".d/" + file, nil
}

// ComponentFile returns the generated "<component>.component" definition for
// a component that ships none. It sets no Enabled=, so it is an
// enabled-by-default component as in sysupdate.
func ComponentFile(component string) []byte {
	return []byte("[Component]\nDescription=" + component + "\n")
}
