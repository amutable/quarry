// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package transferlayout

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetPath(t *testing.T) {
	path, err := TargetPath("sysupdate.d", "12-usr.transfer")
	require.NoError(t, err)
	assert.Equal(t, ".quarry/sysupdate.d/12-usr.transfer", path)

	path, err = TargetPath("sysupdate.k8s.d", "k8s.transfer.d/10-x.conf")
	require.NoError(t, err)
	assert.Equal(t, ".quarry/sysupdate.k8s.d/k8s.transfer.d/10-x.conf", path)

	for _, tc := range []struct{ dir, file string }{
		{"other.d", "x.transfer"},
		{"sysupdate.a.b.d", "x.transfer"},
		{"sysupdate.d", ""},
		{"sysupdate.d", "a/../b"},
	} {
		_, err := TargetPath(tc.dir, tc.file)
		require.Error(t, err, "%v", tc)
	}
}

func TestComponentDir(t *testing.T) {
	assert.Equal(t, "sysupdate.d", ComponentDir(""))
	assert.Equal(t, "sysupdate.k8s.d", ComponentDir("k8s"))
	for _, dir := range []string{"sysupdate.a.b.d", "sysupdate..d"} {
		_, err := ParseComponentDir(dir)
		require.Error(t, err, dir)
	}
	for _, dir := range []string{"sysupdate.d", "sysupdate.k8s.d"} {
		component, err := ParseComponentDir(dir)
		require.NoError(t, err)
		assert.Equal(t, dir, ComponentDir(component))
	}
}

func TestComponentFilePath(t *testing.T) {
	path, err := ComponentFilePath("k8s")
	require.NoError(t, err)
	assert.Equal(t, ".quarry/sysupdate.k8s.component", path)

	for _, component := range []string{"", "a.b", "a/b", ".."} {
		_, err := ComponentFilePath(component)
		require.Error(t, err, "component %q", component)
	}
}

func TestComponentDropInPath(t *testing.T) {
	path, err := ComponentDropInPath("k8s", "10-x.conf")
	require.NoError(t, err)
	assert.Equal(t, ".quarry/sysupdate.k8s.component.d/10-x.conf", path)

	for _, tc := range []struct{ component, file string }{
		{"", "10-x.conf"},
		{"a.b", "10-x.conf"},
		{"k8s", ""},
		{"k8s", "a/../b"},
	} {
		_, err := ComponentDropInPath(tc.component, tc.file)
		require.Error(t, err, "%v", tc)
	}
}

func TestComponentFile(t *testing.T) {
	assert.Equal(t, "[Component]\nDescription=k8s\n", string(ComponentFile("k8s")))
}
