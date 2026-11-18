// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.amutable.dev/quarry/internal/systemdcmd"
)

func TestSysupdateRunArgs(t *testing.T) {
	binds := []string{
		"/var/lib/quarry-sysupdate/xsysupdate/transfers/sysupdate.foo.d/sysupdate.foo.d:/run/sysupdate.foo.d",
		"/var/lib/quarry-sysupdate/xsysupdate/transfers/sysupdate.foo.d/sysupdate.foo.component:/run/sysupdate.foo.component",
	}
	sysupdate := systemdcmd.FindCmd("sysupdate")
	assert.Equal(t, []string{
		"--collect", "--pipe",
		"-p", "BindReadOnlyPaths=" + binds[0],
		"-p", "BindReadOnlyPaths=" + binds[1],
		sysupdate, "--component-all", "update",
	}, sysupdateRunArgs(binds, "--component-all", "update"))

	// There are no -p arguments at all without bind paths.
	assert.Equal(t, []string{"--collect", "--pipe", sysupdate, "update"}, sysupdateRunArgs(nil, "update"))
}
