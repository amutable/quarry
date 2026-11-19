// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseComponents_SkipsDisabled(t *testing.T) {
	// As printed by "systemd-sysupdate --json=short components".
	const output = `{"default":true,"components":["cilium","k8s-cp","k8s-worker"],"details":[` +
		`{"description":"Cilium","enabled":true,"suggested":true,"name":"cilium"},` +
		`{"description":"Kubernetes control plane","enabled":false,"suggested":false,"name":"k8s-cp"},` +
		`{"enabled":true,"suggested":false,"name":"k8s-worker"}]}`

	components, err := parseComponents([]byte(output))
	require.NoError(t, err)
	assert.Equal(t, []string{"cilium", "k8s-worker", defaultComponent}, components)
}

// A systemd-sysupdate without "details" reports the names only.
func TestParseComponents_WithoutDetails(t *testing.T) {
	components, err := parseComponents([]byte(`{"default":false,"components":["a","b"]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, components)

	components, err = parseComponents([]byte(`{"default":true,"components":[]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{defaultComponent}, components)

	_, err = parseComponents([]byte(`not json`))
	require.Error(t, err)
}
