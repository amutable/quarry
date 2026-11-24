// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseComponents(t *testing.T) {
	for _, test := range []struct {
		name    string
		data    string
		want    []string
		wantErr bool
	}{
		{
			name: "SkipsDisabled",
			// As printed by "systemd-sysupdate --json=short components".
			data: `{
				"default": true,
				"components": ["cilium", "k8s-cp", "k8s-worker"],
				"details": [
					{"description": "Cilium", "enabled": true, "suggested": true, "name": "cilium"},
					{"description": "Kubernetes control plane", "enabled": false, "suggested": false, "name": "k8s-cp"},
					{"enabled": true, "suggested": false, "name": "k8s-worker"}
				]
			}`,
			want: []string{"cilium", "k8s-worker", defaultComponent},
		},
		{
			name: "SkipsDisabled_NoDefault",
			data: `{
				"default": false,
				"components": ["a", "b", "c"],
				"details": [
					{"name": "a", "enabled": true},
					{"name": "b", "enabled": false},
					{"name": "c", "enabled": true}
				]
			}`,
			want: []string{"a", "c"},
		},
		{
			name: "AllDisabled_Default",
			data: `{
				"default": true,
				"components": ["a", "b"],
				"details": [
					{"name": "a", "enabled": false},
					{"name": "b", "enabled": false}
				]
			}`,
			want: []string{defaultComponent},
		},
		{
			name: "AllDisabled_NoDefault",
			data: `{
				"default": false,
				"components": ["a", "b"],
				"details": [
					{"name": "a", "enabled": false},
					{"name": "b", "enabled": false}
				]
			}`,
			want: []string{},
		},
		// Only an explicit "enabled": false disables a component.
		{
			name: "EnabledMissing",
			data: `{
				"default": false,
				"components": ["a"],
				"details": [{"name": "a"}]
			}`,
			want: []string{"a"},
		},
		{
			name: "EnabledNull",
			data: `{
				"default": false,
				"components": ["a"],
				"details": [{"name": "a", "enabled": null}]
			}`,
			want: []string{"a"},
		},
		{
			name: "DetailsPartial",
			data: `{
				"default": false,
				"components": ["a", "b"],
				"details": [{"name": "b", "enabled": false}]
			}`,
			want: []string{"a"},
		},
		{
			name: "DetailsUnknownComponent",
			data: `{
				"default": false,
				"components": ["a"],
				"details": [{"name": "b", "enabled": false}]
			}`,
			want: []string{"a"},
		},
		// A systemd-sysupdate without "details" reports the names only.
		{
			name: "WithoutDetails_Default",
			data: `{"default": true, "components": ["a", "b"]}`,
			want: []string{"a", "b", defaultComponent},
		},
		{
			name: "WithoutDetails_NoDefault",
			data: `{"default": false, "components": ["a", "b"]}`,
			want: []string{"a", "b"},
		},
		{
			name: "WithoutDetails_DefaultOnly",
			data: `{"default": true, "components": []}`,
			want: []string{defaultComponent},
		},
		{
			name: "WithoutDetails_Empty",
			data: `{"default": false, "components": []}`,
			want: []string{},
		},
		{
			name: "WithoutDetails_NullComponents",
			data: `{"default": true, "components": null}`,
			want: []string{defaultComponent},
		},
		{name: "EmptyObject", data: `{}`, want: nil},
		{name: "InvalidJSON", data: `not json`, wantErr: true},
		{name: "InvalidComponentsType", data: `{"components": "a"}`, wantErr: true},
		{name: "InvalidDefaultType", data: `{"default": "true"}`, wantErr: true},
		{
			name:    "InvalidEnabledType",
			data:    `{"components": ["a"], "details": [{"name": "a", "enabled": "false"}]}`,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			components, err := parseComponents([]byte(test.data))
			if test.wantErr {
				require.Error(t, err)
				assert.Nil(t, components)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.want, components)
			}
		})
	}
}
