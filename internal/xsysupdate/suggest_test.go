// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefinitionSuggested(t *testing.T) {
	tags := []string{"amutable.os", "amutable.ext.docker", "acp.site=berlin"}
	for _, tc := range []struct {
		name      string
		section   string
		text      string
		suggested bool
		wantErr   bool
	}{
		{name: "no keys", text: "[Feature]\nEnabled=false\n"},
		{name: "no section", text: "[Transfer]\nSuggestOnMachineTag=amutable.os\n"},
		{name: "other section", text: "[Feature]\n[Other]\nSuggestOnMachineTag=amutable.os\n"},
		{name: "matching tag", text: "[Feature]\nSuggestOnMachineTag=amutable.ext.docker\n", suggested: true},
		{name: "missing tag", text: "[Feature]\nSuggestOnMachineTag=amutable.ext.podman\n"},
		{name: "no prefix match", text: "[Feature]\nSuggestOnMachineTag=amutable\n"},
		{name: "glob", text: "[Feature]\nSuggestOnMachineTag=amutable.ext.*\n", suggested: true},
		{name: "glob class", text: "[Feature]\nSuggestOnMachineTag=amutable.[eo]s\n", suggested: true},
		{name: "key and value", text: "[Feature]\nSuggestOnMachineTag=acp.site=berlin\n", suggested: true},
		{name: "key of tag with value", text: "[Feature]\nSuggestOnMachineTag=acp.site\n"},
		{name: "key glob of tag with value", text: "[Feature]\nSuggestOnMachineTag=acp.site=*\n", suggested: true},
		{name: "invalid pattern", text: "[Feature]\nSuggestOnMachineTag=amutable.[\n"},
		{name: "all must hold", text: "[Feature]\nSuggestOnMachineTag=amutable.os\nSuggestOnMachineTag=amutable.k8s\n"},
		{name: "all hold", text: "[Feature]\nSuggestOnMachineTag=amutable.os\nSuggestOnMachineTag=amutable.ext.docker\n", suggested: true},
		{name: "negated", text: "[Feature]\nSuggestOnMachineTag=!amutable.os\n"},
		{name: "negated missing", text: "[Feature]\nSuggestOnMachineTag=!amutable.k8s\n", suggested: true},
		{name: "negated with space", text: "[Feature]\nSuggestOnMachineTag=! amutable.k8s\n", suggested: true},
		{name: "one trigger holds", text: "[Feature]\nSuggestOnMachineTag=|amutable.k8s\nSuggestOnMachineTag=|amutable.os\n", suggested: true},
		{name: "no trigger holds", text: "[Feature]\nSuggestOnMachineTag=|amutable.k8s\nSuggestOnMachineTag=|amutable.gw\n"},
		{name: "trigger and failing condition", text: "[Feature]\nSuggestOnMachineTag=|amutable.os\nSuggestOnMachineTag=amutable.k8s\n"},
		{name: "negated trigger", text: "[Feature]\nSuggestOnMachineTag=| !amutable.k8s\nSuggestOnMachineTag=|amutable.gw\n", suggested: true},
		{name: "reset", text: "[Feature]\nSuggestOnMachineTag=amutable.k8s\nSuggestOnMachineTag=\nSuggestOnMachineTag=amutable.os\n", suggested: true},
		{name: "reset to nothing", text: "[Feature]\nSuggestOnMachineTag=amutable.os\nSuggestOnMachineTag=\n"},
		{name: "suggest ignored", text: "[Feature]\nSuggest=yes\nSuggestOnMachineTag=amutable.k8s\n"},
		{name: "unsupported condition", text: "[Feature]\nSuggestOnMachineTag=amutable.os\nSuggestOnArchitecture=x86-64\n", wantErr: true},
		{name: "unsupported condition reset", text: "[Feature]\nSuggestOnArchitecture=x86-64\nSuggestOnArchitecture=\nSuggestOnMachineTag=amutable.os\n", suggested: true},
		{name: "comments and spaces", text: "# x\n[Feature]\n; SuggestOnMachineTag=amutable.k8s\n  SuggestOnMachineTag = amutable.os  \n", suggested: true},
		{name: "component", section: "Component", text: "[Component]\nSuggestOnMachineTag=amutable.os\n", suggested: true},
	} {
		section := tc.section
		if section == "" {
			section = "Feature"
		}
		suggested, err := definitionSuggested([]byte(tc.text), section, tags)
		if tc.wantErr {
			require.Error(t, err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.suggested, suggested, tc.name)
	}
}

func TestDefinitionEnabled(t *testing.T) {
	for _, tc := range []struct {
		text     string
		def      bool
		expected bool
	}{
		{text: "[Component]\n", def: true, expected: true},
		{text: "[Component]\n", def: false, expected: false},
		{text: "[Component]\nEnabled=false\n", def: true, expected: false},
		{text: "[Component]\nEnabled=On\n", def: false, expected: true},
		{text: "[Component]\nEnabled=1\nEnabled=no\n", def: false, expected: false},
		{text: "[Component]\nEnabled=yes\nEnabled=bogus\n", def: false, expected: true},
		{text: "[Component]\nEnabled=\n", def: true, expected: true},
		{text: "[Other]\nEnabled=yes\n", def: false, expected: false},
	} {
		assert.Equal(t, tc.expected, definitionEnabled([]byte(tc.text), "Component", tc.def), tc.text)
	}
}
