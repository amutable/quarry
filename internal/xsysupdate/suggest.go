// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
)

// suggestOnMachineTag is the only SuggestOn*= condition that quarry evaluates.
const suggestOnMachineTag = "SuggestOnMachineTag"

// assignment is one "Key=Value" line of a definition.
type assignment struct{ key, value string }

// sectionAssignments returns the assignments in the [section] sections of a
// systemd-style definition in file order. Unlike [loadINI], it keeps empty
// assignments because they reset a list.
func sectionAssignments(data []byte, section string) []assignment {
	var (
		assignments []assignment
		inSection   bool
	)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[':
			inSection = line == "["+section+"]"
		case inSection:
			if key, value, ok := strings.Cut(line, "="); ok {
				assignments = append(assignments, assignment{key: strings.TrimSpace(key), value: strings.TrimSpace(value)})
			}
		}
	}
	return assignments
}

// parseBoolean parses a boolean value the way systemd does. ok is false if
// the value is no boolean.
func parseBoolean(value string) (b, ok bool) {
	switch strings.ToLower(value) {
	case "1", "yes", "y", "true", "t", "on":
		return true, true
	case "0", "no", "n", "false", "f", "off":
		return false, true
	}
	return false, false
}

// definitionEnabled returns the Enabled= setting of the [section] of a
// component or feature definition. It is def if the definition sets none. As
// in systemd, the last valid assignment wins and invalid ones are ignored.
func definitionEnabled(data []byte, section string, def bool) bool {
	enabled := def
	for _, a := range sectionAssignments(data, section) {
		if a.key != "Enabled" {
			continue
		}
		if b, ok := parseBoolean(a.value); ok {
			enabled = b
		}
	}
	return enabled
}

// definitionSuggested returns whether the [section] of a component or feature
// definition is suggested for a machine with the given tags. The
// SuggestOnMachineTag= conditions are evaluated like ConditionMachineTag=
// (see [machineTagConditionsHold]). Without any condition the definition is
// not suggested. quarry does not evaluate Suggest= or the other SuggestOn*=
// conditions. Suggest= is ignored, and an error is returned for a definition
// that uses another SuggestOn*= condition.
func definitionSuggested(data []byte, section string, machineTags []string) (bool, error) {
	conditions := map[string][]string{}
	for _, a := range sectionAssignments(data, section) {
		if !strings.HasPrefix(a.key, "SuggestOn") {
			continue
		}
		// An empty value resets the conditions of this key.
		if a.value == "" {
			delete(conditions, a.key)
		} else {
			conditions[a.key] = append(conditions[a.key], a.value)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(conditions)) {
		if key != suggestOnMachineTag {
			return false, fmt.Errorf("quarry does not evaluate %s=", key)
		}
	}
	values := conditions[suggestOnMachineTag]
	if len(values) == 0 {
		return false, nil
	}
	return machineTagConditionsHold(values, machineTags), nil
}

// machineTagConditionsHold evaluates the values of SuggestOnMachineTag= as a
// systemd condition list of ConditionMachineTag=. A condition holds if its
// shell glob pattern matches any of the machine tags ("key" or "key=value").
// A leading "!" negates the condition. A leading "|" makes it a triggering
// condition. The list holds if all non-triggering conditions hold and, if
// there are triggering conditions, at least one of them holds.
func machineTagConditionsHold(values, machineTags []string) bool {
	const whitespace = " \t\n\r"
	hasTrigger, triggered := false, false
	for _, value := range values {
		trigger := strings.HasPrefix(value, "|")
		if trigger {
			value = strings.TrimLeft(value[1:], whitespace)
		}
		negate := strings.HasPrefix(value, "!")
		if negate {
			value = strings.TrimLeft(value[1:], whitespace)
		}
		// Tags contain no "/", so path.Match behaves like fnmatch(3) with no
		// flags, as systemd uses it. An invalid pattern matches nothing.
		matched := slices.ContainsFunc(machineTags, func(tag string) bool {
			ok, err := path.Match(value, tag)
			return err == nil && ok
		})
		result := matched != negate
		switch {
		case trigger:
			hasTrigger = true
			triggered = triggered || result
		case !result:
			return false
		}
	}
	return !hasTrigger || triggered
}
