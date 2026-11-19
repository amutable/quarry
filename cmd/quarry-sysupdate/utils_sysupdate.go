// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"

	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/systemdcmd"
)

const defaultComponent = "<default>" // copied from `systemd-sysupdate components`

func listComponents(ctx context.Context) ([]string, error) {
	sysupdatePath := systemdcmd.FindCmd("sysupdate")
	// systemd-sysupdate --json=short components
	cmd := exec.CommandContext(ctx,
		sysupdatePath, "--json=short", "components")

	slog.Info(fmt.Sprintf("[exec] %s", cmd))
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("get list of sysupdate components (%s): %w", cmd, err)
	}

	components, err := parseComponents(data)
	if err != nil {
		return nil, fmt.Errorf("(%s) produced invalid json: %w", cmd, err)
	}
	return components, nil
}

// parseComponents returns the components to update from the output of
// "systemd-sysupdate --json=short components".
func parseComponents(data []byte) ([]string, error) {
	type outputType struct {
		Default    bool     `json:"default"`
		Components []string `json:"components"`
		Details    []struct {
			Name    string `json:"name"`
			Enabled *bool  `json:"enabled"`
		} `json:"details"`
	}
	out, err := jsonutils.Parse[outputType](data)
	if err != nil {
		return nil, err
	}
	// "systemd-sysupdate update" fails for a disabled component, and one that
	// is gated on a machine tag stays disabled on every machine without it.
	disabled := map[string]bool{}
	for _, detail := range out.Details {
		if detail.Enabled != nil && !*detail.Enabled {
			disabled[detail.Name] = true
		}
	}
	components := make([]string, 0, len(out.Components)+1)
	for _, component := range out.Components {
		if disabled[component] {
			slog.Info("Skipping disabled sysupdate component.", "component", component)
			continue
		}
		components = append(components, component)
	}
	if out.Default {
		components = append(components, defaultComponent)
	}
	return components, nil
}

func sysupdate(ctx context.Context, component string) error {
	// systemd-sysupdate [--component=$component] update
	args := make([]string, 0, 2)
	if component != defaultComponent {
		args = append(args, "--component="+component)
	}
	args = append(args, "update")
	return systemdcmd.Call(ctx, "sysupdate", args...)
}

// sysupdateAll runs "systemd-sysupdate update" for every component.
func sysupdateAll(ctx context.Context) error {
	components, err := listComponents(ctx)
	if err != nil {
		return fmt.Errorf("get list of sysupdate components: %w", err)
	}
	slog.Info("Spawning 'systemd-sysupdate update'...",
		"components", components)
	var errs []error
	for _, component := range components {
		if err := sysupdate(ctx, component); err != nil {
			slog.Error("sysupdate for component failed.",
				"err", err.Error(), "component", component)
			// FIXME: If we hit an error, continue on because we don't have
			// a decent revert story at the moment.
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("sysupdate failed: %w", err)
	}
	slog.Info("'systemd-sysupdate update' completed.")
	return nil
}

// enableSuggested enables the components and features whose SuggestOn*
// conditions now hold, e.g. after the machine tags changed.
func enableSuggested(ctx context.Context) error {
	if err := systemdcmd.Call(ctx, "systemctl", "start", "systemd-sysupdate-auto-enable.service"); err != nil {
		return fmt.Errorf("failed to trigger systemd-sysupdate-auto-enable service: %w", err)
	}
	return nil
}

func sysupdateRefresh(ctx context.Context) error {
	errs := []error{
		// systemd-confext refresh
		systemdcmd.Call(ctx, "confext", "refresh"),
		// systemd-sysext refresh
		systemdcmd.Call(ctx, "sysext", "refresh"),
		// TODO: detect if we need to do systemd-sysupdate reboot...?
		// TODO: bootctl link
	}
	return errors.Join(errs...)
}
