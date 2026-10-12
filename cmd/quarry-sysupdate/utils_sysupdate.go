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

	type outputType struct {
		Default    bool     `json:"default"`
		Components []string `json:"components"`
	}
	out, err := jsonutils.Parse[outputType](data)
	if err != nil {
		return nil, fmt.Errorf("(%s) produced invalid json: %w", cmd, err)
	}
	components := out.Components
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
