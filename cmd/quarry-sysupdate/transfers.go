// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"go.amutable.dev/quarry/internal/systemdcmd"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

// sysupdateRunArgs returns the systemd-run arguments that run systemd-sysupdate
// with the given arguments in a transient service that sees the staged
// definitions through read-only bind mounts (see
// [xsysupdate.StagedTransfers.BindPaths]).
func sysupdateRunArgs(bindPaths []string, args ...string) []string {
	runArgs := []string{"--collect", "--pipe"}
	for _, bind := range bindPaths {
		runArgs = append(runArgs, "-p", "BindReadOnlyPaths="+bind)
	}
	runArgs = append(runArgs, systemdcmd.FindCmd("sysupdate"))
	return append(runArgs, args...)
}

// stageAndUpdate stages the definitions of every component with transfer
// definitions for the given machine tags and updates them in one
// systemd-sysupdate run (see [updateStaged]).
func stageAndUpdate(ctx context.Context, ext *xsysupdate.TransferFileExtension, machineTags []string) error {
	// Only components with transfer definitions are updated. A component
	// without any is not managed by us.
	transfers := ext.Transfers()
	if len(transfers) == 0 {
		slog.Info("No transfer definitions found -- nothing to update.")
		return nil
	}

	var errs []error
	components := slices.Sorted(maps.Keys(transfers))
	slog.Info("Staging transfer definitions for 'systemd-sysupdate update'...",
		"components", len(components), "machineTags", machineTags)
	var staged []*xsysupdate.StagedTransfers
	for _, component := range components {
		componentDir := transferlayout.ComponentDir(component) // for log messages
		sc, err := ext.Stage(ctx, transfers[component], xsysupdate.StageOptions{MachineTags: machineTags})
		if err != nil {
			slog.Error("Staging the component's transfer definitions failed.",
				"err", err.Error(), "component", componentDir)
			// FIXME: If we hit an error, continue on because we don't have
			// a decent revert story at the moment.
			errs = append(errs, err)
			continue
		}
		if sc == nil {
			continue // not enabled on this machine
		}
		slog.Info("Staged transfer definitions.",
			"component", componentDir, "path", sc.Path(), "enabledFeatures", sc.EnabledFeatures)
		staged = append(staged, sc)
	}
	if len(staged) > 0 {
		// There is one run for everything staged. The hook units merge
		// the extensions and relink the UKI after each component.
		// TODO: Make sure we control this better to only do it at the end
		// after everything was successfully updated.
		slog.Info("Spawning 'systemd-sysupdate update' with the staged transfer definitions...",
			"components", len(staged))
		if err := updateStaged(ctx, staged); err != nil {
			slog.Error("sysupdate failed.", "err", err.Error())
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("sysupdate failed: %w", err)
	}
	slog.Info("'systemd-sysupdate update' completed.")
	return nil
}

// updateStaged runs systemd-sysupdate once over all staged components. Their
// definitions are bind-mounted into a transient service, where
// "--component-all update" updates the default component and each enabled
// component.
func updateStaged(ctx context.Context, staged []*xsysupdate.StagedTransfers) (Err error) {
	var bindPaths []string
	for _, sc := range staged {
		bindPaths = append(bindPaths, sc.BindPaths()...)
	}
	defer func() {
		failed := Err != nil
		for _, sc := range staged {
			if failed {
				// Keep the staged definitions for debugging. They are pruned
				// at the start of the next run.
				slog.Warn("Keeping staged transfer definitions of failed update.",
					"component", transferlayout.ComponentDir(sc.Component), "path", sc.Path())
				Err = errors.Join(Err, sc.Close())
			} else {
				Err = errors.Join(Err, sc.Remove())
			}
		}
	}()

	// TODO: Pass --cleanup=yes to garbage-collect files that are no longer
	// covered by this component's transfers, and also explicitly run
	// "systemd-sysupdate -C <c> cleanup" for components that are no longer
	// enabled (or have no transfer definitions anymore) on the bare host,
	// which deletes everything recorded in their installdb. Both are blocked
	// on the sysupdate garbage collector taking "bootctl link" references
	// into account, as otherwise it would remove files still referenced from
	// the ESP.
	//
	// systemd-run --collect --pipe -p BindReadOnlyPaths=... systemd-sysupdate --component-all update
	return systemdcmd.Call(ctx, "run", sysupdateRunArgs(bindPaths, "--component-all", "update")...)
}
