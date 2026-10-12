// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/hostnamed"
	"go.amutable.dev/quarry/internal/third_party/assert"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

// Same cap as systemd-sysupdate-update.service (--loop=16).
const maxUpdateIterations = 16

var updateCommand = withExtensionDirFlag(withQuarryUserFlag(withQuarryProxyFlag(&cli.Command{
	Name:  "update",
	Usage: "extended 'systemd-sysupdate update' wrapper",
	Action: func(ctx context.Context, _ *cli.Command) (Err error) {
		exts := xsysupdate.ExtensionSet{
			&xsysupdate.TransferFileExtension{
				OverrideSourcePathURL: ctxQuarryProxyURL(ctx),
			},
		}
		ctx, err := exts.DoInit(ctx)
		if err != nil {
			return fmt.Errorf("init extensions: %w", err)
		}
		slog.Info("Initialised extensions.",
			"extensions", exts.String())
		// Legacy-prefixed targets are only applied after all other targets so
		// we can allow them to be overridden by the non-legacy prefix.
		// TODO: Drop this.
		var (
			applied       = map[string]struct{}{} // uses the stripped name
			legacyTargets []*tufclient.TargetInfo
		)
		applyTarget := func(target *tufclient.TargetInfo) error {
			slog.Info("Extension target found.",
				"target", target.Path, "repository", target.Repo.Name)
			name, legacy, ok := xsysupdate.CutExtensionTargetPrefix(target.Path)
			assert.Assertf(ok, "extension target path %q must have extension prefix", target.Path)
			if _, ok := applied[name]; ok {
				slog.Info("Skipping legacy extension target superseded by new prefix.",
					"target", target.Path, "repository", target.Repo.Name)
				assert.Assertf(!legacy, "extension target path %q must not be applied after legacy paths", target.Path)
				return nil
			}
			if err := exts.DoApplyTarget(ctx, target); err != nil {
				return fmt.Errorf("apply extension target %s: %w", target.Path, err)
			}
			applied[name] = struct{}{}
			slog.Info("Extension target applied.",
				"target", target.Path, "repository", target.Repo.Name)
			return nil
		}
		for target, err := range unprivIterTargetFiles(ctx) {
			if err != nil {
				return fmt.Errorf("error while scanning repos: %w", err)
			}
			if _, legacy, ok := xsysupdate.CutExtensionTargetPrefix(target.Path); !ok {
				// Not an extension target file.
				continue
			} else if legacy {
				// Defer application of legacy-prefixed extensions until we've
				// done everything else so we can skip them if there was a
				// non-legacy version of the same file.
				legacyTargets = append(legacyTargets, target)
				continue
			}
			// Otherwise, apply the extension target file.
			if err := applyTarget(target); err != nil {
				return err
			}
		}
		for _, target := range legacyTargets {
			if err := applyTarget(target); err != nil {
				return err
			}
		}
		if err := exts.DoBeforeUpdate(ctx); err != nil {
			return fmt.Errorf("before update extensions: %w", err)
		}
		slog.Info("Completed pre-sysupdate extensions.")

		// TODO: Should we do runas.User("root") or use run0 here?

		// FIXME FIXME FIXME
		//
		// If these updates error out we are kind of in a messy position.
		// Because we need to call sysupdate multiple times to update each
		// component, it is possible that one component installation fails. We
		// would ideally never want to allow execution with mixed repo states,
		// but fixing this requires having logic for cleanup so we can abort
		// the extension application, clean up the successfully installed
		// components, and force-downgrade to the old versions.

		// A refreshed confext may ship machine-tags.d(5) files, and features gated on
		// those tags were evaluated against the old tags. Loop until the tags
		// settle.
		// TODO: The real signal to stop looping is whether the set of
		// installable features stopped changing (rather than the tags), but
		// there isn't a really nice way for us to detect that so we use tags
		// as a proxy. In future, sysupdate will handle the loop for us (and
		// thus be responsible for this detection) so this can all be removed
		// then.
		tags, err := hostnamed.CurrentTags(ctx, "")
		if err != nil {
			return fmt.Errorf("fetch machine tags before update: %w", err)
		}

		if err := sysupdateAll(ctx); err != nil {
			return err
		}

		if err := exts.Close(); err != nil {
			return fmt.Errorf("post-update extension cleanup: %w", err)
		}

		for iteration := 1; ; iteration++ {
			// Do online-reload of sysexts and confexts.
			slog.Info("Trigger online-reload of new components.")
			if err := sysupdateRefresh(ctx); err != nil {
				return fmt.Errorf("online-reload components: %w", err)
			}

			newTags, err := hostnamed.CurrentTags(ctx, "")
			if err != nil {
				return fmt.Errorf("fetch machine tags after refresh: %w", err)
			}
			if slices.Equal(tags, newTags) {
				return nil
			}
			if iteration >= maxUpdateIterations {
				slog.Warn("Maximum number of update iterations reached, not looking for further updates.",
					"max", maxUpdateIterations, "before", tags, "after", newTags)
				return nil
			}
			slog.Info("Machine tags changed by refresh, running another update pass.",
				"iteration", iteration, "before", tags, "after", newTags)
			tags = newTags
			if err := sysupdateAll(ctx); err != nil {
				return err
			}
		}
	},
})))
