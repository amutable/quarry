// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/pprint"
	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
)

var repoctlCommand = withRepoFlag(withKeystoreFlag(&cli.Command{
	Name:  "repoctl",
	Usage: "manage quarry repository",
	Commands: []*cli.Command{
		repoctlInitCommand,
		repoctlRefreshCommand,
		repoctlSnapshotCommand,
		// TODO: repoctlRotateKeysCommand,
		// TODO: repoctlInfoCommand, // ??
	},
}))

var repoctlInitCommand = &cli.Command{
	Name:  "init",
	Usage: "create a new quarry repository",
	// --keys takes a comma-sparated list as a single map value, which
	// urfave/cli doesn't allow by default so disable comma splitting (sadly
	// this is a global option).
	DisableSliceFlagSeparator: true,
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				// in-band root.json generation
				generateRootFlags,
				// use an out-of-band root.json
				{
					&cli.StringFlag{
						Name:      "root",
						Usage:     "use a pre-signed root.json as the repo root",
						TakesFile: true,
					},
				},
			},
		},
	},
	Before: checkGenerateRootFlags,
	Action: func(ctx context.Context, cmd *cli.Command) (Err error) {
		repo := ctxRepo(ctx)
		store := ctxKeystore(ctx)

		var (
			signedRoot    *tufext.SignedRoot
			newRoleKeyIDs map[string][]keystore.KeyID
		)
		defer func() {
			// Make sure to clean up any generated keys in case of an error.
			if Err != nil {
				// TODO: We want to force the removal even if the context was
				// cancelled, but we might also want to have some kind of
				// deadline here just in case? Or maybe we should use
				// context.WithoutCancel?
				ctx := context.TODO()
				for _, keyIDs := range newRoleKeyIDs {
					for _, keyID := range keyIDs {
						_ = store.UnlinkKey(ctx, keyID)
					}
				}
				newRoleKeyIDs = nil
			}
		}()

		if cmd.IsSet("root") {
			rootData, err := os.ReadFile(cmd.String("root")) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return err
			}
			if err := json.Unmarshal(rootData, &signedRoot); err != nil {
				return fmt.Errorf("invalid root.json: %w", err)
			}
		} else {
			var err error
			signedRoot, newRoleKeyIDs, err = generateRoot(ctx, cmd)
			if err != nil {
				return err
			}
		}

		// Create an initial transaction to use.
		initTxn := tufrepo.InitTxn(signedRoot)
		initTxn.RefTime, _ = ctxext.RefTime(ctx)
		// TODO: Make the initial transaction configurable...

		// TODO: Do we actually want to Sign this...?

		commitNewKeys, err := initTxn.Sign(ctx, store)
		if err != nil {
			return fmt.Errorf("failed to sign initial transaction: %w", err)
		}
		if len(commitNewKeys) > 0 {
			// Programmer error.
			return fmt.Errorf("Transaction.Sign generated extraneous keys: %v", commitNewKeys)
		}
		timestamp, err := repo.TxnCommit(ctx, initTxn)
		if err != nil {
			return fmt.Errorf("failed to commit the initial transaction to the repo: %w", err)
		}

		wtr := os.Stdout
		if len(newRoleKeyIDs) > 0 {
			mustFprintln(wtr, "Generated keys:")
			for roleName, keyIDs := range newRoleKeyIDs {
				mustFprintf(wtr, "\t%s:\n", roleName)
				for _, keyID := range keyIDs {
					mustFprintf(wtr, "\t - %s\n", keyID)
				}
			}
		}
		mustFprintln(wtr, "root.json:")
		pprint.ToJSON(wtr, "\t", "\t", signedRoot)
		mustFprintln(wtr, "timestamp.json:")
		pprint.ToJSON(wtr, "\t", "\t", timestamp)
		return nil
	},
}

var repoctlRefreshCommand = withTxExpireAfterFlag(&cli.Command{
	Name:  "refresh",
	Usage: "refresh the repo's timestamp.json",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "role",
			Aliases: []string{"r"},
			Usage:   "set of roles to refresh",
			Value:   []string{"timestamp"},
		},
	},
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.DurationFlag{
						Name:  "refresh-if-expires-in",
						Value: 6 * time.Hour,
						Usage: "how far away from expiry should the timestamp.json be for it to be refreshed?",
					},
				},
				{
					&cli.BoolFlag{
						Name:    "force-refresh",
						Aliases: []string{"f", "force"},
						Usage:   "always refresh timestamp.json",
					},
				},
			},
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		repo := ctxRepo(ctx)
		store := ctxKeystore(ctx)

		tx, err := repo.TxnStart(ctx)
		if err != nil {
			return fmt.Errorf("start transaction: %w", err)
		}
		tx.RefTime, _ = ctxext.RefTime(ctx)

		if err := applyTxExpireAfter(ctx, tx); err != nil {
			return err
		}

		var refreshWindow *time.Duration
		if !cmd.Bool("force-refresh") {
			v := cmd.Duration("refresh-if-expires-in")
			refreshWindow = &v
		}

		wtr := os.Stdout
		for _, roleName := range cmd.StringSlice("role") {
			if err := tx.BumpExpiry(ctx, roleName, func(oldExpiry time.Time, _ any) (*time.Time, error) {
				deadline := tx.RefTime.Add(-time.Second)
				if refreshWindow != nil {
					deadline = oldExpiry.Add(-*refreshWindow)
				}
				if tx.RefTime.Before(deadline) {
					mustFprintf(wtr, "Repository %s.json is not due for a refresh until %s (expiry is %s).\n",
						roleName, deadline.Format(time.RFC3339), oldExpiry.Format(time.RFC3339))
					return nil, nil //nolint:nilnil // nil indicates no change needed
				}
				// Use the transaction's configured expiry so that Sign's own
				// expiry bumps (which recompute from the same value) agree
				// with ours rather than clobbering it.
				expireAfter := tx.ExpiresAfter(roleName)
				newExpiry := tx.RefTime.Add(expireAfter)
				mustFprintf(wtr, "Repository %s.json updated to expire at %s (duration is %s).\n",
					roleName, newExpiry.Format(time.RFC3339), expireAfter)
				return &newExpiry, nil
			}); err != nil {
				return fmt.Errorf("error while bumping role %s expiry: %w", roleName, err)
			}
		}

		newTimestampKeyIDs, err := tx.Sign(ctx, store)
		if err != nil {
			return fmt.Errorf("could not sign transaction: %w", err)
		}

		// TODO: Make committing this to the repo optional.
		timestamp, err := repo.TxnCommit(ctx, tx)
		if err != nil {
			return fmt.Errorf("failed to commit the transaction to the repo: %w", err)
		}

		if len(newTimestampKeyIDs) > 0 {
			mustFprintln(wtr, "Rotated timestamp keys:")
			for _, keyID := range newTimestampKeyIDs {
				mustFprintf(wtr, " - %s\n", keyID)
			}
		}

		mustFprintln(wtr, "timestamp.json:")
		pprint.ToJSON(wtr, "\t", "\t", timestamp)
		return nil
	},
})

var repoctlSnapshotCommand = withTxExpireAfterFlag(&cli.Command{
	Name:  "snapshot",
	Usage: "update the repo's snapshot.json",
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "targets",
			UsageText: "<role1>=<path1> [<role2>=<path2>]...",
			Min:       1,
			Max:       -1,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		repo := ctxRepo(ctx)
		store := ctxKeystore(ctx)

		tx, err := repo.TxnStart(ctx)
		if err != nil {
			return fmt.Errorf("start transaction: %w", err)
		}
		tx.RefTime, _ = ctxext.RefTime(ctx)

		if err := applyTxExpireAfter(ctx, tx); err != nil {
			return err
		}

		for _, targets := range cmd.StringArgs("targets") {
			roleName, path, ok := strings.Cut(targets, "=")
			if !ok {
				return fmt.Errorf("%q is an invalid spec: must in the form 'role=path'", targets)
			}
			data, err := os.ReadFile(path) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("cannot read role %s data from path %s: %w", roleName, path, err)
			}
			if err := tx.UpdateRoleData(roleName, data); err != nil {
				return fmt.Errorf("failed to update role %s data in transaction: %w", roleName, err)
			}
		}

		newTimestampKeyIDs, err := tx.Sign(ctx, store)
		if err != nil {
			return fmt.Errorf("could not sign transaction: %w", err)
		}

		// TODO: Make committing this to the repo optional.
		timestamp, err := repo.TxnCommit(ctx, tx)
		if err != nil {
			return fmt.Errorf("failed to commit the transaction to the repo: %w", err)
		}

		wtr := os.Stdout
		if len(newTimestampKeyIDs) > 0 {
			mustFprintln(wtr, "Rotated timestamp keys:")
			for _, keyID := range newTimestampKeyIDs {
				mustFprintf(wtr, " - %s\n", keyID)
			}
		}

		mustFprintln(wtr, "timestamp.json:")
		pprint.ToJSON(wtr, "\t", "\t", timestamp)
		return nil
	},
})
