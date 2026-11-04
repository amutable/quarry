// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package cliext

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/ctxext"
)

// RefTimeOption configures the behaviour of [WithRefTimeFlag].
type RefTimeOption func(*refTimeConfig)

type refTimeConfig struct {
	sourceDateEpoch bool
}

// WithSourceDateEpoch makes [WithRefTimeFlag] fall back to the value of
// $SOURCE_DATE_EPOCH if --ref-time was not explicitly set.
//
// See <https://reproducible-builds.org/specs/source-date-epoch/>.
func WithSourceDateEpoch() RefTimeOption {
	return func(cfg *refTimeConfig) { cfg.sourceDateEpoch = true }
}

// sourceDateEpoch parses $SOURCE_DATE_EPOCH or a zero [time.Time] if it was
// not present or empty.
func sourceDateEpoch() (time.Time, error) {
	epochStr := os.Getenv("SOURCE_DATE_EPOCH")
	if epochStr == "" {
		return time.Time{}, nil
	}
	epoch, err := strconv.ParseUint(epochStr, 10, 63)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid $SOURCE_DATE_EPOCH value %q: %w", epochStr, err)
	}
	return time.Unix(int64(epoch), 0).UTC(), nil
}

// WithRefTimeFlag adds the --ref-time flag to [cli.Command].
func WithRefTimeFlag(cmd *cli.Command, opts ...RefTimeOption) *cli.Command {
	var cfg refTimeConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	usage := "used instead of the wallclock time for all operations"
	if cfg.sourceDateEpoch {
		usage += " (defaults to $SOURCE_DATE_EPOCH if set)"
	}

	cmd.Flags = append(cmd.Flags,
		&cli.TimestampFlag{
			Name:  "ref-time",
			Usage: usage,
			Config: cli.TimestampConfig{
				Layouts: []string{
					time.RFC3339,
					time.RFC3339Nano,
					time.DateOnly,
					// TODO: It would be nice to be able to pass a Unix epoch.
				},
			},
		})

	cmd.Before = WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		refTime := cmd.Timestamp("ref-time").UTC()
		if cfg.sourceDateEpoch && !cmd.IsSet("ref-time") {
			var err error
			refTime, err = sourceDateEpoch()
			if err != nil {
				return ctx, err
			}
		}
		if !refTime.IsZero() {
			ctx = context.WithValue(ctx, ctxext.RefTimeCtxKey, refTime)
		}
		return ctx, nil
	})

	return cmd
}
