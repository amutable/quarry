// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package cliext

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/uapi6conf"
)

type ctxKey string

const configCtxKey ctxKey = "--config"

// WithConfigFlag adds the --config flag to [cli.Command].
func WithConfigFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name: "config",
			Usage: fmt.Sprintf(
				// Split this very long help message over a few lines...
				"path to the quarry-client configuration file\n(default: config.toml in the standard search paths:\n\t%v\nwith \".d\"-style drop-ins)",
				uapi6conf.Standard("", "quarry-client"), // TODO: Should we pass this to config.LoadPath()?
			),
			TakesFile: true,
			Sources:   cli.EnvVars("QUARRY_CLIENT_CONFIG"),
		},
		&cli.StringFlag{
			Name:      "cache-dir",
			Usage:     "local cache directory for TUF metadata",
			TakesFile: true,
			Value:     config.DefaultCacheDir,
			Sources:   cli.EnvVars("QUARRY_CLIENT_CACHEDIR"),
		})

	cmd.Before = WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		cfg, err := LoadConfig(cmd)
		if err != nil {
			return nil, err
		}
		return WithCtxConfig(ctx, cfg), nil
	})

	return cmd
}

// LoadConfig reads the configuration selected by the flags from
// [WithConfigFlag]. Most users want [CtxConfig], which is the configuration
// as it was when the command started. This is for commands that can outlive
// a change to the configuration files.
func LoadConfig(cmd *cli.Command) (*config.Config, error) {
	var (
		cfg *config.Config
		err error
	)
	if cfgPath := cmd.String("config"); cfgPath != "" {
		cfg, err = config.LoadPath(cfgPath)
	} else {
		cfg, err = config.Load()
	}
	if err != nil {
		return nil, err
	}
	// Replace the in-memory config option with --cache-dir if the user
	// explicitly requested it.
	if cmd.IsSet("cache-dir") {
		cfg.CacheDir = cmd.String("cache-dir")
	}
	return cfg, nil
}

// CtxConfig returns the parsed --config flag value for [cli.Command]s
// configured using [WithConfigFlag].
func CtxConfig(ctx context.Context) *config.Config {
	return ctxext.Value[*config.Config](ctx, configCtxKey)
}

// WithCtxConfig manually sets the configuration that would be parsed with
// [WithConfigFlag]. This is primarily intended for use by tests.
func WithCtxConfig(ctx context.Context, cfg *config.Config) context.Context {
	return context.WithValue(ctx, configCtxKey, cfg)
}
