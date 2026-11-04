// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// hardhat is a proof-of-concept helper for managing local quarry repos.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/keystore"
)

var keystoreDriversCommand = &cli.Command{
	Name:  "keystore-drivers",
	Usage: "get a list of supported keystore drivers",
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.BoolFlag{
						Name:    "verbose",
						Usage:   "output more textual information about each driver",
						Aliases: []string{"v"},
					},
				},
				{
					&cli.BoolFlag{
						Name:  "json",
						Usage: "output information about the drivers as a JSON list",
					},
				},
			},
		},
	},
	Action: func(_ context.Context, cmd *cli.Command) error {
		type driverInfo struct {
			Name    string `json:"name"`
			Default bool   `json:"default,omitzero"`
		}

		var allDrivers []driverInfo
		if cmd.Bool("json") {
			allDrivers = make([]driverInfo, 0, 8)
		}

		verbose := cmd.Bool("verbose")
		if verbose {
			mustFprintln(os.Stdout, "Enabled drivers:")
		}
		for driver := range keystore.IterDrivers() {
			isDefault := driver == keystore.DefaultDriver
			if allDrivers != nil {
				allDrivers = append(allDrivers, driverInfo{
					Name:    driver,
					Default: isDefault,
				})
				continue
			}
			var prefix, suffix string
			if verbose {
				prefix = " - "
				if driver == keystore.DefaultDriver {
					suffix = " (default)"
				}
			}
			mustFprintf(os.Stdout, "%s%s%s\n", prefix, driver, suffix)
		}
		if allDrivers != nil {
			return json.NewEncoder(os.Stdout).Encode(allDrivers)
		}
		return nil
	},
}

var app = cliext.WithRefTimeFlag(&cli.Command{
	Name:  "hardhat",
	Usage: "very preliminary quarry operator",
	// TODO: We might want to have a flag to specify a custom context with
	// a deadline? And possibly some SIGINT-based cancellation?
	Commands: []*cli.Command{
		targetsCommand,
		rootCommand,
		keyctlCommand,
		keystoreDriversCommand,
		repoctlCommand,
	},
}, cliext.WithSourceDateEpoch())

func Main(args []string) error {
	return app.Run(context.Background(), args)
}

func main() {
	if err := Main(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
