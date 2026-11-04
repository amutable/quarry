// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package cliext

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/ctxext"
)

func runRefTime(t *testing.T, args []string, opts ...RefTimeOption) (time.Time, bool, error) {
	t.Helper()
	var (
		refTime time.Time
		ok      bool
	)
	cmd := WithRefTimeFlag(&cli.Command{
		Name: "test",
		Action: func(ctx context.Context, _ *cli.Command) error {
			refTime, ok = ctxext.RefTime(ctx)
			return nil
		},
	}, opts...)
	err := cmd.Run(context.Background(), append([]string{"test"}, args...))
	return refTime, ok, err
}

func TestRefTimeFlag(t *testing.T) {
	for _, test := range []struct {
		name     string
		epoch    string
		args     []string
		opts     []RefTimeOption
		wantTime time.Time
		wantOk   bool
		wantErr  bool
	}{
		{name: "Unset"},
		{
			name:     "Explicit",
			args:     []string{"--ref-time=2020-01-02T03:04:05Z"},
			wantTime: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
			wantOk:   true,
		},
		{name: "EpochIgnoredWithoutOpt", epoch: "1600000000"},
		{
			name:     "Epoch",
			epoch:    "1600000000",
			opts:     []RefTimeOption{WithSourceDateEpoch()},
			wantTime: time.Unix(1600000000, 0).UTC(),
			wantOk:   true,
		},
		{
			name:     "EpochZero",
			epoch:    "0",
			opts:     []RefTimeOption{WithSourceDateEpoch()},
			wantTime: time.Unix(0, 0).UTC(),
			wantOk:   true,
		},
		{name: "EpochEmpty", epoch: "", opts: []RefTimeOption{WithSourceDateEpoch()}},
		{
			name:     "ExplicitOverridesEpoch",
			epoch:    "1600000000",
			args:     []string{"--ref-time=2020-01-02T03:04:05Z"},
			opts:     []RefTimeOption{WithSourceDateEpoch()},
			wantTime: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
			wantOk:   true,
		},
		{
			name:     "ExplicitOverridesBadEpoch",
			epoch:    "garbage",
			args:     []string{"--ref-time=2020-01-02"},
			opts:     []RefTimeOption{WithSourceDateEpoch()},
			wantTime: time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
			wantOk:   true,
		},
		{name: "EpochGarbage", epoch: "garbage", opts: []RefTimeOption{WithSourceDateEpoch()}, wantErr: true},
		{name: "EpochNegative", epoch: "-1", opts: []RefTimeOption{WithSourceDateEpoch()}, wantErr: true},
		{name: "EpochFractional", epoch: "1600000000.5", opts: []RefTimeOption{WithSourceDateEpoch()}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", test.epoch)

			refTime, ok, err := runRefTime(t, test.args, test.opts...)
			if test.wantErr {
				require.ErrorContains(t, err, "SOURCE_DATE_EPOCH")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantOk, ok, "ref time set")
			if test.wantOk {
				assert.Equal(t, test.wantTime, refTime, "ref time")
			}
		})
	}
}
