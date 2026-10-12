// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"errors"

	"go.amutable.dev/quarry/internal/systemdcmd"
)

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
