// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package funchelpers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"

	"go.amutable.dev/quarry/internal/third_party/assert"
)

// OnError runs the given closure if there was an error. This is intended to be
// used to shorten defer statements. If an error is returned then the error
// will be joined with Err.
func OnError(Err *error, fn func() error) {
	assert.Assert(Err != nil,
		"OnError must be called with non-nil Err slot") // programmer error
	if *Err != nil && fn != nil {
		if err := fn(); err != nil {
			*Err = errors.Join(*Err, fmt.Errorf("%w (deferred)", err))
		}
	}
}

// CloseOnError closes the given [io.Closer] if there was an error. This is
// intended to be used to shorten defer statements. If an error is returned
// then the error will be joined with Err. [fs.ErrClosed] and [fs.ErrInvalid]
// errors are ignored as they are almost always returned when trying to close
// an already-closed or nil resource.
func CloseOnError(Err *error, closer io.Closer) {
	OnError(Err, func() error {
		if closer != nil {
			err := closer.Close()
			if errors.Is(err, fs.ErrClosed) || errors.Is(err, fs.ErrInvalid) {
				err = nil // no useful error to join
			}
			if err != nil {
				err = fmt.Errorf("error while closing resource: %w", err)
			}
			return err
		}
		return nil
	})
}
