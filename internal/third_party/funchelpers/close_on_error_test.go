// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package funchelpers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloseOnError(t *testing.T) {
	testFn := func(mainErr error, closer io.Closer) (Err error) {
		defer CloseOnError(&Err, closer)
		return mainErr
	}

	t.Run("NoError", func(t *testing.T) {
		closer := &mockCloser{closeErr: errors.New("close error")}
		err := testFn(nil, closer)
		require.NoError(t, err, "no error returned")
		assert.Zero(t, closer.numClosed, "closer should not be closed on success")
	})

	t.Run("MainErr_NoCloseErr", func(t *testing.T) {
		mainErr := errors.New("main error")
		closer := &mockCloser{}
		err := testFn(mainErr, closer)
		require.Error(t, err, "main error should be returned")
		assert.Equal(t, 1, closer.numClosed, "closer should be closed on error")
		assert.ErrorIs(t, err, mainErr, "main error should be kept") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err, "main error",
			"main error should be unchanged if close succeeds")
	})

	t.Run("MainErr_CloseErr", func(t *testing.T) {
		mainErr := errors.New("main error")
		closeErr := errors.New("close error")
		closer := &mockCloser{closeErr: closeErr}
		err := testFn(mainErr, closer)
		require.Error(t, err, "an error should be returned")
		assert.Equal(t, 1, closer.numClosed, "closer should be closed on error")
		assert.ErrorIs(t, err, mainErr, "main error should be kept")     //nolint:testifylint // assert is fine for error path checks
		assert.ErrorIs(t, err, closeErr, "close error should be joined") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err,
			"main error\nerror while closing resource: close error (deferred)",
			"main error should come first, then the wrapped close error")
	})

	t.Run("MainErr_MultipleCloseErr", func(t *testing.T) {
		mainErr := errors.New("main error")
		closeErr1 := errors.New("first close error")
		closeErr2 := errors.New("second close error")
		closer1 := &mockCloser{closeErr: closeErr1}
		closer2 := &mockCloser{closeErr: closeErr2}

		multiFn := func() (Err error) {
			defer CloseOnError(&Err, closer1)
			defer CloseOnError(&Err, closer2)
			return mainErr
		}

		err := multiFn()
		require.Error(t, err, "an error should be returned")
		assert.Equal(t, 1, closer1.numClosed, "each closer should be closed on error")
		assert.Equal(t, 1, closer2.numClosed, "each closer should be closed on error")
		for _, wantErr := range []error{mainErr, closeErr1, closeErr2} {
			assert.ErrorIs(t, err, wantErr, "main and close errors should all be joined")
		}
	})

	t.Run("MainErr_ErrClosed", func(t *testing.T) {
		mainErr := errors.New("main error")
		closer := &mockCloser{closeErr: fs.ErrClosed}
		err := testFn(mainErr, closer)
		require.Error(t, err, "main error should be returned")
		assert.Equal(t, 1, closer.numClosed, "closer should be closed on error")
		assert.NotErrorIs(t, err, fs.ErrClosed, "fs.ErrClosed should be masked") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err, "main error",
			"main error should be unchanged if close returns fs.ErrClosed")
	})

	t.Run("MainErr_WrappedErrClosed", func(t *testing.T) {
		mainErr := errors.New("main error")
		closer := &mockCloser{closeErr: fmt.Errorf("dummy wrapper: %w", fs.ErrClosed)}
		err := testFn(mainErr, closer)
		require.Error(t, err, "main error should be returned")
		assert.NotErrorIs(t, err, fs.ErrClosed, "wrapped fs.ErrClosed should be masked") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err, "main error",
			"main error should be unchanged if close returns a wrapped fs.ErrClosed")
	})

	t.Run("MainErr_ErrInvalid", func(t *testing.T) {
		mainErr := errors.New("main error")
		closer := &mockCloser{closeErr: fmt.Errorf("dummy wrapper: %w", fs.ErrInvalid)}
		err := testFn(mainErr, closer)
		require.Error(t, err, "main error should be returned")
		assert.NotErrorIs(t, err, fs.ErrInvalid, "fs.ErrInvalid should be masked") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err, "main error",
			"main error should be unchanged if close returns fs.ErrInvalid")
	})

	t.Run("MainErr_NilCloser", func(t *testing.T) {
		mainErr := errors.New("main error")
		err := testFn(mainErr, nil)
		assert.EqualError(t, err, "main error", "nil closer is ignored")
	})

	t.Run("NilErrSlot", func(t *testing.T) {
		assert.Panics(t, func() {
			CloseOnError(nil, &mockCloser{})
		}, "CloseOnError with a nil Err slot is a programmer error")
	})
}

func TestOnError(t *testing.T) {
	testFn := func(mainErr error, fn func() error) (Err error) {
		defer OnError(&Err, fn)
		return mainErr
	}

	t.Run("NoError", func(t *testing.T) {
		called := false
		err := testFn(nil, func() error { called = true; return nil })
		require.NoError(t, err, "no error returned")
		assert.False(t, called, "fn should not be called on success")
	})

	t.Run("MainErr_NoFnErr", func(t *testing.T) {
		mainErr := errors.New("main error")
		called := false
		err := testFn(mainErr, func() error { called = true; return nil })
		assert.True(t, called, "fn should be called on error")
		assert.EqualError(t, err, "main error", "main error should be unchanged if fn succeeds")
	})

	t.Run("MainErr_FnErr", func(t *testing.T) {
		mainErr := errors.New("main error")
		fnErr := errors.New("fn error")
		err := testFn(mainErr, func() error { return fnErr })
		require.Error(t, err, "an error should be returned")
		assert.ErrorIs(t, err, mainErr, "main error should be kept") //nolint:testifylint // assert is fine for error path checks
		assert.ErrorIs(t, err, fnErr, "fn error should be joined")   //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err, "main error\nfn error (deferred)",
			"main error should come first, then the fn error")
	})

	t.Run("MainErr_NilFn", func(t *testing.T) {
		mainErr := errors.New("main error")
		err := testFn(mainErr, nil)
		assert.EqualError(t, err, "main error", "nil fn is ignored")
	})

	t.Run("NilErrSlot", func(t *testing.T) {
		assert.Panics(t, func() {
			OnError(nil, func() error { return nil })
		}, "OnError with a nil Err slot is a programmer error")
	})
}
