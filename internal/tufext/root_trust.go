// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// TODO: Make these more configurable.
const (
	MaxRootBytes = 512_000 // 512k
)

// RootTrustSource represents a source of trust for the initial state of a
// client's locally cached root.json. Implementations are parsed from formats
// like JSON and TOML (see internal/serde).
type RootTrustSource interface {
	// Type returns the self-defining string used when generically parsing
	// [RootTrustSource] from formats like JSON and TOML.
	Type() string
	fmt.Stringer

	// IsRemote indicates whether the root source is to be fetched from a
	// remote resource. Callers can use this as a hint for whether some errors
	// from [FetchRoot] should be skipped.
	IsRemote() bool

	// FetchRoot fetches the initial root.json for the given [Repository],
	// based on the internal policy of this [RootTrustSource].
	FetchRoot(ctx context.Context, repo *Repository) ([]byte, error)
}

// TofuRootTrust fetches the root.json directly from the repository with a
// trust-on-first-use policy. *This is inherently insecure*.
type TofuRootTrust struct {
	// TODO: UnrecognizedFields?
}

var _ RootTrustSource = TofuRootTrust{}

// Type returns the self-defining string used when generically parsing
// [RootTrustSource] from formats like JSON and TOML.
func (TofuRootTrust) Type() string { return "insecure-tofu" }

func (t TofuRootTrust) String() string { return t.Type() }

// IsRemote indicates whether the root source is to be fetched from a remote
// resource. It is always true for [TofuRootTrust].
func (TofuRootTrust) IsRemote() bool { return true }

// FetchRoot for [TofuRootTrust] fetches the initial root.json directly from
// the given repository without any validation.
func (TofuRootTrust) FetchRoot(ctx context.Context, repo *Repository) (_ []byte, Err error) {
	// The updater will bump the root.json to the latest version afterwards.
	rootURL, err := repo.RootURL("1.root.json")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rootURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	res, err := repo.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rootURL, err)
	}
	if res.StatusCode >= 300 {
		if res.Body != nil {
			_ = res.Body.Close()
		}
		err := fmt.Errorf("fetch %s failed with status code %.3d", rootURL, res.StatusCode)
		if res.StatusCode == http.StatusNotFound {
			// Emulate ENOENT for 404.
			err = fmt.Errorf("%w: %w", err, fs.ErrNotExist)
		}
		return nil, err
	}
	rdr := http.MaxBytesReader(nil, res.Body, MaxRootBytes) // use same max as client
	defer funchelpers.VerifyClose(&Err, rdr)

	return io.ReadAll(rdr)
}

// InlineRootTrust is used for cases where it makes sense to embed the
// root.json directly inside some structure or configuration rather than
// referencing some external value.
type InlineRootTrust struct {
	RootJSON json.RawMessage `json:"root.json"`
	// TODO: UnrecognizedFields?
}

var _ RootTrustSource = InlineRootTrust{}

// Type returns the self-defining string used when generically parsing
// [RootTrustSource] from formats like JSON and TOML.
func (t InlineRootTrust) Type() string { return "inline" }

func (t InlineRootTrust) String() string { return fmt.Sprintf("%s:%q", t.Type(), t.RootJSON) }

// IsRemote indicates whether the root source is to be fetched from a remote
// resource. It is always false for [InlineRootTrust].
func (InlineRootTrust) IsRemote() bool { return false }

// FetchRoot for [InlineRootTrust] returns the inlined root.json data and
// cannot return an error.
func (t InlineRootTrust) FetchRoot(_ context.Context, _ *Repository) ([]byte, error) {
	return []byte(t.RootJSON), nil
}
