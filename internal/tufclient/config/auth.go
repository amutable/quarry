// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package config

import (
	"fmt"
	"net/http"

	"go.amutable.dev/quarry/internal/serde"
	"go.amutable.dev/quarry/internal/wimseagent"
)

// repoAuth is how requests for a repository's files authenticate.
type repoAuth interface {
	serde.Typed

	// httpClient returns the client that authenticates the repository's
	// requests.
	httpClient() (*http.Client, error)
}

// repoAuths is the set of [repoAuth] implementations that can be used for auth
// in config files.
var repoAuths = serde.NewUnion[repoAuth](
	serde.UnionOptions{TagField: "type", Name: "auth"},
	tomlWimseAuth{},
)

// tomlRepoAuth is a wrapper around [repoAuth] that allows for a generic
// parsing of [repoAuth] implementations.
type tomlRepoAuth struct {
	repoAuth
}

func (t *tomlRepoAuth) UnmarshalTOML(data any) (err error) {
	t.repoAuth, err = repoAuths.DecodeTOML(data)
	return err
}

// tomlWimseAuth signs each request as this machine with a WIT for
// WitAudience from the identity agent at Varlink, and a WIMSE signature for
// WimseAudience (see [wimseagent.Transport]).
//
// TODO: We probably need to support expandos for these options.
type tomlWimseAuth struct {
	WitAudience   string `toml:"wit_audience"`
	WimseAudience string `toml:"wimse_audience"`
	Varlink       string `toml:"varlink"`
}

func (tomlWimseAuth) Type() string { return "wimse" }

func (t *tomlWimseAuth) Validate() error {
	if t.WitAudience == "" {
		return fmt.Errorf("%w %q", serde.ErrMissingField, "wit_audience")
	}
	return nil
}

func (t tomlWimseAuth) httpClient() (*http.Client, error) {
	cred, err := wimseagent.NewCred(wimseagent.ID{WitAudience: t.WitAudience, Provider: t.Varlink}, nil)
	if err != nil {
		return nil, fmt.Errorf("create WIT credential: %w", err)
	}
	return wimseagent.Client(cred, t.WimseAudience), nil
}
