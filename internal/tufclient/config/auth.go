// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package config

import (
	"fmt"
	"net/http"

	"go.amutable.dev/quarry/internal/identityagent"
	"go.amutable.dev/quarry/internal/serde"
)

// repoAuth is how requests to a repository's MetaRootURL host authenticate.
type repoAuth interface {
	serde.Typed

	// httpClient returns the client that authenticates requests to host.
	httpClient(host string) *http.Client
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

// tomlWimseAuth signs each request as this machine with a WIT for Audience
// from the identity agent at Varlink (see [identityagent.Transport]).
type tomlWimseAuth struct {
	Audience string `toml:"audience"`
	Varlink  string `toml:"varlink"`
}

func (tomlWimseAuth) Type() string { return "wimse" }

func (t *tomlWimseAuth) Validate() error {
	if t.Audience == "" {
		return fmt.Errorf("%w %q", serde.ErrMissingField, "audience")
	}
	return nil
}

func (t tomlWimseAuth) httpClient(host string) *http.Client {
	return identityagent.Client(t.Audience, host, t.Varlink)
}
