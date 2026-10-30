// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"fmt"
	"net/http"
	"net/url"
)

// Repository represents a TUF repository that [tufclient] fetches.
type Repository struct {
	// Name is the "logical" name of the repository, which uniquely identifies
	// the repository and thus must remain unchanged for the life of the
	// repository. In [tufclient/config]'s TOML configuration, this is
	// generated based on the repos."..." table keys.
	Name string

	// RootTrust indicates the source of trust for the initial root.json of
	// this repository (if the local cache already has a root.json, this source
	// is ignored).
	RootTrust RootTrustSource

	// MetaRootURL is the base URL for the directory containing TUF metadata.
	// Users should prefer [Repository.RootURL], which handles the default when
	// this is nil.
	//
	// TODO: This should be more flexible than a static string, it should be
	// possible for this to be auto-updated based on <meta> tags or other
	// configuration.
	MetaRootURL *url.URL

	// DataRootURL is the base URL for the directory containing target data
	// files. Users should prefer [Repository.DataURL], which handles the
	// default when this is nil.
	//
	// TODO: This should be more flexible than a static string, it should be
	// possible for this to be auto-updated based on <meta> tags or other
	// configuration.
	DataRootURL *url.URL

	// IsTargetPermittedFn is called by users of [Repository] to validate
	// whether a target file is permitted to be provided by this repository.
	// Callers that use this repository to yield target files *must* call this
	// function. A nil function means all targets are allowed, to avoid nil
	// panics use [Repository.IsTargetPermitted].
	IsTargetPermittedFn func(targetPath string) bool

	// Client is the HTTP client used to fetch this repository's files. Users
	// should prefer [Repository.HTTPClient], which handles the default when
	// this is nil.
	Client *http.Client
}

// HTTPClient returns the client to fetch this repository's files with.
func (repo *Repository) HTTPClient() *http.Client {
	if repo.Client == nil {
		return http.DefaultClient
	}
	return repo.Client
}

// IsTargetPermitted indicates whether the given target path is permitted to be
// provided by this repository. Callers that use this repository to yield
// target files *must* call this function.
func (repo *Repository) IsTargetPermitted(targetPath string) bool {
	return repo.IsTargetPermittedFn == nil || repo.IsTargetPermittedFn(targetPath)
}

// RootURL returns [Repository.MetaRootURL] joined with elem (as with
// [url.URL.JoinPath]). If unset, the metadata URL defaults to "https://" +
// [Repository.Name].
func (repo *Repository) RootURL(elems ...string) (*url.URL, error) {
	rootURL := repo.MetaRootURL
	if rootURL == nil {
		u, err := url.Parse("https://" + repo.Name)
		if err != nil {
			return nil, fmt.Errorf("derive meta_root_url from repository name %q: %w", repo.Name, err)
		}
		rootURL = u
	}
	return rootURL.JoinPath(elems...), nil
}

// DataURL returns [Repository.DataRootURL] joined with elem (as with
// [url.URL.JoinPath]). If unset, the targets URL defaults to the "targets"
// subdirectory of [Repository.RootURL].
func (repo *Repository) DataURL(elems ...string) (*url.URL, error) {
	rootURL := repo.DataRootURL
	if rootURL == nil {
		u, err := repo.RootURL("targets")
		if err != nil {
			return nil, fmt.Errorf("derive data_root_url: %w", err)
		}
		rootURL = u
	}
	return rootURL.JoinPath(elems...), nil
}

// RepositoryLike is implemented by types that are a more specialised form of
// [Repository] but can be represented as the generic [Repository].
type RepositoryLike interface {
	AsRepository() *Repository
}

var _ RepositoryLike = &Repository{}

// AsRepository is a no-op for [Repository].
func (repo *Repository) AsRepository() *Repository {
	return repo
}
