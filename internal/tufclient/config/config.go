// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package config provides helpers to parse the TOML configuration format used
// by Quarry clients.
package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"go.amutable.dev/quarry/internal/expand"
	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/serde"
	"go.amutable.dev/quarry/internal/tufext"
)

// rootTrustSources is the set of [tufext.RootTrustSource] implementations that
// can be used for root_trust in config files.
var rootTrustSources = serde.NewUnion[tufext.RootTrustSource](
	serde.UnionOptions{TagField: "type", Name: "root_trust"},
	tufext.TofuRootTrust{},
	tomlBundledRootTrust{},
	tomlInlineRootTrust{},
)

// tomlRootTrust is a wrapper around [tufext.RootTrustSource] that allows for a
// generic parsing of [tufext.RootTrustSource] implementations.
type tomlRootTrust struct {
	tufext.RootTrustSource
}

func (t *tomlRootTrust) UnmarshalTOML(data any) (err error) {
	t.RootTrustSource, err = rootTrustSources.DecodeTOML(data)
	return err
}

// Expand applies the given [expand.Expansions] to the underlying
// [tufext.RootTrustSource].
func (t *tomlRootTrust) Expand(exp *expand.Expansions) error {
	var newRootTrust tufext.RootTrustSource
	switch rootTrust := t.RootTrustSource.(type) {
	case tufext.TofuRootTrust, tomlInlineRootTrust:
		// nothing to expand
		newRootTrust = rootTrust
	case tomlBundledRootTrust:
		path, err := exp.ExpandString(rootTrust.Path)
		if err != nil {
			return fmt.Errorf("cannot %%-expand path %q: %w", rootTrust.Path, err)
		}
		rootTrust.Path = path
		newRootTrust = rootTrust
	default:
		// Programmer error.
		panic(fmt.Sprintf("missing type switch to expand type %T", rootTrust))
	}
	// We need to re-assign here because tomlRootTrust.RootTrustSource is not a
	// pointer (and cannot be).
	t.RootTrustSource = newRootTrust
	return nil
}

// tomlBundledRootTrust indicates that the root.json for this repository should
// be sourced from a particular on-disk file (usually distributed as part of
// the base OS image). *This only makes sense for repositories defined via
// config files*.
//
// TODO: Does this really belong here and not in [tufclient/config]? It is
// quite a local-config concept.
type tomlBundledRootTrust struct {
	Path string `toml:"path"`
	// TODO: UnrecognizedFields?
}

var _ tufext.RootTrustSource = tomlBundledRootTrust{}

func (t tomlBundledRootTrust) Type() string { return "bundled" }

func (t tomlBundledRootTrust) String() string { return t.Type() + ":" + t.Path }

func (t *tomlBundledRootTrust) Validate() error {
	if t.Path == "" {
		return fmt.Errorf("%w %q", serde.ErrMissingField, "path")
	}
	return nil
}

func (tomlBundledRootTrust) IsRemote() bool { return false }

func (t tomlBundledRootTrust) FetchRoot(_ context.Context, _ *tufext.Repository) ([]byte, error) {
	return os.ReadFile(t.Path) //nolint:forbidigo // user-controlled host path
}

// tomlInlineRootTrust is the TOML version of [tufext.InlineRootTrust].
type tomlInlineRootTrust struct {
	RootJSON string `toml:"root.json"`
}

var _ tufext.RootTrustSource = tomlInlineRootTrust{}

func (t tomlInlineRootTrust) Type() string { return "inline" }

func (t tomlInlineRootTrust) String() string { return fmt.Sprintf("%s:%q", t.Type(), t.RootJSON) }

func (tomlInlineRootTrust) IsRemote() bool { return false }

func (t *tomlInlineRootTrust) Validate() error {
	if t.RootJSON == "" {
		return fmt.Errorf("%w %q", serde.ErrMissingField, "root.json")
	}
	return nil
}

func (t tomlInlineRootTrust) FetchRoot(_ context.Context, _ *tufext.Repository) ([]byte, error) {
	return []byte(t.RootJSON), nil
}

// tomlURL provides a wrapper around [url.URL] which can be parsed and
// serialised as a TOML string.
type tomlURL struct {
	url.URL
	rawString string
}

// UnmarshalText is implemented because we need to post-process the URL later.
//
// Also, the Go stdlib does not provide this method because of concerns around
// compatibility, so we need to work around this. <https://go.dev/issue/25705>
func (u *tomlURL) UnmarshalText(data []byte) error {
	u.rawString = string(data)
	return nil
}

// Expand applies the given [expand.Expansions] to a URL.
func (u *tomlURL) Expand(exp *expand.Expansions) error {
	str := u.rawString
	expanded, err := exp.ExpandString(str)
	if err != nil {
		return fmt.Errorf("cannot %%-expand %q: %w", str, err)
	}
	rootURL, err := url.Parse(expanded)
	if err != nil {
		return fmt.Errorf("expanded url %q is invalid: %w", expanded, err)
	}
	u.URL = *rootURL
	return nil
}

// Repository represents a single TUF repository.
type Repository struct {
	// Name is the "logical" name of the repository, which uniquely identifies
	// the repository and thus must remain unchanged for the life of the
	// repository. In the TOML file, it is generated based on the
	// map[string]... key in the top-level configuration.
	Name string `toml:"-"`

	// RawOrderIndex is an integer value that is used to consistently sort
	// repositories when iterating over them. Smaller values sort earlier, the
	// default value (if unset) is 100, and repositories with the same order
	// index are sorted lexicographically.
	RawOrderIndex *int64 `toml:"order_index"`

	// RootTrust indicates the source of trust for the initial root.json of
	// this repository (if the local cache already has a root.json, this source
	// is ignored).
	RootTrust *tomlRootTrust `toml:"root_trust"`

	// MetaRootURL is the base URL for the directory containing TUF metadata.
	// If unset, the default is derived by [tufext.Repository.RootURL].
	MetaRootURL *tomlURL `toml:"meta_root_url"`

	// DataRootURL is the base URL for the directory containing target data
	// files. If unset, the default is derived by [tufext.Repository.DataURL].
	DataRootURL *tomlURL `toml:"data_root_url"`

	// Auth says how requests to the MetaRootURL host authenticate. Nil means
	// no authentication.
	Auth *tomlRepoAuth `toml:"auth"`

	// httpClient is shared by every config that authenticates with the same
	// audience and host (see [identityagent.Client]).
	httpClient *http.Client
}

// HTTPClient returns the client to fetch this repository's files with.
func (repo Repository) HTTPClient() *http.Client {
	if repo.httpClient == nil {
		return http.DefaultClient
	}
	return repo.httpClient
}

const defaultOrderIndex = 100

// OrderIndex returns [RawOrderIndex] or the default order index if it was not
// configured in [Config]. Users should prefer to use this instead of accessing
// [RawOrderIndex] directly.
func (repo Repository) OrderIndex() int64 {
	if r := repo.RawOrderIndex; r != nil {
		return *r
	}
	return defaultOrderIndex
}

var _ tufext.RepositoryLike = Repository{}

// AsRepository maps this configured repository to the more generic
// [tufext.Repository] representation.
func (repo Repository) AsRepository() *tufext.Repository {
	extRepo := &tufext.Repository{
		Name:      repo.Name,
		RootTrust: repo.RootTrust.RootTrustSource,
		Client:    repo.httpClient,
	}
	if u := repo.MetaRootURL; u != nil {
		extRepo.MetaRootURL = generics.Ptr(u.URL)
	}
	if u := repo.DataRootURL; u != nil {
		extRepo.DataRootURL = generics.Ptr(u.URL)
	}
	return extRepo
}

// ConfigVersion is the current version of the configuration file format.
const ConfigVersion = 1

// Config is the top-level configuration object for quarry-client.
type Config struct {
	// Version is the format version of this configuration file.
	Version int64 `toml:"config_version"`

	// CacheDir is a path to the root of the local client cache directory,
	// which stores local copies of the latest repository metadata.
	//
	// The following %-expansions are supported for the cache dir:
	//
	//    %m -- app-specific machine id (in UUID form)
	//    %e[x] -- "systemd-escape --path" the expando %[x]
	//    %NN -- HTTP-style percent encoding (output is unexpanded)
	CacheDir string `toml:"cache_dir"`

	// Repos is the set of repositories configured for the client.
	//
	// The following %-expansions are supported for the repository name:
	//
	//    %m -- app-specific machine id (in UUID form)
	//    %e[x] -- "systemd-escape --path" the expando %[x]
	//    %NN -- HTTP-style percent encoding (output is unexpanded)
	//
	// The following additioanl %-expansions are supported for certain fields
	// within each repository specification:
	//
	//    %R -- repository name
	Repos map[string]*Repository `toml:"repo"`
}

// ErrUnsupportedVersion is returned by [Parse] if the given configuration file
// is newer than the one supported by this version of quarry.
var ErrUnsupportedVersion = errors.New("unsupported config_version")

// Parse parses the TOML form of [Config].
func Parse(rdr io.Reader) (*Config, error) {
	cfg, err := parseToml(rdr)
	if err != nil {
		return nil, err
	}
	if err := cfg.expandAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseToml parses a single configuration fragment. The repository names are
// expanded here so that fragments merge on the final name, the rest of the
// validation and %-expansion is left to [Config.expandAndValidate], as it
// needs the merged configuration.
func parseToml(rdr io.Reader) (*Config, error) {
	var cfg Config
	meta, err := toml.NewDecoder(rdr).Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	// Files with no TOML content at all (blank or comment-only, such as a
	// drop-in masked with a /dev/null symlink in a higher-priority prefix) are
	// exempt from the config_version requirement.
	if len(meta.Keys()) == 0 {
		// Pretend it was an empty config with just config_version.
		return &Config{Version: ConfigVersion}, nil
	}
	// Because drop-ins have different lifecycles and are managed by different
	// entities, every non-empty fragment declares its own version, so each can
	// be upgraded on its own.
	if v := cfg.Version; v != ConfigVersion {
		return nil, fmt.Errorf("%w %d: only version %d is supported", ErrUnsupportedVersion, v, ConfigVersion)
	}
	if unknown := meta.Undecoded(); len(unknown) > 0 {
		return nil, fmt.Errorf("invalid config: unknown toml keys: %v", unknown)
	}

	expander := expand.NewExpansions()
	repos := make(map[string]*Repository, len(cfg.Repos))
	for oldName, repo := range cfg.Repos {
		repo.Name, err = expander.ExpandString(oldName)
		if err != nil {
			return nil, fmt.Errorf("repository %s has invalid %%-expansion: %w", oldName, err)
		}
		if _, ok := repos[repo.Name]; ok {
			return nil, fmt.Errorf("repository %s clobbers existing repository %s", oldName, repo.Name)
		}
		repos[repo.Name] = repo
	}
	cfg.Repos = repos
	return &cfg, nil
}

// DefaultCacheDir is the default value of [Config.CacheDir] if unspecified.
const DefaultCacheDir = "/var/lib/quarry-client/latest-metadata"

// expandAndValidate applies the %-expansions and validates the merged
// configuration.
func (cfg *Config) expandAndValidate() error {
	var err error

	expander := expand.NewExpansions()

	cfg.CacheDir, err = expander.ExpandString(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("config cache_dir an invalid %%-expansion: %w", err)
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = DefaultCacheDir
	}
	if !filepath.IsAbs(cfg.CacheDir) {
		return fmt.Errorf("config cache_dir invalid value: %q must be an absolute path", cfg.CacheDir)
	}

	for _, repo := range cfg.Repos {
		// Add repo name expansion for repo config options URLs.
		subExpander := expander.Clone().WithSource('R', func(_ *[]any) (string, error) {
			return repo.Name, nil
		})

		if repo.RootTrust == nil {
			return fmt.Errorf("repository %s is missing root_trust specification", repo.Name)
		}
		if err := repo.RootTrust.Expand(subExpander); err != nil {
			return fmt.Errorf("repository %s has invalid root_trust value: %w", repo.Name, err)
		}

		// Unset URLs are defaulted by [tufext.Repository].
		if repo.MetaRootURL != nil {
			if err := repo.MetaRootURL.Expand(subExpander); err != nil {
				return fmt.Errorf("repository %s has invalid meta_root_url value: %w", repo.Name, err)
			}
		}
		if repo.DataRootURL != nil {
			if err := repo.DataRootURL.Expand(subExpander); err != nil {
				return fmt.Errorf("repository %s has invalid data_root_url value: %w", repo.Name, err)
			}
		}
		// Verify the [tufext.Repository]-derived URLs are actually valid URLs.
		metaRootURL, err := repo.AsRepository().RootURL()
		if err := errors.Join(err, generics.TakeError(repo.AsRepository().DataURL())); err != nil {
			return fmt.Errorf("repository %s has invalid default url: %w", repo.Name, err)
		}

		if repo.Auth != nil {
			repo.httpClient = repo.Auth.httpClient(metaRootURL.Host)
		}
	}
	return nil
}

// mergeURL is a helper of [merge] to implement the override semantics of URLs
// -- an unset one keeps the old value, an explicit value overrides it, and an
// empty string clears it to trigger the default URL derivation behaviour.
func mergeURL(old, fragment *tomlURL) *tomlURL {
	switch {
	case fragment == nil:
		return old
	case fragment.rawString == "":
		return nil
	default:
		return fragment
	}
}

// merge applies the fragment on top of cfg with systemd drop-in semantics --
// only the settings the fragment specifies are replaced. This lets a drop-in
// override one setting of a repository without repeating the rest of its
// definition.
func (cfg *Config) merge(fragment *Config) error {
	if v := fragment.Version; v != cfg.Version || v != ConfigVersion {
		return fmt.Errorf("%w %d: only version %d (%d) is supported", ErrUnsupportedVersion, v, cfg.Version, ConfigVersion)
	}
	if fragment.CacheDir != "" {
		cfg.CacheDir = fragment.CacheDir
	}
	for name, repo := range fragment.Repos {
		old, ok := cfg.Repos[name]
		if !ok {
			old = &Repository{Name: repo.Name}
			cfg.Repos[name] = old
		}
		if repo.RootTrust != nil {
			old.RootTrust = repo.RootTrust
		}
		if repo.RawOrderIndex != nil {
			old.RawOrderIndex = repo.RawOrderIndex
		}
		old.MetaRootURL = mergeURL(old.MetaRootURL, repo.MetaRootURL)
		old.DataRootURL = mergeURL(old.DataRootURL, repo.DataRootURL)
		if repo.Auth != nil {
			old.Auth = repo.Auth
		}
	}
	return nil
}
