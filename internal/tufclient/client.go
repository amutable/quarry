// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package tufclient provides helpers for creating a set TUF clients to fetch
// data from Quarry repositories.
package tufclient

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"cyphar.com/go-pathrs"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	tuftrustedmetadata "github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	tufupdater "github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/httputils"
	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
)

// ErrSkippableRepo is returned as part of a wrapped error by [RepoClient] if
// the repository could not be loaded but the error should not necessarily be
// seen as a fatal error condition (i.e., the repository has never been seen
// before and so may not be created yet). [NewClient] skips such repositories,
// though [Client.WithRepos] will return the errors if said repositories are
// requested explicitly.
var ErrSkippableRepo = errors.New("skippable repository error")

// RepoClient constructs a [tufupdater.Updater] for a single TUF repository,
// defined by a [tufext.Repository] configuration.
func RepoClient(ctx context.Context, cacheDir *pathrs.Root, repoLike tufext.RepositoryLike) (_ *tufupdater.Updater, Err error) {
	repo := repoLike.AsRepository()

	metaRootURL, err := repo.RootURL()
	if err != nil {
		return nil, fmt.Errorf("invalid repository definition: %w", err)
	}
	dataRootURL, err := repo.DataURL()
	if err != nil {
		return nil, fmt.Errorf("invalid repository definition: %w", err)
	}

	repoCacheDirHandle, err := cacheDir.MkdirAll(repo.Name, 0o755)
	if err != nil {
		return nil, fmt.Errorf("open repo cache dir: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, repoCacheDirHandle)

	repoCacheDir, err := pathrs.RootFromFile(repoCacheDirHandle.IntoFile())
	if err != nil {
		return nil, fmt.Errorf("convert repo cache dir to root: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, repoCacheDir)

	rootFile, err := repoCacheDir.OpenFile("root.json", unix.O_RDONLY|unix.O_NOFOLLOW)
	if errors.Is(err, fs.ErrNotExist) {
		// Only tag the following root.json fetch errors with ErrSkippableRepo
		// if the root trust source is actually remote -- local sources are
		// meant to always exist and be valid and so we should return errors if
		// they were misconfigured.
		skippableErr := func(err error) error {
			return err
		}
		if repo.RootTrust.IsRemote() {
			skippableErr = func(err error) error {
				return fmt.Errorf("(%w) %w", ErrSkippableRepo, err)
			}
		}
		// Fallback to fetch from the trusted root source.
		rootData, err := repo.RootTrust.FetchRoot(ctx, repo)
		if err != nil {
			err = fmt.Errorf("fetch trusted root.json: %w", err)
			// Only a missing root.json means the repository may not exist
			// yet. Any other failure (auth, network, server error) must not
			// look like an empty repository list.
			if errors.Is(err, fs.ErrNotExist) {
				err = skippableErr(err)
			}
			return nil, err
		}
		rootFile, err = repoCacheDir.Create(".", unix.O_TMPFILE|unix.O_RDWR|unix.O_NOFOLLOW, 0o644)
		if err != nil {
			return nil, fmt.Errorf("create tmpfile for cached root.json: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, rootFile)
		if _, err := rootFile.Write(rootData); err != nil {
			return nil, fmt.Errorf("write cached root.json: %w", err)
		}
		if err := rootFile.Sync(); err != nil {
			return nil, fmt.Errorf("sync cached root.json: %w", err)
		}
		_, _ = rootFile.Seek(0, io.SeekStart) // reset the file
		// Check if the local root.json is actually valid JSON before attaching
		// it. This should not happen with well-behaved servers but if we
		// accidentally commit an invalid root.json, the cache will be poisoned
		// permanently. For bundled root.json, this will cause us to never copy
		// the root.json data to the cache, but that's okay -- the bundled data
		// is static anyway.
		if root, err := jsonutils.Parse[*tufext.SignedRoot](rootData); err != nil {
			return nil, skippableErr(fmt.Errorf("root_trust root.json is invalid JSON: %w", err))
		} else if err := tufext.CheckMetadataType(tufmetadata.ROOT, root); err != nil {
			return nil, skippableErr(fmt.Errorf("root_trust root.json is invalid tuf JSON: %w", err))
		} else if err := root.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
			// root.json must be self-signed.
			return nil, skippableErr(fmt.Errorf("root_trust root.json is not self-signed: %w", err))
		}
		// Attach as cached root.json.
		if err := pathrsext.AttachIntoRoot(repoCacheDir, "root.json", rootFile); err != nil {
			return nil, fmt.Errorf("attach trusted root.json to cache: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("open cached root.json: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, rootFile)

	rootData, err := io.ReadAll(rootFile)
	if err != nil {
		return nil, fmt.Errorf("could not read cached root.json: %w", err)
	}

	// Use the go-tuf defaults and adjust the arguments.
	tufConfig, err := tufconfig.New(metaRootURL.String(), rootData)
	if err != nil {
		return nil, fmt.Errorf("initialise tuf-client config: %w", err)
	}
	tufConfig.RootMaxLength = tufext.MaxRootBytes
	// Custom URLs.
	tufConfig.RemoteMetadataURL = metaRootURL.String()
	tufConfig.RemoteTargetsURL = dataRootURL.String()
	// Use our own cache dir.
	tufConfig.LocalMetadataDir = repoCacheDir.IntoFile().Name()
	// NOTE: Ideally we wouldn't have this (there is little point to this kind
	// of forced local caching) but go-tuf requires you to do it if you want to
	// cache the metadata. Really annoying.
	tufConfig.LocalTargetsDir = fmt.Sprintf("/tmp/quarry-targets-cache/%s", repo.Name)
	// At the moment our publishing flow doesn't use the <hash>.<file> naming.
	tufConfig.PrefixTargetsWithHash = false
	if err := tufConfig.SetDefaultFetcherHTTPClient(repo.HTTPClient()); err != nil {
		return nil, fmt.Errorf("set tuf-client http client: %w", err)
	}

	if err := tufConfig.EnsurePathsExist(); err != nil {
		return nil, fmt.Errorf("ensure tuf-client paths exist: %w", err)
	}
	return tufupdater.New(tufConfig)
}

// Client represents a Quarry client.
type Client struct {
	// Config is a copy of the configuration file used to instantiate this
	// client instance.
	Config *config.Config

	// CacheDir is a handle to the cache directory where all TUF metadata files
	// are stored. You should only operate on this if you are absolutely sure
	// that you know what you're doing (it includes the primary copy of trusted
	// local metadata).
	CacheDir *pathrs.Root

	// updaters contains the TUF updaters for every repository that was
	// successfully loaded by [NewClient], regardless of the subset currently
	// selected with [Client.WithRepos] (activeRepos).
	updaters map[string]*tufupdater.Updater

	// activeRepos contains the TUF updaters for the active set of repositories
	// that all operations act on. By default this is every loaded repository
	// (updaters), but [Client.WithRepos] can swap in a subset.
	activeRepos generics.Set[string]

	// skippedRepos records the (skippable) error that stopped each unloadable
	// repository from being included in updaters by [NewClient].
	skippedRepos map[string]error
}

// WithRepos restricts the [Client] to the given subset of configured
// repositories. Unknown repository names result in an error, as does a
// requested repository that could not be loaded when the [Client] was created
// (even if the failure was tagged as skippable with [ErrSkippableRepo]).
//
// Calling WithRepos with no arguments re-enables all configured repositories.
// If an error is returned, the active set of repositories is unchanged.
func (client *Client) WithRepos(repoNames ...string) error {
	if len(repoNames) == 0 {
		// Reset activeRepos and ignore any client.skippedRepos errors.
		client.activeRepos = generics.SeqSet(maps.Keys(client.updaters))
		return nil
	}
	var (
		active = make(generics.Set[string], len(repoNames))
		errs   []error
	)
	for _, name := range repoNames {
		if _, ok := client.updaters[name]; ok {
			active[name] = struct{}{}
		} else if err, ok := client.skippedRepos[name]; ok {
			errs = append(errs, fmt.Errorf("bad repo %s: %w", name, err))
		} else {
			errs = append(errs, fmt.Errorf("unknown repository %s requested", name))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	client.activeRepos = active
	return nil
}

// IterRepos returns an iterator over the set of repositories in the [Client],
// the order is always consistent for a given configuration and is based on the
// repository order index (and name as a tie-breaker). Note that use of this
// operation directly is very rarely necessary, most of the time
// [GetTargetInfo] and [FetchTargetFile] are more ergonomic.
//
// TODO: Return some custom type?
func (client *Client) IterRepos(_ context.Context) iter.Seq2[string, *tufupdater.Updater] {
	return func(yield func(string, *tufupdater.Updater) bool) {
		repoIndex := func(name string) int64 {
			return client.Config.Repos[name].OrderIndex()
		}
		order := slices.SortedFunc(maps.Keys(client.updaters), func(repoA, repoB string) int {
			return cmp.Or(
				cmp.Compare(repoIndex(repoA), repoIndex(repoB)), // *ascending* order
				cmp.Compare(repoA, repoB),                       // name is for tie-breaks
			)
		})
		for _, name := range order {
			if _, ok := client.activeRepos[name]; !ok {
				continue
			}
			if !yield(name, client.updaters[name]) {
				break
			}
		}
	}
}

// Close closes all resources associated with the client.
func (client *Client) Close() error {
	return client.CacheDir.Close()
}

// SetRefTime configures the reference time for the client. In principle this
// opens you up to freeze attacks, so this should only ever be used for testing
// purposes.
func (client *Client) SetRefTime(ctx context.Context, refTime time.Time) {
	for _, updater := range client.IterRepos(ctx) {
		updater.UnsafeSetRefTime(refTime)
	}
}

// TargetInfo is a tuple of [*tufmetadata.TargetFiles] and [*tufext.Repository]
// which is returned by most [Client] methods. This is necessary to help with
// identifying which repository a target file comes from, as well as doing some
// other operations.
type TargetInfo struct {
	*tufmetadata.TargetFiles
	Repo *tufext.Repository
}

// Fetch retreives the target file referenced by this [TargetInfo] and returns
// a stream to the file contents. This stream is backed by a
// [hardening.VerifiedReadCloser], so users must check the return value of the
// [io.ReadCloser.Close] method before using the data for anything.
//
// A wrapped [fs.ErrNotExist] error is returned if the target file could not be
// found (either in the repository metadata or from the download URL).
func (info *TargetInfo) Fetch(ctx context.Context) (io.ReadCloser, error) {
	infoExt := tufext.TargetFilesExt(info.TargetFiles)

	// Return the inline data if it is available (and valid).
	if data, err := infoExt.InlineData(); err != nil {
		slog.Info("Target file inline data is invalid, falling back to remote URL fetching...",
			"repo", info.Repo.Name, "target", info.Path, "err", err.Error())
	} else if data != nil {
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	// Rather than using the go-tuf DownloadTarget (which requires the data be
	// stored in-memory) we fetch it directly.
	dataRootURL, err := info.Repo.DataURL()
	if err != nil {
		return nil, fmt.Errorf("check target candidate urls: %w", err)
	}
	for url, err := range infoExt.FetchURLs(dataRootURL) {
		if err != nil {
			return nil, fmt.Errorf("check target candidate urls: %w", err)
		}
		rdr, _, err := httputils.VerifiedHTTPGet(ctx, info.Repo.HTTPClient(), url, info.Length, info.Hashes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				slog.Info("Target file not available at URL, trying next candidate...",
					"repo", info.Repo.Name, "target", info.Path, "url", url.String())
			} else {
				slog.Info("Target file could not be fetched from URL, trying next candidate...",
					"repo", info.Repo.Name, "target", info.Path, "url", url.String(), "err", err.Error())
			}
			continue
		}
		return rdr, nil
	}
	return nil, fmt.Errorf("%w: target not present at any fetch url", fs.ErrNotExist)
}

// GetTargetInfo returns the TUF metadata concerning the given file name.
//
// A wrapped [fs.ErrNotExist] error is returned if the target file could not be
// found.
func (client *Client) GetTargetInfo(ctx context.Context, targetPath string) (*TargetInfo, error) {
	for repoName, updater := range client.IterRepos(ctx) {
		info, err := updater.GetTargetInfo(targetPath)
		if err != nil {
			// FIXME: Grrr, why don't they use wrapped errors for this?!
			if err.Error() == fmt.Sprintf("target %s not found", targetPath) {
				continue
			}
			return nil, fmt.Errorf("bad repo %s: %w", repoName, err)
		}
		// As soon as we find a target file we return -- IterRepos provides a
		// consistent order based on order indexes so any later entries need to
		// be masked anyway.
		return &TargetInfo{
			TargetFiles: info,
			Repo:        client.Config.Repos[repoName].AsRepository(),
		}, nil
	}
	return nil, fmt.Errorf("target %s not found: %w", targetPath, fs.ErrNotExist)
}

// FetchTargetFile is shorthand for [ClientGetTargetInfo] followed by
// [TargetInfo.Fetch].
func (client *Client) FetchTargetFile(ctx context.Context, targetPath string) (io.ReadCloser, *TargetInfo, error) {
	info, err := client.GetTargetInfo(ctx, targetPath)
	if err != nil {
		return nil, nil, err
	}
	rdr, err := info.Fetch(ctx)
	if err != nil {
		return nil, nil, err
	}
	return rdr, info, nil
}

// trustedMetadataTargetsFetcher returns a [tufext.TargetMetadataFetchFunc] for
// the given repository in the client.
func (client *Client) trustedMetadataTargetsFetcher(repo *tufext.Repository, metadata *tuftrustedmetadata.TrustedMetadata) tufext.TargetMetadataFetchFunc {
	var mu sync.RWMutex // to serialise access to TrustedMetadata

	return func(ctx context.Context, roleName, delegatorName string) (_ *tufext.SignedTargets, Err error) {
		// TODO: Make this critical section cancellable with ctx?
		mu.RLock()
		// Fetch the link from the snapshot.
		metaRef, isKnownRole := metadata.Snapshot.Signed.Meta[roleName+".json"]
		// Fetch the cached data if we have it already.
		var (
			savedTarget, haveFetched = metadata.Targets[roleName]
			savedDelegator           tufext.TargetDelegatorRole
			haveDelegator            bool
		)
		if delegatorName == tufmetadata.ROOT {
			savedDelegator, haveDelegator = metadata.Root, true
		} else {
			savedDelegator, haveDelegator = metadata.Targets[delegatorName]
		}
		mu.RUnlock()

		if !isKnownRole {
			return nil, fmt.Errorf("role %s: %w", roleName, fs.ErrNotExist)
		}
		// IterTargetRoles can iterate over the same role more than once, so we
		// can avoid unneeded fetches by returning the local data if we've
		// already fetched and validated this role's hashes.
		//
		// It is safe to re-use the data because TrustedMetadata explicitly
		// does not permit the timestamp or snapshot role data to be updated
		// after targets have been fetched -- if we have the target already
		// then this must be the exact same thing we would've fetched anyway.
		if haveFetched {
			// This really cannot happen, but add a check just in case. Sadly
			// we cannot assert the hashes because those are not necessarily
			// recomputable.
			if savedTarget.Signed.Version != metaRef.Version {
				return nil, fmt.Errorf(
					"previously-fetched-and-trusted target role %s has inconsistent version (snapshot says %d but role has %d)",
					roleName, metaRef.Version, savedTarget.Signed.Version,
				)
			}
			// This cannot happen by construction (in order to reach a
			// delegatee we must have already parsed the delegator data), but
			// do it anyway to avoid nil panics.
			if !haveDelegator {
				return nil, fmt.Errorf(
					"target role %s was reached from delegator %s without delegator being fetched (should never happen)",
					roleName, delegatorName,
				)
			}
			// Make sure that the saved target is actually signed by keys
			// trusted by *this* delegator as well.
			// NOTE: go-tuf does not do this because they basically implement
			// <https://github.com/theupdateframework/specification/issues/321>
			// incorrectly and never walk the same role twice.
			// FIXME: This needs to be moved to IterTargetRoles so that the
			// checking logic is generic -- we might even want to skip over bad
			// delegations instead of erroring out...?
			if err := savedDelegator.VerifyDelegate(roleName, savedTarget); err != nil {
				return nil, fmt.Errorf(
					"previously-fetched-and-trusted target role %s has bad signature for delegation from role %s: %w",
					roleName, delegatorName, err,
				)
			}
			return savedTarget, nil
		}
		metaPath := fmt.Sprintf("%d.%s.json", metaRef.Version, roleName)
		metaURL, err := repo.RootURL(metaPath)
		if err != nil {
			return nil, err
		}

		rdr, _, err := httputils.VerifiedHTTPGet(ctx, repo.HTTPClient(), metaURL, metaRef.Length, metaRef.Hashes)
		if err != nil {
			return nil, fmt.Errorf("get role %s (%s): %w", roleName, metaURL, err)
		}
		defer funchelpers.VerifyClose(&Err, rdr)

		data, err := io.ReadAll(rdr)
		if err != nil {
			return nil, fmt.Errorf("read %s (%s) failed: %w", metaPath, metaURL, err)
		}
		if err := rdr.Close(); err != nil {
			return nil, fmt.Errorf("close %s (%s) check failed: %w", metaPath, metaURL, err)
		}

		mu.Lock() // TODO: Make this cancellable with ctx.
		defer mu.Unlock()

		targets, err := metadata.UpdateDelegatedTargets(data, roleName, delegatorName)
		if err != nil {
			return nil, fmt.Errorf("load delegated target %s: %w", roleName, err)
		}

		// Make sure to make a local copy of the file.
		// TODO: Use a pathrs-backed mktemp to allocate and swap over the file.
		filePath := filepath.Join(repo.Name, roleName+".json") //nolint:forbidigo // lexical pathname
		localFile, err := client.CacheDir.Create(filePath, unix.O_TRUNC|unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW, 0o644)
		if err != nil {
			return nil, fmt.Errorf("write role %s cached json: %w", roleName, err)
		}
		defer funchelpers.VerifyClose(&Err, localFile)

		if _, err := localFile.Write(data); err != nil {
			return nil, fmt.Errorf("write role %s cached json: %w", roleName, err)
		}
		return targets, localFile.Sync()
	}
}

// IterTargetFiles iterates over all target files in all repositories defined
// in the [Client]. Each target file will only be listed once even if it is
// provided by multiple repositories (first-repository-wins semantics). The
// order of target files is not consistent, however.
func (client *Client) IterTargetFiles(ctx context.Context) iter.Seq2[*TargetInfo, error] {
	return generics.ErrorIter(func(yield func(*TargetInfo) bool) error {
		seen := make(map[string]struct{}, 512) // TODO: Figure out a reasonable default map size.
		for repoName, updater := range client.IterRepos(ctx) {
			if err := ctx.Err(); err != nil {
				return err
			}

			repo := client.Config.Repos[repoName].AsRepository()
			meta := updater.GetTrustedMetadataSet()
			if meta.Timestamp == nil {
				// FIXME: The local client TrustedMetadata state does not get
				// filled until we do a refresh but go-tuf's client does not
				// allow Refresh on the same updater more than once(?!). So we
				// do a refresh here opportunistically.
				// TODO: Add a (*Client).Refresh helper to make this much less
				// fragile.
				if err := updater.Refresh(); err != nil {
					return fmt.Errorf("refresh repo %s: %w", repo.Name, err)
				}
				meta = updater.GetTrustedMetadataSet()
			}

			fetchFn := client.trustedMetadataTargetsFetcher(repo, &meta)
			for roleChain, err := range tufext.IterTargetRoles(ctx, fetchFn) {
				if err != nil {
					return fmt.Errorf("error while scanning repo %s: %w", repoName, err)
				}

				for _, target := range roleChain.Role.Signed.Targets {
					if err := ctx.Err(); err != nil {
						return err
					}
					if _, ok := seen[target.Path]; ok {
						// First instance of a target wins:
						// 1. IterTargetRoles iterates over the roles in the
						//    TUF lookup order (s5.6.7); and
						// 2. IterRepos provides a consistent ordering, so the
						//    first entry we hit masks any later entries.
						continue
					}
					if !roleChain.IsTargetPermitted(target.Path) {
						// TODO(log): Add logging?
						continue
					}
					seen[target.Path] = struct{}{}

					// TODO: We probably should check if this target file would
					// actually be fetched by a tuf client by seeing how many
					// previous delegation paths match against it -- if it is
					// over the limit (maxDelegationDepth in IterTargetRoles)
					// then we should mask it here too.
					info := &TargetInfo{
						TargetFiles: target,
						Repo:        repo,
					}
					if !yield(info) {
						return nil
					}
				}
			}
		}
		return nil
	})
}

// NewClient constructs a new Quarry [Client] for the given configuration. The
// cache directory referenced by [config.Config.CacheDir] may be written to by
// this operation.
func NewClient(ctx context.Context, config *config.Config) (_ *Client, Err error) {
	// TODO(links): Once we add cross-repo links this will need to expand out
	// the links, either here upfront or on-demand in IterRepos...?

	// TODO: Should this really be world-readable...?
	if err := os.MkdirAll(config.CacheDir, 0o755); err != nil { //nolint:forbidigo // user-controlled host path
		return nil, fmt.Errorf("create client cache directory: %w", err)
	}

	cacheDir, err := pathrs.OpenRoot(config.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("open cache directory: %w", err)
	}
	defer funchelpers.CloseOnError(&Err, cacheDir)

	var (
		updaters     = make(map[string]*tufupdater.Updater, len(config.Repos))
		skippedRepos = make(map[string]error)
	)
	for _, repo := range config.Repos {
		updater, err := RepoClient(ctx, cacheDir, repo)
		if errors.Is(err, ErrSkippableRepo) {
			// If the root.json could not be fetched from the trust source (and
			// RepoClient determines it is reasonable to skip this repo), skip
			// it as the repository presumably doesn't exist.
			//
			// This is not an issue for repositories where we have already
			// cached root.json. Save the error so that [Client.WithRepos] can
			// return it if the repository is requested explicitly.
			slog.Info("Cannot fetch repository root.json from root_trust -- skipping.", "error", err.Error(), "repository", repo.Name)
			skippedRepos[repo.Name] = err
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bad repo %s: %w", repo.Name, err)
		}
		updaters[repo.Name] = updater
	}
	if len(updaters) < 1 {
		slog.Warn("No repositories defined -- all operations are a no-op!")
	}
	return &Client{
		Config:       config,
		CacheDir:     cacheDir,
		updaters:     updaters,
		activeRepos:  generics.SeqSet(maps.Keys(updaters)), // enable all repos
		skippedRepos: skippedRepos,
	}, nil
}
