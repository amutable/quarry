// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cyphar.com/go-pathrs"
	"github.com/opencontainers/go-digest"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/linux"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufext"
)

// stripComponents removes the given number of leading path components, and is
// equivalent to GNU tar's --strip-components flag. Absolute paths have the
// leading slash stripped "for free" if the first component is also to be
// stripped, and multiple "/"s are treated as a single separator.
//
// Unfortunately, GNU tar and bsdtar (libarchive) have different semantics, but
// more users are probably familiar with GNU tar.
func stripComponents(path string, n int) string {
	for ; n > 0; n-- {
		path = strings.TrimLeft(path, "/")
		sepIdx := strings.IndexByte(path, '/')
		if sepIdx < 0 {
			return "." // ran out of components
		}
		path = strings.TrimLeft(path[sepIdx+1:], "/")
	}
	return path
}

// TODO: Support specifying a set of hashes or at least a different hash algo.
var hashAlgorithm = digest.SHA256

func hashToTargets(ctx context.Context, builder *tufext.TargetsBuilder, logicalPath string, file *os.File) error { //nolint:unparam // ctx might be used in the future
	st, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to fstat %s: %w", file.Name(), err)
	}

	if st.IsDir() {
		children, err := file.Readdirnames(-1)
		if err != nil {
			return fmt.Errorf("failed to iterate over directory %s: %w", file.Name(), err)
		}
		for _, child := range children {
			logicalSubpath := filepath.Join(logicalPath, child) //nolint:forbidigo // lexical paths
			subfile, err := linux.Openat(file, child, unix.O_RDONLY|unix.O_NOFOLLOW)
			if err != nil {
				return fmt.Errorf("could not open child %s: %w", logicalSubpath, err)
			}
			err = hashToTargets(ctx, builder, logicalSubpath, subfile)
			_ = subfile.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}

	// Make sure we don't end up with a nonsense name.
	if filepath.Join("/", logicalPath) == "/" { //nolint:forbidigo // lexical paths
		return fmt.Errorf("--skip-components value too large -- no components left for file %s", file.Name())
	}

	digester := hashAlgorithm.Digester()
	// TODO: Make this cancellable.
	size, err := io.Copy(digester.Hash(), file)
	if err != nil {
		return fmt.Errorf("compute file %s hash: %w", file.Name(), err)
	}
	digest := digester.Digest()

	if _, err := builder.AddTargetFile(logicalPath, size, digest); err != nil {
		return fmt.Errorf("add file %s to targets data: %w", logicalPath, err)
	}
	return nil
}

// maxInlineSize bounds the contents the --quarry-* options embed into
// targets.json. Inline data is meant for tiny metadata files, not payloads.
const maxInlineSize = 64 << 10

// addInlineBytes adds data as a target file with its contents inlined.
func addInlineBytes(builder *tufext.TargetsBuilder, logicalPath string, data []byte) (*tufmetadata.TargetFiles, error) {
	if int64(len(data)) > maxInlineSize {
		return nil, fmt.Errorf("target %s is too large (%d bytes) to be inlined (limit %d bytes)", logicalPath, len(data), maxInlineSize)
	}
	target, err := builder.AddTargetFile(logicalPath, int64(len(data)), hashAlgorithm.FromBytes(data))
	if err != nil {
		return nil, fmt.Errorf("add file %s to targets data: %w", logicalPath, err)
	}
	tufext.TargetFilesExt(target).WithInlineData(data)
	return target, nil
}

// applyCustomFrom merges the per-target "custom" objects from the given JSON
// file ({"<target path>": {<custom fields>}}) into the targets. Every path
// must name a target that was already added, so that a typo cannot silently
// drop metadata. No path may be under .quarry/ because the
// --quarry-* options own that metadata. Existing custom fields are kept unless
// overridden by key.
func applyCustomFrom(builder *tufext.TargetsBuilder, path string) error {
	data, err := os.ReadFile(path) //nolint:forbidigo // user-controlled host path
	if err != nil {
		return fmt.Errorf("--custom-from=%q file is invalid: %w", path, err)
	}
	customs, err := jsonutils.Parse[map[string]map[string]json.RawMessage](data)
	if err != nil {
		return fmt.Errorf("--custom-from=%q file is invalid json: %w", path, err)
	}
	targets := builder.TargetsType().Targets
	for targetPath, custom := range customs {
		if strings.HasPrefix(targetPath, transferlayout.Prefix) {
			return fmt.Errorf("--custom-from=%q: target %q is quarry metadata, which --custom-from must not change", path, targetPath)
		}
		target, ok := targets[targetPath]
		if !ok {
			return fmt.Errorf("--custom-from=%q: target %q does not exist", path, targetPath)
		}
		err := updateCustom(target, func(fields map[string]json.RawMessage) error {
			maps.Copy(fields, custom)
			return nil
		})
		if err != nil {
			return fmt.Errorf("--custom-from=%q: target %q: %w", path, targetPath, err)
		}
	}
	return nil
}

// updateCustom lets update change the fields of a target's custom object and
// stores the result. A missing or null custom object is an empty one.
func updateCustom(target *tufmetadata.TargetFiles, update func(fields map[string]json.RawMessage) error) error {
	fields := map[string]json.RawMessage{}
	if target.Custom != nil {
		if err := json.Unmarshal(*target.Custom, &fields); err != nil {
			return fmt.Errorf("existing custom data is not an object: %w", err)
		}
	}
	if fields == nil { // "custom": null
		fields = map[string]json.RawMessage{}
	}
	if err := update(fields); err != nil {
		return err
	}
	encoded, err := jsonutils.MarshalNoEscapeHTML(fields)
	if err != nil {
		return fmt.Errorf("encode custom data: %w", err)
	}
	target.Custom = (*json.RawMessage)(&encoded)
	return nil
}

// addIncludedOverrideURLs points the targets of an --include-from file at
// dataRootURL. A target with inline data needs no URL because its bytes are
// in the metadata, and a target that already has an override URL keeps it.
func addIncludedOverrideURLs(targets map[string]*tufmetadata.TargetFiles, dataRootURL *url.URL) error {
	for path, target := range targets {
		ext := tufext.TargetFilesExt(target)
		inline, err := ext.InlineData()
		if err != nil {
			return fmt.Errorf("target %s: %w", path, err)
		}
		if inline != nil {
			continue
		}
		existing, err := ext.OverrideURL()
		if err != nil {
			return fmt.Errorf("target %s: %w", path, err)
		}
		if existing != nil {
			continue
		}
		ext.WithOverrideURL(dataRootURL.JoinPath(path))
	}
	return nil
}

const dataRootURLCtxKey ctxKey = "--data-root-url"

func ctxDataRootURL(ctx context.Context) *url.URL {
	return ctxext.Value[*url.URL](ctx, dataRootURLCtxKey)
}

const extOverrideURLCtxKey ctxKey = "--ext-override-url"

func ctxExtOverrideURL(ctx context.Context) bool {
	return ctxext.Value[bool](ctx, extOverrideURLCtxKey)
}

// sumFileRe matches the "standard" line format for "hashsum" files.
var sumFileRe = regexp.MustCompile(`^([0-9a-fA-F]+)\s+(.+)$`)

func getContentLength(ctx context.Context, url *url.URL) (int64, error) {
	// TODO: Should we try to use HEAD? Though, RFC 9110 says that
	// Content-Length is not guaranteed to be set with HEAD. R2 does support it
	// but my testing indicated there wasn't really any speed improvement.
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return -1, fmt.Errorf("cannot create http request GET %q: %w", url, err)
	}
	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("fetch %s: %w", url, err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// An error page's Content-Length is not the target's length. R2
		// serves 404 pages with a plausible-looking size that would end up
		// in targets.json and fail length verification on every fetch.
		return -1, fmt.Errorf("fetch %s failed with status code %.3d", url, res.StatusCode)
	}
	if res.ContentLength < 0 {
		return -1, fmt.Errorf("fetch %s: response has no Content-Length", url)
	}
	return res.ContentLength, nil
}

func addPrehashedToTargets(ctx context.Context, builder *tufext.TargetsBuilder, logicalPath string, sumFile *os.File) error {
	dataRootURL := ctxDataRootURL(ctx)
	extOverrideURL := ctxExtOverrideURL(ctx)

	if filepath.Join("/", logicalPath) == "/" { //nolint:forbidigo // lexical paths
		return fmt.Errorf("--skip-components value too large -- no components left for sumfile %s", sumFile.Name())
	}
	// logicalPath references the sumfile, we care about the parent directory
	// for computing the logical subpath of paths referenced in the sumfile.
	logicalPath = filepath.Dir(logicalPath) //nolint:forbidigo // lexical paths

	// We need to open the parent directory of the *actual* sumfile.
	root, err := pathrs.OpenRoot(filepath.Dir(sumFile.Name())) //nolint:forbidigo // lexical paths
	if err != nil {
		return fmt.Errorf("failed to open parent directory of sumfile %s: %w", sumFile.Name(), err)
	}

	var (
		scanner      = bufio.NewScanner(sumFile)
		skippedLines atomic.Uint64
		wg           sync.WaitGroup
		queueCh      = make(chan struct{}, 32)
		errCh        = make(chan error, 32)
	)
	for scanner.Scan() {
		text := scanner.Text()
		wg.Go(func() {
			parts := sumFileRe.FindStringSubmatch(text)
			if len(parts) != 3 {
				// This line does not contain a hashsum line (it might be empty or
				// a inline-signed sumfile that contains non-hash lines).
				// TODO: Add logging?
				skippedLines.Add(1)
				return
			}
			hash, subpath := strings.ToLower(parts[1]), parts[2]

			// Wait for a slot.
			select {
			case <-ctx.Done():
				return // early exit
			case queueCh <- struct{}{}:
				defer func() { <-queueCh }()
			}

			// Compute the logical subpath of the referenced file.
			logicalSubpath := filepath.Join(logicalPath, subpath) //nolint:forbidigo // lexical paths

			// Make sure the digest is valid.
			if err := hashAlgorithm.Validate(hash); err != nil {
				// TODO: Add proper logging.
				fmt.Fprintf(os.Stderr, "skipping invalid hash %q: %v\n", hash, err)
				skippedLines.Add(1)
				return
			}
			digest := digest.NewDigestFromEncoded(hashAlgorithm, hash)

			var dataURL *url.URL
			if dataRootURL != nil {
				dataURL = dataRootURL.JoinPath(logicalSubpath)
			}

			// Get the size.
			size := int64(-1)
			if dataURL != nil {
				var err error
				size, err = getContentLength(ctx, dataURL)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to fetch %q from --data-root-url (%v) -- falling back to local file stat\n", logicalSubpath, err)
				}
			}
			if size < 0 {
				st, err := pathrsext.Stat(root, subpath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "cannot stat hashed file %q: %v\n", subpath, err)
					skippedLines.Add(1)
					return
				}
				size = st.Size()
			}
			target, err := builder.AddTargetFile(logicalSubpath, size, digest)
			if err != nil {
				errCh <- fmt.Errorf("add file %s to targets data: %w", logicalSubpath, err)
				return
			}
			if extOverrideURL {
				tufext.TargetFilesExt(target).WithOverrideURL(dataURL)
			}
		})
	}
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitCh:
	case err := <-errCh:
		// This will cause ctx to get cancelled by urfave/cli.
		return fmt.Errorf("error during targets generation: %w", err)
	}
	if skipped := skippedLines.Load(); skipped > 0 {
		// TODO: Add proper logging.
		fmt.Fprintf(os.Stderr, "== SKIPPED %d invalid lines in %s ==\n", skipped, sumFile.Name())
	}
	return nil
}

var targetsCommand = withKeystoreFlagUnless(&cli.Command{
	Name:  "targets",
	Usage: "generate a TUF targets.json (or delegated target) file",
	Flags: append([]cli.Flag{
		&cli.StringFlag{
			Name:      "output",
			Aliases:   []string{"o"},
			Usage:     "output file for the TUF targets data",
			TakesFile: true,
			Value:     "-",
		},
		&cli.UintFlag{
			Name:  "strip-components",
			Usage: "strip N parent components from paths when adding them to target.json",
		},
		&cli.StringSliceFlag{
			Name:  "include-from",
			Usage: "include targets defined in the given targets.json files (later files take precedence, with <files> arguments taking highest precedence)",
		},
		&cli.StringSliceFlag{
			Name:      "custom-from",
			Usage:     "merge per-target \"custom\" objects from the given JSON file ({\"<target path>\": {...}}), where every path must name a target",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "ext-override-url",
			Usage: "with --data-root-url, add an override URL to make clients fetch from --data-root-url, for each --pre-hashed file and for each --include-from target without inline data or an override URL",
		},
		&cli.StringFlag{
			Name:  "data-root-url",
			Usage: "base url for target files (with --pre-hashed this allows you to generate a target.json entirely from a SHA256SUMS file, and with --ext-override-url the --include-from targets point there)",
		},
		&cli.BoolFlag{
			Name:    "pre-hashed",
			Aliases: []string{"H"},
			Usage:   "indicates that the given paths are all hashsum files (the listed files must still exist to get their size)",
		},
		// TODO: Move --expire-after to utils?
		&cli.DurationFlag{
			Name:  "expire-after",
			Usage: "configure the expiry of the targets file (duration relative to --ref-time)",
		},
	}, quarryTargetsFlags()...),
	Arguments: []cli.Argument{
		// TODO: This doesn't work if you have pre-hashed values.
		// TODO: This won't work if you have enough files to hit the
		// PAGE_SIZE(?) argv limit.
		&cli.StringArgs{
			Name:      "files",
			UsageText: "<file-or-dir> [<file-or-dir>]...",
			Min:       0,
			Max:       -1,
		},
	},
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.StringFlag{
						Name:      "from-root",
						Usage:     "source the signing keys from a root.json",
						TakesFile: true,
					},
				},
				{
					&cli.StringSliceFlag{
						Name:    "keyid",
						Aliases: []string{"k"},
						Usage:   "use the given keys to sign the targets file",
					},
				},
				{
					&cli.BoolFlag{
						Name:  "unsigned",
						Usage: "write the targets file without signatures, with version 1 and, unless --expire-after is set, with the zero time as its expiry, for a consumer that signs it itself (needs no --keystore)",
					},
				},
			},
			Required: true,
		},
	},
	Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if urlStr := cmd.String("data-root-url"); urlStr != "" {
			if !cmd.Bool("pre-hashed") && !cmd.Bool("ext-override-url") {
				return nil, fmt.Errorf("--data-root-url doesn't make sense without --pre-hashed or --ext-override-url")
			}
			rootURL, err := url.Parse(urlStr)
			if err != nil {
				return nil, fmt.Errorf("invalid --data-root-url=%q: %w", urlStr, err)
			}
			ctx = context.WithValue(ctx, dataRootURLCtxKey, rootURL)
		}
		if cmd.Bool("ext-override-url") {
			if !cmd.IsSet("data-root-url") {
				return nil, fmt.Errorf("--ext-override-url doesn't make sense without --data-root-url")
			}
			ctx = context.WithValue(ctx, extOverrideURLCtxKey, true)
		}
		return ctx, nil
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		store := ctxKeystore(ctx)

		// This happens before creating --output so that bad options leave it
		// alone.
		quarry, err := quarrySpecFromFlags(cmd)
		if err != nil {
			return err
		}

		var output io.Writer
		if outPath := cmd.String("output"); outPath != "-" {
			outFile, err := os.Create(outPath) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("invalid --output argument: %w", err)
			}
			defer outFile.Close() //nolint:errcheck // poc cli code
			output = outFile
		} else {
			output = os.Stdout
		}

		var keyIDs []string
		switch {
		case cmd.Bool("unsigned"):
			// No keys, so the targets file gets no signatures.
		case cmd.IsSet("from-root"):
			rootPath := cmd.String("from-root")

			rootData, err := os.ReadFile(rootPath) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("could not read root.json: %w", err)
			}
			root, err := jsonutils.Parse[tufext.SignedRoot](rootData)
			if err != nil {
				return fmt.Errorf("invalid root.json: %w", err)
			}
			// Assume the root is validly signed.
			keyIDs = root.Signed.Roles[tufmetadata.TARGETS].KeyIDs
		case cmd.IsSet("keyid"):
			keyIDs = cmd.StringSlice("keyid")
		default:
			return fmt.Errorf("one of --from-root, --keyid or --unsigned must be set")
		}

		keys := make([]*keystore.GenericKey, 0, len(keyIDs))
		for _, keyID := range keyIDs {
			key, err := store.GetKey(ctx, keystore.KeyID(keyID))
			if err != nil {
				return fmt.Errorf("cannot load signing key %s: %w", keyID, err)
			}
			keys = append(keys, key)
		}

		builder := tufext.NewTargetsBuilder()

		if refTime, ok := ctxext.RefTime(ctx); ok {
			builder.RefTime = refTime
		}
		if cmd.IsSet("expire-after") {
			builder.ExpireAfter = cmd.Duration("expire-after")
		}

		for _, includePath := range cmd.StringSlice("include-from") {
			data, err := os.ReadFile(includePath) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("--include-from=%q file is invalid: %w", includePath, err)
			}
			// TODO: Support unsigned targets.json files?
			targets, err := jsonutils.Parse[tufext.SignedTargets](data)
			if err != nil {
				return fmt.Errorf("--include-from=%q file is invalid json: %w", includePath, err)
			}
			// Make sure it is a targets.json (though we don't care about
			// signatures).
			if err := tufext.CheckMetadataType(tufmetadata.TARGETS, &targets); err != nil {
				return fmt.Errorf("--include-from=%q file is invalid targets.json: %w", includePath, err)
			}
			// TODO: Support delegations...
			if targets.Signed.Delegations != nil {
				return fmt.Errorf("--include-from=%s file is unsupported: hardhat does not yet support delegations", includePath)
			}
			if ctxExtOverrideURL(ctx) {
				if err := addIncludedOverrideURLs(targets.Signed.Targets, ctxDataRootURL(ctx)); err != nil {
					return fmt.Errorf("--include-from=%q: %w", includePath, err)
				}
			}
			// Copy all of the target file specifications into the builder,
			// including any possible extension fields!
			maps.Copy(builder.TargetsType().Targets, targets.Signed.Targets)
		}

		// TODO: Support adding delegations.

		for _, filename := range cmd.StringArgs("files") {
			file, err := os.Open(filename) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return err
			}
			logicalFilename := stripComponents(filename, int(cmd.Uint("strip-components")))
			if cmd.Bool("pre-hashed") {
				if err := addPrehashedToTargets(ctx, builder, logicalFilename, file); err != nil {
					return fmt.Errorf("failed to add sumfile %s contents (as %s) to targets: %w", filename, logicalFilename, err)
				}
			} else {
				if err := hashToTargets(ctx, builder, logicalFilename, file); err != nil {
					return fmt.Errorf("failed to add %s (as %s) to targets: %w", filename, logicalFilename, err)
				}
			}
		}

		if err := addQuarryTargets(builder, quarry); err != nil {
			return err
		}

		for _, customPath := range cmd.StringSlice("custom-from") {
			if err := applyCustomFrom(builder, customPath); err != nil {
				return err
			}
		}
		// This comes after --custom-from because that replaces a target's
		// whole "quarry" object. The .quarry/ targets are skipped
		// because they are quarry metadata and belong to no version.
		if version := cmd.String("custom-version"); version != "" {
			for path, target := range builder.TargetsType().Targets {
				if strings.HasPrefix(path, transferlayout.Prefix) {
					continue
				}
				if err := setQuarryCustomVersion(target, version); err != nil {
					return fmt.Errorf("--custom-version: %s: %w", path, err)
				}
			}
		}

		signed, err := builder.SignWith(ctx, store, keys...)
		if err != nil {
			return fmt.Errorf("failed to sign targets data: %w", err)
		}
		if cmd.Bool("unsigned") {
			// Nothing verifies an unsigned file, so nothing checks its expiry
			// either. The zero time says so, unless --expire-after asks for one.
			if !cmd.IsSet("expire-after") {
				signed.Signed.Expires = time.Time{}
			}
			// Nothing compares its version either: a repository that imports
			// it with --include-from takes its targets and versions them
			// itself. The lowest version TUF allows says so, and unlike the
			// wall-clock time it makes the same input give the same file.
			signed.Signed.Version = 1
		}
		payload, err := cjson.EncodeCanonical(signed)
		if err != nil {
			return fmt.Errorf("failed to encode targets data: %w", err)
		}
		n, err := io.Copy(output, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to write targets data: %w", err)
		}
		if output != os.Stdout {
			mustFprintf(os.Stdout, "wrote %d bytes to %s\n", n, cmd.String("output"))
		} else {
			mustFprintf(os.Stdout, "\n")
		}
		return nil
	},
}, "unsigned")
