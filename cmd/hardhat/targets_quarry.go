// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufext"
)

// quarryTargetsFlags returns the --quarry-* options of "hardhat targets" (and
// --custom-version). They add the transfer definition directories of
// internal/transferlayout that quarry-sysupdate reads. hardhat lays them out
// from plain definition files, so producers need not know the layout.
func quarryTargetsFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "quarry-transfer-dir",
			Usage: "ship sysupdate definitions given as <component dir>=<source>, where <component dir> is \"sysupdate.d\" or \"sysupdate.<component>.d\" and <source> is a directory of definitions or \"" + confextSourcePrefix + "<name>\" to generate a transfer for the confext <name>. Can be repeated. Components are enabled by default; to use a custom component file, place it in the <source> directory as <component>.component (<component>.component.d/ drop-ins are also supported)",
		},
		// TODO: This should probably allow you to specify a subset of targets
		// to apply this to, as applying it to everything is kinda aggressive.
		&cli.StringFlag{
			Name:  "custom-version",
			Usage: "set custom.quarry.version on every target outside " + transferlayout.Prefix,
		},
	}
}

// quarryTransferSource is one <component dir>=<source> of
// --quarry-transfer-dir.
type quarryTransferSource struct {
	componentDir string
	source       string
}

// quarrySpecFromFlags parses and checks the --quarry-* options.
//
// TODO: We should probably return a wrapping struct or something a bit more
// generic so the caller's usage of [addQuarryTargets] makes more sense.
func quarrySpecFromFlags(cmd *cli.Command) ([]quarryTransferSource, error) {
	var sources []quarryTransferSource
	for _, arg := range cmd.StringSlice("quarry-transfer-dir") {
		componentDir, source, ok := strings.Cut(arg, "=")
		if !ok || source == "" {
			return nil, fmt.Errorf("--quarry-transfer-dir=%q must be <component dir>=<source>", arg)
		}
		if _, err := transferlayout.ParseComponentDir(componentDir); err != nil {
			return nil, fmt.Errorf("--quarry-transfer-dir=%q: %w", arg, err)
		}
		sources = append(sources, quarryTransferSource{componentDir: componentDir, source: source})
	}
	return sources, nil
}

// confextSourcePrefix marks a --quarry-transfer-dir source that names a
// confext to generate the definitions for rather than a directory.
const confextSourcePrefix = "confext:"

// hasSpaceOrControl returns whether s would break a definition line.
func hasSpaceOrControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// rejectConflict returns an error if the contents of the existing target at
// targetPath differ from data.
func rejectConflict(existing *tufmetadata.TargetFiles, targetPath string, data []byte) error {
	if err := tufext.VerifyData(data, existing.Length, existing.Hashes); err != nil {
		return fmt.Errorf("target %s is given twice with different contents: %w", targetPath, err)
	}
	return nil
}

// confextTransfer returns the transfer definition installing the confext DDI
// "<name>_<version>.confext.raw" into the /var/lib/confexts/<name>.raw.v/
// directory, from which systemd picks the newest instance. The source pattern
// matches the image at any depth (**/), so a repository may serve it from a
// subdirectory as well as flat. The source path is a placeholder that
// quarry-sysupdate replaces with its proxy URL when staging. Verify=no is set
// because TUF already authenticated the bytes.
func confextTransfer(name string) []byte {
	return []byte(`[Transfer]
Verify=no

[Source]
Type=url-file
Path=__quarry_will_replace_this__
MatchPattern=**/` + name + `_@v.confext.raw

[Target]
Type=regular-file
Path=/var/lib/confexts/` + name + `.raw.v
PathRelativeTo=root
MatchPattern=` + name + `_@v.raw
Mode=0644
InstancesMax=2
`)
}

// addInlineTarget adds an inline target with the given target path. If there
// is an existing entry with identical contents this is a no-op, but if the
// contents are different then an error is returned.
func addInlineTarget(builder *tufext.TargetsBuilder, targetPath string, data []byte) error {
	existing, ok := builder.TargetsType().Targets[targetPath]
	if !ok {
		_, err := addInlineBytes(builder, targetPath, data)
		return err
	}
	if err := rejectConflict(existing, targetPath, data); err != nil {
		return err
	}
	// If there is already an existing entry, make sure we include inline data.
	ext := tufext.TargetFilesExt(existing)
	if inline, err := ext.InlineData(); err != nil {
		return fmt.Errorf("target %s has invalid inline data: %w", targetPath, err)
	} else if inline == nil {
		ext.WithInlineData(data)
	}
	return nil
}

// addDefinitionSource adds the definition files of one source directory to the
// targets under componentDir, keeping their path relative to the source, or
// generates them for a confext source.
func addDefinitionSource(builder *tufext.TargetsBuilder, componentDir, source string) error {
	if name, ok := strings.CutPrefix(source, confextSourcePrefix); ok {
		// systemd reads the confext name up to the first "_" of the file name.
		if !transferlayout.ValidPathComponent(name) || strings.Contains(name, "_") || hasSpaceOrControl(name) {
			return fmt.Errorf("invalid confext name %q in %s", name, source)
		}
		file := "50-" + name + ".transfer"
		targetPath, err := transferlayout.TargetPath(componentDir, file)
		if err != nil {
			return fmt.Errorf("%s: %s: %w", componentDir, file, err)
		}
		return addInlineTarget(builder, targetPath, confextTransfer(name))
	}
	found := false
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error { //nolint:forbidigo // user-controlled host path
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(source, path) //nolint:forbidigo // user-controlled host path
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		targetPath, err := definitionTargetPath(componentDir, rel)
		if err != nil {
			return fmt.Errorf("%s: %s: %w", componentDir, rel, err)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		// TODO: Ideally tufext.TargetsBuilder would auto-detect what sizes
		// this inlining should happen at and we could then provide a reader
		// instead?
		if info.Size() > maxInlineSize {
			return fmt.Errorf("definition file %s is too large (%d bytes) to be inlined (limit %d bytes)", path, info.Size(), maxInlineSize)
		}
		data, err := os.ReadFile(path) //nolint:forbidigo // user-controlled host path
		if err != nil {
			return err
		}
		found = true
		if err := addInlineTarget(builder, targetPath, data); err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s holds no definition files", source)
	}
	return nil
}

// isComponentDefinition returns whether rel is a component file or lies in a
// component drop-in directory.
func isComponentDefinition(rel string) bool {
	return strings.HasSuffix(rel, ".component") || strings.Contains(rel, ".component.d/")
}

// definitionTargetPath returns the target path of the definition file rel of a
// source for componentDir. The component's own <component>.component and
// <component>.component.d/ at the top of the source are published as the
// component file and drop-in directory. Any other component file or drop-in
// directory is an error.
func definitionTargetPath(componentDir, rel string) (string, error) {
	if !isComponentDefinition(rel) {
		return transferlayout.TargetPath(componentDir, rel)
	}
	// quarrySpecFromFlags already checked the directory name.
	component, _ := transferlayout.ParseComponentDir(componentDir)
	if component == "" {
		return "", errors.New("the default component has no component file or drop-ins")
	}
	componentFile := component + ".component"
	if rel == componentFile {
		return transferlayout.ComponentFilePath(component)
	}
	if dropIn, ok := strings.CutPrefix(rel, componentFile+".d/"); ok && !isComponentDefinition(dropIn) {
		return transferlayout.ComponentDropInPath(component, dropIn)
	}
	return "", fmt.Errorf("unexpected component definition (only %s and %s.d/ are allowed)", componentFile, componentFile)
}

// addQuarryTargets adds what the --quarry-* options ask for to the targets.
// Every named component gets a generated <component>.component file if no
// source ships one.
func addQuarryTargets(builder *tufext.TargetsBuilder, sources []quarryTransferSource) error {
	components := map[string]struct{}{}
	for _, src := range sources {
		if err := addDefinitionSource(builder, src.componentDir, src.source); err != nil {
			return err
		}
		// quarrySpecFromFlags already checked the directory name.
		component, _ := transferlayout.ParseComponentDir(src.componentDir)
		if component != "" {
			components[component] = struct{}{}
		}
	}
	for component := range components {
		componentPath, err := transferlayout.ComponentFilePath(component)
		if err != nil {
			return fmt.Errorf("component %s: %w", component, err)
		}
		if _, ok := builder.TargetsType().Targets[componentPath]; ok {
			continue
		}
		if err := addInlineTarget(builder, componentPath, transferlayout.ComponentFile(component)); err != nil {
			return err
		}
	}
	return nil
}

// setQuarryCustomVersion sets custom.quarry.version on a target, keeping its
// other custom fields.
func setQuarryCustomVersion(target *tufmetadata.TargetFiles, version string) error {
	return updateCustom(target, func(custom map[string]json.RawMessage) error {
		quarry := map[string]json.RawMessage{}
		if raw, ok := custom[tufext.QuarryCustomField]; ok {
			if err := json.Unmarshal(raw, &quarry); err != nil {
				return fmt.Errorf("existing custom.quarry data is not an object: %w", err)
			}
		}
		if quarry == nil { // "quarry": null
			quarry = map[string]json.RawMessage{}
		}
		encodedVersion, err := json.Marshal(version)
		if err != nil {
			return err
		}
		quarry["version"] = encodedVersion
		encodedQuarry, err := jsonutils.MarshalNoEscapeHTML(quarry)
		if err != nil {
			return err
		}
		custom[tufext.QuarryCustomField] = encodedQuarry
		return nil
	})
}
