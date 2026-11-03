// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package hostnamedtest provides io.systemd.Hostname services for tests.
//
// [Start] is backed by a real systemd-hostnamed binary, while [StartFake] is
// an in-memory emulated version of the few APIs we use in order primarily to
// allow for error injection. Most tests should use [Start].
package hostnamedtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/hostnamed"
)

// BinaryEnv is the environment variable that (if set) points at a real
// systemd-hostnamed binary for [Start] to spawn, skipping the container build.
const BinaryEnv = "QUARRY_TEST_HOSTNAMED"

// runtimeEnvs are the environment variables consulted (in order) to pick the
// container runtime used to build the systemd binaries.
var runtimeEnvs = []string{"CONTAINER_RUNTIME", "CONTAINER_ENGINE"}

// sharedBinary caches the (fairly expensive) lookup-or-build of the real
// systemd-hostnamed binary for the lifetime of the whole test binary.
var sharedBinary struct {
	once sync.Once
	dir  string // temporary systemd-export output directory (if we built it)
	path string // path to the systemd-hostnamed binary
	skip string // non-empty: reason to skip tests that need the real daemon
	err  error  // non-nil: hard failure to report instead of skipping
}

// Main is a [testing.M]-based TestMain implementation that must be used by
// test packages that use [Start], so that shared build artifacts are
// removed once all of the package's tests have finished:
//
//	func TestMain(m *testing.M) { hostnamedtest.Main(m) }
func Main(m *testing.M) {
	code := m.Run()
	if sharedBinary.dir != "" {
		_ = os.RemoveAll(sharedBinary.dir) //nolint:forbidigo // test code
	}
	os.Exit(code)
}

// findRepo tries to find the repository root (identified by go.mod) by walking
// up from the given starting directory.
func findRepo(dir string) (string, bool) {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil { //nolint:forbidigo // test code
			return dir, true
		}
		parent := filepath.Dir(dir) //nolint:forbidigo // test code
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// repoRoot returns the repository root (identified by go.mod), which is used
// as the container build context.
var repoRoot = sync.OnceValues(func() (string, error) {
	// Try to search based on the location stored in debuginfo.
	if _, file, _, ok := runtime.Caller(0); ok {
		if root, ok := findRepo(filepath.Dir(file)); ok { //nolint:forbidigo // test code
			return root, nil
		}
	}
	// If the test binary was built with -trimpath then we need to fallback to
	// starting in the current directory. For plain "go test" runs, we are
	// guaranteed to be in this package directory.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if root, ok := findRepo(cwd); ok {
		return root, nil
	}
	return "", fmt.Errorf("could not find repository root from %q", cwd)
})

// buildSystemdBinaries builds the systemd binaries needed by the conformance
// tests using the systemd-export stage of our Dockerfile, and returns the
// temporary directory they were exported to.
func buildSystemdBinaries(engine string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}

	dir, err := os.MkdirTemp("", "gotest-quarry-binaries-") //nolint:forbidigo // test code
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(context.Background(), engine, "buildx", "build",
		"--target", "systemd-export",
		"-o", "type=local,dest="+dir,
		root)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir) //nolint:forbidigo // test code
		return "", fmt.Errorf("%s buildx build --target systemd-export: %w\n%s", engine, err, string(out))
	}
	return dir, nil
}

func ensureBinary() {
	if path := os.Getenv(BinaryEnv); path != "" {
		if _, err := os.Stat(path); err != nil {
			sharedBinary.err = fmt.Errorf("$%s does not point at a usable binary: %w", BinaryEnv, err)
			return
		}
		sharedBinary.path = path
		return
	}

	// An explicitly configured container runtime must work, but auto-detected
	// ones fall through to the next candidate (and ultimately a test skip) on
	// any error, so that CI breakage is loud while developers without a
	// working container setup are not blocked on unrelated test runs.
	var runtimes []string
	explicit := false
	for _, env := range runtimeEnvs {
		if engine := os.Getenv(env); engine != "" {
			runtimes, explicit = []string{engine}, true
			break
		}
	}
	if !explicit {
		runtimes = []string{"docker", "podman"}
	}

	var errs []error
	for _, engine := range runtimes {
		if _, err := exec.LookPath(engine); err != nil { //nolint:forbidigo // test code
			errs = append(errs, err)
			continue
		}
		dir, err := buildSystemdBinaries(engine)
		if err != nil {
			if explicit {
				sharedBinary.err = err
				return
			}
			errs = append(errs, err)
			continue
		}
		sharedBinary.dir = dir
		sharedBinary.path = filepath.Join(dir, "systemd-hostnamed") //nolint:forbidigo // test code
		return
	}
	sharedBinary.skip = fmt.Sprintf(
		"no way to get a real systemd-hostnamed binary (set $%s or install docker/podman): %v",
		BinaryEnv, errors.Join(errs...),
	)
}

// realBinary returns the path to a real systemd-hostnamed binary to test
// against, either from $QUARRY_TEST_HOSTNAMED or by building it with buildx.
// The test is skipped if neither is possible.
func realBinary(t *testing.T) string {
	t.Helper()
	sharedBinary.once.Do(ensureBinary)
	if sharedBinary.err != nil {
		t.Fatalf("get real systemd-hostnamed binary: %v", sharedBinary.err)
	}
	if sharedBinary.skip != "" {
		t.Skip(sharedBinary.skip)
	}
	return sharedBinary.path
}

// Hostnamed runs a real systemd-hostnamed binary with all of its state
// (varlink socket, machine-info(5) and hostname(5) files) redirected into a
// temporary directory, so that conformance tests exercise the actual daemon
// -- including what it persists to disk -- rather than our fake
// reimplementation of it.
type Hostnamed struct {
	binary string
	dir    string

	cmd    *exec.Cmd
	waitCh chan error
}

func (h *Hostnamed) socketPath() string      { return filepath.Join(h.dir, "io.systemd.Hostname") } //nolint:forbidigo // test code
func (h *Hostnamed) machineInfoPath() string { return filepath.Join(h.dir, "machine-info") }        //nolint:forbidigo // test code
func (h *Hostnamed) hostnamePath() string    { return filepath.Join(h.dir, "hostname") }            //nolint:forbidigo // test code
func (h *Hostnamed) logPath() string         { return filepath.Join(h.dir, "hostnamed.log") }       //nolint:forbidigo // test code

// Start spawns a real systemd-hostnamed with the given initial machine tags
// for the duration of the test. Tests are skipped if we cannot get a working
// systemd-hostnamed.
func Start(t *testing.T, tags ...string) *Hostnamed {
	t.Helper()

	binary := realBinary(t)

	// Describe hard-fails without a machine ID, and (unlike machine-info)
	// there is no environment override for its path. Every sane system has
	// one -- containers are the exception, and need one written in.
	if id, err := os.ReadFile("/etc/machine-id"); err != nil || len(strings.TrimSpace(string(id))) == 0 { //nolint:forbidigo // test code
		t.Skipf("real systemd-hostnamed requires a populated /etc/machine-id (err: %v)", err)
	}

	// Socket paths are limited to ~108 bytes (unless you futz with /proc which
	// is annoying on the client-side) so we cannot use t.TempDir() here as it
	// includes the test name and so will probably be longer.
	dir, err := os.MkdirTemp("", "gotest-quarry-hostnamed-") //nolint:forbidigo,usetesting // test code; see above
	if err != nil {
		t.Fatalf("create hostnamed state directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:forbidigo // test code

	h := &Hostnamed{
		binary: binary,
		dir:    dir,
	}
	if socketPath := h.socketPath(); len(socketPath) >= 108 {
		t.Fatalf("varlink socket path %q is too long -- set $TMPDIR to something shorter", socketPath)
	}

	// Pre-configure the tags.
	if len(tags) > 0 {
		h.WriteMachineInfo(t, "TAGS="+strings.Join(tags, ":"))
	}

	// Dump the logs on failure. Register this before the daemon starts so that
	// on cleanup the log is dumped after the daemon stops (t.Cleanup is LIFO).
	t.Cleanup(func() {
		if t.Failed() {
			if log, err := os.ReadFile(h.logPath()); err == nil { //nolint:forbidigo // test code
				t.Logf("systemd-hostnamed log:\n%s", log)
			}
		}
	})

	h.start(t)
	return h
}

// start spawns the daemon and waits until its varlink socket is accepting
// connections.
func (h *Hostnamed) start(t *testing.T) {
	t.Helper()

	// Opened with O_APPEND (rather than truncating) so logs survive Restart.
	logFile, err := os.OpenFile(h.logPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644) //nolint:forbidigo // test code
	if err != nil {
		t.Fatalf("create hostnamed log file: %v", err)
	}
	defer func() { _ = logFile.Close() }() // the child process keeps its own copy of the fd

	// Make it easier to tell when hostnamed was restarted by a test.
	_, _ = fmt.Fprintln(logFile, "-- starting hostnamed --")

	// We use a graceful cleanup with Stop in t.Cleanup() rather than aborting
	// hostnamed aggressively with t.Context() so use context.Background().
	cmd := exec.CommandContext(context.Background(), h.binary)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Run the daemon with entirely test-only filesystem state and a test-only
	// varlink service. /etc/machine-id is the only thing that hostnamed
	// consumes from the host.
	cmd.Env = []string{
		"SYSTEMD_VARLINK_LISTEN=" + h.socketPath(),
		"SYSTEMD_ETC_MACHINE_INFO=" + h.machineInfoPath(),
		"SYSTEMD_ETC_HOSTNAME=" + h.hostnamePath(),
		// For easier debugging with test failures.
		"SYSTEMD_LOG_LEVEL=debug",
		"SYSTEMD_LOG_TARGET=console",
		// We do not want to enable DBus here but there is no knob for it
		// explicitly. However, hostnamed uses a "watch bind" bus connection so
		// if the path is not a valid socket it patiently waits for it to be
		// usable while still serving the varlink service.
		"DBUS_SYSTEM_BUS_ADDRESS=unix:path=/dev/null",
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", h.binary, err)
	}

	h.cmd = cmd
	h.waitCh = make(chan error, 1)
	go func() { h.waitCh <- cmd.Wait() }()
	t.Cleanup(func() { h.Stop(t) })

	// Wait for the daemon to get ready and bind to the varlink socket.
	deadlineCh := time.After(10 * time.Second)
	for {
		var dialer net.Dialer
		conn, err := dialer.DialContext(context.Background(), "unix", h.socketPath())
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case waitErr := <-h.waitCh:
			h.cmd = nil
			t.Fatalf("systemd-hostnamed exited during startup: %v", waitErr)
		case <-deadlineCh:
			t.Fatalf("systemd-hostnamed never bound %s: last dial error: %v", h.socketPath(), err)
		case <-time.After(10 * time.Millisecond):
			// retry after a beat
		}
	}
}

// Stop terminates the daemon if it is running. This is registered as a test
// cleanup automatically by [Start] so only call this if you need to exercise
// daemon shutdown explicitly.
func (h *Hostnamed) Stop(t *testing.T) {
	t.Helper()
	if h.cmd == nil {
		return
	}
	_ = h.cmd.Process.Signal(syscall.SIGTERM)
	var err error
	select {
	case err = <-h.waitCh:
	case <-time.After(10 * time.Second):
		_ = h.cmd.Process.Kill()
		err = <-h.waitCh
	}
	if err != nil {
		t.Logf("systemd-hostnamed exited uncleanly: %v", err)
	}
	h.cmd = nil
}

// Restart stops the daemon and starts a fresh instance on the same varlink
// socket path, severing all previously-established client connections (to
// simulate hostnamed's short idle-exit behaviour).
func (h *Hostnamed) Restart(t *testing.T) {
	t.Helper()
	h.Stop(t)
	h.start(t)
}

// URI returns the varlink URI for clients to connect to.
func (h *Hostnamed) URI() string {
	return "unix:" + h.socketPath()
}

// WriteMachineInfo replaces the daemon's machine-info(5) file with the given
// lines. hostnamed re-reads the file whenever it changes so this can be called
// while the daemon is running.
func (h *Hostnamed) WriteMachineInfo(t *testing.T, lines ...string) {
	t.Helper()
	var buf bytes.Buffer
	for _, line := range lines {
		fmt.Fprintln(&buf, line)
	}
	if err := os.WriteFile(h.machineInfoPath(), buf.Bytes(), 0o644); err != nil { //nolint:forbidigo // test code
		t.Fatalf("write machine-info: %v", err)
	}
}

// MachineInfo returns the raw current contents of the daemon's machine-info(5)
// file, or an empty string if the file does not exist (hostnamed removes the
// file entirely rather than leaving it empty).
func (h *Hostnamed) MachineInfo(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile(h.machineInfoPath()) //nolint:forbidigo // test code
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read machine-info: %v", err)
	}
	return string(contents)
}

// Tags returns the machine tag list currently persisted to disk (the TAGS=
// field of the daemon's machine-info(5) file), sorted and deduplicated.
func (h *Hostnamed) Tags(t *testing.T) []string {
	t.Helper()
	for line := range strings.Lines(h.MachineInfo(t)) {
		line = strings.TrimSuffix(line, "\n")
		if value, ok := strings.CutPrefix(line, "TAGS="); ok {
			// Valid tags never contain characters that hostnamed's env-file
			// writer would quote, but be lenient just in case.
			return hostnamed.ParseTags(strings.Trim(value, `"`))
		}
	}
	return nil
}

// MachineInfoFingerprint returns an opaque fingerprint identifying the current
// machine-info(5) file (or noting its absence). hostnamed replaces the file
// wholesale on every store operation, so an unchanged fingerprint proves that
// no SetTags call modified the machine state in the meantime.
func (h *Hostnamed) MachineInfoFingerprint(t *testing.T) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(h.machineInfoPath(), &st); errors.Is(err, os.ErrNotExist) { //nolint:forbidigo // test code
		return "absent"
	} else if err != nil {
		t.Fatalf("stat machine-info: %v", err)
	}
	return fmt.Sprintf("ino=%d mtime=%d.%09d size=%d", st.Ino, st.Mtim.Sec, st.Mtim.Nsec, st.Size)
}
